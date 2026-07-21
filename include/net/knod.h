/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __NET_KNOD_H
#define __NET_KNOD_H

#include <linux/bits.h>
#include <linux/bpf.h>
#include <linux/dma-buf.h>
#include <linux/ethtool_netlink.h>
#include <linux/netdevice.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/rtnetlink.h>
#include <linux/mutex.h>
#include <linux/list.h>
#include <linux/if_link.h>
#include <linux/workqueue.h>
#include <linux/completion.h>
#include <linux/atomic.h>
#include <net/xdp.h>
#include <net/spsc_ring.h>

struct knod_dev;
struct knod_netdev;
struct knod_accel;
struct gen_pool;
struct page_pool;
struct netlink_ext_ack;
struct net_devmem_dmabuf_binding;

extern struct mutex knod_lock;

struct spsc_bd {
	netmem_ref netmem;
	u64 act;
	u16 off;
	u16 len;
	u32 page_idx;
	struct page_pool *pp;
};

/*
 * KNOD action codes for spsc_bd.act
 *
 * Base actions (compatible with XDP constants for BPF/XDP path):
 */
#define KNOD_ABORTED	XDP_ABORTED	/* 0 */
#define KNOD_DROP	XDP_DROP	/* 1 */
#define KNOD_PASS	XDP_PASS	/* 2 */
#define KNOD_TX		XDP_TX		/* 3 */
#define KNOD_REDIRECT	XDP_REDIRECT	/* 4 */

/*
 * Extended actions - accel-specific, must not collide with XDP range [0..7].
 * The NIC act_handler treats any unknown code as "in-flight to accel":
 * stop releasing at that entry and wait for the accel to update bd->act.
 */
#define KNOD_ACT_INFLIGHT	0x80	/* accel processing in progress */
#define KNOD_IPSEC_INFLIGHT	0x100	/* GPU IPsec dispatch in progress */
#define KNOD_IPSEC_PASS		0x101	/* GPU IPsec done, recycle page */
#define KNOD_IPSEC_DROP		0x102	/* GPU IPsec done, drop + recycle */

/*
 * PASS hand-off descriptor: the DD (NIC act_handler) fills one per PASS bd
 * during its single act traversal and hands a batch to accel_ops->pass_copy.
 * @netmem is the source RX page (GPU memory); @off/@len are post-BPF (may
 * differ from the bd's original values if the program adjusted head/tail).
 */
struct spsc_pass_bd {
	/* source RX page, recycled after the copy lands */
	netmem_ref netmem;
	u32 page_idx;		/* page index in the queue's dmabuf RX buffer
				 * (the accel turns this into the GPU src addr;
				 * the netmem dma_addr is the NIC's, not the
				 * GPU's)
				 */
	u16 off;		/* packet offset within the page (post-BPF) */
	u16 len;		/* packet length (post-BPF) */
};

/*
 * Host-page page_pool provider context (GPU->host delivery pools).  The
 * framework fills the public fields, points page_pool_params.mp_priv at it and
 * sets .mp_ops to the NOD-private page_pool_hostmem_ops (knod_dev.c);
 * ->init() builds @genpool and ->destroy() tears it down.  Must outlive the
 * page_pool; @freed fires once the pool has fully drained.
 */
struct page_pool_hostmem {
	struct page **pages;		/* owner-supplied, @count real pages */
	unsigned int count;
	dma_addr_t base_addr;		/* device addr of pages[0] */
	void (*freed)(void *arg);	/* called once the pool fully drains */
	void *arg;
	struct gen_pool *genpool;	/* private: managed by the provider */
};

struct knod_work_priv {
	struct dma_buf *dmabuf;
	netmem_ref *netmems;
	unsigned int *data_lens;
	int *data_offs;
	int cnt;
	int index;
	struct napi_struct *napi;
	struct spsc_ring spsc_bds;
	void *spsc_pool_priv;	/* accel driver priv for spsc pool memory */
	u64 spsc_pool_gaddr;	/* device-visible address of spsc pool */
	/* framework-owned delivery pool */
	struct page_pool *pass_pool;
	/* provider ctx (owner storage) */
	struct page_pool_hostmem pass_hm;
	/* d2h: SDMA-issued, awaiting drain */
	struct spsc_ring pass_pending;
} ____cacheline_aligned_in_smp;

static inline void knod_napi_kick(struct knod_work_priv *wpriv)
{
	struct napi_struct *napi;

	rcu_read_lock();
	napi = READ_ONCE(wpriv->napi);
	if (napi)
		napi_schedule(napi);
	rcu_read_unlock();
}

#define KNOD_DEFAULT_PASS_SLOTS	64

/*
 * GPU->host delivery descriptor: a packet at @off (preserved headroom) for
 * @len bytes within @netmem, a page from the framework delivery pool.  The
 * d2h path fills these into the per-queue pass_pending ring; knod_d2h_drain()
 * turns each into an skb once its SDMA copy lands and hands it to the stack.
 */
struct knod_pass_desc {
	u16 len;		/* head_frag length (ipsec: inner_len) */
	u16 off;		/* head_frag offset (ipsec: inner_off) */
	netmem_ref netmem;	/* dst: framework delivery-pool page */
	netmem_ref src;		/* src: RX page recycled once the copy lands, or
				 * 0 when the producer recycles it elsewhere
				 * (ipsec: NIC act handler recycles via the bd)
				 */
	/* SDMA fence to await before delivery (async) */
	u32 fence_val;
	u8  sdma_idx;		/* which accel SDMA queue's fence to await */
	/* Feature finalisation context, consumed by knod_dev->post_copy. */
	struct {
		u32 sa_slot;	/* ipsec SA table slot */
		u32 seq_lo;	/* ESP sequence low 32 bits */
		u32 seq_hi;	/* ESN high 32 bits (0 if !ESN) */
		u8  mode;	/* XFRM_MODE_TRANSPORT / _TUNNEL */
		u8  next_hdr;	/* ESP trailer next-header */
		u8  family;	/* AF_INET / AF_INET6 */
	} feat;
};

struct knod_accel_xdp_ops {
	/* init/exit: permanent per-attach setup (attach/detach). */
	int (*init)(struct knod_dev *knodev);
	void (*exit)(struct knod_dev *knodev);
	/* activate/deactivate: feature resource alloc/free (feature select). */
	int (*activate)(struct knod_dev *knodev);
	void (*deactivate)(struct knod_dev *knodev);
	/*
	 * true while user XDP progs/maps are still bound (blocks feature
	 * switch).
	 */
	bool (*busy)(struct knod_dev *knodev);
	int (*xdp_offload_init)(struct knod_dev *knodev);
	void (*xdp_offload_uninit)(struct knod_dev *knodev);
	int (*xdp_install)(struct knod_dev *knodev,
			   struct netdev_bpf *bpf);
	int (*rx_netmem)(struct knod_dev *knodev, netmem_ref netmem,
			 unsigned int data_len, int data_offset, int index);
	int (*rx_netmem_bulk)(struct knod_dev *knodev,
			      struct knod_work_priv *wpriv);
	/* Direct dispatch */
	int (*dispatch)(struct knod_dev *knodev, int index);
	/* Direct finish */
	int (*finish)(struct knod_dev *knodev, int index);
	void (*start)(struct knod_dev *knodev);
	void (*stop)(struct knod_dev *knodev);
};

struct xfrm_state;
struct xfrm_policy;
struct netlink_ext_ack;

struct knod_accel_ipsec_ops {
	/* init/exit: permanent per-attach setup (attach/detach). */
	int (*init)(struct knod_dev *knodev);
	void (*exit)(struct knod_dev *knodev);
	/* activate/deactivate: feature resource alloc/free (feature select). */
	int (*activate)(struct knod_dev *knodev);
	void (*deactivate)(struct knod_dev *knodev);
	/*
	 * true while offloaded xfrm SAs are still bound (blocks feature
	 * switch).
	 */
	bool (*busy)(struct knod_dev *knodev);
	/*
	 * start/stop: worker/dispatcher start + GPU drain (interface
	 * up/down).
	 */
	void (*start)(struct knod_dev *knodev);
	void (*stop)(struct knod_dev *knodev);
	int (*xdo_dev_state_add)(struct knod_dev *knodev,
				 struct xfrm_state *x,
				 struct netlink_ext_ack *extack);
	void (*xdo_dev_state_delete)(struct knod_dev *knodev,
				     struct xfrm_state *x);
	void (*xdo_dev_state_free)(struct knod_dev *knodev,
				   struct xfrm_state *x);
	bool (*xdo_dev_offload_ok)(struct knod_dev *knodev,
				   struct sk_buff *skb,
				   struct xfrm_state *x);
	void (*xdo_dev_state_advance_esn)(struct knod_dev *knodev,
					  struct xfrm_state *x);
	void (*xdo_dev_state_update_stats)(struct knod_dev *knodev,
					   struct xfrm_state *x);
	int (*xdo_dev_policy_add)(struct knod_dev *knodev,
				  struct xfrm_policy *x,
				  struct netlink_ext_ack *extack);
	void (*xdo_dev_policy_delete)(struct knod_dev *knodev,
				      struct xfrm_policy *x);
	void (*xdo_dev_policy_free)(struct knod_dev *knodev,
				    struct xfrm_policy *x);
};

struct knod_accel_ops {
	int (*attach)(struct knod_dev *knodev);
	void (*pre_detach)(struct knod_dev *knodev);
	void (*detach)(struct knod_dev *knodev);
	/* interface up/down (NIC driver knod_dev_start/stop): worker only. */
	void (*dev_start)(struct knod_dev *knodev);
	void (*dev_stop)(struct knod_dev *knodev);
	void *(*alloc_mem)(struct knod_dev *knodev, size_t size,
			   u64 *gaddr, struct page ***pages, void **priv);
	void (*free_mem)(struct knod_dev *knodev, void *priv);
	/*
	 * Map dmabuf RX BOs into the GPU VM; must run after
	 * knod_dmabuf_attach().
	 */
	int (*mp_map)(struct knod_dev *knodev);
	/*
	 * Device->host copy primitives, used by the common knod_d2h_copy /
	 * knod_d2h_drain delivery path.  The accel owns the SDMA engine (and
	 * its fence/ring); the framework owns the pending ring and dst pool.
	 *   d2h_submit: queue one GPU->host copy.  Returns a monotonic fence
	 *               position to tag the descriptor with, or 0 if the SDMA
	 *               ring is full (caller drops -- backpressure).
	 *   d2h_kick:   publish the batch (fence + doorbell).
	 *   d2h_fence:  current completed fence position of an SDMA queue
	 *               (drain compares the descriptor's tag against this).
	 */
	u32 (*d2h_submit)(struct knod_dev *knodev, u64 dst, int queue,
			  u32 page_idx, u16 off, u32 len);
	void (*d2h_kick)(struct knod_dev *knodev);
	u32 (*d2h_fence)(struct knod_dev *knodev, int sdma_idx);
	struct knod_accel_xdp_ops *xdp_ops;
	struct knod_accel_ipsec_ops *ipsec_ops;

	/* control plane (knod genetlink) feature select */
	int (*feature_get)(struct knod_accel *accel, u32 *ena, u32 *cap);
	int (*feature_set)(struct knod_accel *accel, u32 feature,
			   struct netlink_ext_ack *extack);
};

struct knod_nic_ops {
	int (*attach)(struct knod_dev *knodev);
	int (*detach)(struct knod_dev *knodev);
	int (*tx_handler)(struct knod_dev *knodev, struct spsc_bd **bds,
			  int cnt, int napi_index, void *priv);
	int (*redir_handler)(struct knod_dev *knodev, netmem_ref *netmems,
			     u16 *lens, int cnt, int napi_index,
			     struct net_device *target_dev, void *priv);
	int (*drop_handler)(struct knod_dev *knodev, netmem_ref *netmems,
			    u16 *lens, int cnt, void *priv);
};

struct knod_dev_stats {
	u64_stats_t             tx_packets;
	u64_stats_t             tx_bytes;
	struct u64_stats_sync   syncp;
	u32                     tx_dropped;
	u32                     tx_errors;
};

#define __NOD_FLAGS_XDP		0
#define __NOD_FLAGS_IPSEC	2
#define __NOD_FLAGS_KTLS	3
#define __NOD_FLAGS_MAX		(__NOD_FLAGS_KTLS + 1)
#define KNOD_FLAGS_XDP		BIT(__NOD_FLAGS_XDP)
#define KNOD_FLAGS_IPSEC	BIT(__NOD_FLAGS_IPSEC)
#define KNOD_FLAGS_KTLS		BIT(__NOD_FLAGS_KTLS)

#define KNOD_TYPE_GPU		0
#define KNOD_TYPE_DPU		1
#define KNOD_TYPE_MAX		(KNOD_TYPE_DPU + 1)

#define KNOD_SPSC_MAX		32
#define KNOD_SPSC_ELEMS_MAX	8192

/* Per-RX-queue GPU->host delivery pages (in-flight cap; sized for the deepest
 * feature pipeline, independent of any per-feature descriptor ring size).
 * Must cover the worst case where one RSS-concentrated flow lands every
 * in-flight work on a single queue: ipsec holds a full batch of delivery
 * pages per work (alloc precedes the SDMA copy into them), so the cap needs
 * KNOD_IPSEC_NR_WORK * KNOD_IPSEC_PKT_BATCH (= 4 * 512) plus the pass_pending
 * ring depth. Sized to absorb a full bd ring (KNOD_SPSC_ELEMS_MAX = 8192)
 * worth of decrypted-but-undelivered packets plus the in-flight works. The
 * backing is GTT, sized nqueues * KNOD_PASS_SLOTS * PAGE_SIZE (2 GiB at the
 * 32-queue cap), which is why the alloc size path is size_t rather than int.
 */
#define KNOD_PASS_SLOTS		16384

#define KNOD_STATUS_FREE		0
#define KNOD_STATUS_USED		1

struct knod_netdev {
	struct list_head list;
	struct net_device *dev;
	struct knod_dev *knodev;
	struct knod_accel *accel;
	struct knod_nic_ops *nic_ops;
	struct module *owner;
	int flags;
	int status;
	void *priv;
};

struct knod_accel_xdp {
	struct bpf_offload_dev *bpf_dev;
	struct xdp_attachment_info xdp;
	struct xdp_attachment_info xdp_hw;
	struct bpf_prog *bpf_offloaded;
	struct list_head bound_maps;
	void *priv;
};

struct knod_accel {
	struct list_head list;
	struct knod_accel_ops *accel_ops;
	struct module *owner;
	struct knod_accel_xdp xdp;
	struct knod_dev *knodev;
	struct knod_netdev *knetdev;
	int status;
	int type;
	int flags;
	int id;
	void *priv;
	char name[16];
};

struct knod_dev {
	struct list_head list;
	struct knod_netdev *knetdev;
	struct knod_accel *accel;
	struct net_devmem_dmabuf_binding *bindings[KNOD_SPSC_MAX];
	/* serialises offloaded prog/map installs against feature teardown */
	struct mutex lock;
	struct net_device *netdev;
	struct knod_dev_stats *stats __percpu;

	struct knod_nic_ops *nic_ops;
	struct knod_accel_ops *accel_ops;
	/* per-queue priv data */
	struct knod_work_priv *wpriv;
	bool started;

	/* IPsec proxy: original NIC xfrmdev_ops/feature state saved at attach,
	 * restored at detach so a NIC's native offload is not clobbered.
	 */
	const struct xfrmdev_ops *ipsec_orig_xfrmdev_ops;
	bool ipsec_added_hw_esp;

	/* framework-owned GPU->host delivery (default pass): drain barrier */
	/* accel handle for the delivery buffer */
	void *pass_priv;
	atomic_t pp_live;		/* live delivery page_pools */
	struct completion pp_drained;	/* all pools drained (teardown) */
	/*
	 * device->host (d2h) delivery: the accel owns the fence counter (its
	 * SDMA ring position); this lock just serialises the shared SDMA
	 * submit path across the per-queue NAPIs that drive knod_d2h_copy.
	 */
	spinlock_t d2h_lock;

	/*
	 * Feature delivery hook, set by the active feature on activate (NULL
	 * for bpf/none).  knod_d2h_drain calls it after building the head_frag
	 * skb to run feature-specific finalisation (ipsec: SA/replay/secpath);
	 * it returns false to drop the packet.
	 */
	bool (*post_copy)(struct knod_dev *knodev, struct sk_buff *skb,
			  const struct knod_pass_desc *desc, int queue_idx);
};

static inline bool knod_dev_active(struct knod_dev *knodev)
{
	return !!knodev->accel->xdp.xdp_hw.prog;
}

static inline struct bpf_prog *
knod_dev_offloaded(struct knod_dev *knodev)
{
	return knodev->accel->xdp.bpf_offloaded;
}

static inline void knod_dev_offload(struct knod_dev *knodev,
				    struct bpf_prog *bpf_offloaded)
{
	knodev->accel->xdp.bpf_offloaded = bpf_offloaded;
}

static inline bool knod_dev_map_empty(struct knod_dev *knodev)
{
	return list_empty(&knodev->accel->xdp.bound_maps);
}

void knod_netdev_register(struct knod_netdev *netdev);
void knod_netdev_unregister(struct knod_netdev *netdev);
void knod_accel_register(struct knod_accel *accel);
void knod_accel_unregister(struct knod_accel *accel);
void knod_dev_start(struct knod_dev *knodev);
void knod_dev_stop(struct knod_dev *knodev);
int knod_dev_xdp_install(struct knod_dev *knodev,
			 struct netdev_bpf *xdp);
void knod_dev_get_stats64(struct knod_dev *knodev,
			  struct rtnl_link_stats64 *stats);
void knod_dev_lock(void);
void knod_dev_unlock(void);
struct sk_buff *knod_pass_build_skb(netmem_ref netmem, u16 off, u16 len,
				    struct page_pool *pool, bool napi);
int knod_d2h_copy(struct knod_dev *knodev, int napi_index,
		  struct spsc_pass_bd *bds, int cnt);
int knod_d2h_drain(struct knod_dev *knodev, int napi_index,
		   struct napi_struct *napi, int budget);

extern struct list_head knod_dev_list;
extern struct list_head knod_netdev_list;
extern struct list_head knod_accel_list;

#define for_each_xdev(d)         \
		list_for_each_entry(d, &knod_dev_list, list)
#define for_each_xdev_safe(d)         \
		list_for_each_entry_safe(d, n, &knod_dev_list, list)
#define for_each_nodev(d)         \
		list_for_each_entry(d, &knod_netdev_list, list)
#define for_each_nodev_safe(d, n)         \
		list_for_each_entry_safe(d, n, &knod_netdev_list, list)
#define for_each_accel(d)         \
		list_for_each_entry(d, &knod_accel_list, list)
#define for_each_accel_safe(d, n)         \
		list_for_each_entry_safe(d, n, &knod_accel_list, list)

/* IPsec proxy functions */
#if IS_ENABLED(CONFIG_XFRM_OFFLOAD)
int knod_ipsec_attach(struct knod_dev *knodev);
void knod_ipsec_detach(struct knod_dev *knodev);
#else
#endif

/* XDP PASS drain - called from NIC NAPI poll */
int knod_dev_xdp_drain_pass(struct knod_dev *knodev,
			    struct napi_struct *napi,
			    int queue_idx, int budget);

#endif
