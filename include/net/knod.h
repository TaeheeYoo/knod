/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __NET_KNOD_H
#define __NET_KNOD_H

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
#include <linux/irq_work.h>
#include <net/xdp.h>
#include <net/spsc_ring.h>

struct knod_dev;
struct knod_netdev;
struct knod_accel;
struct netlink_ext_ack;
struct net_devmem_dmabuf_binding;

extern struct mutex knod_lock;

/* Immutable XDP frame bounds published by the RX provider.  Zero is invalid
 * so a provider cannot silently fall back to page-wide packet bounds.
 */
static inline u32 knod_rx_bounds_encode(u32 headroom, u32 frame_size)
{
	if (headroom > U16_MAX || frame_size > U16_MAX ||
	    frame_size <= headroom)
		return 0;

	return frame_size << 16 | headroom;
}

/* A PASS entry's low half: what the NIC found of the packet's checksums. */
#define KNOD_PASS_CSUM_OK	(1 << 0)	/* IP and L4 good */
#define KNOD_PASS_CSUM_INNER	(1 << 1)	/* the inner ones too */
/* ...and an ESP packet the accel decrypted for SA KNOD_PASS_IPSEC_SA(), with
 * whether its ICV failed.
 */
#define KNOD_PASS_IPSEC		(1 << 2)
#define KNOD_PASS_IPSEC_FAIL	(1 << 3)
#define KNOD_PASS_IPSEC_SA(v)	(((v) >> 8) & 0xff)
#define KNOD_IPSEC_SA_MAX	256

struct knod_work_priv {
	u32 rx_bounds; /* low16: headroom, high16: frame size from hard start */
	/* XDP_PASS: the accel copies a packet to staging page i and appends
	 * {off | len << 16} << 32 | KNOD_PASS_CSUM_* as entry i of @pass_ring,
	 * counting them in @pass_pc.  The drain delivers them and counts the ones done in
	 * @pass_cc, which frees their pages.  Set by the accel.
	 */
	const u64 *pass_ring;
	u32 pass_mask;
	const u32 *pass_pc;
	u32 *pass_cc;
	struct dma_buf *dmabuf;
	struct napi_struct *napi;
	/* The CPU the NIC runs this queue's NAPI on, -1 for any: the
	 * delivery NAPI is kicked there, as the queue's interrupt would.
	 */
	int napi_cpu;
	struct irq_work napi_kick;
	/* The staging pages, KNOD_PASS_SLOTS of them, in a GTT buffer of this
	 * queue's own (the accel's @pass_stage_priv).
	 */
	void *pass_stage;
	u64 pass_stage_gaddr;
	void *pass_stage_priv;
} ____cacheline_aligned_in_smp;

/* A dma-buf mapped for the NIC, peer-to-peer where the exporter allows it. */
struct knod_nic_map {
	struct dma_buf_attachment *attach;
	struct sg_table *sgt;
};

int knod_nic_map_dmabuf(struct dma_buf *dmabuf, struct device *dev,
			struct knod_nic_map *map);
void knod_nic_unmap_dmabuf(struct dma_buf *dmabuf, struct knod_nic_map *map);

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
};

struct xfrm_state;

/* The xfrm states the accel decrypts for, as the NIC's xfrmdev_ops get them
 * while the IPsec feature is on: inbound crypto offload only.
 */
struct knod_accel_ipsec_ops {
	int (*state_add)(struct knod_dev *knodev, struct xfrm_state *x,
			 struct netlink_ext_ack *extack);
	void (*state_delete)(struct knod_dev *knodev, struct xfrm_state *x);
	void (*state_free)(struct knod_dev *knodev, struct xfrm_state *x);
	/* An outbound state's packet, ESP header filled in, to encrypt and
	 * send: true if taken.  Optional.
	 */
	bool (*xmit)(struct knod_dev *knodev, struct sk_buff *skb,
		     struct xfrm_state *x);
};

struct knod_accel_ops {
	int (*attach)(struct knod_dev *knodev);
	void (*pre_detach)(struct knod_dev *knodev);
	void (*detach)(struct knod_dev *knodev);
	/* interface up/down (NIC driver knod_dev_start/stop): worker only. */
	void (*dev_start)(struct knod_dev *knodev);
	void (*dev_stop)(struct knod_dev *knodev);
	void *(*alloc_mem)(struct knod_dev *knodev, size_t size,
			   u64 *gaddr, void **priv);
	void (*free_mem)(struct knod_dev *knodev, void *priv);
	/*
	 * Map dmabuf RX BOs into the GPU VM; must run after
	 * knod_dmabuf_attach().
	 */
	int (*mp_map)(struct knod_dev *knodev);
	/* Attach is done, RX buffers bound and mapped: the default feature
	 * may take the NIC's rings.
	 */
	void (*attached)(struct knod_dev *knodev);
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
};

struct knod_dev_stats {
	u32                     d2h_copied;
};

#define __NOD_FLAGS_XDP		0
#define __NOD_FLAGS_KTLS	3
#define __NOD_FLAGS_MAX		(__NOD_FLAGS_KTLS + 1)
#define KNOD_FLAGS_XDP		(1 << __NOD_FLAGS_XDP)
#define KNOD_FLAGS_KTLS		(1 << __NOD_FLAGS_KTLS)

#define KNOD_TYPE_GPU		0
#define KNOD_TYPE_DPU		1
#define KNOD_TYPE_MAX		(KNOD_TYPE_DPU + 1)

#define KNOD_SPSC_MAX		32

/* GPU->host copies in flight per RX queue, each with a staging page: a
 * queue's staging buffer is KNOD_PASS_SLOTS * PAGE_SIZE of GTT.
 */
#define KNOD_PASS_SLOTS		32768

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
	struct mutex lock;
	struct net_device *netdev;
	struct knod_dev_stats *stats __percpu;

	struct knod_nic_ops *nic_ops;
	struct knod_accel_ops *accel_ops;
	/* per-queue priv data */
	struct knod_work_priv *wpriv;
	bool started;
	/* IPsec: the NIC's own xfrmdev_ops while the accel's stand in, and
	 * the state each SA slot the accel reports decrypting for belongs to.
	 */
	const struct xfrmdev_ops *ipsec_orig_xfrmdev_ops;
	bool ipsec_added_hw_esp;
	struct xfrm_state __rcu *ipsec_sa[KNOD_IPSEC_SA_MAX];
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
void knod_dev_flush_pass(struct knod_dev *knodev);
int knod_dev_xdp_install(struct knod_dev *knodev,
				struct netdev_bpf *xdp);
void knod_dev_lock(void);
void knod_dev_unlock(void);
int knod_d2h_drain(struct knod_dev *knodev, int napi_index,
		   struct napi_struct *napi, int budget);
void knod_dev_pass_kick(struct knod_dev *knodev, int napi_index);
int knod_ipsec_attach(struct knod_dev *knodev);
void knod_ipsec_detach(struct knod_dev *knodev);
void knod_ipsec_sa_set(struct knod_dev *knodev, u32 slot,
		       struct xfrm_state *x);

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

/* XDP PASS drain - called from NIC NAPI poll */
int knod_dev_xdp_drain_pass(struct knod_dev *knodev,
				   struct napi_struct *napi,
				   int queue_idx, int budget);

#endif
