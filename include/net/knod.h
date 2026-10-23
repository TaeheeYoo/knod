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

/*
 * PASS hand-off descriptor: the DD (NIC act_handler) fills one per PASS bd
 * during its single act traversal and hands a batch to accel_ops->pass_copy.
 * @netmem is the source RX page (GPU memory); @off/@len are post-BPF (may
 * differ from the bd's original values if the program adjusted head/tail).
 */
struct spsc_pass_bd {
	u32 page_idx;		/* page index in the queue's dmabuf RX buffer
				 * (the accel turns this into the GPU src addr;
				 * the netmem dma_addr is the NIC's, not the
				 * GPU's)
				 */
	u16 off;		/* packet offset within the page (post-BPF) */
	u16 len;		/* packet length (post-BPF) */
};

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

struct knod_work_priv {
	u32 rx_bounds; /* low16: headroom, high16: frame size from hard start */
	/* GDA: where the drain counts the PASS copies it has finished, which
	 * is how the accel knows their RX pages are its again.  Set by the
	 * accel; NULL on the host-posted path.
	 */
	u32 *gda_pass_cc;
	struct dma_buf *dmabuf;
	struct napi_struct *napi;
	/* The CPU the NIC runs this queue's NAPI on, -1 for any: the
	 * delivery NAPI is kicked there, as the queue's interrupt would.
	 */
	int napi_cpu;
	struct irq_work napi_kick;
	/* d2h: SDMA-issued, awaiting drain */
	struct spsc_ring pass_pending;
	/* How far into pass_pending the copies have landed and their RX pages
	 * gone back to the accel (knod_d2h_credit()).  Moved only by the
	 * producer, and the producer never gets a full ring past it.
	 */
	u32 pass_credited;
	/* What a pass_pending slot's copy lands in: a page per slot, in a
	 * GTT buffer of this queue's own (the accel's @pass_stage_priv).
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

#define KNOD_DEFAULT_PASS_SLOTS	64

/*
 * GPU->host delivery descriptor: a packet at @off (preserved headroom) for
 * @len bytes in the staging page of pass_pending slot @slot.  The d2h path
 * fills these into the per-queue pass_pending ring; knod_d2h_drain() copies
 * each into an skb once its SDMA copy lands and hands it to the stack.  A
 * @len of zero is a copy of nothing, which still takes its place in order.
 */
struct knod_pass_desc {
	u16 len;
	u16 off;
	u32 slot;
	/* SDMA fence to await before delivery (async) */
	u32 fence_val;
	u8  sdma_idx;		/* which accel SDMA queue's fence to await */
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
	/*
	 * Device->host copy primitives, used by the common knod_d2h_copy /
	 * knod_d2h_drain delivery path.  The accel owns the SDMA engine (and
	 * its fence/ring); the framework owns the pending ring and staging.
	 *   d2h_submit: queue one GPU->host copy.  Returns a monotonic fence
	 *               position to tag the descriptor with, or 0 if the SDMA
	 *               ring is full (the caller stops and retries).
	 *   d2h_kick:   publish the batch (fence + doorbell).
	 *   d2h_fence:  current completed fence position of an SDMA queue
	 *               (drain compares the descriptor's tag against this).
	 */
	u32 (*d2h_submit)(struct knod_dev *knodev, u64 dst, int queue,
			  u32 page_idx, u16 off, u32 len);
	void (*d2h_kick)(struct knod_dev *knodev);
	u32 (*d2h_fence)(struct knod_dev *knodev, int sdma_idx);
	/* Publish @n more completed PASS copies of @queue to accelerator-owned
	 * memory.
	 */
	void (*pass_complete)(struct knod_dev *knodev, int queue, unsigned int n);
	struct knod_accel_xdp_ops *xdp_ops;

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
	struct mutex lock;
	struct net_device *netdev;
	struct knod_dev_stats *stats __percpu;

	struct knod_nic_ops *nic_ops;
	struct knod_accel_ops *accel_ops;
	/* per-queue priv data */
	struct knod_work_priv *wpriv;
	bool started;

	/*
	 * device->host (d2h) delivery: the accel owns the fence counter (its
	 * SDMA ring position); this lock just serialises the shared SDMA
	 * submit path across the per-queue NAPIs that drive knod_d2h_copy.
	 */
	spinlock_t d2h_lock;

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
int knod_d2h_copy(struct knod_dev *knodev, int napi_index,
		  const struct spsc_pass_bd *bds, int cnt);
int knod_d2h_drain(struct knod_dev *knodev, int napi_index,
		   struct napi_struct *napi, int budget);
unsigned int knod_d2h_credit(struct knod_dev *knodev, int napi_index);

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
