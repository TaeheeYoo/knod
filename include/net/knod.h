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
struct knod_accel;
struct netlink_ext_ack;

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
#define KNOD_PASS_IPSEC_CSUM	(1 << 4)	/* its inner checksum good */
#define KNOD_PASS_IPSEC_SA(v)	(((v) >> 8) & 0xff)
#define KNOD_IPSEC_SA_MAX	256

/*
 * A PASS packet, in a page of the stack's: a page_pool page the accel copied
 * it into, at @v's {off | len << 16} << 32 and with its KNOD_PASS_* below.
 * No page for an entry the accel had to drop.
 */
struct knod_pass_buf {
	struct page *page;
	u64 v;
};

struct knod_work_priv {
	/* XDP_PASS: the accel puts a packet in a page of its own and the
	 * entry at @pass_buf[@pass_pc & @pass_mask], then publishes @pass_pc;
	 * the drain builds an skb around each page and counts the entries it
	 * took in @pass_cc, which frees them for the accel.  @pass_buf is the
	 * accel's, NULL for none.
	 */
	struct knod_pass_buf *pass_buf;
	u32 pass_mask;
	u32 pass_pc;
	u32 pass_cc;
	struct napi_struct *napi;
	/* The CPU the queue's delivery NAPI runs on, -1 for any: it is
	 * kicked there, as the queue's interrupt would have run it.
	 */
	int napi_cpu;
	struct irq_work napi_kick;
} ____cacheline_aligned_in_smp;

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

/* The xfrm states put on the knod link, for the accel to open and seal
 * their packets with while the IPsec feature is on.
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
	/* the knod link up/down (knod_dev_start/stop). */
	void (*dev_start)(struct knod_dev *knodev);
	void (*dev_stop)(struct knod_dev *knodev);
	void *(*alloc_mem)(struct knod_dev *knodev, size_t size,
			   u64 *gaddr, void **priv);
	void (*free_mem)(struct knod_dev *knodev, void *priv);
	/* Map the RX buffers into the GPU VM. */
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

#define KNOD_STATUS_FREE		0
#define KNOD_STATUS_USED		1

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
	int status;
	int type;
	int flags;
	int id;
	void *priv;
	char name[16];
};

struct knod_dev {
	struct list_head list;
	struct knod_accel *accel;
	struct mutex lock;
	struct net_device *netdev;
	/* The knod link over the NIC, which received packets go up. */
	struct net_device *upper;
	struct knod_dev_stats *stats __percpu;

	struct knod_accel_ops *accel_ops;
	/* per-queue priv data */
	struct knod_work_priv *wpriv;
	bool started;
	/* IPsec: the state each SA slot the accel reports decrypting for
	 * belongs to.
	 */
	struct xfrm_state __rcu *ipsec_sa[KNOD_IPSEC_SA_MAX];
};

/* The device the stack sees the NIC's traffic on: the knod link, if any. */
static inline struct net_device *knod_dev_stack(struct knod_dev *knodev)
{
	return READ_ONCE(knodev->upper) ?: knodev->netdev;
}

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
void knod_ipsec_sa_set(struct knod_dev *knodev, u32 slot,
		       struct xfrm_state *x);

extern struct list_head knod_dev_list;
extern struct list_head knod_accel_list;

#define for_each_xdev(d)         \
		list_for_each_entry(d, &knod_dev_list, list)
#define for_each_xdev_safe(d)         \
		list_for_each_entry_safe(d, n, &knod_dev_list, list)
#define for_each_accel(d)         \
		list_for_each_entry(d, &knod_accel_list, list)
#define for_each_accel_safe(d, n)         \
		list_for_each_entry_safe(d, n, &knod_accel_list, list)

#endif
