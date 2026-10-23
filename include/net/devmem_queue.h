/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Device memory queue ownership: a device that is not the NIC - a GPU, say -
 * runs a NIC queue itself.  It posts RX buffers, polls completions, posts
 * sends and rings the doorbell; the kernel builds the queue in memory the
 * device gave and tells it where everything is.
 *
 * The queue is the device's alone: no NAPI, no page pool, no stack on it.
 * The user is in the kernel, and so is the code that writes the descriptors:
 * the NIC need not keep their DMA in, as for any driver.
 */
#ifndef _NET_DEVMEM_QUEUE_H
#define _NET_DEVMEM_QUEUE_H

#include <linux/dma-buf.h>
#include <linux/iosys-map.h>
#include <linux/types.h>
#include <net/netlink.h>

struct net_device;
struct netdev_queue_config;
struct net_devmem_queue;
struct net_devmem_queue_binding;

/* The layout of a queue's descriptors and completions: the NIC's vendor and
 * the generation of its hardware that has it.  The device's code knows it.
 */
enum {
	NET_DMQ_FMT_NONE,
	NET_DMQ_FMT_MLX5_CX5,
	NET_DMQ_FMT_BNXT_P5,	/* BCM5750x (Thor) */
	NET_DMQ_FMT_BNXT_P7,	/* BCM5760x (Thor2) */
	NET_DMQ_FMT_MAX,
};

/* What the descriptors address the data buffer by. */
enum {
	NET_DMQ_DATA_BUS,	/* the NIC's bus addresses of its pages */
	NET_DMQ_DATA_OFFSET,	/* offsets into it, under data_key */
};

#define NET_DMQ_RINGS_MAX	8
#define NET_DMQ_DOORBELLS_MAX	4
#define NET_DMQ_FMT_PRIV_LEN	64

/* NET_DMQ_FMT_MLX5_CX5: the rings, in order, and what fmt_priv holds. */
enum {
	NET_DMQ_MLX5_RQ,
	NET_DMQ_MLX5_RX_CQ,
	NET_DMQ_MLX5_SQ,
	NET_DMQ_MLX5_TX_CQ,
	NET_DMQ_MLX5_DBR,	/* the doorbell records */
	NET_DMQ_MLX5_RINGS,
};

/* The records in the DBR ring, big endian as the NIC reads them. */
#define NET_DMQ_MLX5_RQ_DBR	0	/* the RQ's receive counter */
#define NET_DMQ_MLX5_CQ_DBR	64	/* its CQ's consumer index */
#define NET_DMQ_MLX5_SQ_DBR	128	/* the SQ's send counter at + 4 */
#define NET_DMQ_MLX5_TX_CQ_DBR	192

struct net_dmq_mlx5 {
	u32 sqn;
	u32 frag_size;		/* an RQ entry's byte count */
	u32 frame_size;		/* the room a packet has in its page */
	u32 headroom;
};

/* NET_DMQ_FMT_BNXT_P5 and _P7: the rings, in order, and what fmt_priv holds.
 * No doorbell records: every ring rings at the one doorbell, with its key.
 */
enum {
	NET_DMQ_BNXT_RQ,
	NET_DMQ_BNXT_RX_CQ,
	NET_DMQ_BNXT_SQ,
	NET_DMQ_BNXT_TX_CQ,
	NET_DMQ_BNXT_RINGS,
};

struct net_dmq_bnxt {
	/* What each ring rings the doorbell with, its index ORed in low. */
	u64 db_key[NET_DMQ_BNXT_RINGS];
	/* bnxt reads a full ring as an empty one: no more than this many RQ
	 * entries are ever posted, a power of two below the ring's size.
	 */
	u32 rq_posted;
	u32 frag_size;		/* an RQ entry's byte count */
	u32 frame_size;		/* the room a packet has in its page */
	u32 headroom;
};

/* One ring the queue needs in the ring buffer. */
struct net_dmq_ring_req {
	u32 bytes;
	u32 align;		/* in the ring buffer's bus addresses */
	bool contiguous;	/* in bus addresses, not only in the buffer */
	u32 max_posted;		/* entries the device may have out at once */
};

/* What it takes to bind a queue with its config now. */
struct net_dmq_layout {
	u32 fmt;
	u32 nr_rings;
	struct net_dmq_ring_req ring[NET_DMQ_RINGS_MAX];
};

/* Where the queue is, once built: what the device needs to run it. */
struct net_dmq_info {
	u32 fmt;
	u32 gen;		/* moves on every rebuild */
	u32 nr_rings;
	struct {
		u32 offset;	/* in the ring buffer */
		u32 entries;
		u32 stride;
	} ring[NET_DMQ_RINGS_MAX];
	u32 data_addr;		/* NET_DMQ_DATA_* */
	u32 data_key;
	u32 nr_doorbells;
	struct {
		phys_addr_t phys;	/* where it is on the bus */
		u8 width;		/* bytes a write */
	} doorbell[NET_DMQ_DOORBELLS_MAX];
	/* The rest the format needs: mlx5's queue numbers, for one. */
	u8 fmt_priv[NET_DMQ_FMT_PRIV_LEN];
};

/* The device side: told when a queue goes, comes back, or dies. */
struct net_dmq_ops {
	/* The queue is about to stop: stop touching it before returning. */
	void (*down)(struct net_devmem_queue *q, void *priv);
	/* Runnable, as @info says.  A new gen is a new build, to start afresh
	 * on; the same gen is the same queue, to carry on with.
	 */
	void (*up)(struct net_devmem_queue *q, const struct net_dmq_info *info,
		   void *priv);
	/* The NIC stopped it for good, or the netdev is going. */
	void (*dead)(struct net_devmem_queue *q, void *priv);
};

/* Where a ring may go in the ring buffer, and how much it may take: the
 * consumer lays the buffer out, the driver keeps its rings inside.
 */
struct net_dmq_region {
	u32 offset;
	u32 bytes;
};

/* One queue to bind: the ring and data buffers are the queue's own.  With
 * no regions, the driver lays the ring buffer out itself.
 */
struct net_dmq_bind_req {
	u32 idx;
	struct dma_buf *rings;
	struct dma_buf *data;
	u32 nr_regions;
	struct net_dmq_region region[NET_DMQ_RINGS_MAX];
};

#if IS_ENABLED(CONFIG_NET_DEVMEM)
/* The consumer's side. */
int net_devmem_queue_query(struct net_device *dev, u32 idx,
			   struct net_dmq_layout *layout,
			   struct netlink_ext_ack *extack);
struct net_devmem_queue_binding *
net_devmem_bind_queues(struct net_device *dev,
		       const struct net_dmq_bind_req *reqs, u32 nr,
		       const struct net_dmq_ops *ops, void *priv,
		       struct netlink_ext_ack *extack);
void net_devmem_unbind_queues(struct net_devmem_queue_binding *binding);
/* What descriptors address each page of queue @idx's data buffer by. */
int net_devmem_queue_data_addrs(struct net_devmem_queue_binding *binding,
				u32 idx, u64 *addrs, u32 nr);
u32 net_dmq_queue_idx(struct net_devmem_queue *q);

/* Whether any of the device's queues is handed over: nothing else may then
 * take a queue of it.
 */
bool netif_has_dmq(struct net_device *dev);
u32 dev_get_min_dmq_channel_count(struct net_device *dev);

/* The driver's side, from its queue (re)build. */
struct net_devmem_queue *netif_rxq_dmq(struct net_device *dev, u32 idx);
struct net_devmem_queue_binding *net_dmq_binding(struct net_devmem_queue *q);
struct sg_table *net_dmq_rings_sgt(struct net_devmem_queue *q);
struct sg_table *net_dmq_data_sgt(struct net_devmem_queue *q);
/* The ring buffer as the CPU sees it, to clear what a new build reads. */
struct iosys_map *net_dmq_rings_map(struct net_devmem_queue *q);
/* The consumer's region for @ring, or false to lay it out at will. */
bool net_dmq_region(struct net_devmem_queue *q, u32 ring,
		    struct net_dmq_region *region);
void *net_dmq_binding_drv_priv(struct net_devmem_queue_binding *binding);
void net_dmq_binding_set_drv_priv(struct net_devmem_queue_binding *binding,
				  void *drv_priv);
void net_dmq_binding_set_data_addr(struct net_devmem_queue_binding *binding,
				   u32 data_addr);
/* The queue is built in the binding's memory: a new gen. */
void net_dmq_built(struct net_devmem_queue *q, const struct net_dmq_info *info);
/* It may run, and it may not: around every activation, build or none. */
void net_dmq_publish(struct net_devmem_queue *q);
void net_dmq_quiesce(struct net_devmem_queue *q);
void net_dmq_dead(struct net_devmem_queue *q);
#else
static inline bool netif_has_dmq(struct net_device *dev)
{
	return false;
}

static inline u32 dev_get_min_dmq_channel_count(struct net_device *dev)
{
	return 0;
}

static inline struct net_devmem_queue *netif_rxq_dmq(struct net_device *dev,
						     u32 idx)
{
	return NULL;
}
#endif

#endif /* _NET_DEVMEM_QUEUE_H */
