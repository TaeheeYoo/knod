/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef BNXT_DMQ_H
#define BNXT_DMQ_H

#include <net/devmem_queue.h>
#include <net/netdev_queues.h>

struct bnxt;
struct bnxt_ring_mem_info;

/* A ring in another device's ring buffer, and the NIC's addresses of the
 * pages it was allocated with, to put back before they are freed.
 */
struct bnxt_dmq_ring {
	struct bnxt_ring_mem_info *rmem;
	dma_addr_t *host;
};

/* A queue another device runs: its RX ring, the XDP TX ring beside it and
 * both their CQs.
 */
struct bnxt_dmq {
	struct net_devmem_queue *q;
	struct bnxt_dmq_ring rings[NET_DMQ_BNXT_RINGS];
	u32 off[NET_DMQ_BNXT_RINGS];
};

#if IS_ENABLED(CONFIG_NET_DEVMEM)
int bnxt_dmq_query(struct net_device *dev, int idx,
		   const struct netdev_queue_config *qcfg,
		   struct net_dmq_layout *layout,
		   struct netlink_ext_ack *extack);
int bnxt_dmq_binding_init(struct net_device *dev,
			  struct net_devmem_queue_binding *binding,
			  struct netlink_ext_ack *extack);
void bnxt_dmq_binding_uninit(struct net_device *dev,
			     struct net_devmem_queue_binding *binding);
int bnxt_dmq_rebuild(struct net_device *dev, struct netlink_ext_ack *extack);

int bnxt_dmq_rings(struct bnxt *bp);
void bnxt_dmq_unrings(struct bnxt *bp);
void bnxt_dmq_open(struct bnxt *bp);
void bnxt_dmq_close(struct bnxt *bp);
#else
static inline int bnxt_dmq_rings(struct bnxt *bp)
{
	return 0;
}

static inline void bnxt_dmq_unrings(struct bnxt *bp) {}
static inline void bnxt_dmq_open(struct bnxt *bp) {}
static inline void bnxt_dmq_close(struct bnxt *bp) {}
#endif

#endif
