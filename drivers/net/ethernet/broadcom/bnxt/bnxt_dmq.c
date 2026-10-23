// SPDX-License-Identifier: GPL-2.0-only
/*
 * Device memory queue ownership on bnxt P5 and P7: a queue whose RX ring, the
 * XDP TX ring beside it and both their CQs another device runs.  The rings are
 * allocated the usual way, then their pages pointed at that device's ring
 * buffer before the NIC is told where they are; the host never posts, polls
 * or arms them.
 *
 * Every ring of the function rings at the one doorbell register, with a key
 * of its own; there are no doorbell records.  The rings address the data by
 * bus address: bnxt has nothing to check them against, so the user is kernel
 * code that writes only what the binding's buffers hold.
 */

#include <linux/dma-buf.h>
#include <linux/pci.h>
#include <net/netdev_lock.h>
#include <net/xdp.h>
#include <linux/bnxt/hsi.h>

#include "bnxt.h"
#include "bnxt_dmq.h"

/* What each ring takes, as the device's params build them now. */
static void bnxt_dmq_sizes(struct bnxt *bp, struct net_dmq_layout *lay)
{
	int i;

	lay->fmt = bp->flags & BNXT_FLAG_CHIP_P7 ? NET_DMQ_FMT_BNXT_P7 :
						    NET_DMQ_FMT_BNXT_P5;
	lay->nr_rings = NET_DMQ_BNXT_RINGS;
	lay->ring[NET_DMQ_BNXT_RQ].bytes = bp->rx_nr_pages * BNXT_PAGE_SIZE;
	lay->ring[NET_DMQ_BNXT_RQ].max_posted =
		rounddown_pow_of_two(bp->rx_ring_size);
	lay->ring[NET_DMQ_BNXT_RX_CQ].bytes = bp->cp_nr_pages * BNXT_PAGE_SIZE;
	lay->ring[NET_DMQ_BNXT_SQ].bytes = bp->tx_nr_pages * BNXT_PAGE_SIZE;
	lay->ring[NET_DMQ_BNXT_SQ].max_posted = bp->tx_ring_mask;
	lay->ring[NET_DMQ_BNXT_TX_CQ].bytes = bp->cp_nr_pages * BNXT_PAGE_SIZE;
	for (i = 0; i < NET_DMQ_BNXT_RINGS; i++)
		lay->ring[i].align = PAGE_SIZE;
}

/* What a queue another device runs needs of the device: rings it knows, an
 * XDP TX ring for every RX ring, one page a packet.
 */
static int bnxt_dmq_check(struct bnxt *bp, struct netlink_ext_ack *extack)
{
	if (!(bp->flags & BNXT_FLAG_CHIP_P5_PLUS) ||
	    BNXT_PAGE_SIZE != PAGE_SIZE) {
		NL_SET_ERR_MSG(extack, "only P5 and P7 rings on 4K pages");
		return -EOPNOTSUPP;
	}
	if (bp->xdp_prog) {
		NL_SET_ERR_MSG(extack, "an XDP program is attached");
		return -EBUSY;
	}
	if (bp->flags & BNXT_FLAG_HDS) {
		NL_SET_ERR_MSG(extack, "turn off header-data split");
		return -EOPNOTSUPP;
	}
	if (!(bp->flags & BNXT_FLAG_SHARED_RINGS)) {
		NL_SET_ERR_MSG(extack, "needs combined channels");
		return -EOPNOTSUPP;
	}
	if (bp->dev->mtu > BNXT_MAX_PAGE_MODE_MTU) {
		NL_SET_ERR_MSG(extack, "MTU too big for one page a packet");
		return -EOPNOTSUPP;
	}
	return 0;
}

int bnxt_dmq_query(struct net_device *dev, int idx,
		   const struct netdev_queue_config *qcfg,
		   struct net_dmq_layout *layout,
		   struct netlink_ext_ack *extack)
{
	struct bnxt *bp = netdev_priv(dev);
	int err;

	err = bnxt_dmq_check(bp, extack);
	if (err)
		return err;
	bnxt_dmq_sizes(bp, layout);
	return 0;
}

/* The rings a bound device runs: an XDP TX ring for every RX ring, and one
 * page per packet with no aggregation ring.
 */
static void bnxt_dmq_mode(struct bnxt *bp, bool on)
{
	struct net_device *dev = bp->dev;
	int tc = bp->num_tc ?: 1;

	if (on) {
		bp->flags &= ~BNXT_FLAG_AGG_RINGS;
		bp->flags |= BNXT_FLAG_NO_AGG_RINGS;
		dev->max_mtu = min_t(u16, bp->max_mtu, BNXT_MAX_PAGE_MODE_MTU);
		bp->rx_dir = DMA_BIDIRECTIONAL;
		bp->tx_nr_rings_xdp = bp->rx_nr_rings;
		netdev_update_features(dev);
	} else {
		bnxt_set_rx_skb_mode(bp, false);
		bp->tx_nr_rings_xdp = 0;
	}
	bp->tx_nr_rings = bp->tx_nr_rings_per_tc * tc + bp->tx_nr_rings_xdp;
	bnxt_set_cp_rings(bp, true);
	bnxt_set_tpa_flags(bp);
	bnxt_set_ring_params(bp);
}

/* Bound down only: the XDP TX rings it takes change what the device opens
 * with, which a queue restart cannot.
 */
int bnxt_dmq_binding_init(struct net_device *dev,
			  struct net_devmem_queue_binding *binding,
			  struct netlink_ext_ack *extack)
{
	struct bnxt *bp = netdev_priv(dev);
	int tc = bp->num_tc ?: 1;
	int err;

	netdev_assert_locked(dev);
	if (netif_running(dev)) {
		NL_SET_ERR_MSG(extack, "bring the device down first");
		return -EBUSY;
	}
	err = bnxt_dmq_check(bp, extack);
	if (err)
		return err;
	err = bnxt_check_rings(bp, bp->tx_nr_rings_per_tc, bp->rx_nr_rings,
			       true, tc, bp->rx_nr_rings);
	if (err) {
		NL_SET_ERR_MSG(extack, "not enough rings for an XDP TX ring per queue");
		return err;
	}

	bp->dmq = kcalloc(bp->rx_nr_rings, sizeof(*bp->dmq), GFP_KERNEL);
	if (!bp->dmq)
		return -ENOMEM;
	bp->dmq_nr = bp->rx_nr_rings;
	bnxt_dmq_mode(bp, true);
	net_dmq_binding_set_data_addr(binding, NET_DMQ_DATA_BUS);
	return 0;
}

void bnxt_dmq_binding_uninit(struct net_device *dev,
			     struct net_devmem_queue_binding *binding)
{
	struct bnxt *bp = netdev_priv(dev);
	bool running = netif_running(dev);

	if (running)
		bnxt_close_nic(bp, true, false);
	bnxt_dmq_mode(bp, false);
	kfree(bp->dmq);
	bp->dmq = NULL;
	bp->dmq_nr = 0;
	if (running && bnxt_open_nic(bp, true, false))
		netdev_err(dev, "dmq: did not open again on the host's rings\n");
}

int bnxt_dmq_rebuild(struct net_device *dev, struct netlink_ext_ack *extack)
{
	struct bnxt *bp = netdev_priv(dev);
	int err;

	bnxt_close_nic(bp, true, false);
	err = bnxt_open_nic(bp, true, false);
	if (err)
		NL_SET_ERR_MSG(extack, "device did not open again");
	return err;
}

/* Each page of a buffer, as the NIC addresses it. */
static dma_addr_t *bnxt_dmq_pages(struct sg_table *sgt, u32 *n)
{
	struct scatterlist *sg;
	u32 i = 0, total = 0;
	dma_addr_t *addrs;
	unsigned int off;
	int si;

	for_each_sgtable_dma_sg(sgt, sg, si)
		total += sg_dma_len(sg) >> PAGE_SHIFT;
	addrs = kvcalloc(total, sizeof(*addrs), GFP_KERNEL);
	if (!addrs)
		return NULL;
	for_each_sgtable_dma_sg(sgt, sg, si)
		for (off = 0; off + PAGE_SIZE <= sg_dma_len(sg); off += PAGE_SIZE)
			addrs[i++] = sg_dma_address(sg) + off;
	*n = i;
	return addrs;
}

static void bnxt_dmq_set_page(struct bnxt_ring_mem_info *rmem, int i,
			      dma_addr_t dma)
{
	rmem->dma_arr[i] = dma;
	/* The page table entry keeps its flags: valid, last, next to last. */
	if (rmem->pg_tbl)
		rmem->pg_tbl[i] = cpu_to_le64(dma |
			(le64_to_cpu(rmem->pg_tbl[i]) & ~PAGE_MASK));
}

/* Point a ring's pages at the ring buffer from page @first on. */
static int bnxt_dmq_swap(struct bnxt_dmq_ring *r,
			 struct bnxt_ring_mem_info *rmem,
			 const dma_addr_t *pages, u32 first, u32 bytes)
{
	int i;

	if (rmem->page_size != PAGE_SIZE ||
	    (size_t)rmem->nr_pages * PAGE_SIZE > bytes)
		return -EINVAL;

	r->host = kcalloc(rmem->nr_pages, sizeof(*r->host), GFP_KERNEL);
	if (!r->host)
		return -ENOMEM;
	for (i = 0; i < rmem->nr_pages; i++) {
		r->host[i] = rmem->dma_arr[i];
		bnxt_dmq_set_page(rmem, i, pages[first + i]);
	}
	r->rmem = rmem;
	return 0;
}

static void bnxt_dmq_unswap(struct bnxt_dmq_ring *r)
{
	int i;

	if (!r->rmem)
		return;
	for (i = 0; i < r->rmem->nr_pages; i++)
		bnxt_dmq_set_page(r->rmem, i, r->host[i]);
	kfree(r->host);
	r->host = NULL;
	r->rmem = NULL;
}

/* The NIC's own pages back, and the queue its own again. */
static void bnxt_dmq_close_one(struct bnxt *bp, int i)
{
	struct bnxt_dmq *d = &bp->dmq[i];
	struct bnxt_tx_ring_info *txr;
	struct bnxt_rx_ring_info *rxr;
	int k;

	if (!d->q)
		return;
	for (k = 0; k < NET_DMQ_BNXT_RINGS; k++)
		bnxt_dmq_unswap(&d->rings[k]);
	rxr = &bp->rx_ring[i];
	txr = bp->bnapi[i]->tx_ring[0];
	rxr->dmq = false;
	rxr->rx_cpr->dmq = 0;
	if (txr)
		txr->tx_cpr->dmq = 0;
	d->q = NULL;
}

/* Queue @i's rings onto the ring buffer, where the binding says. */
static int bnxt_dmq_open_one(struct bnxt *bp, int i, struct net_devmem_queue *q)
{
	struct bnxt_rx_ring_info *rxr = &bp->rx_ring[i];
	struct bnxt_ring_mem_info *rmem[NET_DMQ_BNXT_RINGS];
	struct bnxt_dmq *d = &bp->dmq[i];
	struct net_dmq_layout lay = {};
	struct bnxt_tx_ring_info *txr;
	struct net_dmq_region r;
	struct iosys_map *map;
	u32 n, off = 0, k;
	dma_addr_t *pages;
	int err;

	txr = bp->bnapi[i]->tx_ring[0];
	if (!(bp->bnapi[i]->flags & BNXT_NAPI_FLAG_XDP) || !txr) {
		netdev_warn(bp->dev, "dmq: q%d has no XDP TX ring\n", i);
		return -EINVAL;
	}
	rmem[NET_DMQ_BNXT_RQ] = &rxr->rx_ring_struct.ring_mem;
	rmem[NET_DMQ_BNXT_RX_CQ] = &rxr->rx_cpr->cp_ring_struct.ring_mem;
	rmem[NET_DMQ_BNXT_SQ] = &txr->tx_ring_struct.ring_mem;
	rmem[NET_DMQ_BNXT_TX_CQ] = &txr->tx_cpr->cp_ring_struct.ring_mem;

	pages = bnxt_dmq_pages(net_dmq_rings_sgt(q), &n);
	if (!pages)
		return -ENOMEM;
	bnxt_dmq_sizes(bp, &lay);
	d->q = q;
	for (k = 0; k < NET_DMQ_BNXT_RINGS; k++) {
		if (!net_dmq_region(q, k, &r)) {
			r.offset = off;
			r.bytes = PAGE_ALIGN(lay.ring[k].bytes);
		}
		err = -EINVAL;
		if (!PAGE_ALIGNED(r.offset) ||
		    (r.offset >> PAGE_SHIFT) + (r.bytes >> PAGE_SHIFT) > n) {
			netdev_warn(bp->dev, "dmq: q%d ring %u at %u+%u past the ring buffer\n",
				    i, k, r.offset, r.bytes);
			goto err;
		}
		err = bnxt_dmq_swap(&d->rings[k], rmem[k], pages,
				    r.offset >> PAGE_SHIFT, r.bytes);
		if (err) {
			netdev_warn(bp->dev, "dmq: q%d ring %u needs %d pages, has %u bytes: %d\n",
				    i, k, rmem[k]->nr_pages, r.bytes, err);
			goto err;
		}
		d->off[k] = r.offset;
		off = max(off, r.offset + r.bytes);
	}

	/* What a new CQ holds: no entry valid on the first pass. */
	map = net_dmq_rings_map(q);
	iosys_map_memset(map, d->off[NET_DMQ_BNXT_RX_CQ], 0,
			 (size_t)rmem[NET_DMQ_BNXT_RX_CQ]->nr_pages * PAGE_SIZE);
	iosys_map_memset(map, d->off[NET_DMQ_BNXT_TX_CQ], 0,
			 (size_t)rmem[NET_DMQ_BNXT_TX_CQ]->nr_pages * PAGE_SIZE);
	/* In memory before the NIC is told the CQs are there. */
	wmb();

	rxr->dmq = true;
	rxr->rx_cpr->dmq = 1;
	txr->tx_cpr->dmq = 1;
	kvfree(pages);
	return 0;

err:
	kvfree(pages);
	bnxt_dmq_close_one(bp, i);
	return err;
}

/* After the rings are allocated, before the NIC is told where they are. */
int bnxt_dmq_rings(struct bnxt *bp)
{
	struct net_devmem_queue *q;
	int i, err;

	for (i = 0; i < bp->rx_nr_rings && i < bp->dmq_nr; i++) {
		q = netif_rxq_dmq(bp->dev, i);
		if (!q)
			continue;
		err = bnxt_dmq_open_one(bp, i, q);
		if (err)
			return err;
	}
	return 0;
}

/* The NIC's own pages back before they are freed. */
void bnxt_dmq_unrings(struct bnxt *bp)
{
	int i;

	for (i = 0; i < bp->dmq_nr; i++)
		bnxt_dmq_close_one(bp, i);
}

/* The queue is up in the ring buffer: what the device needs to run it. */
static void bnxt_dmq_built(struct bnxt *bp, int i, phys_addr_t db)
{
	struct bnxt_tx_ring_info *txr = bp->bnapi[i]->tx_ring[0];
	struct bnxt_rx_ring_info *rxr = &bp->rx_ring[i];
	struct bnxt_dmq *d = &bp->dmq[i];
	struct net_dmq_info info = {};
	struct net_dmq_bnxt *b;
	int k;

	info.fmt = bp->flags & BNXT_FLAG_CHIP_P7 ? NET_DMQ_FMT_BNXT_P7 :
						    NET_DMQ_FMT_BNXT_P5;
	info.nr_rings = NET_DMQ_BNXT_RINGS;
	for (k = 0; k < NET_DMQ_BNXT_RINGS; k++)
		info.ring[k].offset = d->off[k];
	info.ring[NET_DMQ_BNXT_RQ].entries = bp->rx_ring_mask + 1;
	info.ring[NET_DMQ_BNXT_RQ].stride = sizeof(struct rx_bd);
	info.ring[NET_DMQ_BNXT_RX_CQ].entries = bp->cp_ring_mask + 1;
	info.ring[NET_DMQ_BNXT_RX_CQ].stride = sizeof(struct tx_cmp);
	info.ring[NET_DMQ_BNXT_SQ].entries = bp->tx_ring_mask + 1;
	info.ring[NET_DMQ_BNXT_SQ].stride = sizeof(struct tx_bd);
	info.ring[NET_DMQ_BNXT_TX_CQ].entries = bp->cp_ring_mask + 1;
	info.ring[NET_DMQ_BNXT_TX_CQ].stride = sizeof(struct tx_cmp);
	info.nr_doorbells = 1;
	info.doorbell[0].phys = db;
	info.doorbell[0].width = 8;

	BUILD_BUG_ON(sizeof(*b) > NET_DMQ_FMT_PRIV_LEN);
	b = (struct net_dmq_bnxt *)info.fmt_priv;
	b->db_key[NET_DMQ_BNXT_RQ] = rxr->rx_db.db_key64;
	b->db_key[NET_DMQ_BNXT_RX_CQ] = rxr->rx_cpr->cp_db.db_key64 |
					DBR_TYPE_CQ;
	b->db_key[NET_DMQ_BNXT_SQ] = txr->tx_db.db_key64;
	b->db_key[NET_DMQ_BNXT_TX_CQ] = txr->tx_cpr->cp_db.db_key64 |
					DBR_TYPE_CQ;
	b->rq_posted = rounddown_pow_of_two(bp->rx_ring_size);
	b->frag_size = bp->rx_buf_use_size;
	b->headroom = XDP_PACKET_HEADROOM;
	b->frame_size = XDP_PACKET_HEADROOM + bp->rx_buf_use_size;

	net_dmq_built(d->q, &info);
	netdev_info(bp->dev, "dmq: q%d RX %u/%u CQ %u TX %u, ids %u/%u/%u/%u\n",
		    i, b->rq_posted, bp->rx_ring_mask + 1, bp->cp_ring_mask + 1,
		    bp->tx_ring_mask + 1, rxr->rx_ring_struct.fw_ring_id,
		    rxr->rx_cpr->cp_ring_struct.fw_ring_id,
		    txr->tx_ring_struct.fw_ring_id,
		    txr->tx_cpr->cp_ring_struct.fw_ring_id);
}

/* The NIC is up on the rings it just built: the device onto them. */
void bnxt_dmq_open(struct bnxt *bp)
{
	phys_addr_t db;
	int i;

	if (!bp->dmq)
		return;
	db = pci_resource_start(bp->pdev, 2) + bp->db_offset;
	for (i = 0; i < bp->dmq_nr; i++) {
		if (!bp->dmq[i].q)
			continue;
		bnxt_dmq_built(bp, i, db);
		net_dmq_publish(bp->dmq[i].q);
	}
}

/* Before the rings go: the device off them. */
void bnxt_dmq_close(struct bnxt *bp)
{
	int i;

	if (!bp->dmq)
		return;
	for (i = 0; i < bp->dmq_nr; i++)
		if (bp->dmq[i].q)
			net_dmq_quiesce(bp->dmq[i].q);
}
