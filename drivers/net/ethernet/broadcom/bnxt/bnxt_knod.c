// SPDX-License-Identifier: GPL-2.0-only
/*
 * knod: the accel runs a queue's rings itself (GDA).  Each queue's RX ring and
 * its CQ, and its XDP TX ring and that one's CQ, are built on accel memory:
 * the accel posts to the rings, polls the CQs and rings their doorbells, and
 * the host never does.  The CQs are never armed, so the queue's NAPI runs
 * only when knod kicks it to hand packets the accel passed to the stack.
 *
 * P5 and P7: every ring of the function rings at the one doorbell register,
 * and each ring has a CQ of its own.
 */

#include <linux/dma-buf.h>
#include <linux/pci.h>
#include <net/knod.h>
#include <net/netdev_lock.h>
#include <net/xdp.h>
#include <linux/bnxt/hsi.h>

#include "bnxt.h"
#include "bnxt_knod.h"

enum {
	BNXT_KNOD_RX,
	BNXT_KNOD_RX_CQ,
	BNXT_KNOD_TX,
	BNXT_KNOD_TX_CQ,
	BNXT_KNOD_RINGS,
};

/* A ring on accel memory, and the NIC's addresses of the pages it was
 * allocated with, to put back before they are freed.
 */
struct bnxt_knod_ring {
	struct bnxt_ring_mem_info *rmem;
	dma_addr_t *host;
};

/* A queue whose rings the accel runs. */
struct bnxt_knod_gda {
	struct dma_buf *ring_buf;	/* RX ring, its CQ, the TX CQ */
	struct dma_buf *sq_buf;		/* the TX ring */
	struct knod_nic_map ring_map;
	struct knod_nic_map sq_map;
	struct bnxt_knod_ring rings[BNXT_KNOD_RINGS];
	/* Marked as the accel's while they are. */
	struct bnxt_rx_ring_info *rxr;
	struct bnxt_cp_ring_info *rx_cpr;
	struct bnxt_cp_ring_info *tx_cpr;
};

/* The NIC's address of each of the first @n pages @map maps. */
static int bnxt_knod_pages(struct knod_nic_map *map, dma_addr_t *dma, u32 n)
{
	struct scatterlist *sg;
	unsigned int off;
	u32 i = 0;
	int sgi;

	for_each_sgtable_dma_sg(map->sgt, sg, sgi) {
		for (off = 0; off + PAGE_SIZE <= sg_dma_len(sg) && i < n;
		     off += PAGE_SIZE, i++)
			dma[i] = sg_dma_address(sg) + off;
		if (i == n)
			return 0;
	}
	return -EIO;
}

static void bnxt_knod_set_page(struct bnxt_ring_mem_info *rmem, int i,
			       dma_addr_t dma)
{
	rmem->dma_arr[i] = dma;
	/* The page table entry keeps its flags: valid, last, next to last. */
	if (rmem->pg_tbl)
		rmem->pg_tbl[i] = cpu_to_le64(dma |
			(le64_to_cpu(rmem->pg_tbl[i]) & ~PAGE_MASK));
}

/* Point @rmem's pages at @bytes of accel memory from @dma, before the NIC is
 * told where the ring is.
 */
static int bnxt_knod_swap(struct bnxt_knod_ring *r,
			  struct bnxt_ring_mem_info *rmem,
			  const dma_addr_t *dma, u32 bytes)
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
		bnxt_knod_set_page(rmem, i, dma[i]);
	}
	r->rmem = rmem;
	return 0;
}

static void bnxt_knod_unswap(struct bnxt_knod_ring *r)
{
	int i;

	if (!r->rmem)
		return;
	for (i = 0; i < r->rmem->nr_pages; i++)
		bnxt_knod_set_page(r->rmem, i, r->host[i]);
	kfree(r->host);
	r->host = NULL;
	r->rmem = NULL;
}

static void bnxt_knod_gda_close(struct bnxt *bp, int i)
{
	struct bnxt_knod_gda *g = &bp->knod_gda[i];
	int k;

	for (k = 0; k < BNXT_KNOD_RINGS; k++)
		bnxt_knod_unswap(&g->rings[k]);
	if (g->sq_buf)
		knod_nic_unmap_dmabuf(g->sq_buf, &g->sq_map);
	if (g->ring_buf)
		knod_nic_unmap_dmabuf(g->ring_buf, &g->ring_map);
	g->sq_buf = NULL;
	g->ring_buf = NULL;

	if (g->rxr) {
		g->rxr->knod_gda = false;
		g->rx_cpr->knod_gda = 0;
		g->tx_cpr->knod_gda = 0;
		g->rxr = NULL;
	}
}

/* Queue @i's rings onto the accel's buffers, if it offers them. */
static int bnxt_knod_gda_open(struct bnxt *bp, int i)
{
	struct knod_work_priv *wpriv = &bp->knodev->wpriv[i];
	struct bnxt_rx_ring_info *rxr = &bp->rx_ring[i];
	struct bnxt_knod_gda *g = &bp->knod_gda[i];
	struct dma_buf *ring_buf, *sq_buf;
	struct bnxt_tx_ring_info *txr;
	u32 nr = KNOD_GDA_BYTES >> PAGE_SHIFT;
	dma_addr_t *dma;
	void *kaddr;
	int rc;

	ring_buf = READ_ONCE(wpriv->gda_rx_dmabuf);
	kaddr = READ_ONCE(wpriv->gda_rx_kaddr);
	sq_buf = READ_ONCE(wpriv->tx_sq_dmabuf);
	/* Not built yet: the accel builds them and the queues open again. */
	if (!ring_buf || !kaddr || !sq_buf)
		return 0;

	txr = bp->bnapi[i]->tx_ring[0];
	if (!(bp->bnapi[i]->flags & BNXT_NAPI_FLAG_XDP) || !txr ||
	    ring_buf->size < KNOD_GDA_BYTES) {
		netdev_warn(bp->dev, "knod: q%d has no XDP TX ring or too small a ring buffer\n",
			    i);
		return -EINVAL;
	}

	dma = kvcalloc(max_t(u32, nr, sq_buf->size >> PAGE_SHIFT),
		       sizeof(*dma), GFP_KERNEL);
	if (!dma)
		return -ENOMEM;

	rc = knod_nic_map_dmabuf(ring_buf, &bp->pdev->dev, &g->ring_map);
	if (rc)
		goto out;
	g->ring_buf = ring_buf;
	rc = bnxt_knod_pages(&g->ring_map, dma, nr);
	if (rc)
		goto out;
	rc = bnxt_knod_swap(&g->rings[BNXT_KNOD_RX],
			    &rxr->rx_ring_struct.ring_mem,
			    dma + (KNOD_GDA_RQ_OFF >> PAGE_SHIFT),
			    KNOD_GDA_RQ_BYTES);
	if (rc)
		goto out;
	rc = bnxt_knod_swap(&g->rings[BNXT_KNOD_RX_CQ],
			    &rxr->rx_cpr->cp_ring_struct.ring_mem,
			    dma + (KNOD_GDA_CQ_OFF >> PAGE_SHIFT),
			    KNOD_GDA_CQ_BYTES);
	if (rc)
		goto out;
	rc = bnxt_knod_swap(&g->rings[BNXT_KNOD_TX_CQ],
			    &txr->tx_cpr->cp_ring_struct.ring_mem,
			    dma + (KNOD_GDA_TX_CQ_OFF >> PAGE_SHIFT),
			    KNOD_GDA_TX_CQ_BYTES);
	if (rc)
		goto out;

	nr = sq_buf->size >> PAGE_SHIFT;
	rc = knod_nic_map_dmabuf(sq_buf, &bp->pdev->dev, &g->sq_map);
	if (rc)
		goto out;
	g->sq_buf = sq_buf;
	rc = bnxt_knod_pages(&g->sq_map, dma, nr);
	if (rc)
		goto out;
	rc = bnxt_knod_swap(&g->rings[BNXT_KNOD_TX],
			    &txr->tx_ring_struct.ring_mem, dma, sq_buf->size);
	if (rc)
		goto out;

	/* What a new CQ holds: no entry valid on the first pass. */
	memset(kaddr + KNOD_GDA_CQ_OFF, 0,
	       (size_t)bp->cp_nr_pages * PAGE_SIZE);
	memset(kaddr + KNOD_GDA_TX_CQ_OFF, 0,
	       (size_t)bp->cp_nr_pages * PAGE_SIZE);
	/* In memory before the NIC is told the CQs are there. */
	wmb();

	rxr->knod_gda = true;
	rxr->rx_cpr->knod_gda = 1;
	txr->tx_cpr->knod_gda = 1;
	g->rxr = rxr;
	g->rx_cpr = rxr->rx_cpr;
	g->tx_cpr = txr->tx_cpr;
out:
	kvfree(dma);
	if (rc)
		netdev_warn(bp->dev, "knod: q%d rings not on accel memory: %d\n",
			    i, rc);
	return rc;
}

/* After the rings are allocated, before the NIC is told where they are. */
int bnxt_knod_rings(struct bnxt *bp)
{
	int i, rc;

	if (!bp->knodev)
		return 0;

	for (i = 0; i < bp->rx_nr_rings && i < KNOD_SPSC_MAX; i++) {
		rc = bnxt_knod_gda_open(bp, i);
		if (rc)
			return rc;
	}
	return 0;
}

/* The NIC's own pages back before they are freed. */
void bnxt_knod_unrings(struct bnxt *bp)
{
	int i;

	if (!bp->knod_gda)
		return;

	for (i = 0; i < KNOD_SPSC_MAX; i++)
		bnxt_knod_gda_close(bp, i);
}

/* What the accel needs to run queue @i's rings, live last. */
static void bnxt_knod_publish(struct bnxt *bp, int i, phys_addr_t db)
{
	struct knod_work_priv *wpriv = &bp->knodev->wpriv[i];
	struct bnxt_tx_ring_info *txr = bp->bnapi[i]->tx_ring[0];
	struct bnxt_rx_ring_info *rxr = &bp->rx_ring[i];
	u32 headroom = XDP_PACKET_HEADROOM;
	u32 cq_log = ilog2(bp->cp_ring_mask + 1);

	WRITE_ONCE(wpriv->rx_bounds,
		   knod_rx_bounds_encode(headroom,
					 headroom + bp->rx_buf_use_size));
	WRITE_ONCE(wpriv->tx_db_phys, db);
	/* Half the ring or less, a power of two: the rest is how the NIC
	 * tells a full ring from an empty one.
	 */
	WRITE_ONCE(wpriv->gda_rq_log_sz,
		   ilog2(rounddown_pow_of_two(bp->rx_ring_size)));
	WRITE_ONCE(wpriv->gda_rq_ring_log, ilog2(bp->rx_ring_mask + 1));
	WRITE_ONCE(wpriv->gda_rq_log_stride, ilog2(sizeof(struct rx_bd)));
	WRITE_ONCE(wpriv->gda_cq_log_sz, cq_log);
	WRITE_ONCE(wpriv->gda_frag_size, bp->rx_buf_use_size);
	WRITE_ONCE(wpriv->gda_headroom, headroom);
	WRITE_ONCE(wpriv->gda_mkey_be, 0);
	WRITE_ONCE(wpriv->gda_db_key[KNOD_GDA_DB_RQ], rxr->rx_db.db_key64);
	WRITE_ONCE(wpriv->gda_db_key[KNOD_GDA_DB_RX_CQ],
		   rxr->rx_cpr->cp_db.db_key64 | DBR_TYPE_CQ);
	WRITE_ONCE(wpriv->gda_db_key[KNOD_GDA_DB_SQ], txr->tx_db.db_key64);
	WRITE_ONCE(wpriv->gda_db_key[KNOD_GDA_DB_TX_CQ],
		   txr->tx_cpr->cp_db.db_key64 | DBR_TYPE_CQ);
	WRITE_ONCE(wpriv->tx_sq_mask, bp->tx_ring_mask);
	WRITE_ONCE(wpriv->tx_mkey_be, 0);
	WRITE_ONCE(wpriv->tx_sqn, txr->tx_ring_struct.fw_ring_id);
	WRITE_ONCE(wpriv->gda_tx_cq_log_sz, cq_log);
	/* A new build of the rings: what the accel carried over from the
	 * last one no longer applies.
	 */
	WRITE_ONCE(wpriv->gda_rx_gen, wpriv->gda_rx_gen + 1);
	WRITE_ONCE(wpriv->gda_tx_gen, wpriv->gda_tx_gen + 1);
	/* The rest before live; pairs with the accel's read after it. */
	smp_wmb();
	WRITE_ONCE(wpriv->gda_tx_live, 1);
	WRITE_ONCE(wpriv->gda_rx_live, 1);
	netdev_info(bp->dev, "knod: q%d rings on accel memory, RX %u/%u CQ %u TX %u, ids %u/%u/%u/%u gen %u\n",
		    i, 1U << READ_ONCE(wpriv->gda_rq_log_sz),
		    bp->rx_ring_mask + 1, bp->cp_ring_mask + 1,
		    bp->tx_ring_mask + 1, rxr->rx_ring_struct.fw_ring_id,
		    rxr->rx_cpr->cp_ring_struct.fw_ring_id,
		    txr->tx_ring_struct.fw_ring_id,
		    txr->tx_cpr->cp_ring_struct.fw_ring_id,
		    wpriv->gda_rx_gen);
}

/* Where queue @i's interrupt is set to run, which no interrupt of the accel's
 * rings comes to: knod kicks the queue's NAPI there to hand packets the accel
 * passed to the stack.
 */
void bnxt_knod_irq_moved(struct bnxt *bp, int i, const struct cpumask *mask)
{
	struct knod_dev *knodev = READ_ONCE(bp->knodev);
	unsigned int cpu;

	if (!knodev || i >= KNOD_SPSC_MAX || i >= bp->rx_nr_rings)
		return;
	cpu = cpumask_first_and(mask, cpu_online_mask);
	WRITE_ONCE(knodev->wpriv[i].napi_cpu, cpu < nr_cpu_ids ? cpu : -1);
}

/* The NIC is up on the rings it just built: the accel onto them. */
void bnxt_knod_open(struct bnxt *bp)
{
	struct knod_dev *knodev = bp->knodev;
	phys_addr_t db;
	int i;

	if (!knodev)
		return;

	db = pci_resource_start(bp->pdev, 2) + bp->db_offset;
	for (i = 0; i < bp->rx_nr_rings && i < KNOD_SPSC_MAX; i++) {
		WRITE_ONCE(knodev->wpriv[i].napi_cpu, -1);
		if (bp->ring_cpu_mask)
			bnxt_knod_irq_moved(bp, i, bp->ring_cpu_mask[i]);
		WRITE_ONCE(knodev->wpriv[i].napi, &bp->bnapi[i]->napi);
		if (bp->rx_ring[i].knod_gda)
			bnxt_knod_publish(bp, i, db);
	}
	knod_dev_start(knodev);
}

/* Before the rings go: the accel off them, and the copies to the stack that
 * still hold RX pages landed, while the page pools are still there.
 */
void bnxt_knod_close(struct bnxt *bp)
{
	struct knod_dev *knodev = bp->knodev;
	struct knod_work_priv *wpriv;
	int i;

	if (!knodev)
		return;

	knod_dev_stop(knodev);
	for (i = 0; i < KNOD_SPSC_MAX; i++) {
		wpriv = &knodev->wpriv[i];
		WRITE_ONCE(wpriv->gda_rx_live, 0);
		WRITE_ONCE(wpriv->gda_tx_live, 0);
		WRITE_ONCE(wpriv->tx_sqn, 0);
		WRITE_ONCE(wpriv->tx_db_phys, 0);
		WRITE_ONCE(wpriv->rx_bounds, 0);
		WRITE_ONCE(wpriv->napi, NULL);
	}
	/* With wpriv[].napi cleared no poll runs the drain any more. */
	synchronize_net();
	knod_dev_flush_pass(knodev);
}

/* NAPI: what the accel passed to the stack, kicked here by knod. */
int bnxt_knod_drain(struct bnxt *bp, struct bnxt_napi *bnapi, int budget)
{
	struct knod_dev *knodev = READ_ONCE(bp->knodev);
	struct napi_struct *napi;

	if (!knodev || bnapi->index >= KNOD_SPSC_MAX)
		return 0;
	napi = READ_ONCE(knodev->wpriv[bnapi->index].napi);
	if (!napi)
		return 0;
	return knod_dev_xdp_drain_pass(knodev, napi, bnapi->index, budget);
}

/* Only as many queues as the accel built rings for. */
int bnxt_knod_check_channels(struct bnxt *bp, int rx)
{
	if (!bp->knodev)
		return 0;
	if (rx > KNOD_SPSC_MAX ||
	    !READ_ONCE(bp->knodev->wpriv[rx - 1].gda_rx_dmabuf)) {
		netdev_warn(bp->dev, "knod offload runs no more queues than it was set up with\n");
		return -EINVAL;
	}
	return 0;
}

/* The rings knod runs: an XDP TX ring for every RX ring, and one page per
 * packet with no aggregation ring.
 */
static void bnxt_knod_mode(struct bnxt *bp, bool on)
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

static int bnxt_knod_attach(struct knod_dev *knodev)
{
	struct bnxt *bp = netdev_priv(knodev->netdev);
	struct net_device *dev = bp->dev;
	int tc = bp->num_tc ?: 1;
	int rc;

	netdev_assert_locked(dev);
	/* Up, the queues would open onto an accel not attached yet. */
	if (netif_running(dev)) {
		netdev_warn(dev, "knod offload attaches to a device that is down\n");
		return -EBUSY;
	}

	if (!(bp->flags & BNXT_FLAG_CHIP_P5_PLUS) ||
	    BNXT_PAGE_SIZE != PAGE_SIZE) {
		netdev_warn(dev, "knod offload runs only on P5 and P7 rings\n");
		return -EOPNOTSUPP;
	}
	if (bp->xdp_prog) {
		netdev_warn(dev, "knod offload does not run with an XDP program\n");
		return -EOPNOTSUPP;
	}
	if (bp->flags & BNXT_FLAG_HDS) {
		netdev_warn(dev, "knod offload does not run with header-data split\n");
		return -EOPNOTSUPP;
	}
	if (!(bp->flags & BNXT_FLAG_SHARED_RINGS)) {
		netdev_warn(dev, "knod offload needs combined channels\n");
		return -EOPNOTSUPP;
	}
	if (bp->rx_nr_rings > KNOD_SPSC_MAX) {
		netdev_warn(dev, "knod offload supports up to %d channels\n",
			    KNOD_SPSC_MAX);
		return -EOPNOTSUPP;
	}
	if (dev->mtu > BNXT_MAX_PAGE_MODE_MTU) {
		netdev_warn(dev, "MTU %u too big for single-page RX offload (max %d)\n",
			    dev->mtu, BNXT_MAX_PAGE_MODE_MTU);
		return -EOPNOTSUPP;
	}
	rc = bnxt_check_rings(bp, bp->tx_nr_rings_per_tc, bp->rx_nr_rings,
			      true, tc, bp->rx_nr_rings);
	if (rc) {
		netdev_warn(dev, "knod offload: not enough rings for an XDP TX ring per queue\n");
		return rc;
	}

	bp->knod_gda = kcalloc(KNOD_SPSC_MAX, sizeof(*bp->knod_gda),
			       GFP_KERNEL);
	if (!bp->knod_gda)
		return -ENOMEM;

	WRITE_ONCE(bp->knodev, knodev);
	bnxt_knod_mode(bp, true);
	return 0;
}

static int bnxt_knod_detach(struct knod_dev *knodev)
{
	struct bnxt *bp = netdev_priv(knodev->netdev);
	bool running = netif_running(bp->dev);

	if (running)
		bnxt_close_nic(bp, true, false);
	WRITE_ONCE(bp->knodev, NULL);
	bnxt_knod_mode(bp, false);
	kfree(bp->knod_gda);
	bp->knod_gda = NULL;
	if (running)
		bnxt_open_nic(bp, true, false);
	return 0;
}

static struct knod_nic_ops bnxt_knod_nic_ops = {
	.attach = bnxt_knod_attach,
	.detach = bnxt_knod_detach,
};

int bnxt_knod_xdp(struct bnxt *bp, struct netdev_bpf *xdp)
{
	if (!bp->knodev)
		return -EOPNOTSUPP;
	return knod_dev_xdp_install(bp->knodev, xdp);
}

int bnxt_knod_init(struct bnxt *bp)
{
	struct knod_netdev *knetdev;

	knetdev = kzalloc_obj(struct knod_netdev, GFP_KERNEL);
	if (!knetdev)
		return -ENOMEM;

	INIT_LIST_HEAD(&knetdev->list);
	knetdev->dev = bp->dev;
	knetdev->priv = bp;
	knetdev->nic_ops = &bnxt_knod_nic_ops;
	knetdev->owner = THIS_MODULE;
	knetdev->flags |= KNOD_FLAGS_XDP;
	/* The rings the accel's engine runs are P5's and P7's. */
	if (bp->flags & BNXT_FLAG_CHIP_P7)
		knetdev->gda_fmt = KNOD_GDA_FMT_BNXT_P7;
	else if (bp->flags & BNXT_FLAG_CHIP_P5_PLUS)
		knetdev->gda_fmt = KNOD_GDA_FMT_BNXT_P5;
	knod_netdev_register(knetdev);
	bp->knetdev = knetdev;
	return 0;
}

void bnxt_knod_uninit(struct bnxt *bp)
{
	if (!bp->knetdev)
		return;
	knod_netdev_unregister(bp->knetdev);
	kfree(bp->knetdev);
	bp->knetdev = NULL;
}
