// SPDX-License-Identifier: GPL-2.0-only
/*
 * knod: the accel runs a queue's rings itself (GDA).  Each queue's RX
 * descriptor ring, and an XDP TX ring of its own, are on the accel's buffers:
 * the queue contexts point there instead of at the rings the driver
 * allocated, the accel posts and reaps them and moves their tail registers,
 * and the host never does.  The RX queue's interrupt cause stays off, so the
 * queue's NAPI runs only when knod kicks it to hand packets the accel passed
 * to the stack.
 *
 * There is no page table: a ring is one stretch of bus addresses, which the
 * accel's buffer has to give it.
 */

#include <linux/dma-buf.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <net/knod.h>
#include <net/xdp.h>

#include "ice.h"
#include "ice_lib.h"
#include "ice_knod.h"

/* Where a packet starts in its page, as XDP has it. */
#define ICE_KNOD_HEADROOM	XDP_PACKET_HEADROOM

/* A queue whose rings the accel runs: its buffers, mapped for the NIC. */
struct ice_knod_gda {
	struct dma_buf *ring_buf;	/* the RX ring */
	struct dma_buf *sq_buf;		/* the TX ring */
	struct knod_nic_map ring_map;
	struct knod_nic_map sq_map;
};

/* The bus address of @len bytes at @off of @map, if they are one stretch. */
static int ice_knod_dma(struct knod_nic_map *map, u64 off, u64 len,
			dma_addr_t *dma)
{
	struct scatterlist *sg;
	bool started = false;
	dma_addr_t next = 0;
	u64 at = 0, l;
	int i;

	for_each_sgtable_dma_sg(map->sgt, sg, i) {
		l = sg_dma_len(sg);
		if (at + l <= off) {
			at += l;
			continue;
		}
		if (!started)
			*dma = sg_dma_address(sg) + off - at;
		else if (sg_dma_address(sg) != next)
			return -EIO;
		started = true;
		next = sg_dma_address(sg) + l;
		at += l;
		if (at >= off + len)
			return 0;
	}
	return -EIO;
}

/* What each RX buffer gives a packet: a frame of the MTU, in 128s. */
u16 ice_knod_rx_buf_len(struct ice_vsi *vsi)
{
	return ALIGN(vsi->netdev->mtu + ICE_ETH_PKT_HDR_PAD,
		     BIT(ICE_RLAN_CTX_DBUF_S));
}

static void ice_knod_gda_close(struct ice_knod_gda *g)
{
	if (g->sq_buf)
		knod_nic_unmap_dmabuf(g->sq_buf, &g->sq_map);
	if (g->ring_buf)
		knod_nic_unmap_dmabuf(g->ring_buf, &g->ring_map);
	g->sq_buf = NULL;
	g->ring_buf = NULL;
}

/* Queue @i's rings onto the accel's buffers, if it offers them. */
static int ice_knod_gda_open(struct ice_vsi *vsi, int i)
{
	struct knod_work_priv *wpriv = &vsi->knodev->wpriv[i];
	struct ice_rx_ring *rx = vsi->rx_rings[i];
	struct ice_knod_gda *g = &vsi->knod_gda[i];
	struct device *dev = ice_pf_to_dev(vsi->back);
	struct ice_tx_ring *tx;
	struct dma_buf *buf;
	dma_addr_t dma;
	int err;

	rx->knod_dma = 0;
	if (!vsi->xdp_rings || i >= vsi->num_xdp_txq)
		return 0;
	tx = vsi->xdp_rings[i];
	tx->knod_dma = 0;

	/* Not built yet: the accel builds them and the queues open again. */
	if (!READ_ONCE(wpriv->gda_rx_dmabuf) || !READ_ONCE(wpriv->gda_rx_kaddr) ||
	    !READ_ONCE(wpriv->tx_sq_dmabuf))
		return 0;

	if (!is_power_of_2(rx->count) || !is_power_of_2(tx->count) ||
	    (u64)rx->count * sizeof(union ice_32byte_rx_desc) >
	    KNOD_GDA_RQ_BYTES) {
		netdev_warn(vsi->netdev, "knod: q%d rings of %u and %u: the accel runs powers of two up to %zu\n",
			    i, rx->count, tx->count,
			    KNOD_GDA_RQ_BYTES / sizeof(union ice_32byte_rx_desc));
		return -EINVAL;
	}

	if (!g->ring_buf) {
		buf = READ_ONCE(wpriv->gda_rx_dmabuf);
		err = knod_nic_map_dmabuf(buf, dev, &g->ring_map);
		if (err)
			return err;
		g->ring_buf = buf;
	}
	if (!g->sq_buf) {
		buf = READ_ONCE(wpriv->tx_sq_dmabuf);
		err = knod_nic_map_dmabuf(buf, dev, &g->sq_map);
		if (err)
			return err;
		g->sq_buf = buf;
	}

	if ((u64)tx->count * sizeof(struct ice_tx_desc) > g->sq_buf->size ||
	    ice_knod_dma(&g->ring_map, KNOD_GDA_RQ_OFF,
			 rx->count * sizeof(union ice_32byte_rx_desc), &dma)) {
		netdev_warn(vsi->netdev, "knod: q%d accel buffers give no ring in one stretch\n",
			    i);
		return -EIO;
	}
	rx->knod_dma = dma;
	if (ice_knod_dma(&g->sq_map, 0, tx->count * sizeof(struct ice_tx_desc),
			 &dma)) {
		rx->knod_dma = 0;
		netdev_warn(vsi->netdev, "knod: q%d accel SQ buffer is not one stretch\n",
			    i);
		return -EIO;
	}
	tx->knod_dma = dma;
	return 0;
}

/* Before the queue contexts are written: where they point the rings. */
int ice_knod_rings(struct ice_vsi *vsi)
{
	int i, err;

	if (!vsi->knodev)
		return 0;

	ice_for_each_rxq(vsi, i) {
		if (i >= KNOD_SPSC_MAX)
			break;
		err = ice_knod_gda_open(vsi, i);
		if (err)
			return err;
	}
	return 0;
}

/* The rings gone: the accel's buffers let go. */
void ice_knod_unrings(struct ice_vsi *vsi)
{
	int i;

	if (!vsi->knod_gda)
		return;

	for (i = 0; i < KNOD_SPSC_MAX; i++)
		ice_knod_gda_close(&vsi->knod_gda[i]);
}

/* What the accel needs to run queue @i's rings, live last. */
static void ice_knod_publish(struct ice_vsi *vsi, int i, phys_addr_t bar)
{
	struct knod_work_priv *wpriv = &vsi->knodev->wpriv[i];
	struct ice_tx_ring *tx = vsi->xdp_rings[i];
	struct ice_rx_ring *rx = vsi->rx_rings[i];
	u32 buf_len = ice_knod_rx_buf_len(vsi);

	WRITE_ONCE(wpriv->rx_bounds,
		   knod_rx_bounds_encode(ICE_KNOD_HEADROOM,
					 ICE_KNOD_HEADROOM + buf_len));
	WRITE_ONCE(wpriv->tx_db_phys, bar + QTX_COMM_DBELL(tx->reg_idx));
	WRITE_ONCE(wpriv->rx_db_phys, bar + QRX_TAIL(vsi->rxq_map[i]));
	/* Half the ring: the rest is how the NIC tells a full ring from an
	 * empty one.
	 */
	WRITE_ONCE(wpriv->gda_rq_log_sz, ilog2(rx->count) - 1);
	WRITE_ONCE(wpriv->gda_rq_ring_log, ilog2(rx->count));
	WRITE_ONCE(wpriv->gda_rq_log_stride,
		   ilog2(sizeof(union ice_32byte_rx_desc)));
	WRITE_ONCE(wpriv->gda_cq_log_sz, ilog2(rx->count));
	WRITE_ONCE(wpriv->gda_frag_size, buf_len);
	WRITE_ONCE(wpriv->gda_headroom, ICE_KNOD_HEADROOM);
	WRITE_ONCE(wpriv->gda_mkey_be, 0);
	WRITE_ONCE(wpriv->tx_sq_mask, tx->count - 1);
	WRITE_ONCE(wpriv->tx_mkey_be, 0);
	WRITE_ONCE(wpriv->tx_sqn, tx->reg_idx);
	/* The accel's list of TX completions asked for: an SQ's worth. */
	WRITE_ONCE(wpriv->gda_tx_cq_log_sz, ilog2(tx->count));
	WRITE_ONCE(wpriv->gda_rx_gen, wpriv->gda_rx_gen + 1);
	WRITE_ONCE(wpriv->gda_tx_gen, wpriv->gda_tx_gen + 1);
	/* The rest before live; pairs with the accel's read after it. */
	smp_wmb();
	WRITE_ONCE(wpriv->gda_tx_live, 1);
	WRITE_ONCE(wpriv->gda_rx_live, 1);
	netdev_info(vsi->netdev, "knod: q%d rings on accel memory, RX %u of %u TX %u, queues %u/%u gen %u\n",
		    i, rx->count / 2, rx->count, tx->count, vsi->rxq_map[i],
		    tx->reg_idx, wpriv->gda_rx_gen);
}

/* Where queue @i's interrupt would run its NAPI: knod kicks it there. */
static int ice_knod_napi_cpu(struct ice_q_vector *q_vector)
{
	const struct cpumask *mask = irq_get_affinity_mask(q_vector->irq.virq);
	unsigned int cpu;

	if (!mask)
		return -1;
	cpu = cpumask_first_and(mask, cpu_online_mask);
	return cpu < nr_cpu_ids ? cpu : -1;
}

/* The queues are up on the rings just configured: the accel onto them. */
void ice_knod_open(struct ice_vsi *vsi)
{
	struct knod_dev *knodev = vsi->knodev;
	phys_addr_t bar;
	int i;

	if (!knodev)
		return;

	bar = pci_resource_start(vsi->back->pdev, 0);
	ice_for_each_rxq(vsi, i) {
		struct ice_rx_ring *rx = vsi->rx_rings[i];

		if (i >= KNOD_SPSC_MAX)
			break;
		WRITE_ONCE(knodev->wpriv[i].napi_cpu,
			   ice_knod_napi_cpu(rx->q_vector));
		WRITE_ONCE(knodev->wpriv[i].napi, &rx->q_vector->napi);
		if (rx->knod_dma && vsi->xdp_rings[i]->knod_dma)
			ice_knod_publish(vsi, i, bar);
	}
	knod_dev_start(knodev);
}

/* Before the queues stop: the accel off them, and the copies to the stack
 * that still hold RX pages landed.
 */
void ice_knod_close(struct ice_vsi *vsi)
{
	struct knod_dev *knodev = vsi->knodev;
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
		WRITE_ONCE(wpriv->rx_db_phys, 0);
		WRITE_ONCE(wpriv->rx_bounds, 0);
		WRITE_ONCE(wpriv->napi, NULL);
	}
	/* With wpriv[].napi cleared no poll runs the drain any more. */
	synchronize_net();
	knod_dev_flush_pass(knodev);
}

/* NAPI: what the accel passed to the stack, kicked here by knod. */
int ice_knod_drain(struct ice_q_vector *q_vector, int budget)
{
	struct knod_dev *knodev = READ_ONCE(q_vector->vsi->knodev);
	struct ice_rx_ring *rx;
	struct napi_struct *napi;
	int done = 0;

	if (!knodev)
		return 0;

	ice_for_each_rx_ring(rx, q_vector->rx) {
		if (rx->q_index >= KNOD_SPSC_MAX)
			continue;
		napi = READ_ONCE(knodev->wpriv[rx->q_index].napi);
		if (napi)
			done += knod_dev_xdp_drain_pass(knodev, napi,
							rx->q_index, budget);
	}
	return done;
}

/* Only as many queues as the accel built rings for. */
int ice_knod_check_channels(struct ice_vsi *vsi, int rx)
{
	if (!vsi->knodev)
		return 0;
	if (rx > KNOD_SPSC_MAX ||
	    !READ_ONCE(vsi->knodev->wpriv[rx - 1].gda_rx_dmabuf)) {
		netdev_warn(vsi->netdev, "knod offload runs no more queues than it was set up with\n");
		return -EINVAL;
	}
	return 0;
}

/* A frame of the MTU in one page, past the headroom. */
int ice_knod_check_mtu(struct ice_vsi *vsi, int mtu)
{
	if (!vsi->knodev)
		return 0;
	if (ICE_KNOD_HEADROOM +
	    ALIGN(mtu + ICE_ETH_PKT_HDR_PAD, BIT(ICE_RLAN_CTX_DBUF_S)) >
	    PAGE_SIZE) {
		netdev_warn(vsi->netdev, "knod offload: MTU %d does not fit a page\n",
			    mtu);
		return -EINVAL;
	}
	return 0;
}

static int ice_knod_attach(struct knod_dev *knodev)
{
	struct ice_netdev_priv *np = netdev_priv(knodev->netdev);
	struct ice_vsi *vsi = np->vsi;
	struct net_device *dev = vsi->netdev;
	int err;

	/* Up, the queues would open onto an accel not attached yet. */
	if (netif_running(dev)) {
		netdev_warn(dev, "knod offload attaches to a device that is down\n");
		return -EBUSY;
	}
	if (vsi->type != ICE_VSI_PF || PAGE_SIZE != SZ_4K) {
		netdev_warn(dev, "knod offload runs on the PF's queues, with 4K pages\n");
		return -EOPNOTSUPP;
	}
	if (vsi->num_rxq > KNOD_SPSC_MAX) {
		netdev_warn(dev, "knod offload supports up to %d channels\n",
			    KNOD_SPSC_MAX);
		return -EOPNOTSUPP;
	}
	if (vsi->hsplit) {
		netdev_warn(dev, "knod offload does not run with header-data split\n");
		return -EOPNOTSUPP;
	}

	mutex_lock(&vsi->xdp_state_lock);
	if (ice_is_xdp_ena_vsi(vsi) || vsi->xdp_rings) {
		netdev_warn(dev, "knod offload does not run with an XDP program\n");
		err = -EOPNOTSUPP;
		goto out;
	}
	if (ice_get_avail_txq_count(vsi->back) < vsi->num_rxq) {
		netdev_warn(dev, "knod offload: not enough TX queues for one per channel\n");
		err = -ENOSPC;
		goto out;
	}

	vsi->knod_gda = kzalloc_objs(*vsi->knod_gda, KNOD_SPSC_MAX);
	if (!vsi->knod_gda) {
		err = -ENOMEM;
		goto out;
	}
	WRITE_ONCE(vsi->knodev, knodev);
	err = ice_knod_check_mtu(vsi, dev->mtu);
	if (!err) {
		/* An XDP TX ring for every RX queue, with no program. */
		vsi->num_xdp_txq = vsi->num_rxq;
		err = ice_prepare_xdp_rings(vsi, NULL, ICE_XDP_CFG_FULL);
	}
	if (err) {
		vsi->num_xdp_txq = 0;
		WRITE_ONCE(vsi->knodev, NULL);
		kfree(vsi->knod_gda);
		vsi->knod_gda = NULL;
	}
out:
	mutex_unlock(&vsi->xdp_state_lock);
	return err;
}

static int ice_knod_detach(struct knod_dev *knodev)
{
	struct ice_netdev_priv *np = netdev_priv(knodev->netdev);
	struct ice_vsi *vsi = np->vsi;

	mutex_lock(&vsi->xdp_state_lock);
	if (vsi->xdp_rings)
		ice_destroy_xdp_rings(vsi, ICE_XDP_CFG_FULL);
	WRITE_ONCE(vsi->knodev, NULL);
	ice_knod_unrings(vsi);
	kfree(vsi->knod_gda);
	vsi->knod_gda = NULL;
	mutex_unlock(&vsi->xdp_state_lock);
	return 0;
}

static struct knod_nic_ops ice_knod_nic_ops = {
	.attach = ice_knod_attach,
	.detach = ice_knod_detach,
};

int ice_knod_xdp(struct ice_vsi *vsi, struct netdev_bpf *xdp)
{
	if (!vsi->knodev)
		return -EOPNOTSUPP;
	return knod_dev_xdp_install(vsi->knodev, xdp);
}

int ice_knod_init(struct ice_vsi *vsi)
{
	struct knod_netdev *knetdev;

	knetdev = kzalloc_obj(struct knod_netdev, GFP_KERNEL);
	if (!knetdev)
		return -ENOMEM;

	INIT_LIST_HEAD(&knetdev->list);
	knetdev->dev = vsi->netdev;
	knetdev->priv = vsi;
	knetdev->nic_ops = &ice_knod_nic_ops;
	knetdev->owner = THIS_MODULE;
	knetdev->flags |= KNOD_FLAGS_XDP;
	knetdev->gda_fmt = KNOD_GDA_FMT_ICE_E810;
	knod_netdev_register(knetdev);
	vsi->knetdev = knetdev;
	return 0;
}

void ice_knod_uninit(struct ice_vsi *vsi)
{
	if (!vsi->knetdev)
		return;
	knod_netdev_unregister(vsi->knetdev);
	kfree(vsi->knetdev);
	vsi->knetdev = NULL;
}
