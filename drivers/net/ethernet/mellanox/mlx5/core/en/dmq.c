// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * Device memory queue ownership on mlx5: a channel whose RQ, XDP SQ and their
 * CQs another device runs.  The queues are built the usual way, then pointed,
 * pages and doorbell records, at that device's ring buffer before the NIC is
 * told where they are; the host never posts, polls or arms them.
 *
 * They go in a PD of the binding's own, whose only keys are one per channel
 * over that channel's data buffer: whatever a descriptor says, the NIC goes
 * nowhere else.  And the SQs ring through a UAR of the binding's own.  The
 * user is kernel code; this keeps a bug in it from reaching other memory.
 */

#include <linux/dma-buf.h>
#include <linux/mlx5/doorbell.h>
#include "en/dmq.h"
#include "en/params.h"

struct mlx5e_dmq_binding {
	u32 pdn;
};

/* What each ring takes, as the channel's params build it.  Only a plain
 * cyclic RQ with one page a packet, and 64-byte CQEs: what a device that
 * reads the format can run.
 */
static int mlx5e_dmq_sizes(struct mlx5e_params *params,
			   struct mlx5e_channel_param *cp,
			   struct net_dmq_layout *lay,
			   struct netlink_ext_ack *extack)
{
	void *rqwq = MLX5_ADDR_OF(rqc, cp->rq.rqc, wq);
	void *sqwq = MLX5_ADDR_OF(sqc, cp->xdp_sq.sqc, wq);
	u32 rq_log = MLX5_GET(wq, rqwq, log_wq_sz);
	u32 rq_stride = MLX5_GET(wq, rqwq, log_wq_stride);
	u32 cq_log = MLX5_GET(cqc, cp->rq.cqp.cqc, log_cq_size);
	u32 sq_log = MLX5_GET(wq, sqwq, log_wq_sz);
	u32 tx_cq_log = MLX5_GET(cqc, cp->xdp_sq.cqp.cqc, log_cq_size);

	if (params->rq_wq_type != MLX5_WQ_TYPE_CYCLIC) {
		NL_SET_ERR_MSG(extack, "needs the legacy RQ: turn off rx_striding_rq");
		return -EOPNOTSUPP;
	}
	if (params->tx_min_inline_mode != MLX5_INLINE_MODE_NONE) {
		NL_SET_ERR_MSG(extack, "the NIC wants headers inlined in sends");
		return -EOPNOTSUPP;
	}
	if (cp->rq.frags_info.num_frags != 1) {
		NL_SET_ERR_MSG(extack, "MTU too big for one page a packet");
		return -EOPNOTSUPP;
	}
	if (MLX5_GET(cqc, cp->rq.cqp.cqc, cqe_sz) ||
	    MLX5_GET(cqc, cp->xdp_sq.cqp.cqc, cqe_sz)) {
		NL_SET_ERR_MSG(extack, "needs 64-byte CQEs");
		return -EOPNOTSUPP;
	}

	lay->fmt = NET_DMQ_FMT_MLX5_CX5;
	lay->nr_rings = NET_DMQ_MLX5_RINGS;
	lay->ring[NET_DMQ_MLX5_RQ].bytes = 1U << (rq_log + rq_stride);
	lay->ring[NET_DMQ_MLX5_RQ].max_posted = 1U << rq_log;
	lay->ring[NET_DMQ_MLX5_RX_CQ].bytes = 64U << cq_log;
	lay->ring[NET_DMQ_MLX5_SQ].bytes = MLX5_SEND_WQE_BB << sq_log;
	lay->ring[NET_DMQ_MLX5_SQ].max_posted = 1U << sq_log;
	lay->ring[NET_DMQ_MLX5_TX_CQ].bytes = 64U << tx_cq_log;
	lay->ring[NET_DMQ_MLX5_DBR].bytes = PAGE_SIZE;
	for (int i = 0; i < NET_DMQ_MLX5_RINGS; i++) {
		lay->ring[i].bytes = PAGE_ALIGN(lay->ring[i].bytes);
		lay->ring[i].align = PAGE_SIZE;
	}
	return 0;
}

int mlx5e_dmq_query(struct net_device *dev, int idx,
		    const struct netdev_queue_config *qcfg,
		    struct net_dmq_layout *layout,
		    struct netlink_ext_ack *extack)
{
	struct mlx5e_priv *priv = netdev_priv(dev);
	struct netdev_queue_config cfg = *qcfg;
	struct mlx5e_channel_param *cp;
	struct mlx5e_params params;
	int err;

	cp = kvzalloc_obj(*cp);
	if (!cp)
		return -ENOMEM;
	mutex_lock(&priv->state_lock);
	params = priv->channels.params;
	mutex_unlock(&priv->state_lock);
	err = mlx5e_build_channel_param(priv->mdev, &params, &cfg, cp);
	if (!err)
		err = mlx5e_dmq_sizes(&params, cp, layout, extack);
	kvfree(cp);
	return err;
}

int mlx5e_dmq_binding_init(struct net_device *dev,
			   struct net_devmem_queue_binding *binding,
			   struct netlink_ext_ack *extack)
{
	struct mlx5e_priv *priv = netdev_priv(dev);
	struct mlx5_core_dev *mdev = priv->mdev;
	struct mlx5e_dmq_binding *b;
	int err;

	b = kzalloc_obj(*b);
	if (!b)
		return -ENOMEM;
	err = mlx5_core_alloc_pd(mdev, &b->pdn);
	if (err) {
		NL_SET_ERR_MSG(extack, "cannot allocate a protection domain");
		goto err_free;
	}
	net_dmq_binding_set_drv_priv(binding, b);
	net_dmq_binding_set_data_addr(binding, NET_DMQ_DATA_OFFSET);
	return 0;

err_free:
	kfree(b);
	return err;
}

void mlx5e_dmq_binding_uninit(struct net_device *dev,
			      struct net_devmem_queue_binding *binding)
{
	struct mlx5e_dmq_binding *b = net_dmq_binding_drv_priv(binding);
	struct mlx5e_priv *priv = netdev_priv(dev);

	mlx5_core_dealloc_pd(priv->mdev, b->pdn);
	net_dmq_binding_set_drv_priv(binding, NULL);
	kfree(b);
}

/* Each page of a buffer, as the NIC addresses it. */
static u64 *mlx5e_dmq_pages(struct sg_table *sgt, u32 *n)
{
	struct scatterlist *sg;
	u32 i = 0, total = 0;
	u64 *addrs, off;
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

/* The biggest page the key can map @addrs with: each one aligned to it and
 * the pages in it contiguous, as ib_umem_find_best_pgsz() picks for mlx5_ib.
 */
static unsigned int mlx5e_dmq_page_shift(struct mlx5_core_dev *mdev,
					 const u64 *addrs, u32 n)
{
	unsigned int max = MLX5_CAP_GEN_2(mdev, max_mkey_log_entity_size_mtt);
	unsigned int min = max_t(unsigned int, PAGE_SHIFT,
				 MLX5_CAP_GEN_2(mdev, log_min_mkey_entity_size));
	unsigned int shift;
	u64 run;
	u32 i;

	if (!max || max > 31)
		max = 31;
	max = min_t(unsigned int, max, order_base_2(n) + PAGE_SHIFT);
	for (shift = max; shift > min; shift--) {
		run = (1ULL << (shift - PAGE_SHIFT)) - 1;
		for (i = 0; i < n; i++) {
			if (i & run) {
				if (addrs[i] != addrs[i - 1] + PAGE_SIZE)
					break;
			} else if (addrs[i] & ((1ULL << shift) - 1)) {
				break;
			}
		}
		if (i == n)
			break;
	}
	return shift;
}

/* A key over a buffer, addressed from zero, in the binding's PD.  The
 * entries carry the address alone: the access bits go with pg_access, and
 * without it the firmware takes them for a misaligned address.
 */
static int mlx5e_dmq_mkey(struct mlx5_core_dev *mdev, u32 pdn,
			  struct sg_table *sgt, u32 *mkey)
{
	u32 n, i, octwords, nmtt, shift;
	struct mlx5_mtt *mtt;
	void *mkc, *in;
	int inlen, err;
	u64 *addrs;

	addrs = mlx5e_dmq_pages(sgt, &n);
	if (!addrs)
		return -ENOMEM;
	err = -EINVAL;
	if (!n)
		goto out;

	shift = mlx5e_dmq_page_shift(mdev, addrs, n);
	nmtt = DIV_ROUND_UP(n, 1U << (shift - PAGE_SHIFT));
	octwords = DIV_ROUND_UP(nmtt, 2);
	inlen = MLX5_FLEXIBLE_INLEN(mdev, MLX5_ST_SZ_BYTES(create_mkey_in),
				    MLX5_OCTWORD, octwords);
	if (inlen < 0) {
		err = inlen;
		goto out;
	}
	in = kvzalloc(inlen, GFP_KERNEL);
	if (!in) {
		err = -ENOMEM;
		goto out;
	}

	mkc = MLX5_ADDR_OF(create_mkey_in, in, memory_key_mkey_entry);
	MLX5_SET(mkc, mkc, lw, 1);
	MLX5_SET(mkc, mkc, lr, 1);
	MLX5_SET(mkc, mkc, access_mode_1_0, MLX5_MKC_ACCESS_MODE_MTT);
	mlx5e_mkey_set_relaxed_ordering(mdev, mkc);
	MLX5_SET(mkc, mkc, qpn, 0xffffff);
	MLX5_SET(mkc, mkc, pd, pdn);
	MLX5_SET64(mkc, mkc, start_addr, 0);
	MLX5_SET64(mkc, mkc, len, (u64)n << PAGE_SHIFT);
	MLX5_SET(mkc, mkc, log_page_size, shift);
	MLX5_SET(mkc, mkc, translations_octword_size, octwords);
	MLX5_SET(create_mkey_in, in, translations_octword_actual_size,
		 octwords);

	mtt = MLX5_ADDR_OF(create_mkey_in, in, klm_pas_mtt);
	for (i = 0; i < nmtt; i++)
		mtt[i].ptag = cpu_to_be64(addrs[i << (shift - PAGE_SHIFT)]);

	err = mlx5_core_create_mkey(mdev, mkey, in, inlen);
	kvfree(in);
	if (err)
		mlx5_core_warn(mdev, "dmq: key: %u pages, %u entries of 2^%u, pd %u: %d\n",
			       n, nmtt, shift, pdn, err);
	else
		mlx5_core_dbg(mdev, "dmq: key %#x: %u pages, %u entries of 2^%u, pd %u, bus %llx..%llx\n",
			      *mkey, n, nmtt, shift, pdn, addrs[0], addrs[n - 1]);
out:
	kvfree(addrs);
	return err;
}

int mlx5e_dmq_open(struct mlx5e_channel *c, struct mlx5e_params *params,
		   struct mlx5e_channel_param *cparam, bool xsk)
{
	struct net_devmem_queue *q = netif_rxq_dmq(c->netdev, c->ix);
	struct mlx5e_dmq_binding *b;
	struct net_dmq_layout lay = {};
	struct net_dmq_region r;
	struct mlx5e_dmq_chan *d;
	struct iosys_map *map;
	u32 off = 0, end = 0, i;
	int err;

	if (!q)
		return 0;
	if (xsk)
		return -EBUSY;
	err = mlx5e_dmq_sizes(params, cparam, &lay, NULL);
	if (err)
		return err;

	d = kvzalloc_obj(*d);
	if (!d)
		return -ENOMEM;
	d->q = q;
	b = net_dmq_binding_drv_priv(net_dmq_binding(q));
	d->pdn = b->pdn;
	/* Where the consumer said, if it did and the ring still fits: the
	 * rings may have grown since it laid the buffer out.
	 */
	for (i = 0; i < NET_DMQ_MLX5_RINGS; i++) {
		if (net_dmq_region(q, i, &r)) {
			if (r.bytes < lay.ring[i].bytes) {
				netdev_warn(c->netdev, "dmq: q%d ring %u needs %u bytes, its region %u\n",
					    c->ix, i, lay.ring[i].bytes, r.bytes);
				err = -ENOSPC;
				goto err_free;
			}
			d->off[i] = r.offset;
			d->bytes[i] = r.bytes;
		} else {
			d->off[i] = off;
			d->bytes[i] = lay.ring[i].bytes;
			off += d->bytes[i];
		}
		end = max(end, d->off[i] + d->bytes[i]);
	}

	err = -ENOMEM;
	d->ring_dma = mlx5e_dmq_pages(net_dmq_rings_sgt(q), &d->ring_pages);
	if (!d->ring_dma)
		goto err_free;
	if (((u64)d->ring_pages << PAGE_SHIFT) < end) {
		netdev_warn(c->netdev, "dmq: q%d ring buffer has %u pages, needs %u\n",
			    c->ix, d->ring_pages, end >> PAGE_SHIFT);
		err = -EINVAL;
		goto err_free;
	}
	netdev_dbg(c->netdev, "dmq: q%d rings: %u pages, bus %llx\n", c->ix,
		   d->ring_pages, d->ring_dma[0]);

	err = mlx5e_dmq_mkey(c->mdev, d->pdn, net_dmq_data_sgt(q), &d->mkey);
	if (err)
		goto err_free;
	/* A UAR of the channel's own: the queues of a binding rung through one
	 * would wait on each other in the NIC.
	 */
	err = mlx5_alloc_uar(c->mdev, &d->uar, &d->uar_phys);
	if (err) {
		mlx5_core_destroy_mkey(c->mdev, d->mkey);
		goto err_free;
	}

	/* A new build starts from zero records, as the NIC's own queues do:
	 * whatever the last build left would read as entries posted.
	 */
	map = net_dmq_rings_map(q);
	iosys_map_memset(map, d->off[NET_DMQ_MLX5_DBR], 0, PAGE_SIZE);

	c->dmq = d;
	return 0;

err_free:
	kvfree(d->ring_dma);
	kvfree(d);
	return err;
}

void mlx5e_dmq_close(struct mlx5e_channel *c)
{
	struct mlx5e_dmq_chan *d = c->dmq;

	if (!d)
		return;
	mlx5_free_uar(c->mdev, d->uar);
	mlx5_core_destroy_mkey(c->mdev, d->mkey);
	kvfree(d->ring_dma);
	kvfree(d);
	c->dmq = NULL;
}

static u32 mlx5e_dmq_dbr(struct mlx5e_dmq_chan *d, int ring)
{
	static const u32 dbr[] = {
		[NET_DMQ_MLX5_RQ] = NET_DMQ_MLX5_RQ_DBR,
		[NET_DMQ_MLX5_RX_CQ] = NET_DMQ_MLX5_CQ_DBR,
		[NET_DMQ_MLX5_SQ] = NET_DMQ_MLX5_SQ_DBR,
		[NET_DMQ_MLX5_TX_CQ] = NET_DMQ_MLX5_TX_CQ_DBR,
	};

	return d->off[NET_DMQ_MLX5_DBR] + dbr[ring];
}

/* Point a queue's pages and doorbell record at the ring buffer. */
int mlx5e_dmq_swap(struct mlx5e_channel *c, int ring,
		   struct mlx5_wq_ctrl *wqc, struct mlx5e_dmq_saved *sv)
{
	struct mlx5_frag_buf *buf = &wqc->buf;
	struct mlx5e_dmq_chan *d = c->dmq;
	u32 first = d->off[ring] >> PAGE_SHIFT, db = mlx5e_dmq_dbr(d, ring);
	int i;

	if (buf->page_shift != PAGE_SHIFT ||
	    ((size_t)buf->npages << PAGE_SHIFT) > d->bytes[ring])
		return -EINVAL;

	sv->maps = kvcalloc(buf->npages, sizeof(*sv->maps), GFP_KERNEL);
	if (!sv->maps)
		return -ENOMEM;
	for (i = 0; i < buf->npages; i++) {
		sv->maps[i] = buf->frags[i].map;
		buf->frags[i].map = d->ring_dma[first + i];
	}
	sv->db = wqc->db.dma;
	wqc->db.dma = d->ring_dma[db >> PAGE_SHIFT] + offset_in_page(db);
	return 0;
}

void mlx5e_dmq_restore(struct mlx5_wq_ctrl *wqc, struct mlx5e_dmq_saved *sv)
{
	struct mlx5_frag_buf *buf = &wqc->buf;
	int i;

	if (!sv->maps)
		return;
	for (i = 0; i < buf->npages; i++)
		buf->frags[i].map = sv->maps[i];
	wqc->db.dma = sv->db;
	kvfree(sv->maps);
	sv->maps = NULL;
}

/* As mlx5e_alloc_cq_common() does for the NIC's own: every CQE invalid and
 * owned by hardware, so the device sees nothing until one lands.
 */
void mlx5e_dmq_init_cq(struct mlx5e_channel *c, int ring, struct mlx5e_cq *cq)
{
	struct iosys_map *map = net_dmq_rings_map(c->dmq->q);
	u32 off = c->dmq->off[ring], i;

	for (i = 0; i < mlx5_cqwq_get_size(&cq->wq); i++, off += 64) {
		iosys_map_wr(map, off + offsetof(struct mlx5_cqe64, op_own),
			     u8, 0xf1);
		iosys_map_wr(map, off + offsetof(struct mlx5_cqe64,
						 validity_iteration_count),
			     u8, 0xff);
	}
}

/* The queues are up in the ring buffer: what the device needs to run them. */
void mlx5e_dmq_built(struct mlx5e_channel *c)
{
	struct mlx5e_dmq_chan *d = c->dmq;
	struct net_dmq_mlx5 *m;
	struct net_dmq_info info = {};
	struct mlx5e_rq *rq = &c->rq;
	struct mlx5e_xdpsq *sq = &c->rq_xdpsq;
	int i;

	if (!d)
		return;
	info.fmt = NET_DMQ_FMT_MLX5_CX5;
	info.nr_rings = NET_DMQ_MLX5_RINGS;
	for (i = 0; i < NET_DMQ_MLX5_RINGS; i++)
		info.ring[i].offset = d->off[i];
	info.ring[NET_DMQ_MLX5_RQ].entries = mlx5_wq_cyc_get_size(&rq->wqe.wq);
	info.ring[NET_DMQ_MLX5_RQ].stride = 1U << rq->wqe.wq.fbc.log_stride;
	info.ring[NET_DMQ_MLX5_RX_CQ].entries = mlx5_cqwq_get_size(&rq->cq.wq);
	info.ring[NET_DMQ_MLX5_RX_CQ].stride = 64;
	info.ring[NET_DMQ_MLX5_SQ].entries = mlx5_wq_cyc_get_size(&sq->wq);
	info.ring[NET_DMQ_MLX5_SQ].stride = MLX5_SEND_WQE_BB;
	info.ring[NET_DMQ_MLX5_TX_CQ].entries = mlx5_cqwq_get_size(&sq->cq.wq);
	info.ring[NET_DMQ_MLX5_TX_CQ].stride = 64;
	info.data_key = d->mkey;
	info.nr_doorbells = 1;
	info.doorbell[0].phys = d->uar_phys + MLX5_BF_OFFSET;
	info.doorbell[0].width = 8;

	BUILD_BUG_ON(sizeof(*m) > NET_DMQ_FMT_PRIV_LEN);
	m = (struct net_dmq_mlx5 *)info.fmt_priv;
	m->sqn = sq->sqn;
	m->frag_size = rq->wqe.info.arr[0].frag_size;
	m->frame_size = rq->wqe.info.arr[0].frag_stride;
	m->headroom = rq->buff.headroom;

	net_dmq_built(d->q, &info);
}

/* The doorbell records the other device keeps for a CQ's channel, as the NIC
 * saw them when it raised the error, and the XDP SQ's error completions - the
 * flushes counted, the first few shown.
 */
static u32 mlx5e_dmq_rd_dbr(struct mlx5e_dmq_chan *d, struct iosys_map *map,
			    int ring, u32 extra)
{
	return be32_to_cpu(iosys_map_rd(map, mlx5e_dmq_dbr(d, ring) + extra,
					__be32));
}

void mlx5e_dmq_cq_error_dump(struct mlx5e_channel *c, struct mlx5_core_cq *mcq)
{
	struct mlx5e_dmq_chan *d = c->dmq;
	u32 i, n, off, shown = 0, flushed = 0;
	struct iosys_map *map;
	u8 cqe[64], op;

	if (!d)
		return;
	map = net_dmq_rings_map(d->q);
	netdev_err(c->netdev,
		   "dmq: q%d cqn 0x%x rq_db %u cq_db %u sq_db %u tx_cq_db %u\n",
		   c->ix, mcq->cqn, mlx5e_dmq_rd_dbr(d, map, NET_DMQ_MLX5_RQ, 0),
		   mlx5e_dmq_rd_dbr(d, map, NET_DMQ_MLX5_RX_CQ, 0),
		   mlx5e_dmq_rd_dbr(d, map, NET_DMQ_MLX5_SQ, 4),
		   mlx5e_dmq_rd_dbr(d, map, NET_DMQ_MLX5_TX_CQ, 0));
	if (!c->xdp)
		return;

	n = mlx5_cqwq_get_size(&c->rq_xdpsq.cq.wq);
	for (i = 0; i < n; i++) {
		off = d->off[NET_DMQ_MLX5_TX_CQ] + i * 64;
		iosys_map_memcpy_from(cqe, map, off, sizeof(cqe));
		op = cqe[63] >> 4;
		if (op != MLX5_CQE_REQ_ERR && op != MLX5_CQE_RESP_ERR)
			continue;
		if (cqe[55] == MLX5_CQE_SYNDROME_WR_FLUSH_ERR) {
			flushed++;
			continue;
		}
		if (shown++ >= 4)
			continue;
		netdev_err(c->netdev,
			   "dmq: q%d tx err cqe %u synd 0x%x vendor 0x%x wqe %u\n",
			   c->ix, i, cqe[55], cqe[54],
			   be16_to_cpu(*(__be16 *)(cqe + 60)));
		print_hex_dump(KERN_ERR, "dmq: tx err cqe ", DUMP_PREFIX_OFFSET,
			       16, 1, cqe, sizeof(cqe), false);
	}
	netdev_err(c->netdev, "dmq: q%d tx err %u, flushed %u\n", c->ix, shown,
		   flushed);
}

void mlx5e_dmq_activate(struct mlx5e_channel *c)
{
	if (c->dmq)
		net_dmq_publish(c->dmq->q);
}

void mlx5e_dmq_deactivate(struct mlx5e_channel *c)
{
	if (c->dmq)
		net_dmq_quiesce(c->dmq->q);
}
