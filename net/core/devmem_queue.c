// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Device memory queue ownership: see <net/devmem_queue.h>.
 *
 * A bound queue is marked on its netdev_rx_queue and restarted; the driver's
 * rebuild finds the mark and builds the queue in the binding's memory, then
 * says where it put it.  Unbinding takes the mark off and restarts it again.
 */

#include <linux/dma-buf.h>
#include <linux/dma-resv.h>
#include <linux/netdevice.h>
#include <linux/slab.h>
#include <net/devmem_queue.h>
#include <net/netdev_lock.h>
#include <net/netdev_queues.h>
#include <net/netdev_rx_queue.h>

#include "dev.h"

struct net_devmem_queue {
	struct net_devmem_queue_binding *binding;
	u32 idx;
	struct dma_buf *rings;
	struct dma_buf *data;
	struct dma_buf_attachment *rings_att;
	struct dma_buf_attachment *data_att;
	struct sg_table *rings_sgt;
	struct sg_table *data_sgt;
	struct iosys_map rings_map;
	u32 nr_regions;
	struct net_dmq_region region[NET_DMQ_RINGS_MAX];
	struct net_dmq_info info;
	bool built;
	bool running;
	bool installed;
};

struct net_devmem_queue_binding {
	struct net_device *dev;
	netdevice_tracker dev_tracker;
	const struct net_dmq_ops *ops;
	void *priv;
	void *drv_priv;
	u32 data_addr;
	bool drv_init;		/* the driver's per-binding state is up */
	u32 nr;
	struct net_devmem_queue queues[] __counted_by(nr);
};

/* Pinned: the NIC reads and writes it with nothing to tell it otherwise. */
static const struct dma_buf_attach_ops net_dmq_attach_ops = {
	.allow_peer2peer = true,
};

static int net_dmq_map(struct dma_buf *buf, struct device *dma_dev,
		       struct dma_buf_attachment **attp, struct sg_table **sgtp)
{
	struct dma_buf_attachment *att;
	struct sg_table *sgt;
	int err;

	att = dma_buf_dynamic_attach(buf, dma_dev, &net_dmq_attach_ops, NULL);
	if (IS_ERR(att))
		return PTR_ERR(att);

	dma_resv_lock(buf->resv, NULL);
	err = dma_buf_pin(att);
	if (err)
		goto err_unlock;
	sgt = dma_buf_map_attachment(att, DMA_BIDIRECTIONAL);
	if (IS_ERR(sgt)) {
		err = PTR_ERR(sgt);
		goto err_unpin;
	}
	dma_resv_unlock(buf->resv);

	*attp = att;
	*sgtp = sgt;
	return 0;

err_unpin:
	dma_buf_unpin(att);
err_unlock:
	dma_resv_unlock(buf->resv);
	dma_buf_detach(buf, att);
	return err;
}

static void net_dmq_unmap(struct dma_buf *buf, struct dma_buf_attachment **attp,
			  struct sg_table **sgtp)
{
	if (!*attp)
		return;
	dma_resv_lock(buf->resv, NULL);
	dma_buf_unmap_attachment(*attp, *sgtp, DMA_BIDIRECTIONAL);
	dma_buf_unpin(*attp);
	dma_resv_unlock(buf->resv);
	dma_buf_detach(buf, *attp);
	*attp = NULL;
	*sgtp = NULL;
}

static void net_dmq_queue_unmap(struct net_devmem_queue *q)
{
	if (!iosys_map_is_null(&q->rings_map)) {
		dma_buf_vunmap_unlocked(q->rings, &q->rings_map);
		iosys_map_clear(&q->rings_map);
	}
	net_dmq_unmap(q->data, &q->data_att, &q->data_sgt);
	net_dmq_unmap(q->rings, &q->rings_att, &q->rings_sgt);
}

static int net_dmq_check_dev(struct net_device *dev,
			     struct netlink_ext_ack *extack)
{
	const struct netdev_queue_mgmt_ops *qops = dev->queue_mgmt_ops;

	if (!qops || !qops->ndo_dmq_query) {
		NL_SET_ERR_MSG(extack, "device cannot hand its queues over");
		return -EOPNOTSUPP;
	}
	if (!netdev_need_ops_lock(dev))
		return -EOPNOTSUPP;
	return 0;
}

/*
 * The whole device or none of it: another device's queues are restarted,
 * steered to and reconfigured together, under whatever memory provider or
 * AF_XDP socket a queue beside them has.
 */
static int net_dmq_check_shared(struct net_device *dev,
				struct netlink_ext_ack *extack)
{
	struct netdev_rx_queue *rxq;
	unsigned int i;

	for (i = 0; i < dev->real_num_rx_queues; i++) {
		rxq = __netif_get_rx_queue(dev, i);
		if (rxq->mp_params.mp_ops) {
			NL_SET_ERR_MSG(extack, "device has a memory provider bound");
			return -EBUSY;
		}
#ifdef CONFIG_XDP_SOCKETS
		if (rxq->pool) {
			NL_SET_ERR_MSG(extack, "device has an AF_XDP socket bound");
			return -EBUSY;
		}
#endif
		if (rxq->dmq) {
			NL_SET_ERR_MSG(extack, "device already has its queues handed over");
			return -EBUSY;
		}
		if (netif_rxq_is_leased(dev, i)) {
			NL_SET_ERR_MSG(extack, "device has a queue leased");
			return -EBUSY;
		}
	}
	return 0;
}

bool netif_has_dmq(struct net_device *dev)
{
	unsigned int i;

	for (i = 0; i < dev->real_num_rx_queues; i++)
		if (__netif_get_rx_queue(dev, i)->dmq)
			return true;
	return false;
}
EXPORT_SYMBOL_GPL(netif_has_dmq);

/* The channels the device's handed-over queues need: the last one's plus 1. */
u32 dev_get_min_dmq_channel_count(struct net_device *dev)
{
	int i;

	for (i = dev->real_num_rx_queues - 1; i >= 0; i--)
		if (__netif_get_rx_queue(dev, i)->dmq)
			return i + 1;
	return 0;
}

int net_devmem_queue_query(struct net_device *dev, u32 idx,
			   struct net_dmq_layout *layout,
			   struct netlink_ext_ack *extack)
{
	struct netdev_queue_config qcfg;
	int err;

	netdev_lock(dev);
	err = net_dmq_check_dev(dev, extack);
	if (err)
		goto out;
	if (idx >= dev->real_num_rx_queues) {
		NL_SET_ERR_MSG(extack, "rx queue index out of range");
		err = -ERANGE;
		goto out;
	}
	memset(layout, 0, sizeof(*layout));
	netdev_queue_config(dev, idx, &qcfg);
	err = dev->queue_mgmt_ops->ndo_dmq_query(dev, idx, &qcfg, layout,
						 extack);
	if (!err && (layout->fmt == NET_DMQ_FMT_NONE ||
		     layout->fmt >= NET_DMQ_FMT_MAX ||
		     layout->nr_rings > NET_DMQ_RINGS_MAX))
		err = -EINVAL;
out:
	netdev_unlock(dev);
	return err;
}
EXPORT_SYMBOL_GPL(net_devmem_queue_query);

/* The consumer's regions: inside the ring buffer, apart, and as big as the
 * rings need now.  The driver checks again on every rebuild.
 */
static int net_dmq_check_regions(struct net_device *dev,
				 struct net_devmem_queue *q,
				 struct netlink_ext_ack *extack)
{
	struct net_dmq_layout lay;
	struct netdev_queue_config qcfg;
	u32 i, j;
	int err;

	if (!q->nr_regions)
		return 0;
	memset(&lay, 0, sizeof(lay));
	netdev_queue_config(dev, q->idx, &qcfg);
	err = dev->queue_mgmt_ops->ndo_dmq_query(dev, q->idx, &qcfg, &lay,
						 extack);
	if (err)
		return err;
	if (q->nr_regions != lay.nr_rings) {
		NL_SET_ERR_MSG(extack, "a region for each ring, or none");
		return -EINVAL;
	}
	for (i = 0; i < q->nr_regions; i++) {
		const struct net_dmq_region *r = &q->region[i];

		if (r->bytes < lay.ring[i].bytes ||
		    (u64)r->offset + r->bytes > q->rings->size ||
		    (lay.ring[i].align &&
		     !IS_ALIGNED(r->offset, lay.ring[i].align))) {
			NL_SET_ERR_MSG(extack, "a ring does not fit its region");
			return -EINVAL;
		}
		for (j = 0; j < i; j++) {
			const struct net_dmq_region *o = &q->region[j];

			if (r->offset < o->offset + o->bytes &&
			    o->offset < r->offset + r->bytes) {
				NL_SET_ERR_MSG(extack, "ring regions overlap");
				return -EINVAL;
			}
		}
	}
	return 0;
}

static int net_dmq_install(struct net_device *dev, struct net_devmem_queue *q,
			   struct netlink_ext_ack *extack)
{
	struct netdev_rx_queue *rxq = __netif_get_rx_queue(dev, q->idx);
	int err;

	WRITE_ONCE(rxq->dmq, q);
	q->installed = true;
	/* Down, the driver builds it the bound way as it opens it; and a
	 * driver that rebuilds them all does so once they are all marked.
	 */
	if (!netif_running(dev) || dev->queue_mgmt_ops->ndo_dmq_rebuild)
		return 0;
	err = netdev_rx_queue_restart(dev, q->idx);
	if (err) {
		q->installed = false;
		WRITE_ONCE(rxq->dmq, NULL);
		NL_SET_ERR_MSG(extack, "rx queue restart failed");
		return err;
	}
	return 0;
}

/* Give the queue back to the kernel: the driver rebuilds it as its own. */
static void net_dmq_uninstall(struct net_device *dev,
			      struct net_devmem_queue *q, bool restart)
{
	struct netdev_rx_queue *rxq = __netif_get_rx_queue(dev, q->idx);
	int err;

	if (!q->installed)
		return;
	q->installed = false;
	WRITE_ONCE(rxq->dmq, NULL);
	if (!restart || !netif_running(dev) ||
	    dev->queue_mgmt_ops->ndo_dmq_rebuild)
		return;
	err = netdev_rx_queue_restart(dev, q->idx);
	WARN_ON(err && err != -ENETDOWN);
}

/* All the device's queues anew, for a driver that cannot do one alone. */
static int net_dmq_rebuild(struct net_device *dev,
			   struct netlink_ext_ack *extack)
{
	const struct netdev_queue_mgmt_ops *qops = dev->queue_mgmt_ops;

	if (!qops->ndo_dmq_rebuild || !netif_running(dev))
		return 0;
	return qops->ndo_dmq_rebuild(dev, extack);
}

/* Undo what the binding holds on the device: its queues, the driver's
 * state, the buffers' mappings.  The device lock is held.
 */
static void net_dmq_release_dev(struct net_devmem_queue_binding *binding,
				bool restart)
{
	struct net_device *dev = binding->dev;
	const struct netdev_queue_mgmt_ops *qops = dev->queue_mgmt_ops;
	u32 i;

	for (i = 0; i < binding->nr; i++)
		net_dmq_uninstall(dev, &binding->queues[i], restart);
	if (restart)
		WARN_ON(net_dmq_rebuild(dev, NULL));
	if (binding->drv_init && qops->ndo_dmq_binding_uninit)
		qops->ndo_dmq_binding_uninit(dev, binding);
	binding->drv_init = false;
	for (i = 0; i < binding->nr; i++)
		net_dmq_queue_unmap(&binding->queues[i]);
}

static void net_dmq_free(struct net_devmem_queue_binding *binding)
{
	u32 i;

	for (i = 0; i < binding->nr; i++) {
		if (binding->queues[i].rings)
			dma_buf_put(binding->queues[i].rings);
		if (binding->queues[i].data)
			dma_buf_put(binding->queues[i].data);
	}
	netdev_put(binding->dev, &binding->dev_tracker);
	kfree(binding);
}

struct net_devmem_queue_binding *
net_devmem_bind_queues(struct net_device *dev,
		       const struct net_dmq_bind_req *reqs, u32 nr,
		       const struct net_dmq_ops *ops, void *priv,
		       struct netlink_ext_ack *extack)
{
	const struct netdev_queue_mgmt_ops *qops;
	struct net_devmem_queue_binding *binding;
	struct net_devmem_queue *q;
	struct device *dma_dev;
	u32 i, j;
	int err;

	if (!nr || !ops || !ops->down || !ops->up)
		return ERR_PTR(-EINVAL);

	binding = kzalloc(struct_size(binding, queues, nr), GFP_KERNEL);
	if (!binding)
		return ERR_PTR(-ENOMEM);
	binding->nr = nr;
	binding->dev = dev;
	binding->ops = ops;
	binding->priv = priv;
	netdev_hold(dev, &binding->dev_tracker, GFP_KERNEL);
	for (i = 0; i < nr; i++) {
		q = &binding->queues[i];
		q->binding = binding;
		q->idx = reqs[i].idx;
		q->rings = reqs[i].rings;
		q->data = reqs[i].data;
		if (!q->rings || !q->data ||
		    reqs[i].nr_regions > NET_DMQ_RINGS_MAX) {
			err = -EINVAL;
			goto err_free;
		}
		get_dma_buf(q->rings);
		get_dma_buf(q->data);
		q->nr_regions = reqs[i].nr_regions;
		memcpy(q->region, reqs[i].region,
		       q->nr_regions * sizeof(q->region[0]));
		for (j = 0; j < i; j++) {
			if (binding->queues[j].idx == q->idx) {
				NL_SET_ERR_MSG(extack, "rx queue bound twice");
				err = -EINVAL;
				goto err_free;
			}
		}
	}

	netdev_lock(dev);
	err = net_dmq_check_dev(dev, extack);
	if (err)
		goto err_unlock;
	if (dev->reg_state != NETREG_REGISTERED) {
		err = -ENODEV;
		goto err_unlock;
	}
	err = net_dmq_check_shared(dev, extack);
	if (err)
		goto err_unlock;
	qops = dev->queue_mgmt_ops;

	for (i = 0; i < nr; i++) {
		q = &binding->queues[i];
		if (q->idx >= dev->real_num_rx_queues) {
			NL_SET_ERR_MSG(extack, "rx queue index out of range");
			err = -ERANGE;
			goto err_release;
		}
		err = net_dmq_check_regions(dev, q, extack);
		if (err)
			goto err_release;
		dma_dev = netdev_queue_get_dma_dev(dev, q->idx,
						   NETDEV_QUEUE_TYPE_RX);
		if (!dma_dev) {
			NL_SET_ERR_MSG(extack, "rx queue has no DMA device");
			err = -EOPNOTSUPP;
			goto err_release;
		}
		err = net_dmq_map(q->rings, dma_dev, &q->rings_att,
				  &q->rings_sgt);
		if (err) {
			NL_SET_ERR_MSG(extack, "cannot map the ring buffer");
			goto err_release;
		}
		err = net_dmq_map(q->data, dma_dev, &q->data_att,
				  &q->data_sgt);
		if (err) {
			NL_SET_ERR_MSG(extack, "cannot map the data buffer");
			goto err_release;
		}
		err = dma_buf_vmap_unlocked(q->rings, &q->rings_map);
		if (err) {
			NL_SET_ERR_MSG(extack, "cannot map the ring buffer for the CPU");
			goto err_release;
		}
	}

	if (qops->ndo_dmq_binding_init) {
		err = qops->ndo_dmq_binding_init(dev, binding, extack);
		if (err)
			goto err_release;
		binding->drv_init = true;
	}

	for (i = 0; i < nr; i++) {
		err = net_dmq_install(dev, &binding->queues[i], extack);
		if (err)
			goto err_release;
	}
	err = net_dmq_rebuild(dev, extack);
	if (err)
		goto err_release;
	netdev_unlock(dev);
	return binding;

err_release:
	net_dmq_release_dev(binding, true);
err_unlock:
	netdev_unlock(dev);
err_free:
	net_dmq_free(binding);
	return ERR_PTR(err);
}
EXPORT_SYMBOL_GPL(net_devmem_bind_queues);

void net_devmem_unbind_queues(struct net_devmem_queue_binding *binding)
{
	struct net_device *dev = binding->dev;

	netdev_lock(dev);
	net_dmq_release_dev(binding, dev->reg_state == NETREG_REGISTERED);
	netdev_unlock(dev);
	net_dmq_free(binding);
}
EXPORT_SYMBOL_GPL(net_devmem_unbind_queues);

/* The device is going: its queues are already down.  The binding stays for
 * its owner to unbind; each queue is dead to it.
 */
void dev_dmq_uninstall(struct net_device *dev)
{
	struct net_devmem_queue_binding *binding;
	struct net_devmem_queue *q;
	unsigned int i, j;

	netdev_assert_locked(dev);
	for (i = 0; i < dev->real_num_rx_queues; i++) {
		q = dev->_rx[i].dmq;
		if (!q)
			continue;
		binding = q->binding;
		for (j = 0; j < binding->nr; j++)
			if (binding->queues[j].installed)
				net_dmq_dead(&binding->queues[j]);
		net_dmq_release_dev(binding, false);
	}
}

int net_devmem_queue_data_addrs(struct net_devmem_queue_binding *binding,
				u32 idx, u64 *addrs, u32 nr)
{
	struct net_devmem_queue *q = NULL;
	struct scatterlist *sg;
	u32 i, n = 0;
	u64 off;
	int si;

	for (i = 0; i < binding->nr; i++)
		if (binding->queues[i].idx == idx)
			q = &binding->queues[i];
	if (!q || !q->data_sgt)
		return -ENOENT;

	if (binding->data_addr == NET_DMQ_DATA_OFFSET) {
		for (n = 0; n < nr && n < q->data->size >> PAGE_SHIFT; n++)
			addrs[n] = (u64)n << PAGE_SHIFT;
		return n;
	}
	for_each_sgtable_dma_sg(q->data_sgt, sg, si)
		for (off = 0; off + PAGE_SIZE <= sg_dma_len(sg) && n < nr;
		     off += PAGE_SIZE)
			addrs[n++] = sg_dma_address(sg) + off;
	return n;
}
EXPORT_SYMBOL_GPL(net_devmem_queue_data_addrs);

u32 net_dmq_queue_idx(struct net_devmem_queue *q)
{
	return q->idx;
}
EXPORT_SYMBOL_GPL(net_dmq_queue_idx);

struct net_devmem_queue *netif_rxq_dmq(struct net_device *dev, u32 idx)
{
	if (idx >= dev->real_num_rx_queues)
		return NULL;
	return READ_ONCE(__netif_get_rx_queue(dev, idx)->dmq);
}
EXPORT_SYMBOL_GPL(netif_rxq_dmq);

struct net_devmem_queue_binding *net_dmq_binding(struct net_devmem_queue *q)
{
	return q->binding;
}
EXPORT_SYMBOL_GPL(net_dmq_binding);

struct sg_table *net_dmq_rings_sgt(struct net_devmem_queue *q)
{
	return q->rings_sgt;
}
EXPORT_SYMBOL_GPL(net_dmq_rings_sgt);

struct sg_table *net_dmq_data_sgt(struct net_devmem_queue *q)
{
	return q->data_sgt;
}
EXPORT_SYMBOL_GPL(net_dmq_data_sgt);

struct iosys_map *net_dmq_rings_map(struct net_devmem_queue *q)
{
	return &q->rings_map;
}
EXPORT_SYMBOL_GPL(net_dmq_rings_map);

bool net_dmq_region(struct net_devmem_queue *q, u32 ring,
		    struct net_dmq_region *region)
{
	if (ring >= q->nr_regions)
		return false;
	*region = q->region[ring];
	return true;
}
EXPORT_SYMBOL_GPL(net_dmq_region);

void *net_dmq_binding_drv_priv(struct net_devmem_queue_binding *binding)
{
	return binding->drv_priv;
}
EXPORT_SYMBOL_GPL(net_dmq_binding_drv_priv);

void net_dmq_binding_set_drv_priv(struct net_devmem_queue_binding *binding,
				  void *drv_priv)
{
	binding->drv_priv = drv_priv;
}
EXPORT_SYMBOL_GPL(net_dmq_binding_set_drv_priv);

void net_dmq_binding_set_data_addr(struct net_devmem_queue_binding *binding,
				   u32 data_addr)
{
	binding->data_addr = data_addr;
}
EXPORT_SYMBOL_GPL(net_dmq_binding_set_data_addr);

void net_dmq_built(struct net_devmem_queue *q, const struct net_dmq_info *info)
{
	u32 gen = q->info.gen + 1;

	q->info = *info;
	q->info.gen = gen;
	q->info.data_addr = q->binding->data_addr;
	q->built = true;
}
EXPORT_SYMBOL_GPL(net_dmq_built);

void net_dmq_publish(struct net_devmem_queue *q)
{
	struct net_devmem_queue_binding *binding = q->binding;

	if (WARN_ON_ONCE(!q->built) || q->running)
		return;
	q->running = true;
	binding->ops->up(q, &q->info, binding->priv);
}
EXPORT_SYMBOL_GPL(net_dmq_publish);

void net_dmq_quiesce(struct net_devmem_queue *q)
{
	struct net_devmem_queue_binding *binding = q->binding;

	if (!q->running)
		return;
	q->running = false;
	binding->ops->down(q, binding->priv);
}
EXPORT_SYMBOL_GPL(net_dmq_quiesce);

void net_dmq_dead(struct net_devmem_queue *q)
{
	struct net_devmem_queue_binding *binding = q->binding;

	q->running = false;
	if (binding->ops->dead)
		binding->ops->dead(q, binding->priv);
}
EXPORT_SYMBOL_GPL(net_dmq_dead);
