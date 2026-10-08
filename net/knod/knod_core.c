// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (c) 2021 Taehee Yoo <ap420073@gmail.com>
 * Copyright (c) 2021 Hoyeon Lee <hoyeon.rhee@gmail.com>
 */

#include <net/knod.h>
#include <net/spsc_ring.h>
#include <linux/dma-buf.h>
#include <linux/dma-resv.h>
#include <net/devmem.h>

#include "knod.h"

DEFINE_MUTEX(knod_lock);
LIST_HEAD(knod_dev_list);
EXPORT_SYMBOL_GPL(knod_dev_list);
LIST_HEAD(knod_netdev_list);
EXPORT_SYMBOL_GPL(knod_netdev_list);
LIST_HEAD(knod_accel_list);
EXPORT_SYMBOL_GPL(knod_accel_list);

void knod_dev_lock(void)
{
	mutex_lock(&knod_lock);
}
EXPORT_SYMBOL_GPL(knod_dev_lock);

void knod_dev_unlock(void)
{
	mutex_unlock(&knod_lock);
}
EXPORT_SYMBOL_GPL(knod_dev_unlock);

void knod_netdev_register(struct knod_netdev *knetdev)
{
	mutex_lock(&knod_lock);
	knetdev->status = KNOD_STATUS_FREE;
	list_add(&knetdev->list, &knod_netdev_list);
	mutex_unlock(&knod_lock);
}
EXPORT_SYMBOL(knod_netdev_register);

void knod_netdev_unregister(struct knod_netdev *knetdev)
{
	mutex_lock(&knod_lock);
	list_del(&knetdev->list);
	mutex_unlock(&knod_lock);
}
EXPORT_SYMBOL(knod_netdev_unregister);

void knod_accel_register(struct knod_accel *accel)
{
	mutex_lock(&knod_lock);
	accel->status = KNOD_STATUS_FREE;
	list_add(&accel->list, &knod_accel_list);
	mutex_unlock(&knod_lock);
}
EXPORT_SYMBOL(knod_accel_register);

void knod_accel_unregister(struct knod_accel *accel)
{
	mutex_lock(&knod_lock);
	list_del(&accel->list);
	mutex_unlock(&knod_lock);
}
EXPORT_SYMBOL(knod_accel_unregister);

struct knod_netdev *knod_netdev_lookup(struct net_device *dev)
{
	struct knod_netdev *knetdev;

	list_for_each_entry(knetdev, &knod_netdev_list, list)
		if (knetdev->dev == dev)
			return knetdev;

	return NULL;
}

struct knod_dev *knod_dev_lookup(struct net_device *dev)
{
	struct knod_dev *knodev;

	list_for_each_entry(knodev, &knod_dev_list, list)
		if (knodev->netdev == dev)
			return knodev;

	return NULL;
}

struct knod_accel *knod_accel_lookup(int id)
{
	struct knod_accel *accel;

	list_for_each_entry(accel, &knod_accel_list, list)
		if (accel->id == id)
			return accel;

	return NULL;
}

static void knod_napi_kick(struct knod_work_priv *wpriv);

void knod_dev_start(struct knod_dev *knodev)
{
	unsigned int qi;

	/* Interface up: start the active feature's worker. */
	knodev->started = true;
	if (knodev->accel_ops->dev_start)
		knodev->accel_ops->dev_start(knodev);
	/* Copies that landed while the queues were being rebuilt wait for a
	 * drain nothing else would schedule.
	 */
	for (qi = 0; qi < KNOD_SPSC_MAX; qi++)
		if (knodev->wpriv[qi].pass_pending.slots &&
		    spsc_count(&knodev->wpriv[qi].pass_pending))
			knod_napi_kick(&knodev->wpriv[qi]);
}
EXPORT_SYMBOL(knod_dev_start);

static void knod_pass_flush(struct knod_dev *knodev, unsigned int qi);

void knod_dev_stop(struct knod_dev *knodev)
{
	/* Interface down: stop the worker + drain the GPU in-flight. */
	if (knodev->accel_ops->dev_stop)
		knodev->accel_ops->dev_stop(knodev);
	knodev->started = false;
}
EXPORT_SYMBOL(knod_dev_stop);

/* Land and let go of every d2h copy still holding an RX page as its source.
 * The NIC calls this once its NAPI can no longer run the drain and before it
 * tears down the RX page_pool those pages belong to.
 */
void knod_dev_flush_pass(struct knod_dev *knodev)
{
	unsigned int qi;

	for (qi = 0; qi < KNOD_SPSC_MAX; qi++)
		knod_pass_flush(knodev, qi);
}
EXPORT_SYMBOL(knod_dev_flush_pass);

int knod_dev_xdp_install(struct knod_dev *knodev, struct netdev_bpf *xdp)
{
	if (!knodev->accel_ops->xdp_ops ||
	    !knodev->accel_ops->xdp_ops->xdp_install)
		return -EOPNOTSUPP;
	return knodev->accel_ops->xdp_ops->xdp_install(knodev, xdp);
}
EXPORT_SYMBOL(knod_dev_xdp_install);

/* The packet at @off in a staging page, copied into an skb of its own: the
 * page is the slot's again as soon as this returns.
 */
static struct sk_buff *knod_pass_skb(const void *page, u16 off, u16 len,
				     bool napi)
{
	struct sk_buff *skb;

	skb = __alloc_skb(off + len, GFP_ATOMIC,
			  SKB_ALLOC_RX | (napi ? SKB_ALLOC_NAPI : 0),
			  NUMA_NO_NODE);
	if (skb) {
		skb_reserve(skb, off);
		skb_put_data(skb, page + off, len);
	}
	return skb;
}

static void knod_napi_schedule(struct knod_work_priv *wpriv)
{
	struct napi_struct *napi;

	rcu_read_lock();
	napi = READ_ONCE(wpriv->napi);
	if (napi)
		napi_schedule(napi);
	rcu_read_unlock();
}

static void knod_napi_kick_work(struct irq_work *work)
{
	knod_napi_schedule(container_of(work, struct knod_work_priv,
					napi_kick));
}

/*
 * Nothing interrupts for a queue whose rings the accel runs, so the delivery
 * NAPI is scheduled from here, and on the CPU the queue's interrupt would
 * have run it on: scheduled where the kicker runs, every queue's delivery
 * would land on one CPU.
 */
static void knod_napi_kick(struct knod_work_priv *wpriv)
{
	int cpu = READ_ONCE(wpriv->napi_cpu);

	if (cpu < 0 || cpu == raw_smp_processor_id())
		knod_napi_schedule(wpriv);
	else
		irq_work_queue_on(&wpriv->napi_kick, cpu);
}

/*
 * Device->host copy for a batch of PASS packets.  The source pages stay posted
 * on the accel's RQ and come back to it in the order it handed them over, once
 * knod_d2h_credit() has seen each copy land and counted it in
 * wpriv->gda_pass_cc.  So nothing is dropped here: at the first one there is
 * no room for this stops, and the caller offers the rest again later.  A
 * packet too long to deliver still takes its place in the order, as a copy of
 * nothing.  Returns the count taken.
 */
int knod_d2h_copy(struct knod_dev *knodev, int napi_index,
		  const struct spsc_pass_bd *bds, int cnt)
{
	struct knod_accel_ops *ops = knodev->accel_ops;
	struct knod_work_priv *wpriv;
	struct knod_pass_desc *desc;
	bool submitted = false;
	u32 slot;
	int i;

	if (napi_index < 0 || napi_index >= KNOD_SPSC_MAX ||
	    !ops->d2h_submit || !ops->d2h_fence)
		return 0;
	wpriv = &knodev->wpriv[napi_index];
	if (!wpriv->pass_stage || !wpriv->pass_pending.slots)
		return 0;

	spin_lock(&knodev->d2h_lock);
	for (i = 0; i < cnt; i++) {
		u16 off = bds[i].off, len = bds[i].len;
		void *ptr;
		u32 fv;

		/* Not over a descriptor knod_d2h_credit() is still to read. */
		if (wpriv->pass_pending.head - wpriv->pass_credited >
		    wpriv->pass_pending.mask)
			break;
		/* The slot this one is about to take: its staging page. */
		slot = wpriv->pass_pending.head & wpriv->pass_pending.mask;
		if (spsc_produce(&wpriv->pass_pending, &ptr))
			break;
		desc = ptr;
		if (!len || off + len > PAGE_SIZE) {
			/* Landed already: the fence is past it. */
			len = 0;
			fv = ops->d2h_fence(knodev, 0);
		} else {
			fv = ops->d2h_submit(knodev, wpriv->pass_stage_gaddr +
					     ((u64)slot << PAGE_SHIFT) + off,
					     napi_index, bds[i].page_idx, off, len);
			if (!fv)
				break;
			submitted = true;
			this_cpu_inc(knodev->stats->d2h_copied);
		}
		desc->slot = slot;
		desc->off = off;
		desc->len = len;
		desc->fence_val = fv;
		desc->sdma_idx = 0;
		spsc_produce_commit(&wpriv->pass_pending);
	}
	if (submitted)
		ops->d2h_kick(knodev);
	spin_unlock(&knodev->d2h_lock);

	if (i)
		knod_napi_kick(wpriv);
	return i;
}
EXPORT_SYMBOL(knod_d2h_copy);

static void knod_pass_credit(struct knod_dev *knodev, int qi, unsigned int n)
{
	u32 *pass_cc = READ_ONCE(knodev->wpriv[qi].gda_pass_cc);

	if (!n || !pass_cc)
		return;
	if (knodev->accel_ops->pass_complete)
		knodev->accel_ops->pass_complete(knodev, qi, n);
	else
		WRITE_ONCE(*pass_cc, READ_ONCE(*pass_cc) + n);
}

/*
 * Give the accel back the RX pages of the copies that have landed.  Their data
 * is in the staging pages now, so the NIC may fill the pages again while the
 * drain is still to deliver them: how long a PASS packet holds its RQ entry no
 * longer depends on when the NAPI runs.  For the producer - the accel's worker
 * - to call; it alone moves pass_credited.  Returns how many copies are still
 * to land.
 */
unsigned int knod_d2h_credit(struct knod_dev *knodev, int napi_index)
{
	struct knod_work_priv *wpriv;
	struct knod_pass_desc *desc;
	struct spsc_ring *r;
	u32 fence, head, c;

	if (napi_index < 0 || napi_index >= KNOD_SPSC_MAX ||
	    !knodev->accel_ops->d2h_fence)
		return 0;
	wpriv = &knodev->wpriv[napi_index];
	r = &wpriv->pass_pending;
	if (!r->slots)
		return 0;

	head = r->head;
	c = wpriv->pass_credited;
	if (c == head)
		return 0;
	fence = knodev->accel_ops->d2h_fence(knodev, 0);
	for (; c != head; c++) {
		desc = r->slots[c & r->mask];
		if ((s32)(fence - desc->fence_val) < 0)
			break;
	}
	knod_pass_credit(knodev, napi_index, c - wpriv->pass_credited);
	wpriv->pass_credited = c;
	return head - c;
}
EXPORT_SYMBOL(knod_d2h_credit);

/*
 * Drain the per-queue pending ring: deliver every descriptor whose batch
 * fence has landed (accel_ops->d2h_fence) as an skb copied out of its staging
 * page; knod_d2h_credit() has given or will give its RX page back.  Stops at
 * the first not-yet-landed descriptor -- the ring is in fence order.  Runs on
 * the NIC NAPI (consumer); the knod_d2h_copy producer runs on the accel's
 * worker.
 */
int knod_d2h_drain(struct knod_dev *knodev, int napi_index,
		   struct napi_struct *napi, int budget)
{
	void *ptrs[KNOD_DEFAULT_PASS_SLOTS];
	struct knod_work_priv *wpriv;
	struct knod_pass_desc *d0;
	unsigned int got = 0, i, n = 0;
	int delivered = 0;
	u32 cur_fence;

	if (napi_index < 0 || napi_index >= KNOD_SPSC_MAX ||
	    !knodev->accel_ops->d2h_fence)
		return 0;
	wpriv = &knodev->wpriv[napi_index];
	if (!wpriv->pass_pending.slots || !wpriv->pass_stage)
		return 0;

	if (spsc_peek(&wpriv->pass_pending, ptrs,
		      min_t(unsigned int, budget, KNOD_DEFAULT_PASS_SLOTS),
		      &got) < 0 || got == 0)
		return 0;

	d0 = ptrs[0];
	cur_fence = knodev->accel_ops->d2h_fence(knodev, d0->sdma_idx);

	for (i = 0; i < got; i++) {
		struct knod_pass_desc *desc = ptrs[i];
		struct sk_buff *skb;

		if ((s32)(cur_fence - desc->fence_val) < 0)
			break;	/* not landed yet; later descs are newer */

		n++;
		if (!desc->len)
			continue;
		skb = knod_pass_skb(wpriv->pass_stage +
				    ((size_t)desc->slot << PAGE_SHIFT),
				    desc->off, desc->len, true);
		if (!skb)
			continue;
		if (likely(skb->len >= ETH_HLEN)) {
			skb->protocol = eth_type_trans(skb, knodev->netdev);
		} else {
			kfree_skb(skb);
			continue;
		}
		/* Coalesced with the rest of its flow, as the NIC's own
		 * receive path would.
		 */
		skb_record_rx_queue(skb, napi_index);
		napi_gro_receive(napi, skb);
		delivered++;
	}

	if (n)
		spsc_consume(&wpriv->pass_pending, n);

	/* Descriptors whose copy has not landed yet remain queued; re-arm so
	 * we poll again instead of waiting for the next RX event.
	 */
	if (spsc_count(&wpriv->pass_pending))
		knod_napi_kick(wpriv);

	return delivered;
}
EXPORT_SYMBOL(knod_d2h_drain);

int knod_dev_xdp_drain_pass(struct knod_dev *knodev, struct napi_struct *napi,
			    int queue_idx, int budget)
{
	if (!knodev || !knodev->accel_ops)
		return 0;
	return knod_d2h_drain(knodev, queue_idx, napi, budget);
}
EXPORT_SYMBOL_GPL(knod_dev_xdp_drain_pass);

static void knod_pass_free(struct knod_dev *knodev, unsigned int qi)
{
	struct knod_work_priv *wpriv = &knodev->wpriv[qi];

	if (wpriv->pass_pending.slots)
		spsc_destroy(&wpriv->pass_pending);
	if (wpriv->pass_stage_priv)
		knodev->accel_ops->free_mem(knodev, wpriv->pass_stage_priv);
	wpriv->pass_stage = NULL;
	wpriv->pass_stage_gaddr = 0;
	wpriv->pass_stage_priv = NULL;
	wpriv->pass_credited = 0;
}

/*
 * Per RX queue, the ring of GPU->host copies in flight and a GTT buffer with
 * a staging page for each of its slots.  Each queue's buffer is its own: one
 * for all of them is more GTT than a single allocation is given.
 */
static int knod_pass_attach(struct knod_dev *knodev)
{
	unsigned int nqueues = min(knodev->netdev->num_rx_queues,
				   KNOD_SPSC_MAX);
	struct knod_work_priv *wpriv;
	unsigned int qi;
	size_t size;

	/* Accels without GPU memory simply run without delivery. */
	if (!knodev->accel_ops->alloc_mem)
		return 0;

	spin_lock_init(&knodev->d2h_lock);

	for (qi = 0; qi < nqueues; qi++) {
		wpriv = &knodev->wpriv[qi];
		if (spsc_init(&wpriv->pass_pending,
			      sizeof(struct knod_pass_desc),
			      KNOD_PASS_SLOTS, GFP_KERNEL))
			goto err_free;

		size = (size_t)(wpriv->pass_pending.mask + 1) << PAGE_SHIFT;
		wpriv->pass_stage = knodev->accel_ops->alloc_mem(knodev, size,
						&wpriv->pass_stage_gaddr,
						&wpriv->pass_stage_priv);
		if (!wpriv->pass_stage) {
			pr_err("%s: q%u: no %zu bytes of staging\n", __func__,
			       qi, size);
			wpriv->pass_stage_priv = NULL;
			goto err_free;
		}
	}
	return 0;

err_free:
	do {
		knod_pass_free(knodev, qi);
	} while (qi--);
	return -ENOMEM;
}

/*
 * Drain a queue's pass_pending ring on teardown.  The interface is down so no
 * new copies are submitted; wait for each queued copy to land and count it
 * back without delivering, so neither its RX page nor its staging page is
 * still being written when they are let go of.
 */
static void knod_pass_flush(struct knod_dev *knodev, unsigned int qi)
{
	struct knod_work_priv *wpriv = &knodev->wpriv[qi];
	void *ptrs[KNOD_DEFAULT_PASS_SLOTS];
	unsigned int got, i;

	if (!wpriv->pass_pending.slots)
		return;

	while (spsc_peek(&wpriv->pass_pending, ptrs,
			 KNOD_DEFAULT_PASS_SLOTS, &got) >= 0 && got) {
		for (i = 0; i < got; i++) {
			struct knod_pass_desc *desc = ptrs[i];
			int spins = 1000000;

			while (knodev->accel_ops->d2h_fence && spins-- &&
			       (s32)(knodev->accel_ops->d2h_fence(knodev,
					desc->sdma_idx) - desc->fence_val) < 0)
				cpu_relax();

			WARN_ONCE(knodev->accel_ops->d2h_fence &&
				  (s32)(knodev->accel_ops->d2h_fence(knodev,
					desc->sdma_idx) - desc->fence_val) < 0,
				  "knod: d2h fence timeout on pass flush q%u idx%u\n",
				  qi, desc->sdma_idx);
		}
		spsc_consume(&wpriv->pass_pending, got);
	}
	/* All landed: what the worker had not yet given back, given back. */
	knod_pass_credit(knodev, qi,
			 wpriv->pass_pending.head - wpriv->pass_credited);
	wpriv->pass_credited = wpriv->pass_pending.head;
}

/*
 * Every copy still in flight landed, then each queue's ring and staging
 * buffer freed.  The skbs already delivered own their data, so nothing here
 * waits on the stack.  Idempotent.
 */
static void knod_pass_detach(struct knod_dev *knodev)
{
	unsigned int qi;

	for (qi = 0; qi < KNOD_SPSC_MAX; qi++) {
		knod_pass_flush(knodev, qi);
		knod_pass_free(knodev, qi);
	}
}

static void knod_dmabuf_move_notify(struct dma_buf_attachment *attach)
{
	WARN_ONCE(1, "knod: accel buffer moved under a pinned mapping\n");
}

static const struct dma_buf_attach_ops knod_dmabuf_attach_ops = {
	.allow_peer2peer = true,
	.invalidate_mappings = knod_dmabuf_move_notify,
};

/* The NIC's address for each page of a queue's RX buffer, in page order. */
unsigned int knod_dev_rx_dma_addrs(struct knod_dev *knodev, int queue,
				   u64 *addrs, unsigned int nr)
{
	if (queue >= KNOD_SPSC_MAX || !knodev->bindings[queue])
		return 0;

	return net_devmem_binding_dma_addrs(knodev->bindings[queue], addrs, nr);
}
EXPORT_SYMBOL_GPL(knod_dev_rx_dma_addrs);

/*
 * Map an accel buffer for the NIC to read or write directly, the way the RX
 * binding maps its buffer: a dynamic attachment that allows peer-to-peer, so
 * an exporter holding it in device memory keeps it there instead of moving it
 * to system memory for an importer that cannot reach it.
 */
int knod_nic_map_dmabuf(struct dma_buf *dmabuf, struct device *dev,
			struct knod_nic_map *map)
{
	struct dma_buf_attachment *attach;
	struct sg_table *sgt;
	int err;

	/* The NIC may outlive the accel's own handle on the buffer - its
	 * queue is torn down with the channel, not with the accel - so the
	 * mapping keeps the buffer.
	 */
	get_dma_buf(dmabuf);
	attach = dma_buf_dynamic_attach(dmabuf, dev, &knod_dmabuf_attach_ops,
					NULL);
	if (IS_ERR(attach)) {
		dma_buf_put(dmabuf);
		return PTR_ERR(attach);
	}

	dma_resv_lock(dmabuf->resv, NULL);
	err = dma_buf_pin(attach);
	dma_resv_unlock(dmabuf->resv);
	if (err)
		goto err_detach;

	sgt = dma_buf_map_attachment_unlocked(attach, DMA_BIDIRECTIONAL);
	if (IS_ERR(sgt)) {
		err = PTR_ERR(sgt);
		goto err_unpin;
	}

	map->attach = attach;
	map->sgt = sgt;
	return 0;

err_unpin:
	dma_resv_lock(dmabuf->resv, NULL);
	dma_buf_unpin(attach);
	dma_resv_unlock(dmabuf->resv);
err_detach:
	dma_buf_detach(dmabuf, attach);
	dma_buf_put(dmabuf);
	return err;
}
EXPORT_SYMBOL_GPL(knod_nic_map_dmabuf);

void knod_nic_unmap_dmabuf(struct dma_buf *dmabuf, struct knod_nic_map *map)
{
	if (!map->attach)
		return;

	dma_buf_unmap_attachment_unlocked(map->attach, map->sgt,
					  DMA_BIDIRECTIONAL);
	dma_resv_lock(dmabuf->resv, NULL);
	dma_buf_unpin(map->attach);
	dma_resv_unlock(dmabuf->resv);
	dma_buf_detach(dmabuf, map->attach);
	dma_buf_put(dmabuf);
	map->attach = NULL;
	map->sgt = NULL;
}
EXPORT_SYMBOL_GPL(knod_nic_unmap_dmabuf);

static int knod_dmabuf_attach(struct knod_dev *knodev)
{
	struct net_device *dev = knodev->netdev;
	struct net_devmem_dmabuf_binding *binding;
	struct dma_buf *dmabuf;
	int i, err;

	for (i = 0; i < min(dev->num_rx_queues, KNOD_SPSC_MAX); i++) {
		dmabuf = knodev->wpriv[i].dmabuf;
		if (!dmabuf)
			continue;

		/* The binding owns a dmabuf reference that
		 * __net_devmem_dmabuf_binding_free() drops on unbind, mirroring
		 * the dma_buf_get(fd) in the fd-based net_devmem_bind_dmabuf().
		 * We hand it the BO's dmabuf directly, so take that reference
		 * here -- otherwise the unbind put races the BO free's put and
		 * underflows the dmabuf file refcount.
		 */
		get_dma_buf(dmabuf);
		binding = __net_devmem_binding_create(dev, dev->dev.parent,
						      dmabuf, DMA_BIDIRECTIONAL,
						      PAGE_SHIFT,
						      &knod_dmabuf_attach_ops,
						      NULL);
		if (IS_ERR(binding)) {
			dma_buf_put(dmabuf);
			err = PTR_ERR(binding);
			goto err_unwind;
		}

		err = net_devmem_bind_dmabuf_to_queue_direct(dev, i, binding);
		if (err) {
			net_devmem_unbind_dmabuf_direct(binding);
			goto err_unwind;
		}

		knodev->bindings[i] = binding;
	}

	return 0;

err_unwind:
	while (i-- > 0) {
		if (knodev->bindings[i]) {
			net_devmem_unbind_dmabuf_direct(knodev->bindings[i]);
			knodev->bindings[i] = NULL;
		}
	}
	return err;
}

static void knod_dmabuf_detach(struct knod_dev *knodev)
{
	int i;

	for (i = 0; i < KNOD_SPSC_MAX; i++) {
		if (!knodev->bindings[i])
			continue;

		net_devmem_unbind_dmabuf_direct(knodev->bindings[i]);
		knodev->bindings[i] = NULL;
	}
}

int knod_dev_attach(struct knod_netdev *knetdev, struct knod_accel *accel)
{
	struct knod_dev *knodev;
	int err = -EINVAL, i;

	if (knetdev->status == KNOD_STATUS_USED ||
	    accel->status == KNOD_STATUS_USED) {
		pr_err("knod: %s already attached\n",
		       netdev_name(knetdev->dev));
		return -EINVAL;
	}

	knodev = kzalloc(sizeof(struct knod_dev), GFP_KERNEL);
	if (!knodev)
		return -ENOMEM;

	if (!try_module_get(knetdev->owner)) {
		pr_err("knod: NIC driver for %s is unloading\n",
		       netdev_name(knetdev->dev));
		kfree(knodev);
		return -ENODEV;
	}
	if (!try_module_get(accel->owner)) {
		pr_err("knod: accelerator driver is unloading\n");
		module_put(knetdev->owner);
		kfree(knodev);
		return -ENODEV;
	}

	knetdev->accel = accel;
	knetdev->knodev = knodev;
	accel->knetdev = knetdev;
	accel->knodev = knodev;
	knodev->knetdev = knetdev;
	knodev->accel = accel;
	knodev->netdev = knetdev->dev;
	knodev->accel_ops = accel->accel_ops;
	knodev->nic_ops = knetdev->nic_ops;
	mutex_init(&knodev->lock);

	knodev->stats = alloc_percpu(struct knod_dev_stats);
	if (!knodev->stats) {
		err = -ENOMEM;
		pr_err("knod: failed to allocate stats for %s\n",
		       netdev_name(knetdev->dev));
		goto free_xdev;
	}

	knodev->wpriv = kmalloc_array(KNOD_SPSC_MAX,
				    sizeof(struct knod_work_priv),
				    GFP_KERNEL | __GFP_ZERO);
	if (!knodev->wpriv) {
		pr_err("knod: failed to allocate work priv for %s\n",
		       netdev_name(knetdev->dev));
		err = -ENOMEM;
		goto free_percpu;
	}
	for (i = 0; i < KNOD_SPSC_MAX; i++) {
		knodev->wpriv[i].napi_cpu = -1;
		init_irq_work(&knodev->wpriv[i].napi_kick, knod_napi_kick_work);
	}

	netdev_lock(knodev->netdev);
	err = knodev->nic_ops->attach(knodev);
	if (err) {
		pr_err("knod: NIC attach failed on %s: %d\n",
		       netdev_name(knetdev->dev), err);
		goto unlock;
	}

	err = knodev->accel_ops->attach(knodev);
	if (err) {
		pr_err("knod: accelerator attach failed on %s: %d\n",
		       netdev_name(knetdev->dev), err);
		goto nic_detach;
	}

	err = knod_pass_attach(knodev);
	if (err) {
		pr_err("%s: knod_pass_attach failed (%d)\n", __func__, err);
		goto accel_detach;
	}

	err = knod_dmabuf_attach(knodev);
	if (err) {
		err = -ENOMEM;
		pr_err("knod: dmabuf attach failed on %s\n",
		       netdev_name(knetdev->dev));
		goto accel_detach;
	}

	pr_info("knod: %s attached to accel %d\n",
		netdev_name(knodev->netdev), accel->id);
	list_add(&knodev->list, &knod_dev_list);
	knetdev->status = KNOD_STATUS_USED;
	accel->status = KNOD_STATUS_USED;

	if (knodev->accel_ops->xdp_ops && knodev->accel_ops->xdp_ops->init) {
		err = knodev->accel_ops->xdp_ops->init(knodev);
		if (err) {
			pr_err("knod: XDP init failed on %s\n",
			       netdev_name(knetdev->dev));
			goto xdp_err;
		}
	}

	/*
	 * The BPF offload allocates its GPU resources and
	 * advertise their netdev capabilities only when the feature is
	 * selected via knod_accel_feature_set(), not at attach.
	 */
	netdev_unlock(knodev->netdev);

	if (knodev->accel_ops->mp_map) {
		err = knodev->accel_ops->mp_map(knodev);
		if (err) {
			pr_err("knod: mp_map failed (%d)\n", err);
			goto dmabuf_detach;
		}
	}
	if (knodev->accel_ops->attached)
		knodev->accel_ops->attached(knodev);

	return err;

dmabuf_detach:
	netdev_lock(knodev->netdev);
xdp_err:
	list_del(&knodev->list);
	knetdev->status = KNOD_STATUS_FREE;
	accel->status = KNOD_STATUS_FREE;
	knod_dmabuf_detach(knodev);
accel_detach:
	knod_pass_detach(knodev);
	knodev->accel_ops->detach(knodev);
nic_detach:
	knodev->nic_ops->detach(knodev);
unlock:
	netdev_unlock(knodev->netdev);
	kfree(knodev->wpriv);
free_percpu:
	free_percpu(knodev->stats);
free_xdev:
	/* Drop the accel<->knetdev<->knodev links set above before freeing
	 * knodev, or a reader (e.g. knod_default_worker via accel->knodev)
	 * dereferences a dangling pointer after a failed attach.
	 */
	accel->knodev = NULL;
	accel->knetdev = NULL;
	knetdev->knodev = NULL;
	knetdev->accel = NULL;
	module_put(accel->owner);
	module_put(knetdev->owner);
	kfree(knodev);
	return err;
}

int knod_dev_detach(struct knod_dev *knodev)
{
	struct knod_accel *accel = knodev->accel;
	struct knod_netdev *knetdev = knodev->knetdev;
	int i;

	if (netif_running(knodev->netdev)) {
		pr_err("knod_dev: interface is up\n");
		return -EINVAL;
	}

	netdev_lock(knodev->netdev);
	/*
	 * pre_detach() runs knod_feature_stop()+knod_feature_deactivate(),
	 * which tears down whatever feature is active and frees its
	 * resources, so no per-feature teardown is needed here.
	 */
	if (knodev->accel_ops->pre_detach)
		knodev->accel_ops->pre_detach(knodev);
	list_del(&knodev->list);
	knod_dmabuf_detach(knodev);
	knod_pass_detach(knodev);
	knodev->nic_ops->detach(knodev);
	knodev->accel_ops->detach(knodev);
	netdev_unlock(knodev->netdev);
	knetdev->status = KNOD_STATUS_FREE;
	knetdev->accel = NULL;
	knetdev->knodev = NULL;
	accel->knetdev = NULL;
	accel->knodev = NULL;
	accel->status = KNOD_STATUS_FREE;
	for (i = 0; i < KNOD_SPSC_MAX; i++)
		irq_work_sync(&knodev->wpriv[i].napi_kick);
	kfree(knodev->wpriv);
	free_percpu(knodev->stats);
	kfree(knodev);

	module_put(accel->owner);
	module_put(knetdev->owner);
	return 0;
}

static int __init knod_dev_init(void)
{
	return genl_register_family(&knod_nl_family);
}

core_initcall(knod_dev_init);
