// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (c) 2021 Taehee Yoo <ap420073@gmail.com>
 * Copyright (c) 2021 Hoyeon Lee <hoyeon.rhee@gmail.com>
 */

#include <net/knod.h>
#include <net/netdev_queues.h>
#include <net/spsc_ring.h>
#include <linux/dma-buf.h>
#include <linux/dma-resv.h>
#include <net/devmem.h>
#include <net/xfrm.h>
#include <linux/ip.h>
#include <linux/srcu.h>

#include "knod.h"

DEFINE_MUTEX(knod_lock);
LIST_HEAD(knod_dev_list);
/* knod_dev_list for the xfrm proxy, which runs under no knod lock. */
DEFINE_STATIC_SRCU(knod_dev_srcu);
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

/* Off the list, and past any xfrm proxy call that found it there. */
static void knod_dev_list_del(struct knod_dev *knodev)
{
	list_del_rcu(&knodev->list);
	synchronize_srcu(&knod_dev_srcu);
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
	/* PASS entries left while the queues were being rebuilt wait for a
	 * drain nothing else would schedule.
	 */
	for (qi = 0; qi < KNOD_SPSC_MAX; qi++)
		if (READ_ONCE(knodev->wpriv[qi].pass_ring) &&
		    READ_ONCE(*knodev->wpriv[qi].pass_pc) !=
		    READ_ONCE(*knodev->wpriv[qi].pass_cc))
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

/* Let go of what the PASS rings still hold.  The NIC calls this once its
 * NAPI can no longer run the drain.
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

#if IS_ENABLED(CONFIG_XFRM_OFFLOAD)
/*
 * An ESP packet the accel decrypted in place for SA slot @v's: the xfrm state
 * it is for on its secpath, crypto done, for esp_input() to take on from.
 * A slot taken by another SA since - whose SPI the packet does not carry -
 * or let go of, and the packet goes up as it came.
 */
static void knod_ipsec_rx(struct knod_dev *knodev, struct sk_buff *skb, u64 v)
{
	const struct iphdr *iph = (const struct iphdr *)skb->data;
	struct xfrm_offload *xo;
	struct xfrm_state *x;
	struct sec_path *sp;
	__be32 spi;

	if (skb->protocol != htons(ETH_P_IP) ||
	    !pskb_may_pull(skb, sizeof(*iph)) ||
	    !pskb_may_pull(skb, iph->ihl * 4 + sizeof(spi)))
		return;
	iph = (const struct iphdr *)skb->data;
	spi = *(__be32 *)(skb->data + iph->ihl * 4);

	rcu_read_lock();
	x = rcu_dereference(knodev->ipsec_sa[KNOD_PASS_IPSEC_SA(v)]);
	if (!x || x->id.spi != spi || !refcount_inc_not_zero(&x->refcnt)) {
		rcu_read_unlock();
		return;
	}
	rcu_read_unlock();

	sp = secpath_set(skb);
	if (!sp || sp->len == XFRM_MAX_DEPTH) {
		xfrm_state_put(x);
		return;
	}
	sp->xvec[sp->len++] = x;
	sp->olen++;
	xo = xfrm_offload(skb);
	xo->flags = CRYPTO_DONE;
	if (!(v & KNOD_PASS_IPSEC_FAIL))
		xo->status = CRYPTO_SUCCESS;
	else if (x->props.mode == XFRM_MODE_TUNNEL)
		xo->status = CRYPTO_TUNNEL_ESP_AUTH_FAILED;
	else
		xo->status = CRYPTO_TRANSPORT_ESP_AUTH_FAILED;
}

/* SA slot @slot is @x's, or nobody's for NULL. */
void knod_ipsec_sa_set(struct knod_dev *knodev, u32 slot, struct xfrm_state *x)
{
	if (slot < KNOD_IPSEC_SA_MAX)
		rcu_assign_pointer(knodev->ipsec_sa[slot], x);
}
EXPORT_SYMBOL(knod_ipsec_sa_set);

/* Under knod_dev_srcu. */
static struct knod_dev *knod_ipsec_find_xdev(struct net_device *dev)
{
	struct knod_dev *knodev;

	list_for_each_entry_srcu(knodev, &knod_dev_list, list,
				 srcu_read_lock_held(&knod_dev_srcu))
		if (knodev->netdev == dev)
			return knodev;
	return NULL;
}

static struct knod_accel_ipsec_ops *knod_ipsec_ops(struct knod_dev *knodev)
{
	return knodev ? knodev->accel_ops->ipsec_ops : NULL;
}

static int knod_ipsec_xdo_state_add(struct net_device *dev,
				    struct xfrm_state *x,
				    struct netlink_ext_ack *extack)
{
	struct knod_accel_ipsec_ops *ops;
	struct knod_dev *knodev;
	int err, idx;

	idx = srcu_read_lock(&knod_dev_srcu);
	knodev = knod_ipsec_find_xdev(dev);
	ops = knod_ipsec_ops(knodev);
	if (ops) {
		err = ops->state_add(knodev, x, extack);
	} else {
		NL_SET_ERR_MSG(extack, "knod: no accel runs IPsec here");
		err = -EOPNOTSUPP;
	}
	srcu_read_unlock(&knod_dev_srcu, idx);
	return err;
}

static void knod_ipsec_xdo_state_delete(struct net_device *dev,
					struct xfrm_state *x)
{
	struct knod_accel_ipsec_ops *ops;
	struct knod_dev *knodev;
	int idx;

	idx = srcu_read_lock(&knod_dev_srcu);
	knodev = knod_ipsec_find_xdev(dev);
	ops = knod_ipsec_ops(knodev);
	if (ops)
		ops->state_delete(knodev, x);
	srcu_read_unlock(&knod_dev_srcu, idx);
}

static void knod_ipsec_xdo_state_free(struct net_device *dev,
				      struct xfrm_state *x)
{
	struct knod_accel_ipsec_ops *ops;
	struct knod_dev *knodev;
	int idx;

	idx = srcu_read_lock(&knod_dev_srcu);
	knodev = knod_ipsec_find_xdev(dev);
	ops = knod_ipsec_ops(knodev);
	if (ops)
		ops->state_free(knodev, x);
	srcu_read_unlock(&knod_dev_srcu, idx);
}

/* Under the TX queue's qdisc: the packet to the accel to send, if it would. */
static bool knod_ipsec_xdo_xmit(struct sk_buff *skb, struct xfrm_state *x)
{
	struct knod_accel_ipsec_ops *ops;
	struct knod_dev *knodev;
	bool taken = false;
	int idx;

	idx = srcu_read_lock(&knod_dev_srcu);
	knodev = knod_ipsec_find_xdev(x->xso.dev);
	ops = knod_ipsec_ops(knodev);
	if (ops && ops->xmit)
		taken = ops->xmit(knodev, skb, x);
	srcu_read_unlock(&knod_dev_srcu, idx);
	return taken;
}

/* Outbound: software ESP until the accel sends packets itself. */
static bool knod_ipsec_xdo_offload_ok(struct sk_buff *skb,
				      struct xfrm_state *x)
{
	struct knod_accel_ipsec_ops *ops;
	bool ok;
	int idx;

	idx = srcu_read_lock(&knod_dev_srcu);
	ops = knod_ipsec_ops(knod_ipsec_find_xdev(x->xso.dev));
	ok = ops && ops->xmit;
	srcu_read_unlock(&knod_dev_srcu, idx);
	return ok;
}

static const struct xfrmdev_ops knod_ipsec_xfrmdev_ops = {
	.xdo_dev_state_add	= knod_ipsec_xdo_state_add,
	.xdo_dev_state_delete	= knod_ipsec_xdo_state_delete,
	.xdo_dev_state_free	= knod_ipsec_xdo_state_free,
	.xdo_dev_offload_ok	= knod_ipsec_xdo_offload_ok,
	.xdo_dev_xmit		= knod_ipsec_xdo_xmit,
};

/* The NIC's xfrm states to the accel, from now on. */
int knod_ipsec_attach(struct knod_dev *knodev)
{
	struct net_device *dev = knodev->netdev;

	if (!knodev->accel_ops->ipsec_ops)
		return -EOPNOTSUPP;
	knodev->ipsec_orig_xfrmdev_ops = dev->xfrmdev_ops;
	knodev->ipsec_added_hw_esp = !(dev->features & NETIF_F_HW_ESP);
	dev->xfrmdev_ops = &knod_ipsec_xfrmdev_ops;
	dev->features |= NETIF_F_HW_ESP;
	dev->hw_enc_features |= NETIF_F_HW_ESP;
	return 0;
}
EXPORT_SYMBOL(knod_ipsec_attach);

void knod_ipsec_detach(struct knod_dev *knodev)
{
	struct net_device *dev = knodev->netdev;

	if (dev->xfrmdev_ops != &knod_ipsec_xfrmdev_ops)
		return;
	if (knodev->ipsec_added_hw_esp) {
		dev->features &= ~NETIF_F_HW_ESP;
		dev->hw_enc_features &= ~NETIF_F_HW_ESP;
	}
	dev->xfrmdev_ops = knodev->ipsec_orig_xfrmdev_ops;
}
EXPORT_SYMBOL(knod_ipsec_detach);
#else
static void knod_ipsec_rx(struct knod_dev *knodev, struct sk_buff *skb, u64 v)
{
}

void knod_ipsec_sa_set(struct knod_dev *knodev, u32 slot, struct xfrm_state *x)
{
}
EXPORT_SYMBOL(knod_ipsec_sa_set);

int knod_ipsec_attach(struct knod_dev *knodev)
{
	return -EOPNOTSUPP;
}
EXPORT_SYMBOL(knod_ipsec_attach);

void knod_ipsec_detach(struct knod_dev *knodev)
{
}
EXPORT_SYMBOL(knod_ipsec_detach);
#endif

/* The accel put PASS entries on queue @napi_index's ring: its NAPI, to
 * deliver them.
 */
void knod_dev_pass_kick(struct knod_dev *knodev, int napi_index)
{
	if (napi_index >= 0 && napi_index < KNOD_SPSC_MAX)
		knod_napi_kick(&knodev->wpriv[napi_index]);
}
EXPORT_SYMBOL(knod_dev_pass_kick);

/*
 * Deliver what the accel copied out to a queue's staging pages: each entry of
 * its PASS ring an skb copied out of its page, then the count of the ones done
 * back to the accel, which frees their pages.  Runs on the queue's NAPI, the
 * ring's one consumer.  Returns the entries taken, up to @budget.
 */
int knod_d2h_drain(struct knod_dev *knodev, int napi_index,
		   struct napi_struct *napi, int budget)
{
	struct knod_work_priv *wpriv;
	const u64 *ring;
	u32 pc, cc, slot;
	int n = 0;

	if (napi_index < 0 || napi_index >= KNOD_SPSC_MAX)
		return 0;
	wpriv = &knodev->wpriv[napi_index];
	ring = READ_ONCE(wpriv->pass_ring);
	if (!ring || !wpriv->pass_stage)
		return 0;

	cc = READ_ONCE(*wpriv->pass_cc);
	/* The entries and their pages before the count that says they are
	 * there.
	 */
	pc = smp_load_acquire(wpriv->pass_pc);
	while (cc != pc && n < budget) {
		struct sk_buff *skb;
		u16 off, len;
		u64 v;

		slot = cc++ & wpriv->pass_mask;
		n++;
		v = READ_ONCE(ring[slot]);
		off = v >> 32 & 0xffff;
		len = v >> 48;
		if (len < ETH_HLEN || off + len > PAGE_SIZE)
			continue;
		skb = knod_pass_skb(wpriv->pass_stage +
				    ((size_t)slot << PAGE_SHIFT), off, len,
				    true);
		if (!skb)
			continue;
		skb->protocol = eth_type_trans(skb, knodev->netdev);
		/* The checksums the NIC checked, not summed again: not for a
		 * packet the accel decrypted, which they were taken over.
		 */
		if (v & KNOD_PASS_IPSEC) {
			knod_ipsec_rx(knodev, skb, v);
		} else if ((v & KNOD_PASS_CSUM_OK) &&
			 (knodev->netdev->features & NETIF_F_RXCSUM)) {
			skb->ip_summed = CHECKSUM_UNNECESSARY;
			skb->csum_level = !!(v & KNOD_PASS_CSUM_INNER);
		}
		/* Coalesced with the rest of its flow, as the NIC's own
		 * receive path would.
		 */
		skb_record_rx_queue(skb, napi_index);
		napi_gro_receive(napi, skb);
		this_cpu_inc(knodev->stats->d2h_copied);
	}
	/* Done with those pages: the accel may copy into them again. */
	smp_store_release(wpriv->pass_cc, cc);
	/* More than the budget: poll again.  A NIC's poll need not look at
	 * what this returns, and nothing else kicks for entries already seen.
	 */
	if (cc != pc)
		knod_napi_kick(wpriv);
	return n;
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

	if (wpriv->pass_stage_priv)
		knodev->accel_ops->free_mem(knodev, wpriv->pass_stage_priv);
	wpriv->pass_stage = NULL;
	wpriv->pass_stage_gaddr = 0;
	wpriv->pass_stage_priv = NULL;
}

/*
 * Per RX queue, a GTT buffer of staging pages the accel copies PASS packets
 * to.  Each queue's buffer is its own: one for all of them is more GTT than a
 * single allocation is given.
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

	for (qi = 0; qi < nqueues; qi++) {
		wpriv = &knodev->wpriv[qi];
		size = (size_t)KNOD_PASS_SLOTS << PAGE_SHIFT;
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
 * What a queue's PASS ring still holds on teardown, let go of undelivered:
 * the accel copies no more, and the skbs already delivered own their data.
 */
static void knod_pass_flush(struct knod_dev *knodev, unsigned int qi)
{
	struct knod_work_priv *wpriv = &knodev->wpriv[qi];

	/* All of it done, as the drain would count it. */
	if (READ_ONCE(wpriv->pass_ring))
		smp_store_release(wpriv->pass_cc, READ_ONCE(*wpriv->pass_pc));
}

/* Each queue's staging buffer freed, its ring let go of first.  Idempotent. */
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

/* A NIC that hands its queues over gives the engine the RX buffers with
 * them (knod_gda_bind()): nothing to bind here, and a memory provider would
 * keep it from handing them over.
 */
static bool knod_dev_hands_queues(struct knod_dev *knodev)
{
	const struct netdev_queue_mgmt_ops *qops =
		knodev->netdev->queue_mgmt_ops;

	return qops && qops->ndo_dmq_query;
}

static int knod_dmabuf_attach(struct knod_dev *knodev)
{
	struct net_device *dev = knodev->netdev;
	struct net_devmem_dmabuf_binding *binding;
	struct dma_buf *dmabuf;
	int i, err;

	if (knod_dev_hands_queues(knodev))
		return 0;
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
	list_add_rcu(&knodev->list, &knod_dev_list);
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
	knod_dev_list_del(knodev);
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
	knod_dev_list_del(knodev);
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
