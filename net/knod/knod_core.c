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
#include <net/page_pool/helpers.h>

#include "knod.h"

DEFINE_MUTEX(knod_lock);
LIST_HEAD(knod_dev_list);
/* knod_dev_list for the xfrm proxy, which runs under no knod lock. */
DEFINE_STATIC_SRCU(knod_dev_srcu);
EXPORT_SYMBOL_GPL(knod_dev_list);
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
		if (READ_ONCE(knodev->wpriv[qi].pass_buf) &&
		    READ_ONCE(knodev->wpriv[qi].pass_pc) !=
		    READ_ONCE(knodev->wpriv[qi].pass_cc))
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

/*
 * An skb around the packet at @off in @page, a page_pool page the skb now
 * holds and gives back to its pool when freed: built in it when the shared
 * info fits after the packet, else the headers copied out and the rest a
 * fragment.  NULL, and the page given back, when there is no skb.
 */
#define KNOD_PASS_HDR	256

static struct sk_buff *knod_pass_skb(struct napi_struct *napi,
				     struct page *page, u16 off, u16 len)
{
	u32 size = PAGE_SIZE << page->pp->p.order;
	void *va = page_address(page);
	struct sk_buff *skb;
	u16 hdr;

	page_pool_dma_sync_for_cpu(page->pp, page, off, len);
	if (off + len + SKB_DATA_ALIGN(sizeof(struct skb_shared_info)) <=
	    size) {
		skb = napi_build_skb(va, size);
		if (!skb)
			goto drop;
		skb_mark_for_recycle(skb);
		skb_reserve(skb, off);
		__skb_put(skb, len);
		return skb;
	}
	hdr = min_t(u16, len, KNOD_PASS_HDR);
	skb = napi_alloc_skb(napi, hdr);
	if (!skb)
		goto drop;
	skb_mark_for_recycle(skb);
	skb_put_data(skb, va + off, hdr);
	if (len > hdr)
		skb_add_rx_frag(skb, 0, page, off + hdr, len - hdr, size);
	else
		page_pool_put_full_page(page->pp, page, true);
	return skb;
drop:
	page_pool_put_full_page(page->pp, page, true);
	return NULL;
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
	/* A packet the accel's ICV check failed: tampered with, or the
	 * accel's decrypting is wrong.
	 */
	if (v & KNOD_PASS_IPSEC_FAIL)
		net_warn_ratelimited("knod: %s: ICV failed, SPI %08x, %u bytes\n",
				     netdev_name(skb->dev), be32_to_cpu(spi),
				     skb->len);
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
		if (knodev->netdev == dev || READ_ONCE(knodev->upper) == dev)
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

static unsigned int knod_ipsec_tx_sw_max = 128;
module_param(knod_ipsec_tx_sw_max, uint, 0644);
MODULE_PARM_DESC(knod_ipsec_tx_sw_max,
		 "Outbound IPsec packets this long or shorter, ACKs, are sealed by the CPU at once, not queued for the accel (0: none)");

/*
 * Outbound: software ESP until the accel sends packets itself, and for a
 * packet small enough that the accel's queueing costs it more than the
 * sealing does - a TCP receiver's ACKs, which the sender waits for.
 */
static bool knod_ipsec_xdo_offload_ok(struct sk_buff *skb,
				      struct xfrm_state *x)
{
	struct knod_accel_ipsec_ops *ops;
	bool ok;
	int idx;

	if (skb->len <= READ_ONCE(knod_ipsec_tx_sw_max))
		return false;
	idx = srcu_read_lock(&knod_dev_srcu);
	ops = knod_ipsec_ops(knod_ipsec_find_xdev(x->xso.dev));
	ok = ops && ops->xmit;
	srcu_read_unlock(&knod_dev_srcu, idx);
	return ok;
}

const struct xfrmdev_ops knod_ipsec_xfrmdev_ops = {
	.xdo_dev_state_add	= knod_ipsec_xdo_state_add,
	.xdo_dev_state_delete	= knod_ipsec_xdo_state_delete,
	.xdo_dev_state_free	= knod_ipsec_xdo_state_free,
	.xdo_dev_offload_ok	= knod_ipsec_xdo_offload_ok,
	.xdo_dev_xmit		= knod_ipsec_xdo_xmit,
};

#else
static void knod_ipsec_rx(struct knod_dev *knodev, struct sk_buff *skb, u64 v)
{
}

void knod_ipsec_sa_set(struct knod_dev *knodev, u32 slot, struct xfrm_state *x)
{
}
EXPORT_SYMBOL(knod_ipsec_sa_set);

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
 * Deliver what the accel put in pages of the stack's for a queue: an skb
 * around each page, then the count of the entries taken back to the accel,
 * which may fill them again.  Runs on the queue's NAPI, the one consumer.
 * Returns the entries taken, up to @budget.
 */
int knod_d2h_drain(struct knod_dev *knodev, int napi_index,
		   struct napi_struct *napi, int budget)
{
	struct knod_work_priv *wpriv;
	struct knod_pass_buf *buf, *b;
	struct net_device *dev;
	u32 pc, cc;
	int n = 0;

	if (napi_index < 0 || napi_index >= KNOD_SPSC_MAX)
		return 0;
	/* Up the knod link over the NIC, if there is one. */
	dev = knod_dev_stack(knodev);
	wpriv = &knodev->wpriv[napi_index];
	buf = READ_ONCE(wpriv->pass_buf);
	if (!buf)
		return 0;

	cc = wpriv->pass_cc;
	/* The entries and their pages before the count that says they are
	 * there.
	 */
	pc = smp_load_acquire(&wpriv->pass_pc);
	while (cc != pc && n < budget) {
		struct sk_buff *skb;
		struct page *page;
		u16 off, len;
		u64 v;

		b = &buf[cc++ & wpriv->pass_mask];
		n++;
		page = b->page;
		v = b->v;
		b->page = NULL;
		if (!page)
			continue;
		off = v >> 32 & 0xffff;
		len = v >> 48;
		skb = knod_pass_skb(napi, page, off, len);
		if (!skb)
			continue;
		skb->protocol = eth_type_trans(skb, dev);
		/* The checksums the NIC checked, not summed again: not for a
		 * packet the accel decrypted, which they were taken over.
		 */
		if (v & KNOD_PASS_IPSEC) {
			knod_ipsec_rx(knodev, skb, v);
			/* ...but the inner one the accel checked once it had
			 * decrypted it: the first checksum the stack finds,
			 * ESP having none.
			 */
			if ((v & KNOD_PASS_IPSEC_CSUM) &&
			    !(v & KNOD_PASS_IPSEC_FAIL) &&
			    (dev->features & NETIF_F_RXCSUM))
				skb->ip_summed = CHECKSUM_UNNECESSARY;
		} else if ((v & KNOD_PASS_CSUM_OK) &&
			 (dev->features & NETIF_F_RXCSUM)) {
			skb->ip_summed = CHECKSUM_UNNECESSARY;
			skb->csum_level = !!(v & KNOD_PASS_CSUM_INNER);
		}
		/* Coalesced with the rest of its flow, as the NIC's own
		 * receive path would.
		 */
		skb_record_rx_queue(skb, napi_index);
		if (dev != knodev->netdev)
			dev_sw_netstats_rx_add(dev, skb->len);
		napi_gro_receive(napi, skb);
		this_cpu_inc(knodev->stats->d2h_copied);
	}
	/* Done with those entries: the accel may fill them again. */
	smp_store_release(&wpriv->pass_cc, cc);
	/* More than the budget: poll again.  A NIC's poll need not look at
	 * what this returns, and nothing else kicks for entries already seen.
	 */
	if (cc != pc)
		knod_napi_kick(wpriv);
	return n;
}
EXPORT_SYMBOL(knod_d2h_drain);

/*
 * What a queue's PASS entries still hold once its NAPI cannot run, let go
 * of undelivered: their pages back to their pools, the entries the
 * accel's again.
 */
static void knod_pass_flush(struct knod_dev *knodev, unsigned int qi)
{
	struct knod_work_priv *wpriv = &knodev->wpriv[qi];
	struct knod_pass_buf *buf = READ_ONCE(wpriv->pass_buf), *b;
	u32 cc, pc;

	if (!buf)
		return;
	cc = wpriv->pass_cc;
	pc = smp_load_acquire(&wpriv->pass_pc);
	while (cc != pc) {
		b = &buf[cc++ & wpriv->pass_mask];
		if (b->page)
			page_pool_put_full_page(b->page->pp, b->page, false);
		b->page = NULL;
	}
	smp_store_release(&wpriv->pass_cc, cc);
}

/* What every queue's PASS entries still hold, let go of.  Idempotent. */
static void knod_pass_detach(struct knod_dev *knodev)
{
	unsigned int qi;

	for (qi = 0; qi < KNOD_SPSC_MAX; qi++)
		knod_pass_flush(knodev, qi);
}

/*
 * The accel onto NIC @dev's queues, for the knod link @upper over it: all the
 * NIC need do is hand its queues over, which the accel binds them for.
 */
int knod_dev_attach(struct net_device *dev, struct knod_accel *accel,
		    struct net_device *upper)
{
	struct knod_dev *knodev;
	int err, i;

	if (knod_dev_lookup(dev) || accel->status == KNOD_STATUS_USED) {
		pr_err("knod: %s already attached\n", netdev_name(dev));
		return -EBUSY;
	}

	knodev = kzalloc(sizeof(struct knod_dev), GFP_KERNEL);
	if (!knodev)
		return -ENOMEM;
	if (!try_module_get(accel->owner)) {
		pr_err("knod: accelerator driver is unloading\n");
		kfree(knodev);
		return -ENODEV;
	}

	accel->knodev = knodev;
	knodev->accel = accel;
	knodev->netdev = dev;
	knodev->upper = upper;
	knodev->accel_ops = accel->accel_ops;
	mutex_init(&knodev->lock);

	err = -ENOMEM;
	knodev->stats = alloc_percpu(struct knod_dev_stats);
	if (!knodev->stats)
		goto free_xdev;
	knodev->wpriv = kmalloc_array(KNOD_SPSC_MAX,
				      sizeof(struct knod_work_priv),
				      GFP_KERNEL | __GFP_ZERO);
	if (!knodev->wpriv)
		goto free_percpu;
	for (i = 0; i < KNOD_SPSC_MAX; i++) {
		knodev->wpriv[i].napi_cpu = -1;
		init_irq_work(&knodev->wpriv[i].napi_kick, knod_napi_kick_work);
	}

	netdev_lock(dev);
	err = knodev->accel_ops->attach(knodev);
	if (err) {
		pr_err("knod: accelerator attach failed on %s: %d\n",
		       netdev_name(dev), err);
		goto unlock;
	}

	pr_info("knod: %s attached to accel %d\n", netdev_name(dev), accel->id);
	list_add_rcu(&knodev->list, &knod_dev_list);
	accel->status = KNOD_STATUS_USED;

	if (knodev->accel_ops->xdp_ops && knodev->accel_ops->xdp_ops->init) {
		err = knodev->accel_ops->xdp_ops->init(knodev);
		if (err) {
			pr_err("knod: XDP init failed on %s\n", netdev_name(dev));
			goto list_del;
		}
	}
	/*
	 * The BPF offload allocates its GPU resources and advertises their
	 * netdev capabilities only when the feature is selected via
	 * knod_accel_feature_set(), not at attach.
	 */
	netdev_unlock(dev);

	if (knodev->accel_ops->mp_map) {
		err = knodev->accel_ops->mp_map(knodev);
		if (err) {
			pr_err("knod: mp_map failed (%d)\n", err);
			netdev_lock(dev);
			goto list_del;
		}
	}
	if (knodev->accel_ops->attached)
		knodev->accel_ops->attached(knodev);
	return 0;

list_del:
	knod_dev_list_del(knodev);
	accel->status = KNOD_STATUS_FREE;
	knod_pass_detach(knodev);
	knodev->accel_ops->detach(knodev);
unlock:
	netdev_unlock(dev);
	kfree(knodev->wpriv);
free_percpu:
	free_percpu(knodev->stats);
free_xdev:
	/* Unlinked before knodev goes, or a reader (e.g. knod_default_worker
	 * via accel->knodev) dereferences a dangling pointer.
	 */
	accel->knodev = NULL;
	module_put(accel->owner);
	kfree(knodev);
	return err;
}

int knod_dev_detach(struct knod_dev *knodev)
{
	struct knod_accel *accel = knodev->accel;
	int i;

	if (netif_running(knodev->netdev)) {
		pr_err("knod_dev: interface is up\n");
		return -EINVAL;
	}

	/*
	 * pre_detach() runs knod_feature_stop()+knod_feature_deactivate(),
	 * which tears down whatever feature is active and frees its
	 * resources, so no per-feature teardown is needed here.  Outside the
	 * netdev lock, as attach's attached() is: it unbinds the NIC's
	 * queues, which takes that lock.
	 */
	if (knodev->accel_ops->pre_detach)
		knodev->accel_ops->pre_detach(knodev);
	netdev_lock(knodev->netdev);
	knod_dev_list_del(knodev);
	knod_pass_detach(knodev);
	knodev->accel_ops->detach(knodev);
	netdev_unlock(knodev->netdev);
	accel->knodev = NULL;
	accel->status = KNOD_STATUS_FREE;
	for (i = 0; i < KNOD_SPSC_MAX; i++)
		irq_work_sync(&knodev->wpriv[i].napi_kick);
	kfree(knodev->wpriv);
	free_percpu(knodev->stats);
	kfree(knodev);
	module_put(accel->owner);
	return 0;
}

static int __init knod_dev_init(void)
{
	return genl_register_family(&knod_nl_family);
}

core_initcall(knod_dev_init);
