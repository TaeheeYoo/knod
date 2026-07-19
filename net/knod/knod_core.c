// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (c) 2021 Taehee Yoo <ap420073@gmail.com>
 * Copyright (c) 2021 Hoyeon Lee <hoyeon.rhee@gmail.com>
 */

#include <net/knod.h>
#include <net/spsc_ring.h>
#include <net/page_pool/types.h>
#include <net/page_pool/helpers.h>
#include <net/page_pool/memory_provider.h>
#include <net/xfrm.h>
#include <linux/genalloc.h>
#include <trace/events/page_pool.h>
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

void knod_dev_start(struct knod_dev *knodev)
{
	/* Interface up: start the active feature's worker. */
	knodev->started = true;
	if (knodev->accel_ops->dev_start)
		knodev->accel_ops->dev_start(knodev);
}
EXPORT_SYMBOL(knod_dev_start);

void knod_dev_stop(struct knod_dev *knodev)
{
	/* Interface down: stop the worker + drain the GPU in-flight. */
	if (knodev->accel_ops->dev_stop)
		knodev->accel_ops->dev_stop(knodev);
	knodev->started = false;
}
EXPORT_SYMBOL(knod_dev_stop);

int knod_dev_xdp_install(struct knod_dev *knodev, struct netdev_bpf *xdp)
{
	if (!knodev->accel_ops->xdp_ops ||
	    !knodev->accel_ops->xdp_ops->xdp_install)
		return -EOPNOTSUPP;
	return knodev->accel_ops->xdp_ops->xdp_install(knodev, xdp);
}
EXPORT_SYMBOL(knod_dev_xdp_install);

void knod_dev_get_stats64(struct knod_dev *knodev,
			  struct rtnl_link_stats64 *stats)
{
	struct knod_dev_stats *p;
	u32 tx_dropped = 0, tx_errors = 0;
	u64 tx_packets, tx_bytes;
	unsigned int start;
	int i;

	for_each_possible_cpu(i) {
		p = per_cpu_ptr(knodev->stats, i);
		do {
			start = u64_stats_fetch_begin(&p->syncp);
			tx_packets      = u64_stats_read(&p->tx_packets);
			tx_bytes        = u64_stats_read(&p->tx_bytes);
		} while (u64_stats_fetch_retry(&p->syncp, start));

		stats->tx_packets       += tx_packets;
		stats->tx_bytes         += tx_bytes;
		tx_dropped      += READ_ONCE(p->tx_dropped);
		tx_errors	+= READ_ONCE(p->tx_errors);
	}
	stats->tx_dropped       += tx_dropped;
	stats->tx_errors	+= tx_errors;
}
EXPORT_SYMBOL(knod_dev_get_stats64);

/*
 * Wrap a delivery-pool page as a zero-copy head_frag skb: the packet sits at
 * @off (preserved headroom) for @len bytes.  Building it linear keeps
 * skb->data on the packet so callers can edit headers in place.  The page
 * recycles to @pool when the skb is freed.  On oversize or alloc failure the
 * page is returned to @pool and NULL is returned.  @napi selects the NAPI skb
 * cache; callers outside softirq pass false.
 */
struct sk_buff *knod_pass_build_skb(netmem_ref netmem, u16 off, u16 len,
				    struct page_pool *pool, bool napi)
{
	struct page *pg = netmem_to_page(netmem);
	struct sk_buff *skb;

	/* Must fit alongside skb_shared_info at the page tail; MTU is capped
	 * below this, so drop the rare oversized outlier.
	 */
	if (off + len > SKB_WITH_OVERHEAD(PAGE_SIZE)) {
		if (pool)
			page_pool_put_full_netmem(pool, netmem, false);
		return NULL;
	}

	if (napi)
		skb = napi_build_skb(page_address(pg), PAGE_SIZE);
	else
		skb = build_skb(page_address(pg), PAGE_SIZE);
	if (unlikely(!skb)) {
		if (pool)
			page_pool_put_full_netmem(pool, netmem, false);
		return NULL;
	}

	skb_mark_for_recycle(skb);
	skb_reserve(skb, off);
	skb_put(skb, len);
	return skb;
}
EXPORT_SYMBOL(knod_pass_build_skb);

/*
 * Device->host copy: the NIC DD hands the PASS bds it accumulated during its
 * single act traversal.  Allocate a delivery page per packet, issue the accel
 * SDMA (GPU -> page) asynchronously, and queue a descriptor on the per-queue
 * pending ring tagged with this batch's fence; knod_d2h_drain delivers them
 * once the fence lands and recycles the source.  Sources that cannot be queued
 * (bad len / ring full / pool empty) are recycled here.  Returns the count
 * queued.  Producer and the drain consumer run on the same per-queue NAPI, so
 * the ring is single-threaded; @d2h_lock only guards the shared SDMA submit.
 */
int knod_d2h_copy(struct knod_dev *knodev, int napi_index,
		  struct spsc_pass_bd *bds, int cnt)
{
	struct knod_accel_ops *ops = knodev->accel_ops;
	struct knod_work_priv *wpriv;
	struct page_pool *pool;
	bool submitted = false;
	int i, produced = 0;

	if (napi_index < 0 || napi_index >= KNOD_SPSC_MAX || !ops->d2h_submit)
		goto drop_all;
	wpriv = &knodev->wpriv[napi_index];
	pool = READ_ONCE(wpriv->pass_pool);
	if (!pool || !wpriv->pass_pending.slots)
		goto drop_all;

	spin_lock(&knodev->d2h_lock);

	for (i = 0; i < cnt; i++) {
		netmem_ref src = bds[i].netmem;
		struct knod_pass_desc *desc;
		netmem_ref dst;
		void *ptr;
		u32 fv;
		u16 off = bds[i].off;
		u16 len = bds[i].len;

		if (!len || off + len > SKB_WITH_OVERHEAD(PAGE_SIZE))
			goto drop;
		if (spsc_produce(&wpriv->pass_pending, &ptr))
			goto drop;
		dst = page_pool_dev_alloc_netmems(pool);
		if (!dst)
			goto drop;	/* slot left uncommitted, reused next */

		fv = ops->d2h_submit(knodev,
				     page_pool_get_dma_addr_netmem(dst) + off,
				     napi_index, bds[i].page_idx, off, len);
		if (!fv) {		/* SDMA ring full: backpressure drop */
			page_pool_put_full_netmem(pool, dst, false);
			goto drop;
		}
		submitted = true;

		desc = ptr;
		desc->netmem = dst;
		desc->src = src;
		desc->off = off;
		desc->len = len;
		desc->fence_val = fv;
		desc->sdma_idx = 0;
		spsc_produce_commit(&wpriv->pass_pending);
		produced++;
		continue;
drop:
		page_pool_recycle_direct_netmem(netmem_get_pp(src), src);
	}

	if (submitted)
		ops->d2h_kick(knodev);
	spin_unlock(&knodev->d2h_lock);

	/* The copies are async; re-arm the NAPI so the drain runs once the
	 * SDMA lands -- at low rate, RX traffic alone may not poll again soon.
	 */
	if (submitted)
		knod_napi_kick(wpriv);
	return produced;

drop_all:
	for (i = 0; i < cnt; i++)
		page_pool_recycle_direct_netmem(netmem_get_pp(bds[i].netmem),
						bds[i].netmem);
	return 0;
}
EXPORT_SYMBOL(knod_d2h_copy);

/*
 * Drain the per-queue pending ring: deliver every descriptor whose batch
 * fence has landed (accel_ops->d2h_fence) as a zero-copy head_frag skb from
 * the delivery page, recycling the source RX page.  Stops at the first
 * not-yet-landed descriptor -- the ring is in fence order.  Runs on the NIC
 * NAPI, the same thread as the knod_d2h_copy producer.
 */
int knod_d2h_drain(struct knod_dev *knodev, int napi_index,
		   struct napi_struct *napi, int budget)
{
	void *ptrs[KNOD_DEFAULT_PASS_SLOTS];
	struct knod_work_priv *wpriv;
	struct knod_pass_desc *d0;
	struct page_pool *pool;
	LIST_HEAD(deliver_list);
	unsigned int got = 0, i, n = 0;
	int delivered = 0;
	u32 cur_fence;

	if (napi_index < 0 || napi_index >= KNOD_SPSC_MAX ||
	    !knodev->accel_ops->d2h_fence)
		return 0;
	wpriv = &knodev->wpriv[napi_index];
	if (!wpriv->pass_pending.slots)
		return 0;
	pool = READ_ONCE(wpriv->pass_pool);

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

		/* bpf carries the RX page as src for post-copy recycle; ipsec
		 * leaves it 0 (the NIC act handler recycles via the bd).
		 */
		if (desc->src)
			page_pool_recycle_direct_netmem(
				netmem_get_pp(desc->src), desc->src);
		skb = knod_pass_build_skb(desc->netmem, desc->off, desc->len,
					  pool, true);
		n++;
		if (!skb)
			continue;
		if (knodev->post_copy) {
			if (!knodev->post_copy(knodev, skb, desc, napi_index)) {
				kfree_skb(skb);
				continue;
			}
		} else if (likely(skb->len >= ETH_HLEN)) {
			skb->protocol = eth_type_trans(skb, knodev->netdev);
		} else {
			kfree_skb(skb);
			continue;
		}
		list_add_tail(&skb->list, &deliver_list);
		delivered++;
	}

	if (n) {
		spsc_acquire(&wpriv->pass_pending, NULL, n, NULL);
		spsc_release_commit(&wpriv->pass_pending, n);
	}

	/* Descriptors whose copy has not landed yet remain queued; re-arm so
	 * we poll again instead of waiting for the next RX event.
	 */
	if (spsc_count(&wpriv->pass_pending))
		knod_napi_kick(wpriv);

	if (!list_empty(&deliver_list))
		netif_receive_skb_list(&deliver_list);
	return delivered;
}
EXPORT_SYMBOL(knod_d2h_drain);

/* ======================================================================
 * NOD IPsec proxy — bridges standard kernel xfrmdev_ops to
 * knod_accel_ipsec_ops on the GPU accelerator.
 * ======================================================================
 */
#if IS_ENABLED(CONFIG_XFRM_OFFLOAD)

static struct knod_dev *knod_ipsec_find_xdev(struct net_device *dev)
{
	struct knod_dev *knodev;

	list_for_each_entry(knodev, &knod_dev_list, list) {
		if (knodev->netdev == dev)
			return knodev;
	}
	return NULL;
}

static int knod_ipsec_xdo_state_add(struct net_device *dev,
				    struct xfrm_state *x,
				    struct netlink_ext_ack *extack)
{
	struct knod_dev *knodev = knod_ipsec_find_xdev(dev);

	if (!knodev || !knodev->accel_ops->ipsec_ops ||
	    !knodev->accel_ops->ipsec_ops->xdo_dev_state_add)
		return -EOPNOTSUPP;
	return knodev->accel_ops->ipsec_ops->xdo_dev_state_add(knodev, x,
							       extack);
}

static void knod_ipsec_xdo_state_delete(struct net_device *dev,
					struct xfrm_state *x)
{
	struct knod_dev *knodev = knod_ipsec_find_xdev(dev);

	if (!knodev || !knodev->accel_ops->ipsec_ops ||
	    !knodev->accel_ops->ipsec_ops->xdo_dev_state_delete)
		return;
	knodev->accel_ops->ipsec_ops->xdo_dev_state_delete(knodev, x);
}

static void knod_ipsec_xdo_state_free(struct net_device *dev,
				      struct xfrm_state *x)
{
	struct knod_dev *knodev = knod_ipsec_find_xdev(dev);

	if (!knodev || !knodev->accel_ops->ipsec_ops ||
	    !knodev->accel_ops->ipsec_ops->xdo_dev_state_free)
		return;
	knodev->accel_ops->ipsec_ops->xdo_dev_state_free(knodev, x);
}

static bool knod_ipsec_xdo_offload_ok(struct sk_buff *skb,
				      struct xfrm_state *x)
{
	struct knod_dev *knodev = knod_ipsec_find_xdev(x->xso.dev);

	if (!knodev || !knodev->accel_ops->ipsec_ops ||
	    !knodev->accel_ops->ipsec_ops->xdo_dev_offload_ok)
		return false;
	return knodev->accel_ops->ipsec_ops->xdo_dev_offload_ok(knodev, skb, x);
}

static void knod_ipsec_xdo_state_advance_esn(struct xfrm_state *x)
{
	struct knod_dev *knodev;

	if (!x->xso.dev)
		return;
	knodev = knod_ipsec_find_xdev(x->xso.dev);
	if (!knodev || !knodev->accel_ops->ipsec_ops ||
	    !knodev->accel_ops->ipsec_ops->xdo_dev_state_advance_esn)
		return;
	knodev->accel_ops->ipsec_ops->xdo_dev_state_advance_esn(knodev, x);
}

static void knod_ipsec_xdo_state_update_stats(struct xfrm_state *x)
{
	struct knod_dev *knodev;

	if (!x->xso.dev)
		return;
	knodev = knod_ipsec_find_xdev(x->xso.dev);
	if (!knodev || !knodev->accel_ops->ipsec_ops ||
	    !knodev->accel_ops->ipsec_ops->xdo_dev_state_update_stats)
		return;
	knodev->accel_ops->ipsec_ops->xdo_dev_state_update_stats(knodev, x);
}

static int knod_ipsec_xdo_policy_add(struct xfrm_policy *xp,
				     struct netlink_ext_ack *extack)
{
	struct knod_dev *knodev;

	if (!xp->xdo.dev)
		return -EOPNOTSUPP;
	knodev = knod_ipsec_find_xdev(xp->xdo.dev);
	if (!knodev || !knodev->accel_ops->ipsec_ops ||
	    !knodev->accel_ops->ipsec_ops->xdo_dev_policy_add)
		return -EOPNOTSUPP;
	return knodev->accel_ops->ipsec_ops->xdo_dev_policy_add(knodev, xp,
								extack);
}

static void knod_ipsec_xdo_policy_delete(struct xfrm_policy *xp)
{
	struct knod_dev *knodev;

	if (!xp->xdo.dev)
		return;
	knodev = knod_ipsec_find_xdev(xp->xdo.dev);
	if (!knodev || !knodev->accel_ops->ipsec_ops ||
	    !knodev->accel_ops->ipsec_ops->xdo_dev_policy_delete)
		return;
	knodev->accel_ops->ipsec_ops->xdo_dev_policy_delete(knodev, xp);
}

static void knod_ipsec_xdo_policy_free(struct xfrm_policy *xp)
{
	struct knod_dev *knodev;

	if (!xp->xdo.dev)
		return;
	knodev = knod_ipsec_find_xdev(xp->xdo.dev);
	if (!knodev || !knodev->accel_ops->ipsec_ops ||
	    !knodev->accel_ops->ipsec_ops->xdo_dev_policy_free)
		return;
	knodev->accel_ops->ipsec_ops->xdo_dev_policy_free(knodev, xp);
}

static const struct xfrmdev_ops knod_ipsec_xfrmdev_ops = {
	.xdo_dev_state_add          = knod_ipsec_xdo_state_add,
	.xdo_dev_state_delete       = knod_ipsec_xdo_state_delete,
	.xdo_dev_state_free         = knod_ipsec_xdo_state_free,
	.xdo_dev_offload_ok         = knod_ipsec_xdo_offload_ok,
	.xdo_dev_state_advance_esn  = knod_ipsec_xdo_state_advance_esn,
	.xdo_dev_state_update_stats = knod_ipsec_xdo_state_update_stats,
	.xdo_dev_policy_add         = knod_ipsec_xdo_policy_add,
	.xdo_dev_policy_delete      = knod_ipsec_xdo_policy_delete,
	.xdo_dev_policy_free        = knod_ipsec_xdo_policy_free,
};

int knod_dev_xdp_drain_pass(struct knod_dev *knodev, struct napi_struct *napi,
			    int queue_idx, int budget)
{
	if (!knodev || !knodev->accel_ops)
		return 0;
	/* Common device->host delivery drain.  PASS bds were SDMA-copied by
	 * knod_d2h_copy from the NIC act handler; deliver the ones whose copy
	 * has landed.
	 */
	return knod_d2h_drain(knodev, queue_idx, napi, budget);
}
EXPORT_SYMBOL_GPL(knod_dev_xdp_drain_pass);

int knod_ipsec_attach(struct knod_dev *knodev)
{
	struct knod_accel_ipsec_ops *ops;

	if (!knodev->accel_ops->ipsec_ops)
		return 0;

	ops = knodev->accel_ops->ipsec_ops;
	if (ops->activate) {
		int err = ops->activate(knodev);

		if (err) {
			pr_err("nod: IPsec activate failed on %s (%d)\n",
			       netdev_name(knodev->netdev), err);
			return err;
		}
	}

	/* Take over xfrmdev_ops, saving the NIC's original so detach can
	 * restore it (and only clear NETIF_F_HW_ESP if we added it).
	 */
	knodev->ipsec_orig_xfrmdev_ops = knodev->netdev->xfrmdev_ops;
	knodev->ipsec_added_hw_esp =
		!(knodev->netdev->features & NETIF_F_HW_ESP);
	knodev->netdev->xfrmdev_ops = &knod_ipsec_xfrmdev_ops;
	knodev->netdev->features |= NETIF_F_HW_ESP;
	knodev->netdev->hw_enc_features |= NETIF_F_HW_ESP;

	pr_info("nod: IPsec offload enabled on %s\n",
		netdev_name(knodev->netdev));
	return 0;
}
EXPORT_SYMBOL(knod_ipsec_attach);

void knod_ipsec_detach(struct knod_dev *knodev)
{
	struct knod_accel_ipsec_ops *ops = knodev->accel_ops->ipsec_ops;

	if (!ops)
		return;
	if (knodev->netdev->xfrmdev_ops != &knod_ipsec_xfrmdev_ops)
		return;

	if (knodev->ipsec_added_hw_esp) {
		knodev->netdev->features &= ~NETIF_F_HW_ESP;
		knodev->netdev->hw_enc_features &= ~NETIF_F_HW_ESP;
	}
	knodev->netdev->xfrmdev_ops = knodev->ipsec_orig_xfrmdev_ops;

	if (ops->deactivate)
		ops->deactivate(knodev);

	pr_info("nod: IPsec offload disabled on %s\n",
		netdev_name(knodev->netdev));
}
EXPORT_SYMBOL(knod_ipsec_detach);

#endif /* CONFIG_XFRM_OFFLOAD */

/*
 * Host-page page_pool memory provider for GPU->host delivery (NOD-private).
 * Unlike the devmem/dma-buf providers (which hand out unreadable net_iov), this
 * returns real host-readable pages (a GPU GTT buffer also mapped into system
 * memory), so delivered data becomes skbs on the normal receive path.  The
 * pages stay owned by the accel and are never returned to the buddy; the
 * gen_pool is only the slow-path backing store (page_pool's cache/ring absorb
 * the per-packet churn), and the device address it hands out doubles as the
 * netmem dma_addr (the worker's SDMA destination).  Selected via
 * page_pool_params.mp_ops in knod_pass_attach().
 */
static int hostmem_pp_init(struct page_pool *pool)
{
	struct page_pool_hostmem *hm = pool->mp_priv;
	int err;

	if (pool->p.order != 0)
		return -E2BIG;
	if (!hm || !hm->pages || !hm->count)
		return -EINVAL;

	hm->genpool = gen_pool_create(PAGE_SHIFT, NUMA_NO_NODE);
	if (!hm->genpool)
		return -ENOMEM;

	err = gen_pool_add(hm->genpool, (unsigned long)hm->base_addr,
			   (size_t)hm->count * PAGE_SIZE, NUMA_NO_NODE);
	if (err) {
		gen_pool_destroy(hm->genpool);
		hm->genpool = NULL;
		return err;
	}

	/* Device addresses are pre-set; page_pool must not DMA-sync them. */
	pool->dma_sync = false;
	pool->dma_sync_for_cpu = false;

	return 0;
}

static netmem_ref hostmem_pp_alloc_netmems(struct page_pool *pool, gfp_t gfp)
{
	struct page_pool_hostmem *hm = pool->mp_priv;
	unsigned long addr;
	netmem_ref netmem;
	unsigned int idx;

	addr = gen_pool_alloc(hm->genpool, PAGE_SIZE);
	if (!addr)
		return 0;

	idx = (addr - hm->base_addr) >> PAGE_SHIFT;
	if (WARN_ON_ONCE(idx >= hm->count)) {
		gen_pool_free(hm->genpool, addr, PAGE_SIZE);
		return 0;
	}

	netmem = page_to_netmem(hm->pages[idx]);
	page_pool_provider_set_netmem(pool, netmem, addr);

	pool->pages_state_hold_cnt++;
	trace_page_pool_state_hold(pool, netmem, pool->pages_state_hold_cnt);

	return netmem;
}

static bool hostmem_pp_release_netmem(struct page_pool *pool, netmem_ref netmem)
{
	struct page_pool_hostmem *hm = pool->mp_priv;
	unsigned long addr = page_pool_get_dma_addr_netmem(netmem);

	page_pool_clear_pp_info(netmem);
	gen_pool_free(hm->genpool, addr, PAGE_SIZE);

	/* Pages are accel-owned: never put_page() them to the buddy. */
	return false;
}

static void hostmem_pp_destroy(struct page_pool *pool)
{
	struct page_pool_hostmem *hm = pool->mp_priv;

	gen_pool_destroy(hm->genpool);
	hm->genpool = NULL;

	/* The pool has fully drained (inflight == 0); tell the owner it may now
	 * release the backing pages.  The struct itself is owner-allocated.
	 */
	if (hm->freed)
		hm->freed(hm->arg);
}

static int hostmem_pp_nl_fill(void *mp_priv, struct sk_buff *rsp,
			      struct netdev_rx_queue *rxq)
{
	/* Nothing provider-specific to report; page_pool_user.c calls this
	 * unconditionally once mp_ops is set, so it must not be NULL.
	 */
	return 0;
}

static const struct memory_provider_ops page_pool_hostmem_ops = {
	.init		= hostmem_pp_init,
	.alloc_netmems	= hostmem_pp_alloc_netmems,
	.release_netmem	= hostmem_pp_release_netmem,
	.destroy	= hostmem_pp_destroy,
	.nl_fill	= hostmem_pp_nl_fill,
	/*
	 * .uninstall is only invoked for rxq-bound pools and is
	 * NULL-checked.
	 */
};

/* Provider drain callback: fires once a delivery pool has no inflight pages. */
static void knod_pass_drained(void *arg)
{
	struct knod_dev *knodev = arg;

	if (atomic_dec_and_test(&knodev->pp_live))
		complete(&knodev->pp_drained);
}

/*
 * Create one GPU->host delivery page_pool per RX queue, backed by a single
 * accel-allocated GTT buffer.  Mirrors the spsc-pool setup: alloc_mem() hands
 * back the buffer (kaddr/gaddr/pages/priv); the framework owns the page_pools
 * and the drain barrier.  The hostmem provider hands out the real GTT pages
 * with their device address as dma_addr, so the worker's SDMA lands directly
 * in the page that later becomes the skb frag.  page_pool inflight accounting
 * then keeps the buffer alive until every delivered skb has drained.
 */
static int knod_pass_attach(struct knod_dev *knodev)
{
	struct page_pool_params pp = {
		.order		= 0,
		.pool_size	= KNOD_PASS_SLOTS,
		.nid		= NUMA_NO_NODE,
		.dev		= knodev->netdev->dev.parent,
		.dma_dir	= DMA_FROM_DEVICE,
		.max_len	= PAGE_SIZE,
		.flags		= PP_FLAG_DMA_MAP | PP_FLAG_DMA_SYNC_DEV |
				  PP_FLAG_CUSTOM_MEMORY_PROVIDER,
		.mp_ops		= &page_pool_hostmem_ops,
	};
	unsigned int nqueues = min(knodev->netdev->num_rx_queues,
				   KNOD_SPSC_MAX);
	struct page **pages;
	void *pass_priv;
	u64 base_gaddr;
	size_t total;
	void *kaddr;
	int qi;

	/* Accels without GPU memory simply run without zero-copy delivery. */
	if (!knodev->accel_ops->alloc_mem)
		return 0;

	total = nqueues * KNOD_PASS_SLOTS * PAGE_SIZE;
	kaddr = knodev->accel_ops->alloc_mem(knodev, total, &base_gaddr, &pages,
					   &pass_priv);
	if (!kaddr) {
		pr_err("%s: delivery alloc_mem failed\n", __func__);
		return -ENOMEM;
	}
	if (!pages) {
		knodev->accel_ops->free_mem(knodev, pass_priv);
		return -ENOMEM;
	}

	init_completion(&knodev->pp_drained);
	atomic_set(&knodev->pp_live, 0);
	spin_lock_init(&knodev->d2h_lock);

	for (qi = 0; qi < nqueues; qi++) {
		struct knod_work_priv *wpriv = &knodev->wpriv[qi];
		int base = qi * KNOD_PASS_SLOTS;

		if (spsc_init(&wpriv->pass_pending,
			      sizeof(struct knod_pass_desc),
			      KNOD_PASS_SLOTS, GFP_KERNEL))
			goto err_destroy;

		wpriv->pass_hm.pages	 = &pages[base];
		wpriv->pass_hm.count	 = KNOD_PASS_SLOTS;
		wpriv->pass_hm.base_addr = base_gaddr + (u64)base * PAGE_SIZE;
		wpriv->pass_hm.freed	 = knod_pass_drained;
		wpriv->pass_hm.arg	 = knodev;
		pp.mp_priv		 = &wpriv->pass_hm;

		wpriv->pass_pool = page_pool_create(&pp);
		if (IS_ERR(wpriv->pass_pool)) {
			wpriv->pass_pool = NULL;
			spsc_destroy(&wpriv->pass_pending);
			goto err_destroy;
		}
		atomic_inc(&knodev->pp_live);
	}

	knodev->pass_priv = pass_priv;
	return 0;

err_destroy:
	while (qi-- > 0) {
		spsc_destroy(&knodev->wpriv[qi].pass_pending);
		page_pool_destroy(knodev->wpriv[qi].pass_pool);
		knodev->wpriv[qi].pass_pool = NULL;
	}
	if (atomic_read(&knodev->pp_live))
		wait_for_completion_timeout(&knodev->pp_drained,
					    msecs_to_jiffies(5000));
	knodev->accel_ops->free_mem(knodev, pass_priv);
	return -ENOMEM;
}

/*
 * Drain a queue's pass_pending ring on teardown.  The interface is down so no
 * new copies are submitted; wait for each queued copy to land, then return its
 * pages to the pool instead of delivering.  Without this, page_pool_destroy()
 * stalls on the pages a detach raced against in-flight d2h copies.
 */
static void knod_pass_flush(struct knod_dev *knodev, unsigned int qi)
{
	struct knod_work_priv *wpriv = &knodev->wpriv[qi];
	struct page_pool *pool = wpriv->pass_pool;
	void *ptrs[KNOD_DEFAULT_PASS_SLOTS];
	unsigned int got, i;

	if (!wpriv->pass_pending.slots || !pool)
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

			if (desc->src) {
				struct page_pool *src_pp =
					netmem_get_pp(desc->src);

				page_pool_recycle_direct_netmem(src_pp,
								desc->src);
			}
			page_pool_put_full_netmem(pool, desc->netmem, false);
		}
		spsc_acquire(&wpriv->pass_pending, NULL, got, NULL);
		spsc_release_commit(&wpriv->pass_pending, got);
	}
}

/*
 * Tear down the delivery pools and free the backing buffer.  page_pool_destroy
 * is async, so wait for every pool to drain (knod_pass_drained) before handing
 * the buffer back to the accel -- otherwise an inflight skb frag would outlive
 * the BO.  Idempotent: a no-op for accels that never allocated.
 */
static void knod_pass_detach(struct knod_dev *knodev)
{
	unsigned int qi;

	if (!knodev->pass_priv)
		return;

	/* Iterate the full array (like the spsc teardown): destroy every pool
	 * that was created, so the drain barrier is guaranteed to reach zero.
	 */
	for (qi = 0; qi < KNOD_SPSC_MAX; qi++) {
		if (!knodev->wpriv[qi].pass_pool)
			continue;
		/* Return any queued (now-landed) d2h pages before destroying
		 * the pool, or page_pool_destroy() stalls on the inflight
		 * count a detach raced against in-flight d2h copies.
		 */
		knod_pass_flush(knodev, qi);
		spsc_destroy(&knodev->wpriv[qi].pass_pending);
		page_pool_destroy(knodev->wpriv[qi].pass_pool);
		knodev->wpriv[qi].pass_pool = NULL;
	}
	if (atomic_read(&knodev->pp_live))
		wait_for_completion_timeout(&knodev->pp_drained,
					    msecs_to_jiffies(5000));
	knodev->accel_ops->free_mem(knodev, knodev->pass_priv);
	knodev->pass_priv = NULL;
}

static void knod_dmabuf_move_notify(struct dma_buf_attachment *attach)
{
}

static const struct dma_buf_attach_ops knod_dmabuf_attach_ops = {
	.allow_peer2peer = true,
	.invalidate_mappings = knod_dmabuf_move_notify,
};

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

	knodev->stats = netdev_alloc_pcpu_stats(struct knod_dev_stats);
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

	netdev_lock(knodev->netdev);
	err = knodev->nic_ops->attach(knodev);
	if (err) {
		err = -ENOMEM;
		pr_err("knod: NIC attach failed on %s\n",
		       netdev_name(knetdev->dev));
		goto unlock;
	}

	err = knodev->accel_ops->attach(knodev);
	if (err) {
		err = -ENOMEM;
		pr_err("knod: accelerator attach failed on %s\n",
		       netdev_name(knetdev->dev));
		goto nic_detach;
	}

	{
		unsigned int nqueues = min(knodev->netdev->num_rx_queues,
					  KNOD_SPSC_MAX);
		unsigned int stride = ALIGN(sizeof(struct spsc_bd),
					    SMP_CACHE_BYTES);
		unsigned int cap = roundup_pow_of_two(KNOD_SPSC_ELEMS_MAX);
		size_t pool_size = (size_t)stride * cap;

		if (knodev->accel_ops->alloc_mem) {
			size_t total = pool_size * nqueues;
			u64 base_gaddr;
			void *base_pool;
			void *pool_priv;

			base_pool = knodev->accel_ops->alloc_mem(knodev, total,
					&base_gaddr, NULL, &pool_priv);
			if (!base_pool) {
				err = -ENOMEM;
				pr_err("%s: alloc_mem failed\n", __func__);
				goto free_spsc;
			}
			memset(base_pool, 0, total);

			/* First queue owns the BO, others reference it */
			knodev->wpriv[0].spsc_pool_priv = pool_priv;
			for (i = 0; i < nqueues; i++) {
				void *pool = base_pool +
					     (unsigned long)i * pool_size;

				knodev->wpriv[i].spsc_pool_gaddr =
					base_gaddr + (u64)i * pool_size;
				err = __spsc_init(&knodev->wpriv[i].spsc_bds,
						  sizeof(struct spsc_bd),
						  KNOD_SPSC_ELEMS_MAX, pool,
						  GFP_KERNEL);
				if (err) {
					pr_err("%s: spsc_init failed q%d\n",
					       __func__, i);
					goto free_spsc;
				}
			}
		} else {
			for (i = 0; i < nqueues; i++) {
				err = spsc_init(&knodev->wpriv[i].spsc_bds,
						sizeof(struct spsc_bd),
						KNOD_SPSC_ELEMS_MAX,
						GFP_KERNEL);
				if (err) {
					pr_err("%s: spsc_init failed q%d\n",
					       __func__, i);
					goto free_spsc;
				}
			}
		}
	}
	goto spsc_done;

free_spsc:
	for (i--; i >= 0; i--)
		spsc_destroy(&knodev->wpriv[i].spsc_bds);
	if (knodev->wpriv[0].spsc_pool_priv)
		knodev->accel_ops->free_mem(knodev,
				knodev->wpriv[0].spsc_pool_priv);
	knodev->accel_ops->detach(knodev);
	goto nic_detach;
spsc_done:

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
	 * Feature offloads (BPF, IPsec) allocate their GPU resources and
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
	for (i = 0; i < KNOD_SPSC_MAX; i++)
		spsc_destroy(&knodev->wpriv[i].spsc_bds);
	if (knodev->wpriv[0].spsc_pool_priv)
		knodev->accel_ops->free_mem(knodev,
				knodev->wpriv[0].spsc_pool_priv);
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
	for (i = 0; i < KNOD_SPSC_MAX; i++)
		spsc_destroy(&knodev->wpriv[i].spsc_bds);
	if (knodev->wpriv[0].spsc_pool_priv)
		knodev->accel_ops->free_mem(knodev,
				knodev->wpriv[0].spsc_pool_priv);
	knodev->nic_ops->detach(knodev);
	knodev->accel_ops->detach(knodev);
	netdev_unlock(knodev->netdev);
	knetdev->status = KNOD_STATUS_FREE;
	knetdev->accel = NULL;
	knetdev->knodev = NULL;
	accel->knetdev = NULL;
	accel->knodev = NULL;
	accel->status = KNOD_STATUS_FREE;
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

