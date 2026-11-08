// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * A knod link: a device over a NIC whose queues a GPU runs.  Creating it
 * attaches the GPU to the NIC; every packet the NIC receives then goes
 * through the GPU and up this device, and what the stack sends on it goes
 * out the NIC.  Deleting it detaches them.
 *
 *	ip link add knod128 link enp0 type knod id 128
 */

#include <linux/etherdevice.h>
#include <linux/if_link.h>
#include <linux/netdevice.h>
#include <linux/rtnetlink.h>
#include <net/rtnetlink.h>

#include "knod.h"

struct knod_link {
	struct net_device *lower;
	struct knod_dev *knodev;
	/* A queue's PASS packets go up this device on its NAPI, the NIC's
	 * own not running for queues it handed over.
	 */
	struct napi_struct napi[KNOD_SPSC_MAX];
};

static int knod_link_poll(struct napi_struct *napi, int budget)
{
	struct knod_link *kl = netdev_priv(napi->dev);
	struct knod_dev *knodev = READ_ONCE(kl->knodev);
	int done = 0;

	if (knodev)
		done = knod_d2h_drain(knodev, napi - kl->napi, napi, budget);
	if (done < budget)
		napi_complete_done(napi, done);
	return done;
}

static netdev_tx_t knod_link_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct knod_link *kl = netdev_priv(dev);
	unsigned int len = skb->len;
	int ret;

	skb->dev = kl->lower;
	ret = dev_queue_xmit(skb);
	if (likely(ret == NET_XMIT_SUCCESS || ret == NET_XMIT_CN))
		dev_sw_netstats_tx_add(dev, 1, len);
	else
		DEV_STATS_INC(dev, tx_dropped);
	return NETDEV_TX_OK;
}

/*
 * Up: each queue's NAPI on the CPU the NIC's channel would have it on, and
 * the GPU onto the NIC's queues, now or once the NIC has them up.
 */
static int knod_link_open(struct net_device *dev)
{
	struct knod_link *kl = netdev_priv(dev);
	struct knod_dev *knodev = kl->knodev;
	int node = dev_to_node(kl->lower->dev.parent), i;

	if (!knodev)
		return -ENODEV;
	for (i = 0; i < KNOD_SPSC_MAX; i++) {
		napi_enable(&kl->napi[i]);
		WRITE_ONCE(knodev->wpriv[i].napi_cpu,
			   cpumask_local_spread(i, node));
		WRITE_ONCE(knodev->wpriv[i].napi, &kl->napi[i]);
	}
	knod_dev_start(knodev);
	netif_stacked_transfer_operstate(kl->lower, dev);
	return 0;
}

/* Down: the GPU off the queues, then what it had passed let go of. */
static int knod_link_stop(struct net_device *dev)
{
	struct knod_link *kl = netdev_priv(dev);
	struct knod_dev *knodev = kl->knodev;
	int i;

	if (!knodev)
		return 0;
	knod_dev_stop(knodev);
	for (i = 0; i < KNOD_SPSC_MAX; i++)
		WRITE_ONCE(knodev->wpriv[i].napi, NULL);
	/* No kick schedules a NAPI any more, nor a poll drains. */
	synchronize_net();
	for (i = 0; i < KNOD_SPSC_MAX; i++)
		napi_disable(&kl->napi[i]);
	knod_dev_flush_pass(knodev);
	return 0;
}

/* XDP offloaded to the GPU, which runs it on every packet the NIC gets. */
static int knod_link_bpf(struct net_device *dev, struct netdev_bpf *xdp)
{
	struct knod_link *kl = netdev_priv(dev);

	switch (xdp->command) {
	case XDP_SETUP_PROG_HW:
	case BPF_OFFLOAD_MAP_ALLOC:
	case BPF_OFFLOAD_MAP_FREE:
		return kl->knodev ? knod_dev_xdp_install(kl->knodev, xdp) :
				    -ENODEV;
	default:
		return -EOPNOTSUPP;
	}
}

static int knod_link_get_iflink(const struct net_device *dev)
{
	struct knod_link *kl = netdev_priv(dev);

	return READ_ONCE(kl->lower->ifindex);
}

static const struct net_device_ops knod_link_netdev_ops = {
	.ndo_open		= knod_link_open,
	.ndo_stop		= knod_link_stop,
	.ndo_start_xmit		= knod_link_xmit,
	.ndo_bpf		= knod_link_bpf,
	.ndo_get_stats64	= dev_get_tstats64,
	.ndo_get_iflink		= knod_link_get_iflink,
};

static void knod_link_setup(struct net_device *dev)
{
	ether_setup(dev);
	dev->netdev_ops = &knod_link_netdev_ops;
	dev->needs_free_netdev = true;
	dev->pcpu_stat_type = NETDEV_PCPU_STAT_TSTATS;
	dev->priv_flags |= IFF_NO_QUEUE;
	dev->priv_flags &= ~IFF_TX_SKB_SHARING;
	dev->lltx = true;
	/* XDP programs go to the GPU, which runs them on every packet. */
	dev->xdp_features = NETDEV_XDP_ACT_HW_OFFLOAD;
#if IS_ENABLED(CONFIG_XFRM_OFFLOAD)
	/* xfrm states put on the link go to its GPU, and with the IPsec
	 * feature on, the GPU opens and seals their packets.
	 */
	dev->xfrmdev_ops = &knod_ipsec_xfrmdev_ops;
#endif
}

static const struct nla_policy knod_link_policy[IFLA_KNOD_MAX + 1] = {
	[IFLA_KNOD_ID]	= { .type = NLA_U32 },
};

static int knod_link_validate(struct nlattr *tb[], struct nlattr *data[],
			      struct netlink_ext_ack *extack)
{
	if (!data || !data[IFLA_KNOD_ID]) {
		NL_SET_ERR_MSG(extack, "the GPU's id is required");
		return -EINVAL;
	}
	return 0;
}

#define KNOD_LINK_FEATURES	(NETIF_F_SG | NETIF_F_CSUM_MASK | \
				 NETIF_F_HIGHDMA | NETIF_F_GSO_SOFTWARE | \
				 NETIF_F_RXCSUM)
#define KNOD_LINK_ESP_FEATURES	(NETIF_F_HW_ESP | NETIF_F_HW_ESP_TX_CSUM | \
				 NETIF_F_GSO_ESP)
/* The segments a GSO packet may make: the GPU's limit. */
#define KNOD_LINK_GSO_SEGS	64

static int knod_link_new(struct net_device *dev,
			 struct rtnl_newlink_params *params,
			 struct netlink_ext_ack *extack)
{
	struct knod_link *kl = netdev_priv(dev);
	struct nlattr **data = params->data;
	struct nlattr **tb = params->tb;
	struct knod_accel *accel;
	struct net_device *lower;
	int err, i;

	if (!tb[IFLA_LINK]) {
		NL_SET_ERR_MSG(extack, "the NIC is required: link <dev>");
		return -EINVAL;
	}
	lower = __dev_get_by_index(rtnl_newlink_link_net(params),
				   nla_get_u32(tb[IFLA_LINK]));
	if (!lower)
		return -ENODEV;

	mutex_lock(&knod_lock);
	if (!knod_nic_hands_queues(lower)) {
		NL_SET_ERR_MSG(extack, "the NIC cannot hand its queues over");
		err = -EOPNOTSUPP;
		goto unlock;
	}
	accel = knod_accel_lookup(nla_get_u32(data[IFLA_KNOD_ID]));
	if (!accel) {
		NL_SET_ERR_MSG(extack, "no such GPU");
		err = -ENODEV;
		goto unlock;
	}
	if (netif_running(lower)) {
		NL_SET_ERR_MSG(extack, "bring the NIC down first");
		err = -EBUSY;
		goto unlock;
	}

	/* What the NIC has, which this device keeps for now. */
	dev->mtu = lower->mtu;
	dev->min_mtu = lower->mtu;
	dev->max_mtu = lower->mtu;
	eth_hw_addr_set(dev, lower->dev_addr);
	dev->hw_features = lower->hw_features & KNOD_LINK_FEATURES;
	dev->features = lower->features & KNOD_LINK_FEATURES;
	/* The GPU seals ESP, fills in the inner checksum and makes a GSO
	 * packet its segments, as a NIC with IPsec crypto offload does.
	 */
	if (dev->xfrmdev_ops) {
		dev->features |= KNOD_LINK_ESP_FEATURES;
		dev->hw_features |= KNOD_LINK_ESP_FEATURES;
		/* What the stack checks of an ESP packet, encapsulated: the
		 * checksum feature the device has, or it segments it itself.
		 */
		dev->hw_enc_features |= KNOD_LINK_ESP_FEATURES | NETIF_F_SG |
					(dev->features & NETIF_F_CSUM_MASK) |
					NETIF_F_TSO;
	}
	netif_inherit_tso_max(dev, lower);
	netif_set_tso_max_segs(dev, KNOD_LINK_GSO_SEGS);
	kl->lower = lower;
	for (i = 0; i < KNOD_SPSC_MAX; i++)
		netif_napi_add(dev, &kl->napi[i], knod_link_poll);

	/* Registered first: the GPU takes it as the one the NIC's traffic
	 * goes up and its programs and SAs are put on.
	 */
	err = register_netdevice(dev);
	if (err)
		goto unlock;
	err = knod_dev_attach(lower, accel, dev);
	if (err) {
		NL_SET_ERR_MSG(extack, "the GPU would not attach to the NIC");
		goto unregister;
	}
	kl->knodev = knod_dev_lookup(lower);
	err = netdev_upper_dev_link(lower, dev, extack);
	if (err)
		goto detach;
	netif_stacked_transfer_operstate(lower, dev);
	knod_nl_notify_dev(kl->knodev, KNOD_CMD_DEV_ADD_NTF);
	mutex_unlock(&knod_lock);
	return 0;

detach:
	knod_dev_detach(kl->knodev);
	kl->knodev = NULL;
unregister:
	unregister_netdevice(dev);
unlock:
	mutex_unlock(&knod_lock);
	return err;
}

/*
 * The GPU let go of the NIC: with the NIC down, as a detach wants, and up
 * again after if it was.
 */
static void knod_link_detach(struct knod_link *kl)
{
	struct net_device *lower = kl->lower;
	bool up = netif_running(lower);

	if (!kl->knodev)
		return;
	knod_nl_notify_dev(kl->knodev, KNOD_CMD_DEV_DEL_NTF);
	if (up)
		dev_close(lower);
	knod_dev_detach(kl->knodev);
	kl->knodev = NULL;
	if (up && dev_open(lower, NULL))
		netdev_warn(lower, "did not come up again after knod let go\n");
}

static void knod_link_del(struct net_device *dev, struct list_head *head)
{
	struct knod_link *kl = netdev_priv(dev);

	/* The GPU off the NIC's queues and the NAPIs quiet before it goes. */
	dev_close(dev);
	netdev_upper_dev_unlink(kl->lower, dev);
	mutex_lock(&knod_lock);
	knod_link_detach(kl);
	mutex_unlock(&knod_lock);
	unregister_netdevice_queue(dev, head);
}

static size_t knod_link_get_size(const struct net_device *dev)
{
	return nla_total_size(sizeof(u32));	/* IFLA_KNOD_ID */
}

static int knod_link_fill_info(struct sk_buff *skb,
			       const struct net_device *dev)
{
	struct knod_link *kl = netdev_priv(dev);
	struct knod_dev *knodev = READ_ONCE(kl->knodev);

	if (knodev && nla_put_u32(skb, IFLA_KNOD_ID, knodev->accel->id))
		return -EMSGSIZE;
	return 0;
}

static struct net *knod_link_get_link_net(const struct net_device *dev)
{
	struct knod_link *kl = netdev_priv(dev);

	return dev_net(kl->lower);
}

static struct rtnl_link_ops knod_link_ops __read_mostly = {
	.kind		= "knod",
	.priv_size	= sizeof(struct knod_link),
	.maxtype	= IFLA_KNOD_MAX,
	.policy		= knod_link_policy,
	.setup		= knod_link_setup,
	.validate	= knod_link_validate,
	.newlink	= knod_link_new,
	.dellink	= knod_link_del,
	.get_size	= knod_link_get_size,
	.fill_info	= knod_link_fill_info,
	.get_link_net	= knod_link_get_link_net,
};

static struct net_device *knod_link_upper(struct net_device *lower)
{
	struct knod_dev *knodev = knod_dev_lookup(lower);

	return knodev ? READ_ONCE(knodev->upper) : NULL;
}

/*
 * The NIC under a knod link: its link state shows on the link, its MTU is
 * the link's to keep, and it going away takes the link with it.
 */
static int knod_link_event(struct notifier_block *nb, unsigned long event,
			   void *ptr)
{
	struct net_device *lower = netdev_notifier_info_to_dev(ptr);
	struct net_device *dev;

	if (lower->rtnl_link_ops == &knod_link_ops)
		return NOTIFY_DONE;
	dev = knod_link_upper(lower);
	if (!dev)
		return NOTIFY_DONE;

	switch (event) {
	case NETDEV_UP:
	case NETDEV_DOWN:
	case NETDEV_CHANGE:
		netif_stacked_transfer_operstate(lower, dev);
		break;
	case NETDEV_PRECHANGEMTU:
		netdev_warn(lower, "%s runs it: its MTU stays\n", dev->name);
		return notifier_from_errno(-EBUSY);
	case NETDEV_UNREGISTER:
		knod_link_del(dev, NULL);
		break;
	}
	return NOTIFY_DONE;
}

static struct notifier_block knod_link_notifier = {
	.notifier_call = knod_link_event,
};

static int __init knod_link_init(void)
{
	int err;

	err = register_netdevice_notifier(&knod_link_notifier);
	if (err)
		return err;
	err = rtnl_link_register(&knod_link_ops);
	if (err)
		unregister_netdevice_notifier(&knod_link_notifier);
	return err;
}
device_initcall(knod_link_init);
