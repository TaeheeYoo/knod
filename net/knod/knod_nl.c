// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (c) 2021 Taehee Yoo <ap420073@gmail.com>
 * Copyright (c) 2021 Hoyeon Lee <hoyeon.rhee@gmail.com>
 */

#include <linux/netdevice.h>
#include <linux/rtnetlink.h>
#include <net/genetlink.h>
#include <net/knod.h>
#include <net/sock.h>

#include "knod-nl-gen.h"
#include "knod.h"

/* ---- accel ---- */

static int knod_nl_accel_fill(struct knod_accel *accel,
			      struct sk_buff *rsp, const struct genl_info *info)
{
	u32 ena = 0, cap = 0;
	void *hdr;

	if (accel->accel_ops->feature_get)
		accel->accel_ops->feature_get(accel, &ena, &cap);

	hdr = genlmsg_iput(rsp, info);
	if (!hdr)
		return -EMSGSIZE;

	if (nla_put_u32(rsp, KNOD_A_ACCEL_ID, accel->id) ||
	    nla_put_string(rsp, KNOD_A_ACCEL_NAME, accel->name) ||
	    nla_put_u32(rsp, KNOD_A_ACCEL_TYPE, accel->type) ||
	    nla_put_u32(rsp, KNOD_A_ACCEL_FEATURE_CAP, cap) ||
	    nla_put_u32(rsp, KNOD_A_ACCEL_FEATURE_ENA, ena)) {
		genlmsg_cancel(rsp, hdr);
		return -EMSGSIZE;
	}

	genlmsg_end(rsp, hdr);
	return 0;
}

int knod_nl_accel_get_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct knod_accel *accel;
	struct sk_buff *rsp;
	int err;

	if (GENL_REQ_ATTR_CHECK(info, KNOD_A_ACCEL_ID))
		return -EINVAL;

	rsp = genlmsg_new(GENLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!rsp)
		return -ENOMEM;

	mutex_lock(&knod_lock);
	accel = knod_accel_lookup(nla_get_u32(info->attrs[KNOD_A_ACCEL_ID]));
	if (!accel) {
		mutex_unlock(&knod_lock);
		err = -ENODEV;
		goto err_free;
	}
	err = knod_nl_accel_fill(accel, rsp, info);
	mutex_unlock(&knod_lock);
	if (err)
		goto err_free;

	return genlmsg_reply(rsp, info);

err_free:
	nlmsg_free(rsp);
	return err;
}

int knod_nl_accel_get_dumpit(struct sk_buff *rsp, struct netlink_callback *cb)
{
	struct knod_accel *accel;
	int idx = 0, s_idx = cb->args[0];

	mutex_lock(&knod_lock);
	list_for_each_entry(accel, &knod_accel_list, list) {
		if (idx < s_idx)
			goto cont;
		if (knod_nl_accel_fill(accel, rsp, genl_info_dump(cb)) < 0)
			break;
cont:
		idx++;
	}
	mutex_unlock(&knod_lock);

	cb->args[0] = idx;
	return rsp->len;
}

int knod_nl_accel_set_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct knod_accel *accel;
	u32 feature;
	int err;

	if (GENL_REQ_ATTR_CHECK(info, KNOD_A_ACCEL_ID) ||
	    GENL_REQ_ATTR_CHECK(info, KNOD_A_ACCEL_FEATURE_ENA))
		return -EINVAL;

	feature = nla_get_u32(info->attrs[KNOD_A_ACCEL_FEATURE_ENA]);

	/*
	 * rtnl serialises the feature switch against attach/detach (which
	 * also take rtnl) and against the NIC driver's interface up/down
	 * (knod_dev_start/stop), and lets feature_set touch netdev->features
	 * and run an expedited synchronize_net().  knod_lock still guards the
	 * accel list walk (lock order: rtnl -> knod_lock).
	 */
	rtnl_lock();
	mutex_lock(&knod_lock);
	accel = knod_accel_lookup(nla_get_u32(info->attrs[KNOD_A_ACCEL_ID]));
	if (!accel) {
		err = -ENODEV;
		goto unlock;
	}
	if (!accel->accel_ops->feature_set) {
		err = -EOPNOTSUPP;
		goto unlock;
	}
	err = accel->accel_ops->feature_set(accel, feature, info->extack);
unlock:
	mutex_unlock(&knod_lock);
	rtnl_unlock();
	return err;
}

/* ---- nic ---- */

static int knod_nl_nic_fill(struct knod_netdev *knetdev,
			    struct sk_buff *rsp, const struct genl_info *info)
{
	void *hdr;

	hdr = genlmsg_iput(rsp, info);
	if (!hdr)
		return -EMSGSIZE;

	if (nla_put_u32(rsp, KNOD_A_NIC_IFINDEX, knetdev->dev->ifindex) ||
	    nla_put_string(rsp, KNOD_A_NIC_NAME, netdev_name(knetdev->dev))) {
		genlmsg_cancel(rsp, hdr);
		return -EMSGSIZE;
	}

	genlmsg_end(rsp, hdr);
	return 0;
}

int knod_nl_nic_get_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct knod_netdev *knetdev;
	struct net_device *dev;
	struct sk_buff *rsp;
	int err;

	if (GENL_REQ_ATTR_CHECK(info, KNOD_A_NIC_IFINDEX))
		return -EINVAL;

	rsp = genlmsg_new(GENLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!rsp)
		return -ENOMEM;

	rtnl_lock();
	mutex_lock(&knod_lock);
	dev = __dev_get_by_index(genl_info_net(info),
				 nla_get_u32(info->attrs[KNOD_A_NIC_IFINDEX]));
	knetdev = dev ? knod_netdev_lookup(dev) : NULL;
	if (!knetdev) {
		mutex_unlock(&knod_lock);
		rtnl_unlock();
		err = -ENODEV;
		goto err_free;
	}
	err = knod_nl_nic_fill(knetdev, rsp, info);
	mutex_unlock(&knod_lock);
	rtnl_unlock();
	if (err)
		goto err_free;

	return genlmsg_reply(rsp, info);

err_free:
	nlmsg_free(rsp);
	return err;
}

int knod_nl_nic_get_dumpit(struct sk_buff *rsp, struct netlink_callback *cb)
{
	struct net *net = sock_net(rsp->sk);
	struct knod_netdev *knetdev;
	int idx = 0, s_idx = cb->args[0];

	rtnl_lock();
	mutex_lock(&knod_lock);
	list_for_each_entry(knetdev, &knod_netdev_list, list) {
		if (idx < s_idx)
			goto cont;
		if (dev_net(knetdev->dev) != net)
			goto cont;
		if (knod_nl_nic_fill(knetdev, rsp, genl_info_dump(cb)) < 0)
			break;
cont:
		idx++;
	}
	mutex_unlock(&knod_lock);
	rtnl_unlock();

	cb->args[0] = idx;
	return rsp->len;
}

/* ---- dev (NIC <-> accel binding) ---- */

static int knod_nl_dev_fill(struct knod_dev *knodev, struct sk_buff *rsp,
			    const struct genl_info *info)
{
	void *hdr;

	hdr = genlmsg_iput(rsp, info);
	if (!hdr)
		return -EMSGSIZE;

	if (nla_put_u32(rsp, KNOD_A_DEV_NIC_IFINDEX, knodev->netdev->ifindex) ||
	    nla_put_u32(rsp, KNOD_A_DEV_ACCEL_ID, knodev->accel->id)) {
		genlmsg_cancel(rsp, hdr);
		return -EMSGSIZE;
	}

	genlmsg_end(rsp, hdr);
	return 0;
}

void knod_nl_notify_dev(struct knod_dev *knodev, u32 cmd)
{
	struct net *net = dev_net(knodev->netdev);
	struct genl_info info;
	struct sk_buff *ntf;

	if (!genl_has_listeners(&knod_nl_family, net, KNOD_NLGRP_MGMT))
		return;

	ntf = genlmsg_new(GENLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!ntf)
		return;

	genl_info_init_ntf(&info, &knod_nl_family, cmd);
	if (knod_nl_dev_fill(knodev, ntf, &info)) {
		nlmsg_free(ntf);
		return;
	}

	genlmsg_multicast_netns(&knod_nl_family, net, ntf, 0,
				KNOD_NLGRP_MGMT, GFP_KERNEL);
}

int knod_nl_attach_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct knod_netdev *knetdev;
	struct knod_accel *accel;
	struct net_device *dev;
	int err;

	if (GENL_REQ_ATTR_CHECK(info, KNOD_A_DEV_NIC_IFINDEX) ||
	    GENL_REQ_ATTR_CHECK(info, KNOD_A_DEV_ACCEL_ID))
		return -EINVAL;

	rtnl_lock();
	mutex_lock(&knod_lock);

	dev = __dev_get_by_index(genl_info_net(info),
				 nla_get_u32(
				 info->attrs[KNOD_A_DEV_NIC_IFINDEX]));
	if (!dev) {
		NL_SET_ERR_MSG(info->extack, "no such netdevice");
		err = -ENODEV;
		goto unlock;
	}

	knetdev = knod_netdev_lookup(dev);
	if (!knetdev) {
		NL_SET_ERR_MSG(info->extack, "netdevice not registered with knod");
		err = -ENODEV;
		goto unlock;
	}

	if (netif_running(dev)) {
		NL_SET_ERR_MSG(info->extack, "bring the netdevice down first");
		err = -EBUSY;
		goto unlock;
	}

	accel = knod_accel_lookup(
			nla_get_u32(info->attrs[KNOD_A_DEV_ACCEL_ID]));
	if (!accel) {
		NL_SET_ERR_MSG(info->extack, "no such accelerator");
		err = -ENODEV;
		goto unlock;
	}

	err = knod_dev_attach(knetdev, accel);
	if (!err)
		knod_nl_notify_dev(knetdev->knodev, KNOD_CMD_DEV_ADD_NTF);

unlock:
	mutex_unlock(&knod_lock);
	rtnl_unlock();
	return err;
}

int knod_nl_detach_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct knod_dev *knodev;
	struct net_device *dev;
	int err;

	if (GENL_REQ_ATTR_CHECK(info, KNOD_A_DEV_NIC_IFINDEX))
		return -EINVAL;

	rtnl_lock();

	dev = __dev_get_by_index(genl_info_net(info),
				 nla_get_u32(
				 info->attrs[KNOD_A_DEV_NIC_IFINDEX]));
	knodev = dev ? knod_dev_lookup(dev) : NULL;
	if (!knodev) {
		NL_SET_ERR_MSG(info->extack, "netdevice not attached");
		err = -ENODEV;
		goto unlock;
	}

	if (netif_running(dev)) {
		NL_SET_ERR_MSG(info->extack, "bring the netdevice down first");
		err = -EBUSY;
		goto unlock;
	}

	knod_nl_notify_dev(knodev, KNOD_CMD_DEV_DEL_NTF);
	err = knod_dev_detach(knodev);

unlock:
	rtnl_unlock();
	return err;
}

int knod_nl_dev_get_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct knod_dev *knodev;
	struct net_device *dev;
	struct sk_buff *rsp;
	int err;

	if (GENL_REQ_ATTR_CHECK(info, KNOD_A_DEV_NIC_IFINDEX))
		return -EINVAL;

	rsp = genlmsg_new(GENLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!rsp)
		return -ENOMEM;

	rtnl_lock();
	dev = __dev_get_by_index(genl_info_net(info),
				 nla_get_u32(
				 info->attrs[KNOD_A_DEV_NIC_IFINDEX]));
	knodev = dev ? knod_dev_lookup(dev) : NULL;
	if (!knodev) {
		rtnl_unlock();
		err = -ENODEV;
		goto err_free;
	}
	err = knod_nl_dev_fill(knodev, rsp, info);
	rtnl_unlock();
	if (err)
		goto err_free;

	return genlmsg_reply(rsp, info);

err_free:
	nlmsg_free(rsp);
	return err;
}

int knod_nl_dev_get_dumpit(struct sk_buff *rsp, struct netlink_callback *cb)
{
	struct net *net = sock_net(rsp->sk);
	struct knod_dev *knodev;
	int idx = 0, s_idx = cb->args[0];

	rtnl_lock();
	list_for_each_entry(knodev, &knod_dev_list, list) {
		if (idx < s_idx)
			goto cont;
		if (dev_net(knodev->netdev) != net)
			goto cont;
		if (knod_nl_dev_fill(knodev, rsp, genl_info_dump(cb)) < 0)
			break;
cont:
		idx++;
	}
	rtnl_unlock();

	cb->args[0] = idx;
	return rsp->len;
}
