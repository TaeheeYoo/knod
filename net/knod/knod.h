/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (c) 2021 Taehee Yoo <ap420073@gmail.com>
 * Copyright (c) 2021 Hoyeon Lee <hoyeon.rhee@gmail.com>
 */

#ifndef _NET_KNOD_KNOD_H
#define _NET_KNOD_KNOD_H

#include <net/knod.h>

#include "knod-nl-gen.h"

#include <linux/netdevice.h>
#include <net/netdev_queues.h>

/* Whether @dev can hand its queues over to a knod link. */
static inline bool knod_nic_hands_queues(struct net_device *dev)
{
	return dev->queue_mgmt_ops && dev->queue_mgmt_ops->ndo_dmq_query;
}

/* knod_core.c */
struct knod_dev *knod_dev_lookup(struct net_device *dev);
struct knod_accel *knod_accel_lookup(int id);
int knod_dev_attach(struct net_device *dev, struct knod_accel *accel,
		    struct net_device *upper);
int knod_dev_detach(struct knod_dev *knodev);

#if IS_ENABLED(CONFIG_XFRM_OFFLOAD)
extern const struct xfrmdev_ops knod_ipsec_xfrmdev_ops;
#endif

/* knod_nl.c */
void knod_nl_notify_dev(struct knod_dev *knodev, u32 cmd);

#endif /* _NET_KNOD_KNOD_H */
