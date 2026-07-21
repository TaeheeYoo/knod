/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (c) 2021 Taehee Yoo <ap420073@gmail.com>
 * Copyright (c) 2021 Hoyeon Lee <hoyeon.rhee@gmail.com>
 */

#ifndef _NET_KNOD_KNOD_H
#define _NET_KNOD_KNOD_H

#include <net/knod.h>

#include "knod-nl-gen.h"

struct net_device;

/* knod_core.c */
struct knod_netdev *knod_netdev_lookup(struct net_device *dev);
struct knod_dev *knod_dev_lookup(struct net_device *dev);
struct knod_accel *knod_accel_lookup(int id);
int knod_dev_attach(struct knod_netdev *knetdev,
		    struct knod_accel *accel);
int knod_dev_detach(struct knod_dev *knodev);

/* knod_nl.c */
void knod_nl_notify_dev(struct knod_dev *knodev, u32 cmd);

#endif /* _NET_KNOD_KNOD_H */
