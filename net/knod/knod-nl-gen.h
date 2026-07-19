/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause) */
/* Do not edit directly, auto-generated from: */
/*	Documentation/netlink/specs/knod.yaml */
/* YNL-GEN kernel header */
/* To regenerate run: tools/net/ynl/ynl-regen.sh */

#ifndef _LINUX_KNOD_GEN_H
#define _LINUX_KNOD_GEN_H

#include <net/netlink.h>
#include <net/genetlink.h>

#include <uapi/linux/knod.h>

int knod_nl_accel_get_doit(struct sk_buff *skb, struct genl_info *info);
int knod_nl_accel_get_dumpit(struct sk_buff *skb, struct netlink_callback *cb);
int knod_nl_accel_set_doit(struct sk_buff *skb, struct genl_info *info);
int knod_nl_nic_get_doit(struct sk_buff *skb, struct genl_info *info);
int knod_nl_nic_get_dumpit(struct sk_buff *skb, struct netlink_callback *cb);
int knod_nl_attach_doit(struct sk_buff *skb, struct genl_info *info);
int knod_nl_detach_doit(struct sk_buff *skb, struct genl_info *info);
int knod_nl_dev_get_doit(struct sk_buff *skb, struct genl_info *info);
int knod_nl_dev_get_dumpit(struct sk_buff *skb, struct netlink_callback *cb);

enum {
	KNOD_NLGRP_MGMT,
};

extern struct genl_family knod_nl_family;

#endif /* _LINUX_KNOD_GEN_H */
