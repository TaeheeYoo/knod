// SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause)
/* Do not edit directly, auto-generated from: */
/*	Documentation/netlink/specs/knod.yaml */
/* YNL-GEN kernel source */
/* To regenerate run: tools/net/ynl/ynl-regen.sh */

#include <net/netlink.h>
#include <net/genetlink.h>

#include "knod-nl-gen.h"

#include <uapi/linux/knod.h>

/* KNOD_CMD_ACCEL_GET - do */
static const struct nla_policy knod_accel_get_nl_policy[KNOD_A_ACCEL_ID + 1] = {
	[KNOD_A_ACCEL_ID] = NLA_POLICY_MIN(NLA_U32, 1),
};

/* KNOD_CMD_ACCEL_SET - do */
static const struct nla_policy knod_accel_set_nl_policy[KNOD_A_ACCEL_FEATURE_ENA + 1] = {
	[KNOD_A_ACCEL_ID] = NLA_POLICY_MIN(NLA_U32, 1),
	[KNOD_A_ACCEL_FEATURE_ENA] = NLA_POLICY_MAX(NLA_U32, 2),
};

/* KNOD_CMD_NIC_GET - do */
static const struct nla_policy knod_nic_get_nl_policy[KNOD_A_NIC_IFINDEX + 1] = {
	[KNOD_A_NIC_IFINDEX] = NLA_POLICY_MIN(NLA_U32, 1),
};

/* KNOD_CMD_ATTACH - do */
static const struct nla_policy knod_attach_nl_policy[KNOD_A_DEV_ACCEL_ID + 1] = {
	[KNOD_A_DEV_NIC_IFINDEX] = NLA_POLICY_MIN(NLA_U32, 1),
	[KNOD_A_DEV_ACCEL_ID] = NLA_POLICY_MIN(NLA_U32, 1),
};

/* KNOD_CMD_DETACH - do */
static const struct nla_policy knod_detach_nl_policy[KNOD_A_DEV_NIC_IFINDEX + 1] = {
	[KNOD_A_DEV_NIC_IFINDEX] = NLA_POLICY_MIN(NLA_U32, 1),
};

/* KNOD_CMD_DEV_GET - do */
static const struct nla_policy knod_dev_get_nl_policy[KNOD_A_DEV_NIC_IFINDEX + 1] = {
	[KNOD_A_DEV_NIC_IFINDEX] = NLA_POLICY_MIN(NLA_U32, 1),
};

/* Ops table for knod */
static const struct genl_split_ops knod_nl_ops[] = {
	{
		.cmd		= KNOD_CMD_ACCEL_GET,
		.doit		= knod_nl_accel_get_doit,
		.policy		= knod_accel_get_nl_policy,
		.maxattr	= KNOD_A_ACCEL_ID,
		.flags		= GENL_CMD_CAP_DO,
	},
	{
		.cmd	= KNOD_CMD_ACCEL_GET,
		.dumpit	= knod_nl_accel_get_dumpit,
		.flags	= GENL_CMD_CAP_DUMP,
	},
	{
		.cmd		= KNOD_CMD_ACCEL_SET,
		.doit		= knod_nl_accel_set_doit,
		.policy		= knod_accel_set_nl_policy,
		.maxattr	= KNOD_A_ACCEL_FEATURE_ENA,
		.flags		= GENL_ADMIN_PERM | GENL_CMD_CAP_DO,
	},
	{
		.cmd		= KNOD_CMD_NIC_GET,
		.doit		= knod_nl_nic_get_doit,
		.policy		= knod_nic_get_nl_policy,
		.maxattr	= KNOD_A_NIC_IFINDEX,
		.flags		= GENL_CMD_CAP_DO,
	},
	{
		.cmd	= KNOD_CMD_NIC_GET,
		.dumpit	= knod_nl_nic_get_dumpit,
		.flags	= GENL_CMD_CAP_DUMP,
	},
	{
		.cmd		= KNOD_CMD_ATTACH,
		.doit		= knod_nl_attach_doit,
		.policy		= knod_attach_nl_policy,
		.maxattr	= KNOD_A_DEV_ACCEL_ID,
		.flags		= GENL_ADMIN_PERM | GENL_CMD_CAP_DO,
	},
	{
		.cmd		= KNOD_CMD_DETACH,
		.doit		= knod_nl_detach_doit,
		.policy		= knod_detach_nl_policy,
		.maxattr	= KNOD_A_DEV_NIC_IFINDEX,
		.flags		= GENL_ADMIN_PERM | GENL_CMD_CAP_DO,
	},
	{
		.cmd		= KNOD_CMD_DEV_GET,
		.doit		= knod_nl_dev_get_doit,
		.policy		= knod_dev_get_nl_policy,
		.maxattr	= KNOD_A_DEV_NIC_IFINDEX,
		.flags		= GENL_CMD_CAP_DO,
	},
	{
		.cmd	= KNOD_CMD_DEV_GET,
		.dumpit	= knod_nl_dev_get_dumpit,
		.flags	= GENL_CMD_CAP_DUMP,
	},
};

static const struct genl_multicast_group knod_nl_mcgrps[] = {
	[KNOD_NLGRP_MGMT] = { "mgmt", },
};

struct genl_family knod_nl_family __ro_after_init = {
	.name		= KNOD_FAMILY_NAME,
	.version	= KNOD_FAMILY_VERSION,
	.netnsok	= true,
	.parallel_ops	= true,
	.module		= THIS_MODULE,
	.split_ops	= knod_nl_ops,
	.n_split_ops	= ARRAY_SIZE(knod_nl_ops),
	.mcgrps		= knod_nl_mcgrps,
	.n_mcgrps	= ARRAY_SIZE(knod_nl_mcgrps),
};
