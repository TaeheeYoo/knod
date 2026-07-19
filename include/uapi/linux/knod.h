/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause) */
/* Do not edit directly, auto-generated from: */
/*	Documentation/netlink/specs/knod.yaml */
/* YNL-GEN uapi header */
/* To regenerate run: tools/net/ynl/ynl-regen.sh */

#ifndef _UAPI_LINUX_KNOD_H
#define _UAPI_LINUX_KNOD_H

#define KNOD_FAMILY_NAME	"knod"
#define KNOD_FAMILY_VERSION	1

enum knod_feature {
	KNOD_FEATURE_NONE,
	KNOD_FEATURE_BPF,
	KNOD_FEATURE_IPSEC,
};

enum knod_accel_type {
	KNOD_ACCEL_TYPE_GPU,
	KNOD_ACCEL_TYPE_DPU,
};

enum {
	KNOD_A_ACCEL_ID = 1,
	KNOD_A_ACCEL_NAME,
	KNOD_A_ACCEL_TYPE,
	KNOD_A_ACCEL_FEATURE_CAP,
	KNOD_A_ACCEL_FEATURE_ENA,

	__KNOD_A_ACCEL_MAX,
	KNOD_A_ACCEL_MAX = (__KNOD_A_ACCEL_MAX - 1)
};

enum {
	KNOD_A_NIC_IFINDEX = 1,
	KNOD_A_NIC_NAME,

	__KNOD_A_NIC_MAX,
	KNOD_A_NIC_MAX = (__KNOD_A_NIC_MAX - 1)
};

enum {
	KNOD_A_DEV_NIC_IFINDEX = 1,
	KNOD_A_DEV_ACCEL_ID,

	__KNOD_A_DEV_MAX,
	KNOD_A_DEV_MAX = (__KNOD_A_DEV_MAX - 1)
};

enum {
	KNOD_CMD_ACCEL_GET = 1,
	KNOD_CMD_ACCEL_SET,
	KNOD_CMD_NIC_GET,
	KNOD_CMD_ATTACH,
	KNOD_CMD_DETACH,
	KNOD_CMD_DEV_GET,
	KNOD_CMD_DEV_ADD_NTF,
	KNOD_CMD_DEV_DEL_NTF,

	__KNOD_CMD_MAX,
	KNOD_CMD_MAX = (__KNOD_CMD_MAX - 1)
};

#define KNOD_MCGRP_MGMT	"mgmt"

#endif /* _UAPI_LINUX_KNOD_H */
