/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _KNOD_PERSISTENT_H
#define _KNOD_PERSISTENT_H
/* One workgroup per RX queue; no X dimension multiplier. */
#define KNOD_PERSIST_VERSION 0x4b500004
#define KNOD_PERSIST_SLOTS 3
#define KNOD_PERSIST_SLOT_BASE 64
#define KNOD_PERSIST_SLOT_BYTES 512
#define KNOD_PERSIST_READY 0
#define KNOD_PERSIST_PARAM 8
#define KNOD_PERSIST_DONE 64
#define KNOD_PERSIST_MAX_QUEUES 32
#define KNOD_PERSIST_STOP 4
#ifndef __ASSEMBLY__
#include <linux/types.h>
struct knod_persistent_slot {
	u64 ready;
	u64 param;
	u8 reserved[48];
	u64 done[KNOD_PERSIST_MAX_QUEUES];
	u8 pad[192];
};

struct knod_persistent_control {
	u32 version;
	u32 stop;
	u8 reserved[56];
	struct knod_persistent_slot slots[KNOD_PERSIST_SLOTS];
};
#endif
#endif
