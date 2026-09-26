/* SPDX-License-Identifier: GPL-2.0 OR MIT */
/*
 * The parameter block the GDA engine's shader and a BPF program run against:
 * a program's context, per queue what its bounds are read from, and the
 * clock.  The blob reaches it through the offsets knod_blob.h publishes.
 */
#ifndef KNOD_PARAM_H
#define KNOD_PARAM_H

#include <linux/types.h>
#include <net/knod.h>
#include "knod_persistent.h"

/* Lanes per queue per round, at most. */
#define KNOD_GDA_LANES		(64 * KNOD_PERSIST_GDA_WAVES_MAX)

struct xdp_md_obj {
	u64 data;
	u64 data_end;
	u64 data_meta;
	/* Below access go through struct xdp_rxq_info */
	u64 ingress_ifindex; /* rxq->dev->ifindex */
	u64 rx_queue_index;  /* rxq->queue_index  */

	u64 egress_ifindex;  /* txq->dev->ifindex */
	u64 retval;
};

struct knod_bpf_subparam_obj {
	struct xdp_md_obj ctx;
};

/* Per queue: the bounds a program's packet may reach, as the NIC published
 * them.  Reached with a shift of the queue id, so a power of two in size.
 */
struct knod_bpf_queue_desc {
	u32 rx_bounds;
	u32 _pad;
};

struct knod_bpf_param {
	u32 page_shift;
	u32 _pad;
	u64 ktime_ns;		/* refreshed by the engine's worker */
	struct knod_bpf_queue_desc queues[KNOD_SPSC_MAX];
	struct knod_bpf_subparam_obj sub[KNOD_SPSC_MAX * KNOD_GDA_LANES];
};

#endif /* KNOD_PARAM_H */
