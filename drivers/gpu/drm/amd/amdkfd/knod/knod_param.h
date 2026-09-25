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

#define KNOD_BPF_BACKLOGS_MAX		65536

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

struct knod_bpf_queue_desc {
	u64 pool_gaddr;		/* SPSC pool GTT address for this queue */
	u64 base_gaddr;		/* dma-buf base address for this queue */
	u32 count;		/* number of packets from this queue */
	/* Kernel-emitted bounds helpers read this; blob ignores this dword. */
	u32 rx_bounds;
	u32 ring_start;		/* acquired cursor at peek time */
	u32 ring_mask;		/* capacity - 1 */
	/* GDA: the queue's XDP SQ in accel memory; tx_sq zero = CPU builds WQEs */
	u64 tx_sq;
	u64 tx_rx_dma;		/* u64[page_idx] -> the NIC's address */
	u32 tx_sqn;
	u32 tx_mkey_be;
	u32 tx_pc_base;		/* SPSC position of WQE counter 0 */
	u32 tx_sq_mask;
};

struct knod_bpf_param {
	u32 nr_backlogs;
	u32 nr_queues;
	u32 spsc_stride;
	u32 _pad0;
	/* Actual sizes permit a non-power-of-two WG768 geometry. */
	u32 packets_per_rxq;
	u32 workgroup_size;
	u32 page_shift;
	u32 spsc_shift;
	u64 ktime_ns;		/* snapshot of ktime_get_ns() at batch preparation */
	struct knod_bpf_queue_desc queues[KNOD_SPSC_MAX];
	struct knod_bpf_subparam_obj sub[KNOD_BPF_BACKLOGS_MAX];
};

#endif /* KNOD_PARAM_H */
