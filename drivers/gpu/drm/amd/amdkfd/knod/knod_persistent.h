/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _KNOD_PERSISTENT_H
#define _KNOD_PERSISTENT_H
/* One workgroup per RX queue; no X dimension multiplier.
 *
 * The control block, and each queue's entry in it, which the host fills and
 * the engine in knod-blob's csrc/gda.c runs from.
 */
#define KNOD_PERSIST_VERSION 0x4b50000e
#define KNOD_PERSIST_MAX_QUEUES 32
/* What a shader that appends PASS entries the host waits on interrupts with;
 * the low 23 bits are all an interrupt carries on every generation.
 */
#define KNOD_PERSIST_PASS_IRQ 0x4b4e44
/* LDS the waves of a queue meet in, past the program's stack, and how many
 * waves take packets at most.
 */
#define KNOD_PERSIST_GDA_LDS_BYTES 64
#define KNOD_PERSIST_GDA_WAVES_MAX 4
#define KNOD_PERSIST_GDA_PASS_ENTRIES 8192
/* regress_dbg[]: an RQ bound older than the one before it. */
#define KNOD_PERSIST_REGRESS_HITS	0
#define KNOD_PERSIST_REGRESS_S2		1
#define KNOD_PERSIST_REGRESS_DELTA	2	/* the bound minus the one before */
#define KNOD_PERSIST_REGRESS_BOUND	3
#define KNOD_PERSIST_REGRESS_SQ_PC	4
#define KNOD_PERSIST_REGRESS_SQ_CC	5
#define KNOD_PERSIST_REGRESS_PASS_CC	6
#define KNOD_PERSIST_REGRESS_CAND	7	/* the PASS candidate */
/* sync_dbg[]: an RX CQE for another RQ entry than s2 says. */
#define KNOD_PERSIST_SYNC_HITS		0
#define KNOD_PERSIST_SYNC_ENTRIES	1	/* s2's low, the CQE's high */
#define KNOD_PERSIST_BYTES 16384
/* The ring buffer's layout, as net/knod.h lays it out for the NIC (the kernel
 * checks the two agree): doorbell records, then the RQ, then its CQ, then the
 * XDP SQ's CQ.
 */
#define KNOD_PERSIST_RING_RQ_DB 0
#define KNOD_PERSIST_RING_CQ_DB 64
/* The SQ's record is two counters and the NIC reads the send one, the second. */
#define KNOD_PERSIST_RING_SQ_DB (128 + 4)
#define KNOD_PERSIST_RING_TX_CQ_DB 192
#define KNOD_PERSIST_RING_RQ_OFF 4096
#define KNOD_PERSIST_RING_CQ_OFF (4096 + 8192 * 64)
#define KNOD_PERSIST_RING_TX_CQ_OFF (KNOD_PERSIST_RING_CQ_OFF + 8192 * 64)
/* u32 per SQ entry: the RQ position its packet came in on.  Nothing past it
 * goes back to the RQ until it is sent.
 */
#define KNOD_PERSIST_RING_RQPOS_OFF (KNOD_PERSIST_RING_TX_CQ_OFF + 8192 * 64)
/* u32 per PASS ring entry: the RQ position its packet came in on. */
#define KNOD_PERSIST_RING_PASS_RQPOS_OFF (KNOD_PERSIST_RING_RQPOS_OFF + 8192 * 4)
#ifndef __ASSEMBLY__
#include <linux/types.h>
/* What the shader needs to run a queue's rings, one entry per queue, and what
 * it reports back and carries over in the same entry.
 */
struct knod_persistent_gda {
	__u64 ring;
	__u64 rx_dma;
	__u64 packets;
	__u64 rounds;		/* rounds that took packets */
	__u32 rq_log;
	__u32 rq_log_stride;
	__u32 cq_log;
	__u32 frag;
	__u32 headroom;
	__u32 mkey_be;
	__u32 live;		/* zero: the rings are not the accel's, waves end */
	/* Which build of the rings this is; the NIC moves it every time it
	 * builds them.  The ring state below outlives a shader, and only rings
	 * of the same generation can pick it up.
	 */
	__u32 gen;
	__u64 rx_base;		/* the RX buffer, page 0 */
	__u32 ci;		/* CQ consumer index, carried over */
	__u32 posted_gen;	/* the generation the RQ was posted for */
	__u32 pause_ack;	/* the pause value this queue parked for */
	__u32 pad;
	/* The queue's XDP SQ and its CQ, when those are the accel's too; sq
	 * zero when they are not, and XDP_TX then drops.
	 */
	__u64 sq;
	__u32 sqn;
	__u32 sq_mask;		/* WQE basic blocks - 1 */
	__u32 tx_mkey_be;	/* already big endian */
	__u32 tx_cq_log;
	__u32 tx_gen;		/* as gen, for the SQ */
	__u32 pad1;
	__u64 tx_packets;
	__u64 tx_full;		/* XDP_TX dropped for want of SQ room */
	/* The shader's: where the SQ and its CQ got to, and for which build. */
	__u32 sq_pc;
	__u32 sq_cc;
	__u32 tx_ci;
	__u32 tx_posted_gen;
	/* RX page i's data starts stagger * (i & stagger_mask) past the
	 * headroom, spreading packets over the memory channels.
	 */
	__u32 stagger;
	__u32 stagger_mask;
	/* XDP_PASS: the shader appends {page, off | len << 16} to the queue's
	 * PASS ring, in host memory, and counts them in pass_pc; the host
	 * copies them out and counts the ones done in pass_cc.  Their RQ
	 * entries are held until then.  Entries before pass_floor belong to an
	 * earlier build of the rings.
	 */
	__u64 pass_ring;
	__u32 pass_mask;
	__u32 pass_pc;
	__u32 pass_cc;
	__u32 pass_floor;
	__u32 regress_dbg[8];	/* KNOD_PERSIST_REGRESS_* */
	__u32 sync_dbg[2];	/* KNOD_PERSIST_SYNC_* */
	__u8 reserved[32];
};

struct knod_persistent_control {
	__u32 version;
	__u32 stop;
	/* Nonzero asks every queue to park at its next round boundary and ack
	 * with the same value in its pause_ack.
	 */
	__u32 pause;
	/* Nonzero: the host sleeps until PASS entries come.  The shader that
	 * next appends some clears it and interrupts with KNOD_PERSIST_PASS_IRQ.
	 */
	__u32 pass_wake;
	/* The parameter block a program runs against, fixed for the shader's
	 * lifetime.
	 */
	__u64 gda_param;
	/* Where past the program's stack the waves of a queue meet in LDS,
	 * KNOD_PERSIST_GDA_LDS_BYTES of it, and how many of them take packets.
	 */
	__u32 gda_lds;
	__u32 gda_waves;
	__u8 reserved[32];
	/* Where each queue's NIC TX doorbell is in the GPU's address space.
	 * Written once when a shader lifetime starts, zero when the NIC
	 * publishes none.
	 */
	__u64 tx_db[KNOD_PERSIST_MAX_QUEUES];
	struct knod_persistent_gda gda[KNOD_PERSIST_MAX_QUEUES];
};
#endif
#endif
