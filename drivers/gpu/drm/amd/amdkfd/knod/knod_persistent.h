/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _KNOD_PERSISTENT_H
#define _KNOD_PERSISTENT_H
/* One workgroup per RX queue; no X dimension multiplier. */
#define KNOD_PERSIST_VERSION 0x4b50000c
#define KNOD_PERSIST_MAX_QUEUES 32
#define KNOD_PERSIST_STOP 4
/* Nonzero asks every queue to park at its next round boundary
 * and ack with the same value; see KNOD_PERSIST_GDA_PAUSE_ACK.
 */
#define KNOD_PERSIST_PAUSE 8
/* The parameter block a program runs against, fixed for the shader's
 * lifetime.
 */
#define KNOD_PERSIST_GDA_PARAM 16
/* Where past the program's stack the waves of a queue meet in
 * LDS, KNOD_PERSIST_GDA_LDS_BYTES of it, and how many of them take packets.
 */
#define KNOD_PERSIST_GDA_LDS 24
#define KNOD_PERSIST_GDA_WAVES 28
#define KNOD_PERSIST_GDA_LDS_BYTES 64
#define KNOD_PERSIST_GDA_WAVES_MAX 4
/* u64 per queue: where this queue's NIC TX doorbell is in the GPU's address
 * space.  Written once when a shader lifetime starts, zero when the NIC
 * publishes none.
 */
#define KNOD_PERSIST_TX_DB 64
/* What the shader needs to run a queue's rings, one entry per queue, and
 * what it reports back and carries over in the same entry.  live zero means
 * the queue's rings are not the accel's; its waves end.
 */
#define KNOD_PERSIST_GDA (KNOD_PERSIST_TX_DB + 8 * KNOD_PERSIST_MAX_QUEUES)
#define KNOD_PERSIST_GDA_BYTES 256
#define KNOD_PERSIST_GDA_RING 0
#define KNOD_PERSIST_GDA_RX_DMA 8
#define KNOD_PERSIST_GDA_PACKETS 16
#define KNOD_PERSIST_GDA_ROUNDS 24	/* rounds that took packets */
#define KNOD_PERSIST_GDA_RQ_LOG 32
#define KNOD_PERSIST_GDA_RQ_LOG_STRIDE 36
#define KNOD_PERSIST_GDA_CQ_LOG 40
#define KNOD_PERSIST_GDA_FRAG 44
#define KNOD_PERSIST_GDA_HEADROOM 48
#define KNOD_PERSIST_GDA_MKEY 52
#define KNOD_PERSIST_GDA_LIVE 56
/* Which build of the rings this is; the NIC moves it every time it builds
 * them.  The ring state below outlives a shader, and only rings of the same
 * generation can pick it up.
 */
#define KNOD_PERSIST_GDA_GEN 60
#define KNOD_PERSIST_GDA_RX_BASE 64	/* the RX buffer, page 0 */
#define KNOD_PERSIST_GDA_BDS 72		/* per-lane descriptors for the program */
#define KNOD_PERSIST_GDA_CI 80		/* CQ consumer index, carried over */
#define KNOD_PERSIST_GDA_POSTED_GEN 84	/* the generation the RQ was posted for */
#define KNOD_PERSIST_GDA_PAUSE_ACK 88
/* The queue's XDP SQ and its CQ, when those are the accel's too; sq zero when
 * they are not, and XDP_TX then drops.
 */
#define KNOD_PERSIST_GDA_SQ 96
#define KNOD_PERSIST_GDA_SQN 104
#define KNOD_PERSIST_GDA_SQ_MASK 108	/* WQE basic blocks - 1 */
#define KNOD_PERSIST_GDA_TX_MKEY 112	/* already big endian */
#define KNOD_PERSIST_GDA_TX_CQ_LOG 116
#define KNOD_PERSIST_GDA_TX_GEN 120	/* as GEN, for the SQ */
#define KNOD_PERSIST_GDA_TX_PACKETS 128
#define KNOD_PERSIST_GDA_TX_FULL 136	/* XDP_TX dropped for want of SQ room */
/* The shader's: where the SQ and its CQ got to, and for which build. */
#define KNOD_PERSIST_GDA_SQ_PC 144
#define KNOD_PERSIST_GDA_SQ_CC 148
#define KNOD_PERSIST_GDA_TX_CI 152
#define KNOD_PERSIST_GDA_TX_POSTED_GEN 156
/* RX page i's data starts stagger * (i & stagger_mask) past the headroom,
 * spreading packets over the memory channels.
 */
#define KNOD_PERSIST_GDA_STAGGER 160
#define KNOD_PERSIST_GDA_STAGGER_MASK 164
/* XDP_PASS: the shader appends {page, off | len << 16} to the queue's PASS
 * ring, in host memory, and counts them in pass_pc; the host copies them out
 * and counts the ones done in pass_cc.  Their RQ entries are held until then.
 * Entries before pass_floor belong to an earlier build of the rings.
 */
#define KNOD_PERSIST_GDA_PASS_RING 168
#define KNOD_PERSIST_GDA_PASS_MASK 176
#define KNOD_PERSIST_GDA_PASS_PC 180
#define KNOD_PERSIST_GDA_PASS_CC 184
#define KNOD_PERSIST_GDA_PASS_FLOOR 188
#define KNOD_PERSIST_GDA_PASS_ENTRIES 8192
#define KNOD_PERSIST_BYTES 16384
/* The ring buffer's layout, as net/knod.h lays it out for the NIC (the kernel
 * checks the two agree): doorbell records, then the RQ, then its CQ, then the
 * per-lane descriptors a program's bounds are read from.
 */
#define KNOD_PERSIST_RING_RQ_DB 0
#define KNOD_PERSIST_RING_CQ_DB 64
/* The SQ's record is two counters and the NIC reads the send one, the second. */
#define KNOD_PERSIST_RING_SQ_DB (128 + 4)
#define KNOD_PERSIST_RING_TX_CQ_DB 192
#define KNOD_PERSIST_RING_RQ_OFF 4096
#define KNOD_PERSIST_RING_CQ_OFF (4096 + 8192 * 64)
#define KNOD_PERSIST_RING_BDS_OFF (KNOD_PERSIST_RING_CQ_OFF + 8192 * 64)
#define KNOD_PERSIST_RING_TX_CQ_OFF (KNOD_PERSIST_RING_BDS_OFF + 256 * 64)
/* u32 per SQ entry: for the first WQE of each round, the RQ position its
 * packet came in on.  Nothing past it goes back to the RQ until it is sent.
 */
#define KNOD_PERSIST_RING_RQPOS_OFF (KNOD_PERSIST_RING_TX_CQ_OFF + 8192 * 64)
/* u32 per PASS ring entry: the RQ position its packet came in on. */
#define KNOD_PERSIST_RING_PASS_RQPOS_OFF (KNOD_PERSIST_RING_RQPOS_OFF + 8192 * 4)
#ifndef __ASSEMBLY__
#include <linux/types.h>
struct knod_persistent_gda {
	u64 ring;
	u64 rx_dma;
	u64 packets;
	u64 rounds;
	u32 rq_log;
	u32 rq_log_stride;
	u32 cq_log;
	u32 frag;
	u32 headroom;
	u32 mkey_be;
	u32 live;
	u32 gen;
	u64 rx_base;
	u64 bds;
	u32 ci;
	u32 posted_gen;
	u32 pause_ack;
	u32 pad;
	u64 sq;
	u32 sqn;
	u32 sq_mask;
	u32 tx_mkey_be;
	u32 tx_cq_log;
	u32 tx_gen;
	u32 pad1;
	u64 tx_packets;
	u64 tx_full;
	u32 sq_pc;
	u32 sq_cc;
	u32 tx_ci;
	u32 tx_posted_gen;
	u32 stagger;
	u32 stagger_mask;
	u64 pass_ring;
	u32 pass_mask;
	u32 pass_pc;
	u32 pass_cc;
	u32 pass_floor;
	u8 reserved[64];
};

struct knod_persistent_control {
	u32 version;
	u32 stop;
	u32 pause;
	u32 pad0;
	u64 gda_param;
	u32 gda_lds;
	u32 gda_waves;
	u8 reserved[32];
	u64 tx_db[KNOD_PERSIST_MAX_QUEUES];
	struct knod_persistent_gda gda[KNOD_PERSIST_MAX_QUEUES];
};
#endif
#endif
