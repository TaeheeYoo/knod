/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _KNOD_PERSISTENT_H
#define _KNOD_PERSISTENT_H
/* One workgroup per RX queue; no X dimension multiplier.
 *
 * The control block, and each queue's entry in it, which the host fills and
 * the engine in knod-blob's csrc/gda.c runs from.
 */
#define KNOD_PERSIST_VERSION 0x4b500018
#define KNOD_PERSIST_MAX_QUEUES 32
/* What a shader that appends PASS entries the host waits on interrupts with;
 * the low 23 bits are all an interrupt carries on every generation.
 */
#define KNOD_PERSIST_PASS_IRQ 0x4b4e44
/* LDS the waves of a queue meet in, past the program's stack, and how many
 * waves take packets at most.
 */
#define KNOD_PERSIST_GDA_LDS_BYTES 128
/* ...and what KNOD_BLOB_GDA_ENGINE_ORDERED's need: a 16-bit flow key and
 * two bits for each of a round's packets besides.
 */
#define KNOD_PERSIST_GDA_ORDER_LDS_BYTES 704
/* ...and what KNOD_BLOB_GDA_ENGINE_IPSEC's need: the AES T-tables, four of
 * 256 words, past the waves' meeting place; then for each of up to four waves
 * the aligned window over a kilobyte of payload it decrypts at a time; then
 * for each the frame it is on, read in one go and shifted so its ESP payload
 * starts on a word; then the round's PASS packets, which the waves share out.
 */
#define KNOD_PERSIST_GDA_IPSEC_TTAB_BYTES 4096
#define KNOD_PERSIST_GDA_IPSEC_BUF_BYTES 1056
#define KNOD_PERSIST_GDA_IPSEC_FRAME_BYTES 4160
#define KNOD_PERSIST_GDA_IPSEC_WORK_BYTES 3088
#define KNOD_PERSIST_GDA_IPSEC_LDS_BYTES \
	(KNOD_PERSIST_GDA_LDS_BYTES + KNOD_PERSIST_GDA_IPSEC_TTAB_BYTES + \
	 4 * KNOD_PERSIST_GDA_IPSEC_BUF_BYTES + \
	 4 * KNOD_PERSIST_GDA_IPSEC_FRAME_BYTES + \
	 KNOD_PERSIST_GDA_IPSEC_WORK_BYTES)
#define KNOD_PERSIST_GDA_WAVES_MAX 4
#define KNOD_PERSIST_GDA_PASS_ENTRIES 16384
/* regress_dbg[]: an RQ bound older than the one before it. */
#define KNOD_PERSIST_REGRESS_HITS	0
#define KNOD_PERSIST_REGRESS_S2		1
#define KNOD_PERSIST_REGRESS_DELTA	2	/* the bound minus the one before */
#define KNOD_PERSIST_REGRESS_BOUND	3
#define KNOD_PERSIST_REGRESS_SQ_PC	4
#define KNOD_PERSIST_REGRESS_SQ_CC	5
#define KNOD_PERSIST_REGRESS_PASS_CC	6
#define KNOD_PERSIST_REGRESS_CAND	7	/* the PASS candidate */
/* sync_dbg[]: an RX completion for another RQ entry than s2 says, or - bnxt -
 * not a plain RX one.
 */
#define KNOD_PERSIST_SYNC_HITS		0
#define KNOD_PERSIST_SYNC_ENTRIES	1	/* s2's low, the CQE's high */
#define KNOD_PERSIST_SYNC_KIND		2	/* mlx5 op_own, bnxt's type */
#define KNOD_PERSIST_BYTES 16384
/* The NIC formats a queue's rings can be in: a vendor's, of a generation of
 * its hardware, as each generation can change them.  An engine is built for
 * each, and the kernel runs the one of the NIC's.  Zero is none.
 */
#define KNOD_PERSIST_FMT_NONE 0
#define KNOD_PERSIST_FMT_MLX5_CX5 1	/* ConnectX-5 on, cyclic RQ: csrc/mlx5.h */
#define KNOD_PERSIST_FMT_BNXT_P5 2	/* BCM5750x (Thor): csrc/bnxt.h */
#define KNOD_PERSIST_FMT_BNXT_P7 3	/* BCM5760x (Thor2): csrc/bnxt.h */
/* db_key[]: what bnxt rings each of a queue's rings with, its index ORed in. */
#define KNOD_PERSIST_DB_RQ 0
#define KNOD_PERSIST_DB_RX_CQ 1
#define KNOD_PERSIST_DB_SQ 2
#define KNOD_PERSIST_DB_TX_CQ 3
#define KNOD_PERSIST_DB_KEYS 4
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
/* Past a PASS ring's last entry: the u32 count of entries appended, which the
 * shader writes, and this far on the u32 the host has finished with.
 */
#define KNOD_PERSIST_PASS_CC 32
/* A PASS entry's low half: what the NIC found of its checksums. */
#define KNOD_PERSIST_PASS_CSUM_OK	(1 << 0)	/* IP and L4 good */
#define KNOD_PERSIST_PASS_CSUM_INNER	(1 << 1)	/* the inner ones too */
/* KNOD_BLOB_GDA_ENGINE_IPSEC's: an ESP packet it decrypted for SA
 * KNOD_PERSIST_PASS_IPSEC_SA(), and whether its ICV failed.
 */
#define KNOD_PERSIST_PASS_IPSEC		(1 << 2)
#define KNOD_PERSIST_PASS_IPSEC_FAIL	(1 << 3)
#define KNOD_PERSIST_PASS_IPSEC_SA_SHIFT 8
#define KNOD_PERSIST_PASS_IPSEC_SA(e)	(((e) >> 8) & 0xff)
/* The IPsec table's entries, a power of two of them, the most a slot holds. */
#define KNOD_PERSIST_IPSEC_SA_MAX	256
/* Where an SA is in the table: the SPI's four bytes read as a little-endian
 * word, hashed to a first slot, and the next ones after it up to the probe
 * count, wrapping at the table's mask.
 */
#define KNOD_PERSIST_IPSEC_SA_HASH(spi)	((__u32)((spi) * 0x9e3779b1u) >> 24)
#define KNOD_PERSIST_IPSEC_SA_PROBE	8
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
	/* bnxt: the RQ has more entries than rq_log's, which are all that are
	 * ever posted; entry i holds page i & ((1 << rq_log) - 1).
	 */
	__u32 rq_ring_log;
	__u32 pad2;
	__u64 db_key[KNOD_PERSIST_DB_KEYS];
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
	/* XDP_PASS: the shader copies a packet to its slot in pass_stage, in
	 * host memory - entry i's at page i, at its offset in the RX page - and
	 * appends {off | len << 16} << 32 | KNOD_PERSIST_PASS_CSUM_* to the
	 * queue's PASS ring, counting them in
	 * pass_pc there and here.  Its RX page goes back to the RQ in the same
	 * round.  The host counts the ones it is done with past the ring; one
	 * that finds no slot free is dropped and counted in pass_full.
	 */
	__u64 pass_ring;
	__u64 pass_stage;
	__u32 pass_mask;
	__u32 pass_pc;
	__u64 pass_full;
	__u32 regress_dbg[8];	/* KNOD_PERSIST_REGRESS_* */
	__u32 sync_dbg[3];	/* KNOD_PERSIST_SYNC_* */
	/* The shader's, for the host to read: the oldest RQ entry it holds -
	 * the RQ producer is that plus the RQ's size - and whether the SQ went
	 * to error.
	 */
	__u32 rq_bound;
	__u32 tx_dead;
	__u8 reserved[12];
};

/* An inbound ESP SA, rfc4106(gcm(aes)), at the slot its SPI hashes to or
 * one probed past it.  The host fills it with active clear and sets active
 * last; the engine skips an inactive one.
 */
struct knod_persistent_ipsec_sa {
	__u32 spi;		/* the packet's four bytes, read little-endian */
	__u32 active;
	__u32 salt;		/* the key's last four bytes, as they come */
	__u32 rounds;		/* 10, 12 or 14; 0 for ChaCha20-Poly1305 */
	__u64 rk;		/* round keys, struct crypto_aes_ctx's key_enc;
				 * ChaCha20's key, eight words as they come
				 */
	__u64 hpow;		/* H^1 .. H^256, 16 bytes each, big endian */
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
	/* KNOD_BLOB_GDA_ENGINE_IPSEC's: the SA table, ipsec_sa_mask + 1
	 * entries looked up by SPI, and the AES T-tables it copies to LDS.
	 */
	__u64 ipsec_sa;
	__u64 ipsec_ttab;
	__u32 ipsec_sa_mask;
	__u8 reserved[12];
	/* Where each queue's NIC TX doorbell is in the GPU's address space.
	 * Written once when a shader lifetime starts, zero when the NIC
	 * publishes none.
	 */
	__u64 tx_db[KNOD_PERSIST_MAX_QUEUES];
	struct knod_persistent_gda gda[KNOD_PERSIST_MAX_QUEUES];
};
#endif
#endif
