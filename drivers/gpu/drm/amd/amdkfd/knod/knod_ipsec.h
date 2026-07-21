/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (c) 2021 Taehee Yoo <ap420073@gmail.com>
 * Copyright (c) 2021 Hoyeon Lee <hoyeon.rhee@gmail.com>
 */

#ifndef KNOD_IPSEC_H_
#define KNOD_IPSEC_H_

#include <linux/types.h>
#include <linux/xarray.h>
#include <linux/mutex.h>
#include <linux/jump_label.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/ktime.h>
#include <linux/mmzone.h>
#include <net/spsc_ring.h>
#include <net/knod.h>		/* KNOD_SPSC_MAX */

struct knod;
struct knod_mem;
struct dentry;
struct xfrm_state;
struct sk_buff;
struct task_struct;
struct net_device;
struct napi_struct;
struct knod_ipsec_priv;

#define KNOD_IPSEC_NR_SA		256
/* The shader-dispatch KAT installs one fake SA per fused_sub entry, so
 * its maximum batch size is bounded by NR_SA. Keep separate from
 * KNOD_IPSEC_PKT_BATCH so production can run larger batches without
 * growing the SA table BO.
 */
#define KNOD_IPSEC_KAT_MAX_BATCH	64
/* 128-bit window, 4 u32 words */
#define KNOD_IPSEC_REPLAY_WORDS		4
#define KNOD_IPSEC_REPLAY_BITS		(KNOD_IPSEC_REPLAY_WORDS * 32)
#define KNOD_IPSEC_REPLAY_BYTES		(KNOD_IPSEC_REPLAY_WORDS * 4)

/*
 * CPU-side per-queue sliding anti-replay window (knod_ipsec_sa_window).
 * Independent from the GPU-side REPLAY_BITS above - the shader's
 * replay region stays 128 bits for GPU-visible state, but the CPU path
 * needs a much larger window because with multi-queue RSS the packets
 * of a single SA may land on several RX queues due to NIC hash
 * collisions. Each per-queue window then sees only a sparse subset of
 * the SA's monotonic seq stream, and the seq gap between consecutive
 * packets arriving at one queue can exceed 128 easily. 2048 bits lets
 * the window absorb worst-case gaps (e.g. 8 queues x 256 batch).
 *
 * Sized as u64 words for easier bit-shift logic in the check function.
 */
#define KNOD_IPSEC_CPU_REPLAY_WORDS	32	/* 32 * 64 = 2048 bits */
#define KNOD_IPSEC_CPU_REPLAY_BITS	\
	(KNOD_IPSEC_CPU_REPLAY_WORDS * 64)

/*
 * Per-dispatch packet batch. The RX fused shader launches grid_y=nr_packets
 * workgroups and each workgroup indexes its own sub[wg_y] entry, so batch
 * scales linearly with GPU occupancy up to the LDS-bound concurrent
 * workgroup limit (~1024 on 64-CU gfx9 with 4 KB LDS per WG). Bumping this
 * grows:
 *   - struct knod_ipsec_fused_param  (sub[] inline in kernarg)
 *   - work_decrypt_pool VRAM          (BATCH * DECRYPT_PKT_SIZE)
 *   - struct knod_ipsec_work          (rx_bds[], rx_pkt_queue[], rx_pending[])
 */
#define KNOD_IPSEC_PKT_BATCH		512

/*
 * Kernarg layout consumed by the fused RX shader.
 *
 * The shader dereferences sa_table_addr/t_tables_addr from the top-level
 * struct and then iterates `sub[]` for per-packet work. Decrypted inner
 * packets are written to `out_addr` (VRAM); a CPU finish worker later
 * SDMA-copies them into a per-queue framework delivery-pool page and
 * publishes a `knod_pass_desc` onto the framework pass_pending ring. The
 * bd ring is not used for verdict delivery.
 */
struct knod_ipsec_fused_sub {
	__le64	pkt_addr;	/* raw packet VRAM addr (ETH start) */
	__le64	out_addr;	/* decrypted inner packet dest */
	__le64	bd_addr;	/* SPSC bd for direct verdict write */
	__le32	pkt_len;
	__le32	result_seq;	/* shader writes bswapped ESP seq here */
};

struct knod_ipsec_fused_param {
	__le64	sa_table_addr;		/* 0 */
	__le64	t_tables_addr;		/* 8 */
	__le64	sdma_ring_addr;		/* 16: SDMA ring buffer gaddr */
	__le32	nr_sa;			/* 24 */
	__le32	family_filter;		/* 28 */
	__le64	sdma_ctl_addr;		/* 32: GPU VA of sdma_ctl region */
	struct knod_ipsec_fused_sub sub[KNOD_IPSEC_PKT_BATCH]; /* 40 */
};

/*
 * GPU-visible SA table entry. Layout is shared with the GPU shader and
 * must remain stable / packed.
 */
struct knod_ipsec_sa_entry {
	/* network byte order in wire, LE in table */
	__le32	spi;
	__le32	dir;			/* 0=IN, 1=OUT */
	__le32	family;			/* AF_INET=2, AF_INET6=10 */
	__le32	flags;			/* bit0: ESN, bit1: CRYPT_ONLY */
	__le64	key_gpu_addr;		/* AES key buffer (VRAM) */
	__le64	htable_gpu_addr;	/* GHASH H-power table (VRAM) */
	__le64	t_tables_gpu_addr;	/* shared T-tables (VRAM) */
	u8	salt[4];
	__le32	key_len;		/* 16/24/32 */
	__le32	nr_rounds;		/* AES rounds: 10/12/14 */
	/* XFRM_MODE_TRANSPORT=0, XFRM_MODE_TUNNEL=1 */
	__le32	mode;
	__le64	replay_bitmap_addr;	/* GPU-visible replay bitmap */
	__le32	replay_window;		/* 64/128/256 */
	__le32	seq_hi;			/* ESN high-32 */
	__le64	seq_last;		/* last accepted sequence number */
	__le32	active;
	__le32	version;		/* rekey protection */
	__le64	stats_addr;		/* per-SA counters (optional) */
	__le64	_pad1;
};

#define KNOD_IPSEC_SA_ENTRY_SIZE	sizeof(struct knod_ipsec_sa_entry)
#define KNOD_IPSEC_SA_TABLE_SIZE	\
	(KNOD_IPSEC_NR_SA * KNOD_IPSEC_SA_ENTRY_SIZE)

/*
 * Replay bitmap + per-SA stats regions are appended to the SA entry table
 * inside the same backing BO. Keeping everything in one BO avoids the
 * multi-BO GPU VA mapping bug (see gtt_multi_bo_bug.md).
 */
#define KNOD_IPSEC_REPLAY_REGION_SIZE	\
	(KNOD_IPSEC_NR_SA * KNOD_IPSEC_REPLAY_BYTES)
#define KNOD_IPSEC_REPLAY_REGION_OFF	KNOD_IPSEC_SA_TABLE_SIZE

/*
 * Per-SA GPU-visible stats. The shader atomically increments these via
 * global_atomic_add_x2 on every successful decrypt. CPU reads them back
 * in xdo_state_update_stats to feed x->curlft.
 */
struct knod_ipsec_sa_gpu_stats {
	__le64	rx_packets;
	__le64	rx_bytes;
};

#define KNOD_IPSEC_SA_STATS_SIZE	sizeof(struct knod_ipsec_sa_gpu_stats)
#define KNOD_IPSEC_STATS_REGION_SIZE	\
	(KNOD_IPSEC_NR_SA * KNOD_IPSEC_SA_STATS_SIZE)
#define KNOD_IPSEC_STATS_REGION_OFF	\
	(KNOD_IPSEC_REPLAY_REGION_OFF + KNOD_IPSEC_REPLAY_REGION_SIZE)

#define KNOD_IPSEC_SA_BO_SIZE		\
	(KNOD_IPSEC_SA_TABLE_SIZE + KNOD_IPSEC_REPLAY_REGION_SIZE + \
	 KNOD_IPSEC_STATS_REGION_SIZE)

/*
 * RFC 4303 anti-replay sliding window - CPU-side, per-SA, per-RXQ.
 *
 * RSS hashes ESP flows on (saddr, daddr, proto, SPI) so that every packet
 * of a given SA lands on the same NIC RX queue. That means a single writer
 * (the NIC dd NAPI for that queue) owns the window and no locking is
 * required on the fast path. Replicated per queue because different SAs
 * may still be hashed to different queues, and we do not want false
 * sharing between queues on a shared cacheline.
 */
struct knod_ipsec_sa_window {
	u64 top_seq;			/* highest accepted seq */
	/* N*64-bit sliding window */
	u64 bitmap[KNOD_IPSEC_CPU_REPLAY_WORDS];
};

/* CPU-side slot metadata */
struct knod_ipsec_sa_slot {
	struct xfrm_state *x;		/* back pointer (CPU only) */
	struct knod_mem *key_mem;
	struct knod_mem *htable_mem;
	struct knod_mem *replay_mem;
	u32 spi;			/* host order */
	u32 slot_idx;
	u32 version;
	bool active;
	/* Per-RXQ sliding window state. Owned by the NIC dd NAPI for that
	 * queue - do not touch from control plane while SA is active.
	 */
	struct knod_ipsec_sa_window win[KNOD_SPSC_MAX];
};

/* Percpu stats for observability */
struct knod_ipsec_stats {
	/* RX */
	u64 rx_packets;
	u64 rx_bytes;
	u64 rx_dispatches;
	u64 rx_batch_total;
	u64 rx_batch_max;
	/* SDMA copy observability: per dispatch we emit 1 copy per raw-bypass
	 * or tunnel packet, 2 copies per transport packet (outer L3 + inner
	 * payload). rx_sdma_copies_total accumulates every call; max tracks
	 * the peak single-dispatch count; bytes tracks total DMA volume.
	 */
	u64 rx_sdma_copies_total;
	u64 rx_sdma_copies_max;
	u64 rx_sdma_bytes_total;
	u64 rx_drop_icv;
	u64 rx_drop_replay;
	u64 rx_drop_no_sa;
	u64 rx_drop_malformed;
	u64 rx_drop_desc_full;
	u64 rx_drop_sdma_full;
	/* Per-phase RX dispatch timings, accumulated per percpu counter.
	 * Hot path guarded by ipsec_stats_enabled_key static branch so
	 * they cost zero cycles when disabled.
	 *
	 * rx_build_ns     : try_rx pre-scan + per-queue drain loop
	 *                   (CPU staging work into kernarg sub[]).
	 * rx_gpu_ns       : spin on GPU completion signal.
	 * rx_sdma_ns      : spin on SDMA fence after finish scheduled
	 *                   per-packet SDMA copies.
	 * rx_finalise_ns  : finish_rx_deliver CPU work excluding SDMA
	 *                   fence wait (verdict loop + desc publish +
	 *                   per-queue NAPI schedule).
	 * rx_total_ns     : end-to-end try_rx call time (build + dispatch
	 *                   wait + finalise + napi kicks).
	 * rx_idle_ns      : time the dispatcher spent in usleep_range
	 *                   waiting for work when both try_tx and
	 *                   try_rx returned false.
	 */
	u64 rx_build_ns;
	u64 rx_gpu_ns;
	u64 rx_sdma_ns;
	u64 rx_finalise_ns;
	u64 rx_total_ns;
	u64 rx_idle_ns;
	/* Control plane */
	u64 sa_add;
	u64 sa_del;
	u64 sa_rekey;
	/* Debug: drain_rx pipeline visibility */
	u64 drain_calls;
	u64 drain_found;
	u64 drain_delivered;
	u64 finish_produced;
	u64 rx_peek_total;
	u64 rx_submit_fail;
	/* drain_rx per-phase timing (ns, summed). Each drain_rx call
	 * processes `drain_found` descriptors; these buckets split the
	 * CPU work per-phase so we can see which step dominates:
	 *   drain_alloc_ns  : knod_pass_build_skb cost
	 *   drain_copy_ns   : legacy copy cost (0 - delivery is zero-copy)
	 *   drain_proto_ns  : L3 header patch + secpath setup
	 *   drain_gro_ns    : netif_receive_skb_list (stack entry)
	 *   drain_total_ns  : end-to-end drain_rx call time
	 * Guarded by ipsec_stats_enabled_key so zero cost when off.
	 */
	u64 drain_alloc_ns;
	u64 drain_copy_ns;
	u64 drain_proto_ns;
	u64 drain_gro_ns;
	u64 drain_total_ns;
	u64 drain_zc_ok;
	u64 drain_zc_fallback;
};

/*
 * Work-slot pool owned by the dispatcher kthread. Depth-2 pipelining:
 * while one slot is executing on the GPU, the dispatcher can build and
 * submit the next batch into the other slot and finalise the one that
 * just completed. kaql[0] is still a single AQL queue; multiple
 * in-flight dispatches are queued in-order and complete in-order.
 *
 * A slot's lifecycle:
 *   EMPTY          -> try_tx/try_rx fills kernarg and submits -> INFLIGHT
 *   INFLIGHT       -> GPU running; dispatcher polls completion signal
 *   INFLIGHT       -> signal fires -> start SDMA copies + fence (no spin)
 *                    -> SDMA_PENDING
 *   SDMA_PENDING   -> dispatcher polls SDMA fence (non-blocking)
 *   SDMA_PENDING   -> fence done -> desc publish, napi kicks, bd PASS,
 *                    stats -> EMPTY
 *
 * The SDMA_PENDING state decouples the SDMA fence wait from the
 * dispatcher loop so the CPU never busy-spins on the fence. While
 * one slot sits in SDMA_PENDING, the dispatcher can build and
 * submit the next batch into another EMPTY slot - true 3-way
 * parallelism of GPU execution, SDMA transfer, and CPU build.
 */
#define KNOD_IPSEC_NR_WORK		4

/*
 * Front offset reserved in each delivery page (= IPv4 transport L3 size).
 * The shader decrypts into a per-work VRAM output buffer; finish_rx_deliver
 * then SDMA-lays the packet into the delivery page by mode:
 *
 *   transport: outer L3 header (20B IPv4 / 40B IPv6) to page+0, decrypted
 *              L4 payload to page+l3_len; inner_off = 0.
 *   tunnel:    decrypted inner L3 packet to page+GTT_OUT_L3_OFF, leaving
 *              20B of headroom at the front; inner_off = 20.
 *
 * (The name is a holdover from a removed mode where the shader wrote
 * straight into a GTT slot at this offset.)
 */
#define KNOD_IPSEC_GTT_OUT_L3_OFF	20

/*
 * GPU-initiated SDMA control block, placed at a fixed offset after
 * knod_ipsec_fused_param in the same kernarg BO.  The shader's Phase 12
 * uses atomic counters here to coordinate multi-workgroup SDMA ring
 * writes without CPU involvement.
 */
#define KNOD_IPSEC_SDMA_CTL_OFF \
	ALIGN(sizeof(struct knod_ipsec_fused_param), 64)

struct knod_ipsec_sdma_ctl {
	/*  0: atomic - SDMA-needing WGs increment */
	__le32	claim_counter;
	__le32	done_counter;		/*  4: atomic - ALL WGs increment */
	/*  8: current wptr byte offset (CPU snapshot) */
	__le64	wptr_val;
	__le64	fence_addr;		/* 16: SDMA fence write target GPU VA */
	/* 24: value SDMA writes on completion */
	__le32	fence_val;
	/* 28: wptr_val / 4 (dword index into ring) */
	__le32	wptr_base_dw;
	__le32	ring_mask;		/* 32: (ring_size_bytes/4) - 1 */
	__le32	nr_total_wg;		/* 36: grid_size_y = nr_packets */
	__le32	copy_hdr;		/* 40: SDMA COPY_LINEAR header dword */
	__le32	fence_hdr;		/* 44: SDMA FENCE header dword */
	__le32	gpu_sdma_ready;		/* 48: last WG sets 1 -> CPU polls */
	/* 52: total SDMA COPY packets emitted */
	__le32	final_sdma_count;
	/* 56: GPU VA of HW wptr (queue->gaddr+8) */
	__le64	wptr_gpu_addr;
};

enum knod_ipsec_work_state {
	KNOD_WORK_EMPTY = 0,
	KNOD_WORK_INFLIGHT,
	KNOD_WORK_SDMA_PENDING,
};

/*
 * Per-work RX decrypt output buffer size. AES-CTR decrypt writes plaintext
 * here instead of overwriting the ciphertext in-place (which would corrupt
 * the data before GHASH reads it). One slot per packet in the batch.
 *
 * Must hold the largest expected plaintext (ctext_len, before ESP trailer
 * strip). Sized for MTU 9000 ESP jumbo frames (up to ~9200B total),
 * rounded up to 16 KB. At PKT_BATCH=64 the total pool is 1 MB of VRAM.
 * Smaller values silently corrupt adjacent slots and eventually fault
 * past the end of the pool BO.
 */
#define KNOD_IPSEC_DECRYPT_PKT_SIZE	16384
#define KNOD_IPSEC_DECRYPT_WORK_SIZE	\
	((size_t)KNOD_IPSEC_PKT_BATCH * KNOD_IPSEC_DECRYPT_PKT_SIZE)

/*
 * Per-work kernarg and decrypt buffers are SLICES of a single large
 * BO owned by `struct knod_ipsec_works`, not individual BOs. Allocating
 * many small BOs and mapping them all to the KFD process GPU VA hits a
 * long-standing AMDKFD issue where only the first BO is reliably mapped
 * (see memory/gtt_multi_bo_bug.md) - subsequent BOs fault on GPU access.
 * One large pool BO, sliced at fixed offsets, sidesteps this entirely.
 */
struct knod_ipsec_slice {
	void	*kaddr;
	u64	gaddr;
};

/*
 * Per-packet finish state built by knod_ipsec_finish_rx_deliver() while it
 * schedules SDMA copies, then read back to publish desc_ring entries.
 *
 * Kept as an array inside struct knod_ipsec_work so the dispatcher does
 * not have to stack-allocate BATCH * sizeof(...) on every finalise - at
 * large PKT_BATCH values (512+) stack allocation would overflow the
 * 16 KB kernel stack.
 */
struct knod_ipsec_rx_pending {
	netmem_ref netmem;	/* delivery page from framework pass_pool */
	u32	inner_len;	/* bytes copied into the delivery page   */
	u32	sa_slot;	/* SA table index, or KNOD_IPSEC_NR_SA (raw) */
	u16	rxq_idx;	/* which priv->rxq[] this packet belongs to */
	u8	mode;		/* XFRM_MODE_TRANSPORT / TUNNEL          */
	u8	next_hdr;	/* ESP trailer next_hdr                  */
	u8	family;		/* AF_INET / AF_INET6                    */
	u8	inner_off;	/* byte offset within the delivery page  */
	u8	_pad[2];
};

struct knod_ipsec_work {
	/* Views into the shared pools in priv. No per-work BO. */
	struct knod_ipsec_slice	param;	/* kernarg slice (VRAM pool) */
	/* RX decrypt output (VRAM pool) */
	u64			rx_out_gaddr;
	/* Pipelined slot state + deferred finalise tracking. The dispatcher
	 * sets state to INFLIGHT on submit, polls completion, then flips to
	 * EMPTY after finalise. Timestamps / per-queue napi info captured
	 * at build time get consumed when finalise runs later.
	 */
	enum knod_ipsec_work_state state;
	u64			t_build_start;
	u64			t_build_end;
	u64			t_submit;
	u64			t_finalise_start;
	/* Per-queue tracker for deferred napi_schedule. try_rx records
	 * which NIC RX queues had packets drained into this slot so the
	 * finalise path (running later, possibly one iteration later) can
	 * wake those NAPIs after finalise completes.
	 */
	u16			per_q_touched[KNOD_SPSC_MAX];
	int			per_q_n;
	/* Per-dispatch state (owned by dispatcher) */
	s64			sigval;
	u64			dispatch_ts;
	/* SDMA deferred-fence state. When the work transitions from
	 * INFLIGHT -> SDMA_PENDING, finish_rx_deliver queues copies +
	 * fence but does NOT spin. The dispatcher checks sdma_fence_ptr
	 * on the next iteration and transitions to EMPTY once the fence
	 * fires. sdma_fence_target is the expected fence value; the
	 * pointer is the host-visible signal->value location.
	 */
	u32			sdma_fence_target;
	s64			*sdma_fence_ptr;
	u64			sdma_submit_ns;
	/* Carry the SDMA fence wait time out of finish_rx_deliver so
	 * the caller (try_rx) can subtract it from the finalise phase
	 * and report it as rx_sdma_ns. Zero when stats are disabled.
	 */
	u64			sdma_wait_ns;
	/* Per-dispatch SDMA copy accounting (populated by finish_rx_deliver).
	 * rx_sdma_copies = number of knod_sdma_copy() calls issued this
	 * batch (1 per raw/tunnel packet, 2 per transport packet). bytes =
	 * total bytes DMA'd. Zero when stats are disabled.
	 */
	u32			rx_sdma_copies;
	u32			rx_sdma_bytes;
	/* Deferred SDMA completion state. finish_rx_deliver stores
	 * n_sdma_pending + pkt_idx_of[] so the dispatcher's
	 * SDMA_PENDING -> EMPTY transition can publish descs and mark
	 * bds without re-scanning the verdict loop.
	 */
	int			n_sdma_pending;
	u16			sdma_pkt_idx_of[KNOD_IPSEC_PKT_BATCH];
	int			nr_packets;
	/* RX: napi to kick after GPU writes verdicts (single-queue fallback
	 * for KAT; production multi-queue dispatch schedules per-queue napis
	 * at dispatcher level and leaves rx_napi == NULL).
	 */
	struct napi_struct	*rx_napi;
	int			rx_queue_idx;
	struct spsc_bd		*rx_bds[KNOD_IPSEC_PKT_BATCH];
	/* Per-packet queue index for multi-queue batched RX dispatches.
	 * finish_rx_deliver uses this to route each decrypted packet to
	 * the correct priv->rxq[] delivery pool + desc_ring.
	 */
	u8			rx_pkt_queue[KNOD_IPSEC_PKT_BATCH];
	/* Heap-backed finish-state scratchpad used by finish_rx_deliver.
	 * Sized to KNOD_IPSEC_PKT_BATCH so we never overflow the dispatcher
	 * kernel stack when BATCH grows.
	 */
	struct knod_ipsec_rx_pending rx_pending[KNOD_IPSEC_PKT_BATCH];
};

/*
 * Hard upper bound on parallel dispatchers. Each dispatcher owns one
 * kaql[i] / sdma[i] pair, one private slice of work_pool and the
 * backing pool BOs, and one contiguous range of RX queues. The actual
 * count is knod_ipsec_priv::nr_dispatchers, set at
 * start time from knod->queue_cnt.
 *
 * Bumped beyond 1 for real parallelism: one GPU AQL queue is a
 * hardware FIFO, so throughput is single-kaql drain rate bound. Two
 * kaqls let the GPU scheduler run two dispatches on disjoint CUs in
 * parallel, subject to CU / memory bandwidth contention.
 */
#define KNOD_IPSEC_MAX_DISPATCHERS	4

/*
 * Per-dispatcher runtime state. Each dispatcher kthread owns exactly
 * one of these and never shares hot-path state with any other
 * dispatcher - cursors, in-flight work slots, pool BOs, fence counters
 * and the kaql/sdma index are all private.
 *
 * Cross-dispatcher sharing lives in knod_ipsec_priv: the SA table +
 * slot array + spi_to_slot xarray (read-mostly), the per-CPU stats,
 * and the delivery pool / desc_ring for RX delivery (but each rxq slot is
 * only drained by the owning dispatcher, so no locking needed inside
 * a queue).
 */
struct knod_ipsec_dispatcher {
	struct knod_ipsec_priv	*priv;
	struct task_struct	*kthread;

	/* kaql[kaql_idx] + sdma[kaql_idx] owned exclusively by this disp. */
	int			kaql_idx;

	/* Slice into priv->work_pool[]. Dispatcher N uses slots
	 * [work_first, work_first+work_count). work_count is usually
	 * KNOD_IPSEC_NR_WORK but can be smaller if the final dispatcher
	 * got a partial slice.
	 */
	int			work_first;
	int			work_count;

	/* Private backing BOs for this dispatcher's work slice. Each
	 * slot within [work_first, work_first+work_count) gets its own
	 * sub-range of these BOs, so no cross-dispatcher aliasing.
	 */
	struct knod_mem		*param_pool;
	struct knod_mem		*decrypt_pool;

	/* RX queue range this dispatcher drains. [rxq_first, rxq_first+
	 * rxq_count) indexes into priv->rxq[] and knodev->wpriv[].spsc_bds.
	 */
	int			rxq_first;
	int			rxq_count;

	/* Hot-path cursors, previously locals in the dispatcher loop. */
	int			rx_rr;
	int			build_cursor;

	/* Forward-looking AQL completion-signal counter. See old priv->
	 * dispatch_sigval_next comment; now per-dispatcher because each
	 * disp has its own kaql signal.
	 */
	s64			dispatch_sigval_next;
};

struct knod_ipsec_priv {
	struct knod *knod;
	struct knod_dev *knodev;

	/* Shared GCM tables (VRAM, one per priv, owned by knod ctx) */
	struct knod_mem *t_tables;

	/* GPU-visible SA table */
	struct knod_mem *sa_table;

	/* CPU-side slot metadata */
	struct knod_ipsec_sa_slot slots[KNOD_IPSEC_NR_SA];
	struct xarray spi_to_slot;
	struct mutex slot_lock;

	/*
	 * Work pool is sized NR_WORK * MAX_DISPATCHERS so each
	 * dispatcher gets its own NR_WORK-sized slice via work_first.
	 * With nr_dispatchers=1 only the first slice is populated, so
	 * runtime cost is identical to the old single-slot layout when
	 * a single dispatcher is in use.
	 */
	struct knod_ipsec_work	work_pool[KNOD_IPSEC_NR_WORK *
					  KNOD_IPSEC_MAX_DISPATCHERS];

	/* Number of NIC RX queues bound to the NOD (<= KNOD_SPSC_MAX); the
	 * finish worker bounds-checks the shader's queue index against it.
	 */
	int			nr_rxq;

	/* Dispatcher state. nr_dispatchers <= KNOD_IPSEC_MAX_DISPATCHERS,
	 * set at start time from the knod queue_cnt the accel was
	 * created with. Each disp[i] owns kaql[i] / sdma[i].
	 */
	struct knod_ipsec_dispatcher disp[KNOD_IPSEC_MAX_DISPATCHERS];
	int			nr_dispatchers;
	bool			running;
	u32			pkt_batch;

	/* Shaders */
	size_t shader_size;
	int isa_version;

	/* Observability */
	struct dentry *debug_dir;
	struct knod_ipsec_stats __percpu *stats;

	/* Persistent KAT scratch BO. Allocated once at priv init, reused on
	 * every KAT invocation. Re-allocating per-KAT re-triggers the GTT/VRAM
	 * multi-BO mapping symptom (only the first BO is reliably mapped on
	 * the KFD process VM), which is the same class of bug documented for
	 * the BPF delivery path. One long-lived BO sidesteps it entirely.
	 */
	struct knod_mem *kat_scratch;
};

/* Public entry points for NIC consumers. */
struct spsc_bd;
int knod_ipsec_rx_submit(struct knod_ipsec_fused_sub *sub, int nr,
			 struct napi_struct *napi, int queue_idx);
int knod_ipsec_rx_submit_bds(struct knod_ipsec_fused_sub *sub,
			     struct spsc_bd **bds, int nr,
			     struct napi_struct *napi, int queue_idx);

#endif /* KNOD_IPSEC_H_ */
