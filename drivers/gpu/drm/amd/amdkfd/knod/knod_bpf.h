/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (c) 2021 Taehee Yoo <ap420073@gmail.com>
 * Copyright (c) 2021 Hoyeon Lee <hoyeon.rhee@gmail.com>
 */

#ifndef KFD_BPF_H_INCLUDED
#define KFD_BPF_H_INCLUDED

#include <linux/align.h>
#include <linux/math.h>
#include <uapi/linux/bpf.h>
#include <net/xdp.h>
#include <net/netmem.h>
#include <net/netlink.h>
#include <net/page_pool/helpers.h>
#include <net/ip.h>
#include <net/net_namespace.h>
#include <net/gro_cells.h>
#include <net/rtnetlink.h>
#include <net/protocol.h>
#include <net/netns/generic.h>
#include <net/xdp.h>
#include <net/netdev_lock.h>
#include <net/spsc_ring.h>
#include <linux/bpf.h>
#include <linux/bpf_verifier.h>
#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/skbuff.h>
#include <linux/net.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/etherdevice.h>
#include <linux/hash.h>
#include <linux/netdevice.h>
#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/bpf_verifier.h>
#include <linux/debugfs.h>
#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/rtnetlink.h>
#include <linux/workqueue.h>
#include <linux/ktime.h>
#include <linux/static_key.h>
#include <linux/wait.h>
#include <uapi/linux/knod_blob.h>
#include "knod_amdgpu_insn.h"
#include "../../../../../../net/core/devmem.h"
#include "../amdgpu/amdgpu_vm.h"
#include "knod_bpf.h"
#include "kfd_knod.h"

#define KNOD_BPF_BACKLOGS_MAX		65536
#define KNOD_BPF_INFLIGHT		3	/* triple-buffered dispatches */
#define KNOD_BPF_WORKGROUPS_DEFAULT     256
#define KNOD_BPF_WORKGROUPS_MIN         64
#define KNOD_BPF_WORKGROUPS_MAX         256
#define KNOD_BPF_EXPIRE_DEFAULT		10
#define KNOD_BPF_EXPIRE_MIN		1
#define KNOD_BPF_EXPIRE_MAX		1000
/* Nothing reaches LDS - not the JIT, not a blob routine - so none is asked for.
 * What it would cost is workgroups per CU: at 256 work-items the registers
 * already allow only one and LDS would be free to take, but at 64 they allow
 * four and taking all the LDS cuts that back to one.
 */
#define KNOD_BPF_LDS_SIZE		0
#define QUEUE_SIZE_DGPU			8192
#define QUEUE_SIZE_IGPU			2048
#define KNOD_MAX_BDS			(KNOD_BPF_BACKLOGS_MAX / KNOD_SPSC_MAX)

#define MAX_KEY_SIZE		64 /* 64Bytes */

#define knod_prog_first_meta(knod_prog)					\
	list_first_entry(&(knod_prog)->insns, struct knod_insn_meta, l)
#define knod_prog_last_meta(knod_prog)					\
	list_last_entry(&(knod_prog)->insns, struct knod_insn_meta, l)
#define knod_prog_pre_last_meta(knod_prog)				\
	list_last_entry(&(knod_prog)->pre_insns, struct knod_insn_meta, l)
#define knod_meta_next(meta)     list_next_entry(meta, l)
#define knod_meta_prev(meta)     list_prev_entry(meta, l)

#define knod_for_each_insn_walk2(knod_prog, pos, next)			  \
	for (pos = list_first_entry(&(knod_prog)->insns, typeof(*pos), l),\
			next = list_next_entry(pos, l);			  \
			&(knod_prog)->insns != &pos->l &&                 \
			&(knod_prog)->insns != &next->l;                  \
			pos = knod_meta_next(pos),                        \
			next = knod_meta_next(pos))

#define knod_for_each_insn_walk3(knod_prog, pos, next, next2)		  \
	for (pos = list_first_entry(&(knod_prog)->insns, typeof(*pos), l),\
			next = list_next_entry(pos, l),			  \
			next2 = list_next_entry(next, l);		  \
			&(knod_prog)->insns != &pos->l &&		  \
			&(knod_prog)->insns != &next->l &&		  \
			&(knod_prog)->insns != &next2->l;		  \
			pos = knod_meta_next(pos),			  \
			next = knod_meta_next(pos),			  \
			next2 = knod_meta_next(next))

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

#define KNOD_BPF_HASH_NEXT_END		0x7FFFFFFFU
#define KNOD_BPF_HASH_NEXT_DELETED	0x80000000U
#define KNOD_BPF_HASH_NEXT_MASK		0x7FFFFFFFU

/* Key and value are both 8-byte aligned so an atomic can land on either.
 * The padding is in the published offsets rather than here, because a key's
 * size is only known at runtime and the prebuilt routines are assembled
 * against those offsets.
 */
struct knod_bpf_hash_elem_obj {
	unsigned int next;
	unsigned char kv[] __aligned(KNOD_BLOB_ELEM_KV_OFF);
};

static inline unsigned int knod_bpf_hash_value_off(unsigned int key_size)
{
	return KNOD_BLOB_ELEM_VALUE_OFF(DIV_ROUND_UP(key_size, 4));
}

static inline unsigned int knod_bpf_hash_elem_size(unsigned int key_size,
						   unsigned int value_size)
{
	return knod_bpf_hash_value_off(key_size) + roundup(value_size, 8);
}

struct knod_bpf_map_hash_meta_obj {
	unsigned int n_buckets;
	unsigned int hashrnd;
	unsigned int cur;
	unsigned int elem_size;
	void *q;
	void *elems;
	unsigned int gc_count;
	void *gc_list;
};

struct knod_bpf_map_array_meta_obj {
	u32 per_instance_size;	/* value_size * max_entries (one instance) */
	u32 n_instances;	/* 1 for ARRAY, num_possible_cpus for PERCPU */
};

union knod_bpf_map_meta_obj {
	struct knod_bpf_map_hash_meta_obj hmeta;
	struct knod_bpf_map_array_meta_obj ameta;
};

struct knod_bpf_map_obj {
	enum bpf_map_type map_type;
	unsigned int key_size;
	unsigned int value_size;
	unsigned int max_entries;
	unsigned int id;
	unsigned long map_extra; /* any per-map-type extra fields */
	unsigned int map_flags;
	union knod_bpf_map_meta_obj meta;
	int mutex;
	/* Per-CPU counters live here and a program updates them with a
	 * 64-bit atomic, which faults on RDNA3 unless 8-byte aligned.
	 * "RDNA3" ISA 3.3.3:
	 * https://docs.amd.com/v/u/en-US/rdna3-shader-instruction-set-architecture-feb-2023_0
	 */
	unsigned char bucket[] __aligned(8);
};

struct knod_bpf_map {
	struct list_head list;
	struct knod_mem *mem, *queue_mem, *hash_elems_mem, *gc_mem;
	/* ptr to mem_k->kaddr */
	struct knod_bpf_map_obj *knod_map_obj;
	/* What a prebuilt routine is told about this map, at the end of the
	 * same BO.  It restates what is above in a layout a blob can read
	 * without knowing any of the kernel's own types.
	 */
	struct knod_blob_map_desc *desc;
	u64 desc_gaddr;
	struct bpf_offloaded_map *offmap;
	struct knod_bpf_priv *priv;
};

struct knod_bpf_queue_desc {
	u64 pool_gaddr;		/* SPSC pool GTT address for this queue */
	u64 base_gaddr;		/* dma-buf base address for this queue */
	u32 count;		/* number of packets from this queue */
	/* was start_idx; kept for global_load_dwordx4 layout */
	u32 _pad;
	u32 ring_start;		/* acquired cursor at peek time */
	u32 ring_mask;		/* capacity - 1 */
};

struct knod_bpf_param {
	u32 nr_backlogs;
	u32 nr_queues;
	u32 spsc_stride;
	u32 _pad0;
	/* Shift counts the prologue needs.  They follow the module parameters,
	 * so a shader built once cannot carry them as immediates; it loads them
	 * from here instead.  Kept in pairs the prologue can reach with the
	 * two-dword scalar load it already has.
	 */
	u32 batch_shift;
	u32 wg_shift;
	u32 page_shift;
	u32 spsc_shift;
	u64 ktime_ns;		/* snapshot of ktime_get_ns() at dispatch */
	u32 pass_count[KNOD_SPSC_MAX];	/* per-queue atomic XDP_PASS counter */
	/* per-queue GTT pass_meta_buf GPU addr */
	u64 pass_meta_buf_gaddr[KNOD_SPSC_MAX];
	struct knod_bpf_queue_desc queues[KNOD_SPSC_MAX];
	/* backlog indices of PASS packets */
	u16 pass_indices[KNOD_BPF_BACKLOGS_MAX];
	struct knod_bpf_subparam_obj sub[KNOD_BPF_BACKLOGS_MAX];
};

struct knod_packet {
	union {
		netmem_ref netmem;
		void *kaddr;
	};
	u16 len;
	u16 off;
};

/* Single Queue Worok */
struct knod_bpf_work_sq {
	struct list_head list;
	struct knod_mem *param;
	int queue_idx[KNOD_SPSC_MAX];
	ktime_t dispatch_time;
	s64 sigval;
	unsigned long expire;
	int backlogs;
};

struct knod_bpf_reg_state {
	struct bpf_reg_state reg;
	int stack_off;
	int packet_off;
	bool var_off;
};

/* Structurized CFG branch types */
enum knod_branch_type {
	KNOD_BR_NONE = 0,	/* not a branch */
	/* backward jump to exit: inline retval + done_mask update */
	KNOD_BR_DIRECT_EXIT,
	KNOD_BR_FORWARD_SKIP,	/* forward jump: skip region via EXEC mask */
	KNOD_BR_FORWARD_GOTO,	/* forward jump crossing other branch scopes */
};

#define KNOD_META_INSNS		1024
#define AMDGPU_INSN_SKIP	-1
struct knod_insn_meta {
	struct bpf_insn insn;
	short bpf_insn_idx;

	/* Set on the store of a percpu read-modify-write, pointing at the add
	 * that gave the amount, so the store can be emitted as one atomic.
	 * @percpu_rmw_swapped says the add found the map's value in its source
	 * rather than its destination, which puts the amount on the other side.
	 */
	struct knod_insn_meta *percpu_rmw_add;
	bool percpu_rmw_swapped;
	/* Every lane reaches the same element, so the wave can send one atomic
	 * between them instead of one each.
	 */
	bool percpu_rmw_uniform;

	/* A routine spliced in whole.  The JIT does not look inside it: it only
	 * has to know how many bytes it added, because the offsets every branch
	 * is resolved against are counted from the front of the program.
	 *
	 * @blob_at is which emitted instruction it goes in front of, so a
	 * routine that needs its arguments set up first can have them emitted
	 * into the same meta.  Zero puts it at the front, which is where the
	 * prologue and the epilogue want it.
	 */
	const u32 *blob;
	u32 blob_size;
	u32 blob_at;

	struct amdgcn_insn amdgpu_insn[KNOD_META_INSNS];
	u32 amdgpu_insn_idx;
	u32 amdgpu_insns;

	union {
		/* pointer ops (ld/st/xadd) */
		struct {
			struct bpf_reg_state ptr;
			struct bpf_insn *paired_st;
			s16 ldst_gather_len;
			bool ptr_not_const;
			struct {
				s16 range_start;
				s16 range_end;
				bool do_init;
			} pkt_cache;
			bool xadd_over_16bit;
			bool xadd_maybe_16bit;
		};
		/* jump */
		struct {
			struct knod_insn_meta *jmp_dst;
			bool jump_neg_op;
			u32 num_insns_after_br; /* only for BPF-to-BPF calls */
			/* structurized CFG */
			enum knod_branch_type branch_type;
			/* SGPR index for s_and_saveexec_b64 */
			u8 exec_save_sreg;
			/* where EXEC is restored */
			struct knod_insn_meta *merge_point;
		};
		/* function calls */
		struct {
			u32 func_id;
			struct bpf_reg_state arg1;
			struct knod_bpf_reg_state arg2;
		};
		/* We are interested in range info for operands of ALU
		 * operations. For example, shift amount, multiplicand and
		 * multiplier etc.
		 */
		struct {
			u64 umin_src;
			u64 umax_src;
			u64 umin_dst;
			u64 umax_dst;
		};
	};

	struct knod_bpf_reg_state sreg;
	struct knod_bpf_reg_state dreg;
	struct knod_bpf_reg_state kreg;
	struct knod_bpf_reg_state vreg;
	unsigned int off;
	unsigned short flags;
	unsigned short subprog_idx;
	bool is_merge_point;	/* EXEC restore target */
	u8 restore_sreg;	/* SGPR to restore EXEC from at merge point */
	int linear_idx;		/* position in the (reordered) emission list */
	struct list_head l;
};

/* Encode one GPU instruction at @meta's running slot and advance it.
 * @meta->amdgpu_insns is both the cursor during emission and the final
 * instruction count afterwards.  @fn names a knod_amdgpu_insn.h encoder
 * without its emit_ prefix (e.g. v_add32 for emit_v_add32); the macro
 * pastes it back, so call sites read knod_emit(priv, meta, v_add32, ...).
 */
#define knod_emit(priv, meta, fn, ...)					\
	do {								\
		struct knod_insn_meta *__m = (meta);			\
									\
		emit_##fn((priv)->isa_version,				\
			  &__m->amdgpu_insn[__m->amdgpu_insns],		\
			  ##__VA_ARGS__);				\
		__m->amdgpu_insns++;					\
	} while (0)

/* JIT debug/error trace: auto-prefix with "knod_jit <func>:<line>".
 * knod_jit_dbg() is a pr_debug(), so it is off by default and toggled
 * with dynamic debug; knod_jit_err() always fires.
 */
#define knod_jit_dbg(fmt, ...)						\
	pr_debug("knod_jit %s:%d" fmt, __func__, __LINE__, ##__VA_ARGS__)
#define knod_jit_err(fmt, ...)						\
	pr_err("knod_jit %s:%d" fmt, __func__, __LINE__, ##__VA_ARGS__)

#define BPF_SIZE_MASK   0x18

struct knod_bb;		/* basic-block CFG analysis (knod_bpf.c) */

struct knod_prog {
	struct knod *knod;
	struct knod_dev *knodev;

	u64 *prog;
	unsigned int prog_len;
	unsigned int __prog_alloc_len;
	int max_stack_off;
	int max_packet_off;

	struct knod_insn_meta *meta;
	enum bpf_prog_type type;
	struct list_head pre_insns;
	struct list_head post_insns;
	struct list_head insns;
	unsigned int n_insns;
	unsigned int pre_n_insns;
	int insn_idx;

	/* Structurized CFG state.  The three below are the same on every
	 * generation and never move; they are kept per program so the cfg
	 * view can print them next to what used them.
	 */
	u8 done_mask_sreg;
	u8 exec_save_base;
	/* in-bounds EXEC snapshot for verdict publish */
	u8 initial_exec_sreg;
	/* number of SGPR pairs allocated for EXEC saves */
	u8 exec_save_pairs_used;

	/* Basic-block CFG analysis, retained for the /bpf/cfg view. */
	struct knod_bb *bbs;
	int n_bbs;
	int n_back;
};

#define KNOD_XDP_MEMCPY 0
#define KNOD_XDP_PT	1
#define KNOD_XDP_NETMEM	2
#define KNOD_XDP_NONE	3
#define KNOD_XDP_DEFAULT	KNOD_XDP_PT

#define KNOD_LAT_BUCKETS 10
#define KNOD_BL_BUCKETS  8

/* A wave says where it ran through a register the generations neither name nor
 * lay out alike: GCN keeps it in HW_ID, RDNA split that and put the unit in
 * HW_ID1.  Both name a unit by (engine, array, unit within the array), and
 * those three pack the same way whichever generation supplied them - so the
 * shader stores the register raw and the decoding happens here.
 *
 * RDNA counts workgroup processors, each a pair of compute units, so a gfx11
 * board with 80 CUs reports 40.
 */
#define KNOD_HWID_SLOTS		256
/* Prologue, program, epilogue. */
#define KNOD_PROBE_PARTS	3

static inline unsigned int knod_hwid_unit(u32 hwid, int isa)
{
	unsigned int unit, array, engine;

	if (isa == 9) {
		unit = (hwid >> 8) & 0xf;	/* CU_ID  */
		array = (hwid >> 12) & 0x1;	/* SH_ID  */
		engine = (hwid >> 13) & 0x3;	/* SE_ID  */
	} else {
		unit = (hwid >> 10) & 0xf;	/* WGP_ID */
		array = (hwid >> 16) & 0x1;	/* SA_ID  */
		engine = (hwid >> 18) & 0x7;	/* SE_ID  */
	}

	return (engine << 5) | (array << 4) | unit;
}

struct knod_bpf_stats {
	/* The window the counters below were gathered over.  Without it a rate
	 * can only be inferred from the completion latency and an assumed pipe
	 * depth, which is how more than one wrong number got believed.
	 */
	u64 start_ns;
	u64 expire_count;
	u64 first_dispatch_ns;
	u64 last_dispatch_ns;
	u64 stop_ns;		/* 0 while still running */

	u64 dispatch_total_ns;
	u64 dispatch_count;
	u64 dispatch_max_ns;

	u64 completion_total_ns;
	u64 completion_count;
	u64 completion_max_ns;
	u64 completion_hist[KNOD_LAT_BUCKETS];

	u64 backlogs_total;
	u64 backlogs_hist[KNOD_BL_BUCKETS];

	u64 decode_act_total_ns;
	u64 decode_act_count;
	u64 decode_act_max_ns;

	/* Packets per compute unit, from the HW_ID a probe build of the blob
	 * leaves in the half of spsc_bd.act nothing on this path reads.  Zero
	 * everywhere with an ordinary blob.
	 */
	u64 hwid_hist[KNOD_HWID_SLOTS];
	u64 hwid_units_total;	/* distinct units, summed over dispatches */
	u64 hwid_dispatches;

	/* Shader clocks per wave, split three ways, from what the cycle probe
	 * leaves in the spare half of a ring slot.  Zero unless it is armed.
	 */
	u64 cyc_total[KNOD_PROBE_PARTS];
	u64 cyc_max[KNOD_PROBE_PARTS];
	u64 cyc_count;
};

#define KNOD_PASS_SLOT_SIZE	PAGE_SIZE

/* pass_meta_buf slot header, written by the shader (offsetof used by the
 * codegen).  The host read path is gone now that PASS delivery goes via the
 * NIC act handler + knod_d2h_copy; the shader still stores {len, src_addr}
 * here pending removal of that store.
 */
struct knod_pass_slot_hdr {
	u32 len;		/* packet length */
	u32 _pad;
	u64 src_addr;		/* VRAM source address (SDMA mode only) */
};

struct knod_bpf_priv {
	struct list_head list;
	struct knod *knod;
	struct knod_accel *accel;
	struct knod_dev *knodev;
	struct net_device *dev;
	struct knod_prog *knod_prog;
	/* retained pass IR for debugfs insn dump */
	struct knod_prog *pass_knod_prog;
	struct bpf_prog *prog;
	struct amdgpu_vm *vm;
	u64 queue_base_gaddr[KNOD_SPSC_MAX];
	struct knod_bpf_work_sq *inflight[KNOD_BPF_INFLIGHT];
	unsigned int inflight_cnt;
	ktime_t next_dispatch_time;
	struct task_struct *worker_task;
	struct list_head free_list_sqw;
	struct mutex map_op_lock;
	bool map_op_quiesce;
	wait_queue_head_t map_op_wq;
	/* maps awaiting deferred free by the worker */
	struct list_head dead_maps;
	u32 maps_tick_skip;
	struct dentry *debug_dir;
	struct knod_bpf_stats stats;
	void *prog_buf;
	void *pass_prog_buf;
	u32 pass_prog_size;
	/* descriptor + live shader bytes per kernel slot */
	u32 kernel_image_len[2];
	/* knod->kernels[] slot the GPU dispatches */
	int active_idx;
	/* knod->kernels[] slot holding the pass kernel */
	int pass_idx;
	/*
	 * XDP_PASS shader-to-GTT metadata (shader-written; host read path
	 * removed). GTT metadata: shader-written headers.
	 */
	struct knod_mem *pass_meta_buf;
	u32 pass_pkts_per_queue;	/* backlogs / nr_works */
	/* batch size per queue */
	int batch_size;
	int nr_works;
	int isa_version;
	bool installing_kernel;
	int start;
	/* Prebuilt routines for this GPU, if any were found.  Kept for as long
	 * as programs built from them might still run.
	 */
	struct knod_blob blob;
};

static inline u8 mbpf_class(const struct knod_insn_meta *meta)
{
	return BPF_CLASS(meta->insn.code);
}

static inline u8 mbpf_src(const struct knod_insn_meta *meta)
{
	return BPF_SRC(meta->insn.code);
}

static inline u8 mbpf_op(const struct knod_insn_meta *meta)
{
	return BPF_OP(meta->insn.code);
}

static inline u8 mbpf_mode(const struct knod_insn_meta *meta)
{
	return BPF_MODE(meta->insn.code);
}

static inline bool is_mbpf_alu(const struct knod_insn_meta *meta)
{
	return mbpf_class(meta) == BPF_ALU64 || mbpf_class(meta) == BPF_ALU;
}

static inline bool is_mbpf_load(const struct knod_insn_meta *meta)
{
	return (meta->insn.code & ~BPF_SIZE_MASK) == (BPF_LDX | BPF_MEM);
}

static inline bool is_mbpf_jmp32(const struct knod_insn_meta *meta)
{
	return mbpf_class(meta) == BPF_JMP32;
}

static inline bool is_mbpf_jmp64(const struct knod_insn_meta *meta)
{
	return mbpf_class(meta) == BPF_JMP;
}

static inline bool is_mbpf_jmp(const struct knod_insn_meta *meta)
{
	return is_mbpf_jmp32(meta) || is_mbpf_jmp64(meta);
}

static inline bool is_mbpf_store(const struct knod_insn_meta *meta)
{
	return (meta->insn.code & ~BPF_SIZE_MASK) == (BPF_STX | BPF_MEM);
}

static inline bool is_mbpf_load_pkt(const struct knod_insn_meta *meta)
{
	return is_mbpf_load(meta) && meta->ptr.type == PTR_TO_PACKET;
}

static inline bool is_mbpf_store_pkt(const struct knod_insn_meta *meta)
{
	return is_mbpf_store(meta) && meta->ptr.type == PTR_TO_PACKET;
}

static inline bool is_mbpf_classic_load(const struct knod_insn_meta *meta)
{
	u8 code = meta->insn.code;

	return BPF_CLASS(code) == BPF_LD &&
	       (BPF_MODE(code) == BPF_ABS || BPF_MODE(code) == BPF_IND);
}

static inline bool is_mbpf_classic_store(const struct knod_insn_meta *meta)
{
	u8 code = meta->insn.code;

	return BPF_CLASS(code) == BPF_ST && BPF_MODE(code) == BPF_MEM;
}

static inline bool is_mbpf_classic_store_pkt(const struct knod_insn_meta *meta)
{
	return is_mbpf_classic_store(meta) && meta->ptr.type == PTR_TO_PACKET;
}

static inline bool is_mbpf_atomic(const struct knod_insn_meta *meta)
{
	return (meta->insn.code & ~BPF_SIZE_MASK) == (BPF_STX | BPF_ATOMIC);
}

static inline bool is_mbpf_mul(const struct knod_insn_meta *meta)
{
	return is_mbpf_alu(meta) && mbpf_op(meta) == BPF_MUL;
}

static inline bool is_mbpf_div(const struct knod_insn_meta *meta)
{
	return is_mbpf_alu(meta) && mbpf_op(meta) == BPF_DIV;
}

static inline bool is_mbpf_mod(const struct knod_insn_meta *meta)
{
	return is_mbpf_alu(meta) && mbpf_op(meta) == BPF_MOD;
}

static inline bool is_mbpf_cond_jump(const struct knod_insn_meta *meta)
{
	u8 op;

	if (is_mbpf_jmp32(meta))
		return true;

	if (!is_mbpf_jmp64(meta))
		return false;

	op = mbpf_op(meta);
	return op != BPF_JA && op != BPF_EXIT && op != BPF_CALL;
}

static inline bool is_mbpf_helper_call(const struct knod_insn_meta *meta)
{
	struct bpf_insn insn = meta->insn;

	return insn.code == (BPF_JMP | BPF_CALL) &&
		insn.src_reg != BPF_PSEUDO_CALL;
}

static inline bool is_mbpf_pseudo_call(const struct knod_insn_meta *meta)
{
	struct bpf_insn insn = meta->insn;

	return insn.code == (BPF_JMP | BPF_CALL) &&
		insn.src_reg == BPF_PSEUDO_CALL;
}

static inline bool is_mbpf_map_call(const struct knod_insn_meta *meta)
{
	struct bpf_insn insn = meta->insn;

	return insn.code == (BPF_JMP | BPF_CALL) && insn.imm <= 3;
}

#define STACK_FRAME_ALIGN 64

#define FLAG_INSN_IS_JUMP_DST                   BIT(0)
#define FLAG_INSN_IS_SUBPROG_START              BIT(1)
#define FLAG_INSN_PTR_CALLER_STACK_FRAME        BIT(2)
/* Instruction is pointless, noop even on its own */
#define FLAG_INSN_SKIP_NOOP                     BIT(3)
/* Instruction is optimized out based on preceding instructions */
#define FLAG_INSN_SKIP_PREC_DEPENDENT           BIT(4)
/* Instruction is optimized by the verifier */
#define FLAG_INSN_SKIP_VERIFIER_OPT             BIT(5)
/* Instruction needs to zero extend to high 32-bit */
#define FLAG_INSN_DO_ZEXT                       BIT(6)

#define FLAG_INSN_SKIP_MASK             (FLAG_INSN_SKIP_NOOP | \
					 FLAG_INSN_SKIP_PREC_DEPENDENT | \
					 FLAG_INSN_SKIP_VERIFIER_OPT)
#endif
