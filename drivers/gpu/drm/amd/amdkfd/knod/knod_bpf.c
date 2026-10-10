// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (c) 2021 Taehee Yoo <ap420073@gmail.com>
 * Copyright (c) 2021 Hoyeon Lee <hoyeon.rhee@gmail.com>
 */

#include <linux/cpumask.h>
#include <linux/types.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/sched.h>
#include <linux/workqueue.h>
#include <linux/file.h>
#include <linux/jhash.h>
#include <drm/ttm/ttm_tt.h>
#include <net/page_pool/helpers.h>
#include "kfd_priv.h"
#include "kfd_hsa.h"
#include "knod_bpf.h"
#include "kfd_migrate.h"
#include "kfd_events.h"
#include "kfd_device_queue_manager.h"
#include <linux/firmware.h>
#include <linux/jhash.h>
#include <net/knod.h>
#include <net/netdev_rx_queue.h>

/* The engine and the helper routines walk these structures, built outside
 * the kernel with only the numbers knod_blob.h publishes to walk them with.
 * Nothing warns when a field moves, so say here what those numbers are
 * supposed to be.
 */
static_assert(offsetof(struct knod_bpf_param, page_shift) ==
	      KNOD_BLOB_PARAM_PAGE_SHIFT);
static_assert(offsetof(struct knod_bpf_param, ktime_ns) ==
	      KNOD_BLOB_PARAM_KTIME_NS);
static_assert(offsetof(struct knod_bpf_param, queues) ==
	      KNOD_BLOB_PARAM_QUEUES);
static_assert(offsetof(struct knod_bpf_param, sub) ==
	      KNOD_BLOB_PARAM_SUB);
static_assert(sizeof(struct knod_bpf_queue_desc) == KNOD_BLOB_QUEUE_SIZE);
static_assert(offsetof(struct knod_bpf_queue_desc, rx_bounds) ==
	      KNOD_BLOB_QUEUE_RX_BOUNDS);
static_assert(sizeof(struct knod_bpf_subparam_obj) ==
	      KNOD_BLOB_SUB_SIZE);

/*+--------+------------+---------+---------+-----------+-----------+-----------+
 *| v0-v63 | v64-v85    | v86-v96 | v97-v99 | v100-v103 | v104-v139 | v140-v155 |
 *+--------+------------+---------+---------+-----------+-----------+-----------+
 *| CALLS  | BPF r0-r10 |   PRO   |   LDS   | GDA, RANK |    TMP    |   SNAP    |
 *+--------+------------+---------+---------+-----------+-----------+-----------+
 * Below KNOD_BLOB_JIT_VREG (v64) is what a blob routine may destroy, so
 * nothing lives across a BPF instruction there: a call's arguments go there,
 * and the engine leaves the lane's index in v40 for the prologue.  From it up
 * is what lasts: the BPF registers, what the engine leaves the program (PRO:
 * the packet's offset, index, context, bounds, page and page index), the LDS
 * stack's window and base, the engine's state and an ordered program's ranks,
 * the JIT's temporaries, and what an ordered program keeps at its resume
 * point.
 */

/* BPF r0-r10, a pair each, lo then hi: rN is v[KNOD_BPF_VREG(N):+1]. */
#define KNOD_BPF_VREG_BASE		KNOD_BLOB_JIT_VREG
#define KNOD_BPF_VREG(r)		(KNOD_BPF_VREG_BASE + 2 * (r))
#define KNOD_BPF_VREG_END		KNOD_BPF_VREG(MAX_BPF_REG)

/* The JIT's temporaries, past the engine's state: no call reaches them. */
#define KNOD_AMDGPU_TMP_VREG_BASE	104
#define KNOD_AMDGPU_TMP_VREG0_LO	(KNOD_AMDGPU_TMP_VREG_BASE + 0)
#define KNOD_AMDGPU_TMP_VREG0_HI	(KNOD_AMDGPU_TMP_VREG_BASE + 1)
#define KNOD_AMDGPU_TMP_VREG1_LO	(KNOD_AMDGPU_TMP_VREG_BASE + 2)
#define KNOD_AMDGPU_TMP_VREG1_HI	(KNOD_AMDGPU_TMP_VREG_BASE + 3)
#define KNOD_AMDGPU_TMP_VREG2_LO	(KNOD_AMDGPU_TMP_VREG_BASE + 4)
#define KNOD_AMDGPU_TMP_VREG2_HI	(KNOD_AMDGPU_TMP_VREG_BASE + 5)
#define KNOD_AMDGPU_TMP_VREG3_LO	(KNOD_AMDGPU_TMP_VREG_BASE + 6)
#define KNOD_AMDGPU_TMP_VREG3_HI	(KNOD_AMDGPU_TMP_VREG_BASE + 7)
#define KNOD_AMDGPU_TMP_VREG4_LO	(KNOD_AMDGPU_TMP_VREG_BASE + 8)
#define KNOD_AMDGPU_TMP_VREG4_HI	(KNOD_AMDGPU_TMP_VREG_BASE + 9)
#define KNOD_AMDGPU_TMP_VREG5_LO	(KNOD_AMDGPU_TMP_VREG_BASE + 10)
#define KNOD_AMDGPU_TMP_VREG5_HI	(KNOD_AMDGPU_TMP_VREG_BASE + 11)
#define KNOD_AMDGPU_TMP_VREG6_LO	(KNOD_AMDGPU_TMP_VREG_BASE + 12)
#define KNOD_AMDGPU_TMP_VREG6_HI	(KNOD_AMDGPU_TMP_VREG_BASE + 13)
#define KNOD_AMDGPU_TMP_VREG7_LO	(KNOD_AMDGPU_TMP_VREG_BASE + 14)
#define KNOD_AMDGPU_TMP_VREG7_HI	(KNOD_AMDGPU_TMP_VREG_BASE + 15)
#define KNOD_AMDGPU_TMP_VREG8_LO	(KNOD_AMDGPU_TMP_VREG_BASE + 16)
#define KNOD_AMDGPU_TMP_VREG8_HI	(KNOD_AMDGPU_TMP_VREG_BASE + 17)
#define KNOD_AMDGPU_TMP_VREG9_LO	(KNOD_AMDGPU_TMP_VREG_BASE + 18)
#define KNOD_AMDGPU_TMP_VREG9_HI	(KNOD_AMDGPU_TMP_VREG_BASE + 19)
#define KNOD_AMDGPU_TMP_VREG10_LO	(KNOD_AMDGPU_TMP_VREG_BASE + 20)
#define KNOD_AMDGPU_TMP_VREG10_HI	(KNOD_AMDGPU_TMP_VREG_BASE + 21)
#define KNOD_AMDGPU_TMP_VREG11_LO	(KNOD_AMDGPU_TMP_VREG_BASE + 22)
#define KNOD_AMDGPU_TMP_VREG11_HI	(KNOD_AMDGPU_TMP_VREG_BASE + 23)
#define KNOD_AMDGPU_TMP_VREG12_LO	(KNOD_AMDGPU_TMP_VREG_BASE + 24)
#define KNOD_AMDGPU_TMP_VREG12_HI	(KNOD_AMDGPU_TMP_VREG_BASE + 25)
#define KNOD_AMDGPU_TMP_VREG13_LO	(KNOD_AMDGPU_TMP_VREG_BASE + 26)
#define KNOD_AMDGPU_TMP_VREG13_HI	(KNOD_AMDGPU_TMP_VREG_BASE + 27)
#define KNOD_AMDGPU_TMP_VREG14_LO	(KNOD_AMDGPU_TMP_VREG_BASE + 28)
#define KNOD_AMDGPU_TMP_VREG14_HI	(KNOD_AMDGPU_TMP_VREG_BASE + 29)
#define KNOD_AMDGPU_TMP_VREG15_LO	(KNOD_AMDGPU_TMP_VREG_BASE + 30)
#define KNOD_AMDGPU_TMP_VREG15_HI	(KNOD_AMDGPU_TMP_VREG_BASE + 31)
#define KNOD_AMDGPU_TMP_VREG16_LO	(KNOD_AMDGPU_TMP_VREG_BASE + 32)
#define KNOD_AMDGPU_TMP_VREG16_HI	(KNOD_AMDGPU_TMP_VREG_BASE + 33)
#define KNOD_AMDGPU_TMP_VREG17_LO	(KNOD_AMDGPU_TMP_VREG_BASE + 34)
#define KNOD_AMDGPU_TMP_VREG17_HI	(KNOD_AMDGPU_TMP_VREG_BASE + 35)
#define KNOD_AMDGPU_TMP_VREG_MAX	KNOD_AMDGPU_TMP_VREG17_HI
static_assert(KNOD_BPF_VREG(BPF_REG_FP) == KNOD_BLOB_BPF_VREG(BPF_REG_FP));
static_assert(KNOD_AMDGPU_TMP_VREG_BASE >=
	      KNOD_BLOB_PRO_GDA_VREG + KNOD_BLOB_PRO_GDA_VREGS);
/* What the engine leaves the program. */
#define KNOD_AMDGPU_OFF_VREG		KNOD_BLOB_PRO_OFF_VREG
#define KNOD_AMDGPU_CTX_VREG_LO		KNOD_BLOB_PRO_CTX_VREG
#define KNOD_AMDGPU_CTX_VREG_HI		(KNOD_BLOB_PRO_CTX_VREG + 1)
#define KNOD_AMDGPU_IDX_VREG		KNOD_BLOB_PRO_IDX_VREG
#define KNOD_AMDGPU_PAGE_IDX_VREG	KNOD_BLOB_PRO_PAGE_IDX_VREG
#define KNOD_AMDGPU_DATA_VREG_LO	KNOD_BLOB_PRO_DATA_VREG
#define KNOD_AMDGPU_DATA_VREG_HI	(KNOD_BLOB_PRO_DATA_VREG + 1)
#define KNOD_AMDGPU_DATA_END_VREG_LO	KNOD_BLOB_PRO_DATA_END_VREG
#define KNOD_AMDGPU_DATA_END_VREG_HI	(KNOD_BLOB_PRO_DATA_END_VREG + 1)
#define KNOD_AMDGPU_PAGE_BASE_VREG_LO	KNOD_BLOB_PRO_PAGE_BASE_VREG
#define KNOD_AMDGPU_PAGE_BASE_VREG_HI	(KNOD_BLOB_PRO_PAGE_BASE_VREG + 1)
static_assert(KNOD_BPF_VREG_END <= KNOD_BLOB_PRO_OFF_VREG);
/* The pair the load and store helpers work a stack slot through.  The
 * emitters name these three past the end of the file; knod_bpf_lds_vreg()
 * puts them where they live.
 */
#define KNOD_AMDGPU_STACK_WIN_VREG0	128
#define KNOD_AMDGPU_STACK_WIN_VREG1	129
/* The lane's byte offset into the LDS stack, lane * 4, computed once. */
#define KNOD_AMDGPU_LDS_BASE_VREG	130

/* Where the three LDS temporaries actually live: the first registers past
 * the engine's.
 */
#define KNOD_AMDGPU_RDNA_LDS_VREG0	97

/* What the wave declares, read off the register map rather than written down:
 * up to the end of the temporaries and the registers an ordered program keeps
 * for a parked lane, the top of the map, in Wave64's allocation unit of four.
 */
#define KNOD_BPF_VGPR_COUNT		ALIGN(KNOD_AMDGPU_TMP_VREG_MAX + 1 + \
					      2 * KNOD_GATE_SNAP_REGS, 4)
static_assert(KNOD_BLOB_PRO_PAGE_IDX_VREG < KNOD_AMDGPU_RDNA_LDS_VREG0);
static_assert(KNOD_BLOB_PRO_PAGE_BASE_VREG + 1 < KNOD_AMDGPU_RDNA_LDS_VREG0);
/* A call's arguments: the descriptor, the key and the value. */
static_assert(2 + KNOD_BLOB_KEY_CHUNKS_MAX + KNOD_BLOB_VALUE_CHUNKS_MAX <=
	      KNOD_BLOB_JIT_VREG);
static_assert(KNOD_AMDGPU_RDNA_LDS_VREG0 + 2 < KNOD_BLOB_PRO_GDA_VREG);
static_assert(KNOD_BPF_VGPR_COUNT <= 256);
/* What the engine's descriptor declares for every kernel it runs. */
static_assert(KNOD_BPF_VGPR_COUNT == KNOD_GDA_VGPR_COUNT);

static unsigned int knod_bpf_lds_vreg(const struct knod_bpf_priv *priv,
				      unsigned int reg)
{
	return KNOD_AMDGPU_RDNA_LDS_VREG0 + reg -
		KNOD_AMDGPU_STACK_WIN_VREG0;
}

/* One VGPR holds four bytes of packet, so what the cache can hold is decided
 * by how many VGPRs sit between its base and the stack.
 */

#define KNOD_BPF_PROG_BUF_SIZE		32768


#define MAX_MAP_KEY_SIZE		56


/*
 * The SGPR map, one layout for every generation so a dump reads the same
 * whichever GPU produced it and a prebuilt routine needs no shim to name a
 * register.
 *
 *+-------+-------+-------+-------+-------+-----+-----+
 *| s0-s3 | s4-s5 | s6-s7 | s8-s9 |s10-s11| s12 | s13 |
 *+-------+-------+-------+-------+-------+-----+-----+
 *|  PSB  | DISP  | QUEUE | KARG  |DISP_ID| WGX | WGY |
 *+-------+-------+-------+-------+-------+-----+-----+
 * The hardware loads these from the dispatch packet before the wave starts,
 * so nothing may be assigned there.  WGY doubles as the queue id.
 *
 *+---------+---------+---------+---------+---------+---------+---------+
 *| s14-s25 | s30-s31 | s32-s33 | s34-s35 | s36-s37 | s38-s95 | s96-s97 |
 *+---------+---------+---------+---------+---------+---------+---------+
 *| TMP 0-5 | CALL RA |  STACK  |DONE MASK|  PARAM  |EXEC SAVE|INIT EXEC|
 *+---------+---------+---------+---------+---------+---------+---------+
 * then s98-s99, where the program returns to; s100-s103, the engine's; and
 * s104, an ordered program's pass.  Implicit: VCC = s[106:107], EXEC =
 * s[126:127].
 *
 * TMP holds nothing across a BPF instruction, so a call into a blob routine,
 * which may destroy everything below s34, loses nothing there; s13 is set to
 * the queue again before one.  From s34 up a routine keeps: DONE MASK and
 * INIT EXEC hold theirs across the whole program, and EXEC SAVE across
 * whichever BPF-level scope was given the pair.  s32 is the stack a call
 * gets, which the engine set.
 */
#define KNOD_AMDGPU_WORKGROUP_ID_Y_SREG	13 /* s13 workgroup_id_y = queue_id */
#define KNOD_AMDGPU_TMP_SREG0_LO	14
#define KNOD_AMDGPU_TMP_SREG0_HI	15
#define KNOD_AMDGPU_TMP_SREG1_LO	16
#define KNOD_AMDGPU_TMP_SREG1_HI	17
#define KNOD_AMDGPU_TMP_SREG2_LO	18
#define KNOD_AMDGPU_TMP_SREG2_HI	19
#define KNOD_AMDGPU_TMP_SREG3_LO	20
#define KNOD_AMDGPU_TMP_SREG3_HI	21
#define KNOD_AMDGPU_TMP_SREG4_LO	22
#define KNOD_AMDGPU_TMP_SREG4_HI	23
#define KNOD_AMDGPU_TMP_SREG5_LO	24
#define KNOD_AMDGPU_TMP_SREG5_HI	25
#define KNOD_AMDGPU_PARAM_SREG_LO	KNOD_BLOB_PRO_PARAM_SREG
#define KNOD_AMDGPU_PARAM_SREG_HI	(KNOD_BLOB_PRO_PARAM_SREG + 1)

/* Structurized CFG: EXEC mask save/restore SGPRs.
 * done_mask tracks lanes that have reached BPF_EXIT.
 * exec_save pairs store EXEC at branch points for restore at merge points.
 *
 * GFX10 and GFX11 use the same indices so dumps and prebuilt routines share
 * one register contract.
 */
/* Common RDNA SGPR special register indices. */
#define AMDGCN_SREG_VCC_LO		106
#define AMDGCN_SREG_EXEC_LO		126
#define AMDGCN_SREG_INTEGER_0		128

#define KNOD_AMDGPU_DONE_MASK_SREG	KNOD_BLOB_DONE_MASK_SREG
#define KNOD_AMDGPU_EXEC_SAVE_SREG_BASE	(KNOD_AMDGPU_PARAM_SREG_HI + 1)
#define KNOD_AMDGPU_EXEC_SAVE_SREG_MAX	95
#define KNOD_AMDGPU_INITIAL_EXEC_SREG	KNOD_BLOB_INITIAL_EXEC_SREG
static_assert(KNOD_AMDGPU_DONE_MASK_SREG + 2 == KNOD_AMDGPU_PARAM_SREG_LO);
static_assert(KNOD_AMDGPU_EXEC_SAVE_SREG_MAX + 1 ==
	      KNOD_AMDGPU_INITIAL_EXEC_SREG);
static_assert(KNOD_AMDGPU_INITIAL_EXEC_SREG + 2 <= KNOD_BLOB_PRO_RET_SREG);
#define KNOD_AMDGPU_MAX_EXEC_SAVE_PAIRS					\
	((KNOD_AMDGPU_EXEC_SAVE_SREG_MAX -				\
	  KNOD_AMDGPU_EXEC_SAVE_SREG_BASE + 1) / 2)

/* Persistent-shader BPF requires the externally built, versioned wrapper blob. */
unsigned int knod_bpf_jit_engine = 1;
MODULE_PARM_DESC(jit_engine, "BPF JIT engine, forced to the blob (1)");
module_param_named(jit_engine, knod_bpf_jit_engine, int, 0444);

/* The BPF stack lives in LDS, laid out slot-major and reached through a
 * two-register window, or in scratch when it is too deep for LDS.
 */

static void knod_mov64(struct knod_bpf_priv *priv,
		       struct knod_insn_meta *meta,
		       struct amdgcn_param64 dst,
		       struct amdgcn_param64 src);
static void knod_lshlrev32(struct knod_bpf_priv *priv,
			   struct knod_insn_meta *meta,
			   struct amdgcn_param32 dst,
			   struct amdgcn_param32 src0,
			   struct amdgcn_param32 src1);
static void knod_and32(struct knod_bpf_priv *priv,
		      struct knod_insn_meta *meta,
		      struct amdgcn_param32 dst,
		      struct amdgcn_param32 src0,
		      struct amdgcn_param32 src1);

/* The lane's byte offset into its slot-major LDS stack: (lane & (wg - 1)) * 4,
 * computed once into KNOD_AMDGPU_LDS_BASE_VREG for the window helpers to add to.
 */
static void knod_bpf_emit_lds_base_init(struct knod_bpf_priv *priv,
					struct knod_insn_meta *meta)
{
	struct amdgcn_param32 base, idx, k;

	knod_vset32(&base,
		    knod_bpf_lds_vreg(priv, KNOD_AMDGPU_LDS_BASE_VREG));
	knod_vset32(&idx, KNOD_BLOB_PRO_LOCAL_IDX_VREG);
	knod_iset32(&k, 2);
	knod_lshlrev32(priv, meta, base, k, idx);
}


DEFINE_STATIC_KEY_FALSE(knod_stats_key);

static LIST_HEAD(priv_list);
/* r64[0..17] describe the scratch pairs; r64[19] describes CTX. */
struct amdgcn_param64 r64[20], sr64[6], p64[4], bpf_reg64[MAX_BPF_REG];
struct amdgcn_param32 r32[36];
/* Its address is a sentinel: a cache pointer equal to it means the stack, which
 * the load and store helpers route through the LDS window instead of reading.
 */
struct amdgcn_param32 stack[1];

struct amdgcn_label {
	struct knod_insn_meta *meta;
	int insn_idx;
};

struct amdgcn_branch_fixup {
	struct amdgcn_label *target_label;
	struct knod_insn_meta *meta;
	int insn_idx;
};

struct knod_accel_xdp_ops accel_xdp_ops;

static int knod_prog_prepare_insns(struct knod_bpf_priv *priv,
				   struct knod_prog *knod_prog);
static int knod_bpf_emit_epilogue(struct knod_bpf_priv *priv,
				  struct knod_prog *knod_prog);
static void knod_prog_free(struct knod_prog *knod_prog);
static int knod_setup_bpf_prog(struct bpf_prog *prog);

static void knod_bpf_gpu_mem_fence(struct knod_bpf_priv *priv)
{
	if (!priv)
		return;

	/* drain the WC store buffer before the GPU reads the map */
	wmb();
}

#include "knod_persistent.h"

/*
 * Whether one packet's run can change what another's sees: a map element
 * inserted or deleted, or a map value written other than by the atomic add a
 * percpu counter is folded into, or an atomic other than an add.  An addition
 * lands the same in any order; nothing else does, so a program doing any of
 * it runs behind the ordered engine, which keeps a flow's packets in order.
 */
static bool knod_bpf_needs_order(const struct knod_prog *knod_prog)
{
	const struct knod_insn_meta *meta;
	u8 class, mode;

	list_for_each_entry(meta, &knod_prog->insns, l) {
		if (is_mbpf_helper_call(meta) &&
		    (meta->insn.imm == BPF_FUNC_map_update_elem ||
		     meta->insn.imm == BPF_FUNC_map_delete_elem))
			return true;
		class = BPF_CLASS(meta->insn.code);
		mode = BPF_MODE(meta->insn.code);
		if (class == BPF_STX && mode == BPF_ATOMIC) {
			if (meta->insn.imm != BPF_ADD)
				return true;
			continue;
		}
		if ((class == BPF_ST || class == BPF_STX) &&
		    meta->ptr.type == PTR_TO_MAP_VALUE && !meta->percpu_rmw_add)
			return true;
	}
	return false;
}

/* A set of registers and of the stack's 8-byte slots. */
struct knod_live {
	u16 regs;
	u64 stack;
};

/* Mark @size bytes of stack from @off, relative to r10; all of it for a
 * place not known.
 */
static void knod_live_stack(u64 *set, int off, int size, bool unknown)
{
	int i;

	if (unknown || off < -MAX_BPF_STACK || off + size > 0) {
		*set = ~0ull;
		return;
	}
	for (i = (off + MAX_BPF_STACK) / 8;
	     i <= (off + size - 1 + MAX_BPF_STACK) / 8; i++)
		*set |= 1ull << i;
}

/* The last argument register a helper reads; r5 for one not known. */
static int knod_bpf_helper_args(const struct knod_insn_meta *meta)
{
	if (!is_mbpf_helper_call(meta))
		return BPF_REG_5;
	switch (meta->insn.imm) {
	case BPF_FUNC_ktime_get_ns:
		return BPF_REG_0;
	case BPF_FUNC_map_lookup_elem:
	case BPF_FUNC_map_delete_elem:
	case BPF_FUNC_xdp_adjust_head:
	case BPF_FUNC_xdp_adjust_tail:
		return BPF_REG_2;
	case BPF_FUNC_map_update_elem:
		return BPF_REG_4;
	default:
		return BPF_REG_5;
	}
}

/* What one instruction reads (@use), overwrites whole (@kill) and writes at
 * all (@write).  False when it writes a place it cannot name.
 */
static bool knod_bpf_use_def(const struct knod_insn_meta *meta,
			     struct knod_live *use, struct knod_live *kill,
			     struct knod_live *write)
{
	const struct bpf_insn *insn = &meta->insn;
	u8 class = BPF_CLASS(insn->code), op = BPF_OP(insn->code);
	int size = bpf_size_to_bytes(BPF_SIZE(insn->code)), off;
	bool known = true;
	int i;

	memset(use, 0, sizeof(*use));
	memset(kill, 0, sizeof(*kill));
	memset(write, 0, sizeof(*write));
	/* The second half of an ld_imm64. */
	if (!insn->code)
		return true;
	if (meta->flags & FLAG_INSN_SUBPROG_RET) {
		knod_live_stack(&use->stack, meta->sub_save_off,
				8 * hweight16(meta->sub_saves), false);
		kill->regs = meta->sub_saves;
		write->regs = meta->sub_saves;
		return true;
	}

	switch (class) {
	case BPF_ALU:
	case BPF_ALU64:
		if (op != BPF_MOV)
			use->regs |= BIT(insn->dst_reg);
		if (BPF_SRC(insn->code) == BPF_X && op != BPF_NEG &&
		    op != BPF_END)
			use->regs |= BIT(insn->src_reg);
		kill->regs |= BIT(insn->dst_reg);
		break;
	case BPF_LD:
		kill->regs |= BIT(insn->dst_reg);
		break;
	case BPF_LDX:
		use->regs |= BIT(insn->src_reg);
		if (meta->ptr.type == PTR_TO_STACK)
			knod_live_stack(&use->stack,
					meta->sreg.stack_off + insn->off, size,
					meta->sreg.var_off);
		kill->regs |= BIT(insn->dst_reg);
		break;
	case BPF_ST:
	case BPF_STX:
		use->regs |= BIT(insn->dst_reg);
		if (class == BPF_STX)
			use->regs |= BIT(insn->src_reg);
		if (BPF_MODE(insn->code) == BPF_ATOMIC) {
			/* The fetching ones give back the old value. */
			kill->regs |= BIT(insn->src_reg) | BIT(BPF_REG_0);
			if (meta->ptr.type == PTR_TO_STACK || !meta->ptr.type)
				known = false;
			break;
		}
		if (meta->ptr.type != PTR_TO_STACK) {
			/* Not the stack, or not known to be. */
			if (!meta->ptr.type)
				known = false;
			break;
		}
		off = meta->dreg.stack_off + insn->off;
		if (meta->dreg.var_off) {
			known = false;
			break;
		}
		knod_live_stack(&write->stack, off, size, false);
		if (size == 8 && !(off & 7))
			knod_live_stack(&kill->stack, off, size, false);
		break;
	case BPF_JMP:
	case BPF_JMP32:
		if (op == BPF_EXIT) {
			use->regs |= BIT(BPF_REG_0);
		} else if (is_mbpf_pseudo_call(meta)) {
			use->regs |= meta->sub_saves;
			knod_live_stack(&write->stack, meta->sub_save_off,
					8 * hweight16(meta->sub_saves), false);
			knod_live_stack(&kill->stack, meta->sub_save_off,
					8 * hweight16(meta->sub_saves), false);
		} else if (op == BPF_CALL) {
			for (i = BPF_REG_1; i <= knod_bpf_helper_args(meta); i++)
				use->regs |= BIT(i);
			if (is_mbpf_map_call(meta) && meta->call_map) {
				if (meta->kreg.reg.type == PTR_TO_STACK)
					knod_live_stack(&use->stack,
							meta->kreg.stack_off,
							meta->call_map->key_size,
							meta->kreg.var_off);
				if (meta->insn.imm == BPF_FUNC_map_update_elem &&
				    meta->vreg.reg.type == PTR_TO_STACK)
					knod_live_stack(&use->stack,
							meta->vreg.stack_off,
							meta->call_map->value_size,
							meta->vreg.var_off);
			}
			for (i = BPF_REG_0; i <= BPF_REG_5; i++)
				kill->regs |= BIT(i);
		} else if (op != BPF_JA) {
			use->regs |= BIT(insn->dst_reg);
			if (BPF_SRC(insn->code) == BPF_X)
				use->regs |= BIT(insn->src_reg);
		}
		break;
	}
	write->regs |= kill->regs;
	return known;
}

/* The live instructions by BPF index: dropped ones keep their numbers. */
static struct knod_insn_meta **knod_bpf_by_idx(struct knod_prog *knod_prog)
{
	struct knod_insn_meta **by_idx, *meta;
	int n = knod_prog->n_insns;

	by_idx = kvcalloc(n, sizeof(*by_idx), GFP_KERNEL);
	if (!by_idx)
		return NULL;
	list_for_each_entry(meta, &knod_prog->insns, l)
		if (meta->bpf_insn_idx >= 0 && meta->bpf_insn_idx < n)
			by_idx[meta->bpf_insn_idx] = meta;
	return by_idx;
}

/* Where BPF instruction @i can go next, live ones only. */
static int knod_bpf_succ(struct knod_insn_meta **by_idx, int n, int i,
			 int succ[2])
{
	const struct knod_insn_meta *meta = by_idx[i];
	int ns = 0, s;

	switch (BPF_CLASS(meta->insn.code)) {
	case BPF_JMP:
	case BPF_JMP32:
		if (BPF_OP(meta->insn.code) == BPF_EXIT)
			break;
		if (BPF_OP(meta->insn.code) == BPF_JA) {
			succ[ns++] = i + 1 +
				(BPF_CLASS(meta->insn.code) == BPF_JMP32 ?
				 meta->insn.imm : meta->insn.off);
			break;
		}
		succ[ns++] = i + 1;
		if (BPF_OP(meta->insn.code) != BPF_CALL)
			succ[ns++] = i + 1 + meta->insn.off;
		break;
	default:
		if (!meta->insn.code)
			break;
		succ[ns++] = i + (meta->insn.code ==
				  (BPF_LD | BPF_IMM | BPF_DW) ? 2 : 1);
	}
	for (s = 0; s < ns; s++)
		while (succ[s] >= 0 && succ[s] < n && !by_idx[succ[s]])
			succ[s]++;
	return ns;
}

/* What is live before each instruction: read on some way from it before
 * being overwritten.  Indexed by BPF instruction; NULL out of memory.
 */
static struct knod_live *knod_bpf_liveness(struct knod_prog *knod_prog,
					   struct knod_insn_meta **by_idx)
{
	int n = knod_prog->n_insns, i, s, succ[2], ns;
	struct knod_live *in, use, kill, write;
	struct knod_live out;
	bool changed;

	in = kvcalloc(n, sizeof(*in), GFP_KERNEL);
	if (!in)
		return NULL;

	do {
		changed = false;
		for (i = n - 1; i >= 0; i--) {
			if (!by_idx[i])
				continue;
			ns = knod_bpf_succ(by_idx, n, i, succ);
			out.regs = 0;
			out.stack = 0;
			for (s = 0; s < ns; s++) {
				if (succ[s] < 0 || succ[s] >= n)
					continue;
				out.regs |= in[succ[s]].regs;
				out.stack |= in[succ[s]].stack;
			}
			knod_bpf_use_def(by_idx[i], &use, &kill, &write);
			out.regs = use.regs | (out.regs & ~kill.regs);
			out.stack = use.stack | (out.stack & ~kill.stack);
			if (out.regs != in[i].regs || out.stack != in[i].stack) {
				in[i] = out;
				changed = true;
			}
		}
	} while (changed);

	return in;
}

/* Whether every way from the start to @to goes through @via. */
static bool knod_bpf_dominates(struct knod_insn_meta **by_idx, int n,
			       int via, int to, unsigned long *seen,
			       int *stack)
{
	int sp = 0, i, s, ns, succ[2];

	if (via == to)
		return true;
	bitmap_zero(seen, n);
	for (i = 0; i < n && !by_idx[i]; i++)
		;
	if (i == n || i == via)
		return true;
	stack[sp++] = i;
	__set_bit(i, seen);
	while (sp) {
		i = stack[--sp];
		if (i == to)
			return false;
		ns = knod_bpf_succ(by_idx, n, i, succ);
		for (s = 0; s < ns; s++) {
			if (succ[s] < 0 || succ[s] >= n || succ[s] == via ||
			    test_bit(succ[s], seen))
				continue;
			__set_bit(succ[s], seen);
			stack[sp++] = succ[s];
		}
	}
	return true;
}

static bool knod_bpf_writes_map(const struct knod_insn_meta *meta,
				const struct bpf_map *map)
{
	u8 class = BPF_CLASS(meta->insn.code);

	if (is_mbpf_helper_call(meta))
		return (meta->insn.imm == BPF_FUNC_map_update_elem ||
			meta->insn.imm == BPF_FUNC_map_delete_elem) &&
		       (!map || meta->call_map == map);
	if (class != BPF_ST && class != BPF_STX)
		return false;
	if (BPF_MODE(meta->insn.code) == BPF_ATOMIC) {
		if (meta->insn.imm == BPF_ADD)
			return false;
	} else if (meta->percpu_rmw_add) {
		return false;
	}
	if (!meta->ptr.type)
		return true;
	return meta->ptr.type == PTR_TO_MAP_VALUE &&
	       (!map || meta->ptr.map_ptr == map);
}

/* Whether @meta writes, or reads, a map an ordered program orders. */
static bool knod_bpf_ordered_access(const struct knod_insn_meta *meta,
				    const struct bpf_map * const *maps, int n,
				    bool writes)
{
	u8 class = BPF_CLASS(meta->insn.code);
	const struct bpf_map *map = NULL;
	int i;

	if (writes) {
		for (i = 0; i < n; i++)
			if (knod_bpf_writes_map(meta, maps[i]))
				return true;
		return false;
	}

	if (is_mbpf_map_call(meta))
		map = meta->call_map;
	else if ((class == BPF_LDX || class == BPF_ST || class == BPF_STX) &&
		 meta->ptr.type == PTR_TO_MAP_VALUE)
		map = meta->ptr.map_ptr;
	else if ((class == BPF_ST || class == BPF_STX) && !meta->ptr.type)
		return true;
	if (!map)
		return false;
	for (i = 0; i < n; i++)
		if (maps[i] == map)
			return true;
	return false;
}

/* Whether anything outside the lane sees what @meta does. */
static bool knod_bpf_side_effect(const struct knod_insn_meta *meta)
{
	u8 class = BPF_CLASS(meta->insn.code);

	/* Its callee follows it; the call only keeps registers on the stack. */
	if (is_mbpf_pseudo_call(meta))
		return false;
	if (is_mbpf_helper_call(meta))
		return meta->insn.imm != BPF_FUNC_map_lookup_elem &&
		       meta->insn.imm != BPF_FUNC_ktime_get_ns;
	if (class == BPF_JMP || class == BPF_JMP32)
		return BPF_OP(meta->insn.code) == BPF_CALL;
	if (class != BPF_ST && class != BPF_STX)
		return false;
	return meta->ptr.type != PTR_TO_STACK ||
	       BPF_MODE(meta->insn.code) == BPF_ATOMIC;
}

/*
 * Where an ordered program parks the lanes that wait for their flow.  At its
 * start always works: every lane but the first of each flow waits.  Better
 * is just before the first thing after the first read of an ordered map, G,
 * that anything outside the lane sees, P: until there nothing a lane did is
 * seen, so any lane can still be run again, from R, and once every wave is at
 * P the ones that may write are known: active at P, or waiting to come back
 * in before the last ordered write.  Then only the flows with such a lane
 * wait, and those that only read go on together.  It holds if R, at or
 * before G with nothing but plain work between, sees what it reads
 * unchanged when run again: nothing it needs is written before P.
 */
static void knod_order_why(struct knod_prog *knod_prog, const char *why,
			   const struct knod_insn_meta *at)
{
	knod_prog->order_why = why;
	knod_prog->order_why_at = at ? at->bpf_insn_idx : -1;
}

#define KNOD_ORDER_WHY(why, at)	knod_order_why(knod_prog, why, at)

static void knod_bpf_plan_order(struct knod_prog *knod_prog)
{
	const struct bpf_map *maps[16];
	struct knod_insn_meta *meta, *g = NULL, *p = NULL, *r;
	struct knod_insn_meta *held[KNOD_GATE_SAVES], **by_idx = NULL;
	int n = 0, i, last_write = -1, steps, ni = knod_prog->n_insns;
	struct knod_live *live = NULL, use, kill, write, w;
	struct knod_insn_meta *best = NULL;
	unsigned long *seen = NULL;
	int *stack = NULL;
	u16 snap, best_snap = 0;
	u64 snap_stack, best_stack = 0;
	bool ok, through;

	knod_prog->gate_at = NULL;
	knod_prog->gate_reach = NULL;
	knod_prog->resume_at = NULL;
	knod_prog->order_why_g = -1;
	knod_prog->order_why_p = -1;
	knod_prog->order_why_r = -1;
	knod_prog->order_why_regs = 0;
	knod_prog->order_why_stack = 0;

	/* The maps whose order matters: the ones written other than by an
	 * add.  One not known stops here.
	 */
	list_for_each_entry(meta, &knod_prog->insns, l) {
		const struct bpf_map *map = NULL;

		if (!knod_bpf_writes_map(meta, NULL))
			continue;
		map = is_mbpf_helper_call(meta) ? meta->call_map :
						 meta->ptr.map_ptr;
		if (!map) {
			KNOD_ORDER_WHY("a write to a place not known", meta);
			return;
		}
		for (i = 0; i < n; i++)
			if (maps[i] == map)
				break;
		if (i < n)
			continue;
		if (n == ARRAY_SIZE(maps)) {
			KNOD_ORDER_WHY("too many maps written", meta);
			return;
		}
		maps[n++] = map;
	}

	list_for_each_entry(meta, &knod_prog->insns, l) {
		if (!g && knod_bpf_ordered_access(meta, maps, n, false))
			g = meta;
		if (g && knod_bpf_side_effect(meta)) {
			p = meta;
			break;
		}
	}
	if (!g || !p) {
		KNOD_ORDER_WHY(g ? "nothing seen after the first read" :
				   "no read of a written map", g);
		return;
	}

	/* A lane not active at P waits in the exec save of a branch it took
	 * before P and comes back in where that branch merges.  Where that is
	 * before the last ordered write it may yet write, so it counts as
	 * about to; the rest never get to a write.
	 */
	knod_prog->order_why_g = g->bpf_insn_idx;
	knod_prog->order_why_p = p->bpf_insn_idx;
	knod_prog->n_gate_saves = 0;
	list_for_each_entry(meta, &knod_prog->insns, l)
		if (knod_bpf_ordered_access(meta, maps, n, true))
			last_write = max(last_write, meta->linear_idx);
	list_for_each_entry(meta, &knod_prog->insns, l) {
		if (meta->branch_type != KNOD_BR_FORWARD_SKIP &&
		    meta->branch_type != KNOD_BR_FORWARD_GOTO)
			continue;
		if (meta->linear_idx >= p->linear_idx ||
		    meta->merge_point->linear_idx <= p->linear_idx ||
		    meta->merge_point->linear_idx > last_write)
			continue;
		if (knod_prog->n_gate_saves == KNOD_GATE_SAVES) {
			KNOD_ORDER_WHY("too many branches open at the gate",
				       meta);
			return;
		}
		held[knod_prog->n_gate_saves] = meta;
		knod_prog->gate_saves[knod_prog->n_gate_saves++] =
			meta->exec_save_sreg;
	}

	/* R: back from G over plain work, until what it needs is not written
	 * before P.
	 */
	by_idx = knod_bpf_by_idx(knod_prog);
	live = by_idx ? knod_bpf_liveness(knod_prog, by_idx) : NULL;
	seen = bitmap_zalloc(ni, GFP_KERNEL);
	stack = kvmalloc_array(ni, sizeof(*stack), GFP_KERNEL);
	if (!live || !seen || !stack) {
		KNOD_ORDER_WHY("no memory", NULL);
		goto out;
	}

	/*
	 * R: back from G over work nothing outside the lane sees.  Every lane
	 * that takes part has to have been through it - it comes before G, P
	 * and the branches holding the lanes that may write, on every way to
	 * them - and run again from it sees what it reads as it was: what it
	 * needs and is written before P, a register or two, is kept at R and
	 * put back when the lane resumes.  The nearest R that keeps least.
	 */
	for (r = g, steps = 0; steps < 256; steps++) {
		if (r->bpf_insn_idx >= 0 && r->insn.code) {
			w.regs = 0;
			w.stack = 0;
			for (meta = r; meta != p; meta = list_next_entry(meta, l)) {
				if (!knod_bpf_use_def(meta, &use, &kill,
						      &write)) {
					KNOD_ORDER_WHY("a write to a place not known",
						       meta);
					goto out;
				}
				w.regs |= write.regs;
				w.stack |= write.stack;
			}
			snap = w.regs & live[r->bpf_insn_idx].regs;
			snap_stack = w.stack & live[r->bpf_insn_idx].stack;
			through = knod_bpf_dominates(by_idx, ni,
						     r->bpf_insn_idx,
						     g->bpf_insn_idx, seen,
						     stack) &&
				  knod_bpf_dominates(by_idx, ni,
						     r->bpf_insn_idx,
						     p->bpf_insn_idx, seen,
						     stack);
			for (i = 0; through && i < knod_prog->n_gate_saves; i++)
				through = held[i]->bpf_insn_idx >= 0 &&
					  knod_bpf_dominates(by_idx, ni,
							     r->bpf_insn_idx,
							     held[i]->bpf_insn_idx,
							     seen, stack);
			if (through && knod_prog->order_why_r < 0) {
				knod_prog->order_why_r = r->bpf_insn_idx;
				knod_prog->order_why_regs = snap;
				knod_prog->order_why_stack = snap_stack;
			}
			ok = through && hweight16(snap) + hweight64(snap_stack) <=
					KNOD_GATE_SNAP_REGS;
			if (ok && (!best ||
				   hweight16(snap) + hweight64(snap_stack) <
				   hweight16(best_snap) + hweight64(best_stack))) {
				best = r;
				best_snap = snap;
				best_stack = snap_stack;
				if (!snap && !snap_stack)
					break;
			}
		}
		if (list_is_first(&r->l, &knod_prog->insns))
			break;
		meta = list_prev_entry(r, l);
		if (knod_bpf_side_effect(meta) ||
		    knod_bpf_ordered_access(meta, maps, n, false))
			break;
		r = meta;
	}
	if (!best) {
		KNOD_ORDER_WHY("what a parked lane needs is changed before it parks",
			       r);
		goto out;
	}
	r = best;
	knod_prog->gate_snap = best_snap;
	knod_prog->gate_snap_stack = best_stack;

	knod_prog->gate_at = p;
	knod_prog->gate_reach = g;
	knod_prog->resume_at = r;
	pr_debug("knod_bpf: ordered at bpf#%d, reads at bpf#%d, resumes at bpf#%d\n",
		 p->bpf_insn_idx, g->bpf_insn_idx, r->bpf_insn_idx);
out:
	kvfree(stack);
	bitmap_free(seen);
	kvfree(live);
	kvfree(by_idx);
}

/* Put a program's code into the engine in whatever ran before it. */
static int knod_bpf_install_kernel(struct knod_bpf_priv *priv,
				   const struct knod_prog *knod_prog,
				   const void *code, u32 size)
{
	int err;

	err = knod_gda_install(priv->knod, code, size, knod_prog->lds_bytes,
			       knod_prog->uses_ktime,
			       knod_prog->ordered ? &priv->ordered_engine : NULL);
	if (err)
		return err;
	priv->lds_bytes = knod_prog->lds_bytes;
	priv->prog_stack_scratch = knod_prog->stack_scratch;
	WRITE_ONCE(priv->gpu_map_gc_possible, knod_prog->uses_map_delete);
	return 0;
}

/* Instruction prefetch runs past s_endpgm by up to three cachelines. */
#define KNOD_SHADER_PAD_DWORDS		64

static struct knod_insn_meta *knod_bpf_pad_shader(struct knod_bpf_priv *priv,
						  struct knod_insn_meta *meta,
						  struct list_head *insns)
{
	int j;

	if (priv->isa_version < 10)
		return meta;

	for (j = 0; j < KNOD_SHADER_PAD_DWORDS; j++) {
		if (meta->amdgpu_insns >= KNOD_META_INSNS) {
			meta = kzalloc_obj(*meta, GFP_KERNEL);
			if (!meta)
				return NULL;
			list_add_tail(&meta->l, insns);
		}
		knod_emit(priv, meta, s_code_end);
	}

	return meta;
}

/* Bytes a meta puts in the program. */
static u32 knod_meta_bytes(const struct knod_insn_meta *meta)
{
	u32 n = 0;
	u32 i;

	for (i = 0; i < meta->amdgpu_insns; i++)
		n += meta->amdgpu_insn[i].size;

	return n;
}

/* Write one meta at @ptr and return where the next one starts. */
static u8 *knod_meta_write(const struct knod_insn_meta *meta, u8 *ptr,
			   bool trace)
{
	const u32 *dw;
	u32 size;
	u32 i;

	for (i = 0; i < meta->amdgpu_insns; i++) {
		size = meta->amdgpu_insn[i].size;
		dw = (const u32 *)&meta->amdgpu_insn[i];
		memcpy(ptr, dw, size);
		ptr += size;

		if (!trace)
			continue;
		if (size == 4)
			knod_jit_dbg(" 0x%.8X\t%.8X\n",
				     meta->amdgpu_insn_idx, dw[0]);
		else if (size == 8)
			knod_jit_dbg(" 0x%.8X\t%.8X %.8X\n",
				     meta->amdgpu_insn_idx, dw[0], dw[1]);
		else if (size == 12)
			knod_jit_dbg(" 0x%.8X\t%.8X %.8X %.8X\n",
				     meta->amdgpu_insn_idx, dw[0], dw[1], dw[2]);
		else
			WARN_ON_ONCE(1);
	}

	return ptr;
}

/* A routine's callee goes in once, after the program, however many places
 * call it.
 */
struct knod_bpf_placed {
	const u32 *code;
	u32 size;
	u32 at;
};

#define knod_for_each_meta(meta, i, lists)				\
	for (i = 0; i < ARRAY_SIZE(lists); i++)				\
		list_for_each_entry(meta, lists[i], l)

/* Give every distinct callee the program's routines call a place from @end,
 * and return where they all end.
 */
static int knod_bpf_place_callees(struct knod_prog *kp, size_t *end,
				  struct knod_bpf_placed **out, u32 *n_out)
{
	struct list_head *lists[] = { &kp->pre_insns, &kp->insns,
				      &kp->post_insns };
	struct knod_bpf_placed *placed;
	struct knod_insn_meta *meta;
	u32 i, j, c, n = 0, sites = 0;

	*out = NULL;
	*n_out = 0;
	knod_for_each_meta(meta, i, lists)
		for (c = 0; c < KNOD_META_CALLEES; c++)
			sites += !!meta->callee[c].size;
	if (!sites)
		return 0;

	placed = kcalloc(sites, sizeof(*placed), GFP_KERNEL);
	if (!placed)
		return -ENOMEM;

	knod_for_each_meta(meta, i, lists) {
		for (c = 0; c < KNOD_META_CALLEES; c++) {
			const struct knod_blob_callee *callee = &meta->callee[c];

			if (!callee->size)
				continue;
			for (j = 0; j < n; j++)
				if (placed[j].code == callee->code)
					break;
			if (j < n)
				continue;
			placed[n].code = callee->code;
			placed[n].size = callee->size;
			placed[n].at = *end;
			*end += callee->size;
			n++;
		}
	}

	*out = placed;
	*n_out = n;
	return 0;
}

/* Copy the callees to their places and point every call at its own; and
 * an ordered program's jump to where a parked lane resumes.
 */
static void knod_bpf_link_callees(struct knod_prog *kp, u8 *buf,
				  const struct knod_bpf_placed *placed, u32 n)
{
	struct list_head *lists[] = { &kp->pre_insns, &kp->insns,
				      &kp->post_insns };
	u32 i, j, c, k, pos = 0, site, from = 0, to = 0;
	struct knod_insn_meta *meta;

	for (j = 0; j < n; j++)
		memcpy(buf + placed[j].at, placed[j].code, placed[j].size);

	knod_for_each_meta(meta, i, lists) {
		for (c = 0; c < KNOD_META_CALLEES; c++) {
			const struct knod_blob_callee *callee = &meta->callee[c];

			if (!callee->size)
				continue;
			site = pos + callee->patch;
			for (j = 0; j < n; j++)
				if (placed[j].code == callee->code)
					break;
			/* s_getpc gives the address of the add whose literal
			 * this is, which is where the offset is measured from.
			 */
			*(u32 *)(buf + site) = placed[j].at - (site - 4);
		}
		if (meta == kp->resume_from) {
			from = pos;
			for (k = 0; k < kp->resume_insn; k++)
				from += meta->amdgpu_insn[k].size;
		}
		if (meta == kp->resume_at)
			to = pos;
		pos += knod_meta_bytes(meta);
	}

	/* A branch's offset is in dwords from the instruction after it. */
	if (kp->resume_from && kp->resume_at)
		*(u16 *)(buf + from) = (to - (from + 4)) / 4;
}

/* No program: the engine's receive kernel, which passes everything. */
static int knod_bpf_reload_pass(struct knod_dev *knodev)
{
	struct knod_bpf_priv *priv = knodev->accel->xdp.priv;
	int err;

	if (!priv)
		return -ENODEV;
	err = knod_gda_install_default(priv->knod);
	if (err)
		return err;
	priv->lds_bytes = 0;
	priv->prog_stack_scratch = false;
	WRITE_ONCE(priv->gpu_map_gc_possible, false);
	return 0;
}

static int knod_setup_bpf_prog(struct bpf_prog *prog)
{
	struct knod_prog *knod_prog = prog->aux->offload->dev_priv;
	struct knod_dev *knodev = knod_prog->knodev;
	struct knod_insn_meta *meta, *tmp;
	struct knod_bpf_placed *placed = NULL;
	size_t total_bytes = 0, prog_bytes;
	struct knod_bpf_priv *priv;
	u32 n_placed = 0;
	u8 *kernel_ptr;
	int err = 0;

	priv = (struct knod_bpf_priv *)knodev->accel->xdp.priv;

	if (prog) {
		list_for_each_entry(meta, &priv->knod_prog->pre_insns, l)
			total_bytes += knod_meta_bytes(meta);
		list_for_each_entry(meta, &priv->knod_prog->insns, l)
			total_bytes += knod_meta_bytes(meta);
		list_for_each_entry(meta, &priv->knod_prog->post_insns, l)
			total_bytes += knod_meta_bytes(meta);

		prog_bytes = total_bytes;
		err = knod_bpf_place_callees(priv->knod_prog, &total_bytes,
					     &placed, &n_placed);
		if (err)
			goto out;

		pr_debug("KNOD JIT: total binary size = %zu bytes (limit %u)\n",
			 total_bytes, KNOD_BPF_PROG_BUF_SIZE);
		if (WARN_ON(total_bytes > KNOD_BPF_PROG_BUF_SIZE)) {
			err = -E2BIG;
			goto out;
		}

		kernel_ptr = priv->prog_buf;
		memset(priv->prog_buf, 0, KNOD_BPF_PROG_BUF_SIZE);

		list_for_each_entry(meta, &priv->knod_prog->pre_insns, l)
			kernel_ptr = knod_meta_write(meta, kernel_ptr, true);

		list_for_each_entry(meta, &priv->knod_prog->insns, l)
			kernel_ptr = knod_meta_write(meta, kernel_ptr, true);

		list_for_each_entry(meta, &priv->knod_prog->post_insns, l)
			kernel_ptr = knod_meta_write(meta, kernel_ptr, true);
		WARN_ON(kernel_ptr - (u8 *)priv->prog_buf != prog_bytes);
		knod_bpf_link_callees(priv->knod_prog, priv->prog_buf, placed,
				      n_placed);
		err = knod_bpf_install_kernel(priv, knod_prog, priv->prog_buf,
						      (u32)total_bytes);
		if (!err)
			WRITE_ONCE(priv->prog, prog);
	} else {
		err = knod_bpf_reload_pass(knodev);
		if (err)
			goto out;

		WRITE_ONCE(priv->prog, NULL);
		list_for_each_entry_safe(meta, tmp, &priv->knod_prog->pre_insns,
					 l) {
			list_del_init(&meta->l);
			kfree(meta);
		}

		list_for_each_entry_safe(meta, tmp, &priv->knod_prog->insns,
					 l) {
			list_del_init(&meta->l);
			kfree(meta);
		}

		list_for_each_entry_safe(meta, tmp,
					 &priv->knod_prog->post_insns, l) {
			list_del_init(&meta->l);
			kfree(meta);
		}

		/* bbs points into the metas just freed */
		kfree(priv->knod_prog->bbs);
		priv->knod_prog->bbs = NULL;
		priv->knod_prog->n_bbs = 0;
	}
out:
	kfree(placed);
	return err;
}

static int knod_bpf_map_hash_init_elem(struct knod_bpf_map *knod_map,
				       struct knod_bpf_map_obj *knod_map_obj)
{
	unsigned int *queue = (unsigned int *)knod_map->queue_mem->kaddr;
	unsigned int *bucket = (unsigned int *)&knod_map_obj->bucket[0];
	void *elems = knod_map->hash_elems_mem->kaddr;
	struct knod_bpf_hash_elem_obj *e;
	int i, elem_size;

	elem_size = knod_bpf_hash_elem_size(knod_map_obj->key_size,
					    knod_map_obj->value_size,
					    knod_map_obj->meta.hmeta.n_instances);
	knod_map_obj->meta.hmeta.elem_size = elem_size;

	for (i = 0; i < knod_map_obj->meta.hmeta.n_buckets; i++)
		bucket[i] = knod_bpf_hash_end(i);

	for (i = 0; i < knod_map_obj->max_entries; i++) {
		e = elems + (i * elem_size);
		e->next = KNOD_BPF_HASH_NEXT_END;
		queue[i] = i;
	}
	knod_map_obj->meta.hmeta.cur = knod_map_obj->max_entries;

	return 0;
}

static inline unsigned char *
knod_bpf_hash_elem_kv(struct knod_bpf_hash_elem_obj *e)
{
	return (unsigned char *)e + offsetof(struct knod_bpf_hash_elem_obj, kv);
}

static inline void *
knod_bpf_array_value_ptr(struct knod_bpf_map_obj *knod_map_obj,
			 unsigned int idx)
{
	return (unsigned char *)knod_map_obj +
	       offsetof(struct knod_bpf_map_obj, bucket) +
	       (size_t)idx * knod_map_obj->value_size;
}

/* Restate the map for a prebuilt routine, which knows this layout and none of
 * the kernel's own.  Everything a routine can reach is an offset from here, so
 * a blob carries no relocations.
 */
static void knod_bpf_map_fill_desc(struct knod_bpf_map *knod_map)
{
	const struct knod_bpf_map_obj *obj = knod_map->knod_map_obj;
	struct knod_blob_map_desc *desc = knod_map->desc;
	u64 obj_gaddr = knod_map->mem->gaddr;

	memset(desc, 0, sizeof(*desc));
	desc->key_size = obj->key_size;
	desc->value_size = obj->value_size;
	desc->max_entries = obj->max_entries;
	desc->bucket_gaddr = obj_gaddr +
			     offsetof(struct knod_bpf_map_obj, bucket);
	/* Where the values are, whatever kind of map this is.  An array keeps
	 * them in the map object itself and a hash in a BO of its own, and a
	 * routine is told the base rather than the difference.
	 */
	desc->elems_gaddr = desc->bucket_gaddr;

	if (knod_bpf_map_type_hash(obj->map_type)) {
		desc->elem_size = obj->meta.hmeta.elem_size;
		desc->elems_gaddr = (u64)obj->meta.hmeta.elems;
		desc->queue_gaddr = (u64)obj->meta.hmeta.q;
		desc->gc_list_gaddr = (u64)obj->meta.hmeta.gc_list;
		desc->gc_count_gaddr = obj_gaddr +
			offsetof(struct knod_bpf_map_obj, meta.hmeta.gc_count);
		desc->free_cur_gaddr = obj_gaddr +
			offsetof(struct knod_bpf_map_obj, meta.hmeta.cur);
		desc->n_buckets = obj->meta.hmeta.n_buckets;
		/* The locks follow the bucket heads in the same array. */
		desc->lock_offset = obj->meta.hmeta.n_buckets *
				    sizeof(unsigned int);
		desc->hashrnd = obj->meta.hmeta.hashrnd;
		/* Non-zero only for PERCPU_HASH: the per-instance value slot
		 * stride the blob adds workgroup_id_y * this to reach.
		 */
		desc->per_instance_size = obj->meta.hmeta.per_instance_size;
		desc->n_instances = obj->meta.hmeta.n_instances;
		if (knod_bpf_map_type_lru(obj->map_type)) {
			desc->flags |= KNOD_BLOB_MAP_LRU;
			desc->clock_gaddr = obj_gaddr +
				offsetof(struct knod_bpf_map_obj,
					 meta.hmeta.clock);
		}
	} else {
		desc->per_instance_size = obj->meta.ameta.per_instance_size;
	}
}

/* Where a map's BOs sit in the GPU's address space, to place a fault. */
static void knod_bpf_map_log(struct knod_bpf_map *knod_map, const char *what)
{
	struct knod_mem *m[] = { knod_map->mem, knod_map->hash_elems_mem,
				 knod_map->queue_mem, knod_map->gc_mem };
	int i;

	for (i = 0; i < ARRAY_SIZE(m); i++)
		if (m[i])
			pr_debug("knod_bpf: map %p %s bo%d 0x%llx-0x%llx\n",
				knod_map, what, i, m[i]->gaddr,
				m[i]->gaddr + m[i]->size);
}

static int __knod_bpf_map_alloc(struct knod_dev *knodev,
				struct bpf_offloaded_map *offmap)
{
	struct knod_bpf_priv *priv =
		(struct knod_bpf_priv *)knodev->accel->xdp.priv;
	struct knod_mem *mem, *queue_mem, *hash_elems_mem, *gc_mem;
	int order, size, queue_size, i, value_size, nents, err;
	int n_instances = 1;
	int flags = KFD_IOC_ALLOC_MEM_FLAGS_WRITABLE |
		    KFD_IOC_ALLOC_MEM_FLAGS_PUBLIC |
		    KFD_IOC_ALLOC_MEM_FLAGS_VRAM;
	struct knod_bpf_map_obj *knod_map_obj;
	struct knod *knod = priv->knod;
	struct knod_bpf_map *knod_map;
	unsigned int gc_size, desc_off;
	unsigned int *q;

	bool is_hash = knod_bpf_map_type_hash(offmap->map.map_type);
	bool is_percpu = offmap->map.map_type == BPF_MAP_TYPE_PERCPU_ARRAY ||
			 knod_bpf_map_type_percpu_hash(offmap->map.map_type);

	if (is_hash) {
		/* An index has to stay clear of a chain end's flag. */
		if (offmap->map.max_entries > KNOD_BLOB_HASH_NULLS / 2)
			return -E2BIG;
		value_size = sizeof(unsigned int);
		nents = roundup_pow_of_two(offmap->map.max_entries);
	} else {
		value_size = offmap->map.value_size;
		nents = offmap->map.max_entries;
	}

	/* A percpu map keeps one value instance per GPU workgroup so each CU
	 * updates its own copy - no cross-CU atomic contention.  Instances map
	 * 1:1 to the per-cpu buffer (workgroup_id_y indexes into it), one per
	 * queue, handed back through the per-cpu slot of the same number, so
	 * there has to be a slot for every queue.  An ordinary NIC gives out no
	 * more queues than there are cpus; some do.  For PERCPU_ARRAY the value
	 * instances live in the map-obj tail; for PERCPU_HASH they are extra
	 * value slots inside each hash element (see knod_bpf_hash_elem_size).
	 */
	if (is_percpu) {
		if (priv->nr_works > num_possible_cpus()) {
			pr_warn("knod_bpf: %d rx queues but %u cpus; a percpu map keeps one instance per queue and has nowhere to report the rest\n",
				priv->nr_works, num_possible_cpus());
			return -EOPNOTSUPP;
		}
		n_instances = num_possible_cpus();
	}

	/* Hash types put their per-instance values in the elems BO, not the
	 * map-obj tail, so n_instances multiplies elem_size (below), not this
	 * bucket-head region.
	 */
	size = sizeof(struct knod_bpf_map_obj) +
	       value_size * nents * (is_hash ? 1 : n_instances);
	if (is_hash)
		size += sizeof(unsigned int) * nents;
	desc_off = round_up(size, __alignof__(struct knod_blob_map_desc));
	size = desc_off + sizeof(struct knod_blob_map_desc);
	order = get_order(size);

	mem = knod_alloc_mem(knod, PAGE_SIZE << order, flags);
	if (IS_ERR(mem))
		return -ENOMEM;

	memset(mem->kaddr, 0, size);
	knod_map = kzalloc_obj(struct knod_bpf_map, GFP_KERNEL);
	if (!knod_map) {
		knod_free_mem(knod, mem);
		return -ENOMEM;
	}

	knod_map->mem = mem;
	knod_map->queue_mem = NULL;
	knod_map->hash_elems_mem = NULL;
	knod_map->offmap = offmap;
	knod_map->priv = priv;
	if (offmap->dev_priv)
		WARN_ON_ONCE(1);
	offmap->dev_priv = knod_map;

	knod_map->desc = mem->kaddr + desc_off;
	knod_map->desc_gaddr = mem->gaddr + desc_off;

	knod_map_obj = (struct knod_bpf_map_obj *)mem->kaddr;
	knod_map_obj->key_size = offmap->map.key_size;
	if (knod_map_obj->key_size > MAX_MAP_KEY_SIZE) {
		pr_warn("request key size is %d, but max key size is %d\n",
			knod_map_obj->key_size, MAX_MAP_KEY_SIZE);
		return -ENOMEM;
	}
	knod_map_obj->value_size = offmap->map.value_size;
	knod_map_obj->max_entries = nents;
	knod_map_obj->id = offmap->map.id;
	knod_map_obj->map_type = offmap->map.map_type;
	if (is_hash) {
		knod_map_obj->meta.hmeta.n_buckets = nents;
		if (offmap->map.map_flags & BPF_F_ZERO_SEED)
			knod_map_obj->meta.hmeta.hashrnd = 0;
		else
			knod_map_obj->meta.hmeta.hashrnd = get_random_u32();
		knod_map_obj->meta.hmeta.n_instances = n_instances;
		knod_map_obj->meta.hmeta.per_instance_size = is_percpu ?
			knod_bpf_hash_value_stride(knod_map_obj->value_size) : 0;
	} else {
		knod_map_obj->meta.ameta.per_instance_size = value_size * nents;
		knod_map_obj->meta.ameta.n_instances = n_instances;
	}
	knod_map->knod_map_obj = knod_map_obj;
	/* map->flags = ? */
	knod_jit_dbg(" map_id = %d\n", knod_map_obj->id);

	if (is_hash) {
		queue_size = sizeof(unsigned int) * nents;
		queue_size = PAGE_SIZE << get_order(queue_size);
		queue_mem = knod_alloc_mem(knod, queue_size, flags);
		if (IS_ERR(queue_mem)) {
			knod_free_mem(knod, mem);
			kfree(knod_map);
			return -ENOMEM;
		}

		memset(queue_mem->kaddr, 0, queue_mem->size);
		q = queue_mem->kaddr;
		for (i = 0; i < knod_map_obj->meta.hmeta.n_buckets; i++)
			q[i] = i;
		knod_map->queue_mem = queue_mem;
		knod_map_obj->meta.hmeta.q = (struct _queue *)queue_mem->gaddr;

		queue_size = knod_bpf_hash_elem_size(knod_map_obj->key_size,
						     knod_map_obj->value_size,
						     n_instances) *
			     knod_map_obj->max_entries;
		queue_size = PAGE_SIZE << get_order(queue_size);

		hash_elems_mem = knod_alloc_mem(knod, queue_size, flags);
		if (IS_ERR(hash_elems_mem)) {
			knod_free_mem(knod, queue_mem);
			knod_free_mem(knod, mem);
			kfree(knod_map);
			return -ENOMEM;
		}

		memset(hash_elems_mem->kaddr, 0, queue_size);
		knod_map->hash_elems_mem = hash_elems_mem;
		knod_map_obj->meta.hmeta.elems = (void *)hash_elems_mem->gaddr;
		knod_bpf_map_hash_init_elem(knod_map, knod_map_obj);

		/* GC list for GPU-side delete: elem_ids pending unlink */
		gc_size = sizeof(unsigned int) * nents;
		gc_size = PAGE_SIZE << get_order(gc_size);
		gc_mem = knod_alloc_mem(knod, gc_size, flags);
		if (IS_ERR(gc_mem)) {
			knod_free_mem(knod, hash_elems_mem);
			knod_free_mem(knod, queue_mem);
			knod_free_mem(knod, mem);
			kfree(knod_map);
			return -ENOMEM;
		}
		memset(gc_mem->kaddr, 0, gc_size);
		knod_map->gc_mem = gc_mem;
		knod_map_obj->meta.hmeta.gc_count = 0;
		knod_map_obj->meta.hmeta.gc_list = (void *)gc_mem->gaddr;
	}

	knod_bpf_map_fill_desc(knod_map);
	knod_bpf_map_log(knod_map, "alloc");

	err = __knod_map_mem(knod, mem);
	if (err) {
		pr_err("knod_bpf: failed to GPU-map map BO\n");
		goto err_map;
	}
	if (is_hash) {
		err = __knod_map_mem(knod, queue_mem);
		if (err) {
			pr_err("knod_bpf: failed to GPU-map queue BO\n");
			goto err_map;
		}
		err = __knod_map_mem(knod, hash_elems_mem);
		if (err) {
			pr_err("knod_bpf: failed to GPU-map hash_elems BO\n");
			goto err_map;
		}
		err = __knod_map_mem(knod, knod_map->gc_mem);
		if (err) {
			pr_err("knod_bpf: failed to GPU-map gc BO\n");
			goto err_map;
		}
	}
	knod_bpf_gpu_mem_fence(priv);

	mutex_lock(&knodev->lock);
	list_add(&knod_map->list, &knodev->accel->xdp.bound_maps);
	mutex_unlock(&knodev->lock);
	return 0;

err_map:
	if (is_hash) {
		knod_free_mem(knod, knod_map->gc_mem);
		knod_free_mem(knod, hash_elems_mem);
		knod_free_mem(knod, queue_mem);
	}
	knod_free_mem(knod, mem);
	kfree(knod_map);
	return err;
}

static void knod_bpf_map_setup(struct bpf_prog *prog)
{
	struct knod_prog *knod_prog = prog->aux->offload->dev_priv;
	struct knod_dev *knodev = knod_prog->knodev;
	struct knod_bpf_map *knod_map;
	struct knod_bpf_map_obj *map;
	struct knod_mem *mem;

	mutex_lock(&knodev->lock);
	list_for_each_entry(knod_map, &knodev->accel->xdp.bound_maps, list) {
		mem = knod_map->mem;
		map = mem->kaddr;
		map->id = knod_map->offmap->map.id;
		map->map_type = knod_map->offmap->map.map_type;
		knod_jit_dbg(" id = %d type = %d\n", knod_map->offmap->map.id,
			knod_map->offmap->map.map_type);
	}
	mutex_unlock(&knodev->lock);
}

static struct knod_bpf_hash_elem_obj *
knod_bpf_map_hash_pop(struct knod_bpf_map *knod_map,
		      struct knod_bpf_map_obj *knod_map_obj)
{
	void *elems = knod_map->hash_elems_mem->kaddr;
	unsigned int *queue = (unsigned int *)knod_map->queue_mem->kaddr;
	struct knod_bpf_hash_elem_obj *e;
	int elem_id;

	/* The count is what is free and the queue is a stack of that many, so
	 * the element to take is the one below the top.  Signed, because the
	 * shader decrements before it knows whether there was anything left.
	 */
	if ((int)knod_map_obj->meta.hmeta.cur <= 0)
		return NULL;

	knod_map_obj->meta.hmeta.cur--;
	elem_id = queue[knod_map_obj->meta.hmeta.cur];
	knod_jit_dbg(" elem_id = 0x%x\n", elem_id);
	e = elems + (elem_id * knod_map_obj->meta.hmeta.elem_size);
	e->next = KNOD_BPF_HASH_NEXT_END;

	return e;
}

/* Copy the value(s) between a hash element and a userspace buffer.  A plain
 * HASH has one value slot after the key; a PERCPU_HASH has n_instances slots,
 * each value_stride bytes, and userspace lays its per-cpu values out with the
 * same stride.
 */
static void knod_bpf_hash_read_value(const struct knod_bpf_map_obj *o,
				     const struct knod_bpf_hash_elem_obj *e,
				     void *value)
{
	unsigned int stride = knod_bpf_hash_value_stride(o->value_size);
	unsigned int voff = knod_bpf_hash_value_off(o->key_size);
	unsigned int n = o->meta.hmeta.n_instances ? : 1;
	unsigned int i;

	for (i = 0; i < n; i++)
		memcpy((char *)value + i * stride,
		       (const char *)e + voff + i * stride, o->value_size);
}

static void knod_bpf_hash_write_value(const struct knod_bpf_map_obj *o,
				      struct knod_bpf_hash_elem_obj *e,
				      const void *value)
{
	unsigned int stride = knod_bpf_hash_value_stride(o->value_size);
	unsigned int voff = knod_bpf_hash_value_off(o->key_size);
	unsigned int n = o->meta.hmeta.n_instances ? : 1;
	unsigned int i;

	for (i = 0; i < n; i++)
		unsafe_memcpy((char *)e + voff + i * stride,
			      (const char *)value + i * stride, o->value_size,
			      "knod hash elems are variable-sized GPU map records");
}

/* A shader insert into a PERCPU_HASH writes only this instance's value slot, so
 * an element handed back to the free list has to leave with every slot zeroed;
 * otherwise the next key it holds inherits the previous key's per-cpu values in
 * the slots this queue never touches, and the summed readback is wrong.  No-op
 * for a plain hash, whose insert overwrites the one value in full.
 */
static void knod_bpf_hash_free_value(const struct knod_bpf_map_obj *o,
				     struct knod_bpf_hash_elem_obj *e)
{
	unsigned int stride = knod_bpf_hash_value_stride(o->value_size);
	unsigned int voff = knod_bpf_hash_value_off(o->key_size);
	unsigned int n = o->meta.hmeta.n_instances ? : 1;

	if (!knod_bpf_map_type_percpu_hash(o->map_type))
		return;

	memset((char *)e + voff, 0, stride * n);
	wmb();
}

/* An LRU hash with nothing free gives up an element the way the program's
 * insert would (see the blob's evict()): by the clock, passing over once what
 * was used since the hand last came by.  Back on the free queue, for the
 * insert to take.  The queues are parked, so no lock.
 */
static void knod_bpf_map_hash_evict(struct knod_bpf_map *knod_map,
				    struct knod_bpf_map_obj *knod_map_obj)
{
	unsigned int elem_size = knod_map_obj->meta.hmeta.elem_size;
	unsigned int n = knod_map_obj->max_entries, id, at, i;
	unsigned int *bucket = (unsigned int *)&knod_map_obj->bucket[0];
	unsigned int *queue = knod_map->queue_mem->kaddr;
	void *elems = knod_map->hash_elems_mem->kaddr;
	struct knod_bpf_hash_elem_obj *e, *pe;
	unsigned int *link;

	for (i = 0; i < 2 * n; i++) {
		id = knod_map_obj->meta.hmeta.clock++ & (n - 1);
		e = elems + id * elem_size;
		if (!(e->lru & KNOD_BLOB_ELEM_LIVE))
			continue;
		if (e->lru & KNOD_BLOB_ELEM_REF) {
			e->lru &= ~KNOD_BLOB_ELEM_REF;
			continue;
		}
		link = &bucket[e->lru >> KNOD_BLOB_ELEM_BUCKET_SHIFT];
		for (at = *link & KNOD_BPF_HASH_NEXT_MASK;
		     !knod_bpf_hash_is_end(at) && at != id;
		     at = *link & KNOD_BPF_HASH_NEXT_MASK) {
			pe = elems + at * elem_size;
			link = &pe->next;
		}
		if (at != id)
			continue;
		*link = (*link & KNOD_BPF_HASH_NEXT_DELETED) |
			(e->next & KNOD_BPF_HASH_NEXT_MASK);
		e->next = KNOD_BPF_HASH_NEXT_END;
		e->lru = 0;
		knod_bpf_hash_free_value(knod_map_obj, e);
		queue[knod_map_obj->meta.hmeta.cur++] = id;
		return;
	}
}

static struct knod_bpf_hash_elem_obj *
knod_bpf_map_hash_alloc_elem(struct knod_bpf_map *knod_map,
			     struct knod_bpf_map_obj *knod_map_obj,
			     void *key, void *value, unsigned int hash)
{
	struct knod_bpf_hash_elem_obj *e;

	e = knod_bpf_map_hash_pop(knod_map, knod_map_obj);
	if (!e)
		return NULL;

	unsafe_memcpy(knod_bpf_hash_elem_kv(e), key, knod_map_obj->key_size,
		      "knod hash elems are variable-sized GPU map records");
	knod_bpf_hash_write_value(knod_map_obj, e, value);
	e->next = knod_bpf_hash_end(hash);
	e->lru = KNOD_BLOB_ELEM_LIVE | hash << KNOD_BLOB_ELEM_BUCKET_SHIFT;
	/* VRAM is ioremap_wc - drain new elem's next and kv stores before
	 * the caller publishes a pointer to this elem.
	 */
	wmb();
	return e;
}

/* Where a host read finds the map: the snapshot if one was taken, else the
 * map itself.
 */
static void knod_bpf_map_view(struct knod_bpf_map *knod_map,
			      struct knod_bpf_map_obj **obj, void **elems)
{
	if (knod_map->snap_ok) {
		*obj = knod_map->snap->kaddr;
		*elems = knod_map->snap_elems ? knod_map->snap_elems->kaddr :
						NULL;
	} else {
		*obj = knod_map->knod_map_obj;
		*elems = knod_map->hash_elems_mem ?
			 knod_map->hash_elems_mem->kaddr : NULL;
	}
}

static int knod_bpf_map_hash_lookup_elem(struct knod_bpf_map_obj *knod_map_obj,
					 void *elems, void *key, void *value)
{
	unsigned int hash, elem_id, elem_size;
	struct knod_bpf_hash_elem_obj *e;
	unsigned int *bucket;

	hash = jhash((const void *)key, knod_map_obj->key_size,
		     knod_map_obj->meta.hmeta.hashrnd);
	knod_jit_dbg(" hash = %x\n", hash);
	hash = hash & (knod_map_obj->meta.hmeta.n_buckets - 1);
	knod_jit_dbg(" hash = %x\n", hash);
	bucket = (unsigned int *)&knod_map_obj->bucket[0];

	elem_id = bucket[hash];
	if (knod_bpf_hash_is_end(elem_id))
		return -ENOENT;

	elem_size = knod_map_obj->meta.hmeta.elem_size;

	e = elems + (elem_id * elem_size);
	while (1) {
		if (!(e->next & KNOD_BPF_HASH_NEXT_DELETED) &&
		    !memcmp(&e->kv[0], (const unsigned char *)key,
			    knod_map_obj->key_size)) {
			knod_bpf_hash_read_value(knod_map_obj, e, value);
			return 0;
		}
		unsigned int real_next = e->next & KNOD_BPF_HASH_NEXT_MASK;

		if (knod_bpf_hash_is_end(real_next))
			return -ENOENT;
		e = elems + (real_next * elem_size);
	}

	return -ENOENT;
}

/* What an insert into a full map says, as the kernel's: an LRU one only gets
 * here when it found nothing to evict.
 */
static int knod_bpf_map_hash_full(const struct knod_bpf_map_obj *knod_map_obj)
{
	return knod_bpf_map_type_lru(knod_map_obj->map_type) ? -ENOMEM : -E2BIG;
}

/* Whether @key is in the chain at @hash, so an update would overwrite it. */
static bool knod_bpf_map_hash_has(struct knod_bpf_map *knod_map,
				  struct knod_bpf_map_obj *knod_map_obj,
				  void *key, unsigned int hash)
{
	unsigned int elem_size = knod_map_obj->meta.hmeta.elem_size;
	unsigned int *bucket = (unsigned int *)&knod_map_obj->bucket[0];
	void *elems = knod_map->hash_elems_mem->kaddr;
	struct knod_bpf_hash_elem_obj *e;
	unsigned int id;

	for (id = bucket[hash]; !knod_bpf_hash_is_end(id);
	     id = e->next & KNOD_BPF_HASH_NEXT_MASK) {
		e = elems + id * elem_size;
		if (!(e->next & KNOD_BPF_HASH_NEXT_DELETED) &&
		    !memcmp(&e->kv[0], key, knod_map_obj->key_size))
			return true;
	}
	return false;
}

static int knod_bpf_map_hash_update_elem(struct knod_bpf_map *knod_map,
					 struct knod_bpf_map_obj *knod_map_obj,
					 void *key, void *value, u64 flags)
{
	void *elems = knod_map->hash_elems_mem->kaddr;
	unsigned int hash, elem_id, elem_size;
	struct knod_bpf_hash_elem_obj *e, *ne;
	unsigned int *bucket;
	bool has;

	if (flags > BPF_EXIST)
		return -EINVAL;

	hash = jhash((const void *)key, knod_map_obj->key_size,
		     knod_map_obj->meta.hmeta.hashrnd);
	hash = hash & (knod_map_obj->meta.hmeta.n_buckets - 1);
	bucket = (unsigned int *)&knod_map_obj->bucket[0];

	has = knod_bpf_map_hash_has(knod_map, knod_map_obj, key, hash);
	if (has && flags == BPF_NOEXIST)
		return -EEXIST;
	if (!has && flags == BPF_EXIST)
		return -ENOENT;
	if (!has && knod_bpf_map_type_lru(knod_map_obj->map_type) &&
	    (int)knod_map_obj->meta.hmeta.cur <= 0)
		knod_bpf_map_hash_evict(knod_map, knod_map_obj);

	elem_size = knod_map_obj->meta.hmeta.elem_size;
	elem_id = bucket[hash];
	if (knod_bpf_hash_is_end(elem_id)) {
		ne = knod_bpf_map_hash_alloc_elem(knod_map, knod_map_obj, key,
						  value, hash);
		if (!ne)
			return knod_bpf_map_hash_full(knod_map_obj);
		bucket[hash] = ((void *)ne - (void *)elems) / elem_size;
		return 0;
	}

	e = elems + (elem_id * elem_size);
	while (1) {
		if (!(e->next & KNOD_BPF_HASH_NEXT_DELETED) &&
		    !memcmp(&e->kv[0], (const unsigned char *)key,
			    knod_map_obj->key_size)) {
			knod_bpf_hash_write_value(knod_map_obj, e, value);
			if (knod_bpf_map_type_lru(knod_map_obj->map_type))
				e->lru |= KNOD_BLOB_ELEM_REF;
			return 0;
		}
		unsigned int real_next = e->next & KNOD_BPF_HASH_NEXT_MASK;

		if (knod_bpf_hash_is_end(real_next)) {
			ne = knod_bpf_map_hash_alloc_elem(knod_map,
							  knod_map_obj,
							  key, value, hash);
			if (!ne)
				return knod_bpf_map_hash_full(knod_map_obj);
			e->next = (e->next & KNOD_BPF_HASH_NEXT_DELETED) |
				  (((void *)ne - (void *)elems) / elem_size);
			return 0;
		}
		e = elems + (real_next * elem_size);
	}

	return -ENOENT;
}

static int knod_bpf_map_hash_delete_elem(struct knod_bpf_map *knod_map,
					 struct knod_bpf_map_obj *knod_map_obj,
					 void *key)
{
	void *elems = knod_map->hash_elems_mem->kaddr;
	unsigned int *queue = knod_map->queue_mem->kaddr;
	unsigned int hash, elem_id, elem_size, cur;
	struct knod_bpf_hash_elem_obj *e, *pe;
	unsigned int *bucket;

	hash = jhash((const void *)key, knod_map_obj->key_size,
		     knod_map_obj->meta.hmeta.hashrnd);
	hash = hash & (knod_map_obj->meta.hmeta.n_buckets - 1);
	bucket = (unsigned int *)&knod_map_obj->bucket[0];

	elem_id = bucket[hash];
	if (knod_bpf_hash_is_end(elem_id))
		return -ENOENT;

	elem_size = knod_map_obj->meta.hmeta.elem_size;

	e = elems + (elem_id * elem_size);
	pe = e;
	while (1) {
		if (!(e->next & KNOD_BPF_HASH_NEXT_DELETED) &&
		    !memcmp(&e->kv[0], (const unsigned char *)key,
			    knod_map_obj->key_size)) {
			unsigned int e_next = e->next & KNOD_BPF_HASH_NEXT_MASK;
			unsigned int del_id = ((void *)e - elems) / elem_size;

			/* Unlink (GPU is paused - safe) */
			if (pe != e)
				pe->next = (pe->next &
					    KNOD_BPF_HASH_NEXT_DELETED) |
					   e_next;
			else
				bucket[hash] = e_next;

			e->next = KNOD_BPF_HASH_NEXT_END;
			e->lru = 0;
			knod_bpf_hash_free_value(knod_map_obj, e);

			/* Return elem to queue */
			cur = knod_map_obj->meta.hmeta.cur;
			queue[cur] = del_id;
			knod_map_obj->meta.hmeta.cur = cur + 1;
			return 0;
		}
		unsigned int real_next = e->next & KNOD_BPF_HASH_NEXT_MASK;

		if (knod_bpf_hash_is_end(real_next))
			return -ENOENT;
		pe = e;
		e = elems + (real_next * elem_size);
	}

	return -ENOENT;
}

static int knod_bpf_map_hash_get_first_key(struct bpf_offloaded_map *offmap,
					   void *nkey)
{
	struct knod_bpf_map *knod_map = (struct knod_bpf_map *)offmap->dev_priv;
	struct knod_bpf_map_obj *knod_map_obj;
	unsigned int *bucket, elem_size, i;
	struct knod_bpf_hash_elem_obj *e;
	void *elems;

	knod_bpf_map_view(knod_map, &knod_map_obj, &elems);
	bucket =  (unsigned int *)&knod_map_obj->bucket[0];

	elem_size = knod_map_obj->meta.hmeta.elem_size;

	for (i = 0; i < knod_map_obj->meta.hmeta.n_buckets; i++) {
		unsigned int eid;

		if (knod_bpf_hash_is_end(bucket[i]))
			continue;
		eid = bucket[i];
		while (!knod_bpf_hash_is_end(eid)) {
			e = elems + (eid * elem_size);
			if (!(e->next & KNOD_BPF_HASH_NEXT_DELETED)) {
				unsafe_memcpy(nkey, knod_bpf_hash_elem_kv(e),
					      knod_map_obj->key_size,
					      "knod hash elems are variable-sized GPU map records");
				return 0;
			}
			eid = e->next & KNOD_BPF_HASH_NEXT_MASK;
		}
	}

	return -ENOENT;
}

static int knod_bpf_map_hash_get_next_key(struct bpf_offloaded_map *offmap,
					  void *key, void *nkey)
{
	struct knod_bpf_map *knod_map = (struct knod_bpf_map *)offmap->dev_priv;
	struct knod_bpf_map_obj *knod_map_obj;
	unsigned int *bucket, elem_size, i;
	struct knod_bpf_hash_elem_obj *e;
	bool found = false;
	unsigned int hash;
	void *elems;

	knod_bpf_map_view(knod_map, &knod_map_obj, &elems);
	bucket =  (unsigned int *)&knod_map_obj->bucket[0];

	hash = jhash((const void *)key, knod_map_obj->key_size,
		     knod_map_obj->meta.hmeta.hashrnd);
	hash = hash & (knod_map_obj->meta.hmeta.n_buckets - 1);
	elem_size = knod_map_obj->meta.hmeta.elem_size;

	for (i = hash; i < knod_map_obj->meta.hmeta.n_buckets; i++) {
		unsigned int eid;

		if (knod_bpf_hash_is_end(bucket[i]))
			continue;

		eid = bucket[i];
		while (!knod_bpf_hash_is_end(eid)) {
			e = elems + (eid * elem_size);
			if (!(e->next & KNOD_BPF_HASH_NEXT_DELETED)) {
				if (found &&
				    memcmp(&e->kv[0],
					   (const unsigned char *)key,
					   knod_map_obj->key_size)) {
					unsafe_memcpy(nkey,
						      knod_bpf_hash_elem_kv(e),
						      knod_map_obj->key_size,
						      "knod hash elems are variable-sized GPU map records");
					return 0;
				}
				if (!memcmp(&e->kv[0],
					    (const unsigned char *)key,
					    knod_map_obj->key_size))
					found = true;
			}
			eid = e->next & KNOD_BPF_HASH_NEXT_MASK;
		}
		/* A key that is gone - evicted, or deleted - starts the walk
		 * over, as the kernel's htab_map_get_next_key() does.
		 */
		if (!found)
			return knod_bpf_map_hash_get_first_key(offmap, nkey);
	}

	return -ENOENT;
}

static void knod_bpf_map_free(struct knod_dev *knodev,
			      struct bpf_offloaded_map *offmap)
{
	struct knod_bpf_map *knod_map = offmap->dev_priv;
	struct knod_bpf_priv *priv = knodev->accel->xdp.priv;

	if (!knod_map)
		return;
	/*
	 * Defer the BO free: a running program may still reference this map's
	 * VRAM.  Move it from bound_maps onto dead_maps under knodev->lock (the
	 * lock that guards the add); the worker reaps it from there with the
	 * queues parked.
	 */
	mutex_lock(&knodev->lock);
	list_del(&knod_map->list);
	list_add(&knod_map->list, &priv->dead_maps);
	WRITE_ONCE(priv->maps_gc_pending, true);
	mutex_unlock(&knodev->lock);
	offmap->dev_priv = NULL;
}

static int __knod_bpf_map_lookup_elem(struct bpf_offloaded_map *offmap,
				      void *key, void *value)
{
	unsigned int idx = *(unsigned int *)key;
	struct knod_bpf_map_obj *knod_map_obj;
	struct knod_bpf_map *knod_map;
	void *bucket, *elems;
	u32 stride;
	int i;

	knod_map = (struct knod_bpf_map *)offmap->dev_priv;
	if (!knod_map || !knod_map->mem || !knod_map->mem->kaddr ||
	    (knod_map->hash_elems_mem && !knod_map->hash_elems_mem->kaddr)) {
		pr_err("knod_bpf: lookup on freed/invalid map (dev_priv=%p)\n",
		       offmap->dev_priv);
		return -ENODEV;
	}
	knod_bpf_map_view(knod_map, &knod_map_obj, &elems);

	if (knod_map_obj->map_type == BPF_MAP_TYPE_ARRAY) {
		if (*(unsigned int *)key >= knod_map_obj->max_entries)
			return -ENOENT;
		bucket = knod_bpf_array_value_ptr(knod_map_obj, idx);

		unsafe_memcpy(value, bucket, knod_map_obj->value_size,
			      "knod array values live in a variable-sized GPU map tail");
	} else if (knod_map_obj->map_type == BPF_MAP_TYPE_PERCPU_ARRAY) {
		if (idx >= knod_map_obj->max_entries)
			return -ENOENT;
		stride = round_up(knod_map_obj->value_size, 8);
		bucket = &knod_map_obj->bucket[0];
		bucket += (idx * knod_map_obj->value_size);
		for (i = 0; i < knod_map_obj->meta.ameta.n_instances; i++)
			unsafe_memcpy(value + i * stride,
				      bucket + i *
				      knod_map_obj->meta.ameta
				      .per_instance_size,
				      knod_map_obj->value_size,
				      "knod percpu array values live in a variable-sized GPU map tail");
	} else if (knod_bpf_map_type_hash(knod_map_obj->map_type)) {
		return knod_bpf_map_hash_lookup_elem(knod_map_obj, elems, key,
						     value);
	}

	return 0;
}

static int knod_bpf_map_visibility(struct knod_bpf_map *knod_map,
				   bool writeback)
{
	struct knod_bpf_priv *priv = knod_map->priv;
	struct knod_mem *mems[] = {
		knod_map->mem,
		knod_map->queue_mem,
		knod_map->hash_elems_mem,
		knod_map->gc_mem,
	};
	u64 begin = ktime_get_ns();
	u32 fence;
	int err;

	/* Before the first persistent-shader launch, no GPU can have cached or
	 * dirtied this map.  Kondor populates and may tear down thousands of map
	 * elements in that state; issuing a GL2 request for every element is both
	 * unnecessary and can overwhelm the interrupt handler on some SDMA 5.x
	 * parts.  Once a launch has occurred, retain maintenance even while the
	 * shader is stopped because GL2 may still contain data from that lifetime.
	 */
	if (!READ_ONCE(priv->knod->gda->launches))
		return 0;

	fence = knod_sdma_gl2_maintain(priv->knod, 0, mems,
					 ARRAY_SIZE(mems), writeback);
	if (!fence) {
		err = -EBUSY;
		goto fail;
	}
	err = knod_sdma_wait(priv->knod, 0, fence, USEC_PER_SEC);
	if (err)
		goto fail;

	if (writeback) {
		priv->map_visibility_before++;
		priv->map_visibility_before_ns += ktime_get_ns() - begin;
	} else {
		priv->map_visibility_after++;
		priv->map_visibility_after_ns += ktime_get_ns() - begin;
	}
	return 0;

fail:
	priv->map_visibility_failures++;
	priv->map_visibility_fault = true;
	pr_err_ratelimited("knod_bpf: map GL2 %s failed: %d; submissions remain paused\n",
			   writeback ? "writeback/invalidate" : "invalidate", err);
	return err;
}

/* Host map state changes with the engine's queues parked; see
 * knod_gda_pause().
 */
static int knod_bpf_pause(struct knod_bpf_priv *priv)
{
	return knod_gda_pause(priv->knod, KNOD_GDA_PAUSE_HOST_MAP);
}

static void knod_bpf_resume(struct knod_bpf_priv *priv,
			    bool advance_generation)
{
	knod_bpf_gpu_mem_fence(priv);
	priv->map_visibility_fault = false;
	if (advance_generation)
		priv->host_map_generation++;
	knod_gda_resume(priv->knod);
}

static void knod_bpf_leave_paused(struct knod_bpf_priv *priv)
{
	knod_gda_leave_paused(priv->knod);
}

static int knod_bpf_map_mutation_begin(struct knod_bpf_map *knod_map)
{
	int err;

	err = knod_bpf_pause(knod_map->priv);
	if (err)
		return err;
	err = knod_bpf_map_visibility(knod_map, true);
	if (err)
		knod_bpf_leave_paused(knod_map->priv);
	return err;
}

static int knod_bpf_map_mutation_end(struct knod_bpf_map *knod_map,
				     bool mutated)
{
	struct knod_bpf_priv *priv = knod_map->priv;
	int err;

	if (mutated)
		WRITE_ONCE(knod_map->snap_ok, false);

	/* Make CPU writes reach the BO before stale GL2 lines are discarded. */
	knod_bpf_gpu_mem_fence(priv);
	err = knod_bpf_map_visibility(knod_map, false);
	if (err) {
		knod_bpf_leave_paused(priv);
		return err;
	}
	knod_bpf_resume(priv, mutated);
	return 0;
}

static int __knod_bpf_map_update_elem(struct bpf_offloaded_map *offmap,
				      void *key, void *value, u64 flags)
{
	struct knod_bpf_map *knod_map = (struct knod_bpf_map *)offmap->dev_priv;
	struct knod_bpf_map_obj *knod_map_obj;
	struct knod_bpf_priv *priv;
	unsigned int idx = *(unsigned int *)key;
	struct knod_dev *knodev;
	void *bucket;
	u32 stride;
	int i, ret;

	if (!knod_map || !knod_map->mem || !knod_map->mem->kaddr)
		return -ENODEV;
	knod_map_obj = knod_map->knod_map_obj;
	priv = knod_map->priv;
	knodev = priv->knodev;
	/* As the kernel's array: every element is always there. */
	if (knod_map_obj->map_type == BPF_MAP_TYPE_ARRAY ||
	    knod_map_obj->map_type == BPF_MAP_TYPE_PERCPU_ARRAY) {
		if (flags > BPF_EXIST)
			return -EINVAL;
		if (idx >= knod_map_obj->max_entries)
			return -E2BIG;
		if (flags == BPF_NOEXIST)
			return -EEXIST;
	}
	if (knod_map_obj->map_type == BPF_MAP_TYPE_ARRAY) {
		ret = knod_bpf_map_mutation_begin(knod_map);
		if (ret)
			return ret;

		bucket = knod_bpf_array_value_ptr(knod_map_obj, idx);
		unsafe_memcpy(bucket, value, knod_map_obj->value_size,
			      "knod array values live in a variable-sized GPU map tail");
		return knod_bpf_map_mutation_end(knod_map, true);
	} else if (knod_map_obj->map_type == BPF_MAP_TYPE_PERCPU_ARRAY) {
		ret = knod_bpf_map_mutation_begin(knod_map);
		if (ret)
			return ret;
		stride = round_up(knod_map_obj->value_size, 8);
		bucket = &knod_map_obj->bucket[0];
		bucket += (idx * knod_map_obj->value_size);
		for (i = 0; i < knod_map_obj->meta.ameta.n_instances; i++)
			unsafe_memcpy(bucket + i *
				      knod_map_obj->meta.ameta
				      .per_instance_size,
				      value + i * stride,
				      knod_map_obj->value_size,
				      "knod percpu array values live in a variable-sized GPU map tail");
		return knod_bpf_map_mutation_end(knod_map, true);
	} else if (knod_bpf_map_type_hash(knod_map_obj->map_type)) {
		ret = -ENOENT;

		mutex_lock(&knodev->lock);
		list_for_each_entry(knod_map, &knodev->accel->xdp.bound_maps,
				    list) {
			if (knod_map->knod_map_obj == knod_map_obj) {
				mutex_unlock(&knodev->lock);
				ret = knod_bpf_map_mutation_begin(knod_map);
				if (ret)
					return ret;
				ret = knod_bpf_map_hash_update_elem(knod_map,
								    knod_map_obj,
								    key, value,
								    flags);
				if (knod_bpf_map_mutation_end(knod_map, !ret))
					return -EIO;
				return ret;
			}
		}
		mutex_unlock(&knodev->lock);
	}

	return -ENOENT;
}

static int __knod_bpf_map_delete_elem(struct bpf_offloaded_map *offmap,
				      void *key)
{
	struct knod_bpf_map *knod_map = (struct knod_bpf_map *)offmap->dev_priv;
	struct knod_bpf_map_obj *knod_map_obj;
	int ret;

	if (!knod_map || !knod_map->mem || !knod_map->mem->kaddr)
		return -ENODEV;
	knod_map_obj = knod_map->knod_map_obj;
	/* An array's elements cannot be deleted, as the kernel's. */
	if (knod_map_obj->map_type == BPF_MAP_TYPE_ARRAY ||
	    knod_map_obj->map_type == BPF_MAP_TYPE_PERCPU_ARRAY)
		return -EINVAL;
	else if (knod_bpf_map_type_hash(knod_map_obj->map_type)) {
		ret = knod_bpf_map_mutation_begin(knod_map);
		if (ret)
			return ret;
		ret = knod_bpf_map_hash_delete_elem(knod_map, knod_map_obj,
						    key);
		if (knod_bpf_map_mutation_end(knod_map, !ret))
			return -EIO;
		return ret;
	}

	return -ENOENT;
}

/* Return the elements the program deleted to the free queue.  The program
 * unlinked each from its chain under the bucket's lock before listing it;
 * with the queues parked, nobody is still on one.
 */
static unsigned int knod_bpf_map_gc_process(struct knod_bpf_map *knod_map)
{
	struct knod_bpf_map_obj *knod_map_obj = knod_map->knod_map_obj;
	unsigned int *gc_list = knod_map->gc_mem->kaddr;
	unsigned int *queue = knod_map->queue_mem->kaddr;
	void *elems = knod_map->hash_elems_mem->kaddr;
	unsigned int elem_size = knod_map_obj->meta.hmeta.elem_size;
	struct knod_bpf_hash_elem_obj *e;
	unsigned int gc_count, cur, i;

	gc_count = READ_ONCE(knod_map_obj->meta.hmeta.gc_count);
	if (!gc_count)
		return 0;

	cur = knod_map_obj->meta.hmeta.cur;
	for (i = 0; i < gc_count; i++) {
		e = elems + gc_list[i] * elem_size;
		e->next = KNOD_BPF_HASH_NEXT_END;
		e->lru = 0;
		knod_bpf_hash_free_value(knod_map_obj, e);
		queue[cur++] = gc_list[i];
	}
	knod_map_obj->meta.hmeta.cur = cur;

	WRITE_ONCE(knod_map_obj->meta.hmeta.gc_count, 0);
	return gc_count;
}

/*
 * Per-loop map maintenance, run from the engine's worker (outside any
 * rcu_read_lock_bh, since knod_free_mem() may sleep).  All bound_maps access
 * is serialized under knodev->lock -- the same lock map_alloc/map_free use:
 * GC live HASH maps, then reap maps that detach moved onto dead_maps.  The
 * caller holds the engine's op lock with the queues parked.
 */
#define KNOD_BPF_MAPS_TICK_INTERVAL (10 * HZ)

static bool knod_bpf_maps_may_need_maintenance(struct knod_bpf_priv *priv)
{
	struct knod_dev *knodev = priv->knodev;
	struct knod_bpf_map *knod_map;
	bool pending = false;

	priv->map_gc_checks++;
	mutex_lock(&knodev->lock);
	if (!list_empty(&priv->dead_maps)) {
		pending = true;
		goto out;
	}
	if (!READ_ONCE(priv->gpu_map_gc_possible))
		goto out;

	list_for_each_entry(knod_map, &knodev->accel->xdp.bound_maps, list) {
		if (knod_bpf_map_type_hash(knod_map->knod_map_obj->map_type)) {
			pending = true;
			break;
		}
	}
out:
	mutex_unlock(&knodev->lock);
	return pending;
}

static int knod_bpf_maps_visibility(struct knod_bpf_priv *priv,
				    bool writeback)
{
	struct knod_dev *knodev = priv->knodev;
	struct knod_bpf_map *knod_map;
	int err = 0;

	/* map_free only moves BOs to dead_maps. The tick is their sole freer,
	 * so both lists remain stable while it holds the engine's op lock.
	 */
	mutex_lock(&knodev->lock);
	list_for_each_entry(knod_map, &knodev->accel->xdp.bound_maps, list) {
		err = knod_bpf_map_visibility(knod_map, writeback);
		if (err)
			goto out;
	}
	list_for_each_entry(knod_map, &priv->dead_maps, list) {
		err = knod_bpf_map_visibility(knod_map, writeback);
		if (err)
			goto out;
	}
out:
	mutex_unlock(&knodev->lock);
	return err;
}

static void knod_bpf_maps_tick(struct knod_bpf_priv *priv)
{
	struct knod_dev *knodev = priv->knodev;
	struct knod_bpf_map *knod_map, *tmp;
	LIST_HEAD(reap);

	mutex_lock(&knodev->lock);
	list_for_each_entry(knod_map, &knodev->accel->xdp.bound_maps, list) {
		if (knod_bpf_map_type_hash(knod_map->knod_map_obj->map_type))
			priv->map_gc_elements +=
				knod_bpf_map_gc_process(knod_map);
	}
	list_splice_init(&priv->dead_maps, &reap);
	/* A later map_free republishes its request under this same lock. */
	WRITE_ONCE(priv->maps_gc_pending, false);
	mutex_unlock(&knodev->lock);

	list_for_each_entry_safe(knod_map, tmp, &reap, list) {
		knod_bpf_map_log(knod_map, "free");
		if (knod_map->snap)
			knod_free_mem(priv->knod, knod_map->snap);
		if (knod_map->snap_elems)
			knod_free_mem(priv->knod, knod_map->snap_elems);
		if (knod_map->gc_mem)
			knod_free_mem(priv->knod, knod_map->gc_mem);
		if (knod_map->queue_mem)
			knod_free_mem(priv->knod, knod_map->queue_mem);
		if (knod_map->hash_elems_mem)
			knod_free_mem(priv->knod, knod_map->hash_elems_mem);
		if (knod_map->mem)
			knod_free_mem(priv->knod, knod_map->mem);
		kfree(knod_map);
		priv->map_gc_maps++;
	}
}

/* From the engine's worker, every loop: the maps' maintenance. */
static void knod_bpf_tick(void *ctx)
{
	struct knod_bpf_priv *priv = ctx;
	struct knod *knod = priv->knod;
	u64 old_elements, old_maps;

	if (time_after_eq(jiffies, priv->maps_tick_at)) {
		priv->maps_tick_at = jiffies + KNOD_BPF_MAPS_TICK_INTERVAL;
		if (knod_bpf_maps_may_need_maintenance(priv))
			WRITE_ONCE(priv->maps_gc_pending, true);
	}

	/* Reclaim map elements with the queues parked, and exclude host map
	 * mutations while processing their free lists.
	 */
	if (!READ_ONCE(priv->maps_gc_pending) ||
	    time_before(jiffies, priv->maps_retry_at) ||
	    !knod_gda_op_trylock(knod))
		return;
	old_elements = priv->map_gc_elements;
	old_maps = priv->map_gc_maps;
	/* Park them, or leave the free lists for another time. */
	if (knod_gda_park(knod)) {
		knod_gda_op_unlock(knod);
		return;
	}
	pr_debug("knod_bpf: maps tick: %s, %s, %s, %s\n",
		knod->gda->code_is_default ? "receive kernel" : "program",
		knod->gda->running ? "running" : "stopped",
		knod->gda->park_value ? "parked" : "not parked",
		READ_ONCE(priv->gpu_map_gc_possible) ? "live gc" : "dead only");
	if (!knod_bpf_maps_visibility(priv, true)) {
		knod_bpf_maps_tick(priv);
		knod_bpf_gpu_mem_fence(priv);
		if (!knod_bpf_maps_visibility(priv, false)) {
			if (old_elements != priv->map_gc_elements ||
			    old_maps != priv->map_gc_maps)
				priv->host_map_generation++;
			priv->map_visibility_fault = false;
		} else {
			WRITE_ONCE(priv->maps_gc_pending, true);
			priv->maps_retry_at = jiffies + HZ / 10;
		}
	} else {
		/* Not every loop: a failure that holds would take the worker
		 * and the log with it.
		 */
		priv->maps_retry_at = jiffies + HZ / 10;
	}
	knod_gda_unpark(knod);
	knod_gda_op_unlock(knod);
}

static const struct knod_gda_client knod_bpf_gda_client = {
	.tick = knod_bpf_tick,
};

static void knod_priv_exit(struct knod_bpf_priv *priv)
{
	struct knod_dev *knodev = priv->knodev;
	struct knod_bpf_map *knod_map, *tmp;
	LIST_HEAD(reap);

	/* No tick runs once this returns, nor any program of ours. */
	knod_gda_set_client(priv->knod, NULL, NULL);
	if (!priv->knod->gda->code_is_default)
		knod_bpf_reload_pass(knodev);

	/*
	 * Serialize under knodev->lock and splice both lists to a local one:
	 * whichever side splices first frees them, the other sees them empty.
	 * Free outside the lock since knod_free_mem() may sleep.
	 */
	mutex_lock(&knodev->lock);
	list_splice_init(&knodev->accel->xdp.bound_maps, &reap);
	list_splice_init(&priv->dead_maps, &reap);
	mutex_unlock(&knodev->lock);

	list_for_each_entry_safe(knod_map, tmp, &reap, list) {
		knod_bpf_map_log(knod_map, "free");
		if (knod_map->snap)
			knod_free_mem(priv->knod, knod_map->snap);
		if (knod_map->snap_elems)
			knod_free_mem(priv->knod, knod_map->snap_elems);
		if (knod_map->gc_mem)
			knod_free_mem(priv->knod, knod_map->gc_mem);
		if (knod_map->queue_mem)
			knod_free_mem(priv->knod, knod_map->queue_mem);
		if (knod_map->hash_elems_mem)
			knod_free_mem(priv->knod, knod_map->hash_elems_mem);
		if (knod_map->mem)
			knod_free_mem(priv->knod, knod_map->mem);
		kfree(knod_map);
	}

	kfree(priv->prog_buf);
	priv->prog_buf = NULL;
	priv->lds_bytes = 0;
	priv->prog = NULL;
}

static int knod_priv_init(struct knod_bpf_priv *priv)
{
	struct knod_gda *gda = priv->knod->gda;

	priv->prog = NULL;
	INIT_LIST_HEAD(&priv->dead_maps);
	priv->maps_tick_at = jiffies + KNOD_BPF_MAPS_TICK_INTERVAL;
	priv->maps_gc_pending = false;
	/* The engine's geometry is what a program is built for. */
	priv->nr_works = gda->nr_queues;
	priv->wg_size = gda->wg_size;
	priv->prog_buf = kzalloc(KNOD_BPF_PROG_BUF_SIZE, GFP_KERNEL);
	if (!priv->prog_buf)
		return -ENOMEM;
	knod_gda_set_client(priv->knod, &knod_bpf_gda_client, priv);
	return 0;
}

static struct knod_bpf_priv *__knod_accel_xdp_init(struct knod_accel *accel,
						   struct knod_dev *knodev)
{
	struct knod *knod = (struct knod *)knodev->accel->priv;
	struct knod_blob_callee callee;
	struct knod_bpf_priv *priv;
	int err;

	priv = kzalloc_obj(struct knod_bpf_priv, GFP_KERNEL);
	if (!priv)
		return ERR_PTR(-ENOMEM);
	mutex_init(&priv->snap_lock);
	priv->map_snap_ms = 100;

	/* Every routine a program calls comes from the blob, so a missing or
	 * ABI-mismatched blob fails the attach rather than deferring to a
	 * program that then cannot be built.
	 */
	err = knod_blob_load(knod, &priv->blob, "bpf-persistent");
	if (err) {
		kfree(priv);
		return ERR_PTR(err);
	}
	priv->ordered_engine.code =
		knod_blob_find_call(&priv->blob, KNOD_BLOB_GDA_ENGINE_ORDERED, 0,
				    &priv->ordered_engine.size, &callee);
	priv->ordered_engine.call = callee.patch;
	priv->ordered_engine.lds_bytes = KNOD_PERSIST_GDA_ORDER_LDS_BYTES;
	priv->gate_code = knod_blob_find(&priv->blob, KNOD_BLOB_GDA_GATE, 0,
					 &priv->gate_size);
	if (!priv->ordered_engine.code || !priv->ordered_engine.call ||
	    !priv->gate_code) {
		pr_warn("knod_bpf: blob has no ordered engine\n");
		knod_blob_free(&priv->blob);
		kfree(priv);
		return ERR_PTR(-EINVAL);
	}

	INIT_LIST_HEAD(&priv->list);
	err = -EOPNOTSUPP;
	if (knod->isa_version != 10 && knod->isa_version != 11) {
		pr_warn("knod_bpf: gfx%d has no persistent shader\n",
			knod->isa_version);
		goto err_blob;
	}

	INIT_LIST_HEAD(&accel->xdp.bound_maps);
	accel->flags |= KNOD_FLAGS_XDP;
	accel->xdp.priv = priv;
	list_add(&priv->list, &priv_list);

	priv->knod = knod;
	priv->accel = accel;
	priv->knodev = knodev;
	priv->dev = knodev->netdev;

	priv->isa_version = knod->isa_version;

	/*
	 * Only permanent per-attach state is set up here; what programs need
	 * (knod_priv_init) is set up by ->activate() when the BPF feature is
	 * selected, on the engine the core already runs.
	 */

	return priv;

err_blob:
	knod_blob_free(&priv->blob);
	kfree(priv);
	return ERR_PTR(err);
}

/* Feature select: allocate the BPF GPU compute resources. */
static int knod_bpf_activate(struct knod_dev *knodev)
{
	struct knod_accel *accel = knodev->accel;
	struct knod_bpf_priv *priv = accel->xdp.priv;
	int err;

	/* Init refused this accel at attach (blob); it said why.  And no
	 * engine to run a program in.
	 */
	if (!priv || !priv->knod->gda)
		return -ENODEV;

	/*
	 * Past gfx11 the emitters would warn and drop every instruction
	 * while the kernel descriptor went out unwritten, so the dispatch
	 * would run whatever was in that VRAM.  Refuse rather than hang.
	 */
	if (priv->isa_version != 10 && priv->isa_version != 11) {
		pr_warn("knod_bpf: persistent-shader XDP offload needs gfx10/11, this GPU is gfx%d\n",
			priv->isa_version);
		return -EOPNOTSUPP;
	}

	/*
	 * Pin the module while BPF is the selected feature: the core calls
	 * into these ops, so it must not be unloaded until feature->none.
	 * (No-op when built in - THIS_MODULE is NULL.)
	 */
	if (!try_module_get(THIS_MODULE))
		return -ENODEV;

	err = knod_priv_init(priv);
	if (err) {
		module_put(THIS_MODULE);
		return err;
	}
	return 0;
}

/* Feature deselect: free the BPF GPU compute resources. */
static void knod_bpf_deactivate(struct knod_dev *knodev)
{
	struct knod_bpf_priv *priv = knodev->accel->xdp.priv;

	knod_priv_exit(priv);
	module_put(THIS_MODULE);
}

/* True while a user XDP prog or offloaded map is still bound to this accel. */
static bool knod_bpf_busy(struct knod_dev *knodev)
{
	struct knod_accel *accel = knodev->accel;
	struct knod_bpf_priv *priv = accel->xdp.priv;

	if (!priv)
		return false;
	return READ_ONCE(priv->prog) || !list_empty(&accel->xdp.bound_maps);
}

static void __knod_accel_xdp_exit(struct knod_accel *accel,
				  struct knod_bpf_priv *priv)
{
	/* GPU compute buffers are freed by ->deactivate(); free the rest. */
	memset(&accel->xdp, 0, sizeof(struct knod_accel_xdp));
	accel->flags &= ~KNOD_FLAGS_XDP;
	list_del(&priv->list);
	knod_blob_free(&priv->blob);
	kfree(priv);
}

/*
 * The copy of @insn_idx the verifier is in: it checks a function every time
 * a call reaches it, with the state that call brings, and the call sites on
 * its stack of frames say which call that is.  NULL for a function the
 * verifier checks on its own, a global one, which no call's copy follows.
 */
static struct knod_insn_meta *knod_bpf_insn_meta(struct knod_prog *knod_prog,
						 struct bpf_verifier_env *env,
						 int insn_idx)
{
	struct bpf_verifier_state *st = env->cur_state;
	const struct knod_subprog_inst *inst;
	int id = 0, f, c;

	for (f = 1; f <= st->curframe; f++) {
		for (c = 1; c < knod_prog->n_insts; c++)
			if (knod_prog->insts[c].parent == id &&
			    knod_prog->insts[c].call == st->frame[f]->callsite)
				break;
		if (c == knod_prog->n_insts)
			return NULL;
		id = c;
	}
	inst = &knod_prog->insts[id];
	if (insn_idx < inst->start || insn_idx >= inst->end)
		return NULL;
	return knod_prog->flat_meta[inst->flat[insn_idx - inst->start]];
}

/* A stack offset off @meta's own r10, as it reads until frames are placed. */
static int knod_bpf_vfp(const struct knod_insn_meta *meta)
{
	return -meta->frame * KNOD_STACK_VSTRIDE;
}

static int knod_bpf_check_stack_access(struct knod_prog *knod_prog,
				       struct knod_insn_meta *meta,
				       const struct bpf_reg_state *reg,
				       struct bpf_verifier_env *env)
{
	s32 old_off, new_off;

	if (!tnum_is_const(reg->var_off)) {
		knod_jit_dbg(" variable ptr stack access\n");
		return -EINVAL;
	}

	if (meta->ptr.type == NOT_INIT)
		return 0;

	old_off = meta->ptr.var_off.value;
	new_off = reg->var_off.value;

	meta->ptr_not_const |= old_off != new_off;

	if (!meta->ptr_not_const)
		return 0;

	if (old_off % 4 == new_off % 4)
		return 0;

	knod_jit_dbg(" stack access changed location was:%d is:%d\n",
		old_off, new_off);
	return -EINVAL;
}

static struct knod_insn_meta *
knod_bpf_lookup_prev_meta_by_dreg(struct knod_prog *knod_prog,
				  struct knod_insn_meta *meta,
				  int dreg_id)
{
	list_for_each_entry_continue_reverse(meta, &knod_prog->insns, l) {
		/* Back past a call that kept it: it is the caller's again. */
		if ((meta->flags & FLAG_INSN_SUBPROG_RET) &&
		    (meta->sub_saves & BIT(dreg_id))) {
			meta = meta->sub_call;
			continue;
		}
		if (!is_mbpf_alu(meta) &&
		    !is_mbpf_ldx(meta) &&
		    !is_mbpf_store(meta))
			continue;
		if (meta->insn.dst_reg == dreg_id)
			return meta;
	}

	return NULL;
}

static int knod_bpf_check_ptr(struct knod_prog *knod_prog,
			      struct knod_insn_meta *meta,
			      struct bpf_verifier_env *env, u8 reg_no)
{
	const struct bpf_reg_state *reg = cur_regs(env) + reg_no;
	int err;

	if (reg->type != PTR_TO_CTX &&
	    reg->type != PTR_TO_STACK &&
	    reg->type != PTR_TO_MAP_VALUE &&
	    reg->type != PTR_TO_PACKET) {
		knod_jit_dbg(" unsupported ptr type: %d\n", reg->type);
		return -EINVAL;
	}

	if (reg->type == PTR_TO_STACK) {
		err = knod_bpf_check_stack_access(knod_prog, meta, reg, env);
		if (err)
			return err;
	}

	if (meta->ptr.type != NOT_INIT && meta->ptr.type != reg->type) {
		knod_jit_dbg(" ptr type changed for instruction %d -> %d\n",
			meta->ptr.type,
			reg->type);
		return -EINVAL;
	}

	meta->ptr = *reg;

	return 0;
}

static int knod_bpf_update_ptr_off(struct knod_prog *knod_prog,
				   struct knod_insn_meta *meta,
				   struct bpf_verifier_env *env)
{
	struct knod_bpf_reg_state *sreg = &meta->sreg;
	struct knod_bpf_reg_state *dreg = &meta->dreg;
	struct knod_insn_meta *prev_meta;

	if (is_mbpf_ldx(meta) && meta->insn.src_reg == BPF_REG_FP) {
		sreg->stack_off = knod_bpf_vfp(meta);
	} else if (is_mbpf_store(meta) && meta->insn.dst_reg == BPF_REG_FP) {
		dreg->stack_off = knod_bpf_vfp(meta);
	} else if (is_mbpf_ldx(meta)) {
		if (sreg->reg.type == PTR_TO_PACKET ||
		    sreg->reg.type == PTR_TO_STACK) {
			prev_meta = knod_bpf_lookup_prev_meta_by_dreg(
				knod_prog, meta, meta->insn.src_reg);
			if (!prev_meta) {
				knod_jit_dbg(" Invalid\n");
				return -EINVAL;
			}
			if (sreg->reg.type == PTR_TO_PACKET)
				sreg->packet_off = prev_meta->dreg.packet_off;
			else
				sreg->stack_off = prev_meta->dreg.stack_off;
		}
	} else if (is_mbpf_store(meta)) {
		if (dreg->reg.type == PTR_TO_PACKET ||
		    dreg->reg.type == PTR_TO_STACK) {
			prev_meta = knod_bpf_lookup_prev_meta_by_dreg(
				knod_prog, meta, meta->insn.dst_reg);
			if (!prev_meta) {
				knod_jit_dbg(" Invalid\n");
				return -EINVAL;
			}
			if (dreg->reg.type == PTR_TO_PACKET)
				dreg->packet_off = prev_meta->dreg.packet_off;
			else
				dreg->stack_off = prev_meta->dreg.stack_off;
		}
	}

	return 0;
}

/* A percpu value has one instance per queue, and a queue is one workgroup: 256
 * lanes reach what a CPU reaches alone.
 *
 * Assigning to it is still right - the memory system picks a winner, which is
 * what the last write on a CPU comes to as well.  Reading it, adding to it and
 * writing that back is not: all 256 read the same value and all but one result
 * is thrown away.  On a CPU that sequence needs no atomic, so it is exactly
 * what a program written for one will do.
 *
 * Where it is an add, the three instructions become one atomic: the load turns
 * into an atomic add that hands back what was there before, the add works on
 * that as it always did, and the store has nothing left to do.  The register
 * ends up holding the same value it would have on a CPU, so nothing downstream
 * has to know.
 *
 * Anything else that reads and writes back is turned away, rather than left to
 * run and report a number that is quietly too small.  So is an add whose
 * amount is not settled by the time the load happens, since that is where the
 * atomic now goes.  Only the shape a compiler emits for += and ++ is matched -
 * a longer chain between the load and the store will get through, which is
 * worth knowing when a count still looks low.
 */
/* Whether a stack slot holds something every lane agrees on.
 *
 * A store of a literal does; a store of a register does when the verifier has
 * proved the register could only be one value.  Anything else is treated as
 * differing per lane, which is never wrong here, only slower.
 */
static bool knod_bpf_stack_is_const(struct knod_prog *knod_prog,
				    struct knod_insn_meta *meta, int stack_off)
{
	struct knod_insn_meta *m = meta;

	list_for_each_entry_continue_reverse(m, &knod_prog->insns, l) {
		if (!is_mbpf_store(m) && mbpf_class(m) != BPF_ST)
			continue;
		if (m->dreg.stack_off + m->insn.off != stack_off)
			continue;
		if (mbpf_class(m) == BPF_ST)
			return true;
		return tnum_is_const(m->sreg.reg.var_off);
	}
	return false;
}

/* Whether every lane of a wave reaches the same element of a percpu map, which
 * is what lets the wave send one atomic between them.
 *
 * The instance is picked by the queue and a workgroup is one queue, so what is
 * left to differ is the key.  A key the program wrote as a constant is the same
 * in every lane; one it worked out from the packet is not.
 *
 * Only the plainest shape is taken: the value pointer is still in r0, and the
 * lookup that put it there was handed a constant.  Anything else falls back to
 * an atomic per lane.
 */
static bool knod_bpf_percpu_addr_uniform(struct knod_prog *knod_prog,
					 struct knod_insn_meta *meta)
{
	struct knod_insn_meta *m = meta;

	if (meta->insn.dst_reg != BPF_REG_0)
		return false;

	list_for_each_entry_continue_reverse(m, &knod_prog->insns, l) {
		if (is_mbpf_map_call(m))
			return knod_bpf_stack_is_const(knod_prog, m,
						       m->kreg.stack_off);
		/* Anything else that lands in r0 breaks the trail. */
		if (mbpf_class(m) == BPF_JMP && BPF_OP(m->insn.code) == BPF_CALL)
			return false;
		if ((is_mbpf_alu(m) || is_mbpf_load(m)) &&
		    m->insn.dst_reg == BPF_REG_0)
			return false;
	}
	return false;
}

/* Whether @load reads the same place @store writes. */
static bool knod_bpf_same_place(const struct knod_insn_meta *load,
				const struct knod_insn_meta *store)
{
	return load && is_mbpf_load(load) &&
	       load->insn.src_reg == store->insn.dst_reg &&
	       load->insn.off == store->insn.off;
}

static int knod_bpf_check_percpu_store(struct knod_prog *knod_prog,
				       struct knod_insn_meta *meta)
{
	struct knod_insn_meta *alu, *load;
	const char *why;

	alu = knod_bpf_lookup_prev_meta_by_dreg(knod_prog, meta,
						meta->insn.src_reg);
	if (!alu || !is_mbpf_alu(alu))
		return 0;

	/* An add takes its operands either way round, and a compiler will use
	 * both: what came out of the map can be what the add starts from, or
	 * what it adds on.  Only the first was looked for, so the second went
	 * out as a plain load and store and lost all but one lane of it.
	 */
	load = knod_bpf_lookup_prev_meta_by_dreg(knod_prog, alu,
						 alu->insn.dst_reg);
	if (!knod_bpf_same_place(load, meta)) {
		load = knod_bpf_lookup_prev_meta_by_dreg(knod_prog, alu,
							 alu->insn.src_reg);
		if (!knod_bpf_same_place(load, meta))
			return 0;
		meta->percpu_rmw_swapped = true;
	}

	if (BPF_OP(alu->insn.code) != BPF_ADD) {
		why = "only an add has an atomic form here; write it with __sync_fetch_and_add()";
		goto reject;
	}

	/* There is no atomic narrower than a dword. */
	if (BPF_SIZE(meta->insn.code) != BPF_W &&
	    BPF_SIZE(meta->insn.code) != BPF_DW) {
		why = "no atomic is narrower than a dword; widen the value to __u32";
		goto reject;
	}
	meta->percpu_rmw_add = alu;
	meta->percpu_rmw_uniform =
		knod_bpf_percpu_addr_uniform(knod_prog, meta);
	return 0;

reject:
	pr_warn("knod_bpf: percpu value at +%d is read and written back (bpf insn %d) where a workgroup's lanes would do it at once and lose all but one: %s\n",
		meta->insn.off, meta->bpf_insn_idx, why);
	return -EOPNOTSUPP;
}

static int knod_bpf_check_store(struct knod_prog *knod_prog,
				struct knod_insn_meta *meta,
				struct bpf_verifier_env *env)
{
	const struct bpf_reg_state *reg = cur_regs(env) + meta->insn.dst_reg;

	if (reg->type == PTR_TO_CTX) {
		if (knod_prog->type == BPF_PROG_TYPE_XDP) {
			/* XDP ctx accesses must be 4B in size */
			switch (meta->insn.off) {
			case offsetof(struct xdp_md, rx_queue_index):
				knod_jit_dbg(" queue selection not supported by FW\n");
				return -EOPNOTSUPP;
			}
		}
		knod_jit_dbg(" unsupported store to context field\n");
		return -EOPNOTSUPP;
	}

	if (reg->type == PTR_TO_MAP_VALUE && reg->map_ptr &&
	    (reg->map_ptr->map_type == BPF_MAP_TYPE_PERCPU_ARRAY ||
	     knod_bpf_map_type_percpu_hash(reg->map_ptr->map_type))) {
		int err = knod_bpf_check_percpu_store(knod_prog, meta);

		if (err)
			return err;
	}

	return knod_bpf_check_ptr(knod_prog, meta, env, meta->insn.dst_reg);
}

/* NOTE:
 * knod_bpf_lookup_prev_meta_by_dreg(), src_reg vs dst_reg ???????/
 */
static int knod_bpf_check_alu(struct knod_prog *knod_prog,
			      struct knod_insn_meta *meta,
			      struct bpf_verifier_env *env)
{
	const struct bpf_reg_state *sreg = cur_regs(env) + meta->insn.src_reg;
	const struct bpf_reg_state *dreg = cur_regs(env) + meta->insn.dst_reg;
	struct knod_bpf_reg_state *ksreg = &meta->sreg;
	struct knod_bpf_reg_state *kdreg = &meta->dreg;
	struct knod_insn_meta *prev_meta;
	int imm;

	/* A move copies a stack pointer whole, so its offset is wherever the
	 * source was last set - the frame pointer itself is offset zero.  Keyed
	 * on the source: the hook sees the state before the move, when the
	 * destination is not a pointer yet and the block below is skipped.
	 */
	if ((meta->insn.code == (BPF_ALU | BPF_MOV | BPF_X) ||
	     meta->insn.code == (BPF_ALU64 | BPF_MOV | BPF_X)) &&
	    sreg->type == PTR_TO_STACK) {
		if (meta->insn.src_reg == BPF_REG_FP) {
			kdreg->stack_off = knod_bpf_vfp(meta);
		} else {
			prev_meta = knod_bpf_lookup_prev_meta_by_dreg(
				knod_prog, meta, meta->insn.src_reg);
			if (!prev_meta) {
				knod_jit_dbg(" Invalid\n");
				return -EINVAL;
			}
			kdreg->stack_off = prev_meta->dreg.stack_off;
		}
	}

	if (dreg->type == PTR_TO_STACK) {
		imm = meta->insn.imm;

		switch (meta->insn.code) {
		/* ALU
		 * If a destination register contains a pointer of STACK,
		 * offset should not be minus.
		 */
		case BPF_ALU | BPF_MOV | BPF_X:
		case BPF_ALU64 | BPF_MOV | BPF_X:
			break;
		case BPF_ALU | BPF_MOV | BPF_K:
		case BPF_ALU64 | BPF_MOV | BPF_K:
			kdreg->stack_off = ksreg->stack_off;
			break;
		case BPF_ALU | BPF_XOR | BPF_X:
		case BPF_ALU64 | BPF_XOR | BPF_X:
			knod_jit_dbg(" PTR_TO_STACK with BPF_X is not supported\n");
			return -EINVAL;
		case BPF_ALU | BPF_XOR | BPF_K:
		case BPF_ALU64 | BPF_XOR | BPF_K:
			prev_meta = knod_bpf_lookup_prev_meta_by_dreg(
				knod_prog, meta, meta->insn.dst_reg);
			if (!prev_meta) {
				knod_jit_dbg(" Invalid\n");
				return -EINVAL;
			}
			kdreg->stack_off = prev_meta->dreg.stack_off ^ imm;
			break;
		case BPF_ALU | BPF_MOD | BPF_X:
		case BPF_ALU64 | BPF_MOD | BPF_X:
			knod_jit_dbg(" PTR_TO_STACK with BPF_X is not supported\n");
			return -EINVAL;
		case BPF_ALU | BPF_MOD | BPF_K:
		case BPF_ALU64 | BPF_MOD | BPF_K:
			prev_meta = knod_bpf_lookup_prev_meta_by_dreg(
				knod_prog, meta, meta->insn.dst_reg);
			if (!prev_meta) {
				knod_jit_dbg(" Invalid\n");
				return -EINVAL;
			}
			kdreg->stack_off = prev_meta->dreg.stack_off % imm;
			break;
		case BPF_ALU | BPF_AND | BPF_X:
		case BPF_ALU64 | BPF_AND | BPF_X:
			knod_jit_dbg(" PTR_TO_STACK with BPF_X is not supported\n");
			return -EINVAL;
		case BPF_ALU | BPF_AND | BPF_K:
		case BPF_ALU64 | BPF_AND | BPF_K:
			prev_meta = knod_bpf_lookup_prev_meta_by_dreg(
				knod_prog, meta, meta->insn.dst_reg);
			if (!prev_meta) {
				knod_jit_dbg(" Invalid\n");
				return -EINVAL;
			}
			kdreg->stack_off = prev_meta->dreg.stack_off & imm;
			break;
		case BPF_ALU | BPF_OR | BPF_X:
		case BPF_ALU64 | BPF_OR | BPF_X:
			knod_jit_dbg(" PTR_TO_STACK with BPF_X is not supported\n");
			return -EINVAL;
		case BPF_ALU | BPF_OR | BPF_K:
		case BPF_ALU64 | BPF_OR | BPF_K:
			prev_meta = knod_bpf_lookup_prev_meta_by_dreg(
				knod_prog, meta, meta->insn.dst_reg);
			if (!prev_meta) {
				knod_jit_dbg(" Invalid\n");
				return -EINVAL;
			}
			kdreg->stack_off = prev_meta->dreg.stack_off | imm;
			break;
		case BPF_ALU | BPF_ADD | BPF_X:
		case BPF_ALU64 | BPF_ADD | BPF_X:
			knod_jit_dbg(" PTR_TO_STACK with BPF_X is not supported\n");
			return -EINVAL;
		case BPF_ALU | BPF_ADD | BPF_K:
		case BPF_ALU64 | BPF_ADD | BPF_K:
			prev_meta = knod_bpf_lookup_prev_meta_by_dreg(
				knod_prog, meta, meta->insn.dst_reg);
			if (!prev_meta) {
				knod_jit_dbg(" Invalid\n");
				return -EINVAL;
			}
			kdreg->stack_off = prev_meta->dreg.stack_off + imm;
			break;
		case BPF_ALU | BPF_SUB | BPF_X:
		case BPF_ALU64 | BPF_SUB | BPF_X:
			knod_jit_dbg(" PTR_TO_STACK with BPF_X is not supported\n");
			return -EINVAL;
		case BPF_ALU | BPF_SUB | BPF_K:
		case BPF_ALU64 | BPF_SUB | BPF_K:
			prev_meta = knod_bpf_lookup_prev_meta_by_dreg(
				knod_prog, meta, meta->insn.dst_reg);
			if (!prev_meta) {
				knod_jit_dbg(" Invalid\n");
				return -EINVAL;
			}
			kdreg->stack_off = prev_meta->dreg.stack_off - imm;
			break;
		case BPF_ALU | BPF_MUL | BPF_X:
		case BPF_ALU64 | BPF_MUL | BPF_X:
			knod_jit_dbg(" PTR_TO_STACK with BPF_X is not supported\n");
			return -EINVAL;
		case BPF_ALU | BPF_MUL | BPF_K:
		case BPF_ALU64 | BPF_MUL | BPF_K:
			prev_meta = knod_bpf_lookup_prev_meta_by_dreg(
				knod_prog, meta, meta->insn.dst_reg);
			if (!prev_meta) {
				knod_jit_dbg(" Invalid\n");
				return -EINVAL;
			}
			kdreg->stack_off = prev_meta->dreg.stack_off * imm;
			break;
		case BPF_ALU | BPF_DIV | BPF_X:
		case BPF_ALU64 | BPF_DIV | BPF_X:
			knod_jit_dbg(" PTR_TO_STACK with BPF_X is not supported\n");
			return -EINVAL;
		case BPF_ALU | BPF_DIV | BPF_K:
		case BPF_ALU64 | BPF_DIV | BPF_K:
			prev_meta = knod_bpf_lookup_prev_meta_by_dreg(
				knod_prog, meta, meta->insn.dst_reg);
			if (!prev_meta) {
				knod_jit_dbg(" Invalid\n");
				return -EINVAL;
			}
			kdreg->stack_off = prev_meta->dreg.stack_off / imm;
			break;
		case BPF_ALU | BPF_NEG:
		case BPF_ALU64 | BPF_NEG:
			break;
		case BPF_ALU | BPF_LSH | BPF_X:
		case BPF_ALU64 | BPF_LSH | BPF_X:
			knod_jit_dbg(" PTR_TO_STACK with BPF_X is not supported\n");
			return -EINVAL;
		case BPF_ALU | BPF_LSH | BPF_K:
		case BPF_ALU64 | BPF_LSH | BPF_K:
			prev_meta = knod_bpf_lookup_prev_meta_by_dreg(
				knod_prog, meta, meta->insn.dst_reg);
			if (!prev_meta) {
				knod_jit_dbg(" Invalid\n");
				return -EINVAL;
			}
			kdreg->stack_off = prev_meta->dreg.stack_off << imm;
			break;
		case BPF_ALU | BPF_RSH | BPF_X:
		case BPF_ALU64 | BPF_RSH | BPF_X:
			knod_jit_dbg(" PTR_TO_STACK with BPF_X is not supported\n");
			return -EINVAL;
		case BPF_ALU | BPF_RSH | BPF_K:
		case BPF_ALU64 | BPF_RSH | BPF_K:
			prev_meta = knod_bpf_lookup_prev_meta_by_dreg(
				knod_prog, meta, meta->insn.dst_reg);
			if (!prev_meta) {
				knod_jit_dbg(" Invalid\n");
				return -EINVAL;
			}
			kdreg->stack_off = prev_meta->dreg.stack_off >> imm;
			break;
		case BPF_ALU | BPF_ARSH | BPF_X:
		case BPF_ALU64 | BPF_ARSH | BPF_X:
			knod_jit_dbg(" PTR_TO_STACK with BPF_X is not supported\n");
			return -EINVAL;
		case BPF_ALU | BPF_ARSH | BPF_K:
		case BPF_ALU64 | BPF_ARSH | BPF_K:
			prev_meta = knod_bpf_lookup_prev_meta_by_dreg(
				knod_prog, meta, meta->insn.dst_reg);
			if (!prev_meta) {
				knod_jit_dbg(" Invalid\n");
				return -EINVAL;
			}
			kdreg->stack_off = prev_meta->dreg.stack_off >> imm;
			break;
		}
		knod_jit_dbg(" %d: dreg->stack_off = %d\n", meta->bpf_insn_idx,
			kdreg->stack_off);
	}

	if (dreg->type == PTR_TO_PACKET) {
		imm = meta->insn.imm;

		switch (meta->insn.code) {
		/* ALU
		 * If a destination register contains a pointer of STACK,
		 * offset should not be minus.
		 */
		case BPF_ALU | BPF_MOV | BPF_X:
		case BPF_ALU64 | BPF_MOV | BPF_X:
			kdreg->packet_off = ksreg->packet_off;
			break;
		case BPF_ALU | BPF_MOV | BPF_K:
		case BPF_ALU64 | BPF_MOV | BPF_K:
			kdreg->packet_off = ksreg->packet_off;
			break;
		case BPF_ALU | BPF_XOR | BPF_X:
		case BPF_ALU64 | BPF_XOR | BPF_X:
			knod_jit_dbg(" PTR_TO_STACK with BPF_X is not supported\n");
			return -EINVAL;
		case BPF_ALU | BPF_XOR | BPF_K:
		case BPF_ALU64 | BPF_XOR | BPF_K:
			prev_meta = knod_bpf_lookup_prev_meta_by_dreg(
				knod_prog, meta, meta->insn.dst_reg);
			if (!prev_meta) {
				knod_jit_dbg(" Invalid\n");
				return -EINVAL;
			}
			kdreg->packet_off = prev_meta->dreg.packet_off ^ imm;
			break;
		case BPF_ALU | BPF_MOD | BPF_X:
		case BPF_ALU64 | BPF_MOD | BPF_X:
			knod_jit_dbg(" PTR_TO_STACK with BPF_X is not supported\n");
			return -EINVAL;
		case BPF_ALU | BPF_MOD | BPF_K:
		case BPF_ALU64 | BPF_MOD | BPF_K:
			prev_meta = knod_bpf_lookup_prev_meta_by_dreg(
				knod_prog, meta, meta->insn.dst_reg);
			if (!prev_meta) {
				knod_jit_dbg(" Invalid\n");
				return -EINVAL;
			}
			kdreg->packet_off = prev_meta->dreg.packet_off % imm;
			break;
		case BPF_ALU | BPF_AND | BPF_X:
		case BPF_ALU64 | BPF_AND | BPF_X:
			knod_jit_dbg(" PTR_TO_STACK with BPF_X is not supported\n");
			return -EINVAL;
		case BPF_ALU | BPF_AND | BPF_K:
		case BPF_ALU64 | BPF_AND | BPF_K:
			prev_meta = knod_bpf_lookup_prev_meta_by_dreg(
				knod_prog, meta, meta->insn.dst_reg);
			if (!prev_meta) {
				knod_jit_dbg(" Invalid\n");
				return -EINVAL;
			}
			kdreg->packet_off = prev_meta->dreg.packet_off & imm;
			break;
		case BPF_ALU | BPF_OR | BPF_X:
		case BPF_ALU64 | BPF_OR | BPF_X:
			knod_jit_dbg(" PTR_TO_STACK with BPF_X is not supported\n");
			return -EINVAL;
		case BPF_ALU | BPF_OR | BPF_K:
		case BPF_ALU64 | BPF_OR | BPF_K:
			prev_meta = knod_bpf_lookup_prev_meta_by_dreg(
				knod_prog, meta, meta->insn.dst_reg);
			if (!prev_meta) {
				knod_jit_dbg(" Invalid\n");
				return -EINVAL;
			}
			kdreg->packet_off = prev_meta->dreg.packet_off | imm;
			break;
		case BPF_ALU | BPF_ADD | BPF_X:
		case BPF_ALU64 | BPF_ADD | BPF_X:
			knod_jit_dbg(" PTR_TO_STACK with BPF_X is not supported\n");
			return -EINVAL;
		case BPF_ALU | BPF_ADD | BPF_K:
		case BPF_ALU64 | BPF_ADD | BPF_K:
			prev_meta = knod_bpf_lookup_prev_meta_by_dreg(
				knod_prog, meta, meta->insn.dst_reg);
			if (!prev_meta) {
				knod_jit_dbg(" Invalid\n");
				return -EINVAL;
			}
			kdreg->packet_off = prev_meta->dreg.packet_off + imm;
			break;
		case BPF_ALU | BPF_SUB | BPF_X:
		case BPF_ALU64 | BPF_SUB | BPF_X:
			knod_jit_dbg(" PTR_TO_STACK with BPF_X is not supported\n");
			return -EINVAL;
		case BPF_ALU | BPF_SUB | BPF_K:
		case BPF_ALU64 | BPF_SUB | BPF_K:
			prev_meta = knod_bpf_lookup_prev_meta_by_dreg(
				knod_prog, meta, meta->insn.dst_reg);
			if (!prev_meta) {
				knod_jit_dbg(" Invalid\n");
				return -EINVAL;
			}
			kdreg->packet_off = prev_meta->dreg.packet_off - imm;
			break;
		case BPF_ALU | BPF_MUL | BPF_X:
		case BPF_ALU64 | BPF_MUL | BPF_X:
			knod_jit_dbg(" PTR_TO_STACK with BPF_X is not supported\n");
			return -EINVAL;
		case BPF_ALU | BPF_MUL | BPF_K:
		case BPF_ALU64 | BPF_MUL | BPF_K:
			prev_meta = knod_bpf_lookup_prev_meta_by_dreg(
				knod_prog, meta, meta->insn.dst_reg);
			if (!prev_meta) {
				knod_jit_dbg(" Invalid\n");
				return -EINVAL;
			}
			kdreg->packet_off = prev_meta->dreg.packet_off * imm;
			break;
		case BPF_ALU | BPF_DIV | BPF_X:
		case BPF_ALU64 | BPF_DIV | BPF_X:
			knod_jit_dbg(" PTR_TO_STACK with BPF_X is not supported\n");
			return -EINVAL;
		case BPF_ALU | BPF_DIV | BPF_K:
		case BPF_ALU64 | BPF_DIV | BPF_K:
			prev_meta = knod_bpf_lookup_prev_meta_by_dreg(
				knod_prog, meta, meta->insn.dst_reg);
			if (!prev_meta) {
				knod_jit_dbg(" Invalid\n");
				return -EINVAL;
			}
			kdreg->packet_off = prev_meta->dreg.packet_off / imm;
			break;
		case BPF_ALU | BPF_NEG:
		case BPF_ALU64 | BPF_NEG:
			break;
		case BPF_ALU | BPF_LSH | BPF_X:
		case BPF_ALU64 | BPF_LSH | BPF_X:
			knod_jit_dbg(" PTR_TO_STACK with BPF_X is not supported\n");
			return -EINVAL;
		case BPF_ALU | BPF_LSH | BPF_K:
		case BPF_ALU64 | BPF_LSH | BPF_K:
			prev_meta = knod_bpf_lookup_prev_meta_by_dreg(
				knod_prog, meta, meta->insn.dst_reg);
			if (!prev_meta) {
				knod_jit_dbg(" Invalid\n");
				return -EINVAL;
			}
			kdreg->packet_off = prev_meta->dreg.packet_off << imm;
			break;
		case BPF_ALU | BPF_RSH | BPF_X:
		case BPF_ALU64 | BPF_RSH | BPF_X:
			knod_jit_dbg(" PTR_TO_STACK with BPF_X is not supported\n");
			return -EINVAL;
		case BPF_ALU | BPF_RSH | BPF_K:
		case BPF_ALU64 | BPF_RSH | BPF_K:
			prev_meta = knod_bpf_lookup_prev_meta_by_dreg(
				knod_prog, meta, meta->insn.dst_reg);
			if (!prev_meta) {
				knod_jit_dbg(" Invalid\n");
				return -EINVAL;
			}
			kdreg->packet_off = prev_meta->dreg.packet_off >> imm;
			break;
		case BPF_ALU | BPF_ARSH | BPF_X:
		case BPF_ALU64 | BPF_ARSH | BPF_X:
			knod_jit_dbg(" PTR_TO_STACK with BPF_X is not supported\n");
			return -EINVAL;
		case BPF_ALU | BPF_ARSH | BPF_K:
		case BPF_ALU64 | BPF_ARSH | BPF_K:
			prev_meta = knod_bpf_lookup_prev_meta_by_dreg(
				knod_prog, meta, meta->insn.dst_reg);
			if (!prev_meta) {
				knod_jit_dbg(" Invalid\n");
				return -EINVAL;
			}
			kdreg->packet_off = prev_meta->dreg.packet_off >> imm;
			break;
		}
		knod_jit_dbg(" %d: dreg->packet_off = %d\n", meta->bpf_insn_idx,
			kdreg->packet_off);
	}
	return 0;
}

static int knod_bpf_verify_insn(struct bpf_verifier_env *env,
				int insn_idx, int prev_insn)
{
	struct knod_prog *knod_prog = env->prog->aux->offload->dev_priv;
	const struct bpf_reg_state *sreg, *dreg, *kreg, *vreg;
	struct knod_insn_meta *meta = knod_prog->meta;
	struct knod_insn_meta *prev_meta;
	int err = 0;

	meta = knod_bpf_insn_meta(knod_prog, env, insn_idx);
	if (!meta) {
		pr_warn("knod_bpf: bpf#%d is in a function the verifier checks apart from its calls - a global one; not supported\n",
			insn_idx);
		return -EOPNOTSUPP;
	}
	meta->flags |= FLAG_INSN_SEEN;
	sreg = cur_regs(env) + meta->insn.src_reg;
	dreg = cur_regs(env) + meta->insn.dst_reg;
	knod_prog->meta = meta;
	meta->sreg.reg = *sreg;
	meta->dreg.reg = *dreg;

	knod_bpf_update_ptr_off(knod_prog, meta, env);

	if (meta->insn.src_reg >= MAX_BPF_REG ||
			meta->insn.dst_reg >= MAX_BPF_REG) {
		knod_jit_dbg(" program uses extended registers - jit hardening?\n");
		err = -EINVAL;
		goto out;
	}

	if (is_mbpf_ldx(meta)) {
		err = knod_bpf_check_ptr(knod_prog, meta, env,
					 meta->insn.src_reg);
		goto out;
	}
	/* Immediate packet stores need the same pointer provenance as STX. */
	if (BPF_CLASS(meta->insn.code) == BPF_ST &&
	    BPF_MODE(meta->insn.code) == BPF_MEM &&
	    cur_regs(env)[meta->insn.dst_reg].type == PTR_TO_PACKET) {
		err = knod_bpf_check_ptr(knod_prog, meta, env,
					 meta->insn.dst_reg);
		goto out;
	}
	if (is_mbpf_store(meta)) {
		err = knod_bpf_check_store(knod_prog, meta, env);
		goto out;
	}

	if (is_mbpf_map_call(meta)) {
		meta->call_map = cur_regs(env)[BPF_REG_1].map_ptr;
		kreg = cur_regs(env) + 2;
		meta->kreg.reg = *kreg;

		prev_meta = knod_bpf_lookup_prev_meta_by_dreg(knod_prog,
							      meta,
							      2);
		if (!prev_meta) {
			knod_jit_dbg(" Invalid\n");
			err = -EINVAL;
			goto out;
		}
		if (base_type(kreg->type) == PTR_TO_PACKET)
			meta->kreg.packet_off = prev_meta->dreg.packet_off;
		else if (base_type(kreg->type) == PTR_TO_STACK)
			meta->kreg.stack_off = prev_meta->dreg.stack_off;
		if (knod_prog->max_stack_off > meta->kreg.stack_off)
			knod_prog->max_stack_off = meta->kreg.stack_off;

		/* bpf_map_update_elem: track r3 (value pointer) */
		if (meta->insn.imm == BPF_FUNC_map_update_elem) {
			vreg = cur_regs(env) + 3;
			meta->vreg.reg = *vreg;

			prev_meta = knod_bpf_lookup_prev_meta_by_dreg(knod_prog,
								      meta,
								      3);
			if (!prev_meta) {
				knod_jit_dbg(" Invalid vreg\n");
				err = -EINVAL;
				goto out;
			}
			if (base_type(vreg->type) == PTR_TO_PACKET)
				meta->vreg.packet_off =
					prev_meta->dreg.packet_off;
			else if (base_type(vreg->type) == PTR_TO_STACK)
				meta->vreg.stack_off =
					prev_meta->dreg.stack_off;
			if (knod_prog->max_stack_off > meta->vreg.stack_off)
				knod_prog->max_stack_off = meta->vreg.stack_off;
		}
	}

	if (is_mbpf_alu(meta))
		err = knod_bpf_check_alu(knod_prog, meta, env);

	/* less stack offset is bigger */
	if (knod_prog->max_stack_off > meta->sreg.stack_off)
		knod_prog->max_stack_off = meta->sreg.stack_off;
	if (knod_prog->max_stack_off > meta->dreg.stack_off)
		knod_prog->max_stack_off = meta->dreg.stack_off;
	/* A load or store reaches insn.off past its register, so the register
	 * alone understates the depth by exactly that - which is why this was
	 * computed for years and read by nothing: it was never quite right.
	 */
	if (BPF_CLASS(meta->insn.code) == BPF_LDX &&
	    meta->ptr.type == PTR_TO_STACK &&
	    knod_prog->max_stack_off > meta->sreg.stack_off + meta->insn.off)
		knod_prog->max_stack_off = meta->sreg.stack_off + meta->insn.off;
	if ((BPF_CLASS(meta->insn.code) == BPF_STX ||
	     BPF_CLASS(meta->insn.code) == BPF_ST) &&
	    meta->ptr.type == PTR_TO_STACK &&
	    knod_prog->max_stack_off > meta->dreg.stack_off + meta->insn.off)
		knod_prog->max_stack_off = meta->dreg.stack_off + meta->insn.off;

out:
	if (err)
		pr_warn("knod_bpf: verifier rejected bpf insn %d (code 0x%02x off %d imm %d): %d\n",
			insn_idx, meta->insn.code, meta->insn.off,
			meta->insn.imm, err);
	return err;
}

/*
 * Place each copy's frame, now that the verifier has measured every
 * function's stack: below its caller's, past what the call keeps of the
 * caller's registers.  All of it within the one stack a program has.
 */
static int knod_bpf_finalize(struct bpf_verifier_env *env)
{
	struct knod_prog *knod_prog = env->prog->aux->offload->dev_priv;
	struct knod_subprog_inst *inst, *up;
	int i, s;

	for (i = 0; i < knod_prog->n_insts; i++) {
		inst = &knod_prog->insts[i];
		inst->depth = 0;
		for (s = 0; s < env->subprog_cnt; s++)
			if (env->subprog_info[s].start == inst->start)
				inst->depth =
					round_up(env->subprog_info[s].stack_depth,
						 8);
		if (!inst->level) {
			inst->fp = 0;
			continue;
		}
		up = &knod_prog->insts[inst->parent];
		inst->fp = up->fp - up->depth - 8 * hweight16(inst->saves);
		if (inst->fp - inst->depth < -MAX_BPF_STACK) {
			pr_warn("knod_bpf: frames down to bpf#%d with the registers calls keep need %d bytes of stack, past %d\n",
				inst->start, inst->depth - inst->fp,
				MAX_BPF_STACK);
			return -E2BIG;
		}
	}
	return 0;
}

/* Where a stack offset from the verifier hook is, once frames are placed. */
static int knod_bpf_place_off(const struct knod_prog *knod_prog,
			      const struct knod_insn_meta *meta, int off)
{
	const struct knod_subprog_inst *inst = &knod_prog->insts[meta->inst];
	int level;

	if (off >= 0)
		return off;
	level = -off / KNOD_STACK_VSTRIDE;
	while (inst->level > level)
		inst = &knod_prog->insts[inst->parent];
	return inst->fp + off + level * KNOD_STACK_VSTRIDE;
}

static void knod_bpf_deepest(int *max, int off)
{
	if (*max > off)
		*max = off;
}

/*
 * Leave out what the verifier never went through in a copy's call context -
 * a branch that call never takes - and put every stack offset where its frame
 * is.  The verifier only removes what no call reaches.
 */
static void knod_bpf_place_frames(struct knod_prog *knod_prog)
{
	const struct knod_subprog_inst *inst;
	struct knod_insn_meta *meta;
	int *m = &knod_prog->max_stack_off;

	*m = 0;
	list_for_each_entry(meta, &knod_prog->insns, l) {
		inst = &knod_prog->insts[meta->inst];
		if (meta->flags & FLAG_INSN_SUBPROG_RET) {
			if (!(meta->sub_call->flags & FLAG_INSN_SEEN))
				meta->flags |= FLAG_INSN_SKIP_VERIFIER_OPT;
			meta->sub_save_off = inst->fp;
			meta->sub_call->sub_save_off = inst->fp;
			if (meta->sub_saves)
				knod_bpf_deepest(m, inst->fp);
			continue;
		}
		/* The verifier never visits an ld_imm64's second half: it goes
		 * with the first.
		 */
		if (!meta->insn.code)
			meta->flags |= knod_meta_prev(meta)->flags &
				       FLAG_INSN_SKIP_VERIFIER_OPT;
		else if (inst->level && !(meta->flags & FLAG_INSN_SEEN))
			meta->flags |= FLAG_INSN_SKIP_VERIFIER_OPT;

		meta->sreg.stack_off = knod_bpf_place_off(knod_prog, meta,
							  meta->sreg.stack_off);
		meta->dreg.stack_off = knod_bpf_place_off(knod_prog, meta,
							  meta->dreg.stack_off);
		meta->kreg.stack_off = knod_bpf_place_off(knod_prog, meta,
							  meta->kreg.stack_off);
		meta->vreg.stack_off = knod_bpf_place_off(knod_prog, meta,
							  meta->vreg.stack_off);
		knod_bpf_deepest(m, meta->sreg.stack_off);
		knod_bpf_deepest(m, meta->dreg.stack_off);
		knod_bpf_deepest(m, meta->kreg.stack_off);
		knod_bpf_deepest(m, meta->vreg.stack_off);
		if (meta->ptr.type != PTR_TO_STACK)
			continue;
		if (BPF_CLASS(meta->insn.code) == BPF_LDX)
			knod_bpf_deepest(m, meta->sreg.stack_off +
					 meta->insn.off);
		else if (BPF_CLASS(meta->insn.code) == BPF_STX ||
			 BPF_CLASS(meta->insn.code) == BPF_ST)
			knod_bpf_deepest(m, meta->dreg.stack_off +
					 meta->insn.off);
	}
}

/*
 * The verifier rewrites and deletes instructions of its own once a program
 * checks out: a conditional jump whose other side it proved unreachable
 * becomes unconditional, and everything it never reached is removed.  Both
 * happen to prog->insnsi, which the meta list is only a copy of, so a driver
 * that does not follow along translates instructions that are no longer in
 * the program - and translates them without any verifier state, since the
 * verifier never walked them.
 *
 * Follow along in the meta list, which stays on the original numbering that
 * its jump offsets and bpf_insn_idx are expressed in.  Deleted instructions
 * are flagged rather than unlinked here; knod_bpf_drop_dead_insns() drops
 * them once the verifier is done rewriting.
 */
static int knod_bpf_replace_insn(struct bpf_verifier_env *env, u32 off,
				 struct bpf_insn *insn)
{
	struct bpf_insn_aux_data *aux_data = env->insn_aux_data;
	struct knod_prog *knod_prog = env->prog->aux->offload->dev_priv;
	int orig = aux_data[off].orig_idx, t = orig + insn->off + 1;
	const struct knod_subprog_inst *inst;
	struct knod_insn_meta *meta;

	/* Every copy of it, each jumping within its own. */
	list_for_each_entry(meta, &knod_prog->insns, l) {
		if (meta->orig_idx != orig ||
		    (meta->flags & FLAG_INSN_SUBPROG_RET))
			continue;
		inst = &knod_prog->insts[meta->inst];
		if (!is_mbpf_cond_jump(meta) ||
		    insn->code != (BPF_JMP | BPF_JA) ||
		    t < inst->start || t >= inst->end) {
			pr_warn("knod_bpf: bpf#%d unsupported replacement %02x -> %02x\n",
				orig, meta->insn.code, insn->code);
			return -EINVAL;
		}
		meta->insn = *insn;
		meta->insn.off = inst->flat[t - inst->start] -
				 meta->bpf_insn_idx - 1;
	}

	return 0;
}

/* Copy @id and everything it calls: when the call to it goes, so do they. */
static void knod_bpf_drop_inst(struct knod_prog *knod_prog, int id)
{
	struct knod_insn_meta *meta;
	int c;

	list_for_each_entry(meta, &knod_prog->insns, l)
		if (meta->inst == id)
			meta->flags |= FLAG_INSN_SKIP_VERIFIER_OPT;
	for (c = id + 1; c < knod_prog->n_insts; c++)
		if (knod_prog->insts[c].parent == id)
			knod_bpf_drop_inst(knod_prog, c);
}

static int knod_bpf_remove_insns(struct bpf_verifier_env *env, u32 off,
				 u32 cnt)
{
	struct bpf_insn_aux_data *aux_data = env->insn_aux_data;
	struct knod_prog *knod_prog = env->prog->aux->offload->dev_priv;
	struct knod_insn_meta *meta;
	int orig;
	u32 i;

	/* The removed instructions as the verifier numbers them now, each in
	 * every copy of its function.
	 */
	for (i = 0; i < cnt; i++) {
		orig = aux_data[off + i].orig_idx;
		list_for_each_entry(meta, &knod_prog->insns, l) {
			if (meta->orig_idx != orig ||
			    (meta->flags & FLAG_INSN_SUBPROG_RET))
				continue;
			meta->flags |= FLAG_INSN_SKIP_VERIFIER_OPT;
			if (meta->sub_call)
				knod_bpf_drop_inst(knod_prog,
						   meta->sub_call->inst);
		}
	}

	return 0;
}

static int knod_bpf_offload(struct knod_dev *knodev,
			    struct bpf_prog *prog, bool oldprog)
{
	struct knod_bpf_priv *priv = knodev->accel->xdp.priv;
	int err = 0;

	WARN(!!knod_dev_offloaded(knodev) != oldprog,
	     "bad offload state, expected offload %sto be active",
	     oldprog ? "" : "not ");

	WRITE_ONCE(priv->prog, prog);
	knod_dev_offload(knodev, prog);

	/*
	 * Uninstalling the prog: reload the pass kernel now, while the prog's
	 * maps are still valid, so no program code is left running against maps
	 * about to be freed.
	 */
	if (!prog)
		err = knod_bpf_reload_pass(knodev);
	if (err)
		knod_gda_mark_fault(priv->knod);

	return err;
}

static int knod_bpf_xdp_offload_prog(struct knod_dev *knodev,
				     struct netdev_bpf *bpf)
{
	if (!knod_dev_active(knodev) && !bpf->prog)
		return 0;

	if (!knod_dev_active(knodev) && bpf->prog &&
	    knodev->accel->xdp.bpf_offloaded) {
		return -EBUSY;
	}

	return knod_bpf_offload(knodev, bpf->prog, knod_dev_active(knodev));
}

static int knod_bpf_xdp_set_prog(struct knod_dev *knodev,
				 struct netdev_bpf *bpf)
{
	int err;

	err = knod_bpf_xdp_offload_prog(knodev, bpf);
	if (err)
		return err;

	xdp_attachment_setup(&knodev->accel->xdp.xdp_hw, bpf);

	return 0;
}

/* Keep the memory accesses a map emitter just made out of the CU's own cache.
 *
 * A map that is not percpu is reached by every workgroup, and a workgroup is a
 * CU with a cache of its own that the next round's prologue invalidates.
 * One CU inserting into a hash table and another looking the same key up in the
 * same round will not find it: the reader answers from a line it read before
 * the write.
 *
 * RDNA holds another cache between the two, shared by the CUs of a shader
 * array, so both have to be stepped past - GLC for the one in the CU, DLC for
 * the one in the array.  GCN has only the first and no bit for the second.
 *
 * Only loads.  A store already reaches L2 whatever the bits say (RDNA2 8.1.10),
 * and DLC on one means bypass L2 instead of missing a cache above it - the
 * write goes to memory and the next reader, looking in L2, does not see it.
 * On an atomic, GLC changes whether it returns anything at all.
 *
 * A percpu map does not need any of this - its instance belongs to one queue,
 * so one workgroup, and the waits at the end of the round carry it from
 * there.  Leaving those in the cache is most of why they are quick.
 *
 * Letting the array cache answer instead of L2 - GLC without DLC, which the ISA
 * allows and calls coherent for stores - was tried and changed the rate by
 * nothing at all, so the weaker guarantee buys nothing and is not taken.
 */
static void knod_map_bypass_l0(struct knod_bpf_priv *priv,
			       struct knod_insn_meta *meta, u32 first)
{
	u32 i;

	for (i = first; i < meta->amdgpu_insns; i++) {
		struct amdgcn_insn *insn = &meta->amdgpu_insn[i];

		if (insn->type != AMDGCN_INSN_TYPE_FLAT)
			continue;
		if (priv->isa_version == 11) {
			if (insn->gfx11.flat.op >= GFX11_GLOBAL_STORE_B8)
				continue;
			insn->gfx11.flat.glc = 1;
			insn->gfx11.flat.dlc = 1;
		} else if (priv->isa_version == 10) {
			if (insn->gfx10.flat.op >= GFX10_GLOBAL_STORE_BYTE)
				continue;
			insn->gfx10.flat.glc = 1;
			insn->gfx10.flat.dlc = 1;
		} else {
			WARN_ON_ONCE(1);
		}
	}
}

/* Apply the RDNA NC packet-store policy only to ranges the verifier proved
 * access packet memory. Loads and unrelated memory retain their existing
 * cache policy. GFX11 stores are device scope regardless of GLC, but keep the
 * explicit GLC/SLC/DLC policy paired with the generation-specific encoding.
 */
static void knod_packet_store_cache_policy(struct knod_bpf_priv *priv,
					   struct knod_insn_meta *meta,
					   u32 first)
{
	u32 i;

	if ((priv->isa_version != 10 && priv->isa_version != 11) ||
	    knod_bpf_jit_engine != 1)
		return;
	for (i = first; i < meta->amdgpu_insns; i++) {
		struct amdgcn_insn *insn = &meta->amdgpu_insn[i];

		if (insn->type != AMDGCN_INSN_TYPE_FLAT)
			continue;
		if (priv->isa_version == 11) {
			if (insn->gfx11.flat.seg != GFX11_FLAT_SEG_GLOBAL)
				continue;
			switch (insn->gfx11.flat.op) {
			case GFX11_GLOBAL_STORE_B8:
			case GFX11_GLOBAL_STORE_B16:
			case GFX11_GLOBAL_STORE_B32:
			case GFX11_GLOBAL_STORE_B64:
			case GFX11_GLOBAL_STORE_B96:
			case GFX11_GLOBAL_STORE_B128:
				insn->gfx11.flat.glc = 1;
				insn->gfx11.flat.slc = 0;
				insn->gfx11.flat.dlc = 1;
				break;
			default:
				break;
			}
		} else {
			if (insn->gfx10.flat.seg != GFX10_FLAT_SEG_GLOBAL)
				continue;
			switch (insn->gfx10.flat.op) {
			case GFX10_GLOBAL_STORE_BYTE:
			case GFX10_GLOBAL_STORE_SHORT:
			case GFX10_GLOBAL_STORE_DWORD:
			case GFX10_GLOBAL_STORE_DWORDX2:
			case GFX10_GLOBAL_STORE_DWORDX3:
			case GFX10_GLOBAL_STORE_DWORDX4:
				insn->gfx10.flat.glc = 1;
				insn->gfx10.flat.slc = 0;
				insn->gfx10.flat.dlc = 1;
				break;
			default:
				break;
			}
		}
	}
}

static void knod_wait_vmcnt(struct knod_bpf_priv *priv,
			   struct knod_insn_meta *meta)
{
	knod_emit(priv, meta, s_waitcnt_vmcnt);
}

static int knod_prog_prepare_insns(struct knod_bpf_priv *priv,
				   struct knod_prog *knod_prog)
{
	struct knod_insn_meta *meta;
	struct amdgcn_param64 fp;

	meta = kzalloc_obj(*meta, GFP_KERNEL);
	if (!meta)
		return -ENOMEM;

	meta->amdgpu_insn_idx = 0;

	/* The engine has left the packets where KNOD_BLOB_PRO_* says.  What is
	 * the program's: r10 at the top of the stack, and the lane's base in
	 * an LDS one.
	 */
	knod_iset64(&fp, KNOD_BLOB_BPF_STACK_SIZE);
	knod_mov64(priv, meta, bpf_reg64[BPF_REG_FP], fp);
	knod_bpf_emit_lds_base_init(priv, meta);
	list_add_tail(&meta->l, &knod_prog->pre_insns);
	return 0;
}

static bool knod_insn_is_pseudo_call(const struct bpf_insn *insn)
{
	return insn->code == (BPF_JMP | BPF_CALL) &&
	       insn->src_reg == BPF_PSEUDO_CALL;
}

static bool knod_insn_is_jump(const struct bpf_insn *insn)
{
	u8 class = BPF_CLASS(insn->code), op = BPF_OP(insn->code);

	return (class == BPF_JMP || class == BPF_JMP32) &&
	       op != BPF_CALL && op != BPF_EXIT;
}

static int knod_insn_jump_off(const struct bpf_insn *insn)
{
	return insn->code == (BPF_JMP32 | BPF_JA) ? insn->imm : insn->off;
}

static void knod_insn_set_jump_off(struct bpf_insn *insn, int off)
{
	if (insn->code == (BPF_JMP32 | BPF_JA))
		insn->imm = off;
	else
		insn->off = off;
}

/* Where the function that starts at @start ends: at the next function, the
 * target of some BPF-to-BPF call, or the end of the program.
 */
static int knod_prog_func_end(const struct bpf_insn *prog, unsigned int cnt,
			      int start)
{
	int end = cnt, i, t;

	for (i = 0; i < cnt; i++) {
		if (!knod_insn_is_pseudo_call(&prog[i]))
			continue;
		t = i + 1 + prog[i].imm;
		if (t > start && t < end)
			end = t;
	}
	return end;
}

/* r6-r9 an instruction writes. */
static u16 knod_insn_writes_saved(const struct bpf_insn *insn)
{
	u8 class = BPF_CLASS(insn->code), r = 0;

	if (class == BPF_ALU || class == BPF_ALU64 || class == BPF_LDX ||
	    class == BPF_LD)
		r = insn->dst_reg;
	else if (class == BPF_STX && BPF_MODE(insn->code) == BPF_ATOMIC &&
		 (insn->imm & BPF_FETCH))
		r = insn->src_reg;
	return r >= BPF_REG_6 && r <= BPF_REG_9 ? BIT(r) : 0;
}

/*
 * Lay out @start's function as copy @parent's call at @call reaches it, and
 * every function it calls in turn after the call that reaches it, so the
 * translated program has no calls: a function the verifier keeps apart is
 * copied in wherever it is called, the way a compiler inlines one.  The
 * copy's instructions are numbered in the order they are laid out.
 */
static int knod_prog_flatten_func(struct knod_prog *knod_prog,
				  const struct bpf_insn *prog,
				  unsigned int cnt, int parent, int call,
				  int start, u8 level)
{
	struct knod_subprog_inst *inst;
	struct knod_insn_meta *meta;
	int id, child, i, err;

	if (knod_prog->n_insts == KNOD_SUBPROG_INSTS ||
	    level >= MAX_CALL_FRAMES || start < 0 || start >= cnt) {
		pr_warn("knod_bpf: BPF-to-BPF calls reach more than %d functions or %d deep\n",
			KNOD_SUBPROG_INSTS, MAX_CALL_FRAMES);
		return -E2BIG;
	}
	id = knod_prog->n_insts++;
	inst = &knod_prog->insts[id];
	inst->start = start;
	inst->end = knod_prog_func_end(prog, cnt, start);
	inst->parent = parent;
	inst->call = call;
	inst->level = level;
	inst->flat = kvcalloc(inst->end - start, sizeof(*inst->flat),
			      GFP_KERNEL);
	if (!inst->flat)
		return -ENOMEM;

	for (i = start; i < inst->end; i++) {
		if (knod_prog->n_insns == SHRT_MAX) {
			pr_warn("knod_bpf: more than %d instructions with every called function copied in\n",
				SHRT_MAX);
			return -E2BIG;
		}
		meta = kzalloc_obj(*meta, GFP_KERNEL);
		if (!meta)
			return -ENOMEM;
		meta->insn = prog[i];
		meta->orig_idx = i;
		meta->inst = id;
		meta->frame = level;
		meta->bpf_insn_idx = knod_prog->n_insns++;
		inst->flat[i - start] = meta->bpf_insn_idx;
		list_add_tail(&meta->l, &knod_prog->insns);
		if (!knod_insn_is_pseudo_call(&prog[i]))
			continue;

		child = knod_prog->n_insts;
		err = knod_prog_flatten_func(knod_prog, prog, cnt, id, i,
					     i + 1 + prog[i].imm, level + 1);
		if (err)
			return err;

		/* Where the copy's exits go, and the caller's registers come
		 * back: a move of r0 to itself, for every pass that only knows
		 * BPF.
		 */
		meta = kzalloc_obj(*meta, GFP_KERNEL);
		if (!meta)
			return -ENOMEM;
		meta->insn = BPF_MOV64_REG(BPF_REG_0, BPF_REG_0);
		meta->flags = FLAG_INSN_SUBPROG_RET | FLAG_INSN_SEEN;
		meta->orig_idx = i;
		meta->inst = child;
		meta->frame = level;
		meta->bpf_insn_idx = knod_prog->n_insns++;
		knod_prog->insts[child].ret = meta->bpf_insn_idx;
		list_add_tail(&meta->l, &knod_prog->insns);
	}
	return 0;
}

static int knod_prog_flatten(struct knod_prog *knod_prog,
			     const struct bpf_insn *prog, unsigned int cnt)
{
	struct knod_subprog_inst *inst, *up;
	struct knod_insn_meta *meta;
	int err, t, off;
	u16 w;

	knod_prog->n_insns = 0;
	knod_prog->n_insts = 0;
	err = knod_prog_flatten_func(knod_prog, prog, cnt, -1, -1, 0, 0);
	if (err)
		return err;

	knod_prog->flat_meta = kvcalloc(knod_prog->n_insns,
					sizeof(*knod_prog->flat_meta),
					GFP_KERNEL);
	if (!knod_prog->flat_meta)
		return -ENOMEM;

	list_for_each_entry(meta, &knod_prog->insns, l) {
		knod_prog->flat_meta[meta->bpf_insn_idx] = meta;
		if (meta->flags & FLAG_INSN_SUBPROG_RET)
			continue;
		inst = &knod_prog->insts[meta->inst];

		/* What a call keeps is what anything it reaches may change. */
		w = knod_insn_writes_saved(&meta->insn);
		for (up = inst; w && up->level;
		     up = &knod_prog->insts[up->parent])
			up->saves |= w;

		/* A called function's exit is its caller's next instruction. */
		if (meta->insn.code == (BPF_JMP | BPF_EXIT) && inst->level) {
			off = inst->ret - meta->bpf_insn_idx - 1;
			meta->insn = BPF_JMP_A(off);
			if (!off)
				meta->flags |= FLAG_INSN_SKIP_NOOP;
			continue;
		}
		if (!knod_insn_is_jump(&meta->insn))
			continue;
		t = meta->orig_idx + knod_insn_jump_off(&meta->insn) + 1;
		if (t < inst->start || t >= inst->end) {
			pr_warn("knod_bpf: bpf#%d jumps out of its function\n",
				meta->orig_idx);
			return -EINVAL;
		}
		knod_insn_set_jump_off(&meta->insn,
				       inst->flat[t - inst->start] -
				       meta->bpf_insn_idx - 1);
	}

	/* Point a call and its return at each other, and leave out the ones
	 * with nothing to keep.
	 */
	list_for_each_entry(meta, &knod_prog->insns, l) {
		if (!(meta->flags & FLAG_INSN_SUBPROG_RET))
			continue;
		inst = &knod_prog->insts[meta->inst];
		meta->sub_call = knod_prog->flat_meta[
			knod_prog->insts[inst->parent].flat[inst->call -
				knod_prog->insts[inst->parent].start]];
		meta->sub_call->sub_call = meta;
		meta->sub_saves = inst->saves;
		meta->sub_call->sub_saves = inst->saves;
		if (!inst->saves) {
			meta->flags |= FLAG_INSN_SKIP_NOOP;
			meta->sub_call->flags |= FLAG_INSN_SKIP_NOOP;
		}
	}
	return 0;
}

static int knod_prog_prepare(struct knod_bpf_priv *priv,
			     struct knod_prog *knod_prog,
			     const struct bpf_insn *prog,
			     unsigned int cnt)
{
	unsigned int i;

	knod_vset64(&r64[0], KNOD_AMDGPU_TMP_VREG0_LO);
	knod_vset64(&r64[1], KNOD_AMDGPU_TMP_VREG1_LO);
	knod_vset64(&r64[2], KNOD_AMDGPU_TMP_VREG2_LO);
	knod_vset64(&r64[3], KNOD_AMDGPU_TMP_VREG3_LO);
	knod_vset64(&r64[4], KNOD_AMDGPU_TMP_VREG4_LO);
	knod_vset64(&r64[5], KNOD_AMDGPU_TMP_VREG5_LO);
	knod_vset64(&r64[6], KNOD_AMDGPU_TMP_VREG6_LO);
	knod_vset64(&r64[7], KNOD_AMDGPU_TMP_VREG7_LO);
	knod_vset64(&r64[8], KNOD_AMDGPU_TMP_VREG8_LO);
	knod_vset64(&r64[9], KNOD_AMDGPU_TMP_VREG9_LO);
	knod_vset64(&r64[10], KNOD_AMDGPU_TMP_VREG10_LO);
	knod_vset64(&r64[11], KNOD_AMDGPU_TMP_VREG11_LO);
	knod_vset64(&r64[12], KNOD_AMDGPU_TMP_VREG12_LO);
	knod_vset64(&r64[13], KNOD_AMDGPU_TMP_VREG13_LO);
	knod_vset64(&r64[14], KNOD_AMDGPU_TMP_VREG14_LO);
	knod_vset64(&r64[15], KNOD_AMDGPU_TMP_VREG15_LO);
	knod_vset64(&r64[16], KNOD_AMDGPU_TMP_VREG16_LO);
	knod_vset64(&r64[17], KNOD_AMDGPU_TMP_VREG17_LO);
	knod_vset64(&r64[19], KNOD_AMDGPU_CTX_VREG_LO);

	knod_sset64(&sr64[0], KNOD_AMDGPU_TMP_SREG0_LO);
	knod_sset64(&sr64[1], KNOD_AMDGPU_TMP_SREG1_LO);
	knod_sset64(&sr64[2], KNOD_AMDGPU_TMP_SREG2_LO);
	knod_sset64(&sr64[3], KNOD_AMDGPU_TMP_SREG3_LO);
	knod_sset64(&sr64[4], KNOD_AMDGPU_TMP_SREG4_LO);
	knod_sset64(&sr64[5], KNOD_AMDGPU_TMP_SREG5_LO);

	for (i = 0; i < MAX_BPF_REG; i++)
		knod_vset64(&bpf_reg64[i], KNOD_BPF_VREG(i));

	knod_vset32(&r32[0], KNOD_AMDGPU_TMP_VREG0_LO);
	for (i = 1; i < 36; i++)
		knod_vset32(&r32[i], r32[i - 1].v + 1);

	return knod_prog_flatten(knod_prog, prog, cnt);
}

static void knod_prog_free(struct knod_prog *knod_prog)
{
	struct knod_insn_meta *meta, *tmp;
	int i;

	list_for_each_entry_safe(meta, tmp, &knod_prog->pre_insns, l) {
		list_del(&meta->l);
		kfree(meta);
	}
	list_for_each_entry_safe(meta, tmp, &knod_prog->insns, l) {
		list_del(&meta->l);
		kfree(meta);
	}
	list_for_each_entry_safe(meta, tmp, &knod_prog->post_insns, l) {
		list_del(&meta->l);
		kfree(meta);
	}
	for (i = 0; i < knod_prog->n_insts; i++)
		kvfree(knod_prog->insts[i].flat);
	kvfree(knod_prog->flat_meta);
	kfree(knod_prog);
}

static int knod_bpf_verifier_prep(struct bpf_prog *prog)
{
	struct knod_prog *knod_prog;
	struct knod_bpf_priv *priv;
	int err;

	knod_prog = kzalloc_obj(struct knod_prog, GFP_KERNEL);
	if (!knod_prog)
		return -ENOMEM;

	INIT_LIST_HEAD(&knod_prog->insns);
	INIT_LIST_HEAD(&knod_prog->pre_insns);
	INIT_LIST_HEAD(&knod_prog->post_insns);
	prog->aux->offload->dev_priv = knod_prog;
	priv = bpf_offload_dev_priv(prog->aux->offload->offdev);
	knod_prog->knodev = priv->knodev;
	WRITE_ONCE(priv->knod_prog, knod_prog);
	knod_prog->knod = priv->knod;
	knod_prog->insn_idx = 0;

	knod_prog->done_mask_sreg = KNOD_AMDGPU_DONE_MASK_SREG;
	knod_prog->exec_save_base = KNOD_AMDGPU_EXEC_SAVE_SREG_BASE;
	knod_prog->initial_exec_sreg = KNOD_AMDGPU_INITIAL_EXEC_SREG;

	err = knod_prog_prepare(priv, knod_prog, prog->insnsi, prog->len);
	if (err)
		goto err_free;

	knod_prog->meta = knod_prog_first_meta(knod_prog);

	return 0;

err_free:
	knod_prog_free(knod_prog);

	return err;
}

static struct knod_insn_meta *knod_bpf_lookup_meta(struct knod_prog *knod_prog,
						   short idx)
{
	struct knod_insn_meta *meta;

	list_for_each_entry(meta, &knod_prog->insns, l) {
		if (meta->amdgpu_insn_idx == AMDGPU_INSN_SKIP)
			continue;
		if (meta->bpf_insn_idx == idx)
			return meta;
	}

	return NULL;
}

static void knod_mov64_imm(struct knod_bpf_priv *priv,
			  struct knod_insn_meta *meta,
			  int d, u64 imm64)
{
	struct amdgcn_param32 param[2];

	knod_vset32(&param[0], d);
	knod_iset32(&param[1], imm64 & ~0U);
	knod_emit(priv, meta, v_mov_b32_e32, param[0], param[1]);
	knod_vset32(&param[0], d + 1);
	knod_iset32(&param[1], imm64 >> 32);
	knod_emit(priv, meta, v_mov_b32_e32, param[0], param[1]);
}

static void knod_mov32(struct knod_bpf_priv *priv,
		      struct knod_insn_meta *meta,
		      struct amdgcn_param32 dst,
		      struct amdgcn_param32 src)
{
	knod_emit(priv, meta, v_mov_b32_e32, dst, src);
}

static void knod_mov64(struct knod_bpf_priv *priv,
		      struct knod_insn_meta *meta,
		      struct amdgcn_param64 dst,
		      struct amdgcn_param64 src)
{
	knod_mov32(priv, meta, dst.lo, src.lo);
	knod_mov32(priv, meta, dst.hi, src.hi);
}

static void knod_add64(struct knod_bpf_priv *priv,
		      struct knod_insn_meta *meta,
		      struct amdgcn_param64 dst,
		      struct amdgcn_param64 src0,
		      struct amdgcn_param64 src1)
{
	knod_emit(priv, meta, v_add_co_u32, dst.lo, src0.lo, src1.lo);
	knod_emit(priv, meta, v_add_co_ci_u32_e32, dst.hi, src0.hi,
		  src1.hi);
}

/* No carry out/in */
static void knod_add32(struct knod_bpf_priv *priv,
		      struct knod_insn_meta *meta,
		      struct amdgcn_param32 dst,
		      struct amdgcn_param32 src0,
		      struct amdgcn_param32 src1)
{
	knod_emit(priv, meta, v_add_u32, dst, src0, src1);
}

static void knod_xor32(struct knod_bpf_priv *priv,
		      struct knod_insn_meta *meta,
		      struct amdgcn_param32 dst,
		      struct amdgcn_param32 src0,
		      struct amdgcn_param32 src1)
{
	knod_emit(priv, meta, v_xor_b32_e32, dst, src0, src1);
}

static void knod_bfe32(struct knod_bpf_priv *priv,
			   struct knod_insn_meta *meta,
			   struct amdgcn_param32 dst,
			   struct amdgcn_param32 src0,
			   struct amdgcn_param32 src1,
			   struct amdgcn_param32 src2)
{
	knod_emit(priv, meta, v_bfe_u32, dst, src0, src1, src2);
}

static void knod_bfi32(struct knod_bpf_priv *priv,
			   struct knod_insn_meta *meta,
			   struct amdgcn_param32 dst,
			   struct amdgcn_param32 src0,
			   struct amdgcn_param32 src1,
			   struct amdgcn_param32 src2)
{
	knod_emit(priv, meta, v_bfi_b32, dst, src0, src1, src2);
}

static void knod_lshrrev32(struct knod_bpf_priv *priv,
			   struct knod_insn_meta *meta,
			   struct amdgcn_param32 dst,
			   struct amdgcn_param32 src0,
			   struct amdgcn_param32 src1)
{
	knod_emit(priv, meta, v_lshrrev_b32, dst, src0, src1);
}

static void knod_lshrrev64(struct knod_bpf_priv *priv,
			   struct knod_insn_meta *meta,
			   struct amdgcn_param64 dst,
			   struct amdgcn_param64 src0,
			   struct amdgcn_param64 src1)
{
	knod_emit(priv, meta, v_lshrrev_b64, dst, src0, src1);
}

static void knod_ashrrev32(struct knod_bpf_priv *priv,
			   struct knod_insn_meta *meta,
			   struct amdgcn_param32 dst,
			   struct amdgcn_param32 src0,
			   struct amdgcn_param32 src1)
{
	knod_emit(priv, meta, v_ashrrev_i32, dst, src0, src1);
}

static void knod_ashrrev64(struct knod_bpf_priv *priv,
			   struct knod_insn_meta *meta,
			   struct amdgcn_param64 dst,
			   struct amdgcn_param64 src0,
			   struct amdgcn_param64 src1)
{
	knod_emit(priv, meta, v_ashrrev_i64, dst, src0, src1);
}

static void knod_lshlrev32(struct knod_bpf_priv *priv,
			   struct knod_insn_meta *meta,
			   struct amdgcn_param32 dst,
			   struct amdgcn_param32 src0,
			   struct amdgcn_param32 src1)
{
	knod_emit(priv, meta, v_lshlrev_b32, dst, src0, src1);
}

static void knod_lshlrev64(struct knod_bpf_priv *priv,
			   struct knod_insn_meta *meta,
			   struct amdgcn_param64 dst,
			   struct amdgcn_param64 src0,
			   struct amdgcn_param64 src1)
{
	knod_emit(priv, meta, v_lshlrev_b64, dst, src0, src1);
}

/* No carry out/in */
static void knod_sub32(struct knod_bpf_priv *priv,
		      struct knod_insn_meta *meta,
		      struct amdgcn_param32 dst,
		      struct amdgcn_param32 src0,
		      struct amdgcn_param32 src1)
{
	knod_emit(priv, meta, v_sub_u32, dst, src0, src1);
}

static void knod_and32(struct knod_bpf_priv *priv,
		      struct knod_insn_meta *meta,
		      struct amdgcn_param32 dst,
		      struct amdgcn_param32 src0,
		      struct amdgcn_param32 src1)
{
	knod_emit(priv, meta, v_and_b32_e32, dst, src0, src1);
}

static void knod_and64(struct knod_bpf_priv *priv,
		      struct knod_insn_meta *meta,
		      struct amdgcn_param64 dst,
		      struct amdgcn_param64 src0,
		      struct amdgcn_param64 src1)
{
	knod_and32(priv, meta, dst.lo, src0.lo, src1.lo);
	knod_and32(priv, meta, dst.hi, src0.hi, src1.hi);
}

static void knod_or32(struct knod_bpf_priv *priv,
		      struct knod_insn_meta *meta,
		      struct amdgcn_param32 dst,
		      struct amdgcn_param32 src0,
		      struct amdgcn_param32 src1)
{
	knod_emit(priv, meta, v_or_b32_e32, dst, src0, src1);
}

static void knod_sub64(struct knod_bpf_priv *priv,
		      struct knod_insn_meta *meta,
		      struct amdgcn_param64 dst,
		      struct amdgcn_param64 src0,
		      struct amdgcn_param64 src1)
{
	knod_emit(priv, meta, v_sub_co_u32, dst.lo, src0.lo, src1.lo);
	knod_emit(priv, meta, v_sub_co_ci_u32_e32, dst.hi, src0.hi,
		  src1.hi);
}

static void knod_mul_lo32(struct knod_bpf_priv *priv,
			 struct knod_insn_meta *meta,
			 struct amdgcn_param32 dst,
			 struct amdgcn_param32 src1,
			 struct amdgcn_param32 src2)
{
	knod_emit(priv, meta, v_mul_lo_u32, dst, src1, src2);
}

static void knod_mul_hi32(struct knod_bpf_priv *priv,
			 struct knod_insn_meta *meta,
			 struct amdgcn_param32 dst,
			 struct amdgcn_param32 src1,
			 struct amdgcn_param32 src2)
{
	knod_emit(priv, meta, v_mul_hi_u32, dst, src1, src2);
}

static void knod_mul64(struct knod_bpf_priv *priv,
		      struct knod_insn_meta *meta,
		      struct amdgcn_param64 dst,
		      struct amdgcn_param64 src1,
		      struct amdgcn_param64 src2,
		      struct amdgcn_param64 tmp)
{
	/*
	 * v_mul_lo_u32 v1, v2, v1
	 * v_mul_hi_u32 v5, v2, v0
	 * v_mul_lo_u32 v3, v3, v0
	 * v_mul_lo_u32 v0, v2, v0
	 * v_add_u32_e32 v1, v5, v1
	 * v_add_u32_e32 v1, v1, v3
	 *
	 * v[0:1] = src1, dst
	 * v[2:3] = src2
	 * v5 = tmp
	 */

	/* v_mul_lo_u32 v1, v2, v1 */
	knod_mul_lo32(priv, meta, src2.hi, src1.lo, src2.hi);
	/* v_mul_hi_u32 v5, v2, v0 */
	knod_mul_hi32(priv, meta, tmp.lo, src1.lo, src2.lo);
	/* v_mul_lo_u32 v3, v3, v0 */
	knod_mul_lo32(priv, meta, src1.hi, src1.hi, src2.lo);
	/* v_mul_lo_u32 v0, v2, v0 */
	knod_mul_lo32(priv, meta, src1.lo, src1.lo, src2.lo);
	/* v_add_u32_e32 v1, v5, v1 */
	knod_add32(priv, meta, src2.lo, tmp.lo, src2.hi);
	/* v_add_u32_e32 v1, v1, v3 */
	knod_add32(priv, meta, src1.hi, src2.lo, src1.hi);
	knod_mov32(priv, meta, dst.lo, src1.lo);
	knod_mov32(priv, meta, dst.hi, src1.hi);
}

static u64 knod_bpf_map_gaddr(struct knod_bpf_priv *priv, int id)
{
	struct knod_dev *knodev = priv->knodev;
	struct knod_bpf_map *knod_map;
	struct knod_mem *mem;

	mutex_lock(&knodev->lock);
	list_for_each_entry(knod_map, &knodev->accel->xdp.bound_maps, list) {
		if (knod_map->offmap->map.id == id) {
			mem = knod_map->mem;
			mutex_unlock(&knodev->lock);
			return (u64)mem->gaddr;
		}
	}
	mutex_unlock(&knodev->lock);

	return 0;
}

static struct knod_bpf_map *knod_bpf_map_find(struct knod_bpf_priv *priv,
					      int id)
{
	struct knod_dev *knodev = priv->knodev;
	struct knod_bpf_map *knod_map;

	mutex_lock(&knodev->lock);
	list_for_each_entry(knod_map, &knodev->accel->xdp.bound_maps, list) {
		if (knod_map->offmap->map.id == id) {
			mutex_unlock(&knodev->lock);
			return knod_map;
		}
	}
	mutex_unlock(&knodev->lock);

	return NULL;
}

static u64 knod_bpf_get_map_gaddr(struct knod_bpf_priv *priv,
				  struct knod_insn_meta *meta1,
				  struct knod_insn_meta *meta2)
{
	struct bpf_map *map;

	map = (void *)(unsigned long)((u32)meta1->insn.imm |
			(u64)meta2->insn.imm << 32);

	return knod_bpf_map_gaddr(priv, map->id);
}

static int knod_bpf_get_map_id(struct knod_bpf_priv *priv,
			       struct knod_insn_meta *meta1,
			       struct knod_insn_meta *meta2)
{
	struct bpf_map *map;

	map = (void *)(unsigned long)((u32)meta1->insn.imm |
			(u64)meta2->insn.imm << 32);

	return map->id;
}

/* Call a blob routine whose arguments are in place, by the calling
 * convention knod_blob.h sets out; its results come back from v0.  The
 * routine itself goes in once, after the program, and
 * knod_bpf_link_callees() points the call at it.
 */
static void knod_bpf_emit_call(struct knod_bpf_priv *priv,
			       struct knod_insn_meta *meta,
			       const u32 *code, u32 size)
{
	struct amdgcn_param32 p32[2];
	u32 guard, call, add, i, n, c;

	for (c = 0; c < KNOD_META_CALLEES && meta->callee[c].size; c++)
		;
	if (WARN_ON_ONCE(c == KNOD_META_CALLEES))
		return;

	/* The queue, which a percpu map's instance is, and which a call
	 * before this one may have taken.
	 */
	knod_sset32(&p32[0], KNOD_AMDGPU_WORKGROUP_ID_Y_SREG);
	knod_sset32(&p32[1], KNOD_BLOB_PRO_QUEUE_SREG);
	knod_emit(priv, meta, s_mov_b32, p32[0], p32[1]);

	/* Scalar instructions are not masked, so a routine entered with no live
	 * lane still runs - and one that elects a lane with mbcnt, or spins on
	 * a lock, does not come back out.  Branch over the call.
	 */
	guard = meta->amdgpu_insns;
	emit_s_cbranch_execz(priv->isa_version, &meta->amdgpu_insn[guard], 0);
	meta->amdgpu_insns++;
	call = meta->amdgpu_insns;

	/* s_getpc gives the address of the add after it; the add's literal
	 * becomes the distance from there to the routine.
	 */
	knod_emit(priv, meta, s_getpc_b64, KNOD_AMDGPU_TMP_SREG0_LO);
	knod_sset32(&p32[0], KNOD_AMDGPU_TMP_SREG0_LO);
	knod_iset32(&p32[1], 0x7fffffff);
	add = meta->amdgpu_insns;
	knod_emit(priv, meta, s_add_u32, p32[0], p32[0], p32[1]);
	knod_sset32(&p32[0], KNOD_AMDGPU_TMP_SREG0_HI);
	knod_iset32(&p32[1], 0);
	knod_emit(priv, meta, s_addc_u32, p32[0], p32[0], p32[1]);
	knod_emit(priv, meta, s_swappc_b64, 30, KNOD_AMDGPU_TMP_SREG0_LO);

	for (i = call, n = 0; i < meta->amdgpu_insns; i++)
		n += meta->amdgpu_insn[i].size;
	emit_s_cbranch_execz(priv->isa_version, &meta->amdgpu_insn[guard],
			     n / 4);

	meta->callee[c].code = code;
	meta->callee[c].size = size;
	for (i = 0, n = 0; i < add; i++)
		n += meta->amdgpu_insn[i].size;
	meta->callee[c].patch = n + 4;
}

/* v@to = v@from, a pair */
static void knod_bpf_mov_pair(struct knod_bpf_priv *priv,
			      struct knod_insn_meta *meta, int to, int from)
{
	struct amdgcn_param32 dst, src;

	knod_vset32(&dst, to);
	knod_vset32(&src, from);
	knod_mov32(priv, meta, dst, src);
	knod_vset32(&dst, to + 1);
	knod_vset32(&src, from + 1);
	knod_mov32(priv, meta, dst, src);
}

/*
 * bpf_xdp_adjust_head() and bpf_xdp_adjust_tail(), by the blob's routines:
 * r2 is the move, and the packet's start or end comes back with r0.  The
 * tailroom the stack needs past a frame's end is the kernel's to know, so it
 * goes as an argument.
 */
static bool knod_bpf_xdp_adjust(struct knod_bpf_priv *priv,
				struct knod_insn_meta *meta, bool head)
{
	u32 kind = head ? KNOD_BLOB_XDP_ADJUST_HEAD : KNOD_BLOB_XDP_ADJUST_TAIL;
	int moves = head ? KNOD_AMDGPU_DATA_VREG_LO :
			   KNOD_AMDGPU_DATA_END_VREG_LO;
	struct amdgcn_param32 dst, src;
	const u32 *code;
	u32 size;

	code = knod_blob_find(&priv->blob, kind, 0, &size);
	if (!code) {
		pr_warn_once("knod_bpf: blob has no %s\n",
			     knod_blob_kind_name(kind));
		return false;
	}

	knod_vset32(&dst, 0);
	knod_sset32(&src, KNOD_AMDGPU_PARAM_SREG_LO);
	knod_mov32(priv, meta, dst, src);
	knod_vset32(&dst, 1);
	knod_sset32(&src, KNOD_AMDGPU_PARAM_SREG_HI);
	knod_mov32(priv, meta, dst, src);
	knod_bpf_mov_pair(priv, meta, 2, KNOD_AMDGPU_PAGE_BASE_VREG_LO);
	knod_bpf_mov_pair(priv, meta, 4, KNOD_AMDGPU_DATA_VREG_LO);
	knod_bpf_mov_pair(priv, meta, 6, KNOD_AMDGPU_DATA_END_VREG_LO);
	knod_vset32(&dst, 8);
	knod_vset32(&src, KNOD_AMDGPU_OFF_VREG);
	knod_mov32(priv, meta, dst, src);
	knod_vset32(&dst, 9);
	knod_mov32(priv, meta, dst, bpf_reg64[BPF_REG_2].lo);
	knod_vset32(&dst, 10);
	knod_iset32(&src, SKB_DATA_ALIGN(sizeof(struct skb_shared_info)));
	knod_mov32(priv, meta, dst, src);

	knod_bpf_emit_call(priv, meta, code, size);

	knod_bpf_mov_pair(priv, meta, KNOD_BPF_VREG(BPF_REG_0), 0);
	knod_bpf_mov_pair(priv, meta, moves, 2);
	return true;
}

/* BPF_DIV and BPF_MOD, by the blob's routines - the GPU has no divide: the
 * dividend in v[0:1], the divisor - src, or the immediate sign-extended - in
 * v[2:3], the result back in v[0:1].
 */
static bool knod_bpf_divmod_call(struct knod_bpf_priv *priv,
				 struct knod_insn_meta *meta, bool mod)
{
	static const u32 kinds[2][2][2] = {	/* [signed][mod][64-bit] */
		{ { KNOD_BLOB_DIV32, KNOD_BLOB_DIV64 },
		  { KNOD_BLOB_MOD32, KNOD_BLOB_MOD64 } },
		{ { KNOD_BLOB_SDIV32, KNOD_BLOB_SDIV64 },
		  { KNOD_BLOB_SMOD32, KNOD_BLOB_SMOD64 } },
	};
	bool alu64 = BPF_CLASS(meta->insn.code) == BPF_ALU64;
	int d = meta->insn.dst_reg, s = meta->insn.src_reg;
	u32 kind = kinds[meta->insn.off == 1][mod][alu64];
	struct amdgcn_param32 dst, imm;
	const u32 *code;
	u32 size;

	code = knod_blob_find(&priv->blob, kind, 0, &size);
	if (!code) {
		pr_warn_once("knod_bpf: blob has no %s\n",
			     knod_blob_kind_name(kind));
		return false;
	}

	knod_bpf_mov_pair(priv, meta, 0, KNOD_BPF_VREG(d));
	if (BPF_SRC(meta->insn.code) == BPF_X) {
		knod_bpf_mov_pair(priv, meta, 2, KNOD_BPF_VREG(s));
	} else {
		knod_vset32(&dst, 2);
		knod_iset32(&imm, meta->insn.imm);
		knod_mov32(priv, meta, dst, imm);
		knod_vset32(&dst, 3);
		knod_iset32(&imm, meta->insn.imm < 0 ? -1 : 0);
		knod_mov32(priv, meta, dst, imm);
	}

	knod_bpf_emit_call(priv, meta, code, size);
	knod_bpf_mov_pair(priv, meta, KNOD_BPF_VREG(d), 0);
	return true;
}

/* @size bytes of @cache at @off, zero-extended into one 32-bit register.
 *
 * Three bytes have no load of their own.  Where they fit inside a dword the
 * bitfield extract takes them; where they straddle one, the dword load brings
 * the byte past the end along and it is masked off.  That byte matters: a key
 * is hashed a dword at a time and the host hashed only the key, so anything
 * carried in past its end lands the two on different buckets.
 */
/* Both accessors below reach exactly two consecutive dwords, cache[off / 4]
 * and the one after it, so a two-register window is all it takes to run them
 * unchanged against a stack that lives in scratch.  Returning the window
 * biased by the dword index is what lets the bodies keep indexing absolutely.
 */
/* Where a stack byte lives in LDS.  The stack is the top max_stack_off bytes of
 * the 512, laid out slot-major - every lane's dword N side by side - so the
 * offset is the slot's distance from the bottom of what is used, times the
 * workgroup.  The size check at finalisation keeps this under sixteen bits.
 */
static u16 knod_bpf_lds_off(struct knod_bpf_priv *priv,
			    struct knod_insn_meta *meta, int off)
{
	if (off < priv->lds_stack_base)
		pr_warn("knod_bpf: stack byte %d is below the tracked base %d (max_stack_off %d) at bpf insn %d code 0x%02x off %d\n",
			off, priv->lds_stack_base,
			priv->knod_prog ? priv->knod_prog->max_stack_off : -1,
			meta->bpf_insn_idx, meta->insn.code, meta->insn.off);
	return (off - priv->lds_stack_base) * priv->wg_size;
}

static struct amdgcn_param32 *knod_bpf_stack_win(struct knod_bpf_priv *priv,
						 struct knod_insn_meta *meta,
						 struct amdgcn_param32 *win,
						 int off, bool load)
{
	knod_vset32(&win[0],
		    knod_bpf_lds_vreg(priv, KNOD_AMDGPU_STACK_WIN_VREG0));
	knod_vset32(&win[1],
		    knod_bpf_lds_vreg(priv, KNOD_AMDGPU_STACK_WIN_VREG1));

	if (load && priv->stack_scratch) {
		int o = (off & ~3) - priv->lds_stack_base;

		knod_emit(priv, meta, scratch_load_dword, win[0], o);
		knod_emit(priv, meta, scratch_load_dword, win[1], o + 4);
		knod_wait_vmcnt(priv, meta);
	} else if (load) {
		struct amdgcn_param32 base;

		knod_vset32(&base,
			    knod_bpf_lds_vreg(priv,
					       KNOD_AMDGPU_LDS_BASE_VREG));
		knod_emit(priv, meta, ds_read_b32, win[0], base,
			  knod_bpf_lds_off(priv, meta, off & ~3));
		knod_emit(priv, meta, ds_read_b32, win[1], base,
			  knod_bpf_lds_off(priv, meta, (off & ~3) + 4));
		knod_emit(priv, meta, s_waitcnt_lgkmcnt);
	}

	return win - (off / 4);
}

static void knod_bpf_stack_win_flush(struct knod_bpf_priv *priv,
				     struct knod_insn_meta *meta,
				     struct amdgcn_param32 *win, int off)
{
	struct amdgcn_param32 base;

	if (priv->stack_scratch) {
		int o = (off & ~3) - priv->lds_stack_base;

		knod_emit(priv, meta, scratch_store_dword, win[0], o);
		knod_emit(priv, meta, scratch_store_dword, win[1], o + 4);
		return;
	}
	knod_vset32(&base,
		    knod_bpf_lds_vreg(priv, KNOD_AMDGPU_LDS_BASE_VREG));
	knod_emit(priv, meta, ds_write_b32, base, win[0],
		  knod_bpf_lds_off(priv, meta, off & ~3));
	knod_emit(priv, meta, ds_write_b32, base, win[1],
		  knod_bpf_lds_off(priv, meta, (off & ~3) + 4));
}

static void __knod_bpf_load_size32(struct knod_bpf_priv *priv,
				   struct knod_insn_meta *meta,
				   struct amdgcn_param32 dst,
				   struct amdgcn_param32 *cache,
				   int size, int off);

static void knod_bpf_load_size32(struct knod_bpf_priv *priv,
				 struct knod_insn_meta *meta,
				 struct amdgcn_param32 dst,
				 struct amdgcn_param32 *cache,
				 int size, int off)
{
	struct amdgcn_param32 win[2];

	if (cache == stack)
		cache = knod_bpf_stack_win(priv, meta, win, off, true);

	__knod_bpf_load_size32(priv, meta, dst, cache, size, off);
}

static void __knod_bpf_load_size32(struct knod_bpf_priv *priv,
				 struct knod_insn_meta *meta,
				 struct amdgcn_param32 dst,
				 /* packet or stack */
				 struct amdgcn_param32 *cache,
				 int size, int off)
{
	struct amdgcn_param32 p32[2];

	if (size == 3 && (off % 4) <= 1) {
		knod_iset32(&p32[0], (off % 4) * 8);
		knod_iset32(&p32[1], 24);
		knod_bfe32(priv, meta, dst, cache[off / 4], p32[0], p32[1]);
		return;
	}

	switch (size) {
	case 3:
	case sizeof(unsigned int):
		if ((off % 4) == 0) {
			knod_mov32(priv, meta, dst, cache[off / 4]);
		} else if ((off % 4) == 1) {
			knod_iset32(&p32[0], 8);
			knod_lshrrev32(priv, meta, r32[0], p32[0],
					   cache[off / 4]);
			knod_iset32(&p32[0], 24);
			knod_lshlrev32(priv, meta, dst, p32[0],
					   cache[(off / 4) + 1]);
			knod_or32(priv, meta, dst, dst, r32[0]);
		} else if ((off % 4) == 2) {
			knod_iset32(&p32[0], 16);
			knod_lshrrev32(priv, meta, r32[0], p32[0],
					   cache[off / 4]);
			knod_lshlrev32(priv, meta, dst, p32[0],
					   cache[(off / 4) + 1]);
			knod_or32(priv, meta, dst, dst, r32[0]);
		} else {
			knod_iset32(&p32[0], 24);
			knod_lshrrev32(priv, meta, r32[0], p32[0],
					   cache[off / 4]);
			knod_iset32(&p32[0], 8);
			knod_lshlrev32(priv, meta, dst, p32[0],
					   cache[(off / 4) + 1]);
			knod_or32(priv, meta, dst, dst, r32[0]);
		}
		if (size == 3) {
			knod_iset32(&p32[0], 0xffffff);
			knod_and32(priv, meta, dst, dst, p32[0]);
		}
		break;
	case sizeof(unsigned short):
		if ((off % 4) == 3) {
			knod_iset32(&p32[0], 24);
			knod_iset32(&p32[1], 8);
			knod_bfe32(priv, meta, r64[0].lo, cache[off / 4],
				       p32[0], p32[1]);
			knod_iset32(&p32[0], 0);
			knod_bfe32(priv, meta, r64[0].hi,
				       cache[(off / 4) + 1], p32[0], p32[1]);
			/* dst = (r64[0].hi << 8) | r64[0].lo. */
			knod_emit(priv, meta, v_lshl_or_b32, dst,
				  r64[0].hi, p32[1], r64[0].lo);
		} else {
			if (!(off % 4))
				knod_iset32(&p32[0], 0);
			else if ((off % 4) == 1)
				knod_iset32(&p32[0], 8);
			else if ((off % 4) == 2)
				knod_iset32(&p32[0], 16);
			knod_iset32(&p32[1], 16);
			knod_bfe32(priv, meta, dst, cache[off / 4],
				       p32[0], p32[1]);
		}
		break;
	case sizeof(unsigned char):
		if ((off % 4) == 0)
			knod_iset32(&p32[0], 0);
		else if ((off % 4) == 1)
			knod_iset32(&p32[0], 8);
		else if ((off % 4) == 2)
			knod_iset32(&p32[0], 16);
		else
			knod_iset32(&p32[0], 24);
		knod_iset32(&p32[1], 8);
		knod_bfe32(priv, meta, dst, cache[off / 4], p32[0],
			       p32[1]);
		break;
	default:
		WARN_ON_ONCE(1);
		break;
	}
}

static void knod_bpf_load_size(struct knod_bpf_priv *priv,
			      struct knod_insn_meta *meta,
			      struct amdgcn_param64 *dst,
			      /* packet or stack */
			      struct amdgcn_param32 *cache,
			      int size, int off)
{
	struct amdgcn_param32 p32;

	knod_jit_dbg(" %d: off = %d off_4 = %d size = %d\n", meta->bpf_insn_idx,
		off, off%4, size);

	if (size == sizeof(unsigned long)) {
		knod_bpf_load_size32(priv, meta, dst->lo, cache, 4, off);
		knod_bpf_load_size32(priv, meta, dst->hi, cache, 4, off + 4);
		return;
	}

	knod_bpf_load_size32(priv, meta, dst->lo, cache, size, off);
	knod_iset32(&p32, 0);
	knod_mov32(priv, meta, dst->hi, p32);
}

/* GFX10/11 queues enable unaligned accesses before code is submitted. */
static void knod_bpf_store_packet_imm(struct knod_bpf_priv *priv,
				  struct knod_insn_meta *meta,
				  struct amdgcn_param64 value,
				  struct amdgcn_param64 base, int off, int size)
{
	struct amdgcn_param64 data;

	knod_vset64(&data, KNOD_AMDGPU_TMP_VREG0_LO);
	knod_mov64(priv, meta, data, value);
	if (size == 2)
		knod_emit(priv, meta, global_store_short, data.lo, base.lo, off);
	else if (size == 4)
		knod_emit(priv, meta, global_store_dword, data.lo, base.lo, off);
	else
		knod_emit(priv, meta, global_store_dwordx2, data.lo, base.lo, off);
}

static void knod_bpf_ktime_get_ns(struct knod_bpf_priv *priv,
				 struct knod_insn_meta *meta)
{
	struct amdgcn_param32 p[2];

	knod_sset32(&p[0], KNOD_AMDGPU_TMP_SREG0_LO);
	knod_sset32(&p[1], KNOD_AMDGPU_PARAM_SREG_LO);
	knod_emit(priv, meta, s_load_dwordx2, p[0], p[1],
		  offsetof(struct knod_bpf_param, ktime_ns));

	knod_emit(priv, meta, s_waitcnt_lgkmcnt);

	knod_sset32(&p[0], KNOD_AMDGPU_TMP_SREG0_LO);
	knod_mov32(priv, meta, bpf_reg64[0].lo, p[0]);
	knod_sset32(&p[0], KNOD_AMDGPU_TMP_SREG0_HI);
	knod_mov32(priv, meta, bpf_reg64[0].hi, p[0]);
}


enum knod_blob_op {
	KNOD_BLOB_OP_LOOKUP,
	KNOD_BLOB_OP_UPDATE,
	KNOD_BLOB_OP_DELETE,
};

/* Helper arguments are pointers, not necessarily addresses in the BPF stack.
 * Keep stack and packet reads in their software caches; map values use the
 * runtime BPF address, including any offset already added by the program.
 * R5 is caller-clobbered and is not used by the map emitters.
 */
static void knod_bpf_load_arg32(struct knod_bpf_priv *priv,
				struct knod_insn_meta *meta,
				struct amdgcn_param32 dst,
				int arg, int off, int len)
{
	const struct knod_bpf_reg_state *state =
		arg == 2 ? &meta->kreg : &meta->vreg;
	const struct bpf_reg_state *reg = &state->reg;
	struct amdgcn_param32 tmp = bpf_reg64[5].lo, shift;
	const struct bpf_map *map = reg->map_ptr;
	u32 first = meta->amdgpu_insns;
	bool aligned = false;
	int i;

	if (base_type(reg->type) == PTR_TO_STACK) {
		knod_bpf_load_size32(priv, meta, dst, stack, len,
				     512 + state->stack_off + off);
		return;
	}

	/* GFX10 dword loads require an aligned effective address.  Array
	 * elements and HASH values need their layout included in that proof.
	 * For other addresses use byte loads, never read beyond the argument.
	 */
	if (base_type(reg->type) == PTR_TO_MAP_VALUE && map &&
	    tnum_is_const(reg->var_off)) {
		u64 bias = reg->var_off.value + off;

		if (knod_bpf_map_type_hash(map->map_type))
			aligned = !((knod_bpf_hash_value_off(map->key_size) +
				     bias) & 3);
		else if (map->map_type == BPF_MAP_TYPE_ARRAY ||
			 map->map_type == BPF_MAP_TYPE_PERCPU_ARRAY)
			aligned = !(map->value_size & 3) && !(bias & 3);
	}
	if (aligned && len == 4) {
		knod_emit(priv, meta, global_load_dword, dst,
			  bpf_reg64[arg].lo, off);
		knod_wait_vmcnt(priv, meta);
	} else {
		knod_emit(priv, meta, global_load_ubyte, dst,
			  bpf_reg64[arg].lo, off);
		knod_wait_vmcnt(priv, meta);
		for (i = 1; i < len; i++) {
			knod_emit(priv, meta, global_load_ubyte, tmp,
				  bpf_reg64[arg].lo, off + i);
			knod_wait_vmcnt(priv, meta);
			knod_iset32(&shift, i * 8);
			knod_lshlrev32(priv, meta, tmp, shift, tmp);
			knod_or32(priv, meta, dst, dst, tmp);
		}
	}
	knod_map_bypass_l0(priv, meta, first);
}

static void knod_bpf_load_arg(struct knod_bpf_priv *priv,
			      struct knod_insn_meta *meta,
			      struct amdgcn_param64 *dst,
			      int arg, int off, int len)
{
	struct amdgcn_param32 zero;

	knod_bpf_load_arg32(priv, meta, dst->lo, arg, off, min(len, 4));
	if (len > 4)
		knod_bpf_load_arg32(priv, meta, dst->hi, arg, off + 4, len - 4);
	else {
		knod_iset32(&zero, 0);
		knod_mov32(priv, meta, dst->hi, zero);
	}
}

/* Gather exactly @len bytes into a call's arguments from v@vreg on. */
static void knod_bpf_stage_arg(struct knod_bpf_priv *priv,
			       struct knod_insn_meta *meta, int vreg,
			       int arg, int len)
{
	struct amdgcn_param64 pair;
	int off = 0, n;

	while (len > 0) {
		n = min(len, 8);
		knod_vset64(&pair, vreg);
		knod_bpf_load_arg(priv, meta, &pair, arg, off, n);
		vreg += 2;
		off += n;
		len -= n;
	}
}

/* Which routine does this, if the blob has one.  A value that is not a whole
 * number of dwords has no routine: an array packs its elements value_size
 * apart, so the tail would have to be cut out of a register chosen at run
 * time, which a prebuilt routine cannot do.
 */
static bool knod_bpf_map_blob_kind(const struct knod_bpf_map_obj *obj,
				   enum knod_blob_op op, u32 *kind, u32 *batches)
{
	static const u32 by_type_op[4][3] = {
		[0] = { KNOD_BLOB_LOOKUP_ARRAY, KNOD_BLOB_UPDATE_ARRAY,
			KNOD_BLOB_DELETE_ARRAY },
		[1] = { KNOD_BLOB_LOOKUP_PERCPU_ARRAY,
			KNOD_BLOB_UPDATE_PERCPU_ARRAY,
			KNOD_BLOB_DELETE_PERCPU_ARRAY },
		[2] = { KNOD_BLOB_LOOKUP_HASH, KNOD_BLOB_UPDATE_HASH,
			KNOD_BLOB_DELETE_HASH },
		/* Delete is element-level (values do not matter), so it reuses
		 * the plain-hash routine.  Update writes only this instance's
		 * value slot; the other slots stay zero because the host clears an
		 * element's value region before returning it to the free list.
		 */
		[3] = { KNOD_BLOB_LOOKUP_PERCPU_HASH,
			KNOD_BLOB_UPDATE_PERCPU_HASH,
			KNOD_BLOB_DELETE_HASH },
	};
	unsigned int row;

	switch (obj->map_type) {
	case BPF_MAP_TYPE_ARRAY:
		row = 0;
		*batches = 0;
		break;
	case BPF_MAP_TYPE_PERCPU_ARRAY:
		row = 1;
		*batches = 0;
		break;
	case BPF_MAP_TYPE_HASH:
	case BPF_MAP_TYPE_LRU_HASH:
		row = 2;
		*batches = DIV_ROUND_UP(obj->key_size, 4);
		break;
	case BPF_MAP_TYPE_PERCPU_HASH:
	case BPF_MAP_TYPE_LRU_PERCPU_HASH:
		row = 3;
		*batches = DIV_ROUND_UP(obj->key_size, 4);
		break;
	default:
		return false;
	}

	if (op != KNOD_BLOB_OP_LOOKUP &&
	    (obj->value_size % 4 ||
	     DIV_ROUND_UP(obj->value_size, 4) > KNOD_BLOB_VALUE_CHUNKS_MAX))
		return false;

	*kind = by_type_op[row][op];

	return true;
}

/* Call the prebuilt routine for this map, by the calling convention
 * knod_blob.h sets out: the descriptor in v[0:1], the key from v2 and an
 * update's value after it, the queue in s13, and the result back in v[0:1],
 * which goes to r0.  The routine itself goes in once, after the program, and
 * knod_bpf_link_callees() points the call at it.
 */
static bool knod_bpf_map_op_blob(struct knod_bpf_priv *priv,
				 struct knod_insn_meta *meta,
				 struct knod_bpf_map *knod_map,
				 enum knod_blob_op op)
{
	const struct knod_bpf_map_obj *obj = knod_map->knod_map_obj;
	struct amdgcn_param32 p32[2];
	u32 kind, batches, size;
	const u32 *code;


	if (!knod_bpf_map_blob_kind(obj, op, &kind, &batches))
		return false;

	code = knod_blob_find(&priv->blob, kind, batches, &size);
	if (!code) {
		pr_warn_once("knod_bpf: blob has no %s for a %u-dword key\n",
			     knod_blob_kind_name(kind), batches);
		return false;
	}

	knod_bpf_stage_arg(priv, meta, 2, 2, obj->key_size);
	if (op == KNOD_BLOB_OP_UPDATE) {
		knod_bpf_stage_arg(priv, meta,
				   2 + DIV_ROUND_UP(obj->key_size, 4), 3,
				   obj->value_size);
		knod_vset32(&p32[0], KNOD_BLOB_UPDATE_FLAGS_VREG(
				    DIV_ROUND_UP(obj->key_size, 4)));
		knod_emit(priv, meta, v_mov_b32_e32, p32[0],
			  bpf_reg64[BPF_REG_4].lo);
	}

	knod_vset32(&p32[0], 0);
	knod_iset32(&p32[1], knod_map->desc_gaddr & ~0U);
	knod_emit(priv, meta, v_mov_b32_e32, p32[0], p32[1]);
	knod_vset32(&p32[0], 1);
	knod_iset32(&p32[1], knod_map->desc_gaddr >> 32);
	knod_emit(priv, meta, v_mov_b32_e32, p32[0], p32[1]);

	knod_bpf_emit_call(priv, meta, code, size);
	knod_bpf_mov_pair(priv, meta, KNOD_BPF_VREG(BPF_REG_0), 0);

	return true;
}

/* True if a prebuilt routine took the operation and the emitter below it can
 * be skipped.
 */
static bool knod_bpf_map_op(struct knod_bpf_priv *priv,
			    struct knod_insn_meta *meta, int map_id,
			    enum knod_blob_op op)
{
	struct knod_bpf_map *knod_map = knod_bpf_map_find(priv, map_id);

	if (!knod_map) {
		WARN_ON_ONCE(1);
		return false;
	}

	return knod_bpf_map_op_blob(priv, meta, knod_map, op);
}

/* A percpu value has one instance per queue, and a queue is one workgroup, so
 * the queue id names the instance.  The same step a lookup takes, for the
 * helpers that reach a value without going through one.
 *
 * r64[1] holds the bucket base and r64[3] is free between the bounds check and
 * the address it is about to be used for.
 */
/* The store of a percpu read-modify-write, as one atomic.
 *
 * A percpu value has one instance per queue, and a queue is one workgroup, so
 * the 256 lanes of it all reach the same copy.  Read it, add, write it back and
 * they each read the same number and one of the results survives; the atomic is
 * what makes every lane's addition land.
 *
 * Counting the lanes and sending their total once is cheaper, but needs them
 * to be adding the same thing to the same place.  Where the key was a constant
 * every lane reaches the same element and that holds; where the program looked
 * one up per packet it does not, and a single atomic would put the whole wave's
 * worth on whichever element the lane that sent it had - which still sums to
 * the right total, and took a per-VIP breakdown to notice.
 */
static void knod_bpf_emit_percpu_add(struct knod_bpf_priv *priv,
				     struct knod_insn_meta *meta)
{
	struct amdgcn_param32 v_tmp, v_tmp_hi, v_zero, s_count, s_exec_lo,
			      s_exec_hi;
	const struct knod_insn_meta *alu = meta->percpu_rmw_add;
	bool is_dw = BPF_SIZE(meta->insn.code) == BPF_DW;
	bool fold = meta->percpu_rmw_uniform;
	int d = meta->insn.dst_reg;

	knod_vset32(&v_tmp, KNOD_AMDGPU_TMP_VREG0_LO);
	knod_vset32(&v_tmp_hi, KNOD_AMDGPU_TMP_VREG0_HI);
	knod_sset32(&s_count, KNOD_AMDGPU_TMP_SREG0_LO);
	knod_sset32(&s_exec_lo, AMDGCN_SREG_EXEC_LO);
	knod_sset32(&s_exec_hi, AMDGCN_SREG_EXEC_LO + 1);
	knod_iset32(&v_zero, 0);

	if (meta->percpu_rmw_swapped) {
		/* The add overwrote the register the amount was in, so take it
		 * back off: what is there now is the amount plus what the map
		 * held, and the map's value is still in the other register.
		 */
		knod_emit(priv, meta, v_sub_u32, v_tmp,
			  bpf_reg64[alu->insn.dst_reg].lo,
			  bpf_reg64[alu->insn.src_reg].lo);
	} else if (BPF_SRC(alu->insn.code) == BPF_K) {
		struct amdgcn_param32 v_imm;

		knod_iset32(&v_imm, alu->insn.imm);
		knod_emit(priv, meta, v_mov_b32_e32, v_tmp, v_imm);
	} else {
		knod_emit(priv, meta, v_mov_b32_e32, v_tmp,
			  bpf_reg64[alu->insn.src_reg].lo);
	}

	if (fold) {
		/* Every lane is adding v_tmp to the same place, so the wave's
		 * total is that times how many of them there are, and the
		 * first of them carries it.
		 */
		knod_emit(priv, meta, s_bcnt1_i32_b64,
			  KNOD_AMDGPU_TMP_SREG0_LO, AMDGCN_SREG_EXEC_LO);
		knod_emit(priv, meta, v_mul_lo_u32, v_tmp, s_count, v_tmp);
		knod_emit(priv, meta, v_mbcnt_lo_u32_b32, v_tmp_hi, s_exec_lo,
			  v_zero);
		knod_emit(priv, meta, v_mbcnt_hi_u32_b32, v_tmp_hi, s_exec_hi,
			  v_tmp_hi);
		knod_emit(priv, meta, v_cmp_eq_u32, v_zero, v_tmp_hi);
		/* The count is spent, so the pair it sat in holds the mask. */
		knod_emit(priv, meta, s_and_saveexec_b64,
			  KNOD_AMDGPU_TMP_SREG0_LO, AMDGCN_SREG_VCC_LO);
	}

	if (is_dw) {
		struct amdgcn_param32 v_31;

		/* The pair the x2 atomic adds is one number, low half first,
		 * so a 32-bit amount goes in the low one and its sign in the
		 * high one.
		 */
		knod_iset32(&v_31, 31);
		knod_emit(priv, meta, v_ashrrev_i32, v_tmp_hi, v_31, v_tmp);
		knod_emit(priv, meta, global_atomic_add_x2, v_tmp,
			  bpf_reg64[d].lo, v_tmp, meta->insn.off, 0);
	} else {
		knod_emit(priv, meta, global_atomic_add, v_tmp,
			  bpf_reg64[d].lo, v_tmp, meta->insn.off, 0);
	}

	if (fold)
		knod_emit(priv, meta, s_mov_b64, AMDGCN_SREG_EXEC_LO,
			  KNOD_AMDGPU_TMP_SREG0_LO);
}

static void __knod_bpf_store_cache_size(struct knod_bpf_priv *priv,
					struct knod_insn_meta *meta,
					struct amdgcn_param64 *src,
					struct amdgcn_param32 *cache,
					int size, int off);

static void knod_bpf_store_cache_size(struct knod_bpf_priv *priv,
				      struct knod_insn_meta *meta,
				      struct amdgcn_param64 *src,
				      struct amdgcn_param32 *cache,
				      int size, int off)
{
	struct amdgcn_param32 win[2];

	if (cache != stack) {
		__knod_bpf_store_cache_size(priv, meta, src, cache, size, off);
		return;
	}

	/* Read-modify-write even when the body writes only one of the pair:
	 * the sub-dword cases merge into what is already there.
	 */
	cache = knod_bpf_stack_win(priv, meta, win, off, true);
	__knod_bpf_store_cache_size(priv, meta, src, cache, size, off);
	knod_bpf_stack_win_flush(priv, meta, win, off);
}

static void __knod_bpf_store_cache_size(struct knod_bpf_priv *priv,
				     struct knod_insn_meta *meta,
				     struct amdgcn_param64 *src,
				     /* packet or stack */
				     struct amdgcn_param32 *cache,
				     int size, int off)
{
	struct amdgcn_param32 p32[2];

	knod_jit_dbg(" %d: off = %d off_4 = %d size = %d\n", meta->bpf_insn_idx,
		off, off%4, size);
	WARN_ON(knod_param_is_literal(src->lo) ||
		knod_param_is_literal(src->hi));
	switch (size) {
	case sizeof(unsigned long):
		if ((off % 4) == 0) {
			knod_mov32(priv, meta,
				       cache[off / 4],
				       src->lo);
			knod_mov32(priv, meta,
				       cache[(off / 4) + 1],
				       src->hi);
		} else if ((off % 4) == 1) {
			WARN_ON_ONCE(1);
		} else if ((off % 4) == 2) {
			WARN_ON_ONCE(1);
		} else {
			WARN_ON_ONCE(1);
		}
		break;
	case sizeof(unsigned int):
		if ((off % 4) == 0) {
			knod_mov32(priv, meta,
				       cache[off / 4],
				       src->lo);
		} else if ((off % 4) == 1) {
			knod_iset64(&p64[0], 8);
			knod_lshlrev64(priv, meta, r64[0], p64[0], *src);

			knod_iset32(&p32[0], 0xffffff00);
			knod_mov32(priv, meta, r32[2], p32[0]);
			knod_bfi32(priv, meta, cache[off / 4],
				       r32[2], r64[0].lo, cache[off / 4]);
			knod_iset32(&p32[0], 0x000000ff);
			knod_mov32(priv, meta, r32[2], p32[0]);
			knod_bfi32(priv, meta, cache[(off / 4) + 1], r32[2],
				       r64[0].hi, cache[(off / 4) + 1]);
		} else if ((off % 4) == 2) {
			knod_iset64(&p64[0], 16);
			knod_lshlrev64(priv, meta, r64[0], p64[0], *src);

			knod_iset32(&p32[0], 0xffff0000);
			knod_mov32(priv, meta, r32[2], p32[0]);
			knod_bfi32(priv, meta, cache[off / 4], r32[2],
				       r64[0].lo, cache[off / 4]);
			knod_iset32(&p32[0], 0x0000ffff);
			knod_mov32(priv, meta, r32[2], p32[0]);
			knod_bfi32(priv, meta, cache[(off / 4) + 1], r32[2],
				       r64[0].hi, cache[(off / 4) + 1]);
		} else {
			knod_iset64(&p64[0], 24);
			knod_lshlrev64(priv, meta, r64[0], p64[0], *src);

			knod_iset32(&p32[0], 0xffff0000);
			knod_mov32(priv, meta, r32[2], p32[0]);
			knod_bfi32(priv, meta, cache[off / 4], r32[2],
				       r64[0].lo, cache[off / 4]);
			knod_iset32(&p32[0], 0x00ffffff);
			knod_mov32(priv, meta, r32[2], p32[0]);
			knod_bfi32(priv, meta, cache[(off / 4) + 1], r32[2],
				       r64[0].hi, cache[(off / 4) + 1]);
		}
		break;
	case sizeof(unsigned short):
		if ((off % 4) == 0) {
			knod_iset32(&p32[0], 0x0000ffff);
			knod_mov32(priv, meta, r32[2], p32[0]);
			knod_bfi32(priv, meta, cache[off / 4], r32[2],
				       src->lo, cache[off / 4]);
		} else if ((off % 4) == 1) {
			knod_iset32(&p32[0], 8);
			knod_lshlrev32(priv, meta, r32[0], p32[0],
					   src->lo);
			knod_iset32(&p32[0], 0x00ffff00);
			knod_mov32(priv, meta, r32[2], p32[0]);
			knod_bfi32(priv, meta, cache[off / 4], r32[2],
				       r32[0], cache[off / 4]);
		} else if ((off % 4) == 2) {
			knod_iset32(&p32[0], 16);
			knod_lshlrev32(priv, meta, r32[0], p32[0],
					   src->lo);
			knod_iset32(&p32[0], 0xffff0000);
			knod_mov32(priv, meta, r32[2], p32[0]);
			knod_bfi32(priv, meta, cache[off / 4], r32[2],
				       r32[0], cache[off / 4]);
		} else {
			knod_iset64(&p64[0], 24);
			knod_lshlrev64(priv, meta, r64[0], p64[0], *src);

			knod_iset32(&p32[0], 0xff000000);
			knod_mov32(priv, meta, r32[2], p32[0]);
			knod_bfi32(priv, meta, cache[off / 4], r32[2],
				       r64[0].lo, cache[off / 4]);
			knod_iset32(&p32[0], 0x000000ff);
			knod_mov32(priv, meta, r32[2], p32[0]);
			knod_bfi32(priv, meta, cache[(off / 4) + 1], r32[2],
				       r64[0].hi, cache[(off / 4) + 1]);
		}
		break;
	case sizeof(unsigned char):
		if ((off % 4) == 0) {
			knod_iset32(&p32[0], 0x000000ff);
			knod_mov32(priv, meta, r32[2], p32[0]);
			knod_bfi32(priv, meta, cache[off / 4], r32[2],
				       src->lo, cache[off / 4]);
			return;
		} else if ((off % 4) == 1) {
			knod_iset32(&p32[0], 8);
			knod_lshlrev32(priv, meta, r32[0], p32[0],
					   src->lo);

			knod_iset32(&p32[0], 0x0000ff00);
		} else if ((off % 4) == 2) {
			knod_iset32(&p32[0], 16);
			knod_lshlrev32(priv, meta, r32[0], p32[0],
					   src->lo);

			knod_iset32(&p32[0], 0x00ff0000);
		} else {
			knod_iset32(&p32[0], 24);
			knod_lshlrev32(priv, meta, r32[0], p32[0],
					   src->lo);
			knod_iset32(&p32[0], 0xff000000);
		}

		knod_mov32(priv, meta, r32[2], p32[0]);
		knod_bfi32(priv, meta, cache[off / 4], r32[2], r32[0],
			       cache[off / 4]);
		break;
	default:
		WARN_ON_ONCE(1);
	}
}

static bool knod_meta_is_exit(const struct knod_insn_meta *meta);
static bool knod_bpf_is_retval_move_to_r0(const struct knod_insn_meta *meta);

/*
 * knod_bpf_emit_branch_tail - Emit EXEC mask manipulation after v_cmp for
 * structurized per-lane branching. Replaces the old s_cbranch_vccnz/vccz.
 *
 * For FORWARD_SKIP:
 *   Save jumping lanes -> narrow EXEC -> s_cbranch_execz
 *   (skip if no active lanes)
 *
 * For DIRECT_EXIT:
 *   Compute exit lanes -> update done_mask -> remove from EXEC (no branch)
 *
 * Emits the required EXEC mask manipulation in-place.
 */
static void knod_bpf_emit_direct_exit_retval(struct knod_bpf_priv *priv,
					     struct knod_insn_meta *emit_meta,
					     struct knod_insn_meta *target)
{
	struct amdgcn_param64 dst, src;
	s64 imm;

	if (!target || knod_meta_is_exit(target))
		return;

	if (WARN_ON_ONCE(!knod_bpf_is_retval_move_to_r0(target)))
		return;

	knod_vset64(&dst, KNOD_BPF_VREG(BPF_REG_0));

	switch (target->insn.code) {
	case BPF_ALU | BPF_MOV | BPF_X:
	case BPF_ALU64 | BPF_MOV | BPF_X:
		knod_vset64(&src, KNOD_BPF_VREG(target->insn.src_reg));
		knod_mov64(priv, emit_meta, dst, src);
		break;
	case BPF_ALU | BPF_MOV | BPF_K:
		imm = (u32)target->insn.imm;
		knod_iset64(&src, imm);
		knod_mov64(priv, emit_meta, dst, src);
		break;
	case BPF_ALU64 | BPF_MOV | BPF_K:
		imm = (s64)(s32)target->insn.imm;
		knod_iset64(&src, imm);
		knod_mov64(priv, emit_meta, dst, src);
		break;
	default:
		WARN_ON_ONCE(1);
		break;
	}
}

static void knod_bpf_emit_branch_tail(struct knod_bpf_priv *priv,
				      struct knod_insn_meta *meta,
				      struct knod_prog *knod_prog,
				      short off)
{
	switch (meta->branch_type) {
	case KNOD_BR_FORWARD_SKIP:
		if (meta->jump_neg_op) {
			/* JNE: VCC=0 -> jump, VCC=1 -> fall-through.
			 * Save jump lanes (VCC=0): s[n] = exec & ~vcc
			 */
			knod_emit(priv, meta, s_andn2_b64,
				  meta->exec_save_sreg,
				  AMDGCN_SREG_EXEC_LO,
				  AMDGCN_SREG_VCC_LO);

			/* Keep fall-through (VCC=1): exec = exec & vcc */
			knod_emit(priv, meta, s_and_b64,
				  AMDGCN_SREG_EXEC_LO,
				  AMDGCN_SREG_EXEC_LO,
				  AMDGCN_SREG_VCC_LO);
		} else {
			/* Normal: VCC=1 -> jump, VCC=0 -> fall-through.
			 * Save jump lanes (VCC=1): s[n] = exec & vcc
			 */
			knod_emit(priv, meta, s_and_b64,
				  meta->exec_save_sreg,
				  AMDGCN_SREG_EXEC_LO,
				  AMDGCN_SREG_VCC_LO);

			/* Keep fall-through (VCC=0): exec = exec & ~vcc */
			knod_emit(priv, meta, s_andn2_b64,
				  AMDGCN_SREG_EXEC_LO,
				  AMDGCN_SREG_EXEC_LO,
				  AMDGCN_SREG_VCC_LO);
		}

		/*
		 * No GPU branch.  After the RPO reorder, branch scopes
		 * interleave, so the jumping lanes must flow through every
		 * following block under the EXEC mask and rejoin at their merge
		 * point.  An s_cbranch_execz skipping ahead to the merge would
		 * jump over other scopes' merge points and strand their saved
		 * lanes (EXEC never restored -> act=0).
		 */
		break;

	case KNOD_BR_DIRECT_EXIT:
		if (meta->jump_neg_op) {
			/* JNE: VCC=0 -> exit. exit_lanes = exec & ~vcc */
			knod_emit(priv, meta, s_andn2_b64,
				  KNOD_AMDGPU_TMP_SREG0_LO,
				  AMDGCN_SREG_EXEC_LO,
				  AMDGCN_SREG_VCC_LO);
		} else {
			/* Normal: VCC=1 -> exit. exit_lanes = exec & vcc */
			knod_emit(priv, meta, s_and_b64,
				  KNOD_AMDGPU_TMP_SREG0_LO,
				  AMDGCN_SREG_EXEC_LO,
				  AMDGCN_SREG_VCC_LO);
		}

		/* Keep the lanes that did not take the exit path. */
		knod_emit(priv, meta, s_andn2_b64,
			  KNOD_AMDGPU_TMP_SREG1_LO,
			  AMDGCN_SREG_EXEC_LO,
			  KNOD_AMDGPU_TMP_SREG0_LO);

		/* Replay a shared "r0 = action; exit" target under the
		 * exiting lanes before marking them done.  Otherwise a direct
		 * branch to the common exit can publish stale r0 scratch state.
		 */
		knod_emit(priv, meta, s_mov_b64, AMDGCN_SREG_EXEC_LO,
			  KNOD_AMDGPU_TMP_SREG0_LO);
		knod_bpf_emit_direct_exit_retval(priv, meta, meta->merge_point);

		/* done_mask |= exit_lanes */
		knod_emit(priv, meta, s_or_b64,
			  knod_prog->done_mask_sreg,
			  knod_prog->done_mask_sreg,
			  AMDGCN_SREG_EXEC_LO);

		/* Continue with the non-exit lanes. */
		knod_emit(priv, meta, s_mov_b64, AMDGCN_SREG_EXEC_LO,
			  KNOD_AMDGPU_TMP_SREG1_LO);

		/* No branch - fall through with reduced EXEC.
		 * No fixup needed.
		 */
		meta->jmp_dst = NULL;
		break;

	default:
		WARN_ON_ONCE(1);
		break;
	}
}

/*
 * --- Basic-block CFG analysis (foundation for block reordering) ---
 *
 * The emitter is a linear SIMT machine: instructions run in list order under
 * an EXEC mask.  A *forward* jump is realized by masking off the jumping
 * lanes and restoring them at the merge point.  A *backward* jump has no such
 * realization unless it is a loop (real GPU branch + EXEC convergence, not yet
 * implemented).
 *
 * LLVM tail-sharing and block placement routinely emit jumps that are
 * backward in BPF byte order but are NOT loops - e.g. a UDP bounds check that
 * jumps back to a shared XDP_PASS tail.  Classifying those as "exit" (the
 * jmp_off < 0 heuristic in knod_bpf_analyze_cfg) silently miscompiles them:
 * the jumping lanes exit carrying whatever R0 happened to hold instead of
 * flowing to the real target.
 *
 * The fix is to classify by control-flow, not byte order:
 *   1. partition the instruction stream into basic blocks,
 *   2. build the control-flow graph (successor edges),
 *   3. DFS for a reverse-postorder (RPO) and detect back-edges,
 *   4. no back-edges (a DAG)  -> reorder blocks into RPO so every edge points
 *      forward, then classify by linear position,
 *   5. a real loop is present -> bail (-EOPNOTSUPP) until loop emission lands.
 *
 * Loop emission (step 5) is not implemented yet, so programs containing a
 * loop are rejected with -EOPNOTSUPP.
 */
struct knod_bb {
	struct knod_insn_meta *leader;	/* first instruction of the block */
	struct knod_insn_meta *last;	/* last instruction of the block */
	/* successors: [0] not-taken, [1] taken */
	struct knod_bb *succ[2];
	int n_succ;
	/* reverse-postorder rank, -1 if unreachable */
	int rpo;
	/* DFS color: 0 white, 1 gray, 2 black */
	int dfs;
	bool loop_header;		/* target of a back-edge */
	/* scratch: member of the loop being walked */
	bool in_loop;
	/* immediate dominator (self for entry) */
	struct knod_bb *idom;
};

static bool knod_meta_is_exit(const struct knod_insn_meta *meta)
{
	u8 code = meta->insn.code;

	return code == (BPF_JMP | BPF_EXIT) || code == (BPF_JMP32 | BPF_EXIT);
}

static struct knod_insn_meta *
knod_bpf_next_meta(struct knod_prog *knod_prog, struct knod_insn_meta *meta)
{
	if (!meta || list_is_last(&meta->l, &knod_prog->insns))
		return NULL;

	return list_next_entry(meta, l);
}

static bool knod_bpf_is_retval_move_to_r0(const struct knod_insn_meta *meta)
{
	u8 code;

	/* A movsx is not a plain move. */
	if (!meta || meta->insn.dst_reg != BPF_REG_0 || meta->insn.off)
		return false;

	code = meta->insn.code;
	return code == (BPF_ALU | BPF_MOV | BPF_X) ||
	       code == (BPF_ALU64 | BPF_MOV | BPF_X) ||
	       code == (BPF_ALU | BPF_MOV | BPF_K) ||
	       code == (BPF_ALU64 | BPF_MOV | BPF_K);
}

static bool knod_bpf_is_direct_exit_target(struct knod_prog *knod_prog,
					   struct knod_insn_meta *target)
{
	if (knod_meta_is_exit(target))
		return true;

	if (!knod_bpf_is_retval_move_to_r0(target))
		return false;

	return knod_meta_is_exit(knod_bpf_next_meta(knod_prog, target));
}

static bool knod_meta_is_ja(const struct knod_insn_meta *meta)
{
	u8 code = meta->insn.code;

	return code == (BPF_JMP | BPF_JA | BPF_K) ||
	       code == (BPF_JMP32 | BPF_JA | BPF_K);
}

/* A block ends after a terminator; the next instruction starts a new block. */
static bool knod_meta_is_terminator(const struct knod_insn_meta *meta)
{
	return is_mbpf_cond_jump(meta) || knod_meta_is_ja(meta) ||
	       knod_meta_is_exit(meta);
}

/* Target instruction index of a conditional jump or BPF_JA. */
static short knod_meta_jump_target_idx(const struct knod_insn_meta *meta)
{
	if (meta->insn.code == (BPF_JMP32 | BPF_JA | BPF_K))
		return meta->bpf_insn_idx + meta->insn.imm + 1;
	return meta->bpf_insn_idx + meta->insn.off + 1;
}

static struct knod_bb *knod_bb_of_leader(struct knod_bb *bbs, int n_bbs,
					 const struct knod_insn_meta *meta)
{
	int i;

	for (i = 0; i < n_bbs; i++)
		if (bbs[i].leader == meta)
			return &bbs[i];
	return NULL;
}

/* Resolve the block a conditional jump / BPF_JA at @jmp transfers to. */
static struct knod_bb *knod_bb_jump_target(struct knod_prog *knod_prog,
					   struct knod_bb *bbs, int n_bbs,
					   const struct knod_insn_meta *jmp)
{
	struct knod_insn_meta *tgt;

	tgt = knod_bpf_lookup_meta(knod_prog, knod_meta_jump_target_idx(jmp));
	return tgt ? knod_bb_of_leader(bbs, n_bbs, tgt) : NULL;
}

/*
 * Partition knod_prog->insns into basic blocks.  A leader is the first
 * instruction, any jump target, or the instruction after a terminator.
 * Returns the block count or a negative errno; @bbs holds >= n_insns blocks.
 */
static int knod_bpf_build_bbs(struct knod_prog *knod_prog, struct knod_bb *bbs)
{
	struct knod_insn_meta *meta, *tgt;
	struct knod_bb *cur = NULL;
	int n_bbs = 0;
	short tgt_idx;

	/* Pass A: mark every jump target as a leader. */
	list_for_each_entry(meta, &knod_prog->insns, l)
		meta->flags &= ~FLAG_INSN_IS_JUMP_DST;

	list_for_each_entry(meta, &knod_prog->insns, l) {
		if (!is_mbpf_cond_jump(meta) && !knod_meta_is_ja(meta))
			continue;
		tgt_idx = knod_meta_jump_target_idx(meta);
		tgt = knod_bpf_lookup_meta(knod_prog, tgt_idx);
		if (!tgt) {
			pr_warn("knod_cfg: bpf#%d jump target %d unresolved\n",
				meta->bpf_insn_idx, tgt_idx);
			return -EINVAL;
		}
		tgt->flags |= FLAG_INSN_IS_JUMP_DST;
	}

	/* Pass B: cut the list into blocks. */
	list_for_each_entry(meta, &knod_prog->insns, l) {
		if (!cur || (meta->flags & FLAG_INSN_IS_JUMP_DST)) {
			cur = &bbs[n_bbs++];
			cur->leader = meta;
			cur->n_succ = 0;
		}
		cur->last = meta;

		if (knod_meta_is_terminator(meta))
			/* next instruction starts a new block */
			cur = NULL;
	}

	return n_bbs;
}

/* Build successor edges for every block from its terminator. */
static int knod_bpf_build_edges(struct knod_prog *knod_prog,
				struct knod_bb *bbs, int n_bbs)
{
	struct knod_bb *bb, *fall, *tgt_bb;
	struct knod_insn_meta *last;
	int i;

	for (i = 0; i < n_bbs; i++) {
		bb = &bbs[i];
		last = bb->last;
		bb->n_succ = 0;

		if (knod_meta_is_exit(last))
			continue;			/* no successors */

		/* Successor in list order: block led by the next
		 * instruction.
		 */
		fall = NULL;
		if (!list_is_last(&last->l, &knod_prog->insns))
			fall = knod_bb_of_leader(bbs, n_bbs,
						 list_next_entry(last, l));

		if (is_mbpf_cond_jump(last)) {
			tgt_bb = knod_bb_jump_target(knod_prog, bbs, n_bbs,
						     last);
			if (!fall || !tgt_bb)
				return -EINVAL;
			bb->succ[bb->n_succ++] = fall;		/* not taken */
			bb->succ[bb->n_succ++] = tgt_bb;	/* taken */
		} else if (knod_meta_is_ja(last)) {
			tgt_bb = knod_bb_jump_target(knod_prog, bbs, n_bbs,
						     last);
			if (!tgt_bb)
				return -EINVAL;
			bb->succ[bb->n_succ++] = tgt_bb;
		} else {
			if (!fall)			/* fell off the end */
				return -EINVAL;
			bb->succ[bb->n_succ++] = fall;
		}
	}

	return 0;
}

/*
 * Iterative DFS from the entry block.  Computes a reverse-postorder rank for
 * every reachable block and flags back-edge targets as loop headers.  Returns
 * the number of back-edges in *n_back, or a negative errno.
 */
static int knod_bpf_compute_rpo(struct knod_bb *bbs, int n_bbs,
				struct knod_bb *entry, int *n_back)
{
	struct knod_bb **stack;
	int *cursor;
	int top = 0, post = 0, nb = 0, i;

	for (i = 0; i < n_bbs; i++) {
		bbs[i].dfs = 0;
		bbs[i].rpo = -1;
		bbs[i].loop_header = false;
	}

	stack = kcalloc(n_bbs, sizeof(*stack), GFP_KERNEL);
	cursor = kcalloc(n_bbs, sizeof(*cursor), GFP_KERNEL);
	if (!stack || !cursor) {
		kfree(stack);
		kfree(cursor);
		return -ENOMEM;
	}

	entry->dfs = 1;
	stack[top] = entry;
	cursor[top] = 0;
	top++;

	while (top > 0) {
		struct knod_bb *bb = stack[top - 1];

		if (cursor[top - 1] < bb->n_succ) {
			struct knod_bb *s = bb->succ[cursor[top - 1]++];

			if (s->dfs == 0) {		/* tree edge */
				s->dfs = 1;
				stack[top] = s;
				cursor[top] = 0;
				top++;
			} else if (s->dfs == 1) {	/* gray -> back-edge */
				s->loop_header = true;
				nb++;
			}
			/* s->dfs == 2 -> forward/cross edge, nothing to do */
		} else {
			/* finished: postorder */
			bb->dfs = 2;
			bb->rpo = post++;
			top--;
		}
	}

	/* postorder -> reverse-postorder rank */
	for (i = 0; i < n_bbs; i++)
		if (bbs[i].rpo >= 0)
			bbs[i].rpo = post - 1 - bbs[i].rpo;

	kfree(stack);
	kfree(cursor);
	*n_back = nb;
	return 0;
}

/*
 * Cooper-Harvey-Kennedy dominator intersect: walk the two fingers up the idom
 * chain (toward the entry, which has the lowest RPO) until they meet.
 */
static struct knod_bb *knod_dom_intersect(struct knod_bb *a, struct knod_bb *b)
{
	while (a != b) {
		while (a->rpo > b->rpo)
			a = a->idom;
		while (b->rpo > a->rpo)
			b = b->idom;
	}
	return a;
}

/*
 * Compute the immediate dominator of every reachable block (Cooper, Harvey,
 * Kennedy, "A Simple, Fast Dominance Algorithm").  Iterates over RPO to a
 * fixpoint; bb->idom is the block's immediate dominator, the entry dominating
 * itself.  Requires bb->rpo from knod_bpf_compute_rpo.
 */
static int knod_bpf_compute_dom(struct knod_bb *bbs, int n_bbs,
				struct knod_bb *entry)
{
	struct knod_bb **order;
	int i, k, n_order = 0;
	bool changed;

	order = kcalloc(n_bbs, sizeof(*order), GFP_KERNEL);
	if (!order)
		return -ENOMEM;

	for (i = 0; i < n_bbs; i++) {
		bbs[i].idom = NULL;
		if (bbs[i].rpo >= 0) {
			order[bbs[i].rpo] = &bbs[i];
			n_order++;
		}
	}
	entry->idom = entry;

	do {
		changed = false;

		/* process every reachable block but the entry, in RPO order */
		for (k = 1; k < n_order; k++) {
			struct knod_bb *n = order[k];
			struct knod_bb *new_idom = NULL;
			int b, s;

			/* intersect over already-processed predecessors */
			for (b = 0; b < n_bbs; b++) {
				for (s = 0; s < bbs[b].n_succ; s++) {
					if (bbs[b].succ[s] != n || !bbs[b].idom)
						continue;
					new_idom = new_idom ?
						knod_dom_intersect(&bbs[b],
								   new_idom) :
						&bbs[b];
				}
			}

			if (new_idom && n->idom != new_idom) {
				n->idom = new_idom;
				changed = true;
			}
		}
	} while (changed);

	kfree(order);
	return 0;
}

/* Does block @a dominate block @b?  Walk @b up the idom chain to the entry. */
static bool knod_dom_dominates(struct knod_bb *a, struct knod_bb *b)
{
	for (;;) {
		if (b == a)
			return true;
		if (b->idom == b)	/* reached the entry */
			return false;
		b = b->idom;
	}
}

/*
 * Mark the natural loop body of back-edge @latch->@hdr in bb->in_loop: the
 * header plus every block that reaches the latch without passing through the
 * header, found by walking predecessors back from the latch.  @stack is
 * caller-provided scratch of at least @n_bbs entries.
 */
static void knod_loop_mark_body(struct knod_bb *bbs, int n_bbs,
				struct knod_bb *latch, struct knod_bb *hdr,
				struct knod_bb **stack)
{
	int b, sp, k, top = 0;

	for (k = 0; k < n_bbs; k++)
		bbs[k].in_loop = false;

	hdr->in_loop = true;
	if (latch != hdr) {
		latch->in_loop = true;
		stack[top++] = latch;
	}

	while (top > 0) {
		struct knod_bb *d = stack[--top];

		for (b = 0; b < n_bbs; b++) {
			if (bbs[b].in_loop)
				continue;
			for (sp = 0; sp < bbs[b].n_succ; sp++) {
				if (bbs[b].succ[sp] != d)
					continue;
				bbs[b].in_loop = true;
				stack[top++] = &bbs[b];
				break;
			}
		}
	}
}

/*
 * Detect natural loops from the dominator tree and report their structure.
 *
 * A back-edge is an edge u->v whose target v dominates its source u - v is
 * the loop header, u the latch.  Its natural loop body is the header plus the
 * blocks that reach the latch without passing through the header; an exit edge
 * leaves a body block for a non-body block.
 *
 * Loops are still rejected by the reorder (-EOPNOTSUPP); this only reports what
 * was found (to dmesg, since a rejected program never attaches so /bpf/cfg is
 * unavailable) so the detection can be verified before emission is built.
 */
static int knod_bpf_detect_loops(struct knod_bb *bbs, int n_bbs)
{
	struct knod_bb **stack;
	int u, s, k, n_be = 0;

	stack = kcalloc(n_bbs, sizeof(*stack), GFP_KERNEL);
	if (!stack)
		return -ENOMEM;

	for (u = 0; u < n_bbs; u++) {
		for (s = 0; s < bbs[u].n_succ; s++) {
			struct knod_bb *hdr = bbs[u].succ[s];
			int body = 0, exits = 0, sp;

			if (!knod_dom_dominates(hdr, &bbs[u]))
				continue;	/* not a back-edge */
			n_be++;

			knod_loop_mark_body(bbs, n_bbs, &bbs[u], hdr, stack);

			for (k = 0; k < n_bbs; k++) {
				if (!bbs[k].in_loop)
					continue;
				body++;
				for (sp = 0; sp < bbs[k].n_succ; sp++)
					if (!bbs[k].succ[sp]->in_loop)
						exits++;
			}

			pr_info("knod_loop: back-edge bpf#%d -> bpf#%d (latch->header) body=%d exits=%d\n",
				bbs[u].leader->bpf_insn_idx,
				hdr->leader->bpf_insn_idx, body, exits);
		}
	}

	kfree(stack);

	if (n_be)
		pr_info("knod_loop: %d back-edge(s) - %s\n", n_be,
			n_be == 1 ? "single loop (simple-shape candidate)" :
				    "nested/multiple loops (complex)");
	return 0;
}

/*
 * Block that lanes fall into in list order when the terminator is not taken:
 * the not-taken successor of a conditional jump, or the sole successor of a
 * block that ended only because the next instruction was a leader.  BPF_JA and
 * EXIT have no such successor (control leaves explicitly).
 */
static struct knod_bb *knod_bb_fall_succ(struct knod_bb *bb)
{
	if (knod_meta_is_exit(bb->last) || knod_meta_is_ja(bb->last))
		return NULL;
	return bb->n_succ ? bb->succ[0] : NULL;
}

/*
 * Reorder the instruction list into reverse-postorder so every control-flow
 * edge points forward, and splice in a synthetic BPF_JA wherever a block's
 * not-taken successor no longer follows it in list order.  After this the
 * emitter's forward-only machinery (FORWARD_SKIP / FORWARD_GOTO) handles the
 * whole program - including the backward-in-byte-order, non-loop jumps that
 * the old jmp_off < 0 heuristic miscompiled.
 *
 * Loops (back-edges) are rejected with -EOPNOTSUPP until loop emission lands.
 */
static int knod_bpf_reorder_rpo(struct knod_prog *knod_prog,
				struct knod_bb *bbs, int n_bbs, int n_back)
{
	struct knod_insn_meta *m, *nx, *sj;
	struct knod_bb **order;
	int n_order = 0, r, i, k, idx = 0;
	LIST_HEAD(new_list);

	if (n_back) {
		pr_warn("knod_cfg: %d loop back-edge(s) - block reorder cannot lower loops yet (-EOPNOTSUPP)\n",
			n_back);
		return -EOPNOTSUPP;
	}

	order = kcalloc(n_bbs, sizeof(*order), GFP_KERNEL);
	if (!order)
		return -ENOMEM;

	/* Reachable blocks in RPO, then any unreachable ones so no instruction
	 * is dropped from the list.
	 */
	for (r = 0; r < n_bbs; r++)
		for (i = 0; i < n_bbs; i++)
			if (bbs[i].rpo == r) {
				order[n_order++] = &bbs[i];
				break;
			}
	for (i = 0; i < n_bbs; i++)
		if (bbs[i].rpo < 0)
			order[n_order++] = &bbs[i];

	for (k = 0; k < n_order; k++) {
		struct knod_bb *bb = order[k];
		struct knod_bb *next = (k + 1 < n_order) ? order[k + 1] : NULL;
		struct knod_bb *fall;

		m = bb->leader;
		while (true) {
			nx = (m == bb->last) ? NULL : knod_meta_next(m);
			list_move_tail(&m->l, &new_list);
			if (m == bb->last)
				break;
			m = nx;
		}

		fall = knod_bb_fall_succ(bb);
		if (!fall || (next && next->leader == fall->leader))
			continue;

		/* Not-taken successor no longer adjacent: route it
		 * explicitly.
		 */
		sj = kzalloc_obj(*sj, GFP_KERNEL);
		if (!sj) {
			list_splice(&new_list, &knod_prog->insns);
			kfree(order);
			return -ENOMEM;
		}
		sj->insn.code = BPF_JMP | BPF_JA | BPF_K;
		/* synthetic, never a jump target */
		sj->bpf_insn_idx = -1;
		/* consumed by classify_linear */
		sj->jmp_dst = fall->leader;
		INIT_LIST_HEAD(&sj->l);
		list_add_tail(&sj->l, &new_list);
	}

	list_splice(&new_list, &knod_prog->insns);

	list_for_each_entry(m, &knod_prog->insns, l)
		m->linear_idx = idx++;

	kfree(order);
	return 0;
}

/*
 * Classify branches by linear position after the RPO reorder.  Every edge is
 * now forward, so a conditional jump is FORWARD_SKIP (or DIRECT_EXIT when it
 * targets the exit), and every BPF_JA - real or synthetic - is FORWARD_GOTO
 * (or DIRECT_EXIT).
 */
static int knod_bpf_classify_linear(struct knod_prog *knod_prog)
{
	struct knod_insn_meta *meta, *target;
	short ti;

	list_for_each_entry(meta, &knod_prog->insns, l) {
		if (is_mbpf_cond_jump(meta)) {
			meta->jump_neg_op = (mbpf_op(meta) == BPF_JNE);
			ti = knod_meta_jump_target_idx(meta);
			target = knod_bpf_lookup_meta(knod_prog, ti);
		} else if (knod_meta_is_ja(meta)) {
			/* synthetic JA carries its destination in jmp_dst;
			 * a real BPF_JA is resolved from its offset.
			 */
			if (meta->jmp_dst) {
				target = meta->jmp_dst;
			} else {
				ti = knod_meta_jump_target_idx(meta);
				target = knod_bpf_lookup_meta(knod_prog, ti);
			}
		} else {
			continue;
		}

		if (!target) {
			pr_err("knod_cfg: bpf#%d unresolved branch target\n",
			       meta->bpf_insn_idx);
			return -EINVAL;
		}

		if (target->linear_idx <= meta->linear_idx)
			pr_warn("knod_cfg: bpf#%d -> #%d still backward after reorder (linear %d -> %d)\n",
				meta->bpf_insn_idx, target->bpf_insn_idx,
				meta->linear_idx, target->linear_idx);

		if (knod_bpf_is_direct_exit_target(knod_prog, target)) {
			meta->branch_type = KNOD_BR_DIRECT_EXIT;
			meta->merge_point = target;
			continue;
		}

		meta->branch_type = is_mbpf_cond_jump(meta) ?
			KNOD_BR_FORWARD_SKIP : KNOD_BR_FORWARD_GOTO;
		meta->merge_point = target;
		target->is_merge_point = true;
	}

	return 0;
}

/*
 * Build the basic-block CFG, compute RPO, reorder the instruction list into
 * RPO and insert synthetic jumps.  Returns 0, or a negative errno (a loop
 * yields -EOPNOTSUPP).
 */
static int knod_bpf_build_cfg(struct knod_prog *knod_prog)
{
	struct knod_insn_meta *meta;
	int n_insns = 0, n_bbs, n_back = 0, ret;
	struct knod_bb *bbs;

	list_for_each_entry(meta, &knod_prog->insns, l)
		n_insns++;
	if (!n_insns)
		return 0;

	bbs = kcalloc(n_insns, sizeof(*bbs), GFP_KERNEL);
	if (!bbs)
		return -ENOMEM;

	n_bbs = knod_bpf_build_bbs(knod_prog, bbs);
	if (n_bbs < 0) {
		ret = n_bbs;
		goto out_free;
	}

	ret = knod_bpf_build_edges(knod_prog, bbs, n_bbs);
	if (ret)
		goto out_free;

	ret = knod_bpf_compute_rpo(bbs, n_bbs, &bbs[0], &n_back);
	if (ret)
		goto out_free;

	ret = knod_bpf_compute_dom(bbs, n_bbs, &bbs[0]);
	if (ret)
		goto out_free;

	if (n_back) {
		ret = knod_bpf_detect_loops(bbs, n_bbs);
		if (ret)
			goto out_free;
	}

	/* Hand the block array to the prog for the /bpf/cfg view (freed at
	 * teardown); kept even if the reorder below rejects a loop, so the
	 * rejection can be inspected.
	 */
	kfree(knod_prog->bbs);
	knod_prog->bbs = bbs;
	knod_prog->n_bbs = n_bbs;
	knod_prog->n_back = n_back;

	return knod_bpf_reorder_rpo(knod_prog, bbs, n_bbs, n_back);

out_free:
	kfree(bbs);
	return ret;
}

/*
 * Assign exec_save SGPR pairs to the forward branches, recycling a pair once
 * its merge point has been passed.  The peak concurrent live count is the
 * actual SGPR requirement - usually far less than the total branch count.
 */
static int knod_bpf_alloc_exec_sregs(struct knod_prog *knod_prog)
{
	struct {
		u8 sreg;
		struct knod_insn_meta *merge;
	} live[KNOD_AMDGPU_MAX_EXEC_SAVE_PAIRS];
	u8 free_stack[KNOD_AMDGPU_MAX_EXEC_SAVE_PAIRS];
	int max_pairs, n_live, peak, j;
	struct knod_insn_meta *meta;
	int free_top;

	max_pairs = (KNOD_AMDGPU_EXEC_SAVE_SREG_MAX -
		     knod_prog->exec_save_base + 1) / 2;

	for (free_top = 0; free_top < max_pairs; free_top++)
		free_stack[free_top] = knod_prog->exec_save_base +
			(max_pairs - 1 - free_top) * 2;

	n_live = 0;
	peak = 0;

	list_for_each_entry(meta, &knod_prog->insns, l) {
		/* Reclaim pairs from scopes that merge at this insn */
		for (j = n_live - 1; j >= 0; j--) {
			if (live[j].merge == meta) {
				free_stack[free_top++] = live[j].sreg;
				live[j] = live[--n_live];
			}
		}

		if (meta->branch_type != KNOD_BR_FORWARD_SKIP &&
		    meta->branch_type != KNOD_BR_FORWARD_GOTO)
			continue;

		if (free_top == 0) {
			pr_err("knod_cfg: exec_save exhausted, peak %d concurrent scopes (max %d)\n",
			       peak, max_pairs);
			return -ENOSPC;
		}

		meta->exec_save_sreg = free_stack[--free_top];
		live[n_live].sreg = meta->exec_save_sreg;
		live[n_live].merge = meta->merge_point;
		n_live++;

		if (n_live > peak)
			peak = n_live;
	}

	knod_prog->exec_save_pairs_used = peak;
	pr_debug("knod_cfg: done, peak %d concurrent scopes (total fwd jumps: %d+%d)\n",
		 peak, peak, n_live);
	return 0;
}

/*
 * knod_bpf_analyze_cfg - Classify branches and allocate SGPRs for
 * structurized CFG.
 *
 * Runs before instruction emission. For each conditional branch:
 *   - Backward jump or jump to EXIT -> DIRECT_EXIT (no SGPR needed)
 *   - Forward jump to non-EXIT -> FORWARD_SKIP, allocate SGPR pair
 *
 * The "save jumping lanes" pattern handles crossing scopes correctly:
 *   branch: s_and_b64 s[n], exec, vcc; s_andn2_b64 exec, exec, vcc
 *   merge:  s_or_b64 exec, exec, s[n]
 *
 * For JNE (jump_neg_op): VCC=0 -> jump, so lanes are swapped.
 */
static int knod_bpf_analyze_cfg(struct knod_prog *knod_prog)
{
	int ret;

	/* Build the basic-block CFG, reorder the instruction list into RPO so
	 * every branch is forward (inserting synthetic jumps where a not-taken
	 * successor would no longer be adjacent), then classify each branch by
	 * linear position.  A loop in the program is rejected (-EOPNOTSUPP).
	 */
	ret = knod_bpf_build_cfg(knod_prog);
	if (ret)
		return ret;
	ret = knod_bpf_classify_linear(knod_prog);
	if (ret)
		return ret;

	return knod_bpf_alloc_exec_sregs(knod_prog);
}

/* What every program ends with: a lane that did not return drops, what the
 * program wrote - maps above all - is out before the engine parks for the
 * host to read them, and back to the engine, which acts on the verdicts.
 */
static int knod_bpf_emit_epilogue(struct knod_bpf_priv *priv,
				  struct knod_prog *knod_prog)
{
	struct amdgcn_param32 drop;
	struct knod_insn_meta *meta;

	meta = kzalloc_obj(*meta, GFP_KERNEL);
	if (!meta)
		return -ENOMEM;
	list_add_tail(&meta->l, &knod_prog->post_insns);

	knod_emit(priv, meta, s_andn2_b64, AMDGCN_SREG_EXEC_LO,
		  knod_prog->initial_exec_sreg, knod_prog->done_mask_sreg);
	knod_iset32(&drop, XDP_DROP);
	knod_mov32(priv, meta, bpf_reg64[BPF_REG_0].lo, drop);
	knod_emit(priv, meta, s_mov_b64, AMDGCN_SREG_EXEC_LO,
		  knod_prog->initial_exec_sreg);
	knod_emit(priv, meta, s_waitcnt_vmcnt_lgkmcnt);
	knod_emit(priv, meta, s_waitcnt_store);
	knod_emit(priv, meta, s_setpc_b64, KNOD_BLOB_PRO_RET_SREG);

	if (!knod_bpf_pad_shader(priv, meta, &knod_prog->post_insns))
		return -ENOMEM;

	return 0;
}

#define AMDGCN_SREG_INTEGER_NEG1	193
/* Where an ordered program keeps registers for a parked lane, past the
 * temporaries.
 */
#define KNOD_BPF_SNAP_VREG		(KNOD_AMDGPU_TMP_VREG_MAX + 1)
static_assert(KNOD_BPF_SNAP_VREG + 2 * KNOD_GATE_SNAP_REGS <=
	      KNOD_GDA_VGPR_COUNT);

/* Copy what @resume_at keeps: into the keeping place, or back. */
static void knod_bpf_emit_snap(struct knod_bpf_priv *priv,
			       struct knod_prog *knod_prog,
			       struct knod_insn_meta *meta, bool keep)
{
	struct amdgcn_param32 reg, kept;
	struct amdgcn_param64 kept64;
	int r, k = 0, half, slot;

	for (r = 0; r < MAX_BPF_REG; r++) {
		if (!(knod_prog->gate_snap & BIT(r)))
			continue;
		for (half = 0; half < 2; half++) {
			knod_vset32(&reg, KNOD_BPF_VREG(r) + half);
			knod_vset32(&kept, KNOD_BPF_SNAP_VREG + 2 * k + half);
			if (keep)
				knod_emit(priv, meta, v_mov_b32_e32, kept, reg);
			else
				knod_emit(priv, meta, v_mov_b32_e32, reg, kept);
		}
		k++;
	}
	for (slot = 0; slot < MAX_BPF_STACK / 8; slot++) {
		if (!(knod_prog->gate_snap_stack & BIT_ULL(slot)))
			continue;
		knod_vset64(&kept64, KNOD_BPF_SNAP_VREG + 2 * k);
		if (keep)
			knod_bpf_load_size(priv, meta, &kept64, &stack[0], 8,
					   slot * 8);
		else
			knod_bpf_store_cache_size(priv, meta, &kept64,
						  &stack[0], 8, slot * 8);
		k++;
	}
}
/* The JIT's own rank flag, beside the blob's: active at the gate. */
#define KNOD_BPF_RANK_AT_GATE		0x80000

/* Park the lanes in VCC: off EXEC, done as far as this pass goes, and marked
 * for the engine to run again.
 */
static void knod_bpf_emit_park(struct knod_bpf_priv *priv,
			       struct knod_prog *knod_prog,
			       struct knod_insn_meta *meta)
{
	struct amdgcn_param32 rank, bit;

	knod_vset32(&rank, KNOD_BLOB_PRO_RANK_VREG);
	knod_iset32(&bit, KNOD_BLOB_RANK_PARKED);
	knod_emit(priv, meta, s_or_b64, knod_prog->done_mask_sreg,
		  knod_prog->done_mask_sreg, AMDGCN_SREG_VCC_LO);
	knod_emit(priv, meta, s_andn2_b64, KNOD_AMDGPU_TMP_SREG0_LO,
		  AMDGCN_SREG_EXEC_LO, AMDGCN_SREG_VCC_LO);
	knod_emit(priv, meta, s_mov_b64, AMDGCN_SREG_EXEC_LO,
		  AMDGCN_SREG_VCC_LO);
	knod_emit(priv, meta, v_or_b32_e32, rank, bit, rank);
	knod_emit(priv, meta, s_mov_b64, AMDGCN_SREG_EXEC_LO,
		  KNOD_AMDGPU_TMP_SREG0_LO);
}

/*
 * knod_bpf_plan_order()'s P, in the first pass: the lanes about to write
 * marked, every lane of the wave into the gate, and the ones it parks off
 * EXEC.  The rest of P's lanes go on.
 */
static void knod_bpf_emit_gate(struct knod_bpf_priv *priv,
			       struct knod_prog *knod_prog,
			       struct knod_insn_meta *meta)
{
	struct amdgcn_param32 pass, zero, bit, rank, arg, v0;
	u32 branch, i, n;

	knod_sset32(&pass, KNOD_BLOB_PRO_PASS_SREG);
	knod_iset32(&zero, 0);
	knod_vset32(&rank, KNOD_BLOB_PRO_RANK_VREG);
	knod_vset32(&v0, 0);
	knod_emit(priv, meta, s_cmp_lg_u32, pass, zero);
	branch = meta->amdgpu_insns;
	knod_emit(priv, meta, s_cbranch_scc1, 0);

	/* The lanes at the gate, and, with the ones waiting to come back in
	 * before the last write, the ones about to write.
	 */
	knod_iset32(&bit, KNOD_BPF_RANK_AT_GATE | KNOD_BLOB_RANK_ACTIVE);
	knod_emit(priv, meta, v_or_b32_e32, rank, bit, rank);
	if (knod_prog->n_gate_saves) {
		knod_emit(priv, meta, s_mov_b64, KNOD_AMDGPU_TMP_SREG0_LO,
			  AMDGCN_SREG_EXEC_LO);
		for (i = 0; i < knod_prog->n_gate_saves; i++)
			knod_emit(priv, meta, s_or_b64,
				  KNOD_AMDGPU_TMP_SREG0_LO,
				  KNOD_AMDGPU_TMP_SREG0_LO,
				  knod_prog->gate_saves[i]);
		knod_emit(priv, meta, s_mov_b64, AMDGCN_SREG_EXEC_LO,
			  KNOD_AMDGPU_TMP_SREG0_LO);
		knod_iset32(&bit, KNOD_BLOB_RANK_ACTIVE);
		knod_emit(priv, meta, v_or_b32_e32, rank, bit, rank);
	}
	knod_emit(priv, meta, s_mov_b64, AMDGCN_SREG_EXEC_LO,
		  AMDGCN_SREG_INTEGER_NEG1);
	knod_iset32(&arg, knod_prog->lds_bytes);
	knod_emit(priv, meta, v_mov_b32_e32, v0, arg);
	knod_vset32(&v0, 1);
	knod_sset32(&arg, KNOD_BLOB_ENGINE_SREG + 3);
	knod_emit(priv, meta, v_mov_b32_e32, v0, arg);
	knod_vset32(&v0, 2);
	knod_emit(priv, meta, v_mov_b32_e32, v0, rank);
	knod_bpf_emit_call(priv, meta, priv->gate_code, priv->gate_size);

	knod_vset32(&v0, 0);
	knod_emit(priv, meta, v_cmp_ne_u32, zero, v0);
	knod_emit(priv, meta, s_mov_b64, KNOD_AMDGPU_TMP_SREG1_LO,
		  AMDGCN_SREG_VCC_LO);
	knod_bpf_emit_park(priv, knod_prog, meta);
	/* EXEC: the lanes at the gate that it did not park.  Those it parked
	 * from an exec save are done, so their merge leaves them out.
	 */
	knod_emit(priv, meta, s_mov_b64, AMDGCN_SREG_EXEC_LO,
		  AMDGCN_SREG_INTEGER_NEG1);
	knod_iset32(&bit, KNOD_BPF_RANK_AT_GATE);
	knod_emit(priv, meta, v_and_b32_e32, v0, bit, rank);
	knod_emit(priv, meta, v_cmp_ne_u32, zero, v0);
	knod_emit(priv, meta, s_andn2_b64, AMDGCN_SREG_EXEC_LO,
		  AMDGCN_SREG_VCC_LO, KNOD_AMDGPU_TMP_SREG1_LO);

	for (i = branch + 1, n = 0; i < meta->amdgpu_insns; i++)
		n += meta->amdgpu_insn[i].size;
	emit_s_cbranch_scc1(priv->isa_version, &meta->amdgpu_insn[branch],
			    n / 4);
}

/*
 * The end of an ordered program's prologue: in a pass after the first,
 * straight to where its parked lanes resume (knod_bpf_link_callees() points
 * the jump); in the first, with no gate further in, park every lane but the
 * first of its flow.
 */
static void knod_bpf_emit_order_entry(struct knod_bpf_priv *priv,
				      struct knod_prog *knod_prog,
				      struct knod_insn_meta *meta)
{
	struct amdgcn_param32 pass, zero;
	u32 skip, i, n;

	knod_sset32(&pass, KNOD_BLOB_PRO_PASS_SREG);
	knod_iset32(&zero, 0);
	knod_emit(priv, meta, s_cmp_lg_u32, pass, zero);
	if (knod_prog->gate_at) {
		/* The registers kept at the resume point back first. */
		skip = meta->amdgpu_insns;
		knod_emit(priv, meta, s_cbranch_scc0, 0);
		knod_bpf_emit_snap(priv, knod_prog, meta, false);
		knod_prog->resume_from = meta;
		knod_prog->resume_insn = meta->amdgpu_insns;
		knod_emit(priv, meta, s_branch, 0);
		for (i = skip + 1, n = 0; i < meta->amdgpu_insns; i++)
			n += meta->amdgpu_insn[i].size;
		emit_s_cbranch_scc0(priv->isa_version,
				    &meta->amdgpu_insn[skip], n / 4);
		return;
	}
	knod_prog->resume_from = meta;
	knod_prog->resume_insn = meta->amdgpu_insns;
	knod_emit(priv, meta, s_cbranch_scc1, 0);

	/* Every lane about to write, so every one but its flow's first parks
	 * and runs the whole program again in its turn.
	 */
	knod_prog->resume_at = list_first_entry(&knod_prog->insns,
						struct knod_insn_meta, l);
	knod_prog->n_gate_saves = 0;
	knod_bpf_emit_gate(priv, knod_prog, meta);
}

typedef void (*knod_alu32_fn)(struct knod_bpf_priv *priv,
			      struct knod_insn_meta *meta,
			      struct amdgcn_param32 dst,
			      struct amdgcn_param32 src0,
			      struct amdgcn_param32 src1);

/* The BPF ops that are one GPU instruction on 32 bits, each taking the
 * operand first and the register it changes second: VOP2 takes a literal
 * only in the first.  Subtraction takes them the other way round, so a
 * constant one is the add of its negation.
 */
static const knod_alu32_fn knod_alu32_ops[16] = {
	[BPF_ADD >> 4]	= knod_add32,
	[BPF_MUL >> 4]	= knod_mul_lo32,
	[BPF_AND >> 4]	= knod_and32,
	[BPF_OR >> 4]	= knod_or32,
	[BPF_XOR >> 4]	= knod_xor32,
	[BPF_LSH >> 4]	= knod_lshlrev32,
	[BPF_RSH >> 4]	= knod_lshrrev32,
	[BPF_ARSH >> 4]	= knod_ashrrev32,
};

/* BPF_ALU: the op on the low half, and the high half cleared. */
static void knod_bpf_alu32(struct knod_bpf_priv *priv,
			   struct knod_insn_meta *meta)
{
	struct amdgcn_param64 dst = bpf_reg64[meta->insn.dst_reg];
	u8 op = BPF_OP(meta->insn.code);
	struct amdgcn_param32 src, zero;

	if (BPF_SRC(meta->insn.code) == BPF_X) {
		src = bpf_reg64[meta->insn.src_reg].lo;
		if (op == BPF_SUB)
			knod_sub32(priv, meta, dst.lo, dst.lo, src);
		else
			knod_alu32_ops[op >> 4](priv, meta, dst.lo, src,
						dst.lo);
	} else if (op == BPF_SUB) {
		knod_iset32(&src, (int)(0U - (u32)meta->insn.imm));
		knod_add32(priv, meta, dst.lo, src, dst.lo);
	} else {
		knod_iset32(&src, meta->insn.imm);
		knod_alu32_ops[op >> 4](priv, meta, dst.lo, src, dst.lo);
	}

	knod_iset32(&zero, 0);
	knod_mov32(priv, meta, dst.hi, zero);
}

/* BPF_ALU64's AND, OR and XOR: each half on its own.  An immediate widens
 * signed, so its high half is all ones or nothing, and the op is left out
 * there when that changes nothing.
 */
static void knod_bpf_bitwise64(struct knod_bpf_priv *priv,
			       struct knod_insn_meta *meta)
{
	knod_alu32_fn fn = knod_alu32_ops[BPF_OP(meta->insn.code) >> 4];
	struct amdgcn_param64 dst = bpf_reg64[meta->insn.dst_reg];
	struct amdgcn_param64 src = bpf_reg64[meta->insn.src_reg];
	struct amdgcn_param32 lo, hi;
	int high, identity;

	if (BPF_SRC(meta->insn.code) == BPF_X) {
		fn(priv, meta, dst.lo, src.lo, dst.lo);
		fn(priv, meta, dst.hi, src.hi, dst.hi);
		return;
	}

	knod_iset32(&lo, meta->insn.imm);
	fn(priv, meta, dst.lo, lo, dst.lo);

	high = meta->insn.imm < 0 ? -1 : 0;
	identity = BPF_OP(meta->insn.code) == BPF_AND ? -1 : 0;
	if (high != identity) {
		knod_iset32(&hi, high);
		fn(priv, meta, dst.hi, hi, dst.hi);
	}
}

/* rN = the low @bits of rN, sign-extended to 64. */
static void knod_bpf_sext(struct knod_bpf_priv *priv,
			  struct knod_insn_meta *meta, int r, int bits)
{
	struct amdgcn_param32 lo, hi, sh;

	knod_vset32(&lo, KNOD_BPF_VREG(r));
	knod_vset32(&hi, KNOD_BPF_VREG(r) + 1);
	if (bits < 32) {
		knod_iset32(&sh, 32 - bits);
		knod_lshlrev32(priv, meta, lo, sh, lo);
		knod_emit(priv, meta, v_ashrrev_i32, lo, sh, lo);
	}
	knod_iset32(&sh, 31);
	knod_emit(priv, meta, v_ashrrev_i32, hi, sh, lo);
}

/* What a BPF-to-BPF call keeps of its caller's r6-r9: to the stack above the
 * callee's frame at the call, back at its return.
 */
static void knod_bpf_emit_subprog_keep(struct knod_bpf_priv *priv,
				       struct knod_insn_meta *meta, bool keep)
{
	int r, k = 0, off;

	for (r = BPF_REG_6; r <= BPF_REG_9; r++) {
		if (!(meta->sub_saves & BIT(r)))
			continue;
		off = MAX_BPF_STACK + meta->sub_save_off + 8 * k++;
		if (keep)
			knod_bpf_store_cache_size(priv, meta, &bpf_reg64[r],
						  &stack[0], 8, off);
		else
			knod_bpf_load_size(priv, meta, &bpf_reg64[r],
					   &stack[0], 8, off);
	}
}

static int knod_bpf_jit(struct knod_dev *knodev,
			struct knod_prog *knod_prog)
{
	struct knod_bpf_priv *priv =
		(struct knod_bpf_priv *)knodev->accel->xdp.priv;
	short off, stack_off;
	struct knod_insn_meta *meta, *meta2;
	struct amdgcn_param64 param64[2];
	u32 insn_idx = 0;
	struct amdgcn_param32 param[3];
	struct amdgcn_param32 p32[2];
	int s, d, imm, imm2, sext;
	bool is_dw, fetch;
	u8 code;
	bool skip = false;
	int atomic_op;
	int map_id;
	u64 imm64;
	u8 sreg;
	int ret;

	/* Analyze CFG before instruction emission */
	ret = knod_bpf_analyze_cfg(knod_prog);

	if (ret)
		return ret;

	ret = knod_prog_prepare_insns(priv, knod_prog);
	if (ret)
		return ret;

	/* Fold the depth again from what will actually be emitted, on the same
	 * test the emitter makes, now that every pointer state is final.  The
	 * per-instruction folds above run inside the verifier hook, where a
	 * store's pointer may not have been seen yet.
	 */
	list_for_each_entry(meta, &knod_prog->insns, l) {
		int depth;

		if (meta->ptr.type != PTR_TO_STACK)
			continue;
		switch (BPF_CLASS(meta->insn.code)) {
		case BPF_LDX:
			depth = meta->sreg.stack_off + meta->insn.off;
			break;
		case BPF_STX:
		case BPF_ST:
			depth = meta->dreg.stack_off + meta->insn.off;
			break;
		default:
			continue;
		}
		if (knod_prog->max_stack_off > depth)
			knod_prog->max_stack_off = depth;
	}
	knod_prog->max_stack_off = -knod_prog->max_stack_off;
	knod_prog->max_stack_off = ALIGN(knod_prog->max_stack_off, 4);
	priv->lds_stack_base = 512 - knod_prog->max_stack_off;
	/* One slot past the top: the window moves two dwords at a time, so the
	 * highest slot's partner lands just beyond the stack, and it has to be
	 * a real, distinct place - not the wrap of a sixteen-bit offset back
	 * onto slot zero.
	 */
	knod_prog->lds_bytes = ALIGN((knod_prog->max_stack_off + 4) *
				     priv->wg_size, 1024);
	/* A stack the workgroup's LDS cannot hold goes to scratch, slower but
	 * of any depth.
	 */
	knod_prog->ordered = knod_bpf_needs_order(knod_prog);
	knod_prog->resume_from = NULL;
	knod_prog->resume_at = NULL;
	knod_prog->gate_at = NULL;
	knod_prog->gate_reach = NULL;
	knod_prog->order_why = NULL;
	knod_prog->gate_snap = 0;
	knod_prog->gate_snap_stack = 0;
	if (knod_prog->ordered)
		knod_bpf_plan_order(knod_prog);
	knod_prog->stack_scratch = priv->knod->lds_size <
		knod_prog->lds_bytes + (knod_prog->ordered ?
					KNOD_PERSIST_GDA_ORDER_LDS_BYTES :
					KNOD_PERSIST_GDA_LDS_BYTES);
	priv->stack_scratch = knod_prog->stack_scratch;
	if (knod_prog->stack_scratch)
		knod_prog->lds_bytes = 0;

	/* Initialize all exec_save SGPRs to 0.
	 * Without this, merge points that restore from exec_save SGPRs
	 * of branches that were skipped (by an outer s_cbranch_execz)
	 * would OR garbage into EXEC, enabling invalid lanes.
	 * In the old code, BPF_EXIT used s_endpgm so execution never
	 * reached those merge points; now it does.
	 *
	 * The whole range, not the part this program uses, so that this is the
	 * same instructions for every program and can be built once.  It costs
	 * nothing: a wave declares all its registers whatever it does with
	 * them, so the ones past the end are not holding anyone back.
	 */
	meta = knod_prog_pre_last_meta(knod_prog);

	for (sreg = KNOD_AMDGPU_EXEC_SAVE_SREG_BASE;
	     sreg < KNOD_AMDGPU_EXEC_SAVE_SREG_MAX;
	     sreg += 2)
		knod_emit(priv, meta, s_mov_b64, sreg,
			  AMDGCN_SREG_INTEGER_0);
	if (knod_prog->ordered)
		knod_bpf_emit_order_entry(priv, knod_prog, meta);

	insn_idx = 0;
	list_for_each_entry(meta, &knod_prog->pre_insns, l)
		insn_idx += knod_meta_bytes(meta) / 4;

	list_for_each_entry(meta, &knod_prog->insns, l) {
		if (skip) {
			skip = false;
			meta->amdgpu_insn_idx = AMDGPU_INSN_SKIP;
			continue;
		}
		s = meta->insn.src_reg;
		d = meta->insn.dst_reg;
		imm = meta->insn.imm;
		off = meta->insn.off;

		meta->amdgpu_insn_idx = insn_idx;
		meta->amdgpu_insns = 0;
		/* Rewinding the cursor has to rewind the call with it, or a
		 * second translation of the same metas keeps a callee from the
		 * first.
		 */
		memset(meta->callee, 0, sizeof(meta->callee));

		/* Structurized CFG: restore EXEC at merge points */
		if (meta->is_merge_point) {
			struct knod_insn_meta *br;

			list_for_each_entry(br, &knod_prog->insns, l) {
				if ((br->branch_type == KNOD_BR_FORWARD_SKIP ||
				     br->branch_type == KNOD_BR_FORWARD_GOTO) &&
				    br->merge_point == meta) {
					knod_emit(priv, meta, s_or_b64,
						  AMDGCN_SREG_EXEC_LO,
						  AMDGCN_SREG_EXEC_LO,
						  br->exec_save_sreg);
				}
			}
			/* Remove done lanes from restored EXEC */
			knod_emit(priv, meta, s_andn2_b64, AMDGCN_SREG_EXEC_LO,
				  AMDGCN_SREG_EXEC_LO,
				  knod_prog->done_mask_sreg);
				}
		if (meta == knod_prog->resume_at && knod_prog->gate_at)
			knod_bpf_emit_snap(priv, knod_prog, meta, true);
		if (meta == knod_prog->gate_at)
			knod_bpf_emit_gate(priv, knod_prog, meta);

		if (meta->percpu_rmw_add) {
			knod_bpf_emit_percpu_add(priv, meta);
			goto insn_emitted;
		}
		if (meta->flags & FLAG_INSN_SUBPROG_RET) {
			knod_bpf_emit_subprog_keep(priv, meta, false);
			goto insn_emitted;
		}

		/* BPF v4's sign-extending load is the load, then the sign. */
		code = meta->insn.code;
		sext = 0;
		if (BPF_CLASS(code) == BPF_LDX && BPF_MODE(code) == BPF_MEMSX) {
			sext = 8 * bpf_size_to_bytes(BPF_SIZE(code));
			code = BPF_LDX | BPF_MEM | BPF_SIZE(code);
		}

		switch (code) {
		/* ALU
		 * If a destination register contains a pointer of STACK,
		 * offset should not be minus.
		 */
		/* A nonzero off is BPF v4's movsx: the low off bits of src,
		 * sign-extended.
		 */
		case BPF_ALU | BPF_MOV | BPF_X:
			if (off && off != 8 && off != 16)
				return -EOPNOTSUPP;
			knod_mov32(priv, meta, bpf_reg64[d].lo, bpf_reg64[s].lo);
			if (off)
				knod_bpf_sext(priv, meta, d, off);
			knod_iset32(&p32[0], 0);
			knod_mov32(priv, meta, bpf_reg64[d].hi, p32[0]);
			break;
		case BPF_ALU64 | BPF_MOV | BPF_X:
			if (off && off != 8 && off != 16 && off != 32)
				return -EOPNOTSUPP;
			knod_mov64(priv, meta, bpf_reg64[d], bpf_reg64[s]);
			if (off)
				knod_bpf_sext(priv, meta, d, off);
			break;
		case BPF_ALU | BPF_MOV | BPF_K:
			knod_iset64(&p64[0], (u32)imm);
			knod_mov64(priv, meta, bpf_reg64[d], p64[0]);
			break;
		case BPF_ALU64 | BPF_MOV | BPF_K:
			knod_iset64(&p64[0], imm);
			knod_mov64(priv, meta, bpf_reg64[d], p64[0]);
			break;
		case BPF_ALU | BPF_ADD | BPF_X:
		case BPF_ALU | BPF_ADD | BPF_K:
		case BPF_ALU | BPF_SUB | BPF_X:
		case BPF_ALU | BPF_SUB | BPF_K:
		case BPF_ALU | BPF_MUL | BPF_X:
		case BPF_ALU | BPF_MUL | BPF_K:
		case BPF_ALU | BPF_AND | BPF_X:
		case BPF_ALU | BPF_AND | BPF_K:
		case BPF_ALU | BPF_OR | BPF_X:
		case BPF_ALU | BPF_OR | BPF_K:
		case BPF_ALU | BPF_XOR | BPF_X:
		case BPF_ALU | BPF_XOR | BPF_K:
		case BPF_ALU | BPF_LSH | BPF_X:
		case BPF_ALU | BPF_LSH | BPF_K:
		case BPF_ALU | BPF_RSH | BPF_X:
		case BPF_ALU | BPF_RSH | BPF_K:
		case BPF_ALU | BPF_ARSH | BPF_X:
		case BPF_ALU | BPF_ARSH | BPF_K:
			knod_bpf_alu32(priv, meta);
			break;
		case BPF_ALU64 | BPF_AND | BPF_X:
		case BPF_ALU64 | BPF_AND | BPF_K:
		case BPF_ALU64 | BPF_OR | BPF_X:
		case BPF_ALU64 | BPF_OR | BPF_K:
		case BPF_ALU64 | BPF_XOR | BPF_X:
		case BPF_ALU64 | BPF_XOR | BPF_K:
			knod_bpf_bitwise64(priv, meta);
			break;
		case BPF_ALU | BPF_MOD | BPF_X:
		case BPF_ALU64 | BPF_MOD | BPF_X:
		case BPF_ALU | BPF_MOD | BPF_K:
		case BPF_ALU64 | BPF_MOD | BPF_K:
			if (!knod_bpf_divmod_call(priv, meta, true))
				return -EOPNOTSUPP;
			break;
		case BPF_ALU | BPF_DIV | BPF_X:
		case BPF_ALU64 | BPF_DIV | BPF_X:
		case BPF_ALU | BPF_DIV | BPF_K:
		case BPF_ALU64 | BPF_DIV | BPF_K:
			if (!knod_bpf_divmod_call(priv, meta, false))
				return -EOPNOTSUPP;
			break;
		case BPF_ALU64 | BPF_ADD | BPF_X:
			knod_add64(priv, meta, bpf_reg64[d], bpf_reg64[d],
				   bpf_reg64[s]);
			break;
		case BPF_ALU64 | BPF_ADD | BPF_K:
			/* The immediate widens signed to the whole register,
			 * and goes through one first: the add that carries
			 * reads VCC without being told to, and a literal cannot
			 * share an instruction with that.
			 */
			knod_iset64(&p64[0], (u64)(s64)imm);
			knod_mov64(priv, meta, r64[0], p64[0]);
			knod_add64(priv, meta, bpf_reg64[d], bpf_reg64[d],
				   r64[0]);
			break;
		case BPF_ALU64 | BPF_SUB | BPF_X:
			knod_sub64(priv, meta, bpf_reg64[d], bpf_reg64[d],
				   bpf_reg64[s]);
			break;
		case BPF_ALU64 | BPF_SUB | BPF_K:
			knod_iset64(&p64[0], (u64)(s64)imm);
			knod_mov64(priv, meta, r64[0], p64[0]);
			knod_sub64(priv, meta, bpf_reg64[d], bpf_reg64[d],
				   r64[0]);
			break;
		case BPF_ALU64 | BPF_MUL | BPF_X:
			knod_mov64(priv, meta, r64[0], bpf_reg64[d]);
			knod_mov64(priv, meta, r64[1], bpf_reg64[s]);
			knod_mul64(priv, meta, bpf_reg64[d], r64[0], r64[1],
				   r64[2]);
			break;
		case BPF_ALU64 | BPF_MUL | BPF_K:
			knod_iset64(&p64[0], (u64)(s64)imm);
			knod_mov64(priv, meta, r64[0], bpf_reg64[d]);
			knod_mov64(priv, meta, r64[1], p64[0]);
			knod_mul64(priv, meta, bpf_reg64[d], r64[0], r64[1],
				   r64[2]);
			break;
		case BPF_ALU | BPF_NEG:
			knod_iset32(&p32[0], 0);
			knod_sub32(priv, meta, bpf_reg64[d].lo, p32[0],
				   bpf_reg64[d].lo);
			knod_mov32(priv, meta, bpf_reg64[d].hi, p32[0]);
			break;
		case BPF_ALU64 | BPF_NEG:
			knod_iset64(&p64[0], 0);
			knod_sub64(priv, meta, bpf_reg64[d], p64[0],
				   bpf_reg64[d]);
			break;
		case BPF_ALU64 | BPF_LSH | BPF_X:
			knod_lshlrev64(priv, meta, bpf_reg64[d], bpf_reg64[s],
				       bpf_reg64[d]);
			break;
		case BPF_ALU64 | BPF_LSH | BPF_K:
			knod_iset64(&p64[0], imm);
			knod_lshlrev64(priv, meta, bpf_reg64[d], p64[0],
				       bpf_reg64[d]);
			break;
		case BPF_ALU64 | BPF_RSH | BPF_X:
			knod_lshrrev64(priv, meta, bpf_reg64[d], bpf_reg64[s],
				       bpf_reg64[d]);
			break;
		case BPF_ALU64 | BPF_RSH | BPF_K:
			knod_iset64(&p64[0], imm);
			knod_lshrrev64(priv, meta, bpf_reg64[d], p64[0],
				       bpf_reg64[d]);
			break;
		case BPF_ALU64 | BPF_ARSH | BPF_X:
			knod_ashrrev64(priv, meta, bpf_reg64[d], bpf_reg64[s],
				       bpf_reg64[d]);
			break;
		case BPF_ALU64 | BPF_ARSH | BPF_K:
			knod_iset64(&p64[0], imm);
			knod_ashrrev64(priv, meta, bpf_reg64[d], p64[0],
				       bpf_reg64[d]);
			break;
		case BPF_LD | BPF_IMM | BPF_DW:
			meta2 = list_next_entry(meta, l);
			if (WARN_ON_ONCE(!meta2))
				return -EINVAL;
			imm2 = meta2->insn.imm;
			skip = true;
			imm64 = (u64)imm2 << 32 | (u32)imm;
			switch (s) {
			case 0x00:
				knod_mov64_imm(priv, meta, KNOD_BPF_VREG(d),
						   imm64);

				break;
			case 0x01:
				imm64 = knod_bpf_get_map_gaddr(priv,
							       meta,
							       meta2);
				map_id = knod_bpf_get_map_id(priv,
							     meta,
							     meta2);
				knod_mov64_imm(priv, meta, KNOD_BPF_VREG(d),
						   imm64);
				break;
			default:
				return -EOPNOTSUPP;
			}
			break;
			/* Legacy BPF packet access, not needed */
		case BPF_LD | BPF_ABS | BPF_B:
		case BPF_LD | BPF_ABS | BPF_H:
		case BPF_LD | BPF_ABS | BPF_W:
		case BPF_LD | BPF_IND | BPF_B:
		case BPF_LD | BPF_IND | BPF_H:
		case BPF_LD | BPF_IND | BPF_W:
			return -EOPNOTSUPP;
		case BPF_LDX | BPF_MEM | BPF_B:
			if (meta->ptr.type == PTR_TO_STACK) {
				stack_off = meta->sreg.stack_off + off;
				knod_bpf_load_size(priv, meta,
						       &bpf_reg64[d],
						       &stack[0],
						       sizeof(unsigned char),
						       512 + stack_off);
			} else if (meta->ptr.type == PTR_TO_CTX) {
				knod_emit(priv, meta, global_load_ubyte,
					  bpf_reg64[d].lo,
					  bpf_reg64[s].lo, off * 2);
			} else if (meta->ptr.type == PTR_TO_MAP_VALUE) {
				knod_emit(priv, meta, global_load_ubyte,
					  bpf_reg64[d].lo,
					  bpf_reg64[s].lo, off);
			} else if (meta->ptr.type == PTR_TO_MAP_KEY) {
				knod_emit(priv, meta, global_load_ubyte,
					  bpf_reg64[d].lo,
					  bpf_reg64[s].lo, off);
			} else if (meta->ptr.type == PTR_TO_PACKET) {
				knod_emit(priv, meta, global_load_ubyte,
					  bpf_reg64[d].lo,
					  bpf_reg64[s].lo, off);
			} else {
				return -EOPNOTSUPP;
			}
			knod_wait_vmcnt(priv, meta);
			knod_iset32(&p32[0], 0);
			knod_mov32(priv, meta, bpf_reg64[d].hi, p32[0]);
			break;
		case BPF_LDX | BPF_MEM | BPF_H:
			if (meta->ptr.type == PTR_TO_STACK) {
				stack_off = meta->sreg.stack_off + off;
				knod_bpf_load_size(priv, meta,
						       &bpf_reg64[d],
						       &stack[0],
						       sizeof(unsigned short),
						       512 + stack_off);
			} else if (meta->ptr.type == PTR_TO_CTX) {
				knod_emit(priv, meta, global_load_ushort,
					  bpf_reg64[d].lo,
					  bpf_reg64[s].lo, off * 2);
			} else if (meta->ptr.type == PTR_TO_MAP_VALUE) {
				knod_emit(priv, meta, global_load_ushort,
					  bpf_reg64[d].lo,
					  bpf_reg64[s].lo, off);
			} else if (meta->ptr.type == PTR_TO_MAP_KEY) {
				knod_emit(priv, meta, global_load_ushort,
					  bpf_reg64[d].lo,
					  bpf_reg64[s].lo, off);
			} else if (meta->ptr.type == SCALAR_VALUE) {
				knod_emit(priv, meta, global_load_ushort,
					  bpf_reg64[d].lo,
					  bpf_reg64[s].lo, off);
			} else if (meta->ptr.type == PTR_TO_PACKET) {
				knod_emit(priv, meta,
					  global_load_ushort,
					  bpf_reg64[d].lo,
					  bpf_reg64[s].lo, off);
			} else {
				knod_jit_err(" type = %d\n", meta->ptr.type);
				return -EOPNOTSUPP;
			}
			knod_iset32(&p32[0], 0);
			knod_mov32(priv, meta, bpf_reg64[d].hi, p32[0]);
			knod_wait_vmcnt(priv, meta);
			break;
		case BPF_LDX | BPF_MEM | BPF_W:
			if (meta->ptr.type == PTR_TO_STACK) {
				stack_off = meta->sreg.stack_off + off;
				knod_bpf_load_size(priv, meta,
						       &bpf_reg64[d],
						       &stack[0],
						       sizeof(unsigned int),
						       512 + stack_off);
			} else if (meta->ptr.type == PTR_TO_CTX) {
				if (off == offsetof(struct xdp_md, data)) {
					knod_mov32(priv, meta,
						bpf_reg64[d].lo,
					    (struct amdgcn_param32){
					    .v = KNOD_AMDGPU_DATA_VREG_LO,
					    .type = AMDGCN_PARAM_TYPE_VGPR});
					knod_mov32(priv, meta,
						bpf_reg64[d].hi,
					    (struct amdgcn_param32){
					    .v = KNOD_AMDGPU_DATA_VREG_HI,
					    .type = AMDGCN_PARAM_TYPE_VGPR});
				} else if (off == offsetof(struct xdp_md,
							   data_end)) {
					knod_mov32(priv, meta,
						bpf_reg64[d].lo,
					    (struct amdgcn_param32){
					    .v = KNOD_AMDGPU_DATA_END_VREG_LO,
					    .type = AMDGCN_PARAM_TYPE_VGPR});
					knod_mov32(priv, meta,
						bpf_reg64[d].hi,
					    (struct amdgcn_param32){
					    .v = KNOD_AMDGPU_DATA_END_VREG_HI,
					    .type = AMDGCN_PARAM_TYPE_VGPR});
				} else {
					emit_global_load_dwordx2(
						priv->isa_version,
						&meta->amdgpu_insn[meta->amdgpu_insns],
						bpf_reg64[d].lo,
						bpf_reg64[s].lo,
						off * 2);
					meta->amdgpu_insns++;
				}
			} else if (meta->ptr.type == PTR_TO_MAP_VALUE) {
				knod_emit(priv, meta, global_load_dword,
					  bpf_reg64[d].lo,
					  bpf_reg64[s].lo, off);
			} else if (meta->ptr.type == PTR_TO_MAP_KEY) {
				knod_emit(priv, meta, global_load_dword,
					  bpf_reg64[d].lo,
					  bpf_reg64[s].lo, off);
			} else if (meta->ptr.type == PTR_TO_PACKET) {
				knod_emit(priv, meta, global_load_dword,
					  bpf_reg64[d].lo,
					  bpf_reg64[s].lo, off);
			} else {
				return -EOPNOTSUPP;
			}
			if (meta->ptr.type != PTR_TO_CTX) {
				knod_iset32(&p32[0], 0);
				knod_mov32(priv, meta, bpf_reg64[d].hi,
					       p32[0]);
			}
			knod_wait_vmcnt(priv, meta);
			break;
		case BPF_LDX | BPF_MEM | BPF_DW:
			if (meta->ptr.type == PTR_TO_STACK) {
				stack_off = meta->sreg.stack_off + off;
				knod_bpf_load_size(priv, meta,
						       &bpf_reg64[d],
						       &stack[0],
						       sizeof(unsigned long),
						       512+stack_off);
			} else if (meta->ptr.type == PTR_TO_CTX) {
				if (off == offsetof(struct xdp_md, data)) {
					knod_mov32(priv, meta,
						bpf_reg64[d].lo,
					    (struct amdgcn_param32){
					    .v = KNOD_AMDGPU_DATA_VREG_LO,
					    .type = AMDGCN_PARAM_TYPE_VGPR});
					knod_mov32(priv, meta,
						bpf_reg64[d].hi,
					    (struct amdgcn_param32){
					    .v = KNOD_AMDGPU_DATA_VREG_HI,
					    .type = AMDGCN_PARAM_TYPE_VGPR});
				} else if (off == offsetof(struct xdp_md,
							   data_end)) {
					knod_mov32(priv, meta,
						bpf_reg64[d].lo,
					    (struct amdgcn_param32){
					    .v = KNOD_AMDGPU_DATA_END_VREG_LO,
					    .type = AMDGCN_PARAM_TYPE_VGPR});
					knod_mov32(priv, meta,
						bpf_reg64[d].hi,
					    (struct amdgcn_param32){
					    .v = KNOD_AMDGPU_DATA_END_VREG_HI,
					    .type = AMDGCN_PARAM_TYPE_VGPR});
				} else {
					knod_emit(priv, meta,
						  global_load_dwordx2,
						  bpf_reg64[d].lo,
						  bpf_reg64[s].lo, off * 2);
				}
			} else if (meta->ptr.type == PTR_TO_MAP_VALUE) {
				knod_emit(priv, meta, global_load_dwordx2,
					  bpf_reg64[d].lo,
					  bpf_reg64[s].lo, off);
			} else if (meta->ptr.type == PTR_TO_MAP_KEY) {
				knod_emit(priv, meta, global_load_dwordx2,
					  bpf_reg64[d].lo,
					  bpf_reg64[s].lo, off);
			} else if (meta->ptr.type == PTR_TO_PACKET) {
				knod_emit(priv, meta,
					  global_load_dwordx2,
					  bpf_reg64[d].lo,
					  bpf_reg64[s].lo, off);
			} else {
				return -EOPNOTSUPP;
			}
			knod_wait_vmcnt(priv, meta);
			break;
		case BPF_STX | BPF_MEM | BPF_B:
			if (meta->ptr.type == PTR_TO_STACK) {
				stack_off = meta->dreg.stack_off + off;
				knod_bpf_store_cache_size(priv, meta,
						&bpf_reg64[s],
						&stack[0],
						sizeof(u8),
						512 + stack_off);
			} else if (meta->ptr.type == PTR_TO_CTX) {
				knod_emit(priv, meta, global_store_byte,
					  bpf_reg64[s].lo,
					  bpf_reg64[d].lo, off * 2);
			} else if (meta->ptr.type == PTR_TO_MAP_VALUE) {
				knod_emit(priv, meta, global_store_byte,
					  bpf_reg64[s].lo,
					  bpf_reg64[d].lo, off);
			} else if (meta->ptr.type == PTR_TO_MAP_KEY) {
				knod_emit(priv, meta, global_store_byte,
					  bpf_reg64[s].lo,
					  bpf_reg64[d].lo, off);
			} else if (meta->ptr.type == PTR_TO_PACKET) {
				knod_emit(priv, meta, global_store_byte,
					  bpf_reg64[s].lo,
					  bpf_reg64[d].lo, off);
			} else {
				return -EOPNOTSUPP;
			}
			break;
		case BPF_STX | BPF_MEM | BPF_H:
			if (meta->ptr.type == PTR_TO_STACK) {
				stack_off = meta->dreg.stack_off + off;
				knod_bpf_store_cache_size(priv, meta,
						&bpf_reg64[s],
						&stack[0],
						sizeof(u16),
						512 + stack_off);
			} else if (meta->ptr.type == PTR_TO_CTX) {
				knod_emit(priv, meta, global_store_short,
					  bpf_reg64[s].lo,
					  bpf_reg64[d].lo, off * 2);
			} else if (meta->ptr.type == PTR_TO_MAP_VALUE) {
				knod_emit(priv, meta, global_store_short,
					  bpf_reg64[s].lo,
					  bpf_reg64[d].lo, off);
			} else if (meta->ptr.type == PTR_TO_MAP_KEY) {
				knod_emit(priv, meta, global_store_short,
					  bpf_reg64[s].lo,
					  bpf_reg64[d].lo, off);
			} else if (meta->ptr.type == PTR_TO_PACKET) {
				knod_emit(priv, meta,
					  global_store_short,
					  bpf_reg64[s].lo,
					  bpf_reg64[d].lo, off);
			} else {
				return -EOPNOTSUPP;
			}
			break;
		case BPF_STX | BPF_MEM | BPF_W:
			if (meta->ptr.type == PTR_TO_STACK) {
				stack_off = meta->dreg.stack_off + off;
				knod_bpf_store_cache_size(priv, meta,
						&bpf_reg64[s],
						&stack[0],
						sizeof(u32),
						512 + stack_off);
			} else if (meta->ptr.type == PTR_TO_CTX) {
				knod_emit(priv, meta, global_store_dword,
					  bpf_reg64[s].lo,
					  bpf_reg64[d].lo, off * 2);
			} else if (meta->ptr.type == PTR_TO_MAP_VALUE) {
				knod_emit(priv, meta, global_store_dword,
					  bpf_reg64[s].lo,
					  bpf_reg64[d].lo, off);
			} else if (meta->ptr.type == PTR_TO_MAP_KEY) {
				knod_emit(priv, meta, global_store_dword,
					  bpf_reg64[s].lo,
					  bpf_reg64[d].lo, off);
			} else if (meta->ptr.type == PTR_TO_PACKET) {
				knod_emit(priv, meta,
					  global_store_dword,
					  bpf_reg64[s].lo,
					  bpf_reg64[d].lo, off);
			} else {
				return -EOPNOTSUPP;
			}
			break;
		case BPF_STX | BPF_MEM | BPF_DW:
			if (meta->ptr.type == PTR_TO_STACK) {
				stack_off = meta->dreg.stack_off + off;
				knod_bpf_store_cache_size(priv, meta,
						&bpf_reg64[s],
						&stack[0],
						sizeof(u64),
						512 + stack_off);
			} else if (meta->ptr.type == PTR_TO_CTX) {
				knod_emit(priv, meta, global_store_dwordx2,
					  bpf_reg64[s].lo,
					  bpf_reg64[d].lo, off * 2);
			} else if (meta->ptr.type == PTR_TO_MAP_VALUE) {
				knod_emit(priv, meta, global_store_dwordx2,
					  bpf_reg64[s].lo,
					  bpf_reg64[d].lo, off);
			} else if (meta->ptr.type == PTR_TO_MAP_KEY) {
				knod_emit(priv, meta, global_store_dwordx2,
					  bpf_reg64[s].lo,
					  bpf_reg64[d].lo, off);
			} else if (meta->ptr.type == PTR_TO_PACKET) {
				knod_emit(priv, meta,
					  global_store_dwordx2,
					  bpf_reg64[s].lo,
					  bpf_reg64[d].lo, off);
			} else {
				return -EOPNOTSUPP;
			}
			break;
		case BPF_STX | BPF_ATOMIC | BPF_W:
		case BPF_STX | BPF_ATOMIC | BPF_DW:
			is_dw = BPF_SIZE(meta->insn.code) == BPF_DW;
			atomic_op = imm & ~BPF_FETCH;
			fetch = imm & BPF_FETCH;

			/*
			 * BPF atomic: *(dst_reg + off) op= src_reg
			 * If BPF_FETCH: src_reg = old value
			 * BPF_CMPXCHG: expect in r0, new in src_reg,
			 *   old value returned in r0.
			 *
			 * global_atomic_* with glc=1 returns old value in vdst.
			 * For non-FETCH ops use glc=0 (fire-and-forget).
			 *
			 * RDNA supports the 64-bit global atomic forms used here.
			 */
			/*
			 * For CMPXCHG/FETCH: drain pending loads so addr/data
			 * VGPRs are ready. For non-fetch ADD wave reduction,
			 * addr was already waited for at map_lookup, and data
			 * is from ALU - no waitcnt needed.
			 */
			if (imm == BPF_CMPXCHG || fetch)
				knod_wait_vmcnt(priv, meta);

			if (imm == BPF_CMPXCHG) {
				/* cmpswap: data = {expect(r0), new(src)}.
				 * AMD cmpswap data reg pair must be
				 * consecutive:
				 *   32-bit: {cmp, new} = 2 consecutive VGPRs
				 *   64-bit: {cmp_lo, cmp_hi, new_lo, new_hi}
				 * Copy r0 and src into TMP consecutive pair.
				 */
				struct amdgcn_param32 tmp0_lo, tmp0_hi,
						      tmp1_lo, tmp1_hi;

				knod_vset32(&tmp0_lo,
					KNOD_AMDGPU_TMP_VREG0_LO);
				knod_vset32(&tmp0_hi,
					KNOD_AMDGPU_TMP_VREG0_HI);
				knod_vset32(&tmp1_lo,
					KNOD_AMDGPU_TMP_VREG1_LO);
				knod_vset32(&tmp1_hi,
					KNOD_AMDGPU_TMP_VREG1_HI);

				if (!is_dw) {
					/* TMP0_LO = r0 (expect),
					 * TMP0_HI = src (new)
					 */
					knod_mov32(priv, meta,
						       tmp0_lo,
						       bpf_reg64[0].lo);
					knod_mov32(priv, meta,
						       tmp0_hi,
						       bpf_reg64[s].lo);

					emit_global_atomic_cmpswap(
						priv->isa_version,
						&meta->amdgpu_insn[meta->amdgpu_insns],
						tmp0_lo, bpf_reg64[d].lo,
						tmp0_lo, off, 1);
					meta->amdgpu_insns++;
					knod_wait_vmcnt(priv, meta);
					/* Return old value in r0 */
					knod_mov32(priv, meta,
						       bpf_reg64[0].lo,
						       tmp0_lo);
				} else {
					/* 64-bit:
					 * {r0_lo, r0_hi, src_lo, src_hi}
					 */
					knod_mov32(priv, meta,
						       tmp0_lo,
						       bpf_reg64[0].lo);
					knod_mov32(priv, meta,
						       tmp0_hi,
						       bpf_reg64[0].hi);
					knod_mov32(priv, meta,
						       tmp1_lo,
						       bpf_reg64[s].lo);
					knod_mov32(priv, meta,
						       tmp1_hi,
						       bpf_reg64[s].hi);

					emit_global_atomic_cmpswap_x2(
						priv->isa_version,
						&meta->amdgpu_insn[meta->amdgpu_insns],
						tmp0_lo, bpf_reg64[d].lo,
						tmp0_lo, off, 1);
					meta->amdgpu_insns++;
					knod_wait_vmcnt(priv, meta);
					knod_mov32(priv, meta,
						       bpf_reg64[0].lo,
						       tmp0_lo);
					knod_mov32(priv, meta,
						       bpf_reg64[0].hi,
						       tmp0_hi);
				}
			} else if (!fetch && atomic_op == BPF_ADD) {
				/* One atomic per lane.  Counting the lanes and
				 * sending their total once needs them to be
				 * adding the same thing to the same place, and
				 * neither is known here: the amount is always a
				 * register, and the address is whatever each
				 * lane worked out.  It used to be folded anyway
				 * and put the wave's total on one lane's
				 * element.
				 */
				struct amdgcn_param32 v_tmp, v_tmp_hi;

				knod_vset32(&v_tmp, KNOD_AMDGPU_TMP_VREG0_LO);
				knod_vset32(&v_tmp_hi,
					    KNOD_AMDGPU_TMP_VREG0_HI);

				if (is_dw) {
					/* The pair the x2 atomic adds is one
					 * number, low half first.
					 */
					knod_emit(priv, meta, v_mov_b32_e32,
						  v_tmp, bpf_reg64[s].lo);
					knod_emit(priv, meta, v_mov_b32_e32,
						  v_tmp_hi, bpf_reg64[s].hi);
					knod_emit(priv, meta,
						  global_atomic_add_x2, v_tmp,
						  bpf_reg64[d].lo, v_tmp, off,
						  0);
				} else {
					knod_emit(priv, meta, global_atomic_add,
						  v_tmp, bpf_reg64[d].lo,
						  bpf_reg64[s].lo, off, 0);
				}
			} else {
				/* 64-bit: AND, OR, XOR, XCHG, or fetch ops */
				struct amdgcn_param32 vdst, data_p;

				if (fetch) {
					vdst = bpf_reg64[s].lo;
				} else {
					knod_vset32(&vdst,
						KNOD_AMDGPU_TMP_VREG0_LO);
				}
				data_p = bpf_reg64[s].lo;

				switch (atomic_op) {
				case BPF_ADD:
					emit_global_atomic_add_x2(
						priv->isa_version,
						&meta->amdgpu_insn[meta->amdgpu_insns],
						vdst, bpf_reg64[d].lo,
						data_p, off, fetch);
					break;
				case BPF_AND:
					emit_global_atomic_and_x2(
						priv->isa_version,
						&meta->amdgpu_insn[meta->amdgpu_insns],
						vdst, bpf_reg64[d].lo,
						data_p, off, fetch);
					break;
				case BPF_OR:
					emit_global_atomic_or_x2(
						priv->isa_version,
						&meta->amdgpu_insn[meta->amdgpu_insns],
						vdst, bpf_reg64[d].lo,
						data_p, off, fetch);
					break;
				case BPF_XOR:
					emit_global_atomic_xor_x2(
						priv->isa_version,
						&meta->amdgpu_insn[meta->amdgpu_insns],
						vdst, bpf_reg64[d].lo,
						data_p, off, fetch);
					break;
				default: /* BPF_XCHG */
					emit_global_atomic_swap_x2(
						priv->isa_version,
						&meta->amdgpu_insn[meta->amdgpu_insns],
						vdst, bpf_reg64[d].lo,
						data_p, off, fetch);
					break;
				}
				meta->amdgpu_insns++;
				/* Always wait for atomic completion */
				knod_wait_vmcnt(priv, meta);
			}
			break;
		case BPF_ST | BPF_MEM | BPF_B:
			knod_iset32(&p32[0], imm);
			if (meta->ptr.type == PTR_TO_STACK) {
				stack_off = meta->dreg.stack_off + off;
				knod_iset64(&p64[0], imm);
				knod_bpf_store_cache_size(priv, meta,
						&p64[0],
						&stack[0],
						sizeof(u8),
						512 + stack_off);
			} else if (meta->ptr.type == PTR_TO_CTX) {
				knod_emit(priv, meta, global_store_byte, p32[0],
					  bpf_reg64[d].lo, off * 2);
			} else if (meta->ptr.type == PTR_TO_MAP_VALUE) {
				knod_emit(priv, meta, global_store_byte, p32[0],
					  bpf_reg64[d].lo, off);
			} else if (meta->ptr.type == PTR_TO_MAP_KEY) {
				knod_emit(priv, meta, global_store_byte, p32[0],
					  bpf_reg64[d].lo, off);
			} else if (meta->ptr.type == PTR_TO_PACKET) {
				knod_iset64(&p64[0], imm);
				knod_emit(priv, meta, global_store_byte,
					  p64[0].lo,
					  bpf_reg64[d].lo, off);
			} else {
				return -EOPNOTSUPP;
			}
			break;
		case BPF_ST | BPF_MEM | BPF_H:
			knod_iset32(&p32[0], imm);
			if (meta->ptr.type == PTR_TO_STACK) {
				stack_off = meta->dreg.stack_off + off;
				knod_iset64(&p64[0], imm);
				knod_bpf_store_cache_size(priv, meta,
						&p64[0],
						&stack[0],
						sizeof(u16),
						512 + stack_off);
			} else if (meta->ptr.type == PTR_TO_CTX) {
				knod_emit(priv, meta, global_store_short,
					  p32[0], bpf_reg64[d].lo, off * 2);
			} else if (meta->ptr.type == PTR_TO_MAP_VALUE) {
				knod_emit(priv, meta, global_store_short,
					  p32[0], bpf_reg64[d].lo, off);
			} else if (meta->ptr.type == PTR_TO_MAP_KEY) {
				knod_emit(priv, meta, global_store_short,
					  p32[0], bpf_reg64[d].lo, off);
			} else if (meta->ptr.type == PTR_TO_PACKET) {
				knod_iset64(&p64[0], imm);
				if (priv->isa_version == 10 ||
				    priv->isa_version == 11) {
					knod_bpf_store_packet_imm(priv, meta,
						p64[0], bpf_reg64[d], off, 2);
				} else {
					knod_emit(priv, meta,
						  global_store_short, p64[0].lo,
						  bpf_reg64[d].lo, off);
				}
			} else {
				return -EOPNOTSUPP;
			}
			break;
		case BPF_ST | BPF_MEM | BPF_W:
			knod_iset32(&p32[0], imm);
			if (meta->ptr.type == PTR_TO_STACK) {
				stack_off = meta->dreg.stack_off + off;
				knod_iset64(&p64[0], imm);
				knod_bpf_store_cache_size(priv, meta,
						&p64[0],
						&stack[0],
						sizeof(u32),
						512 + stack_off);
			} else if (meta->ptr.type == PTR_TO_CTX) {
				knod_emit(priv, meta, global_store_dword,
					  p32[0], bpf_reg64[d].lo, off * 2);
			} else if (meta->ptr.type == PTR_TO_MAP_VALUE) {
				knod_emit(priv, meta, global_store_dword,
					  p32[0], bpf_reg64[d].lo, off);
			} else if (meta->ptr.type == PTR_TO_MAP_KEY) {
				knod_emit(priv, meta, global_store_dword,
					  p32[0], bpf_reg64[d].lo, off);
			} else if (meta->ptr.type == PTR_TO_PACKET) {
				knod_iset64(&p64[0], imm);
				if (priv->isa_version == 10 ||
				    priv->isa_version == 11) {
					knod_bpf_store_packet_imm(priv, meta,
						p64[0], bpf_reg64[d], off, 4);
				} else {
					knod_emit(priv, meta,
						  global_store_dword, p64[0].lo,
						  bpf_reg64[d].lo, off);
				}
			} else {
				return -EOPNOTSUPP;
			}
			break;
		case BPF_ST | BPF_MEM | BPF_DW:
			knod_iset32(&p32[0], imm);
			if (meta->ptr.type == PTR_TO_STACK) {
				stack_off = meta->dreg.stack_off + off;
				knod_iset64(&p64[0], imm);
				knod_bpf_store_cache_size(priv, meta,
						&p64[0],
						&stack[0],
						sizeof(u64),
						512 + stack_off);
			} else if (meta->ptr.type == PTR_TO_CTX) {
				knod_emit(priv, meta, global_store_dwordx2,
					  p32[0], bpf_reg64[d].lo, off * 2);
			} else if (meta->ptr.type == PTR_TO_MAP_VALUE) {
				knod_emit(priv, meta, global_store_dwordx2,
					  p32[0], bpf_reg64[d].lo, off);
			} else if (meta->ptr.type == PTR_TO_MAP_KEY) {
				knod_emit(priv, meta, global_store_dwordx2,
					  p32[0], bpf_reg64[d].lo, off);
			} else if (meta->ptr.type == PTR_TO_PACKET) {
				knod_iset64(&p64[0], imm);
				if (priv->isa_version == 10 ||
				    priv->isa_version == 11) {
					knod_bpf_store_packet_imm(priv, meta,
						p64[0], bpf_reg64[d], off, 8);
				} else {
					knod_emit(priv, meta,
						  global_store_dwordx2,
						  p64[0].lo,
						  bpf_reg64[d].lo, off);
				}
				knod_iset32(&p32[0], imm);
			} else {
				return -EOPNOTSUPP;
			}
			break;
		case BPF_JMP32 | BPF_JA | BPF_K:
			if (meta->branch_type == KNOD_BR_DIRECT_EXIT) {
				knod_bpf_emit_direct_exit_retval(priv, meta,
						meta->merge_point);

				/* Unconditional goto exit:
				 * all active lanes done
				 */
				knod_emit(priv, meta, s_or_b64,
					  knod_prog->done_mask_sreg,
					  knod_prog->done_mask_sreg,
					  AMDGCN_SREG_EXEC_LO);
				knod_emit(priv, meta, s_mov_b64,
					  AMDGCN_SREG_EXEC_LO,
					  AMDGCN_SREG_INTEGER_0);
			} else if (meta->branch_type == KNOD_BR_FORWARD_GOTO) {
				/* Structurized: save all active lanes, clear
				 * EXEC.  Lanes resume at merge_point (target).
				 */
				knod_emit(priv, meta, s_mov_b64,
					  meta->exec_save_sreg,
					  AMDGCN_SREG_EXEC_LO);
				knod_emit(priv, meta, s_mov_b64,
					  AMDGCN_SREG_EXEC_LO,
					  AMDGCN_SREG_INTEGER_0);
			} else {
				/* Reorder classifies every JA as FORWARD_GOTO
				 * or DIRECT_EXIT; reaching here is a bug.
				 */
				WARN_ON_ONCE(1);
				return -EINVAL;
			}
			break;
		case BPF_JMP | BPF_JA | BPF_K:
			if (meta->branch_type == KNOD_BR_DIRECT_EXIT) {
				knod_bpf_emit_direct_exit_retval(priv, meta,
						meta->merge_point);

				/* Unconditional goto exit:
				 * all active lanes done
				 */
				knod_emit(priv, meta, s_or_b64,
					  knod_prog->done_mask_sreg,
					  knod_prog->done_mask_sreg,
					  AMDGCN_SREG_EXEC_LO);
				knod_emit(priv, meta, s_mov_b64,
					  AMDGCN_SREG_EXEC_LO,
					  AMDGCN_SREG_INTEGER_0);
			} else if (meta->branch_type == KNOD_BR_FORWARD_GOTO) {
				/* Structurized: save all active lanes, clear
				 * EXEC.  Lanes resume at merge_point (target).
				 */
				knod_emit(priv, meta, s_mov_b64,
					  meta->exec_save_sreg,
					  AMDGCN_SREG_EXEC_LO);
				knod_emit(priv, meta, s_mov_b64,
					  AMDGCN_SREG_EXEC_LO,
					  AMDGCN_SREG_INTEGER_0);
			} else {
				/* Reorder classifies every JA as FORWARD_GOTO
				 * or DIRECT_EXIT; reaching here is a bug.
				 */
				WARN_ON_ONCE(1);
				return -EINVAL;
			}
			break;
		case BPF_JMP32 | BPF_JEQ | BPF_K:
			knod_vset32(&param[0], KNOD_AMDGPU_TMP_VREG0_LO);
			knod_iset32(&param[1], imm);
			knod_emit(priv, meta, v_mov_b32_e32, param[0],
				  param[1]);
			knod_vset32(&param[0], KNOD_BPF_VREG(d));
			knod_vset32(&param[1], KNOD_AMDGPU_TMP_VREG0_LO);
			knod_emit(priv, meta, v_cmp_eq_u32, param[0],
				  param[1]);
			knod_bpf_emit_branch_tail(priv, meta, knod_prog, off);
			break;
		case BPF_JMP | BPF_JEQ | BPF_K:
			knod_vset32(&param[0], KNOD_AMDGPU_TMP_VREG0_LO);
			knod_iset32(&param[1], imm);
			knod_emit(priv, meta, v_mov_b32_e32, param[0],
				  param[1]);
			knod_vset32(&param[0], KNOD_AMDGPU_TMP_VREG0_HI);
			knod_iset32(&param[1], (s32)imm < 0 ? U32_MAX : 0);
			knod_emit(priv, meta, v_mov_b32_e32, param[0],
				  param[1]);
			knod_vset32(&param[0], KNOD_BPF_VREG(d));
			knod_vset32(&param[1], KNOD_AMDGPU_TMP_VREG0_LO);
			knod_emit(priv, meta, v_cmp_eq_u64, param[0],
				  param[1]);
			knod_bpf_emit_branch_tail(priv, meta, knod_prog, off);
			break;
		case BPF_JMP32 | BPF_JEQ | BPF_X:
			knod_vset32(&param[0], KNOD_BPF_VREG(d));
			knod_vset32(&param[1], KNOD_BPF_VREG(s));
			knod_emit(priv, meta, v_cmp_eq_u32, param[0],
				  param[1]);
			knod_bpf_emit_branch_tail(priv, meta, knod_prog, off);
			break;
		case BPF_JMP | BPF_JEQ | BPF_X:
			knod_vset32(&param[0], KNOD_BPF_VREG(d));
			knod_vset32(&param[1], KNOD_BPF_VREG(s));
			knod_emit(priv, meta, v_cmp_eq_u64, param[0],
				  param[1]);
			knod_bpf_emit_branch_tail(priv, meta, knod_prog, off);
			break;
		case BPF_JMP32 | BPF_JGT | BPF_K:
			knod_vset32(&param[0], KNOD_AMDGPU_TMP_VREG0_LO);
			knod_iset32(&param[1], imm);
			knod_emit(priv, meta, v_mov_b32_e32, param[0],
				  param[1]);
			knod_vset32(&param[0], KNOD_BPF_VREG(d));
			knod_vset32(&param[1], KNOD_AMDGPU_TMP_VREG0_LO);
			knod_emit(priv, meta, v_cmp_gt_u32, param[0],
				  param[1]);
			knod_bpf_emit_branch_tail(priv, meta, knod_prog, off);
			break;
		case BPF_JMP | BPF_JGT | BPF_K:
			knod_vset32(&param[0], KNOD_AMDGPU_TMP_VREG0_LO);
			knod_iset32(&param[1], imm);
			knod_emit(priv, meta, v_mov_b32_e32, param[0],
				  param[1]);
			knod_vset32(&param[0], KNOD_AMDGPU_TMP_VREG0_HI);
			knod_iset32(&param[1], (s32)imm < 0 ? U32_MAX : 0);
			knod_emit(priv, meta, v_mov_b32_e32, param[0],
				  param[1]);
			knod_vset64(&param64[0], KNOD_BPF_VREG(d));
			knod_vset64(&param64[1], KNOD_AMDGPU_TMP_VREG0_LO);
			knod_emit(priv, meta, v_cmp_gt_u64, param64[0],
				  param64[1]);
			knod_bpf_emit_branch_tail(priv, meta, knod_prog, off);
			break;
		case BPF_JMP32 | BPF_JGT | BPF_X:
			knod_vset32(&param[0], KNOD_BPF_VREG(d));
			knod_vset32(&param[1], KNOD_BPF_VREG(s));
			knod_emit(priv, meta, v_cmp_gt_u32, param[0],
				  param[1]);
			knod_bpf_emit_branch_tail(priv, meta, knod_prog, off);
			break;
		case BPF_JMP | BPF_JGT | BPF_X:
			knod_vset64(&param64[0], KNOD_BPF_VREG(d));
			knod_vset64(&param64[1], KNOD_BPF_VREG(s));
			knod_emit(priv, meta, v_cmp_gt_u64, param64[0],
				  param64[1]);
			knod_bpf_emit_branch_tail(priv, meta, knod_prog, off);
			break;
		case BPF_JMP32 | BPF_JGE | BPF_K:
			knod_vset32(&param[0], KNOD_AMDGPU_TMP_VREG0_LO);
			knod_iset32(&param[1], imm);
			knod_emit(priv, meta, v_mov_b32_e32, param[0],
				  param[1]);
			knod_vset32(&param[0], KNOD_BPF_VREG(d));
			knod_vset32(&param[1], KNOD_AMDGPU_TMP_VREG0_LO);
			knod_emit(priv, meta, v_cmp_ge_u32, param[0],
				  param[1]);
			knod_bpf_emit_branch_tail(priv, meta, knod_prog, off);
			break;
		case BPF_JMP | BPF_JGE | BPF_K:
			knod_vset32(&param[0], KNOD_AMDGPU_TMP_VREG0_LO);
			knod_iset32(&param[1], imm);
			knod_emit(priv, meta, v_mov_b32_e32, param[0],
				  param[1]);
			knod_vset32(&param[0], KNOD_AMDGPU_TMP_VREG0_HI);
			knod_iset32(&param[1], (s32)imm < 0 ? U32_MAX : 0);
			knod_emit(priv, meta, v_mov_b32_e32, param[0],
				  param[1]);
			knod_vset64(&param64[0], KNOD_BPF_VREG(d));
			knod_vset64(&param64[1], KNOD_AMDGPU_TMP_VREG0_LO);
			knod_emit(priv, meta, v_cmp_ge_u64, param64[0],
				  param64[1]);
			knod_bpf_emit_branch_tail(priv, meta, knod_prog, off);
			break;
		case BPF_JMP32 | BPF_JGE | BPF_X:
			knod_vset32(&param[0], KNOD_BPF_VREG(d));
			knod_vset32(&param[1], KNOD_BPF_VREG(s));
			knod_emit(priv, meta, v_cmp_ge_u32, param[0],
				  param[1]);
			knod_bpf_emit_branch_tail(priv, meta, knod_prog, off);
			break;
		case BPF_JMP | BPF_JGE | BPF_X:
			knod_vset64(&param64[0], KNOD_BPF_VREG(d));
			knod_vset64(&param64[1], KNOD_BPF_VREG(s));
			knod_emit(priv, meta, v_cmp_ge_u64, param64[0],
				  param64[1]);
			knod_bpf_emit_branch_tail(priv, meta, knod_prog, off);
			break;
		case BPF_JMP32 | BPF_JLT | BPF_K:
			knod_vset32(&param[0], KNOD_AMDGPU_TMP_VREG0_LO);
			knod_iset32(&param[1], imm);
			knod_emit(priv, meta, v_mov_b32_e32, param[0],
				  param[1]);
			knod_vset32(&param[0], KNOD_BPF_VREG(d));
			knod_vset32(&param[1], KNOD_AMDGPU_TMP_VREG0_LO);
			knod_emit(priv, meta, v_cmp_lt_u32, param[0],
				  param[1]);
			knod_bpf_emit_branch_tail(priv, meta, knod_prog, off);
			break;
		case BPF_JMP | BPF_JLT | BPF_K:
			knod_vset32(&param[0], KNOD_AMDGPU_TMP_VREG0_LO);
			knod_iset32(&param[1], imm);
			knod_emit(priv, meta, v_mov_b32_e32, param[0],
				  param[1]);
			knod_vset32(&param[0], KNOD_AMDGPU_TMP_VREG0_HI);
			knod_iset32(&param[1], (s32)imm < 0 ? U32_MAX : 0);
			knod_emit(priv, meta, v_mov_b32_e32, param[0],
				  param[1]);
			knod_vset64(&param64[0], KNOD_BPF_VREG(d));
			knod_vset64(&param64[1], KNOD_AMDGPU_TMP_VREG0_LO);
			knod_emit(priv, meta, v_cmp_lt_u64, param64[0],
				  param64[1]);
			knod_bpf_emit_branch_tail(priv, meta, knod_prog, off);
			break;
		case BPF_JMP32 | BPF_JLT | BPF_X:
			knod_vset32(&param[0], KNOD_BPF_VREG(d));
			knod_vset32(&param[1], KNOD_BPF_VREG(s));
			knod_emit(priv, meta, v_cmp_lt_u32, param[0],
				  param[1]);
			knod_bpf_emit_branch_tail(priv, meta, knod_prog, off);
			break;
		case BPF_JMP | BPF_JLT | BPF_X:
			knod_vset64(&param64[0], KNOD_BPF_VREG(d));
			knod_vset64(&param64[1], KNOD_BPF_VREG(s));
			knod_emit(priv, meta, v_cmp_lt_u64, param64[0],
				  param64[1]);
			knod_bpf_emit_branch_tail(priv, meta, knod_prog, off);
			break;
		case BPF_JMP32 | BPF_JLE | BPF_K:
			knod_vset32(&param[0], KNOD_AMDGPU_TMP_VREG0_LO);
			knod_iset32(&param[1], imm);
			knod_emit(priv, meta, v_mov_b32_e32, param[0],
				  param[1]);
			knod_vset32(&param[0], KNOD_BPF_VREG(d));
			knod_vset32(&param[1], KNOD_AMDGPU_TMP_VREG0_LO);
			knod_emit(priv, meta, v_cmp_le_u32, param[0],
				  param[1]);
			knod_bpf_emit_branch_tail(priv, meta, knod_prog, off);
			break;
		case BPF_JMP | BPF_JLE | BPF_K:
			knod_vset32(&param[0], KNOD_AMDGPU_TMP_VREG0_LO);
			knod_iset32(&param[1], imm);
			knod_emit(priv, meta, v_mov_b32_e32, param[0],
				  param[1]);
			knod_vset32(&param[0], KNOD_AMDGPU_TMP_VREG0_HI);
			knod_iset32(&param[1], (s32)imm < 0 ? U32_MAX : 0);
			knod_emit(priv, meta, v_mov_b32_e32, param[0],
				  param[1]);
			knod_vset64(&param64[0], KNOD_BPF_VREG(d));
			knod_vset64(&param64[1], KNOD_AMDGPU_TMP_VREG0_LO);
			knod_emit(priv, meta, v_cmp_le_u64, param64[0],
				  param64[1]);
			knod_bpf_emit_branch_tail(priv, meta, knod_prog, off);
			break;
		case BPF_JMP32 | BPF_JLE | BPF_X:
			knod_vset32(&param[0], KNOD_BPF_VREG(d));
			knod_vset32(&param[1], KNOD_BPF_VREG(s));
			knod_emit(priv, meta, v_cmp_le_u32, param[0],
				  param[1]);
			knod_bpf_emit_branch_tail(priv, meta, knod_prog, off);
			break;
		case BPF_JMP | BPF_JLE | BPF_X:
			knod_vset64(&param64[0], KNOD_BPF_VREG(d));
			knod_vset64(&param64[1], KNOD_BPF_VREG(s));
			knod_emit(priv, meta, v_cmp_le_u64, param64[0],
				  param64[1]);
			knod_bpf_emit_branch_tail(priv, meta, knod_prog, off);
			break;
		case BPF_JMP32 | BPF_JSGT | BPF_K:
			knod_vset32(&param[0], KNOD_AMDGPU_TMP_VREG0_LO);
			knod_iset32(&param[1], imm);
			knod_emit(priv, meta, v_mov_b32_e32, param[0],
				  param[1]);
			knod_vset32(&param[0], KNOD_BPF_VREG(d));
			knod_vset32(&param[1], KNOD_AMDGPU_TMP_VREG0_LO);
			knod_emit(priv, meta, v_cmp_gt_i32, param[0],
				  param[1]);
			knod_bpf_emit_branch_tail(priv, meta, knod_prog, off);
			break;
		case BPF_JMP | BPF_JSGT | BPF_K:
			knod_vset32(&param[0], KNOD_AMDGPU_TMP_VREG0_LO);
			knod_iset32(&param[1], imm);
			knod_emit(priv, meta, v_mov_b32_e32, param[0],
				  param[1]);
			knod_vset32(&param[0], KNOD_AMDGPU_TMP_VREG0_HI);
			knod_iset32(&param[1], (s32)imm < 0 ? U32_MAX : 0);
			knod_emit(priv, meta, v_mov_b32_e32, param[0],
				  param[1]);
			knod_vset64(&param64[0], KNOD_BPF_VREG(d));
			knod_vset64(&param64[1], KNOD_AMDGPU_TMP_VREG0_LO);
			knod_emit(priv, meta, v_cmp_gt_i64, param64[0],
				  param64[1]);
			knod_bpf_emit_branch_tail(priv, meta, knod_prog, off);
			break;
		case BPF_JMP32 | BPF_JSGT | BPF_X:
			knod_vset32(&param[0], KNOD_BPF_VREG(d));
			knod_vset32(&param[1], KNOD_BPF_VREG(s));
			knod_emit(priv, meta, v_cmp_gt_i32, param[0],
				  param[1]);
			knod_bpf_emit_branch_tail(priv, meta, knod_prog, off);
			break;
		case BPF_JMP | BPF_JSGT | BPF_X:
			knod_vset64(&param64[0], KNOD_BPF_VREG(d));
			knod_vset64(&param64[1], KNOD_BPF_VREG(s));
			knod_emit(priv, meta, v_cmp_gt_i64, param64[0],
				  param64[1]);
			knod_bpf_emit_branch_tail(priv, meta, knod_prog, off);
			break;
		case BPF_JMP32 | BPF_JSGE | BPF_K:
			knod_vset32(&param[0], KNOD_AMDGPU_TMP_VREG0_LO);
			knod_iset32(&param[1], imm);
			knod_emit(priv, meta, v_mov_b32_e32, param[0],
				  param[1]);
			knod_vset32(&param[0], KNOD_BPF_VREG(d));
			knod_vset32(&param[1], KNOD_AMDGPU_TMP_VREG0_LO);
			knod_emit(priv, meta, v_cmp_ge_i32, param[0],
				  param[1]);
			knod_bpf_emit_branch_tail(priv, meta, knod_prog, off);
			break;
		case BPF_JMP | BPF_JSGE | BPF_K:
			knod_vset32(&param[0], KNOD_AMDGPU_TMP_VREG0_LO);
			knod_iset32(&param[1], imm);
			knod_emit(priv, meta, v_mov_b32_e32, param[0],
				  param[1]);
			knod_vset32(&param[0], KNOD_AMDGPU_TMP_VREG0_HI);
			knod_iset32(&param[1], (s32)imm < 0 ? U32_MAX : 0);
			knod_emit(priv, meta, v_mov_b32_e32, param[0],
				  param[1]);
			knod_vset64(&param64[0], KNOD_BPF_VREG(d));
			knod_vset64(&param64[1], KNOD_AMDGPU_TMP_VREG0_LO);
			knod_emit(priv, meta, v_cmp_ge_i64, param64[0],
				  param64[1]);
			knod_bpf_emit_branch_tail(priv, meta, knod_prog, off);
			break;
		case BPF_JMP32 | BPF_JSGE | BPF_X:
			knod_vset32(&param[0], KNOD_BPF_VREG(d));
			knod_vset32(&param[1], KNOD_BPF_VREG(s));
			knod_emit(priv, meta, v_cmp_ge_i32, param[0],
				  param[1]);
			knod_bpf_emit_branch_tail(priv, meta, knod_prog, off);
			break;
		case BPF_JMP | BPF_JSGE | BPF_X:
			knod_vset64(&param64[0], KNOD_BPF_VREG(d));
			knod_vset64(&param64[1], KNOD_BPF_VREG(s));
			knod_emit(priv, meta, v_cmp_ge_i64, param64[0],
				  param64[1]);
			knod_bpf_emit_branch_tail(priv, meta, knod_prog, off);
			break;
		case BPF_JMP32 | BPF_JSLT | BPF_K:
			knod_vset32(&param[0], KNOD_AMDGPU_TMP_VREG0_LO);
			knod_iset32(&param[1], imm);
			knod_emit(priv, meta, v_mov_b32_e32, param[0],
				  param[1]);
			knod_vset32(&param[0], KNOD_BPF_VREG(d));
			knod_vset32(&param[1], KNOD_AMDGPU_TMP_VREG0_LO);
			knod_emit(priv, meta, v_cmp_lt_i32, param[0],
				  param[1]);
			knod_bpf_emit_branch_tail(priv, meta, knod_prog, off);
			break;
		case BPF_JMP | BPF_JSLT | BPF_K:
			knod_vset32(&param[0], KNOD_AMDGPU_TMP_VREG0_LO);
			knod_iset32(&param[1], imm);
			knod_emit(priv, meta, v_mov_b32_e32, param[0],
				  param[1]);
			knod_vset32(&param[0], KNOD_AMDGPU_TMP_VREG0_HI);
			knod_iset32(&param[1], (s32)imm < 0 ? U32_MAX : 0);
			knod_emit(priv, meta, v_mov_b32_e32, param[0],
				  param[1]);
			knod_vset64(&param64[0], KNOD_BPF_VREG(d));
			knod_vset64(&param64[1], KNOD_AMDGPU_TMP_VREG0_LO);
			knod_emit(priv, meta, v_cmp_lt_i64, param64[0],
				  param64[1]);
			knod_bpf_emit_branch_tail(priv, meta, knod_prog, off);
			break;
		case BPF_JMP32 | BPF_JSLT | BPF_X:
			knod_vset32(&param[0], KNOD_BPF_VREG(d));
			knod_vset32(&param[1], KNOD_BPF_VREG(s));
			knod_emit(priv, meta, v_cmp_lt_i32, param[0],
				  param[1]);
			knod_bpf_emit_branch_tail(priv, meta, knod_prog, off);
			break;
		case BPF_JMP | BPF_JSLT | BPF_X:
			knod_vset64(&param64[0], KNOD_BPF_VREG(d));
			knod_vset64(&param64[1], KNOD_BPF_VREG(s));
			knod_emit(priv, meta, v_cmp_lt_i64, param64[0],
				  param64[1]);
			knod_bpf_emit_branch_tail(priv, meta, knod_prog, off);
			break;
		case BPF_JMP32 | BPF_JSLE | BPF_K:
			knod_vset32(&param[0], KNOD_AMDGPU_TMP_VREG0_LO);
			knod_iset32(&param[1], imm);
			knod_emit(priv, meta, v_mov_b32_e32, param[0],
				  param[1]);
			knod_vset32(&param[0], KNOD_BPF_VREG(d));
			knod_vset32(&param[1], KNOD_AMDGPU_TMP_VREG0_LO);
			knod_emit(priv, meta, v_cmp_le_i32, param[0],
				  param[1]);
			knod_bpf_emit_branch_tail(priv, meta, knod_prog, off);
			break;
		case BPF_JMP | BPF_JSLE | BPF_K:
			knod_vset32(&param[0], KNOD_AMDGPU_TMP_VREG0_LO);
			knod_iset32(&param[1], imm);
			knod_emit(priv, meta, v_mov_b32_e32, param[0],
				  param[1]);
			knod_vset32(&param[0], KNOD_AMDGPU_TMP_VREG0_HI);
			knod_iset32(&param[1], (s32)imm < 0 ? U32_MAX : 0);
			knod_emit(priv, meta, v_mov_b32_e32, param[0],
				  param[1]);
			knod_vset64(&param64[0], KNOD_BPF_VREG(d));
			knod_vset64(&param64[1], KNOD_AMDGPU_TMP_VREG0_LO);
			knod_emit(priv, meta, v_cmp_le_i64, param64[0],
				  param64[1]);
			knod_bpf_emit_branch_tail(priv, meta, knod_prog, off);
			break;
		case BPF_JMP32 | BPF_JSLE | BPF_X:
			knod_vset32(&param[0], KNOD_BPF_VREG(d));
			knod_vset32(&param[1], KNOD_BPF_VREG(s));
			knod_emit(priv, meta, v_cmp_le_i32, param[0],
				  param[1]);
			knod_bpf_emit_branch_tail(priv, meta, knod_prog, off);
			break;
		case BPF_JMP | BPF_JSLE | BPF_X:
			knod_vset64(&param64[0], KNOD_BPF_VREG(d));
			knod_vset64(&param64[1], KNOD_BPF_VREG(s));
			knod_emit(priv, meta, v_cmp_le_i64, param64[0],
				  param64[1]);
			knod_bpf_emit_branch_tail(priv, meta, knod_prog, off);
			break;
		case BPF_JMP32 | BPF_JSET | BPF_K:
			knod_vset32(&param[0], KNOD_AMDGPU_TMP_VREG0_LO);
			knod_iset32(&param[1], imm);
			knod_emit(priv, meta, v_mov_b32_e32, param[0],
				  param[1]);
			knod_vset32(&param[0], KNOD_BPF_VREG(d));
			knod_vset32(&param[1], KNOD_BPF_VREG(d));
			knod_vset32(&param[2], KNOD_AMDGPU_TMP_VREG0_LO);
			knod_emit(priv, meta, v_and_b32_e32, param[0],
				  param[1], param[2]);
			knod_vset32(&param[0], KNOD_BPF_VREG(d));
			knod_vset32(&param[1], KNOD_AMDGPU_TMP_VREG0_LO);
			knod_emit(priv, meta, v_cmp_eq_u32, param[0],
				  param[1]);
			knod_bpf_emit_branch_tail(priv, meta, knod_prog, off);
			break;
		case BPF_JMP | BPF_JSET | BPF_K:
			knod_vset32(&param[0], KNOD_AMDGPU_TMP_VREG0_LO);
			knod_iset32(&param[1], imm);
			knod_emit(priv, meta, v_mov_b32_e32, param[0],
				  param[1]);
			knod_vset32(&param[0], KNOD_AMDGPU_TMP_VREG0_HI);
			knod_iset32(&param[1], (s32)imm < 0 ? U32_MAX : 0);
			knod_emit(priv, meta, v_mov_b32_e32, param[0],
				  param[1]);
			knod_vset32(&param[0], KNOD_BPF_VREG(d));
			knod_vset32(&param[1], KNOD_BPF_VREG(d));
			knod_vset32(&param[2], KNOD_AMDGPU_TMP_VREG0_LO);
			knod_emit(priv, meta, v_and_b32_e32, param[0],
				  param[1], param[2]);
			knod_vset32(&param[0], KNOD_BPF_VREG(d) + 1);
			knod_vset32(&param[1], KNOD_BPF_VREG(d) + 1);
			knod_vset32(&param[2], KNOD_AMDGPU_TMP_VREG0_HI);
			knod_emit(priv, meta, v_and_b32_e32, param[0],
				  param[1], param[2]);
			knod_vset32(&param[0], KNOD_BPF_VREG(d));
			knod_vset32(&param[1], KNOD_AMDGPU_TMP_VREG0_LO);
			knod_emit(priv, meta, v_cmp_eq_u64, param[0],
				  param[1]);
			knod_bpf_emit_branch_tail(priv, meta, knod_prog, off);
			break;
		case BPF_JMP32 | BPF_JSET | BPF_X:
			knod_vset32(&param[0], KNOD_BPF_VREG(d));
			knod_vset32(&param[1], KNOD_BPF_VREG(d));
			knod_vset32(&param[2], KNOD_BPF_VREG(s));
			knod_emit(priv, meta, v_and_b32_e32, param[0],
				  param[1], param[2]);
			knod_bpf_emit_branch_tail(priv, meta, knod_prog, off);
			break;
		case BPF_JMP | BPF_JSET | BPF_X:
			knod_vset32(&param[0], KNOD_BPF_VREG(d));
			knod_vset32(&param[1], KNOD_BPF_VREG(d));
			knod_vset32(&param[2], KNOD_BPF_VREG(s));
			knod_emit(priv, meta, v_and_b32_e32, param[0],
				  param[1], param[2]);
			knod_vset32(&param[0], KNOD_BPF_VREG(d) + 1);
			knod_vset32(&param[1], KNOD_BPF_VREG(d) + 1);
			knod_vset32(&param[2], KNOD_BPF_VREG(s) + 1);
			knod_emit(priv, meta, v_and_b32_e32, param[0],
				  param[1], param[2]);
			knod_bpf_emit_branch_tail(priv, meta, knod_prog, off);
			break;
		case BPF_JMP32 | BPF_JNE | BPF_K:
			knod_vset32(&param[0], KNOD_AMDGPU_TMP_VREG0_LO);
			knod_iset32(&param[1], imm);
			knod_emit(priv, meta, v_mov_b32_e32, param[0],
				  param[1]);
			knod_vset32(&param[0], KNOD_BPF_VREG(d));
			knod_vset32(&param[1], KNOD_AMDGPU_TMP_VREG0_LO);
			knod_emit(priv, meta, v_cmp_eq_u32, param[0],
				  param[1]);
			knod_bpf_emit_branch_tail(priv, meta, knod_prog, off);
			break;
		case BPF_JMP | BPF_JNE | BPF_K:
			knod_vset32(&param[0], KNOD_AMDGPU_TMP_VREG0_LO);
			knod_iset32(&param[1], imm);
			knod_emit(priv, meta, v_mov_b32_e32, param[0],
				  param[1]);
			knod_vset32(&param[0], KNOD_AMDGPU_TMP_VREG0_HI);
			knod_iset32(&param[1], (s32)imm < 0 ? U32_MAX : 0);
			knod_emit(priv, meta, v_mov_b32_e32, param[0],
				  param[1]);
			knod_vset32(&param[0], KNOD_BPF_VREG(d));
			knod_vset32(&param[1], KNOD_AMDGPU_TMP_VREG0_LO);
			knod_emit(priv, meta, v_cmp_eq_u64, param[0],
				  param[1]);
			knod_bpf_emit_branch_tail(priv, meta, knod_prog, off);
			break;
		case BPF_JMP32 | BPF_JNE | BPF_X:
			knod_vset32(&param[0], KNOD_BPF_VREG(d));
			knod_vset32(&param[1], KNOD_BPF_VREG(s));
			knod_emit(priv, meta, v_cmp_eq_u32, param[0],
				  param[1]);
			knod_bpf_emit_branch_tail(priv, meta, knod_prog, off);
			break;
		case BPF_JMP | BPF_JNE | BPF_X:
			knod_vset32(&param[0], KNOD_BPF_VREG(d));
			knod_vset32(&param[1], KNOD_BPF_VREG(s));
			knod_emit(priv, meta, v_cmp_eq_u64, param[0],
				  param[1]);
			knod_bpf_emit_branch_tail(priv, meta, knod_prog, off);
			break;
		case BPF_JMP32 | BPF_CALL:
		case BPF_JMP | BPF_CALL:
			/* The callee is copied in after the call. */
			if (is_mbpf_pseudo_call(meta)) {
				knod_bpf_emit_subprog_keep(priv, meta, true);
				break;
			}
			/* kfuncs are not translated. */
			if (!is_mbpf_helper_call(meta))
				return -EOPNOTSUPP;
			switch (imm) {
			case BPF_FUNC_map_lookup_elem:
				if (map_id == -1 ||
				    !knod_bpf_map_op(priv, meta, map_id,
						     KNOD_BLOB_OP_LOOKUP))
					return -EOPNOTSUPP;
				map_id = -1;
				break;
			case BPF_FUNC_map_update_elem:
				if (map_id == -1 ||
				    !knod_bpf_map_op(priv, meta, map_id,
						     KNOD_BLOB_OP_UPDATE))
					return -EOPNOTSUPP;
				map_id = -1;
				break;
			case BPF_FUNC_map_delete_elem:
				if (map_id == -1 ||
				    !knod_bpf_map_op(priv, meta, map_id,
						     KNOD_BLOB_OP_DELETE))
					return -EOPNOTSUPP;
				knod_prog->uses_map_delete = true;
				map_id = -1;
				break;
			case BPF_FUNC_ktime_get_ns:
				knod_prog->uses_ktime = true;
				knod_bpf_ktime_get_ns(priv, meta);
				break;
			case BPF_FUNC_xdp_adjust_head:
			case BPF_FUNC_xdp_adjust_tail:
				if (!knod_bpf_xdp_adjust(priv, meta,
						imm == BPF_FUNC_xdp_adjust_head))
					return -EOPNOTSUPP;
				break;
			default:
				return -EOPNOTSUPP;
			}
			break;
		case BPF_JMP32 | BPF_EXIT:
		case BPF_JMP | BPF_EXIT:
			/* Structurized CFG: BPF_EXIT is NOT a terminator.
			 * Mark all active lanes as done and clear EXEC.
			 * Actual exit handling (retval store,
			 * PASS block, s_endpgm) is in the unified
			 * fallthrough EXIT at the end of the stream.
			 * This follows the LLVM StructurizeCFG model where
			 * all lanes must reach the single exit point.
			 */
			knod_emit(priv, meta, s_or_b64,
				  knod_prog->done_mask_sreg,
				  knod_prog->done_mask_sreg,
				  AMDGCN_SREG_EXEC_LO);

			knod_emit(priv, meta, s_mov_b64, AMDGCN_SREG_EXEC_LO,
				  AMDGCN_SREG_INTEGER_0);
			break;
		/* BPF v4's bswap: the same swap, whatever the host. */
		case BPF_ALU64 | BPF_END | BPF_TO_LE:
		case BPF_ALU | BPF_END | BPF_TO_BE: {
			struct amdgcn_param32 v_dst_lo, v_dst_hi, v_tmp, s_sel;

			knod_vset32(&v_dst_lo, KNOD_BPF_VREG(d));
			knod_vset32(&v_dst_hi, KNOD_BPF_VREG(d) + 1);
			knod_vset32(&v_tmp, KNOD_AMDGPU_TMP_VREG0_LO);
			knod_sset32(&s_sel, KNOD_AMDGPU_TMP_SREG0_LO);

			switch (imm) {
			case 16:
				/* bswap16+zext: {0,0,byte0,byte1} */
				knod_iset32(&param[0], 0x0C0C0001);
				knod_emit(priv, meta, s_mov_b32, s_sel,
					  param[0]);

				knod_emit(priv, meta, v_perm_b32, v_dst_lo,
					  v_dst_lo, v_dst_lo, s_sel);

				knod_iset32(&param[0], 0);
				knod_emit(priv, meta, v_mov_b32_e32, v_dst_hi,
					  param[0]);
				break;
			case 32:
				/* bswap32+zext */
				knod_iset32(&param[0], 0x00010203);
				knod_emit(priv, meta, s_mov_b32, s_sel,
					  param[0]);

				knod_emit(priv, meta, v_perm_b32, v_dst_lo,
					  v_dst_lo, v_dst_lo, s_sel);

				knod_iset32(&param[0], 0);
				knod_emit(priv, meta, v_mov_b32_e32, v_dst_hi,
					  param[0]);
				break;
			case 64: {
				struct amdgcn_param32 v_src_hi;

				knod_vset32(&v_src_hi, KNOD_BPF_VREG(d) + 1);

				/* bswap32 selector */
				knod_iset32(&param[0], 0x00010203);
				knod_emit(priv, meta, s_mov_b32, s_sel,
					  param[0]);

				/* tmp = bswap32(lo) */
				knod_emit(priv, meta, v_perm_b32, v_tmp,
					  v_dst_lo, v_dst_lo, s_sel);

				/* new_lo = bswap32(hi) */
				knod_emit(priv, meta, v_perm_b32, v_dst_lo,
					  v_src_hi, v_src_hi, s_sel);

				/* new_hi = tmp (bswap32(old_lo)) */
				knod_emit(priv, meta, v_mov_b32_e32, v_dst_hi,
					  v_tmp);
				break;
			}
			default:
				return -EOPNOTSUPP;
			}
			break;
		}
		case BPF_ALU | BPF_END | BPF_TO_LE: {
			struct amdgcn_param32 v_dst_lo, v_dst_hi;

			knod_vset32(&v_dst_lo, KNOD_BPF_VREG(d));
			knod_vset32(&v_dst_hi, KNOD_BPF_VREG(d) + 1);

			switch (imm) {
			case 16:
				knod_iset32(&param[0], 0xFFFF);
				knod_emit(priv, meta, v_and_b32_e32, v_dst_lo,
					  param[0], v_dst_lo);

				knod_iset32(&param[0], 0);
				knod_emit(priv, meta, v_mov_b32_e32, v_dst_hi,
					  param[0]);
				break;
			case 32:
				knod_iset32(&param[0], 0);
				knod_emit(priv, meta, v_mov_b32_e32, v_dst_hi,
					  param[0]);
				break;
			case 64:
				break;
			default:
				return -EOPNOTSUPP;
			}
			break;
		}
		default:
			return -EOPNOTSUPP;
		}

		if (sext)
			knod_bpf_sext(priv, meta, d, sext);
insn_emitted:
		/* What the gate counts as having read what the order is for. */
		if (meta == knod_prog->gate_reach) {
			struct amdgcn_param32 rank, bit;

			knod_vset32(&rank, KNOD_BLOB_PRO_RANK_VREG);
			knod_iset32(&bit, KNOD_BLOB_RANK_REACHED);
			knod_emit(priv, meta, v_or_b32_e32, rank, bit, rank);
		}
		if (meta->ptr.type == PTR_TO_PACKET)
			knod_packet_store_cache_policy(priv, meta, 0);
		WARN_ON(meta->amdgpu_insns >= KNOD_META_INSNS);
		insn_idx += knod_meta_bytes(meta) / 4;
	}

	return knod_bpf_emit_epilogue(priv, knod_prog);
}

/* First instruction at or after @idx that is not on its way out. */
static struct knod_insn_meta *knod_bpf_live_meta_at(struct knod_prog *knod_prog,
						    short idx)
{
	struct knod_insn_meta *meta;

	list_for_each_entry(meta, &knod_prog->insns, l) {
		if (meta->bpf_insn_idx < idx)
			continue;
		if (meta->flags & FLAG_INSN_SKIP_MASK)
			continue;
		return meta;
	}

	return NULL;
}

/*
 * Unreachable code is only ever reached by running off the end of a
 * terminator, so unlinking it leaves every surviving successor alone.  A jump
 * landing on it is a different matter: the verifier also drops live no-ops -
 * the JA +0 its own branch hard-wiring produces, among them - and renumbers
 * the jumps that targeted them.  The meta list keeps the original numbering,
 * so do that renumbering here, before anything is unlinked.  A jump that
 * landed on an instruction which does nothing means the one after it.
 */
static int knod_bpf_drop_dead_insns(struct knod_prog *knod_prog,
				    unsigned int *dropped)
{
	struct knod_insn_meta *meta, *tmp, *tgt;
	int off;

	list_for_each_entry(meta, &knod_prog->insns, l) {
		if (meta->flags & FLAG_INSN_SKIP_MASK)
			continue;
		if (!is_mbpf_cond_jump(meta) && !knod_meta_is_ja(meta))
			continue;

		tgt = knod_bpf_live_meta_at(knod_prog,
					    knod_meta_jump_target_idx(meta));
		if (!tgt) {
			pr_warn("knod_bpf: bpf#%d jumps past the last live instruction\n",
				meta->bpf_insn_idx);
			return -EINVAL;
		}

		off = tgt->bpf_insn_idx - meta->bpf_insn_idx - 1;
		if (meta->insn.code == (BPF_JMP32 | BPF_JA | BPF_K))
			meta->insn.imm = off;
		else
			meta->insn.off = off;
	}

	*dropped = 0;
	list_for_each_entry_safe(meta, tmp, &knod_prog->insns, l) {
		if (!(meta->flags & FLAG_INSN_SKIP_MASK))
			continue;
		list_del(&meta->l);
		kfree(meta);
		(*dropped)++;
	}
	knod_prog->meta = knod_prog_first_meta(knod_prog);

	return 0;
}

static int knod_bpf_translate(struct bpf_prog *prog)
{
	struct knod_prog *knod_prog = prog->aux->offload->dev_priv;
	struct knod_dev *knodev = knod_prog->knodev;
	unsigned int dropped;
	int ret;

	knod_bpf_map_setup(prog);
	knod_bpf_place_frames(knod_prog);

	ret = knod_bpf_drop_dead_insns(knod_prog, &dropped);
	if (ret)
		return ret;
	if (dropped)
		pr_info("knod_bpf: verifier removed %u of %u instructions\n",
			dropped, knod_prog->n_insns);

	ret = knod_bpf_jit(knodev, knod_prog);
	if (ret < 0) {
		pr_err("knod: failed to JIT: %d\n", ret);
		return ret;
	}

	return knod_setup_bpf_prog(prog);
}

static void knod_bpf_destroy_prog(struct bpf_prog *prog)
{
	struct knod_prog *knod_prog = prog->aux->offload->dev_priv;
	struct knod_dev *knodev = knod_prog->knodev;
	struct knod_bpf_priv *priv = knodev->accel->xdp.priv;

	/*
	 * Normally the prog was already uninstalled (offload with a NULL prog
	 * flipped back to pass).  Guard the abnormal path where the prog is
	 * freed while still tracked: flip to pass first so the worker stops
	 * submitting this code. The compiled code lives in a kernel slot and
	 * is no longer read once we flip away; knod_prog is CPU-only IR the GPU
	 * never touches, so it is safe to free synchronously.
	 */
	if (priv && READ_ONCE(priv->prog) == prog) {
		WRITE_ONCE(priv->prog, NULL);
		if (knod_bpf_reload_pass(knodev))
			knod_gda_mark_fault(priv->knod);
	}
	knod_prog_free(knod_prog);
}

static const struct bpf_prog_offload_ops knod_bpf_dev_ops = {
	.insn_hook      = knod_bpf_verify_insn,
	.finalize       = knod_bpf_finalize,
	.replace_insn   = knod_bpf_replace_insn,
	.remove_insns   = knod_bpf_remove_insns,
	.prepare        = knod_bpf_verifier_prep,
	.translate      = knod_bpf_translate,
	.destroy        = knod_bpf_destroy_prog,
};


#define KNOD_MAP_SNAP_GL2_ALL	BIT(0)	/* write back all of GL2 first */
#define KNOD_MAP_SNAP_PARK	BIT(1)	/* with the engine parked */

/* How long a walk can pause between keys and still be the same walk. */
#define KNOD_MAP_WALK_IDLE_NS	(10 * NSEC_PER_MSEC)

/* SDMA's linear copy moves at most this much at once. */
#define KNOD_MAP_SNAP_CHUNK	SZ_2M

static int knod_bpf_map_snap_alloc(struct knod_bpf_map *knod_map)
{
	int flags = KFD_IOC_ALLOC_MEM_FLAGS_GTT |
		    KFD_IOC_ALLOC_MEM_FLAGS_WRITABLE |
		    KFD_IOC_ALLOC_MEM_FLAGS_COHERENT;
	struct knod *knod = knod_map->priv->knod;
	struct knod_mem *mem;

	if (!knod_map->snap) {
		mem = knod_alloc_mem(knod, knod_map->mem->size, flags);
		if (IS_ERR_OR_NULL(mem))
			return -ENOMEM;
		knod_map->snap = mem;
	}
	if (knod_map->hash_elems_mem && !knod_map->snap_elems) {
		mem = knod_alloc_mem(knod, knod_map->hash_elems_mem->size,
				     flags);
		if (IS_ERR_OR_NULL(mem))
			return -ENOMEM;
		knod_map->snap_elems = mem;
	}
	return 0;
}

static u32 knod_bpf_map_snap_copy(struct knod *knod, struct knod_mem *dst,
				  struct knod_mem *src)
{
	struct knod_sdma_copy_desc c;
	u32 fence = 0;
	u64 off;

	for (off = 0; off < src->size; off += KNOD_MAP_SNAP_CHUNK) {
		c.dst = dst->gaddr + off;
		c.src = src->gaddr + off;
		c.len = min_t(u64, src->size - off, KNOD_MAP_SNAP_CHUNK);
		fence = knod_sdma_submit(knod, 0, &c, 1);
		if (!fence)
			return 0;
	}
	return fence;
}

/* Copy the map to host memory, past GL2, for host reads to see what the
 * engine wrote without stopping it, and to walk a table that holds still.
 * One taken since the read began serves it if @fresh, else one at most
 * map_snap_ms old.  Without one - nothing has run yet, or no room for it -
 * reads go to the map itself.  Under the priv's snap_lock.
 */
static int knod_bpf_map_snapshot(struct knod_bpf_map *knod_map, bool fresh)
{
	struct knod_mem *mems[] = { knod_map->mem, knod_map->hash_elems_mem };
	struct knod_bpf_priv *priv = knod_map->priv;
	u32 flags = READ_ONCE(priv->map_snap_flags);
	struct knod *knod = priv->knod;
	u64 now = ktime_get_ns(), age;
	u32 fence;
	int err;

	if (!READ_ONCE(knod->gda->launches)) {
		knod_map->snap_ok = false;
		return 0;
	}
	age = (u64)READ_ONCE(priv->map_snap_ms) * NSEC_PER_MSEC;
	if (knod_map->snap_ok && !fresh &&
	    (knod_map->snap_ns + age >= now ||
	     knod_map->walk_ns + KNOD_MAP_WALK_IDLE_NS >= now))
		return 0;

	knod_map->snap_ok = false;
	if (knod_bpf_map_snap_alloc(knod_map))
		return knod_bpf_map_visibility(knod_map, true);

	if (flags & KNOD_MAP_SNAP_PARK) {
		err = knod_bpf_map_mutation_begin(knod_map);
		if (err)
			return err;
	}
	now = ktime_get_ns();
	if (flags & KNOD_MAP_SNAP_GL2_ALL)
		fence = knod_sdma_gl2_maintain_all(knod, 0, true);
	else
		fence = knod_sdma_gl2_maintain(knod, 0, mems,
					       ARRAY_SIZE(mems), true);
	if (fence)
		fence = knod_bpf_map_snap_copy(knod, knod_map->snap,
					       knod_map->mem);
	if (fence && knod_map->hash_elems_mem)
		fence = knod_bpf_map_snap_copy(knod, knod_map->snap_elems,
					       knod_map->hash_elems_mem);
	if (fence) {
		knod_sdma_kick(knod, 0);
		err = knod_sdma_wait(knod, 0, fence, USEC_PER_SEC);
	} else {
		err = -EBUSY;
	}
	if (flags & KNOD_MAP_SNAP_PARK &&
	    knod_bpf_map_mutation_end(knod_map, false) && !err)
		err = -EIO;
	if (err)
		return err;

	knod_map->snap_ns = now;
	knod_map->snap_ok = true;
	return 0;
}

static int knod_bpf_map_get_next_key(struct bpf_offloaded_map *offmap,
				     void *key, void *next_key)
{
	unsigned int *nkey = (unsigned int *)next_key;
	unsigned int *_key = (unsigned int *)key;

	if (offmap->map.map_type == BPF_MAP_TYPE_ARRAY ||
	    offmap->map.map_type == BPF_MAP_TYPE_PERCPU_ARRAY) {
		if (key == NULL)
			*nkey = 0;
		else
			*nkey = (*_key) + 1;

		if (*nkey >= offmap->map.max_entries)
			return -ENOENT;
	} else if (knod_bpf_map_type_hash(offmap->map.map_type)) {
		struct knod_bpf_map *knod_map = offmap->dev_priv;
		int err;

		if (!knod_map)
			return -ENODEV;
		mutex_lock(&knod_map->priv->snap_lock);
		/* A walk from the start gets a snapshot of its own, which the
		 * rest of it reads, so the keys hold still while it goes.
		 */
		err = knod_bpf_map_snapshot(knod_map, !key);
		knod_map->walk_ns = ktime_get_ns();
		if (!err)
			err = key ? knod_bpf_map_hash_get_next_key(offmap, key,
								  nkey) :
				    knod_bpf_map_hash_get_first_key(offmap,
								    next_key);
		mutex_unlock(&knod_map->priv->snap_lock);
		return err;
	}

	return 0;
}

static int knod_bpf_map_lookup_elem(struct bpf_offloaded_map *offmap,
				       void *key, void *value)
{
	struct knod_bpf_map *knod_map = offmap->dev_priv;
	int err;

	if (!knod_map)
		return -ENODEV;
	mutex_lock(&knod_map->priv->snap_lock);
	err = knod_bpf_map_snapshot(knod_map, false);
	if (!err)
		err = __knod_bpf_map_lookup_elem(offmap, key, value);
	mutex_unlock(&knod_map->priv->snap_lock);
	return err;
}

static int knod_bpf_map_update_elem(struct bpf_offloaded_map *offmap,
				    void *key, void *value, u64 flags)
{
	return __knod_bpf_map_update_elem(offmap, key, value, flags);
}

static int knod_bpf_map_delete_elem(struct bpf_offloaded_map *offmap, void *key)
{
	return __knod_bpf_map_delete_elem(offmap, key);
}

static const struct bpf_map_dev_ops knod_bpf_map_ops = {
	.map_get_next_key       = knod_bpf_map_get_next_key,
	.map_lookup_elem        = knod_bpf_map_lookup_elem,
	.map_update_elem        = knod_bpf_map_update_elem,
	.map_delete_elem        = knod_bpf_map_delete_elem,
};

static int knod_bpf_map_alloc(struct knod_dev *knodev,
			      struct bpf_offloaded_map *offmap)
{
	int err;

	if (offmap->map.map_type != BPF_MAP_TYPE_ARRAY &&
	    offmap->map.map_type != BPF_MAP_TYPE_PERCPU_ARRAY &&
	    !knod_bpf_map_type_hash(offmap->map.map_type)) {
		knod_jit_dbg(" unsupported map type: %d\n",
			offmap->map.map_type);
		return -EOPNOTSUPP;
	}

	err = __knod_bpf_map_alloc(knodev, offmap);
	if (err) {
		knod_jit_dbg(" err = %d\n", err);
		return err;
	}

	offmap->dev_ops = &knod_bpf_map_ops;
	return 0;
}

static int knod_bpf_xdp_install(struct knod_dev *knodev,
				struct netdev_bpf *bpf)
{
	int err = 0;

	ASSERT_RTNL();

	switch (bpf->command) {
	case XDP_SETUP_PROG_HW:
		err = knod_bpf_xdp_set_prog(knodev, bpf);
		break;
	case BPF_OFFLOAD_MAP_ALLOC:
		err = knod_bpf_map_alloc(knodev, bpf->offmap);
		break;
	case BPF_OFFLOAD_MAP_FREE:
		knod_bpf_map_free(knodev, bpf->offmap);
		break;
	default:
		knod_jit_dbg(" bpf->command = %d\n", bpf->command);
		err = -EINVAL;
		break;
	}

	return err;
}

static inline int bpf_debugfs_insn(struct knod_insn_meta *meta,
				   struct seq_file *m, int insn_idx)
{
	struct amdgcn_insn *insn = &meta->amdgpu_insn[insn_idx];

	debugfs_insn(insn, m);

	return insn->size;
}

/* Wide enough for the offset and the dwords of the longest instruction, so the
 * tags line up in a column of their own.
 */
#define KNOD_BPF_TAG_COLUMN		40

/* The dwords a meta holds, eight to a line.
 * @col carries the position within the line across metas so the run reads as
 * one block.  Returns how many bytes went out, which is what the offsets the
 * rest of the dump prints are counted in.
 */
static int bpf_debugfs_dwords(struct knod_insn_meta *meta, struct seq_file *m,
			      int *col)
{
	const u32 *dw;
	int n = 0, i, j;

	for (i = 0; i < (int)meta->amdgpu_insns; i++) {
		dw = (const u32 *)&meta->amdgpu_insn[i];
		for (j = 0; j < (int)(meta->amdgpu_insn[i].size / 4); j++) {
			seq_printf(m, "%08x%c", dw[j],
				   ++(*col) % 8 ? ' ' : '\n');
			*col %= 8;
			n++;
		}
	}

	return n * 4;
}

/*
 * Print one GPU instruction at @offset, then drop the trailing newline and
 * append @tag as a right-hand comment aligned to a fixed column (tabs expand
 * to 8) so the origin lines up.  Returns the instruction size in dwords.
 */
static int bpf_debugfs_insn_tagged(struct knod_insn_meta *meta,
				   struct seq_file *m, int j,
				   int offset, const char *tag)
{
	size_t col, p, line_start = m->count;
	int sz;

	seq_printf(m, "%d:\t", offset);
	sz = bpf_debugfs_insn(meta, m, j);
	if (seq_has_overflowed(m))
		return sz;

	if (m->count > line_start && m->buf[m->count - 1] == '\n')
		m->count--;
	col = 0;
	for (p = line_start; p < m->count; p++)
		col = m->buf[p] == '\t' ? (col + 8) & ~(size_t)7 : col + 1;
	while (col < KNOD_BPF_TAG_COLUMN) {
		seq_putc(m, ' ');
		col++;
	}
	seq_printf(m, " ; %s\n", tag);

	return sz;
}

/*
 * Print the instructions a second time, re-sorted into BPF source order so the
 * dump reads like the program.  The offsets are the real (reordered) GPU
 * offsets, so they appear out of sequence - that shows where the reorder
 * placed each block.  Synthetic jumps have no BPF source insn and are last.
 */
static void bpf_insn_show_bpf_order(struct knod_bpf_priv *priv,
				    struct seq_file *m)
{
	struct knod_insn_meta *meta;
	int idx, max_idx = -1, off2, i;
	bool synth_hdr = false;
	char tag[24];

	seq_puts(m, "===[INSTRUCTIONS (bpf order)]===\n");
	seq_puts(m, "# format annotated\n");

	list_for_each_entry(meta, &priv->knod_prog->insns, l)
		if (meta->bpf_insn_idx > max_idx)
			max_idx = meta->bpf_insn_idx;

	for (idx = 0; idx <= max_idx; idx++) {
		list_for_each_entry(meta, &priv->knod_prog->insns, l) {
			if (meta->bpf_insn_idx != idx || !meta->amdgpu_insns)
				continue;
			scnprintf(tag, sizeof(tag), "bpf#%d", idx);
			off2 = meta->amdgpu_insn_idx;
			for (i = 0; i < meta->amdgpu_insns; i++)
				off2 += bpf_debugfs_insn_tagged(meta, m,
								i, off2, tag);
		}
	}

	list_for_each_entry(meta, &priv->knod_prog->insns, l) {
		if (meta->bpf_insn_idx >= 0 || !meta->amdgpu_insns)
			continue;
		if (!synth_hdr) {
			seq_puts(m, "  [synthetic jumps]\n");
			synth_hdr = true;
		}
		scnprintf(tag, sizeof(tag), "synth JA->#%d",
			  meta->jmp_dst ? meta->jmp_dst->bpf_insn_idx : -1);
		off2 = meta->amdgpu_insn_idx;
		for (i = 0; i < meta->amdgpu_insns; i++)
			off2 += bpf_debugfs_insn_tagged(meta, m,
							i, off2, tag);
	}
}

static int bpf_insn_show(struct seq_file *m, void *v)
{
	struct knod_bpf_priv *priv = (struct knod_bpf_priv *)m->private;
	struct knod_insn_meta *meta;
	struct knod_prog *kp;
	int i, insn_idx = 0;
	bool have_prog;
	int col = 0;

	if (!priv)
		return 0;

	knod_seq_dump_header(m, priv->knod, "BPF kernel", "annotated", 0, 0, 64);
	/* Which of the two builds this is.  Otherwise the only way to tell a
	 * dump apart is to recognise a routine in it, and the pieces the two
	 * engines share are byte for byte the same.
	 */
	seq_printf(m, "# jit_engine %d\n", knod_bpf_jit_engine);

	/*
	 * Show the kernel the GPU actually executes: the XDP prog when one is
	 * attached, otherwise the retained pass-through kernel.
	 */
	have_prog = READ_ONCE(priv->prog);
	if (!have_prog) {
		seq_puts(m, "no XDP prog attached -- the engine's receive kernel runs\n");
		return 0;
	}
	kp = priv->knod_prog;
	if (!kp->ordered)
		seq_puts(m, "# ordered no\n");
	else if (!kp->gate_at)
		seq_printf(m, "# ordered from the start: %s at bpf#%d (read bpf#%d, gate bpf#%d, nearest resume bpf#%d keeping registers %#x stack %#llx)\n",
			   kp->order_why ?: "?", kp->order_why_at,
			   kp->order_why_g, kp->order_why_p,
			   kp->order_why_r, kp->order_why_regs,
			   kp->order_why_stack);
	else
		seq_printf(m, "# ordered at bpf#%d, reads at bpf#%d, resumes at bpf#%d, %u branches held, keeping registers %#x stack %#llx\n",
			   kp->gate_at->bpf_insn_idx,
			   kp->gate_reach->bpf_insn_idx,
			   kp->resume_at->bpf_insn_idx, kp->n_gate_saves,
			   kp->gate_snap, kp->gate_snap_stack);

	/* The prologue goes out as dwords: no line of it belongs to a BPF
	 * instruction.
	 */
	seq_puts(m, "===[PROLOGUE]===\n");
	seq_puts(m, "# format block\n");
	seq_printf(m, "# base %d\n", insn_idx);
	list_for_each_entry(meta, &kp->pre_insns, l)
		insn_idx += bpf_debugfs_dwords(meta, m, &col);
	if (col)
		seq_putc(m, '\n');

	/* Emission (RPO) order - the actual GPU layout.  Each line is tagged
	 * with its origin BPF insn since the reorder makes this differ from the
	 * BPF byte order; synthetic jumps inserted by the reorder have none.
	 */
	seq_puts(m, "===[INSTRUCTIONS]===\n");
	seq_puts(m, "# format annotated\n");
	list_for_each_entry(meta, &kp->insns, l) {
		char tag[32];

		if (meta->bpf_insn_idx < 0)
			scnprintf(tag, sizeof(tag), "synth JA->#%d",
				  meta->jmp_dst ?
				  meta->jmp_dst->bpf_insn_idx : -1);
		else if (meta->frame)
			/* A called function's copy: its own number, and
			 * which call deep.
			 */
			scnprintf(tag, sizeof(tag), "bpf#%d=%d@%u",
				  meta->bpf_insn_idx, meta->orig_idx,
				  meta->frame);
		else
			scnprintf(tag, sizeof(tag), "bpf#%d",
				  meta->bpf_insn_idx);

		for (i = 0; i < (int)meta->amdgpu_insns; i++)
			insn_idx += bpf_debugfs_insn_tagged(meta, m, i,
							    insn_idx, tag);
	}

	/* Dwords, for the same reason as the prologue. */
	seq_puts(m, "===[EPILOG]===\n");
	seq_puts(m, "# format block\n");
	seq_printf(m, "# base %d\n", insn_idx);
	col = 0;
	list_for_each_entry(meta, &kp->post_insns, l)
		insn_idx += bpf_debugfs_dwords(meta, m, &col);
	if (col)
		seq_putc(m, '\n');

	if (have_prog)
		bpf_insn_show_bpf_order(priv, m);

	return 0;
}

static int bpf_insn_open(struct inode *inode, struct file *file)
{
	return single_open(file, bpf_insn_show, inode->i_private);
}

static const struct file_operations bpf_insn_fops = {
	.owner   = THIS_MODULE,
	.open    = bpf_insn_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = single_release,
};

static const char *knod_branch_type_str(enum knod_branch_type type)
{
	switch (type) {
	case KNOD_BR_NONE:		return "NONE";
	case KNOD_BR_DIRECT_EXIT:	return "DIRECT_EXIT";
	case KNOD_BR_FORWARD_SKIP:	return "FORWARD_SKIP";
	case KNOD_BR_FORWARD_GOTO:	return "FORWARD_GOTO";
	default:			return "UNKNOWN";
	}
}

static int bpf_cfg_show(struct seq_file *m, void *v)
{
	struct knod_bpf_priv *priv = (struct knod_bpf_priv *)m->private;
	struct knod_insn_meta *meta;

	if (!priv || !priv->knod_prog)
		return 0;

	seq_puts(m, "===[STRUCTURIZED CFG]===\n");
	seq_printf(m, "exec_save_pairs_used: %u\n",
		   priv->knod_prog->exec_save_pairs_used);
	seq_printf(m, "done_mask: s[%d:%d]\n",
		   priv->knod_prog->done_mask_sreg,
		   priv->knod_prog->done_mask_sreg + 1);
	seq_printf(m, "initial_exec: s[%d:%d]\n",
		   priv->knod_prog->initial_exec_sreg,
		   priv->knod_prog->initial_exec_sreg + 1);
	seq_puts(m, "\n");

	seq_printf(m, "%-6s %-8s %-14s %-10s %-10s %-8s\n",
		   "bpf#", "opcode", "branch_type", "exec_save", "merge_pt",
		   "is_merge");

	list_for_each_entry(meta, &priv->knod_prog->insns, l) {
		bool is_jmp = is_mbpf_jmp(meta);

		if (!is_jmp && !meta->is_merge_point)
			continue;

		seq_printf(m, "%-6d 0x%02x     ",
			   meta->bpf_insn_idx, meta->insn.code);

		if (meta->branch_type != KNOD_BR_NONE) {
			seq_printf(m, "%-14s s[%d:%d]    ",
				   knod_branch_type_str(meta->branch_type),
				   meta->exec_save_sreg,
				   meta->exec_save_sreg + 1);
			if (meta->merge_point)
				seq_printf(m, "%-10d ",
					   meta->merge_point->bpf_insn_idx);
			else
				seq_printf(m, "%-10s ", "-");
		} else if (is_jmp) {
			seq_printf(m, "%-14s %-10s %-10s ",
				   knod_branch_type_str(KNOD_BR_NONE),
				   "-", "-");
		} else {
			seq_printf(m, "%-14s %-10s %-10s ",
				   "", "", "");
		}

		if (meta->is_merge_point) {
			struct knod_insn_meta *br;

			seq_puts(m, "YES      restore:");
			list_for_each_entry(br, &priv->knod_prog->insns, l) {
				if ((br->branch_type == KNOD_BR_FORWARD_SKIP ||
				     br->branch_type == KNOD_BR_FORWARD_GOTO) &&
				    br->merge_point == meta)
					seq_printf(m, " s[%d:%d](from bpf#%d)",
						   br->exec_save_sreg,
						   br->exec_save_sreg + 1,
						   br->bpf_insn_idx);
			}
			seq_puts(m, "\n");
		} else {
			seq_puts(m, "\n");
		}
	}

	/* Basic-block CFG from the reorder analysis (origin BPF order). */
	if (priv->knod_prog->bbs) {
		struct knod_bb *bbs = priv->knod_prog->bbs;
		int nb = priv->knod_prog->n_bbs;
		int k, s;

		seq_printf(m, "\n[BASIC BLOCKS]  %d blocks, %d back-edge(s) -> %s\n",
			   nb, priv->knod_prog->n_back,
			   priv->knod_prog->n_back ? "HAS LOOP" : "DAG");

		for (k = 0; k < nb; k++) {
			struct knod_bb *bb = &bbs[k];

			seq_printf(m, "BB%-3d bpf#%d..#%d  rpo=%d  idom=#%d  succ={",
				   k, bb->leader->bpf_insn_idx,
				   bb->last->bpf_insn_idx, bb->rpo,
				   bb->idom ?
				   bb->idom->leader->bpf_insn_idx : -1);
			for (s = 0; s < bb->n_succ; s++)
				seq_printf(m, "%s#%d", s ? "," : "",
					   bb->succ[s]->leader->bpf_insn_idx);
			seq_printf(m, "}%s\n",
				   bb->loop_header ? "  LOOP_HDR" : "");
		}
	}

	return 0;
}

DEFINE_SHOW_ATTRIBUTE(bpf_cfg);

static int knod_stats_show(struct seq_file *s, void *unused)
{
	struct knod_bpf_priv *priv = s->private;
	struct knod_bpf_stats *stats = &priv->stats;
	u32 gfx = priv->knod->gfx_target_version;
	u64 wall, end;

	end = stats->stop_ns ? stats->stop_ns : ktime_get_ns();
	wall = stats->start_ns ? end - stats->start_ns : 0;

	seq_printf(s, "enabled:             %s\n",
		   static_branch_unlikely(&knod_stats_key) ? "yes" : "no");

	/* What the numbers below were taken on.  A dump that does not say is a
	 * dump that gets compared against the wrong one later.
	 */
	seq_puts(s, "\n--- geometry ---\n");
	seq_printf(s, "channels:            %d\n", priv->nr_works);
	seq_printf(s, "workgroup_size:      %u\n", priv->wg_size);
	seq_printf(s, "lds_per_wg:          %u\n", priv->knod->lds_size);
	seq_printf(s, "stack_bytes:         %d per lane\n",
		   priv->knod_prog ? priv->knod_prog->max_stack_off : 0);
	seq_printf(s, "lds_alloc:           %u\n", priv->lds_bytes);
	seq_printf(s, "stack_mem:           %s\n",
		   priv->prog_stack_scratch ? "scratch (too deep for lds)" :
		   "lds");
	seq_printf(s, "mcpu:                gfx%u%u%u\n",
		   gfx / 10000, (gfx / 100) % 100, gfx % 100);
	seq_printf(s, "elapsed_ms:          %llu\n", wall / NSEC_PER_MSEC);

	/* The shader and the rings: the engine's own file, knod/gda. */
	seq_puts(s, "\n--- maps ---\n");
	seq_printf(s, "map_gc_checks:       %llu\n", priv->map_gc_checks);
	seq_printf(s, "map_gc_elements:     %llu\n", priv->map_gc_elements);
	seq_printf(s, "map_gc_maps:         %llu\n", priv->map_gc_maps);
	seq_printf(s, "host_map_generation: %llu\n",
		   priv->host_map_generation);
	seq_printf(s, "map_visibility_before: %llu\n",
		   priv->map_visibility_before);
	seq_printf(s, "map_visibility_after: %llu\n",
		   priv->map_visibility_after);
	seq_printf(s, "map_visibility_failures: %llu\n",
		   priv->map_visibility_failures);
	seq_printf(s, "map_visibility_fault: %s\n",
		   priv->map_visibility_fault ? "yes" : "no");
	seq_printf(s, "map_visibility_before_avg_ns: %llu\n",
		   priv->map_visibility_before ?
		   priv->map_visibility_before_ns /
		   priv->map_visibility_before : 0);
	seq_printf(s, "map_visibility_after_avg_ns: %llu\n",
		   priv->map_visibility_after ?
		   priv->map_visibility_after_ns /
		   priv->map_visibility_after : 0);

	return 0;
}

DEFINE_SHOW_ATTRIBUTE(knod_stats);

static ssize_t knod_stats_enable_write(struct file *file,
				       const char __user *buf,
				       size_t count, loff_t *ppos)
{
	struct knod_bpf_priv *priv = file->private_data;
	bool val;

	if (kstrtobool_from_user(buf, count, &val))
		return -EINVAL;

	if (val) {
		priv->stats.start_ns = ktime_get_ns();
		priv->stats.stop_ns = 0;
		static_branch_enable(&knod_stats_key);
	} else {
		static_branch_disable(&knod_stats_key);
		priv->stats.stop_ns = ktime_get_ns();
	}

	return count;
}

static ssize_t knod_stats_enable_read(struct file *file,
				      char __user *buf,
				      size_t count, loff_t *ppos)
{
	char tmp[4];
	int len;

	len = scnprintf(tmp, sizeof(tmp), "%d\n",
			static_branch_unlikely(&knod_stats_key) ? 1 : 0);

	return simple_read_from_buffer(buf, count, ppos, tmp, len);
}

static const struct file_operations knod_stats_enable_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.read  = knod_stats_enable_read,
	.write = knod_stats_enable_write,
};

static ssize_t knod_stats_reset_write(struct file *file,
		const char __user *buf,
		size_t count, loff_t *ppos)
{
	struct knod_bpf_priv *priv = file->private_data;

	memset(&priv->stats, 0, sizeof(priv->stats));
	priv->stats.start_ns = ktime_get_ns();
	return count;
}

static const struct file_operations knod_stats_reset_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.write = knod_stats_reset_write,
};

static int knod_debugfs_init(struct knod_bpf_priv *priv)
{
	struct dentry *dir = priv->knod->debug_dir;
	struct dentry *bpf_dir;

	if (!dir)
		return -ENOENT;

	bpf_dir = debugfs_create_dir("bpf", dir);
	if (IS_ERR(bpf_dir))
		return PTR_ERR(bpf_dir);

	priv->debug_dir = bpf_dir;

	debugfs_create_file("insn", 0644,
			    bpf_dir, priv, &bpf_insn_fops);
	debugfs_create_file("cfg", 0444, bpf_dir, priv,
			    &bpf_cfg_fops);
	debugfs_create_file("stats", 0444, bpf_dir, priv,
			    &knod_stats_fops);
	debugfs_create_file("stats_enable", 0644, bpf_dir, priv,
			    &knod_stats_enable_fops);
	debugfs_create_file("stats_reset", 0200, bpf_dir, priv,
			    &knod_stats_reset_fops);
	debugfs_create_u32("map_snap_ms", 0644, bpf_dir, &priv->map_snap_ms);
	debugfs_create_x32("map_snap_flags", 0644, bpf_dir,
			   &priv->map_snap_flags);
	return 0;
}

static void knod_debugfs_cleanup(struct knod_bpf_priv *priv)
{
	if (!priv->debug_dir)
		return;

	debugfs_remove_recursive(priv->debug_dir);
	priv->debug_dir = NULL;
}

/* Called when attached or module loading time */
/* attach: allocate the permanent per-attach priv struct. */
static int knod_accel_xdp_init(struct knod_dev *knodev)
{
	struct knod_accel *accel = knodev->accel;
	struct knod_bpf_priv *priv;

	priv = __knod_accel_xdp_init(accel, knodev);
	if (IS_ERR(priv))
		return PTR_ERR(priv);
	return 0;
}

/* detach: free the permanent priv struct. */
static void knod_accel_xdp_exit(struct knod_dev *knodev)
{
	struct knod_accel *accel = knodev->accel;
	struct knod_bpf_priv *priv = accel->xdp.priv;

	/* Nothing to drop when init failed at attach, or when the state has
	 * already been dropped once.
	 */
	if (!priv)
		return;
	__knod_accel_xdp_exit(accel, priv);
}

/*
 * Feature select, phase B: register the BPF offload device so user XDP
 * progs/maps can bind to it.  Called after ->activate() set up the GPU
 * buffers, while xdp_ops already points at the BPF ops.
 */
static int knod_bpf_offload_init(struct knod_dev *knodev)
{
	struct knod_accel *accel = knodev->accel;
	struct knod_bpf_priv *priv = accel->xdp.priv;
	struct bpf_offload_dev *bpf_dev;
	int err;

	bpf_dev = bpf_offload_dev_create(&knod_bpf_dev_ops, priv);
	err = PTR_ERR_OR_ZERO(bpf_dev);
	if (err)
		return err;
	err = bpf_offload_dev_netdev_register(bpf_dev, knodev->netdev);
	if (err) {
		bpf_offload_dev_destroy(bpf_dev);
		return err;
	}
	knod_debugfs_init(priv);
	accel->xdp.bpf_dev = bpf_dev;
	return 0;
}

/*
 * Feature deselect, phase 1: unregister the BPF offload device.  This
 * force-frees any user XDP progs/maps still bound; the map-free ndo is
 * routed back through accel_ops.xdp_ops->xdp_install, so the caller keeps
 * xdp_ops pointed at the BPF ops until this returns.
 */
static void knod_bpf_offload_uninit(struct knod_dev *knodev)
{
	struct knod_accel *accel = knodev->accel;
	struct knod_bpf_priv *priv = accel->xdp.priv;

	knod_debugfs_cleanup(priv);
	bpf_offload_dev_netdev_unregister(accel->xdp.bpf_dev, knodev->netdev);
	bpf_offload_dev_destroy(accel->xdp.bpf_dev);
	accel->xdp.bpf_dev = NULL;
}

struct knod_accel_xdp_ops accel_xdp_ops = {
	/* attach/detach: permanent priv struct */
	.init = &knod_accel_xdp_init,
	.exit = &knod_accel_xdp_exit,
	/* feature select: GPU compute buffers (A) + offload dev (B) */
	.activate = &knod_bpf_activate,
	.deactivate = &knod_bpf_deactivate,
	.busy = &knod_bpf_busy,
	.xdp_offload_init = &knod_bpf_offload_init,
	.xdp_offload_uninit = &knod_bpf_offload_uninit,
	.xdp_install = &knod_bpf_xdp_install,
};

/* The persistent shader leaves these no room to vary, so a module line that
 * asks for something else gets the working value and a line in the log rather
 * than an attach that refuses.  Only the geometry, which depends on the GPU,
 * can still fail.
 */
static void knod_bpf_params_sanitize(void)
{
	if (knod_bpf_jit_engine != 1) {
		pr_warn("knod_bpf: jit_engine=%u ignored, the blob is the only engine\n",
			knod_bpf_jit_engine);
		knod_bpf_jit_engine = 1;
	}
}

static int __init knod_bpf_init_module(void)
{
	pr_info("knod-bpf module load\n");
	knod_bpf_params_sanitize();

	/* knod_accel_xdp_register() already calls xdp_ops->init() on every
	 * registered accel, so a second per-accel init loop here would just
	 * re-create the "bpf" debugfs dir ("already exists" warning) and leak
	 * a duplicate offload dev.
	 */
	knod_dev_lock();
	knod_accel_xdp_register(&accel_xdp_ops);
	knod_dev_unlock();

	return 0;
}
late_initcall(knod_bpf_init_module);

static void __exit knod_bpf_cleanup_module(void)
{
	/* knod_accel_xdp_unregister() forces the feature off and runs
	 * xdp_ops->exit() on every attached accel; a per-accel loop here
	 * would run it twice.
	 */
	rtnl_lock();
	knod_dev_lock();
	knod_accel_xdp_unregister();
	knod_dev_unlock();
	rtnl_unlock();
	pr_info("knod-bpf module unload\n");
}
module_exit(knod_bpf_cleanup_module);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Taehee Yoo <ap420073@gmail.com>");
MODULE_DESCRIPTION("AMDGPU BPF offload backend");
MODULE_VERSION("persistent-shader");
