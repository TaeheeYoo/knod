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
#include <linux/reciprocal_div.h>
#include <linux/jhash.h>
#include <net/knod.h>
#include <net/netdev_rx_queue.h>

/*+--------+---------+-------+------+--+-----+------+------+--------+
 *| v0-v21 | v22-v59 |v60-v61| v62  |63|64-65|66-67 |68-69 | v70-127|
 *+--------+---------+-------+------+--+-----+------+------+--------+
 *|BPF REGS|TMP REGS |CTX REG| WIDX |R |DATA |D_END |PGBASE|PKTCACHE|
 *+--------+---------+-------+------+--+-----+------+------+--------+
 *+-----------------+
 *| v128-v255       |
 *+-----------------+
 *| BPF STACK(512B) |
 *+-----------------+
 */

/* Temp register map
 *+-------------+-------------+---------------+---------------+
 *|TREG0 - TREG2|TREG3 - TREG9|TREG10 - TREG16|TREG17 - TREG18|
 *+-------------+-------------+---------------+---------------+
 *| General Use | Key cache A |   Key in MAP  | JHASH Temp Reg|
 *+-------------+-------------+---------------+---------------+
 * Available Key cache size is 56.
 * So, key size of map can't be exceed 56B.
 */

#define KNOD_AMDGPU_VREG0_LO		0 /* v0 */
#define KNOD_AMDGPU_VREG0_HI		1
#define KNOD_AMDGPU_VREG1_LO		2
#define KNOD_AMDGPU_VREG1_HI		3
#define KNOD_AMDGPU_VREG2_LO		4
#define KNOD_AMDGPU_VREG2_HI		5
#define KNOD_AMDGPU_VREG3_LO		6
#define KNOD_AMDGPU_VREG3_HI		7
#define KNOD_AMDGPU_VREG4_LO		8
#define KNOD_AMDGPU_VREG4_HI		9
#define KNOD_AMDGPU_VREG5_LO		10
#define KNOD_AMDGPU_VREG5_HI		11
#define KNOD_AMDGPU_VREG6_LO		12
#define KNOD_AMDGPU_VREG6_HI		13
#define KNOD_AMDGPU_VREG7_LO		14
#define KNOD_AMDGPU_VREG7_HI		15
#define KNOD_AMDGPU_VREG8_LO		16
#define KNOD_AMDGPU_VREG8_HI		17
#define KNOD_AMDGPU_VREG9_LO		18
#define KNOD_AMDGPU_VREG9_HI		19
#define KNOD_AMDGPU_FRAME_POINTER_VREG_LO 20 /* v20 */
#define KNOD_AMDGPU_FRAME_POINTER_VREG_HI 21 /* v20 */

#define KNOD_AMDGPU_TMP_VREG0_LO	22
#define KNOD_AMDGPU_TMP_VREG0_HI	23
#define KNOD_AMDGPU_TMP_VREG1_LO	24
#define KNOD_AMDGPU_TMP_VREG1_HI	25
#define KNOD_AMDGPU_TMP_VREG2_LO	26
#define KNOD_AMDGPU_TMP_VREG2_HI	27
#define KNOD_AMDGPU_TMP_VREG3_LO	28
#define KNOD_AMDGPU_TMP_VREG3_HI	29
#define KNOD_AMDGPU_TMP_VREG4_LO	30
#define KNOD_AMDGPU_TMP_VREG4_HI	31
#define KNOD_AMDGPU_TMP_VREG5_LO	32
#define KNOD_AMDGPU_TMP_VREG5_HI	33
#define KNOD_AMDGPU_TMP_VREG6_LO	34
#define KNOD_AMDGPU_TMP_VREG6_HI	35
#define KNOD_AMDGPU_TMP_VREG7_LO	36
#define KNOD_AMDGPU_TMP_VREG7_HI	37
#define KNOD_AMDGPU_TMP_VREG8_LO	38
#define KNOD_AMDGPU_TMP_VREG8_HI	39
#define KNOD_AMDGPU_TMP_VREG9_LO	40
#define KNOD_AMDGPU_TMP_VREG9_HI	41
#define KNOD_AMDGPU_TMP_VREG10_LO	42
#define KNOD_AMDGPU_TMP_VREG10_HI	43
#define KNOD_AMDGPU_TMP_VREG11_LO	44
#define KNOD_AMDGPU_TMP_VREG11_HI	45
#define KNOD_AMDGPU_TMP_VREG12_LO	46
#define KNOD_AMDGPU_TMP_VREG12_HI	47
#define KNOD_AMDGPU_TMP_VREG13_LO	48
#define KNOD_AMDGPU_TMP_VREG13_HI	49
#define KNOD_AMDGPU_TMP_VREG14_LO	50
#define KNOD_AMDGPU_TMP_VREG14_HI	51
#define KNOD_AMDGPU_TMP_VREG15_LO	52
#define KNOD_AMDGPU_TMP_VREG15_HI	53
#define KNOD_AMDGPU_TMP_VREG16_LO	54
#define KNOD_AMDGPU_TMP_VREG16_HI	55
#define KNOD_AMDGPU_TMP_VREG17_LO	56
#define KNOD_AMDGPU_TMP_VREG17_HI	57
#define KNOD_AMDGPU_TMP_VREG18_LO	58
#define KNOD_AMDGPU_TMP_VREG18_HI	59
#define KNOD_AMDGPU_TMP_VREG_MAX	KNOD_AMDGPU_TMP_VREG18_HI
#define KNOD_AMDGPU_CTX_VREG_LO		60
#define KNOD_AMDGPU_CTX_VREG_HI		61
#define KNOD_AMDGPU_IDX_VREG		62
#define KNOD_AMDGPU_RESERVED		63
/*
 * After prologue step 4, IDX_VREG is no longer needed.
 * v62:v63 are repurposed to hold slot_addr (spsc_bd GTT address)
 * through BPF execution and into the epilogue.
 *
 * BACKLOG_IDX_VREG (v58) saves the backlog index from IDX_VREG
 * before step 6 overwrites it.  Used in epilogue for XDP_PASS.
 */
#define KNOD_AMDGPU_BACKLOG_IDX_VREG	KNOD_AMDGPU_TMP_VREG18_LO /* v58 */
#define KNOD_AMDGPU_SLOT_VREG_LO	KNOD_AMDGPU_IDX_VREG	/* v62 */
#define KNOD_AMDGPU_SLOT_VREG_HI	KNOD_AMDGPU_RESERVED	/* v63 */
/*
 * DATA/DATA_END VGPRs: hold packet gaddr and end address.
 * Set in prologue, read by BPF ctx->data / ctx->data_end accesses.
 * Replaces GTT round-trip (prologue store → BPF load).
 */
#define KNOD_AMDGPU_DATA_VREG_LO	64
#define KNOD_AMDGPU_DATA_VREG_HI	65
#define KNOD_AMDGPU_DATA_END_VREG_LO	66
#define KNOD_AMDGPU_DATA_END_VREG_HI	67
#define KNOD_AMDGPU_PAGE_BASE_VREG_LO	68
#define KNOD_AMDGPU_PAGE_BASE_VREG_HI	69
#define KNOD_AMDGPU_PKT_CACHE_VREG0	70
#define KNOD_AMDGPU_PKT_CACHE_VREG_MAX	127 /* 0 ~ 127 vgprs are available */
#define KNOD_AMDGPU_STACK_VREG0		128
#define KNOD_AMDGPU_STACK_VREG_MAX	255 /* 128 ~ 255 vgprs are available */

#define KNOD_BPF_PROG_BUF_SIZE		32768

/* Index for r64.
 * r64[TREG64_0]
 */
#define TREG64_0			0
#define TREG64_1			1
#define TREG64_2			2
#define TREG64_3			3
#define KEY_IN_PKT_64			TREG64_3
#define TREG64_4			4
#define TREG64_5			5
#define TREG64_6			6
#define TREG64_7			7
#define TREG64_8			8
#define TREG64_9			9
#define TREG64_10			10
#define KEY_IN_MAP_64			TREG64_10
#define TREG64_11			11
#define TREG64_12			12
#define TREG64_13			13
#define TREG64_14			14
#define TREG64_15			15
#define TREG64_16			16
#define TREG64_17			17
#define TREG64_18			18

#define MAX_MAP_KEY_SIZE		56

/* Index for r32.
 * r32[TREG32_0_LO]
 */
#define TREG32_0_LO			0
#define TREG32_0_HI			1
#define TREG32_1_LO			2
#define TREG32_1_HI			3
#define TREG32_2_LO			4
#define TREG32_2_HI			5
#define TREG32_3_LO			6
#define KEY_IN_PKT_32			TREG32_3_LO
#define TREG32_3_HI			7
#define TREG32_4_LO			8
#define TREG32_4_HI			9
#define TREG32_5_LO			10
#define TREG32_5_HI			11
#define TREG32_6_LO			12
#define TREG32_6_HI			13
#define TREG32_7_LO			14
#define TREG32_7_HI			15
#define TREG32_8_LO			16
#define TREG32_8_HI			17
#define TREG32_9_LO			18
#define TREG32_9_HI			19
#define TREG32_10_LO			20
#define KEY_IN_MAP_32			TREG32_10_LO
#define TREG32_10_HI			21
#define TREG32_11_LO			22
#define TREG32_11_HI			23
#define TREG32_12_LO			24
#define TREG32_12_HI			25
#define TREG32_13_LO			26
#define TREG32_13_HI			27
#define TREG32_14_LO			28
#define TREG32_14_HI			29
#define TREG32_15_LO			30
#define TREG32_15_HI			31
#define TREG32_16_LO			32
#define TREG32_16_HI			33
#define TREG32_17_LO			34
#define TREG32_17_HI			35
#define TREG32_18_LO			36
#define TREG32_18_HI			37
#define TREG32_MAX			TREG32_18_HI

/*+--------+--------------------------------------+---+---+
 *| s[0:3] |s[4:5] s[6:7] s[8:9] s[10:11] s[12:13]|s14|s15|
 *+--------+--------------------------------------+---+---+
 *|  PSB   | USER SGPRs (disp/queue/karg/id/flat) |WGX|QID|
 *+--------+--------------------------------------+---+---+
 *+----------------+------+---+---+------+-------+-------------------+
 *|   s[16:27]     |s28:29|s30|s31|s32:33|s34:35 |    s[36:105]      |
 *+----------------+------+---+---+------+-------+-------------------+
 *|TMP_SREG 0-5    |PARAM |FP | - | GFX9 | DONE  | EXEC_SAVE PAIRS   |
 *|(6 x 64-bit)    |SREG  |   |   |BROKE!| MASK  | (max 35, GFX10)   |
 *+----------------+------+---+---+------+-------+-------------------+
 * Implicit: VCC = s[106:107]  EXEC = s[126:127]
 *
 * user_sgpr_count=14, same on GFX9 and GFX10.
 * enable_sgpr_private_segment_size is disabled so that workgroup_id_y
 * lands at s15 and TMP_SREG0_LO stays at s16 (keeps 64-bit SGPR pair
 * alignment; avoids shifting the entire TMP/PARAM/FRAME layout).
 */
#define KNOD_AMDGPU_PSB_SREG		0  /* s[0:3] private_segment_buffer */
#define KNOD_AMDGPU_DISPATCH_PTR_SREG	4  /* s[4:5] dispatch_ptr */
#define KNOD_AMDGPU_ARG_SREG		4  /* alias for dispatch_ptr */
#define KNOD_AMDGPU_QUEUE_PTR_SREG	6  /* s[6:7] queue_ptr */
#define KNOD_AMDGPU_KERNARG_PTR_SREG	8  /* s[8:9] kernarg_segment_ptr */
#define KNOD_AMDGPU_DISPATCH_ID_SREG	10 /* s[10:11] dispatch_id */
#define KNOD_AMDGPU_FLAT_SCR_INIT_SREG	12 /* s[12:13] flat_scratch_init */
#define KNOD_AMDGPU_WORKGROUP_ID_X_SREG	14 /* s14 workgroup_id_x */
#define KNOD_AMDGPU_WORKGROUP_ID_Y_SREG	15 /* s15 workgroup_id_y = queue_id */
#define KNOD_AMDGPU_TMP_SREG0_LO	16
#define KNOD_AMDGPU_TMP_SREG0_HI	17
#define KNOD_AMDGPU_TMP_SREG1_LO	18
#define KNOD_AMDGPU_TMP_SREG1_HI	19
#define KNOD_AMDGPU_TMP_SREG2_LO	20
#define KNOD_AMDGPU_TMP_SREG2_HI	21
#define KNOD_AMDGPU_TMP_SREG3_LO	22
#define KNOD_AMDGPU_TMP_SREG3_HI	23
#define KNOD_AMDGPU_TMP_SREG4_LO	24
#define KNOD_AMDGPU_TMP_SREG4_HI	25
#define KNOD_AMDGPU_TMP_SREG5_LO	26
#define KNOD_AMDGPU_TMP_SREG5_HI	27
#define KNOD_AMDGPU_PARAM_SREG_LO	28 /* s28 */
#define KNOD_AMDGPU_PARAM_SREG_HI	29 /* s29 */
#define KNOD_AMDGPU_FRAME_POINTER_SREG	30 /* s30 */

/* Structurized CFG: EXEC mask save/restore SGPRs.
 * done_mask tracks lanes that have reached BPF_EXIT.
 * exec_save pairs store EXEC at branch points for restore at merge points.
 * GFX9: s[0:101] addressable (102 SGPRs), GFX10: s[0:105] (106 SGPRs).
 * NOTE: s[32:33] is corrupted by GFX9 hardware — do NOT use on GFX9.
 * GFX10 uses s[32:33] for done_mask and starts exec_save at s[34].
 */
/* Common SGPR special register indices (same on GFX9 and GFX10) */
#define AMDGCN_SREG_VCC_LO		106
#define AMDGCN_SREG_EXEC_LO		126
#define AMDGCN_SREG_INTEGER_0		128
#define AMDGCN_SREG_INTEGER_1		129

/* s[34:35] — must not overlap TMP_SREGs */
#define KNOD_AMDGPU_DONE_MASK_SREG	34
#define KNOD_AMDGPU_EXEC_SAVE_SREG_BASE 36 /* s[36:37], s[38:39], ... */
#define KNOD_AMDGPU_INITIAL_EXEC_SREG_GFX9 100
#define KNOD_AMDGPU_INITIAL_EXEC_SREG_GFX10 104
/* exec_save can fill up to each ISA's top usable SGPR pair. GFX9 lays the
 * initial in-bounds EXEC snapshot immediately after the pairs a program
 * actually uses, so small programs keep the old 64-SGPR occupancy window.
 * GFX10 keeps the original high fixed snapshot pair.
 */
#define KNOD_AMDGPU_EXEC_SAVE_SREG_MAX_GFX9  99
#define KNOD_AMDGPU_EXEC_SAVE_SREG_MAX_GFX10 103
#define KNOD_AMDGPU_MAX_EXEC_SAVE_PAIRS_GFX9 \
	((KNOD_AMDGPU_EXEC_SAVE_SREG_MAX_GFX9 - KNOD_AMDGPU_EXEC_SAVE_SREG_BASE + 1) / 2)
#define KNOD_AMDGPU_MAX_EXEC_SAVE_PAIRS_GFX10 \
	((KNOD_AMDGPU_EXEC_SAVE_SREG_MAX_GFX10 - KNOD_AMDGPU_EXEC_SAVE_SREG_BASE + 1) / 2)

static u8 knod_bpf_gfx9_sgpr_granule(unsigned int sgprs_used)
{
	if (sgprs_used <= 16)
		return 0;

	return 2 * (DIV_ROUND_UP(sgprs_used, 16) - 1);
}

unsigned int knod_bpf_workgroups = KNOD_BPF_WORKGROUPS_DEFAULT;
MODULE_PARM_DESC(workgroups, "Workgroup size, multiple of 64, Min(64) Default/Max(256)");
module_param_named(workgroups, knod_bpf_workgroups, int, 0600);

unsigned int knod_bpf_expire = KNOD_BPF_EXPIRE_DEFAULT;
MODULE_PARM_DESC(queue_expire, "Queue expire time(ms), Min(1), Default(10), Max(1000)");
module_param_named(queue_expire, knod_bpf_expire, int, 0600);

unsigned int knod_bpf_pkt_cache;
MODULE_PARM_DESC(packet_cache, "Use packet cache, 0=Off(Default), 1=On");
module_param_named(packet_cache, knod_bpf_pkt_cache, int, 0600);

unsigned int knod_bpf_wave32;
MODULE_PARM_DESC(wave32, "Use wave32 0=Off(Default), 1=On");
module_param_named(wave32, knod_bpf_wave32, int, 0600);

#define KNOD_EA(extack, msg)   NL_SET_ERR_MSG_MOD((extack), msg)

DEFINE_STATIC_KEY_FALSE(knod_stats_key);

static const u32 bl_bounds[KNOD_BL_BUCKETS - 1] = {
	16, 64, 256, 1024, 4096, 8192, 16384
};

static const char * const lat_labels[] = {
	"< 1us", "1-2us", "2-4us", "4-8us", "8-16us",
	"16-32us", "32-64us", "64-128us", "128-256us", ">= 256us",
};

static const char * const bl_labels[] = {
	"1-16", "17-64", "65-256", "257-1K",
	"1K-4K", "4K-8K", "8K-16K", ">= 16K",
};

static LIST_HEAD(priv_list);
struct amdgcn_param64 r64[20], sr64[6], p64[4], bpf_reg64[11];
struct amdgcn_param32 r32[40]; /* last two is CTX */
struct amdgcn_param32 stack[128];
struct amdgcn_param32 pkt_cache[64];

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
static int knod_bpf_worker(void *arg);
static void knod_bpf_drain_worker(struct knod_bpf_priv *priv);
static void knod_prog_free(struct knod_prog *knod_prog);
static void knod_emit_pass_addr_store(struct knod_bpf_priv *priv,
				      struct knod_insn_meta *meta);
static void knod_setup_bpf_prog(struct bpf_prog *prog);

static void knod_bpf_gpu_mem_fence(struct knod_bpf_priv *priv)
{
	if (!priv)
		return;

	/* drain the WC store buffer before the GPU reads the map */
	wmb();
}

static unsigned int knod_bpf_active_rxq_count(struct net_device *netdev)
{
	unsigned int nr_rxq;

	if (!netdev)
		return 0;

	nr_rxq = READ_ONCE(netdev->real_num_rx_queues);
	if (!nr_rxq)
		nr_rxq = netdev->num_rx_queues;

	return min_t(unsigned int, nr_rxq, KNOD_SPSC_MAX);
}

static void knod_bpf_fill_dispatch(struct knod_bpf_priv *priv,
				   struct knod_bpf_work_sq *sqw,
				   struct knod_dispatch_params *p)
{
	struct knod_bpf_param *param = sqw->param->kaddr;

	p->workgroup_size_x = knod_bpf_workgroups;
	p->grid_size_x = priv->batch_size;
	p->grid_size_y = param->nr_queues;
	p->private_segment_size = 8192;
	p->group_segment_size = 8192;
	p->kernel_object =
		(u64)priv->knod->kernels[READ_ONCE(priv->active_idx)]->gaddr;
	p->kernarg_address = sqw->param->gaddr;
}

static void debug_kernel_descriptor(struct kernel_descriptor *kernel_code)
{
	knod_jit_dbg(" kernel_code->group_segment_fixed_size = %d\n",
		kernel_code->group_segment_fixed_size);
	knod_jit_dbg(" kernel_code->private_segment_fixed_size = %d\n",
		kernel_code->private_segment_fixed_size);
	knod_jit_dbg(" kernel_code->kernarg_size = %d\n",
		kernel_code->kernarg_size);
	knod_jit_dbg(" kernel_code->kernel_code_entry_byte_offset = %lld\n",
		kernel_code->kernel_code_entry_byte_offset);
	knod_jit_dbg(" kernel_code->compute_pgm_rsrc3.accum_offset = %d\n",
		kernel_code->compute_pgm_rsrc3.accum_offset);
	knod_jit_dbg(" kernel_code->compute_pgm_rsrc3.reserved0 = %d\n",
		kernel_code->compute_pgm_rsrc3.reserved0);
	knod_jit_dbg(" kernel_code->compute_pgm_rsrc3.tg_split = %d\n",
		kernel_code->compute_pgm_rsrc3.tg_split);
	knod_jit_dbg(" kernel_code->compute_pgm_rsrc3.reserved1 = %d\n",
		kernel_code->compute_pgm_rsrc3.reserved1);
	knod_jit_dbg(" kernel_code->compute_pgm_rsrc1.granulated_workitem_vgpr_count = %d\n",
		kernel_code->compute_pgm_rsrc1.granulated_workitem_vgpr_count);
	knod_jit_dbg(" kernel_code->compute_pgm_rsrc1.granulated_wavefront_sgpr_count = %d\n",
		kernel_code->compute_pgm_rsrc1.granulated_wavefront_sgpr_count);
	knod_jit_dbg(" kernel_code->compute_pgm_rsrc1.priority = %d\n",
		kernel_code->compute_pgm_rsrc1.priority);
	knod_jit_dbg(" kernel_code->compute_pgm_rsrc1.float_round_mode_32 = %d\n",
		kernel_code->compute_pgm_rsrc1.float_round_mode_32);
	knod_jit_dbg(" kernel_code->compute_pgm_rsrc1.float_round_mode_16_64 = %d\n",
		kernel_code->compute_pgm_rsrc1.float_round_mode_16_64);
	knod_jit_dbg(" kernel_code->compute_pgm_rsrc1.float_denorm_mode_32 = %d\n",
		kernel_code->compute_pgm_rsrc1.float_denorm_mode_32);
	knod_jit_dbg(" kernel_code->compute_pgm_rsrc1.float_denorm_mode_16_64 = %d\n",
		kernel_code->compute_pgm_rsrc1.float_denorm_mode_16_64);
	knod_jit_dbg(" kernel_code->compute_pgm_rsrc1.priv = %d\n",
		kernel_code->compute_pgm_rsrc1.priv);
	knod_jit_dbg(" kernel_code->compute_pgm_rsrc1.enable_dx10_clamp = %d\n",
		kernel_code->compute_pgm_rsrc1.enable_dx10_clamp);
	knod_jit_dbg(" kernel_code->compute_pgm_rsrc1.debug_mode = %d\n",
		kernel_code->compute_pgm_rsrc1.debug_mode);
	knod_jit_dbg(" kernel_code->compute_pgm_rsrc1.enable_ieee_mode = %d\n",
		kernel_code->compute_pgm_rsrc1.enable_ieee_mode);
	knod_jit_dbg(" kernel_code->compute_pgm_rsrc1.bulky = %d\n",
		kernel_code->compute_pgm_rsrc1.bulky);
	knod_jit_dbg(" kernel_code->compute_pgm_rsrc1.cdbg_user = %d\n",
		kernel_code->compute_pgm_rsrc1.cdbg_user);
	knod_jit_dbg(" kernel_code->compute_pgm_rsrc1.fp16_ovfl = %d\n",
		kernel_code->compute_pgm_rsrc1.fp16_ovfl);
	knod_jit_dbg(" kernel_code->compute_pgm_rsrc1.reserved0 = %d\n",
		kernel_code->compute_pgm_rsrc1.reserved0);
	knod_jit_dbg(" kernel_code->compute_pgm_rsrc1.wgp_mode = %d\n",
		kernel_code->compute_pgm_rsrc1.wgp_mode);
	knod_jit_dbg(" kernel_code->compute_pgm_rsrc1.mem_ordered = %d\n",
		kernel_code->compute_pgm_rsrc1.mem_ordered);
	knod_jit_dbg(" kernel_code->compute_pgm_rsrc1.fwd_progress = %d\n",
		kernel_code->compute_pgm_rsrc1.fwd_progress);
	knod_jit_dbg(" kernel_code->compute_pgm_rsrc2.enable_private_segment = %d\n",
		kernel_code->compute_pgm_rsrc2.enable_private_segment);
	knod_jit_dbg(" kernel_code->compute_pgm_rsrc2.user_sgpr_count = %d\n",
		kernel_code->compute_pgm_rsrc2.user_sgpr_count);
	knod_jit_dbg(" kernel_code->compute_pgm_rsrc2.enable_trap_handler = %d\n",
		kernel_code->compute_pgm_rsrc2.enable_trap_handler);
	knod_jit_dbg(" kernel_code->compute_pgm_rsrc2.enable_sgpr_workgroup_id_x = %d\n",
		kernel_code->compute_pgm_rsrc2.enable_sgpr_workgroup_id_x);
	knod_jit_dbg(" kernel_code->compute_pgm_rsrc2.enable_sgpr_workgroup_id_y = %d\n",
		kernel_code->compute_pgm_rsrc2.enable_sgpr_workgroup_id_y);
	knod_jit_dbg(" kernel_code->compute_pgm_rsrc2.enable_sgpr_workgroup_id_z = %d\n",
		kernel_code->compute_pgm_rsrc2.enable_sgpr_workgroup_id_z);
	knod_jit_dbg(" kernel_code->compute_pgm_rsrc2.enable_sgpr_workgroup_info = %d\n",
		kernel_code->compute_pgm_rsrc2.enable_sgpr_workgroup_info);
	knod_jit_dbg(" kernel_code->compute_pgm_rsrc2.enable_vgpr_workitem_id = %d\n",
		kernel_code->compute_pgm_rsrc2.enable_vgpr_workitem_id);
	knod_jit_dbg(" kernel_code->compute_pgm_rsrc2.enable_exception_address_watch = %d\n",
		kernel_code->compute_pgm_rsrc2.enable_exception_address_watch);
	knod_jit_dbg(" kernel_code->compute_pgm_rsrc2.enable_exception_memory = %d\n",
		kernel_code->compute_pgm_rsrc2.enable_exception_memory);
	knod_jit_dbg(" kernel_code->compute_pgm_rsrc2.granulated_lds_size = %d\n",
		kernel_code->compute_pgm_rsrc2.granulated_lds_size);
	knod_jit_dbg(" kernel_code->compute_pgm_rsrc2.enable_exception_ieee_754_fp_invalid_operation = %d\n",
		kernel_code->compute_pgm_rsrc2
			.enable_exception_ieee_754_fp_invalid_operation);
	knod_jit_dbg(" kernel_code->compute_pgm_rsrc2.enable_exception_fp_denormal_source = %d\n",
		kernel_code->compute_pgm_rsrc2
			.enable_exception_fp_denormal_source);
	knod_jit_dbg(" kernel_code->compute_pgm_rsrc2.enable_exception_ieee_754_fp_division_by_zero = %d\n",
		kernel_code->compute_pgm_rsrc2
			.enable_exception_ieee_754_fp_division_by_zero);
	knod_jit_dbg(" kernel_code->compute_pgm_rsrc2.enable_exception_ieee_754_fp_overflow = %d\n",
		kernel_code->compute_pgm_rsrc2
			.enable_exception_ieee_754_fp_overflow);
	knod_jit_dbg(" kernel_code->compute_pgm_rsrc2.enable_exception_ieee_754_fp_underflow = %d\n",
		kernel_code->compute_pgm_rsrc2
			.enable_exception_ieee_754_fp_underflow);
	knod_jit_dbg(" kernel_code->compute_pgm_rsrc2.enable_exception_ieee_754_fp_inexact = %d\n",
		kernel_code->compute_pgm_rsrc2
			.enable_exception_ieee_754_fp_inexact);
	knod_jit_dbg(" kernel_code->compute_pgm_rsrc2.enable_exception_int_divide_by_zero = %d\n",
		kernel_code->compute_pgm_rsrc2
			.enable_exception_int_divide_by_zero);
	knod_jit_dbg(" kernel_code->compute_pgm_rsrc2.reserved0 = %d\n",
		kernel_code->compute_pgm_rsrc2.reserved0);
	knod_jit_dbg(" kernel_code->code_properties.enable_sgpr_private_segment_buffer = %d\n",
		kernel_code->code_properties
			.enable_sgpr_private_segment_buffer);
	knod_jit_dbg(" kernel_code->code_properties.enable_sgpr_dispatch_ptr = %d\n",
		kernel_code->code_properties.enable_sgpr_dispatch_ptr);
	knod_jit_dbg(" kernel_code->code_properties.enable_sgpr_queue_ptr = %d\n",
		kernel_code->code_properties.enable_sgpr_queue_ptr);
	knod_jit_dbg(" kernel_code->code_properties.enable_sgpr_kernarg_segment_ptr = %d\n",
		kernel_code->code_properties.enable_sgpr_kernarg_segment_ptr);
	knod_jit_dbg(" kernel_code->code_properties.enable_sgpr_dispatch_id = %d\n",
		kernel_code->code_properties.enable_sgpr_dispatch_id);
	knod_jit_dbg(" kernel_code->code_properties.enable_sgpr_flat_scratch_init = %d\n",
		kernel_code->code_properties.enable_sgpr_flat_scratch_init);
	knod_jit_dbg(" kernel_code->code_properties.enable_sgpr_private_segment_size = %d\n",
		kernel_code->code_properties.enable_sgpr_private_segment_size);
	knod_jit_dbg(" kernel_code->code_properties.reserved0 = %d\n",
		kernel_code->code_properties.reserved0);
	knod_jit_dbg(" kernel_code->code_properties.enable_wavefront_size32 = %d\n",
		kernel_code->code_properties.enable_wavefront_size32);
	knod_jit_dbg(" kernel_code->code_properties.uses_dynamic_stack = %d\n",
		kernel_code->code_properties.uses_dynamic_stack);
	knod_jit_dbg(" kernel_code->code_properties.reserved1 = %d\n",
		kernel_code->code_properties.reserved1);
}

static void kfd_kernel_gfx9_init(struct knod *knod)
{
	struct kernel_descriptor *kernel_code = knod->kernels[0]->kaddr;

	kernel_code->group_segment_fixed_size = 0;
	kernel_code->private_segment_fixed_size = 8192;
	kernel_code->kernarg_size = 64;
	kernel_code->kernel_code_entry_byte_offset = 1024;

	/* GFX10+ or GFX90A+ */
	kernel_code->compute_pgm_rsrc3.accum_offset = 0;
	kernel_code->compute_pgm_rsrc3.reserved0 = 0;
	kernel_code->compute_pgm_rsrc3.tg_split = 0;
	kernel_code->compute_pgm_rsrc3.reserved1 = 0;

	kernel_code->compute_pgm_rsrc1.granulated_workitem_vgpr_count =
		(256 / 4) - 1;
	/*
	 * Start with the small GFX9 window. BPF install updates each slot
	 * descriptor when a program needs a larger exec_save/initial_exec
	 * range.
	 */
	kernel_code->compute_pgm_rsrc1.granulated_wavefront_sgpr_count =
		knod_bpf_gfx9_sgpr_granule(52);
	kernel_code->compute_pgm_rsrc1.priority = 0;
	kernel_code->compute_pgm_rsrc1.float_round_mode_32 = 0;
	kernel_code->compute_pgm_rsrc1.float_round_mode_16_64 = 0;
	kernel_code->compute_pgm_rsrc1.float_denorm_mode_32 = 3;
	kernel_code->compute_pgm_rsrc1.float_denorm_mode_16_64 = 3;
	kernel_code->compute_pgm_rsrc1.priv = 0;
	kernel_code->compute_pgm_rsrc1.enable_dx10_clamp = 1;
	kernel_code->compute_pgm_rsrc1.debug_mode = 0;
	kernel_code->compute_pgm_rsrc1.enable_ieee_mode = 1;
	kernel_code->compute_pgm_rsrc1.bulky = 0;
	kernel_code->compute_pgm_rsrc1.cdbg_user = 0;
	kernel_code->compute_pgm_rsrc1.fp16_ovfl = 0;
	kernel_code->compute_pgm_rsrc1.reserved0 = 0;
	kernel_code->compute_pgm_rsrc1.wgp_mode = 0;
	kernel_code->compute_pgm_rsrc1.mem_ordered = 0;
	kernel_code->compute_pgm_rsrc1.fwd_progress = 0;

	kernel_code->compute_pgm_rsrc2.enable_private_segment = 0;
	kernel_code->compute_pgm_rsrc2.user_sgpr_count = 14; /* 4+2+2+2+2+2 */
	kernel_code->compute_pgm_rsrc2.enable_trap_handler = 0;
	kernel_code->compute_pgm_rsrc2.enable_sgpr_workgroup_id_x = 1;
	kernel_code->compute_pgm_rsrc2.enable_sgpr_workgroup_id_y = 1;
	kernel_code->compute_pgm_rsrc2.enable_sgpr_workgroup_id_z = 0;
	kernel_code->compute_pgm_rsrc2.enable_sgpr_workgroup_info = 0;
	kernel_code->compute_pgm_rsrc2.enable_vgpr_workitem_id = 0;
	kernel_code->compute_pgm_rsrc2.enable_exception_address_watch = 0;
	kernel_code->compute_pgm_rsrc2.enable_exception_memory = 0;
	kernel_code->compute_pgm_rsrc2.granulated_lds_size = 0;
	kernel_code->compute_pgm_rsrc2
		.enable_exception_ieee_754_fp_invalid_operation = 0;
	kernel_code->compute_pgm_rsrc2.enable_exception_fp_denormal_source = 0;
	kernel_code->compute_pgm_rsrc2
		.enable_exception_ieee_754_fp_division_by_zero = 0;
	kernel_code->compute_pgm_rsrc2
		.enable_exception_ieee_754_fp_overflow = 0;
	kernel_code->compute_pgm_rsrc2
		.enable_exception_ieee_754_fp_underflow = 0;
	kernel_code->compute_pgm_rsrc2.enable_exception_ieee_754_fp_inexact = 0;
	kernel_code->compute_pgm_rsrc2.enable_exception_int_divide_by_zero = 0;
	kernel_code->compute_pgm_rsrc2.reserved0 = 0;

	/*
	 * User SGPR layout — loaded in fixed order, disabled entries are
	 * skipped (not reserved).  The resulting SGPR map depends on which
	 * flags are enabled:
	 *
	 *   enable_sgpr_private_segment_buffer  → 4 SGPRs  (s[0:3])
	 *   enable_sgpr_dispatch_ptr            → 2 SGPRs  (s[4:5])
	 *   enable_sgpr_queue_ptr               → 2 SGPRs
	 *   enable_sgpr_kernarg_segment_ptr     → 2 SGPRs
	 *   enable_sgpr_dispatch_id             → 2 SGPRs
	 *   enable_sgpr_flat_scratch_init       → 2 SGPRs
	 *   enable_sgpr_private_segment_size    → 1 SGPR
	 *
	 * System SGPRs (WorkgroupId etc.) follow immediately after the
	 * last user SGPR.  user_sgpr_count must match the total above.
	 */
	/* 4 SGPRs */
	kernel_code->code_properties.enable_sgpr_private_segment_buffer = 1;
	/* 2 SGPRs */
	kernel_code->code_properties.enable_sgpr_dispatch_ptr = 1;
	/* 2 SGPRs */
	kernel_code->code_properties.enable_sgpr_queue_ptr = 1;
	/* 2 SGPRs */
	kernel_code->code_properties.enable_sgpr_kernarg_segment_ptr = 1;
	/* 2 SGPRs */
	kernel_code->code_properties.enable_sgpr_dispatch_id = 1;
	/* 2 SGPRs */
	kernel_code->code_properties.enable_sgpr_flat_scratch_init = 1;
	/* disabled → s14/s15 free for workgroup_id */
	kernel_code->code_properties.enable_sgpr_private_segment_size = 0;
	/* total = 14 SGPRs */
	kernel_code->code_properties.reserved0 = 0;
	/* GFX10+ */
	kernel_code->code_properties.enable_wavefront_size32 = 0;
	kernel_code->code_properties.uses_dynamic_stack = 0;
	kernel_code->code_properties.reserved1 = 0;

	debug_kernel_descriptor(kernel_code);
}

static void kfd_kernel_gfx10_init(struct knod *knod)
{
	struct kernel_descriptor *kernel_code = knod->kernels[0]->kaddr;

	kernel_code->group_segment_fixed_size = 0;
	kernel_code->private_segment_fixed_size = 8192;
	kernel_code->kernarg_size = 64;
	kernel_code->kernel_code_entry_byte_offset = 1024;

	/*
	 * User SGPR layout — loaded in fixed order, disabled entries are
	 * skipped (not reserved).  The resulting SGPR map depends on which
	 * flags are enabled:
	 *
	 *   enable_sgpr_private_segment_buffer  → 4 SGPRs  (s[0:3])
	 *   enable_sgpr_dispatch_ptr            → 2 SGPRs  (s[4:5])
	 *   enable_sgpr_queue_ptr               → 2 SGPRs
	 *   enable_sgpr_kernarg_segment_ptr     → 2 SGPRs
	 *   enable_sgpr_dispatch_id             → 2 SGPRs
	 *   enable_sgpr_flat_scratch_init       → 2 SGPRs
	 *   enable_sgpr_private_segment_size    → 1 SGPR
	 *
	 * System SGPRs (WorkgroupId etc.) follow immediately after the
	 * last user SGPR.  user_sgpr_count must match the total above.
	 */
	/* 4 SGPRs */
	kernel_code->code_properties.enable_sgpr_private_segment_buffer = 1;
	/* 2 SGPRs */
	kernel_code->code_properties.enable_sgpr_dispatch_ptr = 1;
	/* 2 SGPRs */
	kernel_code->code_properties.enable_sgpr_queue_ptr = 1;
	/* 2 SGPRs */
	kernel_code->code_properties.enable_sgpr_kernarg_segment_ptr = 1;
	/* 2 SGPRs */
	kernel_code->code_properties.enable_sgpr_dispatch_id = 1;
	/* 2 SGPRs */
	kernel_code->code_properties.enable_sgpr_flat_scratch_init = 1;
	/* disabled → s14/s15 free for workgroup_id */
	kernel_code->code_properties.enable_sgpr_private_segment_size = 0;
	/* total = 14 SGPRs */
	kernel_code->code_properties.reserved0 = 0;
	if (knod_bpf_wave32)
		kernel_code->code_properties.enable_wavefront_size32 = 1;
	else
		kernel_code->code_properties.enable_wavefront_size32 = 0;
	kernel_code->code_properties.uses_dynamic_stack = 0;
	kernel_code->code_properties.reserved1 = 0;

	kernel_code->compute_pgm_rsrc3.accum_offset = 0;
	kernel_code->compute_pgm_rsrc3.reserved0 = 0;
	kernel_code->compute_pgm_rsrc3.tg_split = 0;
	kernel_code->compute_pgm_rsrc3.reserved1 = 0;

	if (kernel_code->code_properties.enable_wavefront_size32 == 1)
		kernel_code->compute_pgm_rsrc1.granulated_workitem_vgpr_count =
			(256 / 8) - 1;
	else
		kernel_code->compute_pgm_rsrc1.granulated_workitem_vgpr_count =
			(256 / 4) - 1;
	kernel_code->compute_pgm_rsrc1.granulated_wavefront_sgpr_count = 0;
	kernel_code->compute_pgm_rsrc1.priority = 0;
	kernel_code->compute_pgm_rsrc1.float_round_mode_32 = 0;
	kernel_code->compute_pgm_rsrc1.float_round_mode_16_64 = 0;
	kernel_code->compute_pgm_rsrc1.float_denorm_mode_32 = 3;
	kernel_code->compute_pgm_rsrc1.float_denorm_mode_16_64 = 3;
	kernel_code->compute_pgm_rsrc1.priv = 0;
	kernel_code->compute_pgm_rsrc1.enable_dx10_clamp = 1;
	kernel_code->compute_pgm_rsrc1.debug_mode = 0;
	kernel_code->compute_pgm_rsrc1.enable_ieee_mode = 1;
	kernel_code->compute_pgm_rsrc1.bulky = 0;
	kernel_code->compute_pgm_rsrc1.cdbg_user = 0;
	kernel_code->compute_pgm_rsrc1.fp16_ovfl = 0;
	kernel_code->compute_pgm_rsrc1.reserved0 = 0;
	kernel_code->compute_pgm_rsrc1.wgp_mode = 0;
	kernel_code->compute_pgm_rsrc1.mem_ordered = 1;
	kernel_code->compute_pgm_rsrc1.fwd_progress = 0;

	kernel_code->compute_pgm_rsrc2.enable_private_segment = 0;
	kernel_code->compute_pgm_rsrc2.user_sgpr_count = 14; /* 4+2+2+2+2+2 */
	kernel_code->compute_pgm_rsrc2.enable_trap_handler = 0;
	kernel_code->compute_pgm_rsrc2.enable_sgpr_workgroup_id_x = 1;
	kernel_code->compute_pgm_rsrc2.enable_sgpr_workgroup_id_y = 1;
	kernel_code->compute_pgm_rsrc2.enable_sgpr_workgroup_id_z = 0;
	kernel_code->compute_pgm_rsrc2.enable_sgpr_workgroup_info = 0;
	kernel_code->compute_pgm_rsrc2.enable_vgpr_workitem_id = 1;
	kernel_code->compute_pgm_rsrc2.enable_exception_address_watch = 0;
	kernel_code->compute_pgm_rsrc2.enable_exception_memory = 0;
	kernel_code->compute_pgm_rsrc2.granulated_lds_size = 0;
	kernel_code->compute_pgm_rsrc2
		.enable_exception_ieee_754_fp_invalid_operation = 0;
	kernel_code->compute_pgm_rsrc2.enable_exception_fp_denormal_source = 0;
	kernel_code->compute_pgm_rsrc2
		.enable_exception_ieee_754_fp_division_by_zero = 0;
	kernel_code->compute_pgm_rsrc2
		.enable_exception_ieee_754_fp_overflow = 0;
	kernel_code->compute_pgm_rsrc2
		.enable_exception_ieee_754_fp_underflow = 0;
	kernel_code->compute_pgm_rsrc2.enable_exception_ieee_754_fp_inexact = 0;
	kernel_code->compute_pgm_rsrc2.enable_exception_int_divide_by_zero = 0;
	kernel_code->compute_pgm_rsrc2.reserved0 = 0;

	debug_kernel_descriptor(kernel_code);
}

static int kfd_kernel_init(struct knod *knod, struct knod_bpf_priv *priv)
{
	struct kernel_descriptor *kd;

	if (!knod->kernels[1])
		return -ENOMEM;

	/*
	 * Pass-through starts on slot 0; the first XDP prog attach stages into
	 * slot 1 and flips the active index there, ping-ponging on each
	 * install.
	 */
	priv->active_idx = 0;

	if (priv->isa_version == 9)
		kfd_kernel_gfx9_init(knod);
	else if (priv->isa_version == 10)
		kfd_kernel_gfx10_init(knod);

	/*
	 * Slot 1 must carry the same kernel-descriptor as slot 0 -- gfx init
	 * only touches slot 0, and slot 1's BO is otherwise uninitialised,
	 * which stalls the compute queue.  Copy the kd + pre-code region.
	 */
	kd = knod->kernels[0]->kaddr;
	memcpy(knod->kernels[1]->kaddr, knod->kernels[0]->kaddr,
	       kd->kernel_code_entry_byte_offset);
	knod_bpf_gpu_mem_fence(priv);

	return 0;
}

static struct knod_bpf_work_sq *
__knod_get_free_work_sq(struct knod_bpf_priv *priv)
{
	return list_first_entry_or_null(&priv->free_list_sqw,
					struct knod_bpf_work_sq, list);
}

/* Prepare a dispatch: peek SPSC rings and fill params, but do not submit.
 * Returns the prepared sqw (with backlogs > 0), or NULL if nothing to do.
 *
 * A single in-flight AQL queue means the worker never has to reserve SPSC
 * ranges ahead of the current dispatch. The SPSC acquired pointer is advanced
 * only after the GPU finishes the dispatch that consumed those entries.
 */
static struct knod_bpf_work_sq *knod_prepare_bpf(struct knod_bpf_priv *priv)
{
	int i, cnt, backlogs = 0;
	struct knod_dev *knodev = priv->knodev;
	struct knod_bpf_work_sq *sqw;
	struct knod_bpf_param *param;

	if (READ_ONCE(priv->installing_kernel))
		return NULL;

	if (!priv->pass_prog_buf && !READ_ONCE(priv->prog))
		return NULL;

	sqw = __knod_get_free_work_sq(priv);
	if (!sqw)
		return NULL;

	param = (struct knod_bpf_param *)sqw->param->kaddr;
	memset(sqw->queue_idx, 0, sizeof(sqw->queue_idx));

	/* 2D dispatch: queue_id = workgroup_id_y, tid = workitem within WG.
	 * Per-queue bds live in sqw->bds[i * batch_size + tid] and shader
	 * indexes sub[] / sqw->bds[] using (queue_id * batch_size + tid).
	 * No cumulative start_idx -- each queue's slot range is fixed by i.
	 */
	for (i = 0; i < priv->nr_works; i++) {
		int slot = i * priv->batch_size;
		unsigned int skip = 0, j;

		/* Stage past every in-flight dispatch's claim on this queue so
		 * the new sqw reads disjoint SPSC slots.  Peek self-limits: if
		 * the ring holds fewer entries past @skip, cnt shrinks (or 0).
		 */
		for (j = 0; j < priv->inflight_cnt; j++)
			skip += priv->inflight[j]->queue_idx[i];

		param->queues[i].count = 0;
		spsc_peek_at(&knodev->wpriv[i].spsc_bds, skip,
			     (void **)&sqw->bds[slot],
			     priv->batch_size, &cnt);
		if (!cnt) {
			sqw->queue_idx[i] = 0;
			param->queues[i].count = 0;
			continue;
		}

		/* Fill queue descriptor for GPU direct SPSC read.
		 * ring_start is the absolute ring position where this sqw
		 * begins — shader reads slots[(ring_start + tid) & mask].
		 * Offset by skip to keep staged sqws disjoint.
		 */
		param->queues[i].pool_gaddr = knodev->wpriv[i].spsc_pool_gaddr;
		param->queues[i].base_gaddr = priv->queue_base_gaddr[i];
		param->queues[i].count = cnt;
		param->queues[i].ring_start =
			knodev->wpriv[i].spsc_bds.acquired + skip;
		param->queues[i].ring_mask =
			knodev->wpriv[i].spsc_bds.mask;

		backlogs += cnt;
		sqw->queue_idx[i] = cnt;
	}
	sqw->backlogs = backlogs;
	param->nr_backlogs = backlogs;
	param->nr_queues = priv->nr_works;
	param->spsc_stride = ALIGN(sizeof(struct spsc_bd), SMP_CACHE_BYTES);
	for (i = 0; i < priv->nr_works; i++) {
		param->pass_count[i] = 0;
		param->pass_meta_buf_gaddr[i] = priv->pass_meta_buf ?
			priv->pass_meta_buf->gaddr +
			(u64)i * priv->pass_pkts_per_queue *
			KNOD_PASS_SLOT_SIZE :
			0;
	}
	param->ktime_ns = ktime_get_ns();

	if (!sqw->backlogs)
		return NULL;

	list_del_init(&sqw->list);
	return sqw;
}

/* Submit a prepared sqw: write AQL packet, ring doorbell, record stats. */
static void knod_submit_bpf(struct knod_bpf_priv *priv,
			     struct knod_bpf_work_sq *sqw)
{
	struct amd_signal *signal =
		(struct amd_signal *)priv->knod->kaql[0].queue_signal->kaddr;
	struct knod_bpf_stats *stats = &priv->stats;
	struct knod_dispatch_params p;
	int i, bucket = KNOD_BL_BUCKETS - 1;

	/* The @inflight_cnt dispatches already in flight decrement the signal
	 * before this one, so this sqw completes when the signal drops below
	 * (current value - inflight_cnt).
	 */
	sqw->sigval = signal->value - priv->inflight_cnt;
	sqw->expire = jiffies + msecs_to_jiffies(knod_bpf_expire);
	if (static_branch_unlikely(&knod_stats_key)) {
		sqw->dispatch_time = ktime_get();

		stats->backlogs_total += sqw->backlogs;
		for (i = 0; i < KNOD_BL_BUCKETS - 1; i++) {
			if (sqw->backlogs <= bl_bounds[i]) {
				bucket = i;
				break;
			}
		}
		stats->backlogs_hist[bucket]++;
	}

	knod_bpf_fill_dispatch(priv, sqw, &p);
	/* publish dispatch params before the AQL packet becomes visible */
	wmb();
	knod_setup_header(priv->knod, &p, 0);
}

/* Phase 1: advance SPSC consumer pointers so next dispatch can peek
 * new entries.
 */
static void knod_complete_acquire(struct knod_bpf_priv *priv,
				  struct knod_bpf_work_sq *sqw)
{
	struct knod_dev *knodev = priv->knodev;
	int i;

	for (i = 0; i < priv->nr_works; i++) {
		if (sqw->queue_idx[i] >= 1) {
			spsc_acquire(&knodev->wpriv[i].spsc_bds, NULL,
				     sqw->queue_idx[i], NULL);
		}
	}
}

/* Phase 2: schedule NAPI and free sqw.  Can run after the next dispatch
 * has been submitted — napi_schedule overlaps with GPU execution.
 */
static void knod_complete_napi(struct knod_bpf_priv *priv,
			       struct knod_bpf_work_sq *sqw)
{
	struct knod_dev *knodev = priv->knodev;
	struct knod_bpf_stats *stats = &priv->stats;
	ktime_t start;
	int i;

	if (static_branch_unlikely(&knod_stats_key))
		start = ktime_get();

	for (i = 0; i < priv->nr_works; i++) {
		if (sqw->queue_idx[i] >= 1)
			knod_napi_kick(&knodev->wpriv[i]);
	}

	sqw->backlogs = 0;
	sqw->expire = 0;
	list_add_tail_rcu(&sqw->list, &priv->free_list_sqw);

	if (static_branch_unlikely(&knod_stats_key)) {
		u64 ns = ktime_to_ns(ktime_sub(ktime_get(), start));

		stats->decode_act_total_ns += ns;
		stats->decode_act_count++;
		if (ns > stats->decode_act_max_ns)
			stats->decode_act_max_ns = ns;
	}
}

static void knod_bpf_update_kernel_descriptor(struct knod_bpf_priv *priv,
					      struct kernel_descriptor *kd,
					      const struct knod_prog *knod_prog)
{
	unsigned int sgprs_used;

	if (priv->isa_version != 9 || !knod_prog)
		return;

	sgprs_used = knod_prog->initial_exec_sreg + 2;
	kd->compute_pgm_rsrc1.granulated_wavefront_sgpr_count =
		knod_bpf_gfx9_sgpr_granule(sgprs_used);
}

/*
 * Install kernel code into the inactive slot and atomically flip the active
 * index.  The active slot is never modified while the GPU dispatches it, so
 * the swap never races the live pipeline, and the worker is not touched: new
 * dispatches pick up the new slot, the in-flight one finishes on the old slot.
 */
static void knod_bpf_install_kernel(struct knod_bpf_priv *priv,
				    const struct knod_prog *knod_prog,
				    const void *code, u32 size)
{
	struct kernel_descriptor *kd;
	struct knod *knod = priv->knod;
	struct knod_mem *slot;
	u32 entry_off;
	u32 image_len;
	int idx;

	if (!code || !size || !knod->kernels[1])
		return;

	/*
	 * Before the worker runs, install in place; once it is dispatching,
	 * stage into the inactive slot and flip the active index so the live
	 * pipeline never reads a half-written slot.
	 */
	if (!priv->start || !knod->worker)
		idx = priv->active_idx;
	else
		idx = priv->active_idx ^ 1;

	slot = knod->kernels[idx];
	kd = slot->kaddr;
	knod_bpf_update_kernel_descriptor(priv, kd, knod_prog);
	entry_off = kd->kernel_code_entry_byte_offset;
	if (WARN_ON(entry_off >= slot->size))
		return;
	if (WARN_ON(size > slot->size - entry_off))
		size = slot->size - entry_off;
	image_len = entry_off + size;

	memcpy(slot->kaddr + entry_off, code, size);
	if (image_len < slot->size) {
		u32 clear_end = min_t(u32, slot->size,
					  entry_off + KNOD_BPF_PROG_BUF_SIZE);

		if (image_len < clear_end)
			memset(slot->kaddr + image_len, 0,
			       clear_end - image_len);
	}
	/*
	 * kernels[] is write-combining VRAM.  smp_wmb() is only a compiler
	 * barrier on x86 and does NOT drain the WC buffers, so the GPU could
	 * fetch half-written code and spin.  wmb() (sfence) flushes WC to VRAM
	 * before we publish the new slot; the dispatch doorbell is ordered
	 * behind it.
	 */
	wmb();
	knod_bpf_gpu_mem_fence(priv);
	WRITE_ONCE(priv->kernel_image_len[idx], image_len);

	if (idx != priv->active_idx)
		WRITE_ONCE(priv->active_idx, idx);
}

/*
 * Keep the just-built pass-kernel IR for the debugfs "insn" dump, so it can
 * show the pass-through kernel when no XDP prog is attached.  The machine code
 * already lives in the kernel slot; this only retains the meta list.  Rebuilt
 * on every start (old metas freed first), released in knod_priv_exit().
 */
static void knod_bpf_retain_pass_ir(struct knod_bpf_priv *priv,
				    struct knod_prog *src)
{
	struct knod_insn_meta *meta, *tmp;
	struct knod_prog *dst = priv->pass_knod_prog;

	if (!dst) {
		dst = kzalloc_obj(*dst, GFP_KERNEL);
		if (!dst)
			return;
		INIT_LIST_HEAD(&dst->pre_insns);
		INIT_LIST_HEAD(&dst->insns);
		INIT_LIST_HEAD(&dst->post_insns);
		priv->pass_knod_prog = dst;
	} else {
		list_for_each_entry_safe(meta, tmp, &dst->pre_insns, l) {
			list_del(&meta->l);
			kfree(meta);
		}
		list_for_each_entry_safe(meta, tmp, &dst->insns, l) {
			list_del(&meta->l);
			kfree(meta);
		}
		list_for_each_entry_safe(meta, tmp, &dst->post_insns, l) {
			list_del(&meta->l);
			kfree(meta);
		}
	}
	list_splice_init(&src->pre_insns, &dst->pre_insns);
	list_splice_init(&src->insns, &dst->insns);
	list_splice_init(&src->post_insns, &dst->post_insns);
}

static void knod_bpf_layout_sregs(struct knod_bpf_priv *priv,
				  struct knod_prog *knod_prog)
{
	if (priv->isa_version != 9)
		return;

	knod_prog->initial_exec_sreg =
		knod_prog->exec_save_base + knod_prog->exec_save_pairs_used * 2;
}

static int knod_bpf_jit_pass_kernel(struct knod_bpf_priv *priv)
{
	struct list_head *lists[2];
	struct knod_insn_meta *meta, *tmp, *epi;
	struct amdgcn_param32 p[3];
	struct knod *knod = priv->knod;
	struct knod_prog pass_prog;
	int pass_branch_idx;
	u32 pass_dwords;
	u8 *buf, *ptr;
	u32 total = 0;
	int i, j, li, err;

	memset(&pass_prog, 0, sizeof(pass_prog));
	INIT_LIST_HEAD(&pass_prog.pre_insns);
	INIT_LIST_HEAD(&pass_prog.insns);
	INIT_LIST_HEAD(&pass_prog.post_insns);
	pass_prog.knod = knod;
	pass_prog.knodev = priv->knodev;
	if (priv->isa_version == 10) {
		pass_prog.done_mask_sreg = 32;
		pass_prog.exec_save_base = 34;
		pass_prog.initial_exec_sreg =
			KNOD_AMDGPU_INITIAL_EXEC_SREG_GFX10;
	} else {
		pass_prog.done_mask_sreg = KNOD_AMDGPU_DONE_MASK_SREG;
		pass_prog.exec_save_base = KNOD_AMDGPU_EXEC_SAVE_SREG_BASE;
		pass_prog.initial_exec_sreg =
			KNOD_AMDGPU_INITIAL_EXEC_SREG_GFX9;
	}

	knod_bpf_layout_sregs(priv, &pass_prog);
	err = knod_prog_prepare_insns(priv, &pass_prog);
	if (err)
		return err;

	epi = kzalloc_obj(*epi, GFP_KERNEL);
	if (!epi) {
		err = -ENOMEM;
		goto free_pro;
	}

	/* BPF/XDP actions are 32-bit values; mlx5 consumes bd->act as low32. */
	knod_vset32(&p[0], KNOD_AMDGPU_VREG0_LO);
	knod_iset32(&p[1], XDP_PASS);
	knod_emit(priv, epi, v_mov_b32_e32, p[0], p[1]);

	knod_vset32(&p[0], KNOD_AMDGPU_VREG0_LO);
	knod_vset32(&p[1], KNOD_AMDGPU_SLOT_VREG_LO);
	knod_emit(priv, epi, global_store_dword, p[0], p[1],
		  offsetof(struct spsc_bd, act));

	/* XDP_PASS detection: v_cmp_eq_u32 XDP_PASS, R0 → VCC */
	knod_iset32(&p[0], XDP_PASS);
	knod_vset32(&p[1], KNOD_AMDGPU_VREG0_LO);
	knod_emit(priv, epi, v_cmp_eq_u32, p[0], p[1]);

	pass_branch_idx = epi->amdgpu_insns;
	knod_emit(priv, epi, s_cbranch_vccz, 0);

	/* EXEC &= VCC — only PASS lanes proceed */
	knod_emit(priv, epi, s_and_b64, AMDGCN_SREG_EXEC_LO,
		  AMDGCN_SREG_EXEC_LO, AMDGCN_SREG_VCC_LO);

	/* v_mov param addr to VGPR pair for pass_count atomic */
	knod_vset32(&p[0], KNOD_AMDGPU_TMP_VREG9_LO);
	knod_sset32(&p[1], KNOD_AMDGPU_PARAM_SREG_LO);
	knod_emit(priv, epi, v_mov_b32_e32, p[0], p[1]);

	knod_vset32(&p[0], KNOD_AMDGPU_TMP_VREG9_HI);
	knod_sset32(&p[1], KNOD_AMDGPU_PARAM_SREG_HI);
	knod_emit(priv, epi, v_mov_b32_e32, p[0], p[1]);

	/* v_mov v2, s15 (queue_idx → VGPR) */
	knod_vset32(&p[0], KNOD_AMDGPU_VREG1_LO);
	knod_sset32(&p[1], KNOD_AMDGPU_WORKGROUP_ID_Y_SREG);
	knod_emit(priv, epi, v_mov_b32_e32, p[0], p[1]);

	/* v_lshlrev_b32 v2, 2, v2 (queue_idx * 4) */
	knod_vset32(&p[0], KNOD_AMDGPU_VREG1_LO);
	knod_iset32(&p[1], 2);
	knod_vset32(&p[2], KNOD_AMDGPU_VREG1_LO);
	knod_emit(priv, epi, v_lshlrev_b32, p[0], p[1], p[2]);

	/* v_add_u32 TMP9_LO, v2, TMP9_LO (param_addr += queue_idx * 4) */
	knod_vset32(&p[0], KNOD_AMDGPU_TMP_VREG9_LO);
	knod_vset32(&p[1], KNOD_AMDGPU_VREG1_LO);
	knod_vset32(&p[2], KNOD_AMDGPU_TMP_VREG9_LO);
	knod_emit(priv, epi, v_add_u32, p[0], p[1], p[2]);

	/* v_mov TMP10_LO, 1 */
	knod_vset32(&p[0], KNOD_AMDGPU_TMP_VREG10_LO);
	knod_iset32(&p[1], 1);
	knod_emit(priv, epi, v_mov_b32_e32, p[0], p[1]);

	/* global_atomic_add pass_count[q]++, GLC=1 → old_val in TMP10_LO */
	knod_vset32(&p[0], KNOD_AMDGPU_TMP_VREG10_LO);
	knod_vset32(&p[1], KNOD_AMDGPU_TMP_VREG9_LO);
	knod_vset32(&p[2], KNOD_AMDGPU_TMP_VREG10_LO);
	knod_emit(priv, epi, global_atomic_add, p[0], p[1], p[2],
		  offsetof(struct knod_bpf_param, pass_count), 1);

	/* s_waitcnt vmcnt(0) */
	knod_emit(priv, epi, s_waitcnt_vmcnt);

	/* v_sub_u32 TMP9_LO, TMP9_LO, v2 (restore param_addr_lo) */
	knod_vset32(&p[0], KNOD_AMDGPU_TMP_VREG9_LO);
	knod_vset32(&p[1], KNOD_AMDGPU_TMP_VREG9_LO);
	knod_vset32(&p[2], KNOD_AMDGPU_VREG1_LO);
	knod_emit(priv, epi, v_sub_u32, p[0], p[1], p[2]);

	/* old_val * 2 for pass_indices u16 stride */
	knod_vset32(&p[0], KNOD_AMDGPU_TMP_VREG10_LO);
	knod_iset32(&p[1], 1);
	knod_vset32(&p[2], KNOD_AMDGPU_TMP_VREG10_LO);
	knod_emit(priv, epi, v_lshlrev_b32, p[0], p[1], p[2]);

	/* addr_lo += old_val * 2 */
	knod_vset32(&p[0], KNOD_AMDGPU_TMP_VREG9_LO);
	knod_vset32(&p[1], KNOD_AMDGPU_TMP_VREG10_LO);
	knod_vset32(&p[2], KNOD_AMDGPU_TMP_VREG9_LO);
	knod_emit(priv, epi, v_add_u32, p[0], p[1], p[2]);

	/* global_store_short pass_indices[old_val], BACKLOG_IDX_VREG */
	knod_vset32(&p[0], KNOD_AMDGPU_BACKLOG_IDX_VREG);
	knod_vset32(&p[1], KNOD_AMDGPU_TMP_VREG9_LO);
	knod_emit(priv, epi, global_store_short, p[0], p[1],
		  offsetof(struct knod_bpf_param, pass_indices));

	/* Store len + src_addr to pass_meta_buf slot header */
	knod_emit_pass_addr_store(priv, epi);

	/* Patch s_cbranch_vccz offset (skip pass handling) */
	pass_dwords = 0;
	for (j = pass_branch_idx + 1; j < epi->amdgpu_insns; j++)
		pass_dwords += epi->amdgpu_insn[j].size / 4;
	emit_s_cbranch_vccz(priv->isa_version,
			    &epi->amdgpu_insn[pass_branch_idx], pass_dwords);

	knod_emit(priv, epi, s_endpgm);

	if (priv->isa_version >= 10) {
		for (j = 0; j < 16 && epi->amdgpu_insns < KNOD_META_INSNS; j++)
			knod_emit(priv, epi, s_code_end);
	}
	list_add_tail(&epi->l, &pass_prog.post_insns);

	/* Linearize prologue + epilogue into pass_prog_buf */
	lists[0] = &pass_prog.pre_insns;
	lists[1] = &pass_prog.post_insns;

	for (li = 0; li < 2; li++) {
		list_for_each_entry(meta, lists[li], l)
			for (i = 0; i < meta->amdgpu_insns; i++)
				total += meta->amdgpu_insn[i].size;
	}

	kfree(priv->pass_prog_buf);
	buf = kzalloc(total, GFP_KERNEL);
	if (!buf) {
		err = -ENOMEM;
		goto free_all;
	}

	ptr = buf;
	for (li = 0; li < 2; li++) {
		list_for_each_entry(meta, lists[li], l)
			for (i = 0; i < meta->amdgpu_insns; i++) {
				memcpy(ptr, &meta->amdgpu_insn[i],
				       meta->amdgpu_insn[i].size);
				ptr += meta->amdgpu_insn[i].size;
			}
	}

	priv->pass_prog_buf = buf;
	priv->pass_prog_size = total;

	knod_bpf_install_kernel(priv, &pass_prog, priv->pass_prog_buf,
				priv->pass_prog_size);
	/* Remember which slot now holds pass so detach can flip back to it. */
	priv->pass_idx = priv->active_idx;

	pr_info("knod_bpf: pass kernel JIT'd %u bytes\n", priv->pass_prog_size);
	err = 0;
	/* Retain the IR (moves the lists out) before the cleanup below
	 * frees.
	 */
	knod_bpf_retain_pass_ir(priv, &pass_prog);

free_all:
	list_for_each_entry_safe(meta, tmp, &pass_prog.post_insns, l) {
		list_del_init(&meta->l);
		kfree(meta);
	}
free_pro:
	list_for_each_entry_safe(meta, tmp, &pass_prog.pre_insns, l) {
		list_del_init(&meta->l);
		kfree(meta);
	}
	return err;
}

static void knod_bpf_reset_sqw(struct knod_bpf_work_sq *sqw)
{
	if (!sqw)
		return;

	sqw->backlogs = 0;
	sqw->expire = 0;
}

static void knod_bpf_wait_sqw(struct knod_bpf_priv *priv,
			      struct knod_bpf_work_sq *sqw)
{
	struct amd_signal *signal;
	unsigned long deadline;

	if (!sqw)
		return;

	signal = (struct amd_signal *)
		priv->knod->kaql[0].queue_signal->kaddr;
	deadline = jiffies + msecs_to_jiffies(1000);

	while (sqw->sigval <= READ_ONCE(signal->value) &&
	       time_before(jiffies, deadline))
		usleep_range(100, 200);

	if (sqw->sigval <= READ_ONCE(signal->value))
		pr_warn("knod: timed out waiting for GPU dispatch completion\n");
}

static void knod_bpf_drain_worker(struct knod_bpf_priv *priv)
{
	struct knod_bpf_work_sq *sqw;

	/* stop() runs on interface-down AND on every feature switch, both
	 * with mlx5 RX possibly still producing into knodev->wpriv[].spsc_bds.
	 * So we only quiesce the GPU here; the NIC-owned RX SPSC rings are
	 * drained on interface-down by mlx5e_rx_offload_stop().
	 */
	while (priv->inflight_cnt) {
		sqw = priv->inflight[--priv->inflight_cnt];
		priv->inflight[priv->inflight_cnt] = NULL;
		knod_bpf_wait_sqw(priv, sqw);
		knod_bpf_reset_sqw(sqw);
		list_add_tail_rcu(&sqw->list, &priv->free_list_sqw);
	}
}

static void knod_bpf_drain(struct knod_bpf_priv *priv)
{
	knod_bpf_drain_worker(priv);
}

static void knod_bpf_stop_worker(struct knod_bpf_priv *priv)
{
	priv->start = 0;
	if (priv->worker_task) {
		kthread_stop(priv->worker_task);
		put_task_struct(priv->worker_task);
		priv->worker_task = NULL;
	}
	synchronize_net();
}

static void knod_bpf_configure_worker(struct knod_bpf_priv *priv)
{
	knod_bpf_stop_worker(priv);
	knod_bpf_drain(priv);

	priv->inflight_cnt = 0;
}

static int knod_bpf_start_worker(struct knod_bpf_priv *priv)
{
	struct task_struct *p;

	p = kthread_run(knod_bpf_worker, priv, "knod_%d_0",
			priv->knodev->accel->id);
	if (IS_ERR(p))
		return PTR_ERR(p);

	get_task_struct(p);
	priv->worker_task = p;
	return 0;
}

static bool knod_bpf_uses_percpu(struct knod_bpf_priv *priv)
{
	struct knod_bpf_map *knod_map;

	list_for_each_entry(knod_map, &priv->knodev->accel->xdp.bound_maps,
			    list)
		if (knod_map->knod_map_obj->map_type ==
		    BPF_MAP_TYPE_PERCPU_ARRAY)
			return true;
	return false;
}

/* Fan out one workgroup per CU (rounded down to a power of two).  PERCPU maps
 * keep one instance per RX queue, so a queue must stay on a single workgroup;
 * force xgroups=1 when the program uses them.  Non-PERCPU maps are globally
 * shared with atomics, so fan-out is safe there.  This replaces the old manual
 * xgroups knob.
 */
static unsigned int knod_bpf_auto_xgroups(struct knod_bpf_priv *priv)
{
	struct amdgpu_device *adev = NULL;
	unsigned int cus, xgroups;

	if (knod_bpf_uses_percpu(priv))
		return 1;

	if (priv->knod->dev)
		adev = priv->knod->dev->adev;
	else if (priv->knod->process && priv->knod->process->pdds[0])
		adev = priv->knod->process->pdds[0]->dev->adev;
	if (!adev || !priv->nr_works)
		return 1;

	cus = adev->gfx.cu_info.number;
	xgroups = cus / priv->nr_works;
	if (!xgroups)
		xgroups = 1;
	return rounddown_pow_of_two(xgroups);
}

/* Per-queue dispatch batch = workgroups * xgroups packets, capped by the
 * static descriptor array and rounded down to a power of two (the shader
 * derives the flat slot as queue_id << ilog2(batch_size) + local_idx).
 */
static unsigned int knod_bpf_batch_size(struct knod_bpf_priv *priv)
{
	unsigned int xgroups = knod_bpf_auto_xgroups(priv);
	unsigned int max_flat = KNOD_BPF_BACKLOGS_MAX / priv->nr_works;
	unsigned int batch = min_t(unsigned int,
				   knod_bpf_workgroups * xgroups, max_flat);

	if (!batch)
		batch = knod_bpf_workgroups;
	return rounddown_pow_of_two(batch);
}

static void knod_bpf_start(struct knod_dev *knodev)
{
	struct knod_bpf_priv *priv =
		(struct knod_bpf_priv *)knodev->accel->xdp.priv;
	struct bpf_prog *prog;
	unsigned int active_rxq;
	int err;

	priv->start = 1;
	active_rxq = knod_bpf_active_rxq_count(knodev->netdev);
	if (active_rxq && active_rxq != priv->nr_works)
		pr_warn("knod_bpf: active rx queues changed from %d to %u; using initialized count\n",
			priv->nr_works, active_rxq);

	priv->batch_size = knod_bpf_batch_size(priv);

	knod_jit_dbg(" batch_size = %d\n", priv->batch_size);
	knod_bpf_configure_worker(priv);
	pr_info("knod_bpf: using single AQL queue, rx_works=%d active_rxq=%u batch_size=%d xgroups=%u\n",
		priv->nr_works, active_rxq, priv->batch_size,
		priv->batch_size / knod_bpf_workgroups);

	if (knod_bpf_jit_pass_kernel(priv))
		pr_warn("knod_bpf: pass kernel JIT failed\n");

	prog = READ_ONCE(priv->prog);
	if (prog)
		knod_setup_bpf_prog(prog);

	priv->start = 1;
	err = knod_bpf_start_worker(priv);
	if (err) {
		pr_err("knod_bpf: start_worker failed: %d\n", err);
		priv->start = 0;
		return;
	}
}

static void knod_bpf_stop(struct knod_dev *knodev)
{
	struct knod_bpf_priv *priv =
		(struct knod_bpf_priv *)knodev->accel->xdp.priv;

	knod_bpf_stop_worker(priv);
	knod_bpf_drain(priv);

	kfree(priv->pass_prog_buf);
	priv->pass_prog_buf = NULL;
	priv->pass_prog_size = 0;
}

/*
 * Flip the dispatched kernel back to pass-through when the XDP prog is
 * detached.  The pass slot already holds the pass code, so this is just an
 * atomic index flip -- no re-copy.
 */
static void knod_bpf_reload_pass(struct knod_dev *knodev)
{
	struct knod_bpf_priv *priv = knodev->accel->xdp.priv;

	if (priv)
		WRITE_ONCE(priv->active_idx, priv->pass_idx);
}

static void knod_setup_bpf_prog(struct bpf_prog *prog)
{
	struct knod_prog *knod_prog = prog->aux->offload->dev_priv;
	struct knod_dev *knodev = knod_prog->knodev;
	struct knod_insn_meta *meta, *tmp;
	struct knod_bpf_priv *priv;
	u8 *kernel_ptr, *ptr;
	u32 total_bytes;
	u32 *debug_ptr;
	int i;

	priv = (struct knod_bpf_priv *)knodev->accel->xdp.priv;
	WRITE_ONCE(priv->installing_kernel, true);

	if (prog) {
		WRITE_ONCE(priv->prog, NULL);
		kernel_ptr = priv->prog_buf;
		memset(priv->prog_buf, 0, KNOD_BPF_PROG_BUF_SIZE);

		list_for_each_entry(meta, &priv->knod_prog->pre_insns, l) {
			for (i = 0; i < meta->amdgpu_insns; i++) {
				ptr = (u8 *)&meta->amdgpu_insn[i];
				debug_ptr = (u32 *)ptr;

				memcpy(kernel_ptr, ptr,
				       meta->amdgpu_insn[i].size);
				kernel_ptr += meta->amdgpu_insn[i].size;

				if (meta->amdgpu_insn[i].size == 4) {
					knod_jit_dbg(" 0x%.8X\t%.8X\n",
						meta->amdgpu_insn_idx,
						debug_ptr[0]);
				} else if (meta->amdgpu_insn[i].size == 8) {
					knod_jit_dbg(" 0x%.8X\t%.8X %.8X\n",
						meta->amdgpu_insn_idx,
						debug_ptr[0], debug_ptr[1]);
				} else if (meta->amdgpu_insn[i].size == 12) {
					knod_jit_dbg(" 0x%.8X\t%.8X %.8X %.8X\n",
						meta->amdgpu_insn_idx,
						debug_ptr[0],
						debug_ptr[1], debug_ptr[2]);
				} else {
					WARN_ON(1);
				}
			}
		}

		list_for_each_entry(meta, &priv->knod_prog->insns, l) {
			for (i = 0; i < meta->amdgpu_insns; i++) {
				ptr = (u8 *)&meta->amdgpu_insn[i];
				debug_ptr = (u32 *)ptr;

				memcpy(kernel_ptr, ptr,
				       meta->amdgpu_insn[i].size);
				kernel_ptr += meta->amdgpu_insn[i].size;
				if (meta->amdgpu_insn[i].size == 4) {
					knod_jit_dbg(" 0x%.8X\t%.8X\n",
						meta->amdgpu_insn_idx,
						debug_ptr[0]);
				} else if (meta->amdgpu_insn[i].size == 8) {
					knod_jit_dbg(" 0x%.8X\t%.8X %.8X\n",
						meta->amdgpu_insn_idx,
						debug_ptr[0], debug_ptr[1]);
				} else if (meta->amdgpu_insn[i].size == 12) {
					knod_jit_dbg(" 0x%.8X\t%.8X %.8X %.8X\n",
						meta->amdgpu_insn_idx,
						debug_ptr[0],
						debug_ptr[1], debug_ptr[2]);
				} else {
					WARN_ON(1);
				}
			}
		}

		list_for_each_entry(meta, &priv->knod_prog->post_insns, l) {
			for (i = 0; i < meta->amdgpu_insns; i++) {
				ptr = (u8 *)&meta->amdgpu_insn[i];
				debug_ptr = (u32 *)ptr;

				memcpy(kernel_ptr, ptr,
				       meta->amdgpu_insn[i].size);
				kernel_ptr += meta->amdgpu_insn[i].size;
				if (meta->amdgpu_insn[i].size == 4) {
					knod_jit_dbg(" %.8X\n", debug_ptr[0]);
				} else if (meta->amdgpu_insn[i].size == 8) {
					knod_jit_dbg(" %.8X %.8X\n",
						debug_ptr[0], debug_ptr[1]);
				} else if (meta->amdgpu_insn[i].size == 12) {
					knod_jit_dbg(" %.8X %.8X %.8X\n",
						debug_ptr[0],
						debug_ptr[1], debug_ptr[2]);
				} else {
					WARN_ON(1);
				}
			}
		}
		total_bytes = kernel_ptr - (u8 *)priv->prog_buf;

		pr_debug("KNOD JIT: total binary size = %u bytes (limit %u)\n",
			 total_bytes, KNOD_BPF_PROG_BUF_SIZE);
		if (WARN_ON(total_bytes > KNOD_BPF_PROG_BUF_SIZE))
			total_bytes = KNOD_BPF_PROG_BUF_SIZE;
		knod_bpf_install_kernel(priv, knod_prog, priv->prog_buf,
					total_bytes);
		WRITE_ONCE(priv->prog, prog);
	} else {
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

		if (priv->pass_prog_buf)
			knod_bpf_install_kernel(priv, priv->pass_knod_prog,
						priv->pass_prog_buf,
						priv->pass_prog_size);
	}
	WRITE_ONCE(priv->installing_kernel, false);
}

static int knod_bpf_map_hash_init_elem(struct knod_bpf_map *knod_map,
				       struct knod_bpf_map_obj *knod_map_obj)
{
	unsigned int *queue = (unsigned int *)knod_map->queue_mem->kaddr;
	unsigned int *bucket = (unsigned int *)&knod_map_obj->bucket[0];
	void *elems = knod_map->hash_elems_mem->kaddr;
	struct knod_bpf_hash_elem_obj *e;
	int i, elem_size;

	elem_size = sizeof(struct knod_bpf_hash_elem_obj) +
			   roundup(knod_map_obj->key_size, 4) +
			   roundup(knod_map_obj->value_size, 4);
	knod_map_obj->meta.hmeta.elem_size = elem_size;

	for (i = 0; i < knod_map_obj->meta.hmeta.n_buckets; i++)
		bucket[i] = KNOD_BPF_HASH_NEXT_END;

	for (i = 0; i < knod_map_obj->max_entries; i++) {
		e = elems + (i * elem_size);
		e->next = KNOD_BPF_HASH_NEXT_END;
		queue[i] = i;
	}
	knod_map_obj->meta.hmeta.cur = knod_map_obj->max_entries - 1;

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

static int __knod_bpf_map_alloc(struct knod_dev *knodev,
				struct bpf_offloaded_map *offmap)
{
	struct knod_bpf_priv *priv =
		(struct knod_bpf_priv *)knodev->accel->xdp.priv;
	struct knod_mem *mem, *queue_mem, *hash_elems_mem, *gc_mem;
	int order, size, queue_size, i, value_size, nents, err;
	int n_instances = 1;
	int flags = KFD_IOC_ALLOC_MEM_FLAGS_WRITABLE |
		    KFD_IOC_ALLOC_MEM_FLAGS_COHERENT |
		    KFD_IOC_ALLOC_MEM_FLAGS_PUBLIC |
		    KFD_IOC_ALLOC_MEM_FLAGS_VRAM;
	struct knod_bpf_map_obj *knod_map_obj;
	struct knod *knod = priv->knod;
	struct knod_bpf_map *knod_map;
	unsigned int gc_size;
	unsigned int *q;

	if (offmap->map.map_type == BPF_MAP_TYPE_HASH) {
		value_size = sizeof(unsigned int);
		nents = roundup_pow_of_two(offmap->map.max_entries);
	} else {
		value_size = offmap->map.value_size;
		nents = offmap->map.max_entries;
	}

	/* PERCPU_ARRAY keeps one value array per GPU workgroup (percpu
	 * instance) so each CU updates its own copy — no cross-CU atomic
	 * contention.  Instances map 1:1 to the per-cpu value buffer, so
	 * allocate num_possible_cpus of them (workgroup_id_y indexes into it).
	 */
	if (offmap->map.map_type == BPF_MAP_TYPE_PERCPU_ARRAY)
		n_instances = num_possible_cpus();

	size = sizeof(struct knod_bpf_map_obj) +
	       (value_size * nents * n_instances);
	if (offmap->map.map_type == BPF_MAP_TYPE_HASH)
		size += sizeof(unsigned int) * nents;
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
		WARN_ON(1);
	offmap->dev_priv = knod_map;

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
	if (knod_map_obj->map_type == BPF_MAP_TYPE_HASH) {
		knod_map_obj->meta.hmeta.n_buckets = nents;
		if (offmap->map.map_flags & BPF_F_ZERO_SEED)
			knod_map_obj->meta.hmeta.hashrnd = 0;
		else
			knod_map_obj->meta.hmeta.hashrnd = get_random_u32();
	} else {
		knod_map_obj->meta.ameta.per_instance_size = value_size * nents;
		knod_map_obj->meta.ameta.n_instances = n_instances;
	}
	knod_map->knod_map_obj = knod_map_obj;
	/* map->flags = ? */
	knod_jit_dbg(" map_id = %d\n", knod_map_obj->id);

	if (knod_map_obj->map_type == BPF_MAP_TYPE_HASH) {
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

		queue_size = (sizeof(struct knod_bpf_hash_elem_obj) +
			      roundup(knod_map_obj->key_size, 4) +
			      roundup(knod_map_obj->value_size, 4)) *
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

	err = __knod_map_mem(knod, mem);
	if (err) {
		pr_err("knod_bpf: failed to GPU-map map BO\n");
		goto err_map;
	}
	if (knod_map_obj->map_type == BPF_MAP_TYPE_HASH) {
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
	if (knod_map_obj->map_type == BPF_MAP_TYPE_HASH) {
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

	if (knod_map_obj->meta.hmeta.cur < 1)
		return NULL;

	elem_id = queue[knod_map_obj->meta.hmeta.cur];
	knod_jit_dbg(" elem_id = 0x%x\n", elem_id);
	e = elems + (elem_id * knod_map_obj->meta.hmeta.elem_size);
	knod_map_obj->meta.hmeta.cur--;
	e->next = KNOD_BPF_HASH_NEXT_END;

	return e;
}

static struct knod_bpf_hash_elem_obj *
knod_bpf_map_hash_alloc_elem(struct knod_bpf_map *knod_map,
			     struct knod_bpf_map_obj *knod_map_obj,
			     void *key, void *value)
{
	struct knod_bpf_hash_elem_obj *e;

	e = knod_bpf_map_hash_pop(knod_map, knod_map_obj);
	if (!e)
		return NULL;

	unsafe_memcpy(knod_bpf_hash_elem_kv(e), key, knod_map_obj->key_size,
		      "knod hash elems are variable-sized GPU map records");
	unsafe_memcpy(knod_bpf_hash_elem_kv(e) + knod_map_obj->key_size,
		      value, knod_map_obj->value_size,
		      "knod hash elems are variable-sized GPU map records");
	/* VRAM is ioremap_wc — drain new elem's next and kv stores before
	 * the caller publishes a pointer to this elem.
	 */
	wmb();
	return e;
}

static int knod_bpf_map_hash_lookup_elem(struct knod_bpf_map *knod_map,
					 struct knod_bpf_map_obj *knod_map_obj,
					 void *key,
					 void *value)
{
	void *elems = knod_map->hash_elems_mem->kaddr;
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
	if (elem_id == KNOD_BPF_HASH_NEXT_END)
		return -ENOENT;

	elem_size = knod_map_obj->meta.hmeta.elem_size;

	e = elems + (elem_id * elem_size);
	while (1) {
		if (!(e->next & KNOD_BPF_HASH_NEXT_DELETED) &&
		    !memcmp(&e->kv[0], (const unsigned char *)key,
			    knod_map_obj->key_size)) {
			memcpy(value,
			       (unsigned char *)&e->kv[0] +
			       knod_map_obj->key_size,
			       knod_map_obj->value_size);
			return 0;
		}
		unsigned int real_next = e->next & KNOD_BPF_HASH_NEXT_MASK;

		if (real_next == KNOD_BPF_HASH_NEXT_END)
			return -ENOENT;
		e = elems + (real_next * elem_size);
	}

	return -ENOENT;
}

static int knod_bpf_map_hash_update_elem(struct knod_bpf_map *knod_map,
					 struct knod_bpf_map_obj *knod_map_obj,
					 void *key,
					 void *value)
{
	void *elems = knod_map->hash_elems_mem->kaddr;
	unsigned int hash, elem_id, elem_size;
	struct knod_bpf_hash_elem_obj *e, *ne;
	unsigned int *bucket;

	hash = jhash((const void *)key, knod_map_obj->key_size,
		     knod_map_obj->meta.hmeta.hashrnd);
	hash = hash & (knod_map_obj->meta.hmeta.n_buckets - 1);
	bucket = (unsigned int *)&knod_map_obj->bucket[0];

	elem_size = knod_map_obj->meta.hmeta.elem_size;
	elem_id = bucket[hash];
	if (elem_id == KNOD_BPF_HASH_NEXT_END) {
		ne = knod_bpf_map_hash_alloc_elem(knod_map, knod_map_obj, key,
						  value);
		if (!ne)
			return -ENOMEM;
		bucket[hash] = ((void *)ne - (void *)elems) / elem_size;
		return 0;
	}

	e = elems + (elem_id * elem_size);
	while (1) {
		if (!(e->next & KNOD_BPF_HASH_NEXT_DELETED) &&
		    !memcmp(&e->kv[0], (const unsigned char *)key,
			    knod_map_obj->key_size)) {
			unsafe_memcpy(knod_bpf_hash_elem_kv(e) +
				      knod_map_obj->key_size,
				      value, knod_map_obj->value_size,
				      "knod hash elems are variable-sized GPU map records");
			return 0;
		}
		unsigned int real_next = e->next & KNOD_BPF_HASH_NEXT_MASK;

		if (real_next == KNOD_BPF_HASH_NEXT_END) {
			ne = knod_bpf_map_hash_alloc_elem(knod_map,
							  knod_map_obj,
							  key, value);
			if (!ne)
				return -ENOMEM;
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
	if (elem_id == KNOD_BPF_HASH_NEXT_END)
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

			/* Unlink (GPU is paused — safe) */
			if (pe != e)
				pe->next = (pe->next &
					    KNOD_BPF_HASH_NEXT_DELETED) |
					   e_next;
			else
				bucket[hash] = e_next;

			e->next = KNOD_BPF_HASH_NEXT_END;

			/* Return elem to queue */
			cur = knod_map_obj->meta.hmeta.cur;
			queue[cur] = del_id;
			knod_map_obj->meta.hmeta.cur = cur + 1;
			return 0;
		}
		unsigned int real_next = e->next & KNOD_BPF_HASH_NEXT_MASK;

		if (real_next == KNOD_BPF_HASH_NEXT_END)
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

	knod_map_obj = knod_map->knod_map_obj;
	bucket =  (unsigned int *)&knod_map_obj->bucket[0];
	elems = knod_map->hash_elems_mem->kaddr;

	elem_size = knod_map_obj->meta.hmeta.elem_size;

	for (i = 0; i < knod_map_obj->meta.hmeta.n_buckets; i++) {
		unsigned int eid;

		if (bucket[i] == KNOD_BPF_HASH_NEXT_END)
			continue;
		eid = bucket[i];
		while (eid != KNOD_BPF_HASH_NEXT_END) {
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

	knod_map_obj = knod_map->knod_map_obj;

	bucket =  (unsigned int *)&knod_map_obj->bucket[0];
	elems = knod_map->hash_elems_mem->kaddr;

	hash = jhash((const void *)key, knod_map_obj->key_size,
		     knod_map_obj->meta.hmeta.hashrnd);
	hash = hash & (knod_map_obj->meta.hmeta.n_buckets - 1);
	elem_size = knod_map_obj->meta.hmeta.elem_size;

	for (i = hash; i < knod_map_obj->meta.hmeta.n_buckets; i++) {
		unsigned int eid;

		if (bucket[i] == KNOD_BPF_HASH_NEXT_END)
			continue;

		eid = bucket[i];
		while (eid != KNOD_BPF_HASH_NEXT_END) {
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
	 * Defer the BO free: an in-flight prog dispatch may still reference
	 * this map's VRAM.  Move it from bound_maps onto dead_maps under
	 * knodev->lock (the lock that guards the add); the worker reaps it
	 * from there after its next completion, by which point the in-flight
	 * dispatch on the old slot has retired (clean atomic flip).
	 */
	mutex_lock(&knodev->lock);
	list_del(&knod_map->list);
	list_add(&knod_map->list, &priv->dead_maps);
	mutex_unlock(&knodev->lock);
	offmap->dev_priv = NULL;
}

static int __knod_bpf_map_lookup_elem(struct bpf_offloaded_map *offmap,
				      void *key, void *value)
{
	unsigned int idx = *(unsigned int *)key;
	struct knod_bpf_map_obj *knod_map_obj;
	struct knod_bpf_map *knod_map;
	void *bucket;
	u32 stride;
	int i;

	knod_map = (struct knod_bpf_map *)offmap->dev_priv;
	if (!knod_map || !knod_map->mem || !knod_map->mem->kaddr ||
	    (knod_map->hash_elems_mem && !knod_map->hash_elems_mem->kaddr)) {
		pr_err("knod_bpf: lookup on freed/invalid map (dev_priv=%p)\n",
		       offmap->dev_priv);
		return -ENODEV;
	}
	knod_map_obj = knod_map->knod_map_obj;

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
	} else if (knod_map_obj->map_type == BPF_MAP_TYPE_HASH) {
		return knod_bpf_map_hash_lookup_elem(knod_map, knod_map_obj,
						     key, value);
	}

	return 0;
}

static void knod_bpf_map_op_begin(struct knod_bpf_priv *priv)
{
	/*
	 * Serialize concurrent map ops but do NOT park the worker: stopping it
	 * mid-flight strands the in-flight dispatch and stalls the GPU compute
	 * queue.  A map value updated while the GPU reads it may be seen torn,
	 * which is a transient inconsistency the BPF prog tolerates.
	 */
	mutex_lock(&priv->map_op_lock);
}

static void knod_bpf_map_op_end(struct knod_bpf_priv *priv)
{
	knod_bpf_gpu_mem_fence(priv);
	mutex_unlock(&priv->map_op_lock);
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
	int i;

	if (!knod_map || !knod_map->mem || !knod_map->mem->kaddr)
		return -ENODEV;
	knod_map_obj = knod_map->knod_map_obj;
	priv = knod_map->priv;
	knodev = priv->knodev;
	if (knod_map_obj->map_type == BPF_MAP_TYPE_ARRAY) {
		if (idx >= knod_map_obj->max_entries)
			return -ENOENT;

		bucket = knod_bpf_array_value_ptr(knod_map_obj, idx);
		unsafe_memcpy(bucket, value, knod_map_obj->value_size,
			      "knod array values live in a variable-sized GPU map tail");
		knod_bpf_gpu_mem_fence(priv);
		return 0;
	} else if (knod_map_obj->map_type == BPF_MAP_TYPE_PERCPU_ARRAY) {
		if (idx >= knod_map_obj->max_entries)
			return -ENOENT;
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
		knod_bpf_gpu_mem_fence(priv);
		return 0;
	} else if (knod_map_obj->map_type == BPF_MAP_TYPE_HASH) {
		int ret = -ENOENT;

		mutex_lock(&knodev->lock);
		list_for_each_entry(knod_map, &knodev->accel->xdp.bound_maps,
				    list) {
			if (knod_map->knod_map_obj == knod_map_obj) {
				mutex_unlock(&knodev->lock);
				knod_bpf_map_op_begin(priv);
				ret = knod_bpf_map_hash_update_elem(knod_map,
						knod_map_obj,
								    key, value);
				knod_bpf_map_op_end(priv);
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
	struct knod_bpf_priv *priv;
	int ret;

	if (!knod_map || !knod_map->mem || !knod_map->mem->kaddr)
		return -ENODEV;
	knod_map_obj = knod_map->knod_map_obj;
	priv = knod_map->priv;

	if (knod_map_obj->map_type == BPF_MAP_TYPE_ARRAY ||
	    knod_map_obj->map_type == BPF_MAP_TYPE_PERCPU_ARRAY)
		return 0;
	else if (knod_map_obj->map_type == BPF_MAP_TYPE_HASH) {
		knod_bpf_map_op_begin(priv);
		ret = knod_bpf_map_hash_delete_elem(knod_map, knod_map_obj,
						    key);
		knod_bpf_map_op_end(priv);
		return ret;
	}

	return -ENOENT;
}

static void knod_bpf_map_gc_process(struct knod_bpf_map *knod_map)
{
	struct knod_bpf_map_obj *knod_map_obj = knod_map->knod_map_obj;
	unsigned int *gc_list = knod_map->gc_mem->kaddr;
	unsigned int *queue = knod_map->queue_mem->kaddr;
	void *elems = knod_map->hash_elems_mem->kaddr;
	unsigned int *bucket = (unsigned int *)&knod_map_obj->bucket[0];
	unsigned int elem_size = knod_map_obj->meta.hmeta.elem_size;
	unsigned int gc_count, cur, i;

	gc_count = READ_ONCE(knod_map_obj->meta.hmeta.gc_count);
	if (!gc_count)
		return;

	for (i = 0; i < gc_count; i++) {
		unsigned int del_id = gc_list[i];
		struct knod_bpf_hash_elem_obj *del_elem =
			elems + (del_id * elem_size);
		unsigned int hash, eid;
		struct knod_bpf_hash_elem_obj *e, *pe;

		hash = jhash(&del_elem->kv[0], knod_map_obj->key_size,
			     knod_map_obj->meta.hmeta.hashrnd);
		hash = hash & (knod_map_obj->meta.hmeta.n_buckets - 1);

		eid = bucket[hash];
		pe = NULL;
		while (eid != KNOD_BPF_HASH_NEXT_END) {
			e = elems + (eid * elem_size);
			if (e == del_elem) {
				unsigned int next = e->next &
						   KNOD_BPF_HASH_NEXT_MASK;
				if (pe)
					pe->next =
						(pe->next &
						 KNOD_BPF_HASH_NEXT_DELETED) |
						next;
				else
					bucket[hash] = next;

				e->next = KNOD_BPF_HASH_NEXT_END;

				cur = knod_map_obj->meta.hmeta.cur;
				queue[cur] = del_id;
				knod_map_obj->meta.hmeta.cur = cur + 1;
				break;
			}
			pe = e;
			eid = e->next & KNOD_BPF_HASH_NEXT_MASK;
		}
	}

	WRITE_ONCE(knod_map_obj->meta.hmeta.gc_count, 0);
}

/*
 * Per-loop map maintenance, run from the worker loop head (outside any
 * rcu_read_lock_bh, since knod_free_mem() may sleep).  All bound_maps access
 * is serialized under knodev->lock -- the same lock map_alloc/map_free use:
 * GC live HASH maps, then reap maps that detach moved onto dead_maps.  The
 * worker only reaches here after completing the previous dispatch, so the
 * clean atomic flip guarantees the GPU no longer reads a reaped map's BOs.
 */
#define KNOD_BPF_MAPS_TICK_INTERVAL 65536

static void knod_bpf_maps_tick(struct knod_bpf_priv *priv)
{
	struct knod_dev *knodev = priv->knodev;
	struct knod_bpf_map *knod_map, *tmp;
	LIST_HEAD(reap);

	if (list_empty(&knodev->accel->xdp.bound_maps) &&
	    list_empty(&priv->dead_maps))
		return;

	if (list_empty(&priv->dead_maps) &&
	    (++priv->maps_tick_skip & (KNOD_BPF_MAPS_TICK_INTERVAL - 1)))
		return;

	mutex_lock(&knodev->lock);
	list_for_each_entry(knod_map, &knodev->accel->xdp.bound_maps, list) {
		if (knod_map->knod_map_obj->map_type == BPF_MAP_TYPE_HASH)
			knod_bpf_map_gc_process(knod_map);
	}
	list_splice_init(&priv->dead_maps, &reap);
	mutex_unlock(&knodev->lock);

	list_for_each_entry_safe(knod_map, tmp, &reap, list) {
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
}

/* Completion mode: 0 = event (default, sleep on the AQL signal interrupt),
 * 1 = poll (busy-spin the signal value).  Selectable via debugfs.
 */
static bool knod_bpf_poll_mode;

/* Max spacing (microseconds) between dispatch-ahead submissions.  Once a
 * dispatch is in flight the worker waits up to this long before submitting
 * the next so it batches the packets arriving meanwhile, letting inflight
 * grow >= 2 without degenerating into one-packet dispatches.  This is a
 * ceiling only: an empty pipe submits at once to keep the GPU fed, and a
 * completed dispatch is always retired without waiting.  To actually build
 * depth the value must be below the GPU execution time of a dispatch.
 * 0 disables spacing (submit as soon as the ring has anything).
 */
static u32 knod_bpf_dispatch_delay_us = 20;

static void knod_bpf_wait_event(struct knod_bpf_priv *priv)
{
	struct kfd_event_data events = {
		.event_id = priv->knod->aql_event[0].id,
	};
	u32 timeout_ms = knod_bpf_expire;
	u32 wait_result;

	knod_wait_on_events(priv->knod->process, 1, &events, true,
			    &timeout_ms, &wait_result);
}

static bool knod_bpf_submit_work(struct knod_bpf_priv *priv)
{
	struct knod_bpf_work_sq *sqw;
	struct knod_bpf_stats *stats = &priv->stats;
	ktime_t dispatch_start;

	if (priv->inflight_cnt >= KNOD_BPF_INFLIGHT)
		return false;

	/* Pace dispatch-ahead so the next dispatch batches the packets that
	 * arrive during this window instead of firing one-packet dispatches.
	 * An empty pipe skips the wait so the GPU is never left idle.
	 */
	if (priv->inflight_cnt &&
	    ktime_before(ktime_get(), priv->next_dispatch_time))
		return false;

	if (static_branch_unlikely(&knod_stats_key))
		dispatch_start = ktime_get();

	sqw = knod_prepare_bpf(priv);
	if (!sqw)
		return false;

	if (static_branch_unlikely(&knod_stats_key)) {
		u64 dns = ktime_to_ns(ktime_sub(ktime_get(),
						dispatch_start));

		stats->dispatch_total_ns += dns;
		stats->dispatch_count++;
		if (dns > stats->dispatch_max_ns)
			stats->dispatch_max_ns = dns;
	}

	knod_submit_bpf(priv, sqw);
	priv->inflight[priv->inflight_cnt++] = sqw;
	priv->next_dispatch_time =
		ktime_add_us(ktime_get(),
			     READ_ONCE(knod_bpf_dispatch_delay_us));
	return true;
}

static void knod_bpf_record_completion(struct knod_bpf_priv *priv,
				       struct knod_bpf_work_sq *sqw)
{
	struct knod_bpf_stats *stats = &priv->stats;
	u64 ns;
	int bucket;

	if (!static_branch_unlikely(&knod_stats_key))
		return;

	ns = ktime_to_ns(ktime_sub(ktime_get(), sqw->dispatch_time));
	stats->completion_total_ns += ns;
	stats->completion_count++;

	if (ns > stats->completion_max_ns)
		stats->completion_max_ns = ns;

	if (ns < 1000)
		bucket = 0;
	else
		bucket = min(ilog2(ns / 1000) + 1,
			     KNOD_LAT_BUCKETS - 1);
	stats->completion_hist[bucket]++;
}

static bool knod_bpf_poll_complete(struct knod_bpf_priv *priv,
				   struct knod_bpf_work_sq *sqw)
{
	struct amd_signal *signal;

	if (!sqw)
		return false;

	signal = (struct amd_signal *)
		priv->knod->kaql[0].queue_signal->kaddr;

	if (sqw->sigval > READ_ONCE(signal->value)) {
		knod_bpf_record_completion(priv, sqw);
		return true;
	}

	if (time_after(jiffies, sqw->expire)) {
		pr_warn_ratelimited("knod_bpf: poll expire (sigval=%lld signal=%lld expire_ms=%u)\n",
			sqw->sigval, READ_ONCE(signal->value), knod_bpf_expire);
		knod_bpf_record_completion(priv, sqw);
		return true;
	}

	return false;
}

static void knod_bpf_schedule_pending_napi(struct knod_bpf_priv *priv)
{
	struct knod_dev *knodev = priv->knodev;
	int qi;

	for (qi = 0; qi < priv->nr_works; qi++) {
		if (spsc_pending(&knodev->wpriv[qi].spsc_bds) &&
		    knodev->wpriv[qi].napi)
			napi_schedule(knodev->wpriv[qi].napi);
	}
}

static int knod_bpf_worker(void *arg)
{
	struct knod_bpf_priv *priv = arg;
	struct knod_bpf_work_sq *sqw;
	bool progressed;

	while (!kthread_should_stop()) {
		if (kthread_should_park()) {
			knod_bpf_drain_worker(priv);
			kthread_parkme();
			continue;
		}

		knod_bpf_maps_tick(priv);

		progressed = false;

		rcu_read_lock_bh();
		/* Retire completed dispatches oldest-first: the signal is
		 * monotonic so inflight[0] finishes before inflight[1..].
		 */
		while (priv->inflight_cnt &&
		       knod_bpf_poll_complete(priv, priv->inflight[0])) {
			sqw = priv->inflight[0];
			if (--priv->inflight_cnt)
				memmove(priv->inflight, priv->inflight + 1,
					priv->inflight_cnt *
					sizeof(priv->inflight[0]));
			priv->inflight[priv->inflight_cnt] = NULL;
			knod_complete_acquire(priv, sqw);
			knod_complete_napi(priv, sqw);
			progressed = true;
		}

		/* Keep the pipe full: dispatch ahead up to KNOD_BPF_INFLIGHT.
		 * Staging self-limits, so this stops once the ring is drained.
		 */
		while (knod_bpf_submit_work(priv))
			progressed = true;
		rcu_read_unlock_bh();

		if (!priv->inflight_cnt) {
			knod_bpf_schedule_pending_napi(priv);
			usleep_range(100, 200);
		} else if (!progressed) {
			/* Room to dispatch ahead but the pacing window has not
			 * opened yet: spin so the next submit fires on time and
			 * a completion is retired the instant it lands.  Block
			 * on the event only when the pipe is full (nothing to
			 * submit) or spacing is disabled.
			 */
			if (priv->inflight_cnt < KNOD_BPF_INFLIGHT &&
			    ktime_before(ktime_get(), priv->next_dispatch_time))
				cpu_relax();
			else if (knod_bpf_poll_mode)
				cpu_relax();
			else
				knod_bpf_wait_event(priv);
		}
	}

	return 0;
}

static void knod_bpf_sq_init(struct knod_bpf_priv *priv)
{
	struct knod_bpf_work_sq *sqw;
	int i;

	priv->worker_task = NULL;
	priv->inflight_cnt = 0;
	INIT_LIST_HEAD(&priv->free_list_sqw);

	for (i = 0; i < 32; i++) {
		sqw = kvzalloc_obj(struct knod_bpf_work_sq, GFP_KERNEL);
		if (!sqw)
			continue;

		sqw->param = knod_alloc_mem(priv->knod,
					    sizeof(struct knod_bpf_param),
					    KFD_IOC_ALLOC_MEM_FLAGS_GTT |
					    KFD_IOC_ALLOC_MEM_FLAGS_WRITABLE |
					    KFD_IOC_ALLOC_MEM_FLAGS_COHERENT);
		if (!sqw->param) {
			kvfree(sqw);
			continue;
		}
		memset(sqw->param->kaddr, 0, sizeof(struct knod_bpf_param));
		INIT_LIST_HEAD(&sqw->list);
		list_add(&sqw->list, &priv->free_list_sqw);
		sqw->backlogs = 0;
	}
}

static void knod_bpf_free_sqw(struct knod_bpf_priv *priv,
			      struct knod_bpf_work_sq *sqw)
{
	if (!sqw)
		return;

	knod_free_mem(priv->knod, sqw->param);
	kfree(sqw);
}

static void knod_bpf_free_sqw_list(struct knod_bpf_priv *priv,
				   struct list_head *head)
{
	struct knod_bpf_work_sq *sqw, *tmp;

	list_for_each_entry_safe(sqw, tmp, head, list) {
		list_del(&sqw->list);
		knod_bpf_free_sqw(priv, sqw);
	}
}

static void knod_bpf_sq_exit(struct knod_bpf_priv *priv)
{
	if (!priv->knod)
		return;

	knod_bpf_stop_worker(priv);
	knod_bpf_drain(priv);

	knod_bpf_free_sqw_list(priv, &priv->free_list_sqw);
	priv->inflight_cnt = 0;
}

static void knod_priv_exit(struct knod_bpf_priv *priv)
{
	struct knod_dev *knodev = priv->knodev;
	struct knod_bpf_map *knod_map, *tmp;
	LIST_HEAD(reap);

	knod_bpf_sq_exit(priv);

	/*
	 * The dispatch worker is not stopped until the next feature registers
	 * its own worker, so it may still be running knod_bpf_maps_tick() here.
	 * Serialize under knodev->lock and splice both lists to a local one:
	 * whichever side splices first frees them, the other sees them empty.
	 * Free outside the lock since knod_free_mem() may sleep.
	 */
	mutex_lock(&knodev->lock);
	list_splice_init(&knodev->accel->xdp.bound_maps, &reap);
	list_splice_init(&priv->dead_maps, &reap);
	mutex_unlock(&knodev->lock);

	list_for_each_entry_safe(knod_map, tmp, &reap, list) {
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
	kfree(priv->pass_prog_buf);
	if (priv->pass_knod_prog) {
		knod_prog_free(priv->pass_knod_prog);
		priv->pass_knod_prog = NULL;
	}
	/* kernels[] are owned by knod (freed in knod_release_ctx), not here */
	if (priv->pass_meta_buf)
		knod_free_mem(priv->knod, priv->pass_meta_buf);
}

static int knod_priv_init(struct knod_bpf_priv *priv)
{
	struct knod_dev *knodev = priv->knodev;
	int pass_meta_buf_size;
	int index;

	priv->prog = NULL;
	mutex_init(&priv->map_op_lock);
	INIT_LIST_HEAD(&priv->dead_maps);
	priv->maps_tick_skip = 0;

	priv->nr_works = knod_bpf_active_rxq_count(knodev->netdev);
	if (!priv->nr_works) {
		pr_warn("knod_bpf: no active RX queues for %s\n",
			knodev->netdev ? knodev->netdev->name : "<null>");
		return -EINVAL;
	}

	priv->prog_buf = kzalloc(KNOD_BPF_PROG_BUF_SIZE, GFP_KERNEL);
	if (!priv->prog_buf)
		return -ENOMEM;

	for (index = 0; index < priv->nr_works; index++)
		priv->queue_base_gaddr[index] = priv->knod->buf[index]->gaddr;

	/* Per-queue PASS slot count; sizes the shader pass_meta_buf below.
	 * At most one PASS packet per dispatched slot, i.e. batch_size.
	 */
	priv->pass_pkts_per_queue = knod_bpf_batch_size(priv);

	/* Allocate GTT buffer for per-queue shader PASS copy */
	pass_meta_buf_size = priv->nr_works * priv->pass_pkts_per_queue *
			KNOD_PASS_SLOT_SIZE;
	priv->pass_meta_buf = knod_alloc_mem(priv->knod, pass_meta_buf_size,
					KFD_IOC_ALLOC_MEM_FLAGS_GTT |
					KFD_IOC_ALLOC_MEM_FLAGS_WRITABLE |
					KFD_IOC_ALLOC_MEM_FLAGS_COHERENT);
	if (IS_ERR(priv->pass_meta_buf)) {
		pr_warn("KNOD: failed to allocate pass_meta_buf\n");
		priv->pass_meta_buf = NULL;
		knod_priv_exit(priv);
		return -ENOMEM;
	}
	pr_debug("KNOD: pass_meta_buf gaddr=0x%llx..0x%llx size=%d nr_q=%d pass_pkts_per_queue=%u\n",
		 priv->pass_meta_buf->gaddr,
		 priv->pass_meta_buf->gaddr + pass_meta_buf_size,
		 priv->pass_meta_buf->size, priv->nr_works,
		 priv->pass_pkts_per_queue);

	/* GPU->host delivery pages come from the framework per-queue page_pool
	 * (knodev->wpriv[q].pass_pool): the producer allocs from it and the
	 * NAPI drain recycles, so no per-feature delivery BO is allocated here.
	 */

	knod_bpf_sq_init(priv);

	return 0;
}

static struct knod_bpf_priv *__knod_accel_xdp_init(struct knod_accel *accel,
						   struct knod_dev *knodev)
{
	struct knod *knod = (struct knod *)knodev->accel->priv;
	struct knod_bpf_priv *priv;

	priv = kzalloc_obj(struct knod_bpf_priv, GFP_KERNEL);
	if (!priv)
		return ERR_PTR(-ENOMEM);

	INIT_LIST_HEAD(&priv->list);
	if (knod_bpf_workgroups % 64) {
		knod_bpf_workgroups /= 64;
		knod_bpf_workgroups++;
		knod_bpf_workgroups *= 64;
	}

	if (knod_bpf_workgroups < KNOD_BPF_WORKGROUPS_MIN ||
	    knod_bpf_workgroups > KNOD_BPF_WORKGROUPS_MAX)
		knod_bpf_workgroups = KNOD_BPF_WORKGROUPS_DEFAULT;

	if (knod_bpf_expire < KNOD_BPF_EXPIRE_MIN ||
	    knod_bpf_expire > KNOD_BPF_EXPIRE_MAX)
		knod_bpf_expire = KNOD_BPF_EXPIRE_DEFAULT;
	pr_debug("workgroup size %d\n", knod_bpf_workgroups);
	pr_debug("expire time = %dms\n", knod_bpf_expire);
	pr_debug("packet cache = %d", knod_bpf_pkt_cache);

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
	 * Only permanent per-attach state is set up here; the GPU compute
	 * buffers (knod_priv_init/kfd_kernel_init) are allocated by
	 * ->activate() when the BPF feature is selected.
	 */

	return priv;
}

/* Feature select: allocate the BPF GPU compute resources. */
static int knod_bpf_activate(struct knod_dev *knodev)
{
	struct knod_accel *accel = knodev->accel;
	struct knod_bpf_priv *priv = accel->xdp.priv;
	struct knod *knod = accel->priv;

	/*
	 * Pin the module while BPF is the selected feature: the core calls
	 * into these ops, so it must not be unloaded until feature->none.
	 * (No-op when built in — THIS_MODULE is NULL.)
	 */
	if (!try_module_get(THIS_MODULE))
		return -ENODEV;

	if (knod_priv_init(priv)) {
		WARN_ON_ONCE(1);
		module_put(THIS_MODULE);
		return -EINVAL;
	}
	if (kfd_kernel_init(knod, priv)) {
		knod_priv_exit(priv);
		module_put(THIS_MODULE);
		return -ENOMEM;
	}

	priv->start = 0;
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
	kfree(priv);
}

static struct knod_insn_meta *knod_bpf_goto_meta(struct knod_prog *knod_prog,
						 struct knod_insn_meta *meta,
						 unsigned int insn_idx)
{
	unsigned int forward, backward, i;

	backward = meta->bpf_insn_idx - insn_idx;
	forward = insn_idx - meta->bpf_insn_idx;

	if (min(forward, backward) > knod_prog->n_insns - insn_idx - 1) {
		backward = knod_prog->n_insns - insn_idx - 1;
		meta = knod_prog_last_meta(knod_prog);
	}
	if (min(forward, backward) > insn_idx && backward > insn_idx) {
		forward = insn_idx;
		meta = knod_prog_first_meta(knod_prog);
	}

	if (forward < backward)
		for (i = 0; i < forward; i++)
			meta = knod_meta_next(meta);
	else
		for (i = 0; i < backward; i++)
			meta = knod_meta_prev(meta);

	return meta;
}

static int knod_bpf_check_stack_access(struct knod_prog *knod_prog,
				       struct knod_insn_meta *meta,
				       const struct bpf_reg_state *reg,
				       struct bpf_verifier_env *env)
{
	s32 old_off, new_off;

	if (reg->frameno != env->cur_state->curframe)
		meta->flags |= FLAG_INSN_PTR_CALLER_STACK_FRAME;

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
		if (!is_mbpf_alu(meta) &&
		    !is_mbpf_load(meta) &&
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

	if (is_mbpf_load(meta)) {
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
		    dreg->reg.type == PTR_TO_PACKET) {
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

	return knod_bpf_check_ptr(knod_prog, meta, env, meta->insn.dst_reg);
}

/* TODO
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

	meta->umin_src = min(meta->umin_src, reg_umin(sreg));
	meta->umax_src = max(meta->umax_src, reg_umax(sreg));
	meta->umin_dst = min(meta->umin_dst, reg_umin(dreg));
	meta->umax_dst = max(meta->umax_dst, reg_umax(dreg));

	/* AMDGPU doesn't have divide instructions, we support divide by
	 * constant through reciprocal multiplication. Given NFP support
	 * multiplication no bigger than u32, we'd require divisor and dividend
	 * no bigger than that as well.
	 *
	 * Also eBPF doesn't support signed divide and has enforced this on C
	 * language level by failing compilation. However LLVM assembler hasn't
	 * enforced this, so it is possible for negative constant to leak in as
	 * a BPF_K operand through assembly code, we reject such cases as well.
	 */
	if (is_mbpf_div(meta)) {
		if (meta->umax_dst > U32_MAX) {
			knod_jit_dbg(" dividend is not within u32 value range\n");
			return -EINVAL;
		}
		if (mbpf_src(meta) == BPF_X) {
			if (meta->umin_src != meta->umax_src) {
				knod_jit_dbg(" divisor is not constant\n");
				return -EINVAL;
			}
			if (meta->umax_src > U32_MAX) {
				knod_jit_dbg(" divisor is not within u32 value range\n");
				return -EINVAL;
			}
		}
		if (mbpf_src(meta) == BPF_K && meta->insn.imm < 0) {
			knod_jit_dbg(" divide by negative constant is not supported\n");
			return -EINVAL;
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
			//r[d] = r[s];
			kdreg->stack_off = ksreg->stack_off;
			break;
		case BPF_ALU | BPF_MOV | BPF_K:
		case BPF_ALU64 | BPF_MOV | BPF_K:
			//r[d] = imm;
			kdreg->stack_off = ksreg->stack_off;
			break;
		case BPF_ALU | BPF_XOR | BPF_X:
		case BPF_ALU64 | BPF_XOR | BPF_X:
			//r[d] ^= r[s];
			knod_jit_dbg(" PTR_TO_STACK with BPF_X is not supported\n");
			return -EINVAL;
		case BPF_ALU | BPF_XOR | BPF_K:
		case BPF_ALU64 | BPF_XOR | BPF_K:
			//r[d] ^= imm;
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
			//r[d] %= r[s];
			knod_jit_dbg(" PTR_TO_STACK with BPF_X is not supported\n");
			return -EINVAL;
		case BPF_ALU | BPF_MOD | BPF_K:
		case BPF_ALU64 | BPF_MOD | BPF_K:
			//r[d] %= imm;
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
			//r[d] &= r[s];
			knod_jit_dbg(" PTR_TO_STACK with BPF_X is not supported\n");
			return -EINVAL;
		case BPF_ALU | BPF_AND | BPF_K:
		case BPF_ALU64 | BPF_AND | BPF_K:
			//r[d] &= imm;
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
			//r[d] |= r[s];
			knod_jit_dbg(" PTR_TO_STACK with BPF_X is not supported\n");
			return -EINVAL;
		case BPF_ALU | BPF_OR | BPF_K:
		case BPF_ALU64 | BPF_OR | BPF_K:
			//r[d] |= imm;
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
			//r[d] += r[s];
			knod_jit_dbg(" PTR_TO_STACK with BPF_X is not supported\n");
			return -EINVAL;
		case BPF_ALU | BPF_ADD | BPF_K:
		case BPF_ALU64 | BPF_ADD | BPF_K:
			//r[d] += imm;
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
			//r[d] -= r[s];
			knod_jit_dbg(" PTR_TO_STACK with BPF_X is not supported\n");
			return -EINVAL;
		case BPF_ALU | BPF_SUB | BPF_K:
		case BPF_ALU64 | BPF_SUB | BPF_K:
			//r[d] -= imm;
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
			//r[d] *= r[s];
			knod_jit_dbg(" PTR_TO_STACK with BPF_X is not supported\n");
			return -EINVAL;
		case BPF_ALU | BPF_MUL | BPF_K:
		case BPF_ALU64 | BPF_MUL | BPF_K:
			//r[d] *= imm;
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
			//r[d] /= r[s];
			knod_jit_dbg(" PTR_TO_STACK with BPF_X is not supported\n");
			return -EINVAL;
		case BPF_ALU | BPF_DIV | BPF_K:
		case BPF_ALU64 | BPF_DIV | BPF_K:
			//r[d] /= imm;
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
			//r[d] = -r[d];
			break;
		case BPF_ALU | BPF_LSH | BPF_X:
		case BPF_ALU64 | BPF_LSH | BPF_X:
			//r[d] <<= r[s];
			knod_jit_dbg(" PTR_TO_STACK with BPF_X is not supported\n");
			return -EINVAL;
		case BPF_ALU | BPF_LSH | BPF_K:
		case BPF_ALU64 | BPF_LSH | BPF_K:
			//r[d] <<= imm;
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
			//r[d] >>= r[s];
			knod_jit_dbg(" PTR_TO_STACK with BPF_X is not supported\n");
			return -EINVAL;
		case BPF_ALU | BPF_RSH | BPF_K:
		case BPF_ALU64 | BPF_RSH | BPF_K:
			//r[d] >>= imm;
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
			//r[d] >>= r[s];
			knod_jit_dbg(" PTR_TO_STACK with BPF_X is not supported\n");
			return -EINVAL;
		case BPF_ALU | BPF_ARSH | BPF_K:
		case BPF_ALU64 | BPF_ARSH | BPF_K:
			//r[d] >>= imm;
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
			//r[d] = r[s];
			kdreg->packet_off = ksreg->packet_off;
			break;
		case BPF_ALU | BPF_MOV | BPF_K:
		case BPF_ALU64 | BPF_MOV | BPF_K:
			//r[d] = imm;
			kdreg->packet_off = ksreg->packet_off;
			break;
		case BPF_ALU | BPF_XOR | BPF_X:
		case BPF_ALU64 | BPF_XOR | BPF_X:
			//r[d] ^= r[s];
			knod_jit_dbg(" PTR_TO_STACK with BPF_X is not supported\n");
			return -EINVAL;
		case BPF_ALU | BPF_XOR | BPF_K:
		case BPF_ALU64 | BPF_XOR | BPF_K:
			//r[d] ^= imm;
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
			//r[d] %= r[s];
			knod_jit_dbg(" PTR_TO_STACK with BPF_X is not supported\n");
			return -EINVAL;
		case BPF_ALU | BPF_MOD | BPF_K:
		case BPF_ALU64 | BPF_MOD | BPF_K:
			//r[d] %= imm;
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
			//r[d] &= r[s];
			knod_jit_dbg(" PTR_TO_STACK with BPF_X is not supported\n");
			return -EINVAL;
		case BPF_ALU | BPF_AND | BPF_K:
		case BPF_ALU64 | BPF_AND | BPF_K:
			//r[d] &= imm;
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
			//r[d] |= r[s];
			knod_jit_dbg(" PTR_TO_STACK with BPF_X is not supported\n");
			return -EINVAL;
		case BPF_ALU | BPF_OR | BPF_K:
		case BPF_ALU64 | BPF_OR | BPF_K:
			//r[d] |= imm;
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
			//r[d] += r[s];
			knod_jit_dbg(" PTR_TO_STACK with BPF_X is not supported\n");
			return -EINVAL;
		case BPF_ALU | BPF_ADD | BPF_K:
		case BPF_ALU64 | BPF_ADD | BPF_K:
			//r[d] += imm;
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
			//r[d] -= r[s];
			knod_jit_dbg(" PTR_TO_STACK with BPF_X is not supported\n");
			return -EINVAL;
		case BPF_ALU | BPF_SUB | BPF_K:
		case BPF_ALU64 | BPF_SUB | BPF_K:
			//r[d] -= imm;
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
			//r[d] *= r[s];
			knod_jit_dbg(" PTR_TO_STACK with BPF_X is not supported\n");
			return -EINVAL;
		case BPF_ALU | BPF_MUL | BPF_K:
		case BPF_ALU64 | BPF_MUL | BPF_K:
			//r[d] *= imm;
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
			//r[d] /= r[s];
			knod_jit_dbg(" PTR_TO_STACK with BPF_X is not supported\n");
			return -EINVAL;
		case BPF_ALU | BPF_DIV | BPF_K:
		case BPF_ALU64 | BPF_DIV | BPF_K:
			//r[d] /= imm;
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
			//r[d] = -r[d];
			break;
		case BPF_ALU | BPF_LSH | BPF_X:
		case BPF_ALU64 | BPF_LSH | BPF_X:
			//r[d] <<= r[s];
			knod_jit_dbg(" PTR_TO_STACK with BPF_X is not supported\n");
			return -EINVAL;
		case BPF_ALU | BPF_LSH | BPF_K:
		case BPF_ALU64 | BPF_LSH | BPF_K:
			//r[d] <<= imm;
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
			//r[d] >>= r[s];
			knod_jit_dbg(" PTR_TO_STACK with BPF_X is not supported\n");
			return -EINVAL;
		case BPF_ALU | BPF_RSH | BPF_K:
		case BPF_ALU64 | BPF_RSH | BPF_K:
			//r[d] >>= imm;
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
			//r[d] >>= r[s];
			knod_jit_dbg(" PTR_TO_STACK with BPF_X is not supported\n");
			return -EINVAL;
		case BPF_ALU | BPF_ARSH | BPF_K:
		case BPF_ALU64 | BPF_ARSH | BPF_K:
			//r[d] >>= imm;
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

	meta = knod_bpf_goto_meta(knod_prog, meta, insn_idx);
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

	if (is_mbpf_load(meta)) {
		err = knod_bpf_check_ptr(knod_prog, meta, env,
					 meta->insn.src_reg);
		goto out;
	}
	if (is_mbpf_store(meta)) {
		err = knod_bpf_check_store(knod_prog, meta, env);
		goto out;
	}

	if (is_mbpf_map_call(meta)) {
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
		if (kreg->type == PTR_TO_PACKET)
			meta->kreg.packet_off = prev_meta->dreg.packet_off;
		else
			meta->kreg.stack_off = prev_meta->dreg.stack_off;
		if (knod_prog->max_stack_off > meta->kreg.stack_off)
			knod_prog->max_stack_off = meta->kreg.stack_off;
		if (knod_prog->max_packet_off < meta->kreg.packet_off)
			knod_prog->max_packet_off = meta->kreg.packet_off;

		/* bpf_map_update_elem: track r3 (value pointer) */
		if (meta->insn.imm == 2) {
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
			if (vreg->type == PTR_TO_PACKET)
				meta->vreg.packet_off =
					prev_meta->dreg.packet_off;
			else
				meta->vreg.stack_off =
					prev_meta->dreg.stack_off;
			if (knod_prog->max_stack_off > meta->vreg.stack_off)
				knod_prog->max_stack_off = meta->vreg.stack_off;
			if (knod_prog->max_packet_off < meta->vreg.packet_off)
				knod_prog->max_packet_off =
					meta->vreg.packet_off;
		}
	}

	if (is_mbpf_alu(meta))
		err = knod_bpf_check_alu(knod_prog, meta, env);

	/* less stack offset is bigger */
	if (knod_prog->max_stack_off > meta->sreg.stack_off)
		knod_prog->max_stack_off = meta->sreg.stack_off;
	if (knod_prog->max_stack_off > meta->dreg.stack_off)
		knod_prog->max_stack_off = meta->dreg.stack_off;
	if (knod_prog->max_packet_off < meta->sreg.packet_off)
		knod_prog->max_packet_off = meta->sreg.packet_off;
	if (knod_prog->max_packet_off < meta->dreg.packet_off)
		knod_prog->max_packet_off = meta->dreg.packet_off;

out:
	if (err)
		pr_warn("knod_bpf: verifier rejected bpf insn %d (code 0x%02x off %d imm %d): %d\n",
			insn_idx, meta->insn.code, meta->insn.off,
			meta->insn.imm, err);
	return err;
}

static int knod_bpf_finalize(struct bpf_verifier_env *env)
{
	return 0;
}

static int knod_bpf_offload(struct knod_dev *knodev,
			    struct bpf_prog *prog, bool oldprog)
{
	struct knod_bpf_priv *priv = knodev->accel->xdp.priv;

	WARN(!!knod_dev_offloaded(knodev) != oldprog,
	     "bad offload state, expected offload %sto be active",
	     oldprog ? "" : "not ");

	WRITE_ONCE(priv->prog, prog);
	knod_dev_offload(knodev, prog);

	/*
	 * Uninstalling the prog: reload the pass kernel now, while the prog's
	 * maps are still valid, so the worker stops dispatching prog code that
	 * is about to reference freed maps.
	 */
	if (!prog)
		knod_bpf_reload_pass(knodev);

	return 0;
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

	if (bpf->command == XDP_SETUP_PROG_HW) {
		err = knod_bpf_xdp_offload_prog(knodev, bpf);
		if (err)
			return err;
	}

	xdp_attachment_setup(&knodev->accel->xdp.xdp_hw, bpf);

	return 0;
}

static void knod_wait_vmcnt(struct knod_bpf_priv *priv,
			   struct knod_insn_meta *meta)
{
	knod_emit(priv, meta, s_waitcnt_vmcnt);
}

static void knod_global_load_size_cache(struct knod_bpf_priv *priv,
					struct knod_insn_meta *meta,
					struct amdgcn_param32 *d,
					struct amdgcn_param32 s,
					int dst_idx, int start_off, int length)
{
	int off = start_off;

	/* length is 4B aligned */
	while (length) {
		if (length >= 16) {
			knod_emit(priv, meta, global_load_dwordx4, d[dst_idx],
				  s, off);
			length -= 16;
			off += 16;
			dst_idx += 4;
		} else if (length >= 8) {
			knod_emit(priv, meta, global_load_dwordx2, d[dst_idx],
				  s, off);
			length -= 8;
			off += 8;
			dst_idx += 2;
		} else if (length >= 4) {
			knod_emit(priv, meta, global_load_dword, d[dst_idx],
				  s, off);
			length -= 4;
			off += 4;
			dst_idx += 1;
		}
	}

	knod_wait_vmcnt(priv, meta);
}

static void knod_global_store_size_cache(struct knod_bpf_priv *priv,
					 struct knod_insn_meta *meta,
					 struct amdgcn_param32 *d,
					 struct amdgcn_param32 s,
					 int dst_idx, int start_off, int length)
{
	int off = start_off;

	/* length is 4B aligned */
	while (length) {
		if (length >= 16) {
			knod_emit(priv, meta, global_store_dwordx4, d[dst_idx],
				  s, off);
			length -= 16;
			off += 16;
			dst_idx += 4;
		} else if (length >= 8) {
			knod_emit(priv, meta, global_store_dwordx2, d[dst_idx],
				  s, off);
			length -= 8;
			off += 8;
			dst_idx += 2;
		} else if (length >= 4) {
			knod_emit(priv, meta, global_store_dword, d[dst_idx],
				  s, off);
			length -= 4;
			off += 4;
			dst_idx += 1;
		}
	}

	knod_wait_vmcnt(priv, meta);
}

static int knod_prog_prepare_insns(struct knod_bpf_priv *priv,
				   struct knod_prog *knod_prog)
{
	struct amdgcn_param64 param64[3];
	struct amdgcn_param32 param[10];
	struct knod_insn_meta *meta;
	int bs_shift;

	meta = kzalloc_obj(*meta, GFP_KERNEL);
	if (!meta)
		return -ENOMEM;

	meta->amdgpu_insn_idx = 0;

	/* Invalidate SQC instruction cache so that a re-uploaded shader
	 * at the same VRAM address is fetched from memory, not from the
	 * stale I-cache.  Must be the very first instruction at the entry
	 * point so that every shader version has s_icache_inv at the same
	 * offset — the cached old version executes s_icache_inv too,
	 * which flushes the cache before divergent code is reached.
	 */
	knod_emit(priv, meta, s_icache_inv);
	knod_emit(priv, meta, s_waitcnt_vmcnt_lgkmcnt);

	knod_sset32(&param[0], KNOD_AMDGPU_PARAM_SREG_LO);
	knod_sset32(&param[1], KNOD_AMDGPU_ARG_SREG);
	/* param = (__global struct _knod_bpf_param *)pkt.kernarg_address; */
	knod_emit(priv, meta, s_load_dwordx2, param[0], param[1],
		  offsetof(struct hsa_kernel_dispatch_packet, kernarg_address));

	knod_vset32(&param[0], KNOD_AMDGPU_IDX_VREG);
	knod_vset32(&param[1], KNOD_AMDGPU_VREG0_LO);
	knod_iset32(&param[2], 0);
	/* 10bits, lidx can up to 1024, Do not edit */
	knod_iset32(&param[3], 10);
	/* extract workitem ID to reserved vgpr register.
	 * In the 2D-dispatch layout, IDX_VREG holds the per-workgroup tid
	 * (0..workgroup_size_x-1).  queue_id = workgroup_id_y (s15).  The
	 * flat index (queue_id * batch_size + local_idx) is computed later,
	 * after queue_desc has been loaded and the v_cmpx bounds check has
	 * narrowed EXEC to lanes with local_idx < count.
	 */
	knod_emit(priv, meta, v_bfe_i32, param[0], param[1], param[2],
		  param[3]);
	if (priv->batch_size > knod_bpf_workgroups) {
		/* local_idx = workgroup_id_x * workgroup_size_x
		 * + workitem_id.
		 */
		knod_vset32(&param[0], KNOD_AMDGPU_TMP_VREG5_LO);
		knod_sset32(&param[1], KNOD_AMDGPU_WORKGROUP_ID_X_SREG);
		knod_iset32(&param[2], knod_bpf_workgroups);
		knod_emit(priv, meta,
			v_mul_lo_u32, param[0], param[1], param[2]);
		knod_vset32(&param[0], KNOD_AMDGPU_IDX_VREG);
		knod_vset32(&param[1], KNOD_AMDGPU_TMP_VREG5_LO);
		knod_vset32(&param[2], KNOD_AMDGPU_IDX_VREG);
		knod_emit(priv, meta, v_add_u32, param[0], param[1], param[2]);
	}
	/* set frame pointer to 0 */
	knod_sset32(&param[0], KNOD_AMDGPU_FRAME_POINTER_SREG);
	knod_iset32(&param[1], 0);
	knod_emit(priv, meta, s_mov_b32, param[0], param[1]);
	/* wait for s_load_dwordx2 (kernarg_address) */
	knod_emit(priv, meta, s_waitcnt_vmcnt_lgkmcnt);

	/* load {nr_backlogs, _pad} from param (offset 0, 8-byte aligned) */
	knod_sset32(&param[0], KNOD_AMDGPU_TMP_SREG1_LO);
	knod_sset32(&param[1], KNOD_AMDGPU_PARAM_SREG_LO);
	knod_emit(priv, meta, s_load_dwordx2, param[0], param[1], 0);
	knod_emit(priv, meta, s_waitcnt_vmcnt_lgkmcnt);

	/* NOTE: the bounds check `EXEC &= (tid < count)` is deferred until
	 * after the queue descriptor load (queue↔workgroup binding).
	 * nr_backlogs is no longer the right upper bound because lanes with
	 * tid > this queue's count must be masked, not just the ones past
	 * the aggregate backlog total.
	 */

	/* Initialize done_mask to 0 for structurized CFG */
	knod_emit(priv, meta, s_mov_b64, knod_prog->done_mask_sreg,
		  AMDGCN_SREG_INTEGER_0);

	/* =========================================================
	 * Queue-descriptor prep (2D dispatch: queue_id = workgroup_id_y)
	 *
	 * Loads this WG's queue descriptor from VRAM, performs the
	 * per-lane bounds check (local_idx < queues[queue_id].count), and
	 * converts IDX_VREG from local_idx to flat_IDX (queue_id *
	 * batch_size + local_idx) which the rest of the prologue/BPF body
	 * expects.  TMP_VREG9_LO is repurposed to hold the saved local
	 * tid for use as local_idx in the slot-address step.
	 * =========================================================
	 */
	bs_shift = ilog2(priv->batch_size);

	/* a. queue_id = workgroup_id_y (broadcast scalar to VGPR LO). */
	knod_vset32(&param[0], KNOD_AMDGPU_TMP_VREG0_LO);
	knod_sset32(&param[1], KNOD_AMDGPU_WORKGROUP_ID_Y_SREG);
	knod_emit(priv, meta, v_mov_b32_e32, param[0], param[1]);
	knod_vset32(&param[0], KNOD_AMDGPU_TMP_VREG0_HI);
	knod_iset32(&param[1], 0);
	knod_emit(priv, meta, v_mov_b32_e32, param[0], param[1]);

	/* b. Copy queue_id into TMP_VREG5_LO — separate scratch used as
	 *    the v_mad src-multiplicand.  Avoids dst/src1 overlap on the
	 *    following v_mad_u64_u32 (dst=TMP_VREG0_LO:HI).
	 */
	knod_vset32(&param[0], KNOD_AMDGPU_TMP_VREG5_LO);
	knod_vset32(&param[1], KNOD_AMDGPU_TMP_VREG0_LO);
	knod_emit(priv, meta, v_mov_b32_e32, param[0], param[1]);

	/* c. TMP_VREG0 = PARAM + queue_id * sizeof(queue_desc). */
	knod_vset64(&param64[0], KNOD_AMDGPU_TMP_VREG0_LO);
	knod_sset32(&param[0], KNOD_AMDGPU_TMP_SREG0_LO);
	knod_iset32(&param[1],
				 sizeof(struct knod_bpf_queue_desc));
	knod_vset32(&param[2], KNOD_AMDGPU_TMP_VREG5_LO);
	knod_sset64(&param64[1], KNOD_AMDGPU_PARAM_SREG_LO);
	knod_emit(priv, meta, v_mad_u64_u32, param64[0], param[0],
		  param[1], param[2], param64[1]);

	/* d. TMP_VREG0 += offsetof(queues). */
	knod_vset32(&param[0], KNOD_AMDGPU_TMP_VREG0_LO);
	knod_iset32(&param[1],
				 offsetof(struct knod_bpf_param, queues));
	knod_vset32(&param[2], KNOD_AMDGPU_TMP_VREG0_LO);
	knod_emit(priv, meta, v_add_co_u32, param[0], param[1], param[2]);
	knod_vset32(&param[0], KNOD_AMDGPU_TMP_VREG0_HI);
	knod_iset32(&param[1], 0);
	knod_emit(priv, meta, v_add_co_ci_u32_e32, param[0], param[1],
		  param[0]);

	/* e. Load pool_gaddr + base_gaddr (offset 0, 16 bytes) into
	 *    TMP_VREG1_LO..TMP_VREG2_HI (v24..v27 — must be consecutive).
	 */
	knod_vset32(&param[0], KNOD_AMDGPU_TMP_VREG1_LO);
	knod_vset32(&param[1], KNOD_AMDGPU_TMP_VREG0_LO);
	knod_emit(priv, meta, global_load_dwordx4, param[0], param[1], 0);

	/* f. Load count + _pad + ring_start + ring_mask (offset 16, 16
	 *    bytes) into TMP_VREG3_LO..TMP_VREG4_HI.
	 */
	knod_vset32(&param[0], KNOD_AMDGPU_TMP_VREG3_LO);
	knod_vset32(&param[1], KNOD_AMDGPU_TMP_VREG0_LO);
	knod_emit(priv, meta, global_load_dwordx4, param[0], param[1],
		  offsetof(struct knod_bpf_queue_desc, count));
	knod_emit(priv, meta, s_waitcnt_vmcnt);

	/* g. Bounds check: EXEC &= (workitem_id < count). */
	knod_vset32(&param[0], KNOD_AMDGPU_IDX_VREG);
	knod_vset32(&param[1], KNOD_AMDGPU_TMP_VREG3_LO);
	knod_emit(priv, meta, v_cmpx_lt_u32, param[0], param[1]);

	/* Snapshot the in-bounds lane mask.  The unified epilogue uses this
	 * to publish one verdict for every lane the dispatch claimed, even if
	 * a malformed or newly added CFG path fails to join done_mask.
	 */
	knod_emit(priv, meta, s_mov_b64, knod_prog->initial_exec_sreg,
		  AMDGCN_SREG_EXEC_LO);

	/* h. Save per-queue local_idx to TMP_VREG9_LO.
	 *    The slot-address step consumes this value; keeping it in a
	 *    dedicated VGPR lets us overwrite IDX_VREG with flat_IDX for
	 *    the CTX address computation that immediately follows.
	 */
	knod_vset32(&param[0], KNOD_AMDGPU_TMP_VREG9_LO);
	knod_vset32(&param[1], KNOD_AMDGPU_IDX_VREG);
	knod_emit(priv, meta, v_mov_b32_e32, param[0], param[1]);

	/* i. IDX_VREG = (queue_id << ilog2(batch_size)) + local_idx
	 *    -> flat_IDX into the sub[] / sqw->bds[] arrays, matching the
	 *    CPU-side layout `sqw->bds[queue_id * batch_size + local_idx]`.
	 *    batch_size is rounded down to a power of two at start so the
	 *    shift is exact.
	 */
	knod_vset32(&param[0], KNOD_AMDGPU_IDX_VREG);
	knod_sset32(&param[1], KNOD_AMDGPU_WORKGROUP_ID_Y_SREG);
	knod_iset32(&param[2], bs_shift);
	knod_vset32(&param[3], KNOD_AMDGPU_IDX_VREG);
	knod_emit(priv, meta, v_lshl_add_u32, param[0], param[1],
		  param[2], param[3]);

	/* ctx = &param->sub[flat_IDX].ctx;
	 * v_mad: VREG1 = sizeof(sub_obj) * flat_IDX + PARAM_SREG
	 * then add offsetof(sub) = 8 to account for nr_backlogs/_pad
	 */
	knod_vset64(&param64[0], KNOD_AMDGPU_VREG1_LO);
	knod_sset32(&param[0], KNOD_AMDGPU_TMP_SREG0_LO);
	knod_iset32(&param[1], sizeof(struct knod_bpf_subparam_obj));
	knod_vset32(&param[2], KNOD_AMDGPU_IDX_VREG);
	knod_sset64(&param64[1], KNOD_AMDGPU_PARAM_SREG_LO);
	knod_emit(priv, meta, v_mad_u64_u32, param64[0], param[0],
		  param[1], param[2], param64[1]);
	/* + offsetof(struct knod_bpf_param, sub) */
	knod_vset32(&param[0], KNOD_AMDGPU_VREG1_LO);
	knod_iset32(&param[1], offsetof(struct knod_bpf_param, sub));
	knod_vset32(&param[2], KNOD_AMDGPU_VREG1_LO);
	knod_emit(priv, meta, v_add_co_u32, param[0], param[1], param[2]);
	knod_vset32(&param[0], KNOD_AMDGPU_VREG1_HI);
	knod_iset32(&param[1], 0);
	knod_emit(priv, meta, v_add_co_ci_u32_e32, param[0], param[1],
		  param[0]);
	knod_vset32(&param[0], KNOD_AMDGPU_CTX_VREG_LO);
	knod_vset32(&param[1], KNOD_AMDGPU_VREG1_LO);
	knod_emit(priv, meta, v_mov_b32_e32, param[0], param[1]);
	knod_vset32(&param[0], KNOD_AMDGPU_CTX_VREG_HI);
	knod_vset32(&param[1], KNOD_AMDGPU_VREG1_HI);
	knod_emit(priv, meta, v_mov_b32_e32, param[0], param[1]);
	knod_vset32(&param[0], KNOD_AMDGPU_FRAME_POINTER_VREG_LO);
	knod_iset32(&param[1], 0x200);
	knod_emit(priv, meta, v_mov_b32_e32, param[0], param[1]);
	knod_vset32(&param[0], KNOD_AMDGPU_FRAME_POINTER_VREG_HI);
	knod_iset32(&param[1], 0);
	knod_emit(priv, meta, v_mov_b32_e32, param[0], param[1]);

	/* 5. slot = (ring_start + local_idx) & ring_mask.
	 *    local_idx = saved per-queue local_idx in TMP_VREG9_LO.
	 */
	knod_vset32(&param[0], KNOD_AMDGPU_TMP_VREG5_LO);
	knod_vset32(&param[1], KNOD_AMDGPU_TMP_VREG4_LO);
	knod_vset32(&param[2], KNOD_AMDGPU_TMP_VREG9_LO);
	knod_emit(priv, meta, v_add_u32, param[0], param[1], param[2]);
	knod_vset32(&param[1], KNOD_AMDGPU_TMP_VREG4_HI);
	knod_vset32(&param[2], KNOD_AMDGPU_TMP_VREG5_LO);
	knod_emit(priv, meta, v_and_b32_e32, param[0], param[1], param[2]);

	/* Save backlog index before step 6 overwrites IDX_VREG → SLOT_VREG.
	 * v_mov_b32 BACKLOG_IDX_VREG(v58), IDX_VREG(v62)
	 * Used in epilogue for XDP_PASS pass_indices[] write.
	 */
	knod_vset32(&param[0], KNOD_AMDGPU_BACKLOG_IDX_VREG);
	knod_vset32(&param[1], KNOD_AMDGPU_IDX_VREG);
	knod_emit(priv, meta, v_mov_b32_e32, param[0], param[1]);

	/* 6. slot_addr = pool_gaddr + slot * spsc_stride, where
	 *    spsc_stride = ALIGN(sizeof(spsc_bd), SMP_CACHE_BYTES)
	 *    Compute directly into SLOT_VREG (v62:v63).
	 */
	knod_vset32(&param[0], KNOD_AMDGPU_SLOT_VREG_LO);
	knod_iset32(&param[1],
		ilog2(ALIGN(sizeof(struct spsc_bd), SMP_CACHE_BYTES)));
	knod_emit(priv, meta, v_lshlrev_b32, param[0], param[1], param[2]);
	/* slot_addr = pool_gaddr + slot_offset */
	knod_vset32(&param[1], KNOD_AMDGPU_TMP_VREG1_LO);
	knod_emit(priv, meta, v_add_co_u32, param[0], param[0], param[1]);
	knod_vset32(&param[0], KNOD_AMDGPU_SLOT_VREG_HI);
	knod_iset32(&param[1], 0);
	knod_vset32(&param[2], KNOD_AMDGPU_TMP_VREG1_HI);
	knod_emit(priv, meta, v_add_co_ci_u32_e32, param[0], param[1],
		  param[2]);

	/* 7. Load spsc_bd: {off(u16)|len(u16), page_idx} via single dwordx2
	 *    TMP_VREG6_LO (v34) = off|len, TMP_VREG6_HI (v35) = page_idx
	 */
	knod_vset32(&param[0], KNOD_AMDGPU_TMP_VREG6_LO);
	knod_vset32(&param[1], KNOD_AMDGPU_SLOT_VREG_LO);
	knod_emit(priv, meta, global_load_dwordx2, param[0], param[1],
		  offsetof(struct spsc_bd, off));
	knod_emit(priv, meta, s_waitcnt_vmcnt);

	/* 8. data = base_gaddr + (page_idx << PAGE_SHIFT) + off
	 *    Compute directly into DATA_VREG (v64:v65).
	 */
	knod_vset32(&param[0], KNOD_AMDGPU_DATA_VREG_LO);
	knod_iset32(&param[1], PAGE_SHIFT);
	knod_vset32(&param[2], KNOD_AMDGPU_TMP_VREG6_HI);
	knod_emit(priv, meta, v_lshlrev_b32, param[0], param[1], param[2]);
	knod_vset32(&param[0], KNOD_AMDGPU_DATA_VREG_HI);
	knod_iset32(&param[1], 32 - PAGE_SHIFT);
	knod_emit(priv, meta, v_lshrrev_b32, param[0], param[1], param[2]);

	/* data = base_gaddr + page_gaddr */
	knod_vset32(&param[0], KNOD_AMDGPU_DATA_VREG_LO);
	knod_vset32(&param[1], KNOD_AMDGPU_TMP_VREG2_LO);
	knod_vset32(&param[2], KNOD_AMDGPU_DATA_VREG_LO);
	knod_emit(priv, meta, v_add_co_u32, param[0], param[1], param[2]);
	knod_vset32(&param[0], KNOD_AMDGPU_DATA_VREG_HI);
	knod_vset32(&param[1], KNOD_AMDGPU_TMP_VREG2_HI);
	knod_vset32(&param[2], KNOD_AMDGPU_DATA_VREG_HI);
	knod_emit(priv, meta, v_add_co_ci_u32_e32, param[0], param[1],
		  param[2]);

	if (knod_prog->uses_adjust) {
		/* Save page_base to PAGE_BASE_VREG before adding off */
		knod_vset32(&param[0], KNOD_AMDGPU_PAGE_BASE_VREG_LO);
		knod_vset32(&param[1], KNOD_AMDGPU_DATA_VREG_LO);
		knod_emit(priv, meta, v_mov_b32_e32, param[0], param[1]);
		knod_vset32(&param[0], KNOD_AMDGPU_PAGE_BASE_VREG_HI);
		knod_vset32(&param[1], KNOD_AMDGPU_DATA_VREG_HI);
		knod_emit(priv, meta, v_mov_b32_e32, param[0], param[1]);
	}

	/* extract off (lower 16 bits of TMP_VREG6_LO) */
	knod_vset32(&param[0], KNOD_AMDGPU_TMP_VREG8_LO);
	knod_iset32(&param[1], 0xffff);
	knod_vset32(&param[2], KNOD_AMDGPU_TMP_VREG6_LO);
	knod_emit(priv, meta, v_and_b32_e32, param[0], param[1], param[2]);

	/* data += off */
	knod_vset32(&param[0], KNOD_AMDGPU_DATA_VREG_LO);
	knod_vset32(&param[1], KNOD_AMDGPU_TMP_VREG8_LO);
	knod_vset32(&param[2], KNOD_AMDGPU_DATA_VREG_LO);
	knod_emit(priv, meta, v_add_co_u32, param[0], param[1], param[2]);
	knod_vset32(&param[0], KNOD_AMDGPU_DATA_VREG_HI);
	knod_iset32(&param[1], 0);
	knod_emit(priv, meta, v_add_co_ci_u32_e32, param[0], param[1],
		  param[0]);

	/* 9. data_end = data + len (upper 16 bits of TMP_VREG6_LO)
	 *    Compute directly into DATA_END_VREG (v66:v67).
	 */
	knod_vset32(&param[0], KNOD_AMDGPU_DATA_END_VREG_LO);
	knod_iset32(&param[1], 16);
	knod_vset32(&param[2], KNOD_AMDGPU_TMP_VREG6_LO);
	knod_emit(priv, meta, v_lshrrev_b32, param[0], param[1], param[2]);
	knod_vset32(&param[0], KNOD_AMDGPU_DATA_END_VREG_LO);
	knod_vset32(&param[1], KNOD_AMDGPU_DATA_VREG_LO);
	knod_vset32(&param[2], KNOD_AMDGPU_DATA_END_VREG_LO);
	knod_emit(priv, meta, v_add_co_u32, param[0], param[1], param[2]);
	knod_vset32(&param[0], KNOD_AMDGPU_DATA_END_VREG_HI);
	knod_iset32(&param[1], 0);
	knod_vset32(&param[2], KNOD_AMDGPU_DATA_VREG_HI);
	knod_emit(priv, meta, v_add_co_ci_u32_e32, param[0], param[1],
		  param[2]);

	/* Step 10 eliminated: data→DATA_VREG, data_end→DATA_END_VREG,
	 * slot_addr→SLOT_VREG computed directly in steps 6/8/9 above.
	 */

	pr_debug("knod_bpf DEBUG: prologue emitted idx=%u (KNOD_META_INSNS=%d)\n",
		 meta->amdgpu_insns, KNOD_META_INSNS);
	if (WARN_ON(meta->amdgpu_insns > KNOD_META_INSNS))
		return -ENOSPC;
	list_add_tail(&meta->l, &knod_prog->pre_insns);

	return 0;
}

static int knod_prog_prepare(struct knod_bpf_priv *priv,
			     struct knod_prog *knod_prog,
			     const struct bpf_insn *prog,
			     unsigned int cnt)
{
	struct knod_insn_meta *meta;
	unsigned int i;

	/* Pre-scan: detect helper 44/65 to set uses_adjust early */
	for (i = 0; i < cnt; i++) {
		if (prog[i].code == (BPF_JMP | BPF_CALL) &&
		    (prog[i].imm == 44 || prog[i].imm == 65)) {
			knod_prog->uses_adjust = true;
			break;
		}
	}

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
	knod_vset64(&r64[18], KNOD_AMDGPU_TMP_VREG18_LO);
	knod_vset64(&r64[19], KNOD_AMDGPU_CTX_VREG_LO);

	knod_sset64(&sr64[0], KNOD_AMDGPU_TMP_SREG0_LO);
	knod_sset64(&sr64[1], KNOD_AMDGPU_TMP_SREG1_LO);
	knod_sset64(&sr64[2], KNOD_AMDGPU_TMP_SREG2_LO);
	knod_sset64(&sr64[3], KNOD_AMDGPU_TMP_SREG3_LO);
	knod_sset64(&sr64[4], KNOD_AMDGPU_TMP_SREG4_LO);
	knod_sset64(&sr64[5], KNOD_AMDGPU_TMP_SREG5_LO);

	knod_vset64(&bpf_reg64[0], KNOD_AMDGPU_VREG0_LO);
	knod_vset64(&bpf_reg64[1], KNOD_AMDGPU_VREG1_LO);
	knod_vset64(&bpf_reg64[2], KNOD_AMDGPU_VREG2_LO);
	knod_vset64(&bpf_reg64[3], KNOD_AMDGPU_VREG3_LO);
	knod_vset64(&bpf_reg64[4], KNOD_AMDGPU_VREG4_LO);
	knod_vset64(&bpf_reg64[5], KNOD_AMDGPU_VREG5_LO);
	knod_vset64(&bpf_reg64[6], KNOD_AMDGPU_VREG6_LO);
	knod_vset64(&bpf_reg64[7], KNOD_AMDGPU_VREG7_LO);
	knod_vset64(&bpf_reg64[8], KNOD_AMDGPU_VREG8_LO);
	knod_vset64(&bpf_reg64[9], KNOD_AMDGPU_VREG9_LO);
	knod_vset64(&bpf_reg64[10], KNOD_AMDGPU_FRAME_POINTER_VREG_LO);

	knod_vset32(&r32[0], KNOD_AMDGPU_TMP_VREG0_LO);
	for (i = 1; i < 40; i++)
		knod_vset32(&r32[i], r32[i - 1].v + 1);

	if (knod_bpf_pkt_cache) {
		int pkt_cache_start = knod_prog->uses_adjust ?
			KNOD_AMDGPU_PKT_CACHE_VREG0 :
			KNOD_AMDGPU_PAGE_BASE_VREG_LO;

		knod_vset32(&pkt_cache[0], pkt_cache_start);
		for (i = 1; i < 64; i++)
			knod_vset32(&pkt_cache[i],
						 pkt_cache[i - 1].v + 1);
	}

	/* TODO stack init is required? */
	knod_vset32(&stack[0], KNOD_AMDGPU_STACK_VREG0);
	for (i = 1; i < 128; i++)
		knod_vset32(&stack[i], stack[i - 1].v + 1);

	for (i = 0; i < cnt; i++) {
		meta = kzalloc_obj(*meta, GFP_KERNEL);
		if (!meta)
			return -ENOMEM;

		meta->insn = prog[i];
		meta->bpf_insn_idx = i;

		list_add_tail(&meta->l, &knod_prog->insns);
	}
	knod_prog->n_insns = cnt;

	return 0;
}

static void knod_prog_free(struct knod_prog *knod_prog)
{
	struct knod_insn_meta *meta, *tmp;

	//kfree(knod_prog->subprog);

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

	if (priv->isa_version == 10) {
		knod_prog->done_mask_sreg = 32;
		knod_prog->exec_save_base = 34;
		knod_prog->initial_exec_sreg =
			KNOD_AMDGPU_INITIAL_EXEC_SREG_GFX10;
	} else {
		knod_prog->done_mask_sreg = KNOD_AMDGPU_DONE_MASK_SREG;
		knod_prog->exec_save_base = KNOD_AMDGPU_EXEC_SAVE_SREG_BASE;
		knod_prog->initial_exec_sreg =
			KNOD_AMDGPU_INITIAL_EXEC_SREG_GFX9;
	}

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

static void knod_alignbit32(struct knod_bpf_priv *priv,
			   struct knod_insn_meta *meta,
			   struct amdgcn_param32 dst,
			   struct amdgcn_param32 src0,
			   struct amdgcn_param32 src1,
			   struct amdgcn_param32 src2)
{
	knod_emit(priv, meta, v_alignbit_b32, dst, src0, src1, src2);
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

static void knod_subrev64(struct knod_bpf_priv *priv,
			 struct knod_insn_meta *meta,
			 struct amdgcn_param64 dst,
			 struct amdgcn_param64 src0,
			 struct amdgcn_param64 src1)
{
	knod_emit(priv, meta, v_subrev_co_u32, dst.lo, src0.lo, src1.lo);
	knod_emit(priv, meta, v_subrev_co_ci_u32_e32, dst.hi, src0.hi,
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

/* TODO corruption of src1, src2 */
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

static void knod_div(struct knod_bpf_priv *priv,
		    struct knod_insn_meta *meta,
		    struct amdgcn_param64 dst,
		    struct amdgcn_param64 imm,
		    struct amdgcn_param64 tmp_reg0,
		    struct amdgcn_param64 tmp_reg1,
		    struct amdgcn_param64 tmp_reg2,
		    struct amdgcn_param64 tmp_reg3)
{
	struct reciprocal_value_adv rvalue;
	struct amdgcn_param64 p64[4];
	u8 pre_shift, exp;

	WARN_ON((imm.lo.type != AMDGCN_PARAM_TYPE_INTEGER_0) &&
		     (imm.lo.type != AMDGCN_PARAM_TYPE_LITERAL_CONST));
	WARN_ON((imm.hi.type != AMDGCN_PARAM_TYPE_INTEGER_0) &&
		     (imm.hi.type != AMDGCN_PARAM_TYPE_LITERAL_CONST));
	knod_iset64(&p64[0], 0);
	knod_iset64(&p64[1], 0);
	knod_iset64(&p64[2], 0);
	knod_iset64(&p64[3], 0);
	/*
	 * dst := imm
	 * n := dst_reg
	 */
	if (imm.imm > U32_MAX) {
		knod_mov64(priv, meta, dst, p64[0]);
		return;
	}

	if (imm.imm >= 1U << 31) {
		/* result = n >= dst; */
		knod_mov64(priv, meta, tmp_reg0, imm);
		knod_emit(priv, meta, v_cmp_ge_u64, dst, tmp_reg0);
		return;
	}

	rvalue = reciprocal_value_adv(imm.lo.v, 32);
	exp = rvalue.exp;
	if (rvalue.is_wide_m && !(imm.lo.v & 1)) {
		pre_shift = fls(imm.lo.v & -imm.lo.v) - 1;
		rvalue = reciprocal_value_adv(imm.lo.v >> pre_shift,
					      32 - pre_shift);
	} else {
		pre_shift = 0;
	}

	if (imm.lo.v == 1U << exp) {
		knod_iset64(&p64[0], exp);
		/* n = n >> exp */
		knod_lshrrev64(priv, meta, dst, p64[0], dst);
		return;
	} else if (rvalue.is_wide_m) {
		/*
		 * pre_shift must be zero when reached here.
		 * t = (n * rvalue.m) >> 32;
		 * result = n - t;
		 * result >>= 1;
		 * result += t;
		 * result >>= rvalue.sh - 1;
		 */

		/*
		 * n := VREG0
		 * t := VREG1
		 * rvalue.m := VREG2
		 * tmp := VREG3
		 */

		/* n := TMP_VREG0 */
		knod_mov64(priv, meta, tmp_reg0, dst);

		knod_iset64(&p64[0], rvalue.m);
		/* rvalue.m := TMP_VREG2 */
		knod_mov64(priv, meta, tmp_reg2, p64[0]);

		/* t = n * rvalue.m; */
		knod_mul64(priv, meta,
			   tmp_reg1, /* t */
			   tmp_reg0, /* n */
			   tmp_reg2, /* rvalue.m */
			   tmp_reg3); /* tmp */

		/* t >>= 32; */
		knod_iset64(&p64[0], 0);
		knod_mov32(priv, meta, tmp_reg1.lo, tmp_reg1.hi);
		knod_mov32(priv, meta, tmp_reg1.hi, p64[0].lo);

		/* result = n - t */
		knod_sub64(priv, meta, dst, dst, tmp_reg1);

		/* result >>= 1 */
		knod_iset64(&p64[0], 1);
		knod_lshrrev64(priv, meta, dst, p64[0], dst);

		/* result += t; */
		knod_add64(priv, meta,
			   dst,
			   dst, /* result */
			   tmp_reg1); /* t */

		/* result >>= rvalue.sh - 1; */
		knod_iset64(&p64[0], rvalue.sh - 1);
		WARN_ON(rvalue.sh - 1 > 31);
		knod_lshrrev64(priv, meta, dst, p64[0], dst);
		return;
	}

	/*
	 * if (pre_shift)
	 *   result = n >> pre_shift;
	 * result = ((u64)result * rvalue.m) >> 32;
	 * result >>= rvalue.sh;
	 */

	/*
	 * n := VREG0
	 * <NONE> := VREG1
	 * rvalue.m := VREG2
	 * tmp := VREG3
	 * result := dst * 2
	 */

	/* n := TMP_VREG0 */
	knod_mov64(priv, meta, tmp_reg0, dst);

	/* rvalue.m := TMP_VREG2 */
	knod_iset64(&p64[0], rvalue.m);
	knod_mov64(priv, meta, tmp_reg2, p64[0]);

	if (pre_shift) {
		/* result = n >> pre_shift; */
		knod_iset64(&p64[0], pre_shift);
		knod_lshrrev64(priv, meta, dst, p64[0],
			       tmp_reg0); /* n */
	} else {
		/* tmp = 0 */
		knod_iset64(&p64[0], 0);
		knod_mov64(priv, meta, tmp_reg0, p64[0]);
	}

	/* result = result * rvalue.m; */
	knod_mul64(priv, meta,
		   dst, /* result */
		   dst, /* result */
		   tmp_reg2, /* rvalue.m */
		   tmp_reg3); /* tmp */

	/* result >>= (32 + rvalue.sh); */
	knod_iset64(&p64[0], 32 + rvalue.sh);
	knod_lshrrev64(priv, meta, dst, p64[0], dst);
}

static void knod_mod(struct knod_bpf_priv *priv,
		    struct knod_insn_meta *meta,
		    struct amdgcn_param64 dst,
		    struct amdgcn_param64 imm,
		    struct amdgcn_param64 tmp_reg0,
		    struct amdgcn_param64 tmp_reg1,
		    struct amdgcn_param64 tmp_reg2,
		    struct amdgcn_param64 tmp_reg3,
		    struct amdgcn_param64 tmp_reg4)
{
	WARN_ON((imm.lo.type != AMDGCN_PARAM_TYPE_INTEGER_0) &&
		     (imm.lo.type != AMDGCN_PARAM_TYPE_LITERAL_CONST));
	WARN_ON((imm.hi.type != AMDGCN_PARAM_TYPE_INTEGER_0) &&
		     (imm.hi.type != AMDGCN_PARAM_TYPE_LITERAL_CONST));
	/* q := tmp_reg0 */
	knod_mov64(priv, meta, tmp_reg0, dst);
	/* q = n / imm */
	knod_div(priv, meta, tmp_reg0, imm,
		     tmp_reg1, tmp_reg2, tmp_reg3, tmp_reg4);

	/* tmp_reg1 := imm_reg */
	knod_mov64(priv, meta, tmp_reg1, imm);

	/* imm * q := tmp_reg3 */
	knod_mul64(priv, meta,
		   tmp_reg3, /* imm * q */
		   tmp_reg0, /* q */
		   tmp_reg1, /* imm_reg */
		   tmp_reg2); /* tmp */

	knod_sub64(priv, meta, dst, dst, tmp_reg3);
}

/*
 * Fast constant modulo on the 32-bit value in @dst.lo for divisors of a
 * special form, avoiding knod_mod's reciprocal divide + 64-bit multiply:
 *   2^k     -> dst & (2^k-1)                     (mask)
 *   2^k + 1 -> lo - hi (+C if lo<hi)             (Fermat: 2^k = -1 mod C)
 *   2^k - 1 -> lo + hi (-C while >=C)            (Mersenne: 2^k = 1 mod C)
 * lo/hi are the low/high k-bit halves.  One fold is exact for a 32-bit
 * dividend when 2^k covers the high half (true for e.g. 65537 = 2^16+1,
 * kondor's per-packet `hash % RING_SIZE`).  Returns false for other
 * divisors (caller falls back to knod_mod).  Scratch: r64[0], r64[1].
 */
static bool knod_mod_k32(struct knod_bpf_priv *priv,
			 struct knod_insn_meta *meta,
			 struct amdgcn_param64 dst, u32 imm)
{
	struct amdgcn_param32 p;
	int i;

	if (is_power_of_2(imm)) {
		knod_iset32(&p, imm - 1);
		knod_and32(priv, meta, dst.lo, p, dst.lo);
	} else if (is_power_of_2(imm - 1) && (imm - 1) >= (1u << 16)) {
		knod_iset32(&p, imm - 2);			/* mask 2^k-1 */
		knod_and32(priv, meta, r64[0].lo, p, dst.lo);	/* lo */
		knod_iset32(&p, ilog2(imm - 1));		/* k */
		knod_emit(priv, meta, v_lshrrev_b32, r64[1].lo, p, dst.lo);
		/* lo-hi */
		knod_sub32(priv, meta, dst.lo, r64[0].lo, r64[1].lo);
		knod_emit(priv, meta, v_cmp_lt_u32, r64[0].lo, r64[1].lo);
		knod_iset32(&p, imm);
		knod_add32(priv, meta, r64[1].lo, p, dst.lo);	/* +C */
		knod_emit(priv, meta, v_cndmask_b32_e32, dst.lo, dst.lo,
			  r64[1].lo);
	} else if (is_power_of_2(imm + 1) && (imm + 1) >= (1u << 16)) {
		knod_iset32(&p, imm);				/* mask 2^k-1 */
		knod_and32(priv, meta, r64[0].lo, p, dst.lo);	/* lo */
		knod_iset32(&p, ilog2(imm + 1));		/* k */
		knod_emit(priv, meta, v_lshrrev_b32, r64[1].lo, p, dst.lo);
		/* lo+hi */
		knod_add32(priv, meta, dst.lo, r64[0].lo, r64[1].lo);
		knod_iset32(&p, imm);
		knod_mov32(priv, meta, r64[0].lo, p);		/* C in VGPR */
		for (i = 0; i < 2; i++) {			/* r < 2C */
			knod_emit(priv, meta, v_cmp_le_u32, r64[0].lo, dst.lo);
			knod_sub32(priv, meta, r64[1].lo, dst.lo, r64[0].lo);
			knod_emit(priv, meta, v_cndmask_b32_e32, dst.lo,
				  dst.lo, r64[1].lo);
		}
	} else {
		return false;
	}

	knod_iset32(&p, 0);
	knod_mov32(priv, meta, dst.hi, p);
	return true;
}

/* Considered to be able to use all temporary vregisters
 * Also, key is stack pointer, not global
 */
static void knod_jhash(struct knod_bpf_priv *priv,
		      struct knod_insn_meta *meta,
		      u32 dst_idx, u32 length, u32 initval)
{
	u32 a_reg = TREG32_MAX - 3, b_reg = TREG32_MAX - 2;
	u32 c_reg = TREG32_MAX - 1, d_reg = TREG32_MAX;
	u32 key_in_pkt = KEY_IN_PKT_32;
	struct amdgcn_param32 p32;

	knod_iset32(&p32, JHASH_INITVAL + length + initval);
	knod_mov32(priv, meta, r32[a_reg], p32);
	knod_mov32(priv, meta, r32[b_reg], p32);
	knod_mov32(priv, meta, r32[c_reg], p32);
	knod_iset32(&p32, 0);

	while (length > 12) {
		/* a += *key; */
		knod_add32(priv, meta, r32[a_reg], r32[a_reg],
			       r32[key_in_pkt]);
		/* b += *(key + 4); */
		knod_add32(priv, meta, r32[b_reg], r32[b_reg],
			       r32[key_in_pkt + 1]);
		/* c += *(key + 8); */
		knod_add32(priv, meta, r32[c_reg], r32[c_reg],
			       r32[key_in_pkt + 2]);
		/* a -= c; */
		knod_sub32(priv, meta, r32[a_reg], r32[a_reg], r32[c_reg]);
		/* a ^= rol32(c, 4); */
		knod_iset32(&p32, 32 - 4);
		knod_alignbit32(priv, meta, r32[d_reg], r32[c_reg],
				    r32[c_reg], p32);
		knod_xor32(priv, meta,
			       r32[a_reg], r32[a_reg], r32[d_reg]);
		/* c += b; */
		knod_add32(priv, meta, r32[c_reg], r32[c_reg], r32[b_reg]);
		/* b -= a; */
		knod_sub32(priv, meta, r32[b_reg], r32[b_reg], r32[a_reg]);
		/* b ^= rol32(a, 6); */
		knod_iset32(&p32, 32 - 6);
		knod_alignbit32(priv, meta, r32[d_reg], r32[a_reg],
				    r32[a_reg], p32);
		knod_xor32(priv, meta,
			       r32[b_reg], r32[b_reg], r32[d_reg]);
		/*a += c; */
		knod_add32(priv, meta, r32[a_reg], r32[a_reg], r32[c_reg]);
		/* c -= b; */
		knod_sub32(priv, meta, r32[c_reg], r32[c_reg], r32[b_reg]);
		/* c ^= rol32(b, 8); */
		knod_iset32(&p32, 32 - 8);
		knod_alignbit32(priv, meta, r32[d_reg], r32[b_reg],
				    r32[b_reg], p32);
		knod_xor32(priv, meta,
			       r32[c_reg], r32[c_reg], r32[d_reg]);
		/* b += a; */
		knod_add32(priv, meta, r32[b_reg], r32[b_reg], r32[a_reg]);
		/* a -= c; */
		knod_sub32(priv, meta, r32[a_reg], r32[a_reg], r32[c_reg]);
		/* a ^= rol32(c, 16); */
		knod_iset32(&p32, 32 - 16);
		knod_alignbit32(priv, meta, r32[d_reg], r32[c_reg],
				    r32[c_reg], p32);
		knod_xor32(priv, meta, r32[a_reg], r32[a_reg], r32[d_reg]);
		/* c += b; */
		knod_add32(priv, meta, r32[c_reg], r32[c_reg], r32[b_reg]);
		/* b -= a; */
		knod_sub32(priv, meta, r32[b_reg], r32[b_reg], r32[a_reg]);
		/* b ^= rol32(a, 19); */
		knod_iset32(&p32, 32 - 19);
		knod_alignbit32(priv, meta, r32[d_reg], r32[a_reg],
				    r32[a_reg], p32);
		knod_xor32(priv, meta, r32[b_reg], r32[b_reg], r32[d_reg]);
		/* a += c; */
		knod_add32(priv, meta, r32[a_reg], r32[a_reg], r32[c_reg]);
		/* c -= b; */
		knod_sub32(priv, meta, r32[c_reg], r32[c_reg], r32[b_reg]);
		/* c ^= rol32(b, 4); */
		knod_iset32(&p32, 32 - 4);
		knod_alignbit32(priv, meta, r32[d_reg], r32[b_reg],
				    r32[b_reg], p32);
		knod_xor32(priv, meta, r32[c_reg], r32[c_reg], r32[d_reg]);
		/* b += a; */
		knod_add32(priv, meta, r32[b_reg], r32[b_reg], r32[a_reg]);
		length -= 12;
		key_in_pkt += 3;
	}

	switch (length) {
	case 12:
		/* c += (unsigned int)k[11]<<24; */
		fallthrough;
	case 11:
		/* c += (unsigned int)k[10]<<16; */
		fallthrough;
	case 10:
		/* c += (unsigned int)k[9]<<8; */
		fallthrough;
	case 9:
		/* c += k[8]; */
		knod_add32(priv, meta, r32[c_reg], r32[c_reg],
			       r32[key_in_pkt + 2]);
		fallthrough;
	case 8:
		/* b += (unsigned int)k[7]<<24; */
		fallthrough;
	case 7:
		/* b += (unsigned int)k[6]<<16; */
		fallthrough;
	case 6:
		/* b += (unsigned int)k[5]<<8; */
		fallthrough;
	case 5:
		/* b += k[4]; */
		knod_add32(priv, meta, r32[b_reg], r32[b_reg],
			       r32[key_in_pkt + 1]);
		fallthrough;
	case 4:
		/* a += (unsigned int)k[3]<<24; */
		fallthrough;
	case 3:
		/* a += (unsigned int)k[2]<<16; */
		fallthrough;
	case 2:
		/* a += (unsigned int)k[1]<<8; */
		fallthrough;
	case 1:
		/* a += k[0]; */
		knod_add32(priv, meta, r32[a_reg], r32[a_reg],
			       r32[key_in_pkt]);
		/* c ^= b; */
		knod_xor32(priv, meta, r32[c_reg], r32[c_reg], r32[b_reg]);
		/* c -= rol32(b, 14); */
		knod_iset32(&p32, 32 - 14);
		knod_alignbit32(priv, meta, r32[d_reg], r32[b_reg],
				    r32[b_reg], p32);
		knod_sub32(priv, meta, r32[c_reg], r32[c_reg], r32[d_reg]);
		/* a ^= c; */
		knod_xor32(priv, meta, r32[a_reg], r32[a_reg], r32[c_reg]);
		/* a -= rol32(c, 11); */
		knod_iset32(&p32, 32 - 11);
		knod_alignbit32(priv, meta, r32[d_reg], r32[c_reg],
				    r32[c_reg], p32);
		knod_sub32(priv, meta, r32[a_reg], r32[a_reg], r32[d_reg]);
		/* b ^= a; */
		knod_xor32(priv, meta, r32[b_reg], r32[b_reg], r32[a_reg]);
		/* b -= rol32(a, 25); */
		knod_iset32(&p32, 32 - 25);
		knod_alignbit32(priv, meta, r32[d_reg], r32[a_reg],
				    r32[a_reg], p32);
		knod_sub32(priv, meta, r32[b_reg], r32[b_reg], r32[d_reg]);
		/* c ^= b; */
		knod_xor32(priv, meta, r32[c_reg], r32[c_reg], r32[b_reg]);
		/* c -= rol32(b, 16); */
		knod_iset32(&p32, 32 - 16);
		knod_alignbit32(priv, meta, r32[d_reg], r32[b_reg],
				    r32[b_reg], p32);
		knod_sub32(priv, meta, r32[c_reg], r32[c_reg], r32[d_reg]);
		/* a ^= c; */
		knod_xor32(priv, meta, r32[a_reg], r32[a_reg], r32[c_reg]);
		/* a -= rol32(c, 4); */
		knod_iset32(&p32, 32 - 4);
		knod_alignbit32(priv, meta, r32[d_reg], r32[c_reg],
				    r32[c_reg], p32);
		knod_sub32(priv, meta, r32[a_reg], r32[a_reg], r32[d_reg]);
		/* b ^= a; */
		knod_xor32(priv, meta, r32[b_reg], r32[b_reg], r32[a_reg]);
		/* b -= rol32(a, 14); */
		knod_iset32(&p32, 32 - 14);
		knod_alignbit32(priv, meta, r32[d_reg], r32[a_reg],
				    r32[a_reg], p32);
		knod_sub32(priv, meta, r32[b_reg], r32[b_reg], r32[d_reg]);
		/* c ^= b; */
		knod_xor32(priv, meta, r32[c_reg], r32[c_reg], r32[b_reg]);
		/* c -= rol32(b, 24); */
		knod_iset32(&p32, 32 - 24);
		knod_alignbit32(priv, meta, r32[d_reg], r32[b_reg],
				    r32[b_reg], p32);
		knod_sub32(priv, meta, r32[c_reg], r32[c_reg], r32[d_reg]);
		break;
	case 0: /* Nothing left to add */
		break;
	}

	knod_mov32(priv, meta, r64[dst_idx].lo, r32[c_reg]);
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

static void *knod_bpf_map_kaddr(struct knod_bpf_priv *priv, int id)
{
	struct knod_dev *knodev = priv->knodev;
	struct knod_bpf_map *knod_map;
	struct knod_mem *mem;

	mutex_lock(&knodev->lock);
	list_for_each_entry(knod_map, &knodev->accel->xdp.bound_maps, list) {
		if (knod_map->offmap->map.id == id) {
			mem = knod_map->mem;

			/* GPUVM */
			mutex_unlock(&knodev->lock);
			return (void *)mem->kaddr;
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

static int knod_bpf_get_amdgpu_insn_idx(struct knod_bpf_priv *priv,
					struct knod_insn_meta *meta,
					int t)
{
	int i, insn_idx = meta->amdgpu_insn_idx;

	for (i = 0; i < t; i++)
		insn_idx += meta->amdgpu_insn[i].size / 4;

	return insn_idx;
}

static void knod_bpf_fixup_branch(struct knod_bpf_priv *priv,
				  struct amdgcn_branch_fixup *fixup)
{
	int target_off = knod_bpf_get_amdgpu_insn_idx(priv,
						      fixup->target_label->meta,
			fixup->target_label->insn_idx);
	int cur_off = knod_bpf_get_amdgpu_insn_idx(priv,
						   fixup->meta,
						   fixup->insn_idx);
	cur_off++;

	target_off -= cur_off;
	emit_branch_fixup(priv->isa_version,
			  &fixup->meta->amdgpu_insn[fixup->insn_idx],
			  target_off);
	knod_jit_dbg(" target_off was updated to %d\n", target_off);
}

static void knod_bpf_set_fixup(struct knod_insn_meta *meta,
			       struct amdgcn_branch_fixup *fixup,
			       struct amdgcn_label *target_label,
			       int insn_idx)
{
	fixup->meta = meta;
	fixup->insn_idx = insn_idx;
	fixup->target_label = target_label;
}

static void knod_bpf_set_label(struct knod_insn_meta *meta,
			       struct amdgcn_label *label,
			       int insn_idx)
{
	label->meta = meta;
	label->insn_idx = insn_idx;
}

/*
 * knod_bpf_emit_offlen_writeback - Write updated off/len to spsc_bd.
 *
 * Uses PAGE_BASE_VREG (set once in prologue), computes
 * new_off = DATA_VREG_LO - PAGE_BASE_VREG_LO and
 * new_len = DATA_END_VREG_LO - DATA_VREG_LO, packs them as (len<<16)|off,
 * and stores the result at spsc_bd.off via SLOT_VREG.
 *
 * Clobbers: TMP_VREG2 (v26:v27).
 */
static void knod_bpf_emit_offlen_writeback(struct knod_bpf_priv *priv,
					  struct knod_insn_meta *meta)
{
	struct amdgcn_param32 s0, s1, data_lo, data_end_lo, pbase_lo, slot_lo;
	struct amdgcn_param32 imm;

	knod_vset32(&s0, KNOD_AMDGPU_TMP_VREG2_LO);
	knod_vset32(&s1, KNOD_AMDGPU_TMP_VREG2_HI);
	knod_vset32(&data_lo, KNOD_AMDGPU_DATA_VREG_LO);
	knod_vset32(&data_end_lo, KNOD_AMDGPU_DATA_END_VREG_LO);
	knod_vset32(&pbase_lo, KNOD_AMDGPU_PAGE_BASE_VREG_LO);
	knod_vset32(&slot_lo, KNOD_AMDGPU_SLOT_VREG_LO);

	/* s0 = len = DATA_END_LO - DATA_LO */
	knod_sub32(priv, meta, s0, data_end_lo, data_lo);

	/* s0 = len << 16 */
	knod_iset32(&imm, 16);
	knod_lshlrev32(priv, meta, s0, imm, s0);

	/* s1 = off = DATA_LO - page_base_lo */
	knod_sub32(priv, meta, s1, data_lo, pbase_lo);

	/* s0 = (len << 16) | off */
	knod_or32(priv, meta, s0, s0, s1);

	/* Store packed {off, len} to spsc_bd */
	knod_emit(priv, meta, global_store_dword, s0, slot_lo,
		  offsetof(struct spsc_bd, off));
}

/*
 * knod_bpf_xdp_adjust_head - JIT bpf_xdp_adjust_head (helper 44).
 *
 * R2 = delta (signed 32-bit).  Adjusts DATA_VREG by delta.
 * Bounds: page_base <= DATA_VREG <= DATA_END_VREG - ETH_HLEN.
 * Each bound is checked with its own VOPC, but VCC is captured into
 * VGPRs via v_cndmask (VALU) rather than SGPRs via s_mov_b64 (SALU).
 * VALU reads VCC correctly after VOPC; only SALU suffers the GFX10
 * dual-VOPC stale-read hazard.
 * page_base is reloaded on demand from param + spsc_bd.
 * On failure, DATA_VREG is restored and R0 = -EINVAL.
 * On success, R0 = 0.
 *
 * Clobbers: TMP_VREG0 (v22:v23), TMP_VREG1 (v24:v25), TMP_VREG2 (v26:v27),
 *           TMP_SREG0 (s16), TMP_SREG2 (s20:s21).
 */
static void knod_bpf_xdp_adjust_head(struct knod_bpf_priv *priv,
				    struct knod_insn_meta *meta)
{
	struct amdgcn_param32 ub_lo, ub_hi, dend_lo, dend_hi, sext_dst;
	struct amdgcn_param32 shift_amt;
	struct amdgcn_param32 tmp0_lo, tmp0_hi, data_lo, data_hi, fail_lo;
	struct amdgcn_param32 fail_hi;
	struct amdgcn_param64 data_vreg, pbase_vreg, ub;
	struct amdgcn_param32 r0_lo, r0_hi, imm, delta;

	knod_vset64(&data_vreg, KNOD_AMDGPU_DATA_VREG_LO);

	knod_vset32(&tmp0_lo, KNOD_AMDGPU_TMP_VREG0_LO);
	knod_vset32(&tmp0_hi, KNOD_AMDGPU_TMP_VREG0_HI);
	knod_vset32(&data_lo, KNOD_AMDGPU_DATA_VREG_LO);
	knod_vset32(&data_hi, KNOD_AMDGPU_DATA_VREG_HI);
	knod_vset32(&r0_lo, KNOD_AMDGPU_VREG0_LO);
	knod_vset32(&r0_hi, KNOD_AMDGPU_VREG0_HI);
	knod_vset32(&delta, bpf_reg64[2].lo.v);
	knod_vset32(&fail_lo, KNOD_AMDGPU_TMP_VREG2_LO);
	knod_vset32(&fail_hi, KNOD_AMDGPU_TMP_VREG2_HI);

	/* 1. Save original DATA_VREG → TMP_VREG0 */
	knod_mov32(priv, meta, tmp0_lo, data_lo);
	knod_mov32(priv, meta, tmp0_hi, data_hi);

	/* 2. DATA_VREG += delta (R2.lo, sign-extended to 64-bit) */
	knod_emit(priv, meta, v_add_co_u32, data_lo, delta, data_lo);

	knod_vset32(&sext_dst, KNOD_AMDGPU_TMP_VREG1_LO);
	knod_iset32(&shift_amt, 31);
	knod_emit(priv, meta, v_ashrrev_i32, sext_dst, shift_amt, delta);

	knod_emit(priv, meta, v_add_co_ci_u32_e32, data_hi, sext_dst,
		  data_hi);

	/* 3. Lower bound: DATA_VREG < page_base → VCC = fail */
	knod_vset64(&pbase_vreg, KNOD_AMDGPU_PAGE_BASE_VREG_LO);
	knod_emit(priv, meta, v_cmp_lt_u64, data_vreg, pbase_vreg);

	/*
	 * Capture VCC → VGPR via v_cndmask (VALU reads VCC correctly,
	 * unlike SALU which suffers the dual-VOPC stale-read hazard).
	 */
	knod_iset32(&imm, 1);
	knod_mov32(priv, meta, fail_hi, imm);
	knod_iset32(&imm, 0);
	knod_emit(priv, meta, v_cndmask_b32_e32, fail_lo, imm, fail_hi);

	/* 5. Upper bound: DATA_VREG > DATA_END_VREG - ETH_HLEN */
	knod_vset32(&ub_lo, KNOD_AMDGPU_TMP_VREG1_LO);
	knod_vset32(&ub_hi, KNOD_AMDGPU_TMP_VREG1_HI);
	knod_vset32(&dend_lo, KNOD_AMDGPU_DATA_END_VREG_LO);
	knod_vset32(&dend_hi, KNOD_AMDGPU_DATA_END_VREG_HI);

	knod_iset32(&imm, ETH_HLEN);
	/*
	 * v_sub_co_u32 is VOP2 on GFX9, whose vsrc1 must be a VGPR (a literal
	 * there reads v0). Subtraction is not commutative, so materialise
	 * ETH_HLEN into a scratch VGPR (ub_hi, overwritten by the high half
	 * below) and use it as src1 instead of an immediate.
	 */
	knod_mov32(priv, meta, ub_hi, imm);
	knod_emit(priv, meta, v_sub_co_u32, ub_lo, dend_lo, ub_hi);
	knod_iset32(&imm, 0);
	knod_mov32(priv, meta, delta, imm);
	knod_emit(priv, meta, v_sub_co_ci_u32_e32, ub_hi, dend_hi, delta);

	knod_vset64(&ub, KNOD_AMDGPU_TMP_VREG1_LO);
	knod_emit(priv, meta, v_cmp_gt_u64, data_vreg, ub);

	/* Capture upper_fail via v_cndmask, combine, convert to VCC */
	knod_iset32(&imm, 0);
	knod_emit(priv, meta, v_cndmask_b32_e32, fail_hi, imm, fail_hi);

	knod_emit(priv, meta, v_or_b32_e32, fail_lo, fail_lo, fail_hi);

	knod_emit(priv, meta, v_cmp_lt_u32, imm, fail_lo);

	/* 6. Conditional restore: VCC=1(fail) → original,
	 *    VCC=0(pass) → adjusted
	 */
	knod_emit(priv, meta, v_cndmask_b32_e32, data_lo, data_lo,
		  tmp0_lo);
	knod_emit(priv, meta, v_cndmask_b32_e32, data_hi, data_hi,
		  tmp0_hi);

	/* 7. R0 = VCC ? -EINVAL : 0 */
	knod_iset32(&imm, -EINVAL);
	knod_mov32(priv, meta, tmp0_lo, imm);
	knod_iset32(&imm, 0);
	knod_emit(priv, meta, v_cndmask_b32_e32, r0_lo, imm, tmp0_lo);

	knod_iset32(&imm, -1);
	knod_mov32(priv, meta, tmp0_hi, imm);
	knod_iset32(&imm, 0);
	knod_emit(priv, meta, v_cndmask_b32_e32, r0_hi, imm, tmp0_hi);
}

/*
 * knod_bpf_xdp_adjust_tail - JIT bpf_xdp_adjust_tail (helper 65).
 *
 * R2 = delta (signed 32-bit).  Adjusts DATA_END_VREG by delta.
 * Bounds: DATA_VREG + ETH_HLEN <= DATA_END_VREG <= page_base + PAGE_SIZE.
 * Each bound is checked with its own VOPC, but VCC is captured into
 * VGPRs via v_cndmask (VALU) rather than SGPRs via s_mov_b64 (SALU).
 * VALU reads VCC correctly after VOPC; only SALU suffers the GFX10
 * dual-VOPC stale-read hazard.
 * page_base is reloaded on demand from param + spsc_bd.
 * On failure, DATA_END_VREG is restored and R0 = -EINVAL.
 * On success, R0 = 0.
 *
 * Clobbers: TMP_VREG0 (v22:v23), TMP_VREG1 (v24:v25), TMP_VREG2 (v26:v27),
 *           TMP_SREG0 (s16), TMP_SREG2 (s20:s21).
 */
static void knod_bpf_xdp_adjust_tail(struct knod_bpf_priv *priv,
				    struct knod_insn_meta *meta)
{
	struct amdgcn_param32 tmp0_lo, tmp0_hi, dend_lo, dend_hi, fail_lo;
	struct amdgcn_param32 fail_hi;
	struct amdgcn_param32 lb_lo, lb_hi, d_lo, d_hi, sext_dst, shift_amt;
	struct amdgcn_param32 pb_src_lo, pb_src_hi;
	struct amdgcn_param32 r0_lo, r0_hi;
	struct amdgcn_param32 imm, delta;
	struct amdgcn_param64 dend_vreg, lb;

	knod_vset32(&tmp0_lo, KNOD_AMDGPU_TMP_VREG0_LO);
	knod_vset32(&tmp0_hi, KNOD_AMDGPU_TMP_VREG0_HI);
	knod_vset32(&dend_lo, KNOD_AMDGPU_DATA_END_VREG_LO);
	knod_vset32(&dend_hi, KNOD_AMDGPU_DATA_END_VREG_HI);
	knod_vset32(&r0_lo, KNOD_AMDGPU_VREG0_LO);
	knod_vset32(&r0_hi, KNOD_AMDGPU_VREG0_HI);
	knod_vset32(&delta, bpf_reg64[2].lo.v);
	knod_vset32(&fail_lo, KNOD_AMDGPU_TMP_VREG2_LO);
	knod_vset32(&fail_hi, KNOD_AMDGPU_TMP_VREG2_HI);
	knod_vset64(&dend_vreg, KNOD_AMDGPU_DATA_END_VREG_LO);

	/* 1. Save original DATA_END_VREG → TMP_VREG0 */
	knod_mov32(priv, meta, tmp0_lo, dend_lo);
	knod_mov32(priv, meta, tmp0_hi, dend_hi);

	/* 2. DATA_END_VREG += delta (R2.lo, sign-extended) */
	knod_emit(priv, meta, v_add_co_u32, dend_lo, delta, dend_lo);

	knod_vset32(&sext_dst, KNOD_AMDGPU_TMP_VREG1_LO);
	knod_iset32(&shift_amt, 31);
	knod_emit(priv, meta, v_ashrrev_i32, sext_dst, shift_amt, delta);

	knod_emit(priv, meta, v_add_co_ci_u32_e32, dend_hi, sext_dst,
		  dend_hi);

	/* 3. Lower bound: lb = DATA + ETH_HLEN → TMP_VREG1 */
	knod_vset32(&lb_lo, KNOD_AMDGPU_TMP_VREG1_LO);
	knod_vset32(&lb_hi, KNOD_AMDGPU_TMP_VREG1_HI);
	knod_vset32(&d_lo, KNOD_AMDGPU_DATA_VREG_LO);
	knod_vset32(&d_hi, KNOD_AMDGPU_DATA_VREG_HI);

	knod_iset32(&imm, ETH_HLEN);
	knod_emit(priv, meta, v_add_co_u32, lb_lo, imm, d_lo);
	knod_iset32(&imm, 0);
	knod_emit(priv, meta, v_add_co_ci_u32_e32, lb_hi, imm, d_hi);

	/* VOPC#1: DATA_END < lb → VCC = lower_fail */
	knod_vset64(&lb, KNOD_AMDGPU_TMP_VREG1_LO);
	knod_emit(priv, meta, v_cmp_lt_u64, dend_vreg, lb);

	/*
	 * Capture VCC → VGPR via v_cndmask (VALU reads VCC correctly,
	 * unlike SALU which suffers the GFX10 dual-VOPC stale-read hazard).
	 */
	knod_iset32(&imm, 1);
	knod_mov32(priv, meta, fail_hi, imm);
	knod_iset32(&imm, 0);
	knod_emit(priv, meta, v_cndmask_b32_e32, fail_lo, imm, fail_hi);

	/* 4. Upper bound: ub = page_base + PAGE_SIZE → TMP_VREG1 */
	knod_vset32(&pb_src_lo, KNOD_AMDGPU_PAGE_BASE_VREG_LO);
	knod_vset32(&pb_src_hi, KNOD_AMDGPU_PAGE_BASE_VREG_HI);
	knod_mov32(priv, meta, lb_lo, pb_src_lo);
	knod_mov32(priv, meta, lb_hi, pb_src_hi);

	knod_iset32(&imm, PAGE_SIZE);
	knod_emit(priv, meta, v_add_co_u32, lb_lo, imm, lb_lo);
	knod_iset32(&imm, 0);
	knod_emit(priv, meta, v_add_co_ci_u32_e32, lb_hi, imm, lb_hi);

	/* VOPC#2: DATA_END > ub → VCC = upper_fail */
	knod_emit(priv, meta, v_cmp_gt_u64, dend_vreg, lb);

	/* Capture upper_fail via v_cndmask, combine, convert to VCC */
	knod_iset32(&imm, 0);
	knod_emit(priv, meta, v_cndmask_b32_e32, fail_hi, imm, fail_hi);

	knod_emit(priv, meta, v_or_b32_e32, fail_lo, fail_lo, fail_hi);

	knod_emit(priv, meta, v_cmp_lt_u32, imm, fail_lo);

	/* 5. Conditional restore: VCC=1(fail) → original,
	 *    VCC=0(pass) → adjusted
	 */
	knod_emit(priv, meta, v_cndmask_b32_e32, dend_lo, dend_lo,
		  tmp0_lo);
	knod_emit(priv, meta, v_cndmask_b32_e32, dend_hi, dend_hi,
		  tmp0_hi);

	/* 6. R0 = VCC ? -EINVAL : 0 */
	knod_iset32(&imm, -EINVAL);
	knod_mov32(priv, meta, tmp0_lo, imm);
	knod_iset32(&imm, 0);
	knod_emit(priv, meta, v_cndmask_b32_e32, r0_lo, imm, tmp0_lo);

	knod_iset32(&imm, -1);
	knod_mov32(priv, meta, tmp0_hi, imm);
	knod_iset32(&imm, 0);
	knod_emit(priv, meta, v_cndmask_b32_e32, r0_hi, imm, tmp0_hi);
}

static void knod_bpf_load_size(struct knod_bpf_priv *priv,
			      struct knod_insn_meta *meta,
			      struct amdgcn_param64 *dst,
			      /* packet or stack */
			      struct amdgcn_param32 *cache,
			      int size, int off)
{
	struct amdgcn_param32 p32[2];

	knod_jit_dbg(" %d: off = %d off_4 = %d size = %d\n", meta->bpf_insn_idx,
		off, off%4, size);
	switch (size) {
	case sizeof(unsigned long):
		if ((off % 4) == 0) {
			knod_mov32(priv, meta, dst->lo, cache[off / 4]);
			knod_mov32(priv, meta, dst->hi,
				       cache[(off / 4) + 1]);
		} else if ((off % 4) == 1) {
			WARN_ON(1);
		} else if ((off % 4) == 2) {
			WARN_ON(1);
		} else {
			WARN_ON(1);
		}
		break;
	case sizeof(unsigned int):
		if ((off % 4) == 0) {
			knod_mov32(priv, meta, dst->lo, cache[off / 4]);
		} else if ((off % 4) == 1) {
			knod_iset32(&p32[0], 8);
			knod_lshrrev32(priv, meta, r32[0], p32[0],
					   cache[off / 4]);
			knod_iset32(&p32[0], 24);
			knod_lshlrev32(priv, meta, dst->lo, p32[0],
					   cache[(off / 4) + 1]);
			knod_or32(priv, meta, dst->lo, dst->lo, r32[0]);
		} else if ((off % 4) == 2) {
			knod_iset32(&p32[0], 16);
			knod_lshrrev32(priv, meta, r32[0], p32[0],
					   cache[off / 4]);
			knod_lshlrev32(priv, meta, dst->lo, p32[0],
					   cache[(off / 4) + 1]);
			knod_or32(priv, meta, dst->lo, dst->lo, r32[0]);
		} else {
			knod_iset32(&p32[0], 24);
			knod_lshrrev32(priv, meta, r32[0], p32[0],
					   cache[off / 4]);
			knod_iset32(&p32[0], 8);
			knod_lshlrev32(priv, meta, dst->lo, p32[0],
					   cache[(off / 4) + 1]);
			knod_or32(priv, meta, dst->lo, dst->lo, r32[0]);
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
			/* bpf_reg64[d].lo = (r64[0].hi << 8) | r64[0].lo. */
			knod_emit(priv, meta, v_lshl_or_b32, dst->lo,
				  r64[0].hi, p32[1], r64[0].lo);
		} else {
			if (!(off % 4))
				knod_iset32(&p32[0], 0);
			else if ((off % 4) == 1)
				knod_iset32(&p32[0], 8);
			else if ((off % 4) == 2)
				knod_iset32(&p32[0], 16);
			knod_iset32(&p32[1], 16);
			knod_bfe32(priv, meta, dst->lo, cache[off / 4],
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
		knod_bfe32(priv, meta, dst->lo, cache[off / 4], p32[0],
			       p32[1]);
		break;
	default:
		WARN_ON(1);
		break;
	}

	if (size != sizeof(unsigned long)) {
		knod_iset32(&p32[0], 0);
		knod_mov32(priv, meta, dst->hi, p32[0]);
	}
}

/*
 * GFX10 (RDNA2) quirk: global_load_{dword,dwordx2,dwordx4} silently
 * clear the low 2 bits of the effective address, forcing Dword
 * alignment. For PTR_TO_PACKET loads at a byte offset that is not
 * Dword-aligned, round the offset down to the nearest 4-byte boundary,
 * load enough contiguous dwords to cover the requested range, then use
 * v_alignbit_b32 to extract the byte-aligned result. For size < 4 a
 * final v_and_b32 masks the result to the correct width.
 *
 * Caller is responsible for zeroing dst.hi for size < 8; this helper
 * only writes dst.lo (and dst.hi when size == 8).
 *
 * Scratch: up to 4 contiguous VGPRs at v32..v35
 * (TMP_VREG5_LO..TMP_VREG6_HI).
 */
static void knod_bpf_emit_gfx10_unaligned_load(struct knod_bpf_priv *priv,
					      struct knod_insn_meta *meta,
					      int size,
					      struct amdgcn_param64 dst,
					      struct amdgcn_param32 src_lo,
					      int off)
{
	int off_a = off & ~3;
	int shift_bits = (off - off_a) * 8;
	int needed = DIV_ROUND_UP((off & 3) + size, 4);
	struct amdgcn_param32 tmp[4];
	struct amdgcn_param32 shift_imm, mask_imm;

	knod_vset32(&tmp[0], KNOD_AMDGPU_TMP_VREG5_LO);
	knod_vset32(&tmp[1], KNOD_AMDGPU_TMP_VREG5_HI);
	knod_vset32(&tmp[2], KNOD_AMDGPU_TMP_VREG6_LO);
	knod_vset32(&tmp[3], KNOD_AMDGPU_TMP_VREG6_HI);
	knod_iset32(&shift_imm, shift_bits);

	if (needed <= 1) {
		knod_emit(priv, meta, global_load_dword, tmp[0], src_lo,
			  off_a);
	} else if (needed == 2) {
		knod_emit(priv, meta, global_load_dwordx2, tmp[0], src_lo,
			  off_a);
	} else {
		/* needed == 3: no dwordx3, widen to dwordx4. */
		knod_emit(priv, meta, global_load_dwordx4, tmp[0], src_lo,
			  off_a);
	}
	knod_wait_vmcnt(priv, meta);

	if (size <= 4) {
		/* v_alignbit_b32 D, S0, S1, S2:
		 *   D = ({S0, S1} >> S2)[31:0]
		 * S0 is HIGH, S1 is LOW. tmp[0] holds
		 * bytes[off_a..+4) (memory-low) and tmp[1] holds
		 * bytes[off_a+4..+8) (memory-high), so
		 * src0=tmp[1], src1=tmp[0].
		 */
		if (shift_bits == 0)
			knod_mov32(priv, meta, dst.lo, tmp[0]);
		else
			knod_alignbit32(priv, meta, dst.lo,
					    tmp[1], tmp[0], shift_imm);

		if (size == 1) {
			knod_iset32(&mask_imm, 0xff);
			knod_and32(priv, meta, dst.lo, dst.lo,
				       mask_imm);
		} else if (size == 2) {
			knod_iset32(&mask_imm, 0xffff);
			knod_and32(priv, meta, dst.lo, dst.lo,
				       mask_imm);
		}
	} else {
		/* size == 8: two alignbits for low / high output dwords. */
		if (shift_bits == 0) {
			knod_mov32(priv, meta, dst.lo, tmp[0]);
			knod_mov32(priv, meta, dst.hi, tmp[1]);
		} else {
			knod_alignbit32(priv, meta, dst.lo,
					    tmp[1], tmp[0], shift_imm);
			knod_alignbit32(priv, meta, dst.hi,
					    tmp[2], tmp[1], shift_imm);
		}
	}
}

#define LABEL_NEXT	8
#define LABEL_OUT	9
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

static void knod_bpf_map_lookup(struct knod_bpf_priv *priv,
			       struct knod_insn_meta *meta,
			       int map_id)
{
	struct knod_bpf_map_obj *knod_map_obj_k, *knod_map_obj_g;
	int off, len, _len, idx, key_in_pkt, key_in_map;
	bool first_cmp;
	struct amdgcn_branch_fixup fixups[12] = {0,};
	struct amdgcn_label labels[10] = {0,};
	u32 stack_off = meta->kreg.stack_off;
	unsigned long bucket_gaddr;
	struct amdgcn_param32 p32;
	int fixup_idx = 0;

	knod_map_obj_k =
		(struct knod_bpf_map_obj *)knod_bpf_map_kaddr(priv, map_id);
	knod_map_obj_g =
		(struct knod_bpf_map_obj *)knod_bpf_map_gaddr(priv, map_id);
	bucket_gaddr = (unsigned long)knod_map_obj_g +
		       offsetof(struct knod_bpf_map_obj, bucket);

	/* TODO key is only supporting stack */
	knod_jit_dbg(" stack_off = %d map_id = %d\n", stack_off, map_id);
	if (!knod_map_obj_g || !knod_map_obj_k)
		WARN_ON(1);

	knod_bpf_load_size(priv, meta,
			       &r64[2],
			       &stack[0],
			       sizeof(unsigned int),
			       512 + stack_off);
	/* reg1 := bucket
	 * TODO bucket_gaddr is greater than X, it breaks gpu
	 */
	knod_iset64(&p64[0], bucket_gaddr);
	knod_mov64(priv, meta, r64[1], p64[0]);
	knod_iset64(&p64[1], 0);
	knod_mov32(priv, meta, r64[2].hi, p64[1].lo);

	knod_iset64(&p64[1], 0);
	knod_mov64(priv, meta, bpf_reg64[0], p64[1]);

	/* BPF_REG0 = 0
	 * TMP_REG1 = bucket_gaddr
	 * TMP_REG2 = key
	 */

	if (knod_map_obj_k->map_type == BPF_MAP_TYPE_ARRAY ||
	    knod_map_obj_k->map_type == BPF_MAP_TYPE_PERCPU_ARRAY) {
		/* if (key > knod_map_obj_k.max_entries)
		 * TODO integer
		 */
		knod_iset64(&p64[1], knod_map_obj_k->max_entries);
		knod_mov64(priv, meta, r64[3], p64[1]);
		knod_emit(priv, meta, v_cmp_ge_u64, r64[2], r64[3]);
		/* structurized CFG: save OOB lanes, narrow exec */
		knod_emit(priv, meta, s_and_b64, KNOD_AMDGPU_TMP_SREG3_LO,
			  AMDGCN_SREG_EXEC_LO, AMDGCN_SREG_VCC_LO);
		knod_emit(priv, meta, s_andn2_b64, AMDGCN_SREG_EXEC_LO,
			  AMDGCN_SREG_EXEC_LO, AMDGCN_SREG_VCC_LO);
			emit_s_cbranch_execz(priv->isa_version,
				     &meta->amdgpu_insn[meta->amdgpu_insns],
				     0); /* update required */
		knod_bpf_set_fixup(meta, &fixups[fixup_idx],
				   &labels[LABEL_OUT], meta->amdgpu_insns);
		debug_insn(priv->isa_version,
			   &meta->amdgpu_insn[meta->amdgpu_insns]);
		meta->amdgpu_insns++;
		fixup_idx++;
		/* PERCPU_ARRAY: bucket += workgroup_id_y * per_instance_size so
		 * each RX queue addresses its own instance and the atomic
		 * update after the lookup has no cross-CU contention.  Auto
		 * xgroups keeps PERCPU programs at one workgroup per queue, so
		 * the queue id (workgroup_id_y) is the instance index.
		 */
		if (knod_map_obj_k->map_type == BPF_MAP_TYPE_PERCPU_ARRAY) {
			/* r64[3] is scratch after the bounds check: .lo =
			 * workgroup_id_y, .hi = per_instance_size (too large
			 * for an inline constant, so stage both in VGPRs
			 * first).
			 */
			knod_sset32(&p32, KNOD_AMDGPU_WORKGROUP_ID_Y_SREG);
			knod_emit(priv, meta, v_mov_b32_e32, r64[3].lo, p32);
			knod_iset64(&p64[1],
				    knod_map_obj_k->meta.ameta
				    .per_instance_size);
			knod_mov32(priv, meta, r64[3].hi, p64[1].lo);
			emit_v_mad_u64_u32(priv->isa_version,
					&meta->amdgpu_insn[meta->amdgpu_insns],
					   r64[1],
					   sr64[0].lo,
					   r64[3].hi, /* per_instance_size */
					   r64[3].lo, /* workgroup_id_y */
					   r64[1]); /* bucket */
			debug_insn(priv->isa_version,
				   &meta->amdgpu_insn[meta->amdgpu_insns]);
			meta->amdgpu_insns++;
		}
		/* elem_id = &bucket[key]; */
		knod_iset64(&p64[1], knod_map_obj_k->value_size);
		emit_v_mad_u64_u32(priv->isa_version,
				   &meta->amdgpu_insn[meta->amdgpu_insns],
				   bpf_reg64[0],
				   sr64[0].lo,
				   p64[1].lo, /* value_size */
				   r64[2].lo, /* key */
				   r64[1]); /* bucket */
		debug_insn(priv->isa_version,
			   &meta->amdgpu_insn[meta->amdgpu_insns]);
		meta->amdgpu_insns++;
		/* structurized CFG: restore OOB lanes */
		knod_bpf_set_label(meta, &labels[LABEL_OUT],
				   meta->amdgpu_insns);
		knod_emit(priv, meta, s_or_b64, AMDGCN_SREG_EXEC_LO,
			  AMDGCN_SREG_EXEC_LO, KNOD_AMDGPU_TMP_SREG3_LO);
		for (idx = 0; idx < fixup_idx; idx++)
			knod_bpf_fixup_branch(priv, &fixups[idx]);
	} else if (knod_map_obj_k->map_type == BPF_MAP_TYPE_HASH) {
		key_in_pkt = KEY_IN_PKT_64;
		len = knod_map_obj_k->key_size;
		off = stack_off;

		/* TMP_VREGs(vgpr-pair)
		 * |0|1|2|3|4|5|6|7|8|9|10|11|12|13|14|15|16|17|18|
		 * | | | |K|K|K|K|K|K|K|K |K |K |K |K |K |K |K |K |
		 */
		/* TODO key would be stack or packet */
		while (len) {
			if (len >= sizeof(unsigned long))
				_len = sizeof(unsigned long);
			else
				_len = len;
			knod_bpf_load_size(priv, meta,
					       &r64[key_in_pkt],
					       &stack[0],
					       _len,
					       512 + off);
			key_in_pkt++;
			len -= _len;
			off += _len;
		}

		knod_jhash(priv, meta,
			       2,
			       knod_map_obj_k->key_size,
			       knod_map_obj_k->meta.hmeta.hashrnd);
		/* clear hi register of r64[2] because hash is 32bit */
		knod_iset64(&p64[0], 0);
		knod_mov32(priv, meta, r64[2].hi, p64[0].lo);

		/* hash = hash & (n_buckets - 1) before indexing the bucket
		 * array -- jhash returns the full 32-bit hash and the update
		 * and delete emitters mask it too; without this
		 * bucket_gaddr[hash] runs off the end of the bucket array.
		 */
		knod_iset32(&p64[0].lo,
			    knod_map_obj_k->meta.hmeta.n_buckets - 1);
		knod_and32(priv, meta, r64[2].lo, p64[0].lo, r64[2].lo);

		/* elem_id = bucket_gaddr[hash]; */
		knod_iset64(&p64[1], sizeof(int));
		emit_v_mad_u64_u32(priv->isa_version,
				   &meta->amdgpu_insn[meta->amdgpu_insns],
				   r64[2],
				   sr64[0].lo,
				   p64[1].lo, /* sizeof(int) */
				   r64[2].lo, /* hash */
				   r64[1]); /* bucket */
		debug_insn(priv->isa_version,
			   &meta->amdgpu_insn[meta->amdgpu_insns]);
		meta->amdgpu_insns++;

		/* bpf_reg64[0] = 0 (default return for not-found lanes) */
		knod_iset64(&p64[0], 0);
		knod_mov64(priv, meta, bpf_reg64[0], p64[0]);

		/* structurized CFG: save initial exec for restoring at end */
		knod_emit(priv, meta, s_mov_b64, KNOD_AMDGPU_TMP_SREG3_LO,
			  AMDGCN_SREG_EXEC_LO);

		knod_bpf_set_label(meta, &labels[LABEL_NEXT],
				   meta->amdgpu_insns);
		/* load elem_id from elem structure */
		knod_emit(priv, meta, global_load_dword, r64[2].lo,
			  r64[2].lo, 0);
		knod_wait_vmcnt(priv, meta);

		/* mask out DELETED bit from next field */
		knod_iset32(&p32, KNOD_BPF_HASH_NEXT_MASK);
		knod_emit(priv, meta, v_and_b32_e32, r64[2].lo, p32,
			  r64[2].lo);

		/* if (r64[2].lo == KNOD_BPF_HASH_NEXT_END)
		 *	goto out;
		 * VOPC cannot encode literal constants — move to VGPR first.
		 * NEXT_MASK == NEXT_END (0x7FFFFFFF), reuse p32 from v_and
		 * above.
		 */
		knod_emit(priv, meta, v_mov_b32_e32, r64[0].hi, p32);
		knod_emit(priv, meta, v_cmp_eq_u32, r64[0].hi, r64[2].lo);
		/* structurized CFG: remove end-of-chain lanes */
		knod_emit(priv, meta, s_andn2_b64, AMDGCN_SREG_EXEC_LO,
			  AMDGCN_SREG_EXEC_LO, AMDGCN_SREG_VCC_LO);

		emit_s_cbranch_execz(priv->isa_version,
				     &meta->amdgpu_insn[meta->amdgpu_insns],
				     0); /* update required */
		knod_bpf_set_fixup(meta, &fixups[fixup_idx],
				   &labels[LABEL_OUT], meta->amdgpu_insns);
		debug_insn(priv->isa_version,
			   &meta->amdgpu_insn[meta->amdgpu_insns]);
		meta->amdgpu_insns++;
		fixup_idx++;

		knod_iset64(&p64[0],
			    (unsigned long)knod_map_obj_k->meta.hmeta.elems);
		knod_mov64(priv, meta, r64[1], p64[0]);
		knod_iset64(&p64[0], knod_map_obj_k->meta.hmeta.elem_size);
		knod_mov64(priv, meta, r64[0], p64[0]);

		key_in_map = KEY_IN_MAP_32;
		len = knod_map_obj_k->key_size;
		off = offsetof(struct knod_bpf_hash_elem_obj, kv); /* TODO */

		/* elem = &elems[elem_id]; */
		emit_v_mad_u64_u32(priv->isa_version,
				   &meta->amdgpu_insn[meta->amdgpu_insns],
				   r64[2], /* elem */
				   sr64[0].lo,
				   r64[0].lo, /* elem_size */
				   r64[2].lo, /* elem_id */
				   r64[1]); /* elem_gaddr */
		debug_insn(priv->isa_version,
			   &meta->amdgpu_insn[meta->amdgpu_insns]);
		meta->amdgpu_insns++;

		/* load elem.next for DELETED check (parallel with key loads) */
		knod_emit(priv, meta, global_load_dword, r64[0].hi,
			  r64[2].lo, 0);
		while (len >= 16) {
			knod_emit(priv, meta, global_load_dwordx4,
				  r32[key_in_map],
				  r64[2].lo, /* elem ptr */ off);
			off += 16;
			len -= 16;
			key_in_map += 4;
		}

		if (len >= 8) {
			knod_emit(priv, meta, global_load_dwordx2,
				  r32[key_in_map],
				  /* elem_id */ r64[2].lo, /* elem ptr */ off);
			off += 8;
			len -= 8;
			key_in_map += 2;
		}

		if (len >= 4) {
			knod_emit(priv, meta, global_load_dword,
				  r32[key_in_map],
				  /* elem_id */ r64[2].lo, /* elem ptr */ off);
			off += 4;
			len -= 4;
			key_in_map += 1;
		}

		/* map key padding was inited to zero, no AND is required */
		if (len) {
			knod_emit(priv, meta, global_load_dword,
				  r32[key_in_map],
				  /* elem_id */ r64[2].lo, /* elem ptr */ off);
		}

		knod_wait_vmcnt(priv, meta);

		/* structurized CFG: accumulate key match into TMP_SREG4
		 * instead of early-exit branching per key part
		 */
		key_in_map = KEY_IN_MAP_32;
		key_in_pkt = KEY_IN_PKT_32;
		len = knod_map_obj_k->key_size;
		first_cmp = true;

		while (len >= 8) {
			knod_emit(priv, meta, v_cmp_eq_u64, r32[key_in_map],
				  r32[key_in_pkt]);

			if (first_cmp) {
				knod_emit(priv, meta, s_and_b64,
					  KNOD_AMDGPU_TMP_SREG4_LO,
					  AMDGCN_SREG_EXEC_LO,
					  AMDGCN_SREG_VCC_LO);
				first_cmp = false;
			} else {
				knod_emit(priv, meta, s_and_b64,
					  KNOD_AMDGPU_TMP_SREG4_LO,
					  KNOD_AMDGPU_TMP_SREG4_LO,
					  AMDGCN_SREG_VCC_LO);
			}

			key_in_map += 2;
			key_in_pkt += 2;
			len -= 8;
		}

		if (len >= 4) {
			knod_emit(priv, meta, v_cmp_eq_u32, r32[key_in_map],
				  r32[key_in_pkt]);

			if (first_cmp) {
				knod_emit(priv, meta, s_and_b64,
					  KNOD_AMDGPU_TMP_SREG4_LO,
					  AMDGCN_SREG_EXEC_LO,
					  AMDGCN_SREG_VCC_LO);
				first_cmp = false;
			} else {
				knod_emit(priv, meta, s_and_b64,
					  KNOD_AMDGPU_TMP_SREG4_LO,
					  KNOD_AMDGPU_TMP_SREG4_LO,
					  AMDGCN_SREG_VCC_LO);
			}

			key_in_map += 1;
			key_in_pkt += 1;
			len -= 4;
		}

		if (len) {
			knod_emit(priv, meta, v_cmp_eq_u32, r32[key_in_map],
				  r32[key_in_pkt]);

			if (first_cmp) {
				knod_emit(priv, meta, s_and_b64,
					  KNOD_AMDGPU_TMP_SREG4_LO,
					  AMDGCN_SREG_EXEC_LO,
					  AMDGCN_SREG_VCC_LO);
				first_cmp = false;
			} else {
				knod_emit(priv, meta, s_and_b64,
					  KNOD_AMDGPU_TMP_SREG4_LO,
					  KNOD_AMDGPU_TMP_SREG4_LO,
					  AMDGCN_SREG_VCC_LO);
			}
		}

		/* DELETED check: remove deleted lanes from match result.
		 * r64[0].hi = elem.next (loaded in parallel with key).
		 * Deleted elems have bit 31 set — exclude them from SREG4.
		 */
		knod_iset32(&p32, KNOD_BPF_HASH_NEXT_DELETED);
		knod_emit(priv, meta, v_and_b32_e32, r64[0].hi, p32,
			  r64[0].hi);
		knod_iset32(&p32, 0);
		knod_emit(priv, meta, v_cmp_eq_u32, p32, r64[0].hi);
		knod_emit(priv, meta, s_and_b64, KNOD_AMDGPU_TMP_SREG4_LO,
			  KNOD_AMDGPU_TMP_SREG4_LO, AMDGCN_SREG_VCC_LO);

		/* TMP_SREG4 = lanes where key matched AND not deleted.
		 * Save current exec, narrow to matched lanes for value
		 * computation.
		 */
		knod_emit(priv, meta, s_mov_b64, KNOD_AMDGPU_TMP_SREG5_LO,
			  AMDGCN_SREG_EXEC_LO);
		knod_emit(priv, meta, s_and_b64, AMDGCN_SREG_EXEC_LO,
			  AMDGCN_SREG_EXEC_LO, KNOD_AMDGPU_TMP_SREG4_LO);

		/* bpf_reg64[0] = value address (only for matched lanes) */
		knod_iset64(&p64[1],
				offsetof(struct knod_bpf_hash_elem_obj, kv) +
					 knod_map_obj_k->key_size);
		knod_add64(priv, meta, bpf_reg64[0], p64[1], r64[2]);

		/* set exec to unmatched lanes for next loop iteration */
		knod_emit(priv, meta, s_andn2_b64, AMDGCN_SREG_EXEC_LO,
			  KNOD_AMDGPU_TMP_SREG5_LO, KNOD_AMDGPU_TMP_SREG4_LO);
			/* loop back if any unmatched lanes remain */
		emit_s_cbranch_execnz(priv->isa_version,
				      &meta->amdgpu_insn[meta->amdgpu_insns],
				      0); /* update required */
		knod_bpf_set_fixup(meta, &fixups[fixup_idx],
				   &labels[LABEL_NEXT], meta->amdgpu_insns);
		debug_insn(priv->isa_version,
			   &meta->amdgpu_insn[meta->amdgpu_insns]);
		meta->amdgpu_insns++;
		fixup_idx++;
		/* structurized CFG: restore all original lanes */
		knod_bpf_set_label(meta, &labels[LABEL_OUT],
				   meta->amdgpu_insns);
		knod_emit(priv, meta, s_or_b64, AMDGCN_SREG_EXEC_LO,
			  AMDGCN_SREG_EXEC_LO, KNOD_AMDGPU_TMP_SREG3_LO);
		for (idx = 0; idx < fixup_idx; idx++)
			knod_bpf_fixup_branch(priv, &fixups[idx]);

	} else {
		WARN_ON(1);
	}
}

static void knod_bpf_map_update_array(struct knod_bpf_priv *priv,
				     struct knod_insn_meta *meta,
				     int map_id)
{
	struct knod_bpf_map_obj *knod_map_obj_k, *knod_map_obj_g;
	struct amdgcn_branch_fixup fixups[4] = {0,};
	u32 key_stack_off = meta->kreg.stack_off;
	u32 val_stack_off = meta->vreg.stack_off;
	struct amdgcn_label labels[10] = {0,};
	int idx, val_off, val_len;
	unsigned long bucket_gaddr;
	int fixup_idx = 0;

	knod_map_obj_k =
		(struct knod_bpf_map_obj *)knod_bpf_map_kaddr(priv, map_id);
	knod_map_obj_g =
		(struct knod_bpf_map_obj *)knod_bpf_map_gaddr(priv, map_id);
	bucket_gaddr = (unsigned long)knod_map_obj_g +
		       offsetof(struct knod_bpf_map_obj, bucket);

	if (!knod_map_obj_g || !knod_map_obj_k)
		WARN_ON(1);

	/* load key from stack → r64[2] */
	knod_bpf_load_size(priv, meta,
			       &r64[2],
			       &stack[0],
			       sizeof(unsigned int),
			       512 + key_stack_off);

	/* r64[1] = bucket_gaddr */
	knod_iset64(&p64[0], bucket_gaddr);
	knod_mov64(priv, meta, r64[1], p64[0]);

	/* clear r64[2].hi (key is 32-bit) */
	knod_iset64(&p64[1], 0);
	knod_mov32(priv, meta, r64[2].hi, p64[1].lo);

	/* bpf_reg64[0] = 0 (return value) */
	knod_mov64(priv, meta, bpf_reg64[0], p64[1]);

	/* bounds check: if (key >= max_entries) → skip */
	knod_iset64(&p64[1], knod_map_obj_k->max_entries);
	knod_mov64(priv, meta, r64[3], p64[1]);
	knod_emit(priv, meta, v_cmp_ge_u64, r64[2], r64[3]);

	/* structurized CFG: save OOB lanes, narrow exec */
	knod_emit(priv, meta, s_and_b64, KNOD_AMDGPU_TMP_SREG3_LO,
		  AMDGCN_SREG_EXEC_LO, AMDGCN_SREG_VCC_LO);
	knod_emit(priv, meta, s_andn2_b64, AMDGCN_SREG_EXEC_LO,
		  AMDGCN_SREG_EXEC_LO, AMDGCN_SREG_VCC_LO);
	emit_s_cbranch_execz(priv->isa_version,
			     &meta->amdgpu_insn[meta->amdgpu_insns],
			     0);
	knod_bpf_set_fixup(meta, &fixups[fixup_idx],
			   &labels[LABEL_OUT], meta->amdgpu_insns);
	debug_insn(priv->isa_version, &meta->amdgpu_insn[meta->amdgpu_insns]);
	meta->amdgpu_insns++;
	fixup_idx++;

	/* dest = bucket_gaddr + key * value_size → r64[0] */
	knod_iset64(&p64[1], knod_map_obj_k->value_size);
	knod_emit(priv, meta, v_mad_u64_u32, r64[0], sr64[0].lo,
		  p64[1].lo, r64[2].lo, r64[1]);

	/* load value from stack and store to dest */
	val_off = 0;
	val_len = knod_map_obj_k->value_size;

	while (val_len >= 16) {
		knod_bpf_load_size(priv, meta,
				       &r64[3],
				       &stack[0],
				       sizeof(unsigned long),
				       512 + val_stack_off + val_off);
		knod_bpf_load_size(priv, meta,
				       &r64[4],
				       &stack[0],
				       sizeof(unsigned long),
				       512 + val_stack_off + val_off + 8);
		knod_emit(priv, meta, global_store_dwordx4, r64[3].lo,
			  r64[0].lo, val_off);
		val_off += 16;
		val_len -= 16;
	}

	if (val_len >= 8) {
		knod_bpf_load_size(priv, meta,
				       &r64[3],
				       &stack[0],
				       sizeof(unsigned long),
				       512 + val_stack_off + val_off);
		knod_emit(priv, meta, global_store_dwordx2, r64[3].lo,
			  r64[0].lo, val_off);
		val_off += 8;
		val_len -= 8;
	}

	if (val_len >= 4) {
		knod_bpf_load_size(priv, meta,
				       &r64[3],
				       &stack[0],
				       sizeof(unsigned int),
				       512 + val_stack_off + val_off);
		knod_emit(priv, meta, global_store_dword, r64[3].lo,
			  r64[0].lo, val_off);
		val_off += 4;
		val_len -= 4;
	}

	if (val_len >= 2) {
		knod_bpf_load_size(priv, meta,
				       &r64[3],
				       &stack[0],
				       sizeof(unsigned short),
				       512 + val_stack_off + val_off);
		knod_emit(priv, meta, global_store_short, r64[3].lo,
			  r64[0].lo, val_off);
		val_off += 2;
		val_len -= 2;
	}

	if (val_len >= 1) {
		knod_bpf_load_size(priv, meta,
				       &r64[3],
				       &stack[0],
				       sizeof(unsigned char),
				       512 + val_stack_off + val_off);
		knod_emit(priv, meta, global_store_byte, r64[3].lo,
			  r64[0].lo, val_off);
	}

	/* structurized CFG: restore OOB lanes */
	knod_bpf_set_label(meta, &labels[LABEL_OUT], meta->amdgpu_insns);
	knod_emit(priv, meta, s_or_b64, AMDGCN_SREG_EXEC_LO,
		  AMDGCN_SREG_EXEC_LO, KNOD_AMDGPU_TMP_SREG3_LO);

	for (idx = 0; idx < fixup_idx; idx++)
		knod_bpf_fixup_branch(priv, &fixups[idx]);
}

static void knod_bpf_map_update_hash(struct knod_bpf_priv *priv,
				     struct knod_insn_meta *meta,
				     int map_id)
{
#define LABEL_BUCKET_LOOP	0
#define LABEL_LOCK_RETRY	1
#define LABEL_INSERT_LANE	2
#define LABEL_CHAIN_NEXT	3
#define LABEL_ALLOC_INSERT	4
#define LABEL_LANE_DONE		5
#define LABEL_UNLOCK		6
	struct knod_bpf_map_obj *knod_map_obj_k, *knod_map_obj_g;
	struct amdgcn_param32 s_bucket_lo, v_tmp, v_zero, v_one;
	int off, len, _len, idx, key_in_pkt, key_in_map;
	struct amdgcn_param32 s_exec_lo, s_exec_hi, s_elem_id;
	struct amdgcn_branch_fixup fixups[12] = {0,};
	u32 key_stack_off = meta->kreg.stack_off;
	u32 val_stack_off = meta->vreg.stack_off;
	unsigned long queue_gaddr, elems_gaddr;
	unsigned long bucket_gaddr, cur_gaddr;
	struct amdgcn_label labels[12] = {0,};
	struct amdgcn_param32 v_minus_one;
	struct amdgcn_param64 sr64_carry;
	struct amdgcn_param32 p32;
	unsigned long lock_offset;
	unsigned int elem_size;
	int val_off, val_len;
	int fixup_idx = 0;
	bool first_cmp;
	int koff, voff;

	knod_map_obj_k =
		(struct knod_bpf_map_obj *)knod_bpf_map_kaddr(priv, map_id);
	knod_map_obj_g =
		(struct knod_bpf_map_obj *)knod_bpf_map_gaddr(priv, map_id);
	bucket_gaddr = (unsigned long)knod_map_obj_g +
		       offsetof(struct knod_bpf_map_obj, bucket);
	cur_gaddr = (unsigned long)knod_map_obj_g +
		    offsetof(struct knod_bpf_map_obj, meta.hmeta.cur);
	queue_gaddr = (unsigned long)knod_map_obj_k->meta.hmeta.q;
	elems_gaddr = (unsigned long)knod_map_obj_k->meta.hmeta.elems;
	elem_size = knod_map_obj_k->meta.hmeta.elem_size;

	if (!knod_map_obj_g || !knod_map_obj_k)
		WARN_ON(1);

	/* ======== Phase 1: Setup ======== */

	/* Load key from stack → r64[3..9] (KEY_IN_PKT) */
	key_in_pkt = KEY_IN_PKT_64;
	len = knod_map_obj_k->key_size;
	off = key_stack_off;
	while (len) {
		if (len >= sizeof(unsigned long))
			_len = sizeof(unsigned long);
		else
			_len = len;
		knod_bpf_load_size(priv, meta,
				       &r64[key_in_pkt],
				       &stack[0],
				       _len,
				       512 + off);
		key_in_pkt++;
		len -= _len;
		off += _len;
	}

	/* jhash → r64[2].lo = hash */
	knod_jhash(priv, meta,
		       2,
		       knod_map_obj_k->key_size,
		       knod_map_obj_k->meta.hmeta.hashrnd);
	knod_iset64(&p64[0], 0);
	knod_mov32(priv, meta, r64[2].hi, p64[0].lo);

	/* hash = hash & (n_buckets - 1) */
	knod_iset32(&p64[0].lo,
				 knod_map_obj_k->meta.hmeta.n_buckets - 1);
	knod_and32(priv, meta, r64[2].lo, p64[0].lo, r64[2].lo);

	/* r64[1] = bucket_gaddr */
	knod_iset64(&p64[0], bucket_gaddr);
	knod_mov64(priv, meta, r64[1], p64[0]);

	/* bucket_addr = bucket_gaddr + hash * sizeof(int) → r64[2] */
	knod_iset64(&p64[1], sizeof(int));
	knod_emit(priv, meta, v_mad_u64_u32, r64[2], sr64[0].lo,
		  p64[1].lo, r64[2].lo, r64[1]);

	/* Save bucket_addr to r64[15] for CAS insert */
	knod_mov64(priv, meta, r64[15], r64[2]);

	/* SREG3 = initial exec */
	knod_emit(priv, meta, s_mov_b64, KNOD_AMDGPU_TMP_SREG3_LO,
		  AMDGCN_SREG_EXEC_LO);

	/* ======== Phase 2: Sequential per-lane processing ======== */

	/* SREG5 = exec (all lanes to process, for BUCKET_LOOP) */
	knod_emit(priv, meta, s_mov_b64, KNOD_AMDGPU_TMP_SREG5_LO,
		  AMDGCN_SREG_EXEC_LO);

	/* ---- BUCKET_LOOP: process one unique bucket per iteration ---- */
	knod_bpf_set_label(meta, &labels[LABEL_BUCKET_LOOP],
			   meta->amdgpu_insns);

	lock_offset =
		(unsigned long)knod_map_obj_k->meta.hmeta.n_buckets *
		sizeof(unsigned int);

	knod_sset32(&s_bucket_lo,
				 KNOD_AMDGPU_TMP_SREG1_HI);
	knod_vset32(&v_tmp, KNOD_AMDGPU_TMP_VREG0_HI);
	knod_iset32(&v_zero, 0);
	knod_iset32(&v_one, 1);
	knod_sset32(&s_exec_lo, AMDGCN_SREG_EXEC_LO);
	knod_sset32(&s_exec_hi,
				 AMDGCN_SREG_EXEC_LO + 1);
	knod_sset32(&s_elem_id,
				 KNOD_AMDGPU_TMP_SREG1_LO);
	knod_sset64(&sr64_carry,
				 KNOD_AMDGPU_TMP_SREG1_LO);

	/* Pick first active lane's bucket addr */
	knod_emit(priv, meta, v_readfirstlane_b32, KNOD_AMDGPU_TMP_SREG1_HI,
		  r64[15].lo.v);

	/* vcc = lanes with same bucket */
	knod_emit(priv, meta, v_cmp_eq_u32, s_bucket_lo, r64[15].lo);

	/* SREG5 = remaining lanes; exec = same-bucket lanes */
	knod_emit(priv, meta, s_and_saveexec_b64, KNOD_AMDGPU_TMP_SREG5_LO,
		  AMDGCN_SREG_VCC_LO);

	/* SREG0 = same-bucket lanes */
	knod_emit(priv, meta, s_mov_b64, KNOD_AMDGPU_TMP_SREG0_LO,
		  AMDGCN_SREG_EXEC_LO);

	/* ---- Lock acquire ---- */
	/* r64[10] = r64[15] + lock_offset */
	knod_iset64(&p64[0], lock_offset);
	knod_add64(priv, meta, r64[10], p64[0], r64[15]);

	/* r64[11].lo = 1 (swap data) */
	knod_emit(priv, meta, v_mov_b32_e32, r64[11].lo, v_one);

	/* First-lane isolation via mbcnt */
	knod_emit(priv, meta, v_mbcnt_lo_u32_b32, v_tmp, s_exec_lo,
		  v_zero);
	knod_emit(priv, meta, v_mbcnt_hi_u32_b32, v_tmp, s_exec_hi, v_tmp);
	knod_emit(priv, meta, v_cmp_eq_u32, v_zero, v_tmp);
	knod_emit(priv, meta, s_and_b64, AMDGCN_SREG_EXEC_LO,
		  AMDGCN_SREG_EXEC_LO, AMDGCN_SREG_VCC_LO);

	/* LOCK_RETRY: spin until lock acquired */
	knod_bpf_set_label(meta, &labels[LABEL_LOCK_RETRY], meta->amdgpu_insns);

	knod_emit(priv, meta, global_atomic_swap, r64[11].hi, r64[10].lo,
		  r64[11].lo, 0, 1);
	knod_wait_vmcnt(priv, meta);

	meta->amdgpu_insn[meta->amdgpu_insns].size =
		emit_gfx10_v_cmp_ne_u32(
			&meta->amdgpu_insn[meta->amdgpu_insns].gfx10,
			v_zero, r64[11].hi);
	meta->amdgpu_insn[meta->amdgpu_insns].type = AMDGCN_INSN_TYPE_VOPC;
	debug_insn(priv->isa_version, &meta->amdgpu_insn[meta->amdgpu_insns]);
	meta->amdgpu_insns++;

	emit_s_cbranch_vccnz(priv->isa_version,
			     &meta->amdgpu_insn[meta->amdgpu_insns],
			     0);
	knod_bpf_set_fixup(meta, &fixups[fixup_idx],
			   &labels[LABEL_LOCK_RETRY], meta->amdgpu_insns);
	debug_insn(priv->isa_version, &meta->amdgpu_insn[meta->amdgpu_insns]);
	meta->amdgpu_insns++;
	fixup_idx++;

	/* Lock acquired — restore same-bucket lanes */
	knod_emit(priv, meta, s_mov_b64, AMDGCN_SREG_EXEC_LO,
		  KNOD_AMDGPU_TMP_SREG0_LO);

	/* ---- INSERT_LANE: process one lane at a time ---- */
	knod_bpf_set_label(meta, &labels[LABEL_INSERT_LANE],
			   meta->amdgpu_insns);

	/* SREG4 = exec (remaining same-bucket lanes) */
	knod_emit(priv, meta, s_mov_b64, KNOD_AMDGPU_TMP_SREG4_LO,
		  AMDGCN_SREG_EXEC_LO);

	/* Pick first active lane via mbcnt */
	knod_emit(priv, meta, v_mbcnt_lo_u32_b32, v_tmp, s_exec_lo,
		  v_zero);
	knod_emit(priv, meta, v_mbcnt_hi_u32_b32, v_tmp, s_exec_hi, v_tmp);
	knod_emit(priv, meta, v_cmp_eq_u32, v_zero, v_tmp);
	knod_emit(priv, meta, s_and_b64, AMDGCN_SREG_EXEC_LO,
		  AMDGCN_SREG_EXEC_LO, AMDGCN_SREG_VCC_LO);

	/* SREG2 = exec (single-lane mask) */
	knod_emit(priv, meta, s_mov_b64, KNOD_AMDGPU_TMP_SREG2_LO,
		  AMDGCN_SREG_EXEC_LO);

	/* r64[2] = r64[15] (bucket_addr for chain walk start) */
	knod_mov64(priv, meta, r64[2], r64[15]);

	/* ---- CHAIN_NEXT: walk chain ---- */
	knod_bpf_set_label(meta, &labels[LABEL_CHAIN_NEXT], meta->amdgpu_insns);

	knod_emit(priv, meta, global_load_dword, r64[0].lo, r64[2].lo, 0);
	knod_wait_vmcnt(priv, meta);

	/* Mask out DELETED bit */
	knod_iset32(&p32, KNOD_BPF_HASH_NEXT_MASK);
	knod_emit(priv, meta, v_and_b32_e32, r64[0].lo, p32, r64[0].lo);

	/* End-of-chain check (VOPC literal workaround) */
	knod_emit(priv, meta, v_mov_b32_e32, r64[0].hi, p32);
	knod_emit(priv, meta, v_cmp_eq_u32, r64[0].hi, r64[0].lo);
	knod_emit(priv, meta, s_andn2_b64, AMDGCN_SREG_EXEC_LO,
		  AMDGCN_SREG_EXEC_LO, AMDGCN_SREG_VCC_LO);
	emit_s_cbranch_execz(priv->isa_version,
			     &meta->amdgpu_insn[meta->amdgpu_insns],
			     0);
	knod_bpf_set_fixup(meta, &fixups[fixup_idx],
			   &labels[LABEL_ALLOC_INSERT], meta->amdgpu_insns);
	debug_insn(priv->isa_version, &meta->amdgpu_insn[meta->amdgpu_insns]);
	meta->amdgpu_insns++;
	fixup_idx++;

	/* elem_addr = elems + elem_id * elem_size → r64[2] */
	knod_iset64(&p64[0], elems_gaddr);
	knod_mov64(priv, meta, r64[1], p64[0]);
	knod_iset64(&p64[0], elem_size);
	knod_mov32(priv, meta, r64[10].lo, p64[0].lo);
	knod_emit(priv, meta, v_mad_u64_u32, r64[2], sr64_carry.lo,
		  r64[10].lo, r64[0].lo, r64[1]);

	/* Load elem.next for DELETED check */
	knod_emit(priv, meta, global_load_dword, r64[0].hi, r64[2].lo, 0);

	/* Load key from map element → KEY_IN_MAP */
	key_in_map = KEY_IN_MAP_32;
	len = knod_map_obj_k->key_size;
	off = offsetof(struct knod_bpf_hash_elem_obj, kv);

	while (len >= 16) {
		knod_emit(priv, meta, global_load_dwordx4, r32[key_in_map],
			  r64[2].lo, off);
		off += 16;
		len -= 16;
		key_in_map += 4;
	}

	if (len >= 8) {
		knod_emit(priv, meta, global_load_dwordx2, r32[key_in_map],
			  r64[2].lo, off);
		off += 8;
		len -= 8;
		key_in_map += 2;
	}

	if (len >= 4) {
		knod_emit(priv, meta, global_load_dword, r32[key_in_map],
			  r64[2].lo, off);
		off += 4;
		len -= 4;
		key_in_map += 1;
	}

	if (len) {
		knod_emit(priv, meta, global_load_dword, r32[key_in_map],
			  r64[2].lo, off);
	}

	knod_wait_vmcnt(priv, meta);

	/* Key comparison → SREG1 */
	key_in_map = KEY_IN_MAP_32;
	key_in_pkt = KEY_IN_PKT_32;
	len = knod_map_obj_k->key_size;
	first_cmp = true;

	while (len >= 8) {
		knod_emit(priv, meta, v_cmp_eq_u64, r32[key_in_map],
			  r32[key_in_pkt]);

		if (first_cmp) {
			emit_s_and_b64(priv->isa_version,
				       &meta->amdgpu_insn[meta->amdgpu_insns],
				       KNOD_AMDGPU_TMP_SREG1_LO,
				       AMDGCN_SREG_EXEC_LO,
				       AMDGCN_SREG_VCC_LO);
			first_cmp = false;
		} else {
			emit_s_and_b64(priv->isa_version,
				       &meta->amdgpu_insn[meta->amdgpu_insns],
				       KNOD_AMDGPU_TMP_SREG1_LO,
				       KNOD_AMDGPU_TMP_SREG1_LO,
				       AMDGCN_SREG_VCC_LO);
		}
		debug_insn(priv->isa_version,
			   &meta->amdgpu_insn[meta->amdgpu_insns]);
		meta->amdgpu_insns++;

		key_in_map += 2;
		key_in_pkt += 2;
		len -= 8;
	}

	if (len >= 4) {
		knod_emit(priv, meta, v_cmp_eq_u32, r32[key_in_map],
			  r32[key_in_pkt]);

		if (first_cmp) {
			emit_s_and_b64(priv->isa_version,
				       &meta->amdgpu_insn[meta->amdgpu_insns],
				       KNOD_AMDGPU_TMP_SREG1_LO,
				       AMDGCN_SREG_EXEC_LO,
				       AMDGCN_SREG_VCC_LO);
			first_cmp = false;
		} else {
			emit_s_and_b64(priv->isa_version,
				       &meta->amdgpu_insn[meta->amdgpu_insns],
				       KNOD_AMDGPU_TMP_SREG1_LO,
				       KNOD_AMDGPU_TMP_SREG1_LO,
				       AMDGCN_SREG_VCC_LO);
		}
		debug_insn(priv->isa_version,
			   &meta->amdgpu_insn[meta->amdgpu_insns]);
		meta->amdgpu_insns++;

		key_in_map += 1;
		key_in_pkt += 1;
		len -= 4;
	}

	if (len) {
		knod_emit(priv, meta, v_cmp_eq_u32, r32[key_in_map],
			  r32[key_in_pkt]);

		if (first_cmp) {
			emit_s_and_b64(priv->isa_version,
				       &meta->amdgpu_insn[meta->amdgpu_insns],
				       KNOD_AMDGPU_TMP_SREG1_LO,
				       AMDGCN_SREG_EXEC_LO,
				       AMDGCN_SREG_VCC_LO);
			first_cmp = false;
		} else {
			emit_s_and_b64(priv->isa_version,
				       &meta->amdgpu_insn[meta->amdgpu_insns],
				       KNOD_AMDGPU_TMP_SREG1_LO,
				       KNOD_AMDGPU_TMP_SREG1_LO,
				       AMDGCN_SREG_VCC_LO);
		}
		debug_insn(priv->isa_version,
			   &meta->amdgpu_insn[meta->amdgpu_insns]);
		meta->amdgpu_insns++;
	}

	/* DELETED check: SREG1 &= not_deleted */
	knod_iset32(&p32,
				 KNOD_BPF_HASH_NEXT_DELETED);
	knod_emit(priv, meta, v_and_b32_e32, r64[0].hi, p32, r64[0].hi);
	knod_iset32(&p32, 0);
	knod_emit(priv, meta, v_cmp_eq_u32, p32, r64[0].hi);
	knod_emit(priv, meta, s_and_b64, KNOD_AMDGPU_TMP_SREG1_LO,
		  KNOD_AMDGPU_TMP_SREG1_LO, AMDGCN_SREG_VCC_LO);

	/* Narrow exec to matched lane */
	knod_emit(priv, meta, s_and_b64, AMDGCN_SREG_EXEC_LO,
		  AMDGCN_SREG_EXEC_LO, KNOD_AMDGPU_TMP_SREG1_LO);

	/* Value overwrite for matched lane (exec-masked, skipped if no
	 * match)
	 */
	knod_iset64(&p64[1],
				 offsetof(struct knod_bpf_hash_elem_obj,
					  kv) +
				 knod_map_obj_k->key_size);
	knod_add64(priv, meta, r64[0], p64[1], r64[2]);

	val_off = 0;
	val_len = knod_map_obj_k->value_size;

	while (val_len >= 16) {
		knod_bpf_load_size(priv, meta,
				       &r64[10], &stack[0],
				       sizeof(unsigned long),
				       512 + val_stack_off + val_off);
		knod_bpf_load_size(priv, meta,
				       &r64[11], &stack[0],
				       sizeof(unsigned long),
				       512 + val_stack_off + val_off + 8);
		knod_emit(priv, meta, global_store_dwordx4, r64[10].lo,
			  r64[0].lo, val_off);
		val_off += 16;
		val_len -= 16;
	}

	if (val_len >= 8) {
		knod_bpf_load_size(priv, meta,
				       &r64[10], &stack[0],
				       sizeof(unsigned long),
				       512 + val_stack_off + val_off);
		knod_emit(priv, meta, global_store_dwordx2, r64[10].lo,
			  r64[0].lo, val_off);
		val_off += 8;
		val_len -= 8;
	}

	if (val_len >= 4) {
		knod_bpf_load_size(priv, meta,
				       &r64[10], &stack[0],
				       sizeof(unsigned int),
				       512 + val_stack_off + val_off);
		knod_emit(priv, meta, global_store_dword, r64[10].lo,
			  r64[0].lo, val_off);
		val_off += 4;
		val_len -= 4;
	}

	if (val_len >= 2) {
		knod_bpf_load_size(priv, meta,
				       &r64[10], &stack[0],
				       sizeof(unsigned short),
				       512 + val_stack_off + val_off);
		knod_emit(priv, meta, global_store_short, r64[10].lo,
			  r64[0].lo, val_off);
		val_off += 2;
		val_len -= 2;
	}

	if (val_len >= 1) {
		knod_bpf_load_size(priv, meta,
				       &r64[10], &stack[0],
				       sizeof(unsigned char),
				       512 + val_stack_off + val_off);
		knod_emit(priv, meta, global_store_byte, r64[10].lo,
			  r64[0].lo, val_off);
	}

	/* If matched, done with this lane */
	emit_s_cbranch_execnz(priv->isa_version,
			      &meta->amdgpu_insn[meta->amdgpu_insns],
			      0);
	knod_bpf_set_fixup(meta, &fixups[fixup_idx],
			   &labels[LABEL_LANE_DONE], meta->amdgpu_insns);
	debug_insn(priv->isa_version, &meta->amdgpu_insn[meta->amdgpu_insns]);
	meta->amdgpu_insns++;
	fixup_idx++;

	/* No match: restore lane, continue chain walk */
	knod_emit(priv, meta, s_mov_b64, AMDGCN_SREG_EXEC_LO,
		  KNOD_AMDGPU_TMP_SREG2_LO);

	emit_s_cbranch_execnz(priv->isa_version,
			      &meta->amdgpu_insn[meta->amdgpu_insns],
			      0);
	knod_bpf_set_fixup(meta, &fixups[fixup_idx],
			   &labels[LABEL_CHAIN_NEXT], meta->amdgpu_insns);
	debug_insn(priv->isa_version, &meta->amdgpu_insn[meta->amdgpu_insns]);
	meta->amdgpu_insns++;
	fixup_idx++;

	/* ---- ALLOC_INSERT: key not found, insert new elem ---- */
	knod_bpf_set_label(meta, &labels[LABEL_ALLOC_INSERT],
			   meta->amdgpu_insns);

	/* Restore single-lane exec */
	knod_emit(priv, meta, s_mov_b64, AMDGCN_SREG_EXEC_LO,
		  KNOD_AMDGPU_TMP_SREG2_LO);

	/* Alloc from free pool: atomic_add(cur, -1) */
	knod_iset32(&v_minus_one, -1);
	knod_emit(priv, meta, v_mov_b32_e32, r64[11].lo, v_minus_one);

	knod_iset64(&p64[0], cur_gaddr);
	knod_mov64(priv, meta, r64[1], p64[0]);

	knod_emit(priv, meta, global_atomic_add, r64[11].lo, r64[1].lo,
		  r64[11].lo, 0, 1);
	knod_wait_vmcnt(priv, meta);

	/* my_cur = old_cur - 1 → r64[0].lo */
	knod_emit(priv, meta, v_mov_b32_e32, r64[0].lo, v_one);
	knod_emit(priv, meta, v_sub_u32, r64[0].lo, r64[11].lo, r64[0].lo);

	/* OOM check: if (my_cur < 0) → skip insert */
	knod_emit(priv, meta, v_cmp_gt_i32, v_zero, r64[0].lo);
	knod_emit(priv, meta, s_andn2_b64, AMDGCN_SREG_EXEC_LO,
		  AMDGCN_SREG_EXEC_LO, AMDGCN_SREG_VCC_LO);
	emit_s_cbranch_execz(priv->isa_version,
			     &meta->amdgpu_insn[meta->amdgpu_insns],
			     0);
	knod_bpf_set_fixup(meta, &fixups[fixup_idx],
			   &labels[LABEL_LANE_DONE], meta->amdgpu_insns);
	debug_insn(priv->isa_version, &meta->amdgpu_insn[meta->amdgpu_insns]);
	meta->amdgpu_insns++;
	fixup_idx++;

	/* queue_addr = queue_gaddr + my_cur * 4 → r64[1] */
	knod_iset64(&p64[0], queue_gaddr);
	knod_mov64(priv, meta, r64[1], p64[0]);
	knod_iset64(&p64[1], sizeof(unsigned int));
	knod_emit(priv, meta, v_mad_u64_u32, r64[1], sr64_carry.lo,
		  p64[1].lo, r64[0].lo, r64[1]);

	/* elem_id = queue[my_cur] → r64[0].lo */
	knod_emit(priv, meta, global_load_dword, r64[0].lo, r64[1].lo, 0);
	knod_wait_vmcnt(priv, meta);

	/* new_elem_addr = elems + elem_id * elem_size → r64[2] */
	knod_iset64(&p64[0], elems_gaddr);
	knod_mov64(priv, meta, r64[1], p64[0]);
	knod_iset64(&p64[0], elem_size);
	knod_mov32(priv, meta, r64[10].lo, p64[0].lo);
	knod_emit(priv, meta, v_mad_u64_u32, r64[2], sr64_carry.lo,
		  r64[10].lo, r64[0].lo, r64[1]);

	/* Save elem_id to SGPR (v_mad carry already done) */
	knod_emit(priv, meta, v_readfirstlane_b32, KNOD_AMDGPU_TMP_SREG1_LO,
		  r64[0].lo.v);

	/* Load current bucket head → r64[1].lo */
	knod_emit(priv, meta, global_load_dword, r64[1].lo, r64[15].lo, 0);
	knod_wait_vmcnt(priv, meta);

	/* new_elem.next = old_head */
	knod_emit(priv, meta, global_store_dword, r64[1].lo, r64[2].lo, 0);

	/* Write key to new element */
	koff = offsetof(struct knod_bpf_hash_elem_obj, kv);

	key_in_pkt = KEY_IN_PKT_32;
	len = knod_map_obj_k->key_size;

	while (len >= 8) {
		knod_emit(priv, meta, global_store_dwordx2, r32[key_in_pkt],
			  r64[2].lo, koff);
		koff += 8;
		len -= 8;
		key_in_pkt += 2;
	}

	if (len >= 4) {
		knod_emit(priv, meta, global_store_dword, r32[key_in_pkt],
			  r64[2].lo, koff);
		koff += 4;
		len -= 4;
		key_in_pkt += 1;
	}

	if (len >= 2) {
		knod_emit(priv, meta, global_store_short, r32[key_in_pkt],
			  r64[2].lo, koff);
		koff += 2;
		len -= 2;
	}

	if (len >= 1) {
		knod_emit(priv, meta, global_store_byte, r32[key_in_pkt],
			  r64[2].lo, koff);
	}

	/* Write value to new element */
	voff = offsetof(struct knod_bpf_hash_elem_obj, kv) +
	       knod_map_obj_k->key_size;

	val_off = 0;
	val_len = knod_map_obj_k->value_size;

	knod_iset64(&p64[1], voff);
	knod_add64(priv, meta, r64[0], p64[1], r64[2]);

	while (val_len >= 16) {
		knod_bpf_load_size(priv, meta,
				       &r64[10], &stack[0],
				       sizeof(unsigned long),
				       512 + val_stack_off + val_off);
		knod_bpf_load_size(priv, meta,
				       &r64[11], &stack[0],
				       sizeof(unsigned long),
				       512 + val_stack_off + val_off + 8);
		knod_emit(priv, meta, global_store_dwordx4, r64[10].lo,
			  r64[0].lo, val_off);
		val_off += 16;
		val_len -= 16;
	}

	if (val_len >= 8) {
		knod_bpf_load_size(priv, meta,
				       &r64[10], &stack[0],
				       sizeof(unsigned long),
				       512 + val_stack_off + val_off);
		knod_emit(priv, meta, global_store_dwordx2, r64[10].lo,
			  r64[0].lo, val_off);
		val_off += 8;
		val_len -= 8;
	}

	if (val_len >= 4) {
		knod_bpf_load_size(priv, meta,
				       &r64[10], &stack[0],
				       sizeof(unsigned int),
				       512 + val_stack_off + val_off);
		knod_emit(priv, meta, global_store_dword, r64[10].lo,
			  r64[0].lo, val_off);
		val_off += 4;
		val_len -= 4;
	}

	if (val_len >= 2) {
		knod_bpf_load_size(priv, meta,
				       &r64[10], &stack[0],
				       sizeof(unsigned short),
				       512 + val_stack_off + val_off);
		knod_emit(priv, meta, global_store_short, r64[10].lo,
			  r64[0].lo, val_off);
		val_off += 2;
		val_len -= 2;
	}

	if (val_len >= 1) {
		knod_bpf_load_size(priv, meta,
				       &r64[10], &stack[0],
				       sizeof(unsigned char),
				       512 + val_stack_off + val_off);
		knod_emit(priv, meta, global_store_byte, r64[10].lo,
			  r64[0].lo, val_off);
	}

	knod_wait_vmcnt(priv, meta);

	/* Update bucket[hash] = new elem_id */
	knod_emit(priv, meta, v_mov_b32_e32, r64[1].lo, s_elem_id);
	knod_emit(priv, meta, global_store_dword, r64[1].lo, r64[15].lo,
		  0);
	knod_wait_vmcnt(priv, meta);

	/* ---- LANE_DONE: remove this lane, next lane ---- */
	knod_bpf_set_label(meta, &labels[LABEL_LANE_DONE], meta->amdgpu_insns);

	knod_emit(priv, meta, s_andn2_b64, AMDGCN_SREG_EXEC_LO,
		  KNOD_AMDGPU_TMP_SREG4_LO, KNOD_AMDGPU_TMP_SREG2_LO);

	emit_s_cbranch_execnz(priv->isa_version,
			      &meta->amdgpu_insn[meta->amdgpu_insns],
			      0);
	knod_bpf_set_fixup(meta, &fixups[fixup_idx],
			   &labels[LABEL_INSERT_LANE], meta->amdgpu_insns);
	debug_insn(priv->isa_version, &meta->amdgpu_insn[meta->amdgpu_insns]);
	meta->amdgpu_insns++;
	fixup_idx++;

	/* ---- UNLOCK: release lock + next bucket ---- */
	knod_bpf_set_label(meta, &labels[LABEL_UNLOCK], meta->amdgpu_insns);

	knod_emit(priv, meta, s_mov_b64, AMDGCN_SREG_EXEC_LO,
		  KNOD_AMDGPU_TMP_SREG0_LO);

	/* Recompute lock_addr (r64[10] clobbered) */
	knod_iset64(&p64[0], lock_offset);
	knod_add64(priv, meta, r64[10], p64[0], r64[15]);

	knod_emit(priv, meta, v_mov_b32_e32, r64[1].lo, v_zero);
	knod_emit(priv, meta, global_store_dword, r64[1].lo, r64[10].lo,
		  0);
	knod_wait_vmcnt(priv, meta);

	/* Next bucket */
	knod_emit(priv, meta, s_andn2_b64, AMDGCN_SREG_EXEC_LO,
		  KNOD_AMDGPU_TMP_SREG5_LO, KNOD_AMDGPU_TMP_SREG0_LO);

	emit_s_cbranch_execnz(priv->isa_version,
			      &meta->amdgpu_insn[meta->amdgpu_insns],
			      0);
	knod_bpf_set_fixup(meta, &fixups[fixup_idx],
			   &labels[LABEL_BUCKET_LOOP], meta->amdgpu_insns);
	debug_insn(priv->isa_version, &meta->amdgpu_insn[meta->amdgpu_insns]);
	meta->amdgpu_insns++;
	fixup_idx++;

	/* ======== Phase 5: Restore ======== */

	knod_bpf_set_label(meta, &labels[LABEL_OUT], meta->amdgpu_insns);
	/* exec = SREG3 (restore all original lanes) */
	knod_emit(priv, meta, s_or_b64, AMDGCN_SREG_EXEC_LO,
		  AMDGCN_SREG_EXEC_LO, KNOD_AMDGPU_TMP_SREG3_LO);

	/* bpf_reg64[0] = 0 (return value for all lanes) */
	knod_iset64(&p64[0], 0);
	knod_mov64(priv, meta, bpf_reg64[0], p64[0]);

	for (idx = 0; idx < fixup_idx; idx++)
		knod_bpf_fixup_branch(priv, &fixups[idx]);

	return;
#undef LABEL_BUCKET_LOOP
#undef LABEL_LOCK_RETRY
#undef LABEL_INSERT_LANE
#undef LABEL_CHAIN_NEXT
#undef LABEL_ALLOC_INSERT
#undef LABEL_LANE_DONE
#undef LABEL_UNLOCK
}

static void knod_bpf_map_delete_hash(struct knod_bpf_priv *priv,
				     struct knod_insn_meta *meta,
				     int map_id)
{
#define LABEL_BUCKET_LOOP	0
#define LABEL_LOCK_RETRY	1
#define LABEL_DELETE_LANE	2
#define LABEL_CHAIN_NEXT	3
#define LABEL_LANE_DONE		4
#define LABEL_UNLOCK		5
	struct knod_bpf_map_obj *knod_map_obj_k, *knod_map_obj_g;
	struct amdgcn_param32 s_bucket_lo, v_tmp, v_zero, v_one;
	int off, len, _len, idx, key_in_pkt, key_in_map;
	struct amdgcn_branch_fixup fixups[12] = {0,};
	unsigned long bucket_gaddr, gc_count_gaddr;
	struct amdgcn_param32 s_exec_lo, s_exec_hi;
	unsigned long gc_list_gaddr, elems_gaddr;
	u32 key_stack_off = meta->kreg.stack_off;
	struct amdgcn_label labels[12] = {0,};
	struct amdgcn_param64 sr64_carry;
	struct amdgcn_param32 v_del;
	struct amdgcn_param32 p32;
	unsigned long lock_offset;
	unsigned int elem_size;
	int fixup_idx = 0;
	bool first_cmp;

	knod_map_obj_k =
		(struct knod_bpf_map_obj *)knod_bpf_map_kaddr(priv, map_id);
	knod_map_obj_g =
		(struct knod_bpf_map_obj *)knod_bpf_map_gaddr(priv, map_id);
	bucket_gaddr = (unsigned long)knod_map_obj_g +
		       offsetof(struct knod_bpf_map_obj, bucket);
	gc_count_gaddr = (unsigned long)knod_map_obj_g +
			 offsetof(struct knod_bpf_map_obj, meta.hmeta.gc_count);
	gc_list_gaddr = (unsigned long)knod_map_obj_k->meta.hmeta.gc_list;
	elems_gaddr = (unsigned long)knod_map_obj_k->meta.hmeta.elems;
	elem_size = knod_map_obj_k->meta.hmeta.elem_size;

	if (!knod_map_obj_g || !knod_map_obj_k)
		WARN_ON(1);

	/* ======== Phase 1: Setup ======== */

	/* Load key from stack → r64[3..9] (KEY_IN_PKT) */
	key_in_pkt = KEY_IN_PKT_64;
	len = knod_map_obj_k->key_size;
	off = key_stack_off;
	while (len) {
		if (len >= sizeof(unsigned long))
			_len = sizeof(unsigned long);
		else
			_len = len;
		knod_bpf_load_size(priv, meta,
				       &r64[key_in_pkt],
				       &stack[0],
				       _len,
				       512 + off);
		key_in_pkt++;
		len -= _len;
		off += _len;
	}

	/* jhash → r64[2].lo = hash */
	knod_jhash(priv, meta,
		       2,
		       knod_map_obj_k->key_size,
		       knod_map_obj_k->meta.hmeta.hashrnd);
	knod_iset64(&p64[0], 0);
	knod_mov32(priv, meta, r64[2].hi, p64[0].lo);

	/* hash = hash & (n_buckets - 1) */
	knod_iset32(&p64[0].lo,
				 knod_map_obj_k->meta.hmeta.n_buckets - 1);
	knod_and32(priv, meta, r64[2].lo, p64[0].lo, r64[2].lo);

	/* r64[1] = bucket_gaddr */
	knod_iset64(&p64[0], bucket_gaddr);
	knod_mov64(priv, meta, r64[1], p64[0]);

	/* bucket_addr = bucket_gaddr + hash * sizeof(int) → r64[2] */
	knod_iset64(&p64[1], sizeof(int));
	knod_emit(priv, meta, v_mad_u64_u32, r64[2], sr64[0].lo,
		  p64[1].lo, r64[2].lo, r64[1]);

	/* Save bucket_addr to r64[15] */
	knod_mov64(priv, meta, r64[15], r64[2]);

	/* SREG3 = initial exec */
	knod_emit(priv, meta, s_mov_b64, KNOD_AMDGPU_TMP_SREG3_LO,
		  AMDGCN_SREG_EXEC_LO);

	/* ======== Phase 2: Sequential per-lane processing ======== */

	/* SREG5 = exec (all lanes to process, for BUCKET_LOOP) */
	knod_emit(priv, meta, s_mov_b64, KNOD_AMDGPU_TMP_SREG5_LO,
		  AMDGCN_SREG_EXEC_LO);

	/* ---- BUCKET_LOOP: process one unique bucket per iteration ---- */
	knod_bpf_set_label(meta, &labels[LABEL_BUCKET_LOOP],
			   meta->amdgpu_insns);

	lock_offset =
		(unsigned long)knod_map_obj_k->meta.hmeta.n_buckets *
		sizeof(unsigned int);

	knod_sset32(&s_bucket_lo,
				 KNOD_AMDGPU_TMP_SREG1_HI);
	knod_vset32(&v_tmp, KNOD_AMDGPU_TMP_VREG0_HI);
	knod_iset32(&v_zero, 0);
	knod_iset32(&v_one, 1);
	knod_sset32(&s_exec_lo, AMDGCN_SREG_EXEC_LO);
	knod_sset32(&s_exec_hi,
				 AMDGCN_SREG_EXEC_LO + 1);
	knod_sset64(&sr64_carry,
				 KNOD_AMDGPU_TMP_SREG1_LO);

	/* Pick first active lane's bucket addr */
	knod_emit(priv, meta, v_readfirstlane_b32, KNOD_AMDGPU_TMP_SREG1_HI,
		  r64[15].lo.v);

	/* vcc = lanes with same bucket */
	knod_emit(priv, meta, v_cmp_eq_u32, s_bucket_lo, r64[15].lo);

	/* SREG5 = remaining lanes; exec = same-bucket lanes */
	knod_emit(priv, meta, s_and_saveexec_b64, KNOD_AMDGPU_TMP_SREG5_LO,
		  AMDGCN_SREG_VCC_LO);

	/* SREG0 = same-bucket lanes */
	knod_emit(priv, meta, s_mov_b64, KNOD_AMDGPU_TMP_SREG0_LO,
		  AMDGCN_SREG_EXEC_LO);

	/* ---- Lock acquire ---- */
	/* r64[10] = r64[15] + lock_offset */
	knod_iset64(&p64[0], lock_offset);
	knod_add64(priv, meta, r64[10], p64[0], r64[15]);

	/* r64[11].lo = 1 (swap data) */
	knod_emit(priv, meta, v_mov_b32_e32, r64[11].lo, v_one);

	/* First-lane isolation via mbcnt */
	knod_emit(priv, meta, v_mbcnt_lo_u32_b32, v_tmp, s_exec_lo,
		  v_zero);
	knod_emit(priv, meta, v_mbcnt_hi_u32_b32, v_tmp, s_exec_hi, v_tmp);
	knod_emit(priv, meta, v_cmp_eq_u32, v_zero, v_tmp);
	knod_emit(priv, meta, s_and_b64, AMDGCN_SREG_EXEC_LO,
		  AMDGCN_SREG_EXEC_LO, AMDGCN_SREG_VCC_LO);

	/* LOCK_RETRY: spin until lock acquired */
	knod_bpf_set_label(meta, &labels[LABEL_LOCK_RETRY], meta->amdgpu_insns);

	knod_emit(priv, meta, global_atomic_swap, r64[11].hi, r64[10].lo,
		  r64[11].lo, 0, 1);
	knod_wait_vmcnt(priv, meta);

	meta->amdgpu_insn[meta->amdgpu_insns].size =
		emit_gfx10_v_cmp_ne_u32(
			&meta->amdgpu_insn[meta->amdgpu_insns].gfx10,
			v_zero, r64[11].hi);
	meta->amdgpu_insn[meta->amdgpu_insns].type = AMDGCN_INSN_TYPE_VOPC;
	debug_insn(priv->isa_version, &meta->amdgpu_insn[meta->amdgpu_insns]);
	meta->amdgpu_insns++;

	emit_s_cbranch_vccnz(priv->isa_version,
			     &meta->amdgpu_insn[meta->amdgpu_insns],
			     0);
	knod_bpf_set_fixup(meta, &fixups[fixup_idx],
			   &labels[LABEL_LOCK_RETRY], meta->amdgpu_insns);
	debug_insn(priv->isa_version, &meta->amdgpu_insn[meta->amdgpu_insns]);
	meta->amdgpu_insns++;
	fixup_idx++;

	/* Lock acquired — restore same-bucket lanes */
	knod_emit(priv, meta, s_mov_b64, AMDGCN_SREG_EXEC_LO,
		  KNOD_AMDGPU_TMP_SREG0_LO);

	/* ---- DELETE_LANE: process one lane at a time ---- */
	knod_bpf_set_label(meta, &labels[LABEL_DELETE_LANE],
			   meta->amdgpu_insns);

	/* SREG4 = exec (remaining same-bucket lanes) */
	knod_emit(priv, meta, s_mov_b64, KNOD_AMDGPU_TMP_SREG4_LO,
		  AMDGCN_SREG_EXEC_LO);

	/* Pick first active lane via mbcnt */
	knod_emit(priv, meta, v_mbcnt_lo_u32_b32, v_tmp, s_exec_lo,
		  v_zero);
	knod_emit(priv, meta, v_mbcnt_hi_u32_b32, v_tmp, s_exec_hi, v_tmp);
	knod_emit(priv, meta, v_cmp_eq_u32, v_zero, v_tmp);
	knod_emit(priv, meta, s_and_b64, AMDGCN_SREG_EXEC_LO,
		  AMDGCN_SREG_EXEC_LO, AMDGCN_SREG_VCC_LO);

	/* SREG2 = exec (single-lane mask) */
	knod_emit(priv, meta, s_mov_b64, KNOD_AMDGPU_TMP_SREG2_LO,
		  AMDGCN_SREG_EXEC_LO);

	/* r64[2] = r64[15] (bucket_addr for chain walk start) */
	knod_mov64(priv, meta, r64[2], r64[15]);

	/* ---- CHAIN_NEXT: walk chain ---- */
	knod_bpf_set_label(meta, &labels[LABEL_CHAIN_NEXT], meta->amdgpu_insns);

	knod_emit(priv, meta, global_load_dword, r64[0].lo, r64[2].lo, 0);
	knod_wait_vmcnt(priv, meta);

	/* Mask out DELETED bit */
	knod_iset32(&p32, KNOD_BPF_HASH_NEXT_MASK);
	knod_emit(priv, meta, v_and_b32_e32, r64[0].lo, p32, r64[0].lo);

	/* End-of-chain check (VOPC literal workaround) */
	knod_emit(priv, meta, v_mov_b32_e32, r64[0].hi, p32);
	knod_emit(priv, meta, v_cmp_eq_u32, r64[0].hi, r64[0].lo);
	knod_emit(priv, meta, s_andn2_b64, AMDGCN_SREG_EXEC_LO,
		  AMDGCN_SREG_EXEC_LO, AMDGCN_SREG_VCC_LO);
	emit_s_cbranch_execz(priv->isa_version,
			     &meta->amdgpu_insn[meta->amdgpu_insns],
			     0);
	knod_bpf_set_fixup(meta, &fixups[fixup_idx],
			   &labels[LABEL_LANE_DONE], meta->amdgpu_insns);
	debug_insn(priv->isa_version, &meta->amdgpu_insn[meta->amdgpu_insns]);
	meta->amdgpu_insns++;
	fixup_idx++;

	/* elem_addr = elems + elem_id * elem_size → r64[2] */
	knod_iset64(&p64[0], elems_gaddr);
	knod_mov64(priv, meta, r64[1], p64[0]);
	knod_iset64(&p64[0], elem_size);
	knod_mov32(priv, meta, r64[10].lo, p64[0].lo);
	knod_emit(priv, meta, v_mad_u64_u32, r64[2], sr64_carry.lo,
		  r64[10].lo, r64[0].lo, r64[1]);

	/* Load elem.next for DELETED check */
	knod_emit(priv, meta, global_load_dword, r64[0].hi, r64[2].lo, 0);

	/* Load key from map element → KEY_IN_MAP */
	key_in_map = KEY_IN_MAP_32;
	len = knod_map_obj_k->key_size;
	off = offsetof(struct knod_bpf_hash_elem_obj, kv);

	while (len >= 16) {
		knod_emit(priv, meta, global_load_dwordx4, r32[key_in_map],
			  r64[2].lo, off);
		off += 16;
		len -= 16;
		key_in_map += 4;
	}

	if (len >= 8) {
		knod_emit(priv, meta, global_load_dwordx2, r32[key_in_map],
			  r64[2].lo, off);
		off += 8;
		len -= 8;
		key_in_map += 2;
	}

	if (len >= 4) {
		knod_emit(priv, meta, global_load_dword, r32[key_in_map],
			  r64[2].lo, off);
		off += 4;
		len -= 4;
		key_in_map += 1;
	}

	if (len) {
		knod_emit(priv, meta, global_load_dword, r32[key_in_map],
			  r64[2].lo, off);
	}

	knod_wait_vmcnt(priv, meta);

	/* Key comparison → SREG1 */
	key_in_map = KEY_IN_MAP_32;
	key_in_pkt = KEY_IN_PKT_32;
	len = knod_map_obj_k->key_size;
	first_cmp = true;

	while (len >= 8) {
		knod_emit(priv, meta, v_cmp_eq_u64, r32[key_in_map],
			  r32[key_in_pkt]);

		if (first_cmp) {
			emit_s_and_b64(priv->isa_version,
				       &meta->amdgpu_insn[meta->amdgpu_insns],
				       KNOD_AMDGPU_TMP_SREG1_LO,
				       AMDGCN_SREG_EXEC_LO,
				       AMDGCN_SREG_VCC_LO);
			first_cmp = false;
		} else {
			emit_s_and_b64(priv->isa_version,
				       &meta->amdgpu_insn[meta->amdgpu_insns],
				       KNOD_AMDGPU_TMP_SREG1_LO,
				       KNOD_AMDGPU_TMP_SREG1_LO,
				       AMDGCN_SREG_VCC_LO);
		}
		debug_insn(priv->isa_version,
			   &meta->amdgpu_insn[meta->amdgpu_insns]);
		meta->amdgpu_insns++;

		key_in_map += 2;
		key_in_pkt += 2;
		len -= 8;
	}

	if (len >= 4) {
		knod_emit(priv, meta, v_cmp_eq_u32, r32[key_in_map],
			  r32[key_in_pkt]);

		if (first_cmp) {
			emit_s_and_b64(priv->isa_version,
				       &meta->amdgpu_insn[meta->amdgpu_insns],
				       KNOD_AMDGPU_TMP_SREG1_LO,
				       AMDGCN_SREG_EXEC_LO,
				       AMDGCN_SREG_VCC_LO);
			first_cmp = false;
		} else {
			emit_s_and_b64(priv->isa_version,
				       &meta->amdgpu_insn[meta->amdgpu_insns],
				       KNOD_AMDGPU_TMP_SREG1_LO,
				       KNOD_AMDGPU_TMP_SREG1_LO,
				       AMDGCN_SREG_VCC_LO);
		}
		debug_insn(priv->isa_version,
			   &meta->amdgpu_insn[meta->amdgpu_insns]);
		meta->amdgpu_insns++;

		key_in_map += 1;
		key_in_pkt += 1;
		len -= 4;
	}

	if (len) {
		knod_emit(priv, meta, v_cmp_eq_u32, r32[key_in_map],
			  r32[key_in_pkt]);

		if (first_cmp) {
			emit_s_and_b64(priv->isa_version,
				       &meta->amdgpu_insn[meta->amdgpu_insns],
				       KNOD_AMDGPU_TMP_SREG1_LO,
				       AMDGCN_SREG_EXEC_LO,
				       AMDGCN_SREG_VCC_LO);
			first_cmp = false;
		} else {
			emit_s_and_b64(priv->isa_version,
				       &meta->amdgpu_insn[meta->amdgpu_insns],
				       KNOD_AMDGPU_TMP_SREG1_LO,
				       KNOD_AMDGPU_TMP_SREG1_LO,
				       AMDGCN_SREG_VCC_LO);
		}
		debug_insn(priv->isa_version,
			   &meta->amdgpu_insn[meta->amdgpu_insns]);
		meta->amdgpu_insns++;
	}

	/* DELETED check: SREG1 &= not_deleted */
	knod_iset32(&p32,
				 KNOD_BPF_HASH_NEXT_DELETED);
	knod_emit(priv, meta, v_and_b32_e32, r64[0].hi, p32, r64[0].hi);
	knod_iset32(&p32, 0);
	knod_emit(priv, meta, v_cmp_eq_u32, p32, r64[0].hi);
	knod_emit(priv, meta, s_and_b64, KNOD_AMDGPU_TMP_SREG1_LO,
		  KNOD_AMDGPU_TMP_SREG1_LO, AMDGCN_SREG_VCC_LO);

	/* Narrow exec to matched lane */
	knod_emit(priv, meta, s_and_b64, AMDGCN_SREG_EXEC_LO,
		  AMDGCN_SREG_EXEC_LO, KNOD_AMDGPU_TMP_SREG1_LO);

	/* ---- Match path: set DELETED + append to gc_list ---- */

	/* atomic_or(elem.next, DELETED_BIT) — mark deleted */
	knod_lset32(&v_del,
				 KNOD_BPF_HASH_NEXT_DELETED);
	knod_emit(priv, meta, v_mov_b32_e32, r64[11].lo, v_del);
	knod_emit(priv, meta, global_atomic_or, r64[11].hi, r64[2].lo,
		  r64[11].lo, 0, 0);

	/* atomic_add(gc_count, 1) → old_count in r64[11].lo */
	knod_emit(priv, meta, v_mov_b32_e32, r64[11].lo, v_one);

	knod_iset64(&p64[0], gc_count_gaddr);
	knod_mov64(priv, meta, r64[1], p64[0]);

	knod_emit(priv, meta, global_atomic_add, r64[11].lo, r64[1].lo,
		  r64[11].lo, 0, 1);
	knod_wait_vmcnt(priv, meta);

	/* Store elem_id to gc_list[old_count] */
	knod_iset64(&p64[0], gc_list_gaddr);
	knod_mov64(priv, meta, r64[10], p64[0]);

	knod_iset64(&p64[0], sizeof(unsigned int));
	knod_emit(priv, meta, v_mad_u64_u32, r64[1], sr64_carry.lo,
		  p64[0].lo, r64[11].lo, r64[10]);

	knod_emit(priv, meta, global_store_dword, r64[0].lo, r64[1].lo, 0);
	knod_wait_vmcnt(priv, meta);

	/* If matched, done with this lane */
	emit_s_cbranch_execnz(priv->isa_version,
			      &meta->amdgpu_insn[meta->amdgpu_insns],
			      0);
	knod_bpf_set_fixup(meta, &fixups[fixup_idx],
			   &labels[LABEL_LANE_DONE], meta->amdgpu_insns);
	debug_insn(priv->isa_version, &meta->amdgpu_insn[meta->amdgpu_insns]);
	meta->amdgpu_insns++;
	fixup_idx++;

	/* No match: restore lane, continue chain walk */
	knod_emit(priv, meta, s_mov_b64, AMDGCN_SREG_EXEC_LO,
		  KNOD_AMDGPU_TMP_SREG2_LO);

	emit_s_cbranch_execnz(priv->isa_version,
			      &meta->amdgpu_insn[meta->amdgpu_insns],
			      0);
	knod_bpf_set_fixup(meta, &fixups[fixup_idx],
			   &labels[LABEL_CHAIN_NEXT], meta->amdgpu_insns);
	debug_insn(priv->isa_version, &meta->amdgpu_insn[meta->amdgpu_insns]);
	meta->amdgpu_insns++;
	fixup_idx++;

	/* ---- LANE_DONE: remove this lane, next lane ---- */
	knod_bpf_set_label(meta, &labels[LABEL_LANE_DONE], meta->amdgpu_insns);

	knod_emit(priv, meta, s_andn2_b64, AMDGCN_SREG_EXEC_LO,
		  KNOD_AMDGPU_TMP_SREG4_LO, KNOD_AMDGPU_TMP_SREG2_LO);

	emit_s_cbranch_execnz(priv->isa_version,
			      &meta->amdgpu_insn[meta->amdgpu_insns],
			      0);
	knod_bpf_set_fixup(meta, &fixups[fixup_idx],
			   &labels[LABEL_DELETE_LANE], meta->amdgpu_insns);
	debug_insn(priv->isa_version, &meta->amdgpu_insn[meta->amdgpu_insns]);
	meta->amdgpu_insns++;
	fixup_idx++;

	/* ---- UNLOCK: release lock + next bucket ---- */
	knod_bpf_set_label(meta, &labels[LABEL_UNLOCK], meta->amdgpu_insns);

	knod_emit(priv, meta, s_mov_b64, AMDGCN_SREG_EXEC_LO,
		  KNOD_AMDGPU_TMP_SREG0_LO);

	/* Recompute lock_addr (r64[10] clobbered) */
	knod_iset64(&p64[0], lock_offset);
	knod_add64(priv, meta, r64[10], p64[0], r64[15]);

	knod_emit(priv, meta, v_mov_b32_e32, r64[1].lo, v_zero);
	knod_emit(priv, meta, global_store_dword, r64[1].lo, r64[10].lo,
		  0);
	knod_wait_vmcnt(priv, meta);

	/* Next bucket */
	knod_emit(priv, meta, s_andn2_b64, AMDGCN_SREG_EXEC_LO,
		  KNOD_AMDGPU_TMP_SREG5_LO, KNOD_AMDGPU_TMP_SREG0_LO);

	emit_s_cbranch_execnz(priv->isa_version,
			      &meta->amdgpu_insn[meta->amdgpu_insns],
			      0);
	knod_bpf_set_fixup(meta, &fixups[fixup_idx],
			   &labels[LABEL_BUCKET_LOOP], meta->amdgpu_insns);
	debug_insn(priv->isa_version, &meta->amdgpu_insn[meta->amdgpu_insns]);
	meta->amdgpu_insns++;
	fixup_idx++;

	/* ======== Phase 3: Restore ======== */

	/* exec = SREG3 (restore all original lanes) */
	knod_emit(priv, meta, s_or_b64, AMDGCN_SREG_EXEC_LO,
		  AMDGCN_SREG_EXEC_LO, KNOD_AMDGPU_TMP_SREG3_LO);

	/* bpf_reg64[0] = 0 (return value) */
	knod_iset64(&p64[0], 0);
	knod_mov64(priv, meta, bpf_reg64[0], p64[0]);

	for (idx = 0; idx < fixup_idx; idx++)
		knod_bpf_fixup_branch(priv, &fixups[idx]);

	return;
#undef LABEL_BUCKET_LOOP
#undef LABEL_LOCK_RETRY
#undef LABEL_DELETE_LANE
#undef LABEL_CHAIN_NEXT
#undef LABEL_LANE_DONE
#undef LABEL_UNLOCK
}

static void knod_bpf_map_delete_array(struct knod_bpf_priv *priv,
				      struct knod_insn_meta *meta,
				      int map_id)
{
	struct knod_bpf_map_obj *knod_map_obj_k, *knod_map_obj_g;
	struct amdgcn_branch_fixup fixups[4] = {0,};
	u32 key_stack_off = meta->kreg.stack_off;
	struct amdgcn_label labels[10] = {0,};
	int idx, val_off, val_len;
	struct amdgcn_param32 v_zero;
	unsigned long bucket_gaddr;
	int fixup_idx = 0;

	knod_map_obj_k =
		(struct knod_bpf_map_obj *)knod_bpf_map_kaddr(priv, map_id);
	knod_map_obj_g =
		(struct knod_bpf_map_obj *)knod_bpf_map_gaddr(priv, map_id);
	bucket_gaddr = (unsigned long)knod_map_obj_g +
		       offsetof(struct knod_bpf_map_obj, bucket);

	if (!knod_map_obj_g || !knod_map_obj_k)
		WARN_ON(1);

	/* load key from stack → r64[2] */
	knod_bpf_load_size(priv, meta,
			       &r64[2],
			       &stack[0],
			       sizeof(unsigned int),
			       512 + key_stack_off);

	/* r64[1] = bucket_gaddr */
	knod_iset64(&p64[0], bucket_gaddr);
	knod_mov64(priv, meta, r64[1], p64[0]);

	/* clear r64[2].hi (key is 32-bit) */
	knod_iset64(&p64[1], 0);
	knod_mov32(priv, meta, r64[2].hi, p64[1].lo);

	/* bpf_reg64[0] = 0 (return value) */
	knod_mov64(priv, meta, bpf_reg64[0], p64[1]);

	/* bounds check: if (key >= max_entries) → skip */
	knod_iset64(&p64[1], knod_map_obj_k->max_entries);
	knod_mov64(priv, meta, r64[3], p64[1]);
	knod_emit(priv, meta, v_cmp_ge_u64, r64[2], r64[3]);

	/* structurized CFG: save OOB lanes, narrow exec */
	knod_emit(priv, meta, s_and_b64, KNOD_AMDGPU_TMP_SREG3_LO,
		  AMDGCN_SREG_EXEC_LO, AMDGCN_SREG_VCC_LO);
	knod_emit(priv, meta, s_andn2_b64, AMDGCN_SREG_EXEC_LO,
		  AMDGCN_SREG_EXEC_LO, AMDGCN_SREG_VCC_LO);
	emit_s_cbranch_execz(priv->isa_version,
			     &meta->amdgpu_insn[meta->amdgpu_insns],
			     0);
	knod_bpf_set_fixup(meta, &fixups[fixup_idx],
			   &labels[LABEL_OUT], meta->amdgpu_insns);
	debug_insn(priv->isa_version, &meta->amdgpu_insn[meta->amdgpu_insns]);
	meta->amdgpu_insns++;
	fixup_idx++;

	/* dest = bucket_gaddr + key * value_size → r64[0] */
	knod_iset64(&p64[1], knod_map_obj_k->value_size);
	knod_emit(priv, meta, v_mad_u64_u32, r64[0], sr64[0].lo,
		  p64[1].lo, r64[2].lo, r64[1]);

	/* Zero out value at dest */
	knod_iset32(&v_zero, 0);
	knod_emit(priv, meta, v_mov_b32_e32, r64[3].lo, v_zero);
	knod_emit(priv, meta, v_mov_b32_e32, r64[3].hi, v_zero);
	knod_emit(priv, meta, v_mov_b32_e32, r64[4].lo, v_zero);
	knod_emit(priv, meta, v_mov_b32_e32, r64[4].hi, v_zero);

	val_off = 0;
	val_len = knod_map_obj_k->value_size;

	while (val_len >= 16) {
		knod_emit(priv, meta, global_store_dwordx4, r64[3].lo,
			  r64[0].lo, val_off);
		val_off += 16;
		val_len -= 16;
	}

	if (val_len >= 8) {
		knod_emit(priv, meta, global_store_dwordx2, r64[3].lo,
			  r64[0].lo, val_off);
		val_off += 8;
		val_len -= 8;
	}

	if (val_len >= 4) {
		knod_emit(priv, meta, global_store_dword, r64[3].lo,
			  r64[0].lo, val_off);
		val_off += 4;
		val_len -= 4;
	}

	if (val_len >= 2) {
		knod_emit(priv, meta, global_store_short, r64[3].lo,
			  r64[0].lo, val_off);
		val_off += 2;
		val_len -= 2;
	}

	if (val_len >= 1) {
		knod_emit(priv, meta, global_store_byte, r64[3].lo,
			  r64[0].lo, val_off);
	}

	knod_wait_vmcnt(priv, meta);

	/* structurized CFG: restore OOB lanes */
	knod_bpf_set_label(meta, &labels[LABEL_OUT], meta->amdgpu_insns);
	knod_emit(priv, meta, s_or_b64, AMDGCN_SREG_EXEC_LO,
		  AMDGCN_SREG_EXEC_LO, KNOD_AMDGPU_TMP_SREG3_LO);

	for (idx = 0; idx < fixup_idx; idx++)
		knod_bpf_fixup_branch(priv, &fixups[idx]);
}

static void knod_bpf_store_cache_size(struct knod_bpf_priv *priv,
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
			WARN_ON(1);
		} else if ((off % 4) == 2) {
			WARN_ON(1);
		} else {
			WARN_ON(1);
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
		WARN_ON(1);
	}
}

static bool knod_meta_is_exit(const struct knod_insn_meta *meta);
static bool knod_bpf_is_retval_move_to_r0(const struct knod_insn_meta *meta);

/*
 * knod_bpf_emit_branch_tail - Emit EXEC mask manipulation after v_cmp for
 * structurized per-lane branching. Replaces the old s_cbranch_vccnz/vccz.
 *
 * For FORWARD_SKIP:
 *   Save jumping lanes → narrow EXEC → s_cbranch_execz
 *   (skip if no active lanes)
 *
 * For DIRECT_EXIT:
 *   Compute exit lanes → update done_mask → remove from EXEC (no branch)
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

	knod_vset64(&dst, KNOD_AMDGPU_VREG0_LO);

	switch (target->insn.code) {
	case BPF_ALU | BPF_MOV | BPF_X:
	case BPF_ALU64 | BPF_MOV | BPF_X:
		knod_vset64(&src, target->insn.src_reg * 2);
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
			/* JNE: VCC=0 → jump, VCC=1 → fall-through.
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
			/* Normal: VCC=1 → jump, VCC=0 → fall-through.
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
		 * lanes (EXEC never restored → act=0).
		 */
		break;

	case KNOD_BR_DIRECT_EXIT:
		if (meta->jump_neg_op) {
			/* JNE: VCC=0 → exit. exit_lanes = exec & ~vcc */
			knod_emit(priv, meta, s_andn2_b64,
				  KNOD_AMDGPU_TMP_SREG0_LO,
				  AMDGCN_SREG_EXEC_LO,
				  AMDGCN_SREG_VCC_LO);
		} else {
			/* Normal: VCC=1 → exit. exit_lanes = exec & vcc */
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

		/* No branch — fall through with reduced EXEC.
		 * No fixup needed.
		 */
		meta->jmp_dst = NULL;
		break;

	default:
		WARN_ON(1);
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
 * backward in BPF byte order but are NOT loops — e.g. a UDP bounds check that
 * jumps back to a shared XDP_PASS tail.  Classifying those as "exit" (the
 * jmp_off < 0 heuristic in knod_bpf_analyze_cfg) silently miscompiles them:
 * the jumping lanes exit carrying whatever R0 happened to hold instead of
 * flowing to the real target.
 *
 * The fix is to classify by control-flow, not byte order:
 *   1. partition the instruction stream into basic blocks,
 *   2. build the control-flow graph (successor edges),
 *   3. DFS for a reverse-postorder (RPO) and detect back-edges,
 *   4. no back-edges (a DAG)  → reorder blocks into RPO so every edge points
 *      forward, then classify by linear position,
 *   5. a real loop is present → bail (-EOPNOTSUPP) until loop emission lands.
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

	if (!meta || meta->insn.dst_reg != BPF_REG_0)
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
			} else if (s->dfs == 1) {	/* gray → back-edge */
				s->loop_header = true;
				nb++;
			}
			/* s->dfs == 2 → forward/cross edge, nothing to do */
		} else {
			/* finished: postorder */
			bb->dfs = 2;
			bb->rpo = post++;
			top--;
		}
	}

	/* postorder → reverse-postorder rank */
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
 * A back-edge is an edge u->v whose target v dominates its source u — v is
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
		pr_info("knod_loop: %d back-edge(s) — %s\n", n_be,
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
 * whole program — including the backward-in-byte-order, non-loop jumps that
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
		pr_warn("knod_cfg: %d loop back-edge(s) — block reorder cannot lower loops yet (-EOPNOTSUPP)\n",
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
 * targets the exit), and every BPF_JA — real or synthetic — is FORWARD_GOTO
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
 * actual SGPR requirement — usually far less than the total branch count.
 */
static int knod_bpf_alloc_exec_sregs(struct knod_bpf_priv *priv,
				     struct knod_prog *knod_prog)
{
	struct {
		u8 sreg;
		struct knod_insn_meta *merge;
	} live[72];
	int exec_save_max, max_pairs, n_live, peak, j;
	struct knod_insn_meta *meta;
	u8 free_stack[72];
	int free_top;

	exec_save_max = (priv->isa_version == 10) ?
		KNOD_AMDGPU_EXEC_SAVE_SREG_MAX_GFX10 :
		KNOD_AMDGPU_EXEC_SAVE_SREG_MAX_GFX9;
	max_pairs = (exec_save_max - knod_prog->exec_save_base + 1) / 2;

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
 *   - Backward jump or jump to EXIT → DIRECT_EXIT (no SGPR needed)
 *   - Forward jump to non-EXIT → FORWARD_SKIP, allocate SGPR pair
 *
 * The "save jumping lanes" pattern handles crossing scopes correctly:
 *   branch: s_and_b64 s[n], exec, vcc; s_andn2_b64 exec, exec, vcc
 *   merge:  s_or_b64 exec, exec, s[n]
 *
 * For JNE (jump_neg_op): VCC=0 → jump, so lanes are swapped.
 */
static int knod_bpf_analyze_cfg(struct knod_bpf_priv *priv,
				struct knod_prog *knod_prog)
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

	return knod_bpf_alloc_exec_sregs(priv, knod_prog);
}

/*
 * Shader stores packet address and length into pass_meta_buf slot header.
 * Host-side SDMA engine does the actual copy to the delivery page.
 *
 * At entry:
 *   TMP_VREG10_LO (v42) = old_val * 2 (from pass_indices addressing)
 *   DATA_VREG (v64:v65) = packet source VRAM address
 *   DATA_END_VREG (v66:v67) = packet end address
 *   PARAM_SREG (s28:s29) = param GTT address
 *
 * Stores at slot header:
 *   +0: u32 len (DATA_END_LO - DATA_LO)
 *   +8: u64 src_addr (DATA_VREG)
 */
static void knod_emit_pass_addr_store(struct knod_bpf_priv *priv,
				      struct knod_insn_meta *meta)
{
	struct amdgcn_param32 p[3];

	/* s_lshl_b32 s18, s15, 3 — queue_idx * 8 for pass_meta_buf_gaddr
	 * stride
	 */
	knod_sset32(&p[0], KNOD_AMDGPU_TMP_SREG1_LO);
	knod_sset32(&p[1], KNOD_AMDGPU_WORKGROUP_ID_Y_SREG);
	knod_iset32(&p[2], 3);
	knod_emit(priv, meta, s_lshl_b32, p[0], p[1], p[2]);

	/* s_load_dwordx2 s[16:17], s[28:29], offsetof(pass_meta_buf_gaddr)
	 * soffset=s18
	 */
	knod_sset32(&p[0], KNOD_AMDGPU_TMP_SREG0_LO);
	knod_sset32(&p[1], KNOD_AMDGPU_PARAM_SREG_LO);
	knod_emit(priv, meta, s_load_dwordx2_soff, p[0], p[1],
		  offsetof(struct knod_bpf_param, pass_meta_buf_gaddr),
		  KNOD_AMDGPU_TMP_SREG1_LO);

	/* s_waitcnt lgkmcnt(0) */
	knod_emit(priv, meta, s_waitcnt_lgkmcnt);

	/* Compute slot offset: old_val << 12 = (old_val*2) << 11
	 * v_lshlrev_b32 v44, 11, v42
	 */
	knod_vset32(&p[0], KNOD_AMDGPU_TMP_VREG11_LO);
	knod_iset32(&p[1], 11);
	knod_vset32(&p[2], KNOD_AMDGPU_TMP_VREG10_LO);
	knod_emit(priv, meta, v_lshlrev_b32, p[0], p[1], p[2]);

	/* v_mov_b32 v45, 0 */
	knod_vset32(&p[0], KNOD_AMDGPU_TMP_VREG11_HI);
	knod_iset32(&p[1], 0);
	knod_emit(priv, meta, v_mov_b32_e32, p[0], p[1]);

	/* v_add_co_u32 v44, s16, v44 */
	knod_vset32(&p[0], KNOD_AMDGPU_TMP_VREG11_LO);
	knod_sset32(&p[1], KNOD_AMDGPU_TMP_SREG0_LO);
	knod_vset32(&p[2], KNOD_AMDGPU_TMP_VREG11_LO);
	knod_emit(priv, meta, v_add_co_u32, p[0], p[1], p[2]);

	/*
	 * slot_hi = base_hi (NOT base_hi + carry).  The slot offset is at
	 * most (pass_pkts_per_queue-1)*KNOD_PASS_SLOT_SIZE and the whole
	 * pass_meta_buf is a single contiguous allocation that never straddles
	 * a 4GiB boundary, so base_lo + offset never wraps and the carry is
	 * always 0.  Avoid the v_add_co/v_addc carry chain entirely: on GFX9
	 * the v_addc here was picking up a stale VCC (from the preceding
	 * XDP_PASS v_cmp) instead of the v_add_co carry-out, setting slot_hi=1
	 * and faulting at 0x1_xxxx.
	 * v_mov_b32 v45, s17
	 */
	knod_vset32(&p[0], KNOD_AMDGPU_TMP_VREG11_HI);
	knod_sset32(&p[1], KNOD_AMDGPU_TMP_SREG0_HI);
	knod_emit(priv, meta, v_mov_b32_e32, p[0], p[1]);

	/* v44:v45 = slot_addr in pass_meta_buf */

	/* Store len: v_sub_u32 v0, DATA_END_LO, DATA_LO */
	knod_vset32(&p[0], KNOD_AMDGPU_VREG0_LO);
	knod_vset32(&p[1], KNOD_AMDGPU_DATA_END_VREG_LO);
	knod_vset32(&p[2], KNOD_AMDGPU_DATA_VREG_LO);
	knod_emit(priv, meta, v_sub_u32, p[0], p[1], p[2]);

	/* global_store_dword [slot+0], len */
	knod_vset32(&p[0], KNOD_AMDGPU_VREG0_LO);
	knod_vset32(&p[1], KNOD_AMDGPU_TMP_VREG11_LO);
	knod_emit(priv, meta, global_store_dword, p[0], p[1],
		  offsetof(struct knod_pass_slot_hdr, len));

	/* global_store_dwordx2 [slot+8], DATA_VREG (src_addr) */
	knod_vset32(&p[0], KNOD_AMDGPU_DATA_VREG_LO);
	knod_vset32(&p[1], KNOD_AMDGPU_TMP_VREG11_LO);
	knod_emit(priv, meta, global_store_dwordx2, p[0], p[1],
		  offsetof(struct knod_pass_slot_hdr, src_addr));
}

static int knod_bpf_jit(struct knod_dev *knodev,
			struct knod_prog *knod_prog)
{
	struct knod_bpf_priv *priv =
		(struct knod_bpf_priv *)knodev->accel->xdp.priv;
	short off, packet_off, stack_off;
	struct knod_insn_meta *meta, *meta2;
	struct amdgcn_param64 param64[2];
	u32 insn_idx = 0, i;
	struct amdgcn_param32 param[3];
	struct amdgcn_param32 p32[2];
	struct amdgcn_param32 p[3];
	int s, d, imm, imm2;
	int pass_branch_idx;
	bool is_dw, fetch;
	bool skip = false;
	int pass_dwords;
	int atomic_op;
	int j;
	int map_id;
	u64 imm64;
	int ret;

	/* Analyze CFG before instruction emission */
	ret = knod_bpf_analyze_cfg(priv, knod_prog);

	if (ret)
		return ret;

	knod_bpf_layout_sregs(priv, knod_prog);
	ret = knod_prog_prepare_insns(priv, knod_prog);
	if (ret)
		return ret;

	knod_prog->max_stack_off = -knod_prog->max_stack_off;
	knod_prog->max_stack_off = ALIGN(knod_prog->max_stack_off, 4);
	knod_prog->max_packet_off = ALIGN(knod_prog->max_packet_off, 4);
	/* TODO
	 * packet is accessed with packet_off + size
	 * largest size of it is unsigned long
	 */
	knod_prog->max_packet_off += sizeof(unsigned long);
	/* TODO refer to stack size */
	if (knod_prog->max_packet_off > MAX_PACKET_CACHE) {
		WARN_ON(1);
		knod_bpf_pkt_cache = 0;
	}

	/* Initialize all exec_save SGPRs to 0.
	 * Without this, merge points that restore from exec_save SGPRs
	 * of branches that were skipped (by an outer s_cbranch_execz)
	 * would OR garbage into EXEC, enabling invalid lanes.
	 * In the old code, BPF_EXIT used s_endpgm so execution never
	 * reached those merge points; now it does.
	 */
	if (knod_prog->exec_save_pairs_used > 0) {
		u8 sreg;

		meta = knod_prog_pre_last_meta(knod_prog);

		for (sreg = knod_prog->exec_save_base;
		     sreg < knod_prog->exec_save_base +
			    knod_prog->exec_save_pairs_used * 2;
		     sreg += 2)
			knod_emit(priv, meta, s_mov_b64, sreg,
				  AMDGCN_SREG_INTEGER_0);
	}

	if (knod_bpf_pkt_cache) {
		meta = knod_prog_pre_last_meta(knod_prog);

		/* ctx->data is in DATA_VREG â copy to r32[0] via v_mov */
		knod_vset32(&param[0], r32[0].v);
		knod_vset32(&param[1], KNOD_AMDGPU_DATA_VREG_LO);
		knod_emit(priv, meta, v_mov_b32_e32, param[0], param[1]);
		knod_vset32(&param[0], r32[0].v + 1);
		knod_vset32(&param[1], KNOD_AMDGPU_DATA_VREG_HI);
		knod_emit(priv, meta, v_mov_b32_e32, param[0], param[1]);

		knod_global_load_size_cache(priv, meta,
					    &pkt_cache[0],
					    r32[0],
					    0, /* dst index */
					    0, /* start offset */
					    knod_prog->max_packet_off);
	}

	insn_idx = 0;
	list_for_each_entry(meta, &knod_prog->pre_insns, l) {
		for (i = 0; i < meta->amdgpu_insns; i++)
			insn_idx += (meta->amdgpu_insn[i].size / 4);
	}

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

		switch (meta->insn.code) {
		/* ALU
		 * If a destination register contains a pointer of STACK,
		 * offset should not be minus.
		 */
		case BPF_ALU | BPF_MOV | BPF_X:
		case BPF_ALU64 | BPF_MOV | BPF_X:
			//r[d] = r[s];
			knod_mov64(priv, meta, bpf_reg64[d], bpf_reg64[s]);
			break;
		case BPF_ALU | BPF_MOV | BPF_K:
		case BPF_ALU64 | BPF_MOV | BPF_K:
			//r[d] = imm;
			knod_iset64(&p64[0], imm);
			knod_mov64(priv, meta, bpf_reg64[d], p64[0]);
			break;
		case BPF_ALU | BPF_XOR | BPF_X:
			knod_xor32(priv, meta,
				       bpf_reg64[d].lo, bpf_reg64[d].lo,
				       bpf_reg64[s].lo);
			knod_iset64(&p64[0], 0);
			knod_mov32(priv, meta, bpf_reg64[d].hi, p64[0].lo);
			break;
		case BPF_ALU64 | BPF_XOR | BPF_X:
			//r[d] ^= r[s];
			knod_xor32(priv, meta,
				       bpf_reg64[d].lo, bpf_reg64[d].lo,
				       bpf_reg64[s].lo);
			knod_xor32(priv, meta,
				       bpf_reg64[d].hi, bpf_reg64[d].hi,
				       bpf_reg64[s].hi);
			break;
		case BPF_ALU | BPF_XOR | BPF_K:
		case BPF_ALU64 | BPF_XOR | BPF_K:
			knod_iset64(&p64[0], imm);
			knod_mov64(priv, meta, bpf_reg64[d], p64[0]);
			knod_xor32(priv, meta, bpf_reg64[d].lo,
				       bpf_reg64[d].lo, r64[0].lo);
			break;
			//r[d] ^= imm;
			break;
		case BPF_ALU | BPF_MOD | BPF_X:
		case BPF_ALU64 | BPF_MOD | BPF_X:
			//r[d] %= r[s];
			knod_iset64(&p64[0], meta->umin_src);
			knod_mod(priv, meta, bpf_reg64[d], p64[0],
				     r64[0], r64[1], r64[2], r64[3], r64[4]);
			break;
		case BPF_ALU | BPF_MOD | BPF_K:
		case BPF_ALU64 | BPF_MOD | BPF_K:
			//r[d] %= imm;
			/* The dividend fits 32 bits (verifier rejects wider
			 * div/mod), so the 32-bit fold is valid even when
			 * clang emitted this as a 64-bit ALU op (e.g. u32
			 * hash % 65537 -> `r2 %= 65537`).
			 */
			if (meta->umax_dst <= U32_MAX && imm &&
			    knod_mod_k32(priv, meta, bpf_reg64[d], imm))
				break;
			knod_iset64(&p64[0], imm);
			knod_mod(priv, meta, bpf_reg64[d], p64[0],
				     r64[0], r64[1], r64[2], r64[3], r64[4]);
			break;
		case BPF_ALU | BPF_AND | BPF_X:
			knod_and32(priv, meta, bpf_reg64[d].lo,
				       bpf_reg64[d].lo, bpf_reg64[s].lo);
			knod_iset32(&p32[0], 0);
			knod_mov32(priv, meta, bpf_reg64[d].hi, p32[0]);
			break;
		case BPF_ALU64 | BPF_AND | BPF_X:
			//r[d] &= r[s];
			knod_and64(priv, meta, bpf_reg64[d],
				       bpf_reg64[d], bpf_reg64[s]);
			break;
		case BPF_ALU | BPF_AND | BPF_K:
		case BPF_ALU64 | BPF_AND | BPF_K:
			//r[d] &= imm;
			knod_iset32(&p32[0], imm);
			knod_and32(priv, meta, bpf_reg64[d].lo, p32[0],
				       bpf_reg64[d].lo);
			knod_iset32(&p32[0], 0);
			knod_mov32(priv, meta, bpf_reg64[d].hi, p32[0]);
			break;
		case BPF_ALU | BPF_OR | BPF_X:
			knod_or32(priv, meta, bpf_reg64[d].lo,
				  bpf_reg64[d].lo, bpf_reg64[s].lo);
			knod_iset32(&p32[0], 0);
			knod_mov32(priv, meta, bpf_reg64[d].hi, p32[0]);
			break;
		case BPF_ALU64 | BPF_OR | BPF_X:
			//r[d] |= r[s];
			knod_or32(priv, meta, bpf_reg64[d].lo,
				  bpf_reg64[d].lo, bpf_reg64[s].lo);
			knod_or32(priv, meta, bpf_reg64[d].hi,
				  bpf_reg64[d].hi, bpf_reg64[s].hi);
			break;
		case BPF_ALU | BPF_OR | BPF_K:
		case BPF_ALU64 | BPF_OR | BPF_K:
			//r[d] |= imm;
			knod_iset32(&p32[0], imm);
			knod_or32(priv, meta,
				bpf_reg64[d].lo, p32[0], bpf_reg64[d].lo);
			knod_iset32(&p32[0], 0);
			knod_mov32(priv, meta, bpf_reg64[d].hi, p32[0]);
			break;
		case BPF_ALU | BPF_ADD | BPF_X:
			knod_add32(priv, meta, bpf_reg64[d].lo,
				       bpf_reg64[d].lo, bpf_reg64[s].lo);
			knod_iset32(&p32[0], 0);
			knod_mov32(priv, meta, bpf_reg64[d].hi, p32[0]);
			break;
		case BPF_ALU64 | BPF_ADD | BPF_X:
			knod_add64(priv, meta, bpf_reg64[d],
				       bpf_reg64[d],
				       bpf_reg64[s]);

			//r[d] += r[s];
			break;
		case BPF_ALU | BPF_ADD | BPF_K:
		case BPF_ALU64 | BPF_ADD | BPF_K:
			//r[d] += imm;
			knod_iset32(&p32[0], imm);
			knod_add32(priv, meta, bpf_reg64[d].lo,
				       p32[0], bpf_reg64[d].lo);
			/* TODO
			 * imm is 24bit.
			 * But should we set hi to 0?
			 */
			knod_iset32(&p32[0], 0);
			knod_mov32(priv, meta, bpf_reg64[d].hi, p32[0]);
			break;
		case BPF_ALU | BPF_SUB | BPF_X:
			//r[d] -= r[s];
			knod_sub32(priv, meta, bpf_reg64[d].lo,
				       bpf_reg64[d].lo, bpf_reg64[s].lo);
			knod_iset32(&p32[0], 0);
			knod_mov32(priv, meta, bpf_reg64[d].hi, p32[0]);
			break;
		case BPF_ALU64 | BPF_SUB | BPF_X:
			//r[d] -= r[s];

			knod_sub64(priv, meta, bpf_reg64[d], bpf_reg64[d],
				       bpf_reg64[s]);
			break;
		case BPF_ALU | BPF_SUB | BPF_K:
		case BPF_ALU64 | BPF_SUB | BPF_K:
			//r[d] -= imm;
			knod_iset64(&p64[0], imm);
			knod_subrev64(priv, meta, bpf_reg64[d], p64[0],
					  bpf_reg64[s]);
			break;
		case BPF_ALU | BPF_MUL | BPF_X:
			knod_mul_lo32(priv, meta, bpf_reg64[d].lo,
					  bpf_reg64[d].lo, bpf_reg64[s].lo);
			break;
		case BPF_ALU64 | BPF_MUL | BPF_X:
			//r[d] *= r[s];
			knod_mov64(priv, meta, r64[0], bpf_reg64[d]);
			knod_mov64(priv, meta, r64[1], bpf_reg64[s]);
			/* TODO knod_mul64 source register value corruption */
			knod_mul64(priv, meta,
				       bpf_reg64[d],
				       r64[0],
				       r64[1],
				       r64[2]);
			break;
		case BPF_ALU | BPF_MUL | BPF_K:
			knod_iset32(&p32[0], imm);
			knod_mul_lo32(priv, meta, bpf_reg64[d].lo,
					  p32[0], bpf_reg64[d].lo);
			knod_iset32(&p32[0], 0);
			knod_mov32(priv, meta, bpf_reg64[d].hi, p32[0]);
			break;
		case BPF_ALU64 | BPF_MUL | BPF_K:
			//r[d] *= imm;
			knod_iset64(&p64[0], imm);
			knod_mov64(priv, meta, r64[0], bpf_reg64[d]);
			knod_mov64(priv, meta, r64[1], p64[0]);
			knod_mul64(priv, meta,
				       bpf_reg64[d],
				       r64[0],
				       r64[1],
				       r64[2]);
			break;
		case BPF_ALU | BPF_DIV | BPF_X:
		case BPF_ALU64 | BPF_DIV | BPF_X:
			//r[d] /= r[s];
			knod_iset64(&p64[0], meta->umin_src);
			knod_div(priv, meta, bpf_reg64[d], p64[0],
				     r64[0], r64[1], r64[2], r64[3]);
			break;
		case BPF_ALU | BPF_DIV | BPF_K:
		case BPF_ALU64 | BPF_DIV | BPF_K:
			//r[d] /= imm;
			knod_iset64(&p64[0], imm);
			knod_div(priv, meta, bpf_reg64[d], p64[0],
				     r64[0], r64[1], r64[2], r64[3]);
			break;
		case BPF_ALU | BPF_NEG:
			knod_iset32(&p32[0], 0);
			knod_sub32(priv, meta, bpf_reg64[d].lo, p32[0],
				       bpf_reg64[d].lo);
			knod_iset32(&p32[0], 0);
			knod_mov32(priv, meta, bpf_reg64[d].hi, p32[0]);
			break;
		case BPF_ALU64 | BPF_NEG:
			//r[d] = -r[d];
			WARN_ON(1);
			break;
		case BPF_ALU | BPF_LSH | BPF_X:
			knod_lshlrev32(priv, meta, bpf_reg64[d].lo,
					   bpf_reg64[s].lo, bpf_reg64[d].lo);
			knod_iset32(&p32[0], 0);
			knod_mov32(priv, meta, bpf_reg64[d].hi, p32[0]);
			break;
		case BPF_ALU64 | BPF_LSH | BPF_X:
			//r[d] <<= r[s];
			knod_lshlrev64(priv, meta, bpf_reg64[d],
					   bpf_reg64[s], bpf_reg64[d]);
			break;
		case BPF_ALU | BPF_LSH | BPF_K:
			knod_iset32(&p32[0], imm);
			knod_lshlrev32(priv, meta, bpf_reg64[d].lo, p32[0],
					   bpf_reg64[d].lo);
			knod_iset32(&p32[0], 0);
			knod_mov32(priv, meta, bpf_reg64[d].hi, p32[0]);
			break;
		case BPF_ALU64 | BPF_LSH | BPF_K:
			//r[d] <<= imm;
			knod_iset64(&p64[0], imm);
			knod_lshlrev64(priv, meta, bpf_reg64[d], p64[0],
					   bpf_reg64[d]);
			break;
		case BPF_ALU | BPF_RSH | BPF_X:
			knod_lshrrev32(priv, meta, bpf_reg64[d].lo,
				       bpf_reg64[s].lo,
				       bpf_reg64[d].lo);
			knod_iset32(&p32[0], 0);
			knod_mov32(priv, meta, bpf_reg64[d].hi, p32[0]);
			break;
		case BPF_ALU64 | BPF_RSH | BPF_X:
			//r[d] >>= r[s];
			knod_lshrrev64(priv, meta, bpf_reg64[d],
					   bpf_reg64[s], bpf_reg64[d]);
			break;
		case BPF_ALU | BPF_RSH | BPF_K:
			knod_iset32(&p32[0], imm);
			knod_lshrrev32(priv, meta, bpf_reg64[d].lo, p32[0],
					   bpf_reg64[d].lo);
			knod_iset32(&p32[0], 0);
			knod_mov32(priv, meta, bpf_reg64[d].hi, p32[0]);
			break;
		case BPF_ALU64 | BPF_RSH | BPF_K:
			//r[d] >>= imm;
			knod_iset64(&p64[0], imm);
			knod_lshrrev64(priv, meta, bpf_reg64[d],
					   p64[0], bpf_reg64[d]);
			break;
		case BPF_ALU | BPF_ARSH | BPF_X:
			knod_ashrrev32(priv, meta, bpf_reg64[d].lo,
					   bpf_reg64[s].lo, bpf_reg64[d].lo);
			knod_iset32(&p32[0], 0);
			knod_mov32(priv, meta, bpf_reg64[d].hi, p32[0]);
			break;
		case BPF_ALU64 | BPF_ARSH | BPF_X:
			//r[d] >>= r[s];
			knod_ashrrev64(priv, meta, bpf_reg64[d],
					   bpf_reg64[s], bpf_reg64[d]);
			break;
		case BPF_ALU | BPF_ARSH | BPF_K:
			knod_iset32(&p32[0], imm);
			knod_ashrrev32(priv, meta, bpf_reg64[d].lo,
					   p32[0], bpf_reg64[d].lo);
			knod_iset32(&p32[0], 0);
			knod_mov32(priv, meta, bpf_reg64[d].hi, p32[0]);
			break;
		case BPF_ALU64 | BPF_ARSH | BPF_K:
			//r[d] >>= imm;
			knod_iset64(&p64[0], imm);
			knod_ashrrev64(priv, meta, bpf_reg64[d],
					   p64[0], bpf_reg64[d]);
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
				//r[d] = imm64;
				knod_mov64_imm(priv, meta, d * 2,
						   imm64);

				break;
			case 0x01:
				/* r[d] = param->maps[imm]; */
				imm64 = knod_bpf_get_map_gaddr(priv,
							       meta,
							       meta2);
				map_id = knod_bpf_get_map_id(priv,
							     meta,
							     meta2);
				knod_mov64_imm(priv, meta, d * 2,
						   imm64);
				break;
			default:
				WARN_ON(1);
				break;
			}
			break;
			/* Legacy BPF packet access, not needed */
		case BPF_LD | BPF_ABS | BPF_B:
		case BPF_LD | BPF_ABS | BPF_H:
		case BPF_LD | BPF_ABS | BPF_W:
		case BPF_LD | BPF_IND | BPF_B:
		case BPF_LD | BPF_IND | BPF_H:
		case BPF_LD | BPF_IND | BPF_W:
			//err = pc | 0x0700;
			//exit = true;
			WARN_ON(1);
			break;
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
				if (knod_bpf_pkt_cache) {
					packet_off = meta->sreg.packet_off +
						off;
					knod_bpf_load_size(priv, meta,
							       &bpf_reg64[d],
							       &pkt_cache[0],
							sizeof(unsigned char),
							       packet_off);
				} else {
					knod_emit(priv, meta, global_load_ubyte,
						  bpf_reg64[d].lo,
						  bpf_reg64[s].lo, off);
				}
			} else {
				WARN_ON(1);
			}
			knod_wait_vmcnt(priv, meta);
			knod_iset32(&p32[0], 0);
			knod_mov32(priv, meta, bpf_reg64[d].hi, p32[0]);
			//ptr = (__global void *)r[s] + off;
			//r[d] = *(__global unsigned char *)ptr;
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
				if (knod_bpf_pkt_cache) {
					packet_off = meta->sreg.packet_off +
						off;
					knod_bpf_load_size(priv, meta,
							       &bpf_reg64[d],
							       &pkt_cache[0],
							sizeof(unsigned short),
							       packet_off);
				} else if (priv->isa_version == 10 &&
					   (off & 1)) {
					knod_bpf_emit_gfx10_unaligned_load(
						priv, meta,
						sizeof(unsigned short),
						bpf_reg64[d],
						bpf_reg64[s].lo, off);
				} else {
					knod_emit(priv, meta,
						  global_load_ushort,
						  bpf_reg64[d].lo,
						  bpf_reg64[s].lo, off);
				}
			} else {
				knod_jit_err(" type = %d\n", meta->ptr.type);
				WARN_ON(1);
			}
			//ptr = (__global void *)r[s] + off;
			//r[d] = *(__global unsigned short *)ptr;
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
					debug_insn(priv->isa_version,
						   &meta->amdgpu_insn[meta->amdgpu_insns]);
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
				if (knod_bpf_pkt_cache) {
					packet_off = meta->sreg.packet_off +
						off;
					knod_bpf_load_size(priv, meta,
							       &bpf_reg64[d],
							       &pkt_cache[0],
							sizeof(unsigned int),
							       packet_off);
				} else if (priv->isa_version == 10 &&
					   (off & 3)) {
					knod_bpf_emit_gfx10_unaligned_load(
						priv, meta,
						sizeof(unsigned int),
						bpf_reg64[d],
						bpf_reg64[s].lo, off);
				} else {
					knod_emit(priv, meta, global_load_dword,
						  bpf_reg64[d].lo,
						  bpf_reg64[s].lo, off);
				}
			} else {
				WARN_ON(1);
			}
			//ptr = (__global void *)r[s] + off;
			//r[d] = *(__global unsigned int *)ptr;
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
				if (knod_bpf_pkt_cache) {
					packet_off = meta->sreg.packet_off +
						off;
					knod_bpf_load_size(priv, meta,
							       &bpf_reg64[d],
							       &pkt_cache[0],
							sizeof(unsigned long),
							       packet_off);
				} else if (priv->isa_version == 10 &&
					   (off & 3)) {
					knod_bpf_emit_gfx10_unaligned_load(
						priv, meta,
						sizeof(unsigned long),
						bpf_reg64[d],
						bpf_reg64[s].lo, off);
				} else {
					knod_emit(priv, meta,
						  global_load_dwordx2,
						  bpf_reg64[d].lo,
						  bpf_reg64[s].lo, off);
				}
			} else {
				WARN_ON(1);
			}
			//ptr = (__global void *)r[s] + off;
			//r[d] = *(__global unsigned long *)ptr;
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
				if (knod_bpf_pkt_cache) {
					packet_off = meta->dreg.packet_off +
						off;
					knod_bpf_store_cache_size(priv,
							meta,
							&bpf_reg64[s],
							&pkt_cache[0],
							sizeof(u8),
							packet_off);
				} else {
					knod_emit(priv, meta, global_store_byte,
						  bpf_reg64[s].lo,
						  bpf_reg64[d].lo, off);
				}
			} else {
				WARN_ON(1);
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
				if (knod_bpf_pkt_cache) {
					packet_off = meta->dreg.packet_off +
						off;
					knod_bpf_store_cache_size(priv,
							meta,
							&bpf_reg64[s],
							&pkt_cache[0],
							sizeof(u16),
							packet_off);
				} else {
					knod_emit(priv, meta,
						  global_store_short,
						  bpf_reg64[s].lo,
						  bpf_reg64[d].lo, off);
				}
			} else {
				WARN_ON(1);
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
				if (knod_bpf_pkt_cache) {
					packet_off = meta->dreg.packet_off +
						off;
					knod_bpf_store_cache_size(priv,
							meta,
							&bpf_reg64[s],
							&pkt_cache[0],
							sizeof(u32),
							packet_off);
				} else {
					knod_emit(priv, meta,
						  global_store_dword,
						  bpf_reg64[s].lo,
						  bpf_reg64[d].lo, off);
				}
			} else {
				WARN_ON(1);
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
				if (knod_bpf_pkt_cache) {
					packet_off = meta->dreg.packet_off +
						off;
					knod_bpf_store_cache_size(priv, meta,
							&bpf_reg64[s],
							&pkt_cache[0],
							sizeof(u64),
							packet_off);
				} else {
					knod_emit(priv, meta,
						  global_store_dwordx2,
						  bpf_reg64[s].lo,
						  bpf_reg64[d].lo, off);
				}
			} else {
				WARN_ON(1);
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
			 * 64-bit atomics (global_atomic_*_x2) hang on GFX9
			 * VRAM. GFX10+ supports them.
			 */
			if (is_dw && priv->isa_version == 9) {
				pr_err("knod: 64-bit atomic not supported on GFX9\n");
				return -EOPNOTSUPP;
			}

			/*
			 * For CMPXCHG/FETCH: drain pending loads so addr/data
			 * VGPRs are ready. For non-fetch ADD wave reduction,
			 * addr was already waited for at map_lookup, and data
			 * is from ALU — no waitcnt needed.
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
					debug_insn(priv->isa_version,
						   &meta->amdgpu_insn[meta->amdgpu_insns]);
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
					debug_insn(priv->isa_version,
						   &meta->amdgpu_insn[meta->amdgpu_insns]);
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
				/*
				 * Wave reduction for BPF_ADD (non-fetch):
				 * Instead of all lanes doing atomic_add(val),
				 * count active lanes, multiply by val, and
				 * have a single lane do atomic_add(count*val).
				 *
				 * Assumes src_reg is uniform across all active
				 * lanes (true for constant increments like
				 * +=1).
				 *
				 *   s_bcnt1_i32_b64 s_tmp, exec
				 *   v_mul_lo_u32    v_tmp, s_tmp, v_src
				 *   v_mbcnt_lo      v_tmp2, exec_lo, 0
				 *   v_mbcnt_hi      v_tmp2, exec_hi, v_tmp2
				 *   v_cmp_eq_u32    vcc, v_tmp2, 0
				 *   s_and_saveexec  s_save, vcc
				 *   global_atomic_add addr, v_tmp, off
				 *   s_waitcnt       vmcnt(0)
				 *   s_mov_b64       exec, s_save
				 */
				struct amdgcn_param32 v_tmp, v_tmp2,
						      s_count, s_exec_lo,
						      s_exec_hi, v_zero;

				knod_vset32(&v_tmp,
					KNOD_AMDGPU_TMP_VREG0_LO);
				knod_vset32(&v_tmp2,
					KNOD_AMDGPU_TMP_VREG0_HI);
				knod_sset32(&s_count,
					KNOD_AMDGPU_TMP_SREG0_LO);
				knod_sset32(&s_exec_lo,
					AMDGCN_SREG_EXEC_LO);
				knod_sset32(&s_exec_hi,
					AMDGCN_SREG_EXEC_LO + 1);
				knod_iset32(&v_zero, 0);

				/* s_bcnt1_i32_b64 s_count, exec */
				knod_emit(priv, meta, s_bcnt1_i32_b64,
					  KNOD_AMDGPU_TMP_SREG0_LO,
					  AMDGCN_SREG_EXEC_LO);

				/* v_mul_lo_u32 v_tmp, s_count, v_src */
				knod_emit(priv, meta, v_mul_lo_u32, v_tmp,
					  s_count, bpf_reg64[s].lo);

				/* v_mbcnt_lo_u32_b32 v_tmp2, exec_lo, 0 */
				knod_emit(priv, meta, v_mbcnt_lo_u32_b32,
					  v_tmp2, s_exec_lo, v_zero);

				/* v_mbcnt_hi_u32_b32 v_tmp2, exec_hi, v_tmp2 */
				knod_emit(priv, meta, v_mbcnt_hi_u32_b32,
					  v_tmp2, s_exec_hi, v_tmp2);

				/* v_cmp_eq_u32 vcc, 0, v_tmp2 →
				 * first active lane
				 */
				knod_emit(priv, meta, v_cmp_eq_u32, v_zero,
					  v_tmp2);

				/* s_and_saveexec_b64 s_save, vcc */
				knod_emit(priv, meta, s_and_saveexec_b64,
					  KNOD_AMDGPU_TMP_SREG0_LO,
					  AMDGCN_SREG_VCC_LO);

				if (is_dw) {
					struct amdgcn_param32 v_tmp_hi;

					knod_vset32(&v_tmp_hi,
						KNOD_AMDGPU_TMP_VREG0_HI);
					/*
					 * x2 atomics consume a consecutive
					 * VGPR pair, and the 32-bit addend
					 * lands in the host-visible low dword
					 * when it is placed in the second
					 * register.
					 */
					knod_emit(priv, meta, v_mov_b32_e32,
						  v_tmp_hi, v_tmp);
					knod_emit(priv, meta, v_mov_b32_e32,
						  v_tmp, v_zero);
					/* global_atomic_add_x2 addr,
					 * {0, v_tmp_hi}, off
					 */
					knod_emit(priv, meta,
						  global_atomic_add_x2, v_tmp,
						  bpf_reg64[d].lo, v_tmp, off,
						  0);
				} else {
					/* global_atomic_add addr, v_tmp, off
					 * (single lane)
					 */
					knod_emit(priv, meta, global_atomic_add,
						  v_tmp,
						  bpf_reg64[d].lo, v_tmp, off,
						  0);
				}

				/*
				 * No s_waitcnt needed: glc=0 atomic doesn't
				 * increment vmcnt. The GPU guarantees all
				 * pending ops complete before wave exit.
				 */

				/* s_mov_b64 exec, s_save */
				knod_emit(priv, meta, s_mov_b64,
					  AMDGCN_SREG_EXEC_LO,
					  KNOD_AMDGPU_TMP_SREG0_LO);
			} else if (!is_dw) {
				/* 32-bit: AND, OR, XOR, XCHG, or fetch ops */
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
					emit_global_atomic_add(
						priv->isa_version,
						&meta->amdgpu_insn[meta->amdgpu_insns],
						vdst, bpf_reg64[d].lo,
						data_p, off, fetch);
					break;
				case BPF_AND:
					emit_global_atomic_and(
						priv->isa_version,
						&meta->amdgpu_insn[meta->amdgpu_insns],
						vdst, bpf_reg64[d].lo,
						data_p, off, fetch);
					break;
				case BPF_OR:
					emit_global_atomic_or(
						priv->isa_version,
						&meta->amdgpu_insn[meta->amdgpu_insns],
						vdst, bpf_reg64[d].lo,
						data_p, off, fetch);
					break;
				case BPF_XOR:
					emit_global_atomic_xor(
						priv->isa_version,
						&meta->amdgpu_insn[meta->amdgpu_insns],
						vdst, bpf_reg64[d].lo,
						data_p, off, fetch);
					break;
				default: /* BPF_XCHG */
					emit_global_atomic_swap(
						priv->isa_version,
						&meta->amdgpu_insn[meta->amdgpu_insns],
						vdst, bpf_reg64[d].lo,
						data_p, off, fetch);
					break;
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
				debug_insn(priv->isa_version,
					   &meta->amdgpu_insn[meta->amdgpu_insns]);
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
				if (knod_bpf_pkt_cache) {
					packet_off = meta->dreg.packet_off +
						off;
					knod_bpf_store_cache_size(priv,
							meta,
							&p64[0],
							&pkt_cache[0],
							sizeof(u8),
							packet_off);
				} else {
					knod_emit(priv, meta, global_store_byte,
						  p64[0].lo,
						  bpf_reg64[d].lo, off);
				}
			} else {
				WARN_ON(1);
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
				if (knod_bpf_pkt_cache) {
					packet_off = meta->dreg.packet_off +
						off;
					knod_bpf_store_cache_size(priv,
							meta,
							&p64[0],
							&pkt_cache[0],
							sizeof(u16),
							packet_off);
				} else {
					knod_emit(priv, meta,
						  global_store_short, p64[0].lo,
						  bpf_reg64[d].lo, off);
				}
			} else {
				WARN_ON(1);
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
				if (knod_bpf_pkt_cache) {
					packet_off = meta->dreg.packet_off +
						off;
					knod_bpf_store_cache_size(priv,
							meta,
							&p64[0],
							&pkt_cache[0],
							sizeof(u32),
							packet_off);
				} else {
					knod_emit(priv, meta,
						  global_store_dword, p64[0].lo,
						  bpf_reg64[d].lo, off);
				}
			} else {
				WARN_ON(1);
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
				if (knod_bpf_pkt_cache) {
					packet_off = meta->dreg.packet_off +
						off;
					knod_bpf_store_cache_size(priv, meta,
							&p64[0],
							&pkt_cache[0],
							sizeof(u64),
							packet_off);
				} else {
					knod_emit(priv, meta,
						  global_store_dwordx2,
						  p64[0].lo,
						  bpf_reg64[d].lo, off);
				}
				knod_iset32(&p32[0], imm);
			} else {
				WARN_ON(1);
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
				WARN_ON(1);
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
				WARN_ON(1);
			}
			break;
		case BPF_JMP32 | BPF_JEQ | BPF_K:
			knod_vset32(&param[0], KNOD_AMDGPU_TMP_VREG0_LO);
			knod_iset32(&param[1], imm);
			knod_emit(priv, meta, v_mov_b32_e32, param[0],
				  param[1]);
			knod_vset32(&param[0], d * 2);
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
			knod_iset32(&param[1], 0);
			knod_emit(priv, meta, v_mov_b32_e32, param[0],
				  param[1]);
			knod_vset32(&param[0], d * 2);
			knod_vset32(&param[1], KNOD_AMDGPU_TMP_VREG0_LO);
			knod_emit(priv, meta, v_cmp_eq_u64, param[0],
				  param[1]);
			knod_bpf_emit_branch_tail(priv, meta, knod_prog, off);
			break;
		case BPF_JMP32 | BPF_JEQ | BPF_X:
			knod_vset32(&param[0], d * 2);
			knod_vset32(&param[1], s * 2);
			knod_emit(priv, meta, v_cmp_eq_u32, param[0],
				  param[1]);
			knod_bpf_emit_branch_tail(priv, meta, knod_prog, off);
			break;
		case BPF_JMP | BPF_JEQ | BPF_X:
			knod_vset32(&param[0], d * 2);
			knod_vset32(&param[1], s * 2);
			knod_emit(priv, meta, v_cmp_eq_u64, param[0],
				  param[1]);
			knod_bpf_emit_branch_tail(priv, meta, knod_prog, off);
			break;
		case BPF_JMP32 | BPF_JGT | BPF_K:
			knod_vset32(&param[0], KNOD_AMDGPU_TMP_VREG0_LO);
			knod_iset32(&param[1], imm);
			knod_emit(priv, meta, v_mov_b32_e32, param[0],
				  param[1]);
			knod_vset32(&param[0], d * 2);
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
			knod_iset32(&param[1], 0);
			knod_emit(priv, meta, v_mov_b32_e32, param[0],
				  param[1]);
			knod_vset64(&param64[0], d * 2);
			knod_vset64(&param64[1], KNOD_AMDGPU_TMP_VREG0_LO);
			knod_emit(priv, meta, v_cmp_gt_u64, param64[0],
				  param64[1]);
			knod_bpf_emit_branch_tail(priv, meta, knod_prog, off);
			break;
		case BPF_JMP32 | BPF_JGT | BPF_X:
			knod_vset32(&param[0], d * 2);
			knod_vset32(&param[1], s * 2);
			knod_emit(priv, meta, v_cmp_gt_u32, param[0],
				  param[1]);
			knod_bpf_emit_branch_tail(priv, meta, knod_prog, off);
			break;
		case BPF_JMP | BPF_JGT | BPF_X:
			knod_vset64(&param64[0], d * 2);
			knod_vset64(&param64[1], s * 2);
			knod_emit(priv, meta, v_cmp_gt_u64, param64[0],
				  param64[1]);
			knod_bpf_emit_branch_tail(priv, meta, knod_prog, off);
			break;
		case BPF_JMP32 | BPF_JGE | BPF_K:
			knod_vset32(&param[0], KNOD_AMDGPU_TMP_VREG0_LO);
			knod_iset32(&param[1], imm);
			knod_emit(priv, meta, v_mov_b32_e32, param[0],
				  param[1]);
			knod_vset32(&param[0], d * 2);
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
			knod_iset32(&param[1], 0);
			knod_emit(priv, meta, v_mov_b32_e32, param[0],
				  param[1]);
			knod_vset64(&param64[0], d * 2);
			knod_vset64(&param64[1], KNOD_AMDGPU_TMP_VREG0_LO);
			knod_emit(priv, meta, v_cmp_ge_u64, param64[0],
				  param64[1]);
			knod_bpf_emit_branch_tail(priv, meta, knod_prog, off);
			break;
		case BPF_JMP32 | BPF_JGE | BPF_X:
			knod_vset32(&param[0], d * 2);
			knod_vset32(&param[1], s * 2);
			knod_emit(priv, meta, v_cmp_ge_u32, param[0],
				  param[1]);
			knod_bpf_emit_branch_tail(priv, meta, knod_prog, off);
			break;
		case BPF_JMP | BPF_JGE | BPF_X:
			knod_vset64(&param64[0], d * 2);
			knod_vset64(&param64[1], s * 2);
			knod_emit(priv, meta, v_cmp_ge_u64, param64[0],
				  param64[1]);
			knod_bpf_emit_branch_tail(priv, meta, knod_prog, off);
			break;
		case BPF_JMP32 | BPF_JLT | BPF_K:
			knod_vset32(&param[0], KNOD_AMDGPU_TMP_VREG0_LO);
			knod_iset32(&param[1], imm);
			knod_emit(priv, meta, v_mov_b32_e32, param[0],
				  param[1]);
			knod_vset32(&param[0], d * 2);
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
			knod_iset32(&param[1], 0);
			knod_emit(priv, meta, v_mov_b32_e32, param[0],
				  param[1]);
			knod_vset64(&param64[0], d * 2);
			knod_vset64(&param64[1], KNOD_AMDGPU_TMP_VREG0_LO);
			knod_emit(priv, meta, v_cmp_lt_u64, param64[0],
				  param64[1]);
			knod_bpf_emit_branch_tail(priv, meta, knod_prog, off);
			break;
		case BPF_JMP32 | BPF_JLT | BPF_X:
			knod_vset32(&param[0], d * 2);
			knod_vset32(&param[1], s * 2);
			knod_emit(priv, meta, v_cmp_lt_u32, param[0],
				  param[1]);
			knod_bpf_emit_branch_tail(priv, meta, knod_prog, off);
			break;
		case BPF_JMP | BPF_JLT | BPF_X:
			knod_vset64(&param64[0], d * 2);
			knod_vset64(&param64[1], s * 2);
			knod_emit(priv, meta, v_cmp_lt_u64, param64[0],
				  param64[1]);
			knod_bpf_emit_branch_tail(priv, meta, knod_prog, off);
			break;
		case BPF_JMP32 | BPF_JLE | BPF_K:
			knod_vset32(&param[0], KNOD_AMDGPU_TMP_VREG0_LO);
			knod_iset32(&param[1], imm);
			knod_emit(priv, meta, v_mov_b32_e32, param[0],
				  param[1]);
			knod_vset32(&param[0], d * 2);
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
			knod_iset32(&param[1], 0);
			knod_emit(priv, meta, v_mov_b32_e32, param[0],
				  param[1]);
			knod_vset64(&param64[0], d * 2);
			knod_vset64(&param64[1], KNOD_AMDGPU_TMP_VREG0_LO);
			knod_emit(priv, meta, v_cmp_le_u64, param64[0],
				  param64[1]);
			knod_bpf_emit_branch_tail(priv, meta, knod_prog, off);
			break;
		case BPF_JMP32 | BPF_JLE | BPF_X:
			knod_vset32(&param[0], d * 2);
			knod_vset32(&param[1], s * 2);
			knod_emit(priv, meta, v_cmp_le_u32, param[0],
				  param[1]);
			knod_bpf_emit_branch_tail(priv, meta, knod_prog, off);
			break;
		case BPF_JMP | BPF_JLE | BPF_X:
			knod_vset64(&param64[0], d * 2);
			knod_vset64(&param64[1], 2 * 2);
			knod_emit(priv, meta, v_cmp_le_u64, param64[0],
				  param64[1]);
			knod_bpf_emit_branch_tail(priv, meta, knod_prog, off);
			break;
		case BPF_JMP32 | BPF_JSGT | BPF_K:
			knod_vset32(&param[0], KNOD_AMDGPU_TMP_VREG0_LO);
			knod_iset32(&param[1], imm);
			knod_emit(priv, meta, v_mov_b32_e32, param[0],
				  param[1]);
			knod_vset32(&param[0], d * 2);
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
			knod_iset32(&param[1], 0);
			knod_emit(priv, meta, v_mov_b32_e32, param[0],
				  param[1]);
			knod_vset64(&param64[0], d * 2);
			knod_vset64(&param64[1], KNOD_AMDGPU_TMP_VREG0_LO);
			knod_emit(priv, meta, v_cmp_gt_i64, param64[0],
				  param64[1]);
			knod_bpf_emit_branch_tail(priv, meta, knod_prog, off);
			break;
		case BPF_JMP32 | BPF_JSGT | BPF_X:
			knod_vset32(&param[0], d * 2);
			knod_vset32(&param[1], s * 2);
			knod_emit(priv, meta, v_cmp_gt_i32, param[0],
				  param[1]);
			knod_bpf_emit_branch_tail(priv, meta, knod_prog, off);
			break;
		case BPF_JMP | BPF_JSGT | BPF_X:
			knod_vset64(&param64[0], d * 2);
			knod_vset64(&param64[1], s * 2);
			knod_emit(priv, meta, v_cmp_gt_i64, param64[0],
				  param64[1]);
			knod_bpf_emit_branch_tail(priv, meta, knod_prog, off);
			break;
		case BPF_JMP32 | BPF_JSGE | BPF_K:
			knod_vset32(&param[0], KNOD_AMDGPU_TMP_VREG0_LO);
			knod_iset32(&param[1], imm);
			knod_emit(priv, meta, v_mov_b32_e32, param[0],
				  param[1]);
			knod_vset32(&param[0], d * 2);
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
			knod_iset32(&param[1], 0);
			knod_emit(priv, meta, v_mov_b32_e32, param[0],
				  param[1]);
			knod_vset64(&param64[0], d * 2);
			knod_vset64(&param64[1], KNOD_AMDGPU_TMP_VREG0_LO);
			knod_emit(priv, meta, v_cmp_ge_i64, param64[0],
				  param64[1]);
			knod_bpf_emit_branch_tail(priv, meta, knod_prog, off);
			break;
		case BPF_JMP32 | BPF_JSGE | BPF_X:
			knod_vset32(&param[0], d * 2);
			knod_vset32(&param[1], s * 2);
			knod_emit(priv, meta, v_cmp_ge_i32, param[0],
				  param[1]);
			knod_bpf_emit_branch_tail(priv, meta, knod_prog, off);
			break;
		case BPF_JMP | BPF_JSGE | BPF_X:
			knod_vset64(&param64[0], d * 2);
			knod_vset64(&param64[1], s * 2);
			knod_emit(priv, meta, v_cmp_ge_i64, param64[0],
				  param64[1]);
			knod_bpf_emit_branch_tail(priv, meta, knod_prog, off);
			break;
		case BPF_JMP32 | BPF_JSLT | BPF_K:
			knod_vset32(&param[0], KNOD_AMDGPU_TMP_VREG0_LO);
			knod_iset32(&param[1], imm);
			knod_emit(priv, meta, v_mov_b32_e32, param[0],
				  param[1]);
			knod_vset32(&param[0], d * 2);
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
			knod_iset32(&param[1], 0);
			knod_emit(priv, meta, v_mov_b32_e32, param[0],
				  param[1]);
			knod_vset64(&param64[0], d * 2);
			knod_vset64(&param64[1], KNOD_AMDGPU_TMP_VREG0_LO);
			knod_emit(priv, meta, v_cmp_lt_i64, param64[0],
				  param64[1]);
			knod_bpf_emit_branch_tail(priv, meta, knod_prog, off);
			break;
		case BPF_JMP32 | BPF_JSLT | BPF_X:
			knod_vset32(&param[0], d * 2);
			knod_vset32(&param[1], s * 2);
			knod_emit(priv, meta, v_cmp_lt_i32, param[0],
				  param[1]);
			knod_bpf_emit_branch_tail(priv, meta, knod_prog, off);
			break;
		case BPF_JMP | BPF_JSLT | BPF_X:
			knod_vset64(&param64[0], d * 2);
			knod_vset64(&param64[1], s * 2);
			knod_emit(priv, meta, v_cmp_lt_i64, param64[0],
				  param64[1]);
			knod_bpf_emit_branch_tail(priv, meta, knod_prog, off);
			break;
		case BPF_JMP32 | BPF_JSLE | BPF_K:
			knod_vset32(&param[0], KNOD_AMDGPU_TMP_VREG0_LO);
			knod_iset32(&param[1], imm);
			knod_emit(priv, meta, v_mov_b32_e32, param[0],
				  param[1]);
			knod_vset32(&param[0], d * 2);
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
			knod_iset32(&param[1], 0);
			knod_emit(priv, meta, v_mov_b32_e32, param[0],
				  param[1]);
			knod_vset64(&param64[0], d * 2);
			knod_vset64(&param64[1], KNOD_AMDGPU_TMP_VREG0_LO);
			knod_emit(priv, meta, v_cmp_le_i64, param64[0],
				  param64[1]);
			knod_bpf_emit_branch_tail(priv, meta, knod_prog, off);
			break;
		case BPF_JMP32 | BPF_JSLE | BPF_X:
			knod_vset32(&param[0], d * 2);
			knod_vset32(&param[1], s * 2);
			knod_emit(priv, meta, v_cmp_le_i32, param[0],
				  param[1]);
			knod_bpf_emit_branch_tail(priv, meta, knod_prog, off);
			break;
		case BPF_JMP | BPF_JSLE | BPF_X:
			knod_vset64(&param64[0], d * 2);
			knod_vset64(&param64[1], s * 2);
			knod_emit(priv, meta, v_cmp_le_i64, param64[0],
				  param64[1]);
			knod_bpf_emit_branch_tail(priv, meta, knod_prog, off);
			break;
		case BPF_JMP32 | BPF_JSET | BPF_K:
			knod_vset32(&param[0], KNOD_AMDGPU_TMP_VREG0_LO);
			knod_iset32(&param[1], imm);
			knod_emit(priv, meta, v_mov_b32_e32, param[0],
				  param[1]);
			knod_vset32(&param[0], d * 2);
			knod_vset32(&param[1], d * 2);
			knod_vset32(&param[2], KNOD_AMDGPU_TMP_VREG0_LO);
			knod_emit(priv, meta, v_and_b32_e32, param[0],
				  param[1], param[2]);
			knod_vset32(&param[0], d * 2);
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
			knod_iset32(&param[1], 0);
			knod_emit(priv, meta, v_mov_b32_e32, param[0],
				  param[1]);
			knod_vset32(&param[0], d * 2);
			knod_vset32(&param[1], d * 2);
			knod_vset32(&param[2], KNOD_AMDGPU_TMP_VREG0_LO);
			knod_emit(priv, meta, v_and_b32_e32, param[0],
				  param[1], param[2]);
			knod_vset32(&param[0], (d * 2) + 1);
			knod_vset32(&param[1], (d * 2) + 1);
			knod_vset32(&param[2], KNOD_AMDGPU_TMP_VREG0_HI);
			knod_emit(priv, meta, v_and_b32_e32, param[0],
				  param[1], param[2]);
			knod_vset32(&param[0], d * 2);
			knod_vset32(&param[1], KNOD_AMDGPU_TMP_VREG0_LO);
			knod_emit(priv, meta, v_cmp_eq_u64, param[0],
				  param[1]);
			knod_bpf_emit_branch_tail(priv, meta, knod_prog, off);
			break;
		case BPF_JMP32 | BPF_JSET | BPF_X:
			knod_vset32(&param[0], d * 2);
			knod_vset32(&param[1], d * 2);
			knod_vset32(&param[2], s * 2);
			knod_emit(priv, meta, v_and_b32_e32, param[0],
				  param[1], param[2]);
			knod_bpf_emit_branch_tail(priv, meta, knod_prog, off);
			break;
		case BPF_JMP | BPF_JSET | BPF_X:
			knod_vset32(&param[0], d * 2);
			knod_vset32(&param[1], d * 2);
			knod_vset32(&param[2], s * 2);
			knod_emit(priv, meta, v_and_b32_e32, param[0],
				  param[1], param[2]);
			knod_vset32(&param[0], (d * 2) + 1);
			knod_vset32(&param[1], (d * 2) + 1);
			knod_vset32(&param[2], (s * 2) + 1);
			knod_emit(priv, meta, v_and_b32_e32, param[0],
				  param[1], param[2]);
			knod_bpf_emit_branch_tail(priv, meta, knod_prog, off);
			break;
		case BPF_JMP32 | BPF_JNE | BPF_K:
			knod_vset32(&param[0], KNOD_AMDGPU_TMP_VREG0_LO);
			knod_iset32(&param[1], imm);
			knod_emit(priv, meta, v_mov_b32_e32, param[0],
				  param[1]);
			knod_vset32(&param[0], d * 2);
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
			knod_iset32(&param[1], 0);
			knod_emit(priv, meta, v_mov_b32_e32, param[0],
				  param[1]);
			knod_vset32(&param[0], d * 2);
			knod_vset32(&param[1], KNOD_AMDGPU_TMP_VREG0_LO);
			knod_emit(priv, meta, v_cmp_eq_u64, param[0],
				  param[1]);
			knod_bpf_emit_branch_tail(priv, meta, knod_prog, off);
			break;
		case BPF_JMP32 | BPF_JNE | BPF_X:
			knod_vset32(&param[0], d * 2);
			knod_vset32(&param[1], s * 2);
			knod_emit(priv, meta, v_cmp_eq_u32, param[0],
				  param[1]);
			knod_bpf_emit_branch_tail(priv, meta, knod_prog, off);
			break;
		case BPF_JMP | BPF_JNE | BPF_X:
			knod_vset32(&param[0], d * 2);
			knod_vset32(&param[1], s * 2);
			knod_emit(priv, meta, v_cmp_eq_u64, param[0],
				  param[1]);
			knod_bpf_emit_branch_tail(priv, meta, knod_prog, off);
			break;
		case BPF_JMP32 | BPF_CALL:
		case BPF_JMP | BPF_CALL:
			switch (imm) {
			case 1:
				if (map_id == -1) {
					WARN_ON(1);
					break;
				}
				knod_bpf_map_lookup(priv, meta, map_id);
				map_id = -1;
				break;
			case 2: {
				struct knod_bpf_map_obj *_map_obj;

				if (map_id == -1) {
					WARN_ON(1);
					break;
				}
				_map_obj = knod_bpf_map_kaddr(priv, map_id);
				if (!_map_obj) {
					WARN_ON(1);
					break;
				}
				if (_map_obj->map_type == BPF_MAP_TYPE_ARRAY)
					knod_bpf_map_update_array(priv, meta,
						map_id);
				else if (_map_obj->map_type ==
					 BPF_MAP_TYPE_HASH)
					knod_bpf_map_update_hash(priv, meta,
						map_id);
				else
					WARN_ON(1);
				map_id = -1;
				break;
			}
			case 3: {
				struct knod_bpf_map_obj *_map_obj;

				if (map_id == -1) {
					WARN_ON(1);
					break;
				}
				_map_obj = knod_bpf_map_kaddr(priv, map_id);
				if (!_map_obj) {
					WARN_ON(1);
					break;
				}
				if (_map_obj->map_type == BPF_MAP_TYPE_ARRAY)
					knod_bpf_map_delete_array(priv, meta,
						map_id);
				else if (_map_obj->map_type ==
					 BPF_MAP_TYPE_HASH)
					knod_bpf_map_delete_hash(priv, meta,
						map_id);
				else
					WARN_ON(1);
				map_id = -1;
				break;
			}
			case 5:
				knod_bpf_ktime_get_ns(priv, meta);
				break;
			case 44:
				knod_bpf_xdp_adjust_head(priv, meta);
				break;
			case 65:
				knod_bpf_xdp_adjust_tail(priv, meta);
				break;
			default:
				WARN_ON(1);
				break;
			}
			break;
		case BPF_JMP32 | BPF_EXIT:
		case BPF_JMP | BPF_EXIT:
			/* Structurized CFG: BPF_EXIT is NOT a terminator.
			 * Mark all active lanes as done and clear EXEC.
			 * Actual exit handling (retval store, pkt_cache,
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
		case BPF_ALU | BPF_END | BPF_TO_BE: {
			struct amdgcn_param32 v_dst_lo, v_dst_hi, v_tmp, s_sel;

			knod_vset32(&v_dst_lo, d * 2);
			knod_vset32(&v_dst_hi, d * 2 + 1);
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

				knod_vset32(&v_src_hi, d * 2 + 1);

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
				WARN_ON(1);
				break;
			}
			break;
		}
		case BPF_ALU | BPF_END | BPF_TO_LE: {
			struct amdgcn_param32 v_dst_lo, v_dst_hi;

			knod_vset32(&v_dst_lo, d * 2);
			knod_vset32(&v_dst_hi, d * 2 + 1);

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
				WARN_ON(1);
				break;
			}
			break;
		}
		default:
			WARN_ON(1);
			break;
		}

		WARN_ON(meta->amdgpu_insns >= KNOD_META_INSNS);
		for (i = 0; i < meta->amdgpu_insns; i++)
			insn_idx += (meta->amdgpu_insn[i].size / 4);
	}

	/* Fallthrough EXIT: publish a verdict for every in-bounds lane.
	 * Lanes that did not reach BPF_EXIT are forced to XDP_DROP below.
	 */
	meta = kzalloc(sizeof(*meta), GFP_KERNEL);
	if (!meta)
		return -ENOMEM;
	list_add_tail(&meta->l, &knod_prog->post_insns);

	/* Any in-bounds lane outside done_mask gets a conservative DROP
	 * verdict instead of publishing stale VGPR state or leaving the
	 * recycle-time poison in bd->act.
	 */
	knod_emit(priv, meta, s_andn2_b64, AMDGCN_SREG_EXEC_LO,
		  knod_prog->initial_exec_sreg, knod_prog->done_mask_sreg);
	knod_vset32(&p[0], KNOD_AMDGPU_VREG0_LO);
	knod_iset32(&p[1], XDP_DROP);
	knod_emit(priv, meta, v_mov_b32_e32, p[0], p[1]);

	/* Store bd->act for every lane that participated in this dispatch.
	 * Done lanes retain their low32 action in v0; unfinished lanes publish
	 * the fallback DROP written above.
	 */
	knod_emit(priv, meta, s_mov_b64, AMDGCN_SREG_EXEC_LO,
		  knod_prog->initial_exec_sreg);

	/* BPF/XDP verdicts are low32; do not spend a second GTT dword per
	 * packet.
	 */
	knod_vset32(&p[0], KNOD_AMDGPU_VREG0_LO);
	knod_vset32(&p[1], KNOD_AMDGPU_SLOT_VREG_LO);
	knod_emit(priv, meta, global_store_dword, p[0], p[1],
		  offsetof(struct spsc_bd, act));

	if (knod_prog->uses_adjust)
		knod_bpf_emit_offlen_writeback(priv, meta);

	/* pkt_cache writeback: flush modified packet data back to VRAM */
	if (knod_bpf_pkt_cache) {
		knod_vset32(&p[0], r32[0].v);
		knod_vset32(&p[1],
					 KNOD_AMDGPU_DATA_VREG_LO);
		knod_emit(priv, meta, v_mov_b32_e32, p[0], p[1]);
		knod_vset32(&p[0], r32[0].v + 1);
		knod_vset32(&p[1],
					 KNOD_AMDGPU_DATA_VREG_HI);
		knod_emit(priv, meta, v_mov_b32_e32, p[0], p[1]);

		knod_global_store_size_cache(priv, meta,
					     &pkt_cache[0],
					     r32[0],
					     0, /* dst index */
					     0, /* start offset */
					     knod_prog->max_packet_off);
	}

	/* XDP_PASS detection */
	knod_iset32(&p[0], XDP_PASS);
	knod_vset32(&p[1], KNOD_AMDGPU_VREG0_LO);
	knod_emit(priv, meta, v_cmp_eq_u32, p[0], p[1]);

	pass_branch_idx = meta->amdgpu_insns;
	knod_emit(priv, meta, s_cbranch_vccz, 0);

	/* EXEC &= VCC (only PASS lanes) */
	knod_emit(priv, meta, s_and_b64, AMDGCN_SREG_EXEC_LO,
		  AMDGCN_SREG_EXEC_LO, AMDGCN_SREG_VCC_LO);

	/* v_mov param addr to VGPR pair */
	knod_vset32(&p[0], KNOD_AMDGPU_TMP_VREG9_LO);
	knod_sset32(&p[1], KNOD_AMDGPU_PARAM_SREG_LO);
	knod_emit(priv, meta, v_mov_b32_e32, p[0], p[1]);

	knod_vset32(&p[0], KNOD_AMDGPU_TMP_VREG9_HI);
	knod_sset32(&p[1], KNOD_AMDGPU_PARAM_SREG_HI);
	knod_emit(priv, meta, v_mov_b32_e32, p[0], p[1]);

	/* Per-queue pass_count: offset TMP_VREG9 by queue_idx * 4 */
	/* v_mov_b32 v2, s15 (queue_idx → VGPR) */
	knod_vset32(&p[0], KNOD_AMDGPU_VREG1_LO);
	knod_sset32(&p[1],
				 KNOD_AMDGPU_WORKGROUP_ID_Y_SREG);
	knod_emit(priv, meta, v_mov_b32_e32, p[0], p[1]);

	/* v_lshlrev_b32 v2, 2, v2 (queue_idx * 4) */
	knod_vset32(&p[0], KNOD_AMDGPU_VREG1_LO);
	knod_iset32(&p[1], 2);
	knod_vset32(&p[2], KNOD_AMDGPU_VREG1_LO);
	knod_emit(priv, meta, v_lshlrev_b32, p[0], p[1], p[2]);

	/* v_add_u32 v40, v2, v40 (param_addr_lo += queue_idx * 4) */
	knod_vset32(&p[0], KNOD_AMDGPU_TMP_VREG9_LO);
	knod_vset32(&p[1], KNOD_AMDGPU_VREG1_LO);
	knod_vset32(&p[2], KNOD_AMDGPU_TMP_VREG9_LO);
	knod_emit(priv, meta, v_add_u32, p[0], p[1], p[2]);

	/* v_mov TMP10_LO, 1 */
	knod_vset32(&p[0], KNOD_AMDGPU_TMP_VREG10_LO);
	knod_iset32(&p[1], 1);
	knod_emit(priv, meta, v_mov_b32_e32, p[0], p[1]);

	/* global_atomic_add TMP10_LO, TMP9, TMP10_LO,
	 *                   offsetof(pass_count)
	 * GLC=1 to receive old_val in vdst (needed for per-lane slot
	 * index).  With GLC=0 vdst is NOT written, leaving TMP10_LO
	 * as the addend (1) -- every PASS lane then computes slot=1
	 * and races on the same pass_meta_buf entry, leaving slot 0 empty.
	 */
	knod_vset32(&p[0], KNOD_AMDGPU_TMP_VREG10_LO);
	knod_vset32(&p[1], KNOD_AMDGPU_TMP_VREG9_LO);
	knod_vset32(&p[2], KNOD_AMDGPU_TMP_VREG10_LO);
	knod_emit(priv, meta, global_atomic_add, p[0], p[1], p[2],
		  offsetof(struct knod_bpf_param, pass_count), 1);

	/* s_waitcnt vmcnt(0) */
	knod_emit(priv, meta, s_waitcnt_vmcnt);

	/* v_sub_u32 v40, v40, v2 (restore param_addr_lo) */
	knod_vset32(&p[0], KNOD_AMDGPU_TMP_VREG9_LO);
	knod_vset32(&p[1], KNOD_AMDGPU_TMP_VREG9_LO);
	knod_vset32(&p[2], KNOD_AMDGPU_VREG1_LO);
	knod_emit(priv, meta, v_sub_u32, p[0], p[1], p[2]);

	/* old_val * 2 */
	knod_vset32(&p[0], KNOD_AMDGPU_TMP_VREG10_LO);
	knod_iset32(&p[1], 1);
	knod_vset32(&p[2], KNOD_AMDGPU_TMP_VREG10_LO);
	knod_emit(priv, meta, v_lshlrev_b32, p[0], p[1], p[2]);

	/* addr_lo += old_val * 2 */
	knod_vset32(&p[0], KNOD_AMDGPU_TMP_VREG9_LO);
	knod_vset32(&p[1], KNOD_AMDGPU_TMP_VREG10_LO);
	knod_vset32(&p[2], KNOD_AMDGPU_TMP_VREG9_LO);
	knod_emit(priv, meta, v_add_u32, p[0], p[1], p[2]);

	/* global_store_short pass_indices[old_val],
	 *                    BACKLOG_IDX_VREG
	 * dst=data, src=addr in wrapper convention
	 */
	knod_vset32(&p[0],
				 KNOD_AMDGPU_BACKLOG_IDX_VREG);
	knod_vset32(&p[1], KNOD_AMDGPU_TMP_VREG9_LO);
	knod_emit(priv, meta, global_store_short, p[0], p[1],
		  offsetof(struct knod_bpf_param, pass_indices));

	/* Copy PASS packet data (shader mode) or store src addr (SDMA mode) */
	knod_emit_pass_addr_store(priv, meta);

	/* Patch branch offset */
	pass_dwords = 0;

	for (j = pass_branch_idx + 1; j < meta->amdgpu_insns; j++)
		pass_dwords += meta->amdgpu_insn[j].size / 4;
	emit_s_cbranch_vccz(priv->isa_version,
			    &meta->amdgpu_insn[pass_branch_idx],
			    pass_dwords);

	knod_emit(priv, meta, s_endpgm);

	for (j = 0; j < meta->amdgpu_insns; j++)
		insn_idx += meta->amdgpu_insn[j].size / 4;

	if (priv->isa_version == 10) {
		if (insn_idx % 256) {
			meta = kzalloc_obj(*meta, GFP_KERNEL);
			if (!meta)
				return -ENOMEM;
			list_add_tail(&meta->l, &knod_prog->post_insns);
		}

		while (insn_idx % 256) {
			if (meta->amdgpu_insns >= KNOD_META_INSNS) {
				meta = kzalloc_obj(*meta, GFP_KERNEL);
				if (!meta)
					return -ENOMEM;
				list_add_tail(&meta->l, &knod_prog->post_insns);
			}
			knod_emit(priv, meta, s_code_end);
			insn_idx +=
				meta->amdgpu_insn[meta->amdgpu_insns - 1].size /
				4;
		}
	}

	return 0;
}

static int knod_bpf_translate(struct bpf_prog *prog)
{
	struct knod_prog *knod_prog = prog->aux->offload->dev_priv;
	struct knod_dev *knodev = knod_prog->knodev;
	int ret;

	knod_bpf_map_setup(prog);
	ret = knod_bpf_jit(knodev, knod_prog);
	if (ret < 0) {
		pr_err("knod: failed to JIT: %d\n", ret);
		return ret;
	}

	knod_setup_bpf_prog(prog);

	return 0;
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
	 * dispatching this code.  The compiled code lives in a kernel slot and
	 * is no longer read once we flip away; knod_prog is CPU-only IR the GPU
	 * never touches, so it is safe to free synchronously.
	 */
	if (priv && READ_ONCE(priv->prog) == prog) {
		WRITE_ONCE(priv->prog, NULL);
		knod_bpf_reload_pass(knodev);
	}
	knod_prog_free(knod_prog);
}

static const struct bpf_prog_offload_ops knod_bpf_dev_ops = {
	.insn_hook      = knod_bpf_verify_insn,
	.finalize       = knod_bpf_finalize,
	.prepare        = knod_bpf_verifier_prep,
	.translate      = knod_bpf_translate,
	.destroy        = knod_bpf_destroy_prog,
};

static int knod_bpf_setup_prog_hw_checks(struct knod_dev *knodev,
					 struct netdev_bpf *bpf)
{
	if (!bpf->prog)
		return 0;

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
	} else if (offmap->map.map_type == BPF_MAP_TYPE_HASH) {
		if (key == NULL)
			return knod_bpf_map_hash_get_first_key(offmap,
							       next_key);
		else
			return knod_bpf_map_hash_get_next_key(offmap, key,
							      nkey);
	}

	return 0;
}

static int knod_bpf_map_lookup_elem(struct bpf_offloaded_map *offmap,
				       void *key, void *value)
{
	return __knod_bpf_map_lookup_elem(offmap, key, value);
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
	    offmap->map.map_type != BPF_MAP_TYPE_HASH &&
	    offmap->map.map_type != BPF_MAP_TYPE_PERCPU_ARRAY) {
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
	case XDP_SETUP_PROG:
		WARN_ON(1);
		break;
	case XDP_SETUP_PROG_HW:
		err = knod_bpf_setup_prog_hw_checks(knodev, bpf);
		if (err)
			return err;

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

static inline int bpf_debugfs_insn(struct knod_bpf_priv *priv,
				   struct knod_insn_meta *meta,
				   struct seq_file *m,
				   int insn_idx)
{
	struct amdgcn_insn *insn = &meta->amdgpu_insn[insn_idx];

	if (priv->isa_version == 10)
		gfx10_debugfs_insn(insn, m);
	else if (priv->isa_version == 9)
		gfx9_debugfs_insn(insn, m);
	else
		WARN_ON(1);

	return insn->size;
}

/*
 * Print one disassembled GPU instruction at @offset, then drop the disasm's
 * trailing newline and append @tag as a right-hand comment aligned to a fixed
 * column (tabs expand to 8) so the origin lines up regardless of mnemonic
 * width.  Returns the instruction size in dwords.
 */
static int bpf_debugfs_insn_tagged(struct knod_bpf_priv *priv,
				   struct knod_insn_meta *meta,
				   struct seq_file *m, int j,
				   int offset, const char *tag)
{
	size_t col, p, line_start = m->count;
	int sz;

	seq_printf(m, "%d:\t", offset);
	sz = bpf_debugfs_insn(priv, meta, m, j);
	if (seq_has_overflowed(m))
		return sz;

	if (m->count > line_start && m->buf[m->count - 1] == '\n')
		m->count--;
	col = 0;
	for (p = line_start; p < m->count; p++)
		col = m->buf[p] == '\t' ? (col + 8) & ~(size_t)7 : col + 1;
	while (col < 96) {
		seq_putc(m, ' ');
		col++;
	}
	seq_printf(m, " ; %s\n", tag);

	return sz;
}

/*
 * Print the instructions a second time, re-sorted into BPF source order so the
 * dump reads like the program.  The offsets are the real (reordered) GPU
 * offsets, so they appear out of sequence — that shows where the reorder
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
				off2 += bpf_debugfs_insn_tagged(priv, meta, m,
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
			off2 += bpf_debugfs_insn_tagged(priv, meta, m,
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

	if (!priv)
		return 0;

	/*
	 * Show the kernel the GPU actually dispatches: the XDP prog when one is
	 * attached, otherwise the retained pass-through kernel.
	 */
	have_prog = READ_ONCE(priv->prog);
	if (have_prog) {
		kp = priv->knod_prog;
	} else {
		kp = priv->pass_knod_prog;
		seq_puts(m, "no XDP prog attached -- pass-through kernel:\n");
	}
	if (!kp)
		return 0;

	seq_puts(m, "===[PROLOGUE]===\n");
	list_for_each_entry(meta, &kp->pre_insns, l) {
		for (i = 0; i < meta->amdgpu_insns; i++) {
			seq_printf(m, "%d:\t", insn_idx);
			insn_idx += bpf_debugfs_insn(priv, meta, m, i);
		}
	}

	/* Emission (RPO) order — the actual GPU layout.  Each line is tagged
	 * with its origin BPF insn since the reorder makes this differ from the
	 * BPF byte order; synthetic jumps inserted by the reorder have none.
	 */
	seq_puts(m, "===[INSTRUCTIONS]===\n");
	list_for_each_entry(meta, &kp->insns, l) {
		char tag[24];

		if (meta->bpf_insn_idx < 0)
			scnprintf(tag, sizeof(tag), "synth JA->#%d",
				  meta->jmp_dst ?
				  meta->jmp_dst->bpf_insn_idx : -1);
		else
			scnprintf(tag, sizeof(tag), "bpf#%d",
				  meta->bpf_insn_idx);

		for (i = 0; i < meta->amdgpu_insns; i++)
			insn_idx += bpf_debugfs_insn_tagged(priv, meta, m, i,
							    insn_idx, tag);
	}

	seq_puts(m, "===[EPILOG]===\n");
	list_for_each_entry(meta, &kp->post_insns, l) {
		for (i = 0; i < meta->amdgpu_insns; i++) {
			seq_printf(m, "%d:\t", insn_idx);
			insn_idx += bpf_debugfs_insn(priv, meta, m, i);
		}
	}

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
	u64 p50 = 0, p99 = 0, p999 = 0, acc;
	struct knod_bpf_stats *stats;
	u64 ccnt, dcnt;
	int i;

	stats = &priv->stats;
	ccnt = stats->completion_count;
	dcnt = stats->dispatch_count;
	seq_printf(s, "enabled:             %s\n",
		   static_branch_unlikely(&knod_stats_key) ? "yes" : "no");

	seq_puts(s, "\n--- dispatch ---\n");
	seq_printf(s, "count:               %llu\n", dcnt);
	seq_printf(s, "avg_ns:              %llu\n",
		   dcnt ? stats->dispatch_total_ns / dcnt : 0);
	seq_printf(s, "max_ns:              %llu\n", stats->dispatch_max_ns);
	seq_printf(s, "backlogs_avg:        %llu\n",
		   dcnt ? stats->backlogs_total / dcnt : 0);

	seq_puts(s, "\nbacklogs histogram:\n");
	for (i = 0; i < KNOD_BL_BUCKETS; i++)
		seq_printf(s, "  %-10s %llu\n",
			   bl_labels[i], stats->backlogs_hist[i]);

	seq_puts(s, "\n--- completion ---\n");
	seq_printf(s, "count:               %llu\n", ccnt);
	seq_printf(s, "avg_ns:              %llu\n",
		   ccnt ? stats->completion_total_ns / ccnt : 0);
	seq_printf(s, "max_ns:              %llu\n",
		   stats->completion_max_ns);

	seq_puts(s, "\nlatency histogram:\n");
	for (i = 0; i < KNOD_LAT_BUCKETS; i++)
		seq_printf(s, "  %-10s %llu\n",
			   lat_labels[i], stats->completion_hist[i]);

	if (ccnt) {
		acc = 0;
		for (i = 0; i < KNOD_LAT_BUCKETS; i++) {
			acc += stats->completion_hist[i];
			if (!p50 && acc * 1000 >= ccnt * 500)
				p50 = i;
			if (!p99 && acc * 1000 >= ccnt * 990)
				p99 = i;
			if (!p999 && acc * 1000 >= ccnt * 999)
				p999 = i;
		}
		seq_printf(s, "\np50:  %s\n", lat_labels[p50]);
		seq_printf(s, "p99:  %s\n", lat_labels[p99]);
		seq_printf(s, "p999: %s\n", lat_labels[p999]);
	}

	seq_puts(s, "\n--- decode_act ---\n");
	seq_printf(s, "count:               %llu\n", stats->decode_act_count);
	seq_printf(s, "avg_ns:              %llu\n",
		   stats->decode_act_count ?
		   stats->decode_act_total_ns / stats->decode_act_count : 0);
	seq_printf(s, "max_ns:              %llu\n", stats->decode_act_max_ns);

	return 0;
}

DEFINE_SHOW_ATTRIBUTE(knod_stats);

static ssize_t knod_stats_enable_write(struct file *file,
				       const char __user *buf,
				       size_t count, loff_t *ppos)
{
	bool val;

	if (kstrtobool_from_user(buf, count, &val))
		return -EINVAL;

	if (val)
		static_branch_enable(&knod_stats_key);
	else
		static_branch_disable(&knod_stats_key);

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
	.read  = knod_stats_enable_read,
	.write = knod_stats_enable_write,
};

static ssize_t knod_stats_reset_write(struct file *file,
		const char __user *buf,
		size_t count, loff_t *ppos)
{
	struct knod_bpf_priv *priv = file->private_data;

	memset(&priv->stats, 0, sizeof(priv->stats));
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
	debugfs_create_bool("poll_mode", 0644, bpf_dir, &knod_bpf_poll_mode);
	debugfs_create_u32("dispatch_delay_us", 0644, bpf_dir,
			   &knod_bpf_dispatch_delay_us);

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
	/* interface up/down (or feature switch): worker + GPU drain */
	.start = &knod_bpf_start,
	.stop = &knod_bpf_stop,
	.xdp_install = &knod_bpf_xdp_install,
};

static int __init knod_bpf_init_module(void)
{
	pr_info("knod-bpf module load\n");

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
	struct knod_bpf_priv *priv, *tmp;
	struct knod_accel *accel;

	rtnl_lock();
	knod_dev_lock();
	list_for_each_entry_safe(priv, tmp, &priv_list, list) {
		accel = priv->accel;
		if (accel->knodev)
			accel_xdp_ops.exit(accel->knodev);
	}
	knod_accel_xdp_unregister();
	knod_dev_unlock();
	rtnl_unlock();
	pr_info("knod-bpf module unload\n");
}
module_exit(knod_bpf_cleanup_module);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Taehee Yoo <ap420073@gmail.com>");
MODULE_DESCRIPTION("AMDGPU BPF offload backend");
MODULE_VERSION("multi-aql");
