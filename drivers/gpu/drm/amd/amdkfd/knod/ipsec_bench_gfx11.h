/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (c) 2021 Taehee Yoo <ap420073@gmail.com>
 * Copyright (c) 2021 Hoyeon Lee <hoyeon.rhee@gmail.com>
 */

/*
 * KNOD IPsec per-layer micro-benchmark shaders - GFX11 (RDNA3).
 *
 * The fused RX shader parses ESP, scans the SA table, stages the T-tables,
 * runs AES-CTR, runs GHASH and checks the ICV in one dispatch, so its timing
 * cannot say which layer the time went to.  These kernels run one layer each
 * over the kernarg and buffers the benchmark already builds.  Both crypto
 * kernels pay the same prologue, which the base kernel measures on its own, so
 * the parts add up:
 *
 *	fused = base + (ctr - base) + (ghash - base) + everything else
 *
 * Both skip the SA scan (slot 0 is used directly) and the IP-version branch
 * (the benchmark only builds IPv4 packets).  That is deliberate: those belong
 * to the difference term, not to the layer under test.
 *
 * None of them produces a usable packet - the CTR one writes plaintext but
 * no verdict, the GHASH one writes a tag nobody checks.  They are timing
 * instruments, not a data path, and the dispatcher never runs them.
 */

#ifndef KNOD_HELPERS_IPSEC_BENCH_GFX11_H_
#define KNOD_HELPERS_IPSEC_BENCH_GFX11_H_

#include <linux/types.h>
#include "ipsec_fused_gfx11.h"

/* sub[] fields, live for the whole kernel (above the AES v0-v22 range). */
#define VR_B_PKT_LO	30
#define VR_B_PKT_HI	31
#define VR_B_OUT_LO	32
#define VR_B_OUT_HI	33
#define VR_B_PKTLEN	34

/*
 * Phases 3-6 of the fused shader minus the parsing and the scan: SA slot 0
 * fields, sub[wg_id_y], the GCM nonce, the ciphertext bounds and the
 * T-tables in LDS.  Leaves SR_KEYS/SR_HTABLE/SR_IV0-2/SR_NR_ROUNDS/
 * SR_CTEXT_LEN/SR_NBLOCKS_GCM/SR_TOTAL_GHASH_BLK set and the packet
 * pointers in VR_B_*.
 */
static int knod_gfx11_bench_prologue(u32 *buf, int n)
{
	_E(emit_gfx11_s_dcache_inv, I11(buf, n));
	_E(emit_gfx11_s_waitcnt_lgkmcnt, I11(buf, n));
	_E(emit_gfx11_s_mov_b32, I11(buf, n), P_S(SR_BSWAP), P_L(0x00010203));

	/* s[24:25] = sa_table_addr, read through VMEM for K$ coherence. */
	_E(emit_gfx11_v_mov_b32_e32, I11(buf, n), P_V(16), P_S(8));
	_E(emit_gfx11_v_mov_b32_e32, I11(buf, n), P_V(17), P_S(9));
	_E(emit_gfx11_global_load_dwordx2, I11(buf, n), P_V(18), P_V(16), 0);
	_E(emit_gfx11_s_waitcnt_vmcnt, I11(buf, n));
	_E(emit_gfx11_v_readfirstlane_b32, I11(buf, n), 24, 18);
	_E(emit_gfx11_v_readfirstlane_b32, I11(buf, n), 25, 19);

	/* SA entry 0 - the benchmark installs exactly one. */
	_E(emit_gfx11_v_mov_b32_e32, I11(buf, n), P_V(VR_GA_LO), P_S(24));
	_E(emit_gfx11_v_mov_b32_e32, I11(buf, n), P_V(VR_GA_HI), P_S(25));
	_E(emit_gfx11_global_load_dwordx4, I11(buf, n), P_V(VR_S0),
	   P_V(VR_GA_LO), SA_OFF_KEY_ADDR);
	_E(emit_gfx11_global_load_dwordx4, I11(buf, n), P_V(VR_D0),
	   P_V(VR_GA_LO), SA_OFF_T_TABLES_ADDR);
	_E(emit_gfx11_global_load_dwordx2, I11(buf, n), P_V(VR_DATA0),
	   P_V(VR_GA_LO), SA_OFF_NR_ROUNDS);
	_E(emit_gfx11_s_waitcnt_vmcnt, I11(buf, n));
	_E(emit_gfx11_v_readfirstlane_b32, I11(buf, n), SR_KEYS, VR_S0);
	_E(emit_gfx11_v_readfirstlane_b32, I11(buf, n), SR_KEYS + 1, VR_S1);
	_E(emit_gfx11_v_readfirstlane_b32, I11(buf, n), SR_HTABLE_LO, VR_S2);
	_E(emit_gfx11_v_readfirstlane_b32, I11(buf, n), SR_HTABLE_HI, VR_S3);
	_E(emit_gfx11_v_readfirstlane_b32, I11(buf, n), SR_T_ADDR, VR_D0);
	_E(emit_gfx11_v_readfirstlane_b32, I11(buf, n), SR_T_ADDR + 1, VR_D1);
	_E(emit_gfx11_v_readfirstlane_b32, I11(buf, n), SR_IV0, VR_D2);
	_E(emit_gfx11_v_readfirstlane_b32, I11(buf, n), SR_NR_ROUNDS, VR_DATA0);

	/* v[3:4] = &sub[wg_id_y] = kernarg + 40 + wg_id_y*32 */
	_E(emit_gfx11_v_mov_b32_e32, I11(buf, n), P_V(1), P_S(16));
	_E(emit_gfx11_v_lshlrev_b32, I11(buf, n), P_V(1), P_I(5), P_V(1));
	_E(emit_gfx11_v_add_nc_u32, I11(buf, n), P_V(1), P_L(SUB_BASE_OFF),
	   P_V(1));
	_E(emit_gfx11_v_mov_b32_e32, I11(buf, n), P_V(2), P_S(9));
	_E(emit_gfx11_v_add_co_u32, I11(buf, n), P_V(3), P_S(8), P_V(1));
	_E(emit_gfx11_v_add_co_ci_u32_e32, I11(buf, n), P_V(4), P_I(0), P_V(2));

	_E(emit_gfx11_global_load_dwordx2, I11(buf, n), P_V(VR_B_PKT_LO),
	   P_V(3), SUB_OFF_PKT_ADDR);
	_E(emit_gfx11_global_load_dwordx2, I11(buf, n), P_V(VR_B_OUT_LO),
	   P_V(3), SUB_OFF_OUT_ADDR);
	_E(emit_gfx11_global_load_dword, I11(buf, n), P_V(VR_B_PKTLEN),
	   P_V(3), SUB_OFF_PKT_LEN);
	_E(emit_gfx11_s_waitcnt_vmcnt, I11(buf, n));

	/* nonce[4:11] = IV, at a fixed IPv4 offset that is 2 mod 4. */
	_E(emit_gfx11_global_load_dwordx4, I11(buf, n), P_V(VR_DATA0),
	   P_V(VR_B_PKT_LO), ESP_IV_OFF + ESP_ALIGN_BIAS);
	_E(emit_gfx11_s_waitcnt_vmcnt, I11(buf, n));
	_E(emit_gfx11_v_alignbit_b32, I11(buf, n), P_V(VR_DATA0),
	   P_V(VR_DATA1), P_V(VR_DATA0), P_I(16));
	_E(emit_gfx11_v_alignbit_b32, I11(buf, n), P_V(VR_DATA1),
	   P_V(VR_DATA2), P_V(VR_DATA1), P_I(16));
	_E(emit_gfx11_v_readfirstlane_b32, I11(buf, n), SR_IV1, VR_DATA0);
	_E(emit_gfx11_v_readfirstlane_b32, I11(buf, n), SR_IV2, VR_DATA1);

	/* ctext_len = pkt_len - ctext_off - ICV, nblocks = ceil(len/16) */
	_E(emit_gfx11_v_readfirstlane_b32, I11(buf, n), SR_CTEXT_LEN,
	   VR_B_PKTLEN);
	_E(emit_gfx11_s_sub_u32_p, I11(buf, n), P_S(SR_CTEXT_LEN),
	   P_S(SR_CTEXT_LEN), P_L(ESP_CTEXT_OFF + ESP_ICV_LEN));
	_E(emit_gfx11_s_add_u32, I11(buf, n), P_S(SR_NBLOCKS_GCM), P_I(15),
	   P_S(SR_CTEXT_LEN));
	_E(emit_gfx11_s_lshr_b32, I11(buf, n), P_S(SR_NBLOCKS_GCM),
	   P_S(SR_NBLOCKS_GCM), P_I(4));
	_E(emit_gfx11_s_add_u32, I11(buf, n), P_S(SR_TOTAL_GHASH_BLK), P_I(2),
	   P_S(SR_NBLOCKS_GCM));

	/* T-tables VRAM -> LDS, one u32 per thread per table. */
	_E(emit_gfx11_s_mov_b32, I11(buf, n), P_S(SR_MASK), P_L(0xFF));
	_E(emit_gfx11_v_lshlrev_b32, I11(buf, n), P_V(VR_TMP), P_I(2),
	   P_V(VR_TID));
	_E(emit_gfx11_v_mov_b32_e32, I11(buf, n), P_V(VR_GA_LO),
	   P_S(SR_T_ADDR));
	_E(emit_gfx11_v_mov_b32_e32, I11(buf, n), P_V(VR_GA_HI),
	   P_S(SR_T_ADDR + 1));
	_E(emit_gfx11_v_add_co_u32, I11(buf, n), P_V(VR_GA_LO), P_V(VR_GA_LO),
	   P_V(VR_TMP));
	_E(emit_gfx11_v_add_co_ci_u32_e32, I11(buf, n), P_V(VR_GA_HI), P_I(0),
	   P_V(VR_GA_HI));
	_E(emit_gfx11_global_load_dword, I11(buf, n), P_V(VR_DATA0),
	   P_V(VR_GA_LO), 0);
	_E(emit_gfx11_global_load_dword, I11(buf, n), P_V(VR_DATA1),
	   P_V(VR_GA_LO), 1024);
	_E(emit_gfx11_v_add_co_u32, I11(buf, n), P_V(VR_GA_LO), P_L(2048),
	   P_V(VR_GA_LO));
	_E(emit_gfx11_v_add_co_ci_u32_e32, I11(buf, n), P_V(VR_GA_HI), P_I(0),
	   P_V(VR_GA_HI));
	_E(emit_gfx11_global_load_dword, I11(buf, n), P_V(VR_DATA2),
	   P_V(VR_GA_LO), 0);
	_E(emit_gfx11_global_load_dword, I11(buf, n), P_V(VR_DATA3),
	   P_V(VR_GA_LO), 1024);
	_E(emit_gfx11_s_waitcnt_vmcnt, I11(buf, n));
	_E(emit_gfx11_ds_write_b32, I11(buf, n), VR_TMP, VR_DATA0);
	_E(emit_gfx11_v_add_nc_u32, I11(buf, n), P_V(VR_ADDR), P_L(1024),
	   P_V(VR_TMP));
	_E(emit_gfx11_ds_write_b32, I11(buf, n), VR_ADDR, VR_DATA1);
	_E(emit_gfx11_v_add_nc_u32, I11(buf, n), P_V(VR_ADDR), P_L(2048),
	   P_V(VR_TMP));
	_E(emit_gfx11_ds_write_b32, I11(buf, n), VR_ADDR, VR_DATA2);
	_E(emit_gfx11_v_add_nc_u32, I11(buf, n), P_V(VR_ADDR), P_L(3072),
	   P_V(VR_TMP));
	_E(emit_gfx11_ds_write_b32, I11(buf, n), VR_ADDR, VR_DATA3);
	_E(emit_gfx11_s_waitcnt_lgkmcnt, I11(buf, n));
	_E(emit_gfx11_s_barrier, I11(buf, n));

	return n;
}

/* v[VR_GA_LO:VR_GA_HI] = pkt + ESP_CTEXT_OFF + blk*16, blk from @blk_vgpr. */
static int knod_gfx11_bench_ctext_addr(u32 *buf, int n, int blk_vgpr)
{
	_E(emit_gfx11_v_lshlrev_b32, I11(buf, n), P_V(VR_BLK), P_I(4),
	   P_V(blk_vgpr));
	_E(emit_gfx11_v_add_co_u32, I11(buf, n), P_V(VR_GA_LO),
	   P_I(ESP_CTEXT_OFF), P_V(VR_B_PKT_LO));
	_E(emit_gfx11_v_add_co_ci_u32_e32, I11(buf, n), P_V(VR_GA_HI), P_I(0),
	   P_V(VR_B_PKT_HI));
	_E(emit_gfx11_v_add_co_u32, I11(buf, n), P_V(VR_GA_LO), P_V(VR_GA_LO),
	   P_V(VR_BLK));
	_E(emit_gfx11_v_add_co_ci_u32_e32, I11(buf, n), P_V(VR_GA_HI), P_I(0),
	   P_V(VR_GA_HI));
	return n;
}

/*
 * Neither crypto layer: the shared prologue and nothing else.  Subtracting
 * this from the two below leaves the cost of the layer itself, which is what
 * makes the attribution add up - both of them pay this same floor.
 */
static inline int kfd_ipsec_gen_base_bench_shader_gfx11(void *vbuf)
{
	u32 *buf = (u32 *)vbuf;
	int pad, n = 0;

	n = knod_gfx11_bench_prologue(buf, n);

	/* Publish something derived from the prologue so none of it can be
	 * treated as dead.
	 */
	_E(emit_gfx11_v_mov_b32_e32, I11(buf, n), P_V(VR_S0),
	   P_S(SR_NBLOCKS_GCM));
	_E(emit_gfx11_global_store_dword, I11(buf, n), P_V(VR_B_OUT_LO),
	   P_V(VR_S0), 0);
	_E(emit_gfx11_s_waitcnt_vmcnt, I11(buf, n));
	_E(emit_gfx11_s_endpgm, I11(buf, n));
	for (pad = 0; pad < KNOD_IPSEC_SHADER_PAD_DWORDS; pad++)
		_E(emit_gfx11_s_code_end, I11(buf, n));

	return n * 4;
}

/*
 * AES-CTR only: one counter block per thread, encrypted and XORed into the
 * ciphertext, result stored to sub[].out_addr.  No GHASH, no ICV, no verdict.
 */
static inline int kfd_ipsec_gen_ctr_bench_shader_gfx11(void *vbuf)
{
	u32 *buf = (u32 *)vbuf;
	int br_execz;
	int pad, n = 0;

	n = knod_gfx11_bench_prologue(buf, n);

	/* Only lanes with a real block participate. */
	_E(emit_gfx11_v_cmp_gt_u32, I11(buf, n), P_S(SR_NBLOCKS_GCM),
	   P_V(VR_TID));
	_E(emit_gfx11_s_and_saveexec_b64, I11(buf, n), SR_EXEC_SAVE,
	   106 /* VCC_LO */);
	br_execz = _BR(emit_gfx11_s_cbranch_execz, I11(buf, n), 0);

	n = knod_gfx11_bench_ctext_addr(buf, n, VR_TID);
	_E(emit_gfx11_global_load_dwordx4, I11(buf, n), P_V(VR_PREFETCH0),
	   P_V(VR_GA_LO), ESP_ALIGN_BIAS);
	_E(emit_gfx11_global_load_dword, I11(buf, n), P_V(VR_PREFETCH4),
	   P_V(VR_GA_LO), 16 + ESP_ALIGN_BIAS);

	/* counter block = salt || IV || bswap32(tid + 2) */
	_E(emit_gfx11_v_mov_b32_e32, I11(buf, n), P_V(VR_S0), P_S(SR_IV0));
	_E(emit_gfx11_v_mov_b32_e32, I11(buf, n), P_V(VR_S1), P_S(SR_IV1));
	_E(emit_gfx11_v_mov_b32_e32, I11(buf, n), P_V(VR_S2), P_S(SR_IV2));
	_E(emit_gfx11_v_add_nc_u32, I11(buf, n), P_V(VR_S3), P_I(2),
	   P_V(VR_TID));
	_E(emit_gfx11_v_perm_b32, I11(buf, n), P_V(VR_S3), P_V(VR_S3),
	   P_V(VR_S3), P_S(SR_BSWAP));

	/* AES walks SR_KEYS forward, so keep a copy to restore. */
	_E(emit_gfx11_s_mov_b32, I11(buf, n), P_S(SR_T_ADDR), P_S(SR_KEYS));
	_E(emit_gfx11_s_mov_b32, I11(buf, n), P_S(SR_T_ADDR + 1),
	   P_S(SR_KEYS + 1));
	n = emit_aes_encrypt_block_gfx11(buf, n);
	_E(emit_gfx11_s_mov_b32, I11(buf, n), P_S(SR_KEYS), P_S(SR_T_ADDR));
	_E(emit_gfx11_s_mov_b32, I11(buf, n), P_S(SR_KEYS + 1),
	   P_S(SR_T_ADDR + 1));

	/* ciphertext sits at 2 mod 4, so rebuild the four dwords. */
	_E(emit_gfx11_s_waitcnt_vmcnt, I11(buf, n));
	_E(emit_gfx11_v_alignbit_b32, I11(buf, n), P_V(VR_DATA0),
	   P_V(VR_PREFETCH1), P_V(VR_PREFETCH0), P_I(16));
	_E(emit_gfx11_v_alignbit_b32, I11(buf, n), P_V(VR_DATA1),
	   P_V(VR_PREFETCH2), P_V(VR_PREFETCH1), P_I(16));
	_E(emit_gfx11_v_alignbit_b32, I11(buf, n), P_V(VR_DATA2),
	   P_V(VR_PREFETCH3), P_V(VR_PREFETCH2), P_I(16));
	_E(emit_gfx11_v_alignbit_b32, I11(buf, n), P_V(VR_DATA3),
	   P_V(VR_PREFETCH4), P_V(VR_PREFETCH3), P_I(16));
	_E(emit_gfx11_v_xor_b32_e32, I11(buf, n), P_V(VR_S0), P_V(VR_S0),
	   P_V(VR_DATA0));
	_E(emit_gfx11_v_xor_b32_e32, I11(buf, n), P_V(VR_S1), P_V(VR_S1),
	   P_V(VR_DATA1));
	_E(emit_gfx11_v_xor_b32_e32, I11(buf, n), P_V(VR_S2), P_V(VR_S2),
	   P_V(VR_DATA2));
	_E(emit_gfx11_v_xor_b32_e32, I11(buf, n), P_V(VR_S3), P_V(VR_S3),
	   P_V(VR_DATA3));

	/* out_addr is 16-byte aligned, so no bias needed here. */
	_E(emit_gfx11_v_add_co_u32, I11(buf, n), P_V(VR_GA_LO),
	   P_V(VR_B_OUT_LO), P_V(VR_BLK));
	_E(emit_gfx11_v_add_co_ci_u32_e32, I11(buf, n), P_V(VR_GA_HI), P_I(0),
	   P_V(VR_B_OUT_HI));
	_E(emit_gfx11_global_store_dwordx4, I11(buf, n), P_V(VR_GA_LO),
	   P_V(VR_S0), 0);

	patch_branch(buf, br_execz, n);
	_E(emit_gfx11_s_mov_b64, I11(buf, n), 126 /* EXEC */, SR_EXEC_SAVE);
	_E(emit_gfx11_s_waitcnt_vmcnt, I11(buf, n));
	_E(emit_gfx11_s_endpgm, I11(buf, n));
	for (pad = 0; pad < KNOD_IPSEC_SHADER_PAD_DWORDS; pad++)
		_E(emit_gfx11_s_code_end, I11(buf, n));

	return n * 4;
}

/*
 * GHASH only: every thread multiplies one ciphertext block by its H power and
 * the workgroup XOR-tree-reduces, exactly as the fused shader does.  The
 * fused EXEC-based AAD/len block selection is left out - it is ~60 ALU ops
 * against a ~2700-instruction multiply, and it belongs to the packet-shaped
 * work rather than to GHASH itself.
 *
 * Every lane loads a clamped block so all 256 do the same amount of work
 * without running off the end of the packet.
 */
static inline int kfd_ipsec_gen_ghash_bench_shader_gfx11(void *vbuf)
{
	u32 *buf = (u32 *)vbuf;
	int br_tid0, br_skip, br_skip_gf;
	int level, pad, n = 0;

	n = knod_gfx11_bench_prologue(buf, n);

	/* H^(total - tid - 1), clamped at 0 like the fused shader. */
	_E(emit_gfx11_v_sub_nc_u32, I11(buf, n), P_V(VR_TMP),
	   P_S(SR_TOTAL_GHASH_BLK), P_V(VR_TID));
	_E(emit_gfx11_v_add_nc_u32, I11(buf, n), P_V(VR_TMP), P_L(0xFFFFFFFF),
	   P_V(VR_TMP));
	_E(emit_gfx11_v_max_i32, I11(buf, n), P_V(VR_TMP), P_I(0), P_V(VR_TMP));
	_E(emit_gfx11_v_lshlrev_b32, I11(buf, n), P_V(VR_TMP), P_I(4),
	   P_V(VR_TMP));
	_E(emit_gfx11_v_mov_b32_e32, I11(buf, n), P_V(VR_GA_LO),
	   P_S(SR_HTABLE_LO));
	_E(emit_gfx11_v_mov_b32_e32, I11(buf, n), P_V(VR_GA_HI),
	   P_S(SR_HTABLE_HI));
	_E(emit_gfx11_v_add_co_u32, I11(buf, n), P_V(VR_GA_LO), P_V(VR_GA_LO),
	   P_V(VR_TMP));
	_E(emit_gfx11_v_add_co_ci_u32_e32, I11(buf, n), P_V(VR_GA_HI), P_I(0),
	   P_V(VR_GA_HI));
	_E(emit_gfx11_global_load_dwordx4, I11(buf, n), P_V(VR_D0),
	   P_V(VR_GA_LO), 0);

	/* blk = min(tid, nblocks - 1) keeps every lane inside the packet. */
	_E(emit_gfx11_s_sub_u32_p, I11(buf, n), P_S(SR_LOOP_CTR),
	   P_S(SR_NBLOCKS_GCM), P_I(1));
	_E(emit_gfx11_v_min_i32, I11(buf, n), P_V(VR_TMP2),
	   P_S(SR_LOOP_CTR), P_V(VR_TID));
	n = knod_gfx11_bench_ctext_addr(buf, n, VR_TMP2);
	_E(emit_gfx11_global_load_dwordx4, I11(buf, n), P_V(VR_PREFETCH0),
	   P_V(VR_GA_LO), ESP_ALIGN_BIAS);
	_E(emit_gfx11_global_load_dword, I11(buf, n), P_V(VR_PREFETCH4),
	   P_V(VR_GA_LO), 16 + ESP_ALIGN_BIAS);
	_E(emit_gfx11_s_waitcnt_vmcnt, I11(buf, n));
	_E(emit_gfx11_v_alignbit_b32, I11(buf, n), P_V(VR_DATA0),
	   P_V(VR_PREFETCH1), P_V(VR_PREFETCH0), P_I(16));
	_E(emit_gfx11_v_alignbit_b32, I11(buf, n), P_V(VR_DATA1),
	   P_V(VR_PREFETCH2), P_V(VR_PREFETCH1), P_I(16));
	_E(emit_gfx11_v_alignbit_b32, I11(buf, n), P_V(VR_DATA2),
	   P_V(VR_PREFETCH3), P_V(VR_PREFETCH2), P_I(16));
	_E(emit_gfx11_v_alignbit_b32, I11(buf, n), P_V(VR_DATA3),
	   P_V(VR_PREFETCH4), P_V(VR_PREFETCH3), P_I(16));

	/* GF arithmetic is big-endian on both operands. */
	_E(emit_gfx11_v_perm_b32, I11(buf, n), P_V(VR_DATA0), P_V(VR_DATA0),
	   P_V(VR_DATA0), P_S(SR_BSWAP));
	_E(emit_gfx11_v_perm_b32, I11(buf, n), P_V(VR_DATA1), P_V(VR_DATA1),
	   P_V(VR_DATA1), P_S(SR_BSWAP));
	_E(emit_gfx11_v_perm_b32, I11(buf, n), P_V(VR_DATA2), P_V(VR_DATA2),
	   P_V(VR_DATA2), P_S(SR_BSWAP));
	_E(emit_gfx11_v_perm_b32, I11(buf, n), P_V(VR_DATA3), P_V(VR_DATA3),
	   P_V(VR_DATA3), P_S(SR_BSWAP));
	_E(emit_gfx11_v_perm_b32, I11(buf, n), P_V(VR_D0), P_V(VR_D0),
	   P_V(VR_D0), P_S(SR_BSWAP));
	_E(emit_gfx11_v_perm_b32, I11(buf, n), P_V(VR_D1), P_V(VR_D1),
	   P_V(VR_D1), P_S(SR_BSWAP));
	_E(emit_gfx11_v_perm_b32, I11(buf, n), P_V(VR_D2), P_V(VR_D2),
	   P_V(VR_D2), P_S(SR_BSWAP));
	_E(emit_gfx11_v_perm_b32, I11(buf, n), P_V(VR_D3), P_V(VR_D3),
	   P_V(VR_D3), P_S(SR_BSWAP));

	/* Only lanes that own a GHASH block need the multiply.  Zero the
	 * accumulator for everyone first - the XOR tree below reads every
	 * lane's LDS slot - then narrow EXEC, so a wave sitting entirely
	 * past total_ghash_blk skips ~2700 instructions outright.  A
	 * 1500-byte packet needs 90 of 256 lanes, i.e. two of the four
	 * waves do nothing.
	 */
	_E(emit_gfx11_v_mov_b32_e32, I11(buf, n), P_V(VR_S0), P_I(0));
	_E(emit_gfx11_v_mov_b32_e32, I11(buf, n), P_V(VR_S1), P_I(0));
	_E(emit_gfx11_v_mov_b32_e32, I11(buf, n), P_V(VR_S2), P_I(0));
	_E(emit_gfx11_v_mov_b32_e32, I11(buf, n), P_V(VR_S3), P_I(0));
	_E(emit_gfx11_v_cmp_gt_u32, I11(buf, n), P_S(SR_TOTAL_GHASH_BLK),
	   P_V(VR_TID));
	_E(emit_gfx11_s_and_saveexec_b64, I11(buf, n), SR_GHASH_EXEC,
	   106 /* VCC */);
	br_skip_gf = _BR(emit_gfx11_s_cbranch_execz, I11(buf, n), 0);
	n = emit_gfmul_128_gfx11(buf, n);
	patch_branch(buf, br_skip_gf, n);
	_E(emit_gfx11_s_mov_b64, I11(buf, n), 126 /* EXEC */, SR_GHASH_EXEC);

	/* XOR tree over 256 threads, same shape as the fused reduction. */
	_E(emit_gfx11_v_lshlrev_b32, I11(buf, n), P_V(VR_ADDR), P_I(4),
	   P_V(VR_TID));
	_E(emit_gfx11_ds_write_b128, I11(buf, n), VR_ADDR, VR_S0);
	_E(emit_gfx11_s_waitcnt_lgkmcnt, I11(buf, n));
	_E(emit_gfx11_s_barrier, I11(buf, n));

	for (level = 1; level <= 128; level <<= 1) {
		_E(emit_gfx11_v_and_b32_e32, I11(buf, n), P_V(VR_TMP),
		   P_L(level), P_V(VR_TID));
		_E(emit_gfx11_v_cmp_eq_u32, I11(buf, n), P_I(0), P_V(VR_TMP));
		_E(emit_gfx11_s_and_saveexec_b64, I11(buf, n), SR_GHASH_EXEC,
		   106 /* VCC */);
		br_skip = _BR(emit_gfx11_s_cbranch_execz, I11(buf, n), 0);

		_E(emit_gfx11_v_add_nc_u32, I11(buf, n), P_V(VR_TMP),
		   P_L(level), P_V(VR_TID));
		_E(emit_gfx11_v_lshlrev_b32, I11(buf, n), P_V(VR_TMP), P_I(4),
		   P_V(VR_TMP));
		_E(emit_gfx11_v_lshlrev_b32, I11(buf, n), P_V(VR_ADDR), P_I(4),
		   P_V(VR_TID));
		_E(emit_gfx11_ds_read_b128, I11(buf, n), VR_D0, VR_TMP);
		_E(emit_gfx11_ds_read_b128, I11(buf, n), VR_S0, VR_ADDR);
		_E(emit_gfx11_s_waitcnt_lgkmcnt, I11(buf, n));
		_E(emit_gfx11_v_xor_b32_e32, I11(buf, n), P_V(VR_S0),
		   P_V(VR_S0), P_V(VR_D0));
		_E(emit_gfx11_v_xor_b32_e32, I11(buf, n), P_V(VR_S1),
		   P_V(VR_S1), P_V(VR_D1));
		_E(emit_gfx11_v_xor_b32_e32, I11(buf, n), P_V(VR_S2),
		   P_V(VR_S2), P_V(VR_D2));
		_E(emit_gfx11_v_xor_b32_e32, I11(buf, n), P_V(VR_S3),
		   P_V(VR_S3), P_V(VR_D3));
		_E(emit_gfx11_ds_write_b128, I11(buf, n), VR_ADDR, VR_S0);
		_E(emit_gfx11_s_waitcnt_lgkmcnt, I11(buf, n));

		patch_branch(buf, br_skip, n);
		_E(emit_gfx11_s_mov_b64, I11(buf, n), 126 /* EXEC */,
		   SR_GHASH_EXEC);
		_E(emit_gfx11_s_barrier, I11(buf, n));
	}

	/* Thread 0 publishes the tag so the result cannot be optimised away
	 * by the memory system treating the whole kernel as dead.
	 */
	_E(emit_gfx11_v_cmp_eq_u32, I11(buf, n), P_I(0), P_V(VR_TID));
	_E(emit_gfx11_s_and_saveexec_b64, I11(buf, n), SR_EXEC_SAVE,
	   106 /* VCC */);
	br_tid0 = _BR(emit_gfx11_s_cbranch_execz, I11(buf, n), 0);
	_E(emit_gfx11_v_mov_b32_e32, I11(buf, n), P_V(VR_TMP), P_I(0));
	_E(emit_gfx11_ds_read_b128, I11(buf, n), VR_S0, VR_TMP);
	_E(emit_gfx11_s_waitcnt_lgkmcnt, I11(buf, n));
	_E(emit_gfx11_global_store_dwordx4, I11(buf, n), P_V(VR_B_OUT_LO),
	   P_V(VR_S0), 0);
	patch_branch(buf, br_tid0, n);
	_E(emit_gfx11_s_mov_b64, I11(buf, n), 126 /* EXEC */, SR_EXEC_SAVE);

	_E(emit_gfx11_s_waitcnt_vmcnt, I11(buf, n));
	_E(emit_gfx11_s_endpgm, I11(buf, n));
	for (pad = 0; pad < KNOD_IPSEC_SHADER_PAD_DWORDS; pad++)
		_E(emit_gfx11_s_code_end, I11(buf, n));

	return n * 4;
}

#endif /* KNOD_HELPERS_IPSEC_BENCH_GFX11_H_ */
