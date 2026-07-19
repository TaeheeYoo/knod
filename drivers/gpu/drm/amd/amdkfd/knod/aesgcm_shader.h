/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (c) 2021 Taehee Yoo <ap420073@gmail.com>
 * Copyright (c) 2021 Hoyeon Lee <hoyeon.rhee@gmail.com>
 */

/*
 * AES-GCM GPU shader emit helpers for GFX9 (Vega) / GFX10 (RDNA)
 *
 * Per-step emitters (AES rounds, encrypt block, GHASH gfmul, T-table
 * lookup) shared by the IPsec fused shaders.
 */

#ifndef AESGCM_SHADER_H_
#define AESGCM_SHADER_H_

#include <linux/types.h>
#include <asm/byteorder.h>
#include "knod_amdgpu_insn.h"

/* ======================================================================
 * Emit pattern macros (file-local)
 *
 * _E(fn, ...)   — emit instruction, advance n by instruction size
 * _BR(fn, ...)  — emit branch, save position, advance n
 * ======================================================================
 */

#define _E(fn, ...) (n += fn(__VA_ARGS__) / 4)
#define _BR(fn, ...) ({ int _p = n; n += fn(__VA_ARGS__) / 4; _p; })

/* ======================================================================
 * AES T-table Round Helper
 *
 * Emits one AES round using T-table lookups from LDS.
 *
 * T-table layout in LDS (4KB total):
 *   T0: offset 0..1023     (256 x 4 bytes)
 *   T1: offset 1024..2047
 *   T2: offset 2048..3071
 *   T3: offset 3072..4095
 *
 * AES round function:
 *   new[0] = T0[s0.b0] ^ T1[s1.b1] ^ T2[s2.b2] ^ T3[s3.b3] ^ rk[0]
 *   new[1] = T0[s1.b0] ^ T1[s2.b1] ^ T2[s3.b2] ^ T3[s0.b3] ^ rk[1]
 *   new[2] = T0[s2.b0] ^ T1[s3.b1] ^ T2[s0.b2] ^ T3[s1.b3] ^ rk[2]
 *   new[3] = T0[s3.b0] ^ T1[s0.b1] ^ T2[s1.b2] ^ T3[s2.b3] ^ rk[3]
 * ======================================================================
 */

/*
 * Emit code to extract a byte from a VGPR and compute LDS T-table address.
 *
 * @buf:        instruction buffer
 * @n:          current position
 * @vdst_addr:  output VGPR for LDS address
 * @vdst_val:   output VGPR for loaded T-table value (ds_read destination)
 * @v_state:    input VGPR (state word)
 * @byte_pos:   byte position (0, 1, 2, 3)
 * @table_base: LDS base offset for this table (0, 1024, 2048, 3072)
 * @s_mask:     SGPR holding 0xFF
 * @v_tmp:      temp VGPR for byte extraction
 */
static int emit_ttable_lookup_gfx9(u32 *buf, int n,
				   int v_addr, int v_val,
				   int v_state, int byte_pos,
				   int table_base, int s_mask, int v_tmp)
{
	/*
	 * Extract byte: result = (state >> (byte_pos*8)) & 0xFF
	 * Then: LDS addr = result * 4 + table_base
	 */
	if (byte_pos == 0) {
		/* byte 0: just mask, no shift needed */
		/* v_and_b32: src0=SGPR(mask), vsrc1=VGPR(state) */
		_E(emit_gfx9_v_and_b32_e32, I9(buf, n), P_V(v_tmp), P_S(s_mask),
		   P_V(v_state));
	} else if (byte_pos == 3) {
		/* byte 3: shift right 24, no mask needed */
		/* v_lshrrev: vdst = vsrc1 >> src0 = v_state >> 24 */
		_E(emit_gfx9_v_lshrrev_b32, I9(buf, n), P_V(v_tmp), P_I(24),
		   P_V(v_state));
	} else {
		/* byte 1 or 2: shift then mask */
		_E(emit_gfx9_v_lshrrev_b32, I9(buf, n), P_V(v_tmp),
		   P_I(byte_pos * 8), P_V(v_state));
		_E(emit_gfx9_v_and_b32_e32, I9(buf, n), P_V(v_tmp), P_S(s_mask),
		   P_V(v_tmp));
	}

	/* LDS addr = byte * 4 + table_base */
	/* v_lshlrev: vdst = vsrc1 << src0 = v_tmp << 2 */
	_E(emit_gfx9_v_lshlrev_b32, I9(buf, n), P_V(v_addr), P_I(2),
	   P_V(v_tmp));
	if (table_base > 0)
		_E(emit_gfx9_v_add_u32, I9(buf, n), P_V(v_addr),
		   P_L(table_base), P_V(v_addr));

	/* Issue LDS read (don't wait yet -- caller batches reads) */
	_E(emit_gfx9_ds_read_b32, I9(buf, n), v_val, v_addr, 0);

	return n;
}

/*
 * Emit one full AES round (rounds 1 to Nr-1).
 *
 * @buf, @n:    instruction buffer and position
 * @s0-s3:      input state VGPRs
 * @d0-d3:      output state VGPRs (new state)
 * @rk:         SGPR base for round key (4 consecutive SGPRs)
 * @s_mask:     SGPR holding 0xFF
 * @v_tmp:      temp VGPR for byte extraction
 * @v_addr:     temp VGPR for LDS address
 * @vt0-vt3:    temp VGPRs for 4 T-table values per column
 */
static int emit_aes_round_gfx9(u32 *buf, int n,
			       int s0, int s1, int s2, int s3,
			       int d0, int d1, int d2, int d3,
			       int rk, int s_mask, int v_tmp, int v_addr,
			       int vt0, int vt1, int vt2, int vt3)
{
	/*
	 * Issue all 16 LDS reads (4 per column), then wait once.
	 * This maximizes LDS throughput by overlapping reads.
	 *
	 * Column 0: T0[s0.b0] ^ T1[s1.b1] ^ T2[s2.b2] ^ T3[s3.b3]
	 * Column 1: T0[s1.b0] ^ T1[s2.b1] ^ T2[s3.b2] ^ T3[s0.b3]
	 * Column 2: T0[s2.b0] ^ T1[s3.b1] ^ T2[s0.b2] ^ T3[s1.b3]
	 * Column 3: T0[s3.b0] ^ T1[s0.b1] ^ T2[s1.b2] ^ T3[s2.b3]
	 *
	 * We reuse d0-d3 and vt0-vt3 as temporaries for the 16 results.
	 * Process column by column to minimize register pressure.
	 */

	/* ---- Column 0 ---- */
	n = emit_ttable_lookup_gfx9(buf, n, v_addr, vt0, s0, 0, 0, s_mask,
				    v_tmp);
	n = emit_ttable_lookup_gfx9(buf, n, v_addr, vt1, s1, 1, 1024, s_mask,
				    v_tmp);
	n = emit_ttable_lookup_gfx9(buf, n, v_addr, vt2, s2, 2, 2048, s_mask,
				    v_tmp);
	n = emit_ttable_lookup_gfx9(buf, n, v_addr, vt3, s3, 3, 3072, s_mask,
				    v_tmp);
	_E(emit_gfx9_s_waitcnt, I9(buf, n), 0xF, 0);  /* lgkmcnt=0 */

	/* XOR: d0 = vt0 ^ vt1 ^ vt2 ^ vt3 ^ rk */
	_E(emit_gfx9_v_xor_b32_e32, I9(buf, n), P_V(d0), P_V(vt0), P_V(vt1));
	_E(emit_gfx9_v_xor_b32_e32, I9(buf, n), P_V(d0), P_V(d0), P_V(vt2));
	_E(emit_gfx9_v_xor_b32_e32, I9(buf, n), P_V(d0), P_V(d0), P_V(vt3));
	_E(emit_gfx9_v_xor_b32_e32, I9(buf, n), P_V(d0), P_S(rk), P_V(d0));

	/* ---- Column 1 ---- */
	n = emit_ttable_lookup_gfx9(buf, n, v_addr, vt0, s1, 0, 0, s_mask,
				    v_tmp);
	n = emit_ttable_lookup_gfx9(buf, n, v_addr, vt1, s2, 1, 1024, s_mask,
				    v_tmp);
	n = emit_ttable_lookup_gfx9(buf, n, v_addr, vt2, s3, 2, 2048, s_mask,
				    v_tmp);
	n = emit_ttable_lookup_gfx9(buf, n, v_addr, vt3, s0, 3, 3072, s_mask,
				    v_tmp);
	_E(emit_gfx9_s_waitcnt, I9(buf, n), 0xF, 0);

	_E(emit_gfx9_v_xor_b32_e32, I9(buf, n), P_V(d1), P_V(vt0), P_V(vt1));
	_E(emit_gfx9_v_xor_b32_e32, I9(buf, n), P_V(d1), P_V(d1), P_V(vt2));
	_E(emit_gfx9_v_xor_b32_e32, I9(buf, n), P_V(d1), P_V(d1), P_V(vt3));
	_E(emit_gfx9_v_xor_b32_e32, I9(buf, n), P_V(d1), P_S(rk + 1), P_V(d1));

	/* ---- Column 2 ---- */
	n = emit_ttable_lookup_gfx9(buf, n, v_addr, vt0, s2, 0, 0, s_mask,
				    v_tmp);
	n = emit_ttable_lookup_gfx9(buf, n, v_addr, vt1, s3, 1, 1024, s_mask,
				    v_tmp);
	n = emit_ttable_lookup_gfx9(buf, n, v_addr, vt2, s0, 2, 2048, s_mask,
				    v_tmp);
	n = emit_ttable_lookup_gfx9(buf, n, v_addr, vt3, s1, 3, 3072, s_mask,
				    v_tmp);
	_E(emit_gfx9_s_waitcnt, I9(buf, n), 0xF, 0);

	_E(emit_gfx9_v_xor_b32_e32, I9(buf, n), P_V(d2), P_V(vt0), P_V(vt1));
	_E(emit_gfx9_v_xor_b32_e32, I9(buf, n), P_V(d2), P_V(d2), P_V(vt2));
	_E(emit_gfx9_v_xor_b32_e32, I9(buf, n), P_V(d2), P_V(d2), P_V(vt3));
	_E(emit_gfx9_v_xor_b32_e32, I9(buf, n), P_V(d2), P_S(rk + 2), P_V(d2));

	/* ---- Column 3 ---- */
	n = emit_ttable_lookup_gfx9(buf, n, v_addr, vt0, s3, 0, 0, s_mask,
				    v_tmp);
	n = emit_ttable_lookup_gfx9(buf, n, v_addr, vt1, s0, 1, 1024, s_mask,
				    v_tmp);
	n = emit_ttable_lookup_gfx9(buf, n, v_addr, vt2, s1, 2, 2048, s_mask,
				    v_tmp);
	n = emit_ttable_lookup_gfx9(buf, n, v_addr, vt3, s2, 3, 3072, s_mask,
				    v_tmp);
	_E(emit_gfx9_s_waitcnt, I9(buf, n), 0xF, 0);

	_E(emit_gfx9_v_xor_b32_e32, I9(buf, n), P_V(d3), P_V(vt0), P_V(vt1));
	_E(emit_gfx9_v_xor_b32_e32, I9(buf, n), P_V(d3), P_V(d3), P_V(vt2));
	_E(emit_gfx9_v_xor_b32_e32, I9(buf, n), P_V(d3), P_V(d3), P_V(vt3));
	_E(emit_gfx9_v_xor_b32_e32, I9(buf, n), P_V(d3), P_S(rk + 3), P_V(d3));

	return n;
}

/*
 * Emit the last AES round (SubBytes + ShiftRows + AddRoundKey, no MixColumns).
 *
 * S-box is extracted from T0: S(x) = (T0[x] >> 8) & 0xFF
 * (In standard AES T-table encoding: T0[x] = {2*S(x), S(x), S(x), 3*S(x)})
 *
 * Last round output:
 *   d[c] = S(s[c].b0) | (S(s[(c+1)%4].b1)<<8) |
 *          (S(s[(c+2)%4].b2)<<16) | (S(s[(c+3)%4].b3)<<24) ^ rk[c]
 */
static int emit_aes_last_round_gfx9(u32 *buf, int n,
				    int s0, int s1, int s2, int s3,
				    int d0, int d1, int d2, int d3,
				    int rk, int s_mask, int v_tmp, int v_addr,
				    int vt0, int vt1, int vt2, int vt3)
{
	/*
	 * For each column, look up T0 for all 4 bytes,
	 * extract S(x) = (T0[x] >> 8) & 0xFF, then assemble.
	 */
	int cols[4][4] = {
		{s0, s1, s2, s3},  /* column 0 */
		{s1, s2, s3, s0},  /* column 1 */
		{s2, s3, s0, s1},  /* column 2 */
		{s3, s0, s1, s2},  /* column 3 */
	};
	int dsts[4] = {d0, d1, d2, d3};
	int col;

	for (col = 0; col < 4; col++) {
		/* Look up T0 for all 4 bytes of this column */
		n = emit_ttable_lookup_gfx9(buf, n, v_addr, vt0, cols[col][0],
					    0, 0, s_mask, v_tmp);
		n = emit_ttable_lookup_gfx9(buf, n, v_addr, vt1, cols[col][1],
					    1, 0, s_mask, v_tmp);
		n = emit_ttable_lookup_gfx9(buf, n, v_addr, vt2, cols[col][2],
					    2, 0, s_mask, v_tmp);
		n = emit_ttable_lookup_gfx9(buf, n, v_addr, vt3, cols[col][3],
					    3, 0, s_mask, v_tmp);
		_E(emit_gfx9_s_waitcnt, I9(buf, n), 0xF, 0);

		/*
		 * Extract S(x) from T0[x]:
		 *   S(x) = (T0[x] >> 8) & 0xFF
		 */
		/* byte 0: S(x) in bits [15:8] of T0, place in bits [7:0] */
		_E(emit_gfx9_v_lshrrev_b32, I9(buf, n), P_V(vt0), P_I(8),
		   P_V(vt0));
		_E(emit_gfx9_v_and_b32_e32, I9(buf, n), P_V(vt0), P_S(s_mask),
		   P_V(vt0));

		/* byte 1: S(x) in bits [15:8], place in bits [15:8] */
		_E(emit_gfx9_v_and_b32_e32, I9(buf, n), P_V(vt1), P_L(0xFF00),
		   P_V(vt1));

		/* byte 2: S(x) in bits [15:8], place in bits [23:16] */
		_E(emit_gfx9_v_lshlrev_b32, I9(buf, n), P_V(vt2), P_I(8),
		   P_V(vt2));
		_E(emit_gfx9_v_and_b32_e32, I9(buf, n), P_V(vt2), P_L(0xFF0000),
		   P_V(vt2));

		/* byte 3: S(x) in bits [15:8], place in bits [31:24] */
		_E(emit_gfx9_v_lshlrev_b32, I9(buf, n), P_V(vt3), P_I(16),
		   P_V(vt3));
		_E(emit_gfx9_v_and_b32_e32, I9(buf, n), P_V(vt3),
		   P_L(0xFF000000), P_V(vt3));

		/* Assemble: d = b0 | b1 | b2 | b3 ^ rk */
		_E(emit_gfx9_v_or_b32_e32, I9(buf, n), P_V(dsts[col]), P_V(vt0),
		   P_V(vt1));
		_E(emit_gfx9_v_or_b32_e32, I9(buf, n), P_V(dsts[col]),
		   P_V(dsts[col]), P_V(vt2));
		_E(emit_gfx9_v_or_b32_e32, I9(buf, n), P_V(dsts[col]),
		   P_V(dsts[col]), P_V(vt3));
		_E(emit_gfx9_v_xor_b32_e32, I9(buf, n), P_V(dsts[col]),
		   P_S(rk + col), P_V(dsts[col]));
	}

	return n;
}

/* ======================================================================
 * GFX9 AES-GCM emit helpers
 * ======================================================================
 */

/*
 * Register allocation:
 *
 * SGPRs:
 *   s[0:3]    system: private_segment_buffer
 *   s[4:5]    system: dispatch_ptr
 *   s[6:7]    system: queue_ptr
 *   s[8:9]    system: kernarg_segment_ptr
 *   s[10:11]  system: dispatch_id
 *   s[12:13]  system: flat_scratch_init
 *   s14       system: private_segment_size
 *   s15       system: workgroup_id_x
 *   s16       system: workgroup_id_y (batch lane)
 *   s17       system: workgroup_id_z
 *
 *   s[18:19]  subparam base address (computed)
 *   s[20:21]  input buffer address (from subparam)
 *   s[22:23]  output buffer address (from subparam)
 *   s[24:25]  round keys address (from subparam)
 *   s26       nbytes (from subparam)
 *   s27       temp / block count
 *   s[28:31]  current round key (loaded per-round)
 *   s32       0xFF constant
 *   s[34:35]  T-table VRAM address pair (temp)
 *   s[36:37]  IV word 0-1 (from subparam.iv)
 *   s38       IV word 2 (from subparam.iv, 4 bytes)
 *   s[48:49]  saved EXEC
 *
 * VGPRs:
 *   v0        workitem_id_x (tid)
 *   v[1:4]    AES state A
 *   v[5:8]    AES state B / T-table results
 *   v9        byte extraction temp
 *   v10       LDS address temp
 *   v11       block_id (global)
 *   v[12:13]  64-bit global memory address
 *   v[14:17]  data words (plaintext/ciphertext)
 *   v18       temp
 */

#define SR_KEYS		24	/* s[24:25] */
#define SR_NBLOCKS	27
#define SR_RK		28	/* s[28:31] round key */
#define SR_MASK		32	/* s32 = 0xFF */
#define SR_LOOP_CTR	33	/* s33 = loop counter (Phase 4) */
#define SR_T_ADDR	34	/* s[34:35] temp for T-table load */
#define SR_IV0		36	/* s36 = IV word 0 */
#define SR_IV1		37	/* s37 = IV word 1 */
#define SR_IV2		38	/* s38 = IV word 2 */
#define SR_NR_ROUNDS	39	/* s39 = nr_rounds from subparam */
#define SR_EXEC_SAVE	48	/* s[48:49] */

#define VR_TID		0	/* workitem_id_x */
#define VR_S0		1	/* state A: v[1:4] */
#define VR_S1		2
#define VR_S2		3
#define VR_S3		4
#define VR_D0		5	/* state B / T-table: v[5:8] */
#define VR_D1		6
#define VR_D2		7
#define VR_D3		8
#define VR_TMP		9	/* byte extraction temp */
#define VR_ADDR		10	/* LDS address temp */
#define VR_BLK		11	/* block_id */
#define VR_GA_LO	12	/* 64-bit global addr lo */
#define VR_GA_HI	13	/* 64-bit global addr hi */
#define VR_DATA0	14	/* plaintext/ciphertext v[14:17] */
#define VR_DATA1	15
#define VR_DATA2	16
#define VR_DATA3	17
#define VR_TMP2		18
/* Phase 5.5: saved AES(K, J0) result for ICV finalization */
#define VR_J0_0		19
#define VR_J0_1		20
#define VR_J0_2		21
#define VR_J0_3		22

/* Phase 7 GHASH: additional SGPR for exec save during sub-masking */
#define SR_GHASH_EXEC	40	/* s[40:41] */
#define SR_BSWAP	44	/* s44 = 0x00010203 (bswap32 selector for v_perm_b32) */
#define SR_RK2		56	/* s[56:59] alternate round key for double-buffered AES */

/*
 * sizeof(knod_aesgcm_subparam) = 80
 * Offsets within subparam:
 *   0:  u64 in
 *   8:  u64 out
 *   16: u64 keys
 *   24: u64 h_table
 *   32: u64 aad
 *   40: u64 tag
 *   48: u32 nbytes
 *   52: u32 aad_len
 *   56: u8  iv[12]  (3 words at offsets 56, 60, 64 -- last only 4 bytes)
 *   68: u32 op
 *   72: u32 nr_rounds  (10 or 14)
 *   76: u32 _pad
 *
 * T-table addresses in knod_aesgcm_param (after sub[128]):
 *   128 * 80 = 10240: u64 t0
 *   10248: u64 t1
 *   10256: u64 t2
 *   10264: u64 t3
 */
#define SUBPARAM_SIZE		80

#define OFF_T0			(AESGCM_MAX_DIM_Y * SUBPARAM_SIZE)

/* ======================================================================
 * GFX9 AES Block Encrypt Helper
 *
 * Encrypts the 128-bit block in v[VR_S0:VR_S3] using T-tables in LDS.
 * Expects SR_KEYS = round keys GPU addr (will be advanced).
 * Expects SR_NR_ROUNDS = number of AES rounds.
 * Result in v[VR_S0:VR_S3].
 * Clobbers: v[VR_D0:VR_D3], v[VR_DATA0:VR_DATA3], v[VR_TMP], v[VR_ADDR],
 *           s[SR_RK:SR_RK+3], s[SR_NBLOCKS], s[SR_LOOP_CTR], s[SR_KEYS+1]
 * ======================================================================
 */
static int emit_aes_encrypt_block_gfx9(u32 *buf, int n)
{
	int br_loop, loop_top;

	/* Round 0: XOR with first round key */
	_E(emit_gfx9_s_load_dwordx4, I9(buf, n), P_S(SR_RK), P_S(SR_KEYS), 0);
	_E(emit_gfx9_s_waitcnt_lgkmcnt, I9(buf, n));
	_E(emit_gfx9_v_xor_b32_e32, I9(buf, n), P_V(VR_S0), P_S(SR_RK),
	   P_V(VR_S0));
	_E(emit_gfx9_v_xor_b32_e32, I9(buf, n), P_V(VR_S1), P_S(SR_RK + 1),
	   P_V(VR_S1));
	_E(emit_gfx9_v_xor_b32_e32, I9(buf, n), P_V(VR_S2), P_S(SR_RK + 2),
	   P_V(VR_S2));
	_E(emit_gfx9_v_xor_b32_e32, I9(buf, n), P_V(VR_S3), P_S(SR_RK + 3),
	   P_V(VR_S3));

	_E(emit_gfx9_s_add_u32, I9(buf, n), P_S(SR_KEYS), P_I(16),
	   P_S(SR_KEYS));
	_E(emit_gfx9_s_addc_u32, I9(buf, n), P_S(SR_KEYS + 1), P_I(0),
	   P_S(SR_KEYS + 1));

	/* pair_count = nr_rounds / 2 - 1 */
	_E(emit_gfx9_s_lshr_b32, I9(buf, n), P_S(SR_NBLOCKS), P_S(SR_NR_ROUNDS),
	   P_I(1));
	_E(emit_gfx9_s_add_u32, I9(buf, n), P_S(SR_NBLOCKS), P_L(0xFFFFFFFFu),
	   P_S(SR_NBLOCKS));

	_E(emit_gfx9_s_mov_b32, I9(buf, n), P_S(SR_LOOP_CTR), P_I(0));

	/* Prefetch round 1 key — overlaps with loop-entry overhead */
	_E(emit_gfx9_s_load_dwordx4, I9(buf, n), P_S(SR_RK), P_S(SR_KEYS), 0);

	loop_top = n;

	/* Odd round: S -> D  (SR_RK was prefetched) */
	_E(emit_gfx9_s_waitcnt_lgkmcnt, I9(buf, n));
	_E(emit_gfx9_s_add_u32, I9(buf, n), P_S(SR_KEYS), P_I(16),
	   P_S(SR_KEYS));
	_E(emit_gfx9_s_addc_u32, I9(buf, n), P_S(SR_KEYS + 1), P_I(0),
	   P_S(SR_KEYS + 1));
	_E(emit_gfx9_s_load_dwordx4, I9(buf, n), P_S(SR_RK2), P_S(SR_KEYS), 0);
	n = emit_aes_round_gfx9(buf, n, VR_S0, VR_S1, VR_S2, VR_S3,
				VR_D0, VR_D1, VR_D2, VR_D3,
				SR_RK, SR_MASK, VR_TMP, VR_ADDR,
				VR_DATA0, VR_DATA1, VR_DATA2, VR_DATA3);

	/* Even round: D -> S  (SR_RK2 was prefetched during odd round) */
	_E(emit_gfx9_s_waitcnt_lgkmcnt, I9(buf, n));
	_E(emit_gfx9_s_add_u32, I9(buf, n), P_S(SR_KEYS), P_I(16),
	   P_S(SR_KEYS));
	_E(emit_gfx9_s_addc_u32, I9(buf, n), P_S(SR_KEYS + 1), P_I(0),
	   P_S(SR_KEYS + 1));
	_E(emit_gfx9_s_load_dwordx4, I9(buf, n), P_S(SR_RK), P_S(SR_KEYS), 0);
	n = emit_aes_round_gfx9(buf, n, VR_D0, VR_D1, VR_D2, VR_D3,
				VR_S0, VR_S1, VR_S2, VR_S3,
				SR_RK2, SR_MASK, VR_TMP, VR_ADDR,
				VR_DATA0, VR_DATA1, VR_DATA2, VR_DATA3);

	_E(emit_gfx9_s_add_u32, I9(buf, n), P_S(SR_LOOP_CTR), P_I(1),
	   P_S(SR_LOOP_CTR));
	_E(emit_gfx9_s_cmp_lt_u32, I9(buf, n), P_S(SR_LOOP_CTR),
	   P_S(SR_NBLOCKS));
	br_loop = _BR(emit_gfx9_s_cbranch_scc1, I9(buf, n), 0);
	patch_branch(buf, br_loop, loop_top);

	/* Final odd round: S -> D  (SR_RK prefetched from last even) */
	_E(emit_gfx9_s_waitcnt_lgkmcnt, I9(buf, n));
	_E(emit_gfx9_s_add_u32, I9(buf, n), P_S(SR_KEYS), P_I(16),
	   P_S(SR_KEYS));
	_E(emit_gfx9_s_addc_u32, I9(buf, n), P_S(SR_KEYS + 1), P_I(0),
	   P_S(SR_KEYS + 1));
	_E(emit_gfx9_s_load_dwordx4, I9(buf, n), P_S(SR_RK2), P_S(SR_KEYS), 0);
	n = emit_aes_round_gfx9(buf, n, VR_S0, VR_S1, VR_S2, VR_S3,
				VR_D0, VR_D1, VR_D2, VR_D3,
				SR_RK, SR_MASK, VR_TMP, VR_ADDR,
				VR_DATA0, VR_DATA1, VR_DATA2, VR_DATA3);

	/* Last round: D -> S  (SR_RK2 prefetched during final odd) */
	_E(emit_gfx9_s_waitcnt_lgkmcnt, I9(buf, n));
	n = emit_aes_last_round_gfx9(buf, n, VR_D0, VR_D1, VR_D2, VR_D3,
				      VR_S0, VR_S1, VR_S2, VR_S3,
				      SR_RK2, SR_MASK, VR_TMP, VR_ADDR,
				      VR_DATA0, VR_DATA1, VR_DATA2, VR_DATA3);

	return n;
}

/* ======================================================================
 * GFX9 GF(2^128) Multiply Helper
 *
 * Computes Z = X * Y in GF(2^128) with GCM polynomial.
 *
 * Input:  X in v[VR_DATA0:VR_DATA3], Y in v[VR_D0:VR_D3]
 * Output: Z in v[VR_S0:VR_S3]
 * Clobbers: v[VR_TMP], v[VR_TMP2], v[VR_ADDR] (holds 0xE1000000),
 *           v[VR_DATA0:VR_DATA3] (shifted), v[VR_D0:VR_D3] (shifted),
 *           s[SR_LOOP_CTR]
 *
 * GCM bit ordering: bit 0 = MSB of first byte.
 * Algorithm: Shoup's method (right-shift V, test MSB of X).
 *   Z = 0, V = Y
 *   for i = 0..127:
 *     if MSB(X) set: Z ^= V
 *     lsb = V[3] & 1
 *     V >>= 1  (128-bit right shift)
 *     if lsb: V[0] ^= 0xE1000000
 *     X <<= 1  (128-bit left shift)
 * ======================================================================
 */
static int emit_gfmul_128_gfx9(u32 *buf, int n)
{
	int loop_top, br_loop;

	/* Z = 0 */
	_E(emit_gfx9_v_mov_b32_e32, I9(buf, n), P_V(VR_S0), P_I(0));
	_E(emit_gfx9_v_mov_b32_e32, I9(buf, n), P_V(VR_S1), P_I(0));
	_E(emit_gfx9_v_mov_b32_e32, I9(buf, n), P_V(VR_S2), P_I(0));
	_E(emit_gfx9_v_mov_b32_e32, I9(buf, n), P_V(VR_S3), P_I(0));

	/* Preload reduction constant into VR_ADDR (v10) */
	_E(emit_gfx9_v_mov_b32_e32, I9(buf, n), P_V(VR_ADDR), P_L(0xE1000000));

	/* Loop counter */
	_E(emit_gfx9_s_mov_b32, I9(buf, n), P_S(SR_LOOP_CTR), P_I(0));

	loop_top = n;

	/* Step 1: Test MSB of X[0] via signed compare (bit 31 set = negative) */
	_E(emit_gfx9_v_cmp_gt_i32, I9(buf, n), P_I(0), P_V(VR_DATA0));

	/*
	 * Step 2: Conditional Z ^= V.
	 * v_cndmask selects V[i] or 0 based on VCC, then XOR into Z.
	 * v_cndmask_b32: vdst = VCC ? vsrc1 : src0
	 * We want: VR_TMP2 = VCC ? VR_D0 : 0
	 * So src0=0, vsrc1=VR_D0
	 */
	_E(emit_gfx9_v_cndmask_b32_e32, I9(buf, n), P_V(VR_TMP2), P_I(0),
	   P_V(VR_D0));
	_E(emit_gfx9_v_xor_b32_e32, I9(buf, n), P_V(VR_S0), P_V(VR_S0),
	   P_V(VR_TMP2));
	_E(emit_gfx9_v_cndmask_b32_e32, I9(buf, n), P_V(VR_TMP2), P_I(0),
	   P_V(VR_D1));
	_E(emit_gfx9_v_xor_b32_e32, I9(buf, n), P_V(VR_S1), P_V(VR_S1),
	   P_V(VR_TMP2));
	_E(emit_gfx9_v_cndmask_b32_e32, I9(buf, n), P_V(VR_TMP2), P_I(0),
	   P_V(VR_D2));
	_E(emit_gfx9_v_xor_b32_e32, I9(buf, n), P_V(VR_S2), P_V(VR_S2),
	   P_V(VR_TMP2));
	_E(emit_gfx9_v_cndmask_b32_e32, I9(buf, n), P_V(VR_TMP2), P_I(0),
	   P_V(VR_D3));
	_E(emit_gfx9_v_xor_b32_e32, I9(buf, n), P_V(VR_S3), P_V(VR_S3),
	   P_V(VR_TMP2));

	/*
	 * Step 3: Save LSB of V[3] for reduction.
	 */
	_E(emit_gfx9_v_and_b32_e32, I9(buf, n), P_V(VR_TMP), P_I(1), P_V(VR_D3));

	/*
	 * Step 4: 128-bit right shift V (v[D0:D3]).
	 * v_alignbit_b32(dst, hi, lo, 1) = {hi,lo} >> 1 (lower 32 bits).
	 */
	_E(emit_gfx9_v_alignbit_b32, I9(buf, n), P_V(VR_D3), P_V(VR_D2),
	   P_V(VR_D3), P_I(1));
	_E(emit_gfx9_v_alignbit_b32, I9(buf, n), P_V(VR_D2), P_V(VR_D1),
	   P_V(VR_D2), P_I(1));
	_E(emit_gfx9_v_alignbit_b32, I9(buf, n), P_V(VR_D1), P_V(VR_D0),
	   P_V(VR_D1), P_I(1));
	_E(emit_gfx9_v_lshrrev_b32, I9(buf, n), P_V(VR_D0), P_I(1), P_V(VR_D0));

	/*
	 * Step 5: Conditional reduction V[0] ^= 0xE1000000.
	 * If saved LSB was 1, XOR with reduction polynomial.
	 * 0xE1000000 is preloaded in VR_ADDR (v10).
	 */
	_E(emit_gfx9_v_cmp_ne_u32, I9(buf, n), P_I(0), P_V(VR_TMP));
	/* VR_TMP2 = VCC ? VR_ADDR : 0 */
	_E(emit_gfx9_v_cndmask_b32_e32, I9(buf, n), P_V(VR_TMP2), P_I(0),
	   P_V(VR_ADDR));
	_E(emit_gfx9_v_xor_b32_e32, I9(buf, n), P_V(VR_D0), P_V(VR_D0),
	   P_V(VR_TMP2));

	/*
	 * Step 6: 128-bit left shift X (v[DATA0:DATA3]).
	 * X[0] = (X[0] << 1) | (X[1] >> 31)
	 * X[1] = (X[1] << 1) | (X[2] >> 31)
	 * X[2] = (X[2] << 1) | (X[3] >> 31)
	 * X[3] = X[3] << 1
	 */
	_E(emit_gfx9_v_alignbit_b32, I9(buf, n), P_V(VR_DATA0), P_V(VR_DATA0),
	   P_V(VR_DATA1), P_I(31));
	_E(emit_gfx9_v_alignbit_b32, I9(buf, n), P_V(VR_DATA1), P_V(VR_DATA1),
	   P_V(VR_DATA2), P_I(31));
	_E(emit_gfx9_v_alignbit_b32, I9(buf, n), P_V(VR_DATA2), P_V(VR_DATA2),
	   P_V(VR_DATA3), P_I(31));
	_E(emit_gfx9_v_lshlrev_b32, I9(buf, n), P_V(VR_DATA3), P_I(1),
	   P_V(VR_DATA3));

	/* Loop control: 128 iterations */
	_E(emit_gfx9_s_add_u32, I9(buf, n), P_S(SR_LOOP_CTR), P_I(1),
	   P_S(SR_LOOP_CTR));
	_E(emit_gfx9_s_cmp_lt_u32, I9(buf, n), P_S(SR_LOOP_CTR), P_L(128));
	br_loop = _BR(emit_gfx9_s_cbranch_scc1, I9(buf, n), 0);
	patch_branch(buf, br_loop, loop_top);

	return n;
}

/* ======================================================================
 * GFX10 (RDNA) AES-GCM emit helpers
 *
 * Same as GFX9 but with GFX10 encodings; GLOBAL saddr mode (scalar base
 * + VGPR offset) avoids VOP3B v_add_co_u32 for 64-bit addresses.
 * ======================================================================
 */

/* ---- GFX10 T-table lookup ---- */

static int emit_ttable_lookup_gfx10(u32 *buf, int n,
				    int v_addr, int v_val,
				    int v_state, int byte_pos,
				    int table_base, int s_mask,
				    int v_tmp)
{
	if (byte_pos == 0) {
		_E(emit_gfx10_v_and_b32_e32, I10(buf, n), P_V(v_tmp),
		   P_S(s_mask), P_V(v_state));
	} else if (byte_pos == 3) {
		_E(emit_gfx10_v_lshrrev_b32, I10(buf, n), P_V(v_tmp), P_I(24),
		   P_V(v_state));
	} else {
		_E(emit_gfx10_v_lshrrev_b32, I10(buf, n), P_V(v_tmp),
		   P_I(byte_pos * 8), P_V(v_state));
		_E(emit_gfx10_v_and_b32_e32, I10(buf, n), P_V(v_tmp),
		   P_S(s_mask), P_V(v_tmp));
	}

	_E(emit_gfx10_v_lshlrev_b32, I10(buf, n), P_V(v_addr), P_I(2),
	   P_V(v_tmp));
	if (table_base > 0)
		_E(emit_gfx10_v_add_nc_u32, I10(buf, n), P_V(v_addr),
		   P_L(table_base), P_V(v_addr));

	_E(emit_gfx10_ds_read_b32, I10(buf, n), v_val, v_addr);

	return n;
}

/* ---- GFX10 AES round ---- */

static int emit_aes_round_gfx10(u32 *buf, int n,
				int s0, int s1, int s2, int s3,
				int d0, int d1, int d2, int d3,
				int rk, int s_mask, int v_tmp, int v_addr,
				int vt0, int vt1, int vt2, int vt3)
{
	/* Column 0: T0[s0.b0] ^ T1[s1.b1] ^ T2[s2.b2] ^ T3[s3.b3] */
	n = emit_ttable_lookup_gfx10(buf, n, v_addr, vt0, s0, 0, 0, s_mask,
				     v_tmp);
	n = emit_ttable_lookup_gfx10(buf, n, v_addr, vt1, s1, 1, 1024, s_mask,
				     v_tmp);
	n = emit_ttable_lookup_gfx10(buf, n, v_addr, vt2, s2, 2, 2048, s_mask,
				     v_tmp);
	n = emit_ttable_lookup_gfx10(buf, n, v_addr, vt3, s3, 3, 3072, s_mask,
				     v_tmp);
	_E(emit_gfx10_s_waitcnt, I10(buf, n), 0x3F, 0);

	_E(emit_gfx10_v_xor_b32_e32, I10(buf, n), P_V(d0), P_V(vt0), P_V(vt1));
	_E(emit_gfx10_v_xor_b32_e32, I10(buf, n), P_V(d0), P_V(d0), P_V(vt2));
	_E(emit_gfx10_v_xor_b32_e32, I10(buf, n), P_V(d0), P_V(d0), P_V(vt3));
	_E(emit_gfx10_v_xor_b32_e32, I10(buf, n), P_V(d0), P_S(rk), P_V(d0));

	/* Column 1: T0[s1.b0] ^ T1[s2.b1] ^ T2[s3.b2] ^ T3[s0.b3] */
	n = emit_ttable_lookup_gfx10(buf, n, v_addr, vt0, s1, 0, 0, s_mask,
				     v_tmp);
	n = emit_ttable_lookup_gfx10(buf, n, v_addr, vt1, s2, 1, 1024, s_mask,
				     v_tmp);
	n = emit_ttable_lookup_gfx10(buf, n, v_addr, vt2, s3, 2, 2048, s_mask,
				     v_tmp);
	n = emit_ttable_lookup_gfx10(buf, n, v_addr, vt3, s0, 3, 3072, s_mask,
				     v_tmp);
	_E(emit_gfx10_s_waitcnt, I10(buf, n), 0x3F, 0);

	_E(emit_gfx10_v_xor_b32_e32, I10(buf, n), P_V(d1), P_V(vt0), P_V(vt1));
	_E(emit_gfx10_v_xor_b32_e32, I10(buf, n), P_V(d1), P_V(d1), P_V(vt2));
	_E(emit_gfx10_v_xor_b32_e32, I10(buf, n), P_V(d1), P_V(d1), P_V(vt3));
	_E(emit_gfx10_v_xor_b32_e32, I10(buf, n), P_V(d1), P_S(rk + 1),
	   P_V(d1));

	/* Column 2 */
	n = emit_ttable_lookup_gfx10(buf, n, v_addr, vt0, s2, 0, 0, s_mask,
				     v_tmp);
	n = emit_ttable_lookup_gfx10(buf, n, v_addr, vt1, s3, 1, 1024, s_mask,
				     v_tmp);
	n = emit_ttable_lookup_gfx10(buf, n, v_addr, vt2, s0, 2, 2048, s_mask,
				     v_tmp);
	n = emit_ttable_lookup_gfx10(buf, n, v_addr, vt3, s1, 3, 3072, s_mask,
				     v_tmp);
	_E(emit_gfx10_s_waitcnt, I10(buf, n), 0x3F, 0);

	_E(emit_gfx10_v_xor_b32_e32, I10(buf, n), P_V(d2), P_V(vt0), P_V(vt1));
	_E(emit_gfx10_v_xor_b32_e32, I10(buf, n), P_V(d2), P_V(d2), P_V(vt2));
	_E(emit_gfx10_v_xor_b32_e32, I10(buf, n), P_V(d2), P_V(d2), P_V(vt3));
	_E(emit_gfx10_v_xor_b32_e32, I10(buf, n), P_V(d2), P_S(rk + 2),
	   P_V(d2));

	/* Column 3 */
	n = emit_ttable_lookup_gfx10(buf, n, v_addr, vt0, s3, 0, 0, s_mask,
				     v_tmp);
	n = emit_ttable_lookup_gfx10(buf, n, v_addr, vt1, s0, 1, 1024, s_mask,
				     v_tmp);
	n = emit_ttable_lookup_gfx10(buf, n, v_addr, vt2, s1, 2, 2048, s_mask,
				     v_tmp);
	n = emit_ttable_lookup_gfx10(buf, n, v_addr, vt3, s2, 3, 3072, s_mask,
				     v_tmp);
	_E(emit_gfx10_s_waitcnt, I10(buf, n), 0x3F, 0);

	_E(emit_gfx10_v_xor_b32_e32, I10(buf, n), P_V(d3), P_V(vt0), P_V(vt1));
	_E(emit_gfx10_v_xor_b32_e32, I10(buf, n), P_V(d3), P_V(d3), P_V(vt2));
	_E(emit_gfx10_v_xor_b32_e32, I10(buf, n), P_V(d3), P_V(d3), P_V(vt3));
	_E(emit_gfx10_v_xor_b32_e32, I10(buf, n), P_V(d3), P_S(rk + 3),
	   P_V(d3));

	return n;
}

/* ---- GFX10 AES last round ---- */

static int emit_aes_last_round_gfx10(u32 *buf, int n,
				     int s0, int s1, int s2, int s3,
				     int d0, int d1, int d2, int d3,
				     int rk, int s_mask, int v_tmp, int v_addr,
				     int vt0, int vt1, int vt2, int vt3)
{
	int cols[4][4] = {
		{s0, s1, s2, s3},
		{s1, s2, s3, s0},
		{s2, s3, s0, s1},
		{s3, s0, s1, s2},
	};
	int dsts[4] = {d0, d1, d2, d3};
	int col;

	for (col = 0; col < 4; col++) {
		n = emit_ttable_lookup_gfx10(buf, n, v_addr, vt0, cols[col][0],
					     0, 0, s_mask, v_tmp);
		n = emit_ttable_lookup_gfx10(buf, n, v_addr, vt1, cols[col][1],
					     1, 0, s_mask, v_tmp);
		n = emit_ttable_lookup_gfx10(buf, n, v_addr, vt2, cols[col][2],
					     2, 0, s_mask, v_tmp);
		n = emit_ttable_lookup_gfx10(buf, n, v_addr, vt3, cols[col][3],
					     3, 0, s_mask, v_tmp);
		_E(emit_gfx10_s_waitcnt, I10(buf, n), 0x3F, 0);

		/* S(x) = (T0[x] >> 8) & 0xFF */
		_E(emit_gfx10_v_lshrrev_b32, I10(buf, n), P_V(vt0), P_I(8),
		   P_V(vt0));
		_E(emit_gfx10_v_and_b32_e32, I10(buf, n), P_V(vt0), P_S(s_mask),
		   P_V(vt0));

		_E(emit_gfx10_v_and_b32_e32, I10(buf, n), P_V(vt1), P_L(0xFF00),
		   P_V(vt1));

		_E(emit_gfx10_v_lshlrev_b32, I10(buf, n), P_V(vt2), P_I(8),
		   P_V(vt2));
		_E(emit_gfx10_v_and_b32_e32, I10(buf, n), P_V(vt2),
		   P_L(0xFF0000), P_V(vt2));

		_E(emit_gfx10_v_lshlrev_b32, I10(buf, n), P_V(vt3), P_I(16),
		   P_V(vt3));
		_E(emit_gfx10_v_and_b32_e32, I10(buf, n), P_V(vt3),
		   P_L(0xFF000000), P_V(vt3));

		_E(emit_gfx10_v_or_b32_e32, I10(buf, n), P_V(dsts[col]),
		   P_V(vt0), P_V(vt1));
		_E(emit_gfx10_v_or_b32_e32, I10(buf, n), P_V(dsts[col]),
		   P_V(dsts[col]), P_V(vt2));
		_E(emit_gfx10_v_or_b32_e32, I10(buf, n), P_V(dsts[col]),
		   P_V(dsts[col]), P_V(vt3));
		_E(emit_gfx10_v_xor_b32_e32, I10(buf, n), P_V(dsts[col]),
		   P_S(rk + col), P_V(dsts[col]));
	}

	return n;
}

/* ======================================================================
 * GFX10 AES Encrypt Block Helper
 *
 * Same as emit_aes_encrypt_block_gfx9 but with GFX10 instructions.
 * Input:  plaintext in v[VR_S0:VR_S3]
 * Output: ciphertext in v[VR_S0:VR_S3]
 * Requires: SR_KEYS, SR_NR_ROUNDS set. T-tables in LDS.
 * ======================================================================
 */
static int emit_aes_encrypt_block_gfx10(u32 *buf, int n)
{
	int br_loop, loop_top;

	/* Round 0: XOR with first round key */
	_E(emit_gfx10_s_load_dwordx4, I10(buf, n), P_S(SR_RK), P_S(SR_KEYS), 0);
	_E(emit_gfx10_s_waitcnt_lgkmcnt, I10(buf, n));
	_E(emit_gfx10_v_xor_b32_e32, I10(buf, n), P_V(VR_S0), P_S(SR_RK),
	   P_V(VR_S0));
	_E(emit_gfx10_v_xor_b32_e32, I10(buf, n), P_V(VR_S1), P_S(SR_RK + 1),
	   P_V(VR_S1));
	_E(emit_gfx10_v_xor_b32_e32, I10(buf, n), P_V(VR_S2), P_S(SR_RK + 2),
	   P_V(VR_S2));
	_E(emit_gfx10_v_xor_b32_e32, I10(buf, n), P_V(VR_S3), P_S(SR_RK + 3),
	   P_V(VR_S3));

	_E(emit_gfx10_s_add_u32, I10(buf, n), P_S(SR_KEYS), P_I(16),
	   P_S(SR_KEYS));
	_E(emit_gfx10_s_addc_u32, I10(buf, n), P_S(SR_KEYS + 1), P_I(0),
	   P_S(SR_KEYS + 1));

	/* pair_count = nr_rounds / 2 - 1 */
	_E(emit_gfx10_s_lshr_b32, I10(buf, n), P_S(SR_NBLOCKS),
	   P_S(SR_NR_ROUNDS), P_I(1));
	_E(emit_gfx10_s_add_u32, I10(buf, n), P_S(SR_NBLOCKS), P_L(0xFFFFFFFFu),
	   P_S(SR_NBLOCKS));

	_E(emit_gfx10_s_mov_b32, I10(buf, n), P_S(SR_LOOP_CTR), P_I(0));

	/* Prefetch round 1 key — overlaps with loop-entry overhead */
	_E(emit_gfx10_s_load_dwordx4, I10(buf, n), P_S(SR_RK), P_S(SR_KEYS), 0);

	loop_top = n;

	/* Odd round: S -> D  (SR_RK was prefetched) */
	_E(emit_gfx10_s_waitcnt_lgkmcnt, I10(buf, n));
	_E(emit_gfx10_s_add_u32, I10(buf, n), P_S(SR_KEYS), P_I(16),
	   P_S(SR_KEYS));
	_E(emit_gfx10_s_addc_u32, I10(buf, n), P_S(SR_KEYS + 1), P_I(0),
	   P_S(SR_KEYS + 1));
	_E(emit_gfx10_s_load_dwordx4, I10(buf, n), P_S(SR_RK2), P_S(SR_KEYS),
	   0);
	n = emit_aes_round_gfx10(buf, n, VR_S0, VR_S1, VR_S2, VR_S3,
				 VR_D0, VR_D1, VR_D2, VR_D3,
				 SR_RK, SR_MASK, VR_TMP, VR_ADDR,
				 VR_DATA0, VR_DATA1, VR_DATA2, VR_DATA3);

	/* Even round: D -> S  (SR_RK2 was prefetched during odd round) */
	_E(emit_gfx10_s_waitcnt_lgkmcnt, I10(buf, n));
	_E(emit_gfx10_s_add_u32, I10(buf, n), P_S(SR_KEYS), P_I(16),
	   P_S(SR_KEYS));
	_E(emit_gfx10_s_addc_u32, I10(buf, n), P_S(SR_KEYS + 1), P_I(0),
	   P_S(SR_KEYS + 1));
	_E(emit_gfx10_s_load_dwordx4, I10(buf, n), P_S(SR_RK), P_S(SR_KEYS), 0);
	n = emit_aes_round_gfx10(buf, n, VR_D0, VR_D1, VR_D2, VR_D3,
				 VR_S0, VR_S1, VR_S2, VR_S3,
				 SR_RK2, SR_MASK, VR_TMP, VR_ADDR,
				 VR_DATA0, VR_DATA1, VR_DATA2, VR_DATA3);

	_E(emit_gfx10_s_add_u32, I10(buf, n), P_S(SR_LOOP_CTR), P_I(1),
	   P_S(SR_LOOP_CTR));
	_E(emit_gfx10_s_cmp_lt_u32, I10(buf, n), P_S(SR_LOOP_CTR),
	   P_S(SR_NBLOCKS));
	br_loop = _BR(emit_gfx10_s_cbranch_scc1, I10(buf, n), 0);
	patch_branch(buf, br_loop, loop_top);

	/* Final odd round: S -> D  (SR_RK prefetched from last even) */
	_E(emit_gfx10_s_waitcnt_lgkmcnt, I10(buf, n));
	_E(emit_gfx10_s_add_u32, I10(buf, n), P_S(SR_KEYS), P_I(16),
	   P_S(SR_KEYS));
	_E(emit_gfx10_s_addc_u32, I10(buf, n), P_S(SR_KEYS + 1), P_I(0),
	   P_S(SR_KEYS + 1));
	_E(emit_gfx10_s_load_dwordx4, I10(buf, n), P_S(SR_RK2), P_S(SR_KEYS),
	   0);
	n = emit_aes_round_gfx10(buf, n, VR_S0, VR_S1, VR_S2, VR_S3,
				 VR_D0, VR_D1, VR_D2, VR_D3,
				 SR_RK, SR_MASK, VR_TMP, VR_ADDR,
				 VR_DATA0, VR_DATA1, VR_DATA2, VR_DATA3);

	/* Last round: D -> S  (SR_RK2 prefetched during final odd) */
	_E(emit_gfx10_s_waitcnt_lgkmcnt, I10(buf, n));
	n = emit_aes_last_round_gfx10(buf, n, VR_D0, VR_D1, VR_D2, VR_D3,
				      VR_S0, VR_S1, VR_S2, VR_S3,
				      SR_RK2, SR_MASK, VR_TMP, VR_ADDR,
				      VR_DATA0, VR_DATA1, VR_DATA2, VR_DATA3);

	return n;
}

/* ======================================================================
 * GFX10 GF(2^128) Multiply Helper
 *
 * Same algorithm as GFX9 version but with GFX10 instructions.
 * Input:  X in v[VR_DATA0:VR_DATA3], Y in v[VR_D0:VR_D3]
 * Output: Z in v[VR_S0:VR_S3]
 * ======================================================================
 */
static int emit_gfmul_128_gfx10(u32 *buf, int n)
{
	int loop_top, br_loop;

	/* Z = 0 */
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n), P_V(VR_S0), P_I(0));
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n), P_V(VR_S1), P_I(0));
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n), P_V(VR_S2), P_I(0));
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n), P_V(VR_S3), P_I(0));

	/* Preload reduction constant into VR_ADDR (v10) */
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n), P_V(VR_ADDR),
	   P_L(0xE1000000));

	_E(emit_gfx10_s_mov_b32, I10(buf, n), P_S(SR_LOOP_CTR), P_I(0));

	loop_top = n;

	/* Step 1: Test MSB of X[0] via signed compare (bit 31 set = negative) */
	_E(emit_gfx10_v_cmp_gt_i32, I10(buf, n), P_I(0), P_V(VR_DATA0));

	/* Step 2: Conditional Z ^= V */
	_E(emit_gfx10_v_cndmask_b32_e32, I10(buf, n), P_V(VR_TMP2), P_I(0),
	   P_V(VR_D0));
	_E(emit_gfx10_v_xor_b32_e32, I10(buf, n), P_V(VR_S0), P_V(VR_S0),
	   P_V(VR_TMP2));
	_E(emit_gfx10_v_cndmask_b32_e32, I10(buf, n), P_V(VR_TMP2), P_I(0),
	   P_V(VR_D1));
	_E(emit_gfx10_v_xor_b32_e32, I10(buf, n), P_V(VR_S1), P_V(VR_S1),
	   P_V(VR_TMP2));
	_E(emit_gfx10_v_cndmask_b32_e32, I10(buf, n), P_V(VR_TMP2), P_I(0),
	   P_V(VR_D2));
	_E(emit_gfx10_v_xor_b32_e32, I10(buf, n), P_V(VR_S2), P_V(VR_S2),
	   P_V(VR_TMP2));
	_E(emit_gfx10_v_cndmask_b32_e32, I10(buf, n), P_V(VR_TMP2), P_I(0),
	   P_V(VR_D3));
	_E(emit_gfx10_v_xor_b32_e32, I10(buf, n), P_V(VR_S3), P_V(VR_S3),
	   P_V(VR_TMP2));

	/* Step 3: Save LSB of V[3] */
	_E(emit_gfx10_v_and_b32_e32, I10(buf, n), P_V(VR_TMP), P_I(1),
	   P_V(VR_D3));

	/* Step 4: 128-bit right shift V */
	_E(emit_gfx10_v_alignbit_b32, I10(buf, n), P_V(VR_D3), P_V(VR_D2),
	   P_V(VR_D3), P_I(1));
	_E(emit_gfx10_v_alignbit_b32, I10(buf, n), P_V(VR_D2), P_V(VR_D1),
	   P_V(VR_D2), P_I(1));
	_E(emit_gfx10_v_alignbit_b32, I10(buf, n), P_V(VR_D1), P_V(VR_D0),
	   P_V(VR_D1), P_I(1));
	_E(emit_gfx10_v_lshrrev_b32, I10(buf, n), P_V(VR_D0), P_I(1),
	   P_V(VR_D0));

	/* Step 5: Conditional reduction V[0] ^= 0xE1000000 */
	_E(emit_gfx10_v_cmp_ne_u32, I10(buf, n), P_I(0), P_V(VR_TMP));
	_E(emit_gfx10_v_cndmask_b32_e32, I10(buf, n), P_V(VR_TMP2), P_I(0),
	   P_V(VR_ADDR));
	_E(emit_gfx10_v_xor_b32_e32, I10(buf, n), P_V(VR_D0), P_V(VR_D0),
	   P_V(VR_TMP2));

	/* Step 6: 128-bit left shift X */
	_E(emit_gfx10_v_alignbit_b32, I10(buf, n), P_V(VR_DATA0), P_V(VR_DATA0),
	   P_V(VR_DATA1), P_I(31));
	_E(emit_gfx10_v_alignbit_b32, I10(buf, n), P_V(VR_DATA1), P_V(VR_DATA1),
	   P_V(VR_DATA2), P_I(31));
	_E(emit_gfx10_v_alignbit_b32, I10(buf, n), P_V(VR_DATA2), P_V(VR_DATA2),
	   P_V(VR_DATA3), P_I(31));
	_E(emit_gfx10_v_lshlrev_b32, I10(buf, n), P_V(VR_DATA3), P_I(1),
	   P_V(VR_DATA3));

	/* Loop control: 128 iterations */
	_E(emit_gfx10_s_add_u32, I10(buf, n), P_S(SR_LOOP_CTR), P_I(1),
	   P_S(SR_LOOP_CTR));
	_E(emit_gfx10_s_cmp_lt_u32, I10(buf, n), P_S(SR_LOOP_CTR), P_L(128));
	br_loop = _BR(emit_gfx10_s_cbranch_scc1, I10(buf, n), 0);
	patch_branch(buf, br_loop, loop_top);

	return n;
}

#undef _E
#undef _BR

#endif /* AESGCM_SHADER_H_ */
