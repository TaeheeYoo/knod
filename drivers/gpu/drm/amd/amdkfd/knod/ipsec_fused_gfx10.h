/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (c) 2021 Taehee Yoo <ap420073@gmail.com>
 * Copyright (c) 2021 Hoyeon Lee <hoyeon.rhee@gmail.com>
 */

/*
 * KNOD IPsec fused RX shader - GFX9 (Vega10/20).
 *
 * Full AES-GCM decrypt pipeline for inbound ESP packets:
 *   1) ESP header parse -> SPI + seq extract
 *   2) SA table linear scan -> resolve SPI to slot index
 *   3) Cooperative T-table load (VRAM -> LDS, 256 threads)
 *   4) AES-CTR decrypt ciphertext -> out_addr
 *   5) Parallel GHASH over (AAD || ciphertext || len)
 *   6) ICV verify (GHASH ^ AES(K,J0) vs received tag)
 *   7) ESP trailer strip -> inner_len
 *   8) Write verdict to bd->act, inner_len to bd->len
 *
 * Dispatch geometry:
 *   workgroup  = (256, 1, 1)     - 256 threads = 1 AES block per thread
 *   grid       = (256, nr_pkts, 1)
 *   workgroup_id_y == packet index in the batch
 *
 * Anti-replay is NOT in the shader - CPU-side sliding window in NIC NAPI.
 *
 * Verdict encoding in bd->act high32:
 *   0..NR_SA-1  - SA hit + ICV pass, value is slot_idx
 *   0xFFFFFFFF  - SA miss (no entry for this SPI)
 *   0xFFFFFFFE  - non-IPv4/IPv6 bypass (unknown L3 protocol)
 *   0xFFFFFFFD  - ICV mismatch (decrypt succeeded but tag wrong)
 *
 * bd->len is set to inner_len on success (decrypted payload minus ESP
 * trailer and padding). On miss/bypass/ICV-fail, bd->len is left as-is.
 */

#ifndef KNOD_HELPERS_IPSEC_FUSED_GFX10_H_
#define KNOD_HELPERS_IPSEC_FUSED_GFX10_H_

#include <linux/types.h>
#include "knod_amdgpu_insn.h"
/* Provide AESGCM_MAX_DIM_Y so aesgcm_shader.h compiles (OFF_T0 macro).
 * Only emit_aes_encrypt_block_gfx10 / emit_gfmul_128_gfx10 are used here;
 * the full aesgcm_gen_shader_* functions are unreferenced.
 */
#ifndef AESGCM_MAX_DIM_Y
#define AESGCM_MAX_DIM_Y	1024
#endif
#include "aesgcm_shader.h"

/* SA entry constants - must match knod_ipsec.h */
#define KNOD_IPSEC_SHADER_NR_SA	256
#define KNOD_IPSEC_SHADER_SA_ENTRY_SZ	104

/* SA entry field offsets (struct knod_ipsec_sa_entry) */
#define SA_OFF_SPI		0
#define SA_OFF_KEY_ADDR		16
#define SA_OFF_HTABLE_ADDR	24
#define SA_OFF_T_TABLES_ADDR	32
#define SA_OFF_SALT		40
#define SA_OFF_KEY_LEN		44
#define SA_OFF_NR_ROUNDS	48
#define SA_OFF_MODE		52	/* XFRM_MODE_TRANSPORT=0, TUNNEL=1 */
#define SA_OFF_STATS_ADDR	88	/* per-SA GPU stats (u64 gpu addr) */

/* ESP packet geometry (ETH=14, IPv4=20 / IPv6=40, no VLAN/opts).
 * IPv4: ESP header starts at offset 34 (14+20).
 * IPv6: ESP header starts at offset 54 (14+40).
 * Within ESP header: SPI+0, seq+4, IV+8, ctext+16.
 * The shader dynamically computes offsets based on IP version.
 */
#define ESP_HDR_OFF_V4		34	/* ETH(14) + IPv4(20) */
#define ESP_HDR_OFF_V6		54	/* ETH(14) + IPv6(40) */
#define ESP_REL_SPI		0
#define ESP_REL_SEQ		4
#define ESP_REL_IV		8
#define ESP_REL_CTEXT		16	/* SPI(4)+seq(4)+IV(8) */
#define ESP_ICV_LEN		16

/* Fixed IPv4 layout offsets used by the crypto KAT */
#define ESP_SPI_OFF		34
#define ESP_SEQ_OFF		38
#define ESP_IV_OFF		42
#define ESP_CTEXT_OFF		50

/* Fused sub[] offsets within kernarg (sub[i] = kernarg + 40 + i*32) */
#define SUB_BASE_OFF		40
#define SUB_STRIDE		32
#define SUB_OFF_PKT_ADDR	0
#define SUB_OFF_OUT_ADDR	8
#define SUB_OFF_BD_ADDR		16
#define SUB_OFF_PKT_LEN		24
#define SUB_OFF_RESULT_SEQ	28

/* ICV-fail sentinel (distinct from MISS=0xFFFFFFFF and BYPASS=0xFFFFFFFE) */
#define VERDICT_ICV_FAIL	0xFFFFFFFDu

/* High VGPRs for saving pre-crypto IPsec state (above AES v0-v22 range) */
#define VR_SAVE_SLOT		30
#define VR_SAVE_BD_LO		31
#define VR_SAVE_BD_HI		32
#define VR_SAVE_PKT_LO		33
#define VR_SAVE_PKT_HI		34
#define VR_SAVE_PKTLEN		35
#define VR_SAVE_OUT_LO		36
#define VR_SAVE_OUT_HI		37
#define VR_SAVE_SEQ		38
#define VR_SAVE_SPI		39
#define VR_SAVE_STATS_LO	40	/* per-SA stats GPU addr low */
#define VR_SAVE_STATS_HI	41	/* per-SA stats GPU addr high */
/* ESP header offset: 34(v4) or 54(v6) */
#define VR_SAVE_ESP_OFF		42
/* Ciphertext prefetch destination - free v23-v27, outside AES v0-v22 range */
#define VR_PREFETCH0		23
#define VR_PREFETCH1		24
#define VR_PREFETCH2		25
#define VR_PREFETCH3		26
/* extra dword for GFX10 unaligned fix */
#define VR_PREFETCH4		27

/* Extra SGPRs for IPsec-specific state that survives into AES phases.
 * These must NOT collide with SR_* from aesgcm_shader.h (s18-s49, s56-s59).
 * s50-s55 are IPsec-specific. s56-s59 = SR_RK2 (AES round key double-buffer).
 */
#define SR_CTEXT_LEN		50	/* ciphertext length in bytes */
#define SR_NBLOCKS_GCM		51	/* ceil(ctext_len/16) */
#define SR_HTABLE_LO		52	/* H-power table GPU addr */
#define SR_HTABLE_HI		53
#define SR_TOTAL_GHASH_BLK	54	/* nblocks + 2 (AAD + ctext + len) */
#define SR_SA_MODE		55	/* XFRM_MODE_TRANSPORT=0, TUNNEL=1 */

/* File-local emit helpers */
#ifndef _KNOD_IPSEC_EMIT
#define _KNOD_IPSEC_EMIT
#define _E(fn, ...) (n += fn(__VA_ARGS__) / 4)
#define _BR(fn, ...) ({ int _p = n; n += fn(__VA_ARGS__) / 4; _p; })
#endif

/*
 * KNOD_IPSEC_GFX10_DIAG_STUB - graduated diagnostic stubs.
 * Uncomment exactly one level to bisect the SQC inst-fault:
 *
 *  Level 1: bare s_endpgm - tests KD, entry offset, BO mapping.
 *  Level 2: compute bd_addr from kernarg, store 0xDEAD0001, endpgm.
 *           Tests SGPR layout, VOP2/VOP1 ALU, GLOBAL load/store.
 *  Level 3: full Phase 0 (parse + SA scan) + write result, endpgm.
 *           Tests branches, patch_branch, VOP3B carry, SOPC.
 *
 * Leave all commented out for the real shader.
 */
/* #define KNOD_IPSEC_GFX10_DIAG_STUB 1 */
/* #define KNOD_IPSEC_GFX10_DIAG_STUB 7 */
/* #define KNOD_IPSEC_GFX10_DIAG_STUB 2 */
/* #define KNOD_IPSEC_GFX10_DIAG_STUB 3 */
/* #define KNOD_IPSEC_GFX10_DIAG_STUB 4 */
/* #define KNOD_IPSEC_GFX10_DIAG_STUB 5 */

static inline int kfd_ipsec_gen_fused_shader_gfx10(void *vbuf)
{
	int br_skip12, br_skip14, br_skip15, br_skip18, br_skip16, br_skip13;
	int br_skip_aad, br_skip_ctext, br_skip_len;
	int loop_top, br_match, br_loop, br_end;
	int br_no_sdma, br_no_copy, br_not_last;
	int br_ipv4, br_bypass, br_crypto_end;
	int br_ipv6, br_v6_to_common;
	int br_not_transport, li;
	const int L3_TMP_BASE = 14;	/* v14..v23 */
	u32 *buf = (u32 *)vbuf;
	int br_crypto_done;
	int br_execz_ctr;
	int br_execz2;
	int br_icv_bad;
	int br_icv_ok;
	int br_tid0;
	int br_skip;
	int br_ok;
	int level;
	int n = 0;

#if defined(KNOD_IPSEC_GFX10_DIAG_STUB) && KNOD_IPSEC_GFX10_DIAG_STUB == 1
	/* LEVEL 1: bare s_endpgm - if this faults, KD or BO mapping is
	 * wrong
	 */
	_E(emit_gfx10_s_endpgm, I10(buf, n));
	while (n % 256)
		_E(emit_gfx10_s_code_end, I10(buf, n));
	pr_info("knod_ipsec: GFX10 DIAG STUB level 1 (bare endpgm), %d bytes\n",
		n * 4);
	return n * 4;
#endif

#if defined(KNOD_IPSEC_GFX10_DIAG_STUB) && KNOD_IPSEC_GFX10_DIAG_STUB == 2
	/* LEVEL 2: load bd_addr from kernarg, write 0xDEAD0001 to bd+8.
	 * Tests: s8/s9 kernarg ptr, s16 workgroup_id_y, VOP1/VOP2 ALU,
	 * GLOBAL_LOAD_DWORDX2, GLOBAL_STORE_DWORD, s_waitcnt.
	 */
	_E(emit_gfx10_s_waitcnt_vmcnt_lgkmcnt, I10(buf, n));
	/* v1 = sub offset = 40 + wg_id_y * 32 */
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n), P_V(1), P_S(16));
	_E(emit_gfx10_v_lshlrev_b32, I10(buf, n), P_V(1), P_I(5), P_V(1));
	_E(emit_gfx10_v_add_nc_u32, I10(buf, n), P_V(1), P_L(SUB_BASE_OFF),
	   P_V(1));
	/* v[3:4] = &sub[wg_id_y] */
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n), P_V(2), P_S(9));
	_E(emit_gfx10_v_add_co_u32, I10(buf, n), P_V(3), P_S(8), P_V(1));
	_E(emit_gfx10_v_add_co_ci_u32_e32, I10(buf, n), P_V(4), P_I(0), P_V(2));
	/* v[5:6] = sub[].bd_addr */
	_E(emit_gfx10_global_load_dwordx2, I10(buf, n), P_V(5), P_V(3),
	   SUB_OFF_BD_ADDR);
	_E(emit_gfx10_s_waitcnt_vmcnt, I10(buf, n));
	/* v0 = 0 for lane check: only lane 0 writes */
	_E(emit_gfx10_v_cmp_eq_u32, I10(buf, n), P_I(0), P_V(0));
	br_skip = _BR(emit_gfx10_s_cbranch_vccz, I10(buf, n), 0);
	/* write 0xDEAD0001 to bd->act (offset +8) */
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n), P_V(7),
	   P_L(0xDEAD0001u));
	_E(emit_gfx10_global_store_dword, I10(buf, n), P_V(5), P_V(7), 8);
	_E(emit_gfx10_s_waitcnt_vmcnt, I10(buf, n));
	patch_branch(buf, br_skip, n);
	_E(emit_gfx10_s_endpgm, I10(buf, n));
	while (n % 256)
		_E(emit_gfx10_s_code_end, I10(buf, n));
	pr_info("knod_ipsec: GFX10 DIAG STUB level 2 (bd write), %d bytes\n",
		n * 4);
	return n * 4;
#endif

#if defined(KNOD_IPSEC_GFX10_DIAG_STUB) && KNOD_IPSEC_GFX10_DIAG_STUB == 3
	/* LEVEL 3: s_dcache_inv (SMEM 8-byte) + Level 2 body.
	 * If this faults but Level 2 passed, SMEM encoding is the culprit.
	 */
	_E(emit_gfx10_s_dcache_inv, I10(buf, n));
	_E(emit_gfx10_s_waitcnt_lgkmcnt, I10(buf, n));
	/* --- Level 2 body below --- */
	_E(emit_gfx10_s_waitcnt_vmcnt_lgkmcnt, I10(buf, n));
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n), P_V(1), P_S(16));
	_E(emit_gfx10_v_lshlrev_b32, I10(buf, n), P_V(1), P_I(5), P_V(1));
	_E(emit_gfx10_v_add_nc_u32, I10(buf, n), P_V(1), P_L(SUB_BASE_OFF),
	   P_V(1));
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n), P_V(2), P_S(9));
	_E(emit_gfx10_v_add_co_u32, I10(buf, n), P_V(3), P_S(8), P_V(1));
	_E(emit_gfx10_v_add_co_ci_u32_e32, I10(buf, n), P_V(4), P_I(0), P_V(2));
	_E(emit_gfx10_global_load_dwordx2, I10(buf, n), P_V(5), P_V(3),
	   SUB_OFF_BD_ADDR);
	_E(emit_gfx10_s_waitcnt_vmcnt, I10(buf, n));
	_E(emit_gfx10_v_cmp_eq_u32, I10(buf, n), P_I(0), P_V(0));
	br_skip = _BR(emit_gfx10_s_cbranch_vccz, I10(buf, n), 0);
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n), P_V(7),
	   P_L(0xDEAD0003u));
	_E(emit_gfx10_global_store_dword, I10(buf, n), P_V(5), P_V(7), 8);
	_E(emit_gfx10_s_waitcnt_vmcnt, I10(buf, n));
	patch_branch(buf, br_skip, n);
	_E(emit_gfx10_s_endpgm, I10(buf, n));
	while (n % 256)
		_E(emit_gfx10_s_code_end, I10(buf, n));
	pr_info("knod_ipsec: GFX10 DIAG STUB level 3 (SMEM + bd write), %d bytes\n",
		n * 4);
	return n * 4;
#endif

#if defined(KNOD_IPSEC_GFX10_DIAG_STUB) && KNOD_IPSEC_GFX10_DIAG_STUB == 4
	/* LEVEL 4: SOP1 + SOP2 + SOPC + SMEM + Level 2 body.
	 * Tests the three scalar encoding formats not covered by Levels 1-3.
	 *   SOP1: s_mov_b32 (encoding 0x17D)
	 *   SOP2: s_add_u32, s_lshr_b32 (encoding 0x2)
	 *   SOPC: s_cmp_eq_u32 + s_cbranch_scc1 (encoding 0x17E)
	 */
	_E(emit_gfx10_s_dcache_inv, I10(buf, n));
	_E(emit_gfx10_s_waitcnt_lgkmcnt, I10(buf, n));

	/* SOP1: s_mov_b32 s28, 0xCAFE0004 (literal) */
	_E(emit_gfx10_s_mov_b32, I10(buf, n), P_S(28), P_L(0xCAFE0004u));
	/* SOP2: s_add_u32 s28, s28, 1 (inline const) */
	_E(emit_gfx10_s_add_u32, I10(buf, n), P_S(28), P_S(28), P_I(1));
	/* SOP2: s_lshr_b32 s28, s28, 0 (nop shift) */
	_E(emit_gfx10_s_lshr_b32, I10(buf, n), P_S(28), P_S(28), P_I(0));
	/* SOPC: s_cmp_eq_u32 s28, 0xCAFE0005 - should set SCC=1 */
	_E(emit_gfx10_s_cmp_eq_u32, I10(buf, n), P_S(28), P_L(0xCAFE0005u));
	br_ok = _BR(emit_gfx10_s_cbranch_scc1, I10(buf, n), 0);
	/* SCC=0 path: write 0xBAD00004 as error marker */
	_E(emit_gfx10_s_mov_b32, I10(buf, n), P_S(28), P_L(0xBAD00004u));
	_E(emit_gfx10_s_endpgm, I10(buf, n));
	patch_branch(buf, br_ok, n);

	/* --- Level 2 body: bd write --- */
	_E(emit_gfx10_s_waitcnt_vmcnt_lgkmcnt, I10(buf, n));
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n), P_V(1), P_S(16));
	_E(emit_gfx10_v_lshlrev_b32, I10(buf, n), P_V(1), P_I(5), P_V(1));
	_E(emit_gfx10_v_add_nc_u32, I10(buf, n), P_V(1), P_L(SUB_BASE_OFF),
	   P_V(1));
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n), P_V(2), P_S(9));
	_E(emit_gfx10_v_add_co_u32, I10(buf, n), P_V(3), P_S(8), P_V(1));
	_E(emit_gfx10_v_add_co_ci_u32_e32, I10(buf, n), P_V(4), P_I(0), P_V(2));
	_E(emit_gfx10_global_load_dwordx2, I10(buf, n), P_V(5), P_V(3),
	   SUB_OFF_BD_ADDR);
	_E(emit_gfx10_s_waitcnt_vmcnt, I10(buf, n));
	_E(emit_gfx10_v_cmp_eq_u32, I10(buf, n), P_I(0), P_V(0));
	br_skip = _BR(emit_gfx10_s_cbranch_vccz, I10(buf, n), 0);
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n), P_V(7),
	   P_L(0xDEAD0004u));
	_E(emit_gfx10_global_store_dword, I10(buf, n), P_V(5), P_V(7), 8);
	_E(emit_gfx10_s_waitcnt_vmcnt, I10(buf, n));
	patch_branch(buf, br_skip, n);
	_E(emit_gfx10_s_endpgm, I10(buf, n));
	while (n % 256)
		_E(emit_gfx10_s_code_end, I10(buf, n));
	pr_info("knod_ipsec: GFX10 DIAG STUB level 4 (SOP1/SOP2/SOPC + bd), %d bytes\n",
		n * 4);
	return n * 4;
#endif

	/* ================================================================
	 * Phase 0: Parse ESP header + SA table lookup
	 *
	 * s_dcache_inv: flush K$ so s_load reads fresh round keys.
	 * ================================================================
	 */
	_E(emit_gfx10_s_dcache_inv, I10(buf, n));
	_E(emit_gfx10_s_waitcnt_lgkmcnt, I10(buf, n));
	_E(emit_gfx10_s_mov_b32, I10(buf, n), P_S(SR_BSWAP), P_L(0x00010203));

	/* v1 = 40 + wg_id_y*32 = offset of sub[wg_id_y] within kernarg */
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n), P_V(1), P_S(16));
	_E(emit_gfx10_v_lshlrev_b32, I10(buf, n), P_V(1), P_I(5), P_V(1));
	_E(emit_gfx10_v_add_nc_u32, I10(buf, n), P_V(1), P_L(SUB_BASE_OFF),
	   P_V(1));

	/* v[3:4] = kernarg_ptr + v1 = &sub[wg_id_y] */
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n), P_V(2), P_S(9));
	_E(emit_gfx10_v_add_co_u32, I10(buf, n), P_V(3), P_S(8), P_V(1));
	_E(emit_gfx10_v_add_co_ci_u32_e32, I10(buf, n), P_V(4), P_I(0), P_V(2));

	/* Load sub[].pkt_addr -> v[9:10], sub[].bd_addr -> v[5:6] */
	_E(emit_gfx10_global_load_dwordx2, I10(buf, n), P_V(9), P_V(3),
	   SUB_OFF_PKT_ADDR);
	_E(emit_gfx10_global_load_dwordx2, I10(buf, n), P_V(5), P_V(3),
	   SUB_OFF_BD_ADDR);
	_E(emit_gfx10_s_waitcnt_vmcnt, I10(buf, n));

	/* Seed v[11:12] with pkt_addr as a safe default BEFORE the IP
	 * version branch. The bypass path (non-v4/v6 packets like ARP)
	 * unconditionally branches past the v[11:12] setup at line ~195
	 * and later Phase 1 does a global_load at v[11:12]+ESP_REL_SEQ to
	 * read the ESP sequence number. Without this seed v[11:12] would
	 * hold uninitialised VGPR state (wave launch garbage), producing
	 * a fault at ~0x{random}_00000000. For valid v4/v6 packets the
	 * common path below overwrites v[11:12] with pkt+esp_hdr_off so
	 * this seed is harmless.
	 */
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n), P_V(11), P_V(9));
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n), P_V(12), P_V(10));

	/* IP version gate: load dword at pkt+12 to get first byte of L3
	 * header (byte[14]). Extract version nibble -> s28.
	 */
	_E(emit_gfx10_global_load_dword, I10(buf, n), P_V(15), P_V(9), 12);
	_E(emit_gfx10_s_waitcnt_vmcnt, I10(buf, n));

	_E(emit_gfx10_v_readfirstlane_b32, I10(buf, n), 28, 15);
	_E(emit_gfx10_s_lshr_b32, I10(buf, n), P_S(28), P_S(28), P_I(20));
	_E(emit_gfx10_s_and_b32_p, I10(buf, n), P_S(28), P_I(0xF), P_S(28));

	/* Check IPv4 (version==4) */
	_E(emit_gfx10_s_cmp_eq_u32, I10(buf, n), P_S(28), P_I(4));
	br_ipv4 = _BR(emit_gfx10_s_cbranch_scc1, I10(buf, n), 0);

	/* Check IPv6 (version==6) */
	_E(emit_gfx10_s_cmp_eq_u32, I10(buf, n), P_S(28), P_I(6));
	br_ipv6 = _BR(emit_gfx10_s_cbranch_scc1, I10(buf, n), 0);

	/* Bypass: neither IPv4 nor IPv6 */
	_E(emit_gfx10_s_mov_b32, I10(buf, n), P_S(26), P_L(0xFFFFFFFEu));
	br_bypass = _BR(emit_gfx10_s_branch, I10(buf, n), 0);

	/* IPv6 landing: esp_hdr_off = 54 */
	patch_branch(buf, br_ipv6, n);
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n), P_V(VR_SAVE_ESP_OFF),
	   P_L(ESP_HDR_OFF_V6));
	br_v6_to_common = _BR(emit_gfx10_s_branch, I10(buf, n), 0);

	/* IPv4 landing: esp_hdr_off = 34 */
	patch_branch(buf, br_ipv4, n);
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n), P_V(VR_SAVE_ESP_OFF),
	   P_L(ESP_HDR_OFF_V4));

	/* Common path: both IPv4 and IPv6 converge here */
	patch_branch(buf, br_v6_to_common, n);

	/* v[11:12] = pkt_addr + esp_hdr_off (dynamic) */
	_E(emit_gfx10_v_add_co_u32, I10(buf, n), P_V(11),
	   P_V(VR_SAVE_ESP_OFF), P_V(9));
	_E(emit_gfx10_v_add_co_ci_u32_e32, I10(buf, n), P_V(12), P_I(0),
	   P_V(10));

	/* v13 = *(u32*)(pkt + esp_hdr_off) - SPI in big-endian.
	 *
	 * GFX10 (RDNA2) quirk: global_load_dword silently clears EA's
	 * low 2 bits, so loading at v[11:12] = pkt + 34 (v4) or pkt + 54
	 * (v6) would actually read pkt + 32 / pkt + 52. Both ESP offsets
	 * are 2 mod 4, so the shift to reconstruct the target dword is
	 * always 16 bits. Use dwordx2 (HW still clears low 2 bits, but
	 * we get enough data) + v_alignbit_b32 to extract bytes
	 * [addr..addr+3] from the 8-byte window.
	 */
	_E(emit_gfx10_global_load_dwordx2, I10(buf, n), P_V(20), P_V(11), 0);
	_E(emit_gfx10_s_waitcnt_vmcnt, I10(buf, n));
	/* v_alignbit_b32 D, HIGH, LOW, shift: D = ({HIGH, LOW} >> shift)[31:0].
	 * tmp_lo = v20 (memory-low dword), tmp_hi = v21 (memory-high dword).
	 */
	_E(emit_gfx10_v_alignbit_b32, I10(buf, n), P_V(13), P_V(21), P_V(20),
	   P_I(16));

	/* Byteswap SPI: v13 = bswap32(v13) via v_perm_b32 */
	_E(emit_gfx10_v_perm_b32, I10(buf, n), P_V(13), P_V(13), P_V(13),
	   P_S(SR_BSWAP));

	/* SA table linear scan (VMEM path for K$ coherence).
	 * s22 = target SPI, s[24:25] = sa_table_addr, s23 = counter,
	 * s26 = result (slot_idx or 0xFFFFFFFF), v[16:17] = running ptr.
	 */
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n), P_V(16), P_S(8));
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n), P_V(17), P_S(9));
	_E(emit_gfx10_global_load_dwordx2, I10(buf, n), P_V(18), P_V(16), 0);
	_E(emit_gfx10_s_waitcnt_vmcnt, I10(buf, n));
	_E(emit_gfx10_v_readfirstlane_b32, I10(buf, n), 24, 18);
	_E(emit_gfx10_v_readfirstlane_b32, I10(buf, n), 25, 19);

	_E(emit_gfx10_v_readfirstlane_b32, I10(buf, n), 22, 13);
	_E(emit_gfx10_s_mov_b32, I10(buf, n), P_S(23), P_I(0));
	_E(emit_gfx10_s_mov_b32, I10(buf, n), P_S(26), P_L(0xFFFFFFFFu));

	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n), P_V(16), P_S(24));
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n), P_V(17), P_S(25));

	loop_top = n;
	_E(emit_gfx10_global_load_dword, I10(buf, n), P_V(20), P_V(16),
	   SA_OFF_SPI);
	_E(emit_gfx10_s_waitcnt_vmcnt, I10(buf, n));
	_E(emit_gfx10_v_readfirstlane_b32, I10(buf, n), 27, 20);

	_E(emit_gfx10_v_add_co_u32, I10(buf, n), P_V(16),
	   P_L(KNOD_IPSEC_SHADER_SA_ENTRY_SZ), P_V(16));
	_E(emit_gfx10_v_add_co_ci_u32_e32, I10(buf, n), P_V(17), P_I(0),
	   P_V(17));
	_E(emit_gfx10_s_add_u32, I10(buf, n), P_S(23), P_I(1), P_S(23));
	_E(emit_gfx10_s_nop, I10(buf, n));

	_E(emit_gfx10_s_cmp_eq_u32, I10(buf, n), P_S(27), P_S(22));
	br_match = _BR(emit_gfx10_s_cbranch_scc1, I10(buf, n), 0);

	_E(emit_gfx10_s_cmp_lt_u32, I10(buf, n), P_S(23),
	   P_L(KNOD_IPSEC_SHADER_NR_SA));
	br_loop = _BR(emit_gfx10_s_cbranch_scc1, I10(buf, n), 0);
	patch_branch(buf, br_loop, loop_top);

	br_end = _BR(emit_gfx10_s_branch, I10(buf, n), 0);

	/* Match: s26 = s23 - 1 */
	patch_branch(buf, br_match, n);
	_E(emit_gfx10_s_sub_u32_p, I10(buf, n), P_S(26), P_S(23), P_I(1));

	patch_branch(buf, br_end, n);

	patch_branch(buf, br_bypass, n);

#if defined(KNOD_IPSEC_GFX10_DIAG_STUB) && KNOD_IPSEC_GFX10_DIAG_STUB == 5
	/* LEVEL 5: early exit after real Phase 0.
	 * s26 = slot_idx (or 0xFFFFFFFF if no match).
	 * Write s26 to bd->act via v[5:6] (bd_addr loaded during Phase 0).
	 */
	_E(emit_gfx10_v_cmp_eq_u32, I10(buf, n), P_I(0), P_V(0));
	br_skip = _BR(emit_gfx10_s_cbranch_vccz, I10(buf, n), 0);
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n), P_V(7),
	   P_L(0xDEAD0005u));
	_E(emit_gfx10_global_store_dword, I10(buf, n), P_V(5), P_V(7), 8);
	_E(emit_gfx10_s_waitcnt_vmcnt, I10(buf, n));
	patch_branch(buf, br_skip, n);
	_E(emit_gfx10_s_endpgm, I10(buf, n));
	while (n % 256)
		_E(emit_gfx10_s_code_end, I10(buf, n));
	pr_info("knod_ipsec: GFX10 DIAG STUB level 5 (Phase 0 + exit), %d bytes\n",
		n * 4);
	return n * 4;
#endif

	/* ================================================================
	 * Phase 1: Save pre-crypto state + load extra sub[] fields
	 *
	 * Move IPsec-specific values to v30+ so v1-v22 and s18-s49 are
	 * free for AES-GCM helpers from aesgcm_shader.h.
	 * ================================================================
	 */
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n), P_V(VR_SAVE_SLOT), P_S(26));
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n), P_V(VR_SAVE_BD_LO), P_V(5));
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n), P_V(VR_SAVE_BD_HI), P_V(6));
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n), P_V(VR_SAVE_PKT_LO), P_V(9));
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n), P_V(VR_SAVE_PKT_HI), P_V(10));
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n), P_V(VR_SAVE_SPI), P_V(13));

	/* Load sub[].out_addr -> v[VR_SAVE_OUT_LO:VR_SAVE_OUT_HI] */
	_E(emit_gfx10_global_load_dwordx2, I10(buf, n), P_V(VR_SAVE_OUT_LO),
	   P_V(3), SUB_OFF_OUT_ADDR);
	/* Load sub[].pkt_len -> v[VR_SAVE_PKTLEN] */
	_E(emit_gfx10_global_load_dword, I10(buf, n), P_V(VR_SAVE_PKTLEN),
	   P_V(3), SUB_OFF_PKT_LEN);
	_E(emit_gfx10_s_waitcnt_vmcnt, I10(buf, n));

	/* Load ESP seq number: pkt + esp_hdr_off + 4, BE -> bswap ->
	 * v[VR_SAVE_SEQ].
	 * v[11:12] still holds pkt_addr + esp_hdr_off from Phase 0.
	 *
	 * GFX10 unaligned load fix: esp_hdr_off is 34(v4) or 54(v6),
	 * both == 2 mod 4. EA = pkt+38 clips to pkt+36. Load dwordx2
	 * from the clipped addr, then v_alignbit_b32 shift=16 to
	 * reconstruct the target dword.  v[20:21] are free scratch.
	 */
	_E(emit_gfx10_global_load_dwordx2, I10(buf, n), P_V(20), P_V(11),
	   ESP_REL_SEQ);
	_E(emit_gfx10_s_waitcnt_vmcnt, I10(buf, n));
	_E(emit_gfx10_v_alignbit_b32, I10(buf, n), P_V(VR_SAVE_SEQ), P_V(21),
	   P_V(20), P_I(16));

	_E(emit_gfx10_v_perm_b32, I10(buf, n), P_V(VR_SAVE_SEQ),
	   P_V(VR_SAVE_SEQ), P_V(VR_SAVE_SEQ), P_S(SR_BSWAP));

	/* Write bswapped seq back into sub[].result_seq for CPU finish worker.
	 * v[3:4] still points to &sub[wg_id_y].
	 */
	_E(emit_gfx10_global_store_dword, I10(buf, n), P_V(3),
	   P_V(VR_SAVE_SEQ), SUB_OFF_RESULT_SEQ);

	/* ================================================================
	 * Phase 2: Branch on miss/bypass - skip crypto entirely
	 * ================================================================
	 */
	_E(emit_gfx10_v_readfirstlane_b32, I10(buf, n), 26, VR_SAVE_SLOT);
	_E(emit_gfx10_s_cmp_ge_u32, I10(buf, n), P_S(26),
	   P_L(KNOD_IPSEC_SHADER_NR_SA));
	br_crypto_end = _BR(emit_gfx10_s_cbranch_scc1, I10(buf, n), 0);

	/* ================================================================
	 * Phase 3: Load SA entry fields for the matched slot
	 *
	 * entry_addr = sa_table_addr + slot_idx * SA_ENTRY_SIZE
	 * Load: key_gpu_addr, salt, nr_rounds, t_tables_gpu_addr,
	 *       htable_gpu_addr
	 * ================================================================
	 */
	/* s27 = slot_idx * SA_ENTRY_SIZE (scalar mul) */
	_E(emit_gfx10_s_mul_i32, I10(buf, n), P_S(27), P_S(26),
	   P_L(KNOD_IPSEC_SHADER_SA_ENTRY_SZ));
	/* s[24:25] = sa_table_addr (already there from Phase 0 scan) */
	_E(emit_gfx10_s_add_u32, I10(buf, n), P_S(24), P_S(24), P_S(27));
	_E(emit_gfx10_s_addc_u32, I10(buf, n), P_S(25), P_S(25), P_I(0));

	/* Use VMEM for coherence: stage entry addr into VGPR pair */
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n), P_V(VR_GA_LO), P_S(24));
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n), P_V(VR_GA_HI), P_S(25));

	/* Batched SA entry loads: issue all 4 loads to different
	 * VGPR destinations, then single waitcnt. v1-v8 (S0-S3,
	 * D0-D3) are free at Phase 3 - not used until Phase 7.
	 *
	 * Layout:
	 *   dwordx4 @+16 -> v[1:4]: key_lo, key_hi, htable_lo, htable_hi
	 *   dwordx4 @+32 -> v[5:8]: ttables_lo, ttables_hi, salt, key_len
	 *   dwordx2 @+48 -> v[14:15]: nr_rounds, mode
	 *   dwordx2 @+88 -> v[16:17]: stats_lo, stats_hi
	 */
	_E(emit_gfx10_global_load_dwordx4, I10(buf, n), P_V(VR_S0),
	   P_V(VR_GA_LO), SA_OFF_KEY_ADDR);
	_E(emit_gfx10_global_load_dwordx4, I10(buf, n), P_V(VR_D0),
	   P_V(VR_GA_LO), SA_OFF_T_TABLES_ADDR);
	_E(emit_gfx10_global_load_dwordx2, I10(buf, n), P_V(VR_DATA0),
	   P_V(VR_GA_LO), SA_OFF_NR_ROUNDS);
	_E(emit_gfx10_global_load_dwordx2, I10(buf, n), P_V(VR_DATA2),
	   P_V(VR_GA_LO), SA_OFF_STATS_ADDR);
	_E(emit_gfx10_s_waitcnt_vmcnt, I10(buf, n));

	/* key_addr: v1=lo, v2=hi */
	_E(emit_gfx10_v_readfirstlane_b32, I10(buf, n), SR_KEYS, VR_S0);
	_E(emit_gfx10_v_readfirstlane_b32, I10(buf, n), SR_KEYS + 1, VR_S1);
	/* htable_addr: v3=lo, v4=hi */
	_E(emit_gfx10_v_readfirstlane_b32, I10(buf, n), SR_HTABLE_LO, VR_S2);
	_E(emit_gfx10_v_readfirstlane_b32, I10(buf, n), SR_HTABLE_HI, VR_S3);
	/* t_tables_addr: v5=lo, v6=hi */
	_E(emit_gfx10_v_readfirstlane_b32, I10(buf, n), SR_T_ADDR, VR_D0);
	_E(emit_gfx10_v_readfirstlane_b32, I10(buf, n), SR_T_ADDR + 1, VR_D1);
	/* salt: v7 */
	_E(emit_gfx10_v_readfirstlane_b32, I10(buf, n), SR_IV0, VR_D2);
	/* nr_rounds: v14, mode: v15 */
	_E(emit_gfx10_v_readfirstlane_b32, I10(buf, n), SR_NR_ROUNDS, VR_DATA0);
	_E(emit_gfx10_v_readfirstlane_b32, I10(buf, n), SR_SA_MODE, VR_DATA1);
	/* stats_addr: v16=lo, v17=hi -> save VGPRs for Phase 10 */
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n), P_V(VR_SAVE_STATS_LO),
	   P_V(VR_DATA2));
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n), P_V(VR_SAVE_STATS_HI),
	   P_V(VR_DATA3));

	/* ================================================================
	 * Phase 4: Build AES-GCM nonce
	 *
	 * nonce[12] = salt[4] || IV[8]
	 * salt is already in s[SR_IV0]. Load IV from pkt + esp_hdr_off + 8.
	 * Recompute ESP base from saved pkt_addr + VR_SAVE_ESP_OFF since
	 * v[11:12] were clobbered by Phase 3 SA loads (VR_GA_LO=12).
	 * IV goes to s[SR_IV1] (bytes 4-7) and s[SR_IV2] (bytes 8-11).
	 * ================================================================
	 */
	_E(emit_gfx10_v_add_co_u32, I10(buf, n), P_V(VR_GA_LO),
	   P_V(VR_SAVE_ESP_OFF), P_V(VR_SAVE_PKT_LO));
	_E(emit_gfx10_v_add_co_ci_u32_e32, I10(buf, n), P_V(VR_GA_HI),
	   P_I(0), P_V(VR_SAVE_PKT_HI));
	/* GFX10 unaligned load fix: EA = pkt+42/62 == 2 mod 4, clips
	 * to pkt+40/60. Load dwordx4 (16B from clipped addr), then
	 * alignbit shift=16 to reconstruct IV[0:3] and IV[4:7].
	 */
	_E(emit_gfx10_global_load_dwordx4, I10(buf, n), P_V(VR_DATA0),
	   P_V(VR_GA_LO), ESP_REL_IV);
	_E(emit_gfx10_s_waitcnt_vmcnt, I10(buf, n));
	_E(emit_gfx10_v_alignbit_b32, I10(buf, n), P_V(VR_DATA0),
	   P_V(VR_DATA1), P_V(VR_DATA0), P_I(16));
	_E(emit_gfx10_v_alignbit_b32, I10(buf, n), P_V(VR_DATA1),
	   P_V(VR_DATA2), P_V(VR_DATA1), P_I(16));
	_E(emit_gfx10_v_readfirstlane_b32, I10(buf, n), SR_IV1, VR_DATA0);
	_E(emit_gfx10_v_readfirstlane_b32, I10(buf, n), SR_IV2, VR_DATA1);

	/* ================================================================
	 * Phase 5: Compute ciphertext bounds
	 *
	 * ctext_off = esp_hdr_off + 16 (SPI+seq+IV)
	 * ctext_len = pkt_len - ctext_off - ICV_LEN
	 * nblocks = (ctext_len + 15) >> 4
	 *
	 * s28 is free here (last used in version gate) - use as scratch.
	 * ================================================================
	 */
	_E(emit_gfx10_v_readfirstlane_b32, I10(buf, n), 28, VR_SAVE_ESP_OFF);
	_E(emit_gfx10_s_add_u32, I10(buf, n), P_S(28),
	   P_I(ESP_REL_CTEXT + ESP_ICV_LEN),
	   P_S(28));  /* s28 = ctext_off + ICV_LEN = overhead to subtract */
	_E(emit_gfx10_v_readfirstlane_b32, I10(buf, n), SR_CTEXT_LEN,
	   VR_SAVE_PKTLEN);
	_E(emit_gfx10_s_sub_u32_p, I10(buf, n), P_S(SR_CTEXT_LEN),
	   P_S(SR_CTEXT_LEN), P_S(28));
	/* s[SR_NBLOCKS_GCM] = (ctext_len + 15) >> 4 */
	_E(emit_gfx10_s_add_u32, I10(buf, n), P_S(SR_NBLOCKS_GCM), P_I(15),
	   P_S(SR_CTEXT_LEN));
	_E(emit_gfx10_s_lshr_b32, I10(buf, n), P_S(SR_NBLOCKS_GCM),
	   P_S(SR_NBLOCKS_GCM), P_I(4));
	/* total GHASH blocks = 1(AAD) + nblocks(ctext) + 1(len) = nblocks + 2
	 */
	_E(emit_gfx10_s_add_u32, I10(buf, n), P_S(SR_TOTAL_GHASH_BLK),
	   P_I(2), P_S(SR_NBLOCKS_GCM));

	/* ================================================================
	 * Phase 6: Cooperative T-table load (VRAM -> LDS)
	 *
	 * All 256 threads load from SA's t_tables_gpu_addr. Each thread
	 * loads one u32 per table (4 tables x 256 entries = 4KB).
	 * ================================================================
	 */
	_E(emit_gfx10_s_mov_b32, I10(buf, n), P_S(SR_MASK), P_L(0xFF));

	/* v[VR_TMP] = tid * 4 (byte offset within each 1KB table) */
	_E(emit_gfx10_v_lshlrev_b32, I10(buf, n), P_V(VR_TMP), P_I(2),
	   P_V(VR_TID));

	/* T0: VRAM[t_tables + tid*4] -> LDS[tid*4] */
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n), P_V(VR_GA_LO),
	   P_S(SR_T_ADDR));
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n), P_V(VR_GA_HI),
	   P_S(SR_T_ADDR + 1));
	_E(emit_gfx10_v_add_co_u32, I10(buf, n), P_V(VR_GA_LO), P_V(VR_GA_LO),
	   P_V(VR_TMP));
	_E(emit_gfx10_v_add_co_ci_u32_e32, I10(buf, n), P_V(VR_GA_HI), P_I(0),
	   P_V(VR_GA_HI));
	/* GFX10 GLOBAL offset is 12-bit signed (-2048..+2047).
	 * Offsets 2048 and 3072 overflow, so advance the base VGPR
	 * after the first two loads.
	 */
	_E(emit_gfx10_global_load_dword, I10(buf, n), P_V(VR_DATA0),
	   P_V(VR_GA_LO), 0);
	_E(emit_gfx10_global_load_dword, I10(buf, n), P_V(VR_DATA1),
	   P_V(VR_GA_LO), 1024);
	_E(emit_gfx10_v_add_co_u32, I10(buf, n), P_V(VR_GA_LO), P_L(2048),
	   P_V(VR_GA_LO));
	_E(emit_gfx10_v_add_co_ci_u32_e32, I10(buf, n), P_V(VR_GA_HI), P_I(0),
	   P_V(VR_GA_HI));
	_E(emit_gfx10_global_load_dword, I10(buf, n), P_V(VR_DATA2),
	   P_V(VR_GA_LO), 0);
	_E(emit_gfx10_global_load_dword, I10(buf, n), P_V(VR_DATA3),
	   P_V(VR_GA_LO), 1024);
	_E(emit_gfx10_s_waitcnt_vmcnt, I10(buf, n));

	/* Write to LDS: T0 at +0, T1 at +1024, T2 at +2048, T3 at +3072 */
	_E(emit_gfx10_ds_write_b32, I10(buf, n), VR_TMP, VR_DATA0);
	_E(emit_gfx10_v_add_nc_u32, I10(buf, n), P_V(VR_ADDR), P_L(1024),
	   P_V(VR_TMP));
	_E(emit_gfx10_ds_write_b32, I10(buf, n), VR_ADDR, VR_DATA1);
	_E(emit_gfx10_v_add_nc_u32, I10(buf, n), P_V(VR_ADDR), P_L(2048),
	   P_V(VR_TMP));
	_E(emit_gfx10_ds_write_b32, I10(buf, n), VR_ADDR, VR_DATA2);
	_E(emit_gfx10_v_add_nc_u32, I10(buf, n), P_V(VR_ADDR), P_L(3072),
	   P_V(VR_TMP));
	_E(emit_gfx10_ds_write_b32, I10(buf, n), VR_ADDR, VR_DATA3);

	_E(emit_gfx10_s_waitcnt_lgkmcnt, I10(buf, n));
	_E(emit_gfx10_s_barrier, I10(buf, n));

#if defined(KNOD_IPSEC_GFX10_DIAG_STUB) && KNOD_IPSEC_GFX10_DIAG_STUB == 6
	/* LEVEL 6: early exit after Phase 6 (T-table -> LDS + barrier).
	 * Tests Phase 1-6: SA loads, nonce build, DS writes, s_barrier.
	 * bd_addr is in v[VR_SAVE_BD_LO:VR_SAVE_BD_HI] = v[31:32].
	 */
	_E(emit_gfx10_v_cmp_eq_u32, I10(buf, n), P_I(0), P_V(0));
	br_skip = _BR(emit_gfx10_s_cbranch_vccz, I10(buf, n), 0);
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n), P_V(7),
	   P_L(0xDEAD0006u));
	_E(emit_gfx10_global_store_dword, I10(buf, n), P_V(VR_SAVE_BD_LO),
	   P_V(7), 8);
	_E(emit_gfx10_s_waitcnt_vmcnt, I10(buf, n));
	patch_branch(buf, br_skip, n);
	_E(emit_gfx10_s_endpgm, I10(buf, n));
	while (n % 256)
		_E(emit_gfx10_s_code_end, I10(buf, n));
	pr_info("knod_ipsec: GFX10 DIAG STUB level 6 (Phase 0-6 + exit), %d bytes\n",
		n * 4);
	return n * 4;
#endif

	/* ================================================================
	 * Phase 7: AES-CTR decrypt
	 *
	 * Each thread handles block_id = tid. Only threads with tid <
	 * nblocks are active. Counter = nonce[12] || bswap32(tid+2).
	 * AES-encrypt the counter -> keystream. XOR with ciphertext ->
	 * plaintext. Store to out_addr + tid*16.
	 * ================================================================
	 */
	/* VCC = (nblocks > tid) i.e. tid < nblocks - selects active CTR lanes
	 */
	_E(emit_gfx10_v_cmp_gt_u32, I10(buf, n), P_S(SR_NBLOCKS_GCM),
	   P_V(VR_TID));
	_E(emit_gfx10_s_and_saveexec_b64, I10(buf, n), SR_EXEC_SAVE,
	   106 /* VCC_LO */);
	br_execz_ctr = _BR(emit_gfx10_s_cbranch_execz, I10(buf, n), 0);

	/* Save SR_KEYS for reload after this block encrypt */
	_E(emit_gfx10_s_mov_b32, I10(buf, n), P_S(SR_T_ADDR), P_S(SR_KEYS));
	_E(emit_gfx10_s_mov_b32, I10(buf, n), P_S(SR_T_ADDR + 1),
	   P_S(SR_KEYS + 1));

	/* Prefetch ciphertext into v[23:27] before AES.
	 * GFX10 unaligned fix: ctext addr == 2 mod 4, so load
	 * dwordx4 (clips to aligned) + extra dword at +16.
	 * The ~200+ cycle AES encrypt hides the VMEM latency.
	 * v23-v27 are not touched by AES rounds (which use
	 * v1-v10 only). VR_GA/VR_BLK are also AES-safe.
	 */
	_E(emit_gfx10_v_lshlrev_b32, I10(buf, n), P_V(VR_BLK), P_I(4),
	   P_V(VR_TID));
	_E(emit_gfx10_v_add_co_u32, I10(buf, n), P_V(VR_GA_LO),
	   P_V(VR_SAVE_ESP_OFF), P_V(VR_SAVE_PKT_LO));
	_E(emit_gfx10_v_add_co_ci_u32_e32, I10(buf, n), P_V(VR_GA_HI),
	   P_I(0), P_V(VR_SAVE_PKT_HI));
	_E(emit_gfx10_v_add_co_u32, I10(buf, n), P_V(VR_GA_LO),
	   P_I(ESP_REL_CTEXT), P_V(VR_GA_LO));
	_E(emit_gfx10_v_add_co_ci_u32_e32, I10(buf, n), P_V(VR_GA_HI),
	   P_I(0), P_V(VR_GA_HI));
	_E(emit_gfx10_v_add_co_u32, I10(buf, n), P_V(VR_GA_LO),
	   P_V(VR_GA_LO), P_V(VR_BLK));
	_E(emit_gfx10_v_add_co_ci_u32_e32, I10(buf, n), P_V(VR_GA_HI),
	   P_I(0), P_V(VR_GA_HI));
	_E(emit_gfx10_global_load_dwordx4, I10(buf, n), P_V(VR_PREFETCH0),
	   P_V(VR_GA_LO), 0);
	_E(emit_gfx10_global_load_dword, I10(buf, n), P_V(VR_PREFETCH4),
	   P_V(VR_GA_LO), 16);

	/* Build AES counter block in v[VR_S0:VR_S3]:
	 * VR_S0 = nonce[0:3] = salt (SR_IV0)
	 * VR_S1 = nonce[4:7] = IV[0:3] (SR_IV1)
	 * VR_S2 = nonce[8:11] = IV[4:7] (SR_IV2)
	 * VR_S3 = bswap32(tid + 2)
	 */
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n), P_V(VR_S0), P_S(SR_IV0));
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n), P_V(VR_S1), P_S(SR_IV1));
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n), P_V(VR_S2), P_S(SR_IV2));

	/* v[VR_S3] = bswap32(tid + 2) */
	_E(emit_gfx10_v_add_nc_u32, I10(buf, n), P_V(VR_S3), P_I(2),
	   P_V(VR_TID));
	_E(emit_gfx10_v_perm_b32, I10(buf, n), P_V(VR_S3), P_V(VR_S3),
	   P_V(VR_S3), P_S(SR_BSWAP));

	/* AES encrypt the counter block -> result in v[VR_S0:VR_S3] */
#if defined(KNOD_IPSEC_GFX10_DIAG_STUB) && KNOD_IPSEC_GFX10_DIAG_STUB == 7
	/* LEVEL 7: exit just before emit_aes_encrypt_block_gfx10.
	 * If this passes but Level 8 (after encrypt) faults,
	 * the AES block cipher GFX10 code is the culprit.
	 */
	_E(emit_gfx10_v_cmp_eq_u32, I10(buf, n), P_I(0), P_V(0));
	br_skip = _BR(emit_gfx10_s_cbranch_vccz, I10(buf, n), 0);
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n), P_V(7),
	   P_L(0xDEAD0007u));
	_E(emit_gfx10_global_store_dword, I10(buf, n),
	   P_V(VR_SAVE_BD_LO), P_V(7), 8);
	_E(emit_gfx10_s_waitcnt_vmcnt, I10(buf, n));
	patch_branch(buf, br_skip, n);
	_E(emit_gfx10_s_endpgm, I10(buf, n));
	while (n % 256)
		_E(emit_gfx10_s_code_end, I10(buf, n));
	pr_info("knod_ipsec: GFX10 DIAG STUB level 7 (before AES encrypt), %d bytes\n",
		n * 4);
	return n * 4;
#endif
	n = emit_aes_encrypt_block_gfx10(buf, n);

#if defined(KNOD_IPSEC_GFX10_DIAG_STUB) && KNOD_IPSEC_GFX10_DIAG_STUB == 8
	/* LEVEL 8: exit right after first emit_aes_encrypt_block_gfx10.
	 * If this faults, the illegal insn is inside the AES block cipher.
	 */
	_E(emit_gfx10_v_cmp_eq_u32, I10(buf, n), P_I(0), P_V(0));
	br_skip = _BR(emit_gfx10_s_cbranch_vccz, I10(buf, n), 0);
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n), P_V(7),
	   P_L(0xDEAD0008u));
	_E(emit_gfx10_global_store_dword, I10(buf, n),
	   P_V(VR_SAVE_BD_LO), P_V(7), 8);
	_E(emit_gfx10_s_waitcnt_vmcnt, I10(buf, n));
	patch_branch(buf, br_skip, n);
	_E(emit_gfx10_s_endpgm, I10(buf, n));
	while (n % 256)
		_E(emit_gfx10_s_code_end, I10(buf, n));
	pr_info("knod_ipsec: GFX10 DIAG STUB level 8 (after AES encrypt), %d bytes\n",
		n * 4);
	return n * 4;
#endif

	/* Ciphertext arrived during AES - drain vmcnt */
	_E(emit_gfx10_s_waitcnt_vmcnt, I10(buf, n));

	/* GFX10 unaligned fix: 4x alignbit on prefetched data */
	_E(emit_gfx10_v_alignbit_b32, I10(buf, n), P_V(VR_PREFETCH0),
	   P_V(VR_PREFETCH1), P_V(VR_PREFETCH0), P_I(16));
	_E(emit_gfx10_v_alignbit_b32, I10(buf, n), P_V(VR_PREFETCH1),
	   P_V(VR_PREFETCH2), P_V(VR_PREFETCH1), P_I(16));
	_E(emit_gfx10_v_alignbit_b32, I10(buf, n), P_V(VR_PREFETCH2),
	   P_V(VR_PREFETCH3), P_V(VR_PREFETCH2), P_I(16));
	_E(emit_gfx10_v_alignbit_b32, I10(buf, n), P_V(VR_PREFETCH3),
	   P_V(VR_PREFETCH4), P_V(VR_PREFETCH3), P_I(16));

	/* XOR keystream with ciphertext -> plaintext */
	_E(emit_gfx10_v_xor_b32_e32, I10(buf, n), P_V(VR_PREFETCH0),
	   P_V(VR_S0), P_V(VR_PREFETCH0));
	_E(emit_gfx10_v_xor_b32_e32, I10(buf, n), P_V(VR_PREFETCH1),
	   P_V(VR_S1), P_V(VR_PREFETCH1));
	_E(emit_gfx10_v_xor_b32_e32, I10(buf, n), P_V(VR_PREFETCH2),
	   P_V(VR_S2), P_V(VR_PREFETCH2));
	_E(emit_gfx10_v_xor_b32_e32, I10(buf, n), P_V(VR_PREFETCH3),
	   P_V(VR_S3), P_V(VR_PREFETCH3));

	/* Store plaintext to out_addr + tid*16 */
	_E(emit_gfx10_v_add_co_u32, I10(buf, n), P_V(VR_GA_LO),
	   P_V(VR_BLK), P_V(VR_SAVE_OUT_LO));
	_E(emit_gfx10_v_add_co_ci_u32_e32, I10(buf, n), P_V(VR_GA_HI),
	   P_I(0), P_V(VR_SAVE_OUT_HI));
	_E(emit_gfx10_global_store_dwordx4, I10(buf, n), P_V(VR_GA_LO),
	   P_V(VR_PREFETCH0), 0);

	patch_branch(buf, br_execz_ctr, n);

	/* ================================================================
	 * Phase 7.5: Compute AES(K, J0) for ICV finalization
	 *
	 * J0 = nonce[12] || 0x00000001 (BE). Only thread 0 needs this
	 * but all active lanes can compute it; we just save the result.
	 * ================================================================
	 */
	/* Restore SR_KEYS (consumed by encrypt_block) */
	_E(emit_gfx10_s_mov_b32, I10(buf, n), P_S(SR_KEYS), P_S(SR_T_ADDR));
	_E(emit_gfx10_s_mov_b32, I10(buf, n), P_S(SR_KEYS + 1),
	   P_S(SR_T_ADDR + 1));

	/* Restore full EXEC for J0 encrypt (all 256 threads) */
	_E(emit_gfx10_s_or_b64, I10(buf, n), 126 /* EXEC_LO */, SR_EXEC_SAVE,
	   SR_EXEC_SAVE);

	/* J0 block: nonce || bswap32(1) = nonce || 0x01000000 */
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n), P_V(VR_S0), P_S(SR_IV0));
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n), P_V(VR_S1), P_S(SR_IV1));
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n), P_V(VR_S2), P_S(SR_IV2));
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n), P_V(VR_S3), P_L(0x01000000u));

	n = emit_aes_encrypt_block_gfx10(buf, n);

	/* Save AES(K, J0) -> v[VR_J0_0:VR_J0_3] */
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n), P_V(VR_J0_0), P_V(VR_S0));
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n), P_V(VR_J0_1), P_V(VR_S1));
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n), P_V(VR_J0_2), P_V(VR_S2));
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n), P_V(VR_J0_3), P_V(VR_S3));

	_E(emit_gfx10_s_barrier, I10(buf, n));

#if defined(KNOD_IPSEC_GFX10_DIAG_STUB) && KNOD_IPSEC_GFX10_DIAG_STUB == 9
	/* LEVEL 9: exit after Phase 7.5 (J0 encrypt + barrier).
	 * Tests Phase 7 ctext XOR+store, Phase 7.5 second AES encrypt,
	 * s_or_b64 EXEC restore, s_barrier.
	 */
	_E(emit_gfx10_v_cmp_eq_u32, I10(buf, n), P_I(0), P_V(0));
	br_skip = _BR(emit_gfx10_s_cbranch_vccz, I10(buf, n), 0);
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n), P_V(7),
	   P_L(0xDEAD0009u));
	_E(emit_gfx10_global_store_dword, I10(buf, n),
	   P_V(VR_SAVE_BD_LO), P_V(7), 8);
	_E(emit_gfx10_s_waitcnt_vmcnt, I10(buf, n));
	patch_branch(buf, br_skip, n);
	_E(emit_gfx10_s_endpgm, I10(buf, n));
	while (n % 256)
		_E(emit_gfx10_s_code_end, I10(buf, n));
	pr_info("knod_ipsec: GFX10 DIAG STUB level 9 (Phase 7.5 + exit), %d bytes\n",
		n * 4);
	return n * 4;
#endif

	/* ================================================================
	 * Phase 8: Parallel GHASH
	 *
	 * GHASH input blocks (total_blocks = nblocks + 2):
	 *   tid 0            -> AAD: SPI(4B,BE)||seq(4B,BE)||0s (16B)
	 *   tid 1..nblocks   -> ciphertext block (tid-1)
	 *   tid nblocks+1    -> len: AAD_bitlen(64b)||ctext_bitlen(64b)
	 *   tid > nblocks+1  -> zero (does not participate)
	 *
	 * Each thread loads its block -> v[VR_DATA0:VR_DATA3] (big-endian
	 * for GF multiply), loads H^(total-tid) -> v[VR_D0:VR_D3], runs
	 * GF multiply -> v[VR_S0:VR_S3], then tree-reduces via LDS XOR.
	 * ================================================================
	 */
	/* Prefetch H^(total-tid) from H-power table before data selection.
	 * The ~60 ALU instructions in the data selection block below
	 * cover the VMEM latency. Result lands in VR_D0:D3, which
	 * data selection does not touch. VR_TMP/VR_GA are consumed
	 * here then free for reuse by the ctext section.
	 */
	_E(emit_gfx10_v_sub_nc_u32, I10(buf, n), P_V(VR_TMP),
	   P_S(SR_TOTAL_GHASH_BLK), P_V(VR_TID));
	_E(emit_gfx10_v_add_nc_u32, I10(buf, n), P_V(VR_TMP),
	   P_L(0xFFFFFFFF), P_V(VR_TMP));
	_E(emit_gfx10_v_max_i32, I10(buf, n), P_V(VR_TMP), P_I(0), P_V(VR_TMP));
	_E(emit_gfx10_v_lshlrev_b32, I10(buf, n), P_V(VR_TMP), P_I(4),
	   P_V(VR_TMP));
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n), P_V(VR_GA_LO),
	   P_S(SR_HTABLE_LO));
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n), P_V(VR_GA_HI),
	   P_S(SR_HTABLE_HI));
	_E(emit_gfx10_v_add_co_u32, I10(buf, n), P_V(VR_GA_LO),
	   P_V(VR_GA_LO), P_V(VR_TMP));
	_E(emit_gfx10_v_add_co_ci_u32_e32, I10(buf, n), P_V(VR_GA_HI),
	   P_I(0), P_V(VR_GA_HI));
	_E(emit_gfx10_global_load_dwordx4, I10(buf, n), P_V(VR_D0),
	   P_V(VR_GA_LO), 0);

	/* EXEC-based per-lane data selection. Default = zero, then
	 * each case narrows EXEC to matching lanes and writes data.
	 * This avoids scalar VCC branching (s_cbranch_vccnz) which
	 * makes the entire wave take one path, not individual lanes.
	 */
	/* Default: all threads get zero (non-participating) */
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n), P_V(VR_DATA0), P_I(0));
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n), P_V(VR_DATA1), P_I(0));
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n), P_V(VR_DATA2), P_I(0));
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n), P_V(VR_DATA3), P_I(0));

	/* ---- AAD: tid == 0 ---- */
	_E(emit_gfx10_v_cmp_eq_u32, I10(buf, n), P_I(0), P_V(VR_TID));
	_E(emit_gfx10_s_and_saveexec_b64, I10(buf, n), SR_GHASH_EXEC,
	   106 /* VCC */);
	br_skip_aad = _BR(emit_gfx10_s_cbranch_execz, I10(buf, n), 0);

	/* VR_SAVE_SPI/SEQ are already in BE register convention:
	 * raw LE load from packet (BE wire bytes) + bswap = byte[0]
	 * in bits[31:24]. No second bswap needed - use directly.
	 */
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n), P_V(VR_DATA0),
	   P_V(VR_SAVE_SPI));
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n), P_V(VR_DATA1),
	   P_V(VR_SAVE_SEQ));
	/* DATA2, DATA3 already 0 */

	patch_branch(buf, br_skip_aad, n);
	_E(emit_gfx10_s_mov_b64, I10(buf, n), 126 /* EXEC */,
	   SR_GHASH_EXEC);

#if defined(KNOD_IPSEC_GFX10_DIAG_STUB) && KNOD_IPSEC_GFX10_DIAG_STUB == 12
	_E(emit_gfx10_v_cmp_eq_u32, I10(buf, n), P_I(0), P_V(0));
	br_skip12 = _BR(emit_gfx10_s_cbranch_vccz, I10(buf, n), 0);
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n), P_V(7), P_L(0xDEAD000Cu));
	_E(emit_gfx10_global_store_dword, I10(buf, n), P_V(VR_SAVE_BD_LO),
	   P_V(7), 8);
	_E(emit_gfx10_s_waitcnt_vmcnt, I10(buf, n));
	patch_branch(buf, br_skip12, n);
	_E(emit_gfx10_s_endpgm, I10(buf, n));
	while (n % 256)
		_E(emit_gfx10_s_code_end, I10(buf, n));
	return n * 4;
#endif
	/* ---- Ctext: 1 <= tid <= nblocks ---- */
	/* block_idx = tid - 1 (unsigned; tid==0 -> 0xFFFFFFFF > nblocks) */
	_E(emit_gfx10_v_add_nc_u32, I10(buf, n), P_V(VR_TMP), P_L(0xFFFFFFFF),
	   P_V(VR_TID));
	_E(emit_gfx10_v_cmp_gt_u32, I10(buf, n), P_S(SR_NBLOCKS_GCM),
	   P_V(VR_TMP));
	_E(emit_gfx10_s_and_saveexec_b64, I10(buf, n), SR_GHASH_EXEC,
	   106 /* VCC */);
	br_skip_ctext = _BR(emit_gfx10_s_cbranch_execz, I10(buf, n), 0);

#if defined(KNOD_IPSEC_GFX10_DIAG_STUB) && KNOD_IPSEC_GFX10_DIAG_STUB == 14
	_E(emit_gfx10_s_mov_b64, I10(buf, n), 126 /* EXEC */,
	   SR_GHASH_EXEC);
	_E(emit_gfx10_v_cmp_eq_u32, I10(buf, n), P_I(0), P_V(0));
	br_skip14 = _BR(emit_gfx10_s_cbranch_vccz, I10(buf, n), 0);
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n), P_V(7), P_L(0xDEAD000Eu));
	_E(emit_gfx10_global_store_dword, I10(buf, n), P_V(VR_SAVE_BD_LO),
	   P_V(7), 8);
	_E(emit_gfx10_s_waitcnt_vmcnt, I10(buf, n));
	patch_branch(buf, br_skip14, n);
	_E(emit_gfx10_s_endpgm, I10(buf, n));
	while (n % 256)
		_E(emit_gfx10_s_code_end, I10(buf, n));
	return n * 4;
#endif
	/* Load ctext block: pkt + esp_hdr_off + 16 + block_idx*16 */
	_E(emit_gfx10_v_lshlrev_b32, I10(buf, n), P_V(VR_TMP), P_I(4),
	   P_V(VR_TMP));
	_E(emit_gfx10_v_add_co_u32, I10(buf, n), P_V(VR_GA_LO),
	   P_V(VR_SAVE_ESP_OFF), P_V(VR_SAVE_PKT_LO));
	_E(emit_gfx10_v_add_co_ci_u32_e32, I10(buf, n), P_V(VR_GA_HI),
	   P_I(0), P_V(VR_SAVE_PKT_HI));
	_E(emit_gfx10_v_add_co_u32, I10(buf, n), P_V(VR_GA_LO),
	   P_I(ESP_REL_CTEXT), P_V(VR_GA_LO));
	_E(emit_gfx10_v_add_co_ci_u32_e32, I10(buf, n), P_V(VR_GA_HI),
	   P_I(0), P_V(VR_GA_HI));
	_E(emit_gfx10_v_add_co_u32, I10(buf, n), P_V(VR_GA_LO),
	   P_V(VR_GA_LO), P_V(VR_TMP));
	_E(emit_gfx10_v_add_co_ci_u32_e32, I10(buf, n), P_V(VR_GA_HI),
	   P_I(0), P_V(VR_GA_HI));
	/* GFX10 unaligned load fix: ctext addr == 2 mod 4.
	 * dwordx4 + extra dword + 4x alignbit. VR_BLK is free.
	 */
	_E(emit_gfx10_global_load_dwordx4, I10(buf, n), P_V(VR_DATA0),
	   P_V(VR_GA_LO), 0);
	_E(emit_gfx10_global_load_dword, I10(buf, n), P_V(VR_BLK),
	   P_V(VR_GA_LO), 16);
	_E(emit_gfx10_s_waitcnt_vmcnt, I10(buf, n));
	_E(emit_gfx10_v_alignbit_b32, I10(buf, n), P_V(VR_DATA0),
	   P_V(VR_DATA1), P_V(VR_DATA0), P_I(16));
	_E(emit_gfx10_v_alignbit_b32, I10(buf, n), P_V(VR_DATA1),
	   P_V(VR_DATA2), P_V(VR_DATA1), P_I(16));
	_E(emit_gfx10_v_alignbit_b32, I10(buf, n), P_V(VR_DATA2),
	   P_V(VR_DATA3), P_V(VR_DATA2), P_I(16));
	_E(emit_gfx10_v_alignbit_b32, I10(buf, n), P_V(VR_DATA3),
	   P_V(VR_BLK), P_V(VR_DATA3), P_I(16));

#if defined(KNOD_IPSEC_GFX10_DIAG_STUB) && KNOD_IPSEC_GFX10_DIAG_STUB == 15
	_E(emit_gfx10_s_mov_b64, I10(buf, n), 126 /* EXEC */,
	   SR_GHASH_EXEC);
	_E(emit_gfx10_v_cmp_eq_u32, I10(buf, n), P_I(0), P_V(0));
	br_skip15 = _BR(emit_gfx10_s_cbranch_vccz, I10(buf, n), 0);
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n), P_V(7), P_L(0xDEAD000Fu));
	_E(emit_gfx10_global_store_dword, I10(buf, n), P_V(VR_SAVE_BD_LO),
	   P_V(7), 8);
	_E(emit_gfx10_s_waitcnt_vmcnt, I10(buf, n));
	patch_branch(buf, br_skip15, n);
	_E(emit_gfx10_s_endpgm, I10(buf, n));
	while (n % 256)
		_E(emit_gfx10_s_code_end, I10(buf, n));
	return n * 4;
#endif
	/* Zero trailing dwords in the last partial ctext block.
	 * The load above reads 16 raw bytes, but for the last block
	 * only (ctext_len % 16) bytes are ciphertext - the rest are
	 * ICV bytes which must NOT enter GHASH.  ESP ctext is always
	 * 4-byte aligned so the partial count is 4, 8 or 12 - pure
	 * dword-level zeroing suffices, no byte masking needed.
	 *
	 * VR_TMP still holds block_idx * 16 from the address calc.
	 * remaining = ctext_len - block_idx*16. For full blocks
	 * (remaining >= 16) every v_cmp evaluates true -> no change.
	 */
	_E(emit_gfx10_v_sub_nc_u32, I10(buf, n), P_V(VR_TMP),
	   P_S(SR_CTEXT_LEN), P_V(VR_TMP));
	/* VR_TMP = remaining bytes in this block */

	/* DATA3 (bytes 12-15): keep only if remaining > 12 */
	_E(emit_gfx10_v_cmp_lt_u32, I10(buf, n), P_I(12), P_V(VR_TMP));
#if defined(KNOD_IPSEC_GFX10_DIAG_STUB) && KNOD_IPSEC_GFX10_DIAG_STUB == 18
	_E(emit_gfx10_s_mov_b64, I10(buf, n), 126 /* EXEC */,
	   SR_GHASH_EXEC);
	_E(emit_gfx10_v_cmp_eq_u32, I10(buf, n), P_I(0), P_V(0));
	br_skip18 = _BR(emit_gfx10_s_cbranch_vccz, I10(buf, n), 0);
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n), P_V(7), P_L(0xDEAD0012u));
	_E(emit_gfx10_global_store_dword, I10(buf, n), P_V(VR_SAVE_BD_LO),
	   P_V(7), 8);
	_E(emit_gfx10_s_waitcnt_vmcnt, I10(buf, n));
	patch_branch(buf, br_skip18, n);
	_E(emit_gfx10_s_endpgm, I10(buf, n));
	while (n % 256)
		_E(emit_gfx10_s_code_end, I10(buf, n));
	return n * 4;
#endif
	_E(emit_gfx10_v_cndmask_b32_e32, I10(buf, n),
	   P_V(VR_DATA3), P_I(0), P_V(VR_DATA3));

	/* DATA2 (bytes 8-11): keep only if remaining > 8 */
	_E(emit_gfx10_v_cmp_lt_u32, I10(buf, n), P_I(8), P_V(VR_TMP));
	_E(emit_gfx10_v_cndmask_b32_e32, I10(buf, n),
	   P_V(VR_DATA2), P_I(0), P_V(VR_DATA2));

	/* DATA1 (bytes 4-7): keep only if remaining > 4 */
	_E(emit_gfx10_v_cmp_lt_u32, I10(buf, n), P_I(4), P_V(VR_TMP));
	_E(emit_gfx10_v_cndmask_b32_e32, I10(buf, n),
	   P_V(VR_DATA1), P_I(0), P_V(VR_DATA1));

	/* DATA0 (bytes 0-3): always valid (ESP 4-byte alignment) */

#if defined(KNOD_IPSEC_GFX10_DIAG_STUB) && KNOD_IPSEC_GFX10_DIAG_STUB == 16
	_E(emit_gfx10_s_mov_b64, I10(buf, n), 126 /* EXEC */,
	   SR_GHASH_EXEC);
	_E(emit_gfx10_v_cmp_eq_u32, I10(buf, n), P_I(0), P_V(0));
	br_skip16 = _BR(emit_gfx10_s_cbranch_vccz, I10(buf, n), 0);
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n), P_V(7), P_L(0xDEAD0010u));
	_E(emit_gfx10_global_store_dword, I10(buf, n), P_V(VR_SAVE_BD_LO),
	   P_V(7), 8);
	_E(emit_gfx10_s_waitcnt_vmcnt, I10(buf, n));
	patch_branch(buf, br_skip16, n);
	_E(emit_gfx10_s_endpgm, I10(buf, n));
	while (n % 256)
		_E(emit_gfx10_s_code_end, I10(buf, n));
	return n * 4;
#endif
	/* bswap each dword for GHASH (big-endian GF arithmetic) */
	_E(emit_gfx10_v_perm_b32, I10(buf, n), P_V(VR_DATA0),
	   P_V(VR_DATA0), P_V(VR_DATA0), P_S(SR_BSWAP));
	_E(emit_gfx10_v_perm_b32, I10(buf, n), P_V(VR_DATA1),
	   P_V(VR_DATA1), P_V(VR_DATA1), P_S(SR_BSWAP));
	_E(emit_gfx10_v_perm_b32, I10(buf, n), P_V(VR_DATA2),
	   P_V(VR_DATA2), P_V(VR_DATA2), P_S(SR_BSWAP));
	_E(emit_gfx10_v_perm_b32, I10(buf, n), P_V(VR_DATA3),
	   P_V(VR_DATA3), P_V(VR_DATA3), P_S(SR_BSWAP));

	patch_branch(buf, br_skip_ctext, n);
	_E(emit_gfx10_s_mov_b64, I10(buf, n), 126 /* EXEC */,
	   SR_GHASH_EXEC);

#if defined(KNOD_IPSEC_GFX10_DIAG_STUB) && KNOD_IPSEC_GFX10_DIAG_STUB == 13
	_E(emit_gfx10_v_cmp_eq_u32, I10(buf, n), P_I(0), P_V(0));
	br_skip13 = _BR(emit_gfx10_s_cbranch_vccz, I10(buf, n), 0);
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n), P_V(7), P_L(0xDEAD000Du));
	_E(emit_gfx10_global_store_dword, I10(buf, n), P_V(VR_SAVE_BD_LO),
	   P_V(7), 8);
	_E(emit_gfx10_s_waitcnt_vmcnt, I10(buf, n));
	patch_branch(buf, br_skip13, n);
	_E(emit_gfx10_s_endpgm, I10(buf, n));
	while (n % 256)
		_E(emit_gfx10_s_code_end, I10(buf, n));
	return n * 4;
#endif
	/* ---- Len block: tid == nblocks + 1 ---- */
	/* Compute nblocks+1 in s42 (scratch) */
	_E(emit_gfx10_s_add_u32, I10(buf, n), P_S(42), P_I(1),
	   P_S(SR_NBLOCKS_GCM));
	_E(emit_gfx10_v_cmp_eq_u32, I10(buf, n), P_S(42),
	   P_V(VR_TID));
	_E(emit_gfx10_s_and_saveexec_b64, I10(buf, n), SR_GHASH_EXEC,
	   106 /* VCC */);
	br_skip_len = _BR(emit_gfx10_s_cbranch_execz, I10(buf, n), 0);

	/* Length block format (GCM big-endian):
	 *   DATA0 = AAD_bits[63:32] = 0
	 *   DATA1 = AAD_bits[31:0]  = 64  (8 bytes AAD x 8)
	 *   DATA2 = ctext_bits[63:32] = 0
	 *   DATA3 = ctext_bits[31:0] = ctext_len * 8
	 *
	 * No bswap32: length values are computed integers already
	 * in the correct big-endian register representation.
	 * bswap32 is only needed for data loaded from LE memory.
	 */
	/* DATA0, DATA2 already 0 from default init */
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n), P_V(VR_DATA1),
	   P_L(0x00000040u));
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n), P_V(VR_DATA3),
	   P_S(SR_CTEXT_LEN));
	_E(emit_gfx10_v_lshlrev_b32, I10(buf, n), P_V(VR_DATA3), P_I(3),
	   P_V(VR_DATA3));

	patch_branch(buf, br_skip_len, n);
	_E(emit_gfx10_s_mov_b64, I10(buf, n), 126 /* EXEC */,
	   SR_GHASH_EXEC);

#if defined(KNOD_IPSEC_GFX10_DIAG_STUB) && KNOD_IPSEC_GFX10_DIAG_STUB == 11
	_E(emit_gfx10_v_cmp_eq_u32, I10(buf, n), P_I(0), P_V(0));
	br_skip = _BR(emit_gfx10_s_cbranch_vccz, I10(buf, n), 0);
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n), P_V(7), P_L(0xDEAD000Bu));
	_E(emit_gfx10_global_store_dword, I10(buf, n), P_V(VR_SAVE_BD_LO),
	   P_V(7), 8);
	_E(emit_gfx10_s_waitcnt_vmcnt, I10(buf, n));
	patch_branch(buf, br_skip, n);
	_E(emit_gfx10_s_endpgm, I10(buf, n));
	while (n % 256)
		_E(emit_gfx10_s_code_end, I10(buf, n));
	return n * 4;
#endif
	/* H-table data was prefetched before data selection; drain + bswap */
	_E(emit_gfx10_s_waitcnt_vmcnt, I10(buf, n));
	_E(emit_gfx10_v_perm_b32, I10(buf, n), P_V(VR_D0),
	   P_V(VR_D0), P_V(VR_D0), P_S(SR_BSWAP));
	_E(emit_gfx10_v_perm_b32, I10(buf, n), P_V(VR_D1),
	   P_V(VR_D1), P_V(VR_D1), P_S(SR_BSWAP));
	_E(emit_gfx10_v_perm_b32, I10(buf, n), P_V(VR_D2),
	   P_V(VR_D2), P_V(VR_D2), P_S(SR_BSWAP));
	_E(emit_gfx10_v_perm_b32, I10(buf, n), P_V(VR_D3),
	   P_V(VR_D3), P_V(VR_D3), P_S(SR_BSWAP));

	/* ---- GF(2^128) multiply: Z = DATA * H^k ---- */
#if defined(KNOD_IPSEC_GFX10_DIAG_STUB) && KNOD_IPSEC_GFX10_DIAG_STUB == 10
	_E(emit_gfx10_v_cmp_eq_u32, I10(buf, n), P_I(0), P_V(0));
	br_skip = _BR(emit_gfx10_s_cbranch_vccz, I10(buf, n), 0);
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n), P_V(7), P_L(0xDEAD000Au));
	_E(emit_gfx10_global_store_dword, I10(buf, n), P_V(VR_SAVE_BD_LO),
	   P_V(7), 8);
	_E(emit_gfx10_s_waitcnt_vmcnt, I10(buf, n));
	patch_branch(buf, br_skip, n);
	_E(emit_gfx10_s_endpgm, I10(buf, n));
	while (n % 256)
		_E(emit_gfx10_s_code_end, I10(buf, n));
	return n * 4;
#endif
	n = emit_gfmul_128_gfx10(buf, n);
	/* Result in v[VR_S0:VR_S3] */

	/* ---- Tree reduction via LDS XOR (8 levels for 256 threads) ---- */
	/* Write v[VR_S0:VR_S3] to LDS at tid * 16 */
	_E(emit_gfx10_v_lshlrev_b32, I10(buf, n), P_V(VR_ADDR), P_I(4),
	   P_V(VR_TID));
	_E(emit_gfx10_ds_write_b128, I10(buf, n), VR_ADDR, VR_S0);
	_E(emit_gfx10_s_waitcnt_lgkmcnt, I10(buf, n));
	_E(emit_gfx10_s_barrier, I10(buf, n));

	for (level = 1; level <= 128; level <<= 1) {
		/* if (tid & level) skip */
		_E(emit_gfx10_v_and_b32_e32, I10(buf, n), P_V(VR_TMP),
		   P_L(level), P_V(VR_TID));
		_E(emit_gfx10_v_cmp_eq_u32, I10(buf, n), P_I(0), P_V(VR_TMP));
		_E(emit_gfx10_s_and_saveexec_b64, I10(buf, n), SR_GHASH_EXEC,
		   106 /* VCC */);
		br_skip = _BR(emit_gfx10_s_cbranch_execz, I10(buf, n), 0);

		/* Compute both addresses up front */
		_E(emit_gfx10_v_add_nc_u32, I10(buf, n), P_V(VR_TMP),
		   P_L(level), P_V(VR_TID));
		_E(emit_gfx10_v_lshlrev_b32, I10(buf, n), P_V(VR_TMP),
		   P_I(4), P_V(VR_TMP));
		_E(emit_gfx10_v_lshlrev_b32, I10(buf, n), P_V(VR_ADDR),
		   P_I(4), P_V(VR_TID));

		/* Issue both reads, single wait */
		_E(emit_gfx10_ds_read_b128, I10(buf, n), VR_D0, VR_TMP);
		_E(emit_gfx10_ds_read_b128, I10(buf, n), VR_S0, VR_ADDR);
		_E(emit_gfx10_s_waitcnt_lgkmcnt, I10(buf, n));

		/* XOR */
		_E(emit_gfx10_v_xor_b32_e32, I10(buf, n), P_V(VR_S0),
		   P_V(VR_S0), P_V(VR_D0));
		_E(emit_gfx10_v_xor_b32_e32, I10(buf, n), P_V(VR_S1),
		   P_V(VR_S1), P_V(VR_D1));
		_E(emit_gfx10_v_xor_b32_e32, I10(buf, n), P_V(VR_S2),
		   P_V(VR_S2), P_V(VR_D2));
		_E(emit_gfx10_v_xor_b32_e32, I10(buf, n), P_V(VR_S3),
		   P_V(VR_S3), P_V(VR_D3));

		/* Write back */
		_E(emit_gfx10_ds_write_b128, I10(buf, n), VR_ADDR, VR_S0);
		_E(emit_gfx10_s_waitcnt_lgkmcnt, I10(buf, n));

		patch_branch(buf, br_skip, n);
		/* Restore EXEC */
		_E(emit_gfx10_s_mov_b64, I10(buf, n), 126 /* EXEC */,
		   SR_GHASH_EXEC);
		_E(emit_gfx10_s_barrier, I10(buf, n));
	}

	/* Thread 0 now has the final GHASH in LDS[0..15]. Read it. */
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n), P_V(VR_TMP), P_I(0));
	_E(emit_gfx10_ds_read_b128, I10(buf, n), VR_S0, VR_TMP);
	_E(emit_gfx10_s_waitcnt_lgkmcnt, I10(buf, n));

	/* ================================================================
	 * Phase 9: ICV verify (thread 0 only)
	 *
	 * computed_tag = bswap(GHASH) XOR AES(K, J0)
	 * received_tag = last 16 bytes of ESP packet
	 * ================================================================
	 */
	_E(emit_gfx10_v_cmp_eq_u32, I10(buf, n), P_I(0), P_V(VR_TID));
	_E(emit_gfx10_s_and_saveexec_b64, I10(buf, n), SR_EXEC_SAVE, 106);
	br_tid0 = _BR(emit_gfx10_s_cbranch_execz, I10(buf, n), 0);

	/* bswap GHASH from big-endian to little-endian */
	_E(emit_gfx10_v_perm_b32, I10(buf, n), P_V(VR_S0), P_V(VR_S0),
	   P_V(VR_S0), P_S(SR_BSWAP));
	_E(emit_gfx10_v_perm_b32, I10(buf, n), P_V(VR_S1), P_V(VR_S1),
	   P_V(VR_S1), P_S(SR_BSWAP));
	_E(emit_gfx10_v_perm_b32, I10(buf, n), P_V(VR_S2), P_V(VR_S2),
	   P_V(VR_S2), P_S(SR_BSWAP));
	_E(emit_gfx10_v_perm_b32, I10(buf, n), P_V(VR_S3), P_V(VR_S3),
	   P_V(VR_S3), P_S(SR_BSWAP));

	/* computed_tag = GHASH XOR AES(K, J0) */
	_E(emit_gfx10_v_xor_b32_e32, I10(buf, n), P_V(VR_S0),
	   P_V(VR_S0), P_V(VR_J0_0));
	_E(emit_gfx10_v_xor_b32_e32, I10(buf, n), P_V(VR_S1),
	   P_V(VR_S1), P_V(VR_J0_1));
	_E(emit_gfx10_v_xor_b32_e32, I10(buf, n), P_V(VR_S2),
	   P_V(VR_S2), P_V(VR_J0_2));
	_E(emit_gfx10_v_xor_b32_e32, I10(buf, n), P_V(VR_S3),
	   P_V(VR_S3), P_V(VR_J0_3));

	/* Load received ICV: pkt + pkt_len - 16.
	 * GFX10 unaligned load fix: ICV addr == 2 mod 4.
	 * dwordx4 + extra dword + 4x alignbit. VR_TMP is
	 * free after address calc; use VR_BLK for 5th dword.
	 */
	_E(emit_gfx10_v_add_nc_u32, I10(buf, n), P_V(VR_TMP),
	   P_L(0xFFFFFFF0u), P_V(VR_SAVE_PKTLEN)); /* pkt_len - 16 */
	_E(emit_gfx10_v_add_co_u32, I10(buf, n), P_V(VR_GA_LO),
	   P_V(VR_TMP), P_V(VR_SAVE_PKT_LO));
	_E(emit_gfx10_v_add_co_ci_u32_e32, I10(buf, n), P_V(VR_GA_HI),
	   P_I(0), P_V(VR_SAVE_PKT_HI));
	_E(emit_gfx10_global_load_dwordx4, I10(buf, n), P_V(VR_DATA0),
	   P_V(VR_GA_LO), 0);
	_E(emit_gfx10_global_load_dword, I10(buf, n), P_V(VR_BLK),
	   P_V(VR_GA_LO), 16);
	_E(emit_gfx10_s_waitcnt_vmcnt, I10(buf, n));
	_E(emit_gfx10_v_alignbit_b32, I10(buf, n), P_V(VR_DATA0),
	   P_V(VR_DATA1), P_V(VR_DATA0), P_I(16));
	_E(emit_gfx10_v_alignbit_b32, I10(buf, n), P_V(VR_DATA1),
	   P_V(VR_DATA2), P_V(VR_DATA1), P_I(16));
	_E(emit_gfx10_v_alignbit_b32, I10(buf, n), P_V(VR_DATA2),
	   P_V(VR_DATA3), P_V(VR_DATA2), P_I(16));
	_E(emit_gfx10_v_alignbit_b32, I10(buf, n), P_V(VR_DATA3),
	   P_V(VR_BLK), P_V(VR_DATA3), P_I(16));

	/* Compare: XOR each dword, OR together; if any non-zero -> fail */
	_E(emit_gfx10_v_xor_b32_e32, I10(buf, n), P_V(VR_DATA0),
	   P_V(VR_DATA0), P_V(VR_S0));
	_E(emit_gfx10_v_xor_b32_e32, I10(buf, n), P_V(VR_DATA1),
	   P_V(VR_DATA1), P_V(VR_S1));
	_E(emit_gfx10_v_xor_b32_e32, I10(buf, n), P_V(VR_DATA2),
	   P_V(VR_DATA2), P_V(VR_S2));
	_E(emit_gfx10_v_xor_b32_e32, I10(buf, n), P_V(VR_DATA3),
	   P_V(VR_DATA3), P_V(VR_S3));
	_E(emit_gfx10_v_or_b32_e32, I10(buf, n), P_V(VR_DATA0),
	   P_V(VR_DATA0), P_V(VR_DATA1));
	_E(emit_gfx10_v_or_b32_e32, I10(buf, n), P_V(VR_DATA0),
	   P_V(VR_DATA0), P_V(VR_DATA2));
	_E(emit_gfx10_v_or_b32_e32, I10(buf, n), P_V(VR_DATA0),
	   P_V(VR_DATA0), P_V(VR_DATA3));

	/* If VR_DATA0 != 0 -> ICV fail: overwrite verdict with sentinel */
	_E(emit_gfx10_v_cmp_ne_u32, I10(buf, n), P_I(0), P_V(VR_DATA0));
	br_icv_ok = _BR(emit_gfx10_s_cbranch_vccz, I10(buf, n), 0);
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n), P_V(VR_SAVE_SLOT),
	   P_L(VERDICT_ICV_FAIL));
	patch_branch(buf, br_icv_ok, n);

	/* ================================================================
	 * Phase 10: ESP trailer strip + write verdict (thread 0)
	 *
	 * Decrypted tail: pad_len at out + ctext_len - 2
	 *                 next_hdr at out + ctext_len - 1
	 * inner_len = ctext_len - pad_len - 2
	 * ================================================================
	 */
	/* Only strip if ICV passed (slot < NR_SA) */
	_E(emit_gfx10_v_readfirstlane_b32, I10(buf, n), 27, VR_SAVE_SLOT);
	_E(emit_gfx10_s_cmp_ge_u32, I10(buf, n), P_S(27),
	   P_L(KNOD_IPSEC_SHADER_NR_SA));
	br_icv_bad = _BR(emit_gfx10_s_cbranch_scc1, I10(buf, n), 0);

	/* Load last 4 bytes of decrypted payload: out + ctext_len - 4.
	 * VOP2 src1 must be VGPR, so move SGPR to VR_TMP first.
	 */
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n), P_V(VR_TMP),
	   P_S(SR_CTEXT_LEN));
	_E(emit_gfx10_v_add_nc_u32, I10(buf, n), P_V(VR_TMP),
	   P_L(0xFFFFFFFC), P_V(VR_TMP)); /* ctext_len - 4 */
	_E(emit_gfx10_v_add_co_u32, I10(buf, n), P_V(VR_GA_LO),
	   P_V(VR_TMP), P_V(VR_SAVE_OUT_LO));
	_E(emit_gfx10_v_add_co_ci_u32_e32, I10(buf, n), P_V(VR_GA_HI),
	   P_I(0), P_V(VR_SAVE_OUT_HI));
	_E(emit_gfx10_global_load_dword, I10(buf, n), P_V(VR_DATA0),
	   P_V(VR_GA_LO), 0);
	_E(emit_gfx10_s_waitcnt_vmcnt, I10(buf, n));

	/* On LE: loaded dword has byte layout [b0,b1,b2,b3].
	 * We loaded from (ctext_len - 4), so:
	 *   b2 = pad_len (at ctext_len - 2)
	 *   b3 = next_hdr (at ctext_len - 1)
	 * pad_len = (dword >> 16) & 0xFF
	 */
	_E(emit_gfx10_v_lshrrev_b32, I10(buf, n), P_V(VR_TMP),
	   P_I(16), P_V(VR_DATA0));
	_E(emit_gfx10_v_and_b32_e32, I10(buf, n), P_V(VR_TMP),
	   P_L(0xFF), P_V(VR_TMP));

	/* inner_len = ctext_len - pad_len - 2 */
	_E(emit_gfx10_v_sub_nc_u32, I10(buf, n), P_V(VR_DATA1),
	   P_S(SR_CTEXT_LEN), P_V(VR_TMP));
	_E(emit_gfx10_v_add_nc_u32, I10(buf, n), P_V(VR_DATA1),
	   P_L(0xFFFFFFFE), P_V(VR_DATA1)); /* -2 */

	/* Write bd->len = inner_len (u16 at bd + 18) */
	_E(emit_gfx10_v_add_co_u32, I10(buf, n), P_V(VR_GA_LO),
	   P_L(18), P_V(VR_SAVE_BD_LO));
	_E(emit_gfx10_v_add_co_ci_u32_e32, I10(buf, n), P_V(VR_GA_HI),
	   P_I(0), P_V(VR_SAVE_BD_HI));
	_E(emit_gfx10_global_store_short, I10(buf, n), P_V(VR_GA_LO),
	   P_V(VR_DATA1), 0);

	/* Write bd->off = mode | (next_hdr << 8) (u16 at bd + 16).
	 * next_hdr = byte[3] of the ESP trailer dword (VR_DATA0).
	 * mode from s[SR_SA_MODE].
	 */
	_E(emit_gfx10_v_lshrrev_b32, I10(buf, n), P_V(VR_TMP),
	   P_I(24), P_V(VR_DATA0));
	_E(emit_gfx10_v_lshlrev_b32, I10(buf, n), P_V(VR_TMP),
	   P_I(8), P_V(VR_TMP));
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n), P_V(VR_DATA2),
	   P_S(SR_SA_MODE));
	_E(emit_gfx10_v_or_b32_e32, I10(buf, n), P_V(VR_TMP),
	   P_V(VR_DATA2), P_V(VR_TMP));
	_E(emit_gfx10_v_add_co_u32, I10(buf, n), P_V(VR_GA_LO),
	   P_L(16), P_V(VR_SAVE_BD_LO));
	_E(emit_gfx10_v_add_co_ci_u32_e32, I10(buf, n), P_V(VR_GA_HI),
	   P_I(0), P_V(VR_SAVE_BD_HI));
	_E(emit_gfx10_global_store_short, I10(buf, n), P_V(VR_GA_LO),
	   P_V(VR_TMP), 0);

	/* Per-SA GPU stats: atomically increment rx_packets
	 * and rx_bytes at stats_addr. VR_DATA1 still holds
	 * inner_len from the bd->len computation above.
	 *
	 * global_atomic_add_x2 uses v[data:data+1] as u64.
	 * Save inner_len to VR_TMP before clobbering DATA1.
	 *
	 * stats layout (knod_ipsec_sa_gpu_stats):
	 *   +0: rx_packets (u64, LE)
	 *   +8: rx_bytes   (u64, LE)
	 */
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n), P_V(VR_TMP),
	   P_V(VR_DATA1));	/* save inner_len */
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n), P_V(VR_GA_LO),
	   P_V(VR_SAVE_STATS_LO));
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n), P_V(VR_GA_HI),
	   P_V(VR_SAVE_STATS_HI));

	/* rx_packets += 1: v[DATA0:DATA1] = {1, 0} */
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n), P_V(VR_DATA0), P_I(1));
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n), P_V(VR_DATA1), P_I(0));
	_E(emit_gfx10_global_atomic_add_x2, I10(buf, n),
	   P_V(VR_DATA2), P_V(VR_GA_LO), P_V(VR_DATA0), 0, 0);

	/* rx_bytes += inner_len: v[DATA0:DATA1] = {inner_len, 0} */
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n), P_V(VR_DATA0),
	   P_V(VR_TMP));
	/* DATA1 already 0 from above */
	_E(emit_gfx10_global_atomic_add_x2, I10(buf, n),
	   P_V(VR_DATA2), P_V(VR_GA_LO), P_V(VR_DATA0), 8, 0);

	/* ================================================================
	 * L3 header passthrough (transport mode only).
	 *
	 * Copy 20 B of the outer IPv4 L3 header from
	 * pkt + 14 (skip ETH) to out_addr - 20. In shader-GTT
	 * direct mode (knod_ipsec_sdma=0), out_addr - 20 is
	 * pass_buf_slot + 0 so the host-side finalise can skip
	 * the per-packet L3 SDMA copy entirely - the only
	 * remaining SDMA call on the transport IPv4 fast path.
	 *
	 * Tunnel-mode SAs (SR_SA_MODE != 0) skip this write
	 * because for tunnel the destination at slot+0 wants
	 * the *inner* packet, not an outer IP header.
	 *
	 * The VRAM staging path (knod_ipsec_sdma=1) also runs
	 * this copy, but the destination is the 20-byte
	 * headroom knod_ipsec.c reserves at the front of
	 * the decrypt pool; CPU finalise still SDMAs the real
	 * L3 header from the raw packet into the GTT pass_buf
	 * so the shader's write is harmless wasted work.
	 *
	 * Alignment: pkt + 14 is only 2-byte aligned (ETH hdr
	 * = 14 bytes != 4-byte multiple), so dword / dwordx4
	 * loads would fault. Use 10 x global_load_ushort at
	 * offsets 14,16,...,32, paired with 10 x store_short
	 * at slot + 0,2,...,18. 10 scratch VGPRs (v14..v23),
	 * all free by Phase 10 since AES-GCM / GHASH state is
	 * done. One waitcnt between loads and stores.
	 * ================================================================
	 */

	_E(emit_gfx10_s_cmp_eq_u32, I10(buf, n),
	   P_S(SR_SA_MODE), P_I(0));
	br_not_transport = _BR(emit_gfx10_s_cbranch_scc0,
			       I10(buf, n), 0);

	/* src = pkt_addr + 14 */
	_E(emit_gfx10_v_add_co_u32, I10(buf, n),
	   P_V(VR_GA_LO), P_I(14),
	   P_V(VR_SAVE_PKT_LO));
	_E(emit_gfx10_v_add_co_ci_u32_e32, I10(buf, n),
	   P_V(VR_GA_HI), P_I(0),
	   P_V(VR_SAVE_PKT_HI));

	/* 10 x 2-byte loads from src+0..+18 */
	for (li = 0; li < 10; li++) {
		_E(emit_gfx10_global_load_ushort,
		   I10(buf, n),
		   P_V(L3_TMP_BASE + li),
		   P_V(VR_GA_LO), li * 2);
	}
	_E(emit_gfx10_s_waitcnt_vmcnt, I10(buf, n));

	/* dst = out_addr - 20.
	 *
	 * Two GFX9 landmines here:
	 *
	 *  1. v_add_co_u32 can't take a 32-bit
	 *     literal src together with implicit VCC
	 *     - same class as the v_cndmask literal
	 *     restriction.
	 *  2. P_I(n) is a raw initializer that always
	 *     sets type=INTEGER_0 and stores n in .v.
	 *     For negative inline constants the
	 *     encoder must flip to INTEGER_MINUS_1
	 *     with v=~n, which P_I does NOT do.
	 *     P_I(-1) therefore encodes as
	 *     GFX9_SRC_INTEGER_0 + (-1) = 127, a
	 *     bogus register that gave us random
	 *     high-32 bits and page-faulted stores.
	 *
	 * Dodge both by materialising -20 into VR_TMP
	 * and -1 into VR_TMP2 via v_mov_b32 literals
	 * (VOP1, no VCC, literals fine), then pure
	 * VGPR+VGPR add_co / addc_co. Borrow flows
	 * through VCC as the carry-in to addc_co.
	 */
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n),
	   P_V(VR_TMP), P_L(0xFFFFFFECu));
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n),
	   P_V(VR_TMP2), P_L(0xFFFFFFFFu));
	_E(emit_gfx10_v_add_co_u32, I10(buf, n),
	   P_V(VR_GA_LO),
	   P_V(VR_TMP), P_V(VR_SAVE_OUT_LO));
	_E(emit_gfx10_v_add_co_ci_u32_e32, I10(buf, n),
	   P_V(VR_GA_HI),
	   P_V(VR_TMP2), P_V(VR_SAVE_OUT_HI));

	/* 10 x 2-byte stores to dst+0..+18 */
	for (li = 0; li < 10; li++) {
		_E(emit_gfx10_global_store_short,
		   I10(buf, n),
		   P_V(VR_GA_LO),
		   P_V(L3_TMP_BASE + li),
		   li * 2);
	}

	patch_branch(buf, br_not_transport, n);

	patch_branch(buf, br_icv_bad, n);

	/* Write bd->act (u64 at bd + 8):
	 * high32 = slot_idx (or sentinel),
	 * low32 = KNOD_IPSEC_INFLIGHT so NIC NAPI recognises
	 * this slot as in-flight until the finish worker stamps
	 * the final PASS/DROP.
	 */
	_E(emit_gfx10_v_add_co_u32, I10(buf, n), P_V(VR_GA_LO),
	   P_L(8), P_V(VR_SAVE_BD_LO));
	_E(emit_gfx10_v_add_co_ci_u32_e32, I10(buf, n), P_V(VR_GA_HI),
	   P_I(0), P_V(VR_SAVE_BD_HI));
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n), P_V(VR_DATA0),
	   P_L(KNOD_IPSEC_INFLIGHT));
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n), P_V(VR_DATA1),
	   P_V(VR_SAVE_SLOT));
	_E(emit_gfx10_global_store_dwordx2, I10(buf, n), P_V(VR_GA_LO),
	   P_V(VR_DATA0), 0);
	_E(emit_gfx10_s_waitcnt_vmcnt, I10(buf, n));

	patch_branch(buf, br_tid0, n);

	/* ================================================================
	 * Phase 11: Miss/bypass path verdict - thread 0 only
	 *
	 * If we skipped crypto (Phase 2 branch), write the miss/bypass
	 * sentinel that's still in v[VR_SAVE_SLOT].
	 * ================================================================
	 */
	br_crypto_done = _BR(emit_gfx10_s_branch, I10(buf, n), 0);

	patch_branch(buf, br_crypto_end, n);

	/* Thread 0 writes bd->act with miss/bypass sentinel */
	_E(emit_gfx10_v_cmp_eq_u32, I10(buf, n), P_I(0), P_V(VR_TID));
	_E(emit_gfx10_s_and_saveexec_b64, I10(buf, n), SR_EXEC_SAVE, 106);
	br_execz2 = _BR(emit_gfx10_s_cbranch_execz, I10(buf, n), 0);

	_E(emit_gfx10_v_add_co_u32, I10(buf, n), P_V(VR_GA_LO),
	   P_L(8), P_V(VR_SAVE_BD_LO));
	_E(emit_gfx10_v_add_co_ci_u32_e32, I10(buf, n), P_V(VR_GA_HI),
	   P_I(0), P_V(VR_SAVE_BD_HI));
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n), P_V(VR_DATA0),
	   P_L(KNOD_IPSEC_INFLIGHT));
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n), P_V(VR_DATA1),
	   P_V(VR_SAVE_SLOT));
	_E(emit_gfx10_global_store_dwordx2, I10(buf, n), P_V(VR_GA_LO),
	   P_V(VR_DATA0), 0);
	_E(emit_gfx10_s_waitcnt_vmcnt, I10(buf, n));

	patch_branch(buf, br_execz2, n);

	patch_branch(buf, br_crypto_done, n);

	/* ================================================================
	 * Phase 12: GPU-initiated SDMA dispatch (thread 0 only)
	 *
	 * Identical logic to GFX9 Phase 12.  See ipsec_fused_gfx9.h
	 * for the full protocol description.
	 *
	 * GPU writes SDMA COPY_LINEAR packets only.  FENCE, wptr update,
	 * and doorbell are left to the CPU.
	 *
	 * GFX10 differences:
	 *  - v_add_nc_u32 / v_sub_nc_u32 (no-carry variants)
	 *  - v_add_co_ci_u32_e32 for carry-in addition
	 *  - s_or_b64 for 64-bit zero test (no s_or_b32 helper)
	 *  - GFX10 global offset is 12-bit signed (all offsets <=56 OK)
	 * ================================================================
	 */
	/* --- kernarg loads ---------------------------------------- */
	_E(emit_gfx10_s_load_dwordx2, I10(buf, n),
	   P_S(24), P_S(8), 16);		/* s[24:25] = sdma_ring_addr */
	_E(emit_gfx10_s_load_dwordx2, I10(buf, n),
	   P_S(26), P_S(8), 32);		/* s[26:27] = sdma_ctl_addr */
	_E(emit_gfx10_s_waitcnt_lgkmcnt, I10(buf, n));

	/* s_or_b64 sets SCC = (s[26:27] != 0) */
	_E(emit_gfx10_s_or_b64, I10(buf, n), 28, 26, 26);
	br_no_sdma = _BR(emit_gfx10_s_cbranch_scc0, I10(buf, n), 0);

	/* --- load sdma_ctl into VGPRs ----------------------------- */
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n), P_V(1), P_S(26));
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n), P_V(2), P_S(27));

	/* ctl+28: wptr_base_dw(4) ring_mask(4) nr_total_wg(4) copy_hdr(4)
	 * -> v[3:6]
	 */
	_E(emit_gfx10_global_load_dwordx4, I10(buf, n),
	   P_V(3), P_V(1), 28);
	_E(emit_gfx10_s_waitcnt_vmcnt, I10(buf, n));

	/* v3=wptr_base_dw  v4=ring_mask  v5=nr_total_wg  v6=copy_hdr */

	_E(emit_gfx10_v_readfirstlane_b32, I10(buf, n),
	   28, 5);				/* s28 = nr_total_wg */

	/* --- verdict check ---------------------------------------- */
	_E(emit_gfx10_v_readfirstlane_b32, I10(buf, n),
	   29, VR_SAVE_SLOT);			/* s29 = verdict */
	_E(emit_gfx10_s_cmp_ge_u32, I10(buf, n),
	   P_S(29), P_L(0xFFFFFFFEu));		/* MISS|BYPASS? */
	br_no_copy = _BR(emit_gfx10_s_cbranch_scc0, I10(buf, n), 0);

	/* === This WG needs SDMA copy === */

	/* atomic_add(&ctl->claim_counter, 1, GLC=1) -> my_idx */
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n), P_V(7), P_I(1));
	_E(emit_gfx10_global_atomic_add, I10(buf, n),
	   P_V(7), P_V(1), P_V(7), 0, 1);
	_E(emit_gfx10_s_waitcnt_vmcnt, I10(buf, n));
	/* v7 = my_idx (old claim_counter) */

	/* ring dword position: (wptr_base_dw + my_idx*7) & ring_mask */
	_E(emit_gfx10_v_lshlrev_b32, I10(buf, n),
	   P_V(8), P_I(3), P_V(7));		/* my_idx * 8 */
	_E(emit_gfx10_v_sub_nc_u32, I10(buf, n),
	   P_V(8), P_V(8), P_V(7));		/* my_idx * 7 */
	_E(emit_gfx10_v_add_nc_u32, I10(buf, n),
	   P_V(8), P_V(3), P_V(8));		/* + wptr_base_dw */
	_E(emit_gfx10_v_and_b32_e32, I10(buf, n),
	   P_V(8), P_V(4), P_V(8));		/* & ring_mask */
	_E(emit_gfx10_v_lshlrev_b32, I10(buf, n),
	   P_V(8), P_I(2), P_V(8));		/* * 4 -> byte offset */

	/* v[9:10] = sdma_ring_addr + byte_offset */
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n), P_V(14), P_S(25));
	_E(emit_gfx10_v_add_co_u32, I10(buf, n),
	   P_V(9), P_S(24), P_V(8));
	_E(emit_gfx10_v_add_co_ci_u32_e32, I10(buf, n),
	   P_V(10), P_I(0), P_V(14));

	/* DW0: copy_hdr */
	_E(emit_gfx10_global_store_dword, I10(buf, n),
	   P_V(9), P_V(6), 0);

	/* DW1: nbytes - 1 */
	_E(emit_gfx10_v_add_nc_u32, I10(buf, n),
	   P_V(14), P_L(0xFFFFFFFFu), P_V(VR_SAVE_PKTLEN));
	_E(emit_gfx10_global_store_dword, I10(buf, n),
	   P_V(9), P_V(14), 4);

	/* DW2: 0 (sub-op parameter) */
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n), P_V(14), P_I(0));
	_E(emit_gfx10_global_store_dword, I10(buf, n),
	   P_V(9), P_V(14), 8);

	/* DW3-4: src = pkt_addr (VRAM) */
	_E(emit_gfx10_global_store_dword, I10(buf, n),
	   P_V(9), P_V(VR_SAVE_PKT_LO), 12);
	_E(emit_gfx10_global_store_dword, I10(buf, n),
	   P_V(9), P_V(VR_SAVE_PKT_HI), 16);

	/* DW5-6: dst = out_addr - 20 (GTT slot start) */
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n),
	   P_V(14), P_L(0xFFFFFFECu));		/* -20 */
	_E(emit_gfx10_v_add_co_u32, I10(buf, n),
	   P_V(15), P_V(14), P_V(VR_SAVE_OUT_LO));
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n),
	   P_V(14), P_L(0xFFFFFFFFu));		/* -1 */
	_E(emit_gfx10_v_add_co_ci_u32_e32, I10(buf, n),
	   P_V(16), P_V(14), P_V(VR_SAVE_OUT_HI));

	_E(emit_gfx10_global_store_dword, I10(buf, n),
	   P_V(9), P_V(15), 20);
	_E(emit_gfx10_global_store_dword, I10(buf, n),
	   P_V(9), P_V(16), 24);

	_E(emit_gfx10_s_waitcnt_vmcnt, I10(buf, n));

	/* --- done counter (all WGs) ------------------------------- */
	patch_branch(buf, br_no_copy, n);

	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n), P_V(7), P_I(1));
	_E(emit_gfx10_global_atomic_add, I10(buf, n),
	   P_V(7), P_V(1), P_V(7), 4, 1);	/* ctl+4 = done_counter */
	_E(emit_gfx10_s_waitcnt_vmcnt, I10(buf, n));

	/* Last WG check: my_done + 1 == nr_total_wg? */
	_E(emit_gfx10_v_add_nc_u32, I10(buf, n),
	   P_V(7), P_I(1), P_V(7));
	_E(emit_gfx10_v_readfirstlane_b32, I10(buf, n), 29, 7);
	_E(emit_gfx10_s_cmp_eq_u32, I10(buf, n), P_S(29), P_S(28));
	br_not_last = _BR(emit_gfx10_s_cbranch_scc0, I10(buf, n), 0);

	/* === Last WG - publish counters for CPU === */

	/* Read final claim_counter (atomic add 0, GLC=1) */
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n), P_V(7), P_I(0));
	_E(emit_gfx10_global_atomic_add, I10(buf, n),
	   P_V(7), P_V(1), P_V(7), 0, 1);
	_E(emit_gfx10_s_waitcnt_vmcnt, I10(buf, n));

	/* Store final_sdma_count (ctl+52) and gpu_sdma_ready (ctl+48) */
	_E(emit_gfx10_global_store_dword, I10(buf, n),
	   P_V(1), P_V(7), 52);
	_E(emit_gfx10_v_mov_b32_e32, I10(buf, n), P_V(7), P_I(1));
	_E(emit_gfx10_global_store_dword, I10(buf, n),
	   P_V(1), P_V(7), 48);
	_E(emit_gfx10_s_waitcnt_vmcnt, I10(buf, n));

	patch_branch(buf, br_not_last, n);
	patch_branch(buf, br_no_sdma, n);

	_E(emit_gfx10_s_endpgm, I10(buf, n));

	/* GFX10 RDNA2 prefetches instructions aggressively past s_endpgm.
	 * Without an s_code_end cushion the SQC fetches garbage beyond the
	 * shader and raises an SQC(inst) page fault at a seemingly random
	 * address. Pad to a 256-dword boundary - same pattern the BPF GFX10
	 * emitter (knod_bpf.c) uses on working shaders.
	 */
	while (n % 256)
		_E(emit_gfx10_s_code_end, I10(buf, n));

	return n * 4;
}

#endif /* KNOD_HELPERS_IPSEC_FUSED_GFX10_H_ */
