/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (c) 2021 Taehee Yoo <ap420073@gmail.com>
 * Copyright (c) 2021 Hoyeon Lee <hoyeon.rhee@gmail.com>
 */

#ifndef KFD_AMDGPU_INSN_H_INCLUDED
#define KFD_AMDGPU_INSN_H_INCLUDED

#include "knod_amdgpu.h"
#include "knod_gfx10_insn.h"
#include "knod_gfx9_insn.h"

enum amdgcn_insn_type {
	AMDGCN_INSN_TYPE_SOP2,
	AMDGCN_INSN_TYPE_SOPK,
	AMDGCN_INSN_TYPE_SOP1,
	AMDGCN_INSN_TYPE_SOPC,
	AMDGCN_INSN_TYPE_SOPP,
	AMDGCN_INSN_TYPE_SMEM,
	AMDGCN_INSN_TYPE_VOP2,
	AMDGCN_INSN_TYPE_VOP1,
	AMDGCN_INSN_TYPE_VOPC,
	AMDGCN_INSN_TYPE_VOP3A,
	AMDGCN_INSN_TYPE_VOP3B,
	AMDGCN_INSN_TYPE_VOP3P,
	AMDGCN_INSN_TYPE_SDWA,
	AMDGCN_INSN_TYPE_SDWAB,
	AMDGCN_INSN_TYPE_DPP16,
	AMDGCN_INSN_TYPE_DPP8,
	AMDGCN_INSN_TYPE_VINTRP,
	AMDGCN_INSN_TYPE_DS,
	AMDGCN_INSN_TYPE_MTBUF,
	AMDGCN_INSN_TYPE_MUBUF,
	AMDGCN_INSN_TYPE_MIMG,
	AMDGCN_INSN_TYPE_FLAT,
	AMDGCN_INSN_TYPE_EXP,
	__AMDGCN_INSN_TYPE_MAX,
};

static const char opnames_gfx10[__AMDGCN_INSN_TYPE_MAX][900][30] = {
	[AMDGCN_INSN_TYPE_VOP3A] = {
		[GFX10_V_FMA_LEGACY_F32] = "v_fma_legacy_f32",
		[GFX10_V_MAD_I32_I24] = "V_MAD_I32_I24",
		[GFX10_V_MAD_U32_U24] = "v_mad_u32_u24",
		[GFX10_V_CUBEID_F32] = "v_cubeid_f32",
		[GFX10_V_CUBESC_F32] = "v_cubesc_f32",
		[GFX10_V_CUBETC_F32] = "v_cubetc_f32",
		[GFX10_V_CUBEMA_F32] = "v_cubema_f32",
		[GFX10_V_BFE_U32] = "v_bfe_u32",
		[GFX10_V_BFE_I32] = "v_bfe_i32",
		[GFX10_V_BFI_B32] = "v_bfi_b32",
		[GFX10_V_FMA_F32] = "v_fma_f32",
		[GFX10_V_FMA_F64] = "v_fma_f64",
		[GFX10_V_LERP_U8] = "v_lerp_u8",
		[GFX10_V_ALIGNBIT_B32] = "v_alignbit_b32",
		[GFX10_V_ALIGNBYTE_B32] = "v_alignbyte_b32",
		[GFX10_V_MULLIT_F32] = "v_mullit_f32",
		[GFX10_V_MIN3_F32] = "v_min3_f32",
		[GFX10_V_MIN3_I32] = "v_min3_i32",
		[GFX10_V_MIN3_U32] = "v_min3_u32",
		[GFX10_V_MAX3_F32] = "v_max3_f32",
		[GFX10_V_MAX3_I32] = "v_max3_i32",
		[GFX10_V_MAX3_U32] = "v_max3_u32",
		[GFX10_V_MED3_F32] = "v_med3_f32",
		[GFX10_V_MED3_I32] = "v_med3_i32",
		[GFX10_V_MED3_U32] = "v_med3_u32",
		[GFX10_V_SAD_U8] = "v_sad_u8",
		[GFX10_V_SAD_HI_U8] = "v_sad_hi_u8",
		[GFX10_V_SAD_U16] = "v_sad_u16",
		[GFX10_V_SAD_U32] = "v_sad_u32",
		[GFX10_V_CVT_PK_U8_F32] = "v_cvt_pk_u8_f32",
		[GFX10_V_DIV_FIXUP_F32] = "v_div_fixup_f32",
		[GFX10_V_DIV_FIXUP_F64] = "v_div_fixup_f64",
		[GFX10_V_ADD_F64] = "v_add_f64",
		[GFX10_V_MUL_F64] = "v_mul_f64",
		[GFX10_V_MIN_F64] = "v_min_f64",
		[GFX10_V_MAX_F64] = "v_max_f64",
		[GFX10_V_LDEXP_F64] = "v_ldexp_f64",
		[GFX10_V_MUL_LO_U32] = "v_mul_lo_u32",
		[GFX10_V_MUL_HI_U32] = "v_mul_hi_u32",
		[GFX10_V_MUL_HI_I32] = "v_mul_hi_i32",
		[GFX10_V_DIV_FMAS_F32] = "v_div_fmas_f32",
		[GFX10_V_DIV_FMAS_F64] = "v_div_fmas_f64",
		[GFX10_V_MSAD_U8] = "v_msad_u8",
		[GFX10_V_QSAD_PK_U16_U8] = "v_qsad_pk_u16_u8",
		[GFX10_V_MQSAD_PK_U16_U8] = "v_mqsad_pk_u16_u8",
		[GFX10_V_TRIG_PREOP_F64] = "v_trig_preop_f64",
		[GFX10_V_MQSAD_U32_U8] = "v_mqsad_u32_u8",
		[GFX10_V_XOR3_B32] = "v_xor3_b32",
		[GFX10_V_LSHLREV_B64] = "v_lshlrev_b64",
		[GFX10_V_LSHRREV_B64] = "v_lshrrev_b64",
		[GFX10_V_ASHRREV_I64] = "v_ashrrev_i64",
		[GFX10_V_ADD_NC_U16] = "v_add_nc_u16",
		[GFX10_V_SUB_NC_U16] = "v_sub_nc_u16",
		[GFX10_V_MUL_LO_U16] = "v_mul_lo_u16",
		[GFX10_V_LSHRREV_B16] = "v_lshrrev_b16",
		[GFX10_V_ASHRREV_I16] = "v_ashrrev_i16",
		[GFX10_V_MAX_U16] = "v_max_u16",
		[GFX10_V_MAX_I16] = "v_max_i16",
		[GFX10_V_MIN_U16] = "v_min_u16",
		[GFX10_V_MIN_I16] = "v_min_i16",
		[GFX10_V_ADD_NC_I16] = "v_add_nc_i16",
		[GFX10_V_SUB_NC_I16] = "v_sub_nc_i16",
		[GFX10_V_PACK_B32_F16] = "v_pack_b32_f16",
		[GFX10_V_CVT_PKNORM_I16_F16] = "v_cvt_pknorm_i16_f16",
		[GFX10_V_CVT_PKNORM_U16_F16] = "v_cvt_pknorm_u16_f16",
		[GFX10_V_LSHLREV_B16] = "v_lshlrev_b16",
		[GFX10_V_MAD_U16] = "v_mad_u16",
		[GFX10_V_INTERP_P1LL_F16] = "v_interp_p1ll_f16",
		[GFX10_V_INTERP_P1LV_F16] = "v_interp_p1lv_f16",
		[GFX10_V_PERM_B32] = "v_perm_b32",
		[GFX10_V_XAD_U32] = "v_xad_u32",
		[GFX10_V_LSHL_ADD_U32] = "v_lshl_add_u32",
		[GFX10_V_ADD_LSHL_U32] = "v_add_lshl_u32",
		[GFX10_V_FMA_F16] = "v_fma_f16",
		[GFX10_V_MIN3_F16] = "v_min3_f16",
		[GFX10_V_MIN3_I16] = "v_min3_i16",
		[GFX10_V_MIN3_U16] = "v_min3_u16",
		[GFX10_V_MAX3_F16] = "v_max3_f16",
		[GFX10_V_MAX3_I16] = "v_max3_i16",
		[GFX10_V_MAX3_U16] = "v_max3_u16",
		[GFX10_V_MED3_F16] = "v_med3_f16",
		[GFX10_V_MED3_I16] = "v_med3_i16",
		[GFX10_V_MED3_U16] = "v_med3_u16",
		[GFX10_V_INTERP_P2_F16] = "v_interp_p2_f16",
		[GFX10_V_MAD_I16] = "v_mad_i16",
		[GFX10_V_DIV_FIXUP_F16] = "v_div_fixup_f16",
		[GFX10_V_READLANE_B32] = "v_readlane_b32",
		[GFX10_V_WRITELANE_B32] = "v_writelane_b32",
		[GFX10_V_LDEXP_F32] = "v_ldexp_f32",
		[GFX10_V_BFM_B32] = "v_bfm_b32",
		[GFX10_V_BCNT_U32_B32] = "v_bcnt_u32_b32",
		[GFX10_V_MBCNT_LO_U32_B32] = "v_mbcnt_lo_u32_b32",
		[GFX10_V_MBCNT_HI_U32_B32] = "v_mbcnt_hi_u32_b32",
		[GFX10_V_CVT_PKNORM_I16_F32] = "v_cvt_pknorm_i16_f32",
		[GFX10_V_CVT_PKNORM_U16_F32] = "v_cvt_pknorm_u16_f32",
		[GFX10_V_CVT_PK_U16_U32] = "v_cvt_pk_u16_u32",
		[GFX10_V_CVT_PK_I16_I32] = "v_cvt_pk_i16_i32",
		[GFX10_V_ADD3_U32] = "v_add3_u32",
		[GFX10_V_LSHL_OR_B32] = "v_lshl_or_b32",
		[GFX10_V_AND_OR_B32] = "v_and_or_b32",
		[GFX10_V_OR3_B32] = "v_or3_b32",
		[GFX10_V_MAD_U32_U16] = "v_mad_u32_u16",
		[GFX10_V_MAD_I32_I16] = "v_mad_i32_i16",
		[GFX10_V_SUB_NC_I32] = "v_sub_nc_i32",
		[GFX10_V_PERMLANE16_B32] = "v_permlane16_b32",
		[GFX10_V_PERMLANEX16_B32] = "v_permlanex16_b32",
		[GFX10_V_ADD_NC_I32] = "v_add_nc_i32",
	},
	[AMDGCN_INSN_TYPE_SOP2] = {
		[GFX10_S_ADD_U32] = "s_add_u32",
		[GFX10_S_SUB_U32] = "s_sub_u32",
		[GFX10_S_ADD_I32] = "s_add_i32",
		[GFX10_S_SUB_I32] = "s_sub_i32",
		[GFX10_S_ADDC_U32] = "s_addc_u32",
		[GFX10_S_SUBB_U32] = "s_subb_u32",
		[GFX10_S_MIN_I32] = "s_min_i32",
		[GFX10_S_MIN_U32] = "s_min_u32",
		[GFX10_S_MAX_I32] = "s_max_i32",
		[GFX10_S_MAX_U32] = "s_max_u32",
		[GFX10_S_CSELECT_B32] = "s_cselect_b32",
		[GFX10_S_CELECT_B64] = "s_celect_b64",
		[GFX10_S_AND_B32] = "s_and_b32",
		[GFX10_S_AND_B64] = "s_and_b64",
		[GFX10_S_OR_B32] = "s_or_b32",
		[GFX10_S_OR_B64] = "s_or_b64",
		[GFX10_S_XOR_B32] = "s_xor_b32",
		[GFX10_S_XOR_B64] = "s_xor_b64",
		[GFX10_S_ANDN2_B32] = "s_andn2_b32",
		[GFX10_S_ANDN2_B64] = "s_andn2_b64",
		[GFX10_S_ORN2_B32] = "s_orn2_b32",
		[GFX10_S_ORN2_B64] = "s_orn2_b64",
		[GFX10_S_NAND_B32] = "s_nand_b32",
		[GFX10_S_NAND_B64] = "s_nand_b64",
		[GFX10_S_NOR_B32] = "s_nor_b32",
		[GFX10_S_NOR_B64] = "s_nor_b64",
		[GFX10_S_XNOR_B32] = "s_xnor_b32",
		[GFX10_S_XNOR_B64] = "s_xnor_b64",
		[GFX10_S_LSHL_B32] = "s_lshl_b32",
		[GFX10_S_LSHL_B64] = "s_lshl_b64",
		[GFX10_S_LSHR_B32] = "s_lshr_b32",
		[GFX10_S_LSHR_B64] = "s_lshr_b64",
		[GFX10_S_ASHR_I32] = "s_ashr_i32",
		[GFX10_S_ASHR_I64] = "s_ashr_i64",
		[GFX10_S_BFM_B32] = "s_bfm_b32",
		[GFX10_S_BFM_B64] = "s_bfm_b64",
		[GFX10_S_MUL_I32] = "s_mul_i32",
		[GFX10_S_MUL_I64] = "s_mul_i64",
		[GFX10_S_BFE_U32] = "s_bfe_u32",
		[GFX10_S_BFE_I32] = "s_bfe_i32",
		[GFX10_S_BFE_U64] = "s_bfe_u64",
		[GFX10_S_ABSDIFF_I32] = "s_absdiff_i32",
		[GFX10_S_LSHL1_ADD_U32] = "s_lshl1_add_u32",
		[GFX10_S_LSHL2_ADD_U32] = "s_lshl2_add_u32",
		[GFX10_S_LSHL3_ADD_U32] = "s_lshl3_add_u32",
		[GFX10_S_LSHL4_ADD_U32] = "s_lshl4_add_u32",
		[GFX10_S_PACK_LL_B32_B16] = "s_pack_ll_b32_b16",
		[GFX10_S_PACK_LH_B32_B16] = "s_pack_lh_b32_b16",
		[GFX10_S_MUL_HI_U32] = "s_mul_hi_u32",
		[GFX10_S_MUL_HI_I32] = "s_mul_hi_i32",
	},
	[AMDGCN_INSN_TYPE_SOPK] = {
		[GFX10_S_MOVK_I32] = "s_movk_i32",
		[GFX10_S_VERSION] = "s_version",
		[GFX10_S_CMOVK_I32] = "s_cmovk_i32",
		[GFX10_S_CMPK_EQ_I32] = "s_cmpk_eq_i32",
		[GFX10_S_CMPK_LG_I32] = "s_cmpk_lg_i32",
		[GFX10_S_CMPK_GT_I32] = "s_cmpk_gt_i32",
		[GFX10_S_CMPK_GE_I32] = "s_cmpk_ge_i32",
		[GFX10_S_CMPK_LT_I32] = "s_cmpk_lt_i32",
		[GFX10_S_CMPK_LE_I32] = "s_cmpk_le_i32",
		[GFX10_S_CMPK_EQ_U32] = "s_cmpk_eq_u32",
		[GFX10_S_CMPK_LG_U32] = "s_cmpk_lg_u32",
		[GFX10_S_CMPK_GT_U32] = "s_cmpk_gt_u32",
		[GFX10_S_CMPK_GE_U32] = "s_cmpk_ge_u32",
		[GFX10_S_CMPK_LT_U32] = "s_cmpk_lt_u32",
		[GFX10_S_CMPK_LE_U32] = "s_cmpk_le_u32",
		[GFX10_S_ADDK_I32] = "s_addk_i32",
		[GFX10_S_MULK_I32] = "s_mulk_i32",
		[GFX10_S_GETREG_B32] = "s_getreg_b32",
		[GFX10_S_SETREG_B32] = "s_setreg_b32",
		[GFX10_S_SETREG_IMM32_B32] = "s_setreg_imm32_b32",
		[GFX10_S_CALL_B64] = "s_call_b64",
		[GFX10_S_WAITCNT_VSCNT] = "s_waitcnt_vscnt",
		[GFX10_S_WAITCNT_VMCNT] = "s_waitcnt_vmcnt",
		[GFX10_S_WAITCNT_EXPCNT] = "s_waitcnt_expcnt",
		[GFX10_S_WAITCNT_LGKMCNT] = "s_waitcnt_lgkmcnt",
		[GFX10_S_SUBVECTOR_LOOP_BEGIN] = "s_subvector_loop_begin",
		[GFX10_S_SUBVECTOR_LOOP_END] = "s_subvector_loop_end",
	},
	[AMDGCN_INSN_TYPE_SOP1] = {
		[GFX10_S_MOV_B32] = "s_mov_b32",
		[GFX10_S_MOV_B64] = "s_mov_b64",
		[GFX10_S_CMOV_B32] = "s_cmov_b32",
		[GFX10_S_CMOV_B64] = "s_cmov_b64",
		[GFX10_S_NOT_B32] = "s_not_b32",
		[GFX10_S_NOT_B64] = "s_not_b64",
		[GFX10_S_WQM_B32] = "s_wqm_b32",
		[GFX10_S_WQM_B64] = "s_wqm_b64",
		[GFX10_S_BREV_B32] = "s_brev_b32",
		[GFX10_S_BREV_B64] = "s_brev_b64",
		[GFX10_S_BCNT0_I32_B32] = "s_bcnt0_i32_b32",
		[GFX10_S_BCNT0_I32_B64] = "s_bcnt0_i32_b64",
		[GFX10_S_BCNT1_I32_B32] = "s_bcnt1_i32_b32",
		[GFX10_S_BCNT1_I32_B64] = "s_bcnt1_i32_b64",
		[GFX10_S_FF0_I32_B32] = "s_ff0_i32_b32",
		[GFX10_S_FF0_I32_B64] = "s_ff0_i32_b64",
		[GFX10_S_FF1_I32_B32] = "s_ff1_i32_b32",
		[GFX10_S_FF1_I32_B64] = "s_ff1_i32_b64",
		[GFX10_S_FLBIT_I32_B32] = "s_flbit_i32_b32",
		[GFX10_S_FLBIT_I32_B64] = "s_flbit_i32_b64",
		[GFX10_S_FLBIT_I32] = "s_flbit_i32",
		[GFX10_S_FLBIT_I32_I64] = "s_flbit_i32_i64",
		[GFX10_S_SEXT_I32_I8] = "s_sext_i32_i8",
		[GFX10_S_SEXT_I32_I16] = "s_sext_i32_i16",
		[GFX10_S_BITSET0_B32] = "s_bitset0_b32",
		[GFX10_S_BITSET0_B64] = "s_bitset0_b64",
		[GFX10_S_BITSET1_B32] = "s_bitset1_b32",
		[GFX10_S_BITSET1_B64] = "s_bitset1_b64",
		[GFX10_S_GETPC_B64] = "s_getpc_b64",
		[GFX10_S_SETPC_B64] = "s_setpc_b64",
		[GFX10_S_SWAPPC_B64] = "s_swappc_b64",
		[GFX10_S_RFE_B64] = "s_rfe_b64",
		[GFX10_S_AND_SAVEEXEC_B64] = "s_and_saveexec_b64",
		[GFX10_S_XNOR_SAVEEXEC_B64] = "s_xnor_saveexec_b64",
		[GFX10_S_QUADMASK_B32] = "s_quadmask_b32",
		[GFX10_S_QUADMASK_B64] = "s_quadmask_b64",
		[GFX10_S_MOVRELS_B32] = "s_movrels_b32",
		[GFX10_S_MOVRELS_B64] = "s_movrels_b64",
		[GFX10_S_MOVRELD_B32] = "s_movreld_b32",
		[GFX10_S_MOVRELD_B64] = "s_movreld_b64",
		[GFX10_S_ABS_I32] = "s_abs_i32",
		[GFX10_S_ANDN1_SAVEEXEC_B64] = "s_andn1_saveexec_b64",
		[GFX10_S_ORN1_SAVEEXEC_B64] = "s_orn1_saveexec_b64",
		[GFX10_S_ANDN1_WREXEC_B64] = "s_andn1_wrexec_b64",
		[GFX10_S_ANDN2_WREXEC_B64] = "s_andn2_wrexec_b64",
		[GFX10_S_BITREPLICATE_B64_B32] = "s_bitreplicate_b64_b32",
		[GFX10_S_AND_SAVEEXEC_B32] = "s_and_saveexec_b32",
		[GFX10_S_OR_SAVEEXEC_B32] = "s_or_saveexec_b32",
		[GFX10_S_XOR_SAVEEXEC_B32] = "s_xor_saveexec_b32",
		[GFX10_S_ANDN2_SAVEEXEC_B32] = "s_andn2_saveexec_b32",
		[GFX10_S_ORN2_SAVEEXEC_B32] = "s_orn2_saveexec_b32",
		[GFX10_S_NAND_SAVEEXEC_B32] = "s_nand_saveexec_b32",
		[GFX10_S_NOR_SAVEEXEC_B32] = "s_nor_saveexec_b32",
		[GFX10_S_XNOR_SAVEEXEC_B32] = "s_xnor_saveexec_b32",
		[GFX10_S_ANDN1_SAVEEXEC_B32] = "s_andn1_saveexec_b32",
		[GFX10_S_ORN1_SAVEEXEC_B32] = "s_orn1_saveexec_b32",
		[GFX10_S_ANDN1_WREXEC_B32] = "s_andn1_wrexec_b32",
		[GFX10_S_ANDN2_WREXEC_B32] = "s_andn2_wrexec_b32",
		[GFX10_S_MOVRELSD_2_B32] = "s_movrelsd_2_b32",
	},
	[AMDGCN_INSN_TYPE_SOPC] = {
		[GFX10_S_CMP_EQ_I32] = "s_cmp_eq_i32",
		[GFX10_S_CMP_LG_I32] = "s_cmp_lg_i32",
		[GFX10_S_CMP_GT_I32] = "s_cmp_gt_i32",
		[GFX10_S_CMP_GE_I32] = "s_cmp_ge_i32",
		[GFX10_S_CMP_LT_I32] = "s_cmp_lt_i32",
		[GFX10_S_CMP_LE_I32] = "s_cmp_le_i32",
		[GFX10_S_CMP_EQ_U32] = "s_cmp_eq_u32",
		[GFX10_S_CMP_LG_U32] = "s_cmp_lg_u32",
		[GFX10_S_CMP_GT_U32] = "s_cmp_gt_u32",
		[GFX10_S_CMP_GE_U32] = "s_cmp_ge_u32",
		[GFX10_S_CMP_LT_U32] = "s_cmp_lt_u32",
		[GFX10_S_CMP_LE_U32] = "s_cmp_le_u32",
		[GFX10_S_BITCMP0_B32] = "s_bitcmp0_b32",
		[GFX10_S_BITCMP1_B32] = "s_bitcmp1_b32",
		[GFX10_S_BITCMP0_B64] = "s_bitcmp0_b64",
		[GFX10_S_BITCMP1_B64] = "s_bitcmp1_b64",
		[GFX10_S_CMP_EQ_U64] = "s_cmp_eq_u64",
		[GFX10_S_CMP_LG_U64] = "s_cmp_lg_u64",
	},
	[AMDGCN_INSN_TYPE_SOPP] = {
		[GFX10_S_NOP] = "s_nop",
		[GFX10_S_ENDPGM] = "s_endpgm",
		[GFX10_S_BRANCH] = "s_branch",
		[GFX10_S_WAKEUP] = "s_wakeup",
		[GFX10_S_CBRANCH_SCC0] = "s_cbranch_scc0",
		[GFX10_S_CBRANCH_SCC1] = "s_cbranch_scc1",
		[GFX10_S_CBRANCH_VCCZ] = "s_cbranch_vccz",
		[GFX10_S_CBRANCH_VCCNZ] = "s_cbranch_vccnz",
		[GFX10_S_CBRANCH_EXECZ] = "s_cbranch_execz",
		[GFX10_S_CBRANCH_EXECNZ] = "s_cbranch_execnz",
		[GFX10_S_BARRIER] = "s_barrier",
		[GFX10_S_SETKILL] = "s_setkill",
		[GFX10_S_WAITCNT] = "s_waitcnt",
		[GFX10_S_SETHALT] = "s_sethalt",
		[GFX10_S_SLEEP] = "s_sleep",
		[GFX10_S_SETPRIO] = "s_setprio",
		[GFX10_S_SENDMSG] = "s_sendmsg",
		[GFX10_S_SENDMSGHALT] = "s_sendmsghalt",
		[GFX10_S_TRAP] = "s_trap",
		[GFX10_S_ICACHE_INV] = "s_icache_inv",
		[GFX10_S_INCPERFLEVEL] = "s_incperflevel",
		[GFX10_S_DECPERFLEVEL] = "s_decperflevel",
		[GFX10_S_TTRACEDATA] = "s_ttracedata",
		[GFX10_S_CBRANCH_CDBGSYS] = "s_cbranch_cdbgsys",
		[GFX10_S_CBRANCH_CDBGUSER] = "s_cbranch_cdbguser",
		[GFX10_S_CBRANCH_CDBGSYS_OR_USER] = "s_cbranch_cdbgsys_or_user",
		[GFX10_S_CBRANCH_CDBGSYS_AND_USER] = "s_cbranch_cdbgsys_and_user",
		[GFX10_S_ENDPGM_SAVED] = "s_endpgm_saved",
		[GFX10_S_ENDPGM_ORDERED_PS_DONE] = "s_endpgm_ordered_ps_done",
		[GFX10_S_CODE_END] = "s_code_end",
		[GFX10_S_INST_PREFETCH] = "s_inst_prefetch",
		[GFX10_S_CLAUSE] = "s_clause",
		[GFX10_S_WAITCNT_DEPCTR] = "s_waitcnt_depctr",
		[GFX10_S_ROUND_MODE] = "s_round_mode",
		[GFX10_S_DENORM_MODE] = "s_denorm_mode",
		[GFX10_S_TTRACEDATA_IMM] = "s_ttracedata_imm",
	},
	[AMDGCN_INSN_TYPE_SMEM] = {
		[GFX10_S_LOAD_DWORD] = "s_load_dword",
		[GFX10_S_LOAD_DWORDX2] = "s_load_dwordx2",
		[GFX10_S_LOAD_DWORDX4] = "s_load_dwordx4",
		[GFX10_S_LOAD_DWORDX8] = "s_load_dwordx8",
		[GFX10_S_LOAD_DWORDX16] = "s_load_dwordx16",
		[GFX10_S_BUFFER_LOAD_DWORD] = "s_buffer_load_dword",
		[GFX10_S_BUFFER_LOAD_DWORDX2] = "s_buffer_load_dwordx2",
		[GFX10_S_BUFFER_LOAD_DWORDX4] = "s_buffer_load_dwordx4",
		[GFX10_S_BUFFER_LOAD_DWORDX8] = "s_buffer_load_dwordx8",
		[GFX10_S_BUFFER_LOAD_DWORDX16] = "s_buffer_load_dwordx16",
		[GFX10_S_GL1_INV] = "s_gl1_inv",
		[GFX10_S_DCACHE_INV] = "s_dcache_inv",
		[GFX10_S_MEMTIME] = "s_memtime",
		[GFX10_S_MEMREALTIME] = "s_memrealtime",
		[GFX10_S_ATC_PROBE] = "s_atc_probe",
		[GFX10_S_ATC_PROBE_BUFFER] = "s_atc_probe_buffer",
	},
	[AMDGCN_INSN_TYPE_VOP2] = {
		[GFX10_V_CNDMASK_B32] = "v_cndmask_b32",
		[GFX10_V_DOT2C_F32_F16] = "v_dot2c_f32_f16",
		[GFX10_V_ADD_F32] = "v_add_f32",
		[GFX10_V_SUB_F32] = "v_sub_f32",
		[GFX10_V_SUBREV_F32] = "v_subrev_f32",
		[GFX10_V_FMAC_LEGACY_F32] = "v_fmac_legacy_f32",
		[GFX10_V_MUL_LEGACY_F32] = "v_mul_legacy_f32",
		[GFX10_V_MUL_F32] = "v_mul_f32",
		[GFX10_V_MUL_I32_I24] = "v_mul_i32_i24",
		[GFX10_V_MUL_HI_I32_I24] = "v_mul_hi_i32_i24",
		[GFX10_V_MUL_U32_U24] = "v_mul_u32_u24",
		[GFX10_V_MUL_HI_U32_U24] = "v_mul_hi_u32_u24",
		[GFX10_V_DOT4C_I32_I8] = "v_dot4c_i32_i8",
		[GFX10_V_MIN_F32] = "v_min_f32",
		[GFX10_V_MAX_F32] = "v_max_f32",
		[GFX10_V_MIN_I32] = "v_min_i32",
		[GFX10_V_MAX_I32] = "v_max_i32",
		[GFX10_V_MIN_U32] = "v_min_u32",
		[GFX10_V_MAX_U32] = "v_max_u32",
		[GFX10_V_LSHRREV_B32] = "v_lshrrev_b32",
		[GFX10_V_ASHRREV_I32] = "v_ashrrev_i32",
		[GFX10_V_LSHLREV_B32] = "v_lshlrev_b32",
		[GFX10_V_AND_B32] = "v_and_b32",
		[GFX10_V_OR_B32] = "v_or_b32",
		[GFX10_V_XOR_B32] = "v_xor_b32",
		[GFX10_V_XNOR_B32] = "v_xnor_b32",
		[GFX10_V_ADD_NC_U32] = "v_add_nc_u32",
		[GFX10_V_SUB_NC_U32] = "v_sub_nc_u32",
		[GFX10_V_SUBREV_NC_U32] = "v_subrev_nc_u32",
		[GFX10_V_ADD_CO_CI_U32] = "v_add_co_ci_u32",
		[GFX10_V_SUB_CO_CI_U32] = "v_sub_co_ci_u32",
		[GFX10_V_SUBREV_CO_CI_U32] = "v_subrev_co_ci_u32",
		[GFX10_V_FMAC_F32] = "v_fmac_f32",
		[GFX10_V_FMAMK_F32] = "v_fmamk_f32",
		[GFX10_V_FMAAK_F32] = "v_fmaak_f32",
		[GFX10_V_CVT_PKRTZ_F16_F32] = "v_cvt_pkrtz_f16_f32",
		[GFX10_V_ADD_F16] = "v_add_f16",
		[GFX10_V_SUB_F16] = "v_sub_f16",
		[GFX10_V_SUBREV_F16] = "v_subrev_f16",
		[GFX10_V_MUL_F16] = "v_mul_f16",
		[GFX10_V_FMAC_F16] = "v_fmac_f16",
		[GFX10_V_FMAMK_F16] = "v_fmamk_f16",
		[GFX10_V_FMAAK_F16] = "v_fmaak_f16",
		[GFX10_V_MAX_F16] = "v_max_f16",
		[GFX10_V_MIN_F16] = "v_min_f16",
		[GFX10_V_LDEXP_F16] = "v_ldexp_f16",
		[GFX10_V_PK_FMAC_F16] = "v_pk_fmac_f16",
	},
	[AMDGCN_INSN_TYPE_VOP1] = {
		[GFX10_V_NOP] = "v_nop",
		[GFX10_V_MOV_B32] = "v_mov_b32",
		[GFX10_V_READFIRSTLANE_B32] = "v_readfirstlane_b32",
		[GFX10_V_CVT_I32_F64] = "v_cvt_i32_f64",
		[GFX10_V_CVT_F64_I32] = "v_cvt_f64_i32",
		[GFX10_V_CVT_F32_I32] = "v_cvt_f32_i32",
		[GFX10_V_CVT_F32_U32] = "v_cvt_f32_u32",
		[GFX10_V_CVT_U32_F32] = "v_cvt_u32_f32",
		[GFX10_V_CVT_I32_F32] = "v_cvt_i32_f32",
		[GFX10_V_CVT_F16_F32] = "v_cvt_f16_f32",
		[GFX10_V_CVT_F32_F16] = "v_cvt_f32_f16",
		[GFX10_V_CVT_RPI_I32_F32] = "v_cvt_rpi_i32_f32",
		[GFX10_V_CVT_FLR_I32_F32] = "v_cvt_flr_i32_f32",
		[GFX10_V_CVT_OFF_F32_I4] = "v_cvt_off_f32_i4",
		[GFX10_V_CVT_F32_F64] = "v_cvt_f32_f64",
		[GFX10_V_CVT_F64_F32] = "v_cvt_f64_f32",
		[GFX10_V_CVT_F32_UBYTE0] = "v_cvt_f32_ubyte0",
		[GFX10_V_CVT_F32_UBYTE1] = "v_cvt_f32_ubyte1",
		[GFX10_V_CVT_F32_UBYTE2] = "v_cvt_f32_ubyte2",
		[GFX10_V_CVT_F32_UBYTE3] = "v_cvt_f32_ubyte3",
		[GFX10_V_CVT_U32_F64] = "v_cvt_u32_f64",
		[GFX10_V_CVT_F64_U32] = "v_cvt_f64_u32",
		[GFX10_V_TRUNC_F64] = "v_trunc_f64",
		[GFX10_V_CEIL_F64] = "v_ceil_f64",
		[GFX10_V_RNDNE_F64] = "v_rndne_f64",
		[GFX10_V_FLOOR_F64] = "v_floor_f64",
		[GFX10_V_PIPEFLUSH] = "v_pipeflush",
		[GFX10_V_FRACT_F32] = "v_fract_f32",
		[GFX10_V_TRUNC_F32] = "v_trunc_f32",
		[GFX10_V_CEIL_F32] = "v_ceil_f32",
		[GFX10_V_RNDNE_F32] = "v_rndne_f32",
		[GFX10_V_FLOOR_F32] = "v_floor_f32",
		[GFX10_V_EXP_F32] = "v_exp_f32",
		[GFX10_V_LOG_F32] = "v_log_f32",
		[GFX10_V_RCP_F32] = "v_rcp_f32",
		[GFX10_V_RCP_IFLAG_F32] = "v_rcp_iflag_f32",
		[GFX10_V_RSQ_F32] = "v_rsq_f32",
		[GFX10_V_RCP_F64] = "v_rcp_f64",
		[GFX10_V_RSQ_F64] = "v_rsq_f64",
		[GFX10_V_SQRT_F32] = "v_sqrt_f32",
		[GFX10_V_SQRT_F64] = "v_sqrt_f64",
		[GFX10_V_SIN_F32] = "v_sin_f32",
		[GFX10_V_COS_F32] = "v_cos_f32",
		[GFX10_V_NOT_B32] = "v_not_b32",
		[GFX10_V_BFREV_B32] = "v_bfrev_b32",
		[GFX10_V_FFBH_U32] = "v_ffbh_u32",
		[GFX10_V_FFBL_B32] = "v_ffbl_b32",
		[GFX10_V_FFBH_I32] = "v_ffbh_i32",
		[GFX10_V_FREXP_EXP_I32_F64] = "v_frexp_exp_i32_f64",
		[GFX10_V_FREXP_MANT_F64] = "v_frexp_mant_f64",
		[GFX10_V_FRACT_F64] = "v_fract_f64",
		[GFX10_V_FREXP_EXP_I32_F32] = "v_frexp_exp_i32_f32",
		[GFX10_V_FREXP_MANT_F32] = "v_frexp_mant_f32",
		[GFX10_V_CLREXCP] = "v_clrexcp",
		[GFX10_V_MOVRELD_B32] = "v_movreld_b32",
		[GFX10_V_MOVRELS_B32] = "v_movrels_b32",
		[GFX10_V_MOVRELSD_B32] = "v_movrelsd_b32",
		[GFX10_V_MOVRELSD_2_B32] = "v_movrelsd_2_b32",
		[GFX10_V_CVT_F16_U16] = "v_cvt_f16_u16",
		[GFX10_V_CVT_F16_I16] = "v_cvt_f16_i16",
		[GFX10_V_CVT_U16_F16] = "v_cvt_u16_f16",
		[GFX10_V_CVT_I16_F16] = "v_cvt_i16_f16",
		[GFX10_V_RCP_F16] = "v_rcp_f16",
		[GFX10_V_SQRT_F16] = "v_sqrt_f16",
		[GFX10_V_RSQ_F16] = "v_rsq_f16",
		[GFX10_V_LOG_F16] = "v_log_f16",
		[GFX10_V_EXP_F16] = "v_exp_f16",
		[GFX10_V_FREXP_MANT_F16] = "v_frexp_mant_f16",
		[GFX10_V_FREXP_EXP_I16_F16] = "v_frexp_exp_i16_f16",
		[GFX10_V_FLOOR_F16] = "v_floor_f16",
		[GFX10_V_CEIL_F16] = "v_ceil_f16",
		[GFX10_V_TRUNC_F16] = "v_trunc_f16",
		[GFX10_V_RNDNE_F16] = "v_rndne_f16",
		[GFX10_V_FRACT_F16] = "v_fract_f16",
		[GFX10_V_SIN_F16] = "v_sin_f16",
		[GFX10_V_COS_F16] = "v_cos_f16",
		[GFX10_V_SAT_PK_U8_I16] = "v_sat_pk_u8_i16",
		[GFX10_V_CVT_NORM_I16_F16] = "v_cvt_norm_i16_f16",
		[GFX10_V_CVT_NORM_U16_F16] = "v_cvt_norm_u16_f16",
		[GFX10_V_SWAP_B32] = "v_swap_b32",
		[GFX10_V_SWAPREL_B32] = "v_swaprel_b32",
	},
	[AMDGCN_INSN_TYPE_VOPC] = {
		[GFX10_V_CMP_F_F32] = "v_cmp_f_f32",
		[GFX10_V_CMP_LT_F32] = "v_cmp_lt_f32",
		[GFX10_V_CMP_EQ_F32] = "v_cmp_eq_f32",
		[GFX10_V_CMP_LE_F32] = "v_cmp_le_f32",
		[GFX10_V_CMP_GT_F32] = "v_cmp_gt_f32",
		[GFX10_V_CMP_LG_F32] = "v_cmp_lg_f32",
		[GFX10_V_CMP_GE_F32] = "v_cmp_ge_f32",
		[GFX10_V_CMP_O_F32] = "v_cmp_o_f32",
		[GFX10_V_CMP_U_F32] = "v_cmp_u_f32",
		[GFX10_V_CMP_NGE_F32] = "v_cmp_nge_f32",
		[GFX10_V_CMP_NLG_F32] = "v_cmp_nlg_f32",
		[GFX10_V_CMP_NGT_F32] = "v_cmp_ngt_f32",
		[GFX10_V_CMP_NLE_F32] = "v_cmp_nle_f32",
		[GFX10_V_CMP_NEQ_F32] = "v_cmp_neq_f32",
		[GFX10_V_CMP_NLT_F32] = "v_cmp_nlt_f32",
		[GFX10_V_CMP_TRU_F32] = "v_cmp_tru_f32",
		[GFX10_V_CMPX_F_F32] = "v_cmpx_f_f32",
		[GFX10_V_CMPX_LT_F32] = "v_cmpx_lt_f32",
		[GFX10_V_CMPX_EQ_F32] = "v_cmpx_eq_f32",
		[GFX10_V_CMPX_LE_F32] = "v_cmpx_le_f32",
		[GFX10_V_CMPX_GT_F32] = "v_cmpx_gt_f32",
		[GFX10_V_CMPX_LG_F32] = "v_cmpx_lg_f32",
		[GFX10_V_CMPX_GE_F32] = "v_cmpx_ge_f32",
		[GFX10_V_CMPX_O_F32] = "v_cmpx_o_f32",
		[GFX10_V_CMPX_U_F32] = "v_cmpx_u_f32",
		[GFX10_V_CMPX_NGE_F32] = "v_cmpx_nge_f32",
		[GFX10_V_CMPX_NLG_F32] = "v_cmpx_nlg_f32",
		[GFX10_V_CMPX_NGT_F32] = "v_cmpx_ngt_f32",
		[GFX10_V_CMPX_NLE_F32] = "v_cmpx_nle_f32",
		[GFX10_V_CMPX_NEQ_F32] = "v_cmpx_neq_f32",
		[GFX10_V_CMPX_NLT_F32] = "v_cmpx_nlt_f32",
		[GFX10_V_CMPX_TRU_F32] = "v_cmpx_tru_f32",
		[GFX10_V_CMP_F_F64] = "v_cmp_f_f64",
		[GFX10_V_CMP_LT_F64] = "v_cmp_lt_f64",
		[GFX10_V_CMP_EQ_F64] = "v_cmp_eq_f64",
		[GFX10_V_CMP_LE_F64] = "v_cmp_le_f64",
		[GFX10_V_CMP_GT_F64] = "v_cmp_gt_f64",
		[GFX10_V_CMP_LG_F64] = "v_cmp_lg_f64",
		[GFX10_V_CMP_GE_F64] = "v_cmp_ge_f64",
		[GFX10_V_CMP_O_F64] = "v_cmp_o_f64",
		[GFX10_V_CMP_U_F64] = "v_cmp_u_f64",
		[GFX10_V_CMP_NGE_F64] = "v_cmp_nge_f64",
		[GFX10_V_CMP_NLG_F64] = "v_cmp_nlg_f64",
		[GFX10_V_CMP_NGT_F64] = "v_cmp_ngt_f64",
		[GFX10_V_CMP_NLE_F64] = "v_cmp_nle_f64",
		[GFX10_V_CMP_NEQ_F64] = "v_cmp_neq_f64",
		[GFX10_V_CMP_NLT_F64] = "v_cmp_nlt_f64",
		[GFX10_V_CMP_TRU_F64] = "v_cmp_tru_f64",
		[GFX10_V_CMPX_F_F64] = "v_cmpx_f_f64",
		[GFX10_V_CMPX_LT_F64] = "v_cmpx_lt_f64",
		[GFX10_V_CMPX_EQ_F64] = "v_cmpx_eq_f64",
		[GFX10_V_CMPX_LE_F64] = "v_cmpx_le_f64",
		[GFX10_V_CMPX_GT_F64] = "v_cmpx_gt_f64",
		[GFX10_V_CMPX_LG_F64] = "v_cmpx_lg_f64",
		[GFX10_V_CMPX_GE_F64] = "v_cmpx_ge_f64",
		[GFX10_V_CMPX_O_F64] = "v_cmpx_o_f64",
		[GFX10_V_CMPX_U_F64] = "v_cmpx_u_f64",
		[GFX10_V_CMPX_NGE_F64] = "v_cmpx_nge_f64",
		[GFX10_V_CMPX_NLG_F64] = "v_cmpx_nlg_f64",
		[GFX10_V_CMPX_NGT_F64] = "v_cmpx_ngt_f64",
		[GFX10_V_CMPX_NLE_F64] = "v_cmpx_nle_f64",
		[GFX10_V_CMPX_NEQ_F64] = "v_cmpx_neq_f64",
		[GFX10_V_CMPX_NLT_F64] = "v_cmpx_nlt_f64",
		[GFX10_V_CMPX_TRU_F64] = "v_cmpx_tru_f64",
		[GFX10_V_CMP_F_I32] = "v_cmp_f_i32",
		[GFX10_V_CMP_LT_I32] = "v_cmp_lt_i32",
		[GFX10_V_CMP_EQ_I32] = "v_cmp_eq_i32",
		[GFX10_V_CMP_LE_I32] = "v_cmp_le_i32",
		[GFX10_V_CMP_GT_I32] = "v_cmp_gt_i32",
		[GFX10_V_CMP_NE_I32] = "v_cmp_ne_i32",
		[GFX10_V_CMP_GE_I32] = "v_cmp_ge_i32",
		[GFX10_V_CMP_T_I32] = "v_cmp_t_i32",
		[GFX10_V_CMP_CLASS_F32] = "v_cmp_class_f32",
		[GFX10_V_CMP_LT_I16] = "v_cmp_lt_i16",
		[GFX10_V_CMP_EQ_I16] = "v_cmp_eq_i16",
		[GFX10_V_CMP_LE_I16] = "v_cmp_le_i16",
		[GFX10_V_CMP_GT_I16] = "v_cmp_gt_i16",
		[GFX10_V_CMP_NE_I16] = "v_cmp_ne_i16",
		[GFX10_V_CMP_GE_I16] = "v_cmp_ge_i16",
		[GFX10_V_CMP_CLASS_F16] = "v_cmp_class_f16",
		[GFX10_V_CMPX_F_I32] = "v_cmpx_f_i32",
		[GFX10_V_CMPX_LT_I32] = "v_cmpx_lt_i32",
		[GFX10_V_CMPX_EQ_I32] = "v_cmpx_eq_i32",
		[GFX10_V_CMPX_LE_I32] = "v_cmpx_le_i32",
		[GFX10_V_CMPX_GT_I32] = "v_cmpx_gt_i32",
		[GFX10_V_CMPX_NE_I32] = "v_cmpx_ne_i32",
		[GFX10_V_CMPX_GE_I32] = "v_cmpx_ge_i32",
		[GFX10_V_CMPX_T_I32] = "v_cmpx_t_i32",
		[GFX10_V_CMPX_CLASS_F32] = "v_cmpx_class_f32",
		[GFX10_V_CMPX_LT_I16] = "v_cmpx_lt_i16",
		[GFX10_V_CMPX_EQ_I16] = "v_cmpx_eq_i16",
		[GFX10_V_CMPX_LE_I16] = "v_cmpx_le_i16",
		[GFX10_V_CMPX_GT_I16] = "v_cmpx_gt_i16",
		[GFX10_V_CMPX_NE_I16] = "v_cmpx_ne_i16",
		[GFX10_V_CMPX_GE_I16] = "v_cmpx_ge_i16",
		[GFX10_V_CMPX_CLASS_F16] = "v_cmpx_class_f16",
		[GFX10_V_CMP_F_I64] = "v_cmp_f_i64",
		[GFX10_V_CMP_LT_I64] = "v_cmp_lt_i64",
		[GFX10_V_CMP_EQ_I64] = "v_cmp_eq_i64",
		[GFX10_V_CMP_LE_I64] = "v_cmp_le_i64",
		[GFX10_V_CMP_GT_I64] = "v_cmp_gt_i64",
		[GFX10_V_CMP_NE_I64] = "v_cmp_ne_i64",
		[GFX10_V_CMP_GE_I64] = "v_cmp_ge_i64",
		[GFX10_V_CMP_T_I64] = "v_cmp_t_i64",
		[GFX10_V_CMP_CLASS_F64] = "v_cmp_class_f64",
		[GFX10_V_CMP_LT_U16] = "v_cmp_lt_u16",
		[GFX10_V_CMP_EQ_U16] = "v_cmp_eq_u16",
		[GFX10_V_CMP_LE_U16] = "v_cmp_le_u16",
		[GFX10_V_CMP_GT_U16] = "v_cmp_gt_u16",
		[GFX10_V_CMP_NE_U16] = "v_cmp_ne_u16",
		[GFX10_V_CMP_GE_U16] = "v_cmp_ge_u16",
		[GFX10_V_CMPX_F_I64] = "v_cmpx_f_i64",
		[GFX10_V_CMPX_LT_I64] = "v_cmpx_lt_i64",
		[GFX10_V_CMPX_EQ_I64] = "v_cmpx_eq_i64",
		[GFX10_V_CMPX_LE_I64] = "v_cmpx_le_i64",
		[GFX10_V_CMPX_GT_I64] = "v_cmpx_gt_i64",
		[GFX10_V_CMPX_NE_I64] = "v_cmpx_ne_i64",
		[GFX10_V_CMPX_GE_I64] = "v_cmpx_ge_i64",
		[GFX10_V_CMPX_T_I64] = "v_cmpx_t_i64",
		[GFX10_V_CMPX_CLASS_F64] = "v_cmpx_class_f64",
		[GFX10_V_CMPX_LT_U16] = "v_cmpx_lt_u16",
		[GFX10_V_CMPX_EQ_U16] = "v_cmpx_eq_u16",
		[GFX10_V_CMPX_LE_U16] = "v_cmpx_le_u16",
		[GFX10_V_CMPX_GT_U16] = "v_cmpx_gt_u16",
		[GFX10_V_CMPX_NE_U16] = "v_cmpx_ne_u16",
		[GFX10_V_CMPX_GE_U16] = "v_cmpx_ge_u16",
		[GFX10_V_CMP_F_U32] = "v_cmp_f_u32",
		[GFX10_V_CMP_LT_U32] = "v_cmp_lt_u32",
		[GFX10_V_CMP_EQ_U32] = "v_cmp_eq_u32",
		[GFX10_V_CMP_LE_U32] = "v_cmp_le_u32",
		[GFX10_V_CMP_GT_U32] = "v_cmp_gt_u32",
		[GFX10_V_CMP_NE_U32] = "v_cmp_ne_u32",
		[GFX10_V_CMP_GE_U32] = "v_cmp_ge_u32",
		[GFX10_V_CMP_T_U32] = "v_cmp_t_u32",
		[GFX10_V_CMP_F_F16] = "v_cmp_f_f16",
		[GFX10_V_CMP_LT_F16] = "v_cmp_lt_f16",
		[GFX10_V_CMP_EQ_F16] = "v_cmp_eq_f16",
		[GFX10_V_CMP_LE_F16] = "v_cmp_le_f16",
		[GFX10_V_CMP_GT_F16] = "v_cmp_gt_f16",
		[GFX10_V_CMP_LG_F16] = "v_cmp_lg_f16",
		[GFX10_V_CMP_GE_F16] = "v_cmp_ge_f16",
		[GFX10_V_CMP_O_F16] = "v_cmp_o_f16",
		[GFX10_V_CMPX_F_U32] = "v_cmpx_f_u32",
		[GFX10_V_CMPX_LT_U32] = "v_cmpx_lt_u32",
		[GFX10_V_CMPX_EQ_U32] = "v_cmpx_eq_u32",
		[GFX10_V_CMPX_LE_U32] = "v_cmpx_le_u32",
		[GFX10_V_CMPX_GT_U32] = "v_cmpx_gt_u32",
		[GFX10_V_CMPX_NE_U32] = "v_cmpx_ne_u32",
		[GFX10_V_CMPX_GE_U32] = "v_cmpx_ge_u32",
		[GFX10_V_CMPX_T_U32] = "v_cmpx_t_u32",
		[GFX10_V_CMPX_F_F16] = "v_cmpx_f_f16",
		[GFX10_V_CMPX_LT_F16] = "v_cmpx_lt_f16",
		[GFX10_V_CMPX_EQ_F16] = "v_cmpx_eq_f16",
		[GFX10_V_CMPX_LE_F16] = "v_cmpx_le_f16",
		[GFX10_V_CMPX_GT_F16] = "v_cmpx_gt_f16",
		[GFX10_V_CMPX_LG_F16] = "v_cmpx_lg_f16",
		[GFX10_V_CMPX_GE_F16] = "v_cmpx_ge_f16",
		[GFX10_V_CMPX_O_F16] = "v_cmpx_o_f16",
		[GFX10_V_CMP_F_U64] = "v_cmp_f_u64",
		[GFX10_V_CMP_LT_U64] = "v_cmp_lt_u64",
		[GFX10_V_CMP_EQ_U64] = "v_cmp_eq_u64",
		[GFX10_V_CMP_LE_U64] = "v_cmp_le_u64",
		[GFX10_V_CMP_GT_U64] = "v_cmp_gt_u64",
		[GFX10_V_CMP_NE_U64] = "v_cmp_ne_u64",
		[GFX10_V_CMP_GE_U64] = "v_cmp_ge_u64",
		[GFX10_V_CMP_T_U64] = "v_cmp_t_u64",
		[GFX10_V_CMP_U_F16] = "v_cmp_u_f16",
		[GFX10_V_CMP_NGE_F16] = "v_cmp_nge_f16",
		[GFX10_V_CMP_NLG_F16] = "v_cmp_nlg_f16",
		[GFX10_V_CMP_NGT_F16] = "v_cmp_ngt_f16",
		[GFX10_V_CMP_NLE_F16] = "v_cmp_nle_f16",
		[GFX10_V_CMP_NEQ_F16] = "v_cmp_neq_f16",
		[GFX10_V_CMP_NLT_F16] = "v_cmp_nlt_f16",
		[GFX10_V_CMP_TRU_F16] = "v_cmp_tru_f16",
		[GFX10_V_CMPX_F_U64] = "v_cmpx_f_u64",
		[GFX10_V_CMPX_LT_U64] = "v_cmpx_lt_u64",
		[GFX10_V_CMPX_EQ_U64] = "v_cmpx_eq_u64",
		[GFX10_V_CMPX_LE_U64] = "v_cmpx_le_u64",
		[GFX10_V_CMPX_GT_U64] = "v_cmpx_gt_u64",
		[GFX10_V_CMPX_NE_U64] = "v_cmpx_ne_u64",
		[GFX10_V_CMPX_GE_U64] = "v_cmpx_ge_u64",
		[GFX10_V_CMPX_T_U64] = "v_cmpx_t_u64",
		[GFX10_V_CMPX_U_F16] = "v_cmpx_u_f16",
		[GFX10_V_CMPX_NGE_F16] = "v_cmpx_nge_f16",
		[GFX10_V_CMPX_NLG_F16] = "v_cmpx_nlg_f16",
		[GFX10_V_CMPX_NGT_F16] = "v_cmpx_ngt_f16",
		[GFX10_V_CMPX_NLE_F16] = "v_cmpx_nle_f16",
		[GFX10_V_CMPX_NEQ_F16] = "v_cmpx_neq_f16",
		[GFX10_V_CMPX_NLT_F16] = "v_cmpx_nlt_f16",
		[GFX10_V_CMPX_TRU_F16] = "v_cmpx_tru_f16",
	},
	[AMDGCN_INSN_TYPE_VOP3B] = {
		[GFX10_V_DIV_SCALE_F32] = "v_div_scale_f32",
		[GFX10_V_DIV_SCALE_F64] = "v_div_scale_f64",
		[GFX10_V_MAD_U64_U32] = "v_mad_u64_u32",
		[GFX10_V_MAD_I64_I32] = "v_mad_i64_i32",
		[GFX10_V_ADD_CO_U32] = "v_add_co_u32",
		[GFX10_V_SUB_CO_U32] = "v_sub_co_u32",
		[GFX10_V_SUBREV_CO_U32] = "v_subrev_co_u32",
	},
	[AMDGCN_INSN_TYPE_VOP3P] = {
		[GFX10_V_PK_MAD_I16] = "v_pk_mad_i16",
		[GFX10_V_PK_MUL_LO_U16] = "v_pk_mul_lo_u16",
		[GFX10_V_PK_ADD_I16] = "v_pk_add_i16",
		[GFX10_V_PK_SUB_I16] = "v_pk_sub_i16",
		[GFX10_V_PK_LSHLREV_B16] = "v_pk_lshlrev_b16",
		[GFX10_V_PK_LSHRREV_B16] = "v_pk_lshrrev_b16",
		[GFX10_V_PK_ASHRREV_I16] = "v_pk_ashrrev_i16",
		[GFX10_V_PK_MAX_I16] = "v_pk_max_i16",
		[GFX10_V_PK_MIN_I16] = "v_pk_min_i16",
		[GFX10_V_PK_MAD_U16] = "v_pk_mad_u16",
		[GFX10_V_PK_ADD_U16] = "v_pk_add_u16",
		[GFX10_V_PK_SUB_U16] = "v_pk_sub_u16",
		[GFX10_V_PK_MAX_U16] = "v_pk_max_u16",
		[GFX10_V_PK_MIN_U16] = "v_pk_min_u16",
		[GFX10_V_PK_FMA_F16] = "v_pk_fma_f16",
		[GFX10_V_PK_ADD_F16] = "v_pk_add_f16",
		[GFX10_V_PK_MUL_F16] = "v_pk_mul_f16",
		[GFX10_V_PK_MIN_F16] = "v_pk_min_f16",
		[GFX10_V_PK_MAX_F16] = "v_pk_max_f16",
		[GFX10_V_DOT2_F32_F16] = "v_dot2_f32_f16",
		[GFX10_V_DOT2_I32_I16] = "v_dot2_i32_i16",
		[GFX10_V_DOT2_U32_U16] = "v_dot2_u32_u16",
		[GFX10_V_DOT4_I32_I8] = "v_dot4_i32_i8",
		[GFX10_V_DOT4_U32_U8] = "v_dot4_u32_u8",
		[GFX10_V_DOT8_I32_I4] = "v_dot8_i32_i4",
		[GFX10_V_DOT8_U32_U4] = "v_dot8_u32_u4",
		[GFX10_V_FMA_MIX_F32] = "v_fma_mix_f32",
		[GFX10_V_FMA_MIXLO_F16] = "v_fma_mixlo_f16",
		[GFX10_V_FMA_MIXHI_F16] = "v_fma_mixhi_f16",
	},
	[AMDGCN_INSN_TYPE_MUBUF] = {
		[GFX10_BUFFER_LOAD_FORMAT_X] = "buffer_load_format_x",
		[GFX10_BUFFER_LOAD_FORMAT_XY] = "buffer_load_format_xy",
		[GFX10_BUFFER_LOAD_FORMAT_XYZ] = "buffer_load_format_xyz",
		[GFX10_BUFFER_LOAD_FORMAT_XYZW] = "buffer_load_format_xyzw",
		[GFX10_BUFFER_STORE_FORMAT_X] = "buffer_store_format_x",
		[GFX10_BUFFER_STORE_FORMAT_XY] = "buffer_store_format_xy",
		[GFX10_BUFFER_STORE_FORMAT_XYZ] = "buffer_store_format_xyz",
		[GFX10_BUFFER_STORE_FORMAT_XYZW] = "buffer_store_format_xyzw",
		[GFX10_BUFFER_LOAD_UBYTE] = "buffer_load_ubyte",
		[GFX10_BUFFER_LOAD_SBYTE] = "buffer_load_sbyte",
		[GFX10_BUFFER_LOAD_USHORT] = "buffer_load_ushort",
		[GFX10_BUFFER_LOAD_SSHORT] = "buffer_load_sshort",
		[GFX10_BUFFER_LOAD_DWORD] = "buffer_load_dword",
		[GFX10_BUFFER_LOAD_DWORDX2] = "buffer_load_dwordx2",
		[GFX10_BUFFER_LOAD_DWORDX4] = "buffer_load_dwordx4",
		[GFX10_BUFFER_LOAD_DWORDX3] = "buffer_load_dwordx3",
		[GFX10_BUFFER_STORE_BYTE] = "buffer_store_byte",
		[GFX10_BUFFER_STORE_BYTE_D16_HI] = "buffer_store_byte_d16_hi",
		[GFX10_BUFFER_STORE_SHORT] = "buffer_store_short",
		[GFX10_BUFFER_STORE_SHORT_D16_HI] = "buffer_store_short_d16_hi",
		[GFX10_BUFFER_STORE_DWORD] = "buffer_store_dword",
		[GFX10_BUFFER_STORE_DWORDX2] = "buffer_store_dwordx2",
		[GFX10_BUFFER_STORE_DWORDX4] = "buffer_store_dwordx4",
		[GFX10_BUFFER_STORE_DWORDX3] = "buffer_store_dwordx3",
		[GFX10_BUFFER_LOAD_UBYTE_D16] = "buffer_load_ubyte_d16",
		[GFX10_BUFFER_LOAD_UBYTE_D16_HI] = "buffer_load_ubyte_d16_hi",
		[GFX10_BUFFER_LOAD_SBYTE_D16] = "buffer_load_sbyte_d16",
		[GFX10_BUFFER_LOAD_SBYTE_D16_HI] = "buffer_load_sbyte_d16_hi",
		[GFX10_BUFFER_LOAD_SHORT_D16] = "buffer_load_short_d16",
		[GFX10_BUFFER_LOAD_SHORT_D16_HI] = "buffer_load_short_d16_hi",
		[GFX10_BUFFER_LOAD_FORMAT_D16_HI_X] = "buffer_load_format_d16_hi_x",
		[GFX10_BUFFER_STORE_FORMAT_D16_HI_X] = "buffer_store_format_d16_hi_x",
		[GFX10_BUFFER_ATOMIC_SWAP] = "buffer_atomic_swap",
		[GFX10_BUFFER_ATOMIC_CMPSWAP] = "buffer_atomic_cmpswap",
		[GFX10_BUFFER_ATOMIC_ADD] = "buffer_atomic_add",
		[GFX10_BUFFER_ATOMIC_SUB] = "buffer_atomic_sub",
		[GFX10_BUFFER_ATOMIC_CSUB] = "buffer_atomic_csub",
		[GFX10_BUFFER_ATOMIC_SMIN] = "buffer_atomic_smin",
		[GFX10_BUFFER_ATOMIC_UMIN] = "buffer_atomic_umin",
		[GFX10_BUFFER_ATOMIC_SMAX] = "buffer_atomic_smax",
		[GFX10_BUFFER_ATOMIC_UMAX] = "buffer_atomic_umax",
		[GFX10_BUFFER_ATOMIC_AND] = "buffer_atomic_and",
		[GFX10_BUFFER_ATOMIC_OR] = "buffer_atomic_or",
		[GFX10_BUFFER_ATOMIC_XOR] = "buffer_atomic_xor",
		[GFX10_BUFFER_ATOMIC_INC] = "buffer_atomic_inc",
		[GFX10_BUFFER_ATOMIC_DEC] = "buffer_atomic_dec",
		[GFX10_BUFFER_ATOMIC_FCMPSWAP] = "buffer_atomic_fcmpswap",
		[GFX10_BUFFER_ATOMIC_FMIN] = "buffer_atomic_fmin",
		[GFX10_BUFFER_ATOMIC_FMAX] = "buffer_atomic_fmax",
		[GFX10_BUFFER_ATOMIC_SWAP_X2] = "buffer_atomic_swap_x2",
		[GFX10_BUFFER_ATOMIC_CMPSWAP_X2] = "buffer_atomic_cmpswap_x2",
		[GFX10_BUFFER_ATOMIC_ADD_X2] = "buffer_atomic_add_x2",
		[GFX10_BUFFER_ATOMIC_SUB_X2] = "buffer_atomic_sub_x2",
		[GFX10_BUFFER_ATOMIC_SMIN_X2] = "buffer_atomic_smin_x2",
		[GFX10_BUFFER_ATOMIC_UMIN_X2] = "buffer_atomic_umin_x2",
		[GFX10_BUFFER_ATOMIC_SMAX_X2] = "buffer_atomic_smax_x2",
		[GFX10_BUFFER_ATOMIC_UMAX_X2] = "buffer_atomic_umax_x2",
		[GFX10_BUFFER_ATOMIC_AND_X2] = "buffer_atomic_and_x2",
		[GFX10_BUFFER_ATOMIC_OR_X2] = "buffer_atomic_or_x2",
		[GFX10_BUFFER_ATOMIC_XOR_X2] = "buffer_atomic_xor_x2",
		[GFX10_BUFFER_ATOMIC_INC_X2] = "buffer_atomic_inc_x2",
		[GFX10_BUFFER_ATOMIC_DEC_X2] = "buffer_atomic_dec_x2",
		[GFX10_BUFFER_ATOMIC_FCMPSWAP_X2] = "buffer_atomic_fcmpswap_x2",
		[GFX10_BUFFER_ATOMIC_FMIN_X2] = "buffer_atomic_fmin_x2",
		[GFX10_BUFFER_ATOMIC_FMAX_X2] = "buffer_atomic_fmax_x2",
		[GFX10_BUFFER_GL0_INV] = "buffer_gl0_inv",
		[GFX10_BUFFER_GL1_INV] = "buffer_gl1_inv",
		[GFX10_BUFFER_LOAD_FORMAT_D16_X] = "buffer_load_format_d16_x",
		[GFX10_BUFFER_LOAD_FORMAT_D16_XY] = "buffer_load_format_d16_xy",
		[GFX10_BUFFER_LOAD_FORMAT_D16_XYZ] = "buffer_load_format_d16_xyz",
		[GFX10_BUFFER_LOAD_FORMAT_D16_XYZW] = "buffer_load_format_d16_xyzw",
		[GFX10_BUFFER_STORE_FORMAT_D16_X] = "buffer_store_format_d16_x",
		[GFX10_BUFFER_STORE_FORMAT_D16_XY] = "buffer_store_format_d16_xy",
		[GFX10_BUFFER_STORE_FORMAT_D16_XYZ] = "buffer_store_format_d16_xyz",
		[GFX10_BUFFER_STORE_FORMAT_D16_XYZW] = "buffer_store_format_d16_xyzw",
	},
	[AMDGCN_INSN_TYPE_FLAT] = {
		[GFX10_GLOBAL_LOAD_UBYTE] = "global_load_ubyte",
		[GFX10_GLOBAL_LOAD_SBYTE] = "global_load_sbyte",
		[GFX10_GLOBAL_LOAD_USHORT] = "global_load_ushort",
		[GFX10_GLOBAL_LOAD_SSHORT] = "global_load_sshort",
		[GFX10_GLOBAL_LOAD_DWORD] = "global_load_dword",
		[GFX10_GLOBAL_LOAD_DWORDX2] = "global_load_dwordx2",
		[GFX10_GLOBAL_LOAD_DWORDX4] = "global_load_dwordx4",
		[GFX10_GLOBAL_LOAD_DWORDX3] = "global_load_dwordx3",
		[GFX10_GLOBAL_LOAD_DWORD_ADDTID] = "global_load_dword_addtid",
		[GFX10_GLOBAL_STORE_DWORD_ADDTID] = "global_store_dword_addtid",
		[GFX10_GLOBAL_STORE_BYTE] = "global_store_byte",
		[GFX10_GLOBAL_STORE_BYTE_D16_HI] = "global_store_byte_d16_hi",
		[GFX10_GLOBAL_STORE_SHORT] = "global_store_short",
		[GFX10_GLOBAL_STORE_SHORT_D16_HI] = "global_store_short_d16_hi",
		[GFX10_GLOBAL_STORE_DWORD] = "global_store_dword",
		[GFX10_GLOBAL_STORE_DWORDX2] = "global_store_dwordx2",
		[GFX10_GLOBAL_STORE_DWORDX4] = "global_store_dwordx4",
		[GFX10_GLOBAL_STORE_DWORDX3] = "global_store_dwordx3",
		[GFX10_GLOBAL_LOAD_UBYTE_D16] = "global_load_ubyte_d16",
		[GFX10_GLOBAL_LOAD_UBYTE_D16_HI] = "global_load_ubyte_d16_hi",
		[GFX10_GLOBAL_LOAD_SBYTE_D16] = "global_load_sbyte_d16",
		[GFX10_GLOBAL_LOAD_SBYTE_D16_HI] = "global_load_sbyte_d16_hi",
		[GFX10_GLOBAL_LOAD_SHORT_D16] = "global_load_short_d16",
		[GFX10_GLOBAL_LOAD_SHORT_D16_HI] = "global_load_short_d16_hi",
		[GFX10_GLOBAL_ATOMIC_SWAP] = "global_atomic_swap",
		[GFX10_GLOBAL_ATOMIC_CMPSWAP] = "global_atomic_cmpswap",
		[GFX10_GLOBAL_ATOMIC_ADD] = "global_atomic_add",
		[GFX10_GLOBAL_ATOMIC_SUB] = "global_atomic_sub",
		[GFX10_GLOBAL_ATOMIC_CSUB] = "global_atomic_csub",
		[GFX10_GLOBAL_ATOMIC_SMIN] = "global_atomic_smin",
		[GFX10_GLOBAL_ATOMIC_UMIN] = "global_atomic_umin",
		[GFX10_GLOBAL_ATOMIC_SMAX] = "global_atomic_smax",
		[GFX10_GLOBAL_ATOMIC_UMAX] = "global_atomic_umax",
		[GFX10_GLOBAL_ATOMIC_AND] = "global_atomic_and",
		[GFX10_GLOBAL_ATOMIC_OR] = "global_atomic_or",
		[GFX10_GLOBAL_ATOMIC_XOR] = "global_atomic_xor",
		[GFX10_GLOBAL_ATOMIC_INC] = "global_atomic_inc",
		[GFX10_GLOBAL_ATOMIC_DEC] = "global_atomic_dec",
		[GFX10_GLOBAL_ATOMIC_FCMPSWAP] = "global_atomic_fcmpswap",
		[GFX10_GLOBAL_ATOMIC_FMIN] = "global_atomic_fmin",
		[GFX10_GLOBAL_ATOMIC_FMAX] = "global_atomic_fmax",
		[GFX10_GLOBAL_ATOMIC_SWAP_X2] = "global_atomic_swap_x2",
		[GFX10_GLOBAL_ATOMIC_CMPSWAP_X2] = "global_atomic_cmpswap_x2",
		[GFX10_GLOBAL_ATOMIC_ADD_X2] = "global_atomic_add_x2",
		[GFX10_GLOBAL_ATOMIC_SUB_X2] = "global_atomic_sub_x2",
		[GFX10_GLOBAL_ATOMIC_SMIN_X2] = "global_atomic_smin_x2",
		[GFX10_GLOBAL_ATOMIC_UMIN_X2] = "global_atomic_umin_x2",
		[GFX10_GLOBAL_ATOMIC_SMAX_X2] = "global_atomic_smax_x2",
		[GFX10_GLOBAL_ATOMIC_UMAX_X2] = "global_atomic_umax_x2",
		[GFX10_GLOBAL_ATOMIC_AND_X2] = "global_atomic_and_x2",
		[GFX10_GLOBAL_ATOMIC_OR_X2] = "global_atomic_or_x2",
		[GFX10_GLOBAL_ATOMIC_XOR_X2] = "global_atomic_xor_x2",
		[GFX10_GLOBAL_ATOMIC_INC_X2] = "global_atomic_inc_x2",
		[GFX10_GLOBAL_ATOMIC_DEC_X2] = "global_atomic_dec_x2",
		[GFX10_GLOBAL_ATOMIC_FCMPSWAP_X2] = "global_atomic_fcmpswap_x2",
		[GFX10_GLOBAL_ATOMIC_FMIN_X2] = "global_atomic_fmin_x2",
		[GFX10_GLOBAL_ATOMIC_FMAX_X2] = "global_atomic_fmax_x2",
	},
};

static const char opnames_gfx9[__AMDGCN_INSN_TYPE_MAX][900][30] = {
	[AMDGCN_INSN_TYPE_SOP2] = {
		[GFX9_S_ADD_U32] = "s_add_u32",
		[GFX9_S_SUB_U32] = "s_sub_u32",
		[GFX9_S_ADD_I32] = "s_add_i32",
		[GFX9_S_SUB_I32] = "s_sub_i32",
		[GFX9_S_ADDC_U32] = "s_addc_u32",
		[GFX9_S_SUBB_U32] = "s_subb_u32",
		[GFX9_S_MIN_I32] = "s_min_i32",
		[GFX9_S_MIN_U32] = "s_min_u32",
		[GFX9_S_MAX_I32] = "s_max_i32",
		[GFX9_S_MAX_U32] = "s_max_u32",
		[GFX9_S_CSELECT_B32] = "s_cselect_b32",
		[GFX9_S_CSELECT_B64] = "s_cselect_b64",
		[GFX9_S_AND_B32] = "s_and_b32",
		[GFX9_S_AND_B64] = "s_and_b64",
		[GFX9_S_OR_B32] = "s_or_b32",
		[GFX9_S_OR_B64] = "s_or_b64",
		[GFX9_S_XOR_B32] = "s_xor_b32",
		[GFX9_S_XOR_B64] = "s_xor_b64",
		[GFX9_S_ANDN2_B32] = "s_andn2_b32",
		[GFX9_S_ANDN2_B64] = "s_andn2_b64",
		[GFX9_S_ORN2_B32] = "s_orn2_b32",
		[GFX9_S_ORN2_B64] = "s_orn2_b64",
		[GFX9_S_NAND_B32] = "s_nand_b32",
		[GFX9_S_NAND_B64] = "s_nand_b64",
		[GFX9_S_NOR_B32] = "s_nor_b32",
		[GFX9_S_NOR_B64] = "s_nor_b64",
		[GFX9_S_XNOR_B32] = "s_xnor_b32",
		[GFX9_S_XNOR_B64] = "s_xnor_b64",
		[GFX9_S_LSHL_B32] = "s_lshl_b32",
		[GFX9_S_LSHL_B64] = "s_lshl_b64",
		[GFX9_S_LSHR_B32] = "s_lshr_b32",
		[GFX9_S_LSHR_B64] = "s_lshr_b64",
		[GFX9_S_ASHR_I32] = "s_ashr_i32",
		[GFX9_S_ASHR_I64] = "s_ashr_i64",
		[GFX9_S_BFM_B32] = "s_bfm_b32",
		[GFX9_S_BFM_B64] = "s_bfm_b64",
		[GFX9_S_MUL_I32] = "s_mul_i32",
		[GFX9_S_BFE_U32] = "s_bfe_u32",
		[GFX9_S_BFE_I32] = "s_bfe_i32",
		[GFX9_S_BFE_U64] = "s_bfe_u64",
		[GFX9_S_BFE_I64] = "s_bfe_i64",
		[GFX9_S_CBRANCH_G_FORK] = "s_cbranch_g_fork",
		[GFX9_S_ABSDIFF_I32] = "s_absdiff_i32",
		[GFX9_S_RFE_RESTORE_B64] = "s_rfe_restore_b64",
		[GFX9_S_MUL_HI_U32] = "s_mul_hi_u32",
		[GFX9_S_MUL_HI_I32] = "s_mul_hi_i32",
		[GFX9_S_LSHL1_ADD_U32] = "s_lshl1_add_u32",
		[GFX9_S_LSHL2_ADD_U32] = "s_lshl2_add_u32",
		[GFX9_S_LSHL3_ADD_U32] = "s_lshl3_add_u32",
		[GFX9_S_LSHL4_ADD_U32] = "s_lshl4_add_u32",
		[GFX9_S_PACK_LL_B32_B16] = "s_pack_ll_b32_b16",
		[GFX9_S_PACK_LH_B32_B16] = "s_pack_lh_b32_b16",
		[GFX9_S_PACK_HH_B32_B16] = "s_pack_hh_b32_b16",
	},
	[AMDGCN_INSN_TYPE_SOPK] = {
		[GFX9_S_MOVK_I32] = "s_movk_i32",
		[GFX9_S_CMOVK_I32] = "s_cmovk_i32",
		[GFX9_S_CMPK_EQ_I32] = "s_cmpk_eq_i32",
		[GFX9_S_CMPK_LG_I32] = "s_cmpk_lg_i32",
		[GFX9_S_CMPK_GT_I32] = "s_cmpk_gt_i32",
		[GFX9_S_CMPK_GE_I32] = "s_cmpk_ge_i32",
		[GFX9_S_CMPK_LT_I32] = "s_cmpk_lt_i32",
		[GFX9_S_CMPK_LE_I32] = "s_cmpk_le_i32",
		[GFX9_S_CMPK_EQ_U32] = "s_cmpk_eq_u32",
		[GFX9_S_CMPK_LG_U32] = "s_cmpk_lg_u32",
		[GFX9_S_CMPK_GT_U32] = "s_cmpk_gt_u32",
		[GFX9_S_CMPK_GE_U32] = "s_cmpk_ge_u32",
		[GFX9_S_CMPK_LT_U32] = "s_cmpk_lt_u32",
		[GFX9_S_CMPK_LE_U32] = "s_cmpk_le_u32",
		[GFX9_S_ADDK_I32] = "s_addk_i32",
		[GFX9_S_MULK_I32] = "s_mulk_i32",
		[GFX9_S_CBRANCH_I_FORK] = "s_cbranch_i_fork",
		[GFX9_S_GETREG_B32] = "s_getreg_b32",
		[GFX9_S_SETREG_B32] = "s_setreg_b32",
		[GFX9_S_SETREG_IMM32_B32] = "s_setreg_imm32_b32",
		[GFX9_S_CALL_B64] = "s_call_b64",
	},
	[AMDGCN_INSN_TYPE_SOP1] = {
		[GFX9_S_MOV_B32] = "s_mov_b32",
		[GFX9_S_MOV_B64] = "s_mov_b64",
		[GFX9_S_CMOV_B32] = "s_cmov_b32",
		[GFX9_S_CMOV_B64] = "s_cmov_b64",
		[GFX9_S_NOT_B32] = "s_not_b32",
		[GFX9_S_NOT_B64] = "s_not_b64",
		[GFX9_S_WQM_B32] = "s_wqm_b32",
		[GFX9_S_WQM_B64] = "s_wqm_b64",
		[GFX9_S_BREV_B32] = "s_brev_b32",
		[GFX9_S_BREV_B64] = "s_brev_b64",
		[GFX9_S_BCNT0_I32_B32] = "s_bcnt0_i32_b32",
		[GFX9_S_BCNT0_I32_B64] = "s_bcnt0_i32_b64",
		[GFX9_S_BCNT1_I32_B32] = "s_bcnt1_i32_b32",
		[GFX9_S_BCNT1_I32_B64] = "s_bcnt1_i32_b64",
		[GFX9_S_FF0_I32_B32] = "s_ff0_i32_b32",
		[GFX9_S_FF0_I32_B64] = "s_ff0_i32_b64",
		[GFX9_S_FF1_I32_B32] = "s_ff1_i32_b32",
		[GFX9_S_FF1_I32_B64] = "s_ff1_i32_b64",
		[GFX9_S_FLBIT_I32_B32] = "s_flbit_i32_b32",
		[GFX9_S_FLBIT_I32_B64] = "s_flbit_i32_b64",
		[GFX9_S_FLBIT_I32] = "s_flbit_i32",
		[GFX9_S_FLBIT_I32_I64] = "s_flbit_i32_i64",
		[GFX9_S_SEXT_I32_I8] = "s_sext_i32_i8",
		[GFX9_S_SEXT_I32_I16] = "s_sext_i32_i16",
		[GFX9_S_BITSET0_B32] = "s_bitset0_b32",
		[GFX9_S_BITSET0_B64] = "s_bitset0_b64",
		[GFX9_S_BITSET1_B32] = "s_bitset1_b32",
		[GFX9_S_BITSET1_B64] = "s_bitset1_b64",
		[GFX9_S_GETPC_B64] = "s_getpc_b64",
		[GFX9_S_SETPC_B64] = "s_setpc_b64",
		[GFX9_S_SWAPPC_B64] = "s_swappc_b64",
		[GFX9_S_RFE_B64] = "s_rfe_b64",
		[GFX9_S_AND_SAVEEXEC_B64] = "s_and_saveexec_b64",
		[GFX9_S_XNOR_SAVEEXEC_B64] = "s_xnor_saveexec_b64",
		[GFX9_S_QUADMASK_B32] = "s_quadmask_b32",
		[GFX9_S_QUADMASK_B64] = "s_quadmask_b64",
		[GFX9_S_MOVRELS_B32] = "s_movrels_b32",
		[GFX9_S_MOVRELS_B64] = "s_movrels_b64",
		[GFX9_S_MOVRELD_B32] = "s_movreld_b32",
		[GFX9_S_MOVRELD_B64] = "s_movreld_b64",
		[GFX9_S_ABS_I32] = "s_abs_i32",
		[GFX9_S_ANDN1_SAVEEXEC_B64] = "s_andn1_saveexec_b64",
		[GFX9_S_ORN1_SAVEEXEC_B64] = "s_orn1_saveexec_b64",
		[GFX9_S_ANDN1_WREXEC_B64] = "s_andn1_wrexec_b64",
		[GFX9_S_ANDN2_WREXEC_B64] = "s_andn2_wrexec_b64",
		[GFX9_S_BITREPLICATE_B64_B32] = "s_bitreplicate_b64_b32",
		/* SOP1 opcodes missing from the table (Vega ISA 12.3). */
		[GFX9_S_OR_SAVEEXEC_B64] = "s_or_saveexec_b64",
		[GFX9_S_XOR_SAVEEXEC_B64] = "s_xor_saveexec_b64",
		[GFX9_S_ANDN2_SAVEEXEC_B64] = "s_andn2_saveexec_b64",
		[GFX9_S_ORN2_SAVEEXEC_B64] = "s_orn2_saveexec_b64",
		[GFX9_S_NAND_SAVEEXEC_B64] = "s_nand_saveexec_b64",
		[GFX9_S_NOR_SAVEEXEC_B64] = "s_nor_saveexec_b64",
		[GFX9_S_SET_GPR_IDX_IDX] = "s_set_gpr_idx_idx",
	},
	[AMDGCN_INSN_TYPE_SOPC] = {
		[GFX9_S_CMP_EQ_I32] = "s_cmp_eq_i32",
		[GFX9_S_CMP_LG_I32] = "s_cmp_lg_i32",
		[GFX9_S_CMP_GT_I32] = "s_cmp_gt_i32",
		[GFX9_S_CMP_GE_I32] = "s_cmp_ge_i32",
		[GFX9_S_CMP_LT_I32] = "s_cmp_lt_i32",
		[GFX9_S_CMP_LE_I32] = "s_cmp_le_i32",
		[GFX9_S_CMP_EQ_U32] = "s_cmp_eq_u32",
		[GFX9_S_CMP_LG_U32] = "s_cmp_lg_u32",
		[GFX9_S_CMP_GT_U32] = "s_cmp_gt_u32",
		[GFX9_S_CMP_GE_U32] = "s_cmp_ge_u32",
		[GFX9_S_CMP_LT_U32] = "s_cmp_lt_u32",
		[GFX9_S_CMP_LE_U32] = "s_cmp_le_u32",
		[GFX9_S_BITCMP0_B32] = "s_bitcmp0_b32",
		[GFX9_S_BITCMP1_B32] = "s_bitcmp1_b32",
		[GFX9_S_BITCMP0_B64] = "s_bitcmp0_b64",
		[GFX9_S_BITCMP1_B64] = "s_bitcmp1_b64",
		[GFX9_S_SETVSKIP] = "s_setvskip",
		[GFX9_S_SET_GPR_IDX_ON] = "s_set_gpr_idx_on",
		[GFX9_S_CMP_EQ_U64] = "s_cmp_eq_u64",
		[GFX9_S_CMP_LG_U64] = "s_cmp_lg_u64",
	},
	[AMDGCN_INSN_TYPE_SOPP] = {
		[GFX9_S_NOP] = "s_nop",
		[GFX9_S_ENDPGM] = "s_endpgm",
		[GFX9_S_BRANCH] = "s_branch",
		[GFX9_S_WAKEUP] = "s_wakeup",
		[GFX9_S_CBRANCH_SCC0] = "s_cbranch_scc0",
		[GFX9_S_CBRANCH_SCC1] = "s_cbranch_scc1",
		[GFX9_S_CBRANCH_VCCZ] = "s_cbranch_vccz",
		[GFX9_S_CBRANCH_VCCNZ] = "s_cbranch_vccnz",
		[GFX9_S_CBRANCH_EXECZ] = "s_cbranch_execz",
		[GFX9_S_CBRANCH_EXECNZ] = "s_cbranch_execnz",
		[GFX9_S_BARRIER] = "s_barrier",
		[GFX9_S_SETKILL] = "s_setkill",
		[GFX9_S_WAITCNT] = "s_waitcnt",
		[GFX9_S_SETHALT] = "s_sethalt",
		[GFX9_S_SLEEP] = "s_sleep",
		[GFX9_S_SETPRIO] = "s_setprio",
		[GFX9_S_SENDMSG] = "s_sendmsg",
		[GFX9_S_SENDMSGHALT] = "s_sendmsghalt",
		[GFX9_S_TRAP] = "s_trap",
		[GFX9_S_ICACHE_INV] = "s_icache_inv",
		[GFX9_S_INCPERFLEVEL] = "s_incperflevel",
		[GFX9_S_DECPERFLEVEL] = "s_decperflevel",
		[GFX9_S_TTRACEDATA] = "s_ttracedata",
		[GFX9_S_CBRANCH_CDBGSYS] = "s_cbranch_cdbgsys",
		[GFX9_S_CBRANCH_CDBGUSER] = "s_cbranch_cdbguser",
		[GFX9_S_CBRANCH_CDBGSYS_OR_USER] = "s_cbranch_cdbgsys_or_user",
		[GFX9_S_CBRANCH_CDBGSYS_AND_USER] = "s_cbranch_cdbgsys_and_user",
		[GFX9_S_ENDPGM_SAVED] = "s_endpgm_saved",
		[GFX9_S_SET_GPR_IDX_OFF] = "s_set_gpr_idx_off",
		[GFX9_S_SET_GPR_IDX_MODE] = "s_set_gpr_idx_mode",
		[GFX9_S_ENDPGM_ORDERED_PS_DONE] = "s_endpgm_ordered_ps_done",
	},
	[AMDGCN_INSN_TYPE_SMEM] = {
		[GFX9_S_LOAD_DWORD] = "s_load_dword",
		[GFX9_S_LOAD_DWORDX2] = "s_load_dwordx2",
		[GFX9_S_LOAD_DWORDX4] = "s_load_dwordx4",
		[GFX9_S_LOAD_DWORDX8] = "s_load_dwordx8",
		[GFX9_S_LOAD_DWORDX16] = "s_load_dwordx16",
		[GFX9_S_SCRATCH_LOAD_DWORD] = "s_scratch_load_dword",
		[GFX9_S_SCRATCH_LOAD_DWORDX2] = "s_scratch_load_dwordx2",
		[GFX9_S_SCRATCH_LOAD_DWORDX4] = "s_scratch_load_dwordx4",
		[GFX9_S_BUFFER_LOAD_DWORD] = "s_buffer_load_dword",
		[GFX9_S_BUFFER_LOAD_DWORDX2] = "s_buffer_load_dwordx2",
		[GFX9_S_BUFFER_LOAD_DWORDX4] = "s_buffer_load_dwordx4",
		[GFX9_S_BUFFER_LOAD_DWORDX8] = "s_buffer_load_dwordx8",
		[GFX9_S_BUFFER_LOAD_DWORDX16] = "s_buffer_load_dwordx16",
		[GFX9_S_STORE_DWORD] = "s_store_dword",
		[GFX9_S_STORE_DWORDX2] = "s_store_dwordx2",
		[GFX9_S_STORE_DWORDX4] = "s_store_dwordx4",
		[GFX9_S_SCRATCH_STORE_DWORD] = "s_scratch_store_dword",
		[GFX9_S_SCRATCH_STORE_DWORDX2] = "s_scratch_store_dwordx2",
		[GFX9_S_SCRATCH_STORE_DWORDX4] = "s_scratch_store_dwordx4",
		[GFX9_S_BUFFER_STORE_DWORD] = "s_buffer_store_dword",
		[GFX9_S_BUFFER_STORE_DWORDX2] = "s_buffer_store_dwordx2",
		[GFX9_S_BUFFER_STORE_DWORDX4] = "s_buffer_store_dwordx4",
		[GFX9_S_DCACHE_INV] = "s_dcache_inv",
		[GFX9_S_DCACHE_WB] = "s_dcache_wb",
		[GFX9_S_DCACHE_INV_VOL] = "s_dcache_inv_vol",
		[GFX9_S_DCACHE_WB_VOL] = "s_dcache_wb_vol",
		[GFX9_S_MEMTIME] = "s_memtime",
		[GFX9_S_MEMREALTIME] = "s_memrealtime",
		[GFX9_S_ATC_PROBE] = "s_atc_probe",
		[GFX9_S_ATC_PROBE_BUFFER] = "s_atc_probe_buffer",
		[GFX9_S_DCACHE_DISCARD] = "s_dcache_discard",
		[GFX9_S_DCACHE_DISCARD_X2] = "s_dcache_discard_x2",
		[GFX9_S_BUFFER_ATOMIC_SWAP] = "s_buffer_atomic_swap",
		[GFX9_S_BUFFER_ATOMIC_CMPSWAP] = "s_buffer_atomic_cmpswap",
		[GFX9_S_BUFFER_ATOMIC_ADD] = "s_buffer_atomic_add",
		[GFX9_S_BUFFER_ATOMIC_SUB] = "s_buffer_atomic_sub",
		[GFX9_S_BUFFER_ATOMIC_SMIN] = "s_buffer_atomic_smin",
		[GFX9_S_BUFFER_ATOMIC_UMIN] = "s_buffer_atomic_umin",
		[GFX9_S_BUFFER_ATOMIC_SMAX] = "s_buffer_atomic_smax",
		[GFX9_S_BUFFER_ATOMIC_UMAX] = "s_buffer_atomic_umax",
		[GFX9_S_BUFFER_ATOMIC_AND] = "s_buffer_atomic_and",
		[GFX9_S_BUFFER_ATOMIC_OR] = "s_buffer_atomic_or",
		[GFX9_S_BUFFER_ATOMIC_XOR] = "s_buffer_atomic_xor",
		[GFX9_S_BUFFER_ATOMIC_INC] = "s_buffer_atomic_inc",
		[GFX9_S_BUFFER_ATOMIC_DEC] = "s_buffer_atomic_dec",
		[GFX9_S_BUFFER_ATOMIC_SWAP_X2] = "s_buffer_atomic_swap_x2",
		[GFX9_S_BUFFER_ATOMIC_CMPSWAP_X2] = "s_buffer_atomic_cmpswap_x2",
		[GFX9_S_BUFFER_ATOMIC_ADD_X2] = "s_buffer_atomic_add_x2",
		[GFX9_S_BUFFER_ATOMIC_SUB_X2] = "s_buffer_atomic_sub_x2",
		[GFX9_S_BUFFER_ATOMIC_SMIN_X2] = "s_buffer_atomic_smin_x2",
		[GFX9_S_BUFFER_ATOMIC_UMIN_X2] = "s_buffer_atomic_umin_x2",
		[GFX9_S_BUFFER_ATOMIC_SMAX_X2] = "s_buffer_atomic_smax_x2",
		[GFX9_S_BUFFER_ATOMIC_UMAX_X2] = "s_buffer_atomic_umax_x2",
		[GFX9_S_BUFFER_ATOMIC_AND_X2] = "s_buffer_atomic_and_x2",
		[GFX9_S_BUFFER_ATOMIC_OR_X2] = "s_buffer_atomic_or_x2",
		[GFX9_S_BUFFER_ATOMIC_XOR_X2] = "s_buffer_atomic_xor_x2",
		[GFX9_S_BUFFER_ATOMIC_INC_X2] = "s_buffer_atomic_inc_x2",
		[GFX9_S_BUFFER_ATOMIC_DEC_X2] = "s_buffer_atomic_dec_x2",
		[GFX9_S_ATOMIC_SWAP] = "s_atomic_swap",
		[GFX9_S_ATOMIC_CMPSWAP] = "s_atomic_cmpswap",
		[GFX9_S_ATOMIC_ADD] = "s_atomic_add",
		[GFX9_S_ATOMIC_SUB] = "s_atomic_sub",
		[GFX9_S_ATOMIC_SMIN] = "s_atomic_smin",
		[GFX9_S_ATOMIC_UMIN] = "s_atomic_umin",
		[GFX9_S_ATOMIC_SMAX] = "s_atomic_smax",
		[GFX9_S_ATOMIC_UMAX] = "s_atomic_umax",
		[GFX9_S_ATOMIC_AND] = "s_atomic_and",
		[GFX9_S_ATOMIC_OR] = "s_atomic_or",
		[GFX9_S_ATOMIC_XOR] = "s_atomic_xor",
		[GFX9_S_ATOMIC_INC] = "s_atomic_inc",
		[GFX9_S_ATOMIC_DEC] = "s_atomic_dec",
		[GFX9_S_ATOMIC_SWAP_X2] = "s_atomic_swap_x2",
		[GFX9_S_ATOMIC_CMPSWAP_X2] = "s_atomic_cmpswap_x2",
		[GFX9_S_ATOMIC_ADD_X2] = "s_atomic_add_x2",
		[GFX9_S_ATOMIC_SUB_X2] = "s_atomic_sub_x2",
		[GFX9_S_ATOMIC_SMIN_X2] = "s_atomic_smin_x2",
		[GFX9_S_ATOMIC_UMIN_X2] = "s_atomic_umin_x2",
		[GFX9_S_ATOMIC_SMAX_X2] = "s_atomic_smax_x2",
		[GFX9_S_ATOMIC_UMAX_X2] = "s_atomic_umax_x2",
		[GFX9_S_ATOMIC_AND_X2] = "s_atomic_and_x2",
		[GFX9_S_ATOMIC_OR_X2] = "s_atomic_or_x2",
		[GFX9_S_ATOMIC_XOR_X2] = "s_atomic_xor_x2",
		[GFX9_S_ATOMIC_INC_X2] = "s_atomic_inc_x2",
		[GFX9_S_ATOMIC_DEC_X2] = "s_atomic_dec_x2",
	},
	[AMDGCN_INSN_TYPE_VOP2] = {
		[GFX9_V_CNDMASK_B32] = "v_cndmask_b32",
		[GFX9_V_ADD_F32] = "v_add_f32",
		[GFX9_V_SUB_F32] = "v_sub_f32",
		[GFX9_V_SUBREV_F32] = "v_subrev_f32",
		[GFX9_V_MUL_LEGACY_F32] = "v_mul_legacy_f32",
		[GFX9_V_MUL_F32] = "v_mul_f32",
		[GFX9_V_MUL_I32_I24] = "v_mul_i32_i24",
		[GFX9_V_MUL_HI_I32_I24] = "v_mul_hi_i32_i24",
		[GFX9_V_MUL_U32_U24] = "v_mul_u32_u24",
		[GFX9_V_MUL_HI_U32_U24] = "v_mul_hi_u32_u24",
		[GFX9_V_MIN_F32] = "v_min_f32",
		[GFX9_V_MAX_F32] = "v_max_f32",
		[GFX9_V_MIN_I32] = "v_min_i32",
		[GFX9_V_MAX_I32] = "v_max_i32",
		[GFX9_V_MIN_U32] = "v_min_u32",
		[GFX9_V_MAX_U32] = "v_max_u32",
		[GFX9_V_LSHRREV_B32] = "v_lshrrev_b32",
		[GFX9_V_ASHRREV_I32] = "v_ashrrev_i32",
		[GFX9_V_LSHLREV_B32] = "v_lshlrev_b32",
		[GFX9_V_AND_B32] = "v_and_b32",
		[GFX9_V_OR_B32] = "v_or_b32",
		[GFX9_V_XOR_B32] = "v_xor_b32",
		[GFX9_V_MAC_F32] = "v_mac_f32",
		[GFX9_V_MADMK_F32] = "v_madmk_f32",
		[GFX9_V_MADAK_F32] = "v_madak_f32",
		[GFX9_V_ADD_CO_U32] = "v_add_co_u32",
		[GFX9_V_SUB_CO_U32] = "v_sub_co_u32",
		[GFX9_V_SUBREV_CO_U32] = "v_subrev_co_u32",
		[GFX9_V_ADDC_CO_U32] = "v_addc_co_u32",
		[GFX9_V_SUBB_CO_U32] = "v_subb_co_u32",
		[GFX9_V_SUBBREV_CO_U32] = "v_subbrev_co_u32",
		[GFX9_V_ADD_F16] = "v_add_f16",
		[GFX9_V_SUB_F16] = "v_sub_f16",
		[GFX9_V_SUBREV_F16] = "v_subrev_f16",
		[GFX9_V_MUL_F16] = "v_mul_f16",
		[GFX9_V_MAC_F16] = "v_mac_f16",
		[GFX9_V_MADMK_F16] = "v_madmk_f16",
		[GFX9_V_MADAK_F16] = "v_madak_f16",
		[GFX9_V_ADD_U16] = "v_add_u16",
		[GFX9_V_SUB_U16] = "v_sub_u16",
		[GFX9_V_SUBREV_U16] = "v_subrev_u16",
		[GFX9_V_MUL_LO_U16] = "v_mul_lo_u16",
		[GFX9_V_LSHLREV_B16] = "v_lshlrev_b16",
		[GFX9_V_LSHRREV_B16] = "v_lshrrev_b16",
		[GFX9_V_ASHRREV_I16] = "v_ashrrev_i16",
		[GFX9_V_MAX_F16] = "v_max_f16",
		[GFX9_V_MIN_F16] = "v_min_f16",
		[GFX9_V_MAX_U16] = "v_max_u16",
		[GFX9_V_MAX_I16] = "v_max_i16",
		[GFX9_V_MIN_U16] = "v_min_u16",
		[GFX9_V_MIN_I16] = "v_min_i16",
		[GFX9_V_LDEXP_F16] = "v_ldexp_f16",
		[GFX9_V_ADD_U32] = "v_add_u32",
		[GFX9_V_SUB_U32] = "v_sub_u32",
		[GFX9_V_SUBREV_U32] = "v_subrev_u32",
	},
	[AMDGCN_INSN_TYPE_VOP1] = {
		[GFX9_V_NOP] = "v_nop",
		[GFX9_V_MOV_B32] = "v_mov_b32",
		[GFX9_V_READFIRSTLANE_B32] = "v_readfirstlane_b32",
		[GFX9_V_CVT_I32_F64] = "v_cvt_i32_f64",
		[GFX9_V_CVT_F64_I32] = "v_cvt_f64_i32",
		[GFX9_V_CVT_F32_I32] = "v_cvt_f32_i32",
		[GFX9_V_CVT_F32_U32] = "v_cvt_f32_u32",
		[GFX9_V_CVT_U32_F32] = "v_cvt_u32_f32",
		[GFX9_V_CVT_I32_F32] = "v_cvt_i32_f32",
		[GFX9_V_CVT_F16_F32] = "v_cvt_f16_f32",
		[GFX9_V_CVT_F32_F16] = "v_cvt_f32_f16",
		[GFX9_V_CVT_RPI_I32_F32] = "v_cvt_rpi_i32_f32",
		[GFX9_V_CVT_FLR_I32_F32] = "v_cvt_flr_i32_f32",
		[GFX9_V_CVT_OFF_F32_I4] = "v_cvt_off_f32_i4",
		[GFX9_V_CVT_F32_F64] = "v_cvt_f32_f64",
		[GFX9_V_CVT_F64_F32] = "v_cvt_f64_f32",
		[GFX9_V_CVT_F32_UBYTE0] = "v_cvt_f32_ubyte0",
		[GFX9_V_CVT_F32_UBYTE1] = "v_cvt_f32_ubyte1",
		[GFX9_V_CVT_F32_UBYTE2] = "v_cvt_f32_ubyte2",
		[GFX9_V_CVT_F32_UBYTE3] = "v_cvt_f32_ubyte3",
		[GFX9_V_CVT_U32_F64] = "v_cvt_u32_f64",
		[GFX9_V_CVT_F64_U32] = "v_cvt_f64_u32",
		[GFX9_V_TRUNC_F64] = "v_trunc_f64",
		[GFX9_V_CEIL_F64] = "v_ceil_f64",
		[GFX9_V_RNDNE_F64] = "v_rndne_f64",
		[GFX9_V_FLOOR_F64] = "v_floor_f64",
		[GFX9_V_FRACT_F32] = "v_fract_f32",
		[GFX9_V_TRUNC_F32] = "v_trunc_f32",
		[GFX9_V_CEIL_F32] = "v_ceil_f32",
		[GFX9_V_RNDNE_F32] = "v_rndne_f32",
		[GFX9_V_FLOOR_F32] = "v_floor_f32",
		[GFX9_V_EXP_F32] = "v_exp_f32",
		[GFX9_V_LOG_F32] = "v_log_f32",
		[GFX9_V_RCP_F32] = "v_rcp_f32",
		[GFX9_V_RCP_IFLAG_F32] = "v_rcp_iflag_f32",
		[GFX9_V_RSQ_F32] = "v_rsq_f32",
		[GFX9_V_RCP_F64] = "v_rcp_f64",
		[GFX9_V_RSQ_F64] = "v_rsq_f64",
		[GFX9_V_SQRT_F32] = "v_sqrt_f32",
		[GFX9_V_SQRT_F64] = "v_sqrt_f64",
		[GFX9_V_SIN_F32] = "v_sin_f32",
		[GFX9_V_COS_F32] = "v_cos_f32",
		[GFX9_V_NOT_B32] = "v_not_b32",
		[GFX9_V_BFREV_B32] = "v_bfrev_b32",
		[GFX9_V_FFBH_U32] = "v_ffbh_u32",
		[GFX9_V_FFBL_B32] = "v_ffbl_b32",
		[GFX9_V_FFBH_I32] = "v_ffbh_i32",
		[GFX9_V_FREXP_EXP_I32_F64] = "v_frexp_exp_i32_f64",
		[GFX9_V_FREXP_MANT_F64] = "v_frexp_mant_f64",
		[GFX9_V_FRACT_F64] = "v_fract_f64",
		[GFX9_V_FREXP_EXP_I32_F32] = "v_frexp_exp_i32_f32",
		[GFX9_V_FREXP_MANT_F32] = "v_frexp_mant_f32",
		[GFX9_V_CLREXCP] = "v_clrexcp",
		[GFX9_V_SCREEN_PARTITION_4SE_B32] = "v_screen_partition_4se_b32",
		[GFX9_V_CVT_F16_U16] = "v_cvt_f16_u16",
		[GFX9_V_CVT_F16_I16] = "v_cvt_f16_i16",
		[GFX9_V_CVT_U16_F16] = "v_cvt_u16_f16",
		[GFX9_V_CVT_I16_F16] = "v_cvt_i16_f16",
		[GFX9_V_RCP_F16] = "v_rcp_f16",
		[GFX9_V_SQRT_F16] = "v_sqrt_f16",
		[GFX9_V_RSQ_F16] = "v_rsq_f16",
		[GFX9_V_LOG_F16] = "v_log_f16",
		[GFX9_V_EXP_F16] = "v_exp_f16",
		[GFX9_V_FREXP_MANT_F16] = "v_frexp_mant_f16",
		[GFX9_V_FREXP_EXP_I16_F16] = "v_frexp_exp_i16_f16",
		[GFX9_V_FLOOR_F16] = "v_floor_f16",
		[GFX9_V_CEIL_F16] = "v_ceil_f16",
		[GFX9_V_TRUNC_F16] = "v_trunc_f16",
		[GFX9_V_RNDNE_F16] = "v_rndne_f16",
		[GFX9_V_FRACT_F16] = "v_fract_f16",
		[GFX9_V_SIN_F16] = "v_sin_f16",
		[GFX9_V_COS_F16] = "v_cos_f16",
		[GFX9_V_EXP_LEGACY_F32] = "v_exp_legacy_f32",
		[GFX9_V_LOG_LEGACY_F32] = "v_log_legacy_f32",
		[GFX9_V_CVT_NORM_I16_F16] = "v_cvt_norm_i16_f16",
		[GFX9_V_CVT_NORM_U16_F16] = "v_cvt_norm_u16_f16",
		[GFX9_V_SAT_PK_U8_I16] = "v_sat_pk_u8_i16",
		[GFX9_V_SWAP_B32] = "v_swap_b32",
	},
	[AMDGCN_INSN_TYPE_VOPC] = {
		[GFX9_V_CMP_CLASS_F32] = "v_cmp_class_f32",
		[GFX9_V_CMPX_CLASS_F32] = "v_cmpx_class_f32",
		[GFX9_V_CMP_CLASS_F64] = "v_cmp_class_f64",
		[GFX9_V_CMPX_CLASS_F64] = "v_cmpx_class_f64",
		[GFX9_V_CMP_CLASS_F16] = "v_cmp_class_f16",
		[GFX9_V_CMPX_CLASS_F16] = "v_cmpx_class_f16",
		[GFX9_V_CMP_F_F16] = "v_cmp_f_f16",
		[GFX9_V_CMP_LT_F16] = "v_cmp_lt_f16",
		[GFX9_V_CMP_EQ_F16] = "v_cmp_eq_f16",
		[GFX9_V_CMP_LE_F16] = "v_cmp_le_f16",
		[GFX9_V_CMP_GT_F16] = "v_cmp_gt_f16",
		[GFX9_V_CMP_LG_F16] = "v_cmp_lg_f16",
		[GFX9_V_CMP_GE_F16] = "v_cmp_ge_f16",
		[GFX9_V_CMP_O_F16] = "v_cmp_o_f16",
		[GFX9_V_CMP_U_F16] = "v_cmp_u_f16",
		[GFX9_V_CMP_NGE_F16] = "v_cmp_nge_f16",
		[GFX9_V_CMP_NLG_F16] = "v_cmp_nlg_f16",
		[GFX9_V_CMP_NGT_F16] = "v_cmp_ngt_f16",
		[GFX9_V_CMP_NLE_F16] = "v_cmp_nle_f16",
		[GFX9_V_CMP_NEQ_F16] = "v_cmp_neq_f16",
		[GFX9_V_CMP_NLT_F16] = "v_cmp_nlt_f16",
		[GFX9_V_CMP_TRU_F16] = "v_cmp_tru_f16",
		[GFX9_V_CMPX_F_F16] = "v_cmpx_f_f16",
		[GFX9_V_CMPX_LT_F16] = "v_cmpx_lt_f16",
		[GFX9_V_CMPX_EQ_F16] = "v_cmpx_eq_f16",
		[GFX9_V_CMPX_LE_F16] = "v_cmpx_le_f16",
		[GFX9_V_CMPX_GT_F16] = "v_cmpx_gt_f16",
		[GFX9_V_CMPX_LG_F16] = "v_cmpx_lg_f16",
		[GFX9_V_CMPX_GE_F16] = "v_cmpx_ge_f16",
		[GFX9_V_CMPX_O_F16] = "v_cmpx_o_f16",
		[GFX9_V_CMPX_U_F16] = "v_cmpx_u_f16",
		[GFX9_V_CMPX_NGE_F16] = "v_cmpx_nge_f16",
		[GFX9_V_CMPX_NLG_F16] = "v_cmpx_nlg_f16",
		[GFX9_V_CMPX_NGT_F16] = "v_cmpx_ngt_f16",
		[GFX9_V_CMPX_NLE_F16] = "v_cmpx_nle_f16",
		[GFX9_V_CMPX_NEQ_F16] = "v_cmpx_neq_f16",
		[GFX9_V_CMPX_NLT_F16] = "v_cmpx_nlt_f16",
		[GFX9_V_CMPX_TRU_F16] = "v_cmpx_tru_f16",
		[GFX9_V_CMP_F_F32] = "v_cmp_f_f32",
		[GFX9_V_CMP_LT_F32] = "v_cmp_lt_f32",
		[GFX9_V_CMP_EQ_F32] = "v_cmp_eq_f32",
		[GFX9_V_CMP_LE_F32] = "v_cmp_le_f32",
		[GFX9_V_CMP_GT_F32] = "v_cmp_gt_f32",
		[GFX9_V_CMP_LG_F32] = "v_cmp_lg_f32",
		[GFX9_V_CMP_GE_F32] = "v_cmp_ge_f32",
		[GFX9_V_CMP_O_F32] = "v_cmp_o_f32",
		[GFX9_V_CMP_U_F32] = "v_cmp_u_f32",
		[GFX9_V_CMP_NGE_F32] = "v_cmp_nge_f32",
		[GFX9_V_CMP_NLG_F32] = "v_cmp_nlg_f32",
		[GFX9_V_CMP_NGT_F32] = "v_cmp_ngt_f32",
		[GFX9_V_CMP_NLE_F32] = "v_cmp_nle_f32",
		[GFX9_V_CMP_NEQ_F32] = "v_cmp_neq_f32",
		[GFX9_V_CMP_NLT_F32] = "v_cmp_nlt_f32",
		[GFX9_V_CMP_TRU_F32] = "v_cmp_tru_f32",
		[GFX9_V_CMPX_F_F32] = "v_cmpx_f_f32",
		[GFX9_V_CMPX_LT_F32] = "v_cmpx_lt_f32",
		[GFX9_V_CMPX_EQ_F32] = "v_cmpx_eq_f32",
		[GFX9_V_CMPX_LE_F32] = "v_cmpx_le_f32",
		[GFX9_V_CMPX_GT_F32] = "v_cmpx_gt_f32",
		[GFX9_V_CMPX_LG_F32] = "v_cmpx_lg_f32",
		[GFX9_V_CMPX_GE_F32] = "v_cmpx_ge_f32",
		[GFX9_V_CMPX_O_F32] = "v_cmpx_o_f32",
		[GFX9_V_CMPX_U_F32] = "v_cmpx_u_f32",
		[GFX9_V_CMPX_NGE_F32] = "v_cmpx_nge_f32",
		[GFX9_V_CMPX_NLG_F32] = "v_cmpx_nlg_f32",
		[GFX9_V_CMPX_NGT_F32] = "v_cmpx_ngt_f32",
		[GFX9_V_CMPX_NLE_F32] = "v_cmpx_nle_f32",
		[GFX9_V_CMPX_NEQ_F32] = "v_cmpx_neq_f32",
		[GFX9_V_CMPX_NLT_F32] = "v_cmpx_nlt_f32",
		[GFX9_V_CMPX_TRU_F32] = "v_cmpx_tru_f32",
		[GFX9_V_CMP_F_F64] = "v_cmp_f_f64",
		[GFX9_V_CMP_LT_F64] = "v_cmp_lt_f64",
		[GFX9_V_CMP_EQ_F64] = "v_cmp_eq_f64",
		[GFX9_V_CMP_LE_F64] = "v_cmp_le_f64",
		[GFX9_V_CMP_GT_F64] = "v_cmp_gt_f64",
		[GFX9_V_CMP_LG_F64] = "v_cmp_lg_f64",
		[GFX9_V_CMP_GE_F64] = "v_cmp_ge_f64",
		[GFX9_V_CMP_O_F64] = "v_cmp_o_f64",
		[GFX9_V_CMP_U_F64] = "v_cmp_u_f64",
		[GFX9_V_CMP_NGE_F64] = "v_cmp_nge_f64",
		[GFX9_V_CMP_NLG_F64] = "v_cmp_nlg_f64",
		[GFX9_V_CMP_NGT_F64] = "v_cmp_ngt_f64",
		[GFX9_V_CMP_NLE_F64] = "v_cmp_nle_f64",
		[GFX9_V_CMP_NEQ_F64] = "v_cmp_neq_f64",
		[GFX9_V_CMP_NLT_F64] = "v_cmp_nlt_f64",
		[GFX9_V_CMP_TRU_F64] = "v_cmp_tru_f64",
		[GFX9_V_CMPX_F_F64] = "v_cmpx_f_f64",
		[GFX9_V_CMPX_LT_F64] = "v_cmpx_lt_f64",
		[GFX9_V_CMPX_EQ_F64] = "v_cmpx_eq_f64",
		[GFX9_V_CMPX_LE_F64] = "v_cmpx_le_f64",
		[GFX9_V_CMPX_GT_F64] = "v_cmpx_gt_f64",
		[GFX9_V_CMPX_LG_F64] = "v_cmpx_lg_f64",
		[GFX9_V_CMPX_GE_F64] = "v_cmpx_ge_f64",
		[GFX9_V_CMPX_O_F64] = "v_cmpx_o_f64",
		[GFX9_V_CMPX_U_F64] = "v_cmpx_u_f64",
		[GFX9_V_CMPX_NGE_F64] = "v_cmpx_nge_f64",
		[GFX9_V_CMPX_NLG_F64] = "v_cmpx_nlg_f64",
		[GFX9_V_CMPX_NGT_F64] = "v_cmpx_ngt_f64",
		[GFX9_V_CMPX_NLE_F64] = "v_cmpx_nle_f64",
		[GFX9_V_CMPX_NEQ_F64] = "v_cmpx_neq_f64",
		[GFX9_V_CMPX_NLT_F64] = "v_cmpx_nlt_f64",
		[GFX9_V_CMPX_TRU_F64] = "v_cmpx_tru_f64",
		[GFX9_V_CMP_F_I16] = "v_cmp_f_i16",
		[GFX9_V_CMP_LT_I16] = "v_cmp_lt_i16",
		[GFX9_V_CMP_EQ_I16] = "v_cmp_eq_i16",
		[GFX9_V_CMP_LE_I16] = "v_cmp_le_i16",
		[GFX9_V_CMP_GT_I16] = "v_cmp_gt_i16",
		[GFX9_V_CMP_NE_I16] = "v_cmp_ne_i16",
		[GFX9_V_CMP_GE_I16] = "v_cmp_ge_i16",
		[GFX9_V_CMP_T_I16] = "v_cmp_t_i16",
		[GFX9_V_CMP_F_U16] = "v_cmp_f_u16",
		[GFX9_V_CMP_LT_U16] = "v_cmp_lt_u16",
		[GFX9_V_CMP_EQ_U16] = "v_cmp_eq_u16",
		[GFX9_V_CMP_LE_U16] = "v_cmp_le_u16",
		[GFX9_V_CMP_GT_U16] = "v_cmp_gt_u16",
		[GFX9_V_CMP_NE_U16] = "v_cmp_ne_u16",
		[GFX9_V_CMP_GE_U16] = "v_cmp_ge_u16",
		[GFX9_V_CMP_T_U16] = "v_cmp_t_u16",
		[GFX9_V_CMPX_F_I16] = "v_cmpx_f_i16",
		[GFX9_V_CMPX_LT_I16] = "v_cmpx_lt_i16",
		[GFX9_V_CMPX_EQ_I16] = "v_cmpx_eq_i16",
		[GFX9_V_CMPX_LE_I16] = "v_cmpx_le_i16",
		[GFX9_V_CMPX_GT_I16] = "v_cmpx_gt_i16",
		[GFX9_V_CMPX_NE_I16] = "v_cmpx_ne_i16",
		[GFX9_V_CMPX_GE_I16] = "v_cmpx_ge_i16",
		[GFX9_V_CMPX_T_I16] = "v_cmpx_t_i16",
		[GFX9_V_CMPX_F_U16] = "v_cmpx_f_u16",
		[GFX9_V_CMPX_LT_U16] = "v_cmpx_lt_u16",
		[GFX9_V_CMPX_EQ_U16] = "v_cmpx_eq_u16",
		[GFX9_V_CMPX_LE_U16] = "v_cmpx_le_u16",
		[GFX9_V_CMPX_GT_U16] = "v_cmpx_gt_u16",
		[GFX9_V_CMPX_NE_U16] = "v_cmpx_ne_u16",
		[GFX9_V_CMPX_GE_U16] = "v_cmpx_ge_u16",
		[GFX9_V_CMPX_T_U16] = "v_cmpx_t_u16",
		[GFX9_V_CMP_F_I32] = "v_cmp_f_i32",
		[GFX9_V_CMP_LT_I32] = "v_cmp_lt_i32",
		[GFX9_V_CMP_EQ_I32] = "v_cmp_eq_i32",
		[GFX9_V_CMP_LE_I32] = "v_cmp_le_i32",
		[GFX9_V_CMP_GT_I32] = "v_cmp_gt_i32",
		[GFX9_V_CMP_NE_I32] = "v_cmp_ne_i32",
		[GFX9_V_CMP_GE_I32] = "v_cmp_ge_i32",
		[GFX9_V_CMP_T_I32] = "v_cmp_t_i32",
		[GFX9_V_CMP_F_U32] = "v_cmp_f_u32",
		[GFX9_V_CMP_LT_U32] = "v_cmp_lt_u32",
		[GFX9_V_CMP_EQ_U32] = "v_cmp_eq_u32",
		[GFX9_V_CMP_LE_U32] = "v_cmp_le_u32",
		[GFX9_V_CMP_GT_U32] = "v_cmp_gt_u32",
		[GFX9_V_CMP_NE_U32] = "v_cmp_ne_u32",
		[GFX9_V_CMP_GE_U32] = "v_cmp_ge_u32",
		[GFX9_V_CMP_T_U32] = "v_cmp_t_u32",
		[GFX9_V_CMPX_F_I32] = "v_cmpx_f_i32",
		[GFX9_V_CMPX_LT_I32] = "v_cmpx_lt_i32",
		[GFX9_V_CMPX_EQ_I32] = "v_cmpx_eq_i32",
		[GFX9_V_CMPX_LE_I32] = "v_cmpx_le_i32",
		[GFX9_V_CMPX_GT_I32] = "v_cmpx_gt_i32",
		[GFX9_V_CMPX_NE_I32] = "v_cmpx_ne_i32",
		[GFX9_V_CMPX_GE_I32] = "v_cmpx_ge_i32",
		[GFX9_V_CMPX_T_I32] = "v_cmpx_t_i32",
		[GFX9_V_CMPX_F_U32] = "v_cmpx_f_u32",
		[GFX9_V_CMPX_LT_U32] = "v_cmpx_lt_u32",
		[GFX9_V_CMPX_EQ_U32] = "v_cmpx_eq_u32",
		[GFX9_V_CMPX_LE_U32] = "v_cmpx_le_u32",
		[GFX9_V_CMPX_GT_U32] = "v_cmpx_gt_u32",
		[GFX9_V_CMPX_NE_U32] = "v_cmpx_ne_u32",
		[GFX9_V_CMPX_GE_U32] = "v_cmpx_ge_u32",
		[GFX9_V_CMPX_T_U32] = "v_cmpx_t_u32",
		[GFX9_V_CMP_F_I64] = "v_cmp_f_i64",
		[GFX9_V_CMP_LT_I64] = "v_cmp_lt_i64",
		[GFX9_V_CMP_EQ_I64] = "v_cmp_eq_i64",
		[GFX9_V_CMP_LE_I64] = "v_cmp_le_i64",
		[GFX9_V_CMP_GT_I64] = "v_cmp_gt_i64",
		[GFX9_V_CMP_NE_I64] = "v_cmp_ne_i64",
		[GFX9_V_CMP_GE_I64] = "v_cmp_ge_i64",
		[GFX9_V_CMP_T_I64] = "v_cmp_t_i64",
		[GFX9_V_CMP_F_U64] = "v_cmp_f_u64",
		[GFX9_V_CMP_LT_U64] = "v_cmp_lt_u64",
		[GFX9_V_CMP_EQ_U64] = "v_cmp_eq_u64",
		[GFX9_V_CMP_LE_U64] = "v_cmp_le_u64",
		[GFX9_V_CMP_GT_U64] = "v_cmp_gt_u64",
		[GFX9_V_CMP_NE_U64] = "v_cmp_ne_u64",
		[GFX9_V_CMP_GE_U64] = "v_cmp_ge_u64",
		[GFX9_V_CMP_T_U64] = "v_cmp_t_u64",
		[GFX9_V_CMPX_F_I64] = "v_cmpx_f_i64",
		[GFX9_V_CMPX_LT_I64] = "v_cmpx_lt_i64",
		[GFX9_V_CMPX_EQ_I64] = "v_cmpx_eq_i64",
		[GFX9_V_CMPX_LE_I64] = "v_cmpx_le_i64",
		[GFX9_V_CMPX_GT_I64] = "v_cmpx_gt_i64",
		[GFX9_V_CMPX_NE_I64] = "v_cmpx_ne_i64",
		[GFX9_V_CMPX_GE_I64] = "v_cmpx_ge_i64",
		[GFX9_V_CMPX_T_I64] = "v_cmpx_t_i64",
		[GFX9_V_CMPX_F_U64] = "v_cmpx_f_u64",
		[GFX9_V_CMPX_LT_U64] = "v_cmpx_lt_u64",
		[GFX9_V_CMPX_EQ_U64] = "v_cmpx_eq_u64",
		[GFX9_V_CMPX_LE_U64] = "v_cmpx_le_u64",
		[GFX9_V_CMPX_GT_U64] = "v_cmpx_gt_u64",
		[GFX9_V_CMPX_NE_U64] = "v_cmpx_ne_u64",
		[GFX9_V_CMPX_GE_U64] = "v_cmpx_ge_u64",
		[GFX9_V_CMPX_T_U64] = "v_cmpx_t_u64",
	},
	[AMDGCN_INSN_TYPE_VOP3A] = {
		[GFX9_V_MAD_LEGACY_F32] = "v_mad_legacy_f32",
		[GFX9_V_MAD_F32] = "v_mad_f32",
		[GFX9_V_MAD_I32_I24] = "v_mad_i32_i24",
		[GFX9_V_MAD_U32_U24] = "v_mad_u32_u24",
		[GFX9_V_CUBEID_F32] = "v_cubeid_f32",
		[GFX9_V_CUBESC_F32] = "v_cubesc_f32",
		[GFX9_V_CUBETC_F32] = "v_cubetc_f32",
		[GFX9_V_CUBEMA_F32] = "v_cubema_f32",
		[GFX9_V_BFE_U32] = "v_bfe_u32",
		[GFX9_V_BFE_I32] = "v_bfe_i32",
		[GFX9_V_BFI_B32] = "v_bfi_b32",
		[GFX9_V_FMA_F32] = "v_fma_f32",
		[GFX9_V_FMA_F64] = "v_fma_f64",
		[GFX9_V_LERP_U8] = "v_lerp_u8",
		[GFX9_V_ALIGNBIT_B32] = "v_alignbit_b32",
		[GFX9_V_ALIGNBYTE_B32] = "v_alignbyte_b32",
		[GFX9_V_MIN3_F32] = "v_min3_f32",
		[GFX9_V_MIN3_I32] = "v_min3_i32",
		[GFX9_V_MIN3_U32] = "v_min3_u32",
		[GFX9_V_MAX3_F32] = "v_max3_f32",
		[GFX9_V_MAX3_I32] = "v_max3_i32",
		[GFX9_V_MAX3_U32] = "v_max3_u32",
		[GFX9_V_MED3_F32] = "v_med3_f32",
		[GFX9_V_MED3_I32] = "v_med3_i32",
		[GFX9_V_MED3_U32] = "v_med3_u32",
		[GFX9_V_SAD_U8] = "v_sad_u8",
		[GFX9_V_SAD_HI_U8] = "v_sad_hi_u8",
		[GFX9_V_SAD_U16] = "v_sad_u16",
		[GFX9_V_SAD_U32] = "v_sad_u32",
		[GFX9_V_CVT_PK_U8_F32] = "v_cvt_pk_u8_f32",
		[GFX9_V_DIV_FIXUP_F32] = "v_div_fixup_f32",
		[GFX9_V_DIV_FIXUP_F64] = "v_div_fixup_f64",
		[GFX9_V_DIV_FMAS_F32] = "v_div_fmas_f32",
		[GFX9_V_DIV_FMAS_F64] = "v_div_fmas_f64",
		[GFX9_V_MSAD_U8] = "v_msad_u8",
		[GFX9_V_QSAD_PK_U16_U8] = "v_qsad_pk_u16_u8",
		[GFX9_V_MQSAD_PK_U16_U8] = "v_mqsad_pk_u16_u8",
		[GFX9_V_MQSAD_U32_U8] = "v_mqsad_u32_u8",
		[GFX9_V_MAD_LEGACY_F16] = "v_mad_legacy_f16",
		[GFX9_V_MAD_LEGACY_U16] = "v_mad_legacy_u16",
		[GFX9_V_MAD_LEGACY_I16] = "v_mad_legacy_i16",
		[GFX9_V_PERM_B32] = "v_perm_b32",
		[GFX9_V_FMA_LEGACY_F16] = "v_fma_legacy_f16",
		[GFX9_V_DIV_FIXUP_LEGACY_F16] = "v_div_fixup_legacy_f16",
		[GFX9_V_CVT_PKACCUM_U8_F32] = "v_cvt_pkaccum_u8_f32",
		[GFX9_V_MAD_U32_U16] = "v_mad_u32_u16",
		[GFX9_V_MAD_I32_I16] = "v_mad_i32_i16",
		[GFX9_V_XAD_U32] = "v_xad_u32",
		[GFX9_V_MIN3_F16] = "v_min3_f16",
		[GFX9_V_MIN3_I16] = "v_min3_i16",
		[GFX9_V_MIN3_U16] = "v_min3_u16",
		[GFX9_V_MAX3_F16] = "v_max3_f16",
		[GFX9_V_MAX3_I16] = "v_max3_i16",
		[GFX9_V_MAX3_U16] = "v_max3_u16",
		[GFX9_V_MED3_F16] = "v_med3_f16",
		[GFX9_V_MED3_I16] = "v_med3_i16",
		[GFX9_V_MED3_U16] = "v_med3_u16",
		[GFX9_V_LSHL_ADD_U32] = "v_lshl_add_u32",
		[GFX9_V_ADD_LSHL_U32] = "v_add_lshl_u32",
		[GFX9_V_ADD3_U32] = "v_add3_u32",
		[GFX9_V_LSHL_OR_B32] = "v_lshl_or_b32",
		[GFX9_V_AND_OR_B32] = "v_and_or_b32",
		[GFX9_V_OR3_B32] = "v_or3_b32",
		[GFX9_V_MAD_F16] = "v_mad_f16",
		[GFX9_V_MAD_U16] = "v_mad_u16",
		[GFX9_V_MAD_I16] = "v_mad_i16",
		[GFX9_V_FMA_F16] = "v_fma_f16",
		[GFX9_V_DIV_FIXUP_F16] = "v_div_fixup_f16",
		[GFX9_V_INTERP_P1LL_F16] = "v_interp_p1ll_f16",
		[GFX9_V_INTERP_P1LV_F16] = "v_interp_p1lv_f16",
		[GFX9_V_INTERP_P2_LEGACY_F16] = "v_interp_p2_legacy_f16",
		[GFX9_V_INTERP_P2_F16] = "v_interp_p2_f16",
		[GFX9_V_ADD_F64] = "v_add_f64",
		[GFX9_V_MUL_F64] = "v_mul_f64",
		[GFX9_V_MIN_F64] = "v_min_f64",
		[GFX9_V_MAX_F64] = "v_max_f64",
		[GFX9_V_LDEXP_F64] = "v_ldexp_f64",
		[GFX9_V_MUL_LO_U32] = "v_mul_lo_u32",
		[GFX9_V_MUL_HI_U32] = "v_mul_hi_u32",
		[GFX9_V_MUL_HI_I32] = "v_mul_hi_i32",
		[GFX9_V_LDEXP_F32] = "v_ldexp_f32",
		[GFX9_V_READLANE_B32] = "v_readlane_b32",
		[GFX9_V_WRITELANE_B32] = "v_writelane_b32",
		[GFX9_V_BCNT_U32_B32] = "v_bcnt_u32_b32",
		[GFX9_V_MBCNT_LO_U32_B32] = "v_mbcnt_lo_u32_b32",
		[GFX9_V_MBCNT_HI_U32_B32] = "v_mbcnt_hi_u32_b32",
		[GFX9_V_LSHLREV_B64] = "v_lshlrev_b64",
		[GFX9_V_LSHRREV_B64] = "v_lshrrev_b64",
		[GFX9_V_ASHRREV_I64] = "v_ashrrev_i64",
		[GFX9_V_TRIG_PREOP_F64] = "v_trig_preop_f64",
		[GFX9_V_BFM_B32] = "v_bfm_b32",
		[GFX9_V_CVT_PKNORM_I16_F32] = "v_cvt_pknorm_i16_f32",
		[GFX9_V_CVT_PKNORM_U16_F32] = "v_cvt_pknorm_u16_f32",
		[GFX9_V_CVT_PKRTZ_F16_F32] = "v_cvt_pkrtz_f16_f32",
		[GFX9_V_CVT_PK_U16_U32] = "v_cvt_pk_u16_u32",
		[GFX9_V_CVT_PK_I16_I32] = "v_cvt_pk_i16_i32",
		[GFX9_V_CVT_PKNORM_I16_F16] = "v_cvt_pknorm_i16_f16",
		[GFX9_V_CVT_PKNORM_U16_F16] = "v_cvt_pknorm_u16_f16",
		[GFX9_V_ADD_I32] = "v_add_i32",
		[GFX9_V_SUB_I32] = "v_sub_i32",
		[GFX9_V_ADD_I16] = "v_add_i16",
		[GFX9_V_SUB_I16] = "v_sub_i16",
		[GFX9_V_PACK_B32_F16] = "v_pack_b32_f16",
	},
	[AMDGCN_INSN_TYPE_VOP3B] = {
		[GFX9_V_DIV_SCALE_F64] = "v_div_scale_f64",
		[GFX9_V_MAD_U64_U32] = "v_mad_u64_u32",
		[GFX9_V_MAD_I64_I32] = "v_mad_i64_i32",
	},
	[AMDGCN_INSN_TYPE_VOP3P] = {
		[GFX9_V_PK_MAD_I16] = "v_pk_mad_i16",
		[GFX9_V_PK_MUL_LO_U16] = "v_pk_mul_lo_u16",
		[GFX9_V_PK_ADD_I16] = "v_pk_add_i16",
		[GFX9_V_PK_SUB_I16] = "v_pk_sub_i16",
		[GFX9_V_PK_LSHLREV_B16] = "v_pk_lshlrev_b16",
		[GFX9_V_PK_LSHRREV_B16] = "v_pk_lshrrev_b16",
		[GFX9_V_PK_ASHRREV_I16] = "v_pk_ashrrev_i16",
		[GFX9_V_PK_MAX_I16] = "v_pk_max_i16",
		[GFX9_V_PK_MIN_I16] = "v_pk_min_i16",
		[GFX9_V_PK_MAD_U16] = "v_pk_mad_u16",
		[GFX9_V_PK_ADD_U16] = "v_pk_add_u16",
		[GFX9_V_PK_SUB_U16] = "v_pk_sub_u16",
		[GFX9_V_PK_MAX_U16] = "v_pk_max_u16",
		[GFX9_V_PK_MIN_U16] = "v_pk_min_u16",
		[GFX9_V_PK_FMA_F16] = "v_pk_fma_f16",
		[GFX9_V_PK_ADD_F16] = "v_pk_add_f16",
		[GFX9_V_PK_MUL_F16] = "v_pk_mul_f16",
		[GFX9_V_PK_MIN_F16] = "v_pk_min_f16",
		[GFX9_V_PK_MAX_F16] = "v_pk_max_f16",
		[GFX9_V_MAD_MIX_F32] = "v_mad_mix_f32",
		[GFX9_V_MAD_MIXLO_F16] = "v_mad_mixlo_f16",
		[GFX9_V_MAD_MIXHI_F16] = "v_mad_mixhi_f16",
	},
	[AMDGCN_INSN_TYPE_MUBUF] = {
		[GFX9_BUFFER_LOAD_FORMAT_X] = "buffer_load_format_x",
		[GFX9_BUFFER_LOAD_FORMAT_XY] = "buffer_load_format_xy",
		[GFX9_BUFFER_LOAD_FORMAT_XYZ] = "buffer_load_format_xyz",
		[GFX9_BUFFER_LOAD_FORMAT_XYZW] = "buffer_load_format_xyzw",
		[GFX9_BUFFER_STORE_FORMAT_X] = "buffer_store_format_x",
		[GFX9_BUFFER_STORE_FORMAT_XY] = "buffer_store_format_xy",
		[GFX9_BUFFER_STORE_FORMAT_XYZ] = "buffer_store_format_xyz",
		[GFX9_BUFFER_STORE_FORMAT_XYZW] = "buffer_store_format_xyzw",
		[GFX9_BUFFER_LOAD_FORMAT_D16_X] = "buffer_load_format_d16_x",
		[GFX9_BUFFER_LOAD_FORMAT_D16_XY] = "buffer_load_format_d16_xy",
		[GFX9_BUFFER_LOAD_FORMAT_D16_XYZ] = "buffer_load_format_d16_xyz",
		[GFX9_BUFFER_LOAD_FORMAT_D16_XYZW] = "buffer_load_format_d16_xyzw",
		[GFX9_BUFFER_STORE_FORMAT_D16_X] = "buffer_store_format_d16_x",
		[GFX9_BUFFER_STORE_FORMAT_D16_XY] = "buffer_store_format_d16_xy",
		[GFX9_BUFFER_STORE_FORMAT_D16_XYZ] = "buffer_store_format_d16_xyz",
		[GFX9_BUFFER_STORE_FORMAT_D16_XYZW] = "buffer_store_format_d16_xyzw",
		[GFX9_BUFFER_LOAD_UBYTE] = "buffer_load_ubyte",
		[GFX9_BUFFER_LOAD_SBYTE] = "buffer_load_sbyte",
		[GFX9_BUFFER_LOAD_USHORT] = "buffer_load_ushort",
		[GFX9_BUFFER_LOAD_SSHORT] = "buffer_load_sshort",
		[GFX9_BUFFER_LOAD_DWORD] = "buffer_load_dword",
		[GFX9_BUFFER_LOAD_DWORDX2] = "buffer_load_dwordx2",
		[GFX9_BUFFER_LOAD_DWORDX3] = "buffer_load_dwordx3",
		[GFX9_BUFFER_LOAD_DWORDX4] = "buffer_load_dwordx4",
		[GFX9_BUFFER_STORE_BYTE] = "buffer_store_byte",
		[GFX9_BUFFER_STORE_BYTE_D16_HI] = "buffer_store_byte_d16_hi",
		[GFX9_BUFFER_STORE_SHORT] = "buffer_store_short",
		[GFX9_BUFFER_STORE_SHORT_D16_HI] = "buffer_store_short_d16_hi",
		[GFX9_BUFFER_STORE_DWORD] = "buffer_store_dword",
		[GFX9_BUFFER_STORE_DWORDX2] = "buffer_store_dwordx2",
		[GFX9_BUFFER_STORE_DWORDX3] = "buffer_store_dwordx3",
		[GFX9_BUFFER_STORE_DWORDX4] = "buffer_store_dwordx4",
		[GFX9_BUFFER_LOAD_UBYTE_D16] = "buffer_load_ubyte_d16",
		[GFX9_BUFFER_LOAD_UBYTE_D16_HI] = "buffer_load_ubyte_d16_hi",
		[GFX9_BUFFER_LOAD_SBYTE_D16] = "buffer_load_sbyte_d16",
		[GFX9_BUFFER_LOAD_SBYTE_D16_HI] = "buffer_load_sbyte_d16_hi",
		[GFX9_BUFFER_LOAD_SHORT_D16] = "buffer_load_short_d16",
		[GFX9_BUFFER_LOAD_SHORT_D16_HI] = "buffer_load_short_d16_hi",
		[GFX9_BUFFER_LOAD_FORMAT_D16_HI_X] = "buffer_load_format_d16_hi_x",
		[GFX9_BUFFER_STORE_FORMAT_D16_HI_X] = "buffer_store_format_d16_hi_x",
		[GFX9_BUFFER_STORE_LDS_DWORD] = "buffer_store_lds_dword",
		[GFX9_BUFFER_WBINVL1] = "buffer_wbinvl1",
		[GFX9_BUFFER_WBINVL1_VOL] = "buffer_wbinvl1_vol",
		[GFX9_BUFFER_ATOMIC_SWAP] = "buffer_atomic_swap",
		[GFX9_BUFFER_ATOMIC_CMPSWAP] = "buffer_atomic_cmpswap",
		[GFX9_BUFFER_ATOMIC_ADD] = "buffer_atomic_add",
		[GFX9_BUFFER_ATOMIC_SUB] = "buffer_atomic_sub",
		[GFX9_BUFFER_ATOMIC_SMIN] = "buffer_atomic_smin",
		[GFX9_BUFFER_ATOMIC_UMIN] = "buffer_atomic_umin",
		[GFX9_BUFFER_ATOMIC_SMAX] = "buffer_atomic_smax",
		[GFX9_BUFFER_ATOMIC_UMAX] = "buffer_atomic_umax",
		[GFX9_BUFFER_ATOMIC_AND] = "buffer_atomic_and",
		[GFX9_BUFFER_ATOMIC_OR] = "buffer_atomic_or",
		[GFX9_BUFFER_ATOMIC_XOR] = "buffer_atomic_xor",
		[GFX9_BUFFER_ATOMIC_INC] = "buffer_atomic_inc",
		[GFX9_BUFFER_ATOMIC_DEC] = "buffer_atomic_dec",
		[GFX9_BUFFER_ATOMIC_SWAP_X2] = "buffer_atomic_swap_x2",
		[GFX9_BUFFER_ATOMIC_CMPSWAP_X2] = "buffer_atomic_cmpswap_x2",
		[GFX9_BUFFER_ATOMIC_ADD_X2] = "buffer_atomic_add_x2",
		[GFX9_BUFFER_ATOMIC_SUB_X2] = "buffer_atomic_sub_x2",
		[GFX9_BUFFER_ATOMIC_SMIN_X2] = "buffer_atomic_smin_x2",
		[GFX9_BUFFER_ATOMIC_UMIN_X2] = "buffer_atomic_umin_x2",
		[GFX9_BUFFER_ATOMIC_SMAX_X2] = "buffer_atomic_smax_x2",
		[GFX9_BUFFER_ATOMIC_UMAX_X2] = "buffer_atomic_umax_x2",
		[GFX9_BUFFER_ATOMIC_AND_X2] = "buffer_atomic_and_x2",
		[GFX9_BUFFER_ATOMIC_OR_X2] = "buffer_atomic_or_x2",
		[GFX9_BUFFER_ATOMIC_XOR_X2] = "buffer_atomic_xor_x2",
		[GFX9_BUFFER_ATOMIC_INC_X2] = "buffer_atomic_inc_x2",
		[GFX9_BUFFER_ATOMIC_DEC_X2] = "buffer_atomic_dec_x2",
	},
	[AMDGCN_INSN_TYPE_FLAT] = {
		[GFX9_GLOBAL_LOAD_UBYTE] = "global_load_ubyte",
		[GFX9_GLOBAL_LOAD_SBYTE] = "global_load_sbyte",
		[GFX9_GLOBAL_LOAD_USHORT] = "global_load_ushort",
		[GFX9_GLOBAL_LOAD_SSHORT] = "global_load_sshort",
		[GFX9_GLOBAL_LOAD_DWORD] = "global_load_dword",
		[GFX9_GLOBAL_LOAD_DWORDX2] = "global_load_dwordx2",
		[GFX9_GLOBAL_LOAD_DWORDX3] = "global_load_dwordx3",
		[GFX9_GLOBAL_LOAD_DWORDX4] = "global_load_dwordx4",
		[GFX9_GLOBAL_STORE_BYTE] = "global_store_byte",
		[GFX9_GLOBAL_STORE_BYTE_D16_HI] = "global_store_byte_d16_hi",
		[GFX9_GLOBAL_STORE_SHORT] = "global_store_short",
		[GFX9_GLOBAL_STORE_SHORT_D16_HI] = "global_store_short_d16_hi",
		[GFX9_GLOBAL_STORE_DWORD] = "global_store_dword",
		[GFX9_GLOBAL_STORE_DWORDX2] = "global_store_dwordx2",
		[GFX9_GLOBAL_STORE_DWORDX3] = "global_store_dwordx3",
		[GFX9_GLOBAL_STORE_DWORDX4] = "global_store_dwordx4",
		[GFX9_GLOBAL_LOAD_UBYTE_D16] = "global_load_ubyte_d16",
		[GFX9_GLOBAL_LOAD_UBYTE_D16_HI] = "global_load_ubyte_d16_hi",
		[GFX9_GLOBAL_LOAD_SBYTE_D16] = "global_load_sbyte_d16",
		[GFX9_GLOBAL_LOAD_SBYTE_D16_HI] = "global_load_sbyte_d16_hi",
		[GFX9_GLOBAL_LOAD_SHORT_D16] = "global_load_short_d16",
		[GFX9_GLOBAL_LOAD_SHORT_D16_HI] = "global_load_short_d16_hi",
		[GFX9_GLOBAL_ATOMIC_SWAP] = "global_atomic_swap",
		[GFX9_GLOBAL_ATOMIC_CMPSWAP] = "global_atomic_cmpswap",
		[GFX9_GLOBAL_ATOMIC_ADD] = "global_atomic_add",
		[GFX9_GLOBAL_ATOMIC_SUB] = "global_atomic_sub",
		[GFX9_GLOBAL_ATOMIC_SMIN] = "global_atomic_smin",
		[GFX9_GLOBAL_ATOMIC_UMIN] = "global_atomic_umin",
		[GFX9_GLOBAL_ATOMIC_SMAX] = "global_atomic_smax",
		[GFX9_GLOBAL_ATOMIC_UMAX] = "global_atomic_umax",
		[GFX9_GLOBAL_ATOMIC_AND] = "global_atomic_and",
		[GFX9_GLOBAL_ATOMIC_OR] = "global_atomic_or",
		[GFX9_GLOBAL_ATOMIC_XOR] = "global_atomic_xor",
		[GFX9_GLOBAL_ATOMIC_INC] = "global_atomic_inc",
		[GFX9_GLOBAL_ATOMIC_DEC] = "global_atomic_dec",
		[GFX9_GLOBAL_ATOMIC_SWAP_X2] = "global_atomic_swap_x2",
		[GFX9_GLOBAL_ATOMIC_CMPSWAP_X2] = "global_atomic_cmpswap_x2",
		[GFX9_GLOBAL_ATOMIC_ADD_X2] = "global_atomic_add_x2",
		[GFX9_GLOBAL_ATOMIC_SUB_X2] = "global_atomic_sub_x2",
		[GFX9_GLOBAL_ATOMIC_SMIN_X2] = "global_atomic_smin_x2",
		[GFX9_GLOBAL_ATOMIC_UMIN_X2] = "global_atomic_umin_x2",
		[GFX9_GLOBAL_ATOMIC_SMAX_X2] = "global_atomic_smax_x2",
		[GFX9_GLOBAL_ATOMIC_UMAX_X2] = "global_atomic_umax_x2",
		[GFX9_GLOBAL_ATOMIC_AND_X2] = "global_atomic_and_x2",
		[GFX9_GLOBAL_ATOMIC_OR_X2] = "global_atomic_or_x2",
		[GFX9_GLOBAL_ATOMIC_XOR_X2] = "global_atomic_xor_x2",
		[GFX9_GLOBAL_ATOMIC_INC_X2] = "global_atomic_inc_x2",
		[GFX9_GLOBAL_ATOMIC_DEC_X2] = "global_atomic_dec_x2",
	},
	[AMDGCN_INSN_TYPE_DS] = {
		/* DS opcode names (Vega ISA 12.13, opcodes 0-255). The DS
		 * table was entirely unpopulated, so DS instructions
		 * disassembled with a blank mnemonic. Enum values were
		 * ISA-verified (one known value bug at DS_CONDXCHG32_RTN_B64
		 * is tracked separately).
		 */
		[GFX9_DS_ADD_U32] = "ds_add_u32",
		[GFX9_DS_SUB_U32] = "ds_sub_u32",
		[GFX9_DS_RSUB_U32] = "ds_rsub_u32",
		[GFX9_DS_INC_U32] = "ds_inc_u32",
		[GFX9_DS_DEC_U32] = "ds_dec_u32",
		[GFX9_DS_MIN_I32] = "ds_min_i32",
		[GFX9_DS_MAX_I32] = "ds_max_i32",
		[GFX9_DS_MIN_U32] = "ds_min_u32",
		[GFX9_DS_MAX_U32] = "ds_max_u32",
		[GFX9_DS_AND_B32] = "ds_and_b32",
		[GFX9_DS_OR_B32] = "ds_or_b32",
		[GFX9_DS_XOR_B32] = "ds_xor_b32",
		[GFX9_DS_MSKOR_B32] = "ds_mskor_b32",
		[GFX9_DS_WRITE_B32] = "ds_write_b32",
		[GFX9_DS_WRITE2_B32] = "ds_write2_b32",
		[GFX9_DS_WRITE2ST64_B32] = "ds_write2st64_b32",
		[GFX9_DS_CMPST_B32] = "ds_cmpst_b32",
		[GFX9_DS_CMPST_F32] = "ds_cmpst_f32",
		[GFX9_DS_MIN_F32] = "ds_min_f32",
		[GFX9_DS_MAX_F32] = "ds_max_f32",
		[GFX9_DS_NOP] = "ds_nop",
		[GFX9_DS_ADD_F32] = "ds_add_f32",
		[GFX9_DS_WRITE_ADDTID_B32] = "ds_write_addtid_b32",
		[GFX9_DS_WRITE_B8] = "ds_write_b8",
		[GFX9_DS_WRITE_B16] = "ds_write_b16",
		[GFX9_DS_ADD_RTN_U32] = "ds_add_rtn_u32",
		[GFX9_DS_SUB_RTN_U32] = "ds_sub_rtn_u32",
		[GFX9_DS_RSUB_RTN_U32] = "ds_rsub_rtn_u32",
		[GFX9_DS_INC_RTN_U32] = "ds_inc_rtn_u32",
		[GFX9_DS_DEC_RTN_U32] = "ds_dec_rtn_u32",
		[GFX9_DS_MIN_RTN_I32] = "ds_min_rtn_i32",
		[GFX9_DS_MAX_RTN_I32] = "ds_max_rtn_i32",
		[GFX9_DS_MIN_RTN_U32] = "ds_min_rtn_u32",
		[GFX9_DS_MAX_RTN_U32] = "ds_max_rtn_u32",
		[GFX9_DS_AND_RTN_B32] = "ds_and_rtn_b32",
		[GFX9_DS_OR_RTN_B32] = "ds_or_rtn_b32",
		[GFX9_DS_XOR_RTN_B32] = "ds_xor_rtn_b32",
		[GFX9_DS_MSKOR_RTN_B32] = "ds_mskor_rtn_b32",
		[GFX9_DS_WRXCHG_RTN_B32] = "ds_wrxchg_rtn_b32",
		[GFX9_DS_WRXCHG2_RTN_B32] = "ds_wrxchg2_rtn_b32",
		[GFX9_DS_WRXCHG2ST64_RTN_B32] = "ds_wrxchg2st64_rtn_b32",
		[GFX9_DS_CMPST_RTN_B32] = "ds_cmpst_rtn_b32",
		[GFX9_DS_CMPST_RTN_F32] = "ds_cmpst_rtn_f32",
		[GFX9_DS_MIN_RTN_F32] = "ds_min_rtn_f32",
		[GFX9_DS_MAX_RTN_F32] = "ds_max_rtn_f32",
		[GFX9_DS_WRAP_RTN_B32] = "ds_wrap_rtn_b32",
		[GFX9_DS_ADD_RTN_F32] = "ds_add_rtn_f32",
		[GFX9_DS_READ_B32] = "ds_read_b32",
		[GFX9_DS_READ2_B32] = "ds_read2_b32",
		[GFX9_DS_READ2ST64_B32] = "ds_read2st64_b32",
		[GFX9_DS_READ_I8] = "ds_read_i8",
		[GFX9_DS_READ_U8] = "ds_read_u8",
		[GFX9_DS_READ_I16] = "ds_read_i16",
		[GFX9_DS_READ_U16] = "ds_read_u16",
		[GFX9_DS_SWIZZLE_B32] = "ds_swizzle_b32",
		[GFX9_DS_PERMUTE_B32] = "ds_permute_b32",
		[GFX9_DS_BPERMUTE_B32] = "ds_bpermute_b32",
		[GFX9_DS_ADD_U64] = "ds_add_u64",
		[GFX9_DS_SUB_U64] = "ds_sub_u64",
		[GFX9_DS_RSUB_U64] = "ds_rsub_u64",
		[GFX9_DS_INC_U64] = "ds_inc_u64",
		[GFX9_DS_DEC_U64] = "ds_dec_u64",
		[GFX9_DS_MIN_I64] = "ds_min_i64",
		[GFX9_DS_MAX_I64] = "ds_max_i64",
		[GFX9_DS_MIN_U64] = "ds_min_u64",
		[GFX9_DS_MAX_U64] = "ds_max_u64",
		[GFX9_DS_AND_B64] = "ds_and_b64",
		[GFX9_DS_OR_B64] = "ds_or_b64",
		[GFX9_DS_XOR_B64] = "ds_xor_b64",
		[GFX9_DS_MSKOR_B64] = "ds_mskor_b64",
		[GFX9_DS_WRITE_B64] = "ds_write_b64",
		[GFX9_DS_WRITE2_B64] = "ds_write2_b64",
		[GFX9_DS_WRITE2ST64_B64] = "ds_write2st64_b64",
		[GFX9_DS_CMPST_B64] = "ds_cmpst_b64",
		[GFX9_DS_CMPST_F64] = "ds_cmpst_f64",
		[GFX9_DS_MIN_F64] = "ds_min_f64",
		[GFX9_DS_MAX_F64] = "ds_max_f64",
		[GFX9_DS_WRITE_B8_D16_HI] = "ds_write_b8_d16_hi",
		[GFX9_DS_WRITE_B16_D16_HI] = "ds_write_b16_d16_hi",
		[GFX9_DS_READ_U8_D16] = "ds_read_u8_d16",
		[GFX9_DS_READ_U8_D16_HI] = "ds_read_u8_d16_hi",
		[GFX9_DS_READ_I8_D16] = "ds_read_i8_d16",
		[GFX9_DS_READ_I8_D16_HI] = "ds_read_i8_d16_hi",
		[GFX9_DS_READ_U16_D16] = "ds_read_u16_d16",
		[GFX9_DS_READ_U16_D16_HI] = "ds_read_u16_d16_hi",
		[GFX9_DS_ADD_RTN_U64] = "ds_add_rtn_u64",
		[GFX9_DS_SUB_RTN_U64] = "ds_sub_rtn_u64",
		[GFX9_DS_RSUB_RTN_U64] = "ds_rsub_rtn_u64",
		[GFX9_DS_INC_RTN_U64] = "ds_inc_rtn_u64",
		[GFX9_DS_DEC_RTN_U64] = "ds_dec_rtn_u64",
		[GFX9_DS_MIN_RTN_I64] = "ds_min_rtn_i64",
		[GFX9_DS_MAX_RTN_I64] = "ds_max_rtn_i64",
		[GFX9_DS_MIN_RTN_U64] = "ds_min_rtn_u64",
		[GFX9_DS_MAX_RTN_U64] = "ds_max_rtn_u64",
		[GFX9_DS_AND_RTN_B64] = "ds_and_rtn_b64",
		[GFX9_DS_OR_RTN_B64] = "ds_or_rtn_b64",
		[GFX9_DS_XOR_RTN_B64] = "ds_xor_rtn_b64",
		[GFX9_DS_MSKOR_RTN_B64] = "ds_mskor_rtn_b64",
		[GFX9_DS_WRXCHG_RTN_B64] = "ds_wrxchg_rtn_b64",
		[GFX9_DS_WRXCHG2_RTN_B64] = "ds_wrxchg2_rtn_b64",
		[GFX9_DS_WRXCHG2ST64_RTN_B64] = "ds_wrxchg2st64_rtn_b64",
		[GFX9_DS_CMPST_RTN_B64] = "ds_cmpst_rtn_b64",
		[GFX9_DS_CMPST_RTN_F64] = "ds_cmpst_rtn_f64",
		[GFX9_DS_MIN_RTN_F64] = "ds_min_rtn_f64",
		[GFX9_DS_MAX_RTN_F64] = "ds_max_rtn_f64",
		[GFX9_DS_READ_B64] = "ds_read_b64",
		[GFX9_DS_READ2_B64] = "ds_read2_b64",
		[GFX9_DS_CONDXCHG32_RTN_B64] = "ds_condxchg32_rtn_b64",
		[GFX9_DS_ADD_SRC2_U32] = "ds_add_src2_u32",
		[GFX9_DS_SUB_SRC2_U32] = "ds_sub_src2_u32",
		[GFX9_DS_RSUB_SRC2_U32] = "ds_rsub_src2_u32",
		[GFX9_DS_INC_SRC2_U32] = "ds_inc_src2_u32",
		[GFX9_DS_DEC_SRC2_U32] = "ds_dec_src2_u32",
		[GFX9_DS_MIN_SRC2_I32] = "ds_min_src2_i32",
		[GFX9_DS_MAX_SRC2_I32] = "ds_max_src2_i32",
		[GFX9_DS_MIN_SRC2_U32] = "ds_min_src2_u32",
		[GFX9_DS_MAX_SRC2_U32] = "ds_max_src2_u32",
		[GFX9_DS_AND_SRC2_B32] = "ds_and_src2_b32",
		[GFX9_DS_OR_SRC2_B32] = "ds_or_src2_b32",
		[GFX9_DS_XOR_SRC2_B32] = "ds_xor_src2_b32",
		[GFX9_DS_WRITE_SRC2_B32] = "ds_write_src2_b32",
		[GFX9_DS_MIN_SRC2_F32] = "ds_min_src2_f32",
		[GFX9_DS_MAX_SRC2_F32] = "ds_max_src2_f32",
		[GFX9_DS_ADD_SRC2_F32] = "ds_add_src2_f32",
		[GFX9_DS_GWS_SEMA_RELEASE_ALL] = "ds_gws_sema_release_all",
		[GFX9_DS_ADD_SRC2_U64] = "ds_add_src2_u64",
		[GFX9_DS_SUB_SRC2_U64] = "ds_sub_src2_u64",
		[GFX9_DS_RSUB_SRC2_U64] = "ds_rsub_src2_u64",
		[GFX9_DS_INC_SRC2_U64] = "ds_inc_src2_u64",
		[GFX9_DS_DEC_SRC2_U64] = "ds_dec_src2_u64",
		[GFX9_DS_MIN_SRC2_I64] = "ds_min_src2_i64",
		[GFX9_DS_MAX_SRC2_I64] = "ds_max_src2_i64",
		[GFX9_DS_MIN_SRC2_U64] = "ds_min_src2_u64",
		[GFX9_DS_MAX_SRC2_U64] = "ds_max_src2_u64",
		[GFX9_DS_AND_SRC2_B64] = "ds_and_src2_b64",
		[GFX9_DS_OR_SRC2_B64] = "ds_or_src2_b64",
		[GFX9_DS_XOR_SRC2_B64] = "ds_xor_src2_b64",
		[GFX9_DS_WRITE_SRC2_B64] = "ds_write_src2_b64",
		[GFX9_DS_MIN_SRC2_F64] = "ds_min_src2_f64",
		[GFX9_DS_MAX_SRC2_F64] = "ds_max_src2_f64",
		[GFX9_DS_WRITE_B96] = "ds_write_b96",
		[GFX9_DS_WRITE_B128] = "ds_write_b128",
		[GFX9_DS_READ_B96] = "ds_read_b96",
		[GFX9_DS_READ_B128] = "ds_read_b128",
	},
};

struct amdgcn_insn  {
	union {
		union amdgcn_gfx10_insn gfx10;
		union amdgcn_gfx9_insn gfx9;
	};
	u32 size;
	u32 idx;
	enum amdgcn_insn_type type;
};

static inline void emit_s_load_dwordx2(int version, struct amdgcn_insn *insn,
				struct amdgcn_param32 dst,
				struct amdgcn_param32 src, int offset)
{
	if (version == 10) {
		insn->size = emit_gfx10_s_load_dwordx2(&insn->gfx10, dst,
						       src,
						       offset);
		insn->type = AMDGCN_INSN_TYPE_SMEM;
	} else if (version == 9) {
		insn->size = emit_gfx9_s_load_dwordx2(&insn->gfx9, dst,
						      src,
						      offset);
		insn->type = AMDGCN_INSN_TYPE_SMEM;
	} else {
		WARN_ON(1);
	}
}

static inline void emit_s_load_dwordx2_soff(int version,
				     struct amdgcn_insn *insn,
				     struct amdgcn_param32 dst,
				     struct amdgcn_param32 src,
				     int offset, u8 soffset)
{
	if (version == 10) {
		insn->size = emit_gfx10_s_load_dwordx2(&insn->gfx10, dst,
						       src, offset);
		insn->gfx10.smem.soffset = soffset;
		insn->type = AMDGCN_INSN_TYPE_SMEM;
	} else if (version == 9) {
		insn->size = emit_gfx9_s_load_dwordx2(&insn->gfx9, dst,
						      src, offset);
		insn->gfx9.smem.soe = 1;
		insn->gfx9.smem.soffset = soffset;
		insn->type = AMDGCN_INSN_TYPE_SMEM;
	} else {
		WARN_ON(1);
	}
}

static inline void emit_s_lshl_b32(int version, struct amdgcn_insn *insn,
			     struct amdgcn_param32 dst,
			     struct amdgcn_param32 src0,
			     struct amdgcn_param32 src1)
{
	if (version == 10) {
		insn->size = emit_gfx10_s_lshl_b32(&insn->gfx10, dst,
						    src0, src1);
		insn->type = AMDGCN_INSN_TYPE_SOP2;
	} else if (version == 9) {
		insn->size = emit_gfx9_s_lshl_b32(&insn->gfx9, dst,
						   src0, src1);
		insn->type = AMDGCN_INSN_TYPE_SOP2;
	} else {
		WARN_ON(1);
	}
}

static inline void emit_v_bfe_i32(int version, struct amdgcn_insn *insn,
			   struct amdgcn_param32 dst,
			   struct amdgcn_param32 src0,
			   struct amdgcn_param32 src1,
			   struct amdgcn_param32 src2)
{
	WARN_ON(knod_param_is_literal(src0) ||
		knod_param_is_literal(src1) ||
		knod_param_is_literal(src2));
	if (version == 10) {
		insn->size = emit_gfx10_v_bfe_i32(&insn->gfx10,
						  dst, src0, src1, src2);
		insn->type = AMDGCN_INSN_TYPE_VOP3A;
	} else if (version == 9) {
		insn->size = emit_gfx9_v_bfe_i32(&insn->gfx9,
						 dst, src0, src1, src2);
		insn->type = AMDGCN_INSN_TYPE_VOP3A;
	} else {
		WARN_ON(1);
	}
}

static inline void emit_v_bfe_u32(int version, struct amdgcn_insn *insn,
			   struct amdgcn_param32 dst,
			   struct amdgcn_param32 src0,
			   struct amdgcn_param32 src1,
			   struct amdgcn_param32 src2)
{
	WARN_ON(knod_param_is_literal(src0) ||
		knod_param_is_literal(src1) ||
		knod_param_is_literal(src2));
	if (version == 10) {
		insn->size = emit_gfx10_v_bfe_u32(&insn->gfx10,
						  dst, src0, src1, src2);
		insn->type = AMDGCN_INSN_TYPE_VOP3A;
	} else if (version == 9) {
		insn->size = emit_gfx9_v_bfe_u32(&insn->gfx9,
						 dst, src0, src1, src2);
		insn->type = AMDGCN_INSN_TYPE_VOP3A;
	} else {
		WARN_ON(1);
	}
}

static inline void emit_v_bfi_b32(int version, struct amdgcn_insn *insn,
			   struct amdgcn_param32 dst,
			   struct amdgcn_param32 src0,
			   struct amdgcn_param32 src1,
			   struct amdgcn_param32 src2)
{
	WARN_ON(knod_param_is_literal(src0) ||
		knod_param_is_literal(src1) ||
		knod_param_is_literal(src2));
	if (version == 10) {
		insn->size = emit_gfx10_v_bfi_b32(&insn->gfx10,
						  dst, src0, src1, src2);
		insn->type = AMDGCN_INSN_TYPE_VOP3A;
	} else if (version == 9) {
		insn->size = emit_gfx9_v_bfi_b32(&insn->gfx9,
						 dst, src0, src1, src2);
		insn->type = AMDGCN_INSN_TYPE_VOP3A;
	} else {
		WARN_ON(1);
	}
}

static inline void emit_v_lshl_add_u32(int version, struct amdgcn_insn *insn,
				struct amdgcn_param32 dst,
				struct amdgcn_param32 src0,
				struct amdgcn_param32 src1,
				struct amdgcn_param32 src2)
{
	if (version == 10) {
		insn->size = emit_gfx10_v_lshl_add_u32(&insn->gfx10,
						       dst, src0, src1, src2);
		insn->type = AMDGCN_INSN_TYPE_VOP3A;
	} else if (version == 9) {
		insn->size = emit_gfx9_v_lshl_add_u32(&insn->gfx9,
						      dst, src0, src1, src2);
		insn->type = AMDGCN_INSN_TYPE_VOP3A;
	} else {
		WARN_ON(1);
	}
}

static inline void emit_v_lshl_or_b32(int version, struct amdgcn_insn *insn,
			       struct amdgcn_param32 dst,
			       struct amdgcn_param32 src0,
			       struct amdgcn_param32 src1,
			       struct amdgcn_param32 src2)
{
	if (version == 10) {
		insn->size = emit_gfx10_v_lshl_or_b32(&insn->gfx10,
						      dst, src0, src1, src2);
		insn->type = AMDGCN_INSN_TYPE_VOP3A;
	} else if (version == 9) {
		insn->size = emit_gfx9_v_lshl_or_b32(&insn->gfx9,
						     dst, src0, src1, src2);
		insn->type = AMDGCN_INSN_TYPE_VOP3A;
	} else {
		WARN_ON(1);
	}
}

static inline void emit_v_alignbit_b32(int version, struct amdgcn_insn *insn,
				struct amdgcn_param32 dst,
				struct amdgcn_param32 src0,
				struct amdgcn_param32 src1,
				struct amdgcn_param32 src2)
{
	if (version == 10) {
		insn->size = emit_gfx10_v_alignbit_b32(&insn->gfx10,
						       dst, src0,
						       src1, src2);
		insn->type = AMDGCN_INSN_TYPE_VOP3A;
	} else if (version == 9) {
		insn->size = emit_gfx9_v_alignbit_b32(&insn->gfx9,
						      dst, src0,
						      src1, src2);
		insn->type = AMDGCN_INSN_TYPE_VOP3A;
	} else {
		WARN_ON(1);
	}
}

static inline void emit_v_perm_b32(int version, struct amdgcn_insn *insn,
			    struct amdgcn_param32 dst,
			    struct amdgcn_param32 src0,
			    struct amdgcn_param32 src1,
			    struct amdgcn_param32 src2)
{
	WARN_ON(knod_param_is_literal(src0) ||
		knod_param_is_literal(src1) ||
		knod_param_is_literal(src2));
	if (version == 10) {
		insn->size = emit_gfx10_v_perm_b32(&insn->gfx10,
						    dst, src0, src1, src2);
		insn->type = AMDGCN_INSN_TYPE_VOP3A;
	} else if (version == 9) {
		insn->size = emit_gfx9_v_perm_b32(&insn->gfx9,
						   dst, src0, src1, src2);
		insn->type = AMDGCN_INSN_TYPE_VOP3A;
	} else {
		WARN_ON(1);
	}
}

static inline void emit_v_mad_u64_u32(int version, struct amdgcn_insn *insn,
			       struct amdgcn_param64 dst,
			       struct amdgcn_param32 dst2,
			       struct amdgcn_param32 src0,
			       struct amdgcn_param32 src1,
			       struct amdgcn_param64 src2)
{
	if (version == 10) {
		insn->size = emit_gfx10_v_mad_u64_u32(&insn->gfx10, dst,
						      dst2, src0,
						      src1, src2);
		insn->type = AMDGCN_INSN_TYPE_VOP3B;
	} else if (version == 9) {
		insn->size = emit_gfx9_v_mad_u64_u32(&insn->gfx9, dst,
						     dst2, src0,
						     src1, src2);
		insn->type = AMDGCN_INSN_TYPE_VOP3B;
	} else {
		WARN_ON(1);
	}
}

static inline void emit_s_mov_b32(int version, struct amdgcn_insn *insn,
			   struct amdgcn_param32 dst, struct amdgcn_param32 src)
{
	if (version == 10) {
		insn->size = emit_gfx10_s_mov_b32(&insn->gfx10, dst, src);
		insn->type = AMDGCN_INSN_TYPE_SOP1;
	} else if (version == 9) {
		insn->size = emit_gfx9_s_mov_b32(&insn->gfx9, dst, src);
		insn->type = AMDGCN_INSN_TYPE_SOP1;
	} else {
		WARN_ON(1);
	}
}

static inline void emit_v_mov_b32_e32(int version, struct amdgcn_insn *insn,
			       struct amdgcn_param32 dst,
			       struct amdgcn_param32 src)
{
	if (version == 10) {
		insn->size = emit_gfx10_v_mov_b32_e32(&insn->gfx10, dst, src);
		insn->type = AMDGCN_INSN_TYPE_VOP1;
	} else if (version == 9) {
		insn->size = emit_gfx9_v_mov_b32_e32(&insn->gfx9, dst, src);
		insn->type = AMDGCN_INSN_TYPE_VOP1;
	} else {
		WARN_ON(1);
	}
}

static inline void emit_v_readfirstlane_b32(int version,
				     struct amdgcn_insn *insn,
				     u8 sdst, u8 vsrc)
{
	if (version == 10) {
		insn->size = emit_gfx10_v_readfirstlane_b32(&insn->gfx10,
							    sdst, vsrc);
		insn->type = AMDGCN_INSN_TYPE_VOP1;
	} else if (version == 9) {
		insn->size = emit_gfx9_v_readfirstlane_b32(&insn->gfx9,
							   sdst, vsrc);
		insn->type = AMDGCN_INSN_TYPE_VOP1;
	} else {
		WARN_ON(1);
	}
}

static inline void emit_v_add_co_u32(int version, struct amdgcn_insn *insn,
			      struct amdgcn_param32 dst,
			      struct amdgcn_param32 src0,
			      struct amdgcn_param32 src1)
{
	if (version == 10) {
		insn->size = emit_gfx10_v_add_co_u32(&insn->gfx10, dst,
						     src0, src1);
		insn->type = AMDGCN_INSN_TYPE_VOP3B;
	} else if (version == 9) {
		WARN_ON_ONCE(src1.type != AMDGCN_PARAM_TYPE_VGPR);
		insn->size = emit_gfx9_v_add_co_u32(&insn->gfx9, dst,
						    src0, src1);
		insn->type = AMDGCN_INSN_TYPE_VOP2;
	} else {
		WARN_ON(1);
	}
}

static inline void emit_v_add_co_ci_u32_e32(int version,
				     struct amdgcn_insn *insn,
				     struct amdgcn_param32 dst,
				     struct amdgcn_param32 src0,
				     struct amdgcn_param32 src1)
{
	if (version == 10) {
		insn->size = emit_gfx10_v_add_co_ci_u32_e32(&insn->gfx10,
							    dst, src0,
							    src1);
		insn->type = AMDGCN_INSN_TYPE_VOP2;
	} else if (version == 9) {
		insn->size = emit_gfx9_v_addc_co_u32(&insn->gfx9, dst,
						     src0, src1);
		insn->type = AMDGCN_INSN_TYPE_VOP2;
	} else {
		WARN_ON(1);
	}
}

/* No carry in/out */
static inline void emit_v_add_u32(int version, struct amdgcn_insn *insn,
			      struct amdgcn_param32 dst,
			      struct amdgcn_param32 src0,
			      struct amdgcn_param32 src1)
{
	if (version == 10) {
		WARN_ON_ONCE(src1.type != AMDGCN_PARAM_TYPE_VGPR);
		insn->size = emit_gfx10_v_add_nc_u32(&insn->gfx10, dst,
						     src0, src1);
		insn->type = AMDGCN_INSN_TYPE_VOP2;
	} else if (version == 9) {
		WARN_ON_ONCE(src1.type != AMDGCN_PARAM_TYPE_VGPR);
		insn->size = emit_gfx9_v_add_u32(&insn->gfx9, dst,
						    src0, src1);
		insn->type = AMDGCN_INSN_TYPE_VOP2;
	} else {
		WARN_ON(1);
	}
}

/* No carry in/out */
static inline void emit_v_sub_u32(int version, struct amdgcn_insn *insn,
			      struct amdgcn_param32 dst,
			      struct amdgcn_param32 src0,
			      struct amdgcn_param32 src1)
{
	if (version == 10) {
		WARN_ON_ONCE(src1.type != AMDGCN_PARAM_TYPE_VGPR);
		insn->size = emit_gfx10_v_sub_nc_u32(&insn->gfx10, dst,
						     src0, src1);
		insn->type = AMDGCN_INSN_TYPE_VOP2;
	} else if (version == 9) {
		WARN_ON_ONCE(src1.type != AMDGCN_PARAM_TYPE_VGPR);
		insn->size = emit_gfx9_v_sub_u32(&insn->gfx9, dst,
						    src0, src1);
		insn->type = AMDGCN_INSN_TYPE_VOP2;
	} else {
		WARN_ON(1);
	}
}

static inline void emit_v_xor_b32_e32(int version, struct amdgcn_insn *insn,
			       struct amdgcn_param32 dst,
			       struct amdgcn_param32 src0,
			       struct amdgcn_param32 src1)
{
	if (version == 10) {
		WARN_ON_ONCE(src1.type != AMDGCN_PARAM_TYPE_VGPR);
		insn->size = emit_gfx10_v_xor_b32_e32(&insn->gfx10, dst,
						      src0, src1);
		insn->type = AMDGCN_INSN_TYPE_VOP2;
	} else if (version == 9) {
		WARN_ON_ONCE(src1.type != AMDGCN_PARAM_TYPE_VGPR);
		insn->size = emit_gfx9_v_xor_b32_e32(&insn->gfx9, dst,
						     src0, src1);
		insn->type = AMDGCN_INSN_TYPE_VOP2;
	} else {
		WARN_ON(1);
	}
}

static inline void emit_v_or_b32_e32(int version, struct amdgcn_insn *insn,
			      struct amdgcn_param32 dst,
			      struct amdgcn_param32 src0,
			      struct amdgcn_param32 src1)
{
	if (version == 10) {
		WARN_ON_ONCE(src1.type != AMDGCN_PARAM_TYPE_VGPR);
		insn->size = emit_gfx10_v_or_b32_e32(&insn->gfx10, dst,
						      src0, src1);
		insn->type = AMDGCN_INSN_TYPE_VOP2;
	} else if (version == 9) {
		WARN_ON_ONCE(src1.type != AMDGCN_PARAM_TYPE_VGPR);
		insn->size = emit_gfx9_v_or_b32_e32(&insn->gfx9, dst,
						     src0, src1);
		insn->type = AMDGCN_INSN_TYPE_VOP2;
	} else {
		WARN_ON(1);
	}
}

static inline void emit_v_cndmask_b32_e32(int version, struct amdgcn_insn *insn,
				   struct amdgcn_param32 dst,
				   struct amdgcn_param32 src0,
				   struct amdgcn_param32 src1)
{
	if (version == 10) {
		WARN_ON_ONCE(src1.type != AMDGCN_PARAM_TYPE_VGPR);
		insn->size = emit_gfx10_v_cndmask_b32_e32(&insn->gfx10, dst,
							   src0, src1);
		insn->type = AMDGCN_INSN_TYPE_VOP2;
	} else if (version == 9) {
		WARN_ON_ONCE(src1.type != AMDGCN_PARAM_TYPE_VGPR);
		insn->size = emit_gfx9_v_cndmask_b32_e32(&insn->gfx9, dst,
							  src0, src1);
		insn->type = AMDGCN_INSN_TYPE_VOP2;
	} else {
		WARN_ON(1);
	}
}

static inline void emit_v_and_b32_e32(int version, struct amdgcn_insn *insn,
			       struct amdgcn_param32 dst,
			       struct amdgcn_param32 src0,
			       struct amdgcn_param32 src1)
{
	if (version == 10) {
		WARN_ON_ONCE(src1.type != AMDGCN_PARAM_TYPE_VGPR);
		insn->size = emit_gfx10_v_and_b32_e32(&insn->gfx10, dst,
						      src0, src1);
		insn->type = AMDGCN_INSN_TYPE_VOP2;
	} else if (version == 9) {
		WARN_ON_ONCE(src1.type != AMDGCN_PARAM_TYPE_VGPR);
		insn->size = emit_gfx9_v_and_b32_e32(&insn->gfx9, dst,
						     src0, src1);
		insn->type = AMDGCN_INSN_TYPE_VOP2;
	} else {
		WARN_ON(1);
	}
}

static inline void emit_v_sub_co_ci_u32_e32(int version,
				     struct amdgcn_insn *insn,
				     struct amdgcn_param32 dst,
				     struct amdgcn_param32 src0,
				     struct amdgcn_param32 src1)
{
	if (version == 10) {
		WARN_ON_ONCE(src1.type != AMDGCN_PARAM_TYPE_VGPR);
		insn->size = emit_gfx10_v_sub_co_ci_u32_e32(&insn->gfx10,
							    dst, src0, src1);
		insn->type = AMDGCN_INSN_TYPE_VOP2;
	} else if (version == 9) {
		WARN_ON_ONCE(src1.type != AMDGCN_PARAM_TYPE_VGPR);
		insn->size = emit_gfx9_v_subb_co_u32(&insn->gfx9, dst,
						     src0, src1);
		insn->type = AMDGCN_INSN_TYPE_VOP2;
	} else {
		WARN_ON(1);
	}
}

static inline void emit_v_subrev_co_ci_u32_e32(int version,
					struct amdgcn_insn *insn,
					struct amdgcn_param32 dst,
					struct amdgcn_param32 src0,
					struct amdgcn_param32 src1)
{
	if (version == 10) {
		WARN_ON_ONCE(src1.type != AMDGCN_PARAM_TYPE_VGPR);
		insn->size = emit_gfx10_v_subrev_co_ci_u32_e32(&insn->gfx10,
							       dst, src0, src1);
		insn->type = AMDGCN_INSN_TYPE_VOP2;
	} else if (version == 9) {
		WARN_ON_ONCE(src1.type != AMDGCN_PARAM_TYPE_VGPR);
		insn->size = emit_gfx9_v_subbrev_co_u32(&insn->gfx9, dst,
							src0, src1);
		insn->type = AMDGCN_INSN_TYPE_VOP2;
	} else {
		WARN_ON(1);
	}
}

static inline void emit_v_sub_co_u32(int version, struct amdgcn_insn *insn,
			      struct amdgcn_param32 dst,
			      struct amdgcn_param32 src0,
			      struct amdgcn_param32 src1)
{
	if (version == 10) {
		insn->size = emit_gfx10_v_sub_co_u32(&insn->gfx10, dst,
						     src0, src1);
		insn->type = AMDGCN_INSN_TYPE_VOP3B;
	} else if (version == 9) {
		WARN_ON_ONCE(src1.type != AMDGCN_PARAM_TYPE_VGPR);
		insn->size = emit_gfx9_v_sub_co_u32(&insn->gfx9, dst,
						    src0, src1);
		insn->type = AMDGCN_INSN_TYPE_VOP2;
	} else {
		WARN_ON(1);
	}
}

static inline void emit_v_subrev_co_u32(int version, struct amdgcn_insn *insn,
				 struct amdgcn_param32 dst,
				 struct amdgcn_param32 src0,
				 struct amdgcn_param32 src1)
{
	if (version == 10) {
		insn->size = emit_gfx10_v_subrev_co_u32(&insn->gfx10, dst,
							src0, src1);
		insn->type = AMDGCN_INSN_TYPE_VOP3B;
	} else if (version == 9) {
		WARN_ON_ONCE(src1.type != AMDGCN_PARAM_TYPE_VGPR);
		insn->size = emit_gfx9_v_subrev_co_u32(&insn->gfx9, dst,
						       src0, src1);
		insn->type = AMDGCN_INSN_TYPE_VOP2;
	} else {
		WARN_ON(1);
	}
}

static inline void emit_v_mul_lo_u32(int version, struct amdgcn_insn *insn,
			      struct amdgcn_param32 dst,
			      struct amdgcn_param32 src0,
			      struct amdgcn_param32 src1)
{
	if (version == 10) {
		insn->size = emit_gfx10_v_mul_lo_u32(&insn->gfx10, dst,
						     src0, src1);
		insn->type = AMDGCN_INSN_TYPE_VOP3A;
	} else if (version == 9) {
		insn->size = emit_gfx9_v_mul_lo_u32(&insn->gfx9, dst,
						    src0, src1);
		insn->type = AMDGCN_INSN_TYPE_VOP3A;
	} else {
		WARN_ON(1);
	}
}

static inline void emit_v_mbcnt_lo_u32_b32(int version,
				    struct amdgcn_insn *insn,
				    struct amdgcn_param32 dst,
				    struct amdgcn_param32 src0,
				    struct amdgcn_param32 src1)
{
	if (version == 10) {
		insn->size = emit_gfx10_v_mbcnt_lo_u32_b32(&insn->gfx10,
							    dst, src0, src1);
		insn->type = AMDGCN_INSN_TYPE_VOP3A;
	} else if (version == 9) {
		insn->size = emit_gfx9_v_mbcnt_lo_u32_b32(&insn->gfx9,
							   dst, src0, src1);
		insn->type = AMDGCN_INSN_TYPE_VOP3A;
	} else {
		WARN_ON(1);
	}
}

static inline void emit_v_mbcnt_hi_u32_b32(int version,
				    struct amdgcn_insn *insn,
				    struct amdgcn_param32 dst,
				    struct amdgcn_param32 src0,
				    struct amdgcn_param32 src1)
{
	if (version == 10) {
		insn->size = emit_gfx10_v_mbcnt_hi_u32_b32(&insn->gfx10,
							    dst, src0, src1);
		insn->type = AMDGCN_INSN_TYPE_VOP3A;
	} else if (version == 9) {
		insn->size = emit_gfx9_v_mbcnt_hi_u32_b32(&insn->gfx9,
							   dst, src0, src1);
		insn->type = AMDGCN_INSN_TYPE_VOP3A;
	} else {
		WARN_ON(1);
	}
}

static inline void emit_v_mul_hi_u32(int version, struct amdgcn_insn *insn,
			      struct amdgcn_param32 dst,
			      struct amdgcn_param32 src0,
			      struct amdgcn_param32 src1)
{
	if (version == 10) {
		insn->size = emit_gfx10_v_mul_hi_u32(&insn->gfx10, dst,
						     src0, src1);
		insn->type = AMDGCN_INSN_TYPE_VOP3A;
	} else if (version == 9) {
		insn->size = emit_gfx9_v_mul_hi_u32(&insn->gfx9, dst,
						    src0, src1);
		insn->type = AMDGCN_INSN_TYPE_VOP3A;
	} else {
		WARN_ON(1);
	}
}

static inline void emit_v_lshlrev_b64(int version, struct amdgcn_insn *insn,
			       struct amdgcn_param64 dst,
			       struct amdgcn_param64 src0,
			       struct amdgcn_param64 src1)
{
	/* D.u64 = S1.u64 << S0.u[5:0]. */
	if (version == 10) {
		insn->size = emit_gfx10_v_lshlrev_b64(&insn->gfx10, dst,
						      src0, src1);
		insn->type = AMDGCN_INSN_TYPE_VOP3A;
	} else if (version == 9) {
		insn->size = emit_gfx9_v_lshlrev_b64(&insn->gfx9, dst,
						     src0, src1);
		insn->type = AMDGCN_INSN_TYPE_VOP3A;
	} else {
		WARN_ON(1);
	}
}

static inline void emit_v_lshrrev_b64(int version, struct amdgcn_insn *insn,
			       struct amdgcn_param64 dst,
			       struct amdgcn_param64 src0,
			       struct amdgcn_param64 src1)
{
	WARN_ON(src1.lo.type == AMDGCN_PARAM_TYPE_LITERAL_CONST);
	if (version == 10) {
		insn->size = emit_gfx10_v_lshrrev_b64(&insn->gfx10, dst,
						      src0, src1);
		insn->type = AMDGCN_INSN_TYPE_VOP3A;
	} else if (version == 9) {
		insn->size = emit_gfx9_v_lshrrev_b64(&insn->gfx9, dst,
						     src0, src1);
		insn->type = AMDGCN_INSN_TYPE_VOP3A;
	} else {
		WARN_ON(1);
	}
}

static inline void emit_v_ashrrev_i64(int version, struct amdgcn_insn *insn,
			       struct amdgcn_param64 dst,
			       struct amdgcn_param64 src0,
			       struct amdgcn_param64 src1)
{
	if (version == 10) {
		insn->size = emit_gfx10_v_ashrrev_i64(&insn->gfx10, dst, src0,
						      src1);
		insn->type = AMDGCN_INSN_TYPE_VOP3A;
	} else if (version == 9) {
		insn->size = emit_gfx9_v_ashrrev_i64(&insn->gfx9, dst, src0,
						     src1);
		insn->type = AMDGCN_INSN_TYPE_VOP3A;
	} else {
		WARN_ON(1);
	}
}

static inline void emit_v_ashrrev_i32(int version, struct amdgcn_insn *insn,
			       struct amdgcn_param32 dst,
			       struct amdgcn_param32 src0,
			       struct amdgcn_param32 src1)
{
	if (version == 10) {
		insn->size = emit_gfx10_v_ashrrev_i32(&insn->gfx10, dst, src0,
						      src1);
		insn->type = AMDGCN_INSN_TYPE_VOP3A;
	} else if (version == 9) {
		insn->size = emit_gfx9_v_ashrrev_i32(&insn->gfx9, dst, src0,
						     src1);
		insn->type = AMDGCN_INSN_TYPE_VOP3A;
	} else {
		WARN_ON(1);
	}
}

static inline void emit_v_lshlrev_b32(int version, struct amdgcn_insn *insn,
			       struct amdgcn_param32 dst,
			       struct amdgcn_param32 src0,
			       struct amdgcn_param32 src1)
{
	if (version == 10) {
		WARN_ON_ONCE(src1.type != AMDGCN_PARAM_TYPE_VGPR);
		insn->size = emit_gfx10_v_lshlrev_b32(&insn->gfx10, dst,
						      src0, src1);
		insn->type = AMDGCN_INSN_TYPE_VOP2;
	} else if (version == 9) {
		WARN_ON_ONCE(src1.type != AMDGCN_PARAM_TYPE_VGPR);
		insn->size = emit_gfx9_v_lshlrev_b32(&insn->gfx9, dst,
						     src0, src1);
		insn->type = AMDGCN_INSN_TYPE_VOP2;
	} else {
		WARN_ON(1);
	}
}

static inline void emit_v_lshrrev_b32(int version, struct amdgcn_insn *insn,
			       struct amdgcn_param32 dst,
			       struct amdgcn_param32 src0,
			       struct amdgcn_param32 src1)
{
	if (version == 10) {
		WARN_ON_ONCE(src1.type != AMDGCN_PARAM_TYPE_VGPR);
		insn->size = emit_gfx10_v_lshrrev_b32(&insn->gfx10, dst,
						      src0, src1);
		insn->type = AMDGCN_INSN_TYPE_VOP2;
	} else if (version == 9) {
		WARN_ON_ONCE(src1.type != AMDGCN_PARAM_TYPE_VGPR);
		insn->size = emit_gfx9_v_lshrrev_b32(&insn->gfx9, dst,
						     src0, src1);
		insn->type = AMDGCN_INSN_TYPE_VOP2;
	} else {
		WARN_ON(1);
	}
}

static inline void emit_v_cmp_eq_u64(int version, struct amdgcn_insn *insn,
			      struct amdgcn_param32 dst,
			      struct amdgcn_param32 src)
{
	WARN_ON_ONCE(dst.type == AMDGCN_PARAM_TYPE_LITERAL_CONST);
	WARN_ON(src.type != AMDGCN_PARAM_TYPE_VGPR);
	if (version == 10) {
		insn->size = emit_gfx10_v_cmp_eq_u64(&insn->gfx10, dst, src);
		insn->type = AMDGCN_INSN_TYPE_VOPC;
	} else if (version == 9) {
		insn->size = emit_gfx9_v_cmp_eq_u64(&insn->gfx9, dst, src);
		insn->type = AMDGCN_INSN_TYPE_VOPC;
	} else {
		WARN_ON(1);
	}
}

static inline void emit_v_cmp_eq_u32(int version, struct amdgcn_insn *insn,
			      struct amdgcn_param32 dst,
			      struct amdgcn_param32 src)
{
	WARN_ON_ONCE(dst.type == AMDGCN_PARAM_TYPE_LITERAL_CONST);
	WARN_ON(src.type != AMDGCN_PARAM_TYPE_VGPR);
	if (version == 10) {
		insn->size = emit_gfx10_v_cmp_eq_u32(&insn->gfx10, dst, src);
		insn->type = AMDGCN_INSN_TYPE_VOPC;
	} else if (version == 9) {
		insn->size = emit_gfx9_v_cmp_eq_u32(&insn->gfx9, dst, src);
		insn->type = AMDGCN_INSN_TYPE_VOPC;
	} else {
		WARN_ON(1);
	}
}

static inline void emit_v_cmp_gt_u64(int version, struct amdgcn_insn *insn,
			      struct amdgcn_param64 dst,
			      struct amdgcn_param64 src)
{
	WARN_ON_ONCE(dst.lo.type == AMDGCN_PARAM_TYPE_LITERAL_CONST);
	if (version == 10) {
		insn->size = emit_gfx10_v_cmp_gt_u64(&insn->gfx10, dst, src);
		insn->type = AMDGCN_INSN_TYPE_VOPC;
	} else if (version == 9) {
		insn->size = emit_gfx9_v_cmp_gt_u64(&insn->gfx9, dst, src);
		insn->type = AMDGCN_INSN_TYPE_VOPC;
	} else {
		WARN_ON(1);
	}
}

static inline void emit_v_cmp_gt_i64(int version, struct amdgcn_insn *insn,
			      struct amdgcn_param64 dst,
			      struct amdgcn_param64 src)
{
	WARN_ON_ONCE(dst.lo.type == AMDGCN_PARAM_TYPE_LITERAL_CONST);
	if (version == 10) {
		insn->size = emit_gfx10_v_cmp_gt_i64(&insn->gfx10, dst, src);
		insn->type = AMDGCN_INSN_TYPE_VOPC;
	} else if (version == 9) {
		insn->size = emit_gfx9_v_cmp_gt_i64(&insn->gfx9, dst, src);
		insn->type = AMDGCN_INSN_TYPE_VOPC;
	} else {
		WARN_ON(1);
	}
}

static inline void emit_v_cmp_ge_u32(int version, struct amdgcn_insn *insn,
			      struct amdgcn_param32 dst,
			      struct amdgcn_param32 src)
{
	WARN_ON_ONCE(dst.type == AMDGCN_PARAM_TYPE_LITERAL_CONST);
	if (version == 10) {
		insn->size = emit_gfx10_v_cmp_ge_u32(&insn->gfx10, dst, src);
		insn->type = AMDGCN_INSN_TYPE_VOPC;
	} else if (version == 9) {
		insn->size = emit_gfx9_v_cmp_ge_u32(&insn->gfx9, dst, src);
		insn->type = AMDGCN_INSN_TYPE_VOPC;
	} else {
		WARN_ON(1);
	}
}

static inline void emit_v_cmp_gt_u32(int version, struct amdgcn_insn *insn,
			      struct amdgcn_param32 dst,
			      struct amdgcn_param32 src)
{
	WARN_ON_ONCE(dst.type == AMDGCN_PARAM_TYPE_LITERAL_CONST);
	WARN_ON(src.type != AMDGCN_PARAM_TYPE_VGPR);
	if (version == 10) {
		insn->size = emit_gfx10_v_cmp_gt_u32(&insn->gfx10, dst, src);
		insn->type = AMDGCN_INSN_TYPE_VOPC;
	} else if (version == 9) {
		insn->size = emit_gfx9_v_cmp_gt_u32(&insn->gfx9, dst, src);
		insn->type = AMDGCN_INSN_TYPE_VOPC;
	} else {
		WARN_ON(1);
	}
}

static inline void emit_v_cmp_lt_u32(int version, struct amdgcn_insn *insn,
			      struct amdgcn_param32 dst,
			      struct amdgcn_param32 src)
{
	WARN_ON_ONCE(dst.type == AMDGCN_PARAM_TYPE_LITERAL_CONST);
	WARN_ON(src.type != AMDGCN_PARAM_TYPE_VGPR);
	if (version == 10) {
		insn->size = emit_gfx10_v_cmp_lt_u32(&insn->gfx10, dst, src);
		insn->type = AMDGCN_INSN_TYPE_VOPC;
	} else if (version == 9) {
		insn->size = emit_gfx9_v_cmp_lt_u32(&insn->gfx9, dst, src);
		insn->type = AMDGCN_INSN_TYPE_VOPC;
	} else {
		WARN_ON(1);
	}
}

static inline void emit_v_cmp_le_u32(int version, struct amdgcn_insn *insn,
			      struct amdgcn_param32 dst,
			      struct amdgcn_param32 src)
{
	WARN_ON_ONCE(dst.type == AMDGCN_PARAM_TYPE_LITERAL_CONST);
	WARN_ON(src.type != AMDGCN_PARAM_TYPE_VGPR);
	if (version == 10) {
		insn->size = emit_gfx10_v_cmp_le_u32(&insn->gfx10, dst, src);
		insn->type = AMDGCN_INSN_TYPE_VOPC;
	} else if (version == 9) {
		insn->size = emit_gfx9_v_cmp_le_u32(&insn->gfx9, dst, src);
		insn->type = AMDGCN_INSN_TYPE_VOPC;
	} else {
		WARN_ON(1);
	}
}

static inline void emit_v_cmp_gt_i32(int version, struct amdgcn_insn *insn,
			      struct amdgcn_param32 dst,
			      struct amdgcn_param32 src)
{
	WARN_ON_ONCE(dst.type == AMDGCN_PARAM_TYPE_LITERAL_CONST);
	WARN_ON(src.type != AMDGCN_PARAM_TYPE_VGPR);
	if (version == 10) {
		insn->size = emit_gfx10_v_cmp_gt_i32(&insn->gfx10, dst, src);
		insn->type = AMDGCN_INSN_TYPE_VOPC;
	} else if (version == 9) {
		insn->size = emit_gfx9_v_cmp_gt_i32(&insn->gfx9, dst, src);
		insn->type = AMDGCN_INSN_TYPE_VOPC;
	} else {
		WARN_ON(1);
	}
}

static inline void emit_v_cmp_ge_i32(int version, struct amdgcn_insn *insn,
			      struct amdgcn_param32 dst,
			      struct amdgcn_param32 src)
{
	WARN_ON_ONCE(dst.type == AMDGCN_PARAM_TYPE_LITERAL_CONST);
	WARN_ON(src.type != AMDGCN_PARAM_TYPE_VGPR);
	if (version == 10) {
		insn->size = emit_gfx10_v_cmp_ge_i32(&insn->gfx10, dst, src);
		insn->type = AMDGCN_INSN_TYPE_VOPC;
	} else if (version == 9) {
		insn->size = emit_gfx9_v_cmp_ge_i32(&insn->gfx9, dst, src);
		insn->type = AMDGCN_INSN_TYPE_VOPC;
	} else {
		WARN_ON(1);
	}
}

static inline void emit_v_cmp_lt_i32(int version, struct amdgcn_insn *insn,
			      struct amdgcn_param32 dst,
			      struct amdgcn_param32 src)
{
	WARN_ON_ONCE(dst.type == AMDGCN_PARAM_TYPE_LITERAL_CONST);
	WARN_ON(src.type != AMDGCN_PARAM_TYPE_VGPR);
	if (version == 10) {
		insn->size = emit_gfx10_v_cmp_lt_i32(&insn->gfx10, dst, src);
		insn->type = AMDGCN_INSN_TYPE_VOPC;
	} else if (version == 9) {
		insn->size = emit_gfx9_v_cmp_lt_i32(&insn->gfx9, dst, src);
		insn->type = AMDGCN_INSN_TYPE_VOPC;
	} else {
		WARN_ON(1);
	}
}

static inline void emit_v_cmp_le_i32(int version, struct amdgcn_insn *insn,
			      struct amdgcn_param32 dst,
			      struct amdgcn_param32 src)
{
	WARN_ON_ONCE(dst.type == AMDGCN_PARAM_TYPE_LITERAL_CONST);
	WARN_ON(src.type != AMDGCN_PARAM_TYPE_VGPR);
	if (version == 10) {
		insn->size = emit_gfx10_v_cmp_le_i32(&insn->gfx10, dst, src);
		insn->type = AMDGCN_INSN_TYPE_VOPC;
	} else if (version == 9) {
		insn->size = emit_gfx9_v_cmp_le_i32(&insn->gfx9, dst, src);
		insn->type = AMDGCN_INSN_TYPE_VOPC;
	} else {
		WARN_ON(1);
	}
}

/* EXEC &= (src0 < src1), per-lane mask update */
static inline void emit_v_cmpx_lt_u32(int version, struct amdgcn_insn *insn,
				struct amdgcn_param32 dst,
				struct amdgcn_param32 src)
{
	WARN_ON_ONCE(dst.type == AMDGCN_PARAM_TYPE_LITERAL_CONST);
	if (version == 10) {
		insn->size = emit_gfx10_v_cmpx_lt_u32(&insn->gfx10, dst, src);
		insn->type = AMDGCN_INSN_TYPE_VOPC;
	} else if (version == 9) {
		insn->size = emit_gfx9_v_cmpx_lt_u32(&insn->gfx9, dst, src);
		insn->type = AMDGCN_INSN_TYPE_VOPC;
	} else {
		WARN_ON(1);
	}
}

static inline void emit_v_cmp_ge_u64(int version, struct amdgcn_insn *insn,
			      struct amdgcn_param64 dst,
			      struct amdgcn_param64 src)
{
	WARN_ON_ONCE(dst.lo.type == AMDGCN_PARAM_TYPE_LITERAL_CONST);
	if (version == 10) {
		insn->size = emit_gfx10_v_cmp_ge_u64(&insn->gfx10, dst, src);
		insn->type = AMDGCN_INSN_TYPE_VOPC;
	} else if (version == 9) {
		insn->size = emit_gfx9_v_cmp_ge_u64(&insn->gfx9, dst, src);
		insn->type = AMDGCN_INSN_TYPE_VOPC;
	} else {
		WARN_ON(1);
	}
}

static inline void emit_v_cmp_ge_i64(int version, struct amdgcn_insn *insn,
			      struct amdgcn_param64 dst,
			      struct amdgcn_param64 src)
{
	WARN_ON_ONCE(dst.lo.type == AMDGCN_PARAM_TYPE_LITERAL_CONST);
	if (version == 10) {
		insn->size = emit_gfx10_v_cmp_ge_i64(&insn->gfx10, dst, src);
		insn->type = AMDGCN_INSN_TYPE_VOPC;
	} else if (version == 9) {
		insn->size = emit_gfx9_v_cmp_ge_i64(&insn->gfx9, dst, src);
		insn->type = AMDGCN_INSN_TYPE_VOPC;
	} else {
		WARN_ON(1);
	}
}

static inline void emit_v_cmp_lt_u64(int version, struct amdgcn_insn *insn,
			      struct amdgcn_param64 dst,
			      struct amdgcn_param64 src)
{
	WARN_ON_ONCE(dst.lo.type == AMDGCN_PARAM_TYPE_LITERAL_CONST);
	if (version == 10) {
		insn->size = emit_gfx10_v_cmp_lt_u64(&insn->gfx10, dst, src);
		insn->type = AMDGCN_INSN_TYPE_VOPC;
	} else if (version == 9) {
		insn->size = emit_gfx9_v_cmp_lt_u64(&insn->gfx9, dst, src);
		insn->type = AMDGCN_INSN_TYPE_VOPC;
	} else {
		WARN_ON(1);
	}
}

static inline void emit_v_cmp_lt_i64(int version, struct amdgcn_insn *insn,
			      struct amdgcn_param64 dst,
			      struct amdgcn_param64 src)
{
	WARN_ON_ONCE(dst.lo.type == AMDGCN_PARAM_TYPE_LITERAL_CONST);
	if (version == 10) {
		insn->size = emit_gfx10_v_cmp_lt_i64(&insn->gfx10, dst, src);
		insn->type = AMDGCN_INSN_TYPE_VOPC;
	} else if (version == 9) {
		insn->size = emit_gfx9_v_cmp_lt_i64(&insn->gfx9, dst, src);
		insn->type = AMDGCN_INSN_TYPE_VOPC;
	} else {
		WARN_ON(1);
	}
}

static inline void emit_v_cmp_le_u64(int version, struct amdgcn_insn *insn,
			      struct amdgcn_param64 dst,
			      struct amdgcn_param64 src)
{
	WARN_ON_ONCE(dst.lo.type == AMDGCN_PARAM_TYPE_LITERAL_CONST);
	if (version == 10) {
		insn->size = emit_gfx10_v_cmp_le_u64(&insn->gfx10, dst, src);
		insn->type = AMDGCN_INSN_TYPE_VOPC;
	} else if (version == 9) {
		insn->size = emit_gfx9_v_cmp_le_u64(&insn->gfx9, dst, src);
		insn->type = AMDGCN_INSN_TYPE_VOPC;
	} else {
		WARN_ON(1);
	}
}

static inline void emit_v_cmp_le_i64(int version, struct amdgcn_insn *insn,
			      struct amdgcn_param64 dst,
			      struct amdgcn_param64 src)
{
	WARN_ON_ONCE(dst.lo.type == AMDGCN_PARAM_TYPE_LITERAL_CONST);
	if (version == 10) {
		insn->size = emit_gfx10_v_cmp_le_i64(&insn->gfx10, dst, src);
		insn->type = AMDGCN_INSN_TYPE_VOPC;
	} else if (version == 9) {
		insn->size = emit_gfx9_v_cmp_le_i64(&insn->gfx9, dst, src);
		insn->type = AMDGCN_INSN_TYPE_VOPC;
	} else {
		WARN_ON(1);
	}
}

static inline void emit_buffer_load_ubyte(int version, struct amdgcn_insn *insn,
				   struct amdgcn_param32 dst,
				   struct amdgcn_param32 src,
				   short off)
{
	if (version == 10) {
		insn->size = emit_gfx10_buffer_load_ubyte(&insn->gfx10,
							  dst, src, off);
		insn->type = AMDGCN_INSN_TYPE_MUBUF;
	} else if (version == 9) {
		insn->size = emit_gfx9_buffer_load_ubyte(&insn->gfx9,
							  dst, src, off);
		insn->type = AMDGCN_INSN_TYPE_MUBUF;
	} else {
		WARN_ON(1);
	}
}

static inline void emit_buffer_load_ushort(int version,
				    struct amdgcn_insn *insn,
				    struct amdgcn_param32 dst,
				    struct amdgcn_param32 src,
				    short off)
{
	if (version == 10) {
		insn->size = emit_gfx10_buffer_load_ushort(&insn->gfx10,
							   dst, src, off);
		insn->type = AMDGCN_INSN_TYPE_MUBUF;
	} else if (version == 9) {
		insn->size = emit_gfx9_buffer_load_ushort(&insn->gfx9,
							  dst, src, off);
		insn->type = AMDGCN_INSN_TYPE_MUBUF;
	} else {
		WARN_ON(1);
	}
}

static inline void emit_buffer_load_dword(int version, struct amdgcn_insn *insn,
				   struct amdgcn_param32 dst,
				   struct amdgcn_param32 src,
				   short off)
{
	if (version == 10) {
		insn->size = emit_gfx10_buffer_load_dword(&insn->gfx10,
							  dst, src, off);
		insn->type = AMDGCN_INSN_TYPE_MUBUF;
	} else if (version == 9) {
		insn->size = emit_gfx9_buffer_load_dword(&insn->gfx9,
							 dst, src, off);
		insn->type = AMDGCN_INSN_TYPE_MUBUF;
	} else {
		WARN_ON(1);
	}
}

static inline void emit_buffer_load_dwordx2(int version,
				     struct amdgcn_insn *insn,
				     struct amdgcn_param32 dst,
				     struct amdgcn_param32 src,
				     short off)
{
	if (version == 10) {
		insn->size = emit_gfx10_buffer_load_dwordx2(&insn->gfx10,
							    dst, src, off);
		insn->type = AMDGCN_INSN_TYPE_MUBUF;
	} else if (version == 9) {
		insn->size = emit_gfx9_buffer_load_dwordx2(&insn->gfx9,
							   dst, src, off);
		insn->type = AMDGCN_INSN_TYPE_MUBUF;
	} else {
		WARN_ON(1);
	}
}

static inline void emit_buffer_load_dwordx4(int version,
				     struct amdgcn_insn *insn,
				     struct amdgcn_param32 dst,
				     struct amdgcn_param32 src,
				     short off)
{
	if (version == 10) {
		insn->size = emit_gfx10_buffer_load_dwordx4(&insn->gfx10,
							    dst, src, off);
		insn->type = AMDGCN_INSN_TYPE_MUBUF;
	} else if (version == 9) {
		insn->size = emit_gfx9_buffer_load_dwordx4(&insn->gfx9,
							   dst, src, off);
		insn->type = AMDGCN_INSN_TYPE_MUBUF;
	} else {
		WARN_ON(1);
	}
}

static inline void emit_global_load_ubyte(int version, struct amdgcn_insn *insn,
				   struct amdgcn_param32 dst,
				   struct amdgcn_param32 src,
				   short off)
{
	if (version == 10) {
		insn->size = emit_gfx10_global_load_ubyte(&insn->gfx10,
							  dst, src, off);
		insn->type = AMDGCN_INSN_TYPE_FLAT;
	} else if (version == 9) {
		insn->size = emit_gfx9_global_load_ubyte(&insn->gfx9,
							 dst, src, off);
		insn->type = AMDGCN_INSN_TYPE_FLAT;
	} else {
		WARN_ON(1);
	}
}

static inline void emit_global_load_ushort(int version,
				    struct amdgcn_insn *insn,
				    struct amdgcn_param32 dst,
				    struct amdgcn_param32 src,
				    short off)
{
	if (version == 10) {
		insn->size = emit_gfx10_global_load_ushort(&insn->gfx10,
							   dst, src, off);
		insn->type = AMDGCN_INSN_TYPE_FLAT;
	} else if (version == 9) {
		insn->size = emit_gfx9_global_load_ushort(&insn->gfx9,
							  dst, src, off);
		insn->type = AMDGCN_INSN_TYPE_FLAT;
	} else {
		WARN_ON(1);
	}
}

static inline void emit_global_load_dword(int version, struct amdgcn_insn *insn,
				   struct amdgcn_param32 dst,
				   struct amdgcn_param32 src,
				   short off)
{
	WARN_ON(dst.type != AMDGCN_PARAM_TYPE_VGPR);
	WARN_ON(src.type != AMDGCN_PARAM_TYPE_VGPR);
	if (version == 10) {
		insn->size = emit_gfx10_global_load_dword(&insn->gfx10,
							  dst, src, off);
		insn->type = AMDGCN_INSN_TYPE_FLAT;
	} else if (version == 9) {
		insn->size = emit_gfx9_global_load_dword(&insn->gfx9,
							 dst, src, off);
		insn->type = AMDGCN_INSN_TYPE_FLAT;
	} else {
		WARN_ON(1);
	}
}

static inline void emit_global_load_dwordx2(int version,
				     struct amdgcn_insn *insn,
				     struct amdgcn_param32 dst,
				     struct amdgcn_param32 src,
				     short off)
{
	if (version == 10) {
		insn->size = emit_gfx10_global_load_dwordx2(&insn->gfx10,
							    dst, src, off);
		insn->type = AMDGCN_INSN_TYPE_FLAT;
	} else if (version == 9) {
		insn->size = emit_gfx9_global_load_dwordx2(&insn->gfx9,
							   dst, src, off);
		insn->type = AMDGCN_INSN_TYPE_FLAT;
	} else {
		WARN_ON(1);
	}
}

static inline void emit_global_load_dwordx4(int version,
				     struct amdgcn_insn *insn,
				     struct amdgcn_param32 dst,
				     struct amdgcn_param32 src,
				     short off)
{
	if (version == 10) {
		insn->size = emit_gfx10_global_load_dwordx4(&insn->gfx10,
							    dst, src, off);
		insn->type = AMDGCN_INSN_TYPE_FLAT;
	} else if (version == 9) {
		insn->size = emit_gfx9_global_load_dwordx4(&insn->gfx9,
							   dst, src, off);
		insn->type = AMDGCN_INSN_TYPE_FLAT;
	} else {
		WARN_ON(1);
	}
}

static inline void emit_global_store_byte(int version, struct amdgcn_insn *insn,
				   struct amdgcn_param32 dst,
				   struct amdgcn_param32 src, int off)
{
	if (version == 10) {
		insn->size = emit_gfx10_global_store_byte(&insn->gfx10,
							  src, dst, off);
		insn->type = AMDGCN_INSN_TYPE_FLAT;
	} else if (version == 9) {
		insn->size = emit_gfx9_global_store_byte(&insn->gfx9,
							 src, dst, off);
		insn->type = AMDGCN_INSN_TYPE_FLAT;
	} else {
		WARN_ON(1);
	}
}

#define DEFINE_EMIT_GLOBAL_ATOMIC(name)					\
static inline void emit_global_atomic_##name(int version,		\
				      struct amdgcn_insn *insn,		\
				      struct amdgcn_param32 vdst,	\
				      struct amdgcn_param32 addr,	\
				      struct amdgcn_param32 data,	\
				      int off, int glc)			\
{									\
	if (version == 10) {						\
		insn->size = emit_gfx10_global_atomic_##name(		\
			&insn->gfx10, vdst, addr, data, off, glc);	\
		insn->type = AMDGCN_INSN_TYPE_FLAT;			\
	} else if (version == 9) {					\
		insn->size = emit_gfx9_global_atomic_##name(		\
			&insn->gfx9, vdst, addr, data, off, glc);	\
		insn->type = AMDGCN_INSN_TYPE_FLAT;			\
	} else {							\
		WARN_ON(1);						\
	}								\
}

DEFINE_EMIT_GLOBAL_ATOMIC(add)
DEFINE_EMIT_GLOBAL_ATOMIC(and)
DEFINE_EMIT_GLOBAL_ATOMIC(or)
DEFINE_EMIT_GLOBAL_ATOMIC(xor)
DEFINE_EMIT_GLOBAL_ATOMIC(swap)
DEFINE_EMIT_GLOBAL_ATOMIC(cmpswap)
DEFINE_EMIT_GLOBAL_ATOMIC(add_x2)
DEFINE_EMIT_GLOBAL_ATOMIC(and_x2)
DEFINE_EMIT_GLOBAL_ATOMIC(or_x2)
DEFINE_EMIT_GLOBAL_ATOMIC(xor_x2)
DEFINE_EMIT_GLOBAL_ATOMIC(swap_x2)
DEFINE_EMIT_GLOBAL_ATOMIC(cmpswap_x2)

static inline void emit_global_store_short(int version,
				    struct amdgcn_insn *insn,
				    struct amdgcn_param32 dst,
				    struct amdgcn_param32 src, int off)
{
	if (version == 10) {
		insn->size = emit_gfx10_global_store_short(&insn->gfx10,
							   src, dst, off);
		insn->type = AMDGCN_INSN_TYPE_FLAT;
	} else if (version == 9) {
		insn->size = emit_gfx9_global_store_short(&insn->gfx9,
							  src, dst, off);
		insn->type = AMDGCN_INSN_TYPE_FLAT;
	} else {
		WARN_ON(1);
	}
}

static inline void emit_global_store_dword(int version,
				    struct amdgcn_insn *insn,
				    struct amdgcn_param32 dst,
				    struct amdgcn_param32 src, int off)
{
	if (version == 10) {
		insn->size = emit_gfx10_global_store_dword(&insn->gfx10,
							   src, dst, off);
		insn->type = AMDGCN_INSN_TYPE_FLAT;
	} else if (version == 9) {
		insn->size = emit_gfx9_global_store_dword(&insn->gfx9,
							  src, dst, off);
		insn->type = AMDGCN_INSN_TYPE_FLAT;
	} else {
		WARN_ON(1);
	}
}

static inline void emit_global_store_dwordx2(int version,
				      struct amdgcn_insn *insn,
				      struct amdgcn_param32 dst,
				      struct amdgcn_param32 src, int off)
{
	if (version == 10) {
		insn->size = emit_gfx10_global_store_dwordx2(&insn->gfx10,
							     src, dst, off);
		insn->type = AMDGCN_INSN_TYPE_FLAT;
	} else if (version == 9) {
		insn->size = emit_gfx9_global_store_dwordx2(&insn->gfx9,
							    src, dst, off);
		insn->type = AMDGCN_INSN_TYPE_FLAT;
	} else {
		WARN_ON(1);
	}
}

static inline void emit_global_store_dwordx4(int version,
				      struct amdgcn_insn *insn,
				      struct amdgcn_param32 dst,
				      struct amdgcn_param32 src, int off)
{
	if (version == 10) {
		insn->size = emit_gfx10_global_store_dwordx4(&insn->gfx10,
							     src, dst, off);
		insn->type = AMDGCN_INSN_TYPE_FLAT;
	} else if (version == 9) {
		insn->size = emit_gfx9_global_store_dwordx4(&insn->gfx9,
							    src, dst, off);
		insn->type = AMDGCN_INSN_TYPE_FLAT;
	} else {
		WARN_ON(1);
	}
}

static inline void emit_s_branch(int version, struct amdgcn_insn *insn,
				 short off)
{
	if (version == 10) {
		insn->size = emit_gfx10_s_branch(&insn->gfx10, off);
		insn->type = AMDGCN_INSN_TYPE_SOPP;
	} else if (version == 9) {
		insn->size = emit_gfx9_s_branch(&insn->gfx9, off);
		insn->type = AMDGCN_INSN_TYPE_SOPP;
	} else {
		WARN_ON(1);
	}
}

static inline void emit_s_cbranch_vccz(int version, struct amdgcn_insn *insn,
				       short off)
{
	if (version == 10) {
		insn->size = emit_gfx10_s_cbranch_vccz(&insn->gfx10, off);
		insn->type = AMDGCN_INSN_TYPE_SOPP;
	} else if (version == 9) {
		insn->size = emit_gfx9_s_cbranch_vccz(&insn->gfx9, off);
		insn->type = AMDGCN_INSN_TYPE_SOPP;
	} else {
		WARN_ON(1);
	}
}

static inline void emit_s_cbranch_vccnz(int version, struct amdgcn_insn *insn,
					short off)
{
	if (version == 10) {
		insn->size = emit_gfx10_s_cbranch_vccnz(&insn->gfx10, off);
		insn->type = AMDGCN_INSN_TYPE_SOPP;
	} else if (version == 9) {
		insn->size = emit_gfx9_s_cbranch_vccnz(&insn->gfx9, off);
		insn->type = AMDGCN_INSN_TYPE_SOPP;
	} else {
		WARN_ON(1);
	}
}

/* Structurized CFG wrapper functions.
 * Use raw SGPR indices; EXEC=126, VCC=106, integer_0=128.
 */

static inline void emit_s_and_saveexec_b64(int version,
				    struct amdgcn_insn *insn,
				    u8 sdst, u8 ssrc)
{
	if (version == 10) {
		insn->size = emit_gfx10_s_and_saveexec_b64(&insn->gfx10,
							    sdst, ssrc);
		insn->type = AMDGCN_INSN_TYPE_SOP1;
	} else if (version == 9) {
		insn->size = emit_gfx9_s_and_saveexec_b64(&insn->gfx9,
							   sdst, ssrc);
		insn->type = AMDGCN_INSN_TYPE_SOP1;
	} else {
		WARN_ON(1);
	}
}

static inline void emit_s_bcnt1_i32_b64(int version, struct amdgcn_insn *insn,
				 u8 sdst, u8 ssrc)
{
	if (version == 10) {
		insn->size = emit_gfx10_s_bcnt1_i32_b64(&insn->gfx10,
							 sdst, ssrc);
		insn->type = AMDGCN_INSN_TYPE_SOP1;
	} else if (version == 9) {
		insn->size = emit_gfx9_s_bcnt1_i32_b64(&insn->gfx9,
							sdst, ssrc);
		insn->type = AMDGCN_INSN_TYPE_SOP1;
	} else {
		WARN_ON(1);
	}
}

static inline void emit_s_mov_b64(int version, struct amdgcn_insn *insn,
			   u8 sdst, u8 ssrc)
{
	if (version == 10) {
		insn->size = emit_gfx10_s_mov_b64(&insn->gfx10, sdst, ssrc);
		insn->type = AMDGCN_INSN_TYPE_SOP1;
	} else if (version == 9) {
		insn->size = emit_gfx9_s_mov_b64(&insn->gfx9, sdst, ssrc);
		insn->type = AMDGCN_INSN_TYPE_SOP1;
	} else {
		WARN_ON(1);
	}
}

static inline void emit_s_and_b64(int version, struct amdgcn_insn *insn,
			   u8 sdst, u8 ssrc0, u8 ssrc1)
{
	if (version == 10) {
		insn->size = emit_gfx10_s_and_b64(&insn->gfx10,
						   sdst, ssrc0, ssrc1);
		insn->type = AMDGCN_INSN_TYPE_SOP2;
	} else if (version == 9) {
		insn->size = emit_gfx9_s_and_b64(&insn->gfx9,
						  sdst, ssrc0, ssrc1);
		insn->type = AMDGCN_INSN_TYPE_SOP2;
	} else {
		WARN_ON(1);
	}
}

static inline void emit_s_or_b64(int version, struct amdgcn_insn *insn,
			  u8 sdst, u8 ssrc0, u8 ssrc1)
{
	if (version == 10) {
		insn->size = emit_gfx10_s_or_b64(&insn->gfx10,
						  sdst, ssrc0, ssrc1);
		insn->type = AMDGCN_INSN_TYPE_SOP2;
	} else if (version == 9) {
		insn->size = emit_gfx9_s_or_b64(&insn->gfx9,
						 sdst, ssrc0, ssrc1);
		insn->type = AMDGCN_INSN_TYPE_SOP2;
	} else {
		WARN_ON(1);
	}
}

static inline void emit_s_andn2_b64(int version, struct amdgcn_insn *insn,
			     u8 sdst, u8 ssrc0, u8 ssrc1)
{
	if (version == 10) {
		insn->size = emit_gfx10_s_andn2_b64(&insn->gfx10,
						     sdst, ssrc0, ssrc1);
		insn->type = AMDGCN_INSN_TYPE_SOP2;
	} else if (version == 9) {
		insn->size = emit_gfx9_s_andn2_b64(&insn->gfx9,
						    sdst, ssrc0, ssrc1);
		insn->type = AMDGCN_INSN_TYPE_SOP2;
	} else {
		WARN_ON(1);
	}
}

static inline void emit_s_cbranch_execz(int version, struct amdgcn_insn *insn,
				 short off)
{
	if (version == 10) {
		insn->size = emit_gfx10_s_cbranch_execz(&insn->gfx10, off);
		insn->type = AMDGCN_INSN_TYPE_SOPP;
	} else if (version == 9) {
		insn->size = emit_gfx9_s_cbranch_execz(&insn->gfx9, off);
		insn->type = AMDGCN_INSN_TYPE_SOPP;
	} else {
		WARN_ON(1);
	}
}

static inline void emit_s_cbranch_execnz(int version, struct amdgcn_insn *insn,
				  short off)
{
	if (version == 10) {
		insn->size = emit_gfx10_s_cbranch_execnz(&insn->gfx10, off);
		insn->type = AMDGCN_INSN_TYPE_SOPP;
	} else if (version == 9) {
		insn->size = emit_gfx9_s_cbranch_execnz(&insn->gfx9, off);
		insn->type = AMDGCN_INSN_TYPE_SOPP;
	} else {
		WARN_ON(1);
	}
}

static inline void emit_s_sub_u32(int version, struct amdgcn_insn *insn,
			   u8 sdst, u8 ssrc0, u8 ssrc1)
{
	if (version == 10) {
		insn->size = emit_gfx10_s_sub_u32(&insn->gfx10,
						   sdst, ssrc0, ssrc1);
		insn->type = AMDGCN_INSN_TYPE_SOP2;
	} else if (version == 9) {
		insn->size = emit_gfx9_s_sub_u32(&insn->gfx9,
						  sdst, ssrc0, ssrc1);
		insn->type = AMDGCN_INSN_TYPE_SOP2;
	} else {
		WARN_ON(1);
	}
}

static inline void emit_s_cbranch_scc0(int version, struct amdgcn_insn *insn,
				short off)
{
	if (version == 10) {
		insn->size = emit_gfx10_s_cbranch_scc0(&insn->gfx10, off);
		insn->type = AMDGCN_INSN_TYPE_SOPP;
	} else if (version == 9) {
		insn->size = emit_gfx9_s_cbranch_scc0(&insn->gfx9, off);
		insn->type = AMDGCN_INSN_TYPE_SOPP;
	} else {
		WARN_ON(1);
	}
}

static inline void emit_branch_fixup(int version, struct amdgcn_insn *insn,
				     short off)
{
	if (version == 10)
		insn->size = emit_gfx10_branch_fixup(&insn->gfx10, off);
	else if (version == 9)
		insn->size = emit_gfx9_branch_fixup(&insn->gfx9, off);
	else
		WARN_ON(1);
}

static inline void emit_s_waitcnt_lgkmcnt(int version, struct amdgcn_insn *insn)
{
	if (version == 10) {
		insn->size = emit_gfx10_s_waitcnt_lgkmcnt(&insn->gfx10);
		insn->type = AMDGCN_INSN_TYPE_SOPP;
	} else if (version == 9) {
		insn->size = emit_gfx9_s_waitcnt_lgkmcnt(&insn->gfx9);
		insn->type = AMDGCN_INSN_TYPE_SOPP;
	} else {
		WARN_ON(1);
	}
}

static inline void emit_s_waitcnt_vmcnt(int version, struct amdgcn_insn *insn)
{
	if (version == 10) {
		insn->size = emit_gfx10_s_waitcnt_vmcnt(&insn->gfx10);
		insn->type = AMDGCN_INSN_TYPE_SOPP;
	} else if (version == 9) {
		insn->size = emit_gfx9_s_waitcnt_vmcnt(&insn->gfx9);
		insn->type = AMDGCN_INSN_TYPE_SOPP;
	} else {
		WARN_ON(1);
	}
}

static inline void emit_s_waitcnt_vmcnt_lgkmcnt(int version,
						struct amdgcn_insn *insn)
{
	if (version == 10) {
		insn->size = emit_gfx10_s_waitcnt_vmcnt_lgkmcnt(&insn->gfx10);
		insn->type = AMDGCN_INSN_TYPE_SOPP;
	} else if (version == 9) {
		insn->size = emit_gfx9_s_waitcnt_vmcnt_lgkmcnt(&insn->gfx9);
		insn->type = AMDGCN_INSN_TYPE_SOPP;
	} else {
		WARN_ON(1);
	}
}

static inline void emit_s_nop(int version, struct amdgcn_insn *insn)
{
	if (version == 10) {
		insn->size = emit_gfx10_s_nop(&insn->gfx10);
		insn->type = AMDGCN_INSN_TYPE_SOPP;
	} else if (version == 9) {
		insn->size = emit_gfx9_s_nop(&insn->gfx9);
		insn->type = AMDGCN_INSN_TYPE_SOPP;
	} else {
		WARN_ON(1);
	}
}

static inline void emit_s_endpgm(int version, struct amdgcn_insn *insn)
{
	if (version == 10) {
		insn->size = emit_gfx10_s_endpgm(&insn->gfx10);
		insn->type = AMDGCN_INSN_TYPE_SOPP;
	} else if (version == 9) {
		insn->size = emit_gfx9_s_endpgm(&insn->gfx9);
		insn->type = AMDGCN_INSN_TYPE_SOPP;
	} else {
		WARN_ON(1);
	}
}

static inline void emit_s_code_end(int version, struct amdgcn_insn *insn)
{
	if (version == 10) {
		insn->size = emit_gfx10_s_code_end(&insn->gfx10);
		insn->type = AMDGCN_INSN_TYPE_SOPP;
	} else if (version == 9) {
		WARN_ON(1);
	} else {
		WARN_ON(1);
	}
}

static inline void emit_s_icache_inv(int version, struct amdgcn_insn *insn)
{
	if (version == 10) {
		insn->size = emit_gfx10_s_icache_inv(&insn->gfx10);
		insn->type = AMDGCN_INSN_TYPE_SOPP;
	} else if (version == 9) {
		insn->size = emit_gfx9_s_icache_inv(&insn->gfx9);
		insn->type = AMDGCN_INSN_TYPE_SOPP;
	} else {
		WARN_ON(1);
	}
}

static inline void gfx10_debug_vop3a(union amdgcn_gfx10_insn *insn)
{
	char src0[20];
	char src1[20];
	char src2[20];

	if (insn->vop3a.src0 < GFX10_VOP3A_SRC_VCC_LO)
		sprintf(src0, "s%d", insn->vop3a.src0);
	else if (insn->vop3a.src0 == GFX10_VOP3A_SRC_VCC_LO)
		sprintf(src0, "%s", "vcc_lo");
	else if (insn->vop3a.src0 == GFX10_VOP3A_SRC_VCC_HI)
		sprintf(src0, "%s", "vcc_hi");
	else if (insn->vop3a.src0 == GFX10_VOP3A_SRC_NULL)
		sprintf(src0, "%s", "null");
	else if (insn->vop3a.src0 == GFX10_VOP3A_SRC_EXEC_LO)
		sprintf(src0, "%s", "exec_lo");
	else if (insn->vop3a.src0 == GFX10_VOP3A_SRC_EXEC_HI)
		sprintf(src0, "%s", "exec_hi");
	else if (insn->vop3a.src0 < GFX10_VOP3A_SRC_INTEGER_MINUS_1)
		sprintf(src0, "0x%x",
			insn->vop3a.src0 - GFX10_VOP3A_SRC_INTEGER_0);
	else if (insn->vop3a.src0 < GFX10_VOP3A_SRC_SHARED_BASE)
		sprintf(src0, "-0x%x",
			insn->vop3a.src0 - GFX10_VOP3A_SRC_INTEGER_MINUS_1);
	else if (insn->vop3a.src0 == GFX10_VOP3A_SRC_VCCZ)
		sprintf(src0, "%s", "vcc");
	else if (insn->vop3a.src0 == GFX10_VOP3A_SRC_EXECZ)
		sprintf(src0, "%s", "exec");
	else if (insn->vop3a.src0 == GFX10_VOP3A_SRC_SCC)
		sprintf(src0, "%s", "scc");
	else if (insn->vop3a.src0 == GFX10_VOP3A_SRC_LITERAL_CONST)
		sprintf(src0, "0x%x", insn->vop3a.literal);
	else if (insn->vop3a.src0 >= GFX10_VOP3A_SRC_VGPR_BASE)
		sprintf(src0, "v%d",
			insn->vop3a.src0 - GFX10_VOP3A_SRC_VGPR_BASE);

	if (insn->vop3a.src1 < GFX10_VOP3A_SRC_VCC_LO)
		sprintf(src1, "s%d", insn->vop3a.src1);
	else if (insn->vop3a.src1 == GFX10_VOP3A_SRC_VCC_LO)
		sprintf(src1, "%s", "vcc_lo");
	else if (insn->vop3a.src1 == GFX10_VOP3A_SRC_VCC_HI)
		sprintf(src1, "%s", "vcc_hi");
	else if (insn->vop3a.src1 == GFX10_VOP3A_SRC_NULL)
		sprintf(src1, "%s", "null");
	else if (insn->vop3a.src1 == GFX10_VOP3A_SRC_EXEC_LO)
		sprintf(src1, "%s", "exec_lo");
	else if (insn->vop3a.src1 == GFX10_VOP3A_SRC_EXEC_HI)
		sprintf(src1, "%s", "exec_hi");
	else if (insn->vop3a.src1 < GFX10_VOP3A_SRC_INTEGER_MINUS_1)
		sprintf(src1, "0x%x",
			insn->vop3a.src1 - GFX10_VOP3A_SRC_INTEGER_0);
	else if (insn->vop3a.src1 < GFX10_VOP3A_SRC_SHARED_BASE)
		sprintf(src1, "-0x%x",
			insn->vop3a.src1 - GFX10_VOP3A_SRC_INTEGER_MINUS_1);
	else if (insn->vop3a.src1 == GFX10_VOP3A_SRC_VCCZ)
		sprintf(src1, "%s", "vcc");
	else if (insn->vop3a.src1 == GFX10_VOP3A_SRC_EXECZ)
		sprintf(src1, "%s", "exec");
	else if (insn->vop3a.src1 == GFX10_VOP3A_SRC_SCC)
		sprintf(src1, "%s", "scc");
	else if (insn->vop3a.src1 == GFX10_VOP3A_SRC_LITERAL_CONST)
		sprintf(src1, "0x%x", insn->vop3a.literal);
	else if (insn->vop3a.src1 >= GFX10_VOP3A_SRC_VGPR_BASE)
		sprintf(src1, "v%d",
			insn->vop3a.src1 - GFX10_VOP3A_SRC_VGPR_BASE);

	if (insn->vop3a.src2 < GFX10_VOP3A_SRC_VCC_LO)
		sprintf(src2, "s%d", insn->vop3a.src2);
	else if (insn->vop3a.src2 == GFX10_VOP3A_SRC_VCC_LO)
		sprintf(src2, "%s", "vcc_lo");
	else if (insn->vop3a.src2 == GFX10_VOP3A_SRC_VCC_HI)
		sprintf(src2, "%s", "vcc_hi");
	else if (insn->vop3a.src2 == GFX10_VOP3A_SRC_NULL)
		sprintf(src2, "%s", "null");
	else if (insn->vop3a.src2 == GFX10_VOP3A_SRC_EXEC_LO)
		sprintf(src2, "%s", "exec_lo");
	else if (insn->vop3a.src2 == GFX10_VOP3A_SRC_EXEC_HI)
		sprintf(src2, "%s", "exec_hi");
	else if (insn->vop3a.src2 < GFX10_VOP3A_SRC_INTEGER_MINUS_1)
		sprintf(src2, "0x%x",
			insn->vop3a.src2 - GFX10_VOP3A_SRC_INTEGER_0);
	else if (insn->vop3a.src2 < GFX10_VOP3A_SRC_SHARED_BASE)
		sprintf(src2, "-0x%x",
			insn->vop3a.src2 - GFX10_VOP3A_SRC_INTEGER_MINUS_1);
	else if (insn->vop3a.src2 == GFX10_VOP3A_SRC_VCCZ)
		sprintf(src2, "%s", "vcc");
	else if (insn->vop3a.src2 == GFX10_VOP3A_SRC_EXECZ)
		sprintf(src2, "%s", "exec");
	else if (insn->vop3a.src2 == GFX10_VOP3A_SRC_SCC)
		sprintf(src2, "%s", "scc");
	else if (insn->vop3a.src2 == GFX10_VOP3A_SRC_LITERAL_CONST)
		sprintf(src2, "0x%x", insn->vop3a.literal);
	else if (insn->vop3a.src2 >= GFX10_VOP3A_SRC_VGPR_BASE)
		sprintf(src2, "v%d",
			insn->vop3a.src2 - GFX10_VOP3A_SRC_VGPR_BASE);

	pr_debug("knod_asm %s v%d, %s, %s, %s\n",
		opnames_gfx10[AMDGCN_INSN_TYPE_VOP3A][insn->vop3a.op],
		insn->vop3a.vdst, src0, src1, src2);
}

static inline void gfx10_debug_vop3b(union amdgcn_gfx10_insn *insn)
{
	char src0[20];
	char src1[20];
	char src2[20];
	char sdst[20];

	if (insn->vop3b.sdst < GFX10_VOP3A_SRC_VCC_LO)
		sprintf(sdst, "s%d", insn->vop3b.sdst);
	else if (insn->vop3b.sdst == GFX10_VOP3A_SRC_VCC_LO)
		sprintf(sdst, "%s", "vcc_lo");
	else if (insn->vop3b.sdst == GFX10_VOP3A_SRC_VCC_HI)
		sprintf(sdst, "%s", "vcc_hi");
	else if (insn->vop3b.sdst == GFX10_VOP3A_SRC_NULL)
		sprintf(sdst, "%s", "null");
	else if (insn->vop3b.sdst == GFX10_VOP3A_SRC_EXEC_LO)
		sprintf(sdst, "%s", "exec_lo");
	else if (insn->vop3b.sdst == GFX10_VOP3A_SRC_EXEC_HI)
		sprintf(sdst, "%s", "exec_hi");
	else if (insn->vop3b.sdst < GFX10_VOP3A_SRC_INTEGER_MINUS_1)
		sprintf(sdst, "0x%x",
			insn->vop3b.sdst - GFX10_VOP3A_SRC_INTEGER_0);
	else if (insn->vop3b.sdst < GFX10_VOP3A_SRC_SHARED_BASE)
		sprintf(sdst, "-0x%x",
			insn->vop3b.sdst - GFX10_VOP3A_SRC_INTEGER_MINUS_1);
	else if (insn->vop3b.sdst == GFX10_VOP3A_SRC_VCCZ)
		sprintf(sdst, "%s", "vcc");
	else if (insn->vop3b.sdst == GFX10_VOP3A_SRC_EXECZ)
		sprintf(sdst, "%s", "exec");
	else if (insn->vop3b.sdst == GFX10_VOP3A_SRC_SCC)
		sprintf(sdst, "%s", "scc");
	else if (insn->vop3b.sdst == GFX10_VOP3A_SRC_LITERAL_CONST)
		sprintf(sdst, "0x%x", insn->vop3b.literal);
	else if (insn->vop3b.sdst >= GFX10_VOP3A_SRC_VGPR_BASE)
		sprintf(sdst, "v%d",
			insn->vop3b.sdst - GFX10_VOP3A_SRC_VGPR_BASE);

	if (insn->vop3b.src0 < GFX10_VOP3A_SRC_VCC_LO)
		sprintf(src0, "s%d", insn->vop3b.src0);
	else if (insn->vop3b.src0 == GFX10_VOP3A_SRC_VCC_LO)
		sprintf(src0, "%s", "vcc_lo");
	else if (insn->vop3b.src0 == GFX10_VOP3A_SRC_VCC_HI)
		sprintf(src0, "%s", "vcc_hi");
	else if (insn->vop3b.src0 == GFX10_VOP3A_SRC_NULL)
		sprintf(src0, "%s", "null");
	else if (insn->vop3b.src0 == GFX10_VOP3A_SRC_EXEC_LO)
		sprintf(src0, "%s", "exec_lo");
	else if (insn->vop3b.src0 == GFX10_VOP3A_SRC_EXEC_HI)
		sprintf(src0, "%s", "exec_hi");
	else if (insn->vop3b.src0 < GFX10_VOP3A_SRC_INTEGER_MINUS_1)
		sprintf(src0, "0x%x",
			insn->vop3b.src0 - GFX10_VOP3A_SRC_INTEGER_0);
	else if (insn->vop3b.src0 < GFX10_VOP3A_SRC_SHARED_BASE)
		sprintf(src0, "-0x%x",
			insn->vop3b.src0 - GFX10_VOP3A_SRC_INTEGER_MINUS_1);
	else if (insn->vop3b.src0 == GFX10_VOP3A_SRC_VCCZ)
		sprintf(src0, "%s", "vcc");
	else if (insn->vop3b.src0 == GFX10_VOP3A_SRC_EXECZ)
		sprintf(src0, "%s", "exec");
	else if (insn->vop3b.src0 == GFX10_VOP3A_SRC_SCC)
		sprintf(src0, "%s", "scc");
	else if (insn->vop3b.src0 == GFX10_VOP3A_SRC_LITERAL_CONST)
		sprintf(src0, "0x%x", insn->vop3b.literal);
	else if (insn->vop3b.src0 >= GFX10_VOP3A_SRC_VGPR_BASE)
		sprintf(src0, "v%d",
			insn->vop3b.src0 - GFX10_VOP3A_SRC_VGPR_BASE);

	if (insn->vop3b.src1 < GFX10_VOP3A_SRC_VCC_LO)
		sprintf(src1, "s%d", insn->vop3b.src1);
	else if (insn->vop3b.src1 == GFX10_VOP3A_SRC_VCC_LO)
		sprintf(src1, "%s", "vcc_lo");
	else if (insn->vop3b.src1 == GFX10_VOP3A_SRC_VCC_HI)
		sprintf(src1, "%s", "vcc_hi");
	else if (insn->vop3b.src1 == GFX10_VOP3A_SRC_NULL)
		sprintf(src1, "%s", "null");
	else if (insn->vop3b.src1 == GFX10_VOP3A_SRC_EXEC_LO)
		sprintf(src1, "%s", "exec_lo");
	else if (insn->vop3b.src1 == GFX10_VOP3A_SRC_EXEC_HI)
		sprintf(src1, "%s", "exec_hi");
	else if (insn->vop3b.src1 < GFX10_VOP3A_SRC_INTEGER_MINUS_1)
		sprintf(src1, "0x%x",
			insn->vop3b.src1 - GFX10_VOP3A_SRC_INTEGER_0);
	else if (insn->vop3b.src1 < GFX10_VOP3A_SRC_SHARED_BASE)
		sprintf(src1, "-0x%x",
			insn->vop3b.src1 - GFX10_VOP3A_SRC_INTEGER_MINUS_1);
	else if (insn->vop3b.src1 == GFX10_VOP3A_SRC_VCCZ)
		sprintf(src1, "%s", "vcc");
	else if (insn->vop3b.src1 == GFX10_VOP3A_SRC_EXECZ)
		sprintf(src1, "%s", "exec");
	else if (insn->vop3b.src1 == GFX10_VOP3A_SRC_SCC)
		sprintf(src1, "%s", "scc");
	else if (insn->vop3b.src1 == GFX10_VOP3A_SRC_LITERAL_CONST)
		sprintf(src1, "0x%x", insn->vop3b.literal);
	else if (insn->vop3b.src1 >= GFX10_VOP3A_SRC_VGPR_BASE)
		sprintf(src1, "v%d",
			insn->vop3b.src1 - GFX10_VOP3A_SRC_VGPR_BASE);

	if (insn->vop3b.src2 < GFX10_VOP3A_SRC_VCC_LO)
		sprintf(src2, "s%d", insn->vop3b.src2);
	else if (insn->vop3b.src2 == GFX10_VOP3A_SRC_VCC_LO)
		sprintf(src2, "%s", "vcc_lo");
	else if (insn->vop3b.src2 == GFX10_VOP3A_SRC_VCC_HI)
		sprintf(src2, "%s", "vcc_hi");
	else if (insn->vop3b.src2 == GFX10_VOP3A_SRC_NULL)
		sprintf(src2, "%s", "null");
	else if (insn->vop3b.src2 == GFX10_VOP3A_SRC_EXEC_LO)
		sprintf(src2, "%s", "exec_lo");
	else if (insn->vop3b.src2 == GFX10_VOP3A_SRC_EXEC_HI)
		sprintf(src2, "%s", "exec_hi");
	else if (insn->vop3b.src2 < GFX10_VOP3A_SRC_INTEGER_MINUS_1)
		sprintf(src2, "0x%x",
			insn->vop3b.src2 - GFX10_VOP3A_SRC_INTEGER_0);
	else if (insn->vop3b.src2 < GFX10_VOP3A_SRC_SHARED_BASE)
		sprintf(src2, "-0x%x",
			insn->vop3b.src2 - GFX10_VOP3A_SRC_INTEGER_MINUS_1);
	else if (insn->vop3b.src2 == GFX10_VOP3A_SRC_VCCZ)
		sprintf(src2, "%s", "vcc");
	else if (insn->vop3b.src2 == GFX10_VOP3A_SRC_EXECZ)
		sprintf(src2, "%s", "exec");
	else if (insn->vop3b.src2 == GFX10_VOP3A_SRC_SCC)
		sprintf(src2, "%s", "scc");
	else if (insn->vop3b.src2 == GFX10_VOP3A_SRC_LITERAL_CONST)
		sprintf(src2, "0x%x", insn->vop3b.literal);
	else if (insn->vop3b.src2 >= GFX10_VOP3A_SRC_VGPR_BASE)
		sprintf(src2, "v%d",
			insn->vop3b.src2 - GFX10_VOP3A_SRC_VGPR_BASE);

	pr_debug("knod_asm %s v%d, %s, %s, %s, %s\n",
		 opnames_gfx10[AMDGCN_INSN_TYPE_VOP3B][insn->vop3b.op],
		 insn->vop3b.vdst, sdst, src0, src1, src2);
}

static inline void gfx10_debug_vop1(union amdgcn_gfx10_insn *insn)
{
	char src0[20];

	if (insn->vop1.src0 < GFX10_VOP1_SRC_VCC_LO)
		sprintf(src0, "s%d", insn->vop1.src0);
	else if (insn->vop1.src0 == GFX10_VOP1_SRC_VCC_LO)
		sprintf(src0, "%s", "vcc_lo");
	else if (insn->vop1.src0 == GFX10_VOP1_SRC_VCC_HI)
		sprintf(src0, "%s", "vcc_hi");
	else if (insn->vop1.src0 == GFX10_VOP1_SRC_NULL)
		sprintf(src0, "%s", "null");
	else if (insn->vop1.src0 == GFX10_VOP1_SRC_EXEC_LO)
		sprintf(src0, "%s", "exec_lo");
	else if (insn->vop1.src0 == GFX10_VOP1_SRC_EXEC_HI)
		sprintf(src0, "%s", "exec_hi");
	else if (insn->vop1.src0 < GFX10_VOP1_SRC_INTEGER_MINUS_1)
		sprintf(src0, "0x%x",
			insn->vop1.src0 - GFX10_VOP1_SRC_INTEGER_0);
	else if (insn->vop1.src0 < GFX10_VOP1_SRC_SHARED_BASE)
		sprintf(src0, "-0x%x",
			insn->vop1.src0 - GFX10_VOP1_SRC_INTEGER_MINUS_1);
	else if (insn->vop1.src0 == GFX10_VOP1_SRC_VCCZ)
		sprintf(src0, "%s", "vcc");
	else if (insn->vop1.src0 == GFX10_VOP1_SRC_EXECZ)
		sprintf(src0, "%s", "exec");
	else if (insn->vop1.src0 == GFX10_VOP1_SRC_SCC)
		sprintf(src0, "%s", "scc");
	else if (insn->vop1.src0 == GFX10_VOP1_SRC_LITERAL_CONST)
		sprintf(src0, "0x%x", insn->vop1.literal);
	else if (insn->vop1.src0 >= GFX10_VOP1_SRC_VGPR_BASE)
		sprintf(src0, "v%d",
			insn->vop1.src0 - GFX10_VOP1_SRC_VGPR_BASE);

	pr_debug("knod_asm %s v%d, %s\n",
		 opnames_gfx10[AMDGCN_INSN_TYPE_VOP1][insn->vop1.op],
		 insn->vop1.vdst, src0);
}

static inline void gfx10_debug_vopc(union amdgcn_gfx10_insn *insn)
{
	char src0[20];

	if (insn->vopc.src0 < GFX10_VOPC_SRC_VCC_LO)
		sprintf(src0, "s%d", insn->vopc.src0);
	else if (insn->vopc.src0 == GFX10_VOPC_SRC_VCC_LO)
		sprintf(src0, "%s", "vcc_lo");
	else if (insn->vopc.src0 == GFX10_VOPC_SRC_VCC_HI)
		sprintf(src0, "%s", "vcc_hi");
	else if (insn->vopc.src0 == GFX10_VOPC_SRC_NULL)
		sprintf(src0, "%s", "null");
	else if (insn->vopc.src0 == GFX10_VOPC_SRC_EXEC_LO)
		sprintf(src0, "%s", "exec_lo");
	else if (insn->vopc.src0 == GFX10_VOPC_SRC_EXEC_HI)
		sprintf(src0, "%s", "exec_hi");
	else if (insn->vopc.src0 < GFX10_VOPC_SRC_INTEGER_MINUS_1)
		sprintf(src0, "0x%x",
			insn->vopc.src0 - GFX10_VOPC_SRC_INTEGER_0);
	else if (insn->vopc.src0 < GFX10_VOPC_SRC_SHARED_BASE)
		sprintf(src0, "-0x%x",
			insn->vopc.src0 - GFX10_VOPC_SRC_INTEGER_MINUS_1);
	else if (insn->vopc.src0 == GFX10_VOPC_SRC_VCCZ)
		sprintf(src0, "%s", "vcc");
	else if (insn->vopc.src0 == GFX10_VOPC_SRC_EXECZ)
		sprintf(src0, "%s", "exec");
	else if (insn->vopc.src0 == GFX10_VOPC_SRC_SCC)
		sprintf(src0, "%s", "scc");
	else if (insn->vopc.src0 == GFX10_VOPC_SRC_LITERAL_CONST)
		sprintf(src0, "0x%x", insn->vopc.literal);
	else if (insn->vopc.src0 >= GFX10_VOPC_SRC_VGPR_BASE)
		sprintf(src0, "v%d",
			insn->vopc.src0 - GFX10_VOPC_SRC_VGPR_BASE);

	pr_debug("knod_asm %s %s, v%d\n",
		 opnames_gfx10[AMDGCN_INSN_TYPE_VOPC][insn->vopc.op],
		 src0, insn->vopc.vsrc1);
}

static inline void gfx10_debug_vop2(union amdgcn_gfx10_insn *insn)
{
	char src0[20];

	if (insn->vop2.src0 < GFX10_VOP2_SRC_VCC_LO)
		sprintf(src0, "s%d", insn->vop2.src0);
	else if (insn->vop2.src0 == GFX10_VOP2_SRC_VCC_LO)
		sprintf(src0, "%s", "vcc_lo");
	else if (insn->vop2.src0 == GFX10_VOP2_SRC_VCC_HI)
		sprintf(src0, "%s", "vcc_hi");
	else if (insn->vop2.src0 == GFX10_VOP2_SRC_NULL)
		sprintf(src0, "%s", "null");
	else if (insn->vop2.src0 == GFX10_VOP2_SRC_EXEC_LO)
		sprintf(src0, "%s", "exec_lo");
	else if (insn->vop2.src0 == GFX10_VOP2_SRC_EXEC_HI)
		sprintf(src0, "%s", "exec_hi");
	else if (insn->vop2.src0 < GFX10_VOP2_SRC_INTEGER_MINUS_1)
		sprintf(src0, "0x%x",
			insn->vop2.src0 - GFX10_VOP2_SRC_INTEGER_0);
	else if (insn->vop2.src0 < GFX10_VOP2_SRC_SHARED_BASE)
		sprintf(src0, "-0x%x",
			insn->vop2.src0 - GFX10_VOP2_SRC_INTEGER_MINUS_1);
	else if (insn->vop2.src0 == GFX10_VOP2_SRC_VCCZ)
		sprintf(src0, "%s", "vcc");
	else if (insn->vop2.src0 == GFX10_VOP2_SRC_EXECZ)
		sprintf(src0, "%s", "exec");
	else if (insn->vop2.src0 == GFX10_VOP2_SRC_SCC)
		sprintf(src0, "%s", "scc");
	else if (insn->vop2.src0 == GFX10_VOP2_SRC_LITERAL_CONST)
		sprintf(src0, "0x%x", insn->vop2.literal);
	else if (insn->vop2.src0 >= GFX10_VOP2_SRC_VGPR_BASE)
		sprintf(src0, "v%d",
			insn->vop2.src0 - GFX10_VOP2_SRC_VGPR_BASE);

	pr_debug("knod_asm %s v%d, %s v%d\n",
		 opnames_gfx10[AMDGCN_INSN_TYPE_VOP2][insn->vop2.op],
		 insn->vop2.vdst,
		 src0,
		 insn->vop2.vsrc1);
}

static inline void gfx10_debug_sop1(union amdgcn_gfx10_insn *insn)
{
	char ssrc0[20];

	if (insn->sop1.ssrc0 < GFX10_SOP1_SSRC_VCC_LO)
		sprintf(ssrc0, "s%d", insn->sop1.ssrc0);
	else if (insn->sop1.ssrc0 == GFX10_SOP1_SSRC_VCC_LO)
		sprintf(ssrc0, "%s", "vcc_lo");
	else if (insn->sop1.ssrc0 == GFX10_SOP1_SSRC_VCC_HI)
		sprintf(ssrc0, "%s", "vcc_hi");
	else if (insn->sop1.ssrc0 == GFX10_SOP1_SSRC_NULL)
		sprintf(ssrc0, "%s", "null");
	else if (insn->sop1.ssrc0 == GFX10_SOP1_SSRC_EXEC_LO)
		sprintf(ssrc0, "%s", "exec_lo");
	else if (insn->sop1.ssrc0 == GFX10_SOP1_SSRC_EXEC_HI)
		sprintf(ssrc0, "%s", "exec_hi");
	else if (insn->sop1.ssrc0 < GFX10_SOP1_SSRC_INTEGER_MINUS_1)
		sprintf(ssrc0, "0x%x",
			insn->sop1.ssrc0 - GFX10_SOP1_SSRC_INTEGER_0);
	else if (insn->sop1.ssrc0 < GFX10_SOP1_SSRC_SHARED_BASE)
		sprintf(ssrc0, "-0x%x",
			insn->sop1.ssrc0 - GFX10_SOP1_SSRC_INTEGER_MINUS_1);
	else if (insn->sop1.ssrc0 == GFX10_SOP1_SSRC_VCCZ)
		sprintf(ssrc0, "%s", "vcc");
	else if (insn->sop1.ssrc0 == GFX10_SOP1_SSRC_EXECZ)
		sprintf(ssrc0, "%s", "exec");
	else if (insn->sop1.ssrc0 == GFX10_SOP1_SSRC_SCC)
		sprintf(ssrc0, "%s", "scc");
	else if (insn->sop1.ssrc0 == GFX10_SOP1_SSRC_LITERAL_CONST)
		sprintf(ssrc0, "0x%x", insn->sop1.literal);

	pr_debug("knod_asm %s s%d, %s\n",
		 opnames_gfx10[AMDGCN_INSN_TYPE_SOP1][insn->sop1.op],
		 insn->sop1.sdst,
		 ssrc0);
}

static inline void gfx10_debug_sopp(union amdgcn_gfx10_insn *insn)
{
	pr_debug("knod_asm %s 0x%x\n",
		 opnames_gfx10[AMDGCN_INSN_TYPE_SOPP][insn->sopp.op],
		 insn->sopp.simm16);
}

static inline void gfx10_debug_smem(union amdgcn_gfx10_insn *insn)
{
	pr_debug("%s s[%d:%d], s[%d:%d], 0x%x\n",
		 opnames_gfx10[AMDGCN_INSN_TYPE_SMEM][insn->smem.op],
		 insn->smem.sdata,
		 insn->smem.sdata + 1,
		 (insn->smem.sbase * 2),
		 (insn->smem.sbase * 2) + 1,
		 insn->smem.offset);
}

static inline void gfx10_debug_mubuf(union amdgcn_gfx10_insn *insn)
{
	pr_debug("knod_asm %s v%d, v%d, s[%d:%d], 0x%x offen offset:%d\n",
		 opnames_gfx10[AMDGCN_INSN_TYPE_MUBUF][insn->mubuf.op],
		 insn->mubuf.vdata,
		 insn->mubuf.vaddr,
		 insn->mubuf.srsrc,
		 insn->mubuf.srsrc + 3,
		 insn->mubuf.soffset,
		 insn->mubuf.offset);
}

static inline void gfx10_debug_global(union amdgcn_gfx10_insn *insn)
{
	if (insn->flat.op == GFX9_GLOBAL_STORE_BYTE) {
		pr_debug("knod_asm %s v[%d:%d], v%d, off offset:%d\n",
			 opnames_gfx10[AMDGCN_INSN_TYPE_FLAT][insn->flat.op],
			 insn->flat.addr,
			 insn->flat.addr + 1,
			 insn->flat.data,
			 insn->flat.offset);
	} else if (insn->flat.op == GFX9_GLOBAL_STORE_SHORT) {
		pr_debug("knod_asm %s v[%d:%d], v%d, off offset:%d\n",
			 opnames_gfx10[AMDGCN_INSN_TYPE_FLAT][insn->flat.op],
			 insn->flat.addr,
			 insn->flat.addr + 1,
			 insn->flat.data,
			 insn->flat.offset);
	} else if (insn->flat.op == GFX9_GLOBAL_STORE_DWORD) {
		pr_debug("knod_asm %s v[%d:%d], v%d, off offset:%d\n",
			 opnames_gfx10[AMDGCN_INSN_TYPE_FLAT][insn->flat.op],
			 insn->flat.addr,
			 insn->flat.addr + 1,
			 insn->flat.data,
			 insn->flat.offset);
	} else if (insn->flat.op == GFX9_GLOBAL_STORE_DWORDX2) {
		pr_debug("knod_asm %s v[%d:%d], v[%d:%d], off offset:%d\n",
			 opnames_gfx10[AMDGCN_INSN_TYPE_FLAT][insn->flat.op],
			 insn->flat.addr,
			 insn->flat.addr + 1,
			 insn->flat.data,
			 insn->flat.data + 1,
			 insn->flat.offset);
	} else {
		pr_debug("knod_asm %s v[%d:%d], v[%d:%d], off offset:%d\n",
			 opnames_gfx10[AMDGCN_INSN_TYPE_FLAT][insn->flat.op],
			 insn->flat.vdst,
			 insn->flat.vdst + 1,
			 insn->flat.addr,
			 insn->flat.addr + 1,
			 insn->flat.offset);
	}
}

static inline void decode_ssrc8(int ssrc, u32 literal, char *buf)
{
	if (ssrc < 106)
		sprintf(buf, "s%d", ssrc);
	else if (ssrc == 106)
		sprintf(buf, "vcc_lo");
	else if (ssrc == 107)
		sprintf(buf, "vcc_hi");
	else if (ssrc == 125)
		sprintf(buf, "null");
	else if (ssrc == 126)
		sprintf(buf, "exec_lo");
	else if (ssrc == 127)
		sprintf(buf, "exec_hi");
	else if (ssrc < 193)
		sprintf(buf, "0x%x", ssrc - 128);
	else if (ssrc < 235)
		sprintf(buf, "-0x%x", ssrc - 193);
	else if (ssrc == 251)
		sprintf(buf, "vcc");
	else if (ssrc == 252)
		sprintf(buf, "exec");
	else if (ssrc == 253)
		sprintf(buf, "scc");
	else if (ssrc == 255)
		sprintf(buf, "0x%x", literal);
	else
		sprintf(buf, "?%d", ssrc);
}

static inline void decode_vsrc9(int src, u32 literal, char *buf)
{
	if (src >= 256)
		sprintf(buf, "v%d", src - 256);
	else
		decode_ssrc8(src, literal, buf);
}

static inline void gfx10_debug_sop2(union amdgcn_gfx10_insn *insn)
{
	char ssrc0[20], ssrc1[20];

	decode_ssrc8(insn->sop2.ssrc0, insn->sop2.literal, ssrc0);
	decode_ssrc8(insn->sop2.ssrc1, insn->sop2.literal, ssrc1);
	pr_debug("knod_asm %s s%d, %s, %s\n",
		 opnames_gfx10[AMDGCN_INSN_TYPE_SOP2][insn->sop2.op],
		 insn->sop2.sdst, ssrc0, ssrc1);
}

static inline void gfx10_debug_sopk(union amdgcn_gfx10_insn *insn)
{
	pr_debug("knod_asm %s s%d, 0x%x\n",
		 opnames_gfx10[AMDGCN_INSN_TYPE_SOPK][insn->sopk.op],
		 insn->sopk.sdst, insn->sopk.simm16);
}

static inline void gfx10_debug_sopc(union amdgcn_gfx10_insn *insn)
{
	char ssrc0[20], ssrc1[20];

	decode_ssrc8(insn->sopc.ssrc0, insn->sopc.literal, ssrc0);
	decode_ssrc8(insn->sopc.ssrc1, insn->sopc.literal, ssrc1);
	pr_debug("knod_asm %s %s, %s\n",
		 opnames_gfx10[AMDGCN_INSN_TYPE_SOPC][insn->sopc.op],
		 ssrc0, ssrc1);
}

static inline void gfx10_debug_vop3p(union amdgcn_gfx10_insn *insn)
{
	char src0[20], src1[20], src2[20];

	decode_vsrc9(insn->vop3p.src0, insn->vop3p.literal, src0);
	decode_vsrc9(insn->vop3p.src1, insn->vop3p.literal, src1);
	decode_vsrc9(insn->vop3p.src2, insn->vop3p.literal, src2);
	pr_debug("knod_asm %s v%d, %s, %s, %s\n",
		 opnames_gfx10[AMDGCN_INSN_TYPE_VOP3P][insn->vop3p.op],
		 (int)insn->vop3p.vdst, src0, src1, src2);
}

static inline void gfx10_debug_sdwa(union amdgcn_gfx10_insn *insn)
{
	pr_debug("knod_asm sdwa src0:%d dst_sel:%d src0_sel:%d src1_sel:%d\n",
		 insn->sdwa.src0, insn->sdwa.dst_sel,
		 insn->sdwa.src0_sel, insn->sdwa.src1_sel);
}

static inline void gfx10_debug_sdwab(union amdgcn_gfx10_insn *insn)
{
	pr_debug("knod_asm sdwab src0:%d sdst:s%d src0_sel:%d src1_sel:%d\n",
		 insn->sdwab.src0, insn->sdwab.sdst,
		 insn->sdwab.src0_sel, insn->sdwab.src1_sel);
}

static inline void gfx10_debug_dpp16(union amdgcn_gfx10_insn *insn)
{
	pr_debug("knod_asm dpp16 (not decoded)\n");
}

static inline void gfx10_debug_dpp8(union amdgcn_gfx10_insn *insn)
{
	pr_debug("knod_asm dpp8 (not decoded)\n");
}

static inline void gfx10_debug_vintrp(union amdgcn_gfx10_insn *insn)
{
	pr_debug("knod_asm vintrp (not decoded)\n");
}

static inline void gfx10_debug_ds(union amdgcn_gfx10_insn *insn)
{
	pr_debug("knod_asm %s v%d, v%d, v%d, v%d offset0:%d offset1:%d%s\n",
		 opnames_gfx10[AMDGCN_INSN_TYPE_DS][insn->ds.op],
		 (int)insn->ds.vdst, (int)insn->ds.addr,
		 (int)insn->ds.data0, (int)insn->ds.data1,
		 (int)insn->ds.offset0, (int)insn->ds.offset1,
		 insn->ds.gds ? " gds" : "");
}

static inline void gfx10_debug_mtbuf(union amdgcn_gfx10_insn *insn)
{
	pr_debug("knod_asm %s v%d, v%d, s[%d:%d], s%d format:%d offset:%d\n",
		 opnames_gfx10[AMDGCN_INSN_TYPE_MTBUF][insn->mtbuf.op],
		 (int)insn->mtbuf.vdata, (int)insn->mtbuf.vaddr,
		 (int)insn->mtbuf.srsrc * 4, (int)insn->mtbuf.srsrc * 4 + 3,
		 (int)insn->mtbuf.soffset, (int)insn->mtbuf.foamat,
		 (int)insn->mtbuf.offset);
}

static inline void gfx10_debug_mimg(union amdgcn_gfx10_insn *insn)
{
	pr_debug("knod_asm mimg (not decoded)\n");
}

static inline void gfx10_debug_exp(union amdgcn_gfx10_insn *insn)
{
	pr_debug("knod_asm exp (not decoded)\n");
}

static inline void gfx10_debug_insn(struct amdgcn_insn *insn)
{
	u32 *ptr;

	switch (insn->type) {
	case AMDGCN_INSN_TYPE_SOP2:
		gfx10_debug_sop2(&insn->gfx10);
		break;
	case AMDGCN_INSN_TYPE_SOPK:
		gfx10_debug_sopk(&insn->gfx10);
		break;
	case AMDGCN_INSN_TYPE_SOP1:
		gfx10_debug_sop1(&insn->gfx10);
		break;
	case AMDGCN_INSN_TYPE_SOPC:
		gfx10_debug_sopc(&insn->gfx10);
		break;
	case AMDGCN_INSN_TYPE_SOPP:
		gfx10_debug_sopp(&insn->gfx10);
		break;
	case AMDGCN_INSN_TYPE_SMEM:
		gfx10_debug_smem(&insn->gfx10);
		break;
	case AMDGCN_INSN_TYPE_VOP2:
		gfx10_debug_vop2(&insn->gfx10);
		break;
	case AMDGCN_INSN_TYPE_VOP1:
		gfx10_debug_vop1(&insn->gfx10);
		break;
	case AMDGCN_INSN_TYPE_VOPC:
		gfx10_debug_vopc(&insn->gfx10);
		break;
	case AMDGCN_INSN_TYPE_VOP3A:
		gfx10_debug_vop3a(&insn->gfx10);
		break;
	case AMDGCN_INSN_TYPE_VOP3B:
		gfx10_debug_vop3b(&insn->gfx10);
		break;
	case AMDGCN_INSN_TYPE_VOP3P:
		gfx10_debug_vop3p(&insn->gfx10);
		break;
	case AMDGCN_INSN_TYPE_SDWA:
		gfx10_debug_sdwa(&insn->gfx10);
		break;
	case AMDGCN_INSN_TYPE_SDWAB:
		gfx10_debug_sdwab(&insn->gfx10);
		break;
	case AMDGCN_INSN_TYPE_DPP16:
		gfx10_debug_dpp16(&insn->gfx10);
		break;
	case AMDGCN_INSN_TYPE_DPP8:
		gfx10_debug_dpp8(&insn->gfx10);
		break;
	case AMDGCN_INSN_TYPE_VINTRP:
		gfx10_debug_vintrp(&insn->gfx10);
		break;
	case AMDGCN_INSN_TYPE_DS:
		gfx10_debug_ds(&insn->gfx10);
		break;
	case AMDGCN_INSN_TYPE_MTBUF:
		gfx10_debug_mtbuf(&insn->gfx10);
		break;
	case AMDGCN_INSN_TYPE_MUBUF:
		gfx10_debug_mubuf(&insn->gfx10);
		break;
	case AMDGCN_INSN_TYPE_MIMG:
		gfx10_debug_mimg(&insn->gfx10);
		break;
	case AMDGCN_INSN_TYPE_FLAT:
		gfx10_debug_global(&insn->gfx10);
		break;
	case AMDGCN_INSN_TYPE_EXP:
		gfx10_debug_exp(&insn->gfx10);
		break;
	default:
		WARN_ON(1);
		break;
	}

	ptr = (u32 *)&insn->gfx10;
	if (insn->size == 4) {
		pr_debug("knod_asm %s %u %.8X\n", __func__, __LINE__, ptr[0]);
	} else if (insn->size == 8) {
		pr_debug("knod_asm %s %u %.8X %.8X\n",
			 __func__, __LINE__, ptr[0], ptr[1]);
	} else if (insn->size == 12) {
		pr_debug("knod_asm %s %u %.8X %.8X %.8X\n",
			 __func__, __LINE__, ptr[0], ptr[1], ptr[2]);
	} else {
		WARN_ON(1);
	}
}

static inline void gfx9_debug_vop3a(union amdgcn_gfx9_insn *insn)
{
	char src0[20];
	char src1[20];
	char src2[20];

	if (insn->vop3a.src0 < GFX9_VOP3A_SRC_VCC_LO)
		sprintf(src0, "s%d", insn->vop3a.src0);
	else if (insn->vop3a.src0 == GFX9_VOP3A_SRC_VCC_LO)
		sprintf(src0, "%s", "vcc_lo");
	else if (insn->vop3a.src0 == GFX9_VOP3A_SRC_VCC_HI)
		sprintf(src0, "%s", "vcc_hi");
	else if (insn->vop3a.src0 == GFX9_VOP3A_SRC_NULL)
		sprintf(src0, "%s", "null");
	else if (insn->vop3a.src0 == GFX9_VOP3A_SRC_EXEC_LO)
		sprintf(src0, "%s", "exec_lo");
	else if (insn->vop3a.src0 == GFX9_VOP3A_SRC_EXEC_HI)
		sprintf(src0, "%s", "exec_hi");
	else if (insn->vop3a.src0 < GFX9_VOP3A_SRC_INTEGER_MINUS_1)
		sprintf(src0, "0x%x",
			insn->vop3a.src0 - GFX9_VOP3A_SRC_INTEGER_0);
	else if (insn->vop3a.src0 < GFX9_VOP3A_SRC_SHARED_BASE)
		sprintf(src0, "-0x%x",
			insn->vop3a.src0 - GFX9_VOP3A_SRC_INTEGER_MINUS_1);
	else if (insn->vop3a.src0 == GFX9_VOP3A_SRC_VCCZ)
		sprintf(src0, "%s", "vcc");
	else if (insn->vop3a.src0 == GFX9_VOP3A_SRC_EXECZ)
		sprintf(src0, "%s", "exec");
	else if (insn->vop3a.src0 == GFX9_VOP3A_SRC_SCC)
		sprintf(src0, "%s", "scc");
	else if (insn->vop3a.src0 == GFX9_VOP3A_SRC_LITERAL_CONST)
		sprintf(src0, "0x%x", insn->vop3a.literal);
	else if (insn->vop3a.src0 >= GFX9_VOP3A_SRC_VGPR_BASE)
		sprintf(src0, "v%d",
			insn->vop3a.src0 - GFX9_VOP3A_SRC_VGPR_BASE);

	if (insn->vop3a.src1 < GFX9_VOP3A_SRC_VCC_LO)
		sprintf(src1, "s%d", insn->vop3a.src1);
	else if (insn->vop3a.src1 == GFX9_VOP3A_SRC_VCC_LO)
		sprintf(src1, "%s", "vcc_lo");
	else if (insn->vop3a.src1 == GFX9_VOP3A_SRC_VCC_HI)
		sprintf(src1, "%s", "vcc_hi");
	else if (insn->vop3a.src1 == GFX9_VOP3A_SRC_NULL)
		sprintf(src1, "%s", "null");
	else if (insn->vop3a.src1 == GFX9_VOP3A_SRC_EXEC_LO)
		sprintf(src1, "%s", "exec_lo");
	else if (insn->vop3a.src1 == GFX9_VOP3A_SRC_EXEC_HI)
		sprintf(src1, "%s", "exec_hi");
	else if (insn->vop3a.src1 < GFX9_VOP3A_SRC_INTEGER_MINUS_1)
		sprintf(src1, "0x%x",
			insn->vop3a.src1 - GFX9_VOP3A_SRC_INTEGER_0);
	else if (insn->vop3a.src1 < GFX9_VOP3A_SRC_SHARED_BASE)
		sprintf(src1, "-0x%x",
			insn->vop3a.src1 - GFX9_VOP3A_SRC_INTEGER_MINUS_1);
	else if (insn->vop3a.src1 == GFX9_VOP3A_SRC_VCCZ)
		sprintf(src1, "%s", "vcc");
	else if (insn->vop3a.src1 == GFX9_VOP3A_SRC_EXECZ)
		sprintf(src1, "%s", "exec");
	else if (insn->vop3a.src1 == GFX9_VOP3A_SRC_SCC)
		sprintf(src1, "%s", "scc");
	else if (insn->vop3a.src1 == GFX9_VOP3A_SRC_LITERAL_CONST)
		sprintf(src1, "0x%x", insn->vop3a.literal);
	else if (insn->vop3a.src1 >= GFX9_VOP3A_SRC_VGPR_BASE)
		sprintf(src1, "v%d",
			insn->vop3a.src1 - GFX9_VOP3A_SRC_VGPR_BASE);

	if (insn->vop3a.src2 < GFX9_VOP3A_SRC_VCC_LO)
		sprintf(src2, "s%d", insn->vop3a.src2);
	else if (insn->vop3a.src2 == GFX9_VOP3A_SRC_VCC_LO)
		sprintf(src2, "%s", "vcc_lo");
	else if (insn->vop3a.src2 == GFX9_VOP3A_SRC_VCC_HI)
		sprintf(src2, "%s", "vcc_hi");
	else if (insn->vop3a.src2 == GFX9_VOP3A_SRC_NULL)
		sprintf(src2, "%s", "null");
	else if (insn->vop3a.src2 == GFX9_VOP3A_SRC_EXEC_LO)
		sprintf(src2, "%s", "exec_lo");
	else if (insn->vop3a.src2 == GFX9_VOP3A_SRC_EXEC_HI)
		sprintf(src2, "%s", "exec_hi");
	else if (insn->vop3a.src2 < GFX9_VOP3A_SRC_INTEGER_MINUS_1)
		sprintf(src2, "0x%x",
			insn->vop3a.src2 - GFX9_VOP3A_SRC_INTEGER_0);
	else if (insn->vop3a.src2 < GFX9_VOP3A_SRC_SHARED_BASE)
		sprintf(src2, "-0x%x",
			insn->vop3a.src2 - GFX9_VOP3A_SRC_INTEGER_MINUS_1);
	else if (insn->vop3a.src2 == GFX9_VOP3A_SRC_VCCZ)
		sprintf(src2, "%s", "vcc");
	else if (insn->vop3a.src2 == GFX9_VOP3A_SRC_EXECZ)
		sprintf(src2, "%s", "exec");
	else if (insn->vop3a.src2 == GFX9_VOP3A_SRC_SCC)
		sprintf(src2, "%s", "scc");
	else if (insn->vop3a.src2 == GFX9_VOP3A_SRC_LITERAL_CONST)
		sprintf(src2, "0x%x", insn->vop3a.literal);
	else if (insn->vop3a.src2 >= GFX9_VOP3A_SRC_VGPR_BASE)
		sprintf(src2, "v%d",
			insn->vop3a.src2 - GFX9_VOP3A_SRC_VGPR_BASE);

	pr_debug("knod_asm %s v%d, %s, %s, %s\n",
		 opnames_gfx9[AMDGCN_INSN_TYPE_VOP3A][insn->vop3a.op],
		 insn->vop3a.vdst, src0, src1, src2);
}

static inline void gfx9_debug_vop3b(union amdgcn_gfx9_insn *insn)
{
	char src0[20];
	char src1[20];
	char src2[20];
	char sdst[20];

	if (insn->vop3b.sdst < GFX9_VOP3B_SRC_VCC_LO)
		sprintf(sdst, "s%d", insn->vop3b.sdst);
	else if (insn->vop3b.sdst == GFX9_VOP3B_SRC_VCC_LO)
		sprintf(sdst, "%s", "vcc_lo");
	else if (insn->vop3b.sdst == GFX9_VOP3B_SRC_VCC_HI)
		sprintf(sdst, "%s", "vcc_hi");
	else if (insn->vop3b.sdst == GFX9_VOP3B_SRC_NULL)
		sprintf(sdst, "%s", "null");
	else if (insn->vop3b.sdst == GFX9_VOP3B_SRC_EXEC_LO)
		sprintf(sdst, "%s", "exec_lo");
	else if (insn->vop3b.sdst == GFX9_VOP3B_SRC_EXEC_HI)
		sprintf(sdst, "%s", "exec_hi");
	else if (insn->vop3b.sdst < GFX9_VOP3B_SRC_INTEGER_MINUS_1)
		sprintf(sdst, "0x%x",
			insn->vop3b.sdst - GFX9_VOP3B_SRC_INTEGER_0);
	else if (insn->vop3b.sdst < GFX9_VOP3B_SRC_SHARED_BASE)
		sprintf(sdst, "-0x%x",
			insn->vop3b.sdst - GFX9_VOP3B_SRC_INTEGER_MINUS_1);
	else if (insn->vop3b.sdst == GFX9_VOP3B_SRC_VCCZ)
		sprintf(sdst, "%s", "vcc");
	else if (insn->vop3b.sdst == GFX9_VOP3B_SRC_EXECZ)
		sprintf(sdst, "%s", "exec");
	else if (insn->vop3b.sdst == GFX9_VOP3B_SRC_SCC)
		sprintf(sdst, "%s", "scc");
	else if (insn->vop3b.sdst == GFX9_VOP3B_SRC_LITERAL_CONST)
		sprintf(sdst, "0x%x", insn->vop3b.literal);
	else if (insn->vop3b.sdst >= GFX9_VOP3B_SRC_VGPR_BASE)
		sprintf(sdst, "v%d",
			insn->vop3b.sdst - GFX9_VOP3B_SRC_VGPR_BASE);

	if (insn->vop3b.src0 < GFX9_VOP3B_SRC_VCC_LO)
		sprintf(src0, "s%d", insn->vop3b.src0);
	else if (insn->vop3b.src0 == GFX9_VOP3B_SRC_VCC_LO)
		sprintf(src0, "%s", "vcc_lo");
	else if (insn->vop3b.src0 == GFX9_VOP3B_SRC_VCC_HI)
		sprintf(src0, "%s", "vcc_hi");
	else if (insn->vop3b.src0 == GFX9_VOP3B_SRC_NULL)
		sprintf(src0, "%s", "null");
	else if (insn->vop3b.src0 == GFX9_VOP3B_SRC_EXEC_LO)
		sprintf(src0, "%s", "exec_lo");
	else if (insn->vop3b.src0 == GFX9_VOP3B_SRC_EXEC_HI)
		sprintf(src0, "%s", "exec_hi");
	else if (insn->vop3b.src0 < GFX9_VOP3B_SRC_INTEGER_MINUS_1)
		sprintf(src0, "0x%x",
			insn->vop3b.src0 - GFX9_VOP3B_SRC_INTEGER_0);
	else if (insn->vop3b.src0 < GFX9_VOP3B_SRC_SHARED_BASE)
		sprintf(src0, "-0x%x",
			insn->vop3b.src0 - GFX9_VOP3B_SRC_INTEGER_MINUS_1);
	else if (insn->vop3b.src0 == GFX9_VOP3B_SRC_VCCZ)
		sprintf(src0, "%s", "vcc");
	else if (insn->vop3b.src0 == GFX9_VOP3B_SRC_EXECZ)
		sprintf(src0, "%s", "exec");
	else if (insn->vop3b.src0 == GFX9_VOP3B_SRC_SCC)
		sprintf(src0, "%s", "scc");
	else if (insn->vop3b.src0 == GFX9_VOP3B_SRC_LITERAL_CONST)
		sprintf(src0, "0x%x", insn->vop3b.literal);
	else if (insn->vop3b.src0 >= GFX9_VOP3B_SRC_VGPR_BASE)
		sprintf(src0, "v%d",
			insn->vop3b.src0 - GFX9_VOP3B_SRC_VGPR_BASE);

	if (insn->vop3b.src1 < GFX9_VOP3B_SRC_VCC_LO)
		sprintf(src1, "s%d", insn->vop3b.src1);
	else if (insn->vop3b.src1 == GFX9_VOP3B_SRC_VCC_LO)
		sprintf(src1, "%s", "vcc_lo");
	else if (insn->vop3b.src1 == GFX9_VOP3B_SRC_VCC_HI)
		sprintf(src1, "%s", "vcc_hi");
	else if (insn->vop3b.src1 == GFX9_VOP3B_SRC_NULL)
		sprintf(src1, "%s", "null");
	else if (insn->vop3b.src1 == GFX9_VOP3B_SRC_EXEC_LO)
		sprintf(src1, "%s", "exec_lo");
	else if (insn->vop3b.src1 == GFX9_VOP3B_SRC_EXEC_HI)
		sprintf(src1, "%s", "exec_hi");
	else if (insn->vop3b.src1 < GFX9_VOP3B_SRC_INTEGER_MINUS_1)
		sprintf(src1, "0x%x",
			insn->vop3b.src1 - GFX9_VOP3B_SRC_INTEGER_0);
	else if (insn->vop3b.src1 < GFX9_VOP3B_SRC_SHARED_BASE)
		sprintf(src1, "-0x%x",
			insn->vop3b.src1 - GFX9_VOP3B_SRC_INTEGER_MINUS_1);
	else if (insn->vop3b.src1 == GFX9_VOP3B_SRC_VCCZ)
		sprintf(src1, "%s", "vcc");
	else if (insn->vop3b.src1 == GFX9_VOP3B_SRC_EXECZ)
		sprintf(src1, "%s", "exec");
	else if (insn->vop3b.src1 == GFX9_VOP3B_SRC_SCC)
		sprintf(src1, "%s", "scc");
	else if (insn->vop3b.src1 == GFX9_VOP3B_SRC_LITERAL_CONST)
		sprintf(src1, "0x%x", insn->vop3b.literal);
	else if (insn->vop3b.src1 >= GFX9_VOP3B_SRC_VGPR_BASE)
		sprintf(src1, "v%d",
			insn->vop3b.src1 - GFX9_VOP3B_SRC_VGPR_BASE);

	if (insn->vop3b.src2 < GFX9_VOP3B_SRC_VCC_LO)
		sprintf(src2, "s%d", insn->vop3b.src2);
	else if (insn->vop3b.src2 == GFX9_VOP3B_SRC_VCC_LO)
		sprintf(src2, "%s", "vcc_lo");
	else if (insn->vop3b.src2 == GFX9_VOP3B_SRC_VCC_HI)
		sprintf(src2, "%s", "vcc_hi");
	else if (insn->vop3b.src2 == GFX9_VOP3B_SRC_NULL)
		sprintf(src2, "%s", "null");
	else if (insn->vop3b.src2 == GFX9_VOP3B_SRC_EXEC_LO)
		sprintf(src2, "%s", "exec_lo");
	else if (insn->vop3b.src2 == GFX9_VOP3B_SRC_EXEC_HI)
		sprintf(src2, "%s", "exec_hi");
	else if (insn->vop3b.src2 < GFX9_VOP3B_SRC_INTEGER_MINUS_1)
		sprintf(src2, "0x%x",
			insn->vop3b.src2 - GFX9_VOP3B_SRC_INTEGER_0);
	else if (insn->vop3b.src2 < GFX9_VOP3B_SRC_SHARED_BASE)
		sprintf(src2, "-0x%x",
			insn->vop3b.src2 - GFX9_VOP3B_SRC_INTEGER_MINUS_1);
	else if (insn->vop3b.src2 == GFX9_VOP3B_SRC_VCCZ)
		sprintf(src2, "%s", "vcc");
	else if (insn->vop3b.src2 == GFX9_VOP3B_SRC_EXECZ)
		sprintf(src2, "%s", "exec");
	else if (insn->vop3b.src2 == GFX9_VOP3B_SRC_SCC)
		sprintf(src2, "%s", "scc");
	else if (insn->vop3b.src2 == GFX9_VOP3B_SRC_LITERAL_CONST)
		sprintf(src2, "0x%x", insn->vop3b.literal);
	else if (insn->vop3b.src2 >= GFX9_VOP3B_SRC_VGPR_BASE)
		sprintf(src2, "v%d",
			insn->vop3b.src2 - GFX9_VOP3B_SRC_VGPR_BASE);

	pr_debug("knod_asm %s v%d, %s, %s, %s, %s\n",
		 opnames_gfx9[AMDGCN_INSN_TYPE_VOP3B][insn->vop3b.op],
		 insn->vop3b.vdst, sdst, src0, src1, src2);
}

static inline void gfx9_debug_vop1(union amdgcn_gfx9_insn *insn)
{
	char src0[20];

	if (insn->vop1.src0 < GFX9_VOP1_SRC_VCC_LO)
		sprintf(src0, "s%d", insn->vop1.src0);
	else if (insn->vop1.src0 == GFX9_VOP1_SRC_VCC_LO)
		sprintf(src0, "%s", "vcc_lo");
	else if (insn->vop1.src0 == GFX9_VOP1_SRC_VCC_HI)
		sprintf(src0, "%s", "vcc_hi");
	else if (insn->vop1.src0 == GFX9_VOP1_SRC_NULL)
		sprintf(src0, "%s", "null");
	else if (insn->vop1.src0 == GFX9_VOP1_SRC_EXEC_LO)
		sprintf(src0, "%s", "exec_lo");
	else if (insn->vop1.src0 == GFX9_VOP1_SRC_EXEC_HI)
		sprintf(src0, "%s", "exec_hi");
	else if (insn->vop1.src0 < GFX9_VOP1_SRC_INTEGER_MINUS_1)
		sprintf(src0, "0x%x",
			insn->vop1.src0 - GFX9_VOP1_SRC_INTEGER_0);
	else if (insn->vop1.src0 < GFX9_VOP1_SRC_SHARED_BASE)
		sprintf(src0, "-0x%x",
			insn->vop1.src0 - GFX9_VOP1_SRC_INTEGER_MINUS_1);
	else if (insn->vop1.src0 == GFX9_VOP1_SRC_VCCZ)
		sprintf(src0, "%s", "vcc");
	else if (insn->vop1.src0 == GFX9_VOP1_SRC_EXECZ)
		sprintf(src0, "%s", "exec");
	else if (insn->vop1.src0 == GFX9_VOP1_SRC_SCC)
		sprintf(src0, "%s", "scc");
	else if (insn->vop1.src0 == GFX9_VOP1_SRC_LITERAL_CONST)
		sprintf(src0, "0x%x", insn->vop1.literal);
	else if (insn->vop1.src0 >= GFX9_VOP1_SRC_VGPR_BASE)
		sprintf(src0, "v%d", insn->vop1.src0 - GFX9_VOP1_SRC_VGPR_BASE);

	pr_debug("knod_asm %s v%d, %s\n",
		 opnames_gfx9[AMDGCN_INSN_TYPE_VOP1][insn->vop1.op],
		 insn->vop1.vdst, src0);
}

static inline void gfx9_debug_vopc(union amdgcn_gfx9_insn *insn)
{
	char src0[20];

	if (insn->vopc.src0 < GFX9_VOPC_SRC_VCC_LO)
		sprintf(src0, "s%d", insn->vopc.src0);
	else if (insn->vopc.src0 == GFX9_VOPC_SRC_VCC_LO)
		sprintf(src0, "%s", "vcc_lo");
	else if (insn->vopc.src0 == GFX9_VOPC_SRC_VCC_HI)
		sprintf(src0, "%s", "vcc_hi");
	else if (insn->vopc.src0 == GFX9_VOPC_SRC_NULL)
		sprintf(src0, "%s", "null");
	else if (insn->vopc.src0 == GFX9_VOPC_SRC_EXEC_LO)
		sprintf(src0, "%s", "exec_lo");
	else if (insn->vopc.src0 == GFX9_VOPC_SRC_EXEC_HI)
		sprintf(src0, "%s", "exec_hi");
	else if (insn->vopc.src0 < GFX9_VOPC_SRC_INTEGER_MINUS_1)
		sprintf(src0, "0x%x",
			insn->vopc.src0 - GFX9_VOPC_SRC_INTEGER_0);
	else if (insn->vopc.src0 < GFX9_VOPC_SRC_SHARED_BASE)
		sprintf(src0, "-0x%x",
			insn->vopc.src0 - GFX9_VOPC_SRC_INTEGER_MINUS_1);
	else if (insn->vopc.src0 == GFX9_VOPC_SRC_VCCZ)
		sprintf(src0, "%s", "vcc");
	else if (insn->vopc.src0 == GFX9_VOPC_SRC_EXECZ)
		sprintf(src0, "%s", "exec");
	else if (insn->vopc.src0 == GFX9_VOPC_SRC_SCC)
		sprintf(src0, "%s", "scc");
	else if (insn->vopc.src0 == GFX9_VOPC_SRC_LITERAL_CONST)
		sprintf(src0, "0x%x", insn->vopc.literal);
	else if (insn->vopc.src0 >= GFX9_VOPC_SRC_VGPR_BASE)
		sprintf(src0, "v%d", insn->vopc.src0 - GFX9_VOPC_SRC_VGPR_BASE);

	pr_debug("knod_asm %s %s, v%d\n",
		opnames_gfx9[AMDGCN_INSN_TYPE_VOPC][insn->vopc.op],
		src0,
		insn->vopc.vsrc1);
}

static inline void gfx9_debug_vop2(union amdgcn_gfx9_insn *insn)
{
	char src0[20];

	if (insn->vop2.src0 < GFX9_VOP2_SRC_VCC_LO)
		sprintf(src0, "s%d", insn->vop2.src0);
	else if (insn->vop2.src0 == GFX9_VOP2_SRC_VCC_LO)
		sprintf(src0, "%s", "vcc_lo");
	else if (insn->vop2.src0 == GFX9_VOP2_SRC_VCC_HI)
		sprintf(src0, "%s", "vcc_hi");
	else if (insn->vop2.src0 == GFX9_VOP2_SRC_NULL)
		sprintf(src0, "%s", "null");
	else if (insn->vop2.src0 == GFX9_VOP2_SRC_EXEC_LO)
		sprintf(src0, "%s", "exec_lo");
	else if (insn->vop2.src0 == GFX9_VOP2_SRC_EXEC_HI)
		sprintf(src0, "%s", "exec_hi");
	else if (insn->vop2.src0 < GFX9_VOP2_SRC_INTEGER_MINUS_1)
		sprintf(src0, "0x%x",
			insn->vop2.src0 - GFX9_VOP2_SRC_INTEGER_0);
	else if (insn->vop2.src0 < GFX9_VOP2_SRC_SHARED_BASE)
		sprintf(src0, "-0x%x",
			insn->vop2.src0 - GFX9_VOP2_SRC_INTEGER_MINUS_1);
	else if (insn->vop2.src0 == GFX9_VOP2_SRC_VCCZ)
		sprintf(src0, "%s", "vcc");
	else if (insn->vop2.src0 == GFX9_VOP2_SRC_EXECZ)
		sprintf(src0, "%s", "exec");
	else if (insn->vop2.src0 == GFX9_VOP2_SRC_SCC)
		sprintf(src0, "%s", "scc");
	else if (insn->vop2.src0 == GFX9_VOP2_SRC_LITERAL_CONST)
		sprintf(src0, "0x%x", insn->vop2.literal);
	else if (insn->vop2.src0 >= GFX9_VOP2_SRC_VGPR_BASE)
		sprintf(src0, "v%d", insn->vop2.src0 - GFX9_VOP2_SRC_VGPR_BASE);

	pr_debug("knod_asm %s v%d, %s v%d\n",
		 opnames_gfx9[AMDGCN_INSN_TYPE_VOP2][insn->vop2.op],
		 insn->vop2.vdst,
		 src0,
		 insn->vop2.vsrc1);
}

static inline void gfx9_debug_sop1(union amdgcn_gfx9_insn *insn)
{
	char ssrc0[20];

	if (insn->sop1.ssrc0 < GFX9_SOP1_SSRC_VCC_LO)
		sprintf(ssrc0, "s%d", insn->sop1.ssrc0);
	else if (insn->sop1.ssrc0 == GFX9_SOP1_SSRC_VCC_LO)
		sprintf(ssrc0, "%s", "vcc_lo");
	else if (insn->sop1.ssrc0 == GFX9_SOP1_SSRC_VCC_HI)
		sprintf(ssrc0, "%s", "vcc_hi");
	else if (insn->sop1.ssrc0 == GFX9_SOP1_SSRC_NULL)
		sprintf(ssrc0, "%s", "null");
	else if (insn->sop1.ssrc0 == GFX9_SOP1_SSRC_EXEC_LO)
		sprintf(ssrc0, "%s", "exec_lo");
	else if (insn->sop1.ssrc0 == GFX9_SOP1_SSRC_EXEC_HI)
		sprintf(ssrc0, "%s", "exec_hi");
	else if (insn->sop1.ssrc0 < GFX9_SOP1_SSRC_INTEGER_MINUS_1)
		sprintf(ssrc0, "0x%x",
			insn->sop1.ssrc0 - GFX9_SOP1_SSRC_INTEGER_0);
	else if (insn->sop1.ssrc0 < GFX9_SOP1_SSRC_SHARED_BASE)
		sprintf(ssrc0, "-0x%x",
			insn->sop1.ssrc0 - GFX9_SOP1_SSRC_INTEGER_MINUS_1);
	else if (insn->sop1.ssrc0 == GFX9_SOP1_SSRC_VCCZ)
		sprintf(ssrc0, "%s", "vcc");
	else if (insn->sop1.ssrc0 == GFX9_SOP1_SSRC_EXECZ)
		sprintf(ssrc0, "%s", "exec");
	else if (insn->sop1.ssrc0 == GFX9_SOP1_SSRC_SCC)
		sprintf(ssrc0, "%s", "scc");
	else if (insn->sop1.ssrc0 == GFX9_SOP1_SSRC_LITERAL_CONST)
		sprintf(ssrc0, "0x%x", insn->sop1.literal);

	pr_debug("knod_asm %s s%d, %s\n",
		 opnames_gfx9[AMDGCN_INSN_TYPE_SOP1][insn->sop1.op],
		 insn->sop1.sdst,
		 ssrc0);
}

static inline void gfx9_debug_sopp(union amdgcn_gfx9_insn *insn)
{
	pr_debug("knod_asm %s 0x%x\n",
		 opnames_gfx9[AMDGCN_INSN_TYPE_SOPP][insn->sopp.op],
		 insn->sopp.simm16);
}

static inline void gfx9_debug_smem(union amdgcn_gfx9_insn *insn)
{
	pr_debug("%s s[%d:%d], s[%d:%d], 0x%x\n",
		 opnames_gfx9[AMDGCN_INSN_TYPE_SMEM][insn->smem.op],
		 insn->smem.sdata,
		 insn->smem.sdata + 1,
		 (insn->smem.sbase * 2),
		 (insn->smem.sbase * 2) + 1,
		 insn->smem.offset);
}

static inline void gfx9_debug_mubuf(union amdgcn_gfx9_insn *insn)
{
	pr_debug("knod_asm %s v%d, v%d, s[%d:%d], 0x%x offen offset:%d\n",
		 opnames_gfx9[AMDGCN_INSN_TYPE_MUBUF][insn->mubuf.op],
		 insn->mubuf.vdata,
		 insn->mubuf.vaddr,
		 insn->mubuf.srsrc,
		 insn->mubuf.srsrc + 3,
		 insn->mubuf.soffset,
		 insn->mubuf.offset);
}

static inline void gfx9_debug_global(union amdgcn_gfx9_insn *insn)
{
	if (insn->flat.op == GFX9_GLOBAL_STORE_BYTE) {
		pr_debug("knod_asm %s v[%d:%d], v%d, off offset:%d\n",
			opnames_gfx9[AMDGCN_INSN_TYPE_FLAT][insn->flat.op],
			insn->flat.addr,
			insn->flat.addr + 1,
			insn->flat.data,
			insn->flat.offset);
	} else if (insn->flat.op == GFX9_GLOBAL_STORE_SHORT) {
		pr_debug("knod_asm %s v[%d:%d], v%d, off offset:%d\n",
			opnames_gfx9[AMDGCN_INSN_TYPE_FLAT][insn->flat.op],
			insn->flat.addr,
			insn->flat.addr + 1,
			insn->flat.data,
			insn->flat.offset);
	} else if (insn->flat.op == GFX9_GLOBAL_STORE_DWORD) {
		pr_debug("knod_asm %s v[%d:%d], v%d, off offset:%d\n",
			opnames_gfx9[AMDGCN_INSN_TYPE_FLAT][insn->flat.op],
			insn->flat.addr,
			insn->flat.addr + 1,
			insn->flat.data,
			insn->flat.offset);
	} else if (insn->flat.op == GFX9_GLOBAL_STORE_DWORDX2) {
		pr_debug("knod_asm %s v[%d:%d], v[%d:%d], off offset:%d\n",
			opnames_gfx9[AMDGCN_INSN_TYPE_FLAT][insn->flat.op],
			insn->flat.addr,
			insn->flat.addr + 1,
			insn->flat.data,
			insn->flat.data + 1,
			insn->flat.offset);
	} else {
		pr_debug("knod_asm %s v[%d:%d], v[%d:%d], off offset:%d\n",
			opnames_gfx9[AMDGCN_INSN_TYPE_FLAT][insn->flat.op],
			insn->flat.vdst,
			insn->flat.vdst + 1,
			insn->flat.addr,
			insn->flat.addr + 1,
			insn->flat.offset);
	}
}

static inline void gfx9_debug_sop2(union amdgcn_gfx9_insn *insn)
{
	char ssrc0[20], ssrc1[20];

	decode_ssrc8(insn->sop2.ssrc0, insn->sop2.literal, ssrc0);
	decode_ssrc8(insn->sop2.ssrc1, insn->sop2.literal, ssrc1);
	pr_debug("knod_asm %s s%d, %s, %s\n",
		 opnames_gfx9[AMDGCN_INSN_TYPE_SOP2][insn->sop2.op],
		 insn->sop2.sdst, ssrc0, ssrc1);
}

static inline void gfx9_debug_sopk(union amdgcn_gfx9_insn *insn)
{
	pr_debug("knod_asm %s s%d, 0x%x\n",
		 opnames_gfx9[AMDGCN_INSN_TYPE_SOPK][insn->sopk.op],
		 insn->sopk.sdst, insn->sopk.simm16);
}

static inline void gfx9_debug_sopc(union amdgcn_gfx9_insn *insn)
{
	char ssrc0[20], ssrc1[20];

	decode_ssrc8(insn->sopc.ssrc0, insn->sopc.literal, ssrc0);
	decode_ssrc8(insn->sopc.ssrc1, insn->sopc.literal, ssrc1);
	pr_debug("knod_asm %s %s, %s\n",
		 opnames_gfx9[AMDGCN_INSN_TYPE_SOPC][insn->sopc.op],
		 ssrc0, ssrc1);
}

static inline void gfx9_debug_vop3p(union amdgcn_gfx9_insn *insn)
{
	char src0[20], src1[20], src2[20];

	decode_vsrc9(insn->vop3p.src0, insn->vop3p.literal, src0);
	decode_vsrc9(insn->vop3p.src1, insn->vop3p.literal, src1);
	decode_vsrc9(insn->vop3p.src2, insn->vop3p.literal, src2);
	pr_debug("knod_asm %s v%d, %s, %s, %s\n",
		 opnames_gfx9[AMDGCN_INSN_TYPE_VOP3P][insn->vop3p.op],
		 (int)insn->vop3p.vdst, src0, src1, src2);
}

static inline void gfx9_debug_sdwa(union amdgcn_gfx9_insn *insn)
{
	pr_debug("knod_asm sdwa src0:%d dst_sel:%d src0_sel:%d src1_sel:%d\n",
		 insn->sdwa.src0, insn->sdwa.dst_sel,
		 insn->sdwa.src0_sel, insn->sdwa.src1_sel);
}

static inline void gfx9_debug_sdwab(union amdgcn_gfx9_insn *insn)
{
	pr_debug("knod_asm sdwab src0:%d sdst:s%d src0_sel:%d src1_sel:%d\n",
		 insn->sdwab.src0, insn->sdwab.sdst,
		 insn->sdwab.src0_sel, insn->sdwab.src1_sel);
}

static inline void gfx9_debug_dpp16(union amdgcn_gfx9_insn *insn)
{
	pr_debug("knod_asm dpp16 (not decoded)\n");
}

static inline void gfx9_debug_dpp8(union amdgcn_gfx9_insn *insn)
{
	pr_debug("knod_asm dpp8 (not decoded)\n");
}

static inline void gfx9_debug_vintrp(union amdgcn_gfx9_insn *insn)
{
	pr_debug("knod_asm vintrp (not decoded)\n");
}

static inline void gfx9_debug_ds(union amdgcn_gfx9_insn *insn)
{
	pr_debug("knod_asm %s v%d, v%d, v%d, v%d offset0:%d offset1:%d%s\n",
		 opnames_gfx9[AMDGCN_INSN_TYPE_DS][insn->ds.op],
		 (int)insn->ds.vdst, (int)insn->ds.addr,
		 (int)insn->ds.data0, (int)insn->ds.data1,
		 (int)insn->ds.offset0, (int)insn->ds.offset1,
		 insn->ds.gds ? " gds" : "");
}

static inline void gfx9_debug_mtbuf(union amdgcn_gfx9_insn *insn)
{
	pr_debug("knod_asm %s v%d, v%d, s[%d:%d], s%d dfmt:%d nfmt:%d offset:%d\n",
		 opnames_gfx9[AMDGCN_INSN_TYPE_MTBUF][insn->mtbuf.op],
		 (int)insn->mtbuf.vdata, (int)insn->mtbuf.vaddr,
		 (int)insn->mtbuf.srsrc * 4, (int)insn->mtbuf.srsrc * 4 + 3,
		 (int)insn->mtbuf.soffset, (int)insn->mtbuf.dfmt,
		 (int)insn->mtbuf.nfmt, (int)insn->mtbuf.offset);
}

static inline void gfx9_debug_mimg(union amdgcn_gfx9_insn *insn)
{
	pr_debug("knod_asm mimg (not decoded)\n");
}

static inline void gfx9_debug_exp(union amdgcn_gfx9_insn *insn)
{
	pr_debug("knod_asm exp (not decoded)\n");
}

static inline void gfx9_debug_insn(struct amdgcn_insn *insn)
{
	u32 *ptr;

	switch (insn->type) {
	case AMDGCN_INSN_TYPE_SOP2:
		gfx9_debug_sop2(&insn->gfx9);
		break;
	case AMDGCN_INSN_TYPE_SOPK:
		gfx9_debug_sopk(&insn->gfx9);
		break;
	case AMDGCN_INSN_TYPE_SOP1:
		gfx9_debug_sop1(&insn->gfx9);
		break;
	case AMDGCN_INSN_TYPE_SOPC:
		gfx9_debug_sopc(&insn->gfx9);
		break;
	case AMDGCN_INSN_TYPE_SOPP:
		gfx9_debug_sopp(&insn->gfx9);
		break;
	case AMDGCN_INSN_TYPE_SMEM:
		gfx9_debug_smem(&insn->gfx9);
		break;
	case AMDGCN_INSN_TYPE_VOP2:
		gfx9_debug_vop2(&insn->gfx9);
		break;
	case AMDGCN_INSN_TYPE_VOP1:
		gfx9_debug_vop1(&insn->gfx9);
		break;
	case AMDGCN_INSN_TYPE_VOPC:
		gfx9_debug_vopc(&insn->gfx9);
		break;
	case AMDGCN_INSN_TYPE_VOP3A:
		gfx9_debug_vop3a(&insn->gfx9);
		break;
	case AMDGCN_INSN_TYPE_VOP3B:
		gfx9_debug_vop3b(&insn->gfx9);
		break;
	case AMDGCN_INSN_TYPE_VOP3P:
		gfx9_debug_vop3p(&insn->gfx9);
		break;
	case AMDGCN_INSN_TYPE_SDWA:
		gfx9_debug_sdwa(&insn->gfx9);
		break;
	case AMDGCN_INSN_TYPE_SDWAB:
		gfx9_debug_sdwab(&insn->gfx9);
		break;
	case AMDGCN_INSN_TYPE_DPP16:
		gfx9_debug_dpp16(&insn->gfx9);
		break;
	case AMDGCN_INSN_TYPE_DPP8:
		gfx9_debug_dpp8(&insn->gfx9);
		break;
	case AMDGCN_INSN_TYPE_VINTRP:
		gfx9_debug_vintrp(&insn->gfx9);
		break;
	case AMDGCN_INSN_TYPE_DS:
		gfx9_debug_ds(&insn->gfx9);
		break;
	case AMDGCN_INSN_TYPE_MTBUF:
		gfx9_debug_mtbuf(&insn->gfx9);
		break;
	case AMDGCN_INSN_TYPE_MUBUF:
		gfx9_debug_mubuf(&insn->gfx9);
		break;
	case AMDGCN_INSN_TYPE_MIMG:
		gfx9_debug_mimg(&insn->gfx9);
		break;
	case AMDGCN_INSN_TYPE_FLAT:
		gfx9_debug_global(&insn->gfx9);
		break;
	case AMDGCN_INSN_TYPE_EXP:
		gfx9_debug_exp(&insn->gfx9);
		break;
	default:
		WARN_ON(1);
		break;
	}

	ptr = (u32 *)&insn->gfx9;
	if (insn->size == 4) {
		pr_debug("knod_asm %s %u %.8X\n", __func__, __LINE__, ptr[0]);
	} else if (insn->size == 8) {
		pr_debug("knod_asm %s %u %.8X %.8X\n",
			 __func__, __LINE__, ptr[0], ptr[1]);
	} else if (insn->size == 12) {
		pr_debug("knod_asm %s %u %.8X %.8X %.8X\n",
			 __func__, __LINE__, ptr[0], ptr[1], ptr[2]);
	} else {
		WARN_ON(1);
	}
}

static inline void debug_insn(int version, struct amdgcn_insn *insn)
{
	if (version == 10)
		gfx10_debug_insn(insn);
	else if (version == 9)
		gfx9_debug_insn(insn);
	else
		WARN_ON(1);
}

static inline void gfx10_debugfs_vop3a(union amdgcn_gfx10_insn *insn,
				       struct seq_file *m)
{
	char src0[20];
	char src1[20];
	char src2[20];

	if (insn->vop3a.src0 < GFX10_VOP3A_SRC_VCC_LO)
		sprintf(src0, "s%d", insn->vop3a.src0);
	else if (insn->vop3a.src0 == GFX10_VOP3A_SRC_VCC_LO)
		sprintf(src0, "%s", "vcc_lo");
	else if (insn->vop3a.src0 == GFX10_VOP3A_SRC_VCC_HI)
		sprintf(src0, "%s", "vcc_hi");
	else if (insn->vop3a.src0 == GFX10_VOP3A_SRC_NULL)
		sprintf(src0, "%s", "null");
	else if (insn->vop3a.src0 == GFX10_VOP3A_SRC_EXEC_LO)
		sprintf(src0, "%s", "exec_lo");
	else if (insn->vop3a.src0 == GFX10_VOP3A_SRC_EXEC_HI)
		sprintf(src0, "%s", "exec_hi");
	else if (insn->vop3a.src0 < GFX10_VOP3A_SRC_INTEGER_MINUS_1)
		sprintf(src0, "0x%x",
			insn->vop3a.src0 - GFX10_VOP3A_SRC_INTEGER_0);
	else if (insn->vop3a.src0 < GFX10_VOP3A_SRC_SHARED_BASE)
		sprintf(src0, "-0x%x",
			insn->vop3a.src0 - GFX10_VOP3A_SRC_INTEGER_MINUS_1);
	else if (insn->vop3a.src0 == GFX10_VOP3A_SRC_VCCZ)
		sprintf(src0, "%s", "vcc");
	else if (insn->vop3a.src0 == GFX10_VOP3A_SRC_EXECZ)
		sprintf(src0, "%s", "exec");
	else if (insn->vop3a.src0 == GFX10_VOP3A_SRC_SCC)
		sprintf(src0, "%s", "scc");
	else if (insn->vop3a.src0 == GFX10_VOP3A_SRC_LITERAL_CONST)
		sprintf(src0, "0x%x", insn->vop3a.literal);
	else if (insn->vop3a.src0 >= GFX10_VOP3A_SRC_VGPR_BASE)
		sprintf(src0, "v%d",
			insn->vop3a.src0 - GFX10_VOP3A_SRC_VGPR_BASE);

	if (insn->vop3a.src1 < GFX10_VOP3A_SRC_VCC_LO)
		sprintf(src1, "s%d", insn->vop3a.src1);
	else if (insn->vop3a.src1 == GFX10_VOP3A_SRC_VCC_LO)
		sprintf(src1, "%s", "vcc_lo");
	else if (insn->vop3a.src1 == GFX10_VOP3A_SRC_VCC_HI)
		sprintf(src1, "%s", "vcc_hi");
	else if (insn->vop3a.src1 == GFX10_VOP3A_SRC_NULL)
		sprintf(src1, "%s", "null");
	else if (insn->vop3a.src1 == GFX10_VOP3A_SRC_EXEC_LO)
		sprintf(src1, "%s", "exec_lo");
	else if (insn->vop3a.src1 == GFX10_VOP3A_SRC_EXEC_HI)
		sprintf(src1, "%s", "exec_hi");
	else if (insn->vop3a.src1 < GFX10_VOP3A_SRC_INTEGER_MINUS_1)
		sprintf(src1, "0x%x",
			insn->vop3a.src1 - GFX10_VOP3A_SRC_INTEGER_0);
	else if (insn->vop3a.src1 < GFX10_VOP3A_SRC_SHARED_BASE)
		sprintf(src1, "-0x%x",
			insn->vop3a.src1 - GFX10_VOP3A_SRC_INTEGER_MINUS_1);
	else if (insn->vop3a.src1 == GFX10_VOP3A_SRC_VCCZ)
		sprintf(src1, "%s", "vcc");
	else if (insn->vop3a.src1 == GFX10_VOP3A_SRC_EXECZ)
		sprintf(src1, "%s", "exec");
	else if (insn->vop3a.src1 == GFX10_VOP3A_SRC_SCC)
		sprintf(src1, "%s", "scc");
	else if (insn->vop3a.src1 == GFX10_VOP3A_SRC_LITERAL_CONST)
		sprintf(src1, "0x%x", insn->vop3a.literal);
	else if (insn->vop3a.src1 >= GFX10_VOP3A_SRC_VGPR_BASE)
		sprintf(src1, "v%d",
			insn->vop3a.src1 - GFX10_VOP3A_SRC_VGPR_BASE);

	if (insn->vop3a.src2 < GFX10_VOP3A_SRC_VCC_LO)
		sprintf(src2, "s%d", insn->vop3a.src2);
	else if (insn->vop3a.src2 == GFX10_VOP3A_SRC_VCC_LO)
		sprintf(src2, "%s", "vcc_lo");
	else if (insn->vop3a.src2 == GFX10_VOP3A_SRC_VCC_HI)
		sprintf(src2, "%s", "vcc_hi");
	else if (insn->vop3a.src2 == GFX10_VOP3A_SRC_NULL)
		sprintf(src2, "%s", "null");
	else if (insn->vop3a.src2 == GFX10_VOP3A_SRC_EXEC_LO)
		sprintf(src2, "%s", "exec_lo");
	else if (insn->vop3a.src2 == GFX10_VOP3A_SRC_EXEC_HI)
		sprintf(src2, "%s", "exec_hi");
	else if (insn->vop3a.src2 < GFX10_VOP3A_SRC_INTEGER_MINUS_1)
		sprintf(src2, "0x%x",
			insn->vop3a.src2 - GFX10_VOP3A_SRC_INTEGER_0);
	else if (insn->vop3a.src2 < GFX10_VOP3A_SRC_SHARED_BASE)
		sprintf(src2, "-0x%x",
			insn->vop3a.src2 - GFX10_VOP3A_SRC_INTEGER_MINUS_1);
	else if (insn->vop3a.src2 == GFX10_VOP3A_SRC_VCCZ)
		sprintf(src2, "%s", "vcc");
	else if (insn->vop3a.src2 == GFX10_VOP3A_SRC_EXECZ)
		sprintf(src2, "%s", "exec");
	else if (insn->vop3a.src2 == GFX10_VOP3A_SRC_SCC)
		sprintf(src2, "%s", "scc");
	else if (insn->vop3a.src2 == GFX10_VOP3A_SRC_LITERAL_CONST)
		sprintf(src2, "0x%x", insn->vop3a.literal);
	else if (insn->vop3a.src2 >= GFX10_VOP3A_SRC_VGPR_BASE)
		sprintf(src2, "v%d",
			insn->vop3a.src2 - GFX10_VOP3A_SRC_VGPR_BASE);

	seq_printf(m, "%s v%d, %s, %s, %s\n",
		opnames_gfx10[AMDGCN_INSN_TYPE_VOP3A][insn->vop3a.op],
		insn->vop3a.vdst, src0, src1, src2);
}

static inline void gfx10_debugfs_vop3b(union amdgcn_gfx10_insn *insn,
				       struct seq_file *m)
{
	char src0[20];
	char src1[20];
	char src2[20];
	char sdst[20];

	if (insn->vop3b.sdst < GFX10_VOP3A_SRC_VCC_LO)
		sprintf(sdst, "s%d", insn->vop3b.sdst);
	else if (insn->vop3b.sdst == GFX10_VOP3A_SRC_VCC_LO)
		sprintf(sdst, "%s", "vcc_lo");
	else if (insn->vop3b.sdst == GFX10_VOP3A_SRC_VCC_HI)
		sprintf(sdst, "%s", "vcc_hi");
	else if (insn->vop3b.sdst == GFX10_VOP3A_SRC_NULL)
		sprintf(sdst, "%s", "null");
	else if (insn->vop3b.sdst == GFX10_VOP3A_SRC_EXEC_LO)
		sprintf(sdst, "%s", "exec_lo");
	else if (insn->vop3b.sdst == GFX10_VOP3A_SRC_EXEC_HI)
		sprintf(sdst, "%s", "exec_hi");
	else if (insn->vop3b.sdst < GFX10_VOP3A_SRC_INTEGER_MINUS_1)
		sprintf(sdst, "0x%x",
			insn->vop3b.sdst - GFX10_VOP3A_SRC_INTEGER_0);
	else if (insn->vop3b.sdst < GFX10_VOP3A_SRC_SHARED_BASE)
		sprintf(sdst, "-0x%x",
			insn->vop3b.sdst - GFX10_VOP3A_SRC_INTEGER_MINUS_1);
	else if (insn->vop3b.sdst == GFX10_VOP3A_SRC_VCCZ)
		sprintf(sdst, "%s", "vcc");
	else if (insn->vop3b.sdst == GFX10_VOP3A_SRC_EXECZ)
		sprintf(sdst, "%s", "exec");
	else if (insn->vop3b.sdst == GFX10_VOP3A_SRC_SCC)
		sprintf(sdst, "%s", "scc");
	else if (insn->vop3b.sdst == GFX10_VOP3A_SRC_LITERAL_CONST)
		sprintf(sdst, "0x%x", insn->vop3b.literal);
	else if (insn->vop3b.sdst >= GFX10_VOP3A_SRC_VGPR_BASE)
		sprintf(sdst, "v%d",
			insn->vop3b.sdst - GFX10_VOP3A_SRC_VGPR_BASE);

	if (insn->vop3b.src0 < GFX10_VOP3A_SRC_VCC_LO)
		sprintf(src0, "s%d", insn->vop3b.src0);
	else if (insn->vop3b.src0 == GFX10_VOP3A_SRC_VCC_LO)
		sprintf(src0, "%s", "vcc_lo");
	else if (insn->vop3b.src0 == GFX10_VOP3A_SRC_VCC_HI)
		sprintf(src0, "%s", "vcc_hi");
	else if (insn->vop3b.src0 == GFX10_VOP3A_SRC_NULL)
		sprintf(src0, "%s", "null");
	else if (insn->vop3b.src0 == GFX10_VOP3A_SRC_EXEC_LO)
		sprintf(src0, "%s", "exec_lo");
	else if (insn->vop3b.src0 == GFX10_VOP3A_SRC_EXEC_HI)
		sprintf(src0, "%s", "exec_hi");
	else if (insn->vop3b.src0 < GFX10_VOP3A_SRC_INTEGER_MINUS_1)
		sprintf(src0, "0x%x",
			insn->vop3b.src0 - GFX10_VOP3A_SRC_INTEGER_0);
	else if (insn->vop3b.src0 < GFX10_VOP3A_SRC_SHARED_BASE)
		sprintf(src0, "-0x%x",
			insn->vop3b.src0 - GFX10_VOP3A_SRC_INTEGER_MINUS_1);
	else if (insn->vop3b.src0 == GFX10_VOP3A_SRC_VCCZ)
		sprintf(src0, "%s", "vcc");
	else if (insn->vop3b.src0 == GFX10_VOP3A_SRC_EXECZ)
		sprintf(src0, "%s", "exec");
	else if (insn->vop3b.src0 == GFX10_VOP3A_SRC_SCC)
		sprintf(src0, "%s", "scc");
	else if (insn->vop3b.src0 == GFX10_VOP3A_SRC_LITERAL_CONST)
		sprintf(src0, "0x%x", insn->vop3b.literal);
	else if (insn->vop3b.src0 >= GFX10_VOP3A_SRC_VGPR_BASE)
		sprintf(src0, "v%d",
			insn->vop3b.src0 - GFX10_VOP3A_SRC_VGPR_BASE);

	if (insn->vop3b.src1 < GFX10_VOP3A_SRC_VCC_LO)
		sprintf(src1, "s%d", insn->vop3b.src1);
	else if (insn->vop3b.src1 == GFX10_VOP3A_SRC_VCC_LO)
		sprintf(src1, "%s", "vcc_lo");
	else if (insn->vop3b.src1 == GFX10_VOP3A_SRC_VCC_HI)
		sprintf(src1, "%s", "vcc_hi");
	else if (insn->vop3b.src1 == GFX10_VOP3A_SRC_NULL)
		sprintf(src1, "%s", "null");
	else if (insn->vop3b.src1 == GFX10_VOP3A_SRC_EXEC_LO)
		sprintf(src1, "%s", "exec_lo");
	else if (insn->vop3b.src1 == GFX10_VOP3A_SRC_EXEC_HI)
		sprintf(src1, "%s", "exec_hi");
	else if (insn->vop3b.src1 < GFX10_VOP3A_SRC_INTEGER_MINUS_1)
		sprintf(src1, "0x%x",
			insn->vop3b.src1 - GFX10_VOP3A_SRC_INTEGER_0);
	else if (insn->vop3b.src1 < GFX10_VOP3A_SRC_SHARED_BASE)
		sprintf(src1, "-0x%x",
			insn->vop3b.src1 - GFX10_VOP3A_SRC_INTEGER_MINUS_1);
	else if (insn->vop3b.src1 == GFX10_VOP3A_SRC_VCCZ)
		sprintf(src1, "%s", "vcc");
	else if (insn->vop3b.src1 == GFX10_VOP3A_SRC_EXECZ)
		sprintf(src1, "%s", "exec");
	else if (insn->vop3b.src1 == GFX10_VOP3A_SRC_SCC)
		sprintf(src1, "%s", "scc");
	else if (insn->vop3b.src1 == GFX10_VOP3A_SRC_LITERAL_CONST)
		sprintf(src1, "0x%x", insn->vop3b.literal);
	else if (insn->vop3b.src1 >= GFX10_VOP3A_SRC_VGPR_BASE)
		sprintf(src1, "v%d",
			insn->vop3b.src1 - GFX10_VOP3A_SRC_VGPR_BASE);

	if (insn->vop3b.src2 < GFX10_VOP3A_SRC_VCC_LO)
		sprintf(src2, "s%d", insn->vop3b.src2);
	else if (insn->vop3b.src2 == GFX10_VOP3A_SRC_VCC_LO)
		sprintf(src2, "%s", "vcc_lo");
	else if (insn->vop3b.src2 == GFX10_VOP3A_SRC_VCC_HI)
		sprintf(src2, "%s", "vcc_hi");
	else if (insn->vop3b.src2 == GFX10_VOP3A_SRC_NULL)
		sprintf(src2, "%s", "null");
	else if (insn->vop3b.src2 == GFX10_VOP3A_SRC_EXEC_LO)
		sprintf(src2, "%s", "exec_lo");
	else if (insn->vop3b.src2 == GFX10_VOP3A_SRC_EXEC_HI)
		sprintf(src2, "%s", "exec_hi");
	else if (insn->vop3b.src2 < GFX10_VOP3A_SRC_INTEGER_MINUS_1)
		sprintf(src2, "0x%x",
			insn->vop3b.src2 - GFX10_VOP3A_SRC_INTEGER_0);
	else if (insn->vop3b.src2 < GFX10_VOP3A_SRC_SHARED_BASE)
		sprintf(src2, "-0x%x",
			insn->vop3b.src2 - GFX10_VOP3A_SRC_INTEGER_MINUS_1);
	else if (insn->vop3b.src2 == GFX10_VOP3A_SRC_VCCZ)
		sprintf(src2, "%s", "vcc");
	else if (insn->vop3b.src2 == GFX10_VOP3A_SRC_EXECZ)
		sprintf(src2, "%s", "exec");
	else if (insn->vop3b.src2 == GFX10_VOP3A_SRC_SCC)
		sprintf(src2, "%s", "scc");
	else if (insn->vop3b.src2 == GFX10_VOP3A_SRC_LITERAL_CONST)
		sprintf(src2, "0x%x", insn->vop3b.literal);
	else if (insn->vop3b.src2 >= GFX10_VOP3A_SRC_VGPR_BASE)
		sprintf(src2, "v%d",
			insn->vop3b.src2 - GFX10_VOP3A_SRC_VGPR_BASE);

	seq_printf(m, "%s v%d, %s, %s, %s, %s\n",
		 opnames_gfx10[AMDGCN_INSN_TYPE_VOP3B][insn->vop3b.op],
		 insn->vop3b.vdst, sdst, src0, src1, src2);
}

static inline void gfx10_debugfs_vop1(union amdgcn_gfx10_insn *insn,
				      struct seq_file *m)
{
	char src0[20];

	if (insn->vop1.src0 < GFX10_VOP1_SRC_VCC_LO)
		sprintf(src0, "s%d", insn->vop1.src0);
	else if (insn->vop1.src0 == GFX10_VOP1_SRC_VCC_LO)
		sprintf(src0, "%s", "vcc_lo");
	else if (insn->vop1.src0 == GFX10_VOP1_SRC_VCC_HI)
		sprintf(src0, "%s", "vcc_hi");
	else if (insn->vop1.src0 == GFX10_VOP1_SRC_NULL)
		sprintf(src0, "%s", "null");
	else if (insn->vop1.src0 == GFX10_VOP1_SRC_EXEC_LO)
		sprintf(src0, "%s", "exec_lo");
	else if (insn->vop1.src0 == GFX10_VOP1_SRC_EXEC_HI)
		sprintf(src0, "%s", "exec_hi");
	else if (insn->vop1.src0 < GFX10_VOP1_SRC_INTEGER_MINUS_1)
		sprintf(src0, "0x%x",
			insn->vop1.src0 - GFX10_VOP1_SRC_INTEGER_0);
	else if (insn->vop1.src0 < GFX10_VOP1_SRC_SHARED_BASE)
		sprintf(src0, "-0x%x",
			insn->vop1.src0 - GFX10_VOP1_SRC_INTEGER_MINUS_1);
	else if (insn->vop1.src0 == GFX10_VOP1_SRC_VCCZ)
		sprintf(src0, "%s", "vcc");
	else if (insn->vop1.src0 == GFX10_VOP1_SRC_EXECZ)
		sprintf(src0, "%s", "exec");
	else if (insn->vop1.src0 == GFX10_VOP1_SRC_SCC)
		sprintf(src0, "%s", "scc");
	else if (insn->vop1.src0 == GFX10_VOP1_SRC_LITERAL_CONST)
		sprintf(src0, "0x%x", insn->vop1.literal);
	else if (insn->vop1.src0 >= GFX10_VOP1_SRC_VGPR_BASE)
		sprintf(src0, "v%d",
			insn->vop1.src0 - GFX10_VOP1_SRC_VGPR_BASE);

	seq_printf(m, "%s v%d, %s\n",
		 opnames_gfx10[AMDGCN_INSN_TYPE_VOP1][insn->vop1.op],
		 insn->vop1.vdst, src0);
}

static inline void gfx10_debugfs_vopc(union amdgcn_gfx10_insn *insn,
				      struct seq_file *m)
{
	char src0[20];

	if (insn->vopc.src0 < GFX10_VOPC_SRC_VCC_LO)
		sprintf(src0, "s%d", insn->vopc.src0);
	else if (insn->vopc.src0 == GFX10_VOPC_SRC_VCC_LO)
		sprintf(src0, "%s", "vcc_lo");
	else if (insn->vopc.src0 == GFX10_VOPC_SRC_VCC_HI)
		sprintf(src0, "%s", "vcc_hi");
	else if (insn->vopc.src0 == GFX10_VOPC_SRC_NULL)
		sprintf(src0, "%s", "null");
	else if (insn->vopc.src0 == GFX10_VOPC_SRC_EXEC_LO)
		sprintf(src0, "%s", "exec_lo");
	else if (insn->vopc.src0 == GFX10_VOPC_SRC_EXEC_HI)
		sprintf(src0, "%s", "exec_hi");
	else if (insn->vopc.src0 < GFX10_VOPC_SRC_INTEGER_MINUS_1)
		sprintf(src0, "0x%x",
			insn->vopc.src0 - GFX10_VOPC_SRC_INTEGER_0);
	else if (insn->vopc.src0 < GFX10_VOPC_SRC_SHARED_BASE)
		sprintf(src0, "-0x%x",
			insn->vopc.src0 - GFX10_VOPC_SRC_INTEGER_MINUS_1);
	else if (insn->vopc.src0 == GFX10_VOPC_SRC_VCCZ)
		sprintf(src0, "%s", "vcc");
	else if (insn->vopc.src0 == GFX10_VOPC_SRC_EXECZ)
		sprintf(src0, "%s", "exec");
	else if (insn->vopc.src0 == GFX10_VOPC_SRC_SCC)
		sprintf(src0, "%s", "scc");
	else if (insn->vopc.src0 == GFX10_VOPC_SRC_LITERAL_CONST)
		sprintf(src0, "0x%x", insn->vopc.literal);
	else if (insn->vopc.src0 >= GFX10_VOPC_SRC_VGPR_BASE)
		sprintf(src0, "v%d",
			insn->vopc.src0 - GFX10_VOPC_SRC_VGPR_BASE);

	seq_printf(m, "%s %s, v%d\n",
		 opnames_gfx10[AMDGCN_INSN_TYPE_VOPC][insn->vopc.op],
		 src0, insn->vopc.vsrc1);
}

static inline void gfx10_debugfs_vop2(union amdgcn_gfx10_insn *insn,
				      struct seq_file *m)
{
	char src0[20];

	if (insn->vop2.src0 < GFX10_VOP2_SRC_VCC_LO)
		sprintf(src0, "s%d", insn->vop2.src0);
	else if (insn->vop2.src0 == GFX10_VOP2_SRC_VCC_LO)
		sprintf(src0, "%s", "vcc_lo");
	else if (insn->vop2.src0 == GFX10_VOP2_SRC_VCC_HI)
		sprintf(src0, "%s", "vcc_hi");
	else if (insn->vop2.src0 == GFX10_VOP2_SRC_NULL)
		sprintf(src0, "%s", "null");
	else if (insn->vop2.src0 == GFX10_VOP2_SRC_EXEC_LO)
		sprintf(src0, "%s", "exec_lo");
	else if (insn->vop2.src0 == GFX10_VOP2_SRC_EXEC_HI)
		sprintf(src0, "%s", "exec_hi");
	else if (insn->vop2.src0 < GFX10_VOP2_SRC_INTEGER_MINUS_1)
		sprintf(src0, "0x%x",
			insn->vop2.src0 - GFX10_VOP2_SRC_INTEGER_0);
	else if (insn->vop2.src0 < GFX10_VOP2_SRC_SHARED_BASE)
		sprintf(src0, "-0x%x",
			insn->vop2.src0 - GFX10_VOP2_SRC_INTEGER_MINUS_1);
	else if (insn->vop2.src0 == GFX10_VOP2_SRC_VCCZ)
		sprintf(src0, "%s", "vcc");
	else if (insn->vop2.src0 == GFX10_VOP2_SRC_EXECZ)
		sprintf(src0, "%s", "exec");
	else if (insn->vop2.src0 == GFX10_VOP2_SRC_SCC)
		sprintf(src0, "%s", "scc");
	else if (insn->vop2.src0 == GFX10_VOP2_SRC_LITERAL_CONST)
		sprintf(src0, "0x%x", insn->vop2.literal);
	else if (insn->vop2.src0 >= GFX10_VOP2_SRC_VGPR_BASE)
		sprintf(src0, "v%d",
			insn->vop2.src0 - GFX10_VOP2_SRC_VGPR_BASE);

	seq_printf(m, "%s v%d, %s v%d\n",
		 opnames_gfx10[AMDGCN_INSN_TYPE_VOP2][insn->vop2.op],
		 insn->vop2.vdst,
		 src0,
		 insn->vop2.vsrc1);
}

static inline void gfx10_debugfs_sop1(union amdgcn_gfx10_insn *insn,
				      struct seq_file *m)
{
	char ssrc0[20];

	if (insn->sop1.ssrc0 < GFX10_SOP1_SSRC_VCC_LO)
		sprintf(ssrc0, "s%d", insn->sop1.ssrc0);
	else if (insn->sop1.ssrc0 == GFX10_SOP1_SSRC_VCC_LO)
		sprintf(ssrc0, "%s", "vcc_lo");
	else if (insn->sop1.ssrc0 == GFX10_SOP1_SSRC_VCC_HI)
		sprintf(ssrc0, "%s", "vcc_hi");
	else if (insn->sop1.ssrc0 == GFX10_SOP1_SSRC_NULL)
		sprintf(ssrc0, "%s", "null");
	else if (insn->sop1.ssrc0 == GFX10_SOP1_SSRC_EXEC_LO)
		sprintf(ssrc0, "%s", "exec_lo");
	else if (insn->sop1.ssrc0 == GFX10_SOP1_SSRC_EXEC_HI)
		sprintf(ssrc0, "%s", "exec_hi");
	else if (insn->sop1.ssrc0 < GFX10_SOP1_SSRC_INTEGER_MINUS_1)
		sprintf(ssrc0, "0x%x",
			insn->sop1.ssrc0 - GFX10_SOP1_SSRC_INTEGER_0);
	else if (insn->sop1.ssrc0 < GFX10_SOP1_SSRC_SHARED_BASE)
		sprintf(ssrc0, "-0x%x",
			insn->sop1.ssrc0 - GFX10_SOP1_SSRC_INTEGER_MINUS_1);
	else if (insn->sop1.ssrc0 == GFX10_SOP1_SSRC_VCCZ)
		sprintf(ssrc0, "%s", "vcc");
	else if (insn->sop1.ssrc0 == GFX10_SOP1_SSRC_EXECZ)
		sprintf(ssrc0, "%s", "exec");
	else if (insn->sop1.ssrc0 == GFX10_SOP1_SSRC_SCC)
		sprintf(ssrc0, "%s", "scc");
	else if (insn->sop1.ssrc0 == GFX10_SOP1_SSRC_LITERAL_CONST)
		sprintf(ssrc0, "0x%x", insn->sop1.literal);

	seq_printf(m, "%s s%d, %s\n",
		 opnames_gfx10[AMDGCN_INSN_TYPE_SOP1][insn->sop1.op],
		 insn->sop1.sdst,
		 ssrc0);
}

static inline void gfx10_debugfs_sopp(union amdgcn_gfx10_insn *insn,
				      struct seq_file *m)
{
	seq_printf(m, "%s 0x%x\n",
		 opnames_gfx10[AMDGCN_INSN_TYPE_SOPP][insn->sopp.op],
		 insn->sopp.simm16);
}

static inline void gfx10_debugfs_smem(union amdgcn_gfx10_insn *insn,
				      struct seq_file *m)
{
	seq_printf(m, "%s s[%d:%d], s[%d:%d], 0x%x\n",
		   opnames_gfx10[AMDGCN_INSN_TYPE_SMEM][insn->smem.op],
		   insn->smem.sdata,
		   insn->smem.sdata + 1,
		   (insn->smem.sbase * 2),
		   (insn->smem.sbase * 2) + 1,
		   insn->smem.offset);
}

static inline void gfx10_debugfs_mubuf(union amdgcn_gfx10_insn *insn,
				       struct seq_file *m)
{
	seq_printf(m, "%s v%d, v%d, s[%d:%d], 0x%x offen offset:%d\n",
		 opnames_gfx10[AMDGCN_INSN_TYPE_MUBUF][insn->mubuf.op],
		 insn->mubuf.vdata,
		 insn->mubuf.vaddr,
		 insn->mubuf.srsrc,
		 insn->mubuf.srsrc + 3,
		 insn->mubuf.soffset,
		 insn->mubuf.offset);
}

static inline void gfx10_debugfs_global(union amdgcn_gfx10_insn *insn,
					struct seq_file *m)
{
	if (insn->flat.op == GFX9_GLOBAL_STORE_BYTE) {
		seq_printf(m, "%s v[%d:%d], v%d, off offset:%d\n",
			 opnames_gfx10[AMDGCN_INSN_TYPE_FLAT][insn->flat.op],
			 insn->flat.addr,
			 insn->flat.addr + 1,
			 insn->flat.data,
			 insn->flat.offset);
	} else if (insn->flat.op == GFX9_GLOBAL_STORE_SHORT) {
		seq_printf(m, "%s v[%d:%d], v%d, off offset:%d\n",
			 opnames_gfx10[AMDGCN_INSN_TYPE_FLAT][insn->flat.op],
			 insn->flat.addr,
			 insn->flat.addr + 1,
			 insn->flat.data,
			 insn->flat.offset);
	} else if (insn->flat.op == GFX9_GLOBAL_STORE_DWORD) {
		seq_printf(m, "%s v[%d:%d], v%d, off offset:%d\n",
			 opnames_gfx10[AMDGCN_INSN_TYPE_FLAT][insn->flat.op],
			 insn->flat.addr,
			 insn->flat.addr + 1,
			 insn->flat.data,
			 insn->flat.offset);
	} else if (insn->flat.op == GFX9_GLOBAL_STORE_DWORDX2) {
		seq_printf(m, "%s v[%d:%d], v[%d:%d], off offset:%d\n",
			 opnames_gfx10[AMDGCN_INSN_TYPE_FLAT][insn->flat.op],
			 insn->flat.addr,
			 insn->flat.addr + 1,
			 insn->flat.data,
			 insn->flat.data + 1,
			 insn->flat.offset);
	} else {
		seq_printf(m, "%s v[%d:%d], v[%d:%d], off offset:%d\n",
			 opnames_gfx10[AMDGCN_INSN_TYPE_FLAT][insn->flat.op],
			 insn->flat.vdst,
			 insn->flat.vdst + 1,
			 insn->flat.addr,
			 insn->flat.addr + 1,
			 insn->flat.offset);
	}
}

static inline void gfx10_debugfs_sop2(union amdgcn_gfx10_insn *insn,
				      struct seq_file *m)
{
	char ssrc0[20], ssrc1[20];

	decode_ssrc8(insn->sop2.ssrc0, insn->sop2.literal, ssrc0);
	decode_ssrc8(insn->sop2.ssrc1, insn->sop2.literal, ssrc1);
	seq_printf(m, "%s s%d, %s, %s\n",
		 opnames_gfx10[AMDGCN_INSN_TYPE_SOP2][insn->sop2.op],
		 insn->sop2.sdst, ssrc0, ssrc1);
}

static inline void gfx10_debugfs_sopk(union amdgcn_gfx10_insn *insn,
				      struct seq_file *m)
{
	seq_printf(m, "%s s%d, 0x%x\n",
		 opnames_gfx10[AMDGCN_INSN_TYPE_SOPK][insn->sopk.op],
		 insn->sopk.sdst, insn->sopk.simm16);
}

static inline void gfx10_debugfs_sopc(union amdgcn_gfx10_insn *insn,
				      struct seq_file *m)
{
	char ssrc0[20], ssrc1[20];

	decode_ssrc8(insn->sopc.ssrc0, insn->sopc.literal, ssrc0);
	decode_ssrc8(insn->sopc.ssrc1, insn->sopc.literal, ssrc1);
	seq_printf(m, "%s %s, %s\n",
		 opnames_gfx10[AMDGCN_INSN_TYPE_SOPC][insn->sopc.op],
		 ssrc0, ssrc1);
}

static inline void gfx10_debugfs_vop3p(union amdgcn_gfx10_insn *insn,
					struct seq_file *m)
{
	char src0[20], src1[20], src2[20];

	decode_vsrc9(insn->vop3p.src0, insn->vop3p.literal, src0);
	decode_vsrc9(insn->vop3p.src1, insn->vop3p.literal, src1);
	decode_vsrc9(insn->vop3p.src2, insn->vop3p.literal, src2);
	seq_printf(m, "%s v%d, %s, %s, %s\n",
		 opnames_gfx10[AMDGCN_INSN_TYPE_VOP3P][insn->vop3p.op],
		 (int)insn->vop3p.vdst, src0, src1, src2);
}

static inline void gfx10_debugfs_sdwa(union amdgcn_gfx10_insn *insn,
				      struct seq_file *m)
{
	seq_printf(m, "sdwa src0:%d dst_sel:%d src0_sel:%d src1_sel:%d\n",
		 insn->sdwa.src0, insn->sdwa.dst_sel,
		 insn->sdwa.src0_sel, insn->sdwa.src1_sel);
}

static inline void gfx10_debugfs_sdwab(union amdgcn_gfx10_insn *insn,
					struct seq_file *m)
{
	seq_printf(m, "sdwab src0:%d sdst:s%d src0_sel:%d src1_sel:%d\n",
		 insn->sdwab.src0, insn->sdwab.sdst,
		 insn->sdwab.src0_sel, insn->sdwab.src1_sel);
}

static inline void gfx10_debugfs_dpp16(union amdgcn_gfx10_insn *insn,
					struct seq_file *m)
{
	seq_puts(m, "dpp16 (not decoded)\n");
}

static inline void gfx10_debugfs_dpp8(union amdgcn_gfx10_insn *insn,
				      struct seq_file *m)
{
	seq_puts(m, "dpp8 (not decoded)\n");
}

static inline void gfx10_debugfs_vintrp(union amdgcn_gfx10_insn *insn,
					 struct seq_file *m)
{
	seq_puts(m, "vintrp (not decoded)\n");
}

static inline void gfx10_debugfs_ds(union amdgcn_gfx10_insn *insn,
				    struct seq_file *m)
{
	seq_printf(m, "%s v%d, v%d, v%d, v%d offset0:%d offset1:%d%s\n",
		 opnames_gfx10[AMDGCN_INSN_TYPE_DS][insn->ds.op],
		 (int)insn->ds.vdst, (int)insn->ds.addr,
		 (int)insn->ds.data0, (int)insn->ds.data1,
		 (int)insn->ds.offset0, (int)insn->ds.offset1,
		 insn->ds.gds ? " gds" : "");
}

static inline void gfx10_debugfs_mtbuf(union amdgcn_gfx10_insn *insn,
					struct seq_file *m)
{
	seq_printf(m, "%s v%d, v%d, s[%d:%d], s%d format:%d offset:%d\n",
		 opnames_gfx10[AMDGCN_INSN_TYPE_MTBUF][insn->mtbuf.op],
		 (int)insn->mtbuf.vdata, (int)insn->mtbuf.vaddr,
		 (int)insn->mtbuf.srsrc * 4, (int)insn->mtbuf.srsrc * 4 + 3,
		 (int)insn->mtbuf.soffset, (int)insn->mtbuf.foamat,
		 (int)insn->mtbuf.offset);
}

static inline void gfx10_debugfs_mimg(union amdgcn_gfx10_insn *insn,
				      struct seq_file *m)
{
	seq_puts(m, "mimg (not decoded)\n");
}

static inline void gfx10_debugfs_exp(union amdgcn_gfx10_insn *insn,
				     struct seq_file *m)
{
	seq_puts(m, "exp (not decoded)\n");
}

static inline void gfx10_debugfs_insn(struct amdgcn_insn *insn,
				      struct seq_file *m)
{
	u32 *ptr = (u32 *)&insn->gfx10;

	if (insn->size == 4)
		seq_printf(m, "%.8X\t\t\t", ptr[0]);
	else if (insn->size == 8)
		seq_printf(m, "%.8X %.8X\t\t", ptr[0], ptr[1]);
	else if (insn->size == 12)
		seq_printf(m, "%.8X %.8X %.8X\t\t\t", ptr[0], ptr[1], ptr[2]);
	else
		WARN_ON(1);

	switch (insn->type) {
	case AMDGCN_INSN_TYPE_SOP2:
		gfx10_debugfs_sop2(&insn->gfx10, m);
		break;
	case AMDGCN_INSN_TYPE_SOPK:
		gfx10_debugfs_sopk(&insn->gfx10, m);
		break;
	case AMDGCN_INSN_TYPE_SOP1:
		gfx10_debugfs_sop1(&insn->gfx10, m);
		break;
	case AMDGCN_INSN_TYPE_SOPC:
		gfx10_debugfs_sopc(&insn->gfx10, m);
		break;
	case AMDGCN_INSN_TYPE_SOPP:
		gfx10_debugfs_sopp(&insn->gfx10, m);
		break;
	case AMDGCN_INSN_TYPE_SMEM:
		gfx10_debugfs_smem(&insn->gfx10, m);
		break;
	case AMDGCN_INSN_TYPE_VOP2:
		gfx10_debugfs_vop2(&insn->gfx10, m);
		break;
	case AMDGCN_INSN_TYPE_VOP1:
		gfx10_debugfs_vop1(&insn->gfx10, m);
		break;
	case AMDGCN_INSN_TYPE_VOPC:
		gfx10_debugfs_vopc(&insn->gfx10, m);
		break;
	case AMDGCN_INSN_TYPE_VOP3A:
		gfx10_debugfs_vop3a(&insn->gfx10, m);
		break;
	case AMDGCN_INSN_TYPE_VOP3B:
		gfx10_debugfs_vop3b(&insn->gfx10, m);
		break;
	case AMDGCN_INSN_TYPE_VOP3P:
		gfx10_debugfs_vop3p(&insn->gfx10, m);
		break;
	case AMDGCN_INSN_TYPE_SDWA:
		gfx10_debugfs_sdwa(&insn->gfx10, m);
		break;
	case AMDGCN_INSN_TYPE_SDWAB:
		gfx10_debugfs_sdwab(&insn->gfx10, m);
		break;
	case AMDGCN_INSN_TYPE_DPP16:
		gfx10_debugfs_dpp16(&insn->gfx10, m);
		break;
	case AMDGCN_INSN_TYPE_DPP8:
		gfx10_debugfs_dpp8(&insn->gfx10, m);
		break;
	case AMDGCN_INSN_TYPE_VINTRP:
		gfx10_debugfs_vintrp(&insn->gfx10, m);
		break;
	case AMDGCN_INSN_TYPE_DS:
		gfx10_debugfs_ds(&insn->gfx10, m);
		break;
	case AMDGCN_INSN_TYPE_MTBUF:
		gfx10_debugfs_mtbuf(&insn->gfx10, m);
		break;
	case AMDGCN_INSN_TYPE_MUBUF:
		gfx10_debugfs_mubuf(&insn->gfx10, m);
		break;
	case AMDGCN_INSN_TYPE_MIMG:
		gfx10_debugfs_mimg(&insn->gfx10, m);
		break;
	case AMDGCN_INSN_TYPE_FLAT:
		gfx10_debugfs_global(&insn->gfx10, m);
		break;
	case AMDGCN_INSN_TYPE_EXP:
		gfx10_debugfs_exp(&insn->gfx10, m);
		break;
	default:
		WARN_ON(1);
		break;
	}
}

static inline void gfx9_debugfs_vop3a(union amdgcn_gfx9_insn *insn,
				      struct seq_file *m)
{
	char src0[20];
	char src1[20];
	char src2[20];

	if (insn->vop3a.src0 < GFX9_VOP3A_SRC_VCC_LO)
		sprintf(src0, "s%d", insn->vop3a.src0);
	else if (insn->vop3a.src0 == GFX9_VOP3A_SRC_VCC_LO)
		sprintf(src0, "%s", "vcc_lo");
	else if (insn->vop3a.src0 == GFX9_VOP3A_SRC_VCC_HI)
		sprintf(src0, "%s", "vcc_hi");
	else if (insn->vop3a.src0 == GFX9_VOP3A_SRC_NULL)
		sprintf(src0, "%s", "null");
	else if (insn->vop3a.src0 == GFX9_VOP3A_SRC_EXEC_LO)
		sprintf(src0, "%s", "exec_lo");
	else if (insn->vop3a.src0 == GFX9_VOP3A_SRC_EXEC_HI)
		sprintf(src0, "%s", "exec_hi");
	else if (insn->vop3a.src0 < GFX9_VOP3A_SRC_INTEGER_MINUS_1)
		sprintf(src0, "0x%x",
			insn->vop3a.src0 - GFX9_VOP3A_SRC_INTEGER_0);
	else if (insn->vop3a.src0 < GFX9_VOP3A_SRC_SHARED_BASE)
		sprintf(src0, "-0x%x",
			insn->vop3a.src0 - GFX9_VOP3A_SRC_INTEGER_MINUS_1);
	else if (insn->vop3a.src0 == GFX9_VOP3A_SRC_VCCZ)
		sprintf(src0, "%s", "vcc");
	else if (insn->vop3a.src0 == GFX9_VOP3A_SRC_EXECZ)
		sprintf(src0, "%s", "exec");
	else if (insn->vop3a.src0 == GFX9_VOP3A_SRC_SCC)
		sprintf(src0, "%s", "scc");
	else if (insn->vop3a.src0 == GFX9_VOP3A_SRC_LITERAL_CONST)
		sprintf(src0, "0x%x", insn->vop3a.literal);
	else if (insn->vop3a.src0 >= GFX9_VOP3A_SRC_VGPR_BASE)
		sprintf(src0, "v%d",
			insn->vop3a.src0 - GFX9_VOP3A_SRC_VGPR_BASE);

	if (insn->vop3a.src1 < GFX9_VOP3A_SRC_VCC_LO)
		sprintf(src1, "s%d", insn->vop3a.src1);
	else if (insn->vop3a.src1 == GFX9_VOP3A_SRC_VCC_LO)
		sprintf(src1, "%s", "vcc_lo");
	else if (insn->vop3a.src1 == GFX9_VOP3A_SRC_VCC_HI)
		sprintf(src1, "%s", "vcc_hi");
	else if (insn->vop3a.src1 == GFX9_VOP3A_SRC_NULL)
		sprintf(src1, "%s", "null");
	else if (insn->vop3a.src1 == GFX9_VOP3A_SRC_EXEC_LO)
		sprintf(src1, "%s", "exec_lo");
	else if (insn->vop3a.src1 == GFX9_VOP3A_SRC_EXEC_HI)
		sprintf(src1, "%s", "exec_hi");
	else if (insn->vop3a.src1 < GFX9_VOP3A_SRC_INTEGER_MINUS_1)
		sprintf(src1, "0x%x",
			insn->vop3a.src1 - GFX9_VOP3A_SRC_INTEGER_0);
	else if (insn->vop3a.src1 < GFX9_VOP3A_SRC_SHARED_BASE)
		sprintf(src1, "-0x%x",
			insn->vop3a.src1 - GFX9_VOP3A_SRC_INTEGER_MINUS_1);
	else if (insn->vop3a.src1 == GFX9_VOP3A_SRC_VCCZ)
		sprintf(src1, "%s", "vcc");
	else if (insn->vop3a.src1 == GFX9_VOP3A_SRC_EXECZ)
		sprintf(src1, "%s", "exec");
	else if (insn->vop3a.src1 == GFX9_VOP3A_SRC_SCC)
		sprintf(src1, "%s", "scc");
	else if (insn->vop3a.src1 == GFX9_VOP3A_SRC_LITERAL_CONST)
		sprintf(src1, "0x%x", insn->vop3a.literal);
	else if (insn->vop3a.src1 >= GFX9_VOP3A_SRC_VGPR_BASE)
		sprintf(src1, "v%d",
			insn->vop3a.src1 - GFX9_VOP3A_SRC_VGPR_BASE);

	if (insn->vop3a.src2 < GFX9_VOP3A_SRC_VCC_LO)
		sprintf(src2, "s%d", insn->vop3a.src2);
	else if (insn->vop3a.src2 == GFX9_VOP3A_SRC_VCC_LO)
		sprintf(src2, "%s", "vcc_lo");
	else if (insn->vop3a.src2 == GFX9_VOP3A_SRC_VCC_HI)
		sprintf(src2, "%s", "vcc_hi");
	else if (insn->vop3a.src2 == GFX9_VOP3A_SRC_NULL)
		sprintf(src2, "%s", "null");
	else if (insn->vop3a.src2 == GFX9_VOP3A_SRC_EXEC_LO)
		sprintf(src2, "%s", "exec_lo");
	else if (insn->vop3a.src2 == GFX9_VOP3A_SRC_EXEC_HI)
		sprintf(src2, "%s", "exec_hi");
	else if (insn->vop3a.src2 < GFX9_VOP3A_SRC_INTEGER_MINUS_1)
		sprintf(src2, "0x%x",
			insn->vop3a.src2 - GFX9_VOP3A_SRC_INTEGER_0);
	else if (insn->vop3a.src2 < GFX9_VOP3A_SRC_SHARED_BASE)
		sprintf(src2, "-0x%x",
			insn->vop3a.src2 - GFX9_VOP3A_SRC_INTEGER_MINUS_1);
	else if (insn->vop3a.src2 == GFX9_VOP3A_SRC_VCCZ)
		sprintf(src2, "%s", "vcc");
	else if (insn->vop3a.src2 == GFX9_VOP3A_SRC_EXECZ)
		sprintf(src2, "%s", "exec");
	else if (insn->vop3a.src2 == GFX9_VOP3A_SRC_SCC)
		sprintf(src2, "%s", "scc");
	else if (insn->vop3a.src2 == GFX9_VOP3A_SRC_LITERAL_CONST)
		sprintf(src2, "0x%x", insn->vop3a.literal);
	else if (insn->vop3a.src2 >= GFX9_VOP3A_SRC_VGPR_BASE)
		sprintf(src2, "v%d",
			insn->vop3a.src2 - GFX9_VOP3A_SRC_VGPR_BASE);

	seq_printf(m, "%s v%d, %s, %s, %s\n",
		 opnames_gfx9[AMDGCN_INSN_TYPE_VOP3A][insn->vop3a.op],
		 insn->vop3a.vdst, src0, src1, src2);
}

static inline void gfx9_debugfs_vop3b(union amdgcn_gfx9_insn *insn,
				      struct seq_file *m)
{
	char src0[20];
	char src1[20];
	char src2[20];
	char sdst[20];

	if (insn->vop3b.sdst < GFX9_VOP3B_SRC_VCC_LO)
		sprintf(sdst, "s%d", insn->vop3b.sdst);
	else if (insn->vop3b.sdst == GFX9_VOP3B_SRC_VCC_LO)
		sprintf(sdst, "%s", "vcc_lo");
	else if (insn->vop3b.sdst == GFX9_VOP3B_SRC_VCC_HI)
		sprintf(sdst, "%s", "vcc_hi");
	else if (insn->vop3b.sdst == GFX9_VOP3B_SRC_NULL)
		sprintf(sdst, "%s", "null");
	else if (insn->vop3b.sdst == GFX9_VOP3B_SRC_EXEC_LO)
		sprintf(sdst, "%s", "exec_lo");
	else if (insn->vop3b.sdst == GFX9_VOP3B_SRC_EXEC_HI)
		sprintf(sdst, "%s", "exec_hi");
	else if (insn->vop3b.sdst < GFX9_VOP3B_SRC_INTEGER_MINUS_1)
		sprintf(sdst, "0x%x",
			insn->vop3b.sdst - GFX9_VOP3B_SRC_INTEGER_0);
	else if (insn->vop3b.sdst < GFX9_VOP3B_SRC_SHARED_BASE)
		sprintf(sdst, "-0x%x",
			insn->vop3b.sdst - GFX9_VOP3B_SRC_INTEGER_MINUS_1);
	else if (insn->vop3b.sdst == GFX9_VOP3B_SRC_VCCZ)
		sprintf(sdst, "%s", "vcc");
	else if (insn->vop3b.sdst == GFX9_VOP3B_SRC_EXECZ)
		sprintf(sdst, "%s", "exec");
	else if (insn->vop3b.sdst == GFX9_VOP3B_SRC_SCC)
		sprintf(sdst, "%s", "scc");
	else if (insn->vop3b.sdst == GFX9_VOP3B_SRC_LITERAL_CONST)
		sprintf(sdst, "0x%x", insn->vop3b.literal);
	else if (insn->vop3b.sdst >= GFX9_VOP3B_SRC_VGPR_BASE)
		sprintf(sdst, "v%d",
			insn->vop3b.sdst - GFX9_VOP3B_SRC_VGPR_BASE);

	if (insn->vop3b.src0 < GFX9_VOP3B_SRC_VCC_LO)
		sprintf(src0, "s%d", insn->vop3b.src0);
	else if (insn->vop3b.src0 == GFX9_VOP3B_SRC_VCC_LO)
		sprintf(src0, "%s", "vcc_lo");
	else if (insn->vop3b.src0 == GFX9_VOP3B_SRC_VCC_HI)
		sprintf(src0, "%s", "vcc_hi");
	else if (insn->vop3b.src0 == GFX9_VOP3B_SRC_NULL)
		sprintf(src0, "%s", "null");
	else if (insn->vop3b.src0 == GFX9_VOP3B_SRC_EXEC_LO)
		sprintf(src0, "%s", "exec_lo");
	else if (insn->vop3b.src0 == GFX9_VOP3B_SRC_EXEC_HI)
		sprintf(src0, "%s", "exec_hi");
	else if (insn->vop3b.src0 < GFX9_VOP3B_SRC_INTEGER_MINUS_1)
		sprintf(src0, "0x%x",
			insn->vop3b.src0 - GFX9_VOP3B_SRC_INTEGER_0);
	else if (insn->vop3b.src0 < GFX9_VOP3B_SRC_SHARED_BASE)
		sprintf(src0, "-0x%x",
			insn->vop3b.src0 - GFX9_VOP3B_SRC_INTEGER_MINUS_1);
	else if (insn->vop3b.src0 == GFX9_VOP3B_SRC_VCCZ)
		sprintf(src0, "%s", "vcc");
	else if (insn->vop3b.src0 == GFX9_VOP3B_SRC_EXECZ)
		sprintf(src0, "%s", "exec");
	else if (insn->vop3b.src0 == GFX9_VOP3B_SRC_SCC)
		sprintf(src0, "%s", "scc");
	else if (insn->vop3b.src0 == GFX9_VOP3B_SRC_LITERAL_CONST)
		sprintf(src0, "0x%x", insn->vop3b.literal);
	else if (insn->vop3b.src0 >= GFX9_VOP3B_SRC_VGPR_BASE)
		sprintf(src0, "v%d",
			insn->vop3b.src0 - GFX9_VOP3B_SRC_VGPR_BASE);

	if (insn->vop3b.src1 < GFX9_VOP3B_SRC_VCC_LO)
		sprintf(src1, "s%d", insn->vop3b.src1);
	else if (insn->vop3b.src1 == GFX9_VOP3B_SRC_VCC_LO)
		sprintf(src1, "%s", "vcc_lo");
	else if (insn->vop3b.src1 == GFX9_VOP3B_SRC_VCC_HI)
		sprintf(src1, "%s", "vcc_hi");
	else if (insn->vop3b.src1 == GFX9_VOP3B_SRC_NULL)
		sprintf(src1, "%s", "null");
	else if (insn->vop3b.src1 == GFX9_VOP3B_SRC_EXEC_LO)
		sprintf(src1, "%s", "exec_lo");
	else if (insn->vop3b.src1 == GFX9_VOP3B_SRC_EXEC_HI)
		sprintf(src1, "%s", "exec_hi");
	else if (insn->vop3b.src1 < GFX9_VOP3B_SRC_INTEGER_MINUS_1)
		sprintf(src1, "0x%x",
			insn->vop3b.src1 - GFX9_VOP3B_SRC_INTEGER_0);
	else if (insn->vop3b.src1 < GFX9_VOP3B_SRC_SHARED_BASE)
		sprintf(src1, "-0x%x",
			insn->vop3b.src1 - GFX9_VOP3B_SRC_INTEGER_MINUS_1);
	else if (insn->vop3b.src1 == GFX9_VOP3B_SRC_VCCZ)
		sprintf(src1, "%s", "vcc");
	else if (insn->vop3b.src1 == GFX9_VOP3B_SRC_EXECZ)
		sprintf(src1, "%s", "exec");
	else if (insn->vop3b.src1 == GFX9_VOP3B_SRC_SCC)
		sprintf(src1, "%s", "scc");
	else if (insn->vop3b.src1 == GFX9_VOP3B_SRC_LITERAL_CONST)
		sprintf(src1, "0x%x", insn->vop3b.literal);
	else if (insn->vop3b.src1 >= GFX9_VOP3B_SRC_VGPR_BASE)
		sprintf(src1, "v%d",
			insn->vop3b.src1 - GFX9_VOP3B_SRC_VGPR_BASE);

	if (insn->vop3b.src2 < GFX9_VOP3B_SRC_VCC_LO)
		sprintf(src2, "s%d", insn->vop3b.src2);
	else if (insn->vop3b.src2 == GFX9_VOP3B_SRC_VCC_LO)
		sprintf(src2, "%s", "vcc_lo");
	else if (insn->vop3b.src2 == GFX9_VOP3B_SRC_VCC_HI)
		sprintf(src2, "%s", "vcc_hi");
	else if (insn->vop3b.src2 == GFX9_VOP3B_SRC_NULL)
		sprintf(src2, "%s", "null");
	else if (insn->vop3b.src2 == GFX9_VOP3B_SRC_EXEC_LO)
		sprintf(src2, "%s", "exec_lo");
	else if (insn->vop3b.src2 == GFX9_VOP3B_SRC_EXEC_HI)
		sprintf(src2, "%s", "exec_hi");
	else if (insn->vop3b.src2 < GFX9_VOP3B_SRC_INTEGER_MINUS_1)
		sprintf(src2, "0x%x",
			insn->vop3b.src2 - GFX9_VOP3B_SRC_INTEGER_0);
	else if (insn->vop3b.src2 < GFX9_VOP3B_SRC_SHARED_BASE)
		sprintf(src2, "-0x%x",
			insn->vop3b.src2 - GFX9_VOP3B_SRC_INTEGER_MINUS_1);
	else if (insn->vop3b.src2 == GFX9_VOP3B_SRC_VCCZ)
		sprintf(src2, "%s", "vcc");
	else if (insn->vop3b.src2 == GFX9_VOP3B_SRC_EXECZ)
		sprintf(src2, "%s", "exec");
	else if (insn->vop3b.src2 == GFX9_VOP3B_SRC_SCC)
		sprintf(src2, "%s", "scc");
	else if (insn->vop3b.src2 == GFX9_VOP3B_SRC_LITERAL_CONST)
		sprintf(src2, "0x%x", insn->vop3b.literal);
	else if (insn->vop3b.src2 >= GFX9_VOP3B_SRC_VGPR_BASE)
		sprintf(src2, "v%d",
			insn->vop3b.src2 - GFX9_VOP3B_SRC_VGPR_BASE);

	seq_printf(m, "%s v%d, %s, %s, %s, %s\n",
		 opnames_gfx9[AMDGCN_INSN_TYPE_VOP3B][insn->vop3b.op],
		 insn->vop3b.vdst, sdst, src0, src1, src2);
}

static inline void gfx9_debugfs_vop1(union amdgcn_gfx9_insn *insn,
				     struct seq_file *m)
{
	char src0[20];

	if (insn->vop1.src0 < GFX9_VOP1_SRC_VCC_LO)
		sprintf(src0, "s%d", insn->vop1.src0);
	else if (insn->vop1.src0 == GFX9_VOP1_SRC_VCC_LO)
		sprintf(src0, "%s", "vcc_lo");
	else if (insn->vop1.src0 == GFX9_VOP1_SRC_VCC_HI)
		sprintf(src0, "%s", "vcc_hi");
	else if (insn->vop1.src0 == GFX9_VOP1_SRC_NULL)
		sprintf(src0, "%s", "null");
	else if (insn->vop1.src0 == GFX9_VOP1_SRC_EXEC_LO)
		sprintf(src0, "%s", "exec_lo");
	else if (insn->vop1.src0 == GFX9_VOP1_SRC_EXEC_HI)
		sprintf(src0, "%s", "exec_hi");
	else if (insn->vop1.src0 < GFX9_VOP1_SRC_INTEGER_MINUS_1)
		sprintf(src0, "0x%x",
			insn->vop1.src0 - GFX9_VOP1_SRC_INTEGER_0);
	else if (insn->vop1.src0 < GFX9_VOP1_SRC_SHARED_BASE)
		sprintf(src0, "-0x%x",
			insn->vop1.src0 - GFX9_VOP1_SRC_INTEGER_MINUS_1);
	else if (insn->vop1.src0 == GFX9_VOP1_SRC_VCCZ)
		sprintf(src0, "%s", "vcc");
	else if (insn->vop1.src0 == GFX9_VOP1_SRC_EXECZ)
		sprintf(src0, "%s", "exec");
	else if (insn->vop1.src0 == GFX9_VOP1_SRC_SCC)
		sprintf(src0, "%s", "scc");
	else if (insn->vop1.src0 == GFX9_VOP1_SRC_LITERAL_CONST)
		sprintf(src0, "0x%x", insn->vop1.literal);
	else if (insn->vop1.src0 >= GFX9_VOP1_SRC_VGPR_BASE)
		sprintf(src0, "v%d", insn->vop1.src0 - GFX9_VOP1_SRC_VGPR_BASE);

	seq_printf(m, "%s v%d, %s\n",
		 opnames_gfx9[AMDGCN_INSN_TYPE_VOP1][insn->vop1.op],
		 insn->vop1.vdst, src0);
}

static inline void gfx9_debugfs_vopc(union amdgcn_gfx9_insn *insn,
				     struct seq_file *m)
{
	char src0[20];

	if (insn->vopc.src0 < GFX9_VOPC_SRC_VCC_LO)
		sprintf(src0, "s%d", insn->vopc.src0);
	else if (insn->vopc.src0 == GFX9_VOPC_SRC_VCC_LO)
		sprintf(src0, "%s", "vcc_lo");
	else if (insn->vopc.src0 == GFX9_VOPC_SRC_VCC_HI)
		sprintf(src0, "%s", "vcc_hi");
	else if (insn->vopc.src0 == GFX9_VOPC_SRC_NULL)
		sprintf(src0, "%s", "null");
	else if (insn->vopc.src0 == GFX9_VOPC_SRC_EXEC_LO)
		sprintf(src0, "%s", "exec_lo");
	else if (insn->vopc.src0 == GFX9_VOPC_SRC_EXEC_HI)
		sprintf(src0, "%s", "exec_hi");
	else if (insn->vopc.src0 < GFX9_VOPC_SRC_INTEGER_MINUS_1)
		sprintf(src0, "0x%x",
			insn->vopc.src0 - GFX9_VOPC_SRC_INTEGER_0);
	else if (insn->vopc.src0 < GFX9_VOPC_SRC_SHARED_BASE)
		sprintf(src0, "-0x%x",
			insn->vopc.src0 - GFX9_VOPC_SRC_INTEGER_MINUS_1);
	else if (insn->vopc.src0 == GFX9_VOPC_SRC_VCCZ)
		sprintf(src0, "%s", "vcc");
	else if (insn->vopc.src0 == GFX9_VOPC_SRC_EXECZ)
		sprintf(src0, "%s", "exec");
	else if (insn->vopc.src0 == GFX9_VOPC_SRC_SCC)
		sprintf(src0, "%s", "scc");
	else if (insn->vopc.src0 == GFX9_VOPC_SRC_LITERAL_CONST)
		sprintf(src0, "0x%x", insn->vopc.literal);
	else if (insn->vopc.src0 >= GFX9_VOPC_SRC_VGPR_BASE)
		sprintf(src0, "v%d", insn->vopc.src0 - GFX9_VOPC_SRC_VGPR_BASE);

	seq_printf(m, "%s %s, v%d\n",
		opnames_gfx9[AMDGCN_INSN_TYPE_VOPC][insn->vopc.op],
		src0,
		insn->vopc.vsrc1);
}

static inline void gfx9_debugfs_vop2(union amdgcn_gfx9_insn *insn,
				     struct seq_file *m)
{
	char src0[20];

	if (insn->vop2.src0 < GFX9_VOP2_SRC_VCC_LO)
		sprintf(src0, "s%d", insn->vop2.src0);
	else if (insn->vop2.src0 == GFX9_VOP2_SRC_VCC_LO)
		sprintf(src0, "%s", "vcc_lo");
	else if (insn->vop2.src0 == GFX9_VOP2_SRC_VCC_HI)
		sprintf(src0, "%s", "vcc_hi");
	else if (insn->vop2.src0 == GFX9_VOP2_SRC_NULL)
		sprintf(src0, "%s", "null");
	else if (insn->vop2.src0 == GFX9_VOP2_SRC_EXEC_LO)
		sprintf(src0, "%s", "exec_lo");
	else if (insn->vop2.src0 == GFX9_VOP2_SRC_EXEC_HI)
		sprintf(src0, "%s", "exec_hi");
	else if (insn->vop2.src0 < GFX9_VOP2_SRC_INTEGER_MINUS_1)
		sprintf(src0, "0x%x",
			insn->vop2.src0 - GFX9_VOP2_SRC_INTEGER_0);
	else if (insn->vop2.src0 < GFX9_VOP2_SRC_SHARED_BASE)
		sprintf(src0, "-0x%x",
			insn->vop2.src0 - GFX9_VOP2_SRC_INTEGER_MINUS_1);
	else if (insn->vop2.src0 == GFX9_VOP2_SRC_VCCZ)
		sprintf(src0, "%s", "vcc");
	else if (insn->vop2.src0 == GFX9_VOP2_SRC_EXECZ)
		sprintf(src0, "%s", "exec");
	else if (insn->vop2.src0 == GFX9_VOP2_SRC_SCC)
		sprintf(src0, "%s", "scc");
	else if (insn->vop2.src0 == GFX9_VOP2_SRC_LITERAL_CONST)
		sprintf(src0, "0x%x", insn->vop2.literal);
	else if (insn->vop2.src0 >= GFX9_VOP2_SRC_VGPR_BASE)
		sprintf(src0, "v%d", insn->vop2.src0 - GFX9_VOP2_SRC_VGPR_BASE);

	seq_printf(m, "%s v%d, %s v%d\n",
		 opnames_gfx9[AMDGCN_INSN_TYPE_VOP2][insn->vop2.op],
		 insn->vop2.vdst,
		 src0,
		 insn->vop2.vsrc1);
}

static inline void gfx9_debugfs_sop1(union amdgcn_gfx9_insn *insn,
				     struct seq_file *m)
{
	char ssrc0[20];

	if (insn->sop1.ssrc0 < GFX9_SOP1_SSRC_VCC_LO)
		sprintf(ssrc0, "s%d", insn->sop1.ssrc0);
	else if (insn->sop1.ssrc0 == GFX9_SOP1_SSRC_VCC_LO)
		sprintf(ssrc0, "%s", "vcc_lo");
	else if (insn->sop1.ssrc0 == GFX9_SOP1_SSRC_VCC_HI)
		sprintf(ssrc0, "%s", "vcc_hi");
	else if (insn->sop1.ssrc0 == GFX9_SOP1_SSRC_NULL)
		sprintf(ssrc0, "%s", "null");
	else if (insn->sop1.ssrc0 == GFX9_SOP1_SSRC_EXEC_LO)
		sprintf(ssrc0, "%s", "exec_lo");
	else if (insn->sop1.ssrc0 == GFX9_SOP1_SSRC_EXEC_HI)
		sprintf(ssrc0, "%s", "exec_hi");
	else if (insn->sop1.ssrc0 < GFX9_SOP1_SSRC_INTEGER_MINUS_1)
		sprintf(ssrc0, "0x%x",
			insn->sop1.ssrc0 - GFX9_SOP1_SSRC_INTEGER_0);
	else if (insn->sop1.ssrc0 < GFX9_SOP1_SSRC_SHARED_BASE)
		sprintf(ssrc0, "-0x%x",
			insn->sop1.ssrc0 - GFX9_SOP1_SSRC_INTEGER_MINUS_1);
	else if (insn->sop1.ssrc0 == GFX9_SOP1_SSRC_VCCZ)
		sprintf(ssrc0, "%s", "vcc");
	else if (insn->sop1.ssrc0 == GFX9_SOP1_SSRC_EXECZ)
		sprintf(ssrc0, "%s", "exec");
	else if (insn->sop1.ssrc0 == GFX9_SOP1_SSRC_SCC)
		sprintf(ssrc0, "%s", "scc");
	else if (insn->sop1.ssrc0 == GFX9_SOP1_SSRC_LITERAL_CONST)
		sprintf(ssrc0, "0x%x", insn->sop1.literal);

	seq_printf(m, "%s s%d, %s\n",
		 opnames_gfx9[AMDGCN_INSN_TYPE_SOP1][insn->sop1.op],
		 insn->sop1.sdst,
		 ssrc0);
}

static inline void gfx9_debugfs_sopp(union amdgcn_gfx9_insn *insn,
				     struct seq_file *m)
{
	seq_printf(m, "%s 0x%x\n",
		 opnames_gfx9[AMDGCN_INSN_TYPE_SOPP][insn->sopp.op],
		 insn->sopp.simm16);
}

static inline void gfx9_debugfs_smem(union amdgcn_gfx9_insn *insn,
				     struct seq_file *m)
{
	seq_printf(m, "%s s[%d:%d], s[%d:%d], 0x%x\n",
		   opnames_gfx9[AMDGCN_INSN_TYPE_SMEM][insn->smem.op],
		   insn->smem.sdata,
		   insn->smem.sdata + 1,
		   (insn->smem.sbase * 2),
		   (insn->smem.sbase * 2) + 1,
		   insn->smem.offset);
}

static inline void gfx9_debugfs_mubuf(union amdgcn_gfx9_insn *insn,
				      struct seq_file *m)
{
	seq_printf(m, "%s v%d, v%d, s[%d:%d], 0x%x offen offset:%d\n",
		 opnames_gfx9[AMDGCN_INSN_TYPE_MUBUF][insn->mubuf.op],
		 insn->mubuf.vdata,
		 insn->mubuf.vaddr,
		 insn->mubuf.srsrc,
		 insn->mubuf.srsrc + 3,
		 insn->mubuf.soffset,
		 insn->mubuf.offset);
}

static inline void gfx9_debugfs_global(union amdgcn_gfx9_insn *insn,
				       struct seq_file *m)
{
	if (insn->flat.op == GFX9_GLOBAL_STORE_BYTE) {
		seq_printf(m, "%s v[%d:%d], v%d, off offset:%d\n",
			opnames_gfx9[AMDGCN_INSN_TYPE_FLAT][insn->flat.op],
			insn->flat.addr,
			insn->flat.addr + 1,
			insn->flat.data,
			insn->flat.offset);
	} else if (insn->flat.op == GFX9_GLOBAL_STORE_SHORT) {
		seq_printf(m, "%s v[%d:%d], v%d, off offset:%d\n",
			opnames_gfx9[AMDGCN_INSN_TYPE_FLAT][insn->flat.op],
			insn->flat.addr,
			insn->flat.addr + 1,
			insn->flat.data,
			insn->flat.offset);
	} else if (insn->flat.op == GFX9_GLOBAL_STORE_DWORD) {
		seq_printf(m, "%s v[%d:%d], v%d, off offset:%d\n",
			opnames_gfx9[AMDGCN_INSN_TYPE_FLAT][insn->flat.op],
			insn->flat.addr,
			insn->flat.addr + 1,
			insn->flat.data,
			insn->flat.offset);
	} else if (insn->flat.op == GFX9_GLOBAL_STORE_DWORDX2) {
		seq_printf(m, "%s v[%d:%d], v[%d:%d], off offset:%d\n",
			opnames_gfx9[AMDGCN_INSN_TYPE_FLAT][insn->flat.op],
			insn->flat.addr,
			insn->flat.addr + 1,
			insn->flat.data,
			insn->flat.data + 1,
			insn->flat.offset);
	} else {
		seq_printf(m, "%s v[%d:%d], v[%d:%d], off offset:%d\n",
			opnames_gfx9[AMDGCN_INSN_TYPE_FLAT][insn->flat.op],
			insn->flat.vdst,
			insn->flat.vdst + 1,
			insn->flat.addr,
			insn->flat.addr + 1,
			insn->flat.offset);
	}
}

static inline void gfx9_debugfs_sop2(union amdgcn_gfx9_insn *insn,
				     struct seq_file *m)
{
	char ssrc0[20], ssrc1[20];

	decode_ssrc8(insn->sop2.ssrc0, insn->sop2.literal, ssrc0);
	decode_ssrc8(insn->sop2.ssrc1, insn->sop2.literal, ssrc1);
	seq_printf(m, "%s s%d, %s, %s\n",
		 opnames_gfx9[AMDGCN_INSN_TYPE_SOP2][insn->sop2.op],
		 insn->sop2.sdst, ssrc0, ssrc1);
}

static inline void gfx9_debugfs_sopk(union amdgcn_gfx9_insn *insn,
				     struct seq_file *m)
{
	seq_printf(m, "%s s%d, 0x%x\n",
		 opnames_gfx9[AMDGCN_INSN_TYPE_SOPK][insn->sopk.op],
		 insn->sopk.sdst, insn->sopk.simm16);
}

static inline void gfx9_debugfs_sopc(union amdgcn_gfx9_insn *insn,
				     struct seq_file *m)
{
	char ssrc0[20], ssrc1[20];

	decode_ssrc8(insn->sopc.ssrc0, insn->sopc.literal, ssrc0);
	decode_ssrc8(insn->sopc.ssrc1, insn->sopc.literal, ssrc1);
	seq_printf(m, "%s %s, %s\n",
		 opnames_gfx9[AMDGCN_INSN_TYPE_SOPC][insn->sopc.op],
		 ssrc0, ssrc1);
}

static inline void gfx9_debugfs_vop3p(union amdgcn_gfx9_insn *insn,
				      struct seq_file *m)
{
	char src0[20], src1[20], src2[20];

	decode_vsrc9(insn->vop3p.src0, insn->vop3p.literal, src0);
	decode_vsrc9(insn->vop3p.src1, insn->vop3p.literal, src1);
	decode_vsrc9(insn->vop3p.src2, insn->vop3p.literal, src2);
	seq_printf(m, "%s v%d, %s, %s, %s\n",
		 opnames_gfx9[AMDGCN_INSN_TYPE_VOP3P][insn->vop3p.op],
		 (int)insn->vop3p.vdst, src0, src1, src2);
}

static inline void gfx9_debugfs_sdwa(union amdgcn_gfx9_insn *insn,
				     struct seq_file *m)
{
	seq_printf(m, "sdwa src0:%d dst_sel:%d src0_sel:%d src1_sel:%d\n",
		 insn->sdwa.src0, insn->sdwa.dst_sel,
		 insn->sdwa.src0_sel, insn->sdwa.src1_sel);
}

static inline void gfx9_debugfs_sdwab(union amdgcn_gfx9_insn *insn,
				      struct seq_file *m)
{
	seq_printf(m, "sdwab src0:%d sdst:s%d src0_sel:%d src1_sel:%d\n",
		 insn->sdwab.src0, insn->sdwab.sdst,
		 insn->sdwab.src0_sel, insn->sdwab.src1_sel);
}

static inline void gfx9_debugfs_dpp16(union amdgcn_gfx9_insn *insn,
				      struct seq_file *m)
{
	seq_puts(m, "dpp16 (not decoded)\n");
}

static inline void gfx9_debugfs_dpp8(union amdgcn_gfx9_insn *insn,
				     struct seq_file *m)
{
	seq_puts(m, "dpp8 (not decoded)\n");
}

static inline void gfx9_debugfs_vintrp(union amdgcn_gfx9_insn *insn,
					struct seq_file *m)
{
	seq_puts(m, "vintrp (not decoded)\n");
}

static inline void gfx9_debugfs_ds(union amdgcn_gfx9_insn *insn,
				   struct seq_file *m)
{
	seq_printf(m, "%s v%d, v%d, v%d, v%d offset0:%d offset1:%d%s\n",
		 opnames_gfx9[AMDGCN_INSN_TYPE_DS][insn->ds.op],
		 (int)insn->ds.vdst, (int)insn->ds.addr,
		 (int)insn->ds.data0, (int)insn->ds.data1,
		 (int)insn->ds.offset0, (int)insn->ds.offset1,
		 insn->ds.gds ? " gds" : "");
}

static inline void gfx9_debugfs_mtbuf(union amdgcn_gfx9_insn *insn,
				      struct seq_file *m)
{
	seq_printf(m, "%s v%d, v%d, s[%d:%d], s%d dfmt:%d nfmt:%d offset:%d\n",
		 opnames_gfx9[AMDGCN_INSN_TYPE_MTBUF][insn->mtbuf.op],
		 (int)insn->mtbuf.vdata, (int)insn->mtbuf.vaddr,
		 (int)insn->mtbuf.srsrc * 4, (int)insn->mtbuf.srsrc * 4 + 3,
		 (int)insn->mtbuf.soffset, (int)insn->mtbuf.dfmt,
		 (int)insn->mtbuf.nfmt, (int)insn->mtbuf.offset);
}

static inline void gfx9_debugfs_mimg(union amdgcn_gfx9_insn *insn,
				     struct seq_file *m)
{
	seq_puts(m, "mimg (not decoded)\n");
}

static inline void gfx9_debugfs_exp(union amdgcn_gfx9_insn *insn,
				    struct seq_file *m)
{
	seq_puts(m, "exp (not decoded)\n");
}

static inline void gfx9_debugfs_insn(struct amdgcn_insn *insn,
				     struct seq_file *m)
{
	u32 *ptr = (u32 *)&insn->gfx9;

	if (insn->size == 4)
		seq_printf(m, "%.8X\t\t\t", ptr[0]);
	else if (insn->size == 8)
		seq_printf(m, "%.8X %.8X\t\t", ptr[0], ptr[1]);
	else if (insn->size == 12)
		seq_printf(m, "%.8X %.8X %.8X\t", ptr[0], ptr[1], ptr[2]);
	else
		WARN_ON(1);

	switch (insn->type) {
	case AMDGCN_INSN_TYPE_SOP2:
		gfx9_debugfs_sop2(&insn->gfx9, m);
		break;
	case AMDGCN_INSN_TYPE_SOPK:
		gfx9_debugfs_sopk(&insn->gfx9, m);
		break;
	case AMDGCN_INSN_TYPE_SOP1:
		gfx9_debugfs_sop1(&insn->gfx9, m);
		break;
	case AMDGCN_INSN_TYPE_SOPC:
		gfx9_debugfs_sopc(&insn->gfx9, m);
		break;
	case AMDGCN_INSN_TYPE_SOPP:
		gfx9_debugfs_sopp(&insn->gfx9, m);
		break;
	case AMDGCN_INSN_TYPE_SMEM:
		gfx9_debugfs_smem(&insn->gfx9, m);
		break;
	case AMDGCN_INSN_TYPE_VOP2:
		gfx9_debugfs_vop2(&insn->gfx9, m);
		break;
	case AMDGCN_INSN_TYPE_VOP1:
		gfx9_debugfs_vop1(&insn->gfx9, m);
		break;
	case AMDGCN_INSN_TYPE_VOPC:
		gfx9_debugfs_vopc(&insn->gfx9, m);
		break;
	case AMDGCN_INSN_TYPE_VOP3A:
		gfx9_debugfs_vop3a(&insn->gfx9, m);
		break;
	case AMDGCN_INSN_TYPE_VOP3B:
		gfx9_debugfs_vop3b(&insn->gfx9, m);
		break;
	case AMDGCN_INSN_TYPE_VOP3P:
		gfx9_debugfs_vop3p(&insn->gfx9, m);
		break;
	case AMDGCN_INSN_TYPE_SDWA:
		gfx9_debugfs_sdwa(&insn->gfx9, m);
		break;
	case AMDGCN_INSN_TYPE_SDWAB:
		gfx9_debugfs_sdwab(&insn->gfx9, m);
		break;
	case AMDGCN_INSN_TYPE_DPP16:
		gfx9_debugfs_dpp16(&insn->gfx9, m);
		break;
	case AMDGCN_INSN_TYPE_DPP8:
		gfx9_debugfs_dpp8(&insn->gfx9, m);
		break;
	case AMDGCN_INSN_TYPE_VINTRP:
		gfx9_debugfs_vintrp(&insn->gfx9, m);
		break;
	case AMDGCN_INSN_TYPE_DS:
		gfx9_debugfs_ds(&insn->gfx9, m);
		break;
	case AMDGCN_INSN_TYPE_MTBUF:
		gfx9_debugfs_mtbuf(&insn->gfx9, m);
		break;
	case AMDGCN_INSN_TYPE_MUBUF:
		gfx9_debugfs_mubuf(&insn->gfx9, m);
		break;
	case AMDGCN_INSN_TYPE_MIMG:
		gfx9_debugfs_mimg(&insn->gfx9, m);
		break;
	case AMDGCN_INSN_TYPE_FLAT:
		gfx9_debugfs_global(&insn->gfx9, m);
		break;
	case AMDGCN_INSN_TYPE_EXP:
		gfx9_debugfs_exp(&insn->gfx9, m);
		break;
	default:
		WARN_ON(1);
		break;
	}
}

static inline void debugfs_insn(int version, struct amdgcn_insn *insn,
				struct seq_file *m)
{
	if (version == 10)
		gfx10_debugfs_insn(insn, m);
	else if (version == 9)
		gfx9_debugfs_insn(insn, m);
	else
		WARN_ON(1);
}

/*
 * Recover instruction type + size from a raw machine-code word stream into a
 * struct amdgcn_insn, so code holding only the emitted u32 blob (the feature
 * shaders emit via the low-level emit_gfxN_* helpers straight into the GPU
 * code buffer, discarding type/size) can be fed to the shared disassembler
 * debugfs_insn() instead of a per-feature hand-rolled hex re-parser.
 *
 * This mirrors the proven encoding-detection that used to live in the
 * per-feature disassemblers. The checks are ordered widest
 * fixed-prefix first: SOPP/SOP1/SOPC (9-bit enc) before SOPK (4-bit) before
 * SOP2 (2-bit), and every bit31==1 class (VOP1/VOPC/SMEM/DS/FLAT/MUBUF/VOP3)
 * before the VOP2 (bit31==0) catch-all. Version-specific encodings: SMEM
 * (gfx9 0x30 / gfx10 0x3d), SOPC literal (gfx10 only) and VOP3 (gfx9 0x34 /
 * gfx10 0x35). size is in bytes (4/8/12) to match what emit_* stamps in.
 */
static inline void amdgcn_classify(int version, const u32 *code,
				   struct amdgcn_insn *out)
{
	enum amdgcn_insn_type type;
	u32 w0 = code[0];
	bool is_b;
	u32 dwords;
	u32 enc;
	u32 op;

	enc = (w0 >> 23) & 0x1ff;

	if (enc == 0x17f) {				/* SOPP */
		type = AMDGCN_INSN_TYPE_SOPP;
		dwords = 1;
	} else if (enc == 0x17d) {			/* SOP1 */
		type = AMDGCN_INSN_TYPE_SOP1;
		dwords = ((w0 & 0xff) == 0xff) ? 2 : 1;
	} else if (enc == 0x17e) {			/* SOPC */
		type = AMDGCN_INSN_TYPE_SOPC;
		dwords = (version == 10 &&
			  ((w0 & 0xff) == 0xff || ((w0 >> 8) & 0xff) == 0xff))
			 ? 2 : 1;
	} else if (((w0 >> 28) & 0xf) == 0xb) {		/* SOPK */
		type = AMDGCN_INSN_TYPE_SOPK;
		dwords = 1;
	} else if (((w0 >> 30) & 0x3) == 0x2) {		/* SOP2 */
		type = AMDGCN_INSN_TYPE_SOP2;
		dwords = ((w0 & 0xff) == 0xff ||
			  ((w0 >> 8) & 0xff) == 0xff) ? 2 : 1;
	} else if (((w0 >> 26) & 0x3f) ==
		   (version == 10 ? 0x3d : 0x30)) {	/* SMEM */
		type = AMDGCN_INSN_TYPE_SMEM;
		dwords = 2;
	} else if (((w0 >> 25) & 0x7f) == 0x3f) {	/* VOP1 */
		type = AMDGCN_INSN_TYPE_VOP1;
		dwords = ((w0 & 0xff) == 0xff) ? 2 : 1;
	} else if (((w0 >> 25) & 0x7f) == 0x3e) {	/* VOPC */
		type = AMDGCN_INSN_TYPE_VOPC;
		dwords = 1;
	} else if (((w0 >> 26) & 0x3f) == 0x36) {	/* DS */
		type = AMDGCN_INSN_TYPE_DS;
		dwords = 2;
	/* FLAT/GLOBAL/SCRATCH */
	} else if (((w0 >> 26) & 0x3f) == 0x37) {
		type = AMDGCN_INSN_TYPE_FLAT;
		dwords = 2;
	} else if (((w0 >> 26) & 0x3f) == 0x38) {	/* MUBUF */
		type = AMDGCN_INSN_TYPE_MUBUF;
		dwords = 2;
	} else if (((w0 >> 26) & 0x3f) ==
		   (version == 10 ? 0x35 : 0x34)) {	/* VOP3A / VOP3B */
		op = (w0 >> 16) & 0x3ff;
		if (version == 10)
			is_b = (op == GFX10_V_ADD_CO_U32 ||
				op == GFX10_V_SUB_CO_U32 ||
				op == GFX10_V_SUBREV_CO_U32 ||
				op == GFX10_V_MAD_U64_U32 ||
				op == GFX10_V_MAD_I64_I32 ||
				op == GFX10_V_DIV_SCALE_F32 ||
				op == GFX10_V_DIV_SCALE_F64);
		else
			is_b = (op == GFX9_V_MAD_U64_U32 ||
				op == GFX9_V_MAD_I64_I32 ||
				op == GFX9_V_DIV_SCALE_F64);
		type = is_b ? AMDGCN_INSN_TYPE_VOP3B : AMDGCN_INSN_TYPE_VOP3A;
		dwords = 2;
	} else if (((w0 >> 31) & 0x1) == 0) {		/* VOP2 */
		type = AMDGCN_INSN_TYPE_VOP2;
		dwords = ((w0 & 0xff) == 0xff) ? 2 : 1;
	} else {					/* unknown: 1 dword */
		type = AMDGCN_INSN_TYPE_SOPP;
		dwords = 1;
	}

	memset(out, 0, sizeof(*out));
	out->type = type;
	out->size = dwords * 4;
	memcpy(&out->gfx10, code, dwords * 4);
}

/*
 * Drop-in replacement for the old per-feature hex re-parsers: classify
 * one raw instruction at @code, print it through the
 * shared (complete-opnames) disassembler, and return the number of dwords
 * consumed so the caller can advance. @max_dwords guards against reading a
 * second dword past the end of the buffer.
 */
static inline int amdgcn_disasm_raw(int version, const u32 *code,
				    int max_dwords, struct seq_file *m)
{
	struct amdgcn_insn insn;

	if (max_dwords <= 0)
		return 1;
	amdgcn_classify(version, code, &insn);
	if ((int)(insn.size / 4) > max_dwords) {
		seq_printf(m, "%.8X\t\t\t(truncated)\n", code[0]);
		return 1;
	}
	debugfs_insn(version, &insn, m);
	return insn.size / 4;
}


#endif
