/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (c) 2021 Taehee Yoo <ap420073@gmail.com>
 * Copyright (c) 2021 Hoyeon Lee <hoyeon.rhee@gmail.com>
 */

#ifndef KFD_AMDGPU_INSN_H_INCLUDED
#define KFD_AMDGPU_INSN_H_INCLUDED

#include <linux/seq_file.h>
#include "knod_amdgpu.h"
#include "knod_gfx11_insn.h"
#include "knod_gfx10_insn.h"

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

struct amdgcn_insn  {
	union {
		union amdgcn_gfx11_insn gfx11;
		union amdgcn_gfx10_insn gfx10;
	};
	u32 size;
	u32 idx;
	enum amdgcn_insn_type type;
};

/*
 * An instruction both generations encode from the same operands:
 * emit_<name>() runs @check, then the generation's encoder, and records the
 * format.  @params and @args go in parentheses.
 */
#define KNOD_UNPAREN(...)	__VA_ARGS__
#define KNOD_EMIT_CHECKED(name, kind, params, args, check...)		\
static inline void emit_##name(int version, struct amdgcn_insn *insn,	\
			       KNOD_UNPAREN params)			\
{									\
	check								\
	if (version == 11) {						\
		insn->size = emit_gfx11_##name(&insn->gfx11,		\
					       KNOD_UNPAREN args);	\
		insn->type = AMDGCN_INSN_TYPE_##kind;			\
	} else if (version == 10) {					\
		insn->size = emit_gfx10_##name(&insn->gfx10,		\
					       KNOD_UNPAREN args);	\
		insn->type = AMDGCN_INSN_TYPE_##kind;			\
	} else {							\
		WARN_ON_ONCE(1);					\
	}								\
}
#define KNOD_EMIT(name, kind, params, args)				\
	KNOD_EMIT_CHECKED(name, kind, params, args)

#define KNOD_P32	struct amdgcn_param32
#define KNOD_P64	struct amdgcn_param64
#define KNOD_EMIT_0(n, k)						\
static inline void emit_##n(int version, struct amdgcn_insn *insn)	\
{									\
	if (version == 11) {						\
		insn->size = emit_gfx11_##n(&insn->gfx11);		\
		insn->type = AMDGCN_INSN_TYPE_##k;			\
	} else if (version == 10) {					\
		insn->size = emit_gfx10_##n(&insn->gfx10);		\
		insn->type = AMDGCN_INSN_TYPE_##k;			\
	} else {							\
		WARN_ON_ONCE(1);					\
	}								\
}
#define KNOD_EMIT_P32_2(n, k)	KNOD_EMIT(n, k, (KNOD_P32 a, KNOD_P32 b), (a, b))
#define KNOD_EMIT_P32_3(n, k)						\
	KNOD_EMIT(n, k, (KNOD_P32 a, KNOD_P32 b, KNOD_P32 c), (a, b, c))
#define KNOD_EMIT_P32_4(n, k)						\
	KNOD_EMIT(n, k, (KNOD_P32 a, KNOD_P32 b, KNOD_P32 c, KNOD_P32 d),	\
		  (a, b, c, d))
#define KNOD_EMIT_P64_2(n, k)	KNOD_EMIT(n, k, (KNOD_P64 a, KNOD_P64 b), (a, b))
#define KNOD_EMIT_P64_3(n, k)						\
	KNOD_EMIT(n, k, (KNOD_P64 a, KNOD_P64 b, KNOD_P64 c), (a, b, c))
#define KNOD_EMIT_P32_2_INT(n, k)					\
	KNOD_EMIT(n, k, (KNOD_P32 a, KNOD_P32 b, int c), (a, b, c))
#define KNOD_EMIT_P32_2_S16(n, k)					\
	KNOD_EMIT(n, k, (KNOD_P32 a, KNOD_P32 b, short c), (a, b, c))
#define KNOD_EMIT_S16(n, k)	KNOD_EMIT(n, k, (short a), (a))
#define KNOD_EMIT_U8_1(n, k)	KNOD_EMIT(n, k, (u8 a), (a))
#define KNOD_EMIT_U8_2(n, k)	KNOD_EMIT(n, k, (u8 a, u8 b), (a, b))
#define KNOD_EMIT_U8_3(n, k)	KNOD_EMIT(n, k, (u8 a, u8 b, u8 c), (a, b, c))

KNOD_EMIT_P32_2_INT(s_load_dwordx2, SMEM)

KNOD_EMIT_CHECKED(v_bfe_u32, VOP3A,
		  (KNOD_P32 dst, KNOD_P32 src0, KNOD_P32 src1, KNOD_P32 src2),
		  (dst, src0, src1, src2),
		  WARN_ON(knod_param_is_literal(src0) ||
			  knod_param_is_literal(src1) ||
			  knod_param_is_literal(src2));)

KNOD_EMIT_CHECKED(v_bfi_b32, VOP3A,
		  (KNOD_P32 dst, KNOD_P32 src0, KNOD_P32 src1, KNOD_P32 src2),
		  (dst, src0, src1, src2),
		  WARN_ON(knod_param_is_literal(src0) ||
			  knod_param_is_literal(src1) ||
			  knod_param_is_literal(src2));)

KNOD_EMIT_P32_4(v_lshl_or_b32, VOP3A)

KNOD_EMIT_CHECKED(v_perm_b32, VOP3A,
		  (KNOD_P32 dst, KNOD_P32 src0, KNOD_P32 src1, KNOD_P32 src2),
		  (dst, src0, src1, src2),
		  WARN_ON(knod_param_is_literal(src0) ||
			  knod_param_is_literal(src1) ||
			  knod_param_is_literal(src2));)

KNOD_EMIT_P32_2(s_mov_b32, SOP1)
KNOD_EMIT_P32_2(v_mov_b32_e32, VOP1)

KNOD_EMIT_P32_3(v_add_co_u32, VOP3B)

static inline void emit_v_add_co_ci_u32_e32(int version,
				     struct amdgcn_insn *insn,
				     struct amdgcn_param32 dst,
				     struct amdgcn_param32 src0,
				     struct amdgcn_param32 src1)
{
	if (version == 11) {
		insn->size = emit_gfx11_v_add_co_ci_u32_e32(&insn->gfx11,
							    dst, src0,
							    src1);
		insn->type = AMDGCN_INSN_TYPE_VOP2;
	} else if (version == 10) {
		insn->size = emit_gfx10_v_add_co_ci_u32_e32(&insn->gfx10,
							    dst, src0,
							    src1);
		insn->type = AMDGCN_INSN_TYPE_VOP2;
	} else {
		WARN_ON_ONCE(1);
	}
}

/* No carry in/out */
static inline void emit_v_add_u32(int version, struct amdgcn_insn *insn,
			      struct amdgcn_param32 dst,
			      struct amdgcn_param32 src0,
			      struct amdgcn_param32 src1)
{
	if (version == 11) {
		WARN_ON_ONCE(src1.type != AMDGCN_PARAM_TYPE_VGPR);
		insn->size = emit_gfx11_v_add_nc_u32(&insn->gfx11, dst,
						     src0, src1);
		insn->type = AMDGCN_INSN_TYPE_VOP2;
	} else if (version == 10) {
		WARN_ON_ONCE(src1.type != AMDGCN_PARAM_TYPE_VGPR);
		insn->size = emit_gfx10_v_add_nc_u32(&insn->gfx10, dst,
						     src0, src1);
		insn->type = AMDGCN_INSN_TYPE_VOP2;
	} else {
		WARN_ON_ONCE(1);
	}
}

/* No carry in/out */
static inline void emit_v_sub_u32(int version, struct amdgcn_insn *insn,
			      struct amdgcn_param32 dst,
			      struct amdgcn_param32 src0,
			      struct amdgcn_param32 src1)
{
	if (version == 11) {
		WARN_ON_ONCE(src1.type != AMDGCN_PARAM_TYPE_VGPR);
		insn->size = emit_gfx11_v_sub_nc_u32(&insn->gfx11, dst,
						     src0, src1);
		insn->type = AMDGCN_INSN_TYPE_VOP2;
	} else if (version == 10) {
		WARN_ON_ONCE(src1.type != AMDGCN_PARAM_TYPE_VGPR);
		insn->size = emit_gfx10_v_sub_nc_u32(&insn->gfx10, dst,
						     src0, src1);
		insn->type = AMDGCN_INSN_TYPE_VOP2;
	} else {
		WARN_ON_ONCE(1);
	}
}

KNOD_EMIT_CHECKED(v_xor_b32_e32, VOP2,
		  (KNOD_P32 dst, KNOD_P32 src0, KNOD_P32 src1),
		  (dst, src0, src1),
		  WARN_ON_ONCE(src1.type != AMDGCN_PARAM_TYPE_VGPR);)

KNOD_EMIT_CHECKED(v_or_b32_e32, VOP2,
		  (KNOD_P32 dst, KNOD_P32 src0, KNOD_P32 src1),
		  (dst, src0, src1),
		  WARN_ON_ONCE(src1.type != AMDGCN_PARAM_TYPE_VGPR);)

KNOD_EMIT_CHECKED(v_and_b32_e32, VOP2,
		  (KNOD_P32 dst, KNOD_P32 src0, KNOD_P32 src1),
		  (dst, src0, src1),
		  WARN_ON_ONCE(src1.type != AMDGCN_PARAM_TYPE_VGPR);)

static inline void emit_v_sub_co_ci_u32_e32(int version,
				     struct amdgcn_insn *insn,
				     struct amdgcn_param32 dst,
				     struct amdgcn_param32 src0,
				     struct amdgcn_param32 src1)
{
	if (version == 11) {
		WARN_ON_ONCE(src1.type != AMDGCN_PARAM_TYPE_VGPR);
		insn->size = emit_gfx11_v_sub_co_ci_u32_e32(&insn->gfx11,
							    dst, src0, src1);
		insn->type = AMDGCN_INSN_TYPE_VOP2;
	} else if (version == 10) {
		WARN_ON_ONCE(src1.type != AMDGCN_PARAM_TYPE_VGPR);
		insn->size = emit_gfx10_v_sub_co_ci_u32_e32(&insn->gfx10,
							    dst, src0, src1);
		insn->type = AMDGCN_INSN_TYPE_VOP2;
	} else {
		WARN_ON_ONCE(1);
	}
}

KNOD_EMIT_P32_3(v_sub_co_u32, VOP3B)

KNOD_EMIT_P32_3(v_mul_lo_u32, VOP3A)

static inline void emit_v_mbcnt_lo_u32_b32(int version,
				    struct amdgcn_insn *insn,
				    struct amdgcn_param32 dst,
				    struct amdgcn_param32 src0,
				    struct amdgcn_param32 src1)
{
	if (version == 11) {
		insn->size = emit_gfx11_v_mbcnt_lo_u32_b32(&insn->gfx11,
							    dst, src0, src1);
		insn->type = AMDGCN_INSN_TYPE_VOP3A;
	} else if (version == 10) {
		insn->size = emit_gfx10_v_mbcnt_lo_u32_b32(&insn->gfx10,
							    dst, src0, src1);
		insn->type = AMDGCN_INSN_TYPE_VOP3A;
	} else {
		WARN_ON_ONCE(1);
	}
}

static inline void emit_v_mbcnt_hi_u32_b32(int version,
				    struct amdgcn_insn *insn,
				    struct amdgcn_param32 dst,
				    struct amdgcn_param32 src0,
				    struct amdgcn_param32 src1)
{
	if (version == 11) {
		insn->size = emit_gfx11_v_mbcnt_hi_u32_b32(&insn->gfx11,
							    dst, src0, src1);
		insn->type = AMDGCN_INSN_TYPE_VOP3A;
	} else if (version == 10) {
		insn->size = emit_gfx10_v_mbcnt_hi_u32_b32(&insn->gfx10,
							    dst, src0, src1);
		insn->type = AMDGCN_INSN_TYPE_VOP3A;
	} else {
		WARN_ON_ONCE(1);
	}
}

KNOD_EMIT_P32_3(v_mul_hi_u32, VOP3A)

static inline void emit_v_lshlrev_b64(int version, struct amdgcn_insn *insn,
			       struct amdgcn_param64 dst,
			       struct amdgcn_param64 src0,
			       struct amdgcn_param64 src1)
{
	/* D.u64 = S1.u64 << S0.u[5:0]. */
	if (version == 11) {
		insn->size = emit_gfx11_v_lshlrev_b64(&insn->gfx11, dst,
						      src0, src1);
		insn->type = AMDGCN_INSN_TYPE_VOP3A;
	} else if (version == 10) {
		insn->size = emit_gfx10_v_lshlrev_b64(&insn->gfx10, dst,
						      src0, src1);
		insn->type = AMDGCN_INSN_TYPE_VOP3A;
	} else {
		WARN_ON_ONCE(1);
	}
}

KNOD_EMIT_CHECKED(v_lshrrev_b64, VOP3A,
		  (KNOD_P64 dst, KNOD_P64 src0, KNOD_P64 src1),
		  (dst, src0, src1),
		  WARN_ON(src1.lo.type == AMDGCN_PARAM_TYPE_LITERAL_CONST);)

KNOD_EMIT_P64_3(v_ashrrev_i64, VOP3A)
KNOD_EMIT_P32_3(v_ashrrev_i32, VOP3A)

KNOD_EMIT_CHECKED(v_lshlrev_b32, VOP2,
		  (KNOD_P32 dst, KNOD_P32 src0, KNOD_P32 src1),
		  (dst, src0, src1),
		  WARN_ON_ONCE(src1.type != AMDGCN_PARAM_TYPE_VGPR);)

KNOD_EMIT_CHECKED(v_lshrrev_b32, VOP2,
		  (KNOD_P32 dst, KNOD_P32 src0, KNOD_P32 src1),
		  (dst, src0, src1),
		  WARN_ON_ONCE(src1.type != AMDGCN_PARAM_TYPE_VGPR);)

KNOD_EMIT_CHECKED(v_cmp_eq_u64, VOPC,
		  (KNOD_P32 dst, KNOD_P32 src),
		  (dst, src),
		  WARN_ON_ONCE(dst.type == AMDGCN_PARAM_TYPE_LITERAL_CONST);
		  WARN_ON(src.type != AMDGCN_PARAM_TYPE_VGPR);)

KNOD_EMIT_CHECKED(v_cmp_ne_u32, VOPC,
		  (KNOD_P32 dst, KNOD_P32 src),
		  (dst, src),
		  WARN_ON_ONCE(dst.type == AMDGCN_PARAM_TYPE_LITERAL_CONST);
		  WARN_ON(src.type != AMDGCN_PARAM_TYPE_VGPR);)

KNOD_EMIT_CHECKED(v_cmp_eq_u32, VOPC,
		  (KNOD_P32 dst, KNOD_P32 src),
		  (dst, src),
		  WARN_ON_ONCE(dst.type == AMDGCN_PARAM_TYPE_LITERAL_CONST);
		  WARN_ON(src.type != AMDGCN_PARAM_TYPE_VGPR);)

KNOD_EMIT_CHECKED(v_cmp_gt_u64, VOPC,
		  (KNOD_P64 dst, KNOD_P64 src),
		  (dst, src),
		  WARN_ON_ONCE(dst.lo.type == AMDGCN_PARAM_TYPE_LITERAL_CONST);)

KNOD_EMIT_CHECKED(v_cmp_gt_i64, VOPC,
		  (KNOD_P64 dst, KNOD_P64 src),
		  (dst, src),
		  WARN_ON_ONCE(dst.lo.type == AMDGCN_PARAM_TYPE_LITERAL_CONST);)

KNOD_EMIT_CHECKED(v_cmp_ge_u32, VOPC,
		  (KNOD_P32 dst, KNOD_P32 src),
		  (dst, src),
		  WARN_ON_ONCE(dst.type == AMDGCN_PARAM_TYPE_LITERAL_CONST);)

KNOD_EMIT_CHECKED(v_cmp_gt_u32, VOPC,
		  (KNOD_P32 dst, KNOD_P32 src),
		  (dst, src),
		  WARN_ON_ONCE(dst.type == AMDGCN_PARAM_TYPE_LITERAL_CONST);
		  WARN_ON(src.type != AMDGCN_PARAM_TYPE_VGPR);)

KNOD_EMIT_CHECKED(v_cmp_lt_u32, VOPC,
		  (KNOD_P32 dst, KNOD_P32 src),
		  (dst, src),
		  WARN_ON_ONCE(dst.type == AMDGCN_PARAM_TYPE_LITERAL_CONST);
		  WARN_ON(src.type != AMDGCN_PARAM_TYPE_VGPR);)

KNOD_EMIT_CHECKED(v_cmp_le_u32, VOPC,
		  (KNOD_P32 dst, KNOD_P32 src),
		  (dst, src),
		  WARN_ON_ONCE(dst.type == AMDGCN_PARAM_TYPE_LITERAL_CONST);
		  WARN_ON(src.type != AMDGCN_PARAM_TYPE_VGPR);)

KNOD_EMIT_CHECKED(v_cmp_gt_i32, VOPC,
		  (KNOD_P32 dst, KNOD_P32 src),
		  (dst, src),
		  WARN_ON_ONCE(dst.type == AMDGCN_PARAM_TYPE_LITERAL_CONST);
		  WARN_ON(src.type != AMDGCN_PARAM_TYPE_VGPR);)

KNOD_EMIT_CHECKED(v_cmp_ge_i32, VOPC,
		  (KNOD_P32 dst, KNOD_P32 src),
		  (dst, src),
		  WARN_ON_ONCE(dst.type == AMDGCN_PARAM_TYPE_LITERAL_CONST);
		  WARN_ON(src.type != AMDGCN_PARAM_TYPE_VGPR);)

KNOD_EMIT_CHECKED(v_cmp_lt_i32, VOPC,
		  (KNOD_P32 dst, KNOD_P32 src),
		  (dst, src),
		  WARN_ON_ONCE(dst.type == AMDGCN_PARAM_TYPE_LITERAL_CONST);
		  WARN_ON(src.type != AMDGCN_PARAM_TYPE_VGPR);)

KNOD_EMIT_CHECKED(v_cmp_le_i32, VOPC,
		  (KNOD_P32 dst, KNOD_P32 src),
		  (dst, src),
		  WARN_ON_ONCE(dst.type == AMDGCN_PARAM_TYPE_LITERAL_CONST);
		  WARN_ON(src.type != AMDGCN_PARAM_TYPE_VGPR);)

/* EXEC &= (src0 < src1), per-lane mask update */

KNOD_EMIT_CHECKED(v_cmp_ge_u64, VOPC,
		  (KNOD_P64 dst, KNOD_P64 src),
		  (dst, src),
		  WARN_ON_ONCE(dst.lo.type == AMDGCN_PARAM_TYPE_LITERAL_CONST);)

KNOD_EMIT_CHECKED(v_cmp_ge_i64, VOPC,
		  (KNOD_P64 dst, KNOD_P64 src),
		  (dst, src),
		  WARN_ON_ONCE(dst.lo.type == AMDGCN_PARAM_TYPE_LITERAL_CONST);)

KNOD_EMIT_CHECKED(v_cmp_lt_u64, VOPC,
		  (KNOD_P64 dst, KNOD_P64 src),
		  (dst, src),
		  WARN_ON_ONCE(dst.lo.type == AMDGCN_PARAM_TYPE_LITERAL_CONST);)

KNOD_EMIT_CHECKED(v_cmp_lt_i64, VOPC,
		  (KNOD_P64 dst, KNOD_P64 src),
		  (dst, src),
		  WARN_ON_ONCE(dst.lo.type == AMDGCN_PARAM_TYPE_LITERAL_CONST);)

KNOD_EMIT_CHECKED(v_cmp_le_u64, VOPC,
		  (KNOD_P64 dst, KNOD_P64 src),
		  (dst, src),
		  WARN_ON_ONCE(dst.lo.type == AMDGCN_PARAM_TYPE_LITERAL_CONST);)

KNOD_EMIT_CHECKED(v_cmp_le_i64, VOPC,
		  (KNOD_P64 dst, KNOD_P64 src),
		  (dst, src),
		  WARN_ON_ONCE(dst.lo.type == AMDGCN_PARAM_TYPE_LITERAL_CONST);)

KNOD_EMIT_P32_2_S16(global_load_ubyte, FLAT)

static inline void emit_global_load_ushort(int version,
				    struct amdgcn_insn *insn,
				    struct amdgcn_param32 dst,
				    struct amdgcn_param32 src,
				    short off)
{
	if (version == 11) {
		insn->size = emit_gfx11_global_load_ushort(&insn->gfx11,
							   dst, src, off);
		insn->type = AMDGCN_INSN_TYPE_FLAT;
	} else if (version == 10) {
		insn->size = emit_gfx10_global_load_ushort(&insn->gfx10,
							   dst, src, off);
		insn->type = AMDGCN_INSN_TYPE_FLAT;
	} else {
		WARN_ON_ONCE(1);
	}
}

KNOD_EMIT_CHECKED(global_load_dword, FLAT,
		  (KNOD_P32 dst, KNOD_P32 src, short off),
		  (dst, src, off),
		  WARN_ON(dst.type != AMDGCN_PARAM_TYPE_VGPR);
		  WARN_ON(src.type != AMDGCN_PARAM_TYPE_VGPR);)

/* Scratch: gfx11 is handed FLAT_SCRATCH, gfx10 has the blob build it. */
static inline void emit_scratch_load_dword(int version,
					   struct amdgcn_insn *insn,
					   struct amdgcn_param32 dst, short off)
{
	WARN_ON(dst.type != AMDGCN_PARAM_TYPE_VGPR);
	if (version == 11) {
		insn->size = emit_gfx11_scratch_load_dword(&insn->gfx11, dst,
							   off);
		insn->type = AMDGCN_INSN_TYPE_FLAT;
	} else if (version == 10) {
		insn->size = emit_gfx10_scratch_load_dword(&insn->gfx10, dst,
							   off);
		insn->type = AMDGCN_INSN_TYPE_FLAT;
	} else {
		WARN_ON_ONCE(1);
	}
}

static inline void emit_scratch_store_dword(int version,
					    struct amdgcn_insn *insn,
					    struct amdgcn_param32 src, short off)
{
	WARN_ON(src.type != AMDGCN_PARAM_TYPE_VGPR);
	if (version == 11) {
		insn->size = emit_gfx11_scratch_store_dword(&insn->gfx11, src,
							    off);
		insn->type = AMDGCN_INSN_TYPE_FLAT;
	} else if (version == 10) {
		insn->size = emit_gfx10_scratch_store_dword(&insn->gfx10, src,
							    off);
		insn->type = AMDGCN_INSN_TYPE_FLAT;
	} else {
		WARN_ON_ONCE(1);
	}
}

/* Arming FLAT_SCRATCH is gfx10's alone: gfx11 is handed it. */
/* LDS, with the whole sixteen-bit offset: DS_*_B32 reads offset1:offset0 as
 * one number, and the per-generation _off helpers fill only the low byte.
 */
static inline void emit_ds_read_b32(int version, struct amdgcn_insn *insn,
				    struct amdgcn_param32 dst,
				    struct amdgcn_param32 addr, u16 off)
{
	WARN_ON(dst.type != AMDGCN_PARAM_TYPE_VGPR ||
		addr.type != AMDGCN_PARAM_TYPE_VGPR);
	if (version == 11) {
		__emit_gfx11_ds(&insn->gfx11, GFX11_DS_LOAD_B32, addr.v, 0,
				dst.v, off & 0xff, off >> 8);
		insn->size = 8;
		insn->type = AMDGCN_INSN_TYPE_DS;
	} else if (version == 10) {
		__emit_gfx10_ds(&insn->gfx10, GFX10_DS_READ_B32, addr.v, 0,
				dst.v, off & 0xff, off >> 8);
		insn->size = 8;
		insn->type = AMDGCN_INSN_TYPE_DS;
	} else {
		WARN_ON_ONCE(1);
	}
}

static inline void emit_ds_write_b32(int version, struct amdgcn_insn *insn,
				     struct amdgcn_param32 addr,
				     struct amdgcn_param32 src, u16 off)
{
	WARN_ON(src.type != AMDGCN_PARAM_TYPE_VGPR ||
		addr.type != AMDGCN_PARAM_TYPE_VGPR);
	if (version == 11) {
		__emit_gfx11_ds(&insn->gfx11, GFX11_DS_STORE_B32, addr.v, src.v,
				0, off & 0xff, off >> 8);
		insn->size = 8;
		insn->type = AMDGCN_INSN_TYPE_DS;
	} else if (version == 10) {
		__emit_gfx10_ds(&insn->gfx10, GFX10_DS_WRITE_B32, addr.v, src.v,
				0, off & 0xff, off >> 8);
		insn->size = 8;
		insn->type = AMDGCN_INSN_TYPE_DS;
	} else {
		WARN_ON_ONCE(1);
	}
}

KNOD_EMIT_P32_3(s_add_u32, SOP2)
KNOD_EMIT_P32_3(s_addc_u32, SOP2)

static inline void emit_global_load_dwordx2(int version,
				     struct amdgcn_insn *insn,
				     struct amdgcn_param32 dst,
				     struct amdgcn_param32 src,
				     short off)
{
	if (version == 11) {
		insn->size = emit_gfx11_global_load_dwordx2(&insn->gfx11,
							    dst, src, off);
		insn->type = AMDGCN_INSN_TYPE_FLAT;
	} else if (version == 10) {
		insn->size = emit_gfx10_global_load_dwordx2(&insn->gfx10,
							    dst, src, off);
		insn->type = AMDGCN_INSN_TYPE_FLAT;
	} else {
		WARN_ON_ONCE(1);
	}
}

static inline void emit_global_store_byte(int version, struct amdgcn_insn *insn,
				   struct amdgcn_param32 dst,
				   struct amdgcn_param32 src, int off)
{
	if (version == 11) {
		insn->size = emit_gfx11_global_store_byte(&insn->gfx11,
							  src, dst, off);
		insn->type = AMDGCN_INSN_TYPE_FLAT;
	} else if (version == 10) {
		insn->size = emit_gfx10_global_store_byte(&insn->gfx10,
							  src, dst, off);
		insn->type = AMDGCN_INSN_TYPE_FLAT;
	} else {
		WARN_ON_ONCE(1);
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
	if (version == 11) {						\
		insn->size = emit_gfx11_global_atomic_##name(		\
			&insn->gfx11, vdst, addr, data, off, glc);	\
		insn->type = AMDGCN_INSN_TYPE_FLAT;			\
	} else if (version == 10) {					\
		insn->size = emit_gfx10_global_atomic_##name(		\
			&insn->gfx10, vdst, addr, data, off, glc);	\
		insn->type = AMDGCN_INSN_TYPE_FLAT;			\
	} else {							\
		WARN_ON_ONCE(1);						\
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
	if (version == 11) {
		insn->size = emit_gfx11_global_store_short(&insn->gfx11,
							   src, dst, off);
		insn->type = AMDGCN_INSN_TYPE_FLAT;
	} else if (version == 10) {
		insn->size = emit_gfx10_global_store_short(&insn->gfx10,
							   src, dst, off);
		insn->type = AMDGCN_INSN_TYPE_FLAT;
	} else {
		WARN_ON_ONCE(1);
	}
}

static inline void emit_global_store_dword(int version,
				    struct amdgcn_insn *insn,
				    struct amdgcn_param32 dst,
				    struct amdgcn_param32 src, int off)
{
	if (version == 11) {
		insn->size = emit_gfx11_global_store_dword(&insn->gfx11,
							   src, dst, off);
		insn->type = AMDGCN_INSN_TYPE_FLAT;
	} else if (version == 10) {
		insn->size = emit_gfx10_global_store_dword(&insn->gfx10,
							   src, dst, off);
		insn->type = AMDGCN_INSN_TYPE_FLAT;
	} else {
		WARN_ON_ONCE(1);
	}
}

static inline void emit_global_store_dwordx2(int version,
				      struct amdgcn_insn *insn,
				      struct amdgcn_param32 dst,
				      struct amdgcn_param32 src, int off)
{
	if (version == 11) {
		insn->size = emit_gfx11_global_store_dwordx2(&insn->gfx11,
							     src, dst, off);
		insn->type = AMDGCN_INSN_TYPE_FLAT;
	} else if (version == 10) {
		insn->size = emit_gfx10_global_store_dwordx2(&insn->gfx10,
							     src, dst, off);
		insn->type = AMDGCN_INSN_TYPE_FLAT;
	} else {
		WARN_ON_ONCE(1);
	}
}

KNOD_EMIT_S16(s_branch, SOPP)

/* Structurized CFG wrapper functions.
 * Use raw SGPR indices; EXEC=126, VCC=106, integer_0=128.
 */

static inline void emit_s_and_saveexec_b64(int version,
				    struct amdgcn_insn *insn,
				    u8 sdst, u8 ssrc)
{
	if (version == 11) {
		insn->size = emit_gfx11_s_and_saveexec_b64(&insn->gfx11,
							    sdst, ssrc);
		insn->type = AMDGCN_INSN_TYPE_SOP1;
	} else if (version == 10) {
		insn->size = emit_gfx10_s_and_saveexec_b64(&insn->gfx10,
							    sdst, ssrc);
		insn->type = AMDGCN_INSN_TYPE_SOP1;
	} else {
		WARN_ON_ONCE(1);
	}
}

KNOD_EMIT_U8_2(s_bcnt1_i32_b64, SOP1)
KNOD_EMIT_U8_1(s_getpc_b64, SOP1)
KNOD_EMIT_U8_1(s_setpc_b64, SOP1)
KNOD_EMIT_U8_2(s_swappc_b64, SOP1)
KNOD_EMIT_U8_2(s_mov_b64, SOP1)
KNOD_EMIT_U8_3(s_and_b64, SOP2)
KNOD_EMIT_U8_3(s_or_b64, SOP2)
KNOD_EMIT_U8_3(s_andn2_b64, SOP2)
KNOD_EMIT_S16(s_cbranch_execz, SOPP)

/* The shader clock counter, whose hwreg id is shared by supported ISAs. */
#define KNOD_HWREG_SHADER_CYCLES_20	0x981d

/* The two halves of FLAT_SCRATCH, which is how gfx10 is written: gfx11 needs
 * no writing.
 */
#define KNOD_HWREG_FLAT_SCR_LO_32	0xf814
#define KNOD_HWREG_FLAT_SCR_HI_32	0xf815

KNOD_EMIT_S16(s_cbranch_scc0, SOPP)
KNOD_EMIT_S16(s_cbranch_scc1, SOPP)
KNOD_EMIT_P32_2(s_cmp_lg_u32, SOPC)

KNOD_EMIT_0(s_waitcnt_lgkmcnt, SOPP)

static inline void emit_s_waitcnt_store(int version, struct amdgcn_insn *insn)
{
	if (version == 10) {
		insn->gfx10.sopk.encoding = GFX10_SOPK_ENCODING;
		insn->gfx10.sopk.op = GFX10_S_WAITCNT_VSCNT;
		insn->gfx10.sopk.sdst = GFX10_SRC_NULL;
		insn->gfx10.sopk.simm16 = 0;
	} else if (version == 11) {
		insn->gfx11.sopk.encoding = GFX11_SOPK_ENCODING;
		insn->gfx11.sopk.op = GFX11_S_WAITCNT_VSCNT;
		insn->gfx11.sopk.sdst = GFX11_SRC_NULL;
		insn->gfx11.sopk.simm16 = 0;
	} else {
		WARN_ON_ONCE(1);
	}
	insn->size = 4;
	insn->type = AMDGCN_INSN_TYPE_SOPK;
}

KNOD_EMIT_0(s_waitcnt_vmcnt, SOPP)

static inline void emit_s_waitcnt_vmcnt_lgkmcnt(int version,
						struct amdgcn_insn *insn)
{
	if (version == 11) {
		insn->size = emit_gfx11_s_waitcnt_vmcnt_lgkmcnt(&insn->gfx11);
		insn->type = AMDGCN_INSN_TYPE_SOPP;
	} else if (version == 10) {
		insn->size = emit_gfx10_s_waitcnt_vmcnt_lgkmcnt(&insn->gfx10);
		insn->type = AMDGCN_INSN_TYPE_SOPP;
	} else {
		WARN_ON_ONCE(1);
	}
}

KNOD_EMIT_0(s_code_end, SOPP)

/* Print one instruction as the dwords it is made of.  Naming it is knod-disasm's
 * job: llvm-mc knows every generation's opcodes, so the kernel does not have to
 * carry a table per generation to say the same thing worse.
 */
static inline void debugfs_insn(struct amdgcn_insn *insn, struct seq_file *m)
{
	const u32 *dw = (const u32 *)&insn->gfx11;
	u32 i;

	for (i = 0; i < insn->size / 4; i++)
		seq_printf(m, "%08x ", dw[i]);
	seq_putc(m, '\n');
}

#undef KNOD_P32
#undef KNOD_P64

#endif
