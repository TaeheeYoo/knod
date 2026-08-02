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


struct amdgcn_insn  {
	union {
		union amdgcn_gfx11_insn gfx11;
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
		WARN_ON_ONCE(1);
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
		WARN_ON_ONCE(1);
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
		WARN_ON_ONCE(1);
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
		WARN_ON_ONCE(1);
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
		WARN_ON_ONCE(1);
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
		WARN_ON_ONCE(1);
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
		WARN_ON_ONCE(1);
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
		WARN_ON_ONCE(1);
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
		WARN_ON_ONCE(1);
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
		WARN_ON_ONCE(1);
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
		WARN_ON_ONCE(1);
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
		WARN_ON_ONCE(1);
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
		WARN_ON_ONCE(1);
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
		WARN_ON_ONCE(1);
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
		WARN_ON_ONCE(1);
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
		WARN_ON_ONCE(1);
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
		WARN_ON_ONCE(1);
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
		WARN_ON_ONCE(1);
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
		WARN_ON_ONCE(1);
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
		WARN_ON_ONCE(1);
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
		WARN_ON_ONCE(1);
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
		WARN_ON_ONCE(1);
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
		WARN_ON_ONCE(1);
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
		WARN_ON_ONCE(1);
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
		WARN_ON_ONCE(1);
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
		WARN_ON_ONCE(1);
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
		WARN_ON_ONCE(1);
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
		WARN_ON_ONCE(1);
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
		WARN_ON_ONCE(1);
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
		WARN_ON_ONCE(1);
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
		WARN_ON_ONCE(1);
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
		WARN_ON_ONCE(1);
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
		WARN_ON_ONCE(1);
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
		WARN_ON_ONCE(1);
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
		WARN_ON_ONCE(1);
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
		WARN_ON_ONCE(1);
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
		WARN_ON_ONCE(1);
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
		WARN_ON_ONCE(1);
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
		WARN_ON_ONCE(1);
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
		WARN_ON_ONCE(1);
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
		WARN_ON_ONCE(1);
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
		WARN_ON_ONCE(1);
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
		WARN_ON_ONCE(1);
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
		WARN_ON_ONCE(1);
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
		WARN_ON_ONCE(1);
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
		WARN_ON_ONCE(1);
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
		WARN_ON_ONCE(1);
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
		WARN_ON_ONCE(1);
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
		WARN_ON_ONCE(1);
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
		WARN_ON_ONCE(1);
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
		WARN_ON_ONCE(1);
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
		WARN_ON_ONCE(1);
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
		WARN_ON_ONCE(1);
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
		WARN_ON_ONCE(1);
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
		WARN_ON_ONCE(1);
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
		WARN_ON_ONCE(1);
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
		WARN_ON_ONCE(1);
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
		WARN_ON_ONCE(1);
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
		WARN_ON_ONCE(1);
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
		WARN_ON_ONCE(1);
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
		WARN_ON_ONCE(1);
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
		WARN_ON_ONCE(1);
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
		WARN_ON_ONCE(1);
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
		WARN_ON_ONCE(1);
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
		WARN_ON_ONCE(1);
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
	if (version == 10) {						\
		insn->size = emit_gfx10_global_atomic_##name(		\
			&insn->gfx10, vdst, addr, data, off, glc);	\
		insn->type = AMDGCN_INSN_TYPE_FLAT;			\
	} else if (version == 9) {					\
		insn->size = emit_gfx9_global_atomic_##name(		\
			&insn->gfx9, vdst, addr, data, off, glc);	\
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
	if (version == 10) {
		insn->size = emit_gfx10_global_store_short(&insn->gfx10,
							   src, dst, off);
		insn->type = AMDGCN_INSN_TYPE_FLAT;
	} else if (version == 9) {
		insn->size = emit_gfx9_global_store_short(&insn->gfx9,
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
	if (version == 10) {
		insn->size = emit_gfx10_global_store_dword(&insn->gfx10,
							   src, dst, off);
		insn->type = AMDGCN_INSN_TYPE_FLAT;
	} else if (version == 9) {
		insn->size = emit_gfx9_global_store_dword(&insn->gfx9,
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
	if (version == 10) {
		insn->size = emit_gfx10_global_store_dwordx2(&insn->gfx10,
							     src, dst, off);
		insn->type = AMDGCN_INSN_TYPE_FLAT;
	} else if (version == 9) {
		insn->size = emit_gfx9_global_store_dwordx2(&insn->gfx9,
							    src, dst, off);
		insn->type = AMDGCN_INSN_TYPE_FLAT;
	} else {
		WARN_ON_ONCE(1);
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
		WARN_ON_ONCE(1);
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
		WARN_ON_ONCE(1);
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
		WARN_ON_ONCE(1);
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
		WARN_ON_ONCE(1);
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
		WARN_ON_ONCE(1);
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
		WARN_ON_ONCE(1);
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
		WARN_ON_ONCE(1);
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
		WARN_ON_ONCE(1);
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
		WARN_ON_ONCE(1);
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
		WARN_ON_ONCE(1);
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
		WARN_ON_ONCE(1);
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
		WARN_ON_ONCE(1);
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
		WARN_ON_ONCE(1);
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
		WARN_ON_ONCE(1);
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
		WARN_ON_ONCE(1);
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
		WARN_ON_ONCE(1);
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
		WARN_ON_ONCE(1);
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
		WARN_ON_ONCE(1);
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
		WARN_ON_ONCE(1);
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
		WARN_ON_ONCE(1);
	}
}

static inline void emit_s_code_end(int version, struct amdgcn_insn *insn)
{
	if (version == 10) {
		insn->size = emit_gfx10_s_code_end(&insn->gfx10);
		insn->type = AMDGCN_INSN_TYPE_SOPP;
	} else if (version == 9) {
		WARN_ON_ONCE(1);
	} else {
		WARN_ON_ONCE(1);
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
		WARN_ON_ONCE(1);
	}
}


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

#endif
