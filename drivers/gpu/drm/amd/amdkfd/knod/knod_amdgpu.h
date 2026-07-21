/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (c) 2021 Taehee Yoo <ap420073@gmail.com>
 * Copyright (c) 2021 Hoyeon Lee <hoyeon.rhee@gmail.com>
 */

#ifndef KFD_AMDGPU_H_INCLUDED
#define KFD_AMDGPU_H_INCLUDED

#define KNOD_AMDGPU_REG_PAIR(x)         ((x) / 2)

enum amdgcn_param_type {
	AMDGCN_PARAM_TYPE_SGPR,
	AMDGCN_PARAM_TYPE_VCC_LO,
	AMDGCN_PARAM_TYPE_VCC_HI,
	AMDGCN_PARAM_TYPE_TTPM_BASE,
	AMDGCN_PARAM_TYPE_M0,
	AMDGCN_PARAM_TYPE_NULL,
	AMDGCN_PARAM_TYPE_EXEC_LO,
	AMDGCN_PARAM_TYPE_EXEC_HI,
	AMDGCN_PARAM_TYPE_INTEGER_0,
	AMDGCN_PARAM_TYPE_INTEGER_MINUS_1,
	AMDGCN_PARAM_TYPE_SHARED_BASE,
	AMDGCN_PARAM_TYPE_SHARED_LIMIT,
	AMDGCN_PARAM_TYPE_PRIVATE_BASE,
	AMDGCN_PARAM_TYPE_PRIVATE_LIMIT,
	AMDGCN_PARAM_TYPE_POPS_EXITING_WAVE_ID,
	AMDGCN_PARAM_TYPE_SDWA,
	AMDGCN_PARAM_TYPE_DPP16,
	AMDGCN_PARAM_TYPE_VCCZ,
	AMDGCN_PARAM_TYPE_EXECZ,
	AMDGCN_PARAM_TYPE_SCC,
	AMDGCN_PARAM_TYPE_LITERAL_CONST,
	AMDGCN_PARAM_TYPE_VGPR,
	__AMDGCN_PARAM_TYPE_MAX,
};

struct amdgcn_param32 {
	enum amdgcn_param_type type;
	int v;
};

struct amdgcn_param64 {
	struct amdgcn_param32 lo;
	struct amdgcn_param32 hi;
	u64 imm;
};

inline void knod_set(struct amdgcn_param32 *param,
				  enum amdgcn_param_type type, int v)
{
	param->type = type;
	param->v = v;
}

inline void knod_vset32(struct amdgcn_param32 *param, int v)
{
	param->type = AMDGCN_PARAM_TYPE_VGPR;
	param->v = v;
}

inline void knod_vset64(struct amdgcn_param64 *param, int v)
{
	param->lo.type = AMDGCN_PARAM_TYPE_VGPR;
	param->lo.v = v;
	param->hi.type = AMDGCN_PARAM_TYPE_VGPR;
	param->hi.v = v + 1;
}

inline void knod_sset32(struct amdgcn_param32 *param, int v)
{
	param->type = AMDGCN_PARAM_TYPE_SGPR;
	param->v = v;
}

inline void knod_sset64(struct amdgcn_param64 *param, int v)
{
	param->lo.type = AMDGCN_PARAM_TYPE_SGPR;
	param->lo.v = v;
	param->hi.type = AMDGCN_PARAM_TYPE_SGPR;
	param->hi.v = v + 1;
}

inline void knod_iset32(struct amdgcn_param32 *param, int v)
{
	if (v > 64 || v < -16) {
		param->type = AMDGCN_PARAM_TYPE_LITERAL_CONST;
		param->v = v;
	} else if (v >= 0) {
		param->type = AMDGCN_PARAM_TYPE_INTEGER_0;
		param->v = v;
	} else {
		param->type = AMDGCN_PARAM_TYPE_INTEGER_MINUS_1;
		param->v = ~v;
	}
}

inline void knod_iset64(struct amdgcn_param64 *param,
				     u64 v)
{
	int imm0 = v & ~0U;
	int imm1 = v >> 32;

	param->imm = v;

	if (imm0 > 64 || imm0 < -16) {
		param->lo.type = AMDGCN_PARAM_TYPE_LITERAL_CONST;
		param->lo.v = imm0;
	} else if (imm0 >= 0) {
		param->lo.type = AMDGCN_PARAM_TYPE_INTEGER_0;
		param->lo.v = imm0;
	} else {
		param->lo.type = AMDGCN_PARAM_TYPE_INTEGER_MINUS_1;
		param->lo.v = ~imm0;
	}

	if (imm1 > 64 || imm1 < -16) {
		param->hi.type = AMDGCN_PARAM_TYPE_LITERAL_CONST;
		WARN_ON_ONCE(1);
		param->hi.v = imm1;
	} else if (imm1 >= 0) {
		param->hi.type = AMDGCN_PARAM_TYPE_INTEGER_0;
		param->hi.v = imm1;
	} else {
		param->hi.type = AMDGCN_PARAM_TYPE_INTEGER_MINUS_1;
		param->hi.v = ~imm1;
	}
}

inline void knod_lset32(struct amdgcn_param32 *param, int v)
{
	param->type = AMDGCN_PARAM_TYPE_LITERAL_CONST;
	param->v = v;
}

inline void knod_vccset(struct amdgcn_param32 *param)
{
	param->type = AMDGCN_PARAM_TYPE_VCC_LO;
	param->v = 0;
}

inline bool knod_param_is_literal(struct amdgcn_param32 param)
{
	return param.type == AMDGCN_PARAM_TYPE_LITERAL_CONST;
}

/* ======================================================================
 * Param constructors - common to GFX9/GFX10 shader emitters.
 *
 * Usage: pass directly to emit_gfx{9,10}_* functions that take
 *        struct amdgcn_param32 operands.
 * ======================================================================
 */

#define P_S(n)	((struct amdgcn_param32){ AMDGCN_PARAM_TYPE_SGPR, (n) })
#define P_V(n)	((struct amdgcn_param32){ AMDGCN_PARAM_TYPE_VGPR, (n) })
#define P_I(n)	((struct amdgcn_param32){ AMDGCN_PARAM_TYPE_INTEGER_0, (n) })
#define P_L(v)	((struct amdgcn_param32){ AMDGCN_PARAM_TYPE_LITERAL_CONST, (v) })
#define P_VCC	((struct amdgcn_param32){ AMDGCN_PARAM_TYPE_VCC_LO, 0 })
#define P_EXEC	((struct amdgcn_param32){ AMDGCN_PARAM_TYPE_EXEC_LO, 0 })

/* ======================================================================
 * Branch patching - operates directly on u32 *buf
 * ======================================================================
 */

static inline void patch_branch(u32 *buf, int patch_pos, int target_pos)
{
	int offset = target_pos - (patch_pos + 1);

	buf[patch_pos] = (buf[patch_pos] & 0xFFFF0000u) | (offset & 0xFFFF);
}

#endif
