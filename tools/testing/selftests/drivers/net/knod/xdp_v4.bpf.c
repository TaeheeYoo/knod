// SPDX-License-Identifier: GPL-2.0
/* Instructions the JIT hands to the blob or has to get right by itself:
 * division unsigned and signed, 32 and 64 bits, with the BPF answers for a
 * zero divisor and a signed -1, a 64-bit negation, the high half the other
 * ALU ops leave, and BPF v4's
 * sign-extending loads and moves and its byte swaps.  The operands come out
 * of the packet, so the verifier knows none of them, and each result is
 * checked against what it has to satisfy, so any packet will do.  A packet
 * whose every check holds is dropped; one where any fails is passed up.
 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define ETH_HLEN	14

/* The operations themselves in assembly: in C, a division by zero would be
 * undefined and its checks optimised away, and clang would be free to check
 * a sign extension or a swap with the very instruction under test.
 */
static __always_inline __u64 udiv64(__u64 a, __u64 b)
{
	asm volatile("%[a] /= %[b]" : [a] "+r"(a) : [b] "r"(b));
	return a;
}

static __always_inline __u64 umod64(__u64 a, __u64 b)
{
	asm volatile("%[a] %%= %[b]" : [a] "+r"(a) : [b] "r"(b));
	return a;
}

static __always_inline __u32 udiv32(__u32 a, __u32 b)
{
	asm volatile("%[a] /= %[b]" : [a] "+w"(a) : [b] "w"(b));
	return a;
}

static __always_inline __u32 umod32(__u32 a, __u32 b)
{
	asm volatile("%[a] %%= %[b]" : [a] "+w"(a) : [b] "w"(b));
	return a;
}

static __always_inline __s64 sdiv64(__s64 a, __s64 b)
{
	asm volatile("%[a] s/= %[b]" : [a] "+r"(a) : [b] "r"(b));
	return a;
}

static __always_inline __s64 smod64(__s64 a, __s64 b)
{
	asm volatile("%[a] s%%= %[b]" : [a] "+r"(a) : [b] "r"(b));
	return a;
}

static __always_inline __s32 sdiv32(__s32 a, __s32 b)
{
	asm volatile("%[a] s/= %[b]" : [a] "+w"(a) : [b] "w"(b));
	return a;
}

static __always_inline __s32 smod32(__s32 a, __s32 b)
{
	asm volatile("%[a] s%%= %[b]" : [a] "+w"(a) : [b] "w"(b));
	return a;
}

static __always_inline int u64_ok(__u64 a, __u64 b)
{
	__u64 q = udiv64(a, b), r = umod64(a, b);

	return b ? q * b + r == a && r < b : !q && r == a;
}

static __always_inline int u32_ok(__u32 a, __u32 b)
{
	__u32 q = udiv32(a, b), r = umod32(a, b);

	return b ? q * b + r == a && r < b : !q && r == a;
}

static __always_inline __u64 mag64(__s64 v)
{
	return v < 0 ? -(__u64)v : v;
}

static __always_inline int s64_ok(__s64 a, __s64 b)
{
	__s64 q = sdiv64(a, b), r = smod64(a, b);

	if (!b)
		return !q && r == a;
	if (b == -1)
		return (__u64)q == -(__u64)a && !r;
	return (__u64)q * b + r == (__u64)a && (!r || (r < 0) == (a < 0)) &&
	       mag64(r) < mag64(b);
}

static __always_inline int s32_ok(__s32 a, __s32 b)
{
	__s32 q = sdiv32(a, b), r = smod32(a, b);

	if (!b)
		return !q && r == a;
	if (b == -1)
		return (__u32)q == -(__u32)a && !r;
	return (__u32)q * b + r == (__u32)a && (!r || (r < 0) == (a < 0)) &&
	       mag64(r) < mag64(b);
}

/* x's low @bits bits sign-extended, by shifts. */
static __always_inline __s64 sext_by_shift(__u64 x, int bits)
{
	if (bits == 8)
		asm volatile("%[x] <<= 56; %[x] s>>= 56" : [x] "+r"(x));
	else if (bits == 16)
		asm volatile("%[x] <<= 48; %[x] s>>= 48" : [x] "+r"(x));
	else
		asm volatile("%[x] <<= 32; %[x] s>>= 32" : [x] "+r"(x));
	return x;
}

static __always_inline int ldsx_ok(const void *p, __u64 plain)
{
	__s64 b, h, w;

	asm volatile("%[v] = *(s8 *)(%[p] + 0)" : [v] "=r"(b) : [p] "r"(p));
	asm volatile("%[v] = *(s16 *)(%[p] + 0)" : [v] "=r"(h) : [p] "r"(p));
	asm volatile("%[v] = *(s32 *)(%[p] + 0)" : [v] "=r"(w) : [p] "r"(p));
	return b == sext_by_shift(plain, 8) && h == sext_by_shift(plain, 16) &&
	       w == sext_by_shift(plain, 32);
}

static __always_inline int movsx_ok(__u64 x)
{
	__u64 b, h, w;
	__u32 b32, h32;

	asm volatile("%[d] = (s8)%[s]" : [d] "=r"(b) : [s] "r"(x));
	asm volatile("%[d] = (s16)%[s]" : [d] "=r"(h) : [s] "r"(x));
	asm volatile("%[d] = (s32)%[s]" : [d] "=r"(w) : [s] "r"(x));
	asm volatile("%[d] = (s8)%[s]" : [d] "=w"(b32) : [s] "w"((__u32)x));
	asm volatile("%[d] = (s16)%[s]" : [d] "=w"(h32) : [s] "w"((__u32)x));
	return b == sext_by_shift(x, 8) && h == sext_by_shift(x, 16) &&
	       w == sext_by_shift(x, 32) &&
	       b32 == (__u32)sext_by_shift(x, 8) &&
	       h32 == (__u32)sext_by_shift(x, 16);
}

/* Each byte where a swap puts it, and nothing above the width. */
static __always_inline int bswap_ok(__u64 x)
{
	__u64 s16 = x, s32 = x, s64 = x;
	int i, ok = 1;

	asm volatile("%[v] = bswap16 %[v]" : [v] "+r"(s16));
	asm volatile("%[v] = bswap32 %[v]" : [v] "+r"(s32));
	asm volatile("%[v] = bswap64 %[v]" : [v] "+r"(s64));
	ok &= s16 >> 16 == 0 && s32 >> 32 == 0;
	for (i = 0; i < 2; i++)
		ok &= (s16 >> 8 * i & 0xff) == (x >> 8 * (1 - i) & 0xff);
	for (i = 0; i < 4; i++)
		ok &= (s32 >> 8 * i & 0xff) == (x >> 8 * (3 - i) & 0xff);
	for (i = 0; i < 8; i++)
		ok &= (s64 >> 8 * i & 0xff) == (x >> 8 * (7 - i) & 0xff);
	return ok;
}

/* What a 32-bit op leaves above it, and what a 64-bit AND, OR or XOR with an
 * immediate does to the high half: the immediate widens signed.
 */
static __always_inline int alu_ok(__u64 x)
{
	__u64 and_p = x, and_n = x, or_p = x, or_n = x, xor_n = x, mul;

	asm volatile("%[v] &= 0x7f0f" : [v] "+r"(and_p));
	asm volatile("%[v] &= -16" : [v] "+r"(and_n));
	asm volatile("%[v] |= 0x70" : [v] "+r"(or_p));
	asm volatile("%[v] |= -256" : [v] "+r"(or_n));
	asm volatile("%[v] ^= -1" : [v] "+r"(xor_n));
	asm volatile("r1 = %[x]; w1 *= w1; %[m] = r1"
		     : [m] "=r"(mul) : [x] "r"(x) : "r1");

	return and_p >> 32 == 0 && (__u32)and_p == ((__u32)x & 0x7f0f) &&
	       and_n >> 32 == x >> 32 && and_n << 60 == 0 &&
	       or_p >> 32 == x >> 32 && or_n >> 32 == 0xffffffff &&
	       xor_n + x == (__u64)-1 && mul >> 32 == 0 &&
	       (__u32)mul == (__u32)x * (__u32)x;
}

SEC("xdp")
int xdp_v4(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *end = (void *)(long)ctx->data_end;
	__u32 *w = data + ETH_HLEN;
	__u64 a, b, n;
	int ok = 1;

	if ((void *)(w + 6) > end)
		return XDP_PASS;

	a = (__u64)w[0] << 32 | w[1];
	b = (__u64)w[2] << 32 | w[3];

	ok &= u64_ok(a, b);
	ok &= u64_ok(a, w[4] & 0xff);
	ok &= u32_ok(w[0], w[4]);
	ok &= u32_ok(w[1], w[5] & 0xf);
	ok &= s64_ok(a, b);
	ok &= s64_ok(a, -1);
	ok &= s32_ok(w[0], w[5]);
	ok &= s32_ok(w[1], (__s32)(w[5] & 1) - 1);
	/* By a constant, which the JIT still does itself. */
	ok &= u32_ok(w[0], 7);
	/* And a 64-bit negation. */
	n = -a;
	asm volatile("" : "+r" (n));
	ok &= n + a == 0;
	ok &= ldsx_ok(w, w[0]);
	ok &= movsx_ok(a);
	ok &= bswap_ok(a);
	ok &= alu_ok(a);

	return ok ? XDP_DROP : XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
