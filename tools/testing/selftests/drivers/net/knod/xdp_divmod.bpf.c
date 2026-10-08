// SPDX-License-Identifier: GPL-2.0
/* Division the JIT cannot do by a constant: operands out of the packet, so
 * the verifier knows neither, unsigned and signed, 32 and 64 bits, with the
 * BPF answers for a zero divisor and a signed -1.  Each result is checked
 * against what a quotient and a remainder have to satisfy, so any packet
 * will do.  A packet whose every check holds is dropped; one where any
 * fails is passed up.
 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define ETH_HLEN	14

/* The division itself in assembly: in C, one by zero would be undefined and
 * the checks of it could be optimised away.
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

SEC("xdp")
int xdp_divmod(struct xdp_md *ctx)
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

	return ok ? XDP_DROP : XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
