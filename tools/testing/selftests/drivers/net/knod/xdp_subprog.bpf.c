// SPDX-License-Identifier: GPL-2.0
/* BPF-to-BPF calls, each result a function of the packet's length L that
 * the test checks:
 *
 *   res[0]  1 + L      one function called twice, on two stack buffers
 *   res[1]  100 + 2L
 *   res[2]  6L + 1     three calls deep, each frame with its own stack
 *   res[3]  0xaa       a callee that writes r6-r9; the caller's come back
 *   res[4]  L
 *
 * and L in lens, put there by a callee.
 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 5);
	__type(key, __u32);
	__type(value, __u64);
} res SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u32);
	__type(value, __u64);
} lens SEC(".maps");

static __noinline __u64 add_to(__u64 *acc, __u64 v)
{
	*acc += v;
	return *acc;
}

static __noinline __u64 depth3(__u64 x)
{
	volatile __u64 buf[2] = { x, x + 1 };

	return buf[0] * 2 + buf[1];
}

static __noinline __u64 depth2(__u64 x)
{
	volatile __u64 t[2];

	t[0] = depth3(x);
	t[1] = x;
	return t[0] + t[1];
}

static __noinline __u64 depth1(__u64 x)
{
	volatile __u64 s = x << 1;

	return depth2(x) + s;
}

__attribute__((naked, used)) __noinline
static __u64 clobber(void)
{
	asm volatile("r6 = 0xdead;"
		     "r7 = 0xdead;"
		     "r8 = 0xdead;"
		     "r9 = 0xdead;"
		     "r0 = 0;"
		     "exit;");
}

__attribute__((naked, used)) __noinline
static __u64 keep_regs(void)
{
	asm volatile("r6 = 0x11;"
		     "r7 = 0x22;"
		     "r8 = 0x33;"
		     "r9 = 0x44;"
		     "call clobber;"
		     "r0 = r6;"
		     "r0 += r7;"
		     "r0 += r8;"
		     "r0 += r9;"
		     "exit;");
}

static __noinline int note_len(__u32 len)
{
	__u64 one = 1;

	return bpf_map_update_elem(&lens, &len, &one, BPF_ANY);
}

static __always_inline void put(__u32 k, __u64 v)
{
	__u64 *p = bpf_map_lookup_elem(&res, &k);

	if (p)
		*p = v;
}

SEC("xdp")
int xdp_subprog(struct xdp_md *ctx)
{
	__u32 len = (__u32)(ctx->data_end - ctx->data);
	volatile __u64 a = 1, b = 100;

	add_to((__u64 *)&a, len);
	add_to((__u64 *)&b, 2 * len);
	put(0, a);
	put(1, b);
	put(2, depth1(len));
	put(3, keep_regs());
	put(4, len);
	note_len(len);
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
