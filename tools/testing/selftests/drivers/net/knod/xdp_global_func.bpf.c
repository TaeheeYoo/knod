// SPDX-License-Identifier: GPL-2.0
/* A call to a global function, which the verifier checks on its own rather
 * than as each call reaches it, so knod has no call's state to translate it
 * with and has to refuse it.
 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

__noinline int global_add(int x)
{
	return x + 1;
}

SEC("xdp")
int xdp_global_func(struct xdp_md *ctx)
{
	return global_add(1) == 2 ? XDP_PASS : XDP_DROP;
}

char _license[] SEC("license") = "GPL";
