// SPDX-License-Identifier: GPL-2.0
/* A BPF-to-BPF call, which knod does not translate and has to refuse.
 *
 * The call's imm is the distance to the callee, and the main program is laid
 * out so that it is 5 - the number of bpf_ktime_get_ns().  A JIT that reads
 * every call as a helper translates this one into a clock read and drops the
 * callee without a word.
 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

__attribute__((naked, used)) __noinline
static int pass_subprog(void)
{
	asm volatile("r0 = %[pass];"
		     "exit;"
		     :: [pass] "i"(XDP_PASS));
}

SEC("xdp")
__attribute__((naked))
int xdp_subprog(void)
{
	asm volatile("call pass_subprog;"
		     "r0 = %[drop];"
		     "r0 = %[drop];"
		     "r0 = %[drop];"
		     "r0 = %[drop];"
		     "exit;"
		     :: [drop] "i"(XDP_DROP));
}

char _license[] SEC("license") = "GPL";
