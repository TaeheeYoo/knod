// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/*
 * Minimal bounded-loop XDP program to exercise the KNOD JIT's loop detection.
 *
 * The trip count is read from the packet (runtime) and unrolling is disabled,
 * so the compiler keeps a real loop with a back-edge instead of folding it
 * into straight-line code.  The body is an xorshift step — a non-affine
 * recurrence the compiler cannot reduce to a closed form (a simple sum like
 * "sum += i" gets turned into n*(n-1)/2 and the loop disappears).  It touches
 * no memory inside the loop, so the verifier is happy, and it has the simplest
 * shape: one back-edge, a single exit (the loop condition), no break and no
 * early return.
 */
SEC("xdp")
int xdp_loop_test(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	__u8 *pkt = data;
	__u32 sum;
	int i, n;

	if ((void *)(pkt + 1) > data_end)
		return XDP_DROP;

	n = pkt[0] & 0x3f;		/* runtime bound, 0..63 */
	sum = pkt[0] | 1;		/* nonzero xorshift seed */

#pragma clang loop unroll(disable)
	for (i = 0; i < n; i++) {
		sum ^= sum << 13;
		sum ^= sum >> 17;
		sum ^= sum << 5;
	}

	return (sum & 1) ? XDP_PASS : XDP_DROP;
}

char LICENSE[] SEC("license") = "GPL";
