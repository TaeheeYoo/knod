// SPDX-License-Identifier: GPL-2.0
/* More stack a lane than a 256-lane workgroup's LDS can hold, so knod has to
 * put it in VRAM.  Every slot is written and read back: a program that sees
 * its own stack drops, one that does not passes the packet up.
 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define WORDS	100	/* 400 bytes */

SEC("xdp")
int xdp_deepstack(struct xdp_md *ctx)
{
	volatile __u32 buf[WORDS];
	__u32 sum = 0;
	int i;

#pragma clang loop unroll(full)
	for (i = 0; i < WORDS; i++)
		buf[i] = i;
#pragma clang loop unroll(full)
	for (i = 0; i < WORDS; i++)
		sum += buf[i];

	return sum == WORDS * (WORDS - 1) / 2 ? XDP_DROP : XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
