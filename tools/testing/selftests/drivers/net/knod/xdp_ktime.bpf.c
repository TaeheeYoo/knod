// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, __u64);
} ktime_map SEC(".maps");

SEC("xdp")
int xdp_ktime_test(struct xdp_md *ctx)
{
	__u32 key_ts = 0;
	__u32 key_cnt = 1;
	__u64 ts = bpf_ktime_get_ns();
	__u64 *cnt;
	__u64 new_cnt;

	bpf_map_update_elem(&ktime_map, &key_ts, &ts, BPF_ANY);

	cnt = bpf_map_lookup_elem(&ktime_map, &key_cnt);
	if (cnt) {
		new_cnt = *cnt + 1;
		bpf_map_update_elem(&ktime_map, &key_cnt, &new_cnt, BPF_ANY);
	}

	return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
