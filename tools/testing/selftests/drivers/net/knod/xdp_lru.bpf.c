// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/* Keyed by packet length, as in xdp_hash_ops, so the sender decides which
 * keys arrive and in what order.
 */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 64);
	__type(key, __u32);
	__type(value, __u64);
} lru_map SEC(".maps");

/* [0] packets seen, [1] inserts the map refused. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, __u64);
} stats SEC(".maps");

SEC("xdp")
int xdp_lru(struct xdp_md *ctx)
{
	__u32 len = (__u32)(ctx->data_end - ctx->data);
	__u32 idx = 0;
	__u64 one = 1;
	__u64 *v;

	if (!bpf_map_lookup_elem(&lru_map, &len) &&
	    bpf_map_update_elem(&lru_map, &len, &one, BPF_ANY))
		idx = 1;

	v = bpf_map_lookup_elem(&stats, &idx);
	if (v)
		__sync_fetch_and_add(v, 1);

	return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
