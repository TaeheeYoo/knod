// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/* The key is the packet length, so the sender decides how the lanes are
 * spread: one length puts every lane on one bucket and stresses the lock,
 * a sweep of lengths fills chains and stresses insert.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, __u64);
} len_map SEC(".maps");

/* Lengths this program deletes rather than keeps.  Populated by the test so
 * that which keys should be absent afterwards is the test's decision and not
 * something it has to infer.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, __u64);
} del_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} stats SEC(".maps");

SEC("xdp")
int xdp_hash_ops(struct xdp_md *ctx)
{
	__u32 len = (__u32)(ctx->data_end - ctx->data);
	__u32 zero = 0;
	__u64 one = 1;
	__u64 *v;

	/* Insert on first sight, overwrite after.  Both paths of an update,
	 * and with one length in flight every lane takes them on one bucket.
	 */
	bpf_map_update_elem(&len_map, &len, &one, BPF_ANY);

	/* A length the test marked for deletion is inserted here and taken
	 * straight back out, so delete runs against an element that is
	 * certainly present.
	 */
	if (bpf_map_lookup_elem(&del_map, &len)) {
		bpf_map_update_elem(&del_map, &len, &one, BPF_ANY);
		bpf_map_delete_elem(&del_map, &len);
	}

	v = bpf_map_lookup_elem(&stats, &zero);
	if (v)
		__sync_fetch_and_add(v, 1);

	return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
