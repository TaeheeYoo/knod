// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

/* A flow's 5-tuple, as kondor keys its connection table. */
struct flow_key {
	__u32 saddr;
	__u32 daddr;
	__u16 sport;
	__u16 dport;
	__u8 proto;
	__u8 pad[3];
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1024);
	__type(key, struct flow_key);
	__type(value, __u64);
} flows SEC(".maps");

/* [0] packets keyed, [1] inserts the map refused, [2] packets not keyed. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 3);
	__type(key, __u32);
	__type(value, __u64);
} stats SEC(".maps");

static __always_inline void count(__u32 idx)
{
	__u64 *v = bpf_map_lookup_elem(&stats, &idx);

	if (v)
		*v += 1;
}

SEC("xdp")
int xdp_lru_flow(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	struct flow_key key = {};
	struct iphdr *ip;
	__u16 *ports;
	__u64 one = 1;

	ip = (struct iphdr *)(eth + 1);
	ports = (__u16 *)(ip + 1);
	if ((void *)(ports + 2) > data_end ||
	    eth->h_proto != bpf_htons(ETH_P_IP) || ip->ihl != 5 ||
	    (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP)) {
		count(2);
		return XDP_PASS;
	}

	key.saddr = ip->saddr;
	key.daddr = ip->daddr;
	key.sport = ports[0];
	key.dport = ports[1];
	key.proto = ip->protocol;

	if (!bpf_map_lookup_elem(&flows, &key) &&
	    bpf_map_update_elem(&flows, &key, &one, BPF_ANY))
		count(1);
	count(0);

	return XDP_DROP;
}

char LICENSE[] SEC("license") = "GPL";
