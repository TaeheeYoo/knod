// SPDX-License-Identifier: GPL-2.0
/* Every helper and map type the offload JIT accepts, on every packet, with
 * every verdict: the program the stress scripts load so that a lifecycle
 * exercise also exercises the data path.  The stats map lets a script check
 * the counts add up afterwards.
 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define STAT_TOTAL	0
#define STAT_TX		1
#define STAT_PASS	2
#define STAT_DROP	3
#define STAT_HEAD_FAIL	4
#define STAT_TAIL_NOROOM 5
#define STAT_NR		8

#define MODE_ROTATE	0	/* TX / PASS / DROP by flow */
#define MODE_TX		1
#define MODE_PASS	2
#define MODE_DROP	3

struct flow_key {
	__be32 src;
	__be32 dst;
	__u32 ports;
	__u8 proto;
};

struct counters {
	__u64 pkts;
	__u64 bytes;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, STAT_NR);
	__type(key, __u32);
	__type(value, __u64);
} stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, STAT_NR);
	__type(key, __u32);
	__type(value, struct counters);
} pstats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, struct flow_key);
	__type(value, struct counters);
} flows SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 4096);
	__type(key, struct flow_key);
	__type(value, struct counters);
} flow_pstats SEC(".maps");

/* ctl[0] = verdict mode; the script writes it. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} ctl SEC(".maps");

static __always_inline void stat_add(__u32 idx, __u64 n)
{
	__u64 *v = bpf_map_lookup_elem(&stats, &idx);

	if (v)
		__sync_fetch_and_add(v, n);
}

static __always_inline void pstat_add(__u32 idx, __u64 pkts, __u64 bytes)
{
	struct counters *c = bpf_map_lookup_elem(&pstats, &idx);

	if (c) {
		c->pkts += pkts;
		c->bytes += bytes;
	}
}

SEC("xdp")
int xdp_stress(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct flow_key key = {};
	struct counters *c;
	struct ethhdr *eth = data;
	struct iphdr *iph;
	struct udphdr *udph;
	__u64 len = data_end - data;
	__u32 zero = 0, sel, *mode;
	__u64 ts;
	int verdict;

	ts = bpf_ktime_get_ns();
	stat_add(STAT_TOTAL, 1);
	pstat_add(STAT_TOTAL, 1, len);

	if ((void *)(eth + 1) > data_end)
		goto drop;
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		goto pass;

	iph = (void *)(eth + 1);
	if ((void *)(iph + 1) > data_end)
		goto drop;
	key.src = iph->saddr;
	key.dst = iph->daddr;
	key.proto = iph->protocol;
	if (iph->protocol == IPPROTO_UDP || iph->protocol == IPPROTO_TCP) {
		udph = (void *)iph + sizeof(*iph);
		if ((void *)(udph + 1) > data_end)
			goto drop;
		key.ports = ((__u32)udph->source << 16) | udph->dest;
	}

	/* Shared hash: insert on first sight, atomic add after. */
	c = bpf_map_lookup_elem(&flows, &key);
	if (c) {
		__sync_fetch_and_add(&c->pkts, 1);
		__sync_fetch_and_add(&c->bytes, len);
	} else {
		struct counters init = { .pkts = 1, .bytes = len };

		bpf_map_update_elem(&flows, &key, &init, BPF_ANY);
	}

	/* Per-queue hash: this instance's slot only. */
	c = bpf_map_lookup_elem(&flow_pstats, &key);
	if (c) {
		c->pkts += 1;
		c->bytes += len;
	} else {
		struct counters init = { .pkts = 1, .bytes = len };

		bpf_map_update_elem(&flow_pstats, &key, &init, BPF_ANY);
	}

	/* Churn: flows whose low port byte is 0xff come straight back out,
	 * so delete and the zero-on-free of a reused element get exercised.
	 */
	if ((key.ports & 0xff) == 0xff) {
		bpf_map_delete_elem(&flows, &key);
		bpf_map_delete_elem(&flow_pstats, &key);
	}

	/* Headroom round trip: push, write, pop, leaving the frame as it was. */
	if (bpf_xdp_adjust_head(ctx, -16)) {
		stat_add(STAT_HEAD_FAIL, 1);
		goto drop;
	}
	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;
	if (data + 16 > data_end)
		goto drop;
	*(__u64 *)data = ts;
	*(__u64 *)(data + 8) = len;
	if (bpf_xdp_adjust_head(ctx, 16)) {
		stat_add(STAT_HEAD_FAIL, 1);
		goto drop;
	}

	/* Tailroom round trip; growth is allowed to fail when the frame has
	 * none, which is counted, not treated as an error.
	 */
	if (bpf_xdp_adjust_tail(ctx, 4) == 0) {
		if (bpf_xdp_adjust_tail(ctx, -4))
			goto drop;
	} else {
		stat_add(STAT_TAIL_NOROOM, 1);
	}

	mode = bpf_map_lookup_elem(&ctl, &zero);
	sel = mode ? *mode : MODE_ROTATE;
	if (sel == MODE_ROTATE) {
		__u32 h = key.ports ^ bpf_ntohl(key.src);

		sel = (h & 1) ? MODE_TX : (h & 2) ? MODE_PASS : MODE_DROP;
	}
	if (sel == MODE_TX) {
		verdict = XDP_TX;
		stat_add(STAT_TX, 1);
		pstat_add(STAT_TX, 1, len);
	} else if (sel == MODE_DROP) {
		goto drop;
	} else {
		goto pass;
	}
	return verdict;

pass:
	stat_add(STAT_PASS, 1);
	pstat_add(STAT_PASS, 1, len);
	return XDP_PASS;
drop:
	stat_add(STAT_DROP, 1);
	pstat_add(STAT_DROP, 1, len);
	return XDP_DROP;
}

char LICENSE[] SEC("license") = "GPL";
