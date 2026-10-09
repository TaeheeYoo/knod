#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# knod_xdp_lru_flow.sh - an LRU hash under many flows at line rate
#
# The program keys a 1024-entry LRU_HASH by each IPv4 TCP/UDP packet's
# 5-tuple, as kondor keys its connection table, inserts the flows it has not
# seen and drops the packets.  With more flows than entries every queue and
# wave evicts at once, which knod_xdp_lru.sh, a packet at a time, never
# does.  What it checks is what a broken eviction breaks:
#
#   - an insert refused: eviction found nothing it could take
#   - the map not full, or a key in it twice: an element lost or linked
#     twice
#   - a hang or a complaint from the kernel
#
# Which flows survive is not checked: that takes knowing the order packets
# arrived in, which knod_xdp_lru.sh controls and a generator does not.
#
# Send IPv4 TCP or UDP with well over 1024 flows - say 16384 source
# addresses or ports - from a generator such as TRex.
#
# Requires:
#   - KNOD (knod + amdgpu) modules loaded
#   - AMD GPU with KNOD support
#   - NIC with xdpoffload support (mlx5)
#   - bpftool, jq, iproute2
#   - root privileges
#   - xdp_lru_flow.bpf.o (built by make)
#
# Environment:
#   NIC=<ifname>       (required) NIC to test on
#   ACCEL_ID=<id>      (optional) GPU accel ID, auto-detected if omitted
#   DURATION=<s>       (optional) how long to take traffic, default 30
#   TRAFFIC_START=...  (optional) eval'd to start the generator; without it
#   TRAFFIC_STOP=...   the test waits DURATION for traffic sent by hand
#
# Exit: 0=pass, 1=fail, 4=skip

set -o pipefail

SELFDIR=$(dirname "$(readlink -f "$0")")
source "$SELFDIR/lib.sh"

: "${NIC:=}"
: "${ACCEL_ID:=}"
: "${DURATION:=30}"

PASS=0
FAIL=0
BPF_OBJ="$SELFDIR/xdp_lru_flow.bpf.o"
# flows' size in xdp_lru_flow.bpf.c.
ENTRIES=1024

cleanup() {
	knod_traffic_stop
	if [ -n "$NIC" ]; then
		knod_cleanup "$NIC"
	fi
}
trap cleanup EXIT

check_result() {
	local desc=$1
	local ret=$2

	if [ "$ret" -eq 0 ]; then
		knod_pass "$desc"
		PASS=$((PASS + 1))
	else
		knod_fail "$desc"
		FAIL=$((FAIL + 1))
	fi
}

# The per-cpu stats slot @1, summed.
stat_sum() {
	bpftool -j map lookup id "$stats_map" key "$1" 0 0 0 2>/dev/null | \
		jq 'def byte: ltrimstr("0x") | explode | reduce .[] as $c (0;
			.*16 + (if $c >= 97 then $c - 87 else $c - 48 end));
		    [.values[].value | to_entries
		     | map((.value | byte) * pow(256; .key)) | add] | add // 0'
}

# -- prereq ------------------------------------------------------
knod_check_prereq
command -v jq >/dev/null || knod_skip "jq not installed"
[ -n "$NIC" ] || knod_skip "NIC env var not set"
ip link show "$NIC" >/dev/null 2>&1 || knod_skip "NIC $NIC does not exist"

accel_id=$(knod_find_accel)
[ -n "$accel_id" ] || knod_skip "no KNOD accelerator found"
[ -n "$ACCEL_ID" ] && accel_id="$ACCEL_ID"

echo "=== KNOD XDP LRU hash flow test ==="
echo "    NIC:       $NIC"
echo "    ACCEL_ID:  $accel_id"
echo "    DURATION:  ${DURATION}s"
echo ""

if [ ! -f "$BPF_OBJ" ]; then
	echo "FAIL: $BPF_OBJ not found (run make first)"
	exit 1
fi

# -- attach, select feature, load ------------------------------
ip link set dev "$NIC" down 2>/dev/null
knod_attach "$NIC" "$accel_id" || { echo "FAIL: attach failed"; exit 1; }
knod_feature_select "$accel_id" bpf || knod_skip "cannot select bpf feature"
knod_xdp_load "$NIC" "$BPF_OBJ" || { echo "FAIL: xdpoffload load failed"; exit 1; }

prog_id=$(bpftool prog show 2>/dev/null | \
	  awk '/xdp_lru_flow/ {sub(/:/, "", $1); print $1; exit}')
[ -n "$prog_id" ] || { echo "FAIL: cannot find loaded BPF program"; exit 1; }

flows_map=$(knod_find_map_by_name "$prog_id" flows)
stats_map=$(knod_find_map_by_name "$prog_id" stats)
if [ -z "$flows_map" ] || [ -z "$stats_map" ]; then
	echo "FAIL: cannot find maps (flows=$flows_map stats=$stats_map)"
	exit 1
fi
knod_log "prog_id=$prog_id flows=$flows_map stats=$stats_map"

ip link set dev "$NIC" up
sleep 1
knod_dmesg_mark "lru_flow"

# -- traffic ---------------------------------------------------
if [ -n "$TRAFFIC_START" ]; then
	knod_log "starting traffic for ${DURATION}s"
	knod_traffic_start
else
	knod_log "send traffic now: ${DURATION}s"
fi
sleep "$DURATION"
knod_traffic_stop
TRAFFIC_STOP=
sleep 2

# -- checks ----------------------------------------------------
keyed=$(stat_sum 0)
refused=$(stat_sum 1)
other=$(stat_sum 2)
knod_log "packets keyed $keyed, not keyed $other"

rc=0
[ "$keyed" -gt 0 ] || rc=1
check_result "packets reached the program ($keyed)" $rc

rc=0
[ "$refused" -eq 0 ] || rc=1
check_result "no insert refused ($refused)" $rc

nr=$(knod_map_nr_elems "$flows_map")
rc=0
[ "$nr" -eq "$ENTRIES" ] || rc=1
check_result "the map is full ($nr, want $ENTRIES; fewer flows sent than that?)" $rc

dups=$(bpftool -j map dump id "$flows_map" 2>/dev/null | \
       jq -r '.[].key | join(" ")' | sort | uniq -d | grep -c .)
rc=0
[ "$dups" -eq 0 ] || rc=1
check_result "no key appears twice ($dups duplicated)" $rc

rc=0
knod_cycle_check "lru_flow" || rc=1
check_result "kernel quiet, knod alive" $rc

ip link set dev "$NIC" down

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
