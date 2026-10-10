#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# knod_xdp_subprog.sh - BPF-to-BPF calls run as they do on a CPU
#
# knod copies a called function in where each call reaches it.  The program
# calls one function on two stack buffers, three deep with a frame each, a
# function that writes r6-r9 under a caller that keeps them, and one that
# updates a map; each leaves a function of the packet's length L in res
# (see xdp_subprog.bpf.c), which this checks after a few pings.
#
# Environment:
#   NIC=<ifname>       (required) NIC to test on
#   REMOTE_IP=<ip>     (required) ping target, on a link nothing else sends on
#   ACCEL_ID=<id>      (optional) GPU accel ID, auto-detected if omitted
#
# Exit: 0=pass, 1=fail, 4=skip

set -o pipefail

SELFDIR=$(dirname "$(readlink -f "$0")")
source "$SELFDIR/lib.sh"

: "${NIC:=}"
: "${ACCEL_ID:=}"
: "${REMOTE_IP:=}"

PASS=0
FAIL=0
BPF_OBJ="$SELFDIR/xdp_subprog.bpf.o"
SIZE=100

cleanup() {
	if [ -n "$NIC" ]; then
		knod_cleanup "$NIC"
	fi
}
trap cleanup EXIT

check_eq() {
	local desc=$1 have=$2 want=$3

	if [ "$have" = "$want" ]; then
		knod_pass "$desc ($have)"
		PASS=$((PASS + 1))
	else
		knod_fail "$desc (have $have, want $want)"
		FAIL=$((FAIL + 1))
	fi
}

knod_check_prereq
[ -n "$NIC" ] || knod_skip "NIC env var not set"
[ -n "$REMOTE_IP" ] || \
	knod_skip "REMOTE_IP env var not set (this test generates its own traffic)"
ip link show "$NIC" >/dev/null 2>&1 || knod_skip "NIC $NIC does not exist"

accel_id=$(knod_find_accel)
[ -n "$accel_id" ] || knod_skip "no KNOD accelerator found"
[ -n "$ACCEL_ID" ] && accel_id="$ACCEL_ID"

echo "=== KNOD XDP BPF-to-BPF call test ==="
echo "    NIC:       $NIC"
echo "    REMOTE_IP: $REMOTE_IP"
echo "    ACCEL_ID:  $accel_id"
echo ""

if [ ! -f "$BPF_OBJ" ]; then
	echo "FAIL: $BPF_OBJ not found (run make first)"
	exit 1
fi

ip link set dev "$NIC" down 2>/dev/null
knod_attach "$NIC" "$accel_id" || { echo "FAIL: attach failed"; exit 1; }
knod_feature_select "$accel_id" bpf || knod_skip "cannot select bpf feature"
knod_xdp_load "$NIC" "$BPF_OBJ" || { echo "FAIL: xdpoffload load failed"; exit 1; }

prog_id=$(bpftool prog show 2>/dev/null | \
	  awk '/xdp_subprog/ {sub(/:/, "", $1); print $1; exit}')
[ -n "$prog_id" ] || { echo "FAIL: cannot find loaded BPF program"; exit 1; }
res_map=$(knod_find_map_by_name "$prog_id" res)
lens_map=$(knod_find_map_by_name "$prog_id" lens)
if [ -z "$res_map" ] || [ -z "$lens_map" ]; then
	echo "FAIL: cannot find maps (res=$res_map lens=$lens_map)"
	exit 1
fi

ip link set dev "$NIC" up
sleep 1
ping -c 5 -i 0.05 -W 1 -s "$SIZE" "$REMOTE_IP" >/dev/null 2>&1
sleep 1

len=$(knod_map_lookup_u64 "$res_map" 4)
if [ "$len" -le 0 ]; then
	echo "FAIL: no packet reached the program"
	exit 1
fi
knod_log "packet length $len"

check_eq "one function on two buffers, first" \
	"$(knod_map_lookup_u64 "$res_map" 0)" $((1 + len))
check_eq "one function on two buffers, second" \
	"$(knod_map_lookup_u64 "$res_map" 1)" $((100 + 2 * len))
check_eq "three calls deep" \
	"$(knod_map_lookup_u64 "$res_map" 2)" $((6 * len + 1))
check_eq "r6-r9 kept across a call that writes them" \
	"$(knod_map_lookup_u64 "$res_map" 3)" $((0xaa))
rc=0
knod_map_has_key_u32 "$lens_map" "$len" || rc=1
check_eq "a callee's map update landed" "$rc" 0

ip link set dev "$NIC" down

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
