#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# knod_xdp_ktime.sh — test bpf_ktime_get_ns() on GPU XDP offload
#
# Loads an XDP program that calls bpf_ktime_get_ns() and stores
# the result in an offloaded BPF_MAP_TYPE_ARRAY, then verifies
# the GPU-side timestamp is sane.
#
# Requires:
#   - KNOD (knod + amdgpu) modules loaded
#   - AMD GPU with KNOD support
#   - NIC with xdpoffload support (mlx5, bnxt)
#   - bpftool, iproute2
#   - root privileges
#   - xdp_ktime.bpf.o (built by make)
#
# Environment:
#   NIC=<ifname>       (required) NIC to test on
#   ACCEL_ID=<id>      (optional) GPU accel ID, auto-detected if omitted
#   REMOTE_IP=<ip>     (optional) ping target to generate traffic
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
BPF_OBJ="$SELFDIR/xdp_ktime.bpf.o"

cleanup() {
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

# ── prereq ──────────────────────────────────────────────────────
knod_check_prereq

if [ -z "$NIC" ]; then
	knod_skip "NIC env var not set"
fi

if ! ip link show "$NIC" >/dev/null 2>&1; then
	knod_skip "NIC $NIC does not exist"
fi

accel_id=$(knod_find_accel)
if [ -z "$accel_id" ]; then
	knod_skip "no KNOD accelerator found"
fi
[ -n "$ACCEL_ID" ] && accel_id="$ACCEL_ID"

echo "=== KNOD XDP ktime_get_ns test ==="
echo "    NIC:      $NIC"
echo "    ACCEL_ID: $accel_id"
echo ""

# ── check BPF object ──────────────────────────────────────────
if [ ! -f "$BPF_OBJ" ]; then
	echo "FAIL: $BPF_OBJ not found (run make first)"
	exit 1
fi

# ── attach NIC to GPU, select bpf feature ─────────────────────
ip link set dev "$NIC" down 2>/dev/null
knod_attach "$NIC" "$accel_id"
if [ $? -ne 0 ]; then
	echo "FAIL: attach failed"
	exit 1
fi

knod_feature_select "$accel_id" bpf
if [ $? -ne 0 ]; then
	knod_skip "cannot select bpf feature"
fi

# ── load XDP offload program ──────────────────────────────────
knod_xdp_load "$NIC" "$BPF_OBJ"
if [ $? -ne 0 ]; then
	echo "FAIL: xdpoffload load failed"
	exit 1
fi

# ── find prog/map IDs ─────────────────────────────────────────
prog_id=$(bpftool prog show 2>/dev/null | \
	  awk '/xdp_ktime_test/ {sub(/:/, "", $1); print $1; exit}')
if [ -z "$prog_id" ]; then
	echo "FAIL: cannot find loaded BPF program"
	exit 1
fi
knod_log "prog_id=$prog_id"

map_id=$(knod_get_map_id "$prog_id")
if [ -z "$map_id" ]; then
	echo "FAIL: cannot find BPF map"
	exit 1
fi
knod_log "map_id=$map_id"

# ── bring up interface and generate traffic ───────────────────
ip link set dev "$NIC" up

if [ -n "$REMOTE_IP" ]; then
	knod_log "ping $REMOTE_IP to generate traffic"
	ping -c 5 -W 1 "$REMOTE_IP" >/dev/null 2>&1 || true
else
	knod_log "waiting for ambient traffic (10s)"
	sleep 10
fi

# ── bring down interface before reading map ──────────────────
ip link set dev "$NIC" down

# ── read map and verify ──────────────────────────────────────
ktime_val=$(knod_map_lookup_u64 "$map_id" 0)
pkt_count=$(knod_map_lookup_u64 "$map_id" 1)

knod_log "ktime_ns=$ktime_val  pkt_count=$pkt_count"

# Test 1: packets were processed
rc=0
[ "$pkt_count" -gt 0 ] || rc=1
check_result "packets processed (count=$pkt_count)" $rc

# Test 2: ktime is non-zero
rc=0
[ "$ktime_val" -gt 0 ] || rc=1
check_result "ktime non-zero ($ktime_val)" $rc

# Test 3: ktime is within 30s of current time
if [ "$ktime_val" -gt 0 ]; then
	now_ns=$(awk '{printf "%.0f", $1 * 1000000000}' /proc/uptime)
	if [ -n "$now_ns" ]; then
		diff=$(( now_ns - ktime_val ))
		abs_diff=${diff#-}
		rc=0
		[ "$abs_diff" -lt 30000000000 ] || rc=1
		check_result "ktime within 30s of wall clock (diff=${diff}ns)" $rc
	else
		knod_log "skipping wall clock check (/proc/uptime unavailable)"
	fi
fi

# ── summary ──────────────────────────────────────────────────
echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="

if [ "$FAIL" -gt 0 ]; then
	exit 1
fi
exit 0
