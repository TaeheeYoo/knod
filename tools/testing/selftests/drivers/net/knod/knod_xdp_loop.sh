#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# knod_xdp_loop.sh - the KNOD JIT must reject a bounded-loop XDP program.
#
# Loop emission is not implemented yet, so a program with a real back-edge has
# to be rejected with -EOPNOTSUPP at JIT time rather than miscompiled.  This
# checks that the load fails, that the back-edge is reported to dmesg, and that
# nothing crashed or faulted in the reject path.
#
# Requires:
#   - KNOD (knod + amdgpu) modules loaded
#   - AMD GPU with KNOD support
#   - NIC with xdpoffload support (mlx5, bnxt)
#   - bpftool, iproute2, root
#   - xdp_loop.bpf.o (built by make)
#
# Environment:
#   NIC=<ifname>   (required) NIC to test on
#   ACCEL_ID=<id>  (optional) GPU accel ID, auto-detected if omitted
#
# Exit: 0=pass, 1=fail, 4=skip

set -o pipefail

SELFDIR=$(dirname "$(readlink -f "$0")")
source "$SELFDIR/lib.sh"

: "${NIC:=}"
: "${ACCEL_ID:=}"

PASS=0
FAIL=0
BPF_OBJ="$SELFDIR/xdp_loop.bpf.o"

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

# -- prereq ------------------------------------------------------
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

if [ ! -f "$BPF_OBJ" ]; then
	echo "FAIL: $BPF_OBJ not found (run make first)"
	exit 1
fi

echo "=== KNOD XDP loop-rejection test ==="
echo "    NIC:      $NIC"
echo "    ACCEL_ID: $accel_id"
echo ""

# -- setup: attach NIC to GPU, then select the bpf feature -----
# feature_select needs the accel already attached (it swaps the live
# worker), so attach first.
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

# remember where dmesg is now so we only scan messages from this load
dmesg_mark=$(dmesg | wc -l)

# -- load must fail --------------------------------------------
knod_log "loading bounded-loop program (expecting rejection)"
if knod_xdp_load "$NIC" "$BPF_OBJ" 2>/dev/null; then
	# unexpectedly accepted - unload and fail
	knod_xdp_unload "$NIC"
	check_result "loop program rejected at load" 1
else
	check_result "loop program rejected at load" 0
fi

new_dmesg=$(dmesg | tail -n +"$((dmesg_mark + 1))")

# -- back-edge reported ----------------------------------------
rc=1
echo "$new_dmesg" | grep -q "knod_loop:.*back-edge" && rc=0
check_result "loop back-edge reported in dmesg" $rc

# -- framework still alive -------------------------------------
knod_kernel_alive
check_result "system responsive after rejection" $?

# -- summary --------------------------------------------------
echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="

if [ "$FAIL" -gt 0 ]; then
	exit 1
fi
exit 0
