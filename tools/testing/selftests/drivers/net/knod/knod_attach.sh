#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# knod_attach.sh - exercise the knod attach/detach control plane.
#
# Checks the NIC<->accel binding lifecycle (attach makes the pair appear in the
# xdev list, detach removes it) and that malformed or impossible attach
# requests are rejected without taking the framework down.
#
# Requires:
#   - KNOD (knod + amdgpu) modules loaded
#   - AMD GPU with KNOD support
#   - a NIC registered with knod
#   - iproute2, root
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

cleanup() {
	if [ -n "$NIC" ]; then
		knod_detach "$NIC" 2>/dev/null
		ip link set dev "$NIC" down 2>/dev/null
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

# reject == the ynl attach request fails (exit nonzero)
expect_reject() {
	local desc=$1
	local json=$2

	if knod_ynl --do attach --json "$json" 2>/dev/null; then
		knod_detach "$NIC" 2>/dev/null	# undo an unexpected success
		check_result "$desc" 1
	else
		check_result "$desc" 0
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

echo "=== KNOD attach/detach control-plane test ==="
echo "    NIC:      $NIC"
echo "    ACCEL_ID: $accel_id"
echo ""

# attach requires the interface down; start from a known detached state
ip link set dev "$NIC" down 2>/dev/null
knod_detach "$NIC" 2>/dev/null

# -- positive lifecycle ----------------------------------------
knod_attach "$NIC" "$accel_id"
check_result "attach $NIC -> accel $accel_id" $?

knod_xdev_has "$NIC"
check_result "xdev lists $NIC after attach" $?

knod_detach "$NIC"
check_result "detach $NIC" $?

if knod_xdev_has "$NIC"; then
	check_result "xdev drops $NIC after detach" 1
else
	check_result "xdev drops $NIC after detach" 0
fi

# -- negative requests must be rejected ------------------------
nic_ifindex=$(knod_ifindex "$NIC")
nic_json="\"nic-ifindex\":$nic_ifindex"
expect_reject "reject attach with no accel id"     "{$nic_json}"
expect_reject "reject attach to nonexistent accel" "{$nic_json,\"accel-id\":999999}"
expect_reject "reject attach of nonexistent NIC"   "{\"nic-ifindex\":999999,\"accel-id\":$accel_id}"

ip link set dev "$NIC" up 2>/dev/null
expect_reject "reject attach while NIC is up"      "{$nic_json,\"accel-id\":$accel_id}"
ip link set dev "$NIC" down 2>/dev/null

# -- framework survived the bad requests -----------------------
knod_kernel_alive
check_result "framework responsive after bad requests" $?

# -- re-attach still works (state not corrupted) ---------------
knod_attach "$NIC" "$accel_id"
check_result "re-attach after errors" $?
knod_detach "$NIC" 2>/dev/null

# -- summary --------------------------------------------------
echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="

if [ "$FAIL" -gt 0 ]; then
	exit 1
fi
exit 0
