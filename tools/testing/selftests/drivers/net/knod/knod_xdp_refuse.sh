#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# knod_xdp_refuse.sh - what knod cannot translate is refused, not dropped.
#
# xdp_global_func.bpf.o calls a global function, which the verifier checks
# apart from its calls, so there is no call's state to translate it with.
# Loading it has to fail, with the kernel saying nothing alarming, and the
# device has to take a program after.
#
# Environment:
#   NIC=<ifname>      (required)
#   ACCEL_ID=<id>     (optional, auto-detected)
#
# Exit: 0=pass, 1=fail, 4=skip

set -o pipefail

SELFDIR=$(dirname "$(readlink -f "$0")")
source "$SELFDIR/lib.sh"

: "${NIC:=}"
: "${ACCEL_ID:=}"
REFUSED_OBJ="$SELFDIR/xdp_global_func.bpf.o"
GOOD_OBJ="$SELFDIR/xdp_ktime.bpf.o"

PASS=0
FAIL=0

cleanup() {
	[ -n "$NIC" ] && knod_cleanup "$NIC"
}
trap cleanup EXIT

fail_stop() {
	knod_fail "$1"
	FAIL=$((FAIL + 1))
	knod_stress_epilogue
	exit 1
}

knod_stress_prologue
knod_require_module knod_bpf
[ -r "$REFUSED_OBJ" ] || knod_skip "$REFUSED_OBJ not built"
[ -r "$GOOD_OBJ" ] || knod_skip "$GOOD_OBJ not built"

echo "=== KNOD refuses what it cannot translate ==="
echo "    NIC: $NIC  ACCEL_ID: $accel_id"
echo ""

ip link set dev "$NIC" down 2>/dev/null
knod_detach "$NIC" 2>/dev/null
knod_attach "$NIC" "$accel_id" >/dev/null || fail_stop "attach"
knod_feature_select "$accel_id" bpf >/dev/null || fail_stop "select bpf"
ip link set dev "$NIC" up || fail_stop "link up"

knod_dmesg_mark refuse
if knod_xdp_load "$NIC" "$REFUSED_OBJ" >/dev/null 2>&1; then
	knod_xdp_unload "$NIC"
	fail_stop "a call to a global function was taken"
fi
knod_cycle_check "refuse" || fail_stop "refuse"

knod_xdp_load "$NIC" "$GOOD_OBJ" >/dev/null 2>&1 ||
	fail_stop "a good program refused after the bad one"
knod_xdp_unload "$NIC"
knod_cycle_check "after" || fail_stop "after"

knod_pass "refused, and the device still takes a program"
PASS=$((PASS + 1))
knod_stress_epilogue
