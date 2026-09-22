#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# knod_stress_module.sh - unload/reload an accel feature module repeatedly.
#
# With ATTACHED=1 the NIC stays attached across the reloads: each cycle
# selects the module's feature, optionally runs the interface up, deselects,
# then removes and re-inserts the module.  The first cycle also checks that
# rmmod is refused while the feature is selected (the module pins itself).
#
# Environment:
#   NIC=<ifname>      (required)
#   ACCEL_ID=<id>     (optional)
#   ITER=100
#   MODULE=knod_bpf   knod_bpf | knod_ipsec
#   MODULE_ARGS=''    modprobe arguments (e.g. "nr_dispatch=4")
#   ATTACHED=1        keep the NIC attached across reloads
#   WITH_UP=1  DWELL=1  TRAFFIC_START / TRAFFIC_STOP   as in knod_stress_attach.sh
#
# Exit: 0=pass, 1=fail, 4=skip

set -o pipefail

SELFDIR=$(dirname "$(readlink -f "$0")")
source "$SELFDIR/lib.sh"

: "${NIC:=}"
: "${ACCEL_ID:=}"
: "${ITER:=100}"
: "${MODULE:=knod_bpf}"
: "${MODULE_ARGS:=}"
: "${ATTACHED:=1}"
: "${WITH_UP:=1}"
: "${DWELL:=1}"

PASS=0
FAIL=0

case "$MODULE" in
knod_bpf)   feature=bpf ;;
knod_ipsec) feature=ipsec ;;
*)          knod_skip "unknown MODULE $MODULE" ;;
esac

cleanup() {
	knod_traffic_stop
	[ -n "$NIC" ] && knod_cleanup "$NIC"
	modprobe "$MODULE" $MODULE_ARGS 2>/dev/null
}
trap cleanup EXIT

fail_stop() {
	knod_fail "$1"
	FAIL=$((FAIL + 1))
	knod_stress_epilogue
	exit 1
}

knod_stress_prologue
modinfo "$MODULE" >/dev/null 2>&1 || knod_skip "$MODULE is not a module"

echo "=== KNOD module reload stress ==="
echo "    NIC: $NIC  ACCEL_ID: $accel_id  MODULE: $MODULE  ITER: $ITER  ATTACHED: $ATTACHED"
echo ""

ip link set dev "$NIC" down 2>/dev/null
knod_detach "$NIC" 2>/dev/null
modprobe "$MODULE" $MODULE_ARGS || fail_stop "initial modprobe $MODULE"

if [ "$ATTACHED" = 1 ]; then
	knod_attach "$NIC" "$accel_id" >/dev/null || fail_stop "attach"
	knod_feature_select "$accel_id" "$feature" >/dev/null ||
		fail_stop "select $feature"
	if rmmod "$MODULE" 2>/dev/null; then
		fail_stop "rmmod $MODULE succeeded with feature $feature selected"
	fi
	knod_pass "rmmod refused while $feature is selected"
	PASS=$((PASS + 1))
	knod_feature_select "$accel_id" none >/dev/null || fail_stop "select none"
fi

for ((i = 1; i <= ITER; i++)); do
	knod_dmesg_mark "cycle $i"

	rmmod "$MODULE" || fail_stop "cycle $i: rmmod"
	modprobe "$MODULE" $MODULE_ARGS || fail_stop "cycle $i: modprobe"

	if [ "$ATTACHED" = 1 ]; then
		knod_feature_select "$accel_id" "$feature" >/dev/null ||
			fail_stop "cycle $i: select $feature after reload"
		if [ "$WITH_UP" = 1 ]; then
			ip link set dev "$NIC" up || fail_stop "cycle $i: link up"
			knod_traffic_start
			sleep "$DWELL"
			knod_traffic_stop
			ip link set dev "$NIC" down || fail_stop "cycle $i: link down"
		fi
		knod_feature_select "$accel_id" none >/dev/null ||
			fail_stop "cycle $i: select none"
	fi

	knod_cycle_check "cycle $i" || fail_stop "cycle $i"
	if (( i % KMEMLEAK_EVERY == 0 )); then
		leaks=$(knod_kmemleak_scan)
		(( leaks > KNOD_LEAK_BASE )) &&
			fail_stop "cycle $i: kmemleak +$((leaks - KNOD_LEAK_BASE))"
	fi
	(( i % 10 == 0 )) && knod_log "cycle $i ok"
done

knod_pass "$ITER $MODULE reload cycles"
PASS=$((PASS + 1))
knod_stress_epilogue
