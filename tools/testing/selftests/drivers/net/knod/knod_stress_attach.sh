#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# knod_stress_attach.sh - attach/detach lifecycle under repetition.
#
# Each cycle: attach, select FEATURE, optionally load an XDP program, bring
# the interface up (traffic hooks fire here), dwell, down, detach.  Odd cycles
# detach with the feature still selected so pre_detach tears it down; even
# cycles deselect first.  After every cycle the framework must still answer
# and the kernel must not have complained; kmemleak is scanned every
# KMEMLEAK_EVERY cycles and at the end.
#
# Environment:
#   NIC=<ifname>      (required)
#   ACCEL_ID=<id>     (optional, auto-detected)
#   ITER=200          cycles
#   FEATURE=bpf       none | bpf | ipsec
#   WITH_UP=1         bring the interface up each cycle
#   DWELL=1           seconds to stay up (with traffic, if hooked)
#   XDP_OBJ=<path>    XDP object to load/unload each cycle (bpf only);
#                     default xdp_stress.bpf.o, "" to skip
#   TRAFFIC_START / TRAFFIC_STOP   shell snippets run around the up window
#
# Exit: 0=pass, 1=fail, 4=skip

set -o pipefail

SELFDIR=$(dirname "$(readlink -f "$0")")
source "$SELFDIR/lib.sh"

: "${NIC:=}"
: "${ACCEL_ID:=}"
: "${ITER:=200}"
: "${FEATURE:=bpf}"
: "${WITH_UP:=1}"
: "${DWELL:=1}"
: "${XDP_OBJ=$SELFDIR/xdp_stress.bpf.o}"

PASS=0
FAIL=0

cleanup() {
	knod_traffic_stop
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

case "$FEATURE" in
bpf)   knod_require_module knod_bpf ;;
ipsec) knod_require_module knod_ipsec ;;
esac
if [ -n "$XDP_OBJ" ] && [ "$FEATURE" != bpf ]; then
	knod_skip "XDP_OBJ needs FEATURE=bpf"
fi

echo "=== KNOD attach/detach stress ==="
echo "    NIC: $NIC  ACCEL_ID: $accel_id  ITER: $ITER  FEATURE: $FEATURE"
echo "    WITH_UP: $WITH_UP  DWELL: $DWELL  XDP_OBJ: ${XDP_OBJ:-none}"
echo ""

ip link set dev "$NIC" down 2>/dev/null
knod_detach "$NIC" 2>/dev/null

for ((i = 1; i <= ITER; i++)); do
	knod_dmesg_mark "cycle $i"

	knod_attach "$NIC" "$accel_id" >/dev/null || fail_stop "cycle $i: attach"
	if [ "$FEATURE" != none ]; then
		knod_feature_select "$accel_id" "$FEATURE" >/dev/null ||
			fail_stop "cycle $i: feature $FEATURE"
	fi
	if [ -n "$XDP_OBJ" ]; then
		knod_xdp_load "$NIC" "$XDP_OBJ" >/dev/null 2>&1 ||
			fail_stop "cycle $i: xdp load"
	fi
	if [ "$WITH_UP" = 1 ]; then
		ip link set dev "$NIC" up || fail_stop "cycle $i: link up"
		knod_traffic_start
		sleep "$DWELL"
		knod_traffic_stop
		if [ -n "$XDP_OBJ" ]; then
			knod_stress_verify_maps "$NIC" "${TRAFFIC_START:+1}" ||
				fail_stop "cycle $i: map check"
		fi
		ip link set dev "$NIC" down || fail_stop "cycle $i: link down"
	fi
	if [ -n "$XDP_OBJ" ]; then
		knod_xdp_unload "$NIC"
	fi
	if [ "$FEATURE" != none ] && (( i % 2 == 0 )); then
		knod_feature_select "$accel_id" none >/dev/null ||
			fail_stop "cycle $i: feature none"
	fi
	knod_detach "$NIC" || fail_stop "cycle $i: detach"
	if knod_xdev_has "$NIC"; then
		fail_stop "cycle $i: still listed after detach"
	fi

	knod_cycle_check "cycle $i" || fail_stop "cycle $i"
	if (( i % KMEMLEAK_EVERY == 0 )); then
		leaks=$(knod_kmemleak_scan)
		(( leaks > KNOD_LEAK_BASE )) &&
			fail_stop "cycle $i: kmemleak +$((leaks - KNOD_LEAK_BASE))"
	fi
	(( i % 10 == 0 )) && knod_log "cycle $i ok"
done

knod_pass "$ITER attach/detach cycles"
PASS=$((PASS + 1))
knod_stress_epilogue
