#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# knod_stress_feature.sh - switch the offload feature under traffic.
#
# Attached and up (traffic flowing, if hooked), the accel cycles through
# none -> bpf -> none -> ipsec -> bpf -> ipsec ..., which swaps the live
# worker and frees the outgoing feature's GPU resources while the previous
# worker may still be draining.  ipsec is included only when knod_ipsec is
# loaded.  With XDP_OBJ set, a program is loaded while bpf is selected.
#
# Environment:
#   NIC=<ifname>      (required)
#   ACCEL_ID=<id>     (optional)
#   ITER=200          feature switches
#   DWELL=1           seconds per feature
#   XDP_OBJ=<path>
#   TRAFFIC_START / TRAFFIC_STOP
#
# Exit: 0=pass, 1=fail, 4=skip

set -o pipefail

SELFDIR=$(dirname "$(readlink -f "$0")")
source "$SELFDIR/lib.sh"

: "${NIC:=}"
: "${ACCEL_ID:=}"
: "${ITER:=200}"
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

knod_require_module knod_bpf
seq_features="none bpf none"
if lsmod | grep -q '^knod_ipsec'; then
	seq_features="none bpf none ipsec bpf ipsec"
fi
set -- $seq_features
nfeat=$#

echo "=== KNOD feature switch stress ==="
echo "    NIC: $NIC  ACCEL_ID: $accel_id  ITER: $ITER  sequence: $seq_features"
echo ""

ip link set dev "$NIC" down 2>/dev/null
knod_detach "$NIC" 2>/dev/null
knod_attach "$NIC" "$accel_id" >/dev/null || fail_stop "attach"
ip link set dev "$NIC" up || fail_stop "link up"
knod_traffic_start

for ((i = 1; i <= ITER; i++)); do
	set -- $seq_features
	shift $(( (i - 1) % nfeat ))
	feat=$1
	knod_dmesg_mark "switch $i -> $feat"

	knod_feature_select "$accel_id" "$feat" >/dev/null ||
		fail_stop "switch $i: select $feat"
	if [ "$feat" = bpf ] && [ -n "$XDP_OBJ" ]; then
		knod_xdp_load "$NIC" "$XDP_OBJ" >/dev/null 2>&1 ||
			fail_stop "switch $i: xdp load"
	fi
	sleep "$DWELL"
	if [ "$feat" = bpf ] && [ -n "$XDP_OBJ" ]; then
		knod_stress_verify_maps "$NIC" "${TRAFFIC_START:+1}" ||
			fail_stop "switch $i: map check"
		knod_xdp_unload "$NIC"
	fi

	knod_cycle_check "switch $i ($feat)" || fail_stop "switch $i"
	if (( i % KMEMLEAK_EVERY == 0 )); then
		leaks=$(knod_kmemleak_scan)
		(( leaks > KNOD_LEAK_BASE )) &&
			fail_stop "switch $i: kmemleak +$((leaks - KNOD_LEAK_BASE))"
	fi
	(( i % 10 == 0 )) && knod_log "switch $i ok"
done

knod_traffic_stop
knod_pass "$ITER feature switches"
PASS=$((PASS + 1))
knod_stress_epilogue
