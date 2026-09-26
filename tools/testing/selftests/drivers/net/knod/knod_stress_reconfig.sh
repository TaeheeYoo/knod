#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# knod_stress_reconfig.sh - NIC reconfiguration while attached and up.
#
# The interface stays attached with FEATURE selected and traffic flowing (if
# hooked) while ethtool/ip reconfigure it underneath: channel count, ring
# size, MTU, XDP load/unload.  These rebuild the NIC queues
# without going through ndo_stop, which is where the worker has raced freed
# NAPI state before.  A rejected reconfiguration is logged, not failed: only
# a silent kernel or a kernel complaint fails the run.
#
# Environment:
#   NIC=<ifname>      (required)
#   ACCEL_ID=<id>     (optional)
#   ITER=100          rounds; each round runs every op once
#   FEATURE=bpf
#   CHANNELS="8 4"    two combined counts to alternate ("" = skip)
#   RINGS="1024 512"  two rx ring sizes to alternate ("" = skip)
#   MTUS="1500 1280"  two MTUs to alternate ("" = skip)
#   XDP_OBJ=<path>    load/unload each round (bpf only)
#   OP_DWELL=0.5      seconds between ops
#   TRAFFIC_START / TRAFFIC_STOP
#
# Exit: 0=pass, 1=fail, 4=skip

set -o pipefail

SELFDIR=$(dirname "$(readlink -f "$0")")
source "$SELFDIR/lib.sh"

: "${NIC:=}"
: "${ACCEL_ID:=}"
: "${ITER:=100}"
: "${FEATURE:=bpf}"
: "${CHANNELS:=8 4}"
: "${RINGS:=1024 512}"
: "${MTUS:=1500 1280}"
: "${XDP_OBJ=$SELFDIR/xdp_stress.bpf.o}"
: "${OP_DWELL:=0.5}"

PASS=0
FAIL=0
REJECTED=0

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

# Run one reconfiguration; a refusal is fine, a kernel complaint is not.
op() {
	local label=$1
	shift

	if ! "$@" >/dev/null 2>&1; then
		REJECTED=$((REJECTED + 1))
		knod_log "$label: rejected"
	fi
	sleep "$OP_DWELL"
	knod_cycle_check "$label" || fail_stop "$label"
}

pick() {   # pick <round> <a> <b>: alternate between two values
	if (( $1 % 2 )); then echo "$2"; else echo "$3"; fi
}

knod_stress_prologue
case "$FEATURE" in
bpf)   knod_require_module knod_bpf ;;
ipsec) knod_require_module knod_ipsec ;;
esac

echo "=== KNOD reconfigure-while-attached stress ==="
echo "    NIC: $NIC  ACCEL_ID: $accel_id  ITER: $ITER  FEATURE: $FEATURE"
echo "    CHANNELS: ${CHANNELS:-skip}  RINGS: ${RINGS:-skip}  MTUS: ${MTUS:-skip}"
echo "    XDP_OBJ: ${XDP_OBJ:-none}"
echo ""

orig_mtu=$(cat "/sys/class/net/$NIC/mtu")
ip link set dev "$NIC" down 2>/dev/null
knod_detach "$NIC" 2>/dev/null
knod_attach "$NIC" "$accel_id" >/dev/null || fail_stop "attach"
if [ "$FEATURE" != none ]; then
	knod_feature_select "$accel_id" "$FEATURE" >/dev/null || fail_stop "select $FEATURE"
fi
ip link set dev "$NIC" up || fail_stop "link up"
knod_traffic_start

set -- $CHANNELS; ch_a=$1; ch_b=$2
set -- $RINGS;    rg_a=$1; rg_b=$2
set -- $MTUS;     mt_a=$1; mt_b=$2

for ((i = 1; i <= ITER; i++)); do
	knod_dmesg_mark "round $i"

	[ -n "$ch_a" ] && op "round $i: channels" \
		ethtool -L "$NIC" combined "$(pick $i "$ch_a" "$ch_b")"
	[ -n "$rg_a" ] && op "round $i: ring" \
		ethtool -G "$NIC" rx "$(pick $i "$rg_a" "$rg_b")"
	[ -n "$mt_a" ] && op "round $i: mtu" \
		ip link set dev "$NIC" mtu "$(pick $i "$mt_a" "$mt_b")"
	if [ -n "$XDP_OBJ" ] && [ "$FEATURE" = bpf ]; then
		op "round $i: xdp load"   knod_xdp_load "$NIC" "$XDP_OBJ"
		op "round $i: xdp unload" knod_xdp_unload "$NIC"
	fi

	if (( i % KMEMLEAK_EVERY == 0 )); then
		leaks=$(knod_kmemleak_scan)
		(( leaks > KNOD_LEAK_BASE )) &&
			fail_stop "round $i: kmemleak +$((leaks - KNOD_LEAK_BASE))"
	fi
	(( i % 10 == 0 )) && knod_log "round $i ok ($REJECTED rejected so far)"
done

knod_traffic_stop
ip link set dev "$NIC" mtu "$orig_mtu" 2>/dev/null

knod_pass "$ITER reconfiguration rounds ($REJECTED ops rejected)"
PASS=$((PASS + 1))
knod_stress_epilogue
