#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# knod_xdp_divmod.sh - division the JIT hands to the blob.
#
# xdp_divmod.bpf.o divides with operands out of the packet, so the verifier
# knows neither: unsigned and signed, 32 and 64 bits, by zero and by -1, and
# negates a 64-bit value.  Every result is checked against what a quotient
# and a remainder have to satisfy; a packet whose every check holds is
# dropped and any other passed up.  The program has to load and - with
# traffic - every packet has to be dropped, with nothing passed and no kernel
# complaint.
#
# Environment:
#   NIC=<ifname>      (required)
#   ACCEL_ID=<id>     (optional, auto-detected)
#   DWELL=5           seconds of traffic to judge
#   EXPECT_TRAFFIC=   1: fail without received packets; defaults to 1 when
#                     TRAFFIC_START is set, else 0
#   TRAFFIC_START / TRAFFIC_STOP
#
# Exit: 0=pass, 1=fail, 4=skip

set -o pipefail

SELFDIR=$(dirname "$(readlink -f "$0")")
source "$SELFDIR/lib.sh"

: "${NIC:=}"
: "${ACCEL_ID:=}"
: "${DWELL:=5}"
[ -n "$TRAFFIC_START" ] && : "${EXPECT_TRAFFIC:=1}"
: "${EXPECT_TRAFFIC:=0}"
XDP_OBJ="$SELFDIR/xdp_divmod.bpf.o"

KNOD_DMESG_PATTERN+='|CQ error|page fault'

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

stat_of() {	# stat_of <file> <name>
	awk -v k="$2:" '$1 == k { print $2 }' "$1" 2>/dev/null
}

knod_stress_prologue
knod_require_module knod_bpf
[ -r "$XDP_OBJ" ] || knod_skip "$XDP_OBJ not built"

echo "=== KNOD BPF division by the blob ==="
echo "    NIC: $NIC  ACCEL_ID: $accel_id  DWELL: $DWELL  EXPECT_TRAFFIC: $EXPECT_TRAFFIC"
echo ""

ip link set dev "$NIC" down 2>/dev/null
knod_detach "$NIC" 2>/dev/null
knod_attach "$NIC" "$accel_id" >/dev/null || fail_stop "attach"
knod_feature_select "$accel_id" bpf >/dev/null || fail_stop "select bpf"
ip link set dev "$NIC" up || fail_stop "link up"
knod_xdp_load "$NIC" "$XDP_OBJ" >/dev/null 2>&1 ||
	fail_stop "xdp_divmod refused"

debug=$(knod_debug_dir) || fail_stop "knod debugfs not found"
gda="$debug/gda"
knod_cycle_check "load" || fail_stop "load"

for ((t = 0; t < 300; t++)); do
	[ "$(cat "/sys/class/net/$NIC/carrier" 2>/dev/null)" = 1 ] && break
	sleep 0.1
done

knod_dmesg_mark traffic
knod_traffic_start
sleep 1
rx0=$(stat_of "$gda" rx_packets)
pass0=$(stat_of "$gda" pass_packets)
sleep "$DWELL"
rx1=$(stat_of "$gda" rx_packets)
pass1=$(stat_of "$gda" pass_packets)
knod_traffic_stop

rx=$(( ${rx1:-0} - ${rx0:-0} ))
passed=$(( ${pass1:-0} - ${pass0:-0} ))
knod_log "in $DWELL s: $rx received, $passed passed up"
knod_cycle_check "traffic" || fail_stop "traffic"
[ "$passed" -eq 0 ] ||
	fail_stop "$passed packets passed up: a quotient or remainder was wrong"
if [ "$EXPECT_TRAFFIC" = 1 ] && [ "$rx" -le 0 ]; then
	fail_stop "no packets received"
fi

knod_pass "every division came out right"
PASS=$((PASS + 1))
knod_stress_epilogue
