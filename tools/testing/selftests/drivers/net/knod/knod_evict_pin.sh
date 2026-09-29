#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# knod_evict_pin.sh - VRAM eviction while the NIC runs on accel memory.
#
# The NIC's RX buffers, rings and XDP SQ live in accel VRAM, mapped through
# dma-buf attachments that are pinned so the exporter cannot move them under
# the NIC.  With the interface attached, up and carrying traffic, every
# round asks amdgpu to evict all of its VRAM (amdgpu_evict_vram debugfs).
# Whatever is not pinned moves; the NIC's buffers must not, and only traffic
# shows it - a moved buffer breaks when the NIC next DMAs to it.  A round
# fails on a kernel complaint, a CQ error, a GPU page fault, the knod "moved
# under a pinned mapping" warning, or receive counters that stop moving.
#
# Environment:
#   NIC=<ifname>      (required)
#   ACCEL_ID=<id>     (optional, auto-detected)
#   ITER=50           eviction rounds
#   EVICT_GTT=0       1: evict GTT as well each round
#   DWELL=1           seconds between rounds
#   XDP_OBJ=<path>    XDP object to run under, e.g. xdp_stress.bpf.o, and
#                     check its counts at the end; default none: the
#                     receive kernel alone runs the NIC's rings
#   EXPECT_TRAFFIC=   1: fail if rx_packets stops moving; defaults to 1
#                     when TRAFFIC_START is set, else 0
#   DRI=<dir>         amdgpu's debugfs dir, if the guess is wrong
#   TRAFFIC_START / TRAFFIC_STOP
#
# Exit: 0=pass, 1=fail, 4=skip

set -o pipefail

SELFDIR=$(dirname "$(readlink -f "$0")")
source "$SELFDIR/lib.sh"

: "${NIC:=}"
: "${ACCEL_ID:=}"
: "${ITER:=50}"
: "${EVICT_GTT:=0}"
: "${DWELL:=1}"
: "${XDP_OBJ=}"
[ -n "$TRAFFIC_START" ] && : "${EXPECT_TRAFFIC:=1}"
: "${EXPECT_TRAFFIC:=0}"

KNOD_DMESG_PATTERN+='|CQ error|page fault|moved under a pinned mapping'

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

gda_stat() {   # gda_stat <name>: a counter from the knod gda debugfs file
	awk -v k="$1:" '$1 == k { print $2 }' "$gda" 2>/dev/null
}

# Wait up to <secs> for <cmd...> to succeed.
wait_for() {
	local secs=$1 t

	shift
	for ((t = 0; t < secs * 10; t++)); do
		"$@" && return 0
		sleep 0.1
	done
	return 1
}

# The program's own total, as the host reads it through the map.
prog_total() {
	local prog sid

	prog=$(knod_xdp_prog_id "$NIC")
	[ -n "$prog" ] || return 1
	sid=$(knod_find_map_by_name "$prog" stats)
	[ -n "$sid" ] || return 1
	knod_stress_stat "$sid" 0
}

prog_moving() {
	local a b

	a=$(prog_total) || return 1
	sleep 0.5
	b=$(prog_total) || return 1
	[ "$b" -gt "$a" ]
}

carrier_up() {
	[ "$(cat "/sys/class/net/$NIC/carrier" 2>/dev/null)" = 1 ]
}

rx_moving() {
	local a b

	a=$(gda_stat rx_packets)
	sleep 0.2
	b=$(gda_stat rx_packets)
	[ -n "$b" ] && [ "$b" != "${a:-0}" ]
}

knod_stress_prologue
knod_require_module knod_bpf

# amdgpu's evict files: next to knod's debugfs if they are there, else under
# the primary node of the device the render node <$1> names.
amdgpu_dri() {
	local want d

	d=$(dirname "$1")
	[ -r "$d/amdgpu_evict_vram" ] && { echo "$d"; return 0; }
	want=$(awk '{ print $2 }' "$(dirname "$1")/name" 2>/dev/null)
	for d in /sys/kernel/debug/dri/*; do
		[ -r "$d/amdgpu_evict_vram" ] || continue
		if [ -z "$want" ] || [ "$(awk '{ print $2 }' "$d/name")" = "$want" ]; then
			echo "$d"
			return 0
		fi
	done
	return 1
}

echo "=== KNOD VRAM eviction under a pinned NIC mapping ==="
echo "    NIC: $NIC  ACCEL_ID: $accel_id  ITER: $ITER  EVICT_GTT: $EVICT_GTT"
echo "    XDP_OBJ: ${XDP_OBJ:-none}  EXPECT_TRAFFIC: $EXPECT_TRAFFIC"
echo ""

ip link set dev "$NIC" down 2>/dev/null
knod_detach "$NIC" 2>/dev/null
knod_attach "$NIC" "$accel_id" >/dev/null || fail_stop "attach"
knod_feature_select "$accel_id" bpf >/dev/null || fail_stop "select bpf"
ip link set dev "$NIC" up || fail_stop "link up"
if [ -n "$XDP_OBJ" ]; then
	knod_xdp_load "$NIC" "$XDP_OBJ" >/dev/null 2>&1 || fail_stop "xdp load"
fi

# The knod debugfs directory comes with the accel's context, at attach.
debug=$(knod_debug_dir) || fail_stop "knod debugfs not found after attach"
gda="$debug/gda"
[ -r "$gda" ] || fail_stop "$gda not found"
: "${DRI:=$(amdgpu_dri "$debug")}"
[ -r "$DRI/amdgpu_evict_vram" ] || fail_stop "amdgpu_evict_vram not found (set DRI=)"
dri=$DRI
knod_log "knod: $debug  amdgpu: $dri"
wait_for 30 carrier_up || fail_stop "no carrier on $NIC"
knod_traffic_start
if [ "$EXPECT_TRAFFIC" = 1 ]; then
	wait_for 30 rx_moving || fail_stop "no packets received before the first round"
	if [ -n "$XDP_OBJ" ]; then
		wait_for 30 prog_moving ||
			fail_stop "program counters not moving as the host reads them (total $(prog_total))"
	fi
fi

for ((i = 1; i <= ITER; i++)); do
	knod_dmesg_mark "round $i"
	rx=$(gda_stat rx_packets)

	evicted=$(cat "$dri/amdgpu_evict_vram") || fail_stop "round $i: evict vram"
	[ "$EVICT_GTT" = 1 ] &&
		{ cat "$dri/amdgpu_evict_gtt" >/dev/null || fail_stop "round $i: evict gtt"; }
	sleep "$DWELL"

	knod_cycle_check "round $i" || fail_stop "round $i"
	rx2=$(gda_stat rx_packets)
	if [ "$EXPECT_TRAFFIC" = 1 ] && [ "${rx2:-0}" = "${rx:-0}" ]; then
		fail_stop "round $i: rx_packets stuck at ${rx:-?} after eviction"
	fi
	(( i % 10 == 0 )) &&
		knod_log "round $i ok (evict ret $evicted, rx_packets $rx2)"
done

knod_traffic_stop
if [ -n "$XDP_OBJ" ]; then
	knod_stress_verify_maps "$NIC" "$EXPECT_TRAFFIC" || fail_stop "maps"
fi

knod_pass "$ITER eviction rounds"
PASS=$((PASS + 1))
knod_stress_epilogue
