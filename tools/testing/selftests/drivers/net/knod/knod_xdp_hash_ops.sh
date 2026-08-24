#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# knod_xdp_hash_ops.sh - hash map insert, overwrite and delete on GPU XDP
#
# The offloaded hash writers take a per-bucket lock and then serialise the
# lanes that share a bucket, which is the only part of the map offload that
# can be wrong intermittently rather than always.  This drives the two shapes
# that tell them apart:
#
#   contention  every packet the same length, so every lane keys the same
#               bucket and the lock is what decides the outcome
#   chains      a sweep of lengths, so buckets hold chains and insert has to
#               find its way down them
#
# What is checked is what a broken lock breaks: a key that was inserted and
# is not there, or a key that is there twice.  Counting values would not do
# - a BPF read-modify-write over a looked-up pointer races between lanes by
# construction, lock or no lock.
#
# Requires:
#   - KNOD (knod + amdgpu) modules loaded
#   - AMD GPU with KNOD support
#   - NIC with xdpoffload support (mlx5, bnxt)
#   - bpftool, iproute2, ping
#   - root privileges
#   - xdp_hash_ops.bpf.o (built by make)
#
# Environment:
#   NIC=<ifname>       (required) NIC to test on
#   REMOTE_IP=<ip>     (required) ping target; the key is the packet length,
#                      so the test has to be the one generating traffic
#   ACCEL_ID=<id>      (optional) GPU accel ID, auto-detected if omitted
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
BPF_OBJ="$SELFDIR/xdp_hash_ops.bpf.o"

# Lengths to sweep for the chain phase, as ping payload sizes.
SWEEP_FIRST=64
SWEEP_COUNT=32
SWEEP_STEP=4
# Payload size used for the contention phase.
HOT_SIZE=100
HOT_PINGS=200

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

ping_size() {
	local size=$1
	local count=$2

	ping -c "$count" -i 0.01 -W 1 -s "$size" "$REMOTE_IP" >/dev/null 2>&1
	return 0
}

# -- prereq ------------------------------------------------------
knod_check_prereq

if [ -z "$NIC" ]; then
	knod_skip "NIC env var not set"
fi

if [ -z "$REMOTE_IP" ]; then
	knod_skip "REMOTE_IP env var not set (this test generates its own traffic)"
fi

if ! ip link show "$NIC" >/dev/null 2>&1; then
	knod_skip "NIC $NIC does not exist"
fi

accel_id=$(knod_find_accel)
if [ -z "$accel_id" ]; then
	knod_skip "no KNOD accelerator found"
fi
[ -n "$ACCEL_ID" ] && accel_id="$ACCEL_ID"

echo "=== KNOD XDP hash map insert/overwrite/delete test ==="
echo "    NIC:       $NIC"
echo "    REMOTE_IP: $REMOTE_IP"
echo "    ACCEL_ID:  $accel_id"
echo ""

if [ ! -f "$BPF_OBJ" ]; then
	echo "FAIL: $BPF_OBJ not found (run make first)"
	exit 1
fi

# -- attach, select feature, load ------------------------------
ip link set dev "$NIC" down 2>/dev/null
knod_attach "$NIC" "$accel_id" || { echo "FAIL: attach failed"; exit 1; }
knod_feature_select "$accel_id" bpf || knod_skip "cannot select bpf feature"
knod_xdp_load "$NIC" "$BPF_OBJ" || { echo "FAIL: xdpoffload load failed"; exit 1; }

prog_id=$(bpftool prog show 2>/dev/null | \
	  awk '/xdp_hash_ops/ {sub(/:/, "", $1); print $1; exit}')
if [ -z "$prog_id" ]; then
	echo "FAIL: cannot find loaded BPF program"
	exit 1
fi

len_map=$(knod_find_map_by_name "$prog_id" len_map)
del_map=$(knod_find_map_by_name "$prog_id" del_map)
stats_map=$(knod_find_map_by_name "$prog_id" stats)
if [ -z "$len_map" ] || [ -z "$del_map" ] || [ -z "$stats_map" ]; then
	echo "FAIL: cannot find maps (len=$len_map del=$del_map stats=$stats_map)"
	exit 1
fi
knod_log "prog_id=$prog_id len_map=$len_map del_map=$del_map stats=$stats_map"

ip link set dev "$NIC" up
sleep 1

# -- phase 0: learn what length the GPU sees -------------------
#
# A ping payload of N bytes does not arrive as N: headers, and whatever the
# NIC does with the frame, sit between.  Rather than assume the offset, send
# one size and read back the key it produced.
ping_size "$HOT_SIZE" 20
sleep 1

hot_keys=$(knod_map_keys_u32 "$len_map")
hot_key=$(echo "$hot_keys" | head -1)
nr=$(echo "$hot_keys" | grep -c .)

if [ -z "$hot_key" ] || [ "$hot_key" = "0" ]; then
	echo "FAIL: no key appeared after traffic; is the program running?"
	exit 1
fi
hdr=$((hot_key - HOT_SIZE))
knod_log "payload $HOT_SIZE arrived as length $hot_key (header $hdr bytes)"

# One length in, one key out.  More than one means the sender is not the
# only source of traffic, and the phases below cannot be trusted.
rc=0
[ "$nr" -eq 1 ] || rc=1
check_result "one length gives one key ($nr present)" $rc
if [ "$rc" -ne 0 ]; then
	knod_log "other traffic is reaching the NIC; run this on a quiet link"
	echo ""
	echo "=== Results: $PASS passed, $FAIL failed ==="
	exit 1
fi

# -- phase 1: contention ---------------------------------------
#
# Every packet the same length, so every lane of every wave hashes to one
# bucket and takes the same lock.  The element is already there after phase
# 0, so this is the overwrite path under maximum contention.
knod_log "contention: $HOT_PINGS packets at one length"
ping_size "$HOT_SIZE" "$HOT_PINGS"
sleep 1

nr=$(knod_map_nr_elems "$len_map")
rc=0
[ "$nr" -eq 1 ] || rc=1
check_result "overwrite under contention leaves one element ($nr)" $rc

# -- phase 2: chains -------------------------------------------
#
# A sweep of lengths, each seen many times, so inserts and overwrites run
# together and buckets grow chains.
knod_log "chains: $SWEEP_COUNT lengths, 20 packets each"
expect_keys=""
i=0
while [ "$i" -lt "$SWEEP_COUNT" ]; do
	size=$((SWEEP_FIRST + i * SWEEP_STEP))
	ping_size "$size" 20
	expect_keys="$expect_keys $((size + hdr))"
	i=$((i + 1))
done
sleep 2

missing=0
for k in $expect_keys; do
	if ! knod_map_has_key_u32 "$len_map" "$k"; then
		knod_log "key $k was inserted and is not there"
		missing=$((missing + 1))
	fi
done
rc=0
[ "$missing" -eq 0 ] || rc=1
check_result "every inserted key is present ($missing missing)" $rc

# A duplicate is the other way a broken lock shows: two lanes both decide the
# key is absent and both link an element for it.
dups=$(knod_map_keys_u32 "$len_map" | sort | uniq -d | grep -c . )
rc=0
[ "$dups" -eq 0 ] || rc=1
check_result "no key appears twice ($dups duplicated)" $rc

# The hot key from phase 1 plus the sweep, and nothing else.
nr=$(knod_map_nr_elems "$len_map")
want=$((SWEEP_COUNT + 1))
rc=0
[ "$nr" -eq "$want" ] || rc=1
check_result "element count matches keys sent ($nr, want $want)" $rc

# -- phase 3: delete -------------------------------------------
#
# The host puts the keys in del_map; the program finds them there, writes
# them once more and deletes them.  Anything left afterwards was not deleted.
knod_log "delete: marking $SWEEP_COUNT keys"
for k in $expect_keys; do
	knod_map_update_u32_u64 "$del_map" "$k"
done

marked=$(knod_map_nr_elems "$del_map")
rc=0
[ "$marked" -eq "$SWEEP_COUNT" ] || rc=1
check_result "host populated del_map ($marked, want $SWEEP_COUNT)" $rc

i=0
while [ "$i" -lt "$SWEEP_COUNT" ]; do
	ping_size $((SWEEP_FIRST + i * SWEEP_STEP)) 10
	i=$((i + 1))
done
sleep 2

left=$(knod_map_nr_elems "$del_map")
rc=0
[ "$left" -eq 0 ] || rc=1
check_result "every marked key was deleted ($left left)" $rc

# -- phase 4: the map still works ------------------------------
#
# Deleted elements go to a GC list and the host hands them back on a tick.
# If that did not happen the map is out of elements and this insert fails,
# which is the difference between a delete that unlinked and one that leaked.
knod_log "reuse: inserting after the deletes"
for k in $expect_keys; do
	knod_map_update_u32_u64 "$del_map" "$k"
done
sleep 1
reused=$(knod_map_nr_elems "$del_map")
rc=0
[ "$reused" -eq "$SWEEP_COUNT" ] || rc=1
check_result "deleted elements came back ($reused, want $SWEEP_COUNT)" $rc

# -- packets did flow ------------------------------------------
pkts=$(knod_map_lookup_u64 "$stats_map" 0)
knod_log "packets seen by the program: $pkts"
rc=0
[ "$pkts" -gt 0 ] || rc=1
check_result "packets processed ($pkts)" $rc

ip link set dev "$NIC" down

# -- summary ---------------------------------------------------
echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="

if [ "$FAIL" -gt 0 ]; then
	exit 1
fi
exit 0
