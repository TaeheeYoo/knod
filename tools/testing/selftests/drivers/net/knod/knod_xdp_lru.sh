#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# knod_xdp_lru.sh - an LRU hash evicts, and evicts what was not used
#
# The program inserts each packet length it has not seen into a 64-entry
# LRU_HASH.  A plain hash would refuse the 65th; an LRU one gives up elements
# not used lately.  So:
#
#   fill    64 lengths, once each: the map is full, nothing refused
#   touch   the first 32 again: a lookup marks them used
#   evict   32 new lengths: nothing refused, the new ones are in and the
#           ones touched are still there
#
# Which of the untouched go, and whether the map is still full after, is not
# checked: the kernel's LRU evicts in batches that depend on how many cpus it
# has, and promises no more than this.
#
# Requires:
#   - KNOD (knod + amdgpu) modules loaded
#   - AMD GPU with KNOD support
#   - NIC with xdpoffload support (mlx5)
#   - bpftool, iproute2, ping
#   - root privileges
#   - xdp_lru.bpf.o (built by make)
#
# Environment:
#   NIC=<ifname>       (required) NIC to test on
#   REMOTE_IP=<ip>     (required) ping target; the key is the packet length,
#                      so the test has to be the one generating traffic, on
#                      a link nothing else sends on
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
BPF_OBJ="$SELFDIR/xdp_lru.bpf.o"

# lru_map's size in xdp_lru.bpf.c.
ENTRIES=64
TOUCHED=$((ENTRIES / 2))
FIRST=64
STEP=4
PROBE_SIZE=40

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
	ping -c "$2" -i 0.05 -W 1 -s "$1" "$REMOTE_IP" >/dev/null 2>&1
	return 0
}

# Length i of the sweep, as the program sees it.
key_of() {
	echo $((FIRST + $1 * STEP + hdr))
}

# How many of keys first..last of the sweep the map holds.
count_present() {
	local first=$1 last=$2 n=0 i

	for ((i = first; i <= last; i++)); do
		knod_map_has_key_u32 "$lru_map" "$(key_of "$i")" && n=$((n + 1))
	done
	echo "$n"
}

# -- prereq ------------------------------------------------------
knod_check_prereq

[ -n "$NIC" ] || knod_skip "NIC env var not set"
[ -n "$REMOTE_IP" ] || \
	knod_skip "REMOTE_IP env var not set (this test generates its own traffic)"
ip link show "$NIC" >/dev/null 2>&1 || knod_skip "NIC $NIC does not exist"

accel_id=$(knod_find_accel)
[ -n "$accel_id" ] || knod_skip "no KNOD accelerator found"
[ -n "$ACCEL_ID" ] && accel_id="$ACCEL_ID"

echo "=== KNOD XDP LRU hash eviction test ==="
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
	  awk '/xdp_lru/ {sub(/:/, "", $1); print $1; exit}')
[ -n "$prog_id" ] || { echo "FAIL: cannot find loaded BPF program"; exit 1; }

lru_map=$(knod_find_map_by_name "$prog_id" lru_map)
stats_map=$(knod_find_map_by_name "$prog_id" stats)
if [ -z "$lru_map" ] || [ -z "$stats_map" ]; then
	echo "FAIL: cannot find maps (lru=$lru_map stats=$stats_map)"
	exit 1
fi
knod_log "prog_id=$prog_id lru_map=$lru_map stats=$stats_map"

ip link set dev "$NIC" up
sleep 1

# -- learn what length the GPU sees ----------------------------
#
# A payload below the sweep, so its key is none of the sweep's; it is taken
# back out so the map starts empty.
ping_size "$PROBE_SIZE" 5
sleep 1
probe=$(knod_map_keys_u32 "$lru_map" | head -1)
nr=$(knod_map_nr_elems "$lru_map")
if [ -z "$probe" ] || [ "$nr" -ne 1 ]; then
	echo "FAIL: want one key after the probe, have $nr; is the link quiet?"
	exit 1
fi
hdr=$((probe - PROBE_SIZE))
knod_log "payload $PROBE_SIZE arrived as length $probe (header $hdr bytes)"
bpftool map delete id "$lru_map" key $((probe & 255)) $((probe >> 8 & 255)) 0 0

# -- fill ------------------------------------------------------
for ((i = 0; i < ENTRIES; i++)); do
	ping_size $((FIRST + i * STEP)) 1
done
sleep 1

nr=$(knod_map_nr_elems "$lru_map")
rc=0
[ "$nr" -eq "$ENTRIES" ] || rc=1
check_result "fill: the map is full ($nr, want $ENTRIES)" $rc

# -- touch -----------------------------------------------------
for ((i = 0; i < TOUCHED; i++)); do
	ping_size $((FIRST + i * STEP)) 2
done
sleep 1

# -- evict -----------------------------------------------------
for ((i = ENTRIES; i < ENTRIES + TOUCHED; i++)); do
	ping_size $((FIRST + i * STEP)) 1
done
sleep 1

refused=$(knod_map_lookup_u64 "$stats_map" 1)
rc=0
[ "$refused" -eq 0 ] || rc=1
check_result "no insert refused ($refused)" $rc

nr=$(knod_map_nr_elems "$lru_map")
rc=0
[ "$nr" -le "$ENTRIES" ] || rc=1
check_result "no more than it holds ($nr, at most $ENTRIES)" $rc

n=$(count_present $ENTRIES $((ENTRIES + TOUCHED - 1)))
rc=0
[ "$n" -eq "$TOUCHED" ] || rc=1
check_result "every new length is in ($n of $TOUCHED)" $rc

n=$(count_present 0 $((TOUCHED - 1)))
rc=0
[ "$n" -eq "$TOUCHED" ] || rc=1
check_result "every touched length survived ($n of $TOUCHED)" $rc

pkts=$(knod_map_lookup_u64 "$stats_map" 0)
knod_log "packets seen by the program: $pkts"

ip link set dev "$NIC" down

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
