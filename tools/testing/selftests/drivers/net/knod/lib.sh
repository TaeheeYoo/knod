#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# lib.sh - KNOD XDP offload test utilities
#
# The KNOD control plane is the "knod" generic-netlink family; it is driven
# here through the in-tree ynl CLI (tools/net/ynl/pyynl/cli.py) so the tests
# need no dedicated user-space tool.

KSRC=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../../../.." && pwd)
readonly KNOD_YNL="$KSRC/tools/net/ynl/pyynl/cli.py"
readonly KNOD_SPEC="$KSRC/Documentation/netlink/specs/knod.yaml"

KNOD_NIC=""
KNOD_ACCEL_ID=""
KNOD_CLEANUP_DONE=0

knod_log()   { echo "  [INFO] $*"; }
knod_pass()  { echo "  [PASS] $*"; }
knod_fail()  { echo "  [FAIL] $*"; }
knod_skip()  { echo "  [SKIP] $*"; exit 4; }

# Invoke the knod generic-netlink family via the ynl CLI.
knod_ynl() {
	python3 "$KNOD_YNL" --spec "$KNOD_SPEC" "$@"
}

knod_ifindex() {
	cat "/sys/class/net/$1/ifindex" 2>/dev/null
}

knod_check_prereq() {
	if [ "$(id -u)" -ne 0 ]; then
		knod_skip "must be root"
	fi

	if ! command -v python3 >/dev/null 2>&1; then
		knod_skip "python3 not found (needed for the ynl CLI)"
	fi

	if ! command -v jq >/dev/null 2>&1; then
		knod_skip "jq not found"
	fi

	if ! knod_ynl --dump accel-get >/dev/null 2>&1; then
		knod_skip "knod genl family not available (module not loaded?)"
	fi

	if ! command -v bpftool >/dev/null 2>&1; then
		knod_skip "bpftool not found"
	fi

	if ! command -v ip >/dev/null 2>&1; then
		knod_skip "iproute2 (ip) not found"
	fi
}

# Auto-detect the id of the first amdgpu accelerator.
knod_find_accel() {
	if [ -n "$KNOD_ACCEL_ID" ]; then
		echo "$KNOD_ACCEL_ID"
		return 0
	fi

	knod_ynl --dump accel-get --output-json 2>/dev/null | \
		jq -r 'map(select(.name | startswith("amdgpu"))) | .[0].id // empty'
}

# Locate the knod debugfs directory (the DRI minor number varies).
knod_debug_dir() {
	local d

	for d in /sys/kernel/debug/dri/*/knod; do
		[ -d "$d" ] && { echo "$d"; return 0; }
	done
	return 1
}

# Activate a KNOD offload feature ("none", "bpf", "ipsec") on <accel_id>.
knod_feature_select() {
	local accel_id=$1
	local feat=$2

	knod_log "feature_select accel $accel_id -> $feat"
	if ! out=$(knod_ynl --do accel-set \
		--json "{\"id\":$accel_id,\"feature-ena\":\"$feat\"}" 2>&1); then
		echo "$out" | tail -5
		return 1
	fi
}

# Confirm the framework is still responsive (used after an expected failure to
# catch an oops/hang in the reject path). The accel inventory is persistent
# (independent of attach), so a successful dump means the family is alive.
knod_kernel_alive() {
	knod_ynl --dump accel-get >/dev/null 2>&1
}

# Is <nic> currently bound to an accel (present in the dev list)?
knod_xdev_has() {
	local nic=$1
	local ifindex

	ifindex=$(knod_ifindex "$nic") || return 1
	knod_ynl --dump dev-get --output-json 2>/dev/null | \
		jq -e --argjson i "$ifindex" \
		   'any(.[]; .["nic-ifindex"] == $i)' >/dev/null
}

knod_attach() {
	local nic=$1
	local accel_id=$2
	local ifindex

	ifindex=$(knod_ifindex "$nic") || return 1
	knod_log "attach $nic (ifindex $ifindex) to accel $accel_id"
	knod_ynl --do attach \
		--json "{\"nic-ifindex\":$ifindex,\"accel-id\":$accel_id}" >/dev/null
}

knod_detach() {
	local nic=$1
	local ifindex

	ifindex=$(knod_ifindex "$nic") || return 1
	knod_log "detach $nic"
	knod_ynl --do detach \
		--json "{\"nic-ifindex\":$ifindex}" >/dev/null 2>&1
}

knod_xdp_load() {
	local nic=$1
	local obj=$2

	knod_log "xdpoffload load $obj on $nic"
	ip link set dev "$nic" xdpoffload obj "$obj" sec xdp
}

knod_xdp_unload() {
	local nic=$1

	knod_log "xdpoffload off on $nic"
	ip link set dev "$nic" xdpoffload off 2>/dev/null
}

knod_cleanup() {
	local nic=$1

	[ "$KNOD_CLEANUP_DONE" -eq 1 ] && return
	KNOD_CLEANUP_DONE=1

	knod_log "cleanup $nic"
	knod_xdp_unload "$nic"
	ip link set dev "$nic" down 2>/dev/null
	knod_detach "$nic"
}

knod_get_map_id() {
	local prog_id=$1

	bpftool prog show id "$prog_id" 2>/dev/null | \
		grep -o 'map_ids [0-9]*' | awk '{print $2}'
}

knod_map_lookup_u64() {
	local map_id=$1
	local key=$2
	local hex

	hex=$(bpftool map lookup id "$map_id" \
	      key $key 0 0 0 2>/dev/null | \
	      grep -o 'value:.*' | sed 's/value: //')
	if [ -z "$hex" ]; then
		echo 0
		return
	fi

	printf '%d' "$(echo "$hex" | awk '{
		v = 0;
		for (i = 8; i >= 1; i--)
			v = v * 256 + strtonum("0x" $i);
		printf "0x%x", v;
	}')"
}

knod_get_map_ids() {
	local prog_id=$1

	bpftool prog show id "$prog_id" 2>/dev/null | \
		grep -o 'map_ids [0-9,]*' | awk '{print $2}' | tr ',' ' '
}

# A program with more than one map needs them told apart, and the order
# bpftool lists them in is not the order they are declared in.
knod_find_map_by_name() {
	local prog_id=$1
	local name=$2
	local id

	for id in $(knod_get_map_ids "$prog_id"); do
		if bpftool map show id "$id" 2>/dev/null | \
		   grep -qE "(^|[[:space:]])name ${name}([[:space:]]|$)"; then
			echo "$id"
			return
		fi
	done
}

knod_map_nr_elems() {
	local map_id=$1
	local n

	n=$(bpftool map dump id "$map_id" 2>/dev/null | \
	    awk '/^Found/ {print $2}')
	[ -n "$n" ] || n=0
	echo "$n"
}

# Every key the map holds, one per line, as a decimal u32.
knod_map_keys_u32() {
	local map_id=$1

	bpftool map dump id "$map_id" 2>/dev/null | \
		awk '/^key:/ {
			printf "%d\n", strtonum("0x" $5 $4 $3 $2)
		}'
}

knod_map_has_key_u32() {
	local map_id=$1
	local key=$2
	local b0=$((key & 255))
	local b1=$(((key >> 8) & 255))
	local b2=$(((key >> 16) & 255))
	local b3=$(((key >> 24) & 255))

	bpftool map lookup id "$map_id" key $b0 $b1 $b2 $b3 >/dev/null 2>&1
}

knod_map_update_u32_u64() {
	local map_id=$1
	local key=$2
	local b0=$((key & 255))
	local b1=$(((key >> 8) & 255))
	local b2=$(((key >> 16) & 255))
	local b3=$(((key >> 24) & 255))

	bpftool map update id "$map_id" key $b0 $b1 $b2 $b3 \
		value 1 0 0 0 0 0 0 0 >/dev/null 2>&1
}

# -- stress-test helpers ---------------------------------------
#
# Every stress script takes NIC=<ifname> (required) and ACCEL_ID (optional),
# runs a scenario ITER times, and after each cycle checks that the framework
# still answers and that the kernel logged no complaint since the cycle
# started.  Optional hooks run around the "traffic on" window:
#   TRAFFIC_START='...'  TRAFFIC_STOP='...'   (eval'd; e.g. ssh to the generator)

KNOD_DMESG_PATTERN='KASAN|KFENCE|UBSAN|BUG:|WARNING:|Oops|general protection'
KNOD_DMESG_PATTERN+='|use-after-free|refcount_t|hung task|RCU stall|INFO: task'
KNOD_DMESG_PATTERN+='|NULL pointer|kmemleak'
KNOD_DMESG_TAG=""
KNOD_LEAK_BASE=0
: "${KMEMLEAK_EVERY:=50}"

# Drop a marker into the log; knod_dmesg_check() looks only past it, so a
# wrapped ring buffer cannot make us miss or double-count anything.
knod_dmesg_mark() {
	KNOD_DMESG_TAG="knod-stress[$$] $1"
	echo "$KNOD_DMESG_TAG" > /dev/kmsg
}

knod_dmesg_since_mark() {
	dmesg | awk -v tag="$KNOD_DMESG_TAG" 'index($0, tag) { found = 1; next } found'
}

# 0 when the kernel said nothing alarming since the mark, else prints it.
knod_dmesg_check() {
	local bad

	bad=$(knod_dmesg_since_mark | grep -E "$KNOD_DMESG_PATTERN")
	[ -z "$bad" ] && return 0
	echo "$bad" | head -20
	return 1
}

# Number of kmemleak reports right now; 0 when kmemleak is not built in.
knod_kmemleak_scan() {
	[ -w /sys/kernel/debug/kmemleak ] || { echo 0; return 0; }
	echo scan > /sys/kernel/debug/kmemleak
	sleep 1
	grep -c "unreferenced object" /sys/kernel/debug/kmemleak
}

# Load an accel feature module unless it is already there; skip the test when
# it cannot be loaded (not built, wrong ABI blob, ...).
knod_require_module() {
	local mod=$1

	lsmod | grep -q "^$mod " && return 0
	modprobe "$mod" 2>/dev/null && return 0
	knod_skip "$mod not loaded and modprobe failed"
}

knod_traffic_start() {
	[ -n "$TRAFFIC_START" ] && eval "$TRAFFIC_START"
	return 0
}

knod_traffic_stop() {
	[ -n "$TRAFFIC_STOP" ] && eval "$TRAFFIC_STOP"
	return 0
}

# After one cycle: is the control plane alive, did the kernel complain?
# Prints and returns 1 on trouble so the caller can stop with the evidence.
knod_cycle_check() {
	local label=$1
	local rc=0

	if ! knod_kernel_alive; then
		knod_fail "$label: knod genl family not responding"
		rc=1
	fi
	if ! knod_dmesg_check; then
		knod_fail "$label: kernel complained (above)"
		rc=1
	fi
	return $rc
}

# Common start: prerequisites, NIC/accel resolution, leak baseline, log mark.
# Sets accel_id.
knod_stress_prologue() {
	knod_check_prereq
	[ -z "$NIC" ] && knod_skip "NIC env var not set"
	ip link show "$NIC" >/dev/null 2>&1 || knod_skip "NIC $NIC does not exist"
	accel_id=$(knod_find_accel)
	[ -z "$accel_id" ] && knod_skip "no KNOD accelerator found"
	[ -n "$ACCEL_ID" ] && accel_id="$ACCEL_ID"
	KNOD_LEAK_BASE=$(knod_kmemleak_scan)
	knod_dmesg_mark start
}

# Common end: final leak scan, summary; returns the exit code to use.
knod_stress_epilogue() {
	local leaks

	leaks=$(knod_kmemleak_scan)
	if [ "$leaks" -gt "$KNOD_LEAK_BASE" ]; then
		knod_fail "kmemleak: $((leaks - KNOD_LEAK_BASE)) new report(s)"
		FAIL=$((FAIL + 1))
		sed -n '1,40p' /sys/kernel/debug/kmemleak
	fi
	echo ""
	echo "=== Results: $PASS passed, $FAIL failed ==="
	[ "$FAIL" -gt 0 ] && return 1
	return 0
}

# -- xdp_stress.bpf.o bookkeeping ----------------------------------
#
# The stress program counts every packet into its `stats` array (total, tx,
# pass, drop, ...) and mirrors the total into a per-cpu array, so a run can be
# checked for lost or double-counted verdicts afterwards.

knod_xdp_prog_id() {
	ip -j link show dev "$1" 2>/dev/null | jq -r '.[0].xdp.prog.id // empty'
}

# u64 at <index> of a plain array map
knod_stress_stat() {
	knod_map_lookup_u64 "$1" "$2"
}

# Sum over cpus of the first u64 at <index> of a per-cpu array map.  bpftool
# prints one "value (CPU nn): b0 b1 .. b15" line per cpu; the number is the
# first eight bytes, little-endian.
knod_stress_pstat_sum() {
	local map_id=$1
	local idx=$2

	bpftool map lookup id "$map_id" key "$idx" 0 0 0 2>/dev/null | \
		awk '/^value \(CPU/ {
			v = 0;
			for (i = 11; i >= 4; i--)
				v = v * 256 + strtonum("0x" $i);
			sum += v;
		}
		END { printf "%d\n", sum }'
}

# knod_stress_verify_maps <nic> <expect_traffic:0|1>
# 0 when the counts add up (and, if expected, traffic was seen).  Traffic may
# still be flowing while the maps are read one bpftool call at a time, so the
# total is sampled before and after each group and the group has to land
# between the two samples; with traffic stopped every sample is the same.
knod_stress_verify_maps() {
	local nic=$1
	local expect=$2
	local prog sid pid t1 t2 t3 tx pass drop head_fail sum psum nflows

	prog=$(knod_xdp_prog_id "$nic")
	[ -z "$prog" ] && { knod_fail "no XDP program on $nic"; return 1; }
	sid=$(knod_find_map_by_name "$prog" stats)
	pid=$(knod_find_map_by_name "$prog" pstats)
	[ -z "$sid" ] || [ -z "$pid" ] && { knod_fail "stats maps not found"; return 1; }

	t1=$(knod_stress_stat "$sid" 0)
	tx=$(knod_stress_stat "$sid" 1)
	pass=$(knod_stress_stat "$sid" 2)
	drop=$(knod_stress_stat "$sid" 3)
	t2=$(knod_stress_stat "$sid" 0)
	psum=$(knod_stress_pstat_sum "$pid" 0)
	t3=$(knod_stress_stat "$sid" 0)
	head_fail=$(knod_stress_stat "$sid" 4)
	nflows=$(knod_map_nr_elems "$(knod_find_map_by_name "$prog" flows)")
	sum=$((tx + pass + drop))

	knod_log "stats: total=$t1..$t3 tx=$tx pass=$pass drop=$drop head_fail=$head_fail percpu_total=$psum flows=$nflows"
	if (( sum < t1 || sum > t2 )); then
		knod_fail "verdicts ($sum) outside the total sampled around them ($t1..$t2)"
		return 1
	fi
	if (( psum < t1 || psum > t3 )); then
		knod_fail "per-cpu total ($psum) outside the shared total sampled around it ($t1..$t3)"
		return 1
	fi
	if [ "$head_fail" != 0 ]; then
		knod_fail "adjust_head failed $head_fail times"
		return 1
	fi
	if [ "$expect" = 1 ] && [ "$t1" = 0 ]; then
		knod_fail "no packets counted while traffic was expected"
		return 1
	fi
	return 0
}
