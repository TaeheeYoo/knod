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
	knod_ynl --do accel-set \
		--json "{\"id\":$accel_id,\"feature-ena\":\"$feat\"}" >/dev/null
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
