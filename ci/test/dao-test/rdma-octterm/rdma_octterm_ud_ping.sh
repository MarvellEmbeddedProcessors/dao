#!/bin/bash
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2025 Marvell.

# RDMA Octeon Termination UD Functional Tests
# In octterm mode, kmod+firmware run on the same Octeon SoC (EP_DEVICE).
#
# Scenarios:
#   1. Octeon <-> Mellanox: EP_DEVICE (octterm) <-> EP_REMOTE_HOST (native RoCE)
#   2. Octeon <-> Octeon:   EP_DEVICE (octterm) <-> EP_REMOTE (octterm)
#
# Tests per scenario:
#   a. Local as Server -> Remote as Client
#   b. Remote as Server -> Local as Client

set -euo pipefail

SCRIPT_DIR="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
source "$SCRIPT_DIR/rdma_octterm_utils.sh"

function ud_pingpong_bidir()
{
	local label=$1
	local local_env=$2
	local local_rdma_dev=$3
	local local_gid=$4
	local local_ip=$5
	local remote_env=$6
	local remote_rdma_dev=$7
	local remote_gid=$8
	local remote_ip=$9
	local remote_ssh_fn=${10}

	# Direction 1: Local as server, remote as client
	echo "UD Octterm ($label): Local Server -> Remote Client"
	eval "${local_env}" 2>/dev/null || true
	setsid ibv_ud_pingpong -g $local_gid -d $local_rdma_dev -i 1 >/dev/null 2>&1 &
	sleep 1
	$remote_ssh_fn "bash -c \"${remote_env} ibv_ud_pingpong -g $remote_gid -d $remote_rdma_dev -i 1 $local_ip\""
	local status=$?
	if [[ $status -ne 0 ]]; then
		echo "UD Octterm ($label): Local-server direction FAILED"
		return 1
	fi

	# Direction 2: Remote as server, local as client
	echo "UD Octterm ($label): Remote Server -> Local Client"
	$remote_ssh_fn "bash -c \"${remote_env} setsid ibv_ud_pingpong -g $remote_gid -d $remote_rdma_dev -i 1 > /dev/null 2>&1 &\""
	sleep 1
	eval "${local_env}" 2>/dev/null || true
	ibv_ud_pingpong -g $local_gid -d $local_rdma_dev -i 1 $remote_ip
	status=$?
	if [[ $status -ne 0 ]]; then
		echo "UD Octterm ($label): Remote-server direction FAILED"
		return 1
	fi

	echo "UD Octterm ($label): PASSED (both directions)"
	return 0
}

function ud_ping_topo_run()
{
	ud_pingpong_bidir "$octterm_topo_label" \
		"$local_env" "$local_rdma_dev" "$local_gid" "$local_ip" \
		"$remote_env" "$remote_rdma_dev" "$remote_gid" "$remote_ip" \
		"$remote_ssh_fn"
}

function rdma_octterm_ud_ping()
{
	local octterm_topo_id octterm_topo_label
	local local_ip local_env local_rdma_dev local_gid
	local remote_ip remote_env remote_rdma_dev remote_gid remote_ssh_fn

	rdma_octterm_register_sig_handler

	if ! rdma_octterm_foreach_topo ud_ping_topo_run full; then
		echo "UD Octterm Functional Tests FAILED"
		exit 1
	fi

	echo "UD Octterm Functional Tests completed successfully"
	return 0
}
test_run rdma_octterm_ud_ping 2
