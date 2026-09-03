#!/bin/bash
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2025 Marvell.

# RDMA Octeon Termination Connection Management Tests
# In octterm mode, kmod+firmware run on the same Octeon SoC (EP_DEVICE).
#
# Scenarios:
#   1. Octeon <-> Mellanox: EP_DEVICE (octterm) <-> EP_REMOTE_HOST (native RoCE)
#   2. Octeon <-> Octeon:   EP_DEVICE (octterm) <-> EP_REMOTE (octterm)
#
# Tests per scenario (using udaddy):
#   a. Local as Server -> Remote as Client
#   b. Remote as Server -> Local as Client

set -euo pipefail

SCRIPT_DIR="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
source "$SCRIPT_DIR/rdma_octterm_utils.sh"

function cm_bidir()
{
	local label=$1
	local local_env=$2
	local local_ip=$3
	local remote_env=$4
	local remote_ip=$5
	local remote_ssh_fn=$6
	local status

	# Direction 1: Local as server, remote as client
	echo "RDMA CM Octterm ($label): Local Server -> Remote Client"
	eval "${local_env}" 2>/dev/null || true
	setsid udaddy >/dev/null 2>&1 &
	sleep 1
	$remote_ssh_fn "bash -c \"${remote_env} udaddy -b $remote_ip -s $local_ip\""
	status=$?
	if [[ $status -ne 0 ]]; then
		echo "RDMA CM Octterm ($label): Local-server direction FAILED"
		return 1
	fi

	# Direction 2: Remote as server, local as client
	echo "RDMA CM Octterm ($label): Remote Server -> Local Client"
	$remote_ssh_fn "bash -c \"${remote_env} setsid udaddy >/dev/null 2>&1 &\""
	sleep 1
	eval "${local_env}" 2>/dev/null || true
	udaddy -b $local_ip -s $remote_ip
	status=$?
	if [[ $status -ne 0 ]]; then
		echo "RDMA CM Octterm ($label): Remote-server direction FAILED"
		return 1
	fi

	echo "RDMA CM Octterm ($label): PASSED (both directions)"
	return 0
}

function cm_topo_run()
{
	cm_bidir "$octterm_topo_label" \
		"$local_env" "$local_ip" \
		"$remote_env" "$remote_ip" \
		"$remote_ssh_fn"
}

function rdma_octterm_cm_test()
{
	local octterm_topo_id octterm_topo_label
	local local_ip local_env remote_ip remote_env remote_ssh_fn

	rdma_octterm_register_sig_handler

	if ! rdma_octterm_foreach_topo cm_topo_run start; then
		echo "RDMA CM Octterm Tests FAILED"
		exit 1
	fi

	echo "RDMA CM Octterm Tests completed successfully"
	return 0
}
test_run rdma_octterm_cm_test 2
