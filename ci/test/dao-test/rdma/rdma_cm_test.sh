#!/bin/bash
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2025 Marvell.

# RDMA Connection Management Tests
# Runs udaddy (rdma_cm) in both directions over both octep RDMA data paths:
#   1. Octeon<->Octeon  : EP_HOST octep VF <-> EP_REMOTE_HOST octep VF (30.0.0.x)
#   2. Octeon<->Mellanox: EP_HOST octep VF <-> EP_REMOTE_HOST Mellanox (21.0.0.x)
# NOTE: octep<->octep rdma_cm may not establish (octep picks a RoCE v1 GID it
# cannot use as a CM client); the Octeon<->Mellanox path has a real RoCE v2 peer.

set -euo pipefail

SCRIPT_DIR="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
source "$SCRIPT_DIR/rdma_utils.sh"

function cm_bidir()
{
	local label=$1
	local server_cmd client_cmd

	echo "CM ($label): EP_HOST as Server -> EP_REMOTE_HOST as Client"
	server_cmd="bash -c \"${host_env} setsid udaddy >/dev/null 2>&1 &\""
	client_cmd="bash -c \"${remote_host_env} udaddy -b $remote_host_ip -s $host_ip\""
	ep_host_ssh_cmd "$server_cmd"
	sleep 1
	if ! $remote_host_ssh "$client_cmd"; then
		echo "CM ($label): EP_HOST-server direction FAILED"
		return 1
	fi

	echo "CM ($label): EP_REMOTE_HOST as Server -> EP_HOST as Client"
	server_cmd="bash -c \"${remote_host_env} setsid udaddy >/dev/null 2>&1 &\""
	client_cmd="bash -c \"${host_env} udaddy -b $host_ip -s $remote_host_ip\""
	$remote_host_ssh "$server_cmd"
	sleep 1
	if ! ep_host_ssh_cmd "$client_cmd"; then
		echo "CM ($label): EP_REMOTE_HOST-server direction FAILED"
		return 1
	fi

	echo "CM ($label): PASSED (both directions)"
	return 0
}

function cm_topo_run()
{
	local label="RDMA CM ($rdma_topo_label)"

	if cm_bidir "$rdma_topo_label"; then
		rdma_ci_result_add "$label" "Pass"
		return 0
	fi
	rdma_ci_result_add "$label" "Fail"
	rdma_ci_results_print_interim
	return 1
}

function rdma_cm_test()
{
	rdma_ci_results_reset

	rdma_register_sig_handler
	rdma_ci_running_line "RDMA CM" "1"

	rdma_foreach_topo cm_topo_run start || true

	if rdma_ci_suite_finish; then
		return 0
	fi
	exit 1
}
test_run rdma_cm_test 2
