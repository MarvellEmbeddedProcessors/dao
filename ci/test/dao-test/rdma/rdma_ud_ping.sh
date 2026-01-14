#!/bin/bash
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2025 Marvell.

# RDMA UD Functional Tests
# This test verifies basic UD connectivity in both directions:
# 1. Host (Octeon) as Server -> Remote (RXE) as Client
# 2. Remote (RXE) as Server -> Host (Octeon) as Client

set -euo pipefail

# Load RDMA utilities
SCRIPT_DIR="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
source "$SCRIPT_DIR/rdma_utils.sh"

# Function to run UD functional tests
function rdma_ud_ping()
{
	local remote_ip="30.0.0.11"
	local host_ip="30.0.0.3"
	local remote_env
	local host_env
	local status

	# Register signal handler
	rdma_register_sig_handler

	host_rdma_dev=$(ep_host_op get_rdma_device "$EP_HOST_RDMA_PATH")
	host_gid=$(ep_host_op get_v4_gid_index $host_rdma_dev "$EP_HOST_RDMA_PATH")

	remote_rdma_dev=$(ep_remote_op get_rdma_device "$EP_REMOTE_RDMA_PATH")
	remote_gid=$(ep_remote_op get_v4_gid_index $remote_rdma_dev "$EP_REMOTE_RDMA_PATH")

	remote_env="export PATH=\"${EP_REMOTE_RDMA_PATH}/bin\":\$PATH;export LD_LIBRARY_PATH=\"${EP_REMOTE_RDMA_PATH}/lib:\${LD_LIBRARY_PATH:-}\";"
	host_env="export PATH=\"${EP_HOST_RDMA_PATH}/bin\":\$PATH;export LD_LIBRARY_PATH=\"${EP_HOST_RDMA_PATH}/lib:\${LD_LIBRARY_PATH:-}\";"

	# Test 1: Host as server and Remote as client
	echo "UD Basic Connectivity Tests: Host as Server -> Remote as Client"

	local test_name="UD_FUNC_Host_Server_Remote_Client"
	local server_cmd="bash -c \"${host_env} setsid ibv_ud_pingpong -g $host_gid -d $host_rdma_dev -i 1 >/dev/null 2>&1 &\""
	local client_cmd="bash -c \"${remote_env} ibv_ud_pingpong -g $remote_gid -d $remote_rdma_dev -i 1 $host_ip\""

	ep_host_ssh_cmd "$server_cmd"
	sleep 1
	ep_remote_ssh_cmd "$client_cmd"
	status=$?
	if [[ $status -ne 0 ]]; then
		echo "$test_name failed"
		exit 1
	else
		echo "$test_name Passed"
	fi

	# Test 2: Remote (RXE) as Server -> Host (Octeon) as Client
	echo "UD Basic Connectivity Tests: Remote as Server -> Host as Client"

	test_name="UD_FUNC_Remote_Server_Host_Client"
	server_cmd="bash -c \"${remote_env} setsid ibv_ud_pingpong -g $remote_gid -d $remote_rdma_dev -i 1 > /dev/null 2>&1 &\""
	client_cmd="bash -c \"${host_env} ibv_ud_pingpong -g $host_gid -d $host_rdma_dev -i 1 $remote_ip\""

	ep_remote_ssh_cmd "$server_cmd"
	sleep 1
	ep_host_ssh_cmd "$client_cmd"
	status=$?
	if [[ $status -ne 0 ]]; then
		echo "$test_name failed"
		exit 1
	else
		echo "$test_name Passed"
	fi

	echo "UD Functional Tests completed successfully"
	rdma_tests_cleanup

	return 0
}
test_run ${DAO_TEST} 2
