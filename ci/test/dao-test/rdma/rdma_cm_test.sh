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

# Load RDMA utilities
SCRIPT_DIR="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
source "$SCRIPT_DIR/rdma_utils.sh"

# udaddy both ways EP_HOST <-> EP_REMOTE_HOST via rdma_cm (IP-based, no GID/device); IPs from caller scope. $1=label.
function cm_bidir()
{
	local label=$1
	local server_cmd client_cmd

	# Direction 1: EP_HOST as server, EP_REMOTE_HOST as client.
	echo "CM ($label): EP_HOST as Server -> EP_REMOTE_HOST as Client"
	server_cmd="bash -c \"${host_env} setsid udaddy >/dev/null 2>&1 &\""
	client_cmd="bash -c \"${remote_host_env} udaddy -b $remote_host_ip -s $host_ip\""
	ep_host_ssh_cmd "$server_cmd"
	sleep 1
	if ! $remote_host_ssh "$client_cmd"; then
		echo "CM ($label): EP_HOST-server direction FAILED"
		return 1
	fi

	# Direction 2: EP_REMOTE_HOST as server, EP_HOST as client.
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

# Function to run RDMA CM functional tests
function rdma_cm_test()
{
	local host_ip host_env
	local remote_host_ip remote_host_env remote_host_ssh
	local overall=0 ran=0

	# Register signal handler (cleans up on any failure/exit)
	rdma_register_sig_handler

	# EP_HOST is always octep; EP_REMOTE_HOST is octep (O<->O) or Mellanox (O<->MLX).
	host_env=$HOST_ENV
	remote_host_env=$REMOTE_ENV
	remote_host_ssh=ep_remote_host_ssh_cmd

	# ============ Scenario 1: Octeon <-> Octeon (needs EP_REMOTE) ============
	if [[ "${RDMA_SCENARIO:-both}" != "mlx" && -n "${EP_REMOTE:-}" ]]; then
		echo ""
		echo "==================== SCENARIO: Octeon <-> Octeon ===================="
		echo "  EP_HOST octep VF (30.0.0.3) <-> EP_REMOTE_HOST octep VF (30.0.0.11)"
		host_ip="30.0.0.3"
		remote_host_ip="30.0.0.11"

		# Both Octeon graphs first, then octep VFs with EP_HOST last (else the graph crashes).
		echo "[O<->O] step 1/3: launch dao-rdma_graph on EP_DEVICE + EP_REMOTE"
		rdma_launch_graph_on_device                                   # graph on EP_DEVICE
		rdma_launch_graph_on_remote                                   # graph on EP_REMOTE

		echo "[O<->O] step 2/3: bring up octep VFs (EP_REMOTE_HOST, then EP_HOST last)"
		rdma_setup_host_endpoint ep_remote_host_op "$remote_host_ip"  # octep VF on EP_REMOTE_HOST
		sleep 1
		rdma_setup_host_endpoint ep_host_op        "$host_ip"         # octep VF on EP_HOST - last
		sleep 1

		# octep<->octep rdma_cm may not establish (RoCE v1 GID not usable as CM client).
		echo "[O<->O] step 3/3: run udaddy (both directions)"
		cm_bidir "Octeon<->Octeon" || overall=1
		rdma_tests_cleanup
		ran=1
	fi

	# ================= Scenario 2: Octeon <-> Mellanox =================
	if [[ "${RDMA_SCENARIO:-both}" != "octeon" && -n "${EP_DEVICE_MLX_IFACE:-}" && -n "${EP_REMOTE_HOST_MLX_IFACE:-}" ]]; then
		echo ""
		echo "=================== SCENARIO: Octeon <-> Mellanox ==================="
		echo "  EP_HOST octep VF (21.0.0.3) <-> EP_REMOTE_HOST Mellanox (21.0.0.11)"
		host_ip="21.0.0.3"
		remote_host_ip="21.0.0.11"

		# Graph only on EP_DEVICE MLX port; EP_REMOTE_HOST Mellanox is native RoCE (IP only).
		echo "[O<->MLX] step 1/3: launch dao-rdma_graph on EP_DEVICE MLX port ($EP_DEVICE_MLX_IFACE)"
		rdma_launch_graph_on_device "${EP_DEVICE_MLX_IFACE},force_tail_drop=1" # graph on EP_DEVICE MLX port (force_tail_drop for O<->MLX)

		echo "[O<->MLX] step 2/3: bring up EP_REMOTE_HOST Mellanox IP + EP_HOST octep VF"
		rdma_setup_mlx_endpoint "$EP_REMOTE_HOST_MLX_IFACE" "$remote_host_ip" # Mellanox IP (native)
		sleep 2
		rdma_setup_host_endpoint ep_host_op "$host_ip"                       # octep VF on EP_HOST - last
		sleep 1

		echo "[O<->MLX] step 3/3: run udaddy (both directions)"
		cm_bidir "Octeon<->Mellanox" || overall=1
		rdma_tests_cleanup
		ran=1
	fi

	if [[ $ran -eq 0 ]]; then
		echo "No RDMA scenario selected/available (RDMA_SCENARIO=${RDMA_SCENARIO:-both})"
		exit 77
	fi

	if [[ $overall -ne 0 ]]; then
		echo "RDMA CM Tests FAILED"
		exit 1
	fi

	echo "RDMA CM Tests completed successfully"
	return 0
}
test_run rdma_cm_test 2
