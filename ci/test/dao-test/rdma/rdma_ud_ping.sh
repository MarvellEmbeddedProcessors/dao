#!/bin/bash
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2025 Marvell.

# RDMA UD Functional Tests
# Runs ibv_ud_pingpong in both directions over both octep RDMA data paths:
#   1. Octeon<->Octeon  : EP_HOST octep VF <-> EP_REMOTE_HOST octep VF (30.0.0.x)
#   2. Octeon<->Mellanox: EP_HOST octep VF <-> EP_REMOTE_HOST Mellanox (21.0.0.x)

set -euo pipefail

# Load RDMA utilities
SCRIPT_DIR="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
source "$SCRIPT_DIR/rdma_utils.sh"

# ibv_ud_pingpong both ways EP_HOST <-> EP_REMOTE_HOST; endpoint vars from caller scope. $1=label.
function ud_pingpong_bidir()
{
	local label=$1
	local server_cmd client_cmd

	# Direction 1: EP_HOST as server, EP_REMOTE_HOST as client.
	echo "UD ($label): EP_HOST as Server -> EP_REMOTE_HOST as Client"
	server_cmd="bash -c \"${host_env} setsid ibv_ud_pingpong -g $host_gid_idx -d $host_rdma_dev -i 1 >/dev/null 2>&1 &\""
	client_cmd="bash -c \"${remote_host_env} ibv_ud_pingpong -g $remote_host_gid_idx -d $remote_host_rdma_dev -i 1 $host_ip\""
	ep_host_ssh_cmd "$server_cmd"
	sleep 1
	if ! $remote_host_ssh "$client_cmd"; then
		echo "UD ($label): EP_HOST-server direction FAILED"
		return 1
	fi

	# Direction 2: EP_REMOTE_HOST as server, EP_HOST as client.
	echo "UD ($label): EP_REMOTE_HOST as Server -> EP_HOST as Client"
	server_cmd="bash -c \"${remote_host_env} setsid ibv_ud_pingpong -g $remote_host_gid_idx -d $remote_host_rdma_dev -i 1 >/dev/null 2>&1 &\""
	client_cmd="bash -c \"${host_env} ibv_ud_pingpong -g $host_gid_idx -d $host_rdma_dev -i 1 $remote_host_ip\""
	$remote_host_ssh "$server_cmd"
	sleep 1
	if ! ep_host_ssh_cmd "$client_cmd"; then
		echo "UD ($label): EP_REMOTE_HOST-server direction FAILED"
		return 1
	fi

	echo "UD ($label): PASSED (both directions)"
	return 0
}

# Function to run UD functional tests
function rdma_ud_ping()
{
	local host_ip host_env host_rdma_dev host_gid_idx
	local remote_host_ip remote_host_env remote_host_rdma_dev remote_host_gid_idx remote_host_ssh
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
		echo "[O<->O] step 1/4: launch dao-rdma_graph on EP_DEVICE + EP_REMOTE"
		rdma_launch_graph_on_device                                   # graph on EP_DEVICE
		rdma_launch_graph_on_remote                                   # graph on EP_REMOTE

		echo "[O<->O] step 2/4: bring up octep VFs (EP_REMOTE_HOST, then EP_HOST last)"
		rdma_setup_host_endpoint ep_remote_host_op "$remote_host_ip"  # octep VF on EP_REMOTE_HOST
		sleep 1
		rdma_setup_host_endpoint ep_host_op        "$host_ip"         # octep VF on EP_HOST - last
		sleep 1

		echo "[O<->O] step 3/4: resolve RDMA device + GID index on EP_HOST and EP_REMOTE_HOST"
		host_rdma_dev=$(ep_host_op get_rdma_device "$EP_HOST_RDMA_PATH" "$host_ip")
		host_gid_idx=$(ep_host_op get_v4_gid_index "$host_rdma_dev" "$EP_HOST_RDMA_PATH")
		remote_host_rdma_dev=$(ep_remote_host_op get_rdma_device "$EP_REMOTE_RDMA_PATH" "$remote_host_ip")
		remote_host_gid_idx=$(ep_remote_host_op get_v4_gid_index "$remote_host_rdma_dev" "$EP_REMOTE_RDMA_PATH")

		echo "[O<->O] step 4/4: run ibv_ud_pingpong (both directions)"
		ud_pingpong_bidir "Octeon<->Octeon" || overall=1
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
		echo "[O<->MLX] step 1/4: launch dao-rdma_graph on EP_DEVICE MLX port ($EP_DEVICE_MLX_IFACE)"
		rdma_launch_graph_on_device "${EP_DEVICE_MLX_IFACE},force_tail_drop=1" # graph on EP_DEVICE MLX port (force_tail_drop for O<->MLX)

		echo "[O<->MLX] step 2/4: bring up EP_REMOTE_HOST Mellanox IP + EP_HOST octep VF"
		rdma_setup_mlx_endpoint "$EP_REMOTE_HOST_MLX_IFACE" "$remote_host_ip" # Mellanox IP (native)
		sleep 2
		rdma_setup_host_endpoint ep_host_op "$host_ip"                       # octep VF on EP_HOST - last
		sleep 1

		echo "[O<->MLX] step 3/4: resolve RDMA device + GID index (octep on EP_HOST, Mellanox on EP_REMOTE_HOST)"
		host_rdma_dev=$(ep_host_op get_rdma_device "$EP_HOST_RDMA_PATH" "$host_ip")
		host_gid_idx=$(ep_host_op get_v4_gid_index "$host_rdma_dev" "$EP_HOST_RDMA_PATH")
		remote_host_rdma_dev=$(ep_remote_host_op get_rdma_device "$EP_REMOTE_RDMA_PATH" "$remote_host_ip")
		remote_host_gid_idx=$(ep_remote_host_op get_v4_gid_index "$remote_host_rdma_dev" "$EP_REMOTE_RDMA_PATH")

		echo "[O<->MLX] step 4/4: run ibv_ud_pingpong (both directions)"
		ud_pingpong_bidir "Octeon<->Mellanox" || overall=1
		rdma_tests_cleanup
		ran=1
	fi

	if [[ $ran -eq 0 ]]; then
		echo "No RDMA scenario selected/available (RDMA_SCENARIO=${RDMA_SCENARIO:-both})"
		exit 77
	fi

	if [[ $overall -ne 0 ]]; then
		echo "UD Functional Tests FAILED"
		exit 1
	fi

	echo "UD Functional Tests completed successfully"
	return 0
}
test_run rdma_ud_ping 2
