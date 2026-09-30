#!/bin/bash
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2025 Marvell.

RDMA_IP_OCT_HOST="30.0.0.3"
RDMA_IP_OCT_REMOTE="30.0.0.11"
RDMA_IP_MLX_HOST="21.0.0.3"
RDMA_IP_MLX_REMOTE="21.0.0.11"

function rdma_topo_mtu()
{
	if [[ -n "${RDMA_MTU:-}" ]]; then
		echo "$RDMA_MTU"
		return
	fi
	case "$(rdma_ci_test_type)" in
	benchmark) echo 9000 ;;
	*) echo 1500 ;;
	esac
}

function rdma_topo_octeon_enabled()
{
	[[ "${RDMA_TOPO:-both}" != "mlx" && -n "${EP_REMOTE:-}" ]]
}

function rdma_topo_mlx_enabled()
{
	[[ "${RDMA_TOPO:-both}" != "octeon" \
		&& -n "${EP_DEVICE_MLX_IFACE:-}" && -n "${EP_REMOTE_HOST_MLX_IFACE:-}" ]]
}

function rdma_ep_init_ssh_env()
{
	host_env=$HOST_ENV
	remote_host_env=$REMOTE_ENV
	remote_host_ssh=ep_remote_host_ssh_cmd
}

function rdma_topo_setup_ips()
{
	local id=$1

	rdma_topo_id=$id
	if [[ "$id" == octeon ]]; then
		rdma_topo_label="Octeon<->Octeon"
		host_ip=$RDMA_IP_OCT_HOST
		remote_host_ip=$RDMA_IP_OCT_REMOTE
		echo ""
		echo "==================== TOPOLOGY: Octeon <-> Octeon ===================="
		echo "  EP_HOST octep VF ($host_ip) <-> EP_REMOTE_HOST octep VF ($remote_host_ip)"
	else
		rdma_topo_label="Octeon<->Mellanox"
		host_ip=$RDMA_IP_MLX_HOST
		remote_host_ip=$RDMA_IP_MLX_REMOTE
		echo ""
		echo "==================== TOPOLOGY: Octeon <-> Mellanox ===================="
		echo "  EP_HOST octep VF ($host_ip) <-> EP_REMOTE_HOST Mellanox ($remote_host_ip)"
	fi
	echo "  MTU: $(rdma_topo_mtu) [$(rdma_ci_test_type)]"
}

function rdma_topo_start()
{
	local id=$1

	if [[ "$id" == octeon ]]; then
		rdma_launch_graph_on_device
		rdma_launch_graph_on_remote
		rdma_setup_host_endpoint ep_remote_host_op "$remote_host_ip"
		sleep 1
		rdma_setup_host_endpoint ep_host_op "$host_ip"
		sleep 1
	else
		rdma_launch_graph_on_device "${EP_DEVICE_MLX_IFACE},force_tail_drop=1"
		rdma_setup_mlx_endpoint "$EP_REMOTE_HOST_MLX_IFACE" "$remote_host_ip"
		sleep 2
		rdma_setup_host_endpoint ep_host_op "$host_ip"
		sleep 1
	fi
}

function rdma_ep_resolve_rdma_devices()
{
	host_rdma_dev=$(ep_host_op get_rdma_device "$EP_HOST_RDMA_PATH" "$host_ip")
	host_gid=$(ep_host_op get_v4_gid_index "$host_rdma_dev" "$EP_HOST_RDMA_PATH")
	host_gid_idx=$host_gid
	remote_host_rdma_dev=$(ep_remote_host_op get_rdma_device "$EP_REMOTE_RDMA_PATH" "$remote_host_ip")
	remote_host_gid=$(ep_remote_host_op get_v4_gid_index "$remote_host_rdma_dev" "$EP_REMOTE_RDMA_PATH")
	remote_host_gid_idx=$remote_host_gid
	remote_rdma_dev=$remote_host_rdma_dev
	remote_gid=$remote_host_gid
}

function rdma_topo_exit_if_none()
{
	local ran=$1

	if [[ $ran -eq 0 ]]; then
		echo "No RDMA topology enabled/available (RDMA_TOPO=${RDMA_TOPO:-both})"
		exit 77
	fi
}

# $1 = per-topology run function (receives id: octeon | mlx)
# $2 = setup mode: full (start+resolve) | vars (IPs/label only) | start (no resolve)
function rdma_foreach_topo()
{
	local run_fn=$1
	local mode=${2:-full}
	local ran=0
	local rc=0

	rdma_ep_init_ssh_env

	if rdma_topo_octeon_enabled; then
		rdma_topo_setup_ips octeon
		case "$mode" in
		full)
			rdma_topo_start octeon
			rdma_ep_resolve_rdma_devices
			;;
		start) rdma_topo_start octeon ;;
		vars) ;;
		*) echo "rdma_foreach_topo: unknown mode $mode"; return 1 ;;
		esac
		if ! $run_fn octeon; then
			rc=1
		fi
		[[ "$mode" != vars ]] && rdma_tests_cleanup
		ran=1
	fi

	if rdma_topo_mlx_enabled; then
		rdma_topo_setup_ips mlx
		case "$mode" in
		full)
			rdma_topo_start mlx
			rdma_ep_resolve_rdma_devices
			;;
		start) rdma_topo_start mlx ;;
		vars) ;;
		*) echo "rdma_foreach_topo: unknown mode $mode"; return 1 ;;
		esac
		if ! $run_fn mlx; then
			rc=1
		fi
		[[ "$mode" != vars ]] && rdma_tests_cleanup
		ran=1
	fi

	rdma_topo_exit_if_none $ran
	return $rc
}
