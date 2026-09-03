#!/bin/bash
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2025 Marvell.

set -euo pipefail

DAO_SUITE_SETUP["dao-rdma-octterm"]=dao_rdma_octterm_setup
DAO_SUITE_CLEANUP["dao-rdma-octterm"]=dao_rdma_octterm_cleanup

function dao_rdma_octterm_cleanup()
{
	if [[ -n ${SKIP_SETUP:-} ]]; then
		echo "Skip rdma-octterm cleanup"
		return
	fi

	echo "Starting DAO RDMA octterm cleanup..."

	# Kill perftest processes on remote host (MLX)
	if [[ -n "${EP_REMOTE_HOST:-}" ]]; then
		ep_remote_host_op rdma_test_cleanup true
	fi

	# Stop firmware app and remove kmod on EP_REMOTE (Octeon<->Octeon)
	if [[ -n "${EP_REMOTE:-}" ]]; then
		ep_remote_op rdma_app_cleanup
		local remote_kmod_rm="if grep -q octep_rdma /proc/modules; then rmmod octep_rdma; sleep 5; fi"
		ep_remote_ssh_cmd "$EP_REMOTE_SUDO bash -c '$remote_kmod_rm'" || true
		ep_remote_op safe_kill $EP_DIR
	fi

	# Stop firmware app on device
	ep_device_op rdma_app_cleanup

	# Remove kmod on device
	local kmod_rm_cmd="if grep -q octep_rdma /proc/modules;"
	kmod_rm_cmd+=" then rmmod octep_rdma; sleep 5; fi"
	ep_device_ssh_cmd "$EP_DEVICE_SUDO bash -c '$kmod_rm_cmd'" || true

	# Kill stale processes on device
	ep_device_op safe_kill $EP_DIR

	# Bring MLX interface down
	if [[ -n "${EP_REMOTE_HOST_MLX_IFACE:-}" ]]; then
		ep_remote_host_op if_configure --pcie-addr \
			"$EP_REMOTE_HOST_MLX_IFACE" --down || true
	fi

	# Return external ports to kernel driver (Octeon<->Octeon)
	if [[ -n "${EP_DEVICE_EXT_IFACE:-}" ]]; then
		ep_device_op bind_driver pci "$EP_DEVICE_EXT_IFACE" rvu_nicpf || true
	fi
	if [[ -n "${EP_REMOTE_IFACE:-}" ]]; then
		ep_remote_op bind_driver pci "$EP_REMOTE_IFACE" rvu_nicpf || true
	fi

	# Save dmesg logs (best-effort — must not abort cleanup)
	ep_device_ssh_cmd "$EP_DEVICE_SUDO dmesg" > device_dmesg.log || true
	save_log device_dmesg.log

	# Remove rdma prefix staging symlink created during setup
	local baked_prefix="${BUILD_DIR}/rdma_prefix"
	if [[ "$baked_prefix" != "$EP_DIR/rdma_prefix" ]]; then
		ep_device_ssh_cmd "$EP_DEVICE_SUDO rm -f $baked_prefix" || true
		if [[ -n "${EP_REMOTE:-}" ]]; then
			ep_remote_ssh_cmd "$EP_REMOTE_SUDO rm -f $baked_prefix" || true
		fi
	fi

	echo "DAO RDMA octterm cleanup completed"
}

function dao_rdma_octterm_setup()
{
	if [[ -n ${SKIP_SETUP:-} ]]; then
		echo "Skip EP device setup"
		return
	fi

	echo "Setting up EP device for rdma-octterm tests"

	# Stage rdma-core at the baked cmake prefix path so libibverbs
	# can find its config files and provider plugins at the paths
	# compiled into the binary (CMAKE_INSTALL_PREFIX=$BUILD_DIR/rdma_prefix).
	local baked_prefix="${BUILD_DIR}/rdma_prefix"
	if [[ "$baked_prefix" != "$EP_DIR/rdma_prefix" ]]; then
		echo "Staging RDMA prefix: $EP_DIR/rdma_prefix -> $baked_prefix (EP_DEVICE)"
		ep_device_ssh_cmd "$EP_DEVICE_SUDO mkdir -p $(dirname $baked_prefix)"
		ep_device_ssh_cmd "$EP_DEVICE_SUDO ln -sfn $EP_DIR/rdma_prefix $baked_prefix"
	fi

	ep_device_op dpi_setup
	ep_device_op hugepage_setup 524288 24 24

	if [[ -n "${EP_REMOTE:-}" ]]; then
		echo "Setting up EP_REMOTE (far Octeon) for rdma-octterm tests"
		if [[ "$baked_prefix" != "$EP_DIR/rdma_prefix" ]]; then
			echo "Staging RDMA prefix: $EP_DIR/rdma_prefix -> $baked_prefix (EP_REMOTE)"
			ep_remote_ssh_cmd "$EP_REMOTE_SUDO mkdir -p $(dirname $baked_prefix)"
			ep_remote_ssh_cmd "$EP_REMOTE_SUDO ln -sfn $EP_DIR/rdma_prefix $baked_prefix"
		fi
		ep_remote_op dpi_setup
		ep_remote_op hugepage_setup 524288 24 24
	fi

	echo "Verifying rdma octterm setup"
	verify_rdma_octterm_setup

	echo "RDMA octterm setup completed"
}

function verify_rdma_octterm_setup()
{
	local did_verify=0

	# Octeon <-> Octeon: needs EP_REMOTE.
	if [[ -n "${EP_REMOTE:-}" ]]; then
		populate_ep_interfaces
		if [[ -z "${EP_DEVICE_EXT_IFACE:-}" ]] || [[ -z "${EP_REMOTE_IFACE:-}" ]]; then
			echo "Failed to find EP_DEVICE <-> EP_REMOTE (Octeon<->Octeon) pair"
			exit 1
		fi
		verify_rdma_octterm_octeon_datapath
		did_verify=1
	else
		echo "EP_REMOTE not set - skipping Octeon<->Octeon verification"
	fi

	# Octeon <-> MLX: needs EP_REMOTE_HOST + a Mellanox NIC.
	if [[ -n "${EP_REMOTE_HOST:-}" ]] && populate_ep_mlx_interfaces \
	   && [[ -n "${EP_DEVICE_MLX_IFACE:-}" ]] \
	   && ep_remote_host_op is_mellanox "$EP_REMOTE_HOST_MLX_IFACE"; then
		verify_rdma_octterm_mlx_datapath
		did_verify=1
	else
		echo "No Mellanox NIC discovered on EP_REMOTE_HOST - skipping Octeon<->MLX verification"
	fi

	if [[ $did_verify -eq 0 ]]; then
		echo "No RDMA octterm scenario available (need EP_REMOTE and/or a Mellanox on EP_REMOTE_HOST)"
		exit 1
	fi

	echo "*****************************************************************"
	echo "***  RDMA OCTTERM TEST SCENARIOS ON THIS BENCH:"
	if [[ -n "${EP_REMOTE:-}" ]]; then
		echo "***    Octeon <-> Octeon    :  WILL RUN  (EP_REMOTE set)"
	else
		echo "***    Octeon <-> Octeon    :  SKIPPED   (EP_REMOTE not set)"
	fi
	if [[ -n "${EP_DEVICE_MLX_IFACE:-}" ]]; then
		echo "***    Octeon <-> Mellanox  :  WILL RUN  (Mellanox discovered)"
	else
		echo "***    Octeon <-> Mellanox  :  SKIPPED   (no Mellanox on EP_REMOTE_HOST)"
	fi
	echo "*****************************************************************"
}

# Helper: launch octterm app (kmod+graph) on a given Octeon over SSH.
# $1=ssh_cmd function, $2=sudo var, $3=pci_devs, $4=op function for pcie_addr_get
function octterm_launch_on_node()
{
	local ssh_fn=$1
	local sudo_var=$2
	local pci_devs=$3
	local op_fn=$4
	local dpi_vfs

	dpi_vfs=$($op_fn pcie_addr_get $PCI_DEVID_CN10K_RVU_DPI_VF 16)
	for dpi in $dpi_vfs; do
		pci_devs="$pci_devs $dpi"
	done

	local kmod_cmd="modprobe ib_uverbs; sleep 1;"
	kmod_cmd+=" if grep -q octep_rdma /proc/modules; then rmmod octep_rdma; sleep 2; fi;"
	kmod_cmd+=" insmod $EP_DIR/kmod/rdma/octep_rdma/octep-rdma.ko; sleep 2"
	$ssh_fn "$sudo_var bash -c '$kmod_cmd'"

	# Build --pci-devs arguments directly to avoid printf %q escaping commas in devargs.
	local pci_args=""
	for dev in $pci_devs; do
		pci_args+=" --pci-devs $dev"
	done

	local launch_cmd="EP_DIR=$EP_DIR; source $EP_DIR/ci/test/dao-test/rdma-octterm/rdma_octterm_utils.sh;"
	launch_cmd+=" rdma_octterm_app_launch $pci_args --num-mbufs 131072 --dma-nb-desc 32768"
	local ld_library_path="export LD_LIBRARY_PATH=\"${EP_DIR}/deps-prefix/ep/lib:\${LD_LIBRARY_PATH:-}\";"
	launch_cmd="$ld_library_path $launch_cmd"
	$ssh_fn "$sudo_var -E bash -lc $(printf %q "$launch_cmd")"
}

# Validate: EP_DEVICE (kmod+firmware, octterm) <-> EP_REMOTE_HOST (MLX native RoCE).
function verify_rdma_octterm_mlx_datapath()
{
	local local_ip="21.0.0.3"
	local remote_ip="21.0.0.11"
	local ping_status

	echo "Validating EP_DEVICE <-> EP_REMOTE_HOST (Octeon<->Mellanox) RDMA data path (octterm)"
	echo "  Device $EP_DEVICE_MLX_IFACE (EP_DEVICE) <-> Remote $EP_REMOTE_HOST_MLX_IFACE (EP_REMOTE_HOST MLX)"

	ep_device_op bind_driver pci $EP_DEVICE_MLX_IFACE vfio-pci
	octterm_launch_on_node ep_device_ssh_cmd "$EP_DEVICE_SUDO" \
		"${EP_DEVICE_MLX_IFACE},force_tail_drop=1" ep_device_op
	rdma_wait_app_ready ep_device_ssh_cmd

	ep_device_op octterm_mgmt_ip_configure $local_ip

	ep_remote_host_op if_configure --pcie-addr $EP_REMOTE_HOST_MLX_IFACE --down
	ep_remote_host_op if_configure --pcie-addr $EP_REMOTE_HOST_MLX_IFACE --ip $remote_ip
	ep_remote_host_op link_wait $EP_REMOTE_HOST_MLX_IFACE 15 >/dev/null

	ping_status=$(ep_device_op ping $local_ip $remote_ip 5)

	# Tear down
	ep_device_op rdma_app_cleanup
	local kmod_rm_cmd="if grep -q octep_rdma /proc/modules; then rmmod octep_rdma; sleep 5; fi"
	ep_device_ssh_cmd "$EP_DEVICE_SUDO bash -c '$kmod_rm_cmd'" || true
	ep_remote_host_op if_configure --pcie-addr $EP_REMOTE_HOST_MLX_IFACE --down
	ep_device_op bind_driver pci $EP_DEVICE_MLX_IFACE rvu_nicpf || true

	if [[ "$ping_status" != "SUCCESS" ]]; then
		echo "Cannot ping EP_REMOTE_HOST MLX from EP_DEVICE over the octterm RDMA path"
		exit 1
	fi
	echo "EP_DEVICE <-> EP_REMOTE_HOST (Octeon<->Mellanox) RDMA data path verified (octterm)"
}

# Validate: EP_DEVICE (kmod+firmware, octterm) <-> EP_REMOTE (kmod+firmware, octterm).
function verify_rdma_octterm_octeon_datapath()
{
	local local_ip="30.0.0.3"
	local remote_ip="30.0.0.11"
	local ping_status

	echo "Validating EP_DEVICE <-> EP_REMOTE (Octeon<->Octeon) RDMA data path (octterm)"
	echo "  Device $EP_DEVICE_EXT_IFACE (EP_DEVICE) <-> Remote $EP_REMOTE_IFACE (EP_REMOTE)"

	# Launch octterm on EP_DEVICE
	ep_device_op if_configure --pcie-addr $EP_DEVICE_EXT_IFACE --down
	ep_device_op bind_driver pci $EP_DEVICE_EXT_IFACE vfio-pci
	octterm_launch_on_node ep_device_ssh_cmd "$EP_DEVICE_SUDO" \
		"$EP_DEVICE_EXT_IFACE" ep_device_op
	rdma_wait_app_ready ep_device_ssh_cmd

	# Launch octterm on EP_REMOTE
	ep_remote_op if_configure --pcie-addr $EP_REMOTE_IFACE --down
	ep_remote_op bind_driver pci $EP_REMOTE_IFACE vfio-pci
	octterm_launch_on_node ep_remote_ssh_cmd "$EP_REMOTE_SUDO" \
		"$EP_REMOTE_IFACE" ep_remote_op
	rdma_wait_app_ready ep_remote_ssh_cmd

	# Configure management IPs
	ep_device_op octterm_mgmt_ip_configure $local_ip
	ep_remote_op octterm_mgmt_ip_configure $remote_ip

	ping_status=$(ep_device_op ping $local_ip $remote_ip 5)

	# Tear down
	ep_device_op rdma_app_cleanup
	ep_remote_op rdma_app_cleanup
	local kmod_rm_cmd="if grep -q octep_rdma /proc/modules; then rmmod octep_rdma; sleep 5; fi"
	ep_device_ssh_cmd "$EP_DEVICE_SUDO bash -c '$kmod_rm_cmd'" || true
	ep_remote_ssh_cmd "$EP_REMOTE_SUDO bash -c '$kmod_rm_cmd'" || true
	ep_device_op bind_driver pci $EP_DEVICE_EXT_IFACE rvu_nicpf || true
	ep_remote_op bind_driver pci $EP_REMOTE_IFACE rvu_nicpf || true

	if [[ "$ping_status" != "SUCCESS" ]]; then
		echo "Cannot ping EP_REMOTE from EP_DEVICE over the octterm RDMA path (Octeon<->Octeon)"
		exit 1
	fi
	echo "EP_DEVICE <-> EP_REMOTE (Octeon<->Octeon) RDMA data path verified (octterm)"
}
