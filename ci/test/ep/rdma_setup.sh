#!/bin/bash
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2025 Marvell.

set -euo pipefail

DAO_SUITE_SETUP["dao-rdma"]=dao_rdma_setup
DAO_SUITE_CLEANUP["dao-rdma"]=dao_rdma_cleanup

function dao_rdma_cleanup()
{
	if [[ -n $SKIP_SETUP ]]; then
		echo "Skip rdma cleanup"
		return
	fi

	echo "Starting DAO RDMA cleanup..."

	ep_host_op rdma_cleanup
	ep_remote_op guest_rdma_cleanup $EP_REMOTE_IFACE
	ep_device_op rdma_app_cleanup
	ep_host_op safe_kill $EP_DIR
	ep_device_op safe_kill $EP_DIR
	ep_host_ssh_cmd "$EP_HOST_SUDO dmesg" > host_dmesg.log
	save_log host_dmesg.log
	ep_device_ssh_cmd "$EP_DEVICE_SUDO dmesg" > device_dmesg.log
	save_log device_dmesg.log
	echo "DAO RDMA cleanup completed"
}

function verify_rdma_setup()
{
	local host_ip="30.0.0.3"
	local remote_ip="30.0.0.11"
	local num_mbufs=1048576
	local max_pkt_len=9600
	local dma_nb_desc=8192
	local serialized_args
	local num_eth_ifcs=1
	local eth_pf_ifcs=""
	local remote_iface
	local sdp_vf_name
	local cur_sdp_idx
	local ping_status
	local sdp_pcie_vf
	local pci_devs=""
	local rdma_utils
	local app_cmd
	local ext_iface

	populate_ep_interfaces

	ext_iface=${EP_DEVICE_EXT_IFACE:-}
	remote_iface=${EP_REMOTE_IFACE:-}

	if [[ -n $EP_REMOTE ]]; then
		if [[ -z $ext_iface ]] || [[ -z $remote_iface ]]; then
			echo "Failed to find a valid interface pair"
			exit 1
		fi
	fi

	echo "Device External Interface: $ext_iface"
	echo "Remote Interface: $remote_iface"

	ep_device_op bind_driver pci $ext_iface vfio-pci
	pci_devs="$pci_devs $ext_iface"

	# For RDMA sdp vf shall start from index-2
	cur_sdp_idx=2
	sdp_pcie_vf=$(ep_device_op pcie_addr_get  $PCI_DEVID_CN10K_RVU_SDP_VF)
	for iface in $sdp_pcie_vf; do
		local sdp_pcie_addr=$(get_vf_pcie_addr ${sdp_pcie_vf} $cur_sdp_idx)
		ep_device_op bind_driver pci $sdp_pcie_addr vfio-pci
		pci_devs="$pci_devs $sdp_pcie_addr"

		if (( cur_sdp_idx == num_eth_ifcs + 1 )); then
			break
		fi

		((cur_sdp_idx++))
	done

	# Add DPI VFs
	read -r -a dpi_vfs <<< "$(ep_device_op pcie_addr_get $PCI_DEVID_CN10K_RVU_DPI_VF 16)"
	for dpi in "${dpi_vfs[@]}"; do
		pci_devs="$pci_devs $dpi"
	done

	# Launch RDMA application with all PCI devices
	args=()
	read -r -a tmp <<< "$(form_split_args "--pci-devs"    "$pci_devs")"    ; args+=("${tmp[@]}")
	read -r -a tmp <<< "$(form_split_args "--max-pkt-len" "$max_pkt_len")" ; args+=("${tmp[@]}")
	read -r -a tmp <<< "$(form_split_args "--num-mbufs"   "$num_mbufs")"   ; args+=("${tmp[@]}")
	read -r -a tmp <<< "$(form_split_args "--dma-nb-desc" "$dma_nb_desc")" ; args+=("${tmp[@]}")

	# Serialize args for safe transport through SSH.
	serialized_args=$(printf '%q ' "${args[@]}")

	rdma_utils=$EP_DIR/ci/test/dao-test/rdma/rdma_utils.sh
	app_cmd="EP_DIR=$EP_DIR; source \"$rdma_utils\"; rdma_app_launch $serialized_args"

	ep_device_ssh_cmd "$EP_DEVICE_SUDO -E bash -lc $(printf %q "$app_cmd")"
	sleep 1

	# Configure Octeon Host
	ep_host_op rdma_setup 1
	sleep 1
	sdp_vfs=$(ep_host_op pcie_addr_get "0xB903" 1)

	ep_host_op if_configure --pcie-addr $sdp_vfs --ip $host_ip
	ep_remote_op if_configure --pcie-addr $remote_iface --ip $remote_ip

	# Ping remote from host
	echo "Checking $sdp_vfs (Host) <-> $remote_iface (Remote)"
	ping_status=$(ep_host_op ping $host_ip $remote_ip 2)

	# Undo all the configurations
	ep_host_op if_configure --pcie-addr $sdp_vfs --down
	ep_remote_op if_configure --pcie-addr $remote_iface --down

	# Check output of ping
	if [[ "$ping_status" == "SUCCESS" ]]; then
		echo "Setup verified"
	else
		echo "Cannot ping remote from host"
		exit 1
	fi
}

function dao_rdma_setup()
{
	# Delete the existing rdma directory and copy the new one
	ep_host_ssh_cmd "$EP_HOST_SUDO rm -rf $EP_HOST_RDMA_PATH"
	ep_host_ssh_cmd "$EP_HOST_SUDO mkdir -p $EP_HOST_RDMA_PATH"
	ep_host_ssh_cmd "$EP_HOST_SUDO rsync -a $EP_DIR/rdma_prefix/* $EP_HOST_RDMA_PATH"

	ep_remote_ssh_cmd "$EP_REMOTE_SUDO rm -rf $EP_REMOTE_RDMA_PATH"
	ep_remote_ssh_cmd "$EP_HOST_SUDO mkdir -p $EP_REMOTE_RDMA_PATH"
	ep_remote_ssh_cmd "$EP_HOST_SUDO rsync -a $EP_DIR/ep_files/rdma_remote/* $EP_REMOTE_RDMA_PATH"

	if [[ -n $SKIP_SETUP ]]; then
		echo "Skip EP device setup"
		return
	fi

	echo "Setting up EP device for rdma tests"
	ep_device_op dpi_setup

	ep_device_op hugepage_setup 524288 24 12

	ep_device_op pem_setup

	echo "Verifying rdma setup"
	verify_rdma_setup

	ep_remote_op guest_rdma_setup $EP_REMOTE_IFACE
}
