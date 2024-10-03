#!/bin/bash
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2024 Marvell.

set -euo pipefail

DAO_SUITE_SETUP["dao-ovs"]=dao_ovs_setup
DAO_SUITE_CLEANUP["dao-ovs"]=dao_ovs_cleanup

function dao_ovs_cleanup()
{
	if [[ -n $SKIP_SETUP ]]; then
		echo "Skip agent cleanup"
	else
		ep_device_op agent_cleanup
	fi

	ep_host_op safe_kill $EP_DIR
	ep_device_op safe_kill $EP_DIR
	ep_device_op safe_kill ovs
	ep_host_ssh_cmd "$EP_HOST_SUDO dmesg" > host_dmesg.log
	save_log host_dmesg.log
	ep_device_ssh_cmd "$EP_DEVICE_SUDO dmesg" > device_dmesg.log
	save_log device_dmesg.log
}

function verify_setup()
{
	local remote_ip=20.0.0.51
	local device_ip=20.0.0.52
	local device_sdp_ip=30.0.0.53
	local host_ip=30.0.0.54
	local device_sdp_iface
	local device_part
	local ping_status
	local remote_iface
	local host_sdp_iface
	local ext_iface

	populate_ep_interfaces

	ext_iface=${EP_DEVICE_EXT_IFACE:-}
	remote_iface=${EP_REMOTE_IFACE:-}

	if [[ -z $ext_iface ]] || [[ -z $remote_iface ]]; then
		echo "Failed to find a valid interface pair"
		exit 1
	fi

	device_part=$(ep_device_op get_part)
	host_sdp_iface=$(ep_host_op pcie_addr_get ${device_part}00)
	device_sdp_iface=$(ep_device_op pcie_addr_get $PCI_DEVID_CN10K_RVU_SDP_VF)

	add_test_env EP_HOST_SDP_IFACE=$host_sdp_iface

	echo "Device External Interface: $ext_iface"
	echo "Remote Interface: $remote_iface"
	echo "Device SDP VF Interface: $device_sdp_iface"
	echo "Host SDP Interface: $host_sdp_iface"

	# Configure host interface
	ep_host_op if_configure --pcie-addr $host_sdp_iface --ip $host_ip

	# Configure device SDP VF
	ep_device_op bind_driver pci $device_sdp_iface rvu_nicvf
	ep_device_op if_configure --pcie-addr $device_sdp_iface --ip $device_sdp_ip

	# Enable IP forwarding on device
	ep_device_op ip_forwarding 1

	# Add route on remote
	ep_remote_ssh_cmd "$EP_REMOTE_SUDO ip route add $host_ip via $device_ip"

	# Add route on host
	ep_host_ssh_cmd "$EP_HOST_SUDO ip route add $remote_ip via $device_sdp_ip"

	# Ping remote from host
	ping_status=$(ep_host_op ping $host_ip $remote_ip 2)

	# Undo all the configurations
	ep_host_ssh_cmd "$EP_HOST_SUDO ip route del $remote_ip"
	ep_remote_ssh_cmd "$EP_REMOTE_SUDO ip route del $host_ip"
	ep_device_op ip_forwarding 0
	ep_device_op if_configure --pcie-addr $ext_iface --down
	ep_remote_op if_configure --pcie-addr $remote_iface --down
	ep_device_op if_configure --pcie-addr $device_sdp_iface --down
	ep_host_op if_configure --pcie-addr $host_sdp_iface --down

	# Unbind the interfaces
	ep_device_op unbind_driver pci $device_sdp_iface
	ep_remote_op unbind_driver pci $remote_iface
	ep_device_op unbind_driver pci $ext_iface

	# Check output of ping
	if [[ "$ping_status" == "SUCCESS" ]]; then
		echo "Setup verified"
	else
		echo "Cannot ping remote from host"
		exit 1
	fi

}

function dao_ovs_setup()
{
	# Delete the existing ovs directory and copy the new one
	ep_device_ssh_cmd "$EP_DEVICE_SUDO rm -rf $EP_DEVICE_OVS_PATH"
	ep_device_ssh_cmd "mkdir -p $EP_DEVICE_OVS_PATH"
	ep_device_ssh_cmd "rsync -a $EP_DIR/ep_files/ovs/$OVS_VERSION/* $EP_DEVICE_OVS_PATH"

	if [[ -n $SKIP_SETUP ]]; then
		echo "Skip EP device setup"
		return
	fi

	echo "Copied OVS version: $OVS_VERSION"

	echo "Setting up EP device for ovs tests"
	ep_device_op hugepage_setup 524288 24 6

	echo "Setting up EP Host for ovs"
	ep_host_op sdp_setup

	ep_device_op_bg 10 agent_init

	echo "Verifying setup"
	verify_setup
}
