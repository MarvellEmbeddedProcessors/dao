#!/bin/bash
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2024 Marvell.

set -euo pipefail

OVS_PING_SCRIPT_PATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
source $OVS_PING_SCRIPT_PATH/ovs_utils.sh

function ovs_ping()
{
	local test_type=$1
	local hw_offload=$2
	local eth_pf_ifcs
	local sdp_eth_vf_pairs
	local esw_vf_ifcs
	local num_eth_ifcs=1
	local num_sdp_ifcs_per_eth=2
	local num_esw_ifcs=1
	local ovs_debug=1
	local ssh_ip=$(echo $EP_DEVICE  | awk -F '\@' '{print $2}' 2>/dev/null)
	local host_ip="20.0.0.10"
	local remote_ip="20.0.0.20"
	local extra_args_interface_setup=
	local extra_args_remote_ifconfig=
	local vxlan_local_ip="30.0.0.2"
	local vxlan_remote_ip="30.0.0.254"
	local vxlan_subnet="30.0.0.0"
	local vxlan_vni=5001
	local vlan_id=100

	if [[ $test_type == "vlan" ]]; then
		extra_args_interface_setup="--vlan-id $vlan_id"
		extra_args_remote_ifconfig="--vlan-id $vlan_id"
	elif [[ $test_type == "vxlan" ]]; then
		extra_args_interface_setup="--vxlan-vni $vxlan_vni --vxlan-subnet $vxlan_subnet"
		extra_args_remote_ifconfig="--vxlan-vni $vxlan_vni \
			--vxlan-remote-ip $vxlan_remote_ip --vxlan-local-ip $vxlan_local_ip"
	fi

	# Register signal handler
	ovs_register_sig_handler

	# Get eth interfaces on device
	eth_pf_ifcs=$(ep_device_eth_interfaces_get $ssh_ip $num_eth_ifcs)

	echo "Setting up SDP"
	sdp_eth_vf_pairs=$(ep_device_sdp_setup \
				$(form_split_args "--eth-ifc" "$eth_pf_ifcs") \
				--num-sdp-ifcs-per-eth $num_sdp_ifcs_per_eth)

	echo "Setting up ESW"
	esw_vf_ifcs=$(ep_device_esw_setup $num_esw_ifcs)

	echo "Launching OVS"
	ovs_launch \
		$(form_split_args "--eth-ifc" $eth_pf_ifcs) \
		--hw-offload $hw_offload \
		--debug $ovs_debug

	echo "Setting up OVS interfaces"
	ovs_interface_setup \
		$(form_split_args "--eth-ifc" "$eth_pf_ifcs") \
		--num-sdp-ifcs-per-eth $num_sdp_ifcs_per_eth \
		$extra_args_interface_setup

	echo "Running OVS offload"
	ovs_offload_launch \
		$(form_split_args "--esw-vf-ifc" "$esw_vf_ifcs") \
		$(form_split_args "--sdp-eth-vf-pair" "$sdp_eth_vf_pairs")

	echo "Configure SDP interface on host"
	ep_host_op if_configure --pcie-addr $EP_HOST_SDP_IFACE --ip $host_ip

	echo "Configure remote interface"
	ep_remote_op bind_driver pci $EP_REMOTE_IFACE rvu_nicpf
	ep_remote_op if_configure --pcie-addr $EP_REMOTE_IFACE \
		--ip $remote_ip $extra_args_remote_ifconfig

	if [[ $(ep_host_op ping $host_ip $remote_ip) != "SUCCESS" ]]; then
		echo "Ping Failed"
		exit 1
	else
		echo "Ping Passed"
	fi
}

function ovs_plain_ping()
{
	ovs_ping plain false
}

function ovs_vlan_ping()
{
	ovs_ping vlan false
}

function ovs_vxlan_ping()
{
	ovs_ping vxlan false
}

function ovs_plain_ping_hw_offload()
{
	ovs_ping plain true
}

function ovs_vlan_ping_hw_offload()
{
	ovs_ping vlan true
}

function ovs_vxlan_ping_hw_offload()
{
	ovs_ping vxlan true
}

test_run ${DAO_TEST} 2
