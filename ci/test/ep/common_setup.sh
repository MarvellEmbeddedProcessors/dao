#!/bin/bash
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2024 Marvell.

set -euo pipefail

EP_REMOTE_IFACE=${EP_REMOTE_IFACE:-}
EP_DEVICE_EXT_IFACE=${EP_DEVICE_EXT_IFACE:-}

function populate_ep_interfaces()
{
	local ssh_ip=$(echo $EP_DEVICE | awk -F '\@' '{print $2}' 2>/dev/null)
	local remote_ssh_ip=$(echo $EP_REMOTE | awk -F '\@' '{print $2}' 2>/dev/null)
	local eth_ifaces=$(ep_device_op eth_interfaces_get $ssh_ip)
	local remote_eth_ifaces=$(ep_remote_op eth_interfaces_get $remote_ssh_ip)
	local remote_ip=20.0.0.51
	local device_ip=20.0.0.52
	local remote_iface
	local ext_iface

	echo "Device eth interfaces: $eth_ifaces"
	echo "Remote eth interfaces: $remote_eth_ifaces"

	for e in $eth_ifaces; do
		ep_device_op unbind_driver pci $e
	done
	for re in $remote_eth_ifaces; do
		ep_remote_op unbind_driver pci $re
	done

	# Configure the interfaces one by one and check which ones are pinging
	for e in $eth_ifaces; do
		ep_device_op bind_driver pci $e rvu_nicpf
		ep_device_op if_configure --pcie-addr $e --ip $device_ip
		for re in $remote_eth_ifaces; do
			ep_remote_op bind_driver pci $re rvu_nicpf
			ep_remote_op if_configure --pcie-addr $re --ip $remote_ip
			echo "Checking $e (Device) <-> $re (Remote)"
			if [[ $(ep_device_op ping $device_ip $remote_ip 2) == "SUCCESS" ]]; then
				ext_iface=$e
				remote_iface=$re
				break
			fi
			ep_remote_op if_configure --pcie-addr $re --down
			ep_remote_op unbind_driver pci $re
		done
		if [[ -n $ext_iface ]]; then
			break
		fi
		ep_device_op if_configure --pcie-addr $e --down
		ep_device_op unbind_driver pci $e
	done

	add_test_env EP_REMOTE_IFACE=$remote_iface
	add_test_env EP_DEVICE_EXT_IFACE=$ext_iface

	EP_REMOTE_IFACE=$remote_iface
	EP_DEVICE_EXT_IFACE=$ext_iface
}
