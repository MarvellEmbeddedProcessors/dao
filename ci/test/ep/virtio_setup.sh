#!/bin/bash
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2024 Marvell.

set -euo pipefail

DAO_SUITE_SETUP["dao-virtio"]=dao_virtio_setup
DAO_SUITE_CLEANUP["dao-virtio"]=dao_virtio_cleanup

function dao_virtio_cleanup()
{
	local device_part

	if [[ -n $SKIP_SETUP ]]; then
		echo "Skip EP VDPA cleanup on host"
	else
		device_part=$(ep_device_op get_part)
		echo "Cleaning up VDPA on host"
		ep_host_op vdpa_cleanup $device_part
	fi

	ep_host_op safe_kill $EP_DIR
	ep_device_op safe_kill $EP_DIR
	ep_host_ssh_cmd "$EP_HOST_SUDO dmesg" > host_dmesg.log
	save_log host_dmesg.log
	ep_device_ssh_cmd "$EP_DEVICE_SUDO dmesg" > device_dmesg.log
	save_log device_dmesg.log
}

function dao_virtio_setup()
{
	local device_part

	if [[ -n $SKIP_SETUP ]]; then
		echo "Skip setup"
		return
	fi

	echo "Setting up EP device for virtio tests"
	ep_device_op hugepage_setup 524288 24 6
	ep_device_op dpi_setup
	ep_device_op pem_setup

	echo "Setting up EP Host for virtio tests"
	device_part=$(ep_device_op get_part)
	ep_host_op hugepage_setup 2048 24 2048

	if [[ -n $EP_REMOTE ]]; then
		populate_ep_interfaces
		if [[ -z ${EP_REMOTE_IFACE:-} ]] || [[ -z ${EP_DEVICE_EXT_IFACE:-} ]]; then
			echo "Failed to find a valid pair of interfaces"
			return
		fi

		ep_remote_op if_configure --pcie-addr $EP_REMOTE_IFACE --down
		ep_remote_op unbind_driver pci $EP_REMOTE_IFACE
		ep_device_op if_configure --pcie-addr $EP_DEVICE_EXT_IFACE --down
		ep_device_op unbind_driver pci $EP_DEVICE_EXT_IFACE

		echo "Setting up EP remote for virtio tests"
		ep_remote_op hugepage_setup 524288 24 6
	fi
}
