#!/bin/bash
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2024 Marvell.

set -euo pipefail

function host_sync()
{
	local sync="rsync -azzh --delete --inplace"

	if [[ -z $SYNC_WITH_NO_CLEANUP ]]; then
		echo "Cleanup EP host files"
		ep_host_ssh_cmd "$EP_HOST_SUDO rm -rf $EP_DIR"
	fi

	echo "Syncing EP host files"
	ep_host_ssh_cmd "mkdir -p $EP_DIR"
	ep_host_ssh_cmd "mkdir -p $EP_DIR/ep_files"
	$sync -e "$EP_SSH_CMD" -r $BUILD_HOST_DIR/* $EP_HOST:$EP_DIR
	$sync -e "$EP_SSH_CMD" -r $PROJECT_ROOT/ci $EP_HOST:$EP_DIR
	$sync -e "$EP_SSH_CMD" -r $EP_PREBUILT_BINARIES_SERVER:$EP_PREBUILT_BINARIES_PATH/* \
		/tmp/ep_files
	$sync -e "$EP_SSH_CMD" -r /tmp/ep_files/* $EP_HOST:$EP_DIR/ep_files
}

function device_sync()
{
	local sync="rsync -azzh --delete"

	if [[ -z $SYNC_WITH_NO_CLEANUP ]]; then
		echo "Cleanup EP device files"
		ep_device_ssh_cmd "$EP_DEVICE_SUDO rm -rf $EP_DIR"
	fi

	echo "Syncing EP device files"
	ep_device_ssh_cmd "mkdir -p $EP_DIR"
	$sync -e "$EP_SSH_CMD" -r $BUILD_DIR/* $EP_DEVICE:$EP_DIR
	$sync -e "$EP_SSH_CMD" -r $PROJECT_ROOT/ci $EP_DEVICE:$EP_DIR
	ep_device_ssh_cmd "mkdir -p $EP_DIR/deps-prefix"
	$sync -e "$EP_SSH_CMD" -r $DEPS_PREFIX/* $EP_DEVICE:$EP_DIR/deps-prefix
	$sync -e "$EP_SSH_CMD" -r $EP_PREBUILT_BINARIES_SERVER:$EP_PREBUILT_BINARIES_PATH/* \
		/tmp/ep_files
	# The device never consumes the remote RDMA bundle; excluding it avoids
	# filling the device's limited /tmp with the (possibly x86) binaries.
	$sync -e "$EP_SSH_CMD" -r --exclude='rdma_remote' /tmp/ep_files/* \
		$EP_DEVICE:$EP_DIR/ep_files
	ep_device_ssh_cmd "$EP_DEVICE_SUDO cp $EP_DIR/ep_files/hostname /usr/bin"
}

function remote_sync()
{
	local sync="rsync -azzh --delete"
	local plat
	local arch

	if [[ -z ${EP_REMOTE:-} ]]; then
		echo "EP_REMOTE is not set, skipping remote sync"
		return
	fi

	# DPU-to-DPU: the far side is an octep_rdma host, so provision it like
	# EP_HOST (host build incl. rdma_prefix + octep-rdma.ko) rather than the
	# legacy single-endpoint remote RDMA-core bundle.
	if [[ -n ${EP_REMOTE_DEVICE:-} ]]; then
		local hsync="rsync -azzh --delete --inplace"
		if [[ -z $SYNC_WITH_NO_CLEANUP ]]; then
			echo "Cleanup EP remote (far host) files"
			ep_remote_ssh_cmd "$EP_REMOTE_SUDO rm -rf $EP_DIR"
		fi
		echo "Syncing EP remote (far host) files (DPU-to-DPU, host-style)"
		ep_remote_ssh_cmd "mkdir -p $EP_DIR"
		ep_remote_ssh_cmd "mkdir -p $EP_DIR/ep_files"
		$hsync -e "$EP_SSH_CMD" -r $BUILD_HOST_DIR/* $EP_REMOTE:$EP_DIR
		$hsync -e "$EP_SSH_CMD" -r $PROJECT_ROOT/ci $EP_REMOTE:$EP_DIR
		$hsync -e "$EP_SSH_CMD" -r $EP_PREBUILT_BINARIES_SERVER:$EP_PREBUILT_BINARIES_PATH/* \
			/tmp/ep_files
		$hsync -e "$EP_SSH_CMD" -r /tmp/ep_files/* $EP_REMOTE:$EP_DIR/ep_files
		return
	fi

	if [[ -z $SYNC_WITH_NO_CLEANUP ]]; then
		echo "Cleanup EP remote files"
		ep_remote_ssh_cmd "$EP_REMOTE_SUDO rm -rf $EP_DIR"
	fi

	echo "Syncing EP remote files"
	ep_remote_ssh_cmd "mkdir -p $EP_DIR"
	$sync -e "$EP_SSH_CMD" -r $PROJECT_ROOT/ci $EP_REMOTE:$EP_DIR
	ep_remote_ssh_cmd "mkdir -p $EP_DIR/deps-prefix"
	$sync -e "$EP_SSH_CMD" -r $DEPS_PREFIX/* $EP_REMOTE:$EP_DIR/deps-prefix
	$sync -e "$EP_SSH_CMD" -r $EP_PREBUILT_BINARIES_SERVER:$EP_PREBUILT_BINARIES_PATH/* \
		/tmp/ep_files
	$sync -e "$EP_SSH_CMD" -r /tmp/ep_files/* $EP_REMOTE:$EP_DIR/ep_files

	arch=$(ep_remote_ssh_cmd "uname -m")

	if [[ "$arch" == "x86_64" ]]; then
		# The x86 host_files bundle (incl. dpdk-testpmd) may be absent for
		# RDMA-only remotes; only copy it when actually present.
		if [[ -e /tmp/ep_host_files/dpdk-testpmd ]]; then
			# Force the destination to be a directory. A prior run may have
			# left it as a single file (rsync of one entry into a missing
			# dest), which makes the cp below fail with ENOTDIR.
			ep_remote_ssh_cmd "$EP_REMOTE_SUDO rm -rf $EP_DIR/ep_host_files; mkdir -p $EP_DIR/ep_host_files"
			$sync -e "$EP_SSH_CMD" -r /tmp/ep_host_files/ $EP_REMOTE:$EP_DIR/ep_host_files/
			ep_remote_ssh_cmd "$EP_REMOTE_SUDO cp $EP_DIR/ep_host_files/dpdk-testpmd /usr/bin"
		fi
	else
		plat=$(ep_remote_ssh_cmd "$EP_REMOTE_SUDO cat /proc/device-tree/compatible | tr '\0' '\n'")
		if [[ "$plat" == *"cn10k"* ]]; then
			plat=cn10k
		else
			plat=cn9k
		fi
		ep_remote_ssh_cmd "$EP_REMOTE_SUDO cp $EP_DIR/ep_files/perf/$plat/dpdk-testpmd /usr/bin"
	fi
}

function remote_device_sync()
{
	local sync="rsync -azzh --delete"

	if [[ -z ${EP_REMOTE_DEVICE:-} ]]; then
		echo "EP_REMOTE_DEVICE is not set, skipping remote device sync"
		return
	fi

	if [[ -z $SYNC_WITH_NO_CLEANUP ]]; then
		echo "Cleanup EP remote device files"
		ep_remote_device_ssh_cmd "$EP_REMOTE_DEVICE_SUDO rm -rf $EP_DIR"
	fi

	echo "Syncing EP remote device files"
	ep_remote_device_ssh_cmd "mkdir -p $EP_DIR"
	$sync -e "$EP_SSH_CMD" -r $BUILD_DIR/* $EP_REMOTE_DEVICE:$EP_DIR
	$sync -e "$EP_SSH_CMD" -r $PROJECT_ROOT/ci $EP_REMOTE_DEVICE:$EP_DIR
	ep_remote_device_ssh_cmd "mkdir -p $EP_DIR/deps-prefix"
	$sync -e "$EP_SSH_CMD" -r $DEPS_PREFIX/* $EP_REMOTE_DEVICE:$EP_DIR/deps-prefix
	$sync -e "$EP_SSH_CMD" -r $EP_PREBUILT_BINARIES_SERVER:$EP_PREBUILT_BINARIES_PATH/* \
		/tmp/ep_files
	# The device never consumes the remote RDMA bundle; exclude it as in
	# device_sync.
	$sync -e "$EP_SSH_CMD" -r --exclude='rdma_remote' /tmp/ep_files/* \
		$EP_REMOTE_DEVICE:$EP_DIR/ep_files
	ep_remote_device_ssh_cmd "$EP_REMOTE_DEVICE_SUDO cp $EP_DIR/ep_files/hostname /usr/bin"
}
