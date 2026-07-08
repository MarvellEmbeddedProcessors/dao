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
	# Remove any stale (possibly multi-GB) dao-rdma_graph log from a previous
	# run before the rsync below, so it cannot fill the DPU rootfs and fail
	# the sync. The log is intentionally preserved after a run (including
	# failures) for debugging; it is only cleared here when a new run starts.
	ep_device_ssh_cmd "$EP_DEVICE_SUDO rm -f /tmp/dao_rdma_graph.log" 2>/dev/null || true
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
	local hsync="rsync -azzh --delete --inplace"
	local plat arch

	if [[ -z ${EP_REMOTE:-} ]]; then
		echo "EP_REMOTE is not set, skipping remote sync"
		return
	fi

	if [[ -z $SYNC_WITH_NO_CLEANUP ]]; then
		echo "Cleanup EP remote files"
		ep_remote_ssh_cmd "$EP_REMOTE_SUDO rm -rf $EP_DIR"
	fi

	arch=$(ep_remote_ssh_cmd "uname -m" 2>/dev/null | tr -d '[:space:]')

	# EP_REMOTE is an x86 host in both RDMA topologies (Mellanox native-RoCE
	# host or the DPU-to-DPU far octep_rdma host). Provision it exactly like
	# EP_HOST from the freshly built host artifacts (rdma_prefix with all
	# providers, perftest, octep-rdma.ko), so binaries are rebuilt every run
	# instead of pulling a static bundle from EP_PREBUILT_BINARIES_SERVER.
	if [[ -n ${EP_REMOTE_DEVICE:-} || "$arch" == "x86_64" ]]; then
		echo "Syncing EP remote files (host-style, fresh x86 build)"
		ep_remote_ssh_cmd "mkdir -p $EP_DIR"
		$hsync -e "$EP_SSH_CMD" -r $BUILD_HOST_DIR/* $EP_REMOTE:$EP_DIR
		$hsync -e "$EP_SSH_CMD" -r $PROJECT_ROOT/ci $EP_REMOTE:$EP_DIR
		return
	fi

	# Legacy aarch64 remote (non-RDMA suites / soft-RoCE Octeon remote).
	echo "Syncing EP remote files"
	ep_remote_ssh_cmd "mkdir -p $EP_DIR"
	$sync -e "$EP_SSH_CMD" -r $PROJECT_ROOT/ci $EP_REMOTE:$EP_DIR
	ep_remote_ssh_cmd "mkdir -p $EP_DIR/deps-prefix"
	$sync -e "$EP_SSH_CMD" -r $DEPS_PREFIX/* $EP_REMOTE:$EP_DIR/deps-prefix
	$sync -e "$EP_SSH_CMD" -r $EP_PREBUILT_BINARIES_SERVER:$EP_PREBUILT_BINARIES_PATH/* \
		/tmp/ep_files
	$sync -e "$EP_SSH_CMD" -r /tmp/ep_files/* $EP_REMOTE:$EP_DIR/ep_files

	plat=$(ep_remote_ssh_cmd "$EP_REMOTE_SUDO cat /proc/device-tree/compatible | tr '\0' '\n'")
	if [[ "$plat" == *"cn10k"* ]]; then
		plat=cn10k
	else
		plat=cn9k
	fi
	ep_remote_ssh_cmd "$EP_REMOTE_SUDO cp $EP_DIR/ep_files/perf/$plat/dpdk-testpmd /usr/bin"
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
	# Remove any stale (possibly multi-GB) dao-rdma_graph log from a previous
	# run before the rsync below, so it cannot fill the DPU rootfs and fail
	# the sync. The log is intentionally preserved after a run (including
	# failures) for debugging; it is only cleared here when a new run starts.
	ep_remote_device_ssh_cmd "$EP_REMOTE_DEVICE_SUDO rm -f /tmp/dao_rdma_graph.log" 2>/dev/null || true
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
