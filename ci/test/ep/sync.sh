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
	$sync -e "$EP_SSH_CMD" -r /tmp/ep_files/* $EP_DEVICE:$EP_DIR/ep_files
	ep_device_ssh_cmd "$EP_DEVICE_SUDO cp $EP_DIR/ep_files/hostname /usr/bin"
}

function remote_sync()
{
	local sync="rsync -azzh --delete"
	local plat

	if [[ -z ${EP_REMOTE:-} ]]; then
		echo "EP_REMOTE is not set, skipping remote sync"
		return
	fi

	if [[ -z $SYNC_WITH_NO_CLEANUP ]]; then
		echo "Cleanup EP remote files"
		ep_remote_ssh_cmd "$EP_REMOTE_SUDO rm -rf $EP_DIR"
	fi

	echo "Syncing EP remote files"
	ep_remote_ssh_cmd "mkdir -p $EP_DIR"
	$sync -e "$EP_SSH_CMD" -r $PROJECT_ROOT/ci $EP_REMOTE:$EP_DIR
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
