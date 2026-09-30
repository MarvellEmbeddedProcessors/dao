#!/bin/bash
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2025 Marvell.

function rdma_pingpong_bidir()
{
	local binary=$1
	local label=$2
	local server_cmd client_cmd

	echo "$binary ($label): EP_HOST as Server -> EP_REMOTE_HOST as Client"
	server_cmd="bash -c \"${host_env} setsid $binary -g $host_gid_idx -d $host_rdma_dev -i 1 >/dev/null 2>&1 &\""
	client_cmd="bash -c \"${remote_host_env} $binary -g $remote_host_gid_idx -d $remote_host_rdma_dev -i 1 $host_ip\""
	ep_host_ssh_cmd "$server_cmd"
	sleep 1
	if ! $remote_host_ssh "$client_cmd"; then
		echo "$binary ($label): EP_HOST-server direction FAILED"
		return 1
	fi

	echo "$binary ($label): EP_REMOTE_HOST as Server -> EP_HOST as Client"
	server_cmd="bash -c \"${remote_host_env} setsid $binary -g $remote_host_gid_idx -d $remote_host_rdma_dev -i 1 >/dev/null 2>&1 &\""
	client_cmd="bash -c \"${host_env} $binary -g $host_gid_idx -d $host_rdma_dev -i 1 $remote_host_ip\""
	$remote_host_ssh "$server_cmd"
	sleep 1
	if ! ep_host_ssh_cmd "$client_cmd"; then
		echo "$binary ($label): EP_REMOTE_HOST-server direction FAILED"
		return 1
	fi

	echo "$binary ($label): PASSED (both directions)"
	return 0
}
