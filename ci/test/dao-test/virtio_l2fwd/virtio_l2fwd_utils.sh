#!/bin/bash
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2024 Marvell.

set -euo pipefail

VIRTIO_UTILS_SCRIPT_PATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
source $VIRTIO_UTILS_SCRIPT_PATH/../common/utils.sh
source $VIRTIO_UTILS_SCRIPT_PATH/../common/ep_host_utils.sh
source $VIRTIO_UTILS_SCRIPT_PATH/../common/ep_device_utils.sh
source $VIRTIO_UTILS_SCRIPT_PATH/../common/testpmd.sh

find_executable "dao-virtio-l2fwd" VIRTIO_L2FWD "$VIRTIO_UTILS_SCRIPT_PATH/../../../../app"

function l2fwd_device_start_traffic()
{
	local pfx=$1
	local if0=$2

	echo "Starting traffic on device"
	testpmd_launch "$pfx" "-l 1-3 -a $if0 " \
	       "--no-flush-rx --forward-mode=io --rxq 1 --txq 1"
	testpmd_cmd "$pfx" "start tx_first"
	echo "Started traffic on device"
}

function l2fwd_device_stop_traffic()
{
	local pfx=$1

	echo "Stopping traffic on device"
	testpmd_cmd "$pfx" "stop"
	testpmd_quit "$pfx"
	testpmd_cleanup "$pfx"
	echo "Stopped traffic on device"
}

function l2fwd_device_check_pps()
{
	local pfx=$1
	local wait_time_sec=10

	while [[ wait_time_sec -ne 0 ]]
	do
		rx_pps=$(testpmd_pps $pfx 0)

		if [[ rx_pps -eq 0 ]]; then
			echo "Low PPS for ${pfx} ($rx_pps == 0)"
		else
			echo "Rx PPS $rx_pps as expected"
			return 0
		fi

		sleep 1
		wait_time_sec=$((wait_time_sec - 1))
	done

	return 1
}

function l2fwd_device_cleanup()
{
	local pfx=$1

	echo "Cleaning up device"
	# Issue kill
	ps -ef | grep dao-virtio-l2fwd | grep $pfx | \
		awk '{print $2}' | xargs -I[] -n1 sudo kill -2 [] 2>/dev/null || true
	# Issue kill
	ps -ef | grep dpdk-testpmd | grep $pfx | \
		awk '{print $2}' | xargs -I[] -n1 sudo kill -2 [] 2>/dev/null || true
	echo "Cleaned up device"
}

function l2fwd_host_cleanup()
{
	echo "Cleaning up host"
	ep_host_ssh_cmd "sudo killall -9 dpdk-testpmd"
	echo "Cleaned up host"
}

function l2fwd_sig_handler()
{
	local status=$?
	local sig=$1
	local pfx=$2
	set +e
	trap - ERR
	trap - INT
	trap - QUIT
	trap - EXIT
	if [[ $status -ne 0 ]]; then
		echo "$sig Handler"
	fi

	l2fwd_device_cleanup $pfx
	l2fwd_host_cleanup $pfx
}

function l2fwd_register_sig_handler()
{
	local pfx=$1

	# Register the traps
	trap "l2fwd_sig_handler ERR $pfx" ERR
	trap "l2fwd_sig_handler INT $pfx" INT
	trap "l2fwd_sig_handler QUIT $pfx" QUIT
	trap "l2fwd_sig_handler EXIT $pfx" EXIT
}

