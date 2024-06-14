#!/bin/bash
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2024 Marvell.

set -euo pipefail

L2FWD_1C_SCRIPT_PATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
source $L2FWD_1C_SCRIPT_PATH/virtio_l2fwd_utils.sh

function virtio_l2fwd_1c()
{
	local l2fwd_pfx=${DAO_TEST}
	local host_testpmd_pfx=${DAO_TEST}_testpmd_host
	local dev_testpmd_pfx=${DAO_TEST}_testpmd_dev
	local l2fwd_out=virtio_l2fwd.${l2fwd_pfx}.out
	local if0="0002:01:00.1"
	local if1="0002:01:00.2"

	ep_device_vfio_bind $if0 $if1

	# Launch virtio l2fwd
	if ! l2fwd_app_launch $if1 $l2fwd_pfx $l2fwd_out "4-7" "-p 0x1 -v 0x1 -P"; then
		echo "Failed to launch virtio l2fwd"
		return 1
	fi

	# Start traffic
	l2fwd_host_start_traffic $host_testpmd_pfx
	l2fwd_device_start_traffic $dev_testpmd_pfx $if0

	# Check the performance
	l2fwd_device_check_pps $dev_testpmd_pfx
	local k=$?

	# Stop Traffic
	l2fwd_host_stop_traffic $host_testpmd_pfx
	l2fwd_device_stop_traffic $dev_testpmd_pfx

	return $k
}

l2fwd_register_sig_handler ${DAO_TEST}
test_run ${DAO_TEST} 2
