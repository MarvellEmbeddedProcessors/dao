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
	local l2fwd_out=virtio_l2fwd.${l2fwd_pfx}.out
	local if0=$(ep_device_get_inactive_if)

	ep_device_vfio_bind $if0

	# Launch virtio l2fwd
	if ! l2fwd_app_launch $if0 $l2fwd_pfx $l2fwd_out "4-7" "-p 0x1 -v 0x1 -P -l"; then
		echo "Failed to launch virtio l2fwd"
		return 1
	fi

	# Start traffic
	l2fwd_host_start_traffic $host_testpmd_pfx

	# Check the performance
	l2fwd_host_check_pps $host_testpmd_pfx
	local k=$?

	# Stop Traffic and quit host testpmd
	l2fwd_host_stop_traffic $host_testpmd_pfx

	# Quit l2fwd app
	l2fwd_app_quit $l2fwd_pfx
	return $k
}

l2fwd_register_sig_handler ${DAO_TEST}
test_run ${DAO_TEST} 2
