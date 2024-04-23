#!/bin/bash
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2024 Marvell.

set -euo pipefail

L2FWD_1C_SCRIPT_PATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
source $L2FWD_1C_SCRIPT_PATH/virtio_l2fwd_utils.sh

function virtio_l2fwd_1c()
{
	local dev_pfx=virtio_l2fwd_1c
	local host_testpmd_pfx=virtio_l2fwd_1c_testpmd_host
	local dev_testpmd_pfx=virtio_l2fwd_1c_testpmd_dev
	local args="-p 0x1 -v 0x1 -P"
	local ep_device_out=ep_device.${dev_pfx}.out
	local unbuffer
	local cores="4-7"
	local eal_args="
		-a 0000:06:00.1 -a 0000:06:00.2 -a 0000:06:00.3 -a 0000:06:00.4
		-a 0000:06:00.5 -a 0000:06:00.6 -a 0000:06:00.7 -a 0000:06:01.0
		-a 0000:06:01.1 -a 0000:06:01.2 -a 0000:06:01.3 -a 0000:06:01.4
		-a 0000:06:01.5 -a 0000:06:01.6 -a 0000:06:01.7 -a 0000:06:02.0
		-a 0000:06:02.1 -a 0000:06:02.2 -a 0000:06:02.3 -a 0000:06:02.4
		-a 0000:06:02.5 -a 0000:06:02.6
	"
	local if0="0002:01:00.1"
	local if1="0002:01:00.2"

	ep_device_vfio_bind $if0 $if1

	rm -rf $ep_device_out
	touch $ep_device_out
	unbuffer="$(command -v stdbuf) -o 0" || unbuffer=

	echo "VIRTIO_L2FWD: $dev_pfx: Launching dao-virtio-l2fwd"
	echo "Args: '-l $cores -a $if1 $eal_args -- $args'"

	$unbuffer $VIRTIO_L2FWD --file-prefix $dev_pfx \
		-l $cores -a $if1 $eal_args -- \
		$args &>$ep_device_out 2>&1 &

	# Wait for virtio_l2fwd to be up
	local itr=0
	while ! (tail -n20 $ep_device_out | grep -q "VIRTIO_L2FWD: Entering graph main loop"); do
		sleep 1
		itr=$((itr + 1))
		if [[ itr -eq 10 ]]; then
			echo "Timeout waiting for virtio-l2fwd";
			exit 1;
		fi
		echo "Waiting for virtio-l2fwd to be up"
	done

	# Start traffic
	ep_host_op_bg 10 start_traffic $host_testpmd_pfx
	l2fwd_device_start_traffic $dev_testpmd_pfx $if0

	# Check the performance
	l2fwd_device_check_pps $dev_testpmd_pfx
	local k=$?

	# Stop Traffic
	ep_host_op stop_traffic $host_testpmd_pfx
	l2fwd_device_stop_traffic $dev_testpmd_pfx

	return $k
}

l2fwd_register_sig_handler virtio_l2fwd_1c
test_run virtio_l2fwd_1c 2
