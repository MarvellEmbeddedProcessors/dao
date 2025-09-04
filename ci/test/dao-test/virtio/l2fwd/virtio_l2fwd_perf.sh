#!/bin/bash
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2024 Marvell.

set -euo pipefail

L2FWD_PERF_SCRIPT_PATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
source $L2FWD_PERF_SCRIPT_PATH/virtio_l2fwd_utils.sh
TOLERANCE=${TOLERANCE:-3}

perf_tests=(
	[0]="3C 2-5" #3 cores 1+1+1
	[1]="5C 2-7" #5 cores 1+2+2
)

function virtio_l2fwd_perf()
{
	local l2fwd_pfx=${DAO_TEST}
	local host_testpmd_pfx=${DAO_TEST}_testpmd_host
	local remote_testpmd_pfx=${DAO_TEST}_testpmd_remote
	local l2fwd_out=virtio_l2fwd.${l2fwd_pfx}.out
	local rclk=$(ep_device_get_rclk)
	local sclk=$(ep_device_get_sclk)
	local if0=${EP_DEVICE_EXT_IFACE:-}
	local re_if0=${EP_REMOTE_IFACE:-}
	local tests=(${#perf_tests[@]})
	local failed_tests=""
	local pass_pps
	local ref_pps
	local itr=0
	local k=1

	if [[ -z ${EP_REMOTE:-} ]]; then
		echo "EP_REMOTE is not set, skipping perf test"
		return 1
	fi

	if [[ -z $if0 ]] || [[ -z $re_if0 ]]; then
		echo "Failed to find a valid interface pair"
		return 1
	fi

	echo "RCLK:   $rclk Mhz"
	echo "SCLK:   $sclk Mhz"

	echo "Remote interface $re_if0"
	echo "Device interface $if0"

	# Bind interfaces
	ep_remote_op bind_driver pci $re_if0 vfio-pci
	ep_common_bind_driver pci $if0 vfio-pci

	l2fwd_register_sig_handler ${DAO_TEST} $host_testpmd_pfx $l2fwd_out

	((--tests))
	while [ $itr -le $tests ]
	do

		local list=(${perf_tests[$itr]})
		echo -e "######################## ITERATION $itr" \
			"("${DAO_TEST}"_${list[0]})########################\n"

		# Launch virtio l2fwd
		if ! l2fwd_app_launch $if0 $l2fwd_pfx $l2fwd_out "${list[1]}" "-p 0x1 -v 0x1 -P"; then
			echo "Failed to launch virtio l2fwd"

			# Quit l2fwd app
			l2fwd_app_quit $l2fwd_pfx $l2fwd_out

			((++itr))
			continue
		fi
		ep_host_op vdpa_setup $(ep_device_get_part)

		# Start traffic
		l2fwd_host_start_rx_traffic $host_testpmd_pfx
		l2fwd_remote_start_traffic $remote_testpmd_pfx $re_if0

		sleep 3

		# Check the performance
		ref_pps=$(l2fwd_device_ref_pps l2fwd "${DAO_TEST}"_${list[0]})
		pass_pps=$(l2fwd_device_expected_pps $ref_pps $TOLERANCE)
		l2fwd_remote_validate_perf_pps $remote_testpmd_pfx $ref_pps $pass_pps
		k=$?
		if [[ "$k" != "0" ]]; then
			failed_tests="$failed_tests \""${DAO_TEST}"_${list[0]}\""
		fi

		# Stop traffic and quit host testpmd
		l2fwd_remote_stop_traffic $remote_testpmd_pfx $re_if0
		l2fwd_host_stop_traffic $host_testpmd_pfx

		ep_host_op vdpa_cleanup
		# Quit l2fwd app
		l2fwd_app_quit $l2fwd_pfx $l2fwd_out

		((++itr))
	done

	# Unbind interfaces
	ep_remote_op unbind_driver pci $re_if0
	ep_common_unbind_driver pci $if0

	echo ""
	if [[ -n $failed_tests ]]; then
		echo "FAILURE: Test(s) [$failed_tests] failed"
		k=1
	fi

	return $k
}

test_run ${DAO_TEST} 2
