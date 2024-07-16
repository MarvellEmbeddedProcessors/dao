#!/bin/bash
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2024 Marvell.

set -euo pipefail

L2FWD_1C_SCRIPT_PATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
source $L2FWD_1C_SCRIPT_PATH/virtio_l2fwd_utils.sh

# List-format "offload-name <csum> <mseg> <in_order>
virtio_offloads=(
		[0]="None 0 0 1" #None No-Offload
		[1]="mseg 0 1 1" #MSEG_F
		[2]="cksum 1 0 1" #CSUM_F
		[3]="mseg_cksum 1 1 1" #MSEG_F | CSUM_F
		[4]="noinorder 0 0 0" #D_NOORDER_F
		[5]="noinorder_mseg 0 1 0" #D_NOORDER_F | MSEG_F
		[6]="noinorder_cksum 1 0 0" #D_NOORDER_F | CSUM_F
		[7]="noinorder_mseg_cksum 1 1 0" #D_NOORDER_F | MSEG_F | CSUM_F
		)

function virtio_l2fwd_1c()
{
	local l2fwd_pfx=${DAO_TEST}
	local host_testpmd_pfx=${DAO_TEST}_testpmd_host
	local l2fwd_out=virtio_l2fwd.${l2fwd_pfx}.out
	local if0=$(ep_device_get_inactive_if)

	l2fwd_register_sig_handler ${DAO_TEST} $host_testpmd_pfx $l2fwd_out

	ep_device_vfio_bind $if0

	# Launch virtio l2fwd
	if ! l2fwd_app_launch $if0 $l2fwd_pfx $l2fwd_out "4-7" "-p 0x1 -v 0x1 -P -l"; then
		echo "Failed to launch virtio l2fwd"

		# Quit l2fwd app
		l2fwd_app_quit $l2fwd_pfx $l2fwd_out
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
	l2fwd_app_quit $l2fwd_pfx $l2fwd_out
	return $k
}

failed_tests=""
function virtio_l2fwd_offload_run()
{
	local pfx=$1
	local l2fwd_out=$2
	local ff=$3
	local tx_spcap=$4
	local tx_mpcap=$5
	local cmp_script=$EP_HOST_DIR/ci/test/dao-test/common/scapy/validate_pcap.py
	local rpcap=/tmp/rx_multiseg.pcap
	local tpcap
	local itr=0
	local max_offloads=${#virtio_offloads[@]}
	((--max_offloads))

	while [ $itr -le $max_offloads ]
	do

		local list=(${virtio_offloads[$itr]})
		echo -e "######################## ITERATION $itr" \
			"(virtio_offload = "$ff"_${list[0]})########################\n"

		#TODO: CSUM support
		if [[ ${list[1]} -eq 1 ]]; then
			((++itr))
			continue
		fi

		if [[ ${list[2]} -eq 1 ]]; then
			tpcap=$tx_mpcap
		else
			tpcap=$tx_spcap
		fi

		# Start traffic
		l2fwd_host_launch_testpmd_with_pcap $pfx $tpcap $rpcap ${list[1]} ${list[2]} \
							${list[3]}

		# Wait for host to connect before traffic start
		l2fwd_host_connect_wait $l2fwd_out
		l2fwd_host_start_traffic_with_pcap $pfx

		# Stop Traffic
		l2fwd_host_stop_traffic $pfx

		# validate packets
		l2fwd_host_validate_traffic $cmp_script $tpcap $rpcap
		local k=$?
		if [[ "$k" != "0" ]]; then
			failed_tests="$failed_tests \""$ff"_${list[0]}\""
		fi
		((++itr))
	done
	return 0
}

function virtio_l2fwd_multiseg()
{
	local l2fwd_pfx=${DAO_TEST}
	local host_testpmd_pfx=${DAO_TEST}_testpmd_host
	local l2fwd_out=virtio_l2fwd.${l2fwd_pfx}.out
	local tx_mpcap=$EP_HOST_DIR/ci/test/dao-test/virtio_l2fwd/pcap/tx_mseg.pcap
	local tx_spcap=$EP_HOST_DIR/ci/test/dao-test/virtio_l2fwd/pcap/tx.pcap
	local if0=$(ep_device_get_inactive_if)
	local k=0

	failed_tests=""
	l2fwd_register_sig_handler ${DAO_TEST} $host_testpmd_pfx $l2fwd_out

	ep_device_vfio_bind $if0

	# Launch virtio l2fwd
	if ! l2fwd_app_launch $if0 $l2fwd_pfx $l2fwd_out "4-7" "-p 0x1 -v 0x1 -P -l --max-pkt-len=9200"; then
		echo "Failed to launch virtio l2fwd"

		# Quit l2fwd app
		l2fwd_app_quit $l2fwd_pfx $l2fwd_out
		return 1
	fi

	virtio_l2fwd_offload_run $host_testpmd_pfx $l2fwd_out "" $tx_spcap $tx_mpcap

	# Quit l2fwd app
	l2fwd_app_quit $l2fwd_pfx $l2fwd_out

	sleep 1

	# No fastfree cases
	# Launch virtio l2fwd with no fast free option
	if ! l2fwd_app_launch $if0 $l2fwd_pfx $l2fwd_out "4-7" "-p 0x1 -v 0x1 -P -l --max-pkt-len=9200 -f"; then
		echo "Failed to launch virtio l2fwd with No fastfree"
	else
		virtio_l2fwd_offload_run $host_testpmd_pfx $l2fwd_out "no_ff" $tx_spcap $tx_mpcap
	fi

	# Quit l2fwd app
	l2fwd_app_quit $l2fwd_pfx $l2fwd_out

	echo ""
	if [[ -n $failed_tests ]]; then
		echo "FAILURE: Test(s) [$failed_tests] failed"
		k=1
	fi

	return $k
}

test_run ${DAO_TEST} 2