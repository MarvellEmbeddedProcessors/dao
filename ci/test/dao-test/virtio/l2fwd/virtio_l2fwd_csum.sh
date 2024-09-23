#!/bin/bash
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2024 Marvell.

set -euo pipefail

L2FWD_1C_SCRIPT_PATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
source $L2FWD_1C_SCRIPT_PATH/virtio_l2fwd_utils.sh


# List-format "offload-name <csum> <mseg> <in_order>
virtio_offloads=(
		[0]="cksum 1 0 0" #CSUM_F
		)

function csum_host_start_traffic()
{
	local pfx=$1

	echo "Starting ports"
	ep_host_op testpmd_cmd $pfx set fwd csum
	ep_host_op testpmd_cmd $pfx start
	echo "Started traffic on Host"
}

failed_tests=""
function virtio_csum_offload_run()
{
	local pfx=$1
	local l2fwd_out=$2
	local ff=$3
	local tx_spcap=$4
	local cmp_script=$EP_DIR/ci/test/dao-test/common/scapy/validate_pcap.py
	local rpcap=/tmp/out.pcap
	local ref_pcap=$5
	local tpcap
	local itr=0
	local max_offloads=${#virtio_offloads[@]}
	((--max_offloads))


	local list=(${virtio_offloads[$itr]})
	echo -e "######################## ITERATION $itr" \
		"(virtio_offload = "$ff"_${list[0]})########################\n"

	tpcap=$tx_spcap

       # Start traffic
       l2fwd_host_launch_testpmd_with_pcap $pfx $tpcap $rpcap ${list[1]} ${list[2]} \
						${list[3]}

       # Wait for host to connect before traffic start
       l2fwd_host_connect_wait $l2fwd_out
       csum_host_start_traffic $pfx

       # Stop Traffic
       l2fwd_host_stop_traffic $pfx

       # validate packets
       l2fwd_host_validate_traffic $cmp_script $ref_pcap $rpcap
       local k=$?
       if [[ "$k" != "0" ]]; then
	       failed_tests="$failed_tests \""$ff"_${list[0]}\""
       fi
       return $k
}


function virtio_l2fwd_csum()
{
	local l2fwd_pfx=${DAO_TEST}
	local host_testpmd_pfx=${DAO_TEST}_testpmd_host
	local l2fwd_out=virtio_l2fwd.${l2fwd_pfx}.out
	local tx_spcap=$EP_DIR/ci/test/dao-test/virtio/l2fwd/pcap/csum_tx.pcap
	local ref_pcap=$EP_DIR/ci/test/dao-test/virtio/l2fwd/pcap/csum_expected.pcap
	local if0=$(ep_device_get_inactive_if)
	local k=0


	failed_tests=""
	l2fwd_register_sig_handler ${DAO_TEST} $host_testpmd_pfx $l2fwd_out

	ep_common_bind_driver pci $if0 vfio-pci

       # Launch virtio l2fwd
       if ! l2fwd_app_launch $if0 $l2fwd_pfx $l2fwd_out "4-7" \
	       "-p 0x1 -v 0x1 -P -l --enable-l4-csum"; then
	       echo "Failed to launch virtio l2fwd"

	       # Quit l2fwd app
	       l2fwd_app_quit $l2fwd_pfx $l2fwd_out
	       return 1
       fi

       ep_host_op vdpa_setup $(ep_device_get_part)

       virtio_csum_offload_run $host_testpmd_pfx $l2fwd_out "" $tx_spcap $ref_pcap
       local k=$?

       ep_host_op vdpa_cleanup
       # Quit l2fwd app
       l2fwd_app_quit $l2fwd_pfx $l2fwd_out

       return $k
}


test_run ${DAO_TEST} 2
