#!/bin/bash
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2024 Marvell.

set -euo pipefail

VIRTIO_UTILS_SCRIPT_PATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
source $VIRTIO_UTILS_SCRIPT_PATH/../../common/utils.sh
source $VIRTIO_UTILS_SCRIPT_PATH/../../common/ep_host_utils.sh
source $VIRTIO_UTILS_SCRIPT_PATH/../../common/ep_device_utils.sh
source $VIRTIO_UTILS_SCRIPT_PATH/../../common/testpmd.sh

find_executable "dao-virtio-extbuf" VIRTIO_EXTBUF "$VIRTIO_UTILS_SCRIPT_PATH/../../../../../tests"

function extbuf_host_check_pps()
{
	local pfx=$1
	local wait_time_sec=10

	while [[ wait_time_sec -ne 0 ]]; do
		local rx_pps=$(ep_host_op testpmd_pps $pfx 0)

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

function extbuf_host_start_traffic()
{
	local pfx=$1
	local num_cores
	local fwd_cores
	local eal_args
	local app_args

	num_cores=$(ep_host_ssh_cmd "nproc --all")
	fwd_cores=$((num_cores - 1))
	eal_args="-l 0-$fwd_cores --socket-mem 1024 --proc-type auto --file-prefix=$pfx --no-pci \
		  --vdev=net_virtio_user0,path=/dev/vhost-vdpa-0,mrg_rxbuf=1,packed_vq=1,in_order=1,queue_size=4096"
	app_args="--nb-cores=$fwd_cores --port-topology=loop --rxq=$fwd_cores --txq=$fwd_cores -i"

	echo "Starting Traffic on Host"
	ep_host_op_bg 10 testpmd_launch $pfx "$eal_args" -- "$app_args"
	ep_host_op testpmd_cmd $pfx start tx_first 32
	echo "Started Traffic on Host"
}

function extbuf_host_stop_traffic()
{
	local pfx=$1

	echo "Stopping Traffic on Host"
	ep_host_op testpmd_cmd $pfx stop
	ep_host_op testpmd_stop $pfx
	echo "Stopped Traffic no Host"
}

function extbuf_sig_handler()
{
	local status=$?
	local sig=$1
	local pfx=$2
	local tpmd_pfx=$3
	local dev_log=$4
	set +e
	trap - ERR
	trap - INT
	trap - QUIT
	trap - EXIT
	if [[ $status -ne 0 ]]; then
		echo "$sig Handler"
	fi

	if [ -f $dev_log ]; then
		cat $dev_log
	fi

	ep_host_op testpmd_log $tpmd_pfx
	safe_kill $pfx
	ep_host_op safe_kill $pfx
}

function extbuf_register_sig_handler()
{
	local pfx=$1
	local tpmd_pfx=$2
	local dev_log=$3

	# Register the traps
	trap "extbuf_sig_handler ERR $pfx $tpmd_pfx $dev_log" ERR
	trap "extbuf_sig_handler INT $pfx $tpmd_pfx $dev_log" INT
	trap "extbuf_sig_handler QUIT $pfx $tpmd_pfx $dev_log" QUIT
	trap "extbuf_sig_handler EXIT $pfx $tpmd_pfx $dev_log" EXIT
}

function extbuf_app_launch()
{
	local interface=$1
	local extbuf_pfx=$2
	local extbuf_out=$3
	local cores="$4"
	local app_args="$5"
	local dpi_vfs=$(ep_common_pcie_addr_get $PCI_DEVID_CN10K_RVU_DPI_VF 22)
	local eal_args=$(form_split_args "-a" $dpi_vfs)
	local args="-l $cores -a $interface $eal_args -- $app_args"
	local unbuffer

	unbuffer="$(command -v stdbuf) -o 0" || unbuffer=
	rm -rf $extbuf_out
	echo "VIRTIO_EXTBUF: $extbuf_pfx: Launching $VIRTIO_EXTBUF"
	echo "Args: '$args'"

	$unbuffer $VIRTIO_EXTBUF --file-prefix $extbuf_pfx $args &>$extbuf_out 2>&1 &

	# Wait for virtio_extbuf to be up
	local itr=0
	while ! (tail -n20 $extbuf_out | grep -q "VIRTIO_L2FWD_EXTBUF: Entering main loop on lcore"); do
		sleep 1
		itr=$((itr + 1))
		if [[ itr -eq 10 ]]; then
			echo "Timeout waiting for virtio-extbuf";
			cat $extbuf_out
			return 1;
		fi
		echo "Waiting for virtio-extbuf to be up"
	done
}

function extbuf_app_quit()
{
	local pfx=$1
	local log=$2

	cat $log

	# Issue kill SIGINT
	local pid=$(ps -ef | grep dao-virtio-extbuf | grep $pfx | awk '{print $2}' | xargs -n1 kill -2 2>/dev/null || true)

	# Wait until the process is killed
	local alive=$(ps -ef | grep dao-virtio-extbuf | grep $pfx || true)
	while [[ "$alive" != "" ]]; do
		sleep 1
		alive=$(ps -ef | grep dao-virtio-extbuf | grep $pfx || true)
		continue
	done
	rm -f $log
}
