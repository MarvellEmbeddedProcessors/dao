#!/bin/bash
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2025 Marvell.
set -e

RDMA_UTILS_SCRIPT_PATH="$( cd -- "$(dirname "$BASH_SOURCE[0]")" >/dev/null 2>&1 ; pwd -P )"
source $EP_DIR/ci/test/dao-test/common/utils.sh
source $EP_DIR/ci/test/dao-test/common/ep_host_utils.sh
source $EP_DIR/ci/test/dao-test/common/ep_device_utils.sh

function rdma_tests_cleanup() {

	ep_host_op rdma_test_cleanup
	ep_remote_op rdma_test_cleanup

	return 0
}

function rdma_app_launch()
{
	local dao_rdma_app
	local num_cores=$(ep_device_get_num_cores)
	local pci_devs=""
	local maxpktlen=9600
	local num_mbuf=1048576
	local num_dma_desc=8192
	local max_cores=$num_cores
	local cpu_mask="0x7"
	local port_mask="0x3"
	local num_queues=1
	local file_prefix="ep"
	local log_path="${EP_LOG_PATH:-/tmp}"
	local pid_file="$log_path/dao_rdma_graph_pid.tmp"

	if ! opts=$(getopt \
		-l "pci-devs:,max-pkt-len:,num-mbufs:,dma-nb-desc:" \
		-- rdma_app_launch $@); then
			echo "Failed to parse arguments"
			exit 1
	fi

	eval set -- "$opts"
	while [[ $# -gt 1 ]]; do
		case $1 in
			--pci-devs) shift; pci_devs="$pci_devs $1";;
			--max-pkt-len) shift; maxpktlen=$1;;
			--num-mbufs) shift; num_mbuf=$1;;
			--dma-nb-desc) shift; num_dma_desc=$1;;
			*) echo "Unknown argument $1"; exit 1;;
		esac
		shift
	done

	# Find the dao-rdma_graph executable
	find_executable "dao-rdma_graph" dao_rdma_app "$RDMA_UTILS_SCRIPT_PATH/../../../../app"

	if [[ -z "$dao_rdma_app" ]]; then
		echo "ERROR: dao-rdma_graph binary not found"
		return 1
	fi
	echo "Found dao-rdma_graph binary: $dao_rdma_app"

	# Build the application command
	local app_cmd="$dao_rdma_app -c $cpu_mask"

	# Add all PCI devices
	if [[ -n "$pci_devs" ]]; then
		for dev in $pci_devs; do
			app_cmd="$app_cmd -a $dev"
		done
	fi

	# Add DPDK options
	app_cmd="$app_cmd --file-prefix=$file_prefix -- -p $port_mask -P --max-pkt-len=$maxpktlen -n $num_queues -r 0x1 --num-mbufs $num_mbuf --dma-nb-desc $num_dma_desc"

	echo "Launching RDMA application..."
	echo "Command: $app_cmd"
	echo "Log file: $log_path/dao_rdma_graph.log"

	# Launch the application in background
	setsid $app_cmd > "$log_path/dao_rdma_graph.log" 2>&1 &
	local app_pid=$!
	echo $app_pid > "$pid_file"
	echo "dao-rdma_graph started with PID: $app_pid"

	# Give the application time to initialize
	sleep 5

	# Verify the application is still running
	if kill -0 $app_pid 2>/dev/null; then
		echo "dao-rdma_graph is running successfully with PID: $app_pid"
		return 0
	else
		echo "ERROR: dao-rdma_graph failed to start or crashed immediately"
		echo "Check $log_path/dao_rdma_graph.log for error details:"
		if [[ -f "$log_path/dao_rdma_graph.log" ]]; then
			echo "--- Log file contents ---"
			tail -50 "$log_path/dao_rdma_graph.log"
			echo "--- End of log ---"
		fi
		return 1
	fi
}

function rdma_sig_handler()
{
	local status=$?
	local sig=$1

	set +e
	trap - ERR
	trap - INT
	trap - TERM
	trap - QUIT
	trap - EXIT

	if [[ $status -ne 0 ]]; then
		echo "$sig Handler"
	fi

	rdma_tests_cleanup
}

function rdma_register_sig_handler()
{
	local vlan_id=${1:-}
	# Register the traps
	trap "rdma_sig_handler ERR $vlan_id" ERR
	trap "rdma_sig_handler INT $vlan_id" INT
	trap "rdma_sig_handler QUIT $vlan_id" QUIT
	trap "rdma_sig_handler EXIT $vlan_id" EXIT
}
