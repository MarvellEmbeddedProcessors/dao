#!/bin/bash
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2025 Marvell.
set -e

RDMA_UTILS_SCRIPT_PATH="$( cd -- "$(dirname "$BASH_SOURCE[0]")" >/dev/null 2>&1 ; pwd -P )"
source $EP_DIR/ci/test/dao-test/common/utils.sh
source $EP_DIR/ci/test/dao-test/common/ep_host_utils.sh
source $EP_DIR/ci/test/dao-test/common/ep_device_utils.sh

# Set RDMA environment variables only if both paths are configured
REMOTE_ENV=""
HOST_ENV=""
if [[ -n "${EP_REMOTE_RDMA_PATH:-}" ]] && [[ -n "${EP_HOST_RDMA_PATH:-}" ]]; then
	REMOTE_ENV="export PATH=\"${EP_REMOTE_RDMA_PATH}/bin\":\$PATH;export LD_LIBRARY_PATH=\"${EP_REMOTE_RDMA_PATH}/lib:\${LD_LIBRARY_PATH:-}\";"
	HOST_ENV="export PATH=\"${EP_HOST_RDMA_PATH}/bin\":\$PATH;export LD_LIBRARY_PATH=\"${EP_HOST_RDMA_PATH}/lib:\${LD_LIBRARY_PATH:-}\";"
fi

function rdma_tests_cleanup() {

	ep_host_op rdma_test_cleanup
	ep_remote_op rdma_test_cleanup
	ep_host_op rdma_cleanup
	ep_remote_op guest_rdma_cleanup $EP_REMOTE_IFACE
	ep_device_rdma_app_cleanup

	return 0
}

function rdma_setup_configure()
{
	local host_ip=${1:-"30.0.0.3"}
	local remote_ip=${2:-"30.0.0.11"}
	local skip_mbuf_opts=${3:-false}
	local ext_iface
	local remote_iface
	local pci_devs=""
	local _i _rdma_log

	ext_iface=${EP_DEVICE_EXT_IFACE:-}
	remote_iface=${EP_REMOTE_IFACE:-}

	if [[ -n $EP_REMOTE ]]; then
		if [[ -z $ext_iface ]] || [[ -z $remote_iface ]]; then
			echo "Failed to find a valid interface pair"
			exit 1
		fi
	fi

	pci_devs="$pci_devs $ext_iface"

	# Add DPI VFs
	read -r -a dpi_vfs <<< "$(ep_common_pcie_addr_get $PCI_DEVID_CN10K_RVU_DPI_VF 16)"
	for dpi in "${dpi_vfs[@]}"; do
		pci_devs="$pci_devs $dpi"
	done

	# Launch RDMA application with all PCI devices
	args=()
	read -r -a tmp <<< "$(form_split_args "--pci-devs"    "$pci_devs")"    ; args+=("${tmp[@]}")
	if [[ "$skip_mbuf_opts" != "true" ]]; then
		read -r -a tmp <<< "$(form_split_args "--num-mbufs" "131072")"
		args+=("${tmp[@]}")
		read -r -a tmp <<< "$(form_split_args "--dma-nb-desc" "32768")"
		args+=("${tmp[@]}")
	fi
	serialized_args=$(printf '%q ' "${args[@]}")
	rdma_app_launch $serialized_args

	# Wait until the device RDMA app's mailbox service is up before creating the
	# host octep_rdma VF. If the host driver probes while the app is still
	# initialising, its "get device capabilities" mailbox request times out and
	# ibdev registration fails (-5), leaving the host VF with no RDMA netdev.
	_rdma_log="${EP_LOG_PATH:-/tmp}/dao_rdma_graph.log"
	for _i in $(seq 1 40); do
		grep -q 'Entering service main loop' "$_rdma_log" 2>/dev/null && break
		sleep 1
	done

	# Bring up the remote (external) side FIRST, before the host octep_rdma
	# connects. The device external port (Port 0) links to the remote NIC; if
	# the host connects and dao-rdma_graph configures the management QP while
	# that external link is still down, the app crashes. This matches the
	# working manual order: remote link up, then host insmod/VF.
	ep_remote_op guest_rdma_setup $EP_REMOTE_IFACE
	ep_remote_op if_configure --pcie-addr $remote_iface --ip $remote_ip
	sleep 2

	# Configure Octeon Host (this drives the host<->device RDMA handshake).
	ep_host_op rdma_setup 1
	sleep 1
	rdma_vfs=$(ep_host_op pcie_addr_get "0xB903" 1)

	# The host RDMA VF netdev can take a few seconds to appear after the VF is
	# created and octep_rdma syncs with the device app; poll for it before
	# assigning its IP so the pingpong server can bind to $host_ip.
	for _i in $(seq 1 15); do
		[[ -n "$(ep_host_op if_name_get $rdma_vfs 2>/dev/null)" ]] && break
		sleep 1
	done

	ep_host_op if_configure --pcie-addr $rdma_vfs --ip $host_ip
}

function rdma_app_launch()
{
	local dao_rdma_app
	local num_cores=$(ep_device_get_num_cores)
	local pci_devs=""
	local maxpktlen=9600
	local num_mbuf=131072
	local num_dma_desc=32768
	local max_cores=$num_cores
	local cpu_mask="0xf"
	local port_mask="0x1"
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
