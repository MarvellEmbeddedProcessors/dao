#!/bin/bash
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2025 Marvell.
set -e

RDMA_UTILS_SCRIPT_PATH="$( cd -- "$(dirname "$BASH_SOURCE[0]")" >/dev/null 2>&1 ; pwd -P )"
source $EP_DIR/ci/test/dao-test/common/utils.sh
source $EP_DIR/ci/test/dao-test/common/ep_host_utils.sh
source $EP_DIR/ci/test/dao-test/common/ep_device_utils.sh

# RDMA env strings, only if both paths are set.
REMOTE_ENV=""
HOST_ENV=""
if [[ -n "${EP_REMOTE_RDMA_PATH:-}" ]] && [[ -n "${EP_HOST_RDMA_PATH:-}" ]]; then
	REMOTE_ENV="export PATH=\"${EP_REMOTE_RDMA_PATH}/bin\":\$PATH;export LD_LIBRARY_PATH=\"${EP_REMOTE_RDMA_PATH}/lib:\${LD_LIBRARY_PATH:-}\";"
	HOST_ENV="export PATH=\"${EP_HOST_RDMA_PATH}/bin\":\$PATH;export LD_LIBRARY_PATH=\"${EP_HOST_RDMA_PATH}/lib:\${LD_LIBRARY_PATH:-}\";"
fi

function rdma_app_launch()
{
	local dao_rdma_app
	local num_cores=$(ep_device_get_num_cores)
	local pci_devs=""
	local maxpktlen=9600
	local num_mbuf=531072
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

	# Find the dao-rdma_graph binary.
	find_executable "dao-rdma_graph" dao_rdma_app "$RDMA_UTILS_SCRIPT_PATH/../../../../app"

	if [[ -z "$dao_rdma_app" ]]; then
		echo "ERROR: dao-rdma_graph binary not found"
		return 1
	fi
	echo "Found dao-rdma_graph binary: $dao_rdma_app"

	# Build the app command.
	local app_cmd="$dao_rdma_app -c $cpu_mask"

	# Add PCI devices.
	if [[ -n "$pci_devs" ]]; then
		for dev in $pci_devs; do
			app_cmd="$app_cmd -a $dev"
		done
	fi

	free -h
	cat /proc/meminfo
	cat /proc/cmdline
	# Add DPDK options.
	app_cmd="$app_cmd --file-prefix=$file_prefix -- -p $port_mask -P --max-pkt-len=$maxpktlen -n $num_queues -r 0x1 --num-mbufs $num_mbuf --dma-nb-desc $num_dma_desc"

	echo "Launching RDMA application..."
	echo "Command: $app_cmd"
	echo "Log file: $log_path/dao_rdma_graph.log"

	# Launch in background.
	setsid $app_cmd > "$log_path/dao_rdma_graph.log" 2>&1 &
	local app_pid=$!
	echo $app_pid > "$pid_file"
	echo "dao-rdma_graph started with PID: $app_pid"

	# Let it initialize.
	sleep 5

	# Verify it's still running.
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

# Launch dao-rdma_graph on EP_DEVICE. $1=ext BDF (may carry ,devargs), $2=num-mbufs, $3=dma-nb-desc.
function rdma_launch_graph_on_device()
{
	local ext_iface=${1:-${EP_DEVICE_EXT_IFACE:-}}
	local num_mbufs=${2:-131072}
	local dma_nb_desc=${3:-32768}
	local pci_devs="$ext_iface"
	local pci_bdf="${ext_iface%%,*}"
	local dpi dpi_vfs=() tmp=() args=()
	local _i _rdma_log="${EP_LOG_PATH:-/tmp}/dao_rdma_graph.log"

	if [[ -z "$ext_iface" ]]; then
		echo "rdma_launch_graph_on_device: no external interface given"
		return 1
	fi

	# Bind external port to vfio-pci for DPDK (BDF only; DPDK devargs kept for -a).
	ep_common_bind_driver pci "$pci_bdf" vfio-pci

	# Add DPI (DMA) VFs.
	read -r -a dpi_vfs <<< "$(ep_common_pcie_addr_get $PCI_DEVID_CN10K_RVU_DPI_VF 16)"
	for dpi in "${dpi_vfs[@]}"; do
		pci_devs="$pci_devs $dpi"
	done

	# Assemble args and launch locally.
	read -r -a tmp <<< "$(form_split_args "--pci-devs"    "$pci_devs")"    ; args+=("${tmp[@]}")
	read -r -a tmp <<< "$(form_split_args "--num-mbufs"   "$num_mbufs")"   ; args+=("${tmp[@]}")
	read -r -a tmp <<< "$(form_split_args "--dma-nb-desc" "$dma_nb_desc")" ; args+=("${tmp[@]}")
	rdma_app_launch "${args[@]}"

	# Wait for mailbox ready; fail if not.
	local ready=
	for _i in $(seq 1 40); do
		if grep -q 'Entering service main loop' "$_rdma_log" 2>/dev/null; then
			ready=1
			break
		fi
		sleep 1
	done
	if [[ -z "$ready" ]]; then
		echo "rdma_launch_graph_on_device: dao-rdma_graph did not signal ready (no 'Entering service main loop' after 40s)"
		return 1
	fi
}

# Launch dao-rdma_graph on EP_REMOTE over SSH. $1=ext BDF (may carry ,devargs), $2=num-mbufs, $3=dma-nb-desc.
function rdma_launch_graph_on_remote()
{
	local ext_iface=${1:-${EP_REMOTE_IFACE:-}}
	local num_mbufs=${2:-131072}
	local dma_nb_desc=${3:-32768}
	local pci_devs="$ext_iface"
	local pci_bdf="${ext_iface%%,*}"
	local dpi dpi_vfs=() tmp=() args=()
	local serialized_args app_cmd ld_library_path rdma_utils _i

	if [[ -z "$ext_iface" ]]; then
		echo "rdma_launch_graph_on_remote: no external interface given"
		return 1
	fi

	# Bind remote external port to vfio-pci over SSH (BDF only; DPDK devargs kept for -a).
	ep_remote_op bind_driver pci "$pci_bdf" vfio-pci

	# Add remote DPI (DMA) VFs.
	read -r -a dpi_vfs <<< "$(ep_remote_op pcie_addr_get $PCI_DEVID_CN10K_RVU_DPI_VF 16)"
	for dpi in "${dpi_vfs[@]}"; do
		pci_devs="$pci_devs $dpi"
	done

	# Assemble args and run rdma_app_launch on EP_REMOTE via SSH.
	read -r -a tmp <<< "$(form_split_args "--pci-devs"    "$pci_devs")"    ; args+=("${tmp[@]}")
	read -r -a tmp <<< "$(form_split_args "--num-mbufs"   "$num_mbufs")"   ; args+=("${tmp[@]}")
	read -r -a tmp <<< "$(form_split_args "--dma-nb-desc" "$dma_nb_desc")" ; args+=("${tmp[@]}")
	serialized_args=$(printf '%q ' "${args[@]}")

	rdma_utils=$EP_DIR/ci/test/dao-test/rdma/rdma_utils.sh
	app_cmd="EP_DIR=$EP_DIR; source \"$rdma_utils\"; rdma_app_launch $serialized_args"
	ld_library_path="export LD_LIBRARY_PATH=\"${EP_DIR}/deps-prefix/ep/lib:\${LD_LIBRARY_PATH:-}\";"
	app_cmd="$ld_library_path $app_cmd"
	ep_remote_ssh_cmd "$EP_REMOTE_SUDO -E bash -lc $(printf %q "$app_cmd")"

	# Wait for remote mailbox ready; fail if not.
	local ready=
	for _i in $(seq 1 40); do
		if ep_remote_ssh_cmd "grep -q 'Entering service main loop' /tmp/dao_rdma_graph.log 2>/dev/null"; then
			ready=1
			break
		fi
		sleep 1
	done
	if [[ -z "$ready" ]]; then
		echo "rdma_launch_graph_on_remote: dao-rdma_graph did not signal ready on EP_REMOTE (no 'Entering service main loop' after 40s)"
		return 1
	fi
}

# Bring up an octep_rdma host VF. $1=host op (ep_host_op/ep_remote_host_op), $2=IP.
function rdma_setup_host_endpoint()
{
	local host_op=$1
	local ip=$2
	local vfs if_name _i

	if [[ -z "$host_op" || -z "$ip" ]]; then
		echo "rdma_setup_host_endpoint: usage: <ep_host_op|ep_remote_host_op> <ip>"
		return 1
	fi

	# insmod octep-rdma + create the RDMA VF.
	$host_op rdma_setup 1
	sleep 1

	# VF netdev may take a few seconds; poll before assigning IP.
	vfs=$($host_op pcie_addr_get "0xB903" 1)
	for _i in $(seq 1 15); do
		if_name=$($host_op if_name_get "$vfs" 2>/dev/null)
		[[ -n "$if_name" ]] && break
		sleep 1
	done

	$host_op if_configure --pcie-addr "$vfs" --ip "$ip"
}

# Bring up native Mellanox endpoint on EP_REMOTE_HOST (IP + link wait). $1=BDF, $2=IP.
function rdma_setup_mlx_endpoint()
{
	local mlx_iface=$1
	local ip=$2

	if [[ -z "$mlx_iface" || -z "$ip" ]]; then
		echo "rdma_setup_mlx_endpoint: usage: <mlx_pci_bdf> <ip>"
		return 1
	fi

	ep_remote_host_op if_configure --pcie-addr "$mlx_iface" --down
	ep_remote_host_op if_configure --pcie-addr "$mlx_iface" --ip "$ip"
	ep_remote_host_op link_wait "$mlx_iface" 15 >/dev/null
}

# Best-effort idempotent teardown; scenario-specific steps guarded.
function rdma_tests_cleanup()
{
	set +e

	echo "CLEANUP: ===== rdma_tests_cleanup START ====="

	# 1. Kill leftover test binaries (EP_HOST + EP_REMOTE_HOST).
	ep_host_op rdma_test_cleanup true
	if [[ -n "${EP_REMOTE_HOST:-}" ]]; then
		ep_remote_host_op rdma_test_cleanup true
	fi

	# 2. Tear down host octep stacks; far host first, EP_HOST last.
	#    O<->O: drop EP_REMOTE_HOST octep VF first.
	if [[ -n "${EP_REMOTE:-}" ]]; then
		ep_remote_host_op rdma_cleanup
	fi
	#    O<->MLX: drop Mellanox IP.
	if [[ -n "${EP_REMOTE_HOST_MLX_IFACE:-}" ]]; then
		ep_remote_host_op if_configure --pcie-addr "$EP_REMOTE_HOST_MLX_IFACE" --down
	fi
	#    EP_HOST octep VF last.
	ep_host_op rdma_cleanup

	# 3. Stop dao-rdma_graph (EP_DEVICE always, EP_REMOTE for O<->O).
	ep_device_rdma_app_cleanup
	if [[ -n "${EP_REMOTE:-}" ]]; then
		ep_remote_op rdma_app_cleanup
	fi

	# 4. Return external ports to the kernel driver.
	if [[ -n "${EP_DEVICE_EXT_IFACE:-}" ]]; then
		ep_device_op bind_driver pci "$EP_DEVICE_EXT_IFACE" rvu_nicpf
	fi
	if [[ -n "${EP_REMOTE_IFACE:-}" ]]; then
		ep_remote_op bind_driver pci "$EP_REMOTE_IFACE" rvu_nicpf
	fi

	echo "CLEANUP: ===== rdma_tests_cleanup END ====="
	set -e
	return 0
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
	# Register traps.
	trap "rdma_sig_handler ERR $vlan_id" ERR
	trap "rdma_sig_handler INT $vlan_id" INT
	trap "rdma_sig_handler QUIT $vlan_id" QUIT
	trap "rdma_sig_handler EXIT $vlan_id" EXIT
}
