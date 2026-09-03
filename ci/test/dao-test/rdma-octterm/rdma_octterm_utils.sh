#!/bin/bash
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2025 Marvell.
#
# Utility functions for RDMA Octeon Termination mode CI tests.
#
# In octterm mode, both the kmod and firmware run on the same Octeon SoC.
# The kmod is loaded first, then the dao-rdma_graph firmware app is started
# with --enable-termination.
#
# Two remote peer scenarios are supported:
#   1. Octeon <-> Mellanox (MLX): EP_DEVICE <-> EP_REMOTE_HOST (native RoCE)
#   2. Octeon <-> Octeon:         EP_DEVICE <-> EP_REMOTE (both in octterm mode)
#
# Topology (MLX scenario):
#   EP_DEVICE (Octeon) — runs kmod + firmware, hosts IB device locally
#   EP_REMOTE_HOST     — remote Mellanox peer (native RoCE)
#
# Topology (Octeon scenario):
#   EP_DEVICE (Octeon) — runs kmod + firmware, hosts IB device locally
#   EP_REMOTE (Octeon) — runs kmod + firmware, hosts IB device locally
#
# In both scenarios EP_HOST == EP_DEVICE.

set -e

RDMA_OCTTERM_UTILS_SCRIPT_PATH="$( cd -- "$(dirname "$BASH_SOURCE[0]")" >/dev/null 2>&1 ; pwd -P )"
source $EP_DIR/ci/test/dao-test/common/utils.sh
source $EP_DIR/ci/test/dao-test/common/ep_host_utils.sh
source $EP_DIR/ci/test/dao-test/common/ep_device_utils.sh

# When rdma-core is built with CMAKE_INSTALL_PREFIX=$BUILD_DIR/rdma_prefix,
# the baked IBV_CONFIG_DIR and VERBS_PROVIDER_DIR paths point to the build
# host path.  A symlink on the Octeon ($BUILD_DIR/rdma_prefix -> $EP_DIR/rdma_prefix)
# bridges the baked paths to the actual deployment directory.
# PATH and LD_LIBRARY_PATH use $EP_DIR/rdma_prefix directly.

# LOCAL_ENV: cross-compiled rdma-core on the local Octeon device.
LOCAL_ENV=""
if [[ -n "${EP_HOST_RDMA_PATH:-}" ]]; then
	LOCAL_ENV="export PATH=\"${EP_HOST_RDMA_PATH}/bin\":\$PATH;export LD_LIBRARY_PATH=\"${EP_HOST_RDMA_PATH}/lib\${LD_LIBRARY_PATH:+:\$LD_LIBRARY_PATH}\";"
fi

# REMOTE_MLX_ENV: host-built rdma-core staged to EP_REMOTE_HOST (MLX).
REMOTE_MLX_ENV=""
if [[ -n "${EP_REMOTE_RDMA_PATH:-}" ]]; then
	REMOTE_MLX_ENV="export PATH=\"${EP_REMOTE_RDMA_PATH}/bin\":\$PATH;export LD_LIBRARY_PATH=\"${EP_REMOTE_RDMA_PATH}/lib\${LD_LIBRARY_PATH:+:\$LD_LIBRARY_PATH}\";"
fi

# REMOTE_OCTEON_ENV: cross-compiled rdma-core on the remote Octeon (EP_REMOTE).
REMOTE_OCTEON_ENV=""
if [[ -n "${EP_HOST_RDMA_PATH:-}" ]]; then
	REMOTE_OCTEON_ENV="export PATH=\"${EP_HOST_RDMA_PATH}/bin\":\$PATH;export LD_LIBRARY_PATH=\"${EP_HOST_RDMA_PATH}/lib\${LD_LIBRARY_PATH:+:\$LD_LIBRARY_PATH}\";"
fi

function octterm_local_cmd() {
	eval "$1"
}

function rdma_octterm_tests_cleanup() {
	set +e

	local kill_cmd="source $EP_DIR/ci/test/dao-test/common/utils.sh"
	kill_cmd+=" && safe_kill ibv_ud_pingpong ibv_rc_pingpong"
	kill_cmd+=" ibv_rdma_mq_trf ib_send_bw ib_read_bw udaddy 2>/dev/null"
	octterm_local_cmd "$kill_cmd" || true

	# Kill leftover test binaries on remote host (MLX scenario)
	if [[ -n "${EP_REMOTE_HOST:-}" ]]; then
		ep_remote_host_op rdma_test_cleanup true
	fi

	# Kill leftover test binaries on remote Octeon (Octeon scenario)
	if [[ -n "${EP_REMOTE:-}" ]]; then
		ep_remote_op guest_rdma_cleanup || true
	fi

	ep_device_rdma_app_cleanup
	rdma_octterm_kmod_cleanup

	# Stop firmware app and remove kmod on EP_REMOTE (Octeon scenario)
	if [[ -n "${EP_REMOTE:-}" ]]; then
		ep_remote_op rdma_app_cleanup
		local remote_kmod_rm="if grep -q octep_rdma /proc/modules; then rmmod octep_rdma; sleep 5; fi"
		ep_remote_ssh_cmd "$EP_REMOTE_SUDO bash -c '$remote_kmod_rm'" || true
	fi

	# Bring MLX interface down (MLX scenario)
	if [[ -n "${EP_REMOTE_HOST_MLX_IFACE:-}" ]]; then
		ep_remote_host_op if_configure --pcie-addr \
			"$EP_REMOTE_HOST_MLX_IFACE" --down || true
	fi

	# Return device port to kernel driver
	if [[ -n "${EP_DEVICE_MLX_IFACE:-}" ]]; then
		ep_device_op bind_driver pci "$EP_DEVICE_MLX_IFACE" rvu_nicpf || true
	fi
	if [[ -n "${EP_DEVICE_EXT_IFACE:-}" ]]; then
		ep_device_op bind_driver pci "$EP_DEVICE_EXT_IFACE" rvu_nicpf || true
	fi
	if [[ -n "${EP_REMOTE_IFACE:-}" ]]; then
		ep_remote_op bind_driver pci "$EP_REMOTE_IFACE" rvu_nicpf || true
	fi

	set -e
	return 0
}

function rdma_octterm_kmod_load() {
	local kmod_path="$EP_DIR/kmod/rdma/octep_rdma/octep-rdma.ko"

	set +e
	modprobe ib_uverbs
	sleep 1

	if grep -q 'octep_rdma' /proc/modules; then
		rmmod octep_rdma
		sleep 2
	fi

	echo "Loading octep-rdma kmod (octterm mode)..."
	insmod $kmod_path
	set -e

	sleep 2
	echo "octep-rdma kmod loaded"
}

function rdma_octterm_kmod_cleanup() {
	set +e
	if grep -q 'octep_rdma' /proc/modules; then
		echo "Removing octep-rdma kmod..."
		rmmod octep_rdma
		sleep 5
	fi
	set -e
}

function rdma_octterm_get_rdma_device() {
	local rdma_path=${1:-}
	local ip_hint=${2:-}
	ep_common_get_rdma_device "$rdma_path" "$ip_hint"
}

function rdma_octterm_get_v4_gid_index() {
	local dev=$1
	local rdma_path=${2:-}
	ep_common_get_v4_gid_index "$dev" "$rdma_path"
}

# Set up the octterm RDMA datapath for the MLX scenario.
# Loads kmod, launches dao-rdma_graph with force_tail_drop on the MLX-facing port,
# configures the local management netdev IP, and brings up the MLX remote.
function rdma_octterm_setup_configure_mlx()
{
	local local_ip=${1:-"21.0.0.3"}
	local remote_ip=${2:-"21.0.0.11"}
	local skip_mbuf_opts=${3:-false}
	local mlx_iface
	local pci_devs=""

	mlx_iface=${EP_DEVICE_MLX_IFACE:-}

	if [[ -z "$mlx_iface" ]]; then
		echo "EP_DEVICE_MLX_IFACE not set; cannot configure octterm MLX"
		exit 1
	fi

	ep_common_bind_driver pci $mlx_iface vfio-pci

	pci_devs="$pci_devs ${mlx_iface},force_tail_drop=1"

	read -r -a dpi_vfs <<< "$(ep_common_pcie_addr_get $PCI_DEVID_CN10K_RVU_DPI_VF 16)"
	for dpi in "${dpi_vfs[@]}"; do
		pci_devs="$pci_devs $dpi"
	done

	rdma_octterm_kmod_load

	# Build args directly to avoid printf %q escaping commas in devargs.
	local app_args=""
	for dev in $pci_devs; do
		app_args+=" --pci-devs $dev"
	done
	if [[ "$skip_mbuf_opts" != "true" ]]; then
		app_args+=" --num-mbufs 131072 --dma-nb-desc 32768"
	fi
	rdma_octterm_app_launch $app_args

	local _rdma_log="${EP_LOG_PATH:-/tmp}/dao_rdma_graph.log"
	local _ready=
	local _i
	for _i in $(seq 1 40); do
		if grep -q 'Entering service main loop' "$_rdma_log" 2>/dev/null; then
			_ready=1
			break
		fi
		sleep 1
	done
	if [[ -z "$_ready" ]]; then
		echo "WARNING: dao-rdma_graph did not signal ready (no 'Entering service main loop' after 40s)"
	fi

	local mgmt_iface
	mgmt_iface=$(ip -br link show | grep 'octep\|enp[0-9].*v[0-9]' |
		awk '{print $1}' | head -1) || true
	if [[ -n "$mgmt_iface" ]]; then
		ip addr flush dev $mgmt_iface 2>/dev/null || true
		ip addr add ${local_ip}/24 dev $mgmt_iface
		ip link set $mgmt_iface up
		echo "Configured $mgmt_iface with IP $local_ip"
	else
		echo "WARNING: Could not find management netdev"
	fi

	ep_remote_host_op if_configure --pcie-addr $EP_REMOTE_HOST_MLX_IFACE --down
	ep_remote_host_op if_configure --pcie-addr $EP_REMOTE_HOST_MLX_IFACE --ip $remote_ip
	ep_remote_host_op link_wait $EP_REMOTE_HOST_MLX_IFACE 15 >/dev/null
}

# Set up the octterm RDMA datapath for the Octeon<->Octeon scenario.
# Both Octeons: load kmod, launch dao-rdma_graph, configure management IPs.
function rdma_octterm_setup_configure_octeon()
{
	local local_ip=${1:-"30.0.0.3"}
	local remote_ip=${2:-"30.0.0.11"}
	local skip_mbuf_opts=${3:-false}
	local ext_iface remote_iface
	local pci_devs="" remote_pci_devs=""

	ext_iface=${EP_DEVICE_EXT_IFACE:-}
	remote_iface=${EP_REMOTE_IFACE:-}

	if [[ -z "$ext_iface" ]] || [[ -z "$remote_iface" ]]; then
		echo "EP_DEVICE_EXT_IFACE or EP_REMOTE_IFACE not set; cannot configure octterm Octeon<->Octeon"
		exit 1
	fi

	# Bind and build PCI dev list for local Octeon
	ep_common_bind_driver pci $ext_iface vfio-pci
	pci_devs="$ext_iface"
	read -r -a dpi_vfs <<< "$(ep_common_pcie_addr_get $PCI_DEVID_CN10K_RVU_DPI_VF 16)"
	for dpi in "${dpi_vfs[@]}"; do
		pci_devs="$pci_devs $dpi"
	done

	# Load kmod and launch graph on local Octeon
	rdma_octterm_kmod_load

	# Build args directly to avoid printf %q escaping commas in devargs.
	local app_args=""
	for dev in $pci_devs; do
		app_args+=" --pci-devs $dev"
	done
	if [[ "$skip_mbuf_opts" != "true" ]]; then
		app_args+=" --num-mbufs 131072 --dma-nb-desc 32768"
	fi
	rdma_octterm_app_launch $app_args

	local _rdma_log="${EP_LOG_PATH:-/tmp}/dao_rdma_graph.log"
	local _ready=
	local _i
	for _i in $(seq 1 40); do
		if grep -q 'Entering service main loop' "$_rdma_log" 2>/dev/null; then
			_ready=1
			break
		fi
		sleep 1
	done
	if [[ -z "$_ready" ]]; then
		echo "WARNING: local dao-rdma_graph did not signal ready after 40s"
	fi

	# Load kmod and launch graph on remote Octeon via SSH
	ep_remote_op bind_driver pci $remote_iface vfio-pci

	remote_pci_devs="$remote_iface"
	local remote_dpi_vfs
	remote_dpi_vfs=$(ep_remote_op pcie_addr_get $PCI_DEVID_CN10K_RVU_DPI_VF 16)
	for dpi in $remote_dpi_vfs; do
		remote_pci_devs="$remote_pci_devs $dpi"
	done

	local remote_kmod_cmd="modprobe ib_uverbs; sleep 1;"
	remote_kmod_cmd+=" if grep -q octep_rdma /proc/modules; then rmmod octep_rdma; sleep 2; fi;"
	remote_kmod_cmd+=" insmod $EP_DIR/kmod/rdma/octep_rdma/octep-rdma.ko; sleep 2"
	ep_remote_ssh_cmd "$EP_REMOTE_SUDO bash -c '$remote_kmod_cmd'"

	# Build remote args directly.
	local remote_pci_args=""
	for dev in $remote_pci_devs; do
		remote_pci_args+=" --pci-devs $dev"
	done
	local remote_mbuf_args=""
	if [[ "$skip_mbuf_opts" != "true" ]]; then
		remote_mbuf_args=" --num-mbufs 131072 --dma-nb-desc 32768"
	fi

	local utils_src="$EP_DIR/ci/test/dao-test/rdma-octterm/${BASH_SOURCE[0]##*/}"
	local remote_launch_cmd="EP_DIR=$EP_DIR; source $utils_src;"
	remote_launch_cmd+=" rdma_octterm_app_launch $remote_pci_args $remote_mbuf_args"
	local ld_library_path="export LD_LIBRARY_PATH=\"${EP_DIR}/deps-prefix/ep/lib\${LD_LIBRARY_PATH:+:\$LD_LIBRARY_PATH}\";"
	remote_launch_cmd="$ld_library_path $remote_launch_cmd"
	ep_remote_ssh_cmd "$EP_REMOTE_SUDO -E bash -lc $(printf %q "$remote_launch_cmd")"

	# Wait for remote app ready
	local _rready=
	for _i in $(seq 1 40); do
		local _ready_cmd="grep -q 'Entering service main loop'"
		_ready_cmd+=" /tmp/dao_rdma_graph.log 2>/dev/null"
		if ep_remote_ssh_cmd "$_ready_cmd"; then
			_rready=1
			break
		fi
		sleep 1
	done
	if [[ -z "$_rready" ]]; then
		echo "WARNING: remote dao-rdma_graph did not signal ready after 40s"
	fi

	# Configure management IPs on both Octeons
	local mgmt_iface
	mgmt_iface=$(ip -br link show | grep 'octep\|enp[0-9].*v[0-9]' |
		awk '{print $1}' | head -1) || true
	if [[ -n "$mgmt_iface" ]]; then
		ip addr flush dev $mgmt_iface 2>/dev/null || true
		ip addr add ${local_ip}/24 dev $mgmt_iface
		ip link set $mgmt_iface up
		echo "Configured local $mgmt_iface with IP $local_ip"
	else
		echo "WARNING: Could not find local management netdev"
	fi

	ep_remote_op octterm_mgmt_ip_configure $remote_ip
}

function rdma_octterm_app_launch()
{
	local dao_rdma_app
	local num_cores=$(ep_device_get_num_cores)
	local pci_devs=""
	local maxpktlen=9600
	local num_mbuf=131072
	local num_dma_desc=32768
	local cpu_mask="0xf"
	local port_mask="0x1"
	local num_queues=1
	local file_prefix="ep"
	local log_path="${EP_LOG_PATH:-/tmp}"
	local pid_file="$log_path/dao_rdma_graph_pid.tmp"

	if ! opts=$(getopt \
		-l "pci-devs:,max-pkt-len:,num-mbufs:,dma-nb-desc:" \
		-- rdma_octterm_app_launch "$@"); then
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

	find_executable "dao-rdma_graph" dao_rdma_app "$RDMA_OCTTERM_UTILS_SCRIPT_PATH/../../../../app"

	if [[ -z "$dao_rdma_app" ]]; then
		echo "ERROR: dao-rdma_graph binary not found"
		return 1
	fi
	echo "Found dao-rdma_graph binary: $dao_rdma_app"

	local app_cmd="$dao_rdma_app -c $cpu_mask"

	if [[ -n "$pci_devs" ]]; then
		for dev in $pci_devs; do
			app_cmd="$app_cmd -a $dev"
		done
	fi

	app_cmd="$app_cmd --file-prefix=$file_prefix -- -p $port_mask -P --max-pkt-len=$maxpktlen -n $num_queues -r 0x1 --num-mbufs $num_mbuf --dma-nb-desc $num_dma_desc --enable-termination"

	echo "Launching RDMA octterm application..."
	echo "Command: $app_cmd"
	echo "Log file: $log_path/dao_rdma_graph.log"

	setsid $app_cmd > "$log_path/dao_rdma_graph.log" 2>&1 &
	local app_pid=$!
	echo $app_pid > "$pid_file"
	echo "dao-rdma_graph started with PID: $app_pid"

	sleep 5

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

function rdma_octterm_sig_handler()
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

	rdma_octterm_tests_cleanup
}

function rdma_octterm_register_sig_handler()
{
	local vlan_id=${1:-}
	trap "rdma_octterm_sig_handler ERR $vlan_id" ERR
	trap "rdma_octterm_sig_handler INT $vlan_id" INT
	trap "rdma_octterm_sig_handler QUIT $vlan_id" QUIT
	trap "rdma_octterm_sig_handler EXIT $vlan_id" EXIT
}

# Scenario selection. RDMA_TOPO (mlx | octeon | unset for both) is forwarded
# by exe_wrapper.sh and is shared with the EP-mode rdma suite.
function rdma_octterm_topo_octeon_enabled()
{
	[[ "${RDMA_TOPO:-both}" != "mlx" && -n "${EP_REMOTE:-}" ]]
}

function rdma_octterm_topo_mlx_enabled()
{
	[[ "${RDMA_TOPO:-both}" != "octeon" &&
	   -n "${EP_DEVICE_MLX_IFACE:-}" &&
	   -n "${EP_REMOTE_HOST_MLX_IFACE:-}" ]]
}

# Fill in the per-scenario globals used by the test scripts:
#   octterm_topo_id, octterm_topo_label, local_ip, remote_ip,
#   local_env, remote_env, remote_ssh_fn
function rdma_octterm_topo_setup_vars()
{
	local id=$1

	octterm_topo_id=$id
	local_env=$LOCAL_ENV
	if [[ "$id" == octeon ]]; then
		octterm_topo_label="Octeon<->Octeon"
		local_ip="30.0.0.3"
		remote_ip="30.0.0.11"
		remote_env=$REMOTE_OCTEON_ENV
		remote_ssh_fn=ep_remote_ssh_cmd
		echo ""
		echo "==================== SCENARIO: Octeon <-> Octeon (octterm) ===================="
		echo "  EP_DEVICE ($local_ip) <-> EP_REMOTE ($remote_ip)"
	else
		octterm_topo_label="Octeon<->Mellanox"
		local_ip="21.0.0.3"
		remote_ip="21.0.0.11"
		remote_env=$REMOTE_MLX_ENV
		remote_ssh_fn=ep_remote_host_ssh_cmd
		echo ""
		echo "=================== SCENARIO: Octeon <-> Mellanox (octterm) ==================="
		echo "  EP_DEVICE ($local_ip) <-> EP_REMOTE_HOST Mellanox ($remote_ip)"
	fi
}

function rdma_octterm_topo_start()
{
	if [[ "$octterm_topo_id" == octeon ]]; then
		rdma_octterm_setup_configure_octeon "$local_ip" "$remote_ip"
	else
		rdma_octterm_setup_configure_mlx "$local_ip" "$remote_ip"
	fi
	sleep 1
}

# Resolve local_rdma_dev, local_gid, remote_rdma_dev and remote_gid.
function rdma_octterm_topo_resolve_devices()
{
	local_rdma_dev=$(rdma_octterm_get_rdma_device "$EP_HOST_RDMA_PATH" "$local_ip")
	local_gid=$(rdma_octterm_get_v4_gid_index "$local_rdma_dev" "$EP_HOST_RDMA_PATH")
	if [[ "$octterm_topo_id" == octeon ]]; then
		remote_rdma_dev=$(ep_remote_op get_rdma_device \
			"$EP_HOST_RDMA_PATH" "$remote_ip")
		remote_gid=$(ep_remote_op get_v4_gid_index \
			"$remote_rdma_dev" "$EP_HOST_RDMA_PATH")
	else
		remote_rdma_dev=$(ep_remote_host_op get_rdma_device \
			"$EP_REMOTE_RDMA_PATH" "$remote_ip")
		remote_gid=$(ep_remote_host_op get_v4_gid_index \
			"$remote_rdma_dev" "$EP_REMOTE_RDMA_PATH")
	fi
}

# Run a per-scenario function for every enabled scenario, like the EP-mode
# rdma_foreach_topo. The datapath is torn down after each scenario so the
# next one starts from a clean kmod/firmware state.
# $1 = per-scenario run function
# $2 = setup mode: full  (start datapath + resolve devices)
#                  start (start datapath only)
#                  vars  (variables only; the run function sets up and
#                         cleans up by itself)
function rdma_octterm_foreach_topo()
{
	local run_fn=$1
	local mode=${2:-full}
	local ran=0 rc=0 id

	case "$mode" in
	full | start | vars) ;;
	*) echo "rdma_octterm_foreach_topo: unknown mode $mode"; return 1 ;;
	esac

	for id in octeon mlx; do
		if ! rdma_octterm_topo_${id}_enabled; then
			continue
		fi
		rdma_octterm_topo_setup_vars $id
		if [[ "$mode" != vars ]]; then
			rdma_octterm_topo_start
			[[ "$mode" == full ]] && rdma_octterm_topo_resolve_devices
		fi
		if ! $run_fn; then
			rc=1
		fi
		[[ "$mode" != vars ]] && rdma_octterm_tests_cleanup
		ran=1
	done

	if [[ $ran -eq 0 ]]; then
		echo "No RDMA octterm scenario enabled/available (RDMA_TOPO=${RDMA_TOPO:-both})"
		exit 77
	fi
	return $rc
}
