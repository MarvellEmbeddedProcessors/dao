#!/bin/bash
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2025 Marvell.

# RDMA perftest (ib_*_bw / ib_*_lat) Tests
# Runs the perftest micro-benchmarks between EP_HOST (octep_rdma) and
# EP_REMOTE_HOST over each supported octep RDMA data path, in both directions:
#   1. Octeon<->Octeon  : EP_HOST octep VF <-> EP_REMOTE_HOST octep VF (30.0.0.x)
#   2. Octeon<->Mellanox: EP_HOST octep VF <-> EP_REMOTE_HOST Mellanox (21.0.0.x)
# Each case runs (a) EP_HOST as server, then (b) EP_REMOTE_HOST as server.
#
# Connection establishment:
#   * All tests (SEND / WRITE / READ, UD and RC) are connected through
#     rdma_cm (-R), for both scenarios and both directions.

set -euo pipefail

# Load RDMA utilities
SCRIPT_DIR="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
source "$SCRIPT_DIR/rdma_utils.sh"

# perftest binaries that may be left running and need to be cleaned up
PERFTEST_BINARIES=(
	"ib_send_bw"
	"ib_send_lat"
	"ib_write_bw"
	"ib_write_lat"
	"ib_read_bw"
	"ib_read_lat"
)

# Per-client timeout to guard against a hung benchmark
PERFTEST_CLIENT_TIMEOUT=600
# Number of attempts per case (per direction). A case can transiently time out
# on the octep_rdma path yet pass on an immediate re-run with a fresh server, so
# retry before declaring failure instead of restarting the whole dao-rdma_graph.
PERFTEST_CASE_ATTEMPTS=3

function cleanup_perftest_processes()
{
	local utils="$EP_DIR/ci/test/dao-test/common/utils.sh"
	local kill_cmd
	local binary

	for binary in "${PERFTEST_BINARIES[@]}"; do
		kill_cmd="source $utils && safe_kill $binary"
		ep_host_ssh_cmd "$kill_cmd" || true
		if [[ -n "${EP_REMOTE_HOST:-}" ]]; then
			ep_remote_host_ssh_cmd "$kill_cmd" || true
		fi
	done
	sleep 1
}

# Run a single perftest case in one direction.
#   $1 test_name   - human readable label
#   $2 binary      - perftest binary (e.g. ib_send_bw)
#   $3 conn_type   - connection type (UD or RC)
#   $4 use_cm      - "yes" to connect QPs through rdma_cm (-R), else "no"
#   $5 server_node - "host" (EP_HOST is server) or "remote" (EP_REMOTE_HOST is server)
function run_perftest_case()
{
	local test_name=$1
	local binary=$2
	local conn_type=$3
	local use_cm=$4
	local server_node=$5

	local server_env server_dev server_gid server_ssh
	local client_env client_dev client_gid client_ssh
	local server_ip
	local status

	if [[ "$server_node" == "host" ]]; then
		server_env=$host_env;        server_dev=$host_rdma_dev;        server_gid=$host_gid
		client_env=$remote_host_env; client_dev=$remote_host_rdma_dev; client_gid=$remote_host_gid
		server_ssh="ep_host_ssh_cmd"; client_ssh="ep_remote_host_ssh_cmd"
		server_ip=$host_ip
	else
		server_env=$remote_host_env; server_dev=$remote_host_rdma_dev; server_gid=$remote_host_gid
		client_env=$host_env;        client_dev=$host_rdma_dev;        client_gid=$host_gid
		server_ssh="ep_remote_host_ssh_cmd"; client_ssh="ep_host_ssh_cmd"
		server_ip=$remote_host_ip
	fi

	# Build the common perftest option set.
	# -i 1            : IB port 1
	# -F              : do not fail on CPU frequency scaling (CI hosts)
	# --report_gbits  : report bandwidth in Gb/sec
	# -a              : run over all message sizes (single connection)
	# rdma_cm (-R) is enabled for every case, both scenarios and both
	# directions, per configuration.
	local eff_use_cm=$use_cm

	local cm_opt=""
	[[ "$eff_use_cm" == "yes" ]] && cm_opt="-R"

	# Multiple QPs (-q) are only valid for the bandwidth (_bw) benchmarks;
	# the latency (_lat) binaries reject -q.
	local q_opt=""
	[[ "$binary" == *_bw ]] && q_opt="-q 32"

	local server_opts="-d $server_dev -i 1 -x $server_gid -c $conn_type $cm_opt -F --report_gbits -a $q_opt"
	local client_opts="-d $client_dev -i 1 -x $client_gid -c $conn_type $cm_opt -F --report_gbits -a $q_opt"

	local log_path="${EP_LOG_PATH:-/tmp}"
	local server_log="$log_path/${binary}_${test_name}_server.log"

	echo "  --- $test_name ($server_node server, $conn_type, rdma_cm=$eff_use_cm) ---"

	local server_cmd="bash -c \"( time ( ${server_env} setsid $binary $server_opts ) ) >$server_log 2>&1 &\""
	local client_cmd="bash -c \"time ( ${client_env} $binary $client_opts $server_ip )\""

	# A single case can transiently time out on the octep_rdma path even though
	# it passes when re-run in isolation. Retry with a fresh server a few times
	# before declaring failure, rather than restarting the whole datapath.
	local attempt
	for (( attempt = 1; attempt <= PERFTEST_CASE_ATTEMPTS; attempt++ )); do
		cleanup_perftest_processes

		$server_ssh "$server_cmd"
		# Allow the server to reach the accept/listen state.
		sleep 3

		set +e
		$client_ssh "timeout ${PERFTEST_CLIENT_TIMEOUT} $client_cmd"
		status=$?
		set -e

		if [[ $status -eq 0 ]]; then
			echo "  $test_name [$server_node server] PASSED (attempt $attempt)"
			cleanup_perftest_processes
			return 0
		fi

		if [[ $status -eq 124 ]]; then
			echo "  $test_name [$server_node server] attempt $attempt/$PERFTEST_CASE_ATTEMPTS FAILED" \
				"(TIMEOUT after ${PERFTEST_CLIENT_TIMEOUT}s)"
		else
			echo "  $test_name [$server_node server] attempt $attempt/$PERFTEST_CASE_ATTEMPTS FAILED" \
				"(exit code: $status)"
		fi
		$server_ssh "tail -30 $server_log 2>/dev/null" || true
		cleanup_perftest_processes

		if [[ $attempt -lt PERFTEST_CASE_ATTEMPTS ]]; then
			echo "  retrying $test_name [$server_node server]..."
			sleep 2
		fi
	done

	echo "  $test_name [$server_node server] FAILED after $PERFTEST_CASE_ATTEMPTS attempts"
	return 1
}

# Run a perftest case in both directions (Host server and Remote server).
#   $1 test_name $2 binary $3 conn_type $4 use_cm
function run_perftest_bidir()
{
	local test_name=$1
	local binary=$2
	local conn_type=$3
	local use_cm=$4
	local rc=0

	echo "=========================================================================================="
	echo "[$pt_scenario] $test_name"
	echo "=========================================================================================="

	if ! run_perftest_case "$test_name" "$binary" "$conn_type" "$use_cm" "host"; then
		rc=1
	fi
	if ! run_perftest_case "$test_name" "$binary" "$conn_type" "$use_cm" "remote"; then
		rc=1
	fi
	echo ""
	return $rc
}

# Run the full perftest matrix for the current scenario. The run_perftest_bidir
# invocations are unchanged; only the failed_tests label carries the scenario.
function run_all_perftests()
{
	# Unreliable Datagram (UD) SEND - connected through rdma_cm
	if ! run_perftest_bidir "UD_SEND_LAT" "ib_send_lat" "UD" "yes"; then
		failed_tests="$failed_tests\n  [$pt_scenario] UD_SEND_LAT"
	fi
	if ! run_perftest_bidir "UD_SEND_BW" "ib_send_bw" "UD" "yes"; then
		failed_tests="$failed_tests\n  [$pt_scenario] UD_SEND_BW"
	fi

	# Reliable Connection (RC) SEND - connected through rdma_cm
	if ! run_perftest_bidir "RC_SEND_LAT" "ib_send_lat" "RC" "yes"; then
		failed_tests="$failed_tests\n  [$pt_scenario] RC_SEND_LAT"
	fi
	if ! run_perftest_bidir "RC_SEND_BW" "ib_send_bw" "RC" "yes"; then
		failed_tests="$failed_tests\n  [$pt_scenario] RC_SEND_BW"
	fi

	# Reliable Connection (RC) RDMA WRITE - connected through rdma_cm
	if ! run_perftest_bidir "RC_WRITE_LAT" "ib_write_lat" "RC" "yes"; then
		failed_tests="$failed_tests\n  [$pt_scenario] RC_WRITE_LAT"
	fi
	if ! run_perftest_bidir "RC_WRITE_BW" "ib_write_bw" "RC" "yes"; then
		failed_tests="$failed_tests\n  [$pt_scenario] RC_WRITE_BW"
	fi

	# Reliable Connection (RC) RDMA READ - connected through rdma_cm
	if ! run_perftest_bidir "RC_READ_LAT" "ib_read_lat" "RC" "yes"; then
		failed_tests="$failed_tests\n  [$pt_scenario] RC_READ_LAT"
	fi
	if ! run_perftest_bidir "RC_READ_BW" "ib_read_bw" "RC" "yes"; then
		failed_tests="$failed_tests\n  [$pt_scenario] RC_READ_BW"
	fi
}

function rdma_perftest()
{
	local host_ip host_env host_rdma_dev host_gid
	local remote_host_ip remote_host_env remote_host_rdma_dev remote_host_gid
	local pt_scenario failed_tests="" ran=0

	# Register signal handler
	rdma_register_sig_handler

	# EP_HOST is always octep; EP_REMOTE_HOST is octep (O<->O) or Mellanox (O<->MLX).
	host_env=$HOST_ENV
	remote_host_env=$REMOTE_ENV

	echo "========================================"
	echo "RDMA perftest benchmarks starting"
	echo "========================================"

	# ============ Scenario 1: Octeon <-> Octeon (needs EP_REMOTE) ============
	if [[ "${RDMA_SCENARIO:-both}" != "mlx" && -n "${EP_REMOTE:-}" ]]; then
		pt_scenario="Octeon<->Octeon"
		host_ip="30.0.0.3"
		remote_host_ip="30.0.0.11"
		echo ""
		echo "==================== SCENARIO: Octeon <-> Octeon ===================="
		echo "  EP_HOST octep VF (30.0.0.3) <-> EP_REMOTE_HOST octep VF (30.0.0.11)"

		rdma_launch_graph_on_device                                   # graph on EP_DEVICE
		rdma_launch_graph_on_remote                                   # graph on EP_REMOTE
		rdma_setup_host_endpoint ep_remote_host_op "$remote_host_ip"  # octep VF on EP_REMOTE_HOST
		sleep 1
		rdma_setup_host_endpoint ep_host_op        "$host_ip"         # octep VF on EP_HOST - last
		sleep 1

		host_rdma_dev=$(ep_host_op get_rdma_device "$EP_HOST_RDMA_PATH" "$host_ip")
		host_gid=$(ep_host_op get_v4_gid_index "$host_rdma_dev" "$EP_HOST_RDMA_PATH")
		remote_host_rdma_dev=$(ep_remote_host_op get_rdma_device "$EP_REMOTE_RDMA_PATH" "$remote_host_ip")
		remote_host_gid=$(ep_remote_host_op get_v4_gid_index "$remote_host_rdma_dev" "$EP_REMOTE_RDMA_PATH")

		run_all_perftests
		rdma_tests_cleanup
		ran=1
	fi

	# ================= Scenario 2: Octeon <-> Mellanox =================
	if [[ "${RDMA_SCENARIO:-both}" != "octeon" && -n "${EP_DEVICE_MLX_IFACE:-}" && -n "${EP_REMOTE_HOST_MLX_IFACE:-}" ]]; then
		pt_scenario="Octeon<->Mellanox"
		host_ip="21.0.0.3"
		remote_host_ip="21.0.0.11"
		echo ""
		echo "=================== SCENARIO: Octeon <-> Mellanox ==================="
		echo "  EP_HOST octep VF (21.0.0.3) <-> EP_REMOTE_HOST Mellanox (21.0.0.11)"

		rdma_launch_graph_on_device "${EP_DEVICE_MLX_IFACE},force_tail_drop=1" # graph on EP_DEVICE MLX port (force_tail_drop for O<->MLX)
		rdma_setup_mlx_endpoint "$EP_REMOTE_HOST_MLX_IFACE" "$remote_host_ip" # Mellanox IP (native)
		sleep 2
		rdma_setup_host_endpoint ep_host_op "$host_ip"                       # octep VF on EP_HOST - last
		sleep 1

		host_rdma_dev=$(ep_host_op get_rdma_device "$EP_HOST_RDMA_PATH" "$host_ip")
		host_gid=$(ep_host_op get_v4_gid_index "$host_rdma_dev" "$EP_HOST_RDMA_PATH")
		remote_host_rdma_dev=$(ep_remote_host_op get_rdma_device "$EP_REMOTE_RDMA_PATH" "$remote_host_ip")
		remote_host_gid=$(ep_remote_host_op get_v4_gid_index "$remote_host_rdma_dev" "$EP_REMOTE_RDMA_PATH")

		run_all_perftests
		rdma_tests_cleanup
		ran=1
	fi

	if [[ $ran -eq 0 ]]; then
		echo "No RDMA scenario selected/available (RDMA_SCENARIO=${RDMA_SCENARIO:-both})"
		exit 77
	fi

	# Final cleanup
	echo "Performing final cleanup..."
	cleanup_perftest_processes
	rdma_tests_cleanup

	echo "========================================"
	echo "RDMA perftest benchmarks summary"
	echo "========================================"
	if [[ -z "$failed_tests" ]]; then
		echo "All perftest cases PASSED"
		return 0
	else
		echo -e "Failed perftest cases:$failed_tests"
		exit 1
	fi
}
test_run rdma_perftest 2
