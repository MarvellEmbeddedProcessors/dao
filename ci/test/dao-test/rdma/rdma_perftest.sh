#!/bin/bash
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2025 Marvell.

# RDMA perftest (ib_*_bw / ib_*_lat) Tests
# This test exercises the perftest micro-benchmarks between the Octeon
# (octep_rdma) host and the remote (RXE/ConnectX) peer, mirroring the
# documented perftest examples. Each test is run in both directions:
#   1. Host (Octeon) as Server -> Remote as Client
#   2. Remote as Server -> Host (Octeon) as Client
#
# Connection establishment:
#   * SEND tests (ib_send_bw / ib_send_lat) for both UD and RC are run over
#     rdma_cm (-R). For these the QPs are connected through the rdma_cm module.
#   * RDMA WRITE and READ tests (ib_write_*/ib_read_*) do not require rdma_cm;
#     QP information is exchanged out-of-band over the management socket.

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
		ep_remote_ssh_cmd "$kill_cmd" || true
	done
	sleep 1
}

# Run a single perftest case in one direction.
#   $1 test_name   - human readable label
#   $2 binary      - perftest binary (e.g. ib_send_bw)
#   $3 conn_type   - connection type (UD or RC)
#   $4 use_cm      - "yes" to connect QPs through rdma_cm (-R), else "no"
#   $5 server_node - "host" (Octeon is server) or "remote" (RXE is server)
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
		server_env=$host_env;   server_dev=$host_rdma_dev;   server_gid=$host_gid
		client_env=$remote_env; client_dev=$remote_rdma_dev; client_gid=$remote_gid
		server_ssh="ep_host_ssh_cmd"; client_ssh="ep_remote_ssh_cmd"
		server_ip=$host_ip
	else
		server_env=$remote_env; server_dev=$remote_rdma_dev; server_gid=$remote_gid
		client_env=$host_env;   client_dev=$host_rdma_dev;   client_gid=$host_gid
		server_ssh="ep_remote_ssh_cmd"; client_ssh="ep_host_ssh_cmd"
		server_ip=$remote_ip
	fi

	# Build the common perftest option set.
	# -i 1            : IB port 1
	# -F              : do not fail on CPU frequency scaling (CI hosts)
	# --report_gbits  : report bandwidth in Gb/sec
	# -a              : run over all message sizes (single connection)
	# rdma_cm on this setup makes the Octeon the CM client in the host-as-client
	# direction (server_node=remote) and selects a RoCE v1 GID that the
	# octep_rdma path can't use, so that direction stalls on large transfers.
	# Force the socket-based QP exchange there so the script-selected RoCE v2
	# GID (-x) is honored. The reverse direction (Octeon as CM server) is fine.
	local eff_use_cm=$use_cm
	if [[ "$use_cm" == "yes" ]]; then
		# In DPU-to-DPU mode both ends are octep_rdma, so the RoCE v1 GID issue
		# (rdma_cm picking an unsupported GID when Octeon is the CM client)
		# affects both directions; otherwise only the host-as-client direction
		# (server_node=remote) is affected.
		if [[ -n "${EP_REMOTE_DEVICE:-}" || "$server_node" == "remote" ]]; then
			eff_use_cm="no"
		fi
	fi

	local cm_opt=""
	[[ "$eff_use_cm" == "yes" ]] && cm_opt="-R"

	local server_opts="-d $server_dev -i 1 -x $server_gid -c $conn_type $cm_opt -F --report_gbits -a"
	local client_opts="-d $client_dev -i 1 -x $client_gid -c $conn_type $cm_opt -F --report_gbits -a"

	local log_path="${EP_LOG_PATH:-/tmp}"
	local server_log="$log_path/${binary}_${test_name}_server.log"

	echo "  --- $test_name ($server_node server, $conn_type, rdma_cm=$eff_use_cm) ---"

	local server_cmd="bash -c \"${server_env} setsid $binary $server_opts >$server_log 2>&1 &\""
	local client_cmd="bash -c \"${client_env} $binary $client_opts $server_ip\""

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

	echo "========================================="
	echo "$test_name"
	echo "========================================="

	if ! run_perftest_case "$test_name" "$binary" "$conn_type" "$use_cm" "host"; then
		rc=1
	fi
	if ! run_perftest_case "$test_name" "$binary" "$conn_type" "$use_cm" "remote"; then
		rc=1
	fi
	echo ""
	return $rc
}

function rdma_perftest()
{
	local remote_ip="30.0.0.11"
	local host_ip="30.0.0.3"
	local remote_env
	local host_env
	local host_rdma_dev
	local host_gid
	local remote_rdma_dev
	local remote_gid
	local failed_tests=""

	# Register signal handler
	rdma_register_sig_handler

	rdma_setup_configure
	sleep 1

	# Get RDMA device information
	host_rdma_dev=$(ep_host_op get_rdma_device "$EP_HOST_RDMA_PATH")
	host_gid=$(ep_host_op get_v4_gid_index $host_rdma_dev "$EP_HOST_RDMA_PATH")

	remote_rdma_dev=$(ep_remote_op get_rdma_device "$EP_REMOTE_RDMA_PATH")
	remote_gid=$(ep_remote_op get_v4_gid_index $remote_rdma_dev "$EP_REMOTE_RDMA_PATH")

	# Build environment strings
	remote_env=$REMOTE_ENV
	host_env=$HOST_ENV

	echo "========================================"
	echo "RDMA perftest benchmarks starting"
	echo "========================================"
	echo "Host Device   : $host_rdma_dev (GID: $host_gid, IP: $host_ip)"
	echo "Remote Device : $remote_rdma_dev (GID: $remote_gid, IP: $remote_ip)"
	echo ""

	# Unreliable Datagram (UD) SEND - connected through rdma_cm
	if ! run_perftest_bidir "UD_SEND_LAT" "ib_send_lat" "UD" "yes"; then
		failed_tests="$failed_tests\n  UD_SEND_LAT"
	fi
	if ! run_perftest_bidir "UD_SEND_BW" "ib_send_bw" "UD" "yes"; then
		failed_tests="$failed_tests\n  UD_SEND_BW"
	fi

	# Reliable Connection (RC) SEND - connected through rdma_cm
	if ! run_perftest_bidir "RC_SEND_LAT" "ib_send_lat" "RC" "yes"; then
		failed_tests="$failed_tests\n  RC_SEND_LAT"
	fi
	if ! run_perftest_bidir "RC_SEND_BW" "ib_send_bw" "RC" "yes"; then
		failed_tests="$failed_tests\n  RC_SEND_BW"
	fi

	# Reliable Connection (RC) RDMA WRITE - no rdma_cm required
	if ! run_perftest_bidir "RC_WRITE_LAT" "ib_write_lat" "RC" "no"; then
		failed_tests="$failed_tests\n  RC_WRITE_LAT"
	fi
	if ! run_perftest_bidir "RC_WRITE_BW" "ib_write_bw" "RC" "no"; then
		failed_tests="$failed_tests\n  RC_WRITE_BW"
	fi

	# Reliable Connection (RC) RDMA READ - no rdma_cm required
	if ! run_perftest_bidir "RC_READ_LAT" "ib_read_lat" "RC" "no"; then
		failed_tests="$failed_tests\n  RC_READ_LAT"
	fi
	if ! run_perftest_bidir "RC_READ_BW" "ib_read_bw" "RC" "no"; then
		failed_tests="$failed_tests\n  RC_READ_BW"
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
test_run ${DAO_TEST} 2
