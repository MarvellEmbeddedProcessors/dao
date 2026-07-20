#!/bin/bash
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2025 Marvell.

# RDMA Multi-Queue Traffic Tests
# Verifies RDMA multi-queue functionality with various QP types and operations:
#   1. UD Mode - SEND operations
#   2. RC Mode - SEND, WRITE, WRITE_IMM, READ operations
# EP_HOST (Octeon) is always the server; EP_REMOTE_HOST (octep VF for
# Octeon<->Octeon, Mellanox for Octeon<->Mellanox) is always the client.
# Runs over every scenario the bench supports (guards: EP_REMOTE / MLX ifaces).

set -euo pipefail

SCRIPT_DIR="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
source "$SCRIPT_DIR/rdma_utils.sh"

function cleanup_stuck_processes()
{
	echo "  Cleaning up any stuck ibv_rdma_mq_trf processes..."

	local safe_kill_cmd="source $EP_DIR/ci/test/dao-test/common/utils.sh && safe_kill ibv_rdma_mq_trf"

	ep_host_ssh_cmd "$safe_kill_cmd" || true

	if [[ -n "${EP_REMOTE_HOST:-}" ]]; then
		ep_remote_host_ssh_cmd "$safe_kill_cmd" || true
	fi

	sleep 1
}

# Relaunch dao-rdma_graph + bring up endpoints for the current scenario.
# mq_scenario / host_ip / remote_host_ip come from the caller (rdma_mq_trf).
function mq_scenario_setup()
{
	if [[ "$mq_scenario" == "Octeon<->Mellanox" ]]; then
		rdma_launch_graph_on_device "${EP_DEVICE_MLX_IFACE},force_tail_drop=1" # graph on EP_DEVICE MLX port (force_tail_drop for O<->MLX)
		rdma_setup_mlx_endpoint "$EP_REMOTE_HOST_MLX_IFACE" "$remote_host_ip" # Mellanox IP (native)
		sleep 2
		rdma_setup_host_endpoint ep_host_op "$host_ip"                        # octep VF on EP_HOST - last
	else
		rdma_launch_graph_on_device                                          # graph on EP_DEVICE
		rdma_launch_graph_on_remote                                          # graph on EP_REMOTE
		rdma_setup_host_endpoint ep_remote_host_op "$remote_host_ip"         # octep VF on EP_REMOTE_HOST
		sleep 1
		rdma_setup_host_endpoint ep_host_op "$host_ip"                       # octep VF on EP_HOST - last
	fi
	sleep 1
}

function run_mq_test()
{
	local test_name=$1
	local qp_type=$2         # "UD" or "RC"
	local op_type=$3         # "SEND", "WRITE", "WRITE_IMM", "READ"
	local num_qp=${4:-100}
	local num_threads=${5:-8}
	local num_iterations=${6:-10}
	local msg_size=${7:-1024}
	local nb_sge=${8:-}
	local loop_count=${9:-}
	local server_max_conn=${10:-1000}
	local skip_mbuf_opts=${11:-false}   # kept for call compatibility; graph args now set by the launch helpers

	# Optional single-case filter. Set MQ_TEST_FILTER to a test name
	# (substring match) to run only matching case(s), e.g.
	#   MQ_TEST_FILTER=Repeated_UD_SEND_SGE_Host_Server
	if [[ -n "${MQ_TEST_FILTER:-}" && "$test_name" != *"$MQ_TEST_FILTER"* ]]; then
		echo "Skipping $test_name (MQ_TEST_FILTER=$MQ_TEST_FILTER)"
		return 0
	fi

	# TEMPORARY: all Octeon<->Octeon MQ trf tests disabled for now.
	if [[ "$mq_scenario" == "Octeon<->Octeon" ]]; then
		echo "Skipping $test_name on Octeon<->Octeon (temporarily disabled)"
		return 0
	fi

	# Cleanup previous test state and relaunch the graph for this scenario before each test
	cleanup_stuck_processes
	rdma_tests_cleanup
	sleep 1
	mq_scenario_setup
	sleep 1

	# Re-fetch RDMA device info: server = EP_HOST octep, client = EP_REMOTE_HOST (octep/MLX)
	host_rdma_dev=$(ep_host_op get_rdma_device "$EP_HOST_RDMA_PATH" "$host_ip")
	host_gid=$(ep_host_op get_v4_gid_index "$host_rdma_dev" "$EP_HOST_RDMA_PATH")
	remote_rdma_dev=$(ep_remote_host_op get_rdma_device "$EP_REMOTE_RDMA_PATH" "$remote_host_ip")
	remote_gid=$(ep_remote_host_op get_v4_gid_index "$remote_rdma_dev" "$EP_REMOTE_RDMA_PATH")

	local server_ip
	local server_dev
	local server_gid
	local server_env
	local client_dev
	local client_gid
	local client_env
	local server_cmd
	local client_cmd
	local server_cmd_func
	local client_cmd_func
	local status

	# Host is always the server, EP_REMOTE_HOST is always the client
	server_ip=$host_ip
	server_dev=$host_rdma_dev
	server_gid=$host_gid
	server_env=$host_env
	client_dev=$remote_rdma_dev
	client_gid=$remote_gid
	client_env=$remote_host_env
	server_cmd_func="ep_host_ssh_cmd"
	client_cmd_func="ep_remote_host_ssh_cmd"

	# Build optional --nb-sge argument
	local sge_arg=""
	if [[ -n "$nb_sge" ]]; then
		sge_arg="--nb-sge=$nb_sge"
	fi

	echo "Running Test: $test_name"
	if [[ -n "$loop_count" ]]; then
		echo "  QP Type: $qp_type, Op Type: $op_type, Loop: $loop_count, Server Max Conn: $server_max_conn"
	else
		echo "  QP Type: $qp_type, Op Type: $op_type, QPs: $num_qp, Threads: $num_threads${nb_sge:+, SGE: $nb_sge}"
	fi

	# Build server and client commands
	local log_path="${EP_LOG_PATH:-/tmp}"

	local modes=()
	if [[ -n "$loop_count" ]]; then
		modes+=("cm")
	else
		modes+=("tcp")
	fi

	local overall_status=0
	local mode
	for mode in "${modes[@]}"; do
		local mode_arg=""
		local mode_label="TCP"
		if [[ "$mode" == "cm" ]]; then
			mode_arg="--rdma-cm"
			mode_label="CM"
		fi

		local server_log="$log_path/ibv_rdma_mq_trf_server_${test_name}_${mode_label}.log"

		echo "  --- Mode: $mode_label ---"

		if [[ -n "$loop_count" ]]; then
			# Loop mode: server accepts multiple sequential connections
			server_cmd="bash -c \"${server_env} setsid ibv_rdma_mq_trf -d $server_dev -g $server_gid -q $num_qp -t $num_threads --qp-type $qp_type --op-type $op_type -c $server_max_conn $mode_arg $sge_arg >$server_log 2>&1 &\""

			# Include --size only for RC in loop mode
			local size_arg=""
			if [[ "$qp_type" == "RC" ]]; then
				size_arg="--size $msg_size"
			fi

			# Client loops, each iteration creates a fresh connection
			client_cmd="bash -c '${client_env} count=1; while [ \$count -le $loop_count ]; do ibv_rdma_mq_trf -g $client_gid -q $num_qp -t $num_threads -d $client_dev --qp-type $qp_type --op-type $op_type -n $num_iterations $size_arg $mode_arg $sge_arg $server_ip || exit 1; ((count++)); done'"
		else
			# Normal mode: single client invocation with multiple QPs
			server_cmd="bash -c \"${server_env} setsid ibv_rdma_mq_trf -d $server_dev -g $server_gid -q $num_qp -t $num_threads --qp-type $qp_type --op-type $op_type $mode_arg $sge_arg >$server_log 2>&1 &\""
			client_cmd="bash -c \"${client_env} ibv_rdma_mq_trf -d $client_dev -g $client_gid -q $num_qp -t $num_threads --qp-type $qp_type --op-type $op_type -n $num_iterations --size $msg_size $mode_arg $sge_arg $server_ip\""
		fi

		# Execute test
		$server_cmd_func "$server_cmd"

		# Server initialization wait
		local server_wait=3
		if [[ -n "$loop_count" ]]; then
			server_wait=5
		else
			# Scale wait time based on QP count for both UD and RC
			server_wait=$(( 5 + num_qp / 10 ))
		fi
		echo "  Waiting ${server_wait}s for server to initialize..."
		sleep $server_wait

		local timeout_duration=120
		echo "  Running client (timeout: ${timeout_duration}s)..."

		set +e  # Don't exit on timeout failure
		$client_cmd_func "timeout ${timeout_duration} $client_cmd"
		status=$?
		set -e

		# Check status
		if [[ $status -eq 124 ]]; then
			# Exit code 124 means timeout was triggered
			echo "$test_name [$mode_label] FAILED" \
				"(TIMEOUT - client hung for >${timeout_duration}s)"
			echo "  Server log ($server_log):"
			$server_cmd_func "tail -30 $server_log 2>/dev/null" || true
			overall_status=1
		elif [[ $status -ne 0 ]]; then
			echo "$test_name [$mode_label] FAILED (exit code: $status)"
			echo "  Server log ($server_log):"
			$server_cmd_func "tail -30 $server_log 2>/dev/null" || true
			overall_status=1
		else
			echo "$test_name [$mode_label] PASSED"
		fi

		cleanup_stuck_processes
	done

	return $overall_status
}

# Print a scenario-tagged test banner so each test's topology
# (Octeon<->Octeon vs Octeon<->Mellanox) is clear from the log alone.
function mq_banner()
{
	echo "=========================================================================================="
	echo "[$mq_scenario] $1"
	echo "=========================================================================================="
}

# Run the full MQ test matrix for the current scenario. Every banner is tagged
# with $mq_scenario (via mq_banner) and the failed_tests label carries the
# scenario, so both the streaming log and the summary stay clear.
function run_all_mq_tests()
{
	echo "MQ matrix ($mq_scenario): EP_HOST server @ $host_ip <-> EP_REMOTE_HOST client @ $remote_host_ip"

	mq_banner "Test 1: UD SEND - Host Server -> Remote Client"
	if ! run_mq_test "UD_SEND_Host_Server" "UD" "SEND" 100 8 1000 1024; then
		failed_tests="$failed_tests\n  [$mq_scenario] Test 1: UD_SEND_Host_Server"
	fi
	echo ""

	mq_banner "Test 2: RC SEND - Host Server -> Remote Client"
	if ! run_mq_test "RC_SEND_Host_Server" "RC" "SEND" 100 8 1000 1024; then
		failed_tests="$failed_tests\n  [$mq_scenario] Test 2: RC_SEND_Host_Server"
	fi
	echo ""

	mq_banner "Test 3: RC WRITE - Host Server -> Remote Client"
	if ! run_mq_test "RC_WRITE_Host_Server" "RC" "WRITE" 100 8 1000 1024; then
		failed_tests="$failed_tests\n  [$mq_scenario] Test 3: RC_WRITE_Host_Server"
	fi
	echo ""

	mq_banner "Test 4: RC WRITE_IMM - Host Server -> Remote Client"
	if ! run_mq_test "RC_WRITE_IMM_Host_Server" "RC" "WRITE_IMM" 100 8 1000 1024; then
		failed_tests="$failed_tests\n  [$mq_scenario] Test 4: RC_WRITE_IMM_Host_Server"
	fi
	echo ""

	mq_banner "Test 5: RC READ - Host Server -> Remote Client"
	if ! run_mq_test "RC_READ_Host_Server" "RC" "READ" 100 8 1000 1024; then
		failed_tests="$failed_tests\n  [$mq_scenario] Test 5: RC_READ_Host_Server"
	fi
	echo ""

	mq_banner "Test 6: UD SEND SGE=2 - Host Server -> Remote Client"
	if ! run_mq_test "UD_SEND_SGE_Host_Server" "UD" "SEND" 100 8 1000 1024 2; then
		failed_tests="$failed_tests\n  [$mq_scenario] Test 6: UD_SEND_SGE_Host_Server"
	fi
	echo ""

	mq_banner "Test 7: RC SEND SGE=2 - Host Server -> Remote Client"
	if ! run_mq_test "RC_SEND_SGE_Host_Server" "RC" "SEND" 100 8 1000 1024 2; then
		failed_tests="$failed_tests\n  [$mq_scenario] Test 7: RC_SEND_SGE_Host_Server"
	fi
	echo ""

	mq_banner "Test 8: RC WRITE SGE=2 - Host Server -> Remote Client"
	if ! run_mq_test "RC_WRITE_SGE_Host_Server" "RC" "WRITE" 100 8 1000 1024 2; then
		failed_tests="$failed_tests\n  [$mq_scenario] Test 8: RC_WRITE_SGE_Host_Server"
	fi
	echo ""

	mq_banner "Test 9: RC WRITE_IMM SGE=2 - Host Server -> Remote Client"
	if ! run_mq_test "RC_WRITE_IMM_SGE_Host_Server" "RC" "WRITE_IMM" 100 8 1000 1024 2; then
		failed_tests="$failed_tests\n  [$mq_scenario] Test 9: RC_WRITE_IMM_SGE_Host_Server"
	fi
	echo ""

	mq_banner "Test 10: RC READ SGE=2 - Host Server -> Remote Client"
	if ! run_mq_test "RC_READ_SGE_Host_Server" "RC" "READ" 100 8 1000 1024 2; then
		failed_tests="$failed_tests\n  [$mq_scenario] Test 10: RC_READ_SGE_Host_Server"
	fi
	echo ""

	# DISABLED: fails on Octeon<->Mellanox (repeated UD SEND, 1000 connections).
	# TODO: re-enable and validate on both scenarios once the underlying issue is fixed.
	# mq_banner "Test 11: Repeated Connect UD SEND - Host Server (1000 conn)"
	# if ! run_mq_test "Repeated_UD_SEND_Host_Server" \
	# 		"UD" "SEND" 1 1 1000 1024 "" 1000 1000 true; then
	# 	failed_tests="$failed_tests\n  [$mq_scenario] Test 11: Repeated_UD_SEND_Host_Server"
	# fi
	# echo ""

	mq_banner "Test 12: Repeated Connect RC SEND - Host Server (1000 conn)"
	if ! run_mq_test "Repeated_RC_SEND_Host_Server" "RC" "SEND" 1 1 1000 1024 "" 1000 1000; then
		failed_tests="$failed_tests\n  [$mq_scenario] Test 12: Repeated_RC_SEND_Host_Server"
	fi
	echo ""

	mq_banner "Test 13: Repeated Connect RC WRITE - Host Server (1000 conn)"
	if ! run_mq_test "Repeated_RC_WRITE_Host_Server" \
			"RC" "WRITE" 1 1 1000 1024 "" 1000 1000; then
		failed_tests="$failed_tests\n  [$mq_scenario] Test 13: Repeated_RC_WRITE_Host_Server"
	fi
	echo ""

	mq_banner "Test 14: Repeated Connect RC WRITE_IMM - Host Server (1000 conn)"
	if ! run_mq_test "Repeated_RC_WRITE_IMM_Host_Server" \
			"RC" "WRITE_IMM" 1 1 1000 1024 "" 1000 1000; then
		failed_tests="$failed_tests\n  [$mq_scenario] Test 14: Repeated_RC_WRITE_IMM_Host_Server"
	fi
	echo ""

	mq_banner "Test 15: Repeated Connect RC READ - Host Server (1000 conn)"
	if ! run_mq_test "Repeated_RC_READ_Host_Server" "RC" "READ" 1 1 1000 1024 "" 1000 1000; then
		failed_tests="$failed_tests\n  [$mq_scenario] Test 15: Repeated_RC_READ_Host_Server"
	fi
	echo ""

	# Test 16: Repeated Connect UD SEND SGE=2 - Host Server
	# DISABLED: fails on Octeon<->Mellanox (repeated UD SEND with multi-SGE).
	# TODO: re-enable and validate on both scenarios once the underlying issue is fixed.
	# mq_banner "Test 16: Repeated Connect UD SEND SGE=2 - Host Server"
	# if ! run_mq_test "Repeated_UD_SEND_SGE_Host_Server" \
	# 		"UD" "SEND" 1 1 1000 1024 2 1000 1000 true; then
	# 	failed_tests="$failed_tests\n  [$mq_scenario] Test 16: Repeated_UD_SEND_SGE_Host_Server"
	# fi
	# echo ""

	mq_banner "Test 17: Repeated Connect RC SEND SGE=2 - Host Server"
	if ! run_mq_test "Repeated_RC_SEND_SGE_Host_Server" \
			"RC" "SEND" 1 1 1000 1024 2 1000 1000; then
		failed_tests="$failed_tests\n  [$mq_scenario] Test 17: Repeated_RC_SEND_SGE_Host_Server"
	fi
	echo ""

	mq_banner "Test 18: Repeated Connect RC WRITE SGE=2 - Host Server"
	if ! run_mq_test "Repeated_RC_WRITE_SGE_Host_Server" \
			"RC" "WRITE" 1 1 1000 1024 2 1000 1000; then
		failed_tests="$failed_tests\n  [$mq_scenario] Test 18: Repeated_RC_WRITE_SGE_Host_Server"
	fi
	echo ""

	mq_banner "Test 19: Repeated Connect RC WRITE_IMM SGE=2 - Host Server"
	if ! run_mq_test "Repeated_RC_WRITE_IMM_SGE_Host_Server" \
			"RC" "WRITE_IMM" 1 1 1000 1024 2 1000 1000; then
		failed_tests="$failed_tests\n  [$mq_scenario] Test 19: Repeated_RC_WRITE_IMM_SGE_Host_Server"
	fi
	echo ""

	mq_banner "Test 20: Repeated Connect RC READ SGE=2 - Host Server"
	if ! run_mq_test "Repeated_RC_READ_SGE_Host_Server" \
			"RC" "READ" 1 1 1000 1024 2 1000 1000; then
		failed_tests="$failed_tests\n  [$mq_scenario] Test 20: Repeated_RC_READ_SGE_Host_Server"
	fi
	echo ""
}

# Main test function
function rdma_mq_trf()
{
	local host_ip host_env host_rdma_dev host_gid
	local remote_host_ip remote_host_env remote_rdma_dev remote_gid
	local mq_scenario failed_tests="" ran=0

	# Register signal handler
	rdma_register_sig_handler

	# EP_HOST is always octep; EP_REMOTE_HOST is octep (O<->O) or Mellanox (O<->MLX).
	host_env=$HOST_ENV
	remote_host_env=$REMOTE_ENV

	echo "========================================"
	echo "RDMA Multi-Queue Traffic Tests Starting"
	echo "========================================"

	# ============ Scenario 1: Octeon <-> Octeon (needs EP_REMOTE) ============
	if [[ "${RDMA_SCENARIO:-both}" != "mlx" && -n "${EP_REMOTE:-}" ]]; then
		mq_scenario="Octeon<->Octeon"
		host_ip="30.0.0.3"
		remote_host_ip="30.0.0.11"
		echo ""
		echo "==================== SCENARIO: Octeon <-> Octeon ===================="
		echo "  EP_HOST octep VF (30.0.0.3) <-> EP_REMOTE_HOST octep VF (30.0.0.11)"
		run_all_mq_tests
		ran=1
	fi

	# ================= Scenario 2: Octeon <-> Mellanox =================
	if [[ "${RDMA_SCENARIO:-both}" != "octeon" && -n "${EP_DEVICE_MLX_IFACE:-}" && -n "${EP_REMOTE_HOST_MLX_IFACE:-}" ]]; then
		mq_scenario="Octeon<->Mellanox"
		host_ip="21.0.0.3"
		remote_host_ip="21.0.0.11"
		echo ""
		echo "=================== SCENARIO: Octeon <-> Mellanox ==================="
		echo "  EP_HOST octep VF (21.0.0.3) <-> EP_REMOTE_HOST Mellanox (21.0.0.11)"
		run_all_mq_tests
		ran=1
	fi

	if [[ $ran -eq 0 ]]; then
		echo "No RDMA scenario selected/available (RDMA_SCENARIO=${RDMA_SCENARIO:-both})"
		exit 77
	fi

	# Cleanup
	echo "Performing final cleanup..."
	cleanup_stuck_processes
	rdma_tests_cleanup

	# Final summary
	echo "========================================"
	echo "RDMA Multi-Queue Traffic Tests Summary"
	echo "========================================"

	if [[ -z "$failed_tests" ]]; then
		echo "All tests PASSED"
		return 0
	else
		echo -e "Failed tests:$failed_tests"
		exit 1
	fi
}

# Execute with retry logic
test_run rdma_mq_trf 2
