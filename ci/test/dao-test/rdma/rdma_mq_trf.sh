#!/bin/bash
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2025 Marvell.

# RDMA Multi-Queue Traffic Tests
# Verifies RDMA multi-queue functionality with various QP types and operations:
#   1. UD Mode - SEND operations
#   2. RC Mode - SEND, WRITE, WRITE_IMM, READ operations
# EP_HOST (Octeon) is always the server; EP_REMOTE_HOST (octep VF for
# Octeon<->Octeon, Mellanox for Octeon<->Mellanox) is always the client.
# Runs over every test the bench supports (guards: EP_REMOTE / MLX ifaces).

set -euo pipefail

SCRIPT_DIR="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
source "$SCRIPT_DIR/rdma_utils.sh"
source "$SCRIPT_DIR/rdma_mq_matrix.sh"

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

# Relaunch dao-rdma_graph + bring up endpoints for the current topology.
function mq_topo_setup()
{
	rdma_topo_start "$rdma_topo_id"
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
		rdma_ci_result_add "$test_name" "Skip"
		return 0
	fi

	# TEMPORARY: all Octeon<->Octeon MQ trf tests disabled for now.
	if [[ "$rdma_topo_id" == "octeon" ]]; then
		echo "Skipping $test_name on Octeon<->Octeon (temporarily disabled)"
		rdma_ci_result_add "$test_name" "Skip"
		return 0
	fi

	# Cleanup previous test state and relaunch the graph before each test
	cleanup_stuck_processes
	rdma_tests_cleanup
	sleep 1
	mq_topo_setup
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

	rdma_ci_running_line "$test_name" "$num_qp"
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

	if [[ $overall_status -eq 0 ]]; then
		rdma_ci_result_add "$test_name" "Pass"
	else
		rdma_ci_result_add "$test_name" "Fail"
		rdma_ci_results_print_interim
	fi

	return $overall_status
}

function mq_banner()
{
	echo "=========================================================================================="
	echo "[$rdma_topo_label] $1"
	echo "=========================================================================================="
}

function run_all_mq_tests()
{
	echo "MQ matrix ($rdma_topo_label): EP_HOST server @ $host_ip <-> EP_REMOTE_HOST client @ $remote_host_ip"
	rdma_mq_run_matrix
}

function mq_topo_run()
{
	run_all_mq_tests
}

function rdma_mq_trf()
{
	rdma_ci_results_reset

	rdma_register_sig_handler
	rdma_ci_running_line "RDMA mq_trf" "100"

	rdma_foreach_topo mq_topo_run vars || true

	echo "Performing final cleanup..."
	cleanup_stuck_processes
	rdma_tests_cleanup

	if rdma_ci_suite_finish; then
		return 0
	fi
	exit 1
}

# Execute with retry logic
test_run rdma_mq_trf 2
