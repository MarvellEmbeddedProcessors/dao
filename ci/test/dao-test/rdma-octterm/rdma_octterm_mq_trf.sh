#!/bin/bash
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2025 Marvell.

# RDMA Octeon Termination Multi-Queue Traffic Tests
# In octterm mode, kmod+firmware run on the same Octeon SoC (EP_DEVICE).
# Server runs locally on Octeon, client runs on remote peer.
#
# Scenarios:
#   1. Octeon <-> Mellanox: EP_DEVICE (octterm) <-> EP_REMOTE_HOST (native RoCE)
#   2. Octeon <-> Octeon:   EP_DEVICE (octterm) <-> EP_REMOTE (octterm)
#
# Tests per scenario:
#   UD/RC SEND, RC WRITE/WRITE_IMM/READ, SGE=2 variants, repeated connections.

set -euo pipefail

SCRIPT_DIR="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
source "$SCRIPT_DIR/rdma_octterm_utils.sh"

function cleanup_stuck_processes()
{
	echo "  Cleaning up any stuck ibv_rdma_mq_trf processes..."

	local safe_kill_cmd="source $EP_DIR/ci/test/dao-test/common/utils.sh && safe_kill ibv_rdma_mq_trf"

	octterm_local_cmd "$safe_kill_cmd" || true

	if [[ "$mq_scenario" == "Octeon<->Mellanox" ]]; then
		if [[ -n "${EP_REMOTE_HOST:-}" ]]; then
			ep_remote_host_ssh_cmd "$safe_kill_cmd" || true
		fi
	else
		if [[ -n "${EP_REMOTE:-}" ]]; then
			ep_remote_ssh_cmd "$safe_kill_cmd" || true
		fi
	fi

	sleep 1
}

# Relaunch octterm datapath for the current scenario before each mq test.
# mq_scenario / local_ip / remote_ip come from the caller.
function mq_scenario_setup()
{
	if [[ "$mq_scenario" == "Octeon<->Mellanox" ]]; then
		rdma_octterm_setup_configure_mlx "$local_ip" "$remote_ip" "$skip_mbuf_opts"
	else
		rdma_octterm_setup_configure_octeon "$local_ip" "$remote_ip" "$skip_mbuf_opts"
	fi
}

function run_octterm_mq_test()
{
	local test_name=$1
	local qp_type=$2
	local op_type=$3
	local num_qp=${4:-100}
	local num_threads=${5:-8}
	local num_iterations=${6:-10}
	local msg_size=${7:-1024}
	local nb_sge=${8:-}
	local loop_count=${9:-}
	local server_max_conn=${10:-1000}
	local skip_mbuf_opts=${11:-false}

	cleanup_stuck_processes
	rdma_octterm_tests_cleanup
	sleep 1
	mq_scenario_setup
	sleep 1

	# Resolve RDMA devices after setup
	local local_rdma_dev local_gid remote_rdma_dev remote_gid

	local_rdma_dev=$(rdma_octterm_get_rdma_device "$EP_HOST_RDMA_PATH" "$local_ip")
	local_gid=$(rdma_octterm_get_v4_gid_index $local_rdma_dev "$EP_HOST_RDMA_PATH")

	if [[ "$mq_scenario" == "Octeon<->Mellanox" ]]; then
		remote_rdma_dev=$(ep_remote_host_op get_rdma_device \
			"$EP_REMOTE_RDMA_PATH" "$remote_ip")
		remote_gid=$(ep_remote_host_op get_v4_gid_index \
			$remote_rdma_dev "$EP_REMOTE_RDMA_PATH")
	else
		remote_rdma_dev=$(ep_remote_op get_rdma_device "$EP_HOST_RDMA_PATH" "$remote_ip")
		remote_gid=$(ep_remote_op get_v4_gid_index $remote_rdma_dev "$EP_HOST_RDMA_PATH")
	fi

	local server_ip=$local_ip
	local server_dev=$local_rdma_dev
	local server_gid=$local_gid
	local server_env=$local_env
	local client_dev=$remote_rdma_dev
	local client_gid=$remote_gid
	local client_env=$remote_env
	local client_ssh_fn=$remote_ssh_fn
	local status

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

		local server_cmd
		local client_cmd

		if [[ -n "$loop_count" ]]; then
			server_cmd="${server_env} setsid ibv_rdma_mq_trf -d $server_dev -g $server_gid -q $num_qp -t $num_threads --qp-type $qp_type --op-type $op_type -c $server_max_conn $mode_arg $sge_arg >$server_log 2>&1 &"

			local size_arg=""
			if [[ "$qp_type" == "RC" ]]; then
				size_arg="--size $msg_size"
			fi

			client_cmd="bash -c '${client_env} count=1; while [ \$count -le $loop_count ]; do ibv_rdma_mq_trf -g $client_gid -q $num_qp -t $num_threads -d $client_dev --qp-type $qp_type --op-type $op_type -n $num_iterations $size_arg $mode_arg $sge_arg $server_ip || exit 1; ((count++)); done'"
		else
			server_cmd="${server_env} setsid ibv_rdma_mq_trf -d $server_dev -g $server_gid -q $num_qp -t $num_threads --qp-type $qp_type --op-type $op_type $mode_arg $sge_arg >$server_log 2>&1 &"
			client_cmd="bash -c \"${client_env} ibv_rdma_mq_trf -d $client_dev -g $client_gid -q $num_qp -t $num_threads --qp-type $qp_type --op-type $op_type -n $num_iterations --size $msg_size $mode_arg $sge_arg $server_ip\""
		fi

		# Server runs locally on Octeon
		eval "$server_cmd"

		local server_wait=3
		if [[ -n "$loop_count" ]]; then
			server_wait=5
		else
			server_wait=$(( 5 + num_qp / 10 ))
		fi
		echo "  Waiting ${server_wait}s for server to initialize..."
		sleep $server_wait

		local timeout_duration=120
		echo "  Running client on remote (timeout: ${timeout_duration}s)..."

		set +e
		$client_ssh_fn "timeout ${timeout_duration} $client_cmd"
		status=$?
		set -e

		if [[ $status -eq 124 ]]; then
			echo "$test_name [$mode_label] FAILED" \
				"(TIMEOUT - client hung for >${timeout_duration}s)"
			echo "  Server log ($server_log):"
			tail -30 "$server_log" 2>/dev/null || true
			overall_status=1
		elif [[ $status -ne 0 ]]; then
			echo "$test_name [$mode_label] FAILED (exit code: $status)"
			echo "  Server log ($server_log):"
			tail -30 "$server_log" 2>/dev/null || true
			overall_status=1
		else
			echo "$test_name [$mode_label] PASSED"
		fi

		cleanup_stuck_processes
	done

	return $overall_status
}

function mq_banner()
{
	echo "=========================================================================================="
	echo "[$mq_scenario] $1"
	echo "=========================================================================================="
}

function run_all_octterm_mq_tests()
{
	echo "MQ matrix ($mq_scenario): Local server @ $local_ip <-> Remote client @ $remote_ip"

	mq_banner "Test 1: UD SEND"
	if ! run_octterm_mq_test "UD_SEND_Octterm" "UD" "SEND" 100 8 1000 1024; then
		failed_tests="$failed_tests\n  [$mq_scenario] Test 1: UD_SEND_Octterm"
	fi
	echo ""

	mq_banner "Test 2: RC SEND"
	if ! run_octterm_mq_test "RC_SEND_Octterm" "RC" "SEND" 100 8 1000 1024; then
		failed_tests="$failed_tests\n  [$mq_scenario] Test 2: RC_SEND_Octterm"
	fi
	echo ""

	mq_banner "Test 3: RC WRITE"
	if ! run_octterm_mq_test "RC_WRITE_Octterm" "RC" "WRITE" 100 8 1000 1024; then
		failed_tests="$failed_tests\n  [$mq_scenario] Test 3: RC_WRITE_Octterm"
	fi
	echo ""

	mq_banner "Test 4: RC WRITE_IMM"
	if ! run_octterm_mq_test "RC_WRITE_IMM_Octterm" "RC" "WRITE_IMM" 100 8 1000 1024; then
		failed_tests="$failed_tests\n  [$mq_scenario] Test 4: RC_WRITE_IMM_Octterm"
	fi
	echo ""

	mq_banner "Test 5: RC READ"
	if ! run_octterm_mq_test "RC_READ_Octterm" "RC" "READ" 100 8 1000 1024; then
		failed_tests="$failed_tests\n  [$mq_scenario] Test 5: RC_READ_Octterm"
	fi
	echo ""

	mq_banner "Test 6: UD SEND SGE=2"
	if ! run_octterm_mq_test "UD_SEND_SGE_Octterm" "UD" "SEND" 100 8 1000 1024 2; then
		failed_tests="$failed_tests\n  [$mq_scenario] Test 6: UD_SEND_SGE_Octterm"
	fi
	echo ""

	mq_banner "Test 7: RC SEND SGE=2"
	if ! run_octterm_mq_test "RC_SEND_SGE_Octterm" "RC" "SEND" 100 8 1000 1024 2; then
		failed_tests="$failed_tests\n  [$mq_scenario] Test 7: RC_SEND_SGE_Octterm"
	fi
	echo ""

	mq_banner "Test 8: RC WRITE SGE=2"
	if ! run_octterm_mq_test "RC_WRITE_SGE_Octterm" "RC" "WRITE" 100 8 1000 1024 2; then
		failed_tests="$failed_tests\n  [$mq_scenario] Test 8: RC_WRITE_SGE_Octterm"
	fi
	echo ""

	mq_banner "Test 9: RC WRITE_IMM SGE=2"
	if ! run_octterm_mq_test "RC_WRITE_IMM_SGE_Octterm" "RC" "WRITE_IMM" 100 8 1000 1024 2; then
		failed_tests="$failed_tests\n  [$mq_scenario] Test 9: RC_WRITE_IMM_SGE_Octterm"
	fi
	echo ""

	mq_banner "Test 10: RC READ SGE=2"
	if ! run_octterm_mq_test "RC_READ_SGE_Octterm" "RC" "READ" 100 8 1000 1024 2; then
		failed_tests="$failed_tests\n  [$mq_scenario] Test 10: RC_READ_SGE_Octterm"
	fi
	echo ""

	# DISABLED: repeated UD SEND fails on Octeon<->Mellanox.
	# mq_banner "Test 11: Repeated Connect UD SEND (1000 conn)"
	# if ! run_octterm_mq_test "Repeated_UD_SEND_Octterm" \
	# 		"UD" "SEND" 1 1 1000 1024 "" 1000 1000 true; then
	# 	failed_tests="$failed_tests\n  [$mq_scenario] Test 11: Repeated_UD_SEND_Octterm"
	# fi
	# echo ""

	# DISABLED: repeated RC SEND fails on Octeon<->Mellanox.
	# mq_banner "Test 12: Repeated Connect RC SEND (1000 conn)"
	# if ! run_octterm_mq_test "Repeated_RC_SEND_Octterm" \
	# 		"RC" "SEND" 1 1 1000 1024 "" 1000 1000; then
	# 	failed_tests="$failed_tests\n  [$mq_scenario] Test 12: Repeated_RC_SEND_Octterm"
	# fi
	# echo ""

	# Repeated RC WRITE/WRITE_IMM [CM] disabled for Octeon<->Octeon.
	if [[ "$mq_scenario" != "Octeon<->Octeon" ]]; then
		mq_banner "Test 13: Repeated Connect RC WRITE (1000 conn)"
		if ! run_octterm_mq_test "Repeated_RC_WRITE_Octterm" \
				"RC" "WRITE" 1 1 1000 1024 "" 1000 1000; then
			failed_tests="$failed_tests\n  [$mq_scenario] Test 13: Repeated_RC_WRITE_Octterm"
		fi
		echo ""

		mq_banner "Test 14: Repeated Connect RC WRITE_IMM (1000 conn)"
		if ! run_octterm_mq_test "Repeated_RC_WRITE_IMM_Octterm" \
				"RC" "WRITE_IMM" 1 1 1000 1024 "" 1000 1000; then
			failed_tests="$failed_tests\n  [$mq_scenario] Test 14: Repeated_RC_WRITE_IMM_Octterm"
		fi
		echo ""
	fi

	# Repeated RC READ [CM] disabled for Octeon<->Octeon.
	if [[ "$mq_scenario" != "Octeon<->Octeon" ]]; then
		mq_banner "Test 15: Repeated Connect RC READ (1000 conn)"
		if ! run_octterm_mq_test "Repeated_RC_READ_Octterm" \
				"RC" "READ" 1 1 1000 1024 "" 1000 1000; then
			failed_tests="$failed_tests\n  [$mq_scenario] Test 15: Repeated_RC_READ_Octterm"
		fi
		echo ""
	fi

	# DISABLED: repeated UD SEND SGE=2 fails on Octeon<->Mellanox.
	# mq_banner "Test 16: Repeated Connect UD SEND SGE=2 (1000 conn)"
	# if ! run_octterm_mq_test "Repeated_UD_SEND_SGE_Octterm" \
	# 		"UD" "SEND" 1 1 1000 1024 2 1000 1000 true; then
	# 	failed_tests="$failed_tests\n  [$mq_scenario] Test 16: Repeated_UD_SEND_SGE_Octterm"
	# fi
	# echo ""

	# DISABLED: repeated RC SEND SGE=2 fails on Octeon<->Mellanox.
	# mq_banner "Test 17: Repeated Connect RC SEND SGE=2 (1000 conn)"
	# if ! run_octterm_mq_test "Repeated_RC_SEND_SGE_Octterm" \
	# 		"RC" "SEND" 1 1 1000 1024 2 1000 1000; then
	# 	failed_tests="$failed_tests\n  [$mq_scenario] Test 17: Repeated_RC_SEND_SGE_Octterm"
	# fi
	# echo ""

	# Repeated RC WRITE/WRITE_IMM/READ SGE=2 [CM] disabled for Octeon<->Octeon.
	if [[ "$mq_scenario" != "Octeon<->Octeon" ]]; then
		mq_banner "Test 18: Repeated Connect RC WRITE SGE=2 (1000 conn)"
		if ! run_octterm_mq_test "Repeated_RC_WRITE_SGE_Octterm" \
				"RC" "WRITE" 1 1 1000 1024 2 1000 1000; then
			failed_tests="$failed_tests\n  [$mq_scenario] Test 18: Repeated_RC_WRITE_SGE_Octterm"
		fi
		echo ""

		mq_banner "Test 19: Repeated Connect RC WRITE_IMM SGE=2 (1000 conn)"
		if ! run_octterm_mq_test "Repeated_RC_WRITE_IMM_SGE_Octterm" \
				"RC" "WRITE_IMM" 1 1 1000 1024 2 1000 1000; then
			failed_tests="$failed_tests\n  [$mq_scenario] Test 19: Repeated_RC_WRITE_IMM_SGE_Octterm"
		fi
		echo ""

		mq_banner "Test 20: Repeated Connect RC READ SGE=2 (1000 conn)"
		if ! run_octterm_mq_test "Repeated_RC_READ_SGE_Octterm" \
				"RC" "READ" 1 1 1000 1024 2 1000 1000; then
			failed_tests="$failed_tests\n  [$mq_scenario] Test 20: Repeated_RC_READ_SGE_Octterm"
		fi
		echo ""
	fi
}

function mq_topo_run()
{
	mq_scenario=$octterm_topo_label
	run_all_octterm_mq_tests
}

function rdma_octterm_mq_trf()
{
	local octterm_topo_id octterm_topo_label
	local local_ip remote_ip local_env remote_env remote_ssh_fn
	local mq_scenario failed_tests=""

	rdma_octterm_register_sig_handler

	echo "========================================================"
	echo "RDMA Octterm Multi-Queue Traffic Tests Starting"
	echo "========================================================"

	# Each test cleans up and relaunches the datapath itself, so only the
	# per-scenario variables are needed here.
	rdma_octterm_foreach_topo mq_topo_run vars || true

	# Cleanup
	echo "Performing final cleanup..."
	cleanup_stuck_processes
	rdma_octterm_tests_cleanup

	echo "========================================================"
	echo "RDMA Octterm Multi-Queue Traffic Tests Summary"
	echo "========================================================"

	if [[ -z "$failed_tests" ]]; then
		echo "All tests PASSED"
		return 0
	else
		echo -e "Failed tests:$failed_tests"
		exit 1
	fi
}

test_run rdma_octterm_mq_trf 2
