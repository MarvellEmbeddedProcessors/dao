#!/bin/bash
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2025 Marvell.

# perftest binaries that may be left running and need to be cleaned up
PERFTEST_BINARIES=(
	"ib_send_bw"
	"ib_send_lat"
	"ib_write_bw"
	"ib_write_lat"
	"ib_read_bw"
	"ib_read_lat"
)

PERFTEST_CLIENT_TIMEOUT=600
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

function perftest_use_events()
{
	local want=$1

	if [[ "${PERFTEST_CI_CATEGORY:-}" == "benchmark" ]]; then
		echo no
		return
	fi
	echo "$want"
}

function perftest_case_qp_count()
{
	local binary=$1

	if [[ "$binary" == *_bw ]]; then
		echo "${PERFTEST_BW_QP}"
	else
		echo 1
	fi
}

function run_perftest_case()
{
	local test_name=$1
	local binary=$2
	local conn_type=$3
	local use_cm=$4
	local server_node=$5
	local use_events=${6:-no}

	local server_env server_dev server_gid server_ssh
	local client_env client_dev client_gid client_ssh
	local server_ip
	local status=1
	local bw_qp=${PERFTEST_BW_QP}

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

	local eff_use_cm=$use_cm
	local cm_opt=""
	[[ "$eff_use_cm" == "yes" ]] && cm_opt="-R"

	local q_opt=""
	local qp_label="1"
	if [[ "$binary" == *_bw ]]; then
		q_opt="-q $bw_qp"
		qp_label="$bw_qp"
		if [[ "${PERFTEST_CI_CATEGORY:-}" == "benchmark" ]]; then
			q_opt="$q_opt --max_size_mb 8"
		else
			q_opt="$q_opt --max_size_mb 1"
		fi
	fi

	local event_opt=""
	[[ "$use_events" == "yes" ]] && event_opt="-e"

	local server_opts="-d $server_dev -i 1 -x $server_gid -c $conn_type $cm_opt $event_opt -F --report_gbits -a $q_opt"
	local client_opts="-d $client_dev -i 1 -x $client_gid -c $conn_type $cm_opt -F --report_gbits -a $q_opt"

	local log_path="${EP_LOG_PATH:-/tmp}"
	local server_log="$log_path/${binary}_${test_name}_server.log"

	echo "  --- $test_name ($server_node server, $conn_type, QPs=$qp_label," \
		"cm=$eff_use_cm, events=$use_events, binary=$binary) ---"

	local srv_run="${server_env} setsid stdbuf -oL $binary $server_opts"
	local server_cmd="bash -c \"( time ( ${srv_run} ) ) >$server_log 2>&1 &\""
	local client_cmd="bash -c \"time ( ${client_env} $binary $client_opts $server_ip )\""

	local attempt
	for (( attempt = 1; attempt <= PERFTEST_CASE_ATTEMPTS; attempt++ )); do
		cleanup_perftest_processes

		$server_ssh "$server_cmd"
		local _sw
		local server_ready=""
		for _sw in $(seq 1 30); do
			if $server_ssh "grep -q 'Waiting for client' $server_log 2>/dev/null"; then
				server_ready=1
				break
			fi
			sleep 1
		done
		if [[ -z "$server_ready" ]]; then
			echo "  WARNING: server log did not show 'Waiting for client' after 30s, proceeding with fallback sleep"
			sleep 5
		fi

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
	if [[ $status -eq 124 ]]; then
		rdma_ci_results_print_interim
	fi
	return 1
}

function run_perftest_bidir()
{
	local test_name=$1
	if [[ -n "${PERFTEST_FILTER:-}" && "$test_name" != *"$PERFTEST_FILTER"* ]]; then
		echo "  Skipping $test_name (PERFTEST_FILTER=$PERFTEST_FILTER)"
		rdma_ci_result_add "$test_name" "Skip"
		return 0
	fi
	local binary=$2
	local conn_type=$3
	local use_cm=$4
	local use_events=${5:-no}
	local rc=0

	rdma_ci_running_line "$test_name" "$(perftest_case_qp_count "$binary")"

	if ! run_perftest_case "$test_name" "$binary" \
		"$conn_type" "$use_cm" "host" "$use_events"; then
		rc=1
	fi
	if ! run_perftest_case "$test_name" "$binary" \
		"$conn_type" "$use_cm" "remote" "$use_events"; then
		rc=1
	fi

	if [[ $rc -eq 0 ]]; then
		rdma_ci_result_add "$test_name" "Pass"
	else
		rdma_ci_result_add "$test_name" "Fail"
		rdma_ci_results_print_interim
	fi
	echo ""
	return $rc
}

PERFTEST_MATRIX=(
	"UD_SEND_LAT:ib_send_lat:UD:yes:yes"
	"UD_SEND_BW:ib_send_bw:UD:yes:yes"
	"RC_SEND_LAT:ib_send_lat:RC:yes:yes"
	"RC_SEND_BW:ib_send_bw:RC:yes:yes"
	"RC_WRITE_LAT:ib_write_lat:RC:yes:no"
	"RC_WRITE_BW:ib_write_bw:RC:yes:no"
	"RC_READ_LAT:ib_read_lat:RC:yes:yes"
	"RC_READ_BW:ib_read_bw:RC:yes:yes"
)

function run_all_perftests()
{
	local row name binary conn cm want_events

	echo "Perftest matrix ($rdma_topo_label): ${#PERFTEST_MATRIX[@]} cases, BW QP=${PERFTEST_BW_QP}"

	for row in "${PERFTEST_MATRIX[@]}"; do
		IFS=: read -r name binary conn cm want_events <<< "$row"

		run_perftest_bidir "$name" "$binary" "$conn" "$cm" \
			"$(perftest_use_events "$want_events")" || true
	done
}

function perftest_topo_run()
{
	run_all_perftests
}

function rdma_perftest()
{
	rdma_ci_results_reset

	rdma_register_sig_handler
	rdma_ci_running_line "${PERFTEST_DISPLAY_NAME:-RDMA perftest}" "${PERFTEST_BW_QP:?}"
	rdma_ci_perftest_profile_line

	rdma_foreach_topo perftest_topo_run full || true

	cleanup_perftest_processes

	if rdma_ci_suite_finish; then
		return 0
	fi
	exit 1
}
