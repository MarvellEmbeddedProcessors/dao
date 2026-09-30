#!/bin/bash
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2026 Marvell.

RDMA_CI_RESULTS=()

function rdma_ci_test_type()
{
	case "${RDMA_CI_TEST_TYPE:-functionality}" in
	benchmark) echo "benchmark" ;;
	functionality) echo "functionality" ;;
	*) echo "${RDMA_CI_TEST_TYPE:-functionality}" ;;
	esac
}

function rdma_ci_results_section_title()
{
	case "$(rdma_ci_test_type)" in
	benchmark) echo "Benchmark" ;;
	*) echo "Fun" ;;
	esac
}

function rdma_ci_results_reset()
{
	RDMA_CI_RESULTS=()
}

function rdma_ci_result_add()
{
	local name=$1
	local status=$2

	RDMA_CI_RESULTS+=("$name|$status")
}

function rdma_ci_results_has_fail()
{
	local row _name status

	for row in "${RDMA_CI_RESULTS[@]}"; do
		IFS='|' read -r _name status <<< "$row"
		if [[ "$status" == "Fail" ]]; then
			return 0
		fi
	done
	return 1
}

function rdma_ci_results_print()
{
	local subtitle=${1:-}
	local row name status
	local n=1
	local fails=0
	local title

	title="$(rdma_ci_results_section_title)"
	if [[ -n "$subtitle" ]]; then
		title="$title — $subtitle"
	fi

	echo ""
	echo "========================================"
	echo "$title"
	echo "========================================"
	if [[ ${#RDMA_CI_RESULTS[@]} -eq 0 ]]; then
		echo "   (no test results recorded)"
		echo ""
		return 0
	fi
	for row in "${RDMA_CI_RESULTS[@]}"; do
		IFS='|' read -r name status <<< "$row"
		printf "   %2d. %-42s %s\n" "$n" "$name" "$status"
		n=$((n + 1))
		[[ "$status" == "Fail" ]] && fails=$((fails + 1))
	done
	echo ""
	if [[ $fails -eq 0 ]]; then
		echo "Overall: PASS"
	else
		echo "Overall: FAIL ($fails failed)"
	fi
	return $fails
}

function rdma_ci_results_print_interim()
{
	echo ""
	echo "*** Detailed test state (failure / timeout) ***"
	rdma_ci_results_print
}

function rdma_ci_suite_finish()
{
	rdma_ci_results_print
	if rdma_ci_results_has_fail; then
		return 1
	fi
	return 0
}

function rdma_ci_running_line()
{
	local test_name=$1
	local num_qp=$2

	echo "Running $test_name with $num_qp QP(s) with $(rdma_ci_config_label) config [$(rdma_ci_test_type)]"
}

function rdma_ci_perftest_profile_line()
{
	case "${PERFTEST_CI_CATEGORY:-}" in
	benchmark)
		echo "  perftest: benchmark profile (BW QPs=${PERFTEST_BW_QP:-4}, poll only, no -e)"
		;;
	functionality)
		echo "  perftest: functionality profile (BW QPs=${PERFTEST_BW_QP:-128}, events on SEND/READ)"
		;;
	esac
	if [[ "${RDMA_DMA_OPS_MODE:-0}" == "1" ]]; then
		echo "  dma: graph --dma-ops-mode enabled"
	fi
}

function rdma_ci_summary_header()
{
	local title=$1

	echo "========================================"
	echo "$title"
	echo "========================================"
}

function rdma_ci_summary_ok()
{
	local title=$1

	rdma_ci_summary_header "$title"
	echo "All cases PASSED"
}

function rdma_ci_summary_fail()
{
	local title=$1
	local failed_list=$2

	rdma_ci_summary_header "$title"
	echo -e "Failed cases:$failed_list"
}
