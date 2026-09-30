#!/bin/bash
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2025 Marvell.

function rdma_perf_profile_benchmark()
{
	export RDMA_CI_TEST_TYPE=benchmark
	export PERFTEST_CI_CATEGORY=benchmark
	export PERFTEST_BW_QP=${PERFTEST_BENCH_BW_QP:-4}
	export PERFTEST_DISPLAY_NAME="RDMA benchmark perftest"
}

function rdma_perf_profile_functionality()
{
	export RDMA_CI_TEST_TYPE=functionality
	export PERFTEST_CI_CATEGORY=functionality
	export PERFTEST_BW_QP=${PERFTEST_FUNC_BW_QP:-128}
	export PERFTEST_DISPLAY_NAME="RDMA functionality perftest"
}
