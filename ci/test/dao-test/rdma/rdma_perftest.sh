#!/bin/bash
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2025 Marvell.

set -euo pipefail

SCRIPT_DIR="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
source "$SCRIPT_DIR/rdma_utils.sh"
source "$SCRIPT_DIR/rdma_perf_config.sh"

case "${RDMA_CI_TEST_TYPE:-functionality}" in
benchmark) rdma_perf_profile_benchmark ;;
*) rdma_perf_profile_functionality ;;
esac

if [[ "${RDMA_DMA_OPS_MODE:-0}" == "1" ]]; then
	export PERFTEST_DISPLAY_NAME="RDMA functionality perftest (DMA ops mode)"
fi

source "$SCRIPT_DIR/rdma_perftest_lib.sh"
test_run rdma_perftest 2
