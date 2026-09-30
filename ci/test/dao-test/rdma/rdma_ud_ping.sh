#!/bin/bash
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2025 Marvell.

# RDMA UD Functional Tests
# Runs ibv_ud_pingpong in both directions over both octep RDMA data paths:
#   1. Octeon<->Octeon  : EP_HOST octep VF <-> EP_REMOTE_HOST octep VF (30.0.0.x)
#   2. Octeon<->Mellanox: EP_HOST octep VF <-> EP_REMOTE_HOST Mellanox (21.0.0.x)

set -euo pipefail

SCRIPT_DIR="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
source "$SCRIPT_DIR/rdma_utils.sh"

function ud_ping_topo_run()
{
	local label="UD pingpong ($rdma_topo_label)"

	if rdma_pingpong_bidir ibv_ud_pingpong "$rdma_topo_label"; then
		rdma_ci_result_add "$label" "Pass"
		return 0
	fi
	rdma_ci_result_add "$label" "Fail"
	rdma_ci_results_print_interim
	return 1
}

function rdma_ud_ping()
{
	rdma_ci_results_reset

	rdma_register_sig_handler
	rdma_ci_running_line "UD pingpong" "1"

	rdma_foreach_topo ud_ping_topo_run full || true

	if rdma_ci_suite_finish; then
		return 0
	fi
	exit 1
}
test_run rdma_ud_ping 2
