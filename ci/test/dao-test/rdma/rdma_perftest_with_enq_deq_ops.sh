#!/bin/bash
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2026 Marvell.

set -euo pipefail
export RDMA_DMA_OPS_MODE=1
export RDMA_CI_TEST_TYPE=functionality
SCRIPT_DIR="$( cd -- "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 ; pwd -P )"
source "$SCRIPT_DIR/rdma_perftest.sh"
