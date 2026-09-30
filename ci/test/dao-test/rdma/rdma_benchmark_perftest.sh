#!/bin/bash
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2026 Marvell.

set -euo pipefail
export RDMA_CI_TEST_TYPE=benchmark
SCRIPT_DIR="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
source "$SCRIPT_DIR/rdma_perftest.sh"
