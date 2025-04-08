#!/bin/bash
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2025 Marvell.

mkdir -p ${TARGET_DIR}/root/lc_service/bin

files=("dao-crypto-agent"
       "dpdk-test-crypto-perf"
       "dpdk-test-dma-perf")

for file in "${files[@]}"; do
	if [ -f "${TARGET_DIR}/usr/bin/$file" ]; then
		mv "${TARGET_DIR}/usr/bin/$file" "${TARGET_DIR}/root/lc_service/bin/$file"
	fi
done

# Remove additional DPDK test files
dpdk_files=("dpdk-test*"
	    "dpdk-graph"
	    "dpdk-proc-info"
	    "dpdk-dumpcap")

for file in "${dpdk_files[@]}"; do
	eval rm -f "${TARGET_DIR}/usr/bin/$file"
done

# Remove additional DAO apps
pattern="${TARGET_DIR}/usr/bin/dao*"
eval rm -f "$pattern"
