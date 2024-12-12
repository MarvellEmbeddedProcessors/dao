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
