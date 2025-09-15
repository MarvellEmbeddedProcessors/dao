#!/bin/bash
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2025 Marvell.

mkdir -p ${TARGET_DIR}/root/lc_service/bin
mkdir -p ${TARGET_DIR}/root/lc_service/mc/mrvl/cpt02
mkdir -p ${TARGET_DIR}/root/cpt_module

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

# Copy CPT microcode files

MRVL_FW_DIR=${TARGET_DIR}/root/lib/firmware/mrvl
CPT_MC_DIR=${MRVL_FW_DIR}/cpt

# Move CPT microcode files to the appropriate lc_service directory
if [ -d "${CPT_MC_DIR}/cpt02_lc" ]; then
	mv -f ${CPT_MC_DIR}/cpt02_lc/* ${TARGET_DIR}/root/lc_service/mc/mrvl/cpt02/
fi

if ls ${CPT_MC_DIR}/cpt02/ae.out* 1> /dev/null 2>&1; then
	mv -f ${CPT_MC_DIR}/cpt02/ae.out* ${TARGET_DIR}/root/lc_service/mc/mrvl/cpt02/
fi

# Copy gpio_csr binary

cp ${MRVL_FW_DIR}/gpio/gpio_csr ${TARGET_DIR}/usr/bin/

# Copy CPT kernel modules

MRVL_CPT_DIR=${TARGET_DIR}/lib/modules/6.1.67/kernel/drivers/crypto/marvell/octeontx2
mv -f ${MRVL_CPT_DIR}/rvu_cptpf.ko ${TARGET_DIR}/root/cpt_module/
mv -f ${MRVL_CPT_DIR}/rvu_cptcommon.ko ${TARGET_DIR}/root/cpt_module/

# Remove other firmware files
eval rm -rf ${MRVL_FW_DIR}
