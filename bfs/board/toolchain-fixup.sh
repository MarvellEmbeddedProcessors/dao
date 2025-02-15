# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2025 Marvell.

#!/bin/sh

set -x
STAGING_DIR=$1
TOOLCHAIN_EXTERNAL_PATH=$2
rm -rf ${STAGING_DIR}/lib/ld-linux-aarch64.so.1
if [ -e ${HOST_DIR}/opt/ext-toolchain/aarch64-marvell-linux-gnu/sys-root/lib/ld-linux-aarch64.so.1 ]; then
ln -sf ${HOST_DIR}/opt/ext-toolchain/aarch64-marvell-linux-gnu/sys-root/lib/ld-linux-aarch64.so.1 ${STAGING_DIR}/lib/ld-linux-aarch64.so.1
fi

if [ -e ${TOOLCHAIN_EXTERNAL_PATH}/aarch64-marvell-linux-gnu/sys-root/lib/ld-linux-aarch64.so.1 ]; then
ln -sf ${TOOLCHAIN_EXTERNAL_PATH}/aarch64-marvell-linux-gnu/sys-root/lib/ld-linux-aarch64.so.1 ${STAGING_DIR}/lib/ld-linux-aarch64.so.1
fi
