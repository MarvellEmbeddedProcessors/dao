# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2025 Marvell.

#!/bin/sh

set -x
FILENAME=ld-linux-aarch64.so.1
STAGING_DIR=$1/lib
TOOLCHAIN_EXTERNAL_PATH=$2/aarch64-marvell-linux-gnu/sys-root/lib
HOST_DIR_PATH=${HOST_DIR}/opt/ext-toolchain/aarch64-marvell-linux-gnu/sys-root/lib
rm -rf ${STAGING_DIR}/${FILENAME}
if [ -e ${HOST_DIR_PATH}/${FILENAME} ]; then
echo "__DAO_BFS_TOOLCHAIN_FIXUP__: Copied ${HOST_DIR_PATH}/${FILENAME} -> ${STAGING_DIR}/"
cp -fp ${HOST_DIR_PATH}/${FILENAME} ${STAGING_DIR}/${FILENAME}
fi

if [ -e ${TOOLCHAIN_EXTERNAL_PATH}/${FILENAME} ]; then
echo "__DAO_BFS_TOOLCHAIN_FIXUP__: Copied $TOOLCHAIN_EXTERNAL_PATH/${FILENAME} -> $STAGING_DIR/"
cp -fp ${TOOLCHAIN_EXTERNAL_PATH}/${FILENAME} ${STAGING_DIR}/${FILENAME}
fi
