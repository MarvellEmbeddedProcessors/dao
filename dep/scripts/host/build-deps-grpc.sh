#!/bin/bash
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2025 Marvell.

set -euo pipefail
shopt -s extglob
#set -x

BUILD_ROOT=$(realpath $1)
VERBOSE=${2:-}
MAKE_J=4

if [ "$#" -lt 1 ]; then
	echo "Syntax: build-deps-grpc.sh <build-dir> <verbose>"
	exit 1
fi

# gRPC variables
GRPC_SRC_TAG=v1.66.0
GRPC_SRC_URL=https://github.com/grpc/grpc
GRPC_CXX_ABI_STANDARD=17

GRPC_SRC_DIR=$BUILD_ROOT/grpc
GRPC_BUILD_DIR=$BUILD_ROOT/build
GRPC_INSTALL_DIR=$BUILD_ROOT/install

function build_grpc_host() {
	# Checkout sources
	if [[ ! -d $GRPC_SRC_DIR ]]; then
		mkdir -p $GRPC_SRC_DIR
		cd $GRPC_SRC_DIR
		git clone --recurse-submodules -b $GRPC_SRC_TAG --depth 1 \
			--shallow-submodules $GRPC_SRC_URL .
	fi

	# Build

	GRPC_CMAKE_CMD_VERBOSE=
	if [[ -n $VERBOSE ]]; then
		GRPC_CMAKE_CMD_VERBOSE="-DCMAKE_VERBOSE_MAKEFILE:BOOL=ON"
	fi

	if [[ ! -d $GRPC_BUILD_DIR ]]; then
		mkdir -p $GRPC_BUILD_DIR
		pushd $GRPC_BUILD_DIR
		GRPC_CMAKE_CMD="-DCMAKE_CXX_STANDARD=$GRPC_CXX_ABI_STANDARD \
			-DCMAKE_INSTALL_PREFIX=$GRPC_INSTALL_DIR \
			-DCMAKE_BUILD_TYPE=Release -DgRPC_INSTALL=ON -DgRPC_BUILD_TESTS=OFF \
			-DgRPC_SSL_PROVIDER=package -DBUILD_SHARED_LIBS=ON \
			-DgRPC_ABSL_PROVIDER=module"
		cmake $GRPC_CMAKE_CMD $GRPC_CMAKE_CMD_VERBOSE $GRPC_SRC_DIR
		make -j $MAKE_J
		make install
		popd
	fi
	return 0
}

build_grpc_host
