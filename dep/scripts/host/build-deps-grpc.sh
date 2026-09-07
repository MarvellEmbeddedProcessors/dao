#!/usr/bin/env bash
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2025 Marvell.

set -euo pipefail
shopt -s extglob
#set -x

MAKE_J=4
STATIC_BUILD=0

if [ "$#" -lt 1 ]; then
	echo "Syntax: build-deps-grpc.sh <build-dir> [verbose] [--static]"
	exit 1
fi

mkdir -p -- "$1"
BUILD_ROOT=$(realpath -- "$1")
shift

VERBOSE=
for arg in "$@"; do
	case "$arg" in
	--static)
		STATIC_BUILD=1
		;;
	--*)
		echo "Unknown option: $arg" >&2
		exit 1
		;;
	*)
		if [[ -z $VERBOSE ]]; then
			VERBOSE=$arg
		else
			echo "Unexpected extra argument: $arg" >&2
			exit 1
		fi
		;;
	esac
done

# gRPC variables
GRPC_SRC_TAG=v1.71.0
GRPC_SRC_URL=https://github.com/grpc/grpc
GRPC_CXX_ABI_STANDARD=17

GRPC_SRC_DIR=$BUILD_ROOT/grpc
GRPC_BUILD_DIR=$BUILD_ROOT/build
GRPC_INSTALL_DIR=$BUILD_ROOT/install

function build_grpc_host() {
	# Checkout sources
	if [[ ! -d $GRPC_SRC_DIR ]]; then
		mkdir -p "$GRPC_SRC_DIR"
		pushd "$GRPC_SRC_DIR" >/dev/null
		git clone --recurse-submodules -b "$GRPC_SRC_TAG" --depth 1 \
			--shallow-submodules "$GRPC_SRC_URL" .
		popd >/dev/null
	fi

	# Build

	GRPC_BUILD_SHARED_LIBS=ON
	if [[ $STATIC_BUILD -eq 1 ]]; then
		GRPC_BUILD_SHARED_LIBS=OFF
	fi

	mkdir -p "$GRPC_BUILD_DIR"
	pushd "$GRPC_BUILD_DIR" >/dev/null

	# Build cmake args as an array (not a single string) so that paths
	# containing spaces or other special characters are passed through
	# safely, without relying on word-splitting.
	GRPC_CMAKE_CMD=(
		-DCMAKE_CXX_STANDARD="$GRPC_CXX_ABI_STANDARD"
		-DCMAKE_INSTALL_PREFIX="$GRPC_INSTALL_DIR"
		-DCMAKE_BUILD_TYPE=Release
		-DgRPC_INSTALL=ON
		-DgRPC_BUILD_TESTS=OFF
		-DgRPC_SSL_PROVIDER=package
		-DBUILD_SHARED_LIBS="$GRPC_BUILD_SHARED_LIBS"
		-DgRPC_ABSL_PROVIDER=module
	)
	if [[ -n $VERBOSE ]]; then
		GRPC_CMAKE_CMD+=(-DCMAKE_VERBOSE_MAKEFILE:BOOL=ON)
	fi

	# Always (re)run the cmake configure step, even if the build directory
	# already exists, so that switching --static on/off between runs is
	# honored via BUILD_SHARED_LIBS instead of being silently ignored.
	cmake "${GRPC_CMAKE_CMD[@]}" "$GRPC_SRC_DIR"
	make -j "$MAKE_J"
	make install
	popd >/dev/null
	return 0
}

build_grpc_host
