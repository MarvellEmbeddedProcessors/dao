#!/bin/bash
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2023 Marvell.
#
# Script will build DAO app in <build-root>/build and install in <build-root>/prefix
#

set -euo pipefail

function help() {
	echo "Build DAO libraries and applications"
	echo ""
	echo "Usage:"
	echo "$SCRIPT_NAME [ARGUMENTS]..."
	echo ""
	echo "Mandatory Arguments"
	echo "==================="
	echo "--build-root | -r            : Build root directory"
	echo "--build-env | -b             : Build Environment"
	echo ""
	echo "Optional Arguments"
	echo "==================="
	echo "--extra-meson-args | -m      : Additional arguments to meson"
	echo "--extra-host-meson-args | -M : Additional arguments to meson host build"
	echo "--jobs | -j                  : Number of parallel jobs [Default: 4]"
	echo "--deps-prefix | -f           : Dependency Install path"
	echo "--project-root | -p          : DAO project root [Default: PWD]"
	echo "--build-target | -t          : Build target (host|device|all) [Default: all]"
	echo "--verbose | -v               : Enable verbose logging"
	echo "--help | -h                  : Print this help and exit"
}

SCRIPT_NAME="$(basename "$0")"
if ! OPTS=$(getopt \
	-o "r:b:f:m:M:j:p:t:g:D:Nhv" \
	-l "build-root:,build-env:,deps-prefix:,extra-meson-args:,extra-host-meson-args:,jobs:,
            project-root:, build-target:, help,verbose" \
	-n "$SCRIPT_NAME" \
	-- "$@"); then
	help
	exit 1
fi

BUILD_ROOT=
BUILD_ENV=
MAKE_J=4
EXTRA_ARGS=
EXTRA_HOST_ARGS=
PROJECT_ROOT="$PWD"
DEPS_PREFIX=
VERBOSE=
BUILD_TARGET="all"

eval set -- "$OPTS"
unset OPTS
while [[ $# -gt 1 ]]; do
	case $1 in
		-r|--build-root) shift; BUILD_ROOT=$1;;
		-b|--build-env) shift; BUILD_ENV=$(realpath $1);;
		-f|--deps-prefix) shift; DEPS_PREFIX=$(realpath $1);;
		-m|--extra-meson-args) shift; EXTRA_ARGS="$1";;
		-M|--extra-host-meson-args) shift; EXTRA_HOST_ARGS="$1";;
		-j|--jobs) shift; MAKE_J=$1;;
		-p|--project-root) shift; PROJECT_ROOT=$1;;
		-t|--build-target) shift; BUILD_TARGET=$1;;
		-v|--verbose) VERBOSE='-v';;
		-h|--help) help; exit 0;;
		*) help; exit 1;;
	esac
	shift
done

if [[ -z $DEPS_PREFIX ]]; then
	DEPS_PREFIX=$BUILD_ROOT/deps/deps-prefix
fi

# re2.pc is available in a separate directory
DEPS_RE2_PREFIX=$DEPS_PREFIX/../host/grpc/third_party/re2

HOST_DEPS_PREFIX=$DEPS_PREFIX/host

if [[ -z $BUILD_ROOT || -z $BUILD_ENV ]]; then
	echo "Build root directory and build env should be passed !!"
	help
	exit 1
fi

# Validate BUILD_TARGET
if [[ "$BUILD_TARGET" != "all" && "$BUILD_TARGET" != "host" && "$BUILD_TARGET" != "device" ]]; then
	echo "Error: Invalid build target '$BUILD_TARGET'. Must be 'host', 'device', or 'all'."
	help
	exit 1
fi

PROJECT_ROOT=$(realpath $PROJECT_ROOT)
mkdir -p $BUILD_ROOT
BUILD_ROOT=$(realpath $BUILD_ROOT)

# Update path so that protoc is detected. protoc is required for gRPC build.
export PATH=$PATH:$HOST_DEPS_PREFIX/bin
export LD_LIBRARY_PATH=$HOST_DEPS_PREFIX/lib:${LD_LIBRARY_PATH:-}

# Build for Device (EP) if needed
if [[ "$BUILD_TARGET" == "device" || "$BUILD_TARGET" == "all" ]]; then
	EP_DEPS_PREFIX=$DEPS_PREFIX/ep
	BUILD_DIR=$BUILD_ROOT/build
	PREFIX_DIR=$BUILD_ROOT/prefix

	source $BUILD_ENV

	rm -rf $BUILD_DIR
	rm -rf $PREFIX_DIR

	cd $PROJECT_ROOT

	# Do any pre-build stuff
	${BUILD_SETUP_CMD:-}

	# Building DAO libraries and applications
	cd $PROJECT_ROOT

	# Build for EP
	PKG_CONFIG_PATH_DEFAULT="$EP_DEPS_PREFIX/lib/pkgconfig:$DEPS_RE2_PREFIX"
	export PKG_CONFIG_PATH="${PKG_CONFIG_PATH:-$PKG_CONFIG_PATH_DEFAULT}"

	EXTRA_ARGS="$EXTRA_ARGS --prefer-static"

	# Check if 'libdpdk' is available with pkg-config
	if ! pkg-config --exists libdpdk; then
		echo "Error: 'libdpdk' not found with pkg-config. Please ensure it is installed and available in PKG_CONFIG_PATH."
		exit 1
	fi

	meson $BUILD_DIR --prefix $PREFIX_DIR $EXTRA_ARGS

	ninja -C $BUILD_DIR -j $MAKE_J $VERBOSE
	ninja -C $BUILD_DIR -j $MAKE_J $VERBOSE install
fi

# Build for Host if needed
if [[ "$BUILD_TARGET" == "host" || "$BUILD_TARGET" == "all" ]]; then
	BUILD_HOST_DIR=$BUILD_ROOT/build_host
	rm -rf $BUILD_HOST_DIR

	cd $PROJECT_ROOT

	export PKG_CONFIG_PATH=$HOST_DEPS_PREFIX/lib/pkgconfig
	export PKG_CONFIG_PATH=$PKG_CONFIG_PATH:$DEPS_RE2_PREFIX
	export PKG_CONFIG_PATH=$PKG_CONFIG_PATH:$HOST_DEPS_PREFIX/lib/x86_64-linux-gnu/pkgconfig

	# Check if 'libdpdk' is available with pkg-config
	if ! pkg-config --exists libdpdk; then
		echo "Error: 'libdpdk' not found with pkg-config. Please ensure it is installed and available in PKG_CONFIG_PATH."
		exit 1
	fi

	meson $BUILD_HOST_DIR $EXTRA_HOST_ARGS
	ninja -C $BUILD_HOST_DIR -j $MAKE_J $VERBOSE
fi
