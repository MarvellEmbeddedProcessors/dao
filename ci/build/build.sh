#!/bin/bash
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2023 Marvell.
#
# Script will build DAO app in <build-root>/build and install in <build-root>/prefix
#

set -euo pipefail
set -x

function help() {
	set +x
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
	echo "--jobs | -j                  : Number of parallel jobs [Default: 4]"
	echo "--project-root | -p          : DAO project root [Default: PWD]"
	echo "--verbose | -v               : Enable verbose logging"
	echo "--help | -h                  : Print this help and exit"
	set -x
}

SCRIPT_NAME="$(basename "$0")"
if ! OPTS=$(getopt \
	-o "r:b:m:j:p:g:D:Nhv" \
	-l "build-root:,build-env:,extra-meson-args:,jobs:,project-root:,
	    help,verbose" \
	-n "$SCRIPT_NAME" \
	-- "$@"); then
	help
	exit 1
fi

BUILD_ROOT=
BUILD_ENV=
BUILD_EXT_APPS=
BUILD_DATAPLANE_SRC=
MAKE_J=4
EXTRA_ARGS=
PROJECT_ROOT="$PWD"
PKG_CONFIG_PATH=${PKG_CONFIG_PATH:-}
VERBOSE=

eval set -- "$OPTS"
unset OPTS
while [[ $# -gt 1 ]]; do
	case $1 in
		-r|--build-root) shift; BUILD_ROOT=$1;;
		-b|--build-env) shift; BUILD_ENV=$(realpath $1);;
		-m|--extra-meson-args) shift; EXTRA_ARGS="$1";;
		-j|--jobs) shift; MAKE_J=$1;;
		-p|--project-root) shift; PROJECT_ROOT=$1;;
		-v|--verbose) VERBOSE='-v';;
		-h|--help) help; exit 0;;
		*) help; exit 1;;
	esac
	shift
done


if [[ -z $BUILD_ROOT || -z $BUILD_ENV ]]; then
	echo "Build root directory and build env should be passed !!"
	help
	exit 1
fi

PROJECT_ROOT=$(realpath $PROJECT_ROOT)
mkdir -p $BUILD_ROOT
BUILD_ROOT=$(realpath $BUILD_ROOT)
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
EXTRA_ARGS="$EXTRA_ARGS --prefer-static"
meson $BUILD_DIR --prefix $PREFIX_DIR $EXTRA_ARGS

ninja -C $BUILD_DIR -j $MAKE_J $VERBOSE
ninja -C $BUILD_DIR -j $MAKE_J $VERBOSE install
