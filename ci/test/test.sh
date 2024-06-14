#!/bin/bash
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2024 Marvell.

set -euo pipefail

function help() {
	echo "Run DAO Library Tests"
	echo ""
	echo "Usage:"
	echo "$SCRIPT_NAME [ARGUMENTS]..."
	echo ""
	echo "Mandatory Arguments"
	echo "==================="
	echo "--build-root | -r            : Build root directory"
	echo "--test-env | -t              : Test Environment"
	echo ""
	echo "Optional Arguments"
	echo "==================="
	echo "--run-dir | -d               : Run directory [Default=Build Root]"
	echo "--deps-prefix | -f           : Dependency Install path"
	echo "--project-root | -p          : Project root [Default: PWD]"
	echo "--run-only                   : Only run the tests "
	echo "--list-only                  : Only create the test list"
	echo "--help | -h                  : Print this help and exit"
}

SCRIPT_NAME="$(basename "$0")"
if ! OPTS=$(getopt \
	-o "r:d:f:t:p:h" \
	-l "build-root:,run-dir:,deps-prefix:,test-env:,project-root:,run-only,list-only,help" \
	-n "$SCRIPT_NAME" \
	-- "$@"); then
	help
	exit 1
fi

BUILD_ROOT=
TEST_ENV_CONF=
EXTRA_ARGS=
PROJECT_ROOT="$PWD"
RUN_ONLY=
LIST_ONLY=
DEPS_PREFIX=

eval set -- "$OPTS"
unset OPTS
while [[ $# -gt 1 ]]; do
	case $1 in
		-r|--build-root) shift; BUILD_ROOT=$1;;
		-d|--run-dir) shift; RUN_DIR=$1;;
		-f|--deps-prefix) shift; DEPS_PREFIX=$1;;
		-t|--test-env) shift; TEST_ENV_CONF=$(realpath $1);;
		-p|--project-root) shift; PROJECT_ROOT=$1;;
		-n|--run-only) RUN_ONLY=1;;
		-l|--list-only) LIST_ONLY=1;;
		-h|--help) help; exit 0;;
		*) help; exit 1;;
	esac
	shift
done

if [[ -z $DEPS_PREFIX ]]; then
	DEPS_PREFIX=$BUILD_ROOT/deps/deps-prefix
fi

if [[ -z $BUILD_ROOT || -z $TEST_ENV_CONF ]]; then
	echo "Build root directory and test env should be given !!"
	help
	exit 1
fi

export PROJECT_ROOT=$(realpath $PROJECT_ROOT)
mkdir -p $BUILD_ROOT
export BUILD_ROOT=$(realpath $BUILD_ROOT)
export BUILD_DIR=$BUILD_ROOT/build
export BUILD_HOST_DIR=$BUILD_ROOT/build_host
export DEPS_PREFIX=${DEPS_PREFIX}
export RUN_DIR=${RUN_DIR:-$BUILD_DIR}
mkdir -p $RUN_DIR

source $TEST_ENV_CONF

if [[ -z $RUN_ONLY ]]; then
	# The exe_wrapper path in the config file is overridden as $BUILD_DIR/exe_wrapper.sh
	# at build time. So copy the required exe_wrapper script to $BUILD_DIR/exe_wrapper.sh.
	cp $PROJECT_ROOT/ci/test/common/exe_wrapper.sh $BUILD_DIR/exe_wrapper.sh

	clean_test_list

	# Run the meson test to generate the list of tests
	meson test -C $BUILD_DIR --no-rebuild $EXTRA_ARGS --suite $DAO_SUITE
fi

if [[ -z $LIST_ONLY ]]; then
	# Run the tests
	$TEST_RUN_CMD
fi

