#!/bin/bash
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2024 Marvell.

# This script creates a list of tests from meson test.

set -euo pipefail

TEST_BINARY=$1

if [[ $(basename $TEST_BINARY) == dao-test-script-wrapper ]]; then
	# Tests which are invoked as bash scripts are passed as
	# an argument to cnxk-test-script-wrapper binary by meson test
	# and the directory from where the test is to be run will be
	# given in TEST_DIR env var.
	shift
	TEST_BINARY=$TEST_DIR/$1
else
	# For all other meson, the tests can be run from base build dir.
	TEST_DIR=$BUILD_DIR
fi

shift

TEST_ARGS=$@

source $TEST_ENV_CONF

TEST_ENV_VARS="DAO_TEST=$DAO_TEST "
TEST_ENV_VARS="$TEST_ENV_VARS EP_DEVICE=$EP_DEVICE EP_HOST=$EP_HOST"

add_test "$DAO_TEST" "$TEST_BINARY" "$TEST_DIR" "$TEST_ARGS" "$TEST_ENV_VARS"

exit 77
