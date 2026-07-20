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
TEST_ENV_VARS+=" EP_DEVICE=$EP_DEVICE EP_HOST=$EP_HOST EP_REMOTE=$EP_REMOTE"
TEST_ENV_VARS+=" EP_SSH_CMD='$EP_SSH_CMD' EP_DIR=$EP_DIR"
TEST_ENV_VARS+=" EP_REMOTE_SUDO=$EP_REMOTE_SUDO EP_HOST_SUDO=$EP_HOST_SUDO"
TEST_ENV_VARS+=" EP_HOST_MODULE_DIR=${EP_HOST_MODULE_DIR:-}"
TEST_ENV_VARS+=" LD_LIBRARY_PATH=${EP_DIR}/deps-prefix/ep/lib/:${LD_LIBRARY_PATH:-}"
TEST_ENV_VARS+=" EP_DEVICE_OVS_PATH=${EP_DEVICE_OVS_PATH:-}"
TEST_ENV_VARS+=" EP_HOST_RDMA_PATH=${EP_HOST_RDMA_PATH:-}"
TEST_ENV_VARS+=" EP_REMOTE_RDMA_PATH=${EP_REMOTE_RDMA_PATH:-}"
TEST_ENV_VARS+=" EP_REMOTE_DEVICE_SUDO=${EP_REMOTE_DEVICE_SUDO:-}"
# Emit EP_REMOTE_DEVICE only when non-empty. This static string is appended
# AFTER TEST_ENV_VARS_DYNAMIC in get_test_command, so an empty assignment here
# would clobber the value verify_rdma_setup injects via add_test_env for
# DPU-to-DPU runs (exe_wrapper re-sources the env file and often sees it empty).
if [[ -n "${EP_REMOTE_DEVICE:-}" ]]; then
	TEST_ENV_VARS+=" EP_REMOTE_DEVICE=${EP_REMOTE_DEVICE}"
fi
TEST_ENV_VARS+=" EP_REMOTE_MODULE_DIR=${EP_REMOTE_MODULE_DIR:-}"
TEST_ENV_VARS+=" MQ_TEST_FILTER=${MQ_TEST_FILTER:-}"

add_test "$DAO_TEST" "$TEST_BINARY" "$TEST_DIR" "$TEST_ARGS" "$TEST_ENV_VARS"

exit 77
