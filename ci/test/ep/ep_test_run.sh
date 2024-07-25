#!/bin/bash
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2024 Marvell.

set -euo pipefail

source $TEST_ENV_CONF

EP_TEST_RUN_SCRIPT_PATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
source $EP_TEST_RUN_SCRIPT_PATH/../dao-test/common/ep_device_utils.sh
source $EP_TEST_RUN_SCRIPT_PATH/../dao-test/common/ep_host_utils.sh

declare -A DAO_SUITE_SETUP
declare -A DAO_SUITE_CLEANUP

source $EP_TEST_RUN_SCRIPT_PATH/sync.sh
source $EP_TEST_RUN_SCRIPT_PATH/common_setup.sh
source $EP_TEST_RUN_SCRIPT_PATH/ovs_setup.sh
source $EP_TEST_RUN_SCRIPT_PATH/virtio_setup.sh
source $EP_TEST_RUN_SCRIPT_PATH/unit_test_setup.sh

SKIP_SYNC=${SKIP_SYNC:-}
SKIP_EP_DEVICE_SETUP=${SKIP_EP_DEVICE_SETUP:-}
SKIP_EP_HOST_SETUP=${SKIP_EP_HOST_SETUP:-}
EP_HOST=${EP_HOST:-?}
EP_DEVICE=${EP_DEVICE:-?}
EP_SSH_CMD=${EP_SSH_CMD:-"ssh"}
EP_SCP_CMD=${EP_SCP_CMD:-"scp"}
EP_DIR=${EP_DIR:-/tmp/dao}
PROJECT_ROOT=${PROJECT_ROOT:-$PWD}
BUILD_DIR=${BUILD_DIR:-$PWD/build}
BUILD_HOST_DIR=${BUILD_HOST_DIR:-$PWD/build_host}
DEPS_PREFIX=${DEPS_PREFIX:-$PWD/build/deps/deps-prefix}

function save_log()
{
	local logfile=$1
	local save_name=${2:-}

	if [[ -z $RUN_DIR ]] || [[ ! -d $RUN_DIR ]]; then
		return
	fi

	if [[ -n $save_name ]]; then
		cp $logfile $RUN_DIR/$save_name 2>/dev/null || true
	else
		cp $logfile $RUN_DIR/ 2>/dev/null || true
	fi
}

function run_test()
{
	local name=$1
	local tmo
	local cmd
	local curtime
	local exec_bin
	local res

	exec_bin=$(get_test_exec_bin $name)
	binary_name=$(basename $exec_bin)
	tmo=$(get_test_timeout $name)

	# Update sig handlers to pass in test name also.
	trap "sig_handler INT $binary_name" INT
	trap "sig_handler TERM $binary_name" TERM
	trap "sig_handler QUIT $binary_name" QUIT

	test_info_print $name
	cmd=$(get_test_command $name)

	curtime=$SECONDS
	# Can't use ep_ssh_device_cmd here as we need to run the command under timeout
	timeout --foreground -v -k 30 -s 3 $tmo $EP_SSH_CMD $EP_DEVICE -n "$cmd"
	res=$?
	echo -en "\n$name completed in $((SECONDS - curtime)) seconds ... "
	if [[ $res -eq 0 ]]; then
		echo "TEST SUCCESS (ret = $res)"
	elif [[ $res -eq 77 ]]; then
		echo "TEST SKIPPED (ret = $res)"
	else
		echo "TEST FAILURE (ret = $res)"
	fi

	return $res
}

function run_all_tests()
{
	local tst
	local res
	local test_num=0

	# Errors will be handled inline. No need for sig handler
	set +e
	trap - ERR

	# Read the tests info one by one from the test list created by meson test
	while [[ true ]]; do
		test_num=$((test_num + 1))
		test_enabled $test_num
		res=$?
		if [[ $res == 77 ]]; then
			continue
		fi
		if [[ $res -ne 0 ]]; then
			break
		fi

		tst=$(get_test_name $test_num)

		# Run the tests
		run_test $tst
		res=$?
		if [[ $res -ne 0 ]] && [[ $res -ne 77 ]] ; then
			test_exit -1 "FAILURE: Test $tst failed"
		fi
	done
}

function test_exit()
{
	local result=$1
	local msg=$2

	set +e
	trap - INT
	trap - TERM
	trap - ERR
	trap - QUIT
	trap - EXIT

	${DAO_SUITE_CLEANUP["$DAO_SUITE"]}

	echo "###########################################################"
	echo "Run time: $((SECONDS / 60)) mins $((SECONDS % 60)) secs"
	echo "$msg"
	echo "###########################################################"

	exit $result
}

function sig_handler()
{
	local signame=$1
	local binary_name=$2

	# Make sure that sig_handler is fully executed.
	set +e
	trap - INT
	trap - TERM
	trap - ERR
	trap - QUIT

	test_exit 1 "Error: Caught signal $signame in $0"
}

trap "sig_handler INT NONE" INT
trap "sig_handler TERM NONE" TERM
trap "sig_handler ERR NONE" ERR
trap "sig_handler QUIT NONE" QUIT

host_sync
device_sync
remote_sync
${DAO_SUITE_SETUP["$DAO_SUITE"]}
run_all_tests

test_exit 0 "SUCCESS: Tests Completed"
