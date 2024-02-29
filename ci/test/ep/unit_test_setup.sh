#!/bin/bash
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2024 Marvell.

set -euo pipefail

DAO_SUITE_SETUP["dao-unit-tests"]=dao_unit_test_setup
DAO_SUITE_CLEANUP["dao-unit-tests"]=dao_unit_test_cleanup

function dao_unit_test_cleanup()
{
	ep_device_op safe_kill $EP_DIR
	ep_device_ssh_cmd "$EP_DEVICE_SUDO dmesg" > device_dmesg.log
	save_log device_dmesg.log
}

function dao_unit_test_setup()
{
	if [[ -n $SKIP_SETUP ]]; then
		echo "Skipping setup"
	fi

	ep_device_op hugepage_setup 524288 24 6
}
