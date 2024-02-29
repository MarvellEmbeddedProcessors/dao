#!/bin/bash
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2024 Marvell.

set -euo pipefail

EXTBUF_1C_SCRIPT_PATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
source $EXTBUF_1C_SCRIPT_PATH/virtio_extbuf_utils.sh

function virtio_extbuf_1c()
{
	local extbuf_pfx=${DAO_TEST}
	local host_testpmd_pfx=${DAO_TEST}_testpmd_host
	local extbuf_out=virtio_extbuf.${extbuf_pfx}.out
	local if0=$(ep_device_get_inactive_if)

	extbuf_register_sig_handler ${DAO_TEST} $host_testpmd_pfx $extbuf_out

	ep_common_bind_driver pci $if0 vfio-pci

	# Launch virtio extbuf
	if ! extbuf_app_launch $if0 $extbuf_pfx $extbuf_out "4-5" "-p 0x1 -v 0x1 -P -l"; then
		echo "Failed to launch virtio extbuf"

		# Quit extbuf app
		extbuf_app_quit $extbuf_pfx $extbuf_out
		return 1
	fi

	ep_host_op vdpa_setup $(ep_device_get_part)

	# Start traffic
	extbuf_host_start_traffic $host_testpmd_pfx

	# Check the performance
	extbuf_host_check_pps $host_testpmd_pfx
	local k=$?

	# Stop Traffic and quit host testpmd
	extbuf_host_stop_traffic $host_testpmd_pfx

	ep_host_op vdpa_cleanup

	# Quit extbuf app
	extbuf_app_quit $extbuf_pfx $extbuf_out
	return $k
}

test_run ${DAO_TEST} 2
