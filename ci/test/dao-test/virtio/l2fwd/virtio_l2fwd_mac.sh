#!/bin/bash
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2024 Marvell.

set -euo pipefail

function l2fwd_host_port_start()
{
	local pfx=$1
	local port=$2
	local start=$3

	if [[ $start -eq 1 ]]; then
		ep_host_op testpmd_cmd $pfx port start $port
		ep_host_op testpmd_cmd $pfx clear port stats all
	else
		ep_host_op testpmd_cmd $pfx port stop $port
	fi
}

function l2fwd_host_set_promisc()
{
	local pfx=$1
	local port=$2
	local enable=$3

	if [[ $enable -eq 1 ]]; then
		ep_host_op testpmd_cmd $pfx set promisc $port on
	else
		ep_host_op testpmd_cmd $pfx set promisc $port off
	fi
}

function l2fwd_host_set_mac()
{
	local pfx=$1
	local port=$2
	local mac=$3

	ep_host_op testpmd_cmd $pfx mac_addr set $port $mac
}

function l2fwd_host_add_mac()
{
	local pfx=$1
	local port=$2
	local mac=$3
	local add=$4

	if [[ $add -eq 1 ]]; then
		ep_host_op testpmd_cmd $pfx mac_addr add $port $mac
	else
		ep_host_op testpmd_cmd $pfx mac_addr remove $port $mac
	fi
}

function l2fwd_host_pkt_recv_test()
{
	local pfx=$1
	local port=$2
	local pkt_cnt=$3

	rx_cnt=$(ep_host_op testpmd_port_rx_count $pfx $port)
	if [[ $rx_cnt -eq $pkt_cnt ]]; then
		echo "PASSED"
	else
		echo "test failed expected $pkt_cnt received $rx_cnt"
		return 1
	fi
	return 0
}
