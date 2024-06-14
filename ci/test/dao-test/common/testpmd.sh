#!/bin/bash
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2024 Marvell.

TESTPMD_SCRIPT_PATH=$(dirname $(readlink -f "${BASH_SOURCE[0]}"))
source $TESTPMD_SCRIPT_PATH/utils.sh

find_executable "dpdk-testpmd" TESTPMD "${DEPS_PREFIX:-}/bin"

function testpmd_cleanup()
{
	local pfx=$1
	local in=testpmd.in.$pfx
	local out=testpmd.in.$pfx
	local alive
	local pid

	# Issue kill
	pid=$(ps -ef | grep dpdk-testpmd | grep $pfx | awk '{print $2}' | xargs -n1 kill -9 2>/dev/null || true)

	# Wait until the process is killed
	alive=$(ps -ef | grep dpdk-testpmd | grep $pfx || true)
	while [[ "$alive" != "" ]]; do
		sleep 1
		alive=$(ps -ef | grep dpdk-testpmd | grep $pfx || true)
		continue
	done
	rm -rf $in
	rm -rf $out
}

function testpmd_prompt()
{
	local pfx=$1
	local refresh=${2:-}
	local skip_bytes=${3:-}
	local in=testpmd.in.$pfx
	local out=testpmd.out.$pfx

	local cmd="tail -n1 $out"

	if [[ "$skip_bytes" != "" ]]
	then
		cmd="tail -c +$skip_bytes $out"
	fi

	while ! ($cmd | grep -q "^testpmd> $"); do
		if [ "$refresh" == "yes" ]
		then
			sleep 1
			echo "" >>$in
		fi
		continue;
	done
}

function testpmd_launch()
{
	local pfx=$1
	local eal_args=$2
	local testpmd_args=$3
	local out=testpmd.out.$pfx
	local in=testpmd.in.$pfx
	local unbuffer="stdbuf -o0"

	testpmd_cleanup $pfx
	rm -f $out
	rm -f $in
	touch $in
	tail -f $in | \
		($unbuffer $TESTPMD $eal_args --file-prefix $pfx -- \
			$testpmd_args -i &>$out) &
	# Wait till out file is created
	while [[ ! -f $out ]]; do
		sleep 1
		continue
	done
	# Wait till testpmd prompt comes up
	testpmd_prompt $pfx
}

function testpmd_cmd()
{
	local pfx=$1
	local cmd=${@:2}
	local in=testpmd.in.$pfx
	local skip_bytes=$(stat -c %s testpmd.out.$pfx)

	echo "$cmd" >> $in
	testpmd_prompt $pfx "no"  $skip_bytes
}

function testpmd_cmd_refresh()
{
	local pfx=$1
	local cmd=$2
	local in=testpmd.in.$pfx

	echo "$cmd" >> $in
	testpmd_prompt $pfx "yes"
}

function testpmd_quit()
{
	local pfx=$1
	local in=testpmd.in.$pfx
	local alive

	echo "quit" >> $in
	alive=$(ps -ef | grep testpmd | grep -q $pfx)
	while [[ "$alive" != "" ]]; do
		sleep 1
		alive=$(ps -ef | grep dpdk-testpmd | grep -q $pfx)
		continue
	done
}

function testpmd_port_stats()
{
	local pfx=$1
	local port=$2
	local in=testpmd.in.$pfx
	local out=testpmd.out.$pfx

	echo "show port stats $port" >> $in
	sleep 0.5
	testpmd_prompt $pfx
	cat $out | tail -n10 | head -n4
}

function testpmd_port_rx_count()
{
	local stats=$(testpmd_port_stats $1 $2)

	echo $stats | awk '{print $2}'
}

function testpmd_port_rx_bytes()
{
	local stats=$(testpmd_port_stats $1 $2)

	echo $stats | awk '{print $6}'
}

function testpmd_port_tx_count()
{
	local stats=$(testpmd_port_stats $1 $2)

	echo $stats | awk '{print $12}'
}

function testpmd_port_tx_bytes()
{
	local stats=$(testpmd_port_stats $1 $2)

	echo $stats | awk '{print $16}'
}

function testpmd_log()
{
	local pfx=$1
	local out=testpmd.out.$pfx
	cat $out
}

function testpmd_log_off()
{
	local pfx=$1
	local offset=$2
	local out=testpmd.out.$pfx

	dd if=$out skip=$offset bs=1 status=none
}

function testpmd_log_sz()
{
	local pfx=$1
	local out=testpmd.out.$pfx

	stat -c %s $out
}

function testpmd_pps() {
	local pfx=$1
	local port=$2
        local rx_pps=0

        testpmd_cmd "$pfx" "show port stats $port"
        sleep 1
        testpmd_cmd "$pfx" "show port stats $port"
        sleep 1
        val=$(testpmd_log "$pfx" | tail -4 | grep -ao 'Rx-pps: .*' | awk -e '{print $2}')
        echo $val
}
