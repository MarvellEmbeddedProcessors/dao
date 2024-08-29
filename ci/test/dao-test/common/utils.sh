#!/bin/bash
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2024 Marvell.

set -euo pipefail

function find_executable()
{
	local execname=$1
	local execvar=$2
	local paths=${@:3}
	local bin

	for path in $paths; do
		if [[ $path != "" ]] && [[ -f $path/$execname ]]; then
			eval "$execvar"="$path/$execname"
			return
		fi
	done

	set +e
	bin=$(which $execname)
	set -e
	if [[ $bin != "" ]]; then
		eval "$execvar"="$bin"
		return 0
	fi
	echo "Cannot find $execname"
	return 1
}

function ep_ssh_cmd()
{
	local remote_varname=$1
	local bg=$2
	local wait=$3
	local cmd=$4

	if [[ -z "${!remote_varname}" || -z "$EP_SSH_CMD" ]]; then
		echo "$remote_varname and SSH details are missing!!"
		exit 1
	fi

	if [[ $bg == "true" ]]; then
		$EP_SSH_CMD -f -n ${!remote_varname} "$cmd"
		sleep $wait
	else
		$EP_SSH_CMD ${!remote_varname} "$cmd"
	fi
}

function ep_host_ssh_cmd()
{
	local cmd=$1

	ep_ssh_cmd EP_HOST false 0 "$cmd"
}

function ep_host_ssh_cmd_bg()
{
	local wait=$1
	local cmd=$2

	ep_ssh_cmd EP_HOST true $wait "$cmd 2>&1 &"
}

function ep_host_op()
{
	local op=$1
	local args=${@:2}
	local env="EP_HOST_MODULE_DIR=$EP_HOST_MODULE_DIR $EP_HOST=$EP_HOST EP_DIR=$EP_DIR"

	ep_host_ssh_cmd "$EP_HOST_SUDO $env $EP_DIR/ci/test/dao-test/common/ep_host_utils.sh $op $args"
}

function ep_host_op_bg()
{
	local wait=$1
	local op=$2
	local args=${@:3}
	local env="EP_HOST_MODULE_DIR=$EP_HOST_MODULE_DIR $EP_HOST=$EP_HOST EP_DIR=$EP_DIR"

	ep_ssh_cmd EP_HOST true $wait "$EP_HOST_SUDO $env nohup $EP_DIR/ci/test/dao-test/common/ep_host_utils.sh $op $args 2>&1 &"
}

function ep_remote_ssh_cmd()
{
	local cmd=$1

	ep_ssh_cmd EP_REMOTE false 0 "$cmd"
}

function ep_remote_ssh_cmd_bg()
{
	local wait=$1
	local cmd=$2

	ep_ssh_cmd EP_REMOTE true $wait "$cmd 2>&1 &"
}

function ep_remote_op()
{
	local op=$1
	local args=${@:2}

	ep_remote_ssh_cmd "$EP_REMOTE_SUDO EP_DEVICE=$EP_REMOTE EP_DIR=$EP_DIR $EP_DIR/ci/test/dao-test/common/ep_device_utils.sh $op $args"
}

function ep_remote_op_bg()
{
	local wait=$1
	local op=$2
	local args=${@:3}

	ep_ssh_cmd EP_REMOTE true $wait "$EP_REMOTE_SUDO EP_DEVICE=$EP_REMOTE EP_DIR=$EP_DIR nohup $EP_DIR/ci/test/dao-test/common/ep_device_utils.sh $op $args 2>&1 &"
}

function ep_device_ssh_cmd()
{
	local cmd=$1

	ep_ssh_cmd EP_DEVICE false 0 "$cmd"
}

function ep_device_ssh_cmd_bg()
{
	local wait=$1
	local cmd=$2

	ep_ssh_cmd EP_DEVICE true $wait "$cmd 2>&1 &"
}

function ep_device_op()
{
	local op=$1
	local args=${@:2}

	ep_device_ssh_cmd "$EP_DEVICE_SUDO EP_DEVICE=$EP_DEVICE EP_DIR=$EP_DIR $EP_DIR/ci/test/dao-test/common/ep_device_utils.sh $op $args"
}

function ep_device_op_bg()
{
	local wait=$1
	local op=$2
	local args=${@:3}

	ep_ssh_cmd EP_DEVICE true $wait "$EP_DEVICE_SUDO EP_DEVICE=$EP_DEVICE EP_DIR=$EP_DIR nohup $EP_DIR/ci/test/dao-test/common/ep_device_utils.sh $op $args 2>&1 &"
}

function test_run()
{
	local func=$1
	local retry=${2:-1}
	local attempt=1
	local res

	while true; do
		echo "================================"
		echo "Run $func (Attempt $attempt)"
		echo "================================"
		set +e
		$func
		res=$?
		set -e

		# Break if test is successful
		if [[ $res == 0 ]]; then
			 break
		fi

		# Break if retry attempts exceeded
		attempt=$((attempt + 1))
		if [[ $attempt -gt $retry ]]; then
			break
		fi
	done

	return $res
}

function get_process_tree() {
	local pid=$BASHPID
	local ps_out
	local tree=""

	while [[ $pid != 1 ]]; do
		ps_out=$(ps -ef | grep $pid | awk '{printf("%d-%d ", $2, $3)}')
		tree+="$pid "
		for l in $ps_out; do
			if [[ $(echo $l | awk -F '-' '{print $1}') == $pid ]]; then
				pid=$(echo $l | awk -F '-' '{print $2}')
				break
			fi
		done
	done
	echo "$tree"
}

function safe_kill()
{
	local pattern=$@
	local killpids
	local ptree=$(get_process_tree)
	local maxwait=5
	local elapsed=0

	# Safely kill all processes which has the pattern in 'ps -ef' but
	# make sure that the current process tree is not affected.
	set +e
	killpids=$(ps -ef | grep "$pattern" | awk '{print $2}')
	for p in $killpids; do
		if ! $(echo $ptree | grep -qw $p); then
			elapsed=0
			while $(kill -s TERM $p > /dev/null 2>&1); do
				sleep 1
				elapsed=$((elapsed + 1))
				if [[ $elapsed == $maxwait ]]; then
					kill -9 $p > /dev/null 2>&1
					break
				fi
			done
		fi
	done
}

function file_offset()
{
	local logfile=$1

	# Get the offset of the file
	wc -c $logfile | awk '{print $1}'
}

function file_search_pattern()
{
	local logfile=$1
	local skip_bytes=$2
	local pattern=$3

	tail -c +$skip_bytes $logfile | grep -q "$pattern"
}

function get_vf_pcie_addr()
{
	local pcie_addr=$1
	local vf_idx=$2
	local base
	local device
	local func

	base=$(echo $pcie_addr | awk -F ':' '{print $1":"$2":"}')
	device=$(printf "%02x" $((vf_idx / 8)))
	func=$((vf_idx % 8))
	echo "${base}${device}.${func}"
}

function form_split_args()
{
	local param=$1
	local values=${@:2}
	local args=""

	for v in $values; do
		args+="${param} $v "
	done

	echo $args
}

function pkill_with_wait()
{
	local proc=$1
	local sig=${2:-SIGKILL}
	local timeout=60

	set +e
	pkill -$sig $proc
	set -e

	while (ps -ef | grep -v grep | grep $proc &> /dev/null); do
		sleep 1
		timeout=$((timeout - 1))
		if [[ $timeout == 0 ]]; then
			echo "Forcefully killing $proc after timeout"
			pkill -SIGKILL $proc
			timeout=60
		fi
	done
}
