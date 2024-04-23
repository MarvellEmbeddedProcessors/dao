#!/bin/bash
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2024 Marvell.

HOST_UTILS_SCRIPT_PATH=$(dirname $(readlink -f "${BASH_SOURCE[0]}"))
source "$HOST_UTILS_SCRIPT_PATH/testpmd.sh"

function ep_host_hugepage_setup()
{
	echo "Setting up hugepages on host"
	# Check for hugepages
	if mount | grep hugetlbfs | grep none; then
		echo "Hugepages already setup"
	else
		mkdir /dev/huge
		mount -t hugetlbfs none /dev/huge
	fi
	echo 24 > /proc/sys/vm/nr_hugepages
	echo 2048 >/sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
}

function ep_host_vdpa_setup()
{
	local part=$1
	local host_pf
	local vf_cnt
	local vf_cnt_max
	local sdp_vfs

	echo "Setting up VDPA on host"
	modprobe vdpa
	modprobe vhost-vdpa
	set +e # Module may be already loaded
	insmod $EP_HOST_DIR/kmod/vdpa/octeon_ep/octep_vdpa.ko
	set -e

	host_pf=$(lspci -Dn -d :${part}00 | head -1 | cut -f 1 -d " ")
	vf_cnt=1
	vf_cnt_max=$(cat /sys/bus/pci/devices/$host_pf/sriov_totalvfs)
	vf_cnt=$((vf_cnt >vf_cnt_max ? vf_cnt_max : vf_cnt))

	echo $host_pf > /sys/bus/pci/devices/$host_pf/driver/unbind
	echo octep_vdpa > /sys/bus/pci/devices/$host_pf/driver_override
	echo $host_pf > /sys/bus/pci/drivers_probe
	echo $vf_cnt > /sys/bus/pci/devices/$host_pf/sriov_numvfs

	set +x
	sdp_vfs=$(lspci -Dn -d :${part}03 | cut -f 1 -d " ")
	for dev in $sdp_vfs; do
		set +e # Grep can return non-zero status
		vdev=$(ls /sys/bus/pci/devices/$dev | grep vdpa)
		while [[ "$vdev" == "" ]]; do
			echo "Waiting for vdpa device for $dev"
			sleep 1
			vdev=$(ls /sys/bus/pci/devices/$dev | grep vdpa)
		done
		set -e

		set +e # virtio vdpa driver may not be present on host
		echo $vdev > /sys/bus/vdpa/drivers/virtio_vdpa/unbind
		set -e

		echo "Binding $vdev to vhost_vdpa"
		echo $vdev > /sys/bus/vdpa/drivers/vhost_vdpa/bind || true
	done
}

function ep_host_start_traffic()
{
	local pfx=$1
	local num_cores
	local fwd_cores
	local eal_args
	local app_args

	num_cores=$(nproc --all)
	fwd_cores=$((num_cores - 1))
	eal_args="-l 0-$fwd_cores --socket-mem 1024 --proc-type auto --file-prefix=$pfx --no-pci \
		  --vdev=net_virtio_user0,path=/dev/vhost-vdpa-0,mrg_rxbuf=01,packed_vq=1,in_order=1,queue_size=4096"
	app_args="--nb-cores=$fwd_cores --port-topology=loop --rxq=$fwd_cores --txq=$fwd_cores -i"

	echo "Starting Traffic on Host"
	testpmd_launch $pfx "$eal_args" "$app_args"
	testpmd_cmd $pfx start
	echo "Started Traffic on Host"
}

function ep_host_stop_traffic()
{
	local pfx=$1

	echo "Stopping Traffic on Host"
	testpmd_cmd $pfx stop
	testpmd_quit $pfx
	testpmd_cleanup $pfx
	echo "Stopped Traffic on Host"
}

# If this script is directly invoked from the shell execute the
# op specified
if [[ ${BASH_SOURCE[0]} == ${0} ]]; then
	OP=$1
	ARGS=${@:2}
	ep_host_$OP $ARGS
fi
