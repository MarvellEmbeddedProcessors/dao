#!/bin/bash
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2024 Marvell.

function ep_common_testpmd_launch()
{
	local pfx=$1
	local args=${@:2}
	local eal_args
	local app_args=""

	for a in $args; do
		if [[ $a == "--" ]]; then
			eal_args=$app_args
			app_args=""
			continue
		fi
		app_args+=" $a"
	done

	echo "Launching testpmd pfx=$pfx"
	testpmd_launch $pfx "$eal_args" "$app_args"
	echo "Launched testpmd pfx=$pfx"
}

function ep_common_testpmd_stop()
{
	local pfx=$1

	echo "Stopping testpmd pfx=$pfx"
	testpmd_quit $pfx
	testpmd_cleanup $pfx
	echo "Stopped testpmd pfx=$pfx"
}

function ep_common_hugepage_setup()
{
	local hp_sz=$1
	local hp_num=$2
	local hp_pool_sz=$3

	# Check for hugepages
	if mount | grep hugetlbfs | grep none; then
		echo "Hugepages already mounted"
	else
		echo "Mounting Hugepages"
		mkdir -p /dev/huge
		mount -t hugetlbfs none /dev/huge
	fi
	echo $hp_num > /proc/sys/vm/nr_hugepages
	echo $hp_pool_sz >/sys/kernel/mm/hugepages/hugepages-${hp_sz}kB/nr_hugepages
}

function ep_common_pcie_addr_get()
{
	local devid=$1
	local num=${2:-}

	if [[ -z $num ]]; then
		num=1
	elif [[ $num == "all" ]]; then
		num=100
	fi

	echo $(lspci -Dd :$devid | awk '{print $1}' | head -n$num)
}

function ep_common_if_name_get()
{
	local pcie_addr=$1

	set +e
	grep PCI_SLOT_NAME /sys/class/net/*/device/uevent | grep $pcie_addr | \
		awk -F '/' '{print $5}'
	set -e
}

function ep_common_if_configure()
{
	local ip_addr
	local opts
	local iface_name
	local pcie_addr=
	local down=
	local vxlan_remote_ip=
	local vxlan_local_ip=
	local vxlan_vni=
	local vlan_id=

	if ! opts=$(getopt \
		-l "ip:,pcie-addr:,down,vxlan-remote-ip:,vxlan-local-ip:,vxlan-vni:,vlan-id:" \
		-- configure_sdp_interface $@); then
		echo "Failed to parse arguments"
		exit 1
	fi

	eval set -- "$opts"
	while [[ $# -gt 1 ]]; do
		case $1 in
			--ip) shift; ip_addr=$1;;
			--pcie-addr) shift; pcie_addr=$1;;
			--vxlan-vni) shift; vxlan_vni=$1;;
			--vxlan-remote-ip) shift; vxlan_remote_ip=$1;;
			--vxlan-local-ip) shift; vxlan_local_ip=$1;;
			--vlan-id) shift; vlan_id=$1;;
			--down) down=1;;
			*) echo "Invalid argument $1"; exit 1;;
		esac
		shift
	done

	iface_name=$(ep_common_if_name_get $pcie_addr)
	if [[ -z $iface_name ]]; then
		echo "Failed to get interface name for $pcie_addr"
		exit
	fi

	ep_common_cleanup_interfaces $iface_name

	if [[ -z $down ]]; then
		if [[ -n $vlan_id ]]; then
			nmcli dev set $iface_name managed no &> /dev/null || true
			ifconfig $iface_name up
			ifconfig $iface_name 0
			ip link add link $iface_name name $iface_name.v$vlan_id \
				type vlan id $vlan_id
			nmcli dev set $iface_name.v$vlan_id managed no &> /dev/null || true
			ip link set dev $iface_name.v$vlan_id up
			ip addr add $ip_addr/24 dev $iface_name.v$vlan_id
		elif [[ -n $vxlan_vni ]]; then
			nmcli dev set $iface_name managed no &> /dev/null || true
			ifconfig $iface_name up
			ifconfig $iface_name $vxlan_local_ip/24
			ip link add $iface_name.vx$vxlan_vni \
				type vxlan id $vxlan_vni \
				remote $vxlan_remote_ip \
				local $vxlan_local_ip \
				dev $iface_name \
				dstport 4789
			nmcli dev set $iface_name.vx$vxlan_vni managed no &> /dev/null || true
			ip link set dev $iface_name.vx$vxlan_vni up
			ifconfig $iface_name.vx$vxlan_vni $ip_addr/24
		else
			nmcli dev set $iface_name managed no &> /dev/null || true
			ifconfig $iface_name up
			ifconfig $iface_name $ip_addr/24
		fi
	fi
}

function ep_common_ip_forwarding()
{
	local op=$1

	echo $op > /proc/sys/net/ipv4/ip_forward
}

function ep_common_ping()
{
	local src=$1
	local dst=$2
	local count=${3:-32}
	local ping_out

	ping_out=$(ping -c $count -i 0.2 -I $src $dst || true)
	if [[ -n $(echo $ping_out | grep ", 0% packet loss,") ]]; then
		echo "SUCCESS"
	else
		echo "FAILURE"
	fi
}

ep_common_cleanup_interfaces()
{
	local prefix=$1
	local ifcs=$(ifconfig | grep flags | grep "${prefix}.*:" | awk -F ':' '{print $1}')

	for ifc in $ifcs; do
		ifconfig $ifc down
		ip link del $ifc 2>/dev/null || true
	done
}

function ep_common_set_numvfs()
{
	local dev=$1
	local numvfs=$2

	echo 0 > /sys/bus/pci/devices/$dev/sriov_numvfs
	sleep 1
	echo $numvfs > /sys/bus/pci/devices/$dev/sriov_numvfs
	sleep 1
}

function ep_common_unbind_driver()
{
	local s=$1
	local dev=$2

	if [[ -e /sys/bus/$s/devices/$dev/driver/unbind ]]; then
		echo $dev > /sys/bus/$s/devices/$dev/driver/unbind
		sleep 1
		echo > /sys/bus/$s/devices/$dev/driver_override
		sleep 1
	fi
}

function ep_common_bind_driver()
{
	local s=$1
	local dev=$2
	local driver=$3

	ep_common_unbind_driver $s $dev
	echo $driver > /sys/bus/$s/devices/$dev/driver_override
	echo $dev > /sys/bus/$s/drivers/$driver/bind
	echo $dev > /sys/bus/$s/drivers_probe
}
