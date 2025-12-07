#!/bin/bash
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2024 Marvell.

COMMON_OPS_SCRIPT_PATH=$(dirname $(readlink -f "${BASH_SOURCE[0]}"))
source "$COMMON_OPS_SCRIPT_PATH/testpmd.sh"

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
	local num_alias=
	local vlan_id=
	local mtu=

	if ! opts=$(getopt \
		-l "ip:,pcie-addr:,down,vxlan-remote-ip:,vxlan-local-ip:,vxlan-vni:,vlan-id:,mtu:,\
			alias:" -- configure_sdp_interface $@); then
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
			--alias) shift; num_alias=$1;;
			--down) down=1;;
			--mtu) shift; mtu=$1;;
			*) echo "Invalid argument $1"; exit 1;;
		esac
		shift
	done

	iface_name=$(ep_common_if_name_get $pcie_addr)
	if [[ -z $iface_name ]]; then
		echo "Failed to get interface name for $pcie_addr"
		exit
	fi

	if [[ -z $num_alias ]]; then
		ep_common_cleanup_interfaces $iface_name
	fi


	if [[ -z $down ]]; then
		if [[ -n $num_alias ]]; then
			IFS='.' read -r -a ip_parts <<< "$ip_addr"
			for ((i=0; i<$num_alias; i++)); do
				ip="${ip_parts[0]}.${ip_parts[1]}.${ip_parts[2]}.${ip_parts[3]}"
				if [[ -n $vlan_id ]]; then
					vlan_id=$((vlan_id + 1))
					ip link add link $iface_name name \
						$iface_name.v$vlan_id type vlan id $vlan_id
					ip link set dev $iface_name.v$vlan_id up
					ip addr add $ip/24 dev $iface_name.v$vlan_id
				else
					ifconfig $iface_name:$i $ip/24
				fi
				((ip_parts[3]++))
			done
		elif [[ -n $vlan_id ]]; then
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

		if [[ -n $mtu ]]; then
			ifconfig $iface_name mtu $mtu
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
	local pktsz=${4:-56}
	local ping_out

	ping_out=$(ping -c $count -i 0.2 -s $pktsz -I $src $dst || true)
	echo "$ping_out">&2
	if [[ -n $(echo $ping_out | grep ", 0% packet loss,") ]]; then
		echo "SUCCESS"
	else
		echo "FAILURE"
	fi
}

function ep_common_multiple_pings()
{
	local host_ip=$1
	local remote_ip=$2
	local num_ifs=$3
	local remote_if

	IFS='.' read -r -a hip <<< "$host_ip"
	IFS='.' read -r -a rip <<< "$remote_ip"

	for ((i=0; i<$num_ifs; i++)); do
		if [[ $(ep_common_ping $host_ip $remote_ip) != "SUCCESS" ]]; then
			echo "FAILURE"
			exit 1
		fi

		((hip[3]++))
		((rip[3]++))
		host_ip="${hip[0]}.${hip[1]}.${hip[2]}.${hip[3]}"
		remote_ip="${rip[0]}.${rip[1]}.${rip[2]}.${rip[3]}"
	done

	echo "SUCCESS"
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

ep_host_clean_sdp_host_ifcs()
{
	local sdp_vfs="$@"

	for vf in $sdp_vfs; do
		iface=$(ep_common_if_name_get $vf)
		ep_common_cleanup_interfaces $iface
	done
}

ep_common_cleanup_alias_ifcs()
{
	local pci_addr=$1
	local num_alias=$2
	local ip=$3
	local test_type=$4
	local vlan_id=$5
	local iface=$(ep_common_if_name_get $pci_addr)

	IFS='.' read -r -a ip_parts <<< "$ip"

	if [[ $test_type == "vlan" ]]; then
		ip link del $iface.v$vlan_id
		((vlan_id++))
	fi

	for ((i=0; i<$num_alias; i++)); do
	  if [[ $test_type == "plane" ]]; then
		  ip addr del $ip/24 dev $iface:$i
	  elif [[ $test_type == "vlan" ]]; then
		  ip link del $iface.v$vlan_id
		  ((vlan_id++))
	  fi
	  ((ip_parts[3]++))
	  ip="${ip_parts[0]}.${ip_parts[1]}.${ip_parts[2]}.${ip_parts[3]}"
	done

	ep_common_cleanup_interfaces $iface
}

function ep_common_set_numvfs()
{
	local dev=$1
	local numvfs=$2
	local maxvfs=$(cat /sys/bus/pci/devices/$dev/sriov_totalvfs)

	numvfs=$((numvfs >  maxvfs ? maxvfs : numvfs))

	echo 0 > /sys/bus/pci/devices/$dev/sriov_numvfs
	sleep 1
	echo $numvfs > /sys/bus/pci/devices/$dev/sriov_numvfs
	sleep 1
}

function ep_common_unbind_driver()
{
	local s=$1
	local dev=$2
	local vendor_id

	if [[ "$s" == "pci" ]]; then
		vendor_id=$(cat /sys/bus/pci/devices/$dev/vendor 2>/dev/null || echo "")
		# Mellanox device needs no unbinding
		if [[ "$vendor_id" == "0x15b3" ]]; then
			return 0
		fi
	fi

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
	local vendor_id

	if [[ "$s" == "pci" ]]; then
		vendor_id=$(cat /sys/bus/pci/devices/$dev/vendor 2>/dev/null || echo "")
		# Mellanox device needs no binding
		if [[ "$vendor_id" == "0x15b3" ]]; then
			return 0
		fi
	fi

	ep_common_unbind_driver $s $dev
	echo $driver > /sys/bus/$s/devices/$dev/driver_override
	echo $dev > /sys/bus/$s/drivers/$driver/bind
	echo $dev > /sys/bus/$s/drivers_probe
}

function ep_common_get_v4_gid_index()
{
	local dev="$1"
	local rdma_build="${2:-}"
	local bin_path="$rdma_build/bin"
	local lib_path="$rdma_build/lib"
	local gid=

	[[ -n "$bin_path" ]] && export PATH="${bin_path}:${PATH}"
	[[ -n "$lib_path"  ]] && export LD_LIBRARY_PATH="${lib_path}:${LD_LIBRARY_PATH:-}"

	# Get gid index of 1st ipv4 address configured on the interface
	gid=$(ibv_devinfo -d "$dev" -vvv 2>/dev/null | \
	      awk -F'[[]|[]]' '/GID\[.*::ffff:/ { gsub(/^ +/, "", $2); print $2;}')

	echo $gid
}

function ep_common_get_rdma_device()
{
	local rdma_build="${1:-}"
	local bin_path="$rdma_build/bin"
	local lib_path="$rdma_build/lib"
	local devices=
	local dev=

	[[ -n "$bin_path" ]] && export PATH="${bin_path}:${PATH}"
	[[ -n "$lib_path"  ]] && export LD_LIBRARY_PATH="${lib_path}:${LD_LIBRARY_PATH:-}"

	devices="$(ibv_devices 2>/dev/null | awk 'NR>2 && NF {print $1}')"
	if [ -z "$devices" ]; then
		echo "Error: No RDMA devices found." >&2
		return 2
	fi

	while IFS= read -r dev; do
		if ibv_devinfo -d "$dev" 2>/dev/null | awk '/state:/ && /PORT_ACTIVE/ {exit 0} AND {exit 1}'; then
			echo $dev
			return 0
		fi
	done <<< "$devices"

	echo "Error: No devices have a port in PORT_ACTIVE state." >&2
	return 3
}

function ep_common_rdma_test_cleanup()
{
	local force_mode="${1:-false}"
	local test_binaries=(
		"ibv_ud_pingpong"
		"ibv_rc_pingpong"
		)

	for binary in "${test_binaries[@]}"; do
		if pgrep -f "$binary" >/dev/null 2>&1; then
			echo "Stopping $binary processes..."
			pkill -9 -f "$binary" 2>/dev/null || echo "Warning: Failed to stop some $binary processes"
			sleep 2

			# Verify cleanup
			if pgrep -f "$binary" >/dev/null 2>&1; then
				echo "WARNING: Some $binary processes still running"
				if [[ "$force_mode" != "true" ]]; then
					return 1
				fi
			else
				echo "$binary processes stopped successfully"
			fi
		fi
	done

	return 0
}
