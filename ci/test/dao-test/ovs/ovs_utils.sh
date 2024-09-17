#!/bin/bash
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2024 Marvell.
set -e

OVS_UTILS_SCRIPT_PATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
source $OVS_UTILS_SCRIPT_PATH/../common/utils.sh
source $OVS_UTILS_SCRIPT_PATH/../common/ep_host_utils.sh
source $OVS_UTILS_SCRIPT_PATH/../common/ep_device_utils.sh

PATH=$PATH:$EP_DEVICE_OVS_PATH/sbin:$EP_DEVICE_OVS_PATH/bin
export PATH=$PATH:$EP_DEVICE_OVS_PATH/share/openvswitch/scripts

function ovs_cleanup() {
	local log=$EP_DEVICE_OVS_PATH/var/log/ovs-vswitchd.log

	set +e
	ovs_bridge_del_all
	ovs-ctl stop
	sleep 2

	pkill_with_wait ovsdb-server
	pkill_with_wait ovs-vswitchd
	set -e

	if [[ -e $log ]]; then
		echo "=========== OVS LOG ============="
		cat $log
	fi
}

function ovs_launch()
{
	local hw_offload=false
	local debug
	local allow=""
	local sock="$EP_DEVICE_OVS_PATH/var/run/openvswitch/db.sock"
	local conf="$EP_DEVICE_OVS_PATH/etc/openvswitch/conf.db"
	local schema="$EP_DEVICE_OVS_PATH/share/openvswitch/vswitch.ovsschema"
	local log="$EP_DEVICE_OVS_PATH/var/log/ovs-vswitchd.log"

	if ! opts=$(getopt \
		-l "hw-offload:,eth-ifc:,debug:" \
		-- ovs_launch $@); then
			echo "Failed to parse arguments"
			exit 1
	fi

	eval set -- "$opts"
	while [[ $# -gt 1 ]]; do
		case $1 in
			--hw-offload) shift; hw_offload=$1;;
			--eth-ifc) shift; allow="$allow --allow=$1";;
			--debug) shift; debug=1;;
			*) echo "Unknown argument $1"; exit 1;;
		esac
		shift
	done

	mkdir -p $EP_DEVICE_OVS_PATH/var/run/openvswitch
	mkdir -p $EP_DEVICE_OVS_PATH/var/log/openvswitch
	mkdir -p $EP_DEVICE_OVS_PATH/share/openvswitch
	mkdir -p $EP_DEVICE_OVS_PATH/etc/openvswitch

	# Init OVS
	ovsdb-tool create $conf $schema

	ovsdb-server \
		--remote=punix:"$sock" \
		--remote=db:Open_vSwitch,Open_vSwitch,manager_options \
		--pidfile \
		--detach

	echo "Starting OVS"
	ovs-ctl start \
		--db-sock="$sock" \
		--db-file="$conf" \
		--db-schema="$schema" \
		--no-ovs-vswitchd

	ovs-vsctl --no-wait init

	ovs-vsctl \
		--no-wait \
		set Open_vSwitch . other_config:dpdk-init=true \
		other_config:dpdk-socket-mem="1024" other_config:hw-offload=$hw_offload \
		other_config:dpdk-extra="--vfio-vf-token=\"$VFIO_TOKEN\" $allow"

        # Removing old vswitchd logs before launching new OVS vswitchd instance
	rm -f $log
	ovs-vswitchd \
		unix:"${sock}" \
		--pidfile \
		--detach \
		--log-file=$log

	# Raise log level
	if [[ $debug -eq "1" ]]; then
		ovs-appctl vlog/set netdev_dpdk:file:dbg
		ovs-appctl vlog/set netdev_offload_dpdk:file:dbg
		ovs-appctl vlog/set netdev_dpdk:console:info
	fi

	ovs-vsctl show
}

function ovs_interface_setup()
{
	local eth_ifcs=""
	local eth_ifc_idx
	local eth_ifc_max
	local esw_pf_pcie
	local opts
	local vxlan_vni=
	local vxlan_subnet=
	local net
	local ipaddr
	local vlan_id=
	local mtu=

	if ! opts=$(getopt \
		-l "eth-ifc:,num-sdp-ifcs-per-eth:,vxlan-vni:,vxlan-subnet:,vlan-id:,mtu-request:" \
		-- interface_setup $@); then
			echo "Failed to parse arguments"
			exit 1
	fi

	eval set -- "$opts"
	while [[ $# -gt 1 ]]; do
		case $1 in
			--eth-ifc) shift; eth_ifcs="$eth_ifcs $1";;
			--vxlan-vni) shift; vxlan_vni=$1;;
			--vxlan-subnet) shift; vxlan_subnet=$1;;
			--vlan-id) shift; vlan_id=$1;;
			--num-sdp-ifcs-per-eth) shift; num_sdp_ifcs_per_eth=$1;;
			--mtu-request) shift; mtu=$1;;
			*) echo "Unknown argument $1"; exit 1;;
		esac
		shift
	done

	esw_pf_pcie=$(ep_common_pcie_addr_get $PCI_DEVID_CN10K_RVU_ESW_PF)
	eth_ifc_idx=0
	for eth_ifc in $eth_ifcs; do
		ovs_bridge_add br${eth_ifc_idx} "netdev"
		sleep 1

		for sdp_idx in $(seq 0 $((num_sdp_ifcs_per_eth - 1))); do
			local pfid=$(echo $eth_ifc | awk -F ":" '{print $2}')

			pfid=$((pfid - 1))
			ovs_port_add \
				"br${eth_ifc_idx}" \
				"e${eth_ifc_idx}_vf_rep${sdp_idx}" \
				$esw_pf_pcie \
				"representor=pf${pfid}vf${sdp_idx}" \
				"mtu_request=$mtu"

		done

		if [[ -n $vxlan_vni ]]; then
			local vni=$((vxlan_vni + eth_ifc_idx))
			net=$((eth_ifc_idx + 2))
			ipaddr=${vxlan_subnet%.*}.$net
			ovs_vxlan_port_add "br${eth_ifc_idx}" "vxlan${eth_ifc_idx}" \
				"$ipaddr" $vni "mtu_request=$mtu"
		else
			ovs_port_add "br${eth_ifc_idx}" "e${eth_ifc_idx}_pf" $eth_ifc \
				"" "mtu_request=$mtu"
		fi

		sleep 1

		# Bring the bridge up
		ovs_iface_link_set "br${eth_ifc_idx}" "up"
		eth_ifc_idx=$((eth_ifc_idx + 1))
	done

	eth_ifc_max=$eth_ifc_idx
	if [[ -n $vxlan_vni ]]; then
		net=254
		eth_ifc_idx=0
		for eth_ifc in $eth_ifcs; do
			local k=$((eth_ifc_max + eth_ifc_idx))
			local khex=$(printf "%x" $k)

			br_args="-- br-set-external-id br${k} bridge-id br${k} \
				 -- set bridge br${k} fail-mode=standalone \
				 other_config:hwaddr=00:00:00:aa:bb:$khex"

			ovs_bridge_add br${k} "netdev" "$br_args"
			ovs_port_add "br${k}" "e${eth_ifc_idx}_pf" $eth_ifc "" "mtu_request=$mtu"

			# Bring the bridge up
			ovs_iface_link_set "br${k}" "up"

			ipaddr=${vxlan_subnet%.*}.$net
			ip addr add $ipaddr/24 dev "br${k}"
			ovs-appctl ovs/route/add $ipaddr/24 "br${k}"
			net=$((net - 1))
			eth_ifc_idx=$((eth_ifc_idx + 1))
		done
	fi

	echo "List of bridges"
	ovs-vsctl list-br
	if [[ -n $vlan_id ]]; then
		ovs-vsctl set port e0_vf_rep0 tag=$vlan_id
	fi
	ovs-vsctl show
}

function ovs_bridge_add()
{
	local br_name=$1
	local dp_type=$2
	local br_args=${3:-}

	ovs-vsctl add-br $br_name -- set bridge $br_name datapath_type=$dp_type $br_args
}

function ovs_bridge_del()
{
	local br_name=$1

        timeout 3 ovs-vsctl del-br $br_name
}

function ovs_bridge_del_all()
{
	local bridges=$(ovs-vsctl list-br)

	if [ $? -eq 0 ]; then
		for br in $bridges; do
			ovs_bridge_del $br
		done
	fi
}

function ovs_port_add()
{
	local br_name=$1
	local port=$2
	local pcie_addr=$3
	local rep_args=${4:-}
	local mtu_args=${5:-}

	if [[ -n $rep_args ]]; then
		rep_args=",$rep_args"
	fi
	ovs-vsctl add-port $br_name $port -- set Interface $port type=dpdk \
		options:dpdk-devargs="$pcie_addr"$rep_args $mtu_args
}

function ovs_vxlan_port_add()
{
	local br_name=$1
	local port=$2
	local raddr=$3
	local vni=$4
	local mtu_args=${5:-}

	ovs-vsctl add-port $br_name $port -- set Interface $port type=vxlan \
		options:remote_ip=$raddr options:key=$vni $mtu_args
}

function ovs_port_del()
{
	local br_name=$1
	local port=$2

	ovs-vsctl del-port --if-exists $br_name $port
}

function ovs_vlan_tag_add()
{
	local iface=$1
	local vtag=$2

	ovs-vsctl set port $iface tag=$vtag
}

function ovs_iface_link_set()
{
	local iface=$1
	local action=$2

	ip link set dev $iface $action
}

function ovs_offload_cleanup()
{
	local log=$EP_DEVICE_OVS_PATH/var/log/dao-ovs-offload.log

	pkill_with_wait dao-ovs-offload SIGINT

	if [[ -e $log ]]; then
		echo "OVS OFFLOAD Logs"
		echo "================"
		cat $log
	fi
}

function ovs_offload_launch()
{
	local num_cores=$(ep_device_get_num_cores)
	local num_ports=0
	local opts
	local allowlist=""
	local portmap=""
	local sdp_vf
	local eth_vf
	local dao_offload
	local coremask=0
	local portconf=""
	local maxpktlen=0
	local tmp

	if ! opts=$(getopt \
		-l "sdp-eth-vf-pair:,esw-vf-ifc:,max-pkt-len:" \
		-- get_allowlist $@); then
			echo "Failed to parse arguments"
			exit 1
	fi

	eval set -- "$opts"
	while [[ $# -gt 1 ]]; do
		case $1 in
			--sdp-eth-vf-pair) shift;
				# One additional core required for control thread
				if [[ $num_cores -le 2 ]]; then
					echo "Error: Number of cores: $num_cores not sufficient"
					exit 1
				fi
				sdp_vf=$(echo $1 | awk -F ',' '{print $1}');
				eth_vf=$(echo $1 | awk -F ',' '{print $2}');
				allowlist="$allowlist -a $sdp_vf -a $eth_vf";
				portmap="${portmap}(${1}),";
				tmp="($num_ports,0,$((num_cores - 1))),"
				tmp+="($((num_ports + 1)),0,$((num_cores - 2))),";
				portconf="${portconf}${tmp}";
				num_ports=$((num_ports + 2));
				num_cores=$((num_cores - 2));
				coremask=$((coremask | 3 << num_cores));;
			--esw-vf-ifc) shift;
				allowlist="$allowlist -a $1";;
			--max-pkt-len) shift;
				maxpktlen=$1;;
			*) echo "Unknown argument $1"; exit 1;;
		esac
		shift
	done

	portmap=${portmap::-1}
	portconf=${portconf::-1}

	# 1 extra core for control thread
	num_cores=$((num_cores - 1))
	coremask=$((coremask | 1 << num_cores))
	# Convert the coremask to hex
	coremask=$(printf "%x" $coremask)
	coremask="0x$coremask"

	find_executable "dao-ovs-offload" dao_offload "$OVS_UTILS_SCRIPT_PATH/../../../../app"

	echo "$dao_offload \
		-c $coremask \
		$allowlist \
		--vfio-vf-token="$VFIO_TOKEN" \
		--file-prefix=ep \
		-- \
		-p 0xff \
		--portmap="$portmap" \
		--max-pkt-len=$maxpktlen \
		--config="$portconf" &> $EP_DEVICE_OVS_PATH/var/log/dao-ovs-offload.log &"
	$dao_offload \
		-c $coremask \
		$allowlist \
		--vfio-vf-token="$VFIO_TOKEN" \
		--file-prefix=ep \
		-- \
		-p 0xff \
		--portmap="$portmap" \
		--max-pkt-len=$maxpktlen \
		--config="$portconf" &> $EP_DEVICE_OVS_PATH/var/log/dao-ovs-offload.log &

	sleep 10
}

function ovs_sig_handler()
{
	local status=$?
	local sig=$1
	local vlan_id=${2:-}

	set +e
	trap - ERR
	trap - INT
	trap - TERM
	trap - QUIT
	trap - EXIT

	if [[ $status -ne 0 ]]; then
		echo "$sig Handler"
	fi

	ovs_offload_cleanup
	ovs_cleanup
	# Cleanup any leftover bridges
	ep_common_cleanup_interfaces "br"
	ep_host_op if_configure --pcie-addr $EP_HOST_SDP_IFACE --down
	ep_remote_op if_configure --pcie-addr $EP_REMOTE_IFACE --down
}

function ovs_register_sig_handler()
{
	local vlan_id=${1:-}
	# Register the traps
	trap "ovs_sig_handler ERR $vlan_id" ERR
	trap "ovs_sig_handler INT $vlan_id" INT
	trap "ovs_sig_handler QUIT $vlan_id" QUIT
	trap "ovs_sig_handler EXIT $vlan_id" EXIT
}
