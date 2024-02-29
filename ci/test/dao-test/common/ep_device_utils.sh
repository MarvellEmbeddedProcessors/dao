#!/bin/bash
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2024 Marvell.

DEVICE_UTILS_SCRIPT_PATH=$(dirname $(readlink -f "${BASH_SOURCE[0]}"))
source $DEVICE_UTILS_SCRIPT_PATH/utils.sh
source "$DEVICE_UTILS_SCRIPT_PATH/ep_common_ops.sh"

PCI_VENDOR_ID_CAVIUM="0x177d"

PCI_DEVID_CNXK_RVU_PF="0xa063"
PCI_DEVID_CNXK_RVU_VF="0xa064"
PCI_DEVID_CNXK_RVU_AF="0xa065"
PCI_DEVID_CNXK_RVU_SSO_TIM_PF="0xa0f9"
PCI_DEVID_CNXK_RVU_SSO_TIM_VF="0xa0fa"
PCI_DEVID_CNXK_RVU_NPA_PF="0xa0fb"
PCI_DEVID_CNXK_RVU_NPA_VF="0xa0fc"
PCI_DEVID_CNXK_RVU_AF_VF="0xa0f8"
PCI_DEVID_CN10K_RVU_CPT_PF="0xa0f2"
PCI_DEVID_CN10K_RVU_CPT_VF="0xa0f3"
PCI_DEVID_CN10K_RVU_SDP_VF="0xa0f7"
PCI_DEVID_CN10K_RVU_DPI_PF="0xa080"
PCI_DEVID_CN10K_RVU_DPI_VF="0xa081"
PCI_DEVID_CN10K_RVU_ESW_PF="0xa0e0"

RVU_DEV_IDS="
$PCI_DEVID_CNXK_RVU_PF
$PCI_DEVID_CNXK_RVU_VF
$PCI_DEVID_CNXK_RVU_AF
$PCI_DEVID_CNXK_RVU_SSO_TIM_PF
$PCI_DEVID_CNXK_RVU_SSO_TIM_VF
$PCI_DEVID_CNXK_RVU_NPA_PF
$PCI_DEVID_CNXK_RVU_NPA_VF
$PCI_DEVID_CNXK_RVU_AF_VF
$PCI_DEVID_CN10K_RVU_CPT_PF
$PCI_DEVID_CN10K_RVU_CPT_VF
"

CPUPARTNUM_106XX=0xd49
PCI_DEV_PART_105XX=0xba
PCI_DEV_PART_106XX=0xb9

VFIO_TOKEN="9d75f7af-606e-47ff-8ae4-f459fce4a422"

function ep_device_eth_interfaces_get()
{
	local ssh_ip=$1
	local req_ifcs=${2:-}
	local num_ifcs=0
	local eth_ifcs_filtered=""
	# Get the SSH IP and the eth interface it is connected to
	local ssh_ifc_name=$(ip -f inet addr show | grep $ssh_ip -B 1 | head -n1 | \
				awk -F '[ :]' '{print $3}')
	local ssh_ifc=$(cat /sys/class/net/$ssh_ifc_name/device/uevent | grep PCI_SLOT_NAME | \
				awk -F '=' '{print $2}')
	local eth_ifcs=$(ep_common_pcie_addr_get $PCI_DEVID_CNXK_RVU_PF all)

	# Filter out the eth ports that are not connected to the SSH interface
	for e in $eth_ifcs; do
		if [[ "$e" != "$ssh_ifc" ]]; then
			eth_ifcs_filtered="$eth_ifcs_filtered $e"
			num_ifcs=$((num_ifcs + 1))
			if [[ -n $req_ifcs ]] && [[ $num_ifcs -eq $req_ifcs ]]; then
				break
			fi
		fi
	done
	if [[ -n $req_ifcs ]] && [[ $num_ifcs -lt $req_ifcs ]]; then
		echo "Not enough eth interfaces available"
		exit 1
	fi
	echo $eth_ifcs_filtered
}

function ep_device_sdp_setup()
{
	local eth_ifcs=""
	local sdp_pcie_pf
	# This is the number of bridges/eth ports to set up.
	# This is the number of SDP interfaces to bind per eth.
	local num_sdp_ifcs_per_eth=2
	local cur_sdp_idx
	local cur_eth_idx
	local opts

	if ! opts=$(getopt \
			-l "num-sdp-ifcs-per-eth:,eth-ifc:" \
			-- sdp_setup ${@}); then
		echo "Failed to parse arguments"
		exit 1
	fi

	eval set -- "$opts"
	while [[ $# -gt 1 ]]; do
		case $1 in
			--eth-ifc) shift; eth_ifcs="$eth_ifcs $1";;
			--num-sdp-ifcs-per-eth) shift; num_sdp_ifcs_per_eth=$1;;
			*) echo "Unknown argument $1"; exit 1;;
		esac
		shift
	done

	# Setting up SDP device
	sdp_pcie_pf=$(ep_common_pcie_addr_get  $PCI_DEVID_CN10K_RVU_SDP_VF)

	cur_sdp_idx=1
	cur_eth_idx=1
	for eth_pf in $eth_ifcs; do
		# Bind to vfio and then create VFs
		ep_common_bind_driver pci $eth_pf vfio-pci
		ep_common_set_numvfs $eth_pf $num_sdp_ifcs_per_eth

		for j in $(seq 1 $num_sdp_ifcs_per_eth); do
			local eth_pcie_addr=$(get_vf_pcie_addr ${eth_pf} $j)
			local sdp_pcie_addr=$(get_vf_pcie_addr ${sdp_pcie_pf} $cur_sdp_idx)

			ep_common_bind_driver pci $sdp_pcie_addr vfio-pci
			echo "${sdp_pcie_addr},${eth_pcie_addr} "
			sleep 1
			cur_sdp_idx=$((cur_sdp_idx + 1))
		done
	done
}

function ep_device_esw_setup()
{
	local num_esw_vfs=$1
	local esw_pf_pcie
	local cur_esw_idx
	local esw_vfs=""

	# Setting up ESW device
	esw_pf_pcie=$(ep_common_pcie_addr_get $PCI_DEVID_CN10K_RVU_ESW_PF)
	ep_common_bind_driver pci $esw_pf_pcie vfio-pci
	ep_common_set_numvfs $esw_pf_pcie $num_esw_vfs

	cur_esw_idx=1
	for j in $(seq 1 $num_esw_vfs); do
		local esw_pcie_addr=$(get_vf_pcie_addr ${esw_pf_pcie} $j)
		esw_vfs="$esw_vfs $esw_pcie_addr"
		cur_esw_idx=$((cur_esw_idx + 1))
	done
	echo $esw_vfs
}

function ep_device_dpi_setup()
{
	# Bind DPI devices
	local dpi_pf=$(ep_common_pcie_addr_get $PCI_DEVID_CN10K_RVU_DPI_PF)
	local dpi_vfs

	echo "Binding DPI devices"
	# Bind required DMA devices to vfio-pci
	# Enhance DPI engine FIFO size and MRRS
	echo 0x10101010 > /sys/bus/pci/drivers/octeontx2-dpi/module/parameters/eng_fifo_buf
	echo 512 > /sys/bus/pci/drivers/octeontx2-dpi/module/parameters/mrrs
	echo 256 > /sys/bus/pci/drivers/octeontx2-dpi/module/parameters/mps

	ep_common_bind_driver pci $dpi_pf octeontx2-dpi
	ep_common_set_numvfs $dpi_pf 32

	dpi_vfs=$(ep_common_pcie_addr_get $PCI_DEVID_CN10K_RVU_DPI_VF 22)
	for v in $dpi_vfs; do
		ep_common_bind_driver pci $v vfio-pci
	done
	echo "Done Binding DPI devices"
}

function ep_device_pem_setup()
{
	# Bind PEM BAR4 and DPI BAR0 platform devices to vfio-platform
	# Platform device suffixes to search for
	local pem_sfx="pem0-bar4-mem"
	local sdp_sfx="dpi_sdp_regs"

	# Loop through devices
	echo "Binding PEM/SDP regs devices"
	for dev_path in /sys/bus/platform/devices/*; do
		if [[ -d "$dev_path" && "$dev_path" =~ $pem_sfx || "$dev_path" =~ $sdp_sfx ]]; then
			# Get device name from path
			local dev_name=$(basename "$dev_path")

			# Bind the device to vfio-platform driver
			ep_common_bind_driver platform $dev_name vfio-platform
			echo "Device $dev_name configured."
		fi
	done
	echo "Done binding PEM/SDP regs devices"
}

function ep_device_get_cpu_partnum()
{
	local partnum=$(grep -m 1 'CPU part' /proc/cpuinfo | awk -F': ' '{print $2}')
	echo $partnum
}

function ep_device_get_part()
{
	local vendor
	local dev_id
	local subsys_dev_id
	local part

	for d in $(ls /sys/bus/pci/devices); do
		local is_rvu_dev=0

		vendor=$(cat /sys/bus/pci/devices/$d/vendor)
		if [[ "$vendor" != "$PCI_VENDOR_ID_CAVIUM" ]]; then
			continue
		fi
		dev_id=$(cat /sys/bus/pci/devices/$d/device)
		for r in $RVU_DEV_IDS; do
			if [[ "$dev_id" == "$r" ]]; then
				is_rvu_dev=1
				break
			fi
		done
		if [[ $is_rvu_dev == 0 ]]; then
			continue
		fi
		subsys_dev_id=$(cat /sys/bus/pci/devices/$d/subsystem_device)
		part=${subsys_dev_id:2:2}
		break
	done
	echo $part
}

function ep_device_get_rclk()
{
	local sysclk_dir
	local fp_rclk
	local div=1000000
	local cpupartnum
	local rclk

	sysclk_dir="/sys/kernel/debug/clk"
	cpupartnum=$(ep_device_get_cpu_partnum)
	if [[ $cpupartnum == $CPUPARTNUM_106XX ]]; then
		fp_rclk="$sysclk_dir/coreclk/clk_rate"
	else
		fp_rclk="$sysclk_dir/rclk/clk_rate"
	fi

	if test -f "$fp_rclk"; then
		rclk=$(echo "$(cat $fp_rclk) / $div" | bc)
	else
		echo "$fp_rclk not available"
		exit 1
	fi
	echo $rclk
}

function ep_device_get_sclk()
{
	local sysclk_dir
	local fp_sclk
	local div=1000000
	local sclk

	sysclk_dir="/sys/kernel/debug/clk"
	fp_sclk="$sysclk_dir/sclk/clk_rate"

	if test -f "$fp_sclk"; then
		sclk=$(echo "$(cat $fp_sclk) / $div" | bc)
	else
		echo "$fp_sclk not available"
		exit 1
	fi

	echo $sclk
}

function ep_device_agent_cleanup()
{
	set +e
	pkill -9 octep_cp_agent
	rmmod pcie_marvell_cnxk_ep
	set -e
}

function ep_device_agent_init()
{
	local mod=$(lsmod | grep pcie_marvell_cnxk_ep)
	local ep_agent=$(pidof octep_cp_agent)
	local ep_bin_dir=$EP_DIR/ep_files
	local part=$(ep_device_get_part)
	local agent_conf

	if [[ 0x${part} == ${PCI_DEV_PART_106XX} ]]; then
		agent_conf=$ep_bin_dir/cn106xx.cfg
	elif [[ 0x${part} == 0x${PCI_DEV_PART_105XX} ]]; then
		agent_conf=$ep_bin_dir/cnf105xx.cfg
	else
		echo "Unknown part $part"
		exit 1
	fi

	if [[ $mod == "" ]]; then
		insmod $ep_bin_dir/pcie-marvell-cnxk-ep.ko
	fi

	if [[ $ep_agent == "" ]]; then
		$ep_bin_dir/octep_cp_agent \
			$agent_conf 2>&1 > $ep_bin_dir/octep_cp_agent.log &
	fi
}

function ep_device_get_inactive_if()
{
	for i in $(ep_common_pcie_addr_get $PCI_DEVID_CNXK_RVU_PF all); do
		local ethname=
		local active=
		if [ -d "/sys/bus/pci/devices/$i/net" ]; then
			ethname=$(ls /sys/bus/pci/devices/$i/net)
		fi

		if [[ "$ethname"  != "" ]]; then
			active=$(ip route show dev $ethname)
		fi
		# Return non active device found
		if [[ "$active" == "" ]]; then
			echo $i
			break
		fi
	done
}

function ep_device_get_num_cores()
{
	local num_cores=$(lscpu | grep "On-line CPU(s) list" | awk -F '-' '{print $3}')
	echo $(($num_cores + 1))
}

# If this script is directly invoked from the shell execute the
# op specified
if [[ ${BASH_SOURCE[0]} == ${0} ]]; then
	OP=$1
	ARGS=${@:2}
	if [[ $(type -t ep_device_$OP) == function ]]; then
		ep_device_$OP $ARGS
	elif [[ $(type -t ep_common_$OP) == function ]]; then
		ep_common_$OP $ARGS
	else
		$OP $ARGS
	fi
fi
