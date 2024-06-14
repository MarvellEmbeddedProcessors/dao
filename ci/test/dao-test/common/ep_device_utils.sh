#!/bin/bash
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2024 Marvell.

EP_UTILS_SCRIPT_PATH=$(dirname $(readlink -f "${BASH_SOURCE[0]}"))
source $EP_UTILS_SCRIPT_PATH/utils.sh

find_executable "oxk-devbind-basic.sh" DEVBIND "$EP_UTILS_SCRIPT_PATH"

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

function ep_device_vfio_bind()
{
	$DEVBIND -b vfio-pci $@
}

function ep_device_vfio_unbind()
{
	$DEVBIND -u vfio-pci $@
}

function ep_device_hugepage_setup()
{
	echo "Setting up hugepages"
	# Check for hugepages
	if mount | grep hugetlbfs | grep none; then
		echo "Hugepages already mounted"
	else
		echo "Mounting Hugepages"
		mkdir -p /dev/huge
		mount -t hugetlbfs none /dev/huge
	fi
	echo 24 > /proc/sys/vm/nr_hugepages
	echo 6 >/sys/kernel/mm/hugepages/hugepages-524288kB/nr_hugepages
	echo "Done setting up hugepages"
}

function ep_device_dpi_setup()
{
	# Bind DPI devices
	local dpi_pf=$(lspci -d :a080 | awk -e '{print $1}')
	local dpi_vf

	echo "Binding DPI devices"
	# Bind required DMA devices to vfio-pci
	# Enhance DPI engine FIFO size and MRRS
	echo 0x10101010 > /sys/bus/pci/drivers/octeontx2-dpi/module/parameters/eng_fifo_buf
	echo 512 > /sys/bus/pci/drivers/octeontx2-dpi/module/parameters/mrrs
	echo 256 > /sys/bus/pci/drivers/octeontx2-dpi/module/parameters/mps

	echo $dpi_pf > /sys/bus/pci/devices/$dpi_pf/driver/unbind || true
	echo octeontx2-dpi > /sys/bus/pci/devices/$dpi_pf/driver_override
	echo $dpi_pf > /sys/bus/pci/drivers_probe

	echo 32 >/sys/bus/pci/devices/$dpi_pf/sriov_numvfs
	dpi_vf=$(lspci -d :a081 | awk -e '{print $1}' | head -22)
	ep_device_vfio_bind $dpi_vf
	echo "Done Binding DPI devices"

	# Bind required RPM VF's to vfio-pci
	echo "Binding RPM devices"
	ep_device_vfio_bind 0002:01:00.2 0002:01:00.1
	echo "Done Binding RPM devices"
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
			echo "vfio-platform" | tee "$dev_path/driver_override" || true
			echo "$dev_name" | tee "/sys/bus/platform/drivers/vfio-platform/bind" || true

			echo "Device $dev_name configured."
		fi
	done
	echo "Done binding PEM/SDP regs devices"
}

function ep_device_fw_cleanup()
{
	set +e
	ps -ef | grep dao-virtio-l2fwd | grep fw_launch | awk '{print $2}' | head -n1 | xargs -n1 kill -9
	set -e
}

function ep_device_fw_launch()
{
	local dpi_vf
	local cmd

	ep_device_fw_cleanup

	dpi_vf=$(lspci -d :a081 | awk -e '{print $1}' | head -22)

	# Launch EP firmware application
	echo "Launching EP Firwmare App"
	local virtio_l2fwd
	find_executable "dao-virtio-l2fwd" virtio_l2fwd "$EP_UTILS_SCRIPT_PATH/../../../../app"
	local dpi_allow=""
	for d in $dpi_vf; do
		dpi_allow="$dpi_allow -a $d"
	done
	cmd="$virtio_l2fwd --file-prefix fw_launch -l 4-6 -a 0002:01:00.2 $dpi_allow -- -p 0x1 -v 0x1 -P"
	echo $cmd
	$cmd
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

# If this script is directly invoked from the shell execute the
# op specified
if [[ ${BASH_SOURCE[0]} == ${0} ]]; then
	OP=$1
	ARGS=${@:2}
	if [[ $(type -t ep_device_$OP) == function ]]; then
		ep_device_$OP $ARGS
	else
		$OP $ARGS
	fi
fi
