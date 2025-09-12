#!/bin/sh
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2025 Marvell.

APP_HOME=$1
SCRIPTS="$APP_HOME/scripts"
BIN="$APP_HOME/bin"
CPT_MODULE="/root/cpt_module"

function load_ep() {
	# Unload the module if it is already loaded
	/sbin/rmmod pcie-marvell-cnxk-ep || true
	insmod /lib/modules/*/kernel/drivers/pci/controller/pcie-marvell-cnxk-ep.ko
}

function mount_hugetlbfs() {
	# Mount hugetlbfs.
	mkdir /dev/hugepages
	if ! mount | grep -q hugepages; then
		mount -t hugetlbfs none /dev/hugepages/
	fi
}

function setup_hp() {
	# Enable HP hugepages.
	echo $HP > /proc/sys/vm/nr_hugepages
}

function load_cpt() {
	insmod $CPT_MODULE/rvu_cptcommon.ko
	insmod $CPT_MODULE/rvu_cptpf.ko
}

function setup_devices() {
	local npa_pf
	local cpt_pf=""
	local cpt_vf=""
	local sdp_vf
	local devs

	cpt_pf=$(lspci -d :a0fd | awk '{ print $1 }')

	# Disable existing VFs and enable CPT VFs
	if [[ -e /sys/bus/pci/devices/$cpt_pf/sriov_numvfs ]]; then
		echo 0 > /sys/bus/pci/devices/$cpt_pf/sriov_numvfs
		echo 2 > /sys/bus/pci/devices/$cpt_pf/sriov_numvfs
		devlink dev info pci/$cpt_pf
	fi

	#CPT VF devices
	for cpt_vf in $(lspci -d :a0fe | awk '{ print $1 }'); do
		devs=$devs" $cpt_vf"
	done

	# SDP devices
	for sdp_vf in ${SDP_DEV:-$(lspci -d :a0f7 | awk 'NR > 1 { print $1 }')}; do
		devs=$devs" $sdp_vf"
	done

	# NPA devices
	npa_pf=${NPA_DEV:-$(lspci -d :a0fb | tail -1 | awk '{ print $1 }')}
	devs=$devs" $npa_pf"

	# Bind devices
	for d in $devs; do
		$SCRIPTS/lc_devbind.sh -b vfio-pci $d || exit 1
	done

	set -euo pipefail
}

function run_cp() {
	nohup /usr/bin/octep_cp_agent /etc/cn96xx.cfg &
}

function config_static_ip() {
	export $(grep -v '^#' config.env | xargs)
	LC_IP_ADDRESS=${LC_IP_ADDRESS:-192.168.1.1/24}
	ip addr add $LC_IP_ADDRESS dev sdp15-0
	ip link set sdp15-0 up
}

function enable_ssh() {
	sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
	/etc/init.d/S50sshd restart
}

# Wrapper to invoke partition logic only when booted from MMC
setup_redirection() {
	cmdline=$(cat /proc/cmdline)
	if echo "$cmdline" | grep -q "root="; then
		check_or_create_partition6
	else
		echo "[partition6] Skipping (non-MMC root)"
	fi
}

# Environment variables
HP=${HP:-8}

load_ep
mount_hugetlbfs
setup_hp
load_cpt
setup_devices
run_cp
config_static_ip
enable_ssh
setup_redirection
