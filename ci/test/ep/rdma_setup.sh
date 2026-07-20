#!/bin/bash
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2025 Marvell.

set -euo pipefail

DAO_SUITE_SETUP["dao-rdma"]=dao_rdma_setup
DAO_SUITE_CLEANUP["dao-rdma"]=dao_rdma_cleanup

function dao_rdma_cleanup()
{
	if [[ -n $SKIP_SETUP ]]; then
		echo "Skip rdma cleanup"
		return
	fi

	echo "Starting DAO RDMA cleanup..."

	ep_host_op rdma_cleanup
	ep_remote_op guest_rdma_cleanup $EP_REMOTE_IFACE
	ep_device_op rdma_app_cleanup
	ep_host_op safe_kill $EP_DIR
	ep_device_op safe_kill $EP_DIR
	ep_host_ssh_cmd "$EP_HOST_SUDO dmesg" > host_dmesg.log
	save_log host_dmesg.log
	ep_device_ssh_cmd "$EP_DEVICE_SUDO dmesg" > device_dmesg.log
	save_log device_dmesg.log
	echo "DAO RDMA cleanup completed"
}

# Launch dao-rdma_graph on the EP device with the given external interface
# (plus the DPI VFs). Mirrors the per-test rdma_app_launch invocation.
function rdma_launch_device_app()
{
	local ext_iface=$1
	local num_mbufs=524288
	local max_pkt_len=9600
	local dma_nb_desc=8192
	local pci_devs="$ext_iface"
	local serialized_args app_cmd ld_library_path rdma_utils
	local dpi
	local dpi_vfs=()
	local tmp=()
	local args=()

	# Add DPI VFs
	read -r -a dpi_vfs <<< "$(ep_device_op pcie_addr_get $PCI_DEVID_CN10K_RVU_DPI_VF 16)"
	for dpi in "${dpi_vfs[@]}"; do
		pci_devs="$pci_devs $dpi"
	done

	read -r -a tmp <<< "$(form_split_args "--pci-devs"    "$pci_devs")"    ; args+=("${tmp[@]}")
	read -r -a tmp <<< "$(form_split_args "--max-pkt-len" "$max_pkt_len")" ; args+=("${tmp[@]}")
	read -r -a tmp <<< "$(form_split_args "--num-mbufs"   "$num_mbufs")"   ; args+=("${tmp[@]}")
	read -r -a tmp <<< "$(form_split_args "--dma-nb-desc" "$dma_nb_desc")" ; args+=("${tmp[@]}")

	# Serialize args for safe transport through SSH.
	serialized_args=$(printf '%q ' "${args[@]}")

	rdma_utils=$EP_DIR/ci/test/dao-test/rdma/rdma_utils.sh
	app_cmd="EP_DIR=$EP_DIR; source \"$rdma_utils\"; rdma_app_launch $serialized_args"
	ld_library_path="export LD_LIBRARY_PATH=\"${EP_DIR}/deps-prefix/ep/lib:\${LD_LIBRARY_PATH:-}\";"
	app_cmd="$ld_library_path $app_cmd"

	ep_device_ssh_cmd "$EP_DEVICE_SUDO -E bash -lc $(printf %q "$app_cmd")"
}

function verify_rdma_setup()
{
	local host_ip="30.0.0.3"
	local remote_ip="30.0.0.11"
	local ping_status
	local ext_iface=
	local remote_iface=
	local rdma_vfs
	local ssh_ip remote_ssh_ip
	local dev_candidates remote_candidates
	local e re

	ssh_ip=$(echo $EP_DEVICE | awk -F '@' '{print $2}' 2>/dev/null)
	remote_ssh_ip=$(echo $EP_REMOTE | awk -F '@' '{print $2}' 2>/dev/null)

	# If both the device external port and the remote port are pinned by the
	# operator (e.g. Mellanox x86 remote), skip the app-first pair discovery and
	# validation entirely. Bringing the full RDMA stack up here and then again in
	# the per-test rdma_setup_configure launches dao-rdma_graph twice in one run;
	# the second launch can crash on leftover host/device RDMA state. With the
	# pair already known, let the per-test do a single clean bring-up instead.
	if [[ -n "${EP_DEVICE_EXT_IFACE:-}" ]] && [[ -n "${EP_REMOTE_IFACE:-}" ]]; then
		echo "Device External Interface: $EP_DEVICE_EXT_IFACE (pinned)"
		echo "Remote Interface: $EP_REMOTE_IFACE (pinned)"
		add_test_env EP_DEVICE_EXT_IFACE=$EP_DEVICE_EXT_IFACE
		add_test_env EP_REMOTE_IFACE=$EP_REMOTE_IFACE
		echo "Setup verified (pinned interfaces)"
		return 0
	fi

	# Candidate device external interface(s). No pre-app ping is used: the EP
	# device external port only gains carrier once dao-rdma_graph drives it, so
	# the interface pair is validated app-first below.
	if [[ -n "${EP_DEVICE_EXT_IFACE:-}" ]]; then
		dev_candidates="$EP_DEVICE_EXT_IFACE"
	else
		# Enumerate all RVU PF (a063) ports and drop only the one whose netdev
		# actually carries the SSH IP. Done on the orchestrator with primitive
		# ops so it does not depend on syncing a device-side helper, and so all
		# data ports (not just one) become candidates for the app-first ping.
		local _all_ports _p
		_all_ports=$(ep_device_op pcie_addr_get "${PCI_DEVID_CNXK_RVU_PF:-0xa063}" all)
		dev_candidates=""
		for _p in $_all_ports; do
			if [[ -n "$ssh_ip" ]] && \
			   ep_device_ssh_cmd "nd=\$(ls /sys/bus/pci/devices/$_p/net 2>/dev/null | head -n1); [ -n \"\$nd\" ] && ip -o -4 addr show dev \"\$nd\" 2>/dev/null | grep -qw $ssh_ip" >/dev/null 2>&1; then
				continue
			fi
			dev_candidates="$dev_candidates $_p"
		done
	fi

	# With no remote there is nothing to pair; pick the first device port.
	if [[ -z ${EP_REMOTE:-} ]]; then
		ext_iface=$(echo $dev_candidates | awk '{print $1}')
		echo "EP_REMOTE not set; skipping RDMA pair validation"
		add_test_env EP_DEVICE_EXT_IFACE=$ext_iface
		EP_DEVICE_EXT_IFACE=$ext_iface
		return 0
	fi

	# Candidate remote interface(s). Prefer a Mellanox (native RoCE) NIC, then
	# an explicit override, then any Octeon/eth netdev (legacy remote).
	remote_candidates=$(ep_remote_op mellanox_rdma_iface_get $remote_ssh_ip)
	if [[ -n "$remote_candidates" ]]; then
		echo "Remote Mellanox RDMA NIC detected: $remote_candidates"
	elif [[ -n "${EP_REMOTE_IFACE:-}" ]]; then
		remote_candidates="$EP_REMOTE_IFACE"
	else
		remote_candidates=$(ep_remote_op eth_interfaces_get $remote_ssh_ip)
	fi

	echo "Device eth interfaces: $dev_candidates"
	echo "Remote eth interfaces: $remote_candidates"

	# App-first pairing. For each device external port: start the graph app and
	# the host octep_rdma stack (insmod + RDMA VF), then find the remote port
	# that can ping the host through the RDMA data path (host VF <-> remote).
	for e in $dev_candidates; do
		echo "Trying device external interface $e"

		ep_device_op bind_driver pci $e vfio-pci
		rdma_launch_device_app $e

		# Wait until the device app's RDMA mailbox service is up before
		# creating the host VF. If the host octep_rdma VF probes while the app
		# is still initialising (e.g. stuck in "Checking link status"), its
		# "get device capabilities" mailbox request times out and ibdev
		# registration fails (-5), leaving no host RDMA netdev.
		local app_ready=
		local aw
		for aw in $(seq 1 40); do
			if ep_device_ssh_cmd "grep -q 'Entering service main loop' /tmp/dao_rdma_graph.log 2>/dev/null"; then
				app_ready=1
				break
			fi
			sleep 1
		done
		if [[ -n "$app_ready" ]]; then
			echo "Device RDMA app ready (mailbox service up)"
		else
			echo "WARNING: device RDMA app readiness marker not seen after 40s"
		fi
		sleep 2

		# Host: insmod octep_rdma + create RDMA VF, bring up host VF.
		ep_host_op rdma_setup 1
		sleep 1
		rdma_vfs=$(ep_host_op pcie_addr_get "0xB903" 1)

		# The host RDMA VF netdev can take a few seconds to appear after the
		# VF is created and octep_rdma syncs with the device app; poll for it.
		local host_if=
		local w
		for w in $(seq 1 15); do
			host_if=$(ep_host_op if_name_get $rdma_vfs 2>/dev/null)
			[[ -n "$host_if" ]] && break
			sleep 1
		done
		if [[ -z "$host_if" ]]; then
			echo "WARNING: host RDMA VF $rdma_vfs has no netdev yet"
		else
			echo "Host RDMA VF $rdma_vfs -> $host_if"
		fi

		ep_host_op if_configure --pcie-addr $rdma_vfs --ip $host_ip

		for re in $remote_candidates; do
			ep_remote_op bind_driver pci $re rvu_nicpf
			ep_remote_op if_configure --pcie-addr $re --ip $remote_ip

			# Give the link time to negotiate now that the device port is
			# driven by the app; the ping is the actual pair selector.
			ep_remote_op link_wait $re 15 >/dev/null

			echo "Checking $rdma_vfs (Host) <-> $re (Remote)"
			ping_status=$(ep_host_op ping $host_ip $remote_ip 5)
			if [[ "$ping_status" == "SUCCESS" ]]; then
				ext_iface=$e
				remote_iface=$re
				break
			fi

			ep_remote_op if_configure --pcie-addr $re --down
			ep_remote_op unbind_driver pci $re
		done

		# Tear down this attempt. The winning external port is left bound to
		# vfio-pci so the per-test setup can relaunch the app on it.
		ep_host_op if_configure --pcie-addr $rdma_vfs --down
		[[ -n "$remote_iface" ]] && \
			ep_remote_op if_configure --pcie-addr $remote_iface --down
		ep_host_op rdma_cleanup
		ep_device_op rdma_app_cleanup

		[[ -n "$ext_iface" ]] && break

		# This device port did not pair; return it to the kernel driver.
		ep_device_op bind_driver pci $e rvu_nicpf || true
	done

	if [[ -z $ext_iface ]] || [[ -z $remote_iface ]]; then
		echo "Failed to find a valid interface pair"
		exit 1
	fi

	echo "Device External Interface: $ext_iface"
	echo "Remote Interface: $remote_iface"

	# Persist the selected pair so the per-test rdma_setup_configure reuses it.
	add_test_env EP_DEVICE_EXT_IFACE=$ext_iface
	add_test_env EP_REMOTE_IFACE=$remote_iface
	EP_DEVICE_EXT_IFACE=$ext_iface
	EP_REMOTE_IFACE=$remote_iface

	echo "Setup verified"
}

function dao_rdma_setup()
{
	local remote_arch
	local remote_rdma_src

	# Delete the existing rdma directory and copy the new one
	ep_host_ssh_cmd "$EP_HOST_SUDO rm -rf $EP_HOST_RDMA_PATH"
	ep_host_ssh_cmd "$EP_HOST_SUDO mkdir -p $EP_HOST_RDMA_PATH"
	ep_host_ssh_cmd "$EP_HOST_SUDO rsync -a $EP_DIR/rdma_prefix/* $EP_HOST_RDMA_PATH"

	# Stage the remote RDMA stack matching the remote's architecture. x86
	# remotes (e.g. Mellanox host) use the prebuilt x86 bundle, others use
	# the default (aarch64) bundle. The existence check must run ON THE REMOTE
	# because that is where the rsync source path lives (populated by
	# remote_sync into $EP_DIR/ep_files); checking it locally in the container
	# is wrong and silently falls back to the default bundle.
	remote_arch=$(ep_remote_ssh_cmd "uname -m" 2>/dev/null | tr -d '[:space:]')
	if [[ "$remote_arch" == "x86_64" ]] && \
	   ep_remote_ssh_cmd "[ -d $EP_DIR/ep_files/rdma_remote/x86 ]"; then
		remote_rdma_src="$EP_DIR/ep_files/rdma_remote/x86"
	else
		remote_rdma_src="$EP_DIR/ep_files/rdma_remote"
	fi
	echo "Staging remote RDMA stack ($remote_arch) from $remote_rdma_src to $EP_REMOTE_RDMA_PATH"

	ep_remote_ssh_cmd "$EP_REMOTE_SUDO rm -rf $EP_REMOTE_RDMA_PATH"
	ep_remote_ssh_cmd "$EP_REMOTE_SUDO mkdir -p $EP_REMOTE_RDMA_PATH"
	ep_remote_ssh_cmd "$EP_REMOTE_SUDO rsync -a $remote_rdma_src/* $EP_REMOTE_RDMA_PATH"

	if [[ -n $SKIP_SETUP ]]; then
		echo "Skip EP device setup"
		return
	fi

	echo "Setting up EP device for rdma tests"
	ep_device_op dpi_setup

	ep_device_op hugepage_setup 524288 24 24

	ep_device_op pem_setup

	echo "Verifying rdma setup"
	verify_rdma_setup
}
