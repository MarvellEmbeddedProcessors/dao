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

	# Host octep teardown: EP_HOST always; EP_REMOTE_HOST only if in the bench.
	ep_host_op rdma_cleanup
	[[ -n "${EP_REMOTE_HOST:-}" ]] && ep_remote_host_op rdma_cleanup

	# Stop dao-rdma_graph: EP_DEVICE always; EP_REMOTE only if set (Octeon<->Octeon).
	ep_device_op rdma_app_cleanup
	[[ -n "${EP_REMOTE:-}" ]] && ep_remote_op rdma_app_cleanup

	# Kill leftover $EP_DIR processes: EP_HOST/EP_DEVICE always; EP_REMOTE only if set.
	ep_host_op safe_kill $EP_DIR
	ep_device_op safe_kill $EP_DIR
	[[ -n "${EP_REMOTE:-}" ]] && ep_remote_op safe_kill $EP_DIR

	# Capture dmesg from EP_HOST and EP_DEVICE.
	ep_host_ssh_cmd "$EP_HOST_SUDO dmesg" > host_dmesg.log
	save_log host_dmesg.log
	ep_device_ssh_cmd "$EP_DEVICE_SUDO dmesg" > device_dmesg.log
	save_log device_dmesg.log

	echo "DAO RDMA cleanup completed"
}

# Launch dao-rdma_graph on the given Octeon external port (plus DPI VFs).
function rdma_launch_device_app()
{
	local ext_iface=$1
	local role=${2:-device}
	local op_fn ssh_fn sudo_var
	local num_mbufs=131072
	local max_pkt_len=9600
	local dma_nb_desc=32768
	local pci_devs="$ext_iface"
	local serialized_args app_cmd ld_library_path rdma_utils
	local dpi
	local dpi_vfs=()
	local tmp=()
	local args=()

	# Select the near (EP_DEVICE) or remote (EP_REMOTE) Octeon role.
	if [[ "$role" == "remote" ]]; then
		op_fn=ep_remote_op
		ssh_fn=ep_remote_ssh_cmd
		sudo_var=$EP_REMOTE_SUDO
	else
		op_fn=ep_device_op
		ssh_fn=ep_device_ssh_cmd
		sudo_var=$EP_DEVICE_SUDO
	fi

	# Add DPI VFs
	read -r -a dpi_vfs <<< "$($op_fn pcie_addr_get $PCI_DEVID_CN10K_RVU_DPI_VF 16)"
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

	$ssh_fn "$sudo_var -E bash -lc $(printf %q "$app_cmd")"
}

# Wait up to 40s for a DPU app's RDMA mailbox service. $1=ssh function.
function rdma_wait_app_ready()
{
	local ssh_fn=$1
	local aw

	for aw in $(seq 1 40); do
		if $ssh_fn "grep -q 'Entering service main loop' /tmp/dao_rdma_graph.log 2>/dev/null"; then
			echo "Device RDMA app ready (mailbox service up)"
			return 0
		fi
		sleep 1
	done
	echo "WARNING: device RDMA app readiness marker not seen after 40s"
}

# Find the EP_DEVICE <-> EP_REMOTE_HOST Mellanox port pair via a plain kernel-NIC ping.
function populate_ep_mlx_interfaces()
{
	local device_ip=21.0.0.52
	local mlx_ip=21.0.0.51
	local device_ssh_ip remote_host_ssh_ip
	local device_ifaces mlx_ifaces
	local e re paired_device_iface= paired_mlx_iface=

	if [[ -z "${EP_REMOTE_HOST:-}" ]]; then
		echo "EP_REMOTE_HOST not set; no Mellanox remote host to discover"
		return 0
	fi

	device_ssh_ip=$(echo $EP_DEVICE | awk -F '@' '{print $2}' 2>/dev/null)
	remote_host_ssh_ip=$(echo $EP_REMOTE_HOST | awk -F '@' '{print $2}' 2>/dev/null)

	# EP_DEVICE external ports, skipping the one already paired with the remote Octeon.
	device_ifaces=""
	for e in $(ep_device_op eth_interfaces_get $device_ssh_ip); do
		[[ "$e" == "${EP_DEVICE_EXT_IFACE:-}" ]] && continue
		device_ifaces="$device_ifaces $e"
	done

	# Mellanox NIC(s) on EP_REMOTE_HOST (IB vendor 0x15b3), already up under mlx5.
	mlx_ifaces=$(ep_remote_host_op mellanox_rdma_iface_get $remote_host_ssh_ip)

	echo "Discovering EP_DEVICE <-> EP_REMOTE_HOST (MLX) pair (plain kernel NIC)"
	echo "  EP_DEVICE candidate ports: $device_ifaces"
	echo "  EP_REMOTE_HOST MLX ports : $mlx_ifaces"

	if [[ -z "$mlx_ifaces" ]]; then
		echo "No Mellanox (vendor 0x15b3) NIC found on EP_REMOTE_HOST"
		return 1
	fi

	for e in $device_ifaces; do
		# Bring the device external port up as a plain kernel NIC.
		ep_device_op bind_driver pci $e rvu_nicpf
		ep_device_op if_configure --pcie-addr $e --ip $device_ip

		for re in $mlx_ifaces; do
			# mlx5 already owns the NIC; just (re)assign the data-plane IP.
			ep_remote_host_op if_configure --pcie-addr $re --down
			ep_remote_host_op if_configure --pcie-addr $re --ip $mlx_ip
			ep_remote_host_op link_wait $re 15 >/dev/null

			echo "Checking $e (EP_DEVICE) <-> $re (EP_REMOTE_HOST MLX)"
			if [[ "$(ep_device_op ping $device_ip $mlx_ip 5)" == "SUCCESS" ]]; then
				paired_device_iface=$e
				paired_mlx_iface=$re
				break
			fi
			ep_remote_host_op if_configure --pcie-addr $re --down
		done

		[[ -n "$paired_device_iface" ]] && break

		# This device port did not pair; return it to a clean state.
		ep_device_op if_configure --pcie-addr $e --down
		ep_device_op unbind_driver pci $e
	done

	# Bring the discovered pair's verification IPs back down.
	[[ -n "$paired_mlx_iface" ]] && ep_remote_host_op if_configure --pcie-addr $paired_mlx_iface --down
	[[ -n "$paired_device_iface" ]] && ep_device_op if_configure --pcie-addr $paired_device_iface --down

	if [[ -z "$paired_device_iface" ]]; then
		echo "No EP_DEVICE <-> MLX plain-NIC link came up (L1 not trained on any port)"
		return 1
	fi

	add_test_env EP_DEVICE_MLX_IFACE=$paired_device_iface
	add_test_env EP_REMOTE_HOST_MLX_IFACE=$paired_mlx_iface
	EP_DEVICE_MLX_IFACE=$paired_device_iface
	EP_REMOTE_HOST_MLX_IFACE=$paired_mlx_iface

	echo "EP_DEVICE <-> MLX pair: $paired_device_iface <-> $paired_mlx_iface"
}

# Validate the Octeon<->Mellanox octep RDMA path (uses the pair from populate_ep_mlx_interfaces).
function verify_rdma_mlx_datapath()
{
	local host_ip="21.0.0.3"
	local mlx_ip="21.0.0.11"
	local rdma_vfs host_if w ping_status

	echo "Validating EP_HOST <-> EP_REMOTE_HOST (Octeon<->Mellanox) RDMA data path"
	echo "  Near $EP_DEVICE_MLX_IFACE (EP_DEVICE) <-> Far $EP_REMOTE_HOST_MLX_IFACE (EP_REMOTE_HOST MLX)"

	# Run dao-rdma_graph on the EP_DEVICE MLX-facing port.
	ep_device_op if_configure --pcie-addr $EP_DEVICE_MLX_IFACE --down
	ep_device_op bind_driver pci $EP_DEVICE_MLX_IFACE vfio-pci
	rdma_launch_device_app $EP_DEVICE_MLX_IFACE device
	rdma_wait_app_ready ep_device_ssh_cmd

	# Bring up the EP_HOST octep RDMA VF and assign its IP.
	ep_host_op rdma_setup 1
	sleep 1
	rdma_vfs=$(ep_host_op pcie_addr_get "0xB903" 1)
	for w in $(seq 1 15); do
		host_if=$(ep_host_op if_name_get $rdma_vfs 2>/dev/null)
		[[ -n "$host_if" ]] && break
		sleep 1
	done
	ep_host_op if_configure --pcie-addr $rdma_vfs --ip $host_ip

	# Assign the data-plane IP to the Mellanox NIC (mlx5 already owns it).
	ep_remote_host_op if_configure --pcie-addr $EP_REMOTE_HOST_MLX_IFACE --down
	ep_remote_host_op if_configure --pcie-addr $EP_REMOTE_HOST_MLX_IFACE --ip $mlx_ip
	ep_remote_host_op link_wait $EP_REMOTE_HOST_MLX_IFACE 15 >/dev/null

	echo "Checking $rdma_vfs (Host) <-> $EP_REMOTE_HOST_MLX_IFACE (Remote host MLX)"
	ping_status=$(ep_host_op ping $host_ip $mlx_ip 5)

	# Tear down the host octep stack, then the DPU app.
	ep_host_op if_configure --pcie-addr $rdma_vfs --down
	ep_remote_host_op if_configure --pcie-addr $EP_REMOTE_HOST_MLX_IFACE --down
	ep_host_op rdma_cleanup
	ep_device_op rdma_app_cleanup

	# Return the MLX-facing port to the kernel driver.
	ep_device_op bind_driver pci $EP_DEVICE_MLX_IFACE rvu_nicpf || true

	if [[ "$ping_status" != "SUCCESS" ]]; then
		echo "Cannot ping EP_REMOTE_HOST MLX from EP_HOST over the octep<->MLX RDMA path"
		exit 1
	fi
	echo "EP_HOST <-> EP_REMOTE_HOST (Octeon<->Mellanox) RDMA data path verified"
}

# Validate the Octeon<->Octeon octep RDMA path.
function verify_rdma_octeon_datapath()
{
	# Per-test RDMA data-plane verification subnet.
	local host_ip="30.0.0.3"
	local remote_ip="30.0.0.11"
	local rdma_vfs rhost_rdma_vfs host_if rhost_if w ping_status

	echo "Validating EP_HOST <-> EP_REMOTE_HOST (Octeon<->Octeon) RDMA data path"
	echo "  Near $EP_DEVICE_EXT_IFACE (EP_DEVICE) <-> Far $EP_REMOTE_IFACE (EP_REMOTE)"

	# Run dao-rdma_graph on both Octeons (links up before host octep connects).
	ep_device_op if_configure --pcie-addr $EP_DEVICE_EXT_IFACE --down
	ep_device_op bind_driver pci $EP_DEVICE_EXT_IFACE vfio-pci
	rdma_launch_device_app $EP_DEVICE_EXT_IFACE device
	rdma_wait_app_ready ep_device_ssh_cmd

	ep_remote_op if_configure --pcie-addr $EP_REMOTE_IFACE --down
	ep_remote_op bind_driver pci $EP_REMOTE_IFACE vfio-pci
	rdma_launch_device_app $EP_REMOTE_IFACE remote
	rdma_wait_app_ready ep_remote_ssh_cmd

	# Bring up both host octep RDMA VFs.
	ep_host_op rdma_setup 1
	ep_remote_host_op rdma_setup 1
	sleep 1
	rdma_vfs=$(ep_host_op pcie_addr_get "0xB903" 1)
	rhost_rdma_vfs=$(ep_remote_host_op pcie_addr_get "0xB903" 1)

	ep_host_op if_configure --pcie-addr $rdma_vfs --ip $host_ip
	ep_remote_host_op if_configure --pcie-addr $rhost_rdma_vfs --ip $remote_ip

	echo "Checking $rdma_vfs (Host) <-> $rhost_rdma_vfs (Remote host)"
	ping_status=$(ep_host_op ping $host_ip $remote_ip 5)

	# Tear down host octep stacks, then the DPU apps.
	ep_host_op if_configure --pcie-addr $rdma_vfs --down
	ep_remote_host_op if_configure --pcie-addr $rhost_rdma_vfs --down
	ep_host_op rdma_cleanup
	ep_remote_host_op rdma_cleanup
	ep_device_op rdma_app_cleanup
	ep_remote_op rdma_app_cleanup

	# Return external ports to the kernel driver for a clean MLX check.
	ep_device_op bind_driver pci $EP_DEVICE_EXT_IFACE rvu_nicpf || true
	ep_remote_op bind_driver pci $EP_REMOTE_IFACE rvu_nicpf || true

	if [[ "$ping_status" != "SUCCESS" ]]; then
		echo "Cannot ping EP_REMOTE_HOST from EP_HOST over the octep<->octep RDMA path"
		exit 1
	fi
	echo "EP_HOST <-> EP_REMOTE_HOST (Octeon<->Octeon) RDMA data path verified"
}

function verify_rdma_setup()
{
	# Verify whichever scenario(s) the bench supports; require at least one.
	local did_verify=0

	# EP_DEVICE <-> EP_REMOTE (Octeon <-> Octeon) - needs EP_REMOTE.
	if [[ -n "${EP_REMOTE:-}" ]]; then
		populate_ep_interfaces
		if [[ -z "${EP_DEVICE_EXT_IFACE:-}" ]] || [[ -z "${EP_REMOTE_IFACE:-}" ]]; then
			echo "Failed to find EP_DEVICE <-> EP_REMOTE (Octeon<->Octeon) pair"
			exit 1
		fi
		verify_rdma_octeon_datapath
		did_verify=1
	else
		echo "EP_REMOTE not set - skipping Octeon<->Octeon verification"
	fi

	# O<->MLX: needs EP_REMOTE_HOST + a Mellanox; populate_ep_mlx_interfaces probes non-fatally (skips if none).
	if [[ -n "${EP_REMOTE_HOST:-}" ]] && populate_ep_mlx_interfaces \
	   && [[ -n "${EP_DEVICE_MLX_IFACE:-}" ]] \
	   && ep_remote_host_op is_mellanox "$EP_REMOTE_HOST_MLX_IFACE"; then
		verify_rdma_mlx_datapath
		did_verify=1
	else
		echo "No Mellanox NIC discovered on EP_REMOTE_HOST - skipping Octeon<->MLX verification"
	fi

	if [[ $did_verify -eq 0 ]]; then
		echo "No RDMA scenario available (need EP_REMOTE and/or a Mellanox on EP_REMOTE_HOST)"
		exit 1
	fi

	# Announce which whole test families will RUN vs be SKIPPED on this bench.
	echo "*****************************************************************"
	echo "***  RDMA TEST SCENARIOS ON THIS BENCH:"
	if [[ -n "${EP_REMOTE:-}" ]]; then
		echo "***    Octeon <-> Octeon    :  WILL RUN  (EP_REMOTE set)"
	else
		echo "***    Octeon <-> Octeon    :  SKIPPED   (EP_REMOTE not set)"
	fi
	if [[ -n "${EP_DEVICE_MLX_IFACE:-}" ]]; then
		echo "***    Octeon <-> Mellanox  :  WILL RUN  (Mellanox discovered)"
	else
		echo "***    Octeon <-> Mellanox  :  SKIPPED   (no Mellanox on EP_REMOTE_HOST)"
	fi
	echo "*****************************************************************"

	echo "Setup verified"
	return 0
}

function dao_rdma_setup()
{
	# Delete the existing rdma directory and copy the new one
	echo "Staging host RDMA stack from $EP_DIR/rdma_prefix to $EP_HOST_RDMA_PATH (EP_HOST)"
	ep_host_ssh_cmd "$EP_HOST_SUDO rm -rf $EP_HOST_RDMA_PATH"
	ep_host_ssh_cmd "$EP_HOST_SUDO mkdir -p $EP_HOST_RDMA_PATH"
	ep_host_ssh_cmd "$EP_HOST_SUDO rsync -a $EP_DIR/rdma_prefix/* $EP_HOST_RDMA_PATH"

	if [[ -n "${EP_REMOTE_HOST:-}" ]]; then
		echo "Staging remote host RDMA stack from $EP_DIR/rdma_prefix to $EP_REMOTE_RDMA_PATH (EP_REMOTE_HOST)"
		ep_remote_host_ssh_cmd "$EP_REMOTE_HOST_SUDO rm -rf $EP_REMOTE_RDMA_PATH"
		ep_remote_host_ssh_cmd "$EP_REMOTE_HOST_SUDO mkdir -p $EP_REMOTE_RDMA_PATH"
		ep_remote_host_ssh_cmd "$EP_REMOTE_HOST_SUDO rsync -a $EP_DIR/rdma_prefix/* $EP_REMOTE_RDMA_PATH"
	else
		echo "EP_REMOTE_HOST not set - skipping remote host RDMA stack staging"
	fi

	if [[ -n $SKIP_SETUP ]]; then
		echo "Skip EP device setup"
		return
	fi

	echo "Setting up EP device for rdma tests"
	ep_device_op dpi_setup

	ep_device_op hugepage_setup 524288 72 72

	ep_device_op pem_setup

	if [[ -n "${EP_REMOTE:-}" ]]; then
		echo "Setting up EP_REMOTE (far Octeon) for rdma tests"
		ep_remote_op dpi_setup
		ep_remote_op hugepage_setup 524288 24 24
		ep_remote_op pem_setup
	else
		echo "EP_REMOTE not set - skipping far Octeon setup (Octeon<->Octeon disabled)"
	fi

	echo "Verifying rdma setup"
	verify_rdma_setup
}
