#!/bin/bash
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2024 Marvell.

set -euo pipefail

L2FWD_1C_SCRIPT_PATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
source $L2FWD_1C_SCRIPT_PATH/virtio_l2fwd_utils.sh

# List-format "offload-name <csum> <mseg> <in_order>
virtio_offloads=(
		[0]="None 0 0 1" #None No-Offload
		[1]="mseg 0 1 1" #MSEG_F
		[2]="cksum 1 0 1" #CSUM_F
		[3]="mseg_cksum 1 1 1" #MSEG_F | CSUM_F
		[4]="noinorder 0 0 0" #D_NOORDER_F
		[5]="noinorder_mseg 0 1 0" #D_NOORDER_F | MSEG_F
		[6]="noinorder_cksum 1 0 0" #D_NOORDER_F | CSUM_F
		[7]="noinorder_mseg_cksum 1 1 0" #D_NOORDER_F | MSEG_F | CSUM_F
		)

function virtio_l2fwd_1c()
{
	local l2fwd_pfx=${DAO_TEST}
	local host_testpmd_pfx=${DAO_TEST}_testpmd_host
	local l2fwd_out=virtio_l2fwd.${l2fwd_pfx}.out
	local if0=$(ep_device_get_inactive_if)

	l2fwd_register_sig_handler ${DAO_TEST} $host_testpmd_pfx $l2fwd_out

	ep_common_bind_driver pci $if0 vfio-pci

	# Launch virtio l2fwd
	if ! l2fwd_app_launch $if0 $l2fwd_pfx $l2fwd_out "4-7" "-p 0x1 -v 0x1 -P -l"; then
		echo "Failed to launch virtio l2fwd"

		# Quit l2fwd app
		l2fwd_app_quit $l2fwd_pfx $l2fwd_out
		return 1
	fi

	ep_host_op vdpa_setup $(ep_device_get_part)
	# Start traffic
	l2fwd_host_start_traffic $host_testpmd_pfx

	# Check the performance
	l2fwd_host_check_pps $host_testpmd_pfx
	local k=$?

	# Stop Traffic and quit host testpmd
	l2fwd_host_stop_traffic $host_testpmd_pfx

	ep_host_op vdpa_cleanup
	# Quit l2fwd app
	l2fwd_app_quit $l2fwd_pfx $l2fwd_out
	return $k
}

failed_tests=""
function virtio_l2fwd_offload_run()
{
	local pfx=$1
	local l2fwd_out=$2
	local ff=$3
	local tx_spcap=$4
	local tx_mpcap=$5
	local cmp_script=$EP_DIR/ci/test/dao-test/common/scapy/validate_pcap.py
	local rpcap=/tmp/rx_multiseg.pcap
	local tpcap
	local itr=0
	local max_offloads=${#virtio_offloads[@]}
	((--max_offloads))

	while [ $itr -le $max_offloads ]
	do

		local list=(${virtio_offloads[$itr]})
		echo -e "######################## ITERATION $itr" \
			"(virtio_offload = "$ff"_${list[0]})########################\n"

		if [[ ${list[2]} -eq 1 ]]; then
			tpcap=$tx_mpcap
		else
			tpcap=$tx_spcap
		fi

		# Start traffic
		l2fwd_host_launch_testpmd_with_pcap $pfx $tpcap $rpcap ${list[1]} ${list[2]} \
							${list[3]}

		# Wait for host to connect before traffic start
		l2fwd_host_connect_wait $l2fwd_out
		l2fwd_host_start_traffic_with_pcap $pfx

		# Stop Traffic
		l2fwd_host_stop_traffic $pfx

		# validate packets
		l2fwd_host_validate_traffic $cmp_script $tpcap $rpcap
		local k=$?
		if [[ "$k" != "0" ]]; then
			failed_tests="$failed_tests \""$ff"_${list[0]}\""
		fi
		((++itr))
	done
	return 0
}

function virtio_l2fwd_multiseg()
{
	local l2fwd_pfx=${DAO_TEST}
	local host_testpmd_pfx=${DAO_TEST}_testpmd_host
	local l2fwd_out=virtio_l2fwd.${l2fwd_pfx}.out
	local tx_mpcap=$EP_DIR/ci/test/dao-test/virtio/l2fwd/pcap/tx_mseg.pcap
	local tx_spcap=$EP_DIR/ci/test/dao-test/virtio/l2fwd/pcap/tx.pcap
	local if0=$(ep_device_get_inactive_if)
	local k=0

	failed_tests=""
	l2fwd_register_sig_handler ${DAO_TEST} $host_testpmd_pfx $l2fwd_out

	ep_common_bind_driver pci $if0 vfio-pci

	# Launch virtio l2fwd
	if ! l2fwd_app_launch $if0 $l2fwd_pfx $l2fwd_out "4-7" "-p 0x1 -v 0x1 -P -l --max-pkt-len=9200 --enable-l4-csum"; then
		echo "Failed to launch virtio l2fwd"

		# Quit l2fwd app
		l2fwd_app_quit $l2fwd_pfx $l2fwd_out
		return 1
	fi

	ep_host_op vdpa_setup $(ep_device_get_part)

	virtio_l2fwd_offload_run $host_testpmd_pfx $l2fwd_out "" $tx_spcap $tx_mpcap

	ep_host_op vdpa_cleanup
	# Quit l2fwd app
	l2fwd_app_quit $l2fwd_pfx $l2fwd_out

	sleep 1

	# No fastfree cases
	# Launch virtio l2fwd with no fast free option
	if ! l2fwd_app_launch $if0 $l2fwd_pfx $l2fwd_out "4-7" "-p 0x1 -v 0x1 -P -l --max-pkt-len=9200 --enable-l4-csum -f"; then
		echo "Failed to launch virtio l2fwd with No fastfree"
	else
		ep_host_op vdpa_setup $(ep_device_get_part)
		virtio_l2fwd_offload_run $host_testpmd_pfx $l2fwd_out "no_ff" $tx_spcap $tx_mpcap
		ep_host_op vdpa_cleanup
	fi

	# Quit l2fwd app
	l2fwd_app_quit $l2fwd_pfx $l2fwd_out

	echo ""
	if [[ -n $failed_tests ]]; then
		echo "FAILURE: Test(s) [$failed_tests] failed"
		k=1
	fi

	return $k
}

function virtio_l2fwd_guest_1c()
{
	local l2fwd_pfx=${DAO_TEST}
	local host_pfx=${DAO_TEST}_guest
	local l2fwd_out=virtio_l2fwd.${l2fwd_pfx}.out
	local if0=$(ep_device_get_inactive_if)
	local args

	l2fwd_register_sig_handler ${DAO_TEST} $host_pfx $l2fwd_out

	ep_common_bind_driver pci $if0 vfio-pci

	# Launch virtio l2fwd
	if ! l2fwd_app_launch $if0 $l2fwd_pfx $l2fwd_out "4-7" "-p 0x1 -v 0x1 -P -l"; then
		echo "Failed to launch virtio l2fwd"
		# Quit l2fwd app
		l2fwd_app_quit $l2fwd_pfx $l2fwd_out
		return 1
	fi

	ep_host_op vdpa_setup $(ep_device_get_part)
	ep_host_op_bg 220 launch_guest $host_pfx
	local k=$?
	if [[ "$k" != "0" ]]; then
		echo "Failed to launch Guest"
		# Quit l2fwd app
		l2fwd_app_quit $l2fwd_pfx $l2fwd_out
		ep_host_op vdpa_cleanup
		return 1
	fi

	args="-c 0xff -a 0000:00:03.0 -- --nb-cores=4 --port-topology=loop --rxq=4 --txq=4 -i"
	# Start traffic
	ep_host_op start_guest_traffic $host_pfx $args

	# Check the performance
	ep_host_op guest_testpmd_pps $host_pfx
	local k=$?

	# Stop Traffic
	ep_host_op stop_guest_traffic $host_pfx

	ep_host_op shutdown_guest $host_pfx
	ep_host_op vdpa_cleanup
	# Quit l2fwd app
	l2fwd_app_quit $l2fwd_pfx $l2fwd_out

	return $k
}

function virtio_l2fwd_host_net_1c_run()
{
	local l2fwd_pfx=${DAO_TEST}
	local host_netdev_pfx=${DAO_TEST}_host_netdev
	local l2fwd_out=virtio_l2fwd.${l2fwd_pfx}.out
	local npa_pf=$(ep_device_get_unused_npa_pf)
	local ep_device_dtap_addr=20.20.20.2
	local ep_host_ip_addr=20.20.20.1
	#TODO:
	#Some PMDs need to allocate buffers that as large as the packet size
	#to receive jumbo packets. Therefore, verify up to 1500, which falls
	#with in the range of the default mbuf data
	pkt_sizes=(64 1000 1500)
	local app_args
	local cidr=24
	local ping_out
	local count=60
	local k=0

	if [ -z "${1:-}" ]; then
		ff_enable=""
	else
		ff_enable=$1
	fi

	l2fwd_register_sig_handler ${DAO_TEST} $host_netdev_pfx $l2fwd_out

	ep_common_bind_driver pci $npa_pf vfio-pci

	# Launch virtio l2fwd without cgx loopback
	app_args="-p 0x1 -v 0x1 -P $ff_enable"
	if ! l2fwd_app_launch_with_tap_dev $npa_pf $l2fwd_pfx $l2fwd_out "4-7" "$app_args"; then
		echo "Failed to launch virtio l2fwd"

		# Quit l2fwd app
		l2fwd_app_quit $l2fwd_pfx $l2fwd_out

		# Unbind NPA device
		ep_common_unbind_driver pci $npa_pf vfio-pci

		return 1
	fi

	echo "Configuring TAP interface on EP device"
	#By default, Linux interfaces are named dtapX
	ep_device_configure_tap_iface dtap0 $ep_device_dtap_addr/$cidr

	ep_host_op virtio_vdpa_setup $(ep_device_get_part) $ep_host_ip_addr/$cidr

	echo "Verifying ping"
	for pkt_size in "${pkt_sizes[@]}"
	do
		ping_out=$(ping -c $count -s $pkt_size -i 0.2 \
				-I $ep_device_dtap_addr $ep_host_ip_addr || true)
		if [[ -n $(echo $ping_out | grep ", 0% packet loss,") ]]; then
			echo "$pkt_size packet size ping test SUCCESS"
		else
			echo "$pkt_size packet size ping FAILED"
			echo "stopping test execution"
			k=1
			break
		fi
		sleep 1
	done

	echo "virtio_vdpa_cleanup"
	ep_host_op virtio_vdpa_cleanup

	# Quit l2fwd app
	l2fwd_app_quit $l2fwd_pfx $l2fwd_out

	#Unbind NPA device
	ep_common_unbind_driver pci $npa_pf vfio-pci

	return $k
}

function virtio_l2fwd_host_net_1c()
{
        local k

        virtio_l2fwd_host_net_1c_run
        k=$?
        if [[ "$k" != "0" ]]; then
                echo ${DAO_TEST}" FF Test FAILED"
                return $k
        fi

        virtio_l2fwd_host_net_1c_run -f
        k=$?
        if [[ "$k" != "0" ]]; then
                echo ${DAO_TEST}" NO_FF Test FAILED "
                return $k
        fi

        echo ${DAO_TEST}" Test PASSED"
}

test_run ${DAO_TEST} 2
