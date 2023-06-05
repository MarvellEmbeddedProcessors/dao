..  SPDX-License-Identifier: Marvell-MIT
    Copyright (c) 2024 Marvell.

************
VirtIO-l2fwd
************

The ``dpdk-virtio-l2fwd`` EP application is a Dataplane development kit(DPDK) application that
allows to exercise virtio usecase of forwarding traffic between VirtIO net device and
DPDK ethdev device. VirtIO net device is emulated using ``virtio-net`` DAO library.
Application maps a ``virtio-net` device to a ``rte-ethdev`` device 1:1.

The application is dependent on below libraries for its functionality.
* ``rte_dma`` library to use DPI HW and transfer data between Host and Octeon memory.
* ``rte_ethdev`` library to receive and send traffic to RPM interfaces
* ``dao_dma`` library as a wrapper to ``rte_dma`` library for request management.
* ``dao_virtio_netdev`` library to enqueue / dequeue packets to / from host.

Application created lcores are below:

* One lcore as service lcore to do ``dao_virtio_netdev_desc_manage()`` API call per virtio dev.
* One or more lcores as worker cores to do ``rte_eth_rx_burst()`` on ethdev's and enqueue packets
  to Host using ``dao_virtio_net_enqueue_burst()``
* One or more lcores as worker cores to do ``dao_virtio_net_dequeue_burst()`` on virtio-net devices
  and enqueue packets to Host using ``rte_eth_tx_burst()``

Apart from application created lcore's, virtio library creates a control lcore for management
purposes.

Setting up EP environment
-------------------------

Setup SDP PF/VF count in EBF menu
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Number of virtio devices is equal to number of SDP VF's enabled. So make sure that config is setup
correctly in EBF menu.

Setup huge pages for DPDK application
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Setup enough hugepages and a mount point for the same in order for the dpdk-virtio-l2fwd application
to run.

Bind required DMA devices to vfio-pci
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
``virtio-l2fwd`` application needs two DMA devices per lcore one for DEV2MEM and another for
MEM2DEV and two more for control lcore. Control lcore is created by virtio library to
handle control commands. Below is sample code to bind DMA VF's to vfio-pci.

.. code-block:: bash

   DPI_PF=`lspci -d :a080 | awk -e '{print $1}'`

   # Enhance DPI engine FIFO size and MRRS
   echo 0x10101010 > /sys/bus/pci/drivers/octeontx2-dpi/module/parameters/eng_fifo_buf
   echo 512 > /sys/bus/pci/drivers/octeontx2-dpi/module/parameters/mrrs
   echo 256 > /sys/bus/pci/drivers/octeontx2-dpi/module/parameters/mps

   echo $DPI_PF > /sys/bus/pci/devices/$DPI_PF/driver/unbind
   echo octeontx2-dpi > /sys/bus/pci/devices/$DPI_PF/driver_override
   echo $DPI_PF > /sys/bus/pci/drivers_probe

   echo 32 >/sys/bus/pci/devices/$DPI_PF/sriov_numvfs
   DPI_VF=`lspci -d :a081 | awk -e '{print $1}' | head -22`
   dpdk-devbind.py -b vfio-pci $DPI_VF

Bind required RPM VF's to vfio-pci
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Application maps ``virtio-net`` device to ``rte-ethdev`` 1:1.

Sample code to map CN10K ethdev's to vfio-pci.

.. code-block:: bash

   ETH_PF=0002:02:00.0
   ETH_PF_NAME=enP2p2s0
   VF_CNT=1

   dpdk-devbind.py -b rvu_nicpf $ETH_PF
   echo $VF_CNT > /sys/bus/pci/devices/$ETH_PF/sriov_numvfs

   ETH_VF=`lspci -d :a064 | awk -e '{print $1}'`

   dpdk-devbind.py -u $ETH_VF
   dpdk-devbind.py -b vfio-pci $ETH_VF

Bind PEM BAR4 and DPI BAR0 platform devices to vfio-platform
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
VirtIO library uses ``pem0-bar4-mem`` and ``dpi_sdp_regs`` platform devices via ``vfio-platform``.
Hence enable ``vfio-platform`` in kernel build.

* Use ``vfio-platform.reset_required=0`` in kernel command line if ``vfio-platform`` is inbuilt
  kernel or pass ``reset_required=0`` as module parameter while doing loading ``vfio-platform``
  kernel module.

* Bind ``pem0-bar4-mem`` and ``dpi_sdp_regs`` to vfio-platform.

Sample code to bind platform devices to vfio-platform.

.. code-block:: bash

   # Platform device suffixes to search for
   pem_sfx="pem0-bar4-mem"
   sdp_sfx="dpi_sdp_regs"

   # Loop through devices
   for dev_path in /sys/bus/platform/devices/*; do
       if [[ -d "$dev_path" && "$dev_path" =~ $pem_sfx || "$dev_path" =~ $sdp_sfx ]]; then
           # Get device name from path
           dev_name=$(basename "$dev_path")

           # Bind the device to vfio-platform driver
           echo "vfio-platform" | tee "$dev_path/driver_override" > /dev/null
           echo "$dev_name" | tee "/sys/bus/platform/drivers/vfio-platform/bind" > /dev/null

           echo "Device $dev_name configured."
       fi
   done

Running the EP firmware application
-----------------------------------

The application as number of command line options:

.. code-block:: console

   dpdk-virtio-l2fwd [EAL Options] -- -p <PORTMASK_L[,PORTMASK_H]> -v <VIRTIOMASK_L[,VIRTIOMASK_H]> [other application options]

EAL Options
~~~~~~~~~~~

The following are the EAL command-line options that can be used in conjunction
with the ``dpdk-virtio-l2fwd`` application.
See the DPDK Getting Started Guides for more information on these options.

*   ``-c <COREMASK>`` or ``-l <CORELIST>``

        Set the hexadecimal bitmask of the cores to run on. The corelist is a
        list of cores to use.

Application Options
~~~~~~~~~~~~~~~~~~~

The following are the application command-line options:

* ``-p PORTMASK_L[,PORTMASK_H]``

        Hexadecimal bitmask of ``rte_ethdev`` ports to configure. Comma separated
        64 bit mask to support upto 128 eth devices. This is mandatory option.

* ``-v VIRTIOMASK_L[,VIRTIOMASK_H]``

        Hexadecimal bitmask of virtio-net devices to configure. Comma separated
        64 bit mask to support 128 virtio-net devices. This is a mandatory option.

* ``-P``

        Enable promisc mode. Default is promisc mode disabled.

* ``-d <n>``

        Set DMA flush threshold. Default value is 8. Value indicates max number of pointers
        to cache when requested through ``dao_dma_*()`` API, before doing DMA submit via
        ``rte_dma_*`` API.
* ``-f``

        Disable auto free. Auto free of mbufs by DPI post outbound DMA to Host memory is enabled
        by default. This option disables it for debug purposes.

* ``-s``

        Enable graph stats. Default value is disable. Giving this option multiple times dumps stats
        in verbose.

* ``-y <n>``

        Override PCI device info in DMA device vchan config. For debug purposes only.


* ``--eth-config (port,lcore_mask)[,(port,lcore_mask)]``

        Config to indicate on which lcores Rx polling would happen for a given ``rte_ethdev`` port.
        Default config is, all the configured ethdev ports would be polled for Rx on half of the
        lcore's that are detected and available excluding 1 service lcore.

* ``--virtio-config (dev,lcore_mask)[,(dev,lcore_mask)]``

        Config to indicate on which lcores deq polling would happen for a given ``virtio-net`` port.
        Default config is, all the configured virtio-net devices would be polled for pkts from host
        on half of the lcore's that are detected and available excluding 1 service lcore.

* ``l2fwd-map (eX,vY)[,eX,vY]``

        Config to map one ``rte-ethdev`` port to one ``virtio-net`` device 1:1.
        By default, ethdev 0 is mapped to virtio-netdev 0, ethdev 1 is mapped to virtio-netdev 1 and
        so on.

* ``--max-pkt-len <PKTLEN>``

        Set MTU on all the ethdev devices to <PKTLEN>. Default MTU configured is 1500B.

* ``--pool-buf-len``

        Set max pkt mbuf buffer len. Default is set to RTE_MBUF_DEFAULT_BUF_SIZE.

* ``--per-port-pool``

        Enable per port pool. When provided, enables creates one pktmbuf pool per
        ethdev/virtio-netdev port.
        Default is one pktmbuf pool for all ethdev's and one pktmbuf pool for all virtio-net
        devices.

* ``--disable-tx-mseg``

        Disable ethdev Tx multi-seg offload. When provided, disables Tx multi-seg offload
        configuration on ethdev port during initialization process.
        Default is Tx multi-seg offload enable on all ethdev devices.

* ``--pcap-enable``

        Enable packet capture feature in ``librte_graph``. Default is disabled.

* ``--pcap-num-cap <n>``

        Number of packets to capture via packet capture feature of ``librte_graph``.

* ``pcap-file-name <name>``

        Pcap file name to use.

Example EP firmware command
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Example to command to run ``dpdk-virtio-l2fwd`` on 1 ethdev and 1 virtio-net dev port
with 2 lcores on ethdev-rx, 2 lcores on ethdev-tx, 1 lcore for service core.


.. code-block:: console

   DPI_ALLOW='-a 0000:06:00.1 -a 0000:06:00.2 -a 0000:06:00.3 -a 0000:06:00.4 -a 0000:06:00.5 -a 0000:06:00.6 -a 0000:06:00.7 -a 0000:06:01.0 -a 0000:06:01.1 -a 0000:06:01.2 -a 0000:06:01.3 -a 0000:06:01.4 -a 0000:06:01.5 -a 0000:06:01.6 -a 0000:06:01.7 -a 0000:06:02.0 -a 0000:06:02.1 -a 0000:06:02.2 -a 0000:06:02.3 -a 0000:06:02.4 -a 0000:06:02.5 -a 0000:06:02.6'

   dpdk-virtio-l2fwd -l 2-7 -a 0002:02:00.1 $DPI_ALLOW -- -p 0x1 -v 0x1

If ``dpdk-virtio-l2fwd`` is not build with static linking to DPDK, we need to explicitly load
node library and PMD libraries for the application to function.

.. code-block:: console

   DPI_ALLOW='-a 0000:06:00.1 -a 0000:06:00.2 -a 0000:06:00.3 -a 0000:06:00.4 -a 0000:06:00.5 -a 0000:06:00.6 -a 0000:06:00.7 -a 0000:06:01.0 -a 0000:06:01.1 -a 0000:06:01.2 -a 0000:06:01.3 -a 0000:06:01.4 -a 0000:06:01.5 -a 0000:06:01.6 -a 0000:06:01.7 -a 0000:06:02.0 -a 0000:06:02.1 -a 0000:06:02.2 -a 0000:06:02.3 -a 0000:06:02.4 -a 0000:06:02.5 -a 0000:06:02.6'

   dpdk-virtio-l2fwd -d librte_node.so -d librte_net_cnxk.so -d librte_mempool_cnxk.so -d librte_dma_cnxk.so -d librte_mempool_ring.so -l 2-7 -a 0002:02:00.1 $DPI_ALLOW -- -p 0x1 -v 0x1

Setting up Host environment
---------------------------

:doc:`Steps to setup up host for VirtIO solutions <../howtoguides/virtio_host>`
