..  SPDX-License-Identifier: Marvell-MIT
    Copyright (c) 2025 Marvell.

*************
VirtIO-crypto
*************

The ``dao-virtio-crypto`` application is a sample application that shows how to use the
DAO ``virtio_crypto`` library. The application is designed to work with the VirtIO crypto
device, which is a virtualized crypto device that can be used to offload crypto operations
to a hardware crypto engine.
The application maps ``dao_virtio_cryptodev`` queues to ``rte_cryptodev`` queues.
Only ``crypto_cn10k`` PMD is allowed to be used with the this application, as crypto sessions
cannot be shared between different PMDs.

The application is dependent on below libraries for its functionality:

* DPDK ``dmadev`` library to use DPI HW and transfer data between Host and Octeon memory.
* DPDK ``cryptodev`` library to receive and send crypto operations to Octeon CPT engine.
* DAO ``virtio_crypto`` library to receive / send crypto operations from / to host.


Application creates lcores as below:

* One lcore as service core to do ``dao_virtio_cryptodev_desc_manage()`` API call per virtio dev.
* One or more lcores as worker cores to do ``dao_virtio_crypto_host_rx()`` on virtio device and
  enqueue crypto ops to crypto device using ``rte_cryptodev_enqueue_burst()``.
* One or more lcores as worker cores to do ``rte_cryptodev_dequeue_burst()`` on crypto device
  to dequeue crypto ops and send them to Host using ``dao_virtio_crypto_host_tx()``.


Setting up EP environment
-------------------------

Setup SDP PF/VF count in EBF menu
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Number of virtio devices is equal to number of SDP VF's enabled.
So, make sure that config is setup correctly in EBF menu.

:doc:`Steps to configure PCIe EP <../howtoguides/pcie_config>`

Setup huge pages for DPDK application
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Setup enough hugepages and a mount point for the same in order for the dao-virtio-crypto
application to run.

.. code-block:: bash

   echo 8 > /sys/kernel/mm/hugepages/hugepages-524288kB/nr_hugepages

Bind required DMA devices to vfio-pci
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
``dao-virtio-crypto`` application needs two DMA devices per lcore one for DEV2MEM and another for
MEM2DEV and two more for control lcore. Control lcore is created by virtio library to
handle control commands. Below is sample code to bind DMA VF's to vfio-pci.

.. code-block:: bash

   DPI_PF=`lspci -d :a080 | awk -e '{print $1}'`

   # Enhance DPI engine FIFO size and MRRS
   echo 0x10101010 > /sys/module/octeontx2_dpi/parameters/eng_fifo_buf
   echo 512 > /sys/module/octeontx2_dpi/parameters/mrrs
   echo 256 > /sys/module/octeontx2_dpi/parameters/mps

   echo $DPI_PF > /sys/bus/pci/devices/$DPI_PF/driver/unbind
   echo octeontx2-dpi > /sys/bus/pci/devices/$DPI_PF/driver_override
   echo $DPI_PF > /sys/bus/pci/drivers_probe

   echo 32 >/sys/bus/pci/devices/$DPI_PF/sriov_numvfs
   DPI_VF=`lspci -d :a081 | awk -e '{print $1}' | head -22`
   dpdk-devbind.py -b vfio-pci $DPI_VF

Bind required CPT VF's to vfio-pci
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Application maps ``dao_virtio_cryptodev`` device to ``rte_cryptodev``.

Sample code to map CN10K cryptodev's to vfio-pci.

.. code-block:: bash

   CPT_PF=0002:20:00.0
   VF_CNT=1

   dpdk-devbind.py -b rvu_cptpf $CPT_PF
   echo $VF_CNT > /sys/bus/pci/devices/$CPT_PF/sriov_numvfs

   CPT_VF=`lspci -d :a0f3 | awk -e '{print $1}'`

   dpdk-devbind.py -u $CPT_VF
   dpdk-devbind.py -b vfio-pci $CPT_VF

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

The application has number of command line options.

.. code-block:: console

   dao-virtio-crypto [EAL Options] -- [VC offload options]
   VC offload options:
     -h, --help
     -v, --virtio-mask=<VIRTO_MASK_L[,VIRTIO_MASK_H]> Hexadecimal bitmask of virtio devices
     -c, --crypto-mask=<CRYPTO_MASK_L[,CRYPTO_MASK_H]> Hexadecimal bitmask of crypto devices
     -C, --crypto-config=(dev,lcore_mask)[,(dev,lcore_mask)] : Crypto enq lcore mapping
     -n, --nb_cryptodev_desc=NB_DESC : Number of descriptors (in range 1024 to 16384)
     -q, --virtio-q-lcore-map=(lcore_id, vdev_id, vq_id)[, (lcore_id, vdev_id, vq_id1, vq_id2)] : Lcore and virtio-queue id map
     -b, --buffer-size=<BUFFER_SIZE> : Virtio mempool buffer size [64, 9216]

EAL Options
~~~~~~~~~~~

The following are the EAL command-line options that can be used in conjunction
with the ``dao-virtio-l2fwd`` application.
See the DPDK Getting Started Guides for more information on these options.

* ``-c <COREMASK>`` or ``-l <CORELIST>``

        Set the hexadecimal bitmask of the cores to run on. The corelist is a
        list of cores to use.

Application Options
~~~~~~~~~~~~~~~~~~~

The following are the application command-line options:

* ``-v VIRTIO_MASK_L[,VIRTIO_MASK_H]``

        Hexadecimal bitmask of virtio-crypto devices to configure. Comma separated
        64 bit mask to support 128 virtio-crypto devices. This is a mandatory option.

* ``-p CRYPTO_MASK_L[,CRYPTO_MASK_H]``

        Hexadecimal bitmask of ``rte_cryptodev`` devices to configure. Comma separated
        64 bit mask to support up to 128 crypto devices. This is mandatory option.

* ``--crypto-config (dev,lcore_mask)[,(dev,lcore_mask)]``

        Config to indicate on which lcores crypto enqueue would happen for a given
        ``rte_cryptodev`` device. By default all the configured cryptodev devices would be
        enqueued on all lcore's that are detected and available excluding 1 service lcore.

* ``--nb_cryptodev_desc <NB_DESC>``
        Number of descriptors to be used for each ``rte_cryptodev`` device. The number of
        descriptors should be in the range 1024 to 16384. Default is 8192.

* ``--virtio-q-lcore-map (lcore_id, vdev_id, vq_id)[, (lcore_id, vdev_id, vq_id1, vq_id2)]``
        Lcore and virtio-queue id map. This is used to configure the lcore id and virtio queue
        id mapping. The default is to use the first available lcore for each virtio queue.
        The lcore id and virtio queue id are separated by a comma. Multiple lcore and virtio
        queue id mapping can be specified by separating them with a comma. The default is to
        use the first available lcore for each virtio queue.

* ``--buffer-size <BUFFER_SIZE>``
        This is the size of the buffer used for the virtio mempool.
        The buffer size should be in the range 64 to 9216.
        Default is 2048.

* ``--help``
        Display the help message and exit.

Example EP firmware command
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Example to command to run ``dao-virtio-crypto`` on CN10K with one virtio device and
one crypto device.

.. code-block:: console

   DPI_ALLOW='-a 0000:06:00.1 -a 0000:06:00.2 -a 0000:06:00.3 -a 0000:06:00.4 -a 0000:06:00.5 -a 0000:06:00.6 -a 0000:06:00.7 -a 0000:06:01.0 -a 0000:06:01.1 -a 0000:06:01.2 -a 0000:06:01.3 -a 0000:06:01.4 -a 0000:06:01.5 -a 0000:06:01.6 -a 0000:06:01.7 -a 0000:06:02.0 -a 0000:06:02.1 -a 0000:06:02.2 -a 0000:06:02.3 -a 0000:06:02.4 -a 0000:06:02.5 -a 0000:06:02.6'

   dao-virtio-crypto -l 0,4,5,6 -a 0002:20:00.1 $DPI_ALLOW --  -v 0x1 -c 0x1 --crypto-config "(0,0x10)" --virtio-q-lcore-map "(4,0,0)"

If ``dao-virtio-crypto`` is not build with static linking to DPDK, we need to explicitly load
node library and PMD libraries for the application to function.

.. code-block:: console

   DPI_ALLOW='-a 0000:06:00.1 -a 0000:06:00.2 -a 0000:06:00.3 -a 0000:06:00.4 -a 0000:06:00.5 -a 0000:06:00.6 -a 0000:06:00.7 -a 0000:06:01.0 -a 0000:06:01.1 -a 0000:06:01.2 -a 0000:06:01.3 -a 0000:06:01.4 -a 0000:06:01.5 -a 0000:06:01.6 -a 0000:06:01.7 -a 0000:06:02.0 -a 0000:06:02.1 -a 0000:06:02.2 -a 0000:06:02.3 -a 0000:06:02.4 -a 0000:06:02.5 -a 0000:06:02.6'

   dao-virtio-crypto -d librte_node.so -d librte_crypto_cnxk.so -d librte_mempool_cnxk.so -d librte_dma_cnxk.so -d librte_mempool_ring.so -l 2-7 -a 0002:02:00.1 -l 0,4,5,6 -a 0002:20:00.1 $DPI_ALLOW --  -v 0x1 -c 0x1 --crypto-config "(0,0x10)" --virtio-q-lcore-map "(4,0,0)"

Setting up Host environment
---------------------------

For host setup, refer to the following guide which provides detailed steps on
how to set up the host for VirtIO solutions:

:doc:`Steps to setup up host for VirtIO solutions <../howtoguides/virtio_host>`

Running DPDK crypto-perf on host virtio device
----------------------------------------------
To run DPDK ``dpdk-test-crypto-perf`` application on the host virtio device,
you can use the following command:

.. code-block:: console

   dpdk-test-crypto-perf -c 0x3 --socket-mem 1024 --proc-type auto --file-prefix=virtio-user0 --no-pci --vdev=crypto_virtio_user0,path=/dev/vhost-vdpa-0,queue_size=2048 --log-level="pmd.crypto.virtio,info" -- --devtype crypto_virtio_user --optype rsa  --pool-sz 16384 --total-ops 100000 --burst-sz 32 --buffer-sz 20 --ptest throughput --asym-op sign --rsa-priv-keytype qt --rsa-modlen 1024

This command will benchmark the crypto performance on the virtio device with the
specified parameters. Make sure to adjust the parameters according to your requirements.
For more information on the available options and how to use the ``dpdk-test-crypto-perf``
application, refer to the DPDK documentation.
