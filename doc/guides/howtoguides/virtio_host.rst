..  SPDX-License-Identifier: Marvell-MIT
    Copyright (c) 2024 Marvell.

Getting started with VirtIO on host
###################################

Setting up Host environment
---------------------------

Host requirements
~~~~~~~~~~~~~~~~~
Host needs Linux Kernel version of >= 6.5 (for example latest ubuntu version supports 6.5)
IOMMU should always be on if we need to use VF's with Guest. (x86 intel_iommu=on)

Host kernel patches to enable DAO on v6.1 kernel
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. include:: ../../../patches/kernel/v6.1/vdpa/README.rst

Build KMOD specifically for Host with native compilation(For example x86)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Not providing 'kernel_dir' option would pick /lib/modules/`uname -r`/source  as kernel source

.. code-block:: console

   git clone https://github.com/MarvellEmbeddedProcessors/dpu-accelerator-offload.git
   git checkout dao-devel

   meson build
   ninja -C build

Bind PEM PF and VF to Host Octeon VDPA driver
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
On Host, we need to bind host PF and VF devices provided by CN10K to ``octep_vdpa`` driver and
then bind the VDPA devices to ``vhost_vdpa`` devices to be available for DPDK or guest.

.. code-block:: console

   modprobe vfio-pci
   modprobe vdpa
   modprobe vhost-vdpa

   insmod octep_vdpa.ko

   HOST_PF=`lspci -Dn -d :b900 | head -1 | cut -f 1 -d " "`
   VF_CNT=1
   VF_CNT_MAX=`cat /sys/bus/pci/devices/$HOST_PF/sriov_totalvfs`
   VF_CNT=$((VF_CNT >VF_CNT_MAX ? VF_CNT_MAX : VF_CNT))

   echo $HOST_PF > /sys/bus/pci/devices/$HOST_PF/driver/unbind
   echo octep_vdpa > /sys/bus/pci/devices/$HOST_PF/driver_override
   echo $HOST_PF > /sys/bus/pci/drivers_probe
   echo $VF_CNT >/sys/bus/pci/devices/$HOST_PF/sriov_numvfs

   SDP_VFS=`lspci -Dn -d :b903 | cut -f 1 -d " "`
   for dev in $SDP_VFS
   do
       vdev=`ls /sys/bus/pci/devices/$dev | grep vdpa`
       while [[ "$vdev" == "" ]]
       do
           echo "Waiting for vdpa device for $dev"
           sleep 1
           vdev=`ls /sys/bus/pci/devices/$dev | grep vdpa`
       done
    echo $vdev >/sys/bus/vdpa/drivers/virtio_vdpa/unbind
    echo $vdev > /sys/bus/vdpa/drivers/vhost_vdpa/bind
   done

Tune MRRS and MPS of PEM PF/VF on Host for performance
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Tune MRRS and MPS on Host PF in order to increase virtio performance.
Example code to do the same if the PEM PF and its bridge devices seen on host are ``0003:01:00.0``
and ``0003:00:00.0``.

.. code-block:: console

   setpci -s 0003:00:00.0 78.w=$(printf %x $((0x$(setpci -s 0003:00:00.0 78.w)|0x20)))
   setpci -s 0003:01:00.0 78.w=$(printf %x $((0x$(setpci -s 0003:01:00.0 78.w)|0x20)))

Running DPDK testpmd on Host virtio device
------------------------------------------

Setup huge pages for DPDK application
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Need to enable sufficient enough hugepages for DPDK application to run.

Increase ulimit for 'max locked memory' to unlimited
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
DPDK application needs to be able to lock memory that is DMA mapped on host. So increase the ulimit
to max for locked memory.

.. code-block:: console

   ulimit -l unlimited

Example command for DPDK testpmd on host with vhost-vdpa device
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Below is example to launch ``dpdk-testpmd`` application on host using ``vhost-vdpa`` device.

.. code-block:: console

   ./dpdk-testpmd -c 0xfff000 --socket-mem 1024 --proc-type auto --file-prefix=virtio-user0 --no-pci --vdev=net_virtio_user0,path=/dev/vhost-vdpa-0,mrg_rxbuf=1,packed_vq=1,in_order=1,queue_size=4096 -- -i --txq=1 --rxq=1 --nb-cores=1 --portmask 0x1 --port-topology=loop

Running DPDK testpmd on virtio-net device on guest
--------------------------------------------------

Host requirements for running Guest
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Follow `Setting up Host environment`_ as a first step.

* Install qemu related packages on host
* Get qemu-8.1.1 and apply below patches on top of it.
* https://patchwork.kernel.org/project/qemu-devel/patch/d01d0de97688c5587935da753c63f0441808cb9d.1691766252.git.yin31149@gmail.com/
* https://patchwork.kernel.org/project/qemu-devel/patch/20240102111432.36817-1-schalla@marvell.com/
* https://patchwork.kernel.org/project/qemu-devel/patch/20240220070935.1617570-1-schalla@marvell.com/ (Note: This patch is not required if the host has page size of 4K)

Build Qemu
^^^^^^^^^^

.. code-block:: console

   wget https://download.qemu.org/qemu-8.1.1.tar.xz
   tar xvJf qemu-8.1.1.tar.xz
   cd qemu-8.1.1
   /* Apply above mentioned patches */
   ./configure
   make

Prepare the Ubuntu cloud image for guest
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Below is the example to prepare ubuntu cloud image for ARM guest.

.. code-block:: console

   wget https://cloud-images.ubuntu.com/mantic/current/mantic-server-cloudimg-arm64.img
   virt-customize -a mantic-server-cloudimg-arm64.img --root-password password:a
   mkdir mnt_img

   cat mount_img.sh
   #!/bin/bash
   modprobe nbd max_part=8
   qemu-nbd --connect=/dev/nbd0 $1
   sleep 2
   fdisk /dev/nbd0 -l
   mount /dev/nbd0p1 mnt_img

   # Copy required files to mnt_img/root for example dpdk-testpmd and user tools from dpdk
   cat unmount_img.sh
   #!/bin/bash
   umount mnt_img
   qemu-nbd --disconnect /dev/nbd0
   #rmmod nbd

Launch guest using Qemu
~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: console

   ulimit -l unlimited
   cd qemu-8.1.1
   ./build/qemu-system-aarch64  -hda /home/cavium/ws/mantic-server-cloudimg-arm64_vm1.img -name vm1 \
   -netdev type=vhost-vdpa,vhostdev=/dev/vhost-vdpa-0,id=vhost-vdpa1 -device \
   virtio-net-pci,netdev=vhost-vdpa1,disable-modern=off,page-per-vq=on,packed=on,mrg_rxbuf=on,mq=on,rss=on,rx_queue_size=1024,tx_queue_size=1024,disable-legacy=on -enable-kvm -nographic -m 2G -cpu host -smp 3 -machine virt,gic_version=3 -bios /usr/share/qemu-efi-aarch64/QEMU_EFI.fd

Launch dpdk-testpmd on guest
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Below code block shows method to bind device to vfio-pci to use with DPDK testpmd in guest.

.. code-block:: console

   modprobe vfio-pci
   echo 1 > /sys/module/vfio/parameters/enable_unsafe_noiommu_mode
   # On 106xx $VIRTIO_NETDEV_BDF would come as 0000:00:01.0
   ./usertools/dpdk-devbind.py -b vfio-pci $VIRTIO_NETDEV_BDF
   echo 256 > /proc/sys/vm/nr_hugepages
   ./dpdk-testpmd -c 0x3 -a $VIRTIO_NETDEV_BDF -- -i --nb-cores=1 --txq=1 --rxq=1


Using VDPA device as Kernel virtio-net device on guest
------------------------------------------------------

* Follow `Setting up Host environment`_, `Host requirements for running Guest`_,
  `Prepare the Ubuntu cloud image for guest`_ and `Launch guest using Qemu`_
* Probe virtio_net kernel module if not present already and check for the virtio network interface using ifconfig/ip tool.

Using VDPA device as Kernel virtio-net device on host
-----------------------------------------------------

Run the code block below to create a virtio device on host for each VF using virtio_vdpa.

.. code-block:: console

   modprobe vfio-pci
   modprobe vdpa
   insmod octep_vdpa.ko
   HOST_PF=`lspci -Dn -d :b900 | head -1 | cut -f 1 -d " "`
   VF_CNT=1
   VF_CNT_MAX=`cat /sys/bus/pci/devices/$HOST_PF/sriov_totalvfs`
   VF_CNT=$((VF_CNT >VF_CNT_MAX ? VF_CNT_MAX : VF_CNT))

   echo $HOST_PF > /sys/bus/pci/devices/$HOST_PF/driver/unbind
   echo octep_vdpa > /sys/bus/pci/devices/$HOST_PF/driver_override
   echo $HOST_PF > /sys/bus/pci/drivers_probe
   echo $VF_CNT >/sys/bus/pci/devices/$HOST_PF/sriov_numvfs

   modprobe virtio_vdpa
   modprobe virtio_net
