..  SPDX-License-Identifier: Marvell-MIT
    Copyright (c) 2024 Marvell.

Getting started with SDP on host
################################

SDP Host driver
---------------

The SDP host driver enables efficient packet I/O between any host and an Octeon CN9K or CN10K
device connected via PCIe EP mode.

Identify the Octeon PF and VF devices on Host
---------------------------------------------

Use lspci command to list Octeon devices on Host, as below:

.. code-block:: console

  # lspci | grep Cavium

The above command should show an output similar to

.. code-block:: console

  /* cn10ka PF  */
  01:00.0 Network controller: Cavium, Inc. Device b900
  /* cn10ka VF0  */
  01:02.0 Network controller: Cavium, Inc. Device b903

.. note :: The PCI BDFs in the above example will vary from system to system.

Mapping between SDP VFs on Octeon and Host SDP PF/VFs
-----------------------------------------------------

On all CNXK models, the SDP PF is identified by the device ID 0xa0f6

.. code-block:: console

  # lspci -nn | grep a0f6
  0002:0f:00.0 Ethernet controller [0200]: Cavium, Inc. Device [177d:a0f6] (rev 60)

On Octeon, the SDP VFs are created by Octeon kernel at boot time.

SDP VFs are identified by device ID 0xa0f7 on all CNXK models.

.. code-block:: console

  # lspci -nn | grep a0f7
  0002:0f:00.1 Ethernet controller [0200]: Cavium, Inc. Device [177d:a0f7] (rev 60)
  0002:0f:00.2 Ethernet controller [0200]: Cavium, Inc. Device [177d:a0f7] (rev 60)
  0002:0f:00.3 Ethernet controller [0200]: Cavium, Inc. Device [177d:a0f7] (rev 60)

Every SDP PF or VF on host is connected one-to-one to an SDP VF on Octeon as described below:

.. code-block:: console

  0002:0f:00.1 is SDP VF0 on Octeon connected to SDP PF on Host.
  0002:0f:00.2 is SDP VF1 on Octeon connected to SDP VF0 on Host.
  0002:0f:00.3 is SDP VF2 on Octeon connected to SDP VF1 on Host.
  ...
  0002:0f:00.7 is SDP VF6 on Octeon connected to SDP VF5 on Host.
  0002:0f:01.0 is SDP VF7 on Octeon connected to SDP VF6 on Host.
  0002:0f:01.1 is SDP VF8 on Octeon connected to SDP VF7 on Host.
  ...

SDP PF on host is connected to SDP VF0 on Octeon. SDP VF[n] on host is connected to SDP VF[n+1] on Octeon.

So, max SDP VFs that can be created on Host = (<no.of SDP VFs on Octeon> - 1).

Host SDP kernel driver
----------------------

Build Instructions
``````````````````

Checkout PCIe EP host Linux kernel drivers sources from the below repo with appropriate release
TAG and execute the following commands to build the drivers:

.. code-block:: console

  git clone https://github.com/MarvellEmbeddedProcessors/pcie_ep_octeon_host.git -b <release_tag>

  Example:
  # git clone https://github.com/MarvellEmbeddedProcessors/pcie_ep_octeon_host.git -b v24.08
  # cd pcie_ep_octeon_host
  # make

The successful build process generates .ko files in their respective driver directory

.. code-block:: console

  ./drivers/octeon_ep/octeon_ep.ko
  ./drivers/octeon_ep_vf/octeon_ep_vf.ko

.. _sdp_host_kernel_modules:

Installing the kernel modules
`````````````````````````````

Before installing the host driver ``octep_cp_agent`` should be launched.

:ref:`Launching octep_agent<octep_cp_agent>`

Installing PF driver:

.. code-block:: console

  # insmod drivers/octeon_ep/octeon_ep.ko

Create VFs and installing VF driver

.. code-block:: console

  # echo 3 > /sys/bus/pci/devices/0000\:01\:00.0/sriov_numvfs
  # insmod drivers/octeon_ep_vf/octeon_ep_vf.ko

Identify PF/VF kernel netdev interface names on Host
````````````````````````````````````````````````````

Run below command to identify the name of the PF/V interface, once respective
octeon_ep/octeon_ep_vf driver is loaded on Host:

.. code-block:: console

  # lshw -businfo -c network|egrep "Class|Cavium|==="
  Bus info          Device          Class          Description
  ============================================================
  pci@0000:01:00.0  enp1s0f0        network        Cavium, Inc.     /* PF  */
  pci@0000:01:02.0  enp1s0f0v0      network        Cavium, Inc.     /* VF0 */
  pci@0000:01:02.1  enp1s0f0v1      network        Cavium, Inc.     /* VF1 */
  pci@0000:01:02.2  enp1s0f0v2      network        Cavium, Inc.     /* VF2 */

Bring up the netdev interface

.. code-block:: console

  # ifconfig <host-iface> <ip addr> up

Host SDP DPDK driver
--------------------

Build Instructions
``````````````````

Steps to build DPDK are as follows:

.. code-block:: console

  # git clone https://github.com/MarvellEmbeddedProcessors/marvell-dpdk.git
  # cd marvell-dpdk
  # git checkout dpdk-23.11-release
  # meson build –prefix=${PWD}/install
  # ninja -C build install

Setting up the Environment and bind SDP VF to vfio-pci
``````````````````````````````````````````````````````

.. code-block:: console

  # mkdir /mnt/huge
  # mount -t hugetlbfs nodev /mnt/huge
  # echo 1024 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
  # modprobe vfio-pci
  # echo 1 >/sys/module/vfio/parameters/enable_unsafe_noiommu_mode
  # usertools/dpdk-devbind.py -b vfio-pci <VF-pci-bdf>

Performance Optimizations
-------------------------

To optimize performance, include the following parameters in the host kernel bootargs.

Update the kernel bootargs in ``/etc/default/grub`` by modifying the ``GRUB_CMDLINE_LINUX=""`` line.

If Intel host:

.. code-block:: console

  GRUB_CMDLINE_LINUX="memmap=512M\\\$1G iommu=off intel_iommu=off"

If AMD host:

.. code-block:: console

  GRUB_CMDLINE_LINUX="memmap=512M\\\$1G iommu=off amd_iommu=off"
