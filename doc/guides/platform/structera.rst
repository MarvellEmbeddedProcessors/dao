..  SPDX-License-Identifier: Marvell-MIT
    Copyright (c) 2025 Marvell.

*********
Structera
*********

Structera™ is Marvell's family of CXL-based memory expanders and near-memory accelerators
designed for hyperscaler memory applications. These devices provide scalable memory
expansion and low-latency near-memory acceleration for cloud and datacenter workloads.

The Structera product line includes:

* **Structera 2XXX (Iliad)** - CXL-based memory expanders with compression capabilities

Structera™ SLX24041 is an SoC optimized for hyperscaler memory applications that provides
the ability to expand DDR memory over CXL™ and connect to host compute servers with high
bandwidth and low latency.

The system features:

* **CPU Subsystem:** 2 high-performance Arm Neoverse V2 cores based on Armv9.0-A and
    Armv8.5-A architecture
* **Memory Expansion:** CXL 2.0 interface supporting up to 16-lane PCIe Gen 5.0 connectivity

Getting Started
===============

Host Setup
----------

Host Kernel Configuration
~~~~~~~~~~~~~~~~~~~~~~~~~

The host kernel requires the following CXL-related configuration options:

.. code-block:: none

    CONFIG_CXL_BUS=m
    CONFIG_CXL_PCI=m
    CONFIG_CXL_MEM_RAW_COMMANDS=y
    CONFIG_CXL_ACPI=m
    CONFIG_CXL_PMEM=m
    CONFIG_CXL_MEM=m
    CONFIG_CXL_PORT=m
    CONFIG_CXL_SUSPEND=y
    CONFIG_CXL_REGION=n
    CONFIG_CXL_REGION_INVALIDATION_TEST=y
    CONFIG_CXL_PMU=m

    CONFIG_FS_DAX=y
    CONFIG_DEV_DAX_CXL=m

Boot Parameters
~~~~~~~~~~~~~~~

Add the following boot time parameter to the kernel command line:

.. code-block:: none

    memhp_default_state=offline

Configuring CXL Memory as a DAX Device
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Load the required kernel modules in the following order:

.. code-block:: bash

    #rmmod cxl_pci cxl_mem cxl_pmem cxl_acpi cxl_port cxl_core dax_hmem
    #modprobe dax_hmem
    #modprobe cxl_core
    #modprobe cxl_mem
    #modprobe cxl_acpi
    #modprobe cxl_port
    #modprobe cxl_pci
    #modprobe cxl_pmem

Verify the DAX device configuration:

.. code-block:: bash

    daxctl list --human

Expected output:

.. code-block:: json

    {
      "chardev":"dax0.0",
      "size":"200.00 GiB (214.75 GB)",
      "target_node":3,
      "align":2097152,
      "mode":"system-ram"
    }

Configure the DAX device for device DAX mode:

.. code-block:: bash

    daxctl offline-memory dax0.0
    daxctl reconfigure-device --mode=devdax dax0.0

DPU Setup
---------

Booting Linux on Board with CXL DAX Memory
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To boot Linux on the board using CXL DAX memory, use the following command:

.. code-block:: bash

    iliad_core_mgmt -m mem0 -D dax0.0 -l <PATH to Linux kernel Image>

Replace ``<PATH to Linux kernel Image>`` with the actual path to your Linux kernel image.

Running Applications
====================

After running the virtio-l2fwd application on the board using the run script
(``kmod/iliad/scripts/run_virtio_l2fwd_iliad.sh``), perform the following steps on the host
to create a vDPA platform device and establish communication with the board.

vDPA Platform Driver Overview
-----------------------------

The vDPA platform driver (``octep_vdpa_plat.ko``) is a specialized driver for the Iliad
platform that enables vDPA functionality through platform devices rather than direct PCI
device access. This architecture is necessary because:

* **CXL and ODM Coexistence**: On Iliad, CXL and ODM (Offload DMA Unit) share a single
  Physical Function (PF). The CXL functionality uses certain PCI resources, while ODM
  requires access to other resources (ODM BAR0 space at an offset of CXL PCI device BAR0,
  ODM interrupts which are the same as CXL PCI device interrupts - the cxl_pci driver
  allocates the first 16 vectors but only uses a few, leaving vectors 8-15 available).
  Additionally, PEM (PCI Express Interface) BAR4 space, which appears at the host as CXL
  PCI device BAR4, is needed for shared memory. In vDPA functionality, the ODM block is
  used for DMA and interrupt delivery, while the PEM block is used for shared memory.

* **Resource Separation**: The quirk module (``octep_cxl_quirk.ko``) extracts unused CXL PCI
  resources and creates a platform device (``octep_vdpa_plat``) with these resources. The
  platform driver then probes this device, allowing vDPA to use ODM block for DMA and
  interrupt delivery, and PEM block for shared memory, without interfering with CXL operations.

* **Platform Device Architecture**: Unlike the PCI-based vDPA driver (``octep_vdpa_pci.ko``) used
  on CN10K platforms, the platform driver uses Linux platform device framework, which
  provides better resource isolation and management for devices that share PCI resources
  with other drivers.

The platform driver implements the same vDPA operations as the PCI driver but interfaces
through platform device resources instead of direct PCI BAR access.

Load Quirk Module
-----------------

Load the quirk module to create a vDPA platform device from the CXL PCI device:

.. code-block:: bash

    insmod octep_cxl_quirk.ko

This module:

* Identifies the CXL PCI device
* Extracts unused resources from the CXL PCI device:

  - ODM BAR0 space (at offset of CXL PCI device BAR0) - used to acknowledge interrupts from the ODM block
  - PEM BAR4 space (CXL PCI device BAR4) - used for shared memory between device and host for vDPA functionality
  - ODM unused MSI-X vectors (vectors 8-15 from CXL PCI device interrupts; the cxl_pci driver allocates
    the first 16 vectors but only uses a few, leaving vectors 8-15 available for the quirk module) -
    used for interrupt delivery from the ODM block

* Creates a platform device named ``octep_vdpa_plat`` with these resources

Load vDPA Platform Driver
--------------------------

Load the vDPA platform driver:

.. code-block:: bash

    modprobe virtio_vdpa
    insmod octep_vdpa_plat.ko

The platform driver will automatically probe the ``octep_vdpa_plat`` platform device created
by the quirk module and register itself as a vDPA management device.

Stop NetworkManager
-------------------

Stop the NetworkManager service:

.. code-block:: bash

    sudo service NetworkManager stop

Create vDPA Device
------------------

Create a vDPA device named ``vdpa0`` using the platform management device:

.. code-block:: bash

    vdpa dev add name vdpa0 mgmtdev platform/octep_vdpa_plat

This step creates a kernel interface that enables communication with the board.

Delete vDPA Device
------------------

To remove the vDPA device when no longer needed:

.. code-block:: bash

    vdpa dev del vdpa0

This removes the vDPA device and frees associated resources.

References
==========

For more details on the libraries supported by Structera platform, refer to:

* :doc:`../prog_guide/virtio_net_lib` - VirtIO Net Library
* :doc:`../prog_guide/pem_lib` - PEM Library
