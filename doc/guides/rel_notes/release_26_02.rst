.. SPDX-License-Identifier: Marvell-MIT
   Copyright (c) 2026 Marvell.

DAO Release 26.02.0
===================

.. note::

   DAO (Data Accelerator Offload) provides libraries and reference applications
   that enable developers to build high-performance networking, security, and storage solutions on Marvell SoCs and Platforms.

Release Overview
----------------

DAO 26.02.0 delivers significant enhancements to various components across networking, cryptography,
and system infrastructure. This release includes a major version upgrade of the
DPDK base to 25.11, along with updates to several other components. Platform
support is expanded to include OCTEON-20, the Iliad EPF driver, and multi-PEM
device capabilities. It also introduces RDMA support with connection manager
capabilities and adds comprehensive VPP features, including traffic management
and control-plane XFRM integration.

Release Highlights
------------------

- **DPDK 25.11 integration**


- **Component additions/removals**:

    - New components:

        - **RDMA Library**: Added RDMA support with UD/RC modes and connection manager.

    - Updated components:

        - **VPP**: Added traffic management framework, inline IPsec for OCTEON-20, Linux CP XFRM support, and priority flow control.
        - **DPDK**: Added DMA enqueue/dequeue operations, inter-domain transfers, PQC algorithm support, and CPT CQ for CN20K.
        - **PEM Library**: Added multi-device support and Iliad platform device integration.
        - **Marvell OpenSSL Engine**: Added RSA-PSS support for TLS1.3 and software fallback mechanisms.

- **Documentation / Guides**:

    - Added Structera platform guide.
    - Added accelerated OpenSSL and NGINX solution whitepapers.

Components
----------

DPDK
~~~~

- **Base DPDK Version:** 25.11.0
- **Marvell DAO Version:** 26.02.0
- **Source repo / patches**:

    - `Marvell DPDK Repo <https://github.com/MarvellEmbeddedProcessors/marvell-dpdk/>`_

- **Changes**:

    - **DMA Enhancements**:

        - Added enqueue/dequeue operations for DMA devices.
        - Added inter-process and inter-OS DMA device API.
        - Added inter-domain control plane API and domain parameter for access groups.

    - **Crypto Features**:

        - Added post-quantum ML-KEM and ML-DSA algorithm support in cryptodev.
        - Added CPT CQ support for CN20K outbound traffic.
        - Added ECDSA P192/P224/P384/P521 curve support in crypto-perf.

    - **Network Enhancements**:

        - Added 800G Ethernet link speed support.
        - Added TM tree support for SDP interface.
        - Added IPv4 fragmentation offload support.
        - Added ethdev API to get link connector type.
        - Added SQ resize and per-packet SQ count update support.

    - **Framework Improvements**:

        - Added automatic lcore-id remapping option (``--remap-lcore-ids`` or ``-R``).
        - Added packet capture (pdump) support for secondary process.

Marvell OpenSSL Engine
~~~~~~~~~~~~~~~~~~~~~~

- **Version:** 26.02.0
- **Source repo / patches**:

    - `Marvell OpenSSL Engine Repo <https://github.com/MarvellEmbeddedProcessors/marvell-openssl-engine/>`_

- **Changes**:

    - Added RSA-PSS support for TLS1.3.
    - Added EC point multiplication software fallback in keygen.
    - Added RSA sign and verify software fallback.
    - Added SIGINT handler for proper device cleanup.
    - Moved CPT hardware init function to PAL layer.

VPP
~~~

- **Base VPP Version:** 25.02.0
- **Marvell DAO Version:** 26.02.0
- **Source repo / patches**:

    - `VPP Repo <https://github.com/MarvellEmbeddedProcessors/vpp/>`_

- **Changes**:

    - **Traffic Management**:

        - Added TM framework for hardware traffic management.
        - Added TM node suspend, resume, and dynamic weight update support.
        - Added support for fetching TM capabilities.
        - Enabled SDP TM tree for multiple Tx queues.

    - **IPsec Offload**:

        - Added inline IPsec support for OCTEON-20 platform.
        - Added policy-based inline IPsec for tunnel and transport modes.
        - Added post-IPsec reassembly and multi-segment support.
        - Enabled 3DES-CBC crypto algorithm.

    - **Linux Control Plane**:

        - Added XFRM netlink notification support.
        - Added IPsec interface support for XFRM.

    - **Flow Control & Configuration**:

        - Added priority flow control (PFC) framework and OCTEON support.
        - Added support for changing RSS key and flowkey bitmap.
        - Added host checksum offload support via OCTEP control plane.
        - Added OP-TEE support and interrupt mechanism.

RDMA Library
~~~~~~~~~~~~

- **Version:** 26.02.0
- **Source repo / patches**:

    - `RDMA Library <https://github.com/MarvellEmbeddedProcessors/dao/tree/dao-26.02/lib/rdma/>`_

- **Changes**:

    - Initial release of RDMA library with UD and RC queue pair support.
    - Added RDMA connection manager (CM) support.
    - Added DCQCN congestion control and burst scheduling support.
    - Added RDMA kernel module support.
    - Added RDMA graph application.

- **Notices**:

    - Requires corresponding kernel module for operation.

Machine Learning
~~~~~~~~~~~~~~~~

- **Version:** 26.02.0
- **Dependencies:** ML Firmware
- **Source repo / patches**:

    - `Machine Learning Library <https://github.com/MarvellEmbeddedProcessors/MarvellMLTools>`_

- **Changes**:

    - Added Resnet101 and Darknet53 model support documentation.
    - Added MNIST model flow and Resnet50 Jupyter Notebook workflow.
    - Updated documentation with Marvell GitHub TVM compiler options.

VirtIO Network
~~~~~~~~~~~~~~

- **Version:** 26.02.0

- **Changes**:

    - Added vDPA platform driver support.
    - Added net_virtio_user and virtio-only mode support.
    - Added interrupt completion logic for host Tx queue.
    - Added Iliad platform setup and launch scripts.
    - Added retry mechanism for sending packets to ethdev.

PEM Library
~~~~~~~~~~~

- **Version:** 26.02.0

- **Changes**:

    - Added support for multiple PEM devices.
    - Added Iliad platform device support.
    - Added DMA ops submit version 2.
    - Enabled SDP ring configuration.

PCIe EP
~~~~~~~

- **Version:** 26.01.0
- **Source repo / patches**:

    - `PCIe EP Repo <https://github.com/MarvellEmbeddedProcessors/pcie_ep_octeon_target/>`_

- **Changes**:

    - Added Iliad EPF platform device driver.
    - Added CXL PCI device resources quirk module.
    - Added usage printing for library arguments.
    - Improved detection of extra arguments parsed by library.

Firmware
~~~~~~~~

- **Version:** 26.02.0
- **Source repo / patches**:

    - `Marvell Firmware Repo <https://github.com/MarvellEmbeddedProcessors/marvell-firmware/>`_

- **Changes**:

    - Updated ML firmware binaries with 25.08 artifacts.
    - Added blue LED signaling for firmware readiness.

Known Issues
------------

- The ``dev_octeon_virtio_plugin.so`` plugin is not included in the VPP Debian package (``vpp-25.02.0-cn10k-devel``). The plugin is absent, preventing VirtIO-based use cases from being configured.

------------

.. rubric:: Additional Information

- `DAO Programmer's Guide <https://marvellembeddedprocessors.github.io/dao/guides/dao-26.02/>`_
