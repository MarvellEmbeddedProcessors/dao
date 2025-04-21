.. SPDX-License-Identifier: Marvell-MIT
   Copyright (c) 2025 Marvell.

DAO 25.05.0 Release Notes
=========================

.. note::
   DAO (Data Accelerator Offload) provides libraries and reference
   applications that enable developers to build high-performance
   networking, security, and storage solutions on Marvell SoCs and Platforms.

Release Overview
----------------

DAO 25.05.0 brings a mix of new features and key enhancements across networking,
 crypto, and system libraries. This release introduces a Kubernetes CNI offload
 application and a user-space Conntrack library, adds advanced flow table handling,
 and improves vDPA device management through new PEM APIs. Updates to VPP add
 support for inline IPsec reassembly and WireGuard async crypto, while the OpenSSL
 engine sees internal restructuring. Build support has also been expanded with
 new static linking options for EP targets.

Release Highlights
------------------

- **Component additions/removals**:
    - New components:
        - **Conntrack Library**: User-space DPDK-based connection tracking.
        - **Kubernetes CNI Offload**: Cilium-based PoC for DPU traffic offload.
    - Updated components:
        - **Flow Library**: Multiple flow table support with exact match capabilities.
        - **PEM Library**: Host-device vDPA management APIs.
        - **VPP**: New inline IPsec and WireGuard async crypto features.
        - **OpenSSL Engine**: Codebase reorganization for maintainability, with feature additions and restructuring.
    - No components have been removed in this release.

- **Build system / toolchain updates**:
    - Support for static linking of DPDK libraries on EP (aarch64) builds.
    - Introduced `static_only` Meson option to toggle static vs. shared builds.

- **Documentation / Guides**:
    - New usage guides for Conntrack, Flow, and PEM libraries.
    - Integration guide for `k8s-cni-offload` with Cilium.

Components
----------

Conntrack - Connection Tracking Library
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- **Version:** 25.05.0
- **Source repo / patches**:
    - GitHub: https://github.com/MarvellEmbeddedProcessors/dao/conntrack
- **Changes**:
    - Initial release of the 'Conntrack'.
- **Notes**:
    - DAO-Conntrack is a DPDK-based connection tracking
      library. It is a user-space library built on top of DPDK (Data Plane Development Kit)
      that replicates and extends the functionality of the Linux kernel's
      Conntrack (Connection Tracking) subsystem. It monitors the state of network connections
      (e.g., TCP, ICMP) by maintaining a connection table in memory.
    - Tracks network connections (TCP, ICMP, etc.) in both directions.
    - Maintains a hash-based connection table with fast lookups.
    - Uses RCU (Read-Copy-Update) for safe, lock-free memory reclamation.
    - Periodically cleans up expired connections in a background thread.
    - Provides real-time statistics and connection dumps for observability.
- **Notices**:
    - To build and run the project, follow the instructions in the repository's README file.

Flow Library
~~~~~~~~~~~~

- **Version:** 25.05.0
- **Dependencies:** DPDK ≥ 25.03.0, CPT ≥ 24.09.0
- **Source repo / patches**:
    - GitHub: https://github.com/MarvellEmbeddedProcessors/dao/flow
- **Changes**:
    - Support for multiple flow tables
    - Support multiple flow key extraction profiles
    - Support for flow key exact match algorithm

Kubernetes CNI Offload
~~~~~~~~~~~~~~~~~~~~~~

- **Version:** 25.05.0
- **Dependencies:** Cilium ≥ 1.17.0-dev, CPT ≥ 24.09.0, linux kernel ≥ 6.1.67
- **Source repo / patches**:
    - GitHub: https://github.com/MarvellEmbeddedProcessors/k8s-cni-offload
- **Changes**:
    - Initial release of the `k8s-cni-offload`.
- **Notes**:
    - This project introduces a solution to offload Kubernetes networking tasks to Marvell DPUs, leveraging the standardized Container Network Interface (CNI) framework.
    - The initial implementation focuses on offloading Cilium, the most widely adopted CNI, including by hyper-scalers.
    - The architecture is designed to be flexible, enabling future support for offloading other CNIs without requiring changes to Kubernetes itself.
    - A working proof-of-concept (PoC) has been successfully developed with Cilium as the offloaded CNI.
    - Comprehensive documentation for setup, usage, and integration is included in the repository.
- **Notices**:
    - To build and run the project, follow the instructions in the repository's README file.

Marvell OpenSSL Engine
~~~~~~~~~~~~~~~~~~~~~~

- **Version:** 25.05.0
- **Dependencies:** DPDK ≥ 25.03.0, CPT ≥ 24.09.0
- **Source repo / patches**:
    - GitHub: https://github.com/MarvellEmbeddedProcessors/marvell-openssl-engine
- **Changes**:
    - Repurposed code for better code organization. However, no changes from user API perspective

PEM Library
~~~~~~~~~~~

- **Version:** 25.05.0
- **Source repo / patches**:
    - GitHub: https://github.com/MarvellEmbeddedProcessors/lib/pem
- **Changes**:
    - Introduced new DAO PEM APIs to manage host-facing vDPA devices.
    - Added dao_pem_host_dev_add() API to register a vDPA device.
    - Added dao_pem_host_dev_del() API to remove a vDPA device.

VPP
~~~

- **Version:** 25.05.0
- **Dependencies:** DPDK ≥ 25.03.0, CPT ≥ 24.09.0
- **Source repo / patches**:
    - GitHub: https://github.com/MarvellEmbeddedProcessors/vpp
- **Changes**:
    - Inline IPsec offload support for OCTEON-10.
    - Inline IPsec inner packet reassembly support for OCTEON-10.
    - Implemented async mode in the WireGuard encryption/decryption path.
- **Notes**:
    - Async mode is disabled by default; enable with ``--enable-async-crypto``.
- **Notices**:
    - Disable DPDK plugin in startup.conf while running OCTEON device plugin.
    - Inline IPsec reassembly supports only single-segment fragments.
    - Async crypto feature is experimental; API may change.

Known Issues
------------

.. rubric:: Additional Information

- `DAO Programmer's Guide <https://marvellembeddedprocessors.github.io/dao/guides/>`_