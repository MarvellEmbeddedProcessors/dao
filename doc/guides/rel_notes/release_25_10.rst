.. SPDX-License-Identifier: Marvell-MIT
   Copyright (c) 2025 Marvell.

DAO Release 25.10.0
===================

.. note::
   DAO (Data Accelerator Offload) provides libraries and reference
   applications that enable developers to build high-performance
   networking, security, and storage solutions on Marvell SoCs and Platforms.

Release Overview
----------------

DAO 25.10.0 brings a mix of new features and key enhancements across networking,
crypto, and system libraries. This release marks a major transition for the OpenSSL Engine,
introducing support for the OpenSSL Provider framework to enable Liquid Crypto
platform offloads. VPP receives substantial updates, including
Inline IPsec support for OCTEON-20, new transport mode capabilities, and advanced
traffic management features.

Release Highlights
------------------

- **Component additions/removals**:
    - Updated components:
        - **Marvell OpenSSL Engine**: Support for OpenSSL Provider framework; added Liquid Crypto platform offload.
        - **VPP**: Added Inline IPsec support for OCTEON-20, IPsec Transport mode, and Priority Flow Control (PFC) support.

- **Build system / toolchain updates**:
    - **DPDK Build Configuration**:
        - **IOVA Configuration**: The Meson build option ``enable_iova_as_pa`` must be set to ``false``.
        - **Driver Support**: Added the ``raw/cnxk_emdev`` driver to the enabled drivers list.

- **Documentation / Guides**:
    - **Solutions Showcase**: Added a new section dedicated to solution briefs and in-depth white papers.
    - **VirtIO-blkIO**: Added comprehensive documentation and usage guides for the VirtIO-blkIO application.
    - Updated Programmer's Guide for OpenSSL Provider implementation.

Components
----------

Marvell OpenSSL Engine
~~~~~~~~~~~~~~~~~~~~~~

- **Version:** 25.10.0

- **Dependencies:** DPDK ≥ 25.10.0, CPT ≥ 24.09.0

- **Source repo / patches**:
    - `Marvell OpenSSL Engine Repo <https://github.com/MarvellEmbeddedProcessors/marvell-openssl-engine/>`_

- **Changes**:
    - Added support for crypto offload using the OpenSSL Provider framework.
    - Enabled Liquid Crypto platform offload via OpenSSL provider framework.
    - Addressed minor bug fixes and stability improvements.

VPP
~~~

- **Version:** 25.10.0

- **Dependencies:** DPDK ≥ 25.10.0, CPT ≥ 24.09.0

- **Source repo / patches**:
    - `VPP repo <https://github.com/MarvellEmbeddedProcessors/vpp/>`_

- **Changes**:
    - **IPsec Offload**:
        - Added Inline IPsec offload support for OCTEON-20.
        - Added Inline IPsec transport mode support for OCTEON platforms.
    - **Flow Control & RSS**:
        - Implemented Vnet framework for priority flow control.
        - Added Priority Flow Control (PFC) support for OCTEON.
        - Added support for changing RSS key for OCTEON.
        - Added support to specify RSS flowkey bitmap for OCTEON.
- **Notices**:
    - Disable DPDK plugin in startup.conf while running OCTEON device plugin.
    - Inline IPsec reassembly supports only single-segment fragments.
    - Async crypto feature is experimental; API may change.

Known Issues
------------

- **VPP: SDP Interface unavailable in vppctl**
    SDP interface support is temporarily unavailable and will be re-enabled in upcoming release.

- **Secgw-graph: Remote Telnet CLI Access Unavailable**
    Remote telnet connections to the secgw-graph CLI are currently unsupported and will result in a connection refusal.
    Please use a local telnet connection to access, until remote support is implemented in the next release.

------------

.. rubric:: Additional Information

- `DAO Programmer's Guide <https://marvellembeddedprocessors.github.io/dao/guides/dao-25.10/>`_
