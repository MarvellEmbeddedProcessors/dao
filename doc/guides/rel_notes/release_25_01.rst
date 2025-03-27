..  SPDX-License-Identifier: Marvell-MIT
    Copyright (c) 2025 Marvell.

DAO Release 25.01.0
===================

New Features
------------

* **Applications**

  * *DPDK based OpenSSL Engine*

    Added support for OpenSSL 3.x version.
    Bug fixes in ECDSA verify operations.

  * *OVS*

    Solution migrated to OVS-3.4.1.
    Integration with Flow library - enhancing scope to manage large no of flows.

* **Infrastructure**

  * New debian packages for DAO solutions

    - ML Models
    - Snort

  * Linking Mode Updated

    Starting in this release, DAO builds have been switched from static to dynamic linking.
    For details on how to preload DPDK libraries for DAO applications, please refer to the **FAQ** section.

Debian Packages List
--------------------

- **DAO**
  - **dao-cn10k**
  - **Version:** 25.01.0

- **DPDK**
  - **dpdk-24.11-cn10k**
  - **Version:** 25.01.0

- **OVS**
  - **ovs-3.4.1-cn10k**
  - **Version:** 25.01.0

- **NGINX**
  - **nginx-1.22.0-cn10k**
  - **Version:** 25.01.0

- **OpenSSL**
  - **openssl-1.1.1q-cn10k**
  - **Version:** 25.01.0

- **DPDK based OpenSSL Engine**
  - **openssl-engine-1.0.0-cn10k**
  - **Version:** 25.01.0

- **VPP**
  - **vpp-24.02.0-cn10k**
  - **Version:** 25.01.0

- **octep-target**
  - **oct-ep-target-cn10k**
  - **Version:** 25.01.0

- **firmware-cpt**
  - **cpt-firmware-cn10k**
  - **Version:** 24.09.0

- **firmware-ml**
  - **ml-firmware-cn10k**
  - **Version:** 24.09.0

- **ML models**
  - **ml-models-cn10k**
  - **Version:** 25.01.0

- **Snort**
  - **snort-3-cn10k**
  - **Version:** 25.01.0

Removed Items
-------------

API Changes
-----------

ABI Changes
-----------
