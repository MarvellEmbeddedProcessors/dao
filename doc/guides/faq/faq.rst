..  SPDX-License-Identifier: Marvell-MIT
    Copyright (c) 2024 Marvell.

Why is --prefer-static meson option required in DAO compilation?
----------------------------------------------------------------

Meson option ``--prefer-static`` is important to ensure static linkage of
dependent libraries like DPDK. Constructor declarations made in DPDK do not
function correctly when used without static linkage.

Eg. The DPDK graph library, utilized by many DAO applications, has the
uses custom nodes from the node library. However, these nodes being constructor
declarations, fail to become part of the constructed graph when DPDK is not
statically linked.

.. _dep_issue:

Why is installing older DAO version causing dependency issues?
--------------------------------------------------------------

DAO package is dependent on DPDK and it gets installed as a dependency when
DAO is installed. If user wants to install an older version of DAO and it may be
dependent on older DPDK version.

``apt-get`` may insist to install latest version of DPDK when installing the older
version of DAO, which may cause dependency issues:

.. code-block:: bash

   The following packages have unmet dependencies:
    dao-cn10k : Depends: dpdk-23.11-cn10k (= 24.07.0) but 24.08.0 is to be installed
   E: Unable to correct problems, you have held broken package

To avoid this user may follow two approaches:

1. Install dependent DPDK package alongside required DAO version.

.. code-block:: bash

    sudo apt-get install dao-cn10k=<version> dpdk-23.11-cn10k=<dependent_version>

.. code-block:: bash

    # apt-get install dao-cn10k=24.09.0 dpdk-23.11-cn10k=24.07.0
    Reading package lists... Done
    Building dependency tree... Done
    Reading state information... Done
    The following NEW packages will be installed:
      dao-cn10k dpdk-23.11-cn10k
    0 upgraded, 2 newly installed, 0 to remove and 33 not upgraded.
    Need to get 0 B/309 MB of archives.
    After this operation, 0 B of additional disk space will be used.
    Selecting previously unselected package dpdk-23.11-cn10k.
    (Reading database ... 115644 files and directories currently installed.)
    Preparing to unpack .../dpdk-23.11-cn10k_24.07.0_arm64.deb ...
    Unpacking dpdk-23.11-cn10k (24.07.0) ...
    Selecting previously unselected package dao-cn10k.
    Preparing to unpack .../dao-cn10k_24.09.0_arm64.deb ...
    Unpacking dao-cn10k (24.09.0) ...
    Setting up dpdk-23.11-cn10k (24.07.0) ...
    Setting up dao-cn10k (24.09.0) ...

2. User can follow an interactive process using ``aptitude`` which gives suggestions
   and let user choose the version to downgrade the packages:

.. code-block:: bash

    # sudo apt-get install aptitude
    # aptitude install dao-cn10k=24.09.0
    The following NEW packages will be installed:
      dao-cn10k{b}
    0 packages upgraded, 1 newly installed, 0 to remove and 33 not upgraded.
    Need to get 39.0 MB of archives. After unpacking 0 B will be used.
    The following packages have unmet dependencies:
     dao-cn10k : Depends: dpdk-23.11-cn10k (= 24.07.0) but it is not going to be installed
    The following actions will resolve these dependencies:

         Keep the following packages at their current version:
    1)     dao-cn10k [Not Installed]

    Accept this solution? [Y/n/q/?] n
    The following actions will resolve these dependencies:

         Install the following packages:
    1)     dpdk-23.11-cn10k [24.07.0 (<NULL>)]

    Accept this solution? [Y/n/q/?] Y
    The following NEW packages will be installed:
      dao-cn10k dpdk-23.11-cn10k{a}
    0 packages upgraded, 2 newly installed, 0 to remove and 33 not upgraded.
    Need to get 309 MB of archives. After unpacking 0 B will be used.
    Do you want to continue? [Y/n/?] Y
    Get: 1 https://www.marvell.com/public/repo/octeon/dao/cn10k/ubuntu/v2204/release ./ dpdk-23.11-cn10k 24.07.0 [270 MB]
    Get: 2 https://www.marvell.com/public/repo/octeon/dao/cn10k/ubuntu/v2204/release ./ dao-cn10k 24.09.0 [39.0 MB]
    Fetched 309 MB in 46s (6,666 kB/s)
    Selecting previously unselected package dpdk-23.11-cn10k.
    (Reading database ... 115644 files and directories currently installed.)
    Preparing to unpack .../dpdk-23.11-cn10k_24.07.0_arm64.deb ...
    Unpacking dpdk-23.11-cn10k (24.07.0) ...
    Selecting previously unselected package dao-cn10k.
    Preparing to unpack .../dao-cn10k_24.09.0_arm64.deb ...
    Unpacking dao-cn10k (24.09.0) ...
    Setting up dpdk-23.11-cn10k (24.07.0) ...
    Setting up dao-cn10k (24.09.0) ...

    Current status: 35 (+2) upgradable.
