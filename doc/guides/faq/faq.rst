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

How do I run DAO applications that rely on DPDK shared libraries?
-----------------------------------------------------------------

Some DAO applications rely on DPDK libraries compiled as shared objects.

To ensure these applications run correctly, you can either preload all required DPDK libraries or specify them on the command line:

**Option 1: Using LD_PRELOAD**

.. code-block:: bash

   export LD_PRELOAD="/lib/aarch64-linux-gnu/librte_acl.so \
   /lib/aarch64-linux-gnu/librte_argparse.so \
   /lib/aarch64-linux-gnu/librte_bbdev.so \
   /lib/aarch64-linux-gnu/librte_bitratestats.so \
   /lib/aarch64-linux-gnu/librte_bpf.so \
   /lib/aarch64-linux-gnu/librte_bus_pci.so \
   /lib/aarch64-linux-gnu/librte_bus_vdev.so \
   /lib/aarch64-linux-gnu/librte_cfgfile.so \
   /lib/aarch64-linux-gnu/librte_cmdline.so \
   /lib/aarch64-linux-gnu/librte_common_cnxk.so \
   /lib/aarch64-linux-gnu/librte_compressdev.so \
   /lib/aarch64-linux-gnu/librte_crypto_cnxk.so \
   /lib/aarch64-linux-gnu/librte_cryptodev.so \
   /lib/aarch64-linux-gnu/librte_dispatcher.so \
   /lib/aarch64-linux-gnu/librte_distributor.so \
   /lib/aarch64-linux-gnu/librte_dma_cnxk.so \
   /lib/aarch64-linux-gnu/librte_dmadev.so \
   /lib/aarch64-linux-gnu/librte_eal.so \
   /lib/aarch64-linux-gnu/librte_efd.so \
   /lib/aarch64-linux-gnu/librte_ethdev.so \
   /lib/aarch64-linux-gnu/librte_event_cnxk.so \
   /lib/aarch64-linux-gnu/librte_eventdev.so \
   /lib/aarch64-linux-gnu/librte_fib.so \
   /lib/aarch64-linux-gnu/librte_gpudev.so \
   /lib/aarch64-linux-gnu/librte_graph.so \
   /lib/aarch64-linux-gnu/librte_gro.so \
   /lib/aarch64-linux-gnu/librte_gso.so \
   /lib/aarch64-linux-gnu/librte_hash.so \
   /lib/aarch64-linux-gnu/librte_ip_frag.so \
   /lib/aarch64-linux-gnu/librte_ipsec.so \
   /lib/aarch64-linux-gnu/librte_jobstats.so \
   /lib/aarch64-linux-gnu/librte_kvargs.so \
   /lib/aarch64-linux-gnu/librte_latencystats.so \
   /lib/aarch64-linux-gnu/librte_log.so \
   /lib/aarch64-linux-gnu/librte_lpm.so \
   /lib/aarch64-linux-gnu/librte_mbuf.so \
   /lib/aarch64-linux-gnu/librte_member.so \
   /lib/aarch64-linux-gnu/librte_mempool.so \
   /lib/aarch64-linux-gnu/librte_mempool_cnxk.so \
   /lib/aarch64-linux-gnu/librte_mempool_ring.so \
   /lib/aarch64-linux-gnu/librte_meter.so \
   /lib/aarch64-linux-gnu/librte_metrics.so \
   /lib/aarch64-linux-gnu/librte_ml_cnxk.so \
   /lib/aarch64-linux-gnu/librte_mldev.so \
   /lib/aarch64-linux-gnu/librte_net.so \
   /lib/aarch64-linux-gnu/librte_net_cnxk.so \
   /lib/aarch64-linux-gnu/librte_net_ring.so \
   /lib/aarch64-linux-gnu/librte_net_tap.so \
   /lib/aarch64-linux-gnu/librte_node.so \
   /lib/aarch64-linux-gnu/librte_pcapng.so \
   /lib/aarch64-linux-gnu/librte_pci.so \
   /lib/aarch64-linux-gnu/librte_pdcp.so \
   /lib/aarch64-linux-gnu/librte_pdump.so \
   /lib/aarch64-linux-gnu/librte_pipeline.so \
   /lib/aarch64-linux-gnu/librte_port.so \
   /lib/aarch64-linux-gnu/librte_power.so \
   /lib/aarch64-linux-gnu/librte_rawdev.so \
   /lib/aarch64-linux-gnu/librte_rcu.so \
   /lib/aarch64-linux-gnu/librte_regexdev.so \
   /lib/aarch64-linux-gnu/librte_reorder.so \
   /lib/aarch64-linux-gnu/librte_rib.so \
   /lib/aarch64-linux-gnu/librte_ring.so \
   /lib/aarch64-linux-gnu/librte_sched.so \
   /lib/aarch64-linux-gnu/librte_security.so \
   /lib/aarch64-linux-gnu/librte_stack.so \
   /lib/aarch64-linux-gnu/librte_table.so \
   /lib/aarch64-linux-gnu/librte_telemetry.so \
   /lib/aarch64-linux-gnu/librte_timer.so \
   /lib/aarch64-linux-gnu/librte_vhost.so"

Make sure the libraries are installed at ``/lib/aarch64-linux-gnu/``, or update the paths accordingly.

**Option 2: Using the -d Flag**

Alternatively, if you do not wish to preload every library, you can specify the needed DPDK libraries individually using the ``-d`` parameter.