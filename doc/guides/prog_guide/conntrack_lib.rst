..  SPDX-License-Identifier: Marvell-MIT
    Copyright (c) 2025 Marvell.

******************
Conntrack Library
******************

Introduction
============

DAO-Conntrack is a high-performance, DPDK-based connection tracking
library. It is a user-space library built on top of DPDK (Data Plane Development Kit)
that replicates and extends the functionality of the Linux kernel's
Conntrack (Connection Tracking) subsystem. It monitors the state of network connections
(e.g., TCP, ICMP) by maintaining a connection table in memory. Designed for fast packet
processing, DAO-Conntrack enables stateful inspection, and advanced traffic
filtering at scale. Its DPDK-based architecture ensures low-latency, high-throughput
connection tracking suitable for modern, cloud-native, and data center environments.

.. _What_it_does:

What it does
============

DAO Conntrack is a stateful packet processing engine that:

* Tracks network connections (TCP, ICMP, etc.) in both directions.
* Maintains a hash-based connection table with fast lookups.
* Uses RCU (Read-Copy-Update) for safe, lock-free memory reclamation.
* Periodically cleans up expired connections in a background thread.
* Provides real-time statistics and connection dumps for observability.

.. _How_to_use_it:

How to use it
=============

Initialization
--------------

Call `dao_conntrack_init()` during application startup.

.. code-block:: c

   dao_conntrack_init(&qsbr_obj);

Packet Processing
-----------------

For each burst of packets:

.. code-block:: c

   dao_conntrack_execute(pkts, num_pkts, commit);

* `pkts`: Array of `rte_mbuf*`.
* `commit`: Whether to commit new connections to the table.

Connection Cleanup
------------------

Runs automatically in a background thread every ~200ms. You can also trigger it manually.

.. code-block:: c

   conn_cleanup();

Shutdown
--------

Call `dao_conntrack_fini()` to clean up.

.. code-block:: c

   dao_conntrack_fini();

Debugging & Monitoring
----------------------

Dump active connections:

.. code-block:: c

   dao_conntrack_dump();

Dump statistics:

.. code-block:: c

   dao_conntrack_stats_dump();
