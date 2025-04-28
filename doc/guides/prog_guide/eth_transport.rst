..  SPDX-License-Identifier: Marvell-MIT
    Copyright (c) 2025 Marvell.

**************************
Ethernet Transport Library
**************************

Ethernet transport library provides a set of APIs for managing hardware network accelerators and
pushing network packets to the hardware accelerators using DPDK. The library provides common APIs
which could be used by DAO libraries that uses ethernet as transport layer.

Architecture Overview
---------------------

The ethernet transport library abstracts 'rte_ethdev' library from DPDK and exposes only the
necessary functionality to the user.

API Usage
---------

#. **Initialize** the ethernet transport library using ``dao_eth_trs_init()``.
#. **Retrieve information** about the ethernet transport devices using ``dao_eth_trs_info()``.
#. **Allocate** the ethernet transport device using ``dao_eth_trs_dev_alloc()``.
#. **Configure** the ethernet transport device queues using ``dao_eth_trs_dev_queue_configure()``.
#. **Map queues** using ``dao_eth_trs_dev_queue_map()`` to get the actual ethernet port ID and
   queue ID corresponding to the transport device ID and queue ID.
#. **Start** the ethernet transport device using ``dao_eth_trs_dev_start()``.
#. **Transmit/Receive data** using ``dao_eth_trs_tx()`` and ``dao_eth_trs_rx()`` with the port ID
   and queue ID obtained from ``dao_eth_trs_dev_queue_map()``.
#. **Stop** the ethernet transport device using ``dao_eth_trs_dev_stop()``.
#. **Close** the ethernet transport device using ``dao_eth_trs_dev_free()``.
#. **Finalize** the ethernet transport library using ``dao_eth_trs_fini()``.

Transport Protocol
------------------

The ethernet transport library uses the DPDK ethernet interface. To minimize the overhead of
transport, the library uses the following format for the packet.

TRS header format
~~~~~~~~~~~~~~~~~

.. literalinclude:: ../../../lib/eth_transport/dao_eth_trs.h
   :language: c
   :start-after: Structure dao_eth_trs_hdr 8<
   :end-before: >8 End of structure dao_eth_trs_hdr.

TRS packet format
~~~~~~~~~~~~~~~~~

.. literalinclude:: ../../../lib/eth_transport/dao_eth_trs.h
   :language: c
   :start-after: Structure dao_eth_trs_pkt 8<
   :end-before: >8 End of structure dao_eth_trs_pkt.

Usage Restrictions
------------------

* The ethernet transport library's datapath APIs are intended for single-threaded environments.
  Concurrent access from multiple threads is not supported.
* Multi-segment packets are not supported by the library.
* Packet fragmentation and reassembly are not handled by the ethernet transport library.
* Features such as packet filtering and classification are not provided.
* Advanced offloading features, including checksum offloading and TCP segmentation offloading,
  are not supported.
* Flow control checks are not performed by the library. Users must ensure that hardware network
  accelerators are not overloaded.
