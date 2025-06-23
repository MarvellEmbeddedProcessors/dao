..  SPDX-License-Identifier: Marvell-MIT
    Copyright (c) 2025 Marvell.

Conntrack-Based Applications
****************************

This section highlights example applications built using the conntrack library, used for tracking and
managing the state of network connections. It provides developers and network engineers
with the ability to observe, control, and optimize how connections are handled
across various layers of the networking stack.

Conntrack Functional Test
=========================

The 'dao-ct-func' application verifies the basic operations of the Conntrack subsystem, such as creation, maintenance,
and teardown of connection entries. Ensures that connection states transition correctly
and that packet flows are properly tracked and handled.

.. code-block:: console

    ~# ./dao-ct-func <pcap_file_path>
    Expiration: 30.000021 [ORIG] saddr: 10.28.35.178 sport: 512 daddr: 10.28.35.175 dport: 512
    [REV] saddr: 10.28.35.175 sport: 512 daddr: 10.28.35.178 dport: 512 proto: 1
    Expiration: 30.000021 [ORIG] saddr: 10.28.35.178 sport: 2304 daddr: 10.28.35.177 dport: 2304
    [REV] saddr: 10.28.35.177 sport: 2304 daddr: 10.28.35.178 dport: 2304 proto: 1
    Expiration: 86400.000000 [ORIG] saddr: 10.28.36.157 sport: 59112 daddr: 10.28.35.178 dport: 22
    [REV] saddr: 10.28.35.178 sport: 22 daddr: 10.28.36.157 dport: 59112 proto: 6
    Expiration: 86400.000000 [ORIG] saddr: 10.28.35.178 sport: 709 daddr: 10.28.36.157 dport: 2049
    [REV] saddr: 10.28.36.157 sport: 2049 daddr: 10.28.35.178 dport: 709 proto: 6
    ct-pkts: 100
    conn-lookup-fail: 1
    Conntrack add success


Conntrack Core Scalability Test
===============================

The 'dao-ct-scalability' application evaluates how effectively the Conntrack subsystem scales with an increasing
number of CPU cores.

.. code-block:: console

    ~# ./dao-ct-scalability <DPDK EAL args>
    Starting mainloop on core 1
    Starting mainloop on core 2
    dump_conntrack
    Connectrack start. Lcore: 1
    ct-pkts: 513
    Connectrack start. Lcore: 2
    ct-pkts: 1026

* -l 0-3: Launches logical cores 0 to 3 (ensure at least 2-3 worker cores).
* -n 4: Specifies number of memory channels (adjust as per system configuration).

The program uses DPDK's EAL and assumes multiple worker cores to simulate
concurrent packet processing.

Conntrack Connection Per Second (CPS) Test
==========================================

The 'dao-ct-load' application measures the number of new connections the Conntrack subsystem can handle per second.
It helps assess the traffic load Conntrack can sustain, which is critical for high-throughput
environments like data centers or firewalls.

**On DUT (Device Under Test):**

1. Bind two devices to a DPDK-compatible driver (e.g., `vfio-pci`, `uio_pci_generic`, or `igb_uio`)
   using the `dpdk-devbind.py` script:

   .. code-block:: console

       ~# sudo dpdk-devbind.py --bind=vfio-pci <PCI_DEVICE_ID 1>
       ~# sudo dpdk-devbind.py --bind=vfio-pci <PCI_DEVICE_ID 2>

2. Execute the test with the appropriate DPDK EAL arguments:

   .. code-block:: console

       ~# ./dao-ct-load <DPDK EAL args>
       [lcore  2] DAO_INFO: Conntrack object already initialized.
       [lcore  3] DAO_INFO: Conntrack object already initialized.
       [lcore  4] DAO_INFO: Conntrack object already initialized.
       Core 2 [Queue 0]: RX=1000 TX=1000 DROP=0
       Core 2 [Queue 1]: RX=2000 TX=2000 DROP=0
       Core 2 [Queue 2]: RX=182 TX=182 DROP=0
       Core 3 [Queue 0]: RX=4243 TX=4232 DROP=0
       Core 3 [Queue 1]: RX=2324 TX=2324 DROP=0
       Core 3 [Queue 2]: RX=2445 TX=2445 DROP=0
       Core 4 [Queue 0]: RX=1000 TX=1000 DROP=0

   *Note:* Ensure this is **running and fully initialized** before starting TRex to guarantee correct packet processing.


**On TRex:**

1. Navigate to the TRex scripts directory and run the test:

   .. code-block:: console

       ~# cd trex/scripts/
       ~# sudo ./t-rex-64 -f cap2/http_simple.yaml -m "Packet Rate" -c 1 -d 20

2. Start with lower traffic and gradually increase the load until packet drops are observed.

3. Identify the optimal combination of **Set CPS** and **Packet Rate** to achieve the maximum sustainable connection rate.

   *Note:* The **Set CPS** is defined in the `cap2/http_simple.yaml` file.

