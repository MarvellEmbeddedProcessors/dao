..  SPDX-License-Identifier: Marvell-MIT
    Copyright (c) 2024 Marvell.

****************
Security Gateway
****************
``secgw-graph`` is a security gateway application based on rte_graph library
which provides IP and IPsec functionality.

Features
--------
 * DPDK rte_graph based fast path application integrated with LINUX control plane
 * Supports integration with Strongswan daemon for SA negotiations
 * Supports dynamic addition of IP routes (LPM based)
 * Supports dynamic updates of IPsec SA and policies on a per-port basis.
 * Leverages ARP and ICMP functionality from LINUX
 * Supports dynamic addition/deletion of ports forRQ polling in fast path
 * Supports IPv4 (but not IPv6 yet)

Setting up EP environment
-------------------------

Setup SDP PF/VF count in EBF menu
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Make sure that config is setup correctly in EBF menu for SDP VFs

Setup huge pages for DPDK application
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Setup enough hugepages and a mount point for the same in order for the dpdk-secgw-graph application
to run.

Bind required RPM VF's to vfio-pci
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Sample code to map CN10K ethdev's to vfio-pci.

.. code-block:: bash

   ETH_PF=0002:02:00.0
   ETH_PF_NAME=enP2p2s0
   VF_CNT=1

   dpdk-devbind.py -b rvu_nicpf $ETH_PF
   echo $VF_CNT > /sys/bus/pci/devices/$ETH_PF/sriov_numvfs

   ETH_VF=`lspci -d :a064 | awk -e '{print $1}'`

   dpdk-devbind.py -u $ETH_VF
   dpdk-devbind.py -b vfio-pci $ETH_V

Running the application
-----------------------

The application has number of command line options:

.. code-block:: console

   dpdk-secgw-graph [EAL Options] -- -s <CLI_SCRIPT_FILE> -i <Host IP address running app> -p <CLI Listening Port Number>

EAL Options
~~~~~~~~~~~

The following are the EAL command-line options that can be used in conjunction
with the ``dpdk-secgw-graph`` application.
See the DPDK Getting Started Guides for more information on these options.

*   ``-c <COREMASK>`` or ``-l <CORELIST>``

        Set the hexadecimal bitmask of the cores to run on. The corelist is a
        list of cores to use.

Application Options
~~~~~~~~~~~~~~~~~~~

The following are the application command-line options:

* ``-s <CLI Script file>``

        CLI script file supported by applications. Default: ``secgw.cli``

* ``-i <Host IP address running application>``

        IP address of host running this application

* ``-p <Listening Port Number>``

        UDP Port on which app is listening for CLI telnet connection

Example to run app
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Example to command to run ``dpdk-secgw-graph`` on 1 ethdev and 1 SDP dev port with two tap devices

.. code-block:: console

    dpdk-secgw-graph -a 0002:02:00.0 -a 0002:1f:00.2 -c 0xf000 -vdev=net_tap0 -vdev=net_tap1 -- -s ./app/secgw-graph/secgw.cli -i
    10.28.34.240 -p 50000

CLI terminal
~~~~~~~~~~~~
Connect to CLI terminal via telnet

.. code-block:: console

   telnet <Host IP running app>:<Listening Port Number>

Example

.. code-block:: console

   # telnet 10.28.34.240:50000
   Connected to 10.28.34.240:50000

          WELCOME to Security Gateway App!

   secgw-graph>
   secgw-graph>

Setting up Host environment
---------------------------
TBD

Performance Tuning on Host
~~~~~~~~~~~~~~~~~~~~~~~~~~
TBD
