..  SPDX-License-Identifier: Marvell-MIT
    Copyright (c) 2024 Marvell.

Running VPP L3 forward application
==================================

Prerequisites
-------------
a. Linux booted on x86 Host and Octeon DPU

b. Login to x-86 host and Octeon DPU

.. code-block:: console

   source dao-env.sh


DAO Environment Setup
---------------------
Following step is required to run only once after the first login to docker

.. code-block:: console

   ~# source /dao-env.sh


Steps to run on OCTEON DPU
--------------------------
1. Prepare vpp startup configuration file as below.

.. code-block:: console

   root@localhost:~#cat /etc/vpp/startup.conf
   unix
   {
     log /var/log/vpp/vpp.log
     cli-listen /run/vpp/cli.sock
     cli-no-pager
     full-coredump
   }
   socksvr
   {
     socket-name /run/vpp/api.sock
   }
   statseg
   {
     per-node-counters on
   }
   plugins
   {
     plugin default
     {
       disable
     }
     plugin dev_octeon_plugin.so
     {
       enable
     }
     plugin perfmon_plugin.so
     {
       enable
     }
   }
   cpu
   {
     main-core 1
     corelist-workers 2
   }
   buffers
   {
     buffers-per-numa 107520
   }
   devices
   {
     dev pci/0002:02:00.0
     {
       driver octeon
       port 0
       {
         name eth0
         num-tx-queues 16
         num-rx-queues 17
       }
     }
     dev pci/0002:03:00.0
     {
       driver octeon
       port 0
       {
         name eth1
         num-tx-queues 16
         num-rx-queues 17
       }
     }
   }

2. Bind vpp pktio interfaces to vfio-pci dpdk driver.

.. code-block:: console

   root@localhost:~#./dpdk-devbind.py -b vfio-pci 0002:02:00.0 0002:03:00.0

3. Run vpp

.. code-block:: console

   root@localhost:~# vpp -c /etc/vpp/startup.conf

4. Run vppctl and apply the vpp interface configurations.

.. code-block:: console

   root@localhost:~# vppctl
       _______    _        _   _____  ___
    __/ __/ _ \  (_)__    | | / / _ \/ _ \
    _/ _// // / / / _ \   | |/ / ___/ ___/
    /_/ /____(_)_/\___/   |___/_/  /_/
   vpp# show int

   Name               Idx    State  MTU (L3/IP4/IP6/MPLS)     Counter          Count
   eth0                1     down         9000/0/0/0
   eth1                2     down         9000/0/0/0
   local0              0     down          0/0/0/0
   vpp#
   vpp#set int state eth0 up
   vpp#set int state eth1 up
   vpp#set int ip address eth0 10.10.10.1/24
   vpp#set int ip address eth1 20.20.20.1/24
   vpp#ip neighbor eth0 10.10.10.2 0c:42:a1:67:d5:e7
   vpp#ip neighbor eth1 20.20.20.2 0c:42:a1:67:d5:e6


Steps to run on x-86 Host
-------------------------
1. Identify interfaces which are connected to Octeon DPU

.. code-block:: console

   root@localhost:~#ifconfig

2. Assign IP addresses to interfaces

.. code-block:: console

   root@localhost:~#ifconfig enp217s0f1np1 10.10.10.2/24 up
   root@localhost:~#ifconfig enp217s0f0np0 20.20.20.2/24 up

3. Install scapy traffic generator on x-86 host (If not already installed).

.. code-block:: console

   root@localhost:~#apt-get install scapy

4. Run scapy and send packets

.. code-block:: console

   root@localhost:~#scapy
   INFO: Can't import PyX. Won't be able to use psdump() or pdfdump().
   WARNING: No alternative Python interpreters found ! Using standard Python shell instead.
   INFO: Using the default Python shell: History is disabled.

                        aSPY//YASa
                apyyyyCY//////////YCa       |
               sY//////YSpcs  scpCY//Pp     | Welcome to Scapy
    ayp ayyyyyyySCP//Pp           syY//C    | Version 2.6.1
    AYAsAYYYYYYYY///Ps              cY//S   |
            pCCCCY//p          cSSps y//Y   | https://github.com/secdev/scapy
            SPPPP///a          pP///AC//Y   |
                 A//A            cyP////C   | Have fun!
                 p///Ac            sC///a   |
                 P////YCpc           A//A   | Craft packets like I craft my beer.
          scccccp///pSP///p          p//Y   |               -- Jean De Clerck
         sY/////////y  caa           S//P   |
          cayCyayP//Ya              pY/Ya
           sY/PsY////YCc          aC//Yp
            sc  sccaCY//PCypaapyCP//YSs
                     spCPY//////YPSps
                          ccaacs
   >>>sendp(Ether(dst="f2:b8:4c:4b:55:d9",src="0c:42:a1:67:d5:e7")/IP(src="10.10.10.2",dst="20.20.20.2",len=60)/UDP(dport=4000,sport=5000,len=40)/Raw(RandString(size=32)), iface="enp217s0f1np1", return_packets=True, count=10)
   ..........
   Sent 10 packets.
   <PacketList: TCP:0 UDP:10 ICMP:0 Other:0>
   >>>
   >>>sendp(Ether(dst="ee:bf:45:74:e9:12",src="0c:42:a1:67:d5:e6")/IP(src="20.20.20.2",dst="10.10.10.2",len=60)/UDP(dport=5000,sport=4000,len=40)/Raw(RandString(size=32)), iface="enp217s0f0np0", return_packets=True, count=10)
   ..........
   Sent 10 packets.
   <PacketList: TCP:0 UDP:10 ICMP:0 Other:0>
   >>>


Verify Traffic On Octeon DPU
----------------------------

.. code-block:: console

   root@localhost:~# vppctl
       _______    _        _   _____  ___
    __/ __/ _ \  (_)__    | | / / _ \/ _ \
    _/ _// // / / / _ \   | |/ / ___/ ___/
    /_/ /____(_)_/\___/   |___/_/  /_/

   vpp#
   vpp# show int
                 Name               Idx    State  MTU (L3/IP4/IP6/MPLS)     Counter          Count
   eth0                              1      up          9000/0/0/0     rx packets                    10
                                                                       rx bytes                     740
                                                                       tx packets                    10
                                                                       tx bytes                     740
                                                                       ip4                           10
   eth1                              2      up          9000/0/0/0     rx packets                    10
                                                                       rx bytes                     740
                                                                       tx packets                    10
                                                                       tx bytes                     740
                                                                       ip4                           10
   local0                            0     down          0/0/0/0
   vpp#
