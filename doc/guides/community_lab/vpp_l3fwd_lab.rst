..  SPDX-License-Identifier: Marvell-MIT
    Copyright (c) 2024 Marvell.

Running VPP L3 forward application
==================================

Prerequisites
-------------
a. Linux booted on x86 Host and Octeon DPU

b. Login to x-86 host and Octeon DPU

DAO Environment Setup
---------------------
DAO should be preinstalled as given in below link.
`Downloading and installing DAO packages <https://marvellembeddedprocessors.github.io/dao/guides/gsg/install.html>`_


Steps to run on OCTEON DPU
--------------------------
1. Prepare vpp startup configuration file as below.
   This is the minimal startup.conf required to start vpp octeon plugin with 2 devices (see plugin and devices section).
   NOTE: Default vpp configuration file is placed at /etc/vpp/startup.conf path.

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

   ## Identify devices using below command
   root@localhost:~# lspci | grep "Octeon Tx2 RVU Physical Function"
   0002:02:00.0 Ethernet controller: Cavium, Inc. Octeon Tx2 RVU Physical Function (rev 54)
   0002:03:00.0 Ethernet controller: Cavium, Inc. Octeon Tx2 RVU Physical Function (rev 54)
   0002:04:00.0 Ethernet controller: Cavium, Inc. Octeon Tx2 RVU Physical Function (rev 54)
   0002:05:00.0 Ethernet controller: Cavium, Inc. Octeon Tx2 RVU Physical Function (rev 54)
   root@localhost:~#

   ## Identify interface nake corresponding to each device (see if=<interface name>)
   root@localhost:~# dpdk-devbind.py -s | grep 0002:02:00.0
   0002:02:00.0 'Octeon Tx2 RVU Physical Function a063' numa_node=0 if=enP2p2s0 drv=rvu_nicpf unused=vfio-pci
   root@localhost:~#

   ## Identify link speed and link status
   root@localhost:~# ethtool enP2p2s0 | grep -iE "Speed|Link detected"
           Speed: 25000Mb/s
           Link detected: yes
   root@localhost:~#

   ## From above detail this link is 25GBPS and status is "yes", so I can use this.
   ## Perform similar check for other devices.
   ## Identified 2 devices (0002:02:00.0 0002:03:00.0)
   ## Bind these 2 devices to vfio-pci driver.
   ## Update these device PCI addresses in startup.conf.
   root@localhost:~# dpdk-devbind.py -b vfio-pci 0002:02:00.0 0002:03:00.0

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

   ## MAC addresses 0c:42:a1:67:d5:e7 and 0c:42:a1:67:d5:e7 are taken from x-86 interfaces.(Refer section 1.4.1)

   ## To see the MAC addresses of VPP interfaces run below command in vppctl and check Ethernet address(MAC).

   vpp#DBGvpp# show hardware-interfaces eth0
                 Name                Idx   Link  Hardware
   eth0                               1    down  eth0
     Link speed: unknown
     Ethernet address a2:6e:ed:21:b4:9e
     Device:
       Driver is 'octeon', bus is 'pci', description is 'Marvell Octeon Resource Virtualization Unit PF'
       PCIe address is 0002:02:00.0, port is P0, speed is unknown speed x0 (max unknown speed x0)
       Assigned process node is 'pci/0002:02:00.0-process'
       Device Specific Arguments:
         Name     Value   Default Description
         n_desc <not set>   16384 number of cpt descriptors, applicable to cpt devices only
     Port 0:
       Hardware Address is a2:6e:ed:21:b4:9e, 1 RX queues (max 64), 2 TX queues (max 64)
       Max RX frame size is 16380 (max supported 16380)
       Caps: rss
       RX Offloads: ip4-cksum
       TX Offloads: ip4-cksum
       Device Specific Port Status:

       Device Specific Port Arguments:
         Name              Value   Default Description
         allmulti        <not set>       0 Set allmulti mode, applicable to network devices only
         eth_pause_frame <not set>       0 Enable ethernet pause frame support, applicable to network devices only
         switch_header   <not set>      '' Enable switch header and set specific switch header type, applicable to network devices only
       Interface assigned, interface name is 'eth0', RX node is 'eth0-rx'
       RX queue 0:
         Size is 1024, buffer pool index is 0
         Polling thread is 1, enabled, not-started, polling mode

       TX queue 0:
         Size is 1024
         Used by thread 0

       TX queue 1:
         Size is 1024
         Used by thread 1

   vpp#


Steps to run on x-86 Host
-------------------------
1. Identify interfaces which are connected to Octeon DPU

.. code-block:: console

   ## Identify devices
   root@transport-2:~# lspci | grep Mellanox
   5e:00.0 Ethernet controller: Mellanox Technologies MT28800 Family [ConnectX-5 Ex]
   5e:00.1 Ethernet controller: Mellanox Technologies MT28800 Family [ConnectX-5 Ex]
   b1:00.0 Ethernet controller: Mellanox Technologies MT27700 Family [ConnectX-4]
   b1:00.1 Ethernet controller: Mellanox Technologies MT27700 Family [ConnectX-4]
   d9:00.0 Ethernet controller: Mellanox Technologies MT28800 Family [ConnectX-5 Ex]
   d9:00.1 Ethernet controller: Mellanox Technologies MT28800 Family [ConnectX-5 Ex]
   root@transport-2:~#

   ## Identify interface name (see if=<Interface name>)
   root@transport-2:~# dpdk-devbind.py -s | grep d9:00.1
   0000:d9:00.1 'MT28800 Family [ConnectX-5 Ex] 1019' numa_node=1 if=enp217s0f1np1 drv=mlx5_core unused=vfio-pci *Active*
   root@transport-2:~#

   ## Identify link speed and link status
   root@transport-2:~# ethtool enp217s0f1np1 | grep -iE "Speed|Link detected"
        Speed: 25000Mb/s
        Link detected: yes
   root@transport-2:~#

   ## Identify MAC address
   root@transport-2:~# ifconfig enp217s0f1np1 | grep ether
        ether 0c:42:a1:67:d5:e7  txqueuelen 1000  (Ethernet)
   root@transport-2:~#

   ## Identified interfaces are enp217s0f1np1 and enp217s0f0np0

   NOTE: To confirm links on both x-86 and Octeon side, verify using ping.
   For example:
      Interface on Octeon : enP2p2s0
      Interface on x-86   : enp217s0f0np0
   Assign IP address to both interfaces in same subnet.
   #ifconfig enP2p2s0 20.20.20.1/24 up
   #ifconfig enp217s0f0np0 20.20.20.2/24 up
   Ping each other and verify link connectivity.

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

   ## Destination MACs are taken from vpp eth0 and eth1 interfaces. (f2:b8:4c:4b:55:d9 and ee:bf:45:74:e9:12). (Refer section 1.3.4)

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
