..  SPDX-License-Identifier: Marvell-MIT
    Copyright (c) 2024 Marvell.

************************************
FD.io Vector Packet Processing (VPP)
************************************

What is VPP?
============
Vector Packet Processing (VPP) is an open-source framework developed under the FD.io (Fast Data project) umbrella. It is designed to offer high-performance packet processing capabilities. VPP uses vector processing techniques to handle multiple packets simultaneously, enhancing throughput and reducing latency. The framework is renowned for its modularity, flexibility, and ability to manage various network functions and protocols.

VPP Accelerations
=================
VPP offers several accelerations, primarily through vector processing and efficient utilization of CPU cache and memory. Key aspects include:

- **Vector Processing:** Processes packets in batches (vectors) rather than individually, leveraging modern CPU architecture for parallel processing.

- **Cache Efficiency:** Optimizes data structures and algorithms to minimize cache misses, thereby improving performance.

- **Memory Management:** Employs efficient memory allocation and deallocation techniques to reduce overhead.

- **Plugin Architecture:** Supports the integration of various plugins to accommodate different network functions and protocols.

- **IPsec and Crypto Accelerations:** VPP supports both hardware and software accelerations for IPsec, utilizing crypto acceleration hardware when available.

Marvell's High-Performance VPP for OCTEON
=========================================
Marvell's VPP leverages OCTEON's specialized workloads to provide a high-performance VPP stack. The specialized accelerations include:

- **Packet I/O Accelerations:** Enhancements for packet input, output, checksum calculations, and RSS. VPP can be optimized to run on Marvell’s Octeon processors, which are designed for high-performance networking and security applications.

- **Packet Parsing and Classifications:** Programmable parser and classifier that can offload and extend vnet-flow.

- **Crypto Accelerations:** High-performance cryptographic accelerator to offload all cryptographic operations from VPP's crypto layer.

- **Inline IPsec:** Very high-performance inline IPsec implementation that can offload the complete IPsec protocol to OCTEON's cryptographic accelerators.

- **Inline Traffic Management:** Inline traffic shaping and scheduling hardware that can perform inline QoS at line rates.

Installing and Running VPP for Packet I/O Acceleration Demo
-----------------------------------------------------------

.. raw:: html
  :file: ../_static/demo/vpp_pktio.html


Running VPP for Crypto offload Demo
-----------------------------------

.. raw:: html
  :file: ../_static/demo/vpp_crypto_offload.html


VPP FD.io Documentation
-----------------------
Comprehensive open-source documentation for VPP release 24.02 is available at the following link.
`FD.io's VPP documentation for 24.02 release <https://s3-docs.fd.io/vpp/24.02/>`_

VPP Usage and Integrations
==========================
VPP is used in various high-performance networking applications, including routers, switches, firewalls, and load balancers. Other applications can integrate with VPP through several interfaces:

- **CLI (Command Line Interface):** Provides an interactive shell for configuration and management.

- **VPP API:** Allows external applications to interact with VPP programmatically.

- **VPP Graph Nodes:** Developers can create custom processing nodes within the VPP graph to extend functionality.

- **Memif (Memory Interface):** A high-performance, shared-memory-based packet I/O mechanism for communication between VPP and other applications.

- **VPP's Plugin System:** Enables the addition of new features and protocols without modifying the core code.

- **Sockets Using LD_PRELOAD:** VPP can intercept and accelerate socket operations via the ``LD_PRELOAD`` mechanism, which allows it to replace standard socket library functions with optimized versions.

- **Other Integrations:** VPP can integrate with various other systems and applications, providing APIs and interfaces for seamless communication and interoperability. Examples include:

  - **Kubernetes and Docker:** VPP can be used in containerized environments to provide high-performance networking for microservices.
  - **OpenStack:** VPP can integrate with OpenStack to enhance network functions virtualization (NFV) performance.
  - **gRPC:** VPP can be accessed and managed via gRPC, allowing integration with cloud-native applications.
  - **P4 Runtime:** VPP can interact with P4-programmable devices, providing a flexible data plane programming model.
  - **Linux Control Plane Integration:** VPP can be integrated with the Linux control plane to manage networking and leverage existing Linux networking tools and configurations.

Compiling VPP from sources
==========================

.. note::
 Follow the steps to :doc:`compile VPP from sources. <../howtoguides/vpp>`

Enhancing VPP IPsec offload with Strongswan Integration
=======================================================
The purpose of introducing Linux XFRM netlink support in the linux_nl_plugin is to mirror Linux XFRM configurations to the VPP IPsec subsystem. These configurations can be manually set using ip commands or via keying daemons like StrongSwan. In both cases, the netlink notifications generated from Linux are read by this XFRM module and translated into VPP's IPsec configuration.
 - The XFRM node piggybacks on the libnl-xfrm system library for parsing/extracting netlink messages.
 - The XFRM node will support both policy-based and tunnel/route-based IPsec. The mode can be selected via startup.conf
 - The XFRM module supports packet and byte-based soft life and hard life expiry as the datapath will be handled in VPP.

Strongswan Integration
----------------------
StrongSwan is an open-source IPsec-based VPN solution that provides robust security and encryption capabilities. By integrating StrongSwan with VPP, users can leverage StrongSwan's keying daemon to manage IPsec configurations and policies, which are then mirrored to VPP's IPsec subsystem via the XFRM module. This integration enhances VPP's IPsec offload capabilities and simplifies the management of IPsec configurations. Below figure illustrates the integration of StrongSwan with VPP for IPsec offload.

   .. figure:: ./img/sswan_integration.png

The above diagram illustrates how linux-cp plugin and xfrm module of linux_nl plugin interact with the StrongSwan keying daemon and kernel to mirror IPsec configurations to VPP's IPsec subsystem. The IKE messages are flowing between StrongSwan and VPP's IPsec subsystem with help of linux-cp plugin. To route IKE messages from the network adaptor owned by VPP to strongswan, we create linux-cp instance, which binds the mirror interfaces pair(tap interface).When an IKE message is received by VPP through RPM port, it will be routed to the kernel through the Tun/Tap port and is processed by the Linux kernel stack before being passed to StrongSwan and vice versa.

If the SA is negotiated successfully, StrongSwan will configure the IPsec SA's in the Linux kernel. The XFRM module in VPP will read the netlink messages generated by the Linux kernel and mirror the IPsec configurations to VPP's IPsec subsystem. This integration allows users to manage IPsec configurations using StrongSwan while benefiting from VPP's high-performance IPsec offload capabilities.

Note: Strongswan support for Inline IPsec is available as an early access feature and is currently experimental.

Configuring VPP IPsec route mode or policy mode
-----------------------------------------------
The XFRM module in VPP supports both policy-based and tunnel/route-based IPsec configurations. The mode can be selected via the startup.conf file. The following configuration options are available:

.. code-block:: text

  linux-xfrm-nl{
    # Following parameter enables route mode IPsec.
    enable-route-mode-ipsec,
    # Specifies Ipsec interface type "ipsec" or "ipip".
    interface <"interface_type">,
    # Set the RX buffer size to be used on the netlink socket.
    nl-rx-buffer-size <>,
    # Set the batch size - maximum netlink messages to process at one time.
    nl-batch-size <>,
    # Set the batch delay - how long to wait in ms between processing batches.
    nl-batch-delay-ms <>
  }

If the `enable-route-mode-ipsec` parameter is set to true, the XFRM module will operate in route mode IPseci otherwise, it defaults to policy mode.The `interface` parameter specifies the IPsec interface type, which can be either "ipsec" or "ipip". The `nl-rx-buffer-size` parameter sets the RX buffer size to be used on the netlink socket, while the `nl-batch-size` and `nl-batch-delay-ms` parameters control the batch processing behavior. For inline IPsec offload on OCTEON 10, interface type should be set to "ipsec".

VPP startup.conf configuration and CLI commands
-----------------------------------------------
The following configuration options can be set in the startup.conf file to enable the XFRM module and configure the IPsec mode:

.. code-block:: text

  unix {
     log /var/log/vpp/vpp.log
     cli-listen /run/vpp/cli.sock
  }

  cpu {
     main-core 1
     corelist-workers 7-8
  }

  socksvr { socket-name /tmp/vpp-api.sock }

  buffers {
     ## Increase number of buffers allocated, needed only in scenarios with
     ## large number of interfaces and worker threads. Value is per numa node.
     ## Default is 16384 (8192 if running unprivileged)
     buffers-per-numa 128000

     ## Size of buffer data area
     ## Default is 2048
     default data-size 2048
  }

  linux-xfrm-nl {
    enable-route-mode-ipsec
    interface ipsec
  }

  devices {
     dev pci/0002:02:00.0
     {
       driver octeon
       port 0
        {
          name eth0
          num-rx-queues 4
          num-tx-queues 5
        }
     }

     dev pci/0002:03:00.0
     {
       driver octeon
       port 0
        {
          name eth1
          num-rx-queues 5
          num-tx-queues 6
        }
     }

     dev pci/0002:20:00.1
     {
       driver octeon
     }
  }

  plugins {
    path /usr/lib/vpp_plugins
    plugin dpdk_plugin.so { disable }
    plugin dev_octeon_plugin.so { enable }
    plugin linux_cp_plugin.so { enable }
    plugin linux_nl_plugin.so { enable }
  }

  logging {
    ## set default logging level for logging buffer
    ## logging levels: emerg, alert,crit, error, warn, notice, info, debug, disabled
    default-log-level info
    ## set default logging level for syslog or stderr output
    default-syslog-log-level info
    ## Set per-class configuration
    # class dpdk/cryptodev { rate-limit 100 level debug syslog-level error }
  }

VPP CLI commands:

.. code-block:: text

    ~# vppctl set int ip address eth1 60.60.60.1/24
    ~# vppctl set int state eth0 up
    ~# vppctl set int promiscuous on eth0
    ~# vppctl lcp create eth0 host-if lcp1

Linux CLI commands:

.. code-block:: text

  ~# ifconfig lcp1 70.70.70.1/24 up

Strongswan configuration on DPU
-------------------------------
Enable make_before_break for IKEv2 reauthentication in charon.conf. This setting creates new SAs before tearing down old ones, avoiding traffic interruptions,

charon.conf:

.. code-block:: text

  charon {
      .....
      # Initiate IKEv2 reauthentication with a make-before-break scheme.
      make_before_break = yes
      .....
  }

ipsec.conf :

.. code-block:: text

  # /etc/ipsec.conf - Openswan IPsec configuration file
  # This file:  /usr/share/doc/openswan/ipsec.conf-sample
     #
     # Manual:     ipsec.conf.5
     version 2.0     # conforms to second version of ipsec.conf specification
     config setup
             charondebug="all"
             strictcrlpolicy=no
             uniqueids=yes
             cachecrls=no

     conn tunnel-dpu1-dpu2
           mobike=no
           type=tunnel
           leftauth=psk
           rightauth=psk
           auto=start
           keyexchange=ikev2
           authby=secret
           aggressive=no
           keyingtries=%forever
           rekey=yes
           ikelifetime=28800s
           lifetime=3600s
           # Once the specified number of lifepackets has been processed, the SAs will be reestablished.
           # lifepackets=0
           left=70.70.70.1
           leftsubnet=60.60.60.0/24
           right=70.70.70.2
           rightsubnet=80.80.80.0/24
           ike=aes256-sha1-modp2048!
           esp=aes192-sha1-esn!
           replay_window=32

ipsec.secrets :

.. code-block:: text

 ~# cat /etc/ipsec.secrets
  # ipsec.secrets - strongSwan IPsec secrets file
  : PSK "Marvelldpu"

Strongswan configuration on remote DPU/Host:
--------------------------------------------

ipsec.conf :

.. code-block:: text

  # /etc/ipsec.conf - Openswan IPsec configuration file
  # This file:  /usr/share/doc/openswan/ipsec.conf-sample
  # Manual:     ipsec.conf.5
  version 2.0     # conforms to second version of ipsec.conf specification
  config setup
          charondebug="all"
          strictcrlpolicy=no
          uniqueids=yes
          cachecrls=no

  conn %default
          ike=aes256-sha1-modp2048!
          esp=aes192-sha1-esn!
          keyexchange=ikev2
          mobike=no

  conn tunnel-dpu2-dpu1
        type=tunnel
        auto=start
        leftauth=psk
        rightauth=psk
        aggressive=no
        keyingtries=%forever
        ikelifetime=24h
        lifetime=3600s
        # Once the specified number of lifepackets has been processed, the SAs will be reestablished.
        # lifepackets=0
        rekey=yes
        left=70.70.70.2
        leftsubnet=80.80.80.0/24
        right=70.70.70.1
        rightsubnet=60.60.60.0/24
        replay_window=32

ipsec.secrets :

.. code-block:: text

 ~# cat /etc/ipsec.secrets
  # ipsec.secrets - strongSwan IPsec secrets file
  : PSK "Marvelldpu"

Ipsec Linux commands
--------------------
.. code-block:: text

  # On both DPU and HOST
  ipsec start
  ipsec statusall
  ipsec stop

Host Offload to OCTEON DPU Via Virtio Interface over PCIe
=========================================================
The Virtio interface is a virtualized network interface that allows communication between the host and the DPU. The Virtio interface is used to offload IPsec processing from the host to the DPU, leveraging the DPU's high-performance IPsec offload capabilities.
Introducing VPP OCTEON virtio plugin for Host IPsec offload, supporting packet input and output to and from the HOST virtio interface over PCIe, with the Marvell OCTEON SoC operating in endpoint mode. This plugin uses Marvell DAO library to communicate with the HOST device.
An alternate way for Host-OCTEON communication is using the SDP interface. The primary difference is that SDP interfaces utilize NIX device bandwidth, thereby limiting the device to 50Gbps when used in endpoint NIC mode. In contrast, by using the Virtio plugin, OCTEON can function as a 100Gbps NIC.

Below figure illustrates the Host-OCTEON communication via the Virtio interface over PCIe:

   .. figure:: ./img/host_offload_via_virtio_interface.png

Configuring OCTEON DPU
----------------------
The following steps outline the configuration and setup of the Virtio interface for Host offload:

Configure DMA and NPA devices on OCTEON
+++++++++++++++++++++++++++++++++++++++

.. code-block:: text

  # Determine DMA/DPI device on OCTEON.

  # lspci -d 177d:a080:0880
  0000:06:00.0 System peripheral: Cavium, Inc. Device a080

  # Bind and Create (2 + 2 * number of workers) DMA devices.

  echo 0000:06:00.0 > /sys/bus/pci/devices/0000:06:00.0/driver/unbind
  echo octeontx2-dpi > /sys/bus/pci/devices/0000:06:00.0/driver_override
  echo 0000:06:00.0 > /sys/bus/pci/drivers_probe
  echo 32 >/sys/bus/pci/devices/0000:06:00.0/sriov_numvfs

  # Determine NPA PCI on OCTEON and bind to vfio-pci.
  #lspci -d 177d:a0fb:0880

  0002:17:00.0 System peripheral: Cavium, Inc. Device a0fb (rev 54)
  echo 0002:17:00.0 > /sys/bus/pci/devices/0002:17:00.0/driver/unbind
  echo 177d a0fb > /sys/bus/pci/drivers/vfio-pci/new_id
  oecho 0002:17:00.0 > /sys/bus/pci/drivers/vfio-pci/bind

  # Bind platform devices pem0-bar4-mem and dpi_sdp_regs to vfio-platform if available

  echo "vfio-platform" | sudo tee "/sys/bus/platform/devices/\*pem0-bar4-mem/driver_override" > /dev/null
  echo "\*pem0-bar4-mem" | sudo tee "/sys/bus/platform/drivers/vfio-platform/bind" > /dev/null
  echo "vfio-platform" | sudo tee "/sys/bus/platform/devices/\*dpi_sdp_regs/driver_override" > /dev/null
  echo "\*dpi_sdp_regs" | sudo tee "/sys/bus/platform/drivers/vfio-platform/bind" > /dev/null
  Note: Replace * with actual runtime address attached with platform device.

  # Bind RVU SDP devices to vfio-pci if above platform devices are not present.
  echo 1 > /sys/bus/pci/devices/0002\:19\:00.0/remove
  echo 1 > /sys/bus/pci/devices/0002\:18\:00.0/remove
  echo 1 > /sys/bus/pci/rescan
  echo 177d a0fe > /sys/bus/pci/drivers/vfio-pci/new_id
  echo 0002:18:00.0 > /sys/bus/pci/drivers/vfio-pci/bind
  echo 0002:19:00.0 > /sys/bus/pci/drivers/vfio-pci/bind

VPP Configuration
+++++++++++++++++
VPP virtio device bringup with OCTEON virtio plugin is possible either through vppctl commands or startup conf.This plugin takes following device arguments for the first device attach. And the arguments passed on next devices are ignored.
``nb_virtio`` - Max number of virtio devices will be configured.
``dma`` - List of all DMA devices.
``enable_csum_offld`` - Enable checksum offload.
``misc`` - List of all miscellaneous devices (example NPA device).
Number of DMA devices needed is calculated as:
2 (for control) + 2 (for virtio service thread) + 2 x (number of workers)

Through Virtio device configuration in startup.conf:

Sample startup.conf file for OCTEON virtio plugin:

.. code-block:: text

  unix {
     log /var/log/vpp/vpp.log
     cli-listen /run/vpp/cli.sock
  }

  plugins {
    path /usr/lib/vpp_plugins
    plugin dpdpk_plugin.so { disable }
    plugin dev_octeon_virtio_plugin.so { enable }
  }

  cpu {
      main-core 1
      corelist-workers 8-9
      corelist-virtio-ctrl 7
  }

  devices {
     dev virtio/0
     {
       driver octeon_virtio
       port 0
        {
          name eth0
          num-rx-queues 4
          num-tx-queues 5
        }
       args 'nb_virtio=1,dma=\"0000:06:00.1,0000:06:00.2,0000:06:00.3,0000:06:00.4,0000:06:00.5,0000:06:00.6,0000:06:00.7,0000:06:01.1,0000:06:01.2,0000:06:01.3\",misc=\"0002:17:00.0\"'
     }
  }

  logging {
    ## set default logging level for logging buffer
    ## logging levels: emerg, alert,crit, error, warn, notice, info, debug, disabled
    default-log-level info
    ## set default logging level for syslog or stderr output
    default-syslog-log-level info
    ## Set per-class configuration
    # class dpdk/cryptodev { rate-limit 100 level debug syslog-level error }
  }

Through vppctl commands:

Sample startup.conf file:

.. code-block:: text

  unix {
     log /var/log/vpp/vpp.log
     cli-listen /run/vpp/cli.sock
  }

  plugins {
    path /usr/lib/vpp_plugins
    plugin dpdpk_plugin.so { disable }
    plugin dev_octeon_virtio_plugin.so { enable }
  }

  cpu {
      main-core 1
      corelist-workers 8-9
      corelist-virtio-ctrl 7
  }

  logging {
    ## set default logging level for logging buffer
    ## logging levels: emerg, alert,crit, error, warn, notice, info, debug, disabled
    default-log-level info
    ## set default logging level for syslog or stderr output
    default-syslog-log-level info
    ## Set per-class configuration
    # class dpdk/cryptodev { rate-limit 100 level debug syslog-level error }
  }

Launch VPP with startup.conf:

.. code-block:: text

  vpp -c /etc/vpp/startup.conf

VPP CLI Commands:

.. code-block:: text

  vppctl -s /run/vpp/cli.sock

  vppctl device attach virtio/0 driver octeon_virtio args nb_virtio=1,dma=\"0000:06:00.1,0000:06:00.2,0000:06:00.3,0000:06:00.4,0000:06:00.5,0000:06:00.6,0000:06:00.7,0000:06:01.1,0000:06:01.2,0000:06:01.3\",misc=\"0002:17:00.0\"
  vppctl device create-interface virtio/0  port 0 num-rx-queues 2 num-tx-queues 3
  vppctl device attach virtio/1 driver octeon_virtio
  vppctl device create-interface virtio/1  port 1 num-rx-queues 2 num-tx-queues 3

HOST Configuration
++++++++++++++++++

.. code-block:: text

  modprobe vfio-pci
  modprobe vdpa
  modprobe virtio_vdpa
  modprobe virtio_net
  insmod octep_vdpa_pci.ko
  SDP_PF=`lspci -Dn -d :b900 | head -1 | cut -f 1 -d " "`
  VF_CNT=1
  VF_CNT_MAX=`cat /sys/bus/pci/devices/$SDP_PF/sriov_totalvfs`
  VF_CNT=$((VF_CNT >VF_CNT_MAX ? VF_CNT_MAX : VF_CNT))
  dpdk-devbind.py -b octep_vdpa_pci $SDP_PF
  echo $VF_CNT >/sys/bus/pci/devices/$SDP_PF/sriov_numvfs
  vdpa dev add name vdpa0 mgmtdev pci/0000:01:02.0

Host offload to OCTEON DPU via SDP interface  over PCIe
=======================================================
System DPI packet interface (SDP) provides PCIe endpint support for remote host to DMA packets in and out of the OCTEON DPU. The SDP interface is used to offload IPsec processing from the host to the OCTEON DPU, leveraging the OCTEON DPU's high-performance IPsec offload capabilities. SDP shows up as a PCIe device in the host. Host can use this PCIe device to send/receive packets to/from DPU.

Below figure illustrates the Host-OCTEON communication via the SDP interface over PCIe:

   .. figure:: ./img/host_offload_via_sdp_interface.png

Configuring OCTEON DPU
----------------------
The following steps outline the configuration and setup of the SDP interface for Host offload in OCTEON DPU:

OCTEON endpoint control plane configuration
+++++++++++++++++++++++++++++++++++++++++++
The VPP OCTEON endpoint control plane plugin (octep_cp_plugin.so) has been added to support the SDP interface control plane. This plugin is used to configure the SDP interface on the OCTEON DPU. It implements the Marvell OCTEON PCIe endpoint control plane protocol and utilizes the /etc/vpp/octep_cp_cn10kxx.cfg file for configuration.

The configuration file includes the following parameters:
 | ``mac_addr``: MAC address of the SDP interface.
 | ``link_state``: Default link state of the SDP interface.
 | ``rx_state``: Default RX state of the SDP interface.
 | ``autoneg``:  Enable/disable link modes and speed autonegotiation.
 | ``pause_mode``: Flow control pause mode for both receive and transmit.
 | ``speed``: Set link speed of the SDP interface.
 | ``supported_modes``: Supported link modes/speeds for the SDP interface.
 | ``advertised_modes``: Advertised link modes/speeds for the SDP interface.
 | ``hb_interval``: Heartbeat interval for the SDP interface.
 | ``hb_miss_count``: Heartbeat miss count for the SDP interface.
 | ``pkind``: checksum offload support enabled/disabled.
 | ``if_name```: Name of the SDP interface.

Enable octep_cp plugin in startup.conf:

.. code-block:: text

  plugins {
    ....
    plugin octep_cp_plugin.so { enable }
    ....
  }

Configure the SDP interface:
++++++++++++++++++++++++++++

.. code-block:: text

  ##Determine SDP interface on OCTEON

  "lspci | grep SDP" OR "dmesg | grep sdp"
  0002:1f:00.0 Ethernet controller: Cavium, Inc. Octeon Tx2 SDP Physical Function (rev 51)
  0002:1f:00.1 Ethernet controller: Cavium, Inc. Octeon Tx2 SDP Virtual Function (rev 51)

  ##Bind SDP VF to vfio-pci driver

  dpdk-devbind.py -b vfio-pci 0002:1f:00.1

 sample VPP startup.conf file:

.. code-block:: text

  unix {
     log /var/log/vpp/vpp.log
     cli-listen /run/vpp/cli.sock
  }

  plugins {
    path /usr/lib/vpp_plugins
    plugin dpdpk_plugin.so { disable }
    plugin dev_octeon_plugin.so { enable }
    plugin octep_cp_plugin.so { enable }
  }

  cpu {
      main-core 1
      corelist-workers 8-9
  }

  devices {
     dev pci/0002:1f:00.1
     {
       driver virtio
       port 0
        {
          name eth0
          num-rx-queues 4
          num-tx-queues 5
        }
     }

     dev pci/0002:20:00.1
     {
       driver octeon
     }
  }

  logging {
    ## set default logging level for logging buffer
    ## logging levels: emerg, alert,crit, error, warn, notice, info, debug, disabled
    default-log-level info
    ## set default logging level for syslog or stderr output
    default-syslog-log-level info
    ## Set per-class configuration
    # class dpdk/cryptodev { rate-limit 100 level debug syslog-level error }
  }

Configuring Host
----------------

.. code-block:: text

  ##Determine SDP interface on HOST side
  - lspci | grep Cavium
    17:00.0 Network controller: Cavium, Inc. Device b900
  - load OCTEON PF and VF driver, insmod octeon_ep.ko octeon_ep_vf.ko
  - create required VF's with 'echo 1 > /sys/bus/pci/devices/0000\:17\:00.0/sriov_numvfs'
