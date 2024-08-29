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

  onp {
    ## whitelist interface
    #RPM interface
    dev 0002:03:00.0 {
      name eth0
      num-rx-queues 2
      num-tx-queues 2
      num-tx-desc  16384
    }
    #SDP/RPM interface
    dev 0002:01:00.2 {
      name eth1
      num-rx-queues 8
      num-tx-queues 8
      num-tx-desc  16384
    }
    #Inline device
    dev 0002:10:00.0
    #Event device
    dev sched 0002:1e:00.0
    #CPT device
    dev crypto 0002:20:00.1
    num-pkt-buf 16384

    ipsec {
      enable-inline-ipsec-outbound
    }
  }

  plugins {
    path /usr/lib/vpp_plugins
    plugin dpdk_plugin.so { disable }
    plugin onp_plugin.so { enable }
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
The maximum SPI value supported for inline IPsec is 2^32 -1 but it varies based on memory availability. With current ONP release max supported SPI value is 5000.  Update spi_max and spi_min in charon.conf. Enable make_before_break for IKEv2 reauthentication. This setting creates new SAs before tearing down old ones, avoiding traffic interruptions,

charon.conf:

.. code-block:: text

  charon {
      .....
      # Determine plugins to load via each plugin's load option.
      # load_modular = no

      # Initiate IKEv2 reauthentication with a make-before-break scheme.
      make_before_break = yes

      # The upper limit for SPIs requested from the kernel for IPsec SAs.
      spi_max = 0x1388

      # The lower limit for SPIs requested from the kernel for IPsec SAs.
      spi_min = 0

      # Name of the user the daemon changes to after startup.
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
