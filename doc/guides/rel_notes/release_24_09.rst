..  SPDX-License-Identifier: Marvell-MIT
    Copyright (c) 2024 Marvell.

DAO Release 24.09.0
===================

New Features
------------

* **Libraries**

  * *Flow Library*

    The Flow Library provides interfaces to configure hardware for identifying the traffic and
    executing actions based on rules defined by the user. Once a continuous stream of packets
    matching the flow is received, the flow is offloaded to the hardware.

  * *Feature Arc*

    Feature arc library added for rte_graph applications to allow dynamic packet path at runtime.

  * *Bitmap Helper*

    Bitmap helper provides abstracted APIs to setup a bitmap, get a free index and return the
    index back to bitmap.

  * *Assert Helper*

    Assert helper provides macros for assertions in user test cases. These assertions can be normal
    i.e. reporting as an error, or fatal i.e. causing test to abort.

* **Applications**

  * *Secgw-graph*

    DPDK rte_graph based security gateway application providing IPv4 and IPsec dataplane
    functionalities which is integrated with strongSwan for control plane configuration, via netlink
    protocol.

  * *Vector Packet Processing(VPP)*

    Vector Packet Processing (VPP) enhances network throughput and efficiency by processing multiple
    packets simultaneously, with optimized support for Marvell OCTEON-10 SoCs and acceleration for
    packet ingress, egress, flow classification, and cryptographic operations.


  * *NGINX*

    NGINX application provides HTTP/HTTPS server, TLS proxy features with optional load balancing.
    NGINX achieves accelerated TLS processing using Marvell OpenSSL Engine library.


* **Infrastructure**

  * Comprehensive documentation includes getting started guides, a programming guide, an application
    user guide, and demo videos.

  * New dependent debian packages for DAO solutions

    - OVS
    - NGNIX/OpenSSL

Compatible Packages
-------------------

List of compatible dependent packages with version details:

  * *DPDK* - dpdk-23.11_24.07.0-ubuntu-22.04-24.07.0
  * *OVS* - ovs-3.3.0-24.07.0-ubuntu-22.04
  * *NGINX/OpenSSL* - nginx-1.22.0-24.09.0-ubuntu-22.04-devel/openssl-1.1.1q-24.09.0-ubuntu-22.04-devel
  * *VPP* - devel
  * *octep-target* - oct-ep-target-cn10k-24.07.0-ubuntu-22.04-24.07.0
  * *firmware-cpt* - cpt-firmware-24.07.0-ubuntu-22.04-24.07.0
  * *firmware-ml* - ml-firmware-24.07.0-ubuntu-22.04-24.07.0

Removed Items
-------------

API Changes
-----------

ABI Changes
-----------
