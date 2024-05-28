..  SPDX-License-Identifier: Marvell-MIT
    Copyright (c) 2024 Marvell.

DAO Release 24.05.0
===================

New Features
------------

* **Libraries**

  * *VirtIO*

    VirtIO-net library is the virtualization solution used in CN10K for networking.
    This model emulates SMART NICs for VM and front end virtio network driver.

    Currently, VirtIO emulation device supports VirtIO 1.2 specification, where it offers
    below features.

  * *Netlink Library*

    Netlink library provides an abstraction on top of open source libnl library using
    which application gets notified for a received netlink message from LINUX. Applications
    are notified via function callback for the netlink protocols they have registered.

  * *Port Group*

    Port group is a control path library that facilitates applications to iterate
    over group of homogeneous ports (or devices) and apply common configurations on
    them. Homogeneity of ports is decided by an application.

  * *VFIO-Platform*

    Library provides APIs to interact with platform devices from user space leveraging
    vfio-platform kernel driver framework

  * *Helper*

    Helper library is the collection of utility functions. These APIs serve as public interfaces
    and abstract the hardware-specific DAO implementations.


* **Applications**

  * *OVS-offload*

    Open vSwitch(OVS) is often used in conjunction with companion applications to
    enhance and extend its capabilities. OVS offload is a companion application which
    enhance OVS functionality between host ports and mac ports.

  * *VirtIO-l2fwd*

    It is a DPDK application that allows to exercise virtio usecase of forwarding traffic
    between VirtIO net device and DPDK ethdev device. VirtIO net device is emulated using
    virtio DAO library.

  * *Smart-NIC*

    Universal smart nic app is a powerful tool that harnesses the performance and efficiency
    of hardware accelerators in DPUs. It also mitigates some hardware gaps by providing
    optimized software solution for advanced features like as port hair pinning, tunnel-transport,
    port hotplugging, etc.

  * *virtio-extbuf*

    This DPDK application enables testing of the VirtIO external buffer use case by forwarding
    traffic between a VirtIO net device and a DPDK ethdev device. The application leverages a
    helper library for the control path and utilizes VirtIO external buffer APIs for the data path.
    The VirtIO net device is emulated using the VirtIO DAO library.

Removed Items
-------------

API Changes
-----------

ABI Changes
-----------
