..  SPDX-License-Identifier: Marvell-MIT
    Copyright (c) 2024 Marvell.

**************
VirtIO Library
**************

VirtIO library is a base library, which is used by other libraries such as ``virtio-net``.
It's responsibilities include populating virtio device capabilities as per virtio spec in the bar
area, handling mailbox messages between host and FW, and fetching the virtio control commands.
VirtIO control queue polling and fetching control commands is handled by this library itself
with up call made to higher virtio-net layer.
There will be further up calls to virtio-net layer if the virtio device is of type ``virtio-net``
on things such as device status change, etc.
Currently, this library uses SDP device's BAR memory mapped by ``pem library`` for mailbox messages
between host and Octeon FW.

VirtIO Device initialization
-----------------------------

The initialization of each virtio device includes the following operations:

* Gets the bar region info for the given virtio device from ``pem library``.
* Populates the virtio capabilities to be available to the host as per virtio specification.
* Registers ``struct virtio_pci_common_cfg`` bar area to the ``pem library`` using
  ``dao_pem_ctrl_region_register()`` to get notifications when host changes in this area.

Since this is base virtio device, its initialization is called as part of higher level device
initialization such as ``dao_virtio_netdev_init()``.

Features
--------

Other libraries can set the features using ``virtio_dev_features_bits_set()`` API. So, that virtio library
shares the device supported features with the host.
