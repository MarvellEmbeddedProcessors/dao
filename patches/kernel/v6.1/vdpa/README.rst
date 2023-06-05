..  SPDX-License-Identifier: Marvell-MIT
    Copyright (c) 2024 Marvell.

The DPU accelerator offloads(DAO) requires additional patches for compatibility
with the v6.1 kernel.
These patches have been back-ported and can be found in DAO source directory under
**patches/kernel/v6.1/vdpa/**. They are part of the Marvell SDK kernel.

Steps to apply patches and cross-compile kernel
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
* Checkout v6.1 vanilla kernel and apply patches.

.. code-block:: console

 # git am DAO_SRC_DIR/patches/kernel/v6.1/vdpa/000*

* Prepare build

.. code-block:: console

 # make ARCH=arm64 CROSS_COMPILE=aarch64-marvell-linux-gnu- O=build olddefconfig

Make sure the VDPA config options are enabled in **build/.config** file. ::

 CONFIG_VIRTIO_VDPA=m
 CONFIG_VDPA=m
 CONFIG_VP_VDPA=m
 CONFIG_VHOST_VDPA=m

* Build kernel

.. code-block:: console

 # make ARCH=arm64 CROSS_COMPILE=aarch64-marvell-linux-gnu- O=build
