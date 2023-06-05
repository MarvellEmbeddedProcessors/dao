..  SPDX-License-Identifier: Marvell-MIT
    Copyright (c) 2024 Marvell.

Kernel Modules
==============

OCTEON vDPA driver
------------------

OCTEON vDPA driver(octep_vdpa.ko) manages the virtio controlplane over vDPA bus
for OCTEON devices.

Compilation
***********

Kernel modules building is enabled by default and can be disabled via meson Options

.. code-block:: console

 # meson build -Denable_kmods=false

To compile the module ``kernel_dir`` option should be set to kernel build
tree. By default compilation of kernel modules is disabled.

Make sure following lines are enabled in the $kernel_dir .config file for vDPA framework.

.. code-block:: console

 CONFIG_VDPA=y
 CONFIG_VHOST_IOTLB=y
 CONFIG_VHOST=y
 CONFIG_VHOST_VDPA=y
 CONFIG_VIRTIO_VDPA=y

.. code-block:: console

 # meson build --cross config/arm64_cn10k_linux_gcc -Dkernel_dir=KERNEL_BUILD_DIR
 # ninja -C build

Loading the module
******************
Make sure dpdk-virtio-l2fwd application is started running on
endpoint Octeon before inserting the octep_vdpa.ko module on host.

.. code-block:: console

 # insmod octep_vdpa.ko
