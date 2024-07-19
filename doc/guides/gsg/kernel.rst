..  SPDX-License-Identifier: Marvell-MIT
    Copyright (c) 2024 Marvell.

Compiling Linux kernel from sources
***********************************

Here are the general steps to compile a Linux kernel:

Get the Linux Kernel sources
============================

Linux kernel sources can be downloaded from

.. code-block:: console

 git clone https://github.com/MarvellEmbeddedProcessors/linux-marvell.git
 git checkout linux-6.1.x-release

Setting up the environment
==========================

To set up the workspace for either native or cross compilation of the kernel,
the installation of the following packages is required:

.. code-block:: console

 sudo apt-get -y install build-essential imagemagick graphviz dvipng python3-venv fonts-noto-cjk latexmk librsvg2-bin texlive-xetex flex bison libssl-dev bc

Configuring and Building Kernel
===============================

Cross Compilation
-----------------

Cross-compiling a Linux kernel involves building the kernel on one platform
(the host) for use on another platform (the target). Here are the general

Getting the toolchain
`````````````````````

The cross-compiler toolchain is specific to the target platform. For example,
to cross-compile a kernel for AArch64 on Ubuntu ``gcc-aarch64-linux-gnu`` is
required.

.. code-block:: console

 sudo apt-get install gcc-aarch64-linux-gnu

Set environment variables
`````````````````````````

Export ``ARCH`` and ``CROSS_COMPILE`` environment variables.
ARCH specifies the target architecture, and CROSS_COMPILE specifies the prefix
for the cross-compile

.. code-block:: console

 export ARCH=arm64
 export CROSS_COMPILE=aarch64-linux-gnu-

Configuring the Kernel
```````````````````````

Use the following configuration obtained from the DAO repository to configure the kernel:

`Kernel Config <https://github.com/MarvellEmbeddedProcessors/dpu-accelerator-offload/tree/dao-devel/config/kernel/v6.1/cn10k.config>`_

.. code-block:: console

 cp cn10k.config <path_to_kernel_directory>/arch/arm64/configs/
 cd <path_to_kernel_directory>
 make ARCH=arm64 marvell_v8_octeon_kernel_asim.config

This generates a .config file which can be edited if a driver needs any
changes in configuration such as enabling/disabling a driver, statically
built-in or loadable module of a driver into kernel.

Generating a kernel Image
`````````````````````````

.. code-block:: console

 make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- Image

With this, the Kernel Image is built and is located in ``arch/arm64/boot``

Generating and installing kernel modules
`````````````````````````````````````````

.. code-block:: console

 make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- modules

To install modules to a specific root file system, mount the rootfs first.
Then, use the ``INSTALL_MOD_PATH`` environment variable to specify the root
directory of the mount point.

.. code-block:: console

 make modules_install INSTALL_MOD_PATH=<Path_to_rootfs_mount_point>
 Eg.
    make modules_install INSTALL_MOD_PATH=/mnt/disk

Native Compilation
------------------

Native compilation refers to where the kernel is built directly on the target
machine

Installing additional packages
``````````````````````````````

Apart from the packages mentioned above, install additional packages on target

.. code-block:: console

 sudo apt-get -y gcc make

Configuring the Kernel
```````````````````````

Same procedure as described in cross-compilation section

.. code-block:: console

 cp marvell_v8_octeon_kernel_asim.config <path_to_kernel_directory>/arch/arm64/configs/
 cd <path_to_kernel_directory>
 make ARCH=arm64 marvell_v8_octeon_kernel_asim.config

Building and install kernel modules
```````````````````````````````````

.. code-block:: console

 make ARCH=arm64 Image
 make ARCH=arm64 modules
 make modules_install

Kernel Image is built and located in ``arch/arm64/boot``, while modules are
installed to ``/lib/modules/`uname -r```

Kernel boot parameters
======================

Some important kernel boot parameters that need to be defined before booting the
kernel

.. code::

 vfio-pci.enable_sriov=1
 rvu_af.kpu_profile=ovs_kpu_cnxk
