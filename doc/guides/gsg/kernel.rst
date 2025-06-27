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
 cd linux-marvell
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

`Kernel Config <https://github.com/MarvellEmbeddedProcessors/dao/tree/dao-devel/config/kernel/v6.1/cn10k.config>`_

.. code-block:: console

 cp cn10k.config <path_to_kernel_directory>/arch/arm64/configs/
 cd <path_to_kernel_directory>
 make ARCH=arm64 cn10k.config

.. note:: If above steps reports "The base file '.config' does not exist.  Exit." error.
 As a workaround, ``touch .config`` in make kernel directory and retry the step.

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

 cp cn10k.config <path_to_kernel_directory>/arch/arm64/configs/
 cd <path_to_kernel_directory>
 make ARCH=arm64 cn10k.config

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

 ``vfio-pci.enable_sriov=1`` to enable sriov support in userspace applications

 ``rvu_af.kpu_profile=ovs_kpu_cnxk`` load profile to configure flow classifier HW for
 extracting/parsingdifferent headers including tunnels. Required for OVS use cases only.

 ``vfio_platform.reset_required=0`` required only for virtio use case

 ``modprobe.blacklist=pcie_marvell_cnxk_ep`` is required only on cn10k platforms

.. code::

 Eg. booting rootfs from mmc card
  setenv bootargs "console=ttyAMA0,115200n8 earlycon=pl011,0x87e028000000 maxcpus=24 rootwait rw \
	  coherent_pool=16M root=/dev/mmcblk0p2 vfio-pci.enable_sriov=1 \
          rvu_af.kpu_profile=ovs_kpu_cnxk modprobe.blacklist=pcie_marvell_cnxk_ep"

 Eg. booting rootfs from nfs
  setenv bootargs "console=ttyAMA0,115200n8 earlycon=pl011,0x87e028000000 maxcpus=24 rootwait rw \
	  coherent_pool=16M root=/dev/nfs nfsroot=<path_to_rootfs_hosted_on_nfs_server> \
	  vfio-pci.enable_sriov=1 rvu_af.kpu_profile=ovs_kpu_cnxk  vfio_platform.reset_required=0 \
          modprobe.blacklist=pcie_marvell_cnxk_ep"

Booting Kernel Image
====================

* Boot the target platform and stop at u-boot prompt.

* Setting up board environment and TFTP server:

.. code-block:: console

  # Set ethernet adaptor, some common adaptors are ax88179_eth or r8152_eth or e1000#0 or rvu_pf#4
  # set ethact <ethernet adaptor>
  Eg.
  crb106-pcie> set ethact e1000#0

  # Obtain dynamic IP using dhcp for the board or assign static IP
  # setenv ipaddr <board IP>
  Eg
  crb106-pcie> dhcp
  or
  crb106-pcie> setenv ipaddr 10.28.35.116

  # Set TFTP server IP
  # setenv serverip <TFTP server IP>
  Eg.
  crb106-pcie> setenv serverip 10.28.35.121

  # Verify the tftp server is reachable from the board.
  # ping $serverip
  Eg.
  crb106-pcie> ping 10.28.35.121
  Waiting for RPM1 LMAC0 link status... 10G_R [10G]
  Using rvu_pf#1 device
  host 10.28.35.121 is alive

* Load kernel image to DDR from the tftp server

.. code-block:: console

  # tftpboot $loadaddr <Path to firmware image in TFTP server>

  Eg.
  crb106-pcie> tftpboot $loadaddr Image_dao
  Waiting for RPM1 LMAC0 link status... 10G_R [10G]
  Using rvu_pf#1 device
  TFTP from server 10.28.34.13; our IP address is 10.28.35.115
  Filename 'Image_dao'.
  Load address: 0x20080000
  Loading: ##################################################  40.6 MiB
           8.5 MiB/s
  done
  Bytes transferred = 42615296 (28a4200 hex)

* Booting the kernel

.. code-block:: console

  # booti $loadaddr - $fdtcontroladdr

  Eg.
  crb106-pcie>  booti $loadaddr - $fdtcontroladdr
  Moving Image from 0x20080000 to 0x20200000, end=22bf0000
  ## Flattened Device Tree blob at 9f3909b20
     Booting using the fdt blob at 0x9f3909b20
  Working FDT set to 9f3909b20
     Loading Device Tree to 00000009f28e1000, end 00000009f2901264 ... OK
  Working FDT set to 9f28e1000

  Skip Switch micro-init option is set

  Starting kernel ...

  [    0.000000] Booting Linux on physical CPU 0x0000000000 [0x410fd490]
  ...
  <snip>
  ...
