..  SPDX-License-Identifier: Marvell-MIT
    Copyright (c) 2024 Marvell.

Compiling DAO from sources
==========================

Developers can refer to the following guide, which provides various options
for manually compiling DAO sources, allowing them to tailor the process
according to their specific needs.

Getting the sources
-------------------
DPU accelerator offload (DAO) sources can be downloaded from:

.. code-block:: console

   git clone https://github.com/MarvellEmbeddedProcessors/dpu-accelerator-offload.git
   git checkout dao-devel

Compiling and Installing
------------------------

When compiling for the Octeon platform, DAO has a mandatory dependency on DPDK.

.. note::

 Steps to build DPDK are as follows

 * git clone https://github.com/MarvellEmbeddedProcessors/marvell-dpdk.git
 * git checkout dpdk-23.11-release
 * meson build -Dexamples=all -Denable_drivers=*/cnxk,net/ring -Dplatform=cn10k --prefix=${PWD}/install
 * ninja -C build install

Native Compilation
``````````````````
Compiling on ARM server for CN10k platform

.. code-block:: console

  # meson build -Dplatform=cn10k --prefix="${PWD}/install" -Denable_kmods=false --prefer-static
  # ninja -C build install

Compiling on x86 machine

.. code-block:: console

  # meson build --prefix="${PWD}/install" -Denable_kmods=false --prefer-static
  # ninja -C build install

.. note::

 To link dpdk library statically, meson option ``--prefer-static`` shall be
 used.

Cross compilation
`````````````````
Setup the toolchain and follow the below steps.

.. code-block:: console

 # PKG_CONFIG_LIBDIR=/path/to/dpdk/build/prefix/lib/pkgconfig/ meson setup --cross config/arm64_cn10k_linux_gcc build --prefer-static
 # ninja -C build

Compiling the documentation
---------------------------
Install ``sphinx-build`` package. If this utility is found in PATH then
documentation will be built by default.

Meson Options
-------------
 - kernel_dir: Path to the kernel for building kernel modules (octep_vdpa).
   Headers must be in $kernel_dir.
 - dma_stats: Enable DMA statistics for DAO library
 - virtio_debug: Enable virtio debug that perform descriptor validation, etc.
