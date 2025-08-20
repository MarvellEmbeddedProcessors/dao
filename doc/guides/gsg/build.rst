..  SPDX-License-Identifier: Marvell-MIT
    Copyright (c) 2024 Marvell.

Compiling DAO from sources
==========================

Developers can refer to the following guide, which provides various options
for manually compiling DAO sources, allowing them to tailor the process
according to their specific needs.

.. _getting_dao_sources:

Getting the sources
-------------------
Data accelerator offload (DAO) sources can be downloaded from:

.. code-block:: console

  # git clone https://github.com/MarvellEmbeddedProcessors/dao.git
  # cd dao
  # git checkout dao-devel

Installing Dependencies
-----------------------

Before compiling DAO, install the required packages:

.. code-block:: console

  # apt-get update
  # apt-get install -y \
    build-essential gcc-14 ninja-build meson git \
    wget flex bison check file \
    pkg-config libssl-dev libsystemd-dev \
    libnl-3-dev libnl-route-3-dev libnl-xfrm-3-dev \
    libarchive-dev libbsd-dev libbpf-dev \
    libfdt-dev libjansson-dev zlib1g-dev \
    doxygen sphinx-common python3-sphinx-rtd-theme \
    python3-pip python3-setuptools python3-wheel python3-pyelftools \
    gcc-aarch64-linux-gnu g++-aarch64-linux-gnu

Compiling and Installing
------------------------

When compiling for the Octeon platform, DAO has a mandatory dependency on DPDK and gRPC.

.. note::

 Steps to build DPDK and gRPC are as follows:
 (Steps are for natively compiling DPDK and gRPC on ARM based rootfs)

 * # Build DPDK
 * git clone https://github.com/MarvellEmbeddedProcessors/marvell-dpdk.git
 * cd marvell-dpdk
 * git checkout dpdk-24.11-release
 * meson build -Dexamples=all -Denable_drivers=*/cnxk,net/ring -Dplatform=cn10k --prefix=/usr
 * ninja -C build install
 * # Build gRPC
 * cd <Path to DAO repo>/dao
 * export GRPC_BUILD_DIR=/tmp/dao-deps-build
 * ./ci/build/build-deps.sh $GRPC_BUILD_DIR <git user name> cn10k grpc
 * export PATH=$GRPC_BUILD_DIR/deps/deps-prefix/host/bin:$PATH
 * export LD_LIBRARY_PATH=$GRPC_BUILD_DIR/deps/deps-prefix/host/lib:$LD_LIBRARY_PATH
 * export PKG_CONFIG_PATH="$GRPC_BUILD_DIR/deps/deps-prefix/ep/lib/pkgconfig:$GRPC_BUILD_DIR/deps/host/grpc/third_party/re2:${PKG_CONFIG_PATH:-}"

Native Compilation
``````````````````
Compiling on ARM server for CN10k platform

.. code-block:: console

  # cd <Path to DAO repo>/dao
  # meson build -Dplatform=cn10k --prefix="${PWD}/install" -Denable_kmods=false -Dprefer_static_build=true --prefer-static
  # ninja -C build install

Compiling on x86 machine

.. code-block:: console

  # cd <Path to DAO repo>/dao
  # meson build --prefix="${PWD}/install" -Denable_kmods=false
  # ninja -C build install

.. note::

 To link dpdk library statically, meson option ``--prefer-static`` shall be
 used. To build only static DAO libraries, use ``-Dprefer_static_build=true``.

Cross compilation
`````````````````
Setup the toolchain and follow the below steps.

.. code-block:: console

 # cd <Path to DAO repo>/dao
 # PKG_CONFIG_LIBDIR=/path/to/dpdk/build/prefix/lib/pkgconfig/ meson setup --cross config/arm64_cn10k_linux_gcc build -Dprefer_static_build=true --prefer-static
 # ninja -C build

Compiling the documentation
---------------------------
Install ``sphinx-build`` package. If this utility is found in PATH then
documentation will be built by default.

Meson Options
-------------

 - **dma_stats**: Enable DMA statistics for DAO library
 - **disable_libs**: Comma-separated list of optional libraries to explicitly disable.
   [NOTE: mandatory libs cannot be disabled]
 - **enable_apps**: Comma-separated list of apps to build.
   If unspecified, all apps will be built.
 - **enable_host_build**: Enable the host build for the DAO library. This option
   compiles only the components necessary for the host environment.
 - **enable_libs**: Comma-separated list of optional libraries to explicitly enable.
   [NOTE: mandatory libs are always enabled]
 - **kernel_dir**: Path to the kernel for building kernel modules (octep_vdpa).
   Headers must be in $kernel_dir.
 - **prefer_static_build**: Build only static DAO libraries.
 - **virtio_debug**: Enable virtio debug that perform descriptor validation, etc.

