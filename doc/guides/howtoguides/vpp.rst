..  SPDX-License-Identifier: Marvell-MIT
    Copyright (c) 2025 Marvell.

**************************
Compiling VPP from sources
**************************

This section provides step-by-step instructions to compile VPP from sources.

Installing required packages
============================

.. code-block:: console

    apt-get update  -q -y
    apt-get install -y apt-utils build-essential gcc-14 git wget patch sudo

Configure and build VPP
=======================

.. code-block:: console

    # Clone the VPP repository
    git clone https://github.com/MarvellEmbeddedProcessors/vpp.git
    cd vpp
    sudo APT_ARGS='-y -q' make install-deps
    #Install Oct-EP target package
    wget "https://github.com/MarvellEmbeddedProcessors/pcie_ep_octeon_target/releases/download/oct-ep-target-cn10k-25.01.0-ubuntu-24.04-25.01.0/oct-ep-target-cn10k_25.01.0_arm64.deb"
    sudo apt-get install -y ./"oct-ep-target-cn10k_25.01.0_arm64.deb"
    #Build VPP
    make build-release VPP_PLATFORM=octeon10
    # Files will be installed in ./build-root/install-vpp-native/vpp/. Please sync this VPP build to root '/' directory.