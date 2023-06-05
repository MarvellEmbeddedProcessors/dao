..  SPDX-License-Identifier: Marvell-MIT
    Copyright (c) 2024 Marvell.

Downloading and installing DAO packages
#######################################

The DAO software is comprehensively packaged for both Debian and RPM
packaging systems, ensuring broad compatibility across different Linux
distributions
Following are supported operating systems which can run with ease on
Marvell's Octeon platform.

1. Ubuntu 22.04
2. RHEL

Packages available for different distributions
==============================================

.. table:: Distribution Package Matrix
   :widths: auto

   +-------------------------+-----------------------+-----------------------+
   |   Available Packages    |        Ubuntu         |        RHEL           |
   +=========================+=======================+=======================+
   | DAO 24.04               | Yes                   | Planned               |
   +-------------------------+-----------------------+-----------------------+
   | DPDK 23.11              | Yes                   | Planned               |
   +-------------------------+-----------------------+-----------------------+
   | OVS 3.3                 | Yes                   | Planned               |
   +-------------------------+-----------------------+-----------------------+
   | VPP                     | Planned               | Planned               |
   +-------------------------+-----------------------+-----------------------+
   | OpenSSL                 | Planned               | Planned               |
   +-------------------------+-----------------------+-----------------------+

Ubuntu 22.04
============

To get started with the DAO package on Ubuntu, first set up the root
file system for octeon platform, then follow the step-by-step instructions
for installing and configuring the DAO package, ensuring a smooth and
efficient setup process.

Preparing ubuntu root file system
---------------------------------

To access the Ubuntu root file system from the Octeon platform, prepare
the file system first and then enable Network File Sharing (NFS), thereby
facilitating seamless cross-platform file access and management.

.. code-block:: console

 # mkdir ubuntu_base
 # cd ubuntu_base
 # wget https://cdimage.ubuntu.com/ubuntu-base/releases/22.04/release/ubuntu-base-22.04-base-arm64.tar.gz
 # sudo tar xvfp ubuntu-base-22.04-base-arm64.tar.gz

Setting up the ubuntu environment
---------------------------------

Once the octeon board is UP with above ubuntu rootfs

* Setting up the environment by updating and upgrading ubuntu distro.

.. code-block:: console

 # echo "185.125.190.36 ports.ubuntu.com" >> /etc/hosts
 # apt-get update
 # apt-get upgrade

* Installing required packages:

.. code-block:: console

 # apt-get -y install initramfs-tools init dbus iproute2 sudo nano openssh-server netbase
 # apt-get -y install libnfs-utils nfs-common iputils-ping curl gpg
 # apt-get -y install apt-utils dialog locales vim
 # locale-gen en_US.UTF-8

* Set Root password

.. code-block:: console

 # passwd

* Enable root login by updating sshd_config

.. code-block:: console

 # vim /etc/ssh/sshd_config
 Update PermitRootLogin to yes

* Reboot the board

* Resolving DNS

.. code-block:: console

 # vim /etc/systemd/resolved.conf

 Above file should contain following stuff
 --
 [Resolve]
 DNS=1.1.1.1 8.8.8.8
 --

 # systemctl restart systemd-resolved

 # hostnamectl hostname <hostname>

* Update ubuntu repository to download dao packages

.. code-block:: console

 # curl -fsSL https://uat.marvell.com/public/repo/octeon/dao/ubuntu/dao.gpg | sudo gpg --dearmor -o /etc/apt/keyrings/dao.gpg
 # curl -SsL -o /etc/apt/sources.list.d/dao.list https://uat.marvell.com/public/repo/octeon/dao/ubuntu/dao.list
 # sudo chmod 644 /etc/apt/sources.list.d/dao.list
 # sudo chmod 644 /etc/apt/keyrings/dao.gpg
 # apt-get update

Installing DAO package
----------------------

.. code-block:: console

 # apt-get install dao-cn10k-latest

 This will also install mandatory dependency viz DPDK

Installing OVS package (optional)
---------------------------------

.. code-block:: console

 # apt-get install ovs-3.3

RHEL
====

<TBD>
