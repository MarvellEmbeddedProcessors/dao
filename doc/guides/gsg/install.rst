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
   | DAO 24.05               | Yes                   | Planned               |
   +-------------------------+-----------------------+-----------------------+
   | DPDK 23.11              | Yes                   | Planned               |
   +-------------------------+-----------------------+-----------------------+
   | OVS 3.3                 | Yes                   | Planned               |
   +-------------------------+-----------------------+-----------------------+
   | VPP                     | Yes                   | Planned               |
   +-------------------------+-----------------------+-----------------------+
   | PCIe-oct-ep-target      | Yes                   | Planned               |
   +-------------------------+-----------------------+-----------------------+
   | Nginx 1.22.0            | Yes                   | Planned               |
   +-------------------------+-----------------------+-----------------------+
   | OpenSSL 1.1.1q          | Yes                   | Planned               |
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

Update ubuntu repository to download dao packages
-------------------------------------------------

Two types of packages are available for the DAO - stable and release packages.
Each have their own PPA's. User can choose either stable or development version
and update the repository accordingly.

PPA for stable version:

.. code-block:: console

 # curl -fsSL https://www.marvell.com/public/repo/octeon/dao/cn10k/ubuntu/v2204/release/dao.gpg | sudo gpg --dearmor -o /etc/apt/keyrings/dao.gpg
 # curl -SsL -o /etc/apt/sources.list.d/dao.list https://www.marvell.com/public/repo/octeon/dao/cn10k/ubuntu/v2204/release/dao.list
 # sudo chmod 644 /etc/apt/sources.list.d/dao.list
 # sudo chmod 644 /etc/apt/keyrings/dao.gpg
 # apt-get update

.. _devel_ppa:

PPA for development version:

.. code-block:: console

 # curl -fsSL https://www.marvell.com/public/repo/octeon/dao/cn10k/ubuntu/v2204/devel/dao.gpg | sudo gpg --dearmor -o /etc/apt/keyrings/dao.gpg
 # curl -SsL -o /etc/apt/sources.list.d/dao.list https://www.marvell.com/public/repo/octeon/dao/cn10k/ubuntu/v2204/devel/dao.list
 # sudo chmod 644 /etc/apt/sources.list.d/dao.list
 # sudo chmod 644 /etc/apt/keyrings/dao.gpg
 # apt-get update

Installing DAO package
----------------------

Two typeis of DAO packages are available for installation:

Release version
^^^^^^^^^^^^^^^

These are stable versions of the DAO package, which are thoroughly tested

.. code-block:: console

 # apt-get install dao-cn10k

 This will also install mandatory dependency viz DPDK

To check all available release versions of the package, user can run below command:

.. code-block:: console

 # apt-cache policy dao-cn10k
 dao-cn10k:
  Installed: (none)
  Candidate: 24.09.0
  Version table:
     24.09.0 500
        500 https://www.marvell.com/public/repo/octeon/dao/ubuntu/v2204 ./ Packages
     24.05.1 500
        500 https://www.marvell.com/public/repo/octeon/dao/ubuntu/v2204 ./ Packages
     24.05.0 500
        500 https://www.marvell.com/public/repo/octeon/dao/ubuntu/v2204 ./ Packages

By default it will install the latest version of the package. If user wants to
install a specific version, then user can specify the version as below:

.. code-block:: console

 # apt-get install dao-cn10k=24.05

.. note:: While installing an older package user may observe some dependency issues:

   ***dao-cn10k : Depends: dpdk-23.11-cn10k (= 24.07.0) but 24.08.0 is to be installed***

   Refer :ref:`troubleshoot dependency issue<dep_issue>` to resolve the dependency issues.

Its recommended to clear the repository cache before installing different versions of the
package.

:ref:`Clear repository cache<clear_repo_cache>`

Development version
^^^^^^^^^^^^^^^^^^^

These are the latest versions of the DAO package, which are still under
development and may contain bugs. User should install these versions only
at their own risk.

Change the repository to development version as mentioned in

:ref:`PPA for development<devel_ppa>`

.. code-block:: console

 # apt-get install dao-cn10k-devel

Removing old packages
---------------------

* Remove old packages

.. code-block:: console

 Remove dao release package
 # apt-get remove dao-cn10k -y

 Remove dao development package
 # apt-get remove dao-cn10k-devel -y

 Remove dpdk package and its dependents
 # apt-get remove dpdk-23.11-cn10k -y

.. _clear_repo_cache:

* Clear ubuntu repo cache

.. code-block:: console

 # rm /var/cache/apt/archives/dao-cn10k*
 # rm /var/cache/apt/archives/dpdk-23.11-cn10k_*

Installation demo
-----------------

.. raw:: html
  :file: ../_static/demo/install.html

RHEL
====

<TBD>
