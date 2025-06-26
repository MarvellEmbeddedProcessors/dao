..  SPDX-License-Identifier: Marvell-MIT
    Copyright (c) 2024 Marvell.

*********************
Octeon Endpoint Agent
*********************

Introduction
############

The Control Plane (CP) is a crucial component that encompasses all control or status
messages that are exchanged between an Octeon device and host-side drivers or applications.
The Octeon Endpoint Control Plane Agent ``octep-agent``, an application that operates on the
Octeon, takes charge of these messages, thereby streamlining the control plane functionality.
This agent effectively acts as a mediator, ensuring smooth communication and operation within
the system.

Getting started with CP Agent
#############################

The Octep CP Agent, which is located in the /usr/bin directory of the target (Octeon) rootfs,
comes with a specific config file for the system on a chip (SoC). The CP Agent package currently
includes a set of provisioned config files for current platforms, e.g ``cn106xx.cfg``

Installing the package
======================

Ubuntu Debian package
---------------------

Before downloading the octep CP agent package, make sure ubuntu repository is setup properly

`Setting up Ubuntu repo for DAO <https://marvellembeddedprocessors.github.io/dao/guides/gsg/install.html#update-ubuntu-repository-to-download-dao-packages>`_

Installing the octep CP agent package

.. code-block:: console

 Release repository
 # apt-get install oct-ep-target-cn10k

.. _octep_cp_agent:

Setting up the Environment
==========================

Hugepage setup
--------------

.. code-block:: console

 # mkdir /dev/huge
 # mount -t hugetlbfs none /dev/huge
 # echo 12 > /proc/sys/vm/nr_hugepages
 or
 # echo 256 >/sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages

Loading vfio-pci driver
-----------------------

.. code-block:: console

   modprobe vfio-pci

This ensures that the vfio-pci driver is loaded before binding devices.

Binding the required devices
----------------------------

Binding PEM device
``````````````````

Check for device ID ``0xa06c`` viz PEM and bind to vfio-pci

.. code-block:: console

 # lspci | grep a06c
 0001:00:10.0 System peripheral: Cavium, Inc. Device a06c

.. note :: In case no device found with ``lspci | grep a06c`` means incompatible firmware
 is flashed on the board.

Bind to vfio-pci

.. code-block:: console

 echo  "177d a06c" > /sys/bus/pci/drivers/vfio-pci/new_id
 echo  0001:00:10.0 > /sys/bus/pci/drivers/vfio-pci/bind

.. note ::
 Please ignore any error message, something like ``-bash: echo: write error: Device or resource busy``

Execute ``lspci -ks 0001:00:10.0`` to confirm successful binding of PEM device with vfio

.. code-block:: console

 # lspci -ks 0001:00:10.0
 0001:00:10.0 System peripheral: Cavium, Inc. Device a06c
      Subsystem: Cavium, Inc. Device b900
      Kernel driver in use: vfio-pci

Binding SDP RVU PF devices
``````````````````````````

Check for device ID ``0xa0ef`` and bind to vfio-pci:

.. code-block:: console

  #lspci | grep a0ef
  0002:18:00.0 Ethernet controller: Cavium, Inc. Device a0ef
  0002:19:00.0 Ethernet controller: Cavium, Inc. Device a0ef

Bind both to vfio-pci:

.. code-block:: console

  echo 1 > /sys/bus/pci/devices/0002\:19\:00.0/remove
  echo 1 > /sys/bus/pci/devices/0002\:18\:00.0/remove
  echo 1 > /sys/bus/pci/rescan

  echo "177d a0ef" > /sys/bus/pci/drivers/vfio-pci/new_id
  echo "0002:18:00.0" > /sys/bus/pci/drivers/vfio-pci/bind
  echo "0002:19:00.0" > /sys/bus/pci/drivers/vfio-pci/bind

.. note::
   If the device is already bound to another driver, unbind it first:

.. code-block:: console

  lspci -ks <BDF>
  echo "<BDF>" > /sys/bus/pci/drivers/<driver>/unbind

Running the octep-agent
-----------------------

Using SDP RVU PF devices
````````````````````````

When SDP RVU PF devices are used, pass them via --sdp_rvu_pf argument:

.. code-block:: console

  /usr/bin/octep_cp_agent /usr/bin/cn106xx.cfg
  -- --sdp_rvu_pf 0002:18:00.0,0002:19:00.0 --pem_dev 0001:00:10.0

.. note::
  The first SDP RVU PF (e.g., 0002:18:00.0) must appear first in the comma-separated list passed to --sdp_rvu_pf.

To run the application in background and dump logs:

.. code-block:: console

   /usr/bin/octep_cp_agent /usr/bin/cn106xx.cfg -- --pem_dev 0001:00:10.0 --sdp_rvu_pf 0002:18:00.0,0002:19:00.0 2>&1 > /tmp/octep-cp-log.txt &

Upon successful launch of the application, the following logs will be displayed and application
will run in background

.. code-block:: console

  CNXK: PEM: device = 0001:00:10.0; IOMMU group = 73
  CNXK: SDP RVU PF: device = 0002:18:00.0; IOMMU group = 74
  CNXK: SDP RVU PF: device = 0002:19:00.0; IOMMU group = 75
  LIB: init
  SOC: Model: cn10ka_a0
  CNXK: init
  CNXK: Created VFIO container successfully; fd=3
  CNXK: Initializing SDP RVU PF ...
  CNXK: mapped SDP RVU PF device region-2; size=0x400000.
  CNXK: mapped SDP RVU PF device region-4; size=0x2000000.
  CNXK: mapped SDP RVU PF device region-2; size=0x40080000.
  CNXK: mapped SDP RVU PF device region-4; size=0x2000000.
  CNXK: mapped PEM device region-0; size=0x40000000.
  CNXK: mapped PEM device region-4; size=0x100000.
  CNXK: Number of PEM interrupts = 10
  CNXK: Enabled PEM link down and PERST interrupts
  CNXK: pem[0] pf[0] control plane versions 10000:10000
  CNXK: pem[0] pf[0] mbox h2fq sz 16256 addr 0xffff8dec0120
  CNXK: pem[0] pf[0] mbox f2hq sz 16256 addr 0xffff8dec40a0
  CNXK: pem[0] pf[0] oei_trig_addr 0xffff8be40000
  CNXK: pem[0] pf[0] fw ready 1 addr 0xffff0a248418

Runtime Configurations
######################

As previously mentioned, the Control Plane (CP) agent can receive specific information related
to the Data Processing Unit (DPU) through configuration files.
For instance, they may specify number of PEMs (PCIe MACs), number of PFs per PEM, number of VFs
per PF, default MAC address of each interface etc.

A config file is expected to include following configurations:

* Number of PEMs - including indices of respective PEMs.
* Number of PFs per PEM - including indices of respective PFs.
* Number of VFs per PF - including indices of respective VFs.
* Default MAC address of each interface, where interface can be a PF or a VF. Users can edit
  the default MAC and is of the following format:

    mac_addr = [0xXX, 0xXX, 0xXX, 0xXX, 0xXX, 0xXX];

  where XX indicate specific bytes in hex.

* Default link state of each interface, where interface can be a PF or a VF.

    eg: link_state = 0;

* Default receive state (rx state) of each interface.

    eg: rx_state = 0;

* Default auto negotiation flags an interface provides.

    eg: autoneg = 0x3;

* Default pause mode flags an interface advertises.

    eg: pause_mode = 0x3;

* Default link speed of an interface

    eg: speed = 10000;

* Default supported and advertised modes of an interface.

    eg: supported_modes = 0x1;
        advertised_modes = 0x1;

* Default heartbeat interval (hb_interval) and heartbeat miss count (hb_miss_count) for a PF.
  (Valid only for PF entries)

    eg: hb_interval = 1000;
        hb_miss_count = 20;

Sample configuration for 1 PEM with 1 PF and 1 VF looks like:

.. code-block:: console

 soc = {
 	/* 1 pem */
 	pems = (
 		{
 			idx = 0;
 			/* 1 pf per pem */
                        pfs = (
 				{
                                        idx = 0;
 					mac_addr = [0x00, 0x00, 0x00, 0x01, 0x01];
 					link_state = 0;
 					rx_state = 0;
 					autoneg = 0x3;
 					pause_mode = 0x3;
 					speed = 10000;
 					supported_modes = 0x1;
 					advertised_modes = 0x1;
 					hb_interval = 1000;
 					hb_miss_count = 20;
 					/* 64 vf's per pf */
 					vfs = (
 						{
 							idx = 0;
 							mac_addr = [0x00, 0x00, 0x00, 0x01, 0x01, 0x01];
 							link_state = 0;
 							rx_state = 0;
 							autoneg = 0x3;
 							pause_mode = 0x3;
 							speed = 10000;
 							supported_modes = 0x1;
 							advertised_modes = 0x1;
 						},
                                        );
                                }
                        );
                }
        );
 };
