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

Binding DPI device
``````````````````

Check for device ID ``0xa080`` viz DPI and bind to vfio-pci

.. code-block:: console

 # lspci | grep a080
 0000:06:00.0 System peripheral: Cavium, Inc. Device a080

Bind to vfio-pci

.. code-block:: console

 echo  0000:06:00.0 > /sys/bus/pci/drivers/octeontx2-dpi/unbind
 echo  "177d a080" > /sys/bus/pci/drivers/vfio-pci/new_id
 echo  0000:06:00.0 > /sys/bus/pci/drivers/vfio-pci/bind

.. note ::
 Please ignore any error message, something like ``-bash: echo: write error: Device or resource busy``

Execute ``lspci -ks 0000:06:00.0`` to confirm successful binding of DPI device with vfio

.. code-block:: console

 # lspci -ks 0000:06:00.0
 0000:06:00.0 System peripheral: Cavium, Inc. Device a080
      Subsystem: Cavium, Inc. Device b900
      Kernel driver in use: vfio-pci

Running the octep-agent
-----------------------

.. code-block:: console

  /usr/bin/octep_cp_agent /usr/bin/<soc>.cfg  -- --dpi_dev 0000:06:00.0 --pem_dev 0001:00:10.0

  <soc> has to replaced with soc name of the target on which the app is to be run.
  Eg.
     /usr/bin/octep_cp_agent /usr/bin/cn106xx.cfg -- --dpi_dev 0000:06:00.0 --pem_dev 0001:00:10.0

To run the application in background and dump logs:

.. code-block:: console

   /usr/bin/octep_cp_agent /usr/bin/cn106xx.cfg -- --dpi_dev 0000:06:00.0 --pem_dev 0001:00:10.0 2>&1 > /tmp/octep-cp-log.txt &

Optional parameters
  ``-y`` <milliseconds> yield cpu for msecs between subsequent calls to msg poll (default: 1ms)

  ``-m`` <1-n> Max control messages and events to be polled at one time (default: 6)
  htop can be used to check cpu usage by the app

Upon successful launch of the application, the following logs will be displayed and application
will run in background

.. code-block:: console

 # CNXK: DPI: device = 0000:06:00.0; IOMMU group = 29
 CNXK: PEM: device = 0001:00:10.0; IOMMU group = 32
 LIB: init
 SOC: Model: cn10ka_a0
 CNXK: init
 CNXK: Created VFIO container successfully; fd=3
 CNXK: Initializing DPI ...
 CNXK: mapped DPI device region-0; size=0x100000000.
 CNXK: Enabling DPI engine 0 ...
 CNXK: Enabling DPI engine 1 ...
 CNXK: Enabling DPI engine 2 ...
 CNXK: Enabling DPI engine 3 ...
 CNXK: Enabling DPI engine 4 ...
 CNXK: Enabling DPI engine 5 ...
 CNXK: mapped PEM device region-0; size=0x40000000.
 CNXK: mapped PEM device region-4; size=0x100000.
 CNXK: CP mailbox: virt_addr = 0xfffe20000000; phys_addr = 0x320000000
 CNXK: Number of PEM interrupts = 10
 CNXK: Enabled PEM link down and PERST interrupts
 CNXK: pem[0] pf[0] control plane versions 10000:10000
 CNXK: pem[0] pf[0] mbox h2fq sz 16256 addr 0xfffe20000120
 CNXK: pem[0] pf[0] mbox f2hq sz 16256 addr 0xfffe200040a0
 CNXK: pem[0] pf[0] oei_trig_addr 0xffff44c10000
 CNXK: pem[0] pf[0] fw ready 1 addr 0xfffe44c18418

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
