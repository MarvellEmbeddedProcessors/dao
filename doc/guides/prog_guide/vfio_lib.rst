..  SPDX-License-Identifier: Marvell-MIT
    Copyright (c) 2024 Marvell.

*********************
VFIO Platform Library
*********************
Platform devices in Linux refer to System-on-Chip (SoC) components that aren't situated on standard
buses such as PCI or USB. You can see them in Linux at the path /sys/bus/platform/devices/. To
interact with platform devices from user space, the vfio-platform driver provides a framework. This
library provides DAO APIs built upon this framework, enabling access to the device resources.

Prerequisites:
~~~~~~~~~~~~~~
To make use of VFIO platform framework, the ``vfio-platform`` module must be loaded first:

.. code-block:: console

   sudo modprobe vfio-platform

.. note::

   By default ``vfio-platform`` assumes that platform device has dedicated reset driver. If such
   driver is missing or device does not require one, this option can be turned off by setting
   ``reset_required=0`` module parameter.

Afterwards, the platform device needs to be bound to vfio-platform, following a standard two-step
procedure. Initially, the driver_override, located within the platform device directory, must be
configured to vfio-platform:

.. code-block:: console

   echo vfio-platform | sudo tee /sys/bus/platform/devices/DEV/driver_override

Next ``DEV`` device must be bound to ``vfio-platform`` driver:

.. code-block:: console

   echo DEV | sudo tee /sys/bus/platform/drivers/vfio-platform/bind


Platform device initialization
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Invoking the `dao_vfio_platform_init()` API creates a VFIO container by opening the /dev/vfio/vfio
character device and initializes the memory used for storing the details of platform devices. This
API should be invoked only once to initiate the library.

.. code-block:: c

   int dao_vfio_platform_init(void);

After initializing the library, the `dao_vfio_platform_device_setup()` API can be used to initialize
a platform device. The function takes the memory for storing platform device details, specified by
the `struct dao_vfio_platform_device` argument. Upon successful execution, the resources of the
platform devices are mapped, and the device structure is populated.

.. code-block:: c

   int dao_vfio_platform_device_setup(const char *dev_name, struct dao_vfio_platform_device *pdev);

.. literalinclude:: ../../../lib/vfio/dao_vfio_platform.h
   :language: c
   :start-at: struct dao_vfio_mem_resouce
   :end-before: End of structure dao_vfio_platform_device.


Platform device cleanup
~~~~~~~~~~~~~~~~~~~~~~~

`dao_vfio_platform_device_free()` releases the VFIO platform device and frees the associated
memory.

.. code-block:: c

   void dao_vfio_platform_device_free(struct dao_vfio_platform_device *pdev);


Upon closing all open devices, the container can be shut down by calling `dao_vfio_platform_fini()`.

.. code-block:: c

   void dao_vfio_platform_fini(void);

