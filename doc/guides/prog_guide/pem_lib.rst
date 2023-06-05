..  SPDX-License-Identifier: Marvell-MIT
    Copyright (c) 2024 Marvell.

***********
PEM Library
***********

The PEM library provides a framework for memory mapping PEM(SDP) BAR region and dividing
BAR area among all VFs. BAR area would be used by other libraries such as ``virtio-net``
for communication between host and Octeon DPU FW. This library runs on Octeon DPU cores.

Prerequisites:
~~~~~~~~~~~~~~
* Load kernel module `pcie-marvell-cnxk-ep.ko` on Octeon DPU, which provisions framework
  for memory mapping PER bar area.

Device Identification
~~~~~~~~~~~~~~~~~~~~~
Each PEM device is designated by a unique device index starts from 0, in all functions.
It is the same device number where the PF/VF to host are setup such as PEM0, PEM1 etc.

Device Initialization
~~~~~~~~~~~~~~~~~~~~~

The initialization of each PEM device includes the following operations:

* Memory maps BAR area of PEM device to be used by other libraries such as ``virtio`` for
  communication between host and Octeon DPU FW.
* Divides BAR area among all the VFs based on ``host_page_sz``.
* Creates control thread ``pem_ctrl_reg_poll`` to poll on registered bar areas to get
  notified when something changes by the host.

The ``dao_pem_dev_init()`` API is used to initialize a PEM device.

.. code-block:: c

   int dao_pem_dev_init(uint16_t pem_devid, struct dao_pem_dev_conf conf)

The ``dao_pem_dev_conf`` structure is used to pass the configuration parameters. Currently,
application is expected to pass the host_page_sz, which will be used to divide
the bar area among the VFs as notification area of each virtqueue must be ``host_page_sz``
aligned. Number of VF's to divide is based on number of VF's configured in Host PF config space.
This VF count is controllable via Octeon's boot menu. Less VF's implies more pages/queues available
per VF.

.. literalinclude:: ../../../lib/pem/dao_pem.h
   :language: c
   :start-at: struct dao_pem_dev_conf
   :end-before: End of structure dao_pem_dev_conf.

Memory regions registration for polling
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

PEM library provisions polling on registered areas. So that, other libraries such as ``virtio``
can register memory regions to get notified when something changes on that region.

The API ``dao_pem_ctrl_region_register()`` is used to register the memory regions.

.. code-block:: c

   dao_pem_ctrl_region_register(uint16_t pem_devid, uintptr_t base, uint32_t len,
                                dao_pem_ctrl_region_cb_t cb, void *ctx, bool sync_shadow)

PEM library calls the ``cb`` when something changes in the memory specified by ``base``.

Get VF specific bar region info
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The API ``dao_pem_vf_region_info_get()`` is used to get VF specific bar region info.

.. code-block:: c

   dao_pem_vf_region_info_get(uint16_t pem_devid, uint16_t dev_id, uint8_t bar_idx, uint64_t *addr,
                              uint64_t *size)

This API uses a PEM device identifier and a VF device identifier to specify the VF.
Currently, a PEM device can have maximum of 64 VFs.
