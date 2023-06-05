..  SPDX-License-Identifier: Marvell-MIT
    Copyright (c) 2024 Marvell.

******************
Port Group Library
******************

Introduction
============
Port group is a control path library that facilitates applications to iterate
over group of homogeneous ports (or devices) and apply common configurations on
them. Homogeneity of ports is decided by an application.

One such example of port grouping is iterating over all TAP PMD ports to enable
promiscuous mode on each of them.

Programming model
=================

Initializing Port group library
-------------------------------
Port group library must be first initialized using
``dao_port_group_main_init(int num_port_groups)`` before calling any of other
APIs. ``num_port_groups`` represents how many port groups are required by
applications to be supported by library

Creating a Port Group
---------------------
``dao_port_group_create(char *name, int max_ports, dao_port_group_t *)``
creates a port group object which supports to accommodate ``max_ports`` ports.
API returns port group handle ``dao_port_group_t``

Adding port to a Port Group
---------------------------
``dao_port_group_port_add(dao_port_group_t, dao_port_t, int32_t *index)`` adds
``dao_port_t`` to already created port group. On successful addition, returned
``index`` can be used to get ``dao_port_t`` via ``dao_port_group_port_get()``

Example of adding all TAP devices to a port group:

.. code-block:: c

   #include <dao_port_group.h>

   dao_port_group_t tap_group_handle = DAO_PORT_GROUP_INITIALIZER;
   struct rte_eth_dev_info dev_info;
   dao_port_t port;
   int32_t index;
   uint16_t i;

   dao_port_group_create("tap_devices", 10 /* max_tap_devices */, &tap_group_handle);

   RTE_ETH_FOREACH_DEV(i){
       if(!rte_eth_dev_is_valid(i))
           continue;

       rte_eth_dev_info_get(i, &dev_info);

       /* Identify if device is tap device by its driver name */
       if(strstr(devinfo.driver_name, "tap")){
          if(dao_port_group_add(tap_group_handle, i, &index) <0)
              return -1;

          /* Try retrieving newly added dao_port_t to port_group */
          dao_port_group_port_get(tap_group_handle, index, &port);

          /* Both must be same *//
          assert(i == (int32_t)port);
       }
   }

Number of ports in Port group
-----------------------------
See ``dao_port_group_port_get_num()``

Port group lookup by name
-------------------------
``dao_port_group_get_by_name (char *name, dao_port_group_t *handle)`` returns
port group handle of already created port group with name as ``name``

Iterating over Port group
-------------------------
Use ``DAO_PORT_GROUP_FOREACH_PORT()`` macro for iterating over all ports added
to ``dao_port_group_t`` as described below

.. code-block:: c

   #include <dao_port_group.h>

   dao_port_t port;
   int32_t index;

   DAO_PORT_GROUP_FOREACH_PORT(tap_group_handle, port, index) {
       /* Retrieved port is dpdk port id associated to a tap port added above
        *to tap_group_handle
        */
       rte_eth_dev_start(port);
       rte_eth_promiscuous_enable(port);
       rte_eth_dev_set_link_up(port);
   }

Deleting port from Port group
-----------------------------
See ``dao_port_group_port_delete()``

Destroying a Port group
-----------------------
See ``dao_port_group_destroy()``
