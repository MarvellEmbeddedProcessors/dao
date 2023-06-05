..  SPDX-License-Identifier: Marvell-MIT
    Copyright (c) 2024 Marvell.

************************
Port Queue Group Library
************************

Introduction
============
Port queue group is a fast path library that facilitates each ``core``
to iterate over list of ``[port, queue]`` groups for polling.

In a typical ``rte_graph`` application various source nodes (nodes registered
with ``RTE_NODE_SOURCE_F``) are created for calling ``rte_eth_rx_burst()`` on
each ``[port, queue]``. Assume there are 2 ethdev ports and each port has 8
queues assigned to each core in a system. Two source nodes (``rte_node_t``)
would be needed on each core for polling [port-0, queue-Cx] and [port-1,
queue-Cx], where Cx indicates core_id

Port queue library facilitates to create single source node (``rte_node_t``) on
a core capable of polling multiple ``[port, queue]`` combinations. Thereby
optimally utilizing ICACHE benefits by having small code foot print. It also
allows run time addition/deletion of ``[port, queue]`` combination from a port
queue group

Programming model
=================

Initializing Port queue group library
-------------------------------------
Port queue group library must be first initialized using
``dao_portq_group_init(int num_port_queue_groups)`` before calling any of other
APIs. ``num_port_queue_groups`` represents how many port queue groups are required by
applications to be supported by library

Creating a Port queue group
---------------------------
``dao_portq_group_create(char *name, int num_cores, int num_ports, dao_portq_group_t *)``
creates a port queue group object which supports to accommodate ``num_ports``
on ``num_cores``. API returns port queue group handle ``dao_portq_group_t``

Assigning [port, queue] to a core within Port queue group
------------------------------------------------------------
``dao_portq_group_portq_add (dao_portq_group_t, int core_id, dao_portq_t, int *index)``
assigns ``dao_portq_t`` (aka [port, queue]) to a core of port queue group. On successful
addition, returned ``index`` can be used to get next ``dao_portq_t`` via
``dao_portq_group_portq_get_next())``

Example of adding ``[port, queue]`` to a port queue group:

.. code-block:: c

   #include <dao_portq_group.h>

   dao_portq_group_t portq_handle = DAO_PORTQ_GROUP_INITIALIZER;
   dao_portq_t portq;
   int num_workers = 8;
   int num_ports = 2;
   int32_t index;

   dao_portq_group_create("sample_portq", num_workers, num_ports, &portq_handle);

   for(i=0; i< num_workers; i++){
       for(j=0; j< num_ports, j++){
           portq.port_id = j;
           portq.rq_id = i;
           dao_portq_group_portq_add(portq_handle, i, &portq, &index);
       }
   }

Number of [port, queue] in Port queue group
-------------------------------------------
See ``dao_portq_group_portq_get_num()``

Port queue group lookup by name
-------------------------------
``dao_portq_group_get_by_name (char *name, dao_portq_group_t *handle)`` returns
port queue group handle of already created port queue group with name as ``name``

Iterating over Port queue group on fast path core
-------------------------------------------------
Use fast path macro ``DAO_PORTQ_GROUP_FOREACH_CORE`` on each polling core as
follows

.. code-block:: c

   #include <dao_portq_group.h>

   source_node_process_func(...)
   {
      dao_portq_group_t pg = DAO_PORTQ_GROUP_INITIALIZER;
      struct rte_mbuf *num_bufs[256];
      dao_portq_t portq;
      int32_t index;

      /* Lookup portq group that we created above */
      if(dao_portq_group_get_by_name("sample_portq", &pg)<0)
          return -1;

      /* Iterate over all [port, queue] assigned to this core */
      DAO_PORT_GROUP_FOREACH_PORT(pg, &portq, index) {
          rte_eth_rx_burst(portq.port_id, portq.rq_id, num_bufs, 256);

          /* process mbufs here */
      }
   }

Deleting port from Port queue group
-----------------------------------
See ``dao_portq_group_portq_delete()``

Destroying a Port queue group
-----------------------------
See ``dao_portq_group_destroy()``
