..  SPDX-License-Identifier: Marvell-MIT
    Copyright (c) 2024 Marvell.

************
Flow Library
************

Introduction
============

The Flow Library provides interfaces to configure hardware for identifying the
traffic and executing actions based on rules defined by the user.
The library defines APIs for constructing flow rules that include match criteria
and a set of actions. Once a continuous stream of packets matching the flow is
received, the flow is offloaded to the hardware.

The flows can be cascaded, allowing a packet to proceed to another flow after a
flow-defined action is executed

There are some challenges which flow library can meet:

* Optimal performance is achieved when flow rules are offloaded to hardware, however,
  the capacity of TCAM entries, which store these flow rules, is finite. Consequently,
  once the TCAM entries reach their maximum limit, a precipitous decline in performance
  is inevitable.

  This TCAM limit can be mitigated via Flow library that manages these flows, making
  decisions on when to install and age out a flow from the hardware.

* This flow library could be instrumental in fulfilling the requirement of managing
  up to 1 million flows through software ACL tables.


Flow Rule
=========

A flow rule is the combination of attributes with a matching pattern and a list of
actions.

Refer `DPDK Flow Rule Description <https://doc.dpdk.org/guides/prog_guide/rte_flow.html#flow-rule>`_ for more details.

Programming Model
=================

The Flow Library is designed to provide a generic means for applications to offload
flows to hardware (HW) or perform ACL lookups in case of HW flow miss for packet
classification. Applications such as ovs-offload or virtio-l2fwd can subscribe to
this library.

Initialization
--------------

As part of the application initialization sequence, ``dao_flow_init()`` is invoked.
This function takes struct ``dao_flow_offload_config`` as input, providing details of
whether the ACL table should be backed by TCAM and the KEX profile to be used for ACL
lookup.
This function should be invoked for each port, taking into account that an application
can have two types of ports: RPM ports, which require hardware flow offloading, and
virtio ports, which do not have hardware TCAM backing

User flow offloading configuration structure

.. code-block:: c

 struct dao_flow_offload_config {
        /* Different features supported */
        uint32_t feature;
        /* Key exchange profiles supported */
        char parse_profile[DAO_FLOW_PROFILE_NAME_MAX];
        /* Flow aging timeout */
        uint32_t aging_tmo_sec;
 };

Flow initialization API

.. code-block:: c

 int dao_flow_init(uint16_t port_id, struct dao_flow_offload_config *config);

Arguments:
 ``config``: User provided flow offloading configuration

Sample initialization code:

.. code-block:: c

  struct dao_flow_offload_config config = {0};
  uint16_t port_id = 0;

  config.feature |= hw_offload_enable ? DAO_FLOW_HW_OFFLOAD_ENABLE : 0;
  rte_strscpy(config.parse_profile, prfl, DAO_FLOW_PROFILE_NAME_MAX);
  config.aging_tmo = 10;

  rc = dao_flow_init(port_id, &config);
  if (rc) {
        dao_err("Error: DAO flow init failed, err %d", rc);
        return;
  }

Flow Creation
-------------

``dao_flow_create()`` is used to add a new flow to the ACL table, which is maintained
per port. At this stage, the flow is added only to the ACL table and nothing goes to
TCAM.

.. code-block:: c

 struct dao_flow *dao_flow_create(uint16_t port_id, const struct rte_flow_attr *attr,
                                  const struct rte_flow_item pattern[],
                                  const struct rte_flow_action actions[],
                                  struct rte_flow_error *error);

Arguments:
 ``port_id``: Port identifier of Ethernet device
 ``attr``: Flow rule attributes
 ``pattern``: Pattern specification (list terminated by the END pattern item)
 ``actions``: Associated actions (list terminated by the END action)
 ``error``: Perform verbose error reporting if not NULL

Return value:
  A valid handle in case of success, NULL otherwise and errno is set

Flow Lookup
-----------

On the arrival of the first packet, the ACL table is looked up via ``dao_flow_lookup()``.
If no rule is found, the packet takes the exception path (i.e., port representor to OVS
path in the case of OVS). If a rule is hit, the flow is installed to the HW TCAM
(provided port has requested for HW offload capability while dao_flow_init()). One hit is
enough to decide to push the rule to HW.

.. code-block:: c

 int dao_flow_lookup(uint16_t port_id, struct rte_mbuf **objs, uint16_t nb_objs);

Arguments:
 ``port_id``: Port identifier of Ethernet device
 ``objs``: Array of packet buffers
 ``nb_objs``: No of packet buffers

Return value:
  0 on success, a negative errno value

Flow Destruction
----------------

Applications can call ``dao_flow_destroy()``. This function removes the rule from HW TCAM
(if installed) and ACL.

.. code-block:: c

 int dao_flow_destroy(uint16_t port_id, struct dao_flow *flow, struct rte_flow_error *error);

Arguments:
 ``port_id``: Port identifier of Ethernet device
 ``flow``: Flow rule handle to destroy
 ``error``: Perform verbose error reporting if not NULL

Return value:
  0 on success, a negative errno value

Flow Query
----------

This function enables the extraction of flow-specific data, such as counters, which is
accumulated through special actions that are integral to the flow rule definition.

.. code-block:: c

  int dao_flow_query(uint16_t port_id, struct dao_flow *flow, const struct rte_flow_action *action, void *data, struct rte_flow_error *error);

Arguments:
 ``port_id``: Port identifier of Ethernet device
 ``flow``: Flow rule handle to query
 ``action``: Action definition as defined in original flow rule
 ``data``: Pointer to storage for the associated query data type
 ``error``: Perform verbose error reporting if not NULL

Return value:
  0 on success, a negative errno value otherwise and rte_errno is set

Flow Flush
----------

In the unlikely event of failure, there may be a requirement to destroy all flow rule
handles associated with a port.

.. code-block:: c

 int dao_flow_flush(uint16_t port_id, struct rte_flow_error *error);

Arguments:
 ``port_id``: Port identifier of Ethernet device
 ``error``: Perform verbose error reporting if not NULL

Return value:
 0 on success, a negative value otherwise.

Flow Information
----------------

Dumping internal information about a flow.

.. code-block:: c

 int dao_flow_dev_dump(uint16_t port_id, struct dao_flow *flow, FILE *file, struct rte_flow_error *error);

Arguments:
 ``port_id``: The port identifier of the Ethernet device
 ``flow``: The pointer of flow rule to dump. Dump all rules if NULL
 ``file``: A pointer to a file for output
 ``error``: Perform verbose error reporting if not NULL

Return value:
 0 on success, a negative value otherwise.
