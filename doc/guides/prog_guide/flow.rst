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

* This flow library can be used to manage millions of flows using hardware-accelerated
  exact match tables via CPT engines, or through software ACL tables.


Flow Rule
=========

A flow rule is the combination of attributes with a matching pattern and a list of
actions.

Refer `DPDK Flow Rule Description <https://doc.dpdk.org/guides-24.07/prog_guide/rte_flow.html#flow-rule>`_ for more details.

Programming Model
=================

The Flow Library is designed to provide a generic means for applications to offload
flows to hardware (HW) or perform lookups in software maintained tables(ACL or EM)
in case of HW flow miss for packet classification. Applications such as ovs-offload
or virtio-l2fwd can subscribe to this library.

The library supports multiple algorithms for flow matching:
* **EM (Exact Match)**: Software-based exact match hash tables
* **ACL**: Software-based ACL tables
* **CPT-EM (CPT Exact Match)**: Hardware-accelerated exact match tables using CPT (Crypto Processing Unit) hardware

Initialization
--------------

As part of the application initialization sequence, ``dao_flow_init()`` is invoked.
This function takes struct ``dao_flow_offload_config`` as input, providing details of
whether the flow table should be backed by TCAM, the KEX profile to be used for key
extraction and the algorithm (ACL based table, EM hash table, or CPT-EM table).
This function should be invoked for each port, taking into account that an application
can have two types of ports: RPM ports, which require hardware flow offloading, and
virtio ports, which do not have hardware TCAM backing

User flow offloading configuration structure

.. code-block:: c

 struct dao_flow_offload_config {
        /* Different features supported */
        #define DAO_FLOW_HW_OFFLOAD_ENABLE DAO_BIT(0)
        uint32_t feature;
        #define DAO_FLOW_ALG_EM     DAO_BIT(0)
        #define DAO_FLOW_ALG_ACL    DAO_BIT(1)
        #define DAO_FLOW_ALG_CPT_EM DAO_BIT(2)
        uint32_t alg;
        #define DAO_FLOW_KEX_DEFAULT DAO_BIT(0)
        #define DAO_FLOW_KEX_OVS     DAO_BIT(1)
        #define DAO_FLOW_KEX_CPT_EM  DAO_BIT(2)
        uint32_t kex_profile;
        /* Key exchange profiles supported */
        char parse_profile[DAO_FLOW_PROFILE_NAME_MAX];
        /* Flow aging timeout in seconds */
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
  config.kex_profile = DAO_FLOW_KEX_OVS;
  config.alg = DAO_FLOW_ALG_ACL;
  rte_strscpy(config.parse_profile, prfl, DAO_FLOW_PROFILE_NAME_MAX);
  config.aging_tmo_sec = 10;

  rc = dao_flow_init(port_id, &config);
  if (rc) {
        dao_err("Error: DAO flow init failed, err %d", rc);
        return;
  }

CPT-EM (CPT Exact Match) Configuration
---------------------------------------

CPT-EM provides hardware-accelerated exact match table functionality using the CPT
(Crypto Processing Unit) hardware. This feature leverages CPT microcode for key
generation and lookup operations, providing high-performance flow matching capabilities.

To use CPT-EM, configure the flow library with the following settings:

.. code-block:: c

  struct dao_flow_offload_config config = {0};
  uint16_t port_id = 0;

  config.feature |= hw_offload_enable ? DAO_FLOW_HW_OFFLOAD_ENABLE : 0;
  config.kex_profile = DAO_FLOW_KEX_CPT_EM;
  config.alg = DAO_FLOW_ALG_CPT_EM;
  rte_strscpy(config.parse_profile, "cpt-em", DAO_FLOW_PROFILE_NAME_MAX);
  config.aging_tmo_sec = 10;

  /* CPT-specific options */
  config.cpt_egrp = 0;                /* CPT engine group (0 or 1) */
  config.cpt_ctx_cache_enable = true;  /* Enable on-chip SRAM context caching */
  config.cpt_null_mode = false;        /* Set true for passthrough (benchmarking only) */

  rc = dao_flow_init(port_id, &config);
  if (rc) {
        dao_err("Error: DAO flow init failed, err %d", rc);
        return;
  }

CPT-specific configuration fields:

* ``cpt_egrp``: CPT engine group to use (0 or 1). Both SE engine groups are supported.
* ``cpt_ctx_cache_enable``: When set to ``true``, enables context caching which allows
  the EM table to be loaded into CPT's on-chip SRAM for faster lookups. Required for
  using ``dao_flow_ctx_cache_warm()``.
* ``cpt_null_mode``: When set to ``true``, CPT instructions are submitted in passthrough
  mode (no actual EM lookup). This is useful for benchmarking CPT submission overhead.

Key Features of CPT-EM:

* **Hardware Acceleration**: Key generation and lookup operations are performed by CPT
  hardware microcode, providing superior performance compared to software-based EM tables.

* **KEX Profile**: The CPT-EM KEX (Key Extraction) profile ("cpt-em") is specifically
  designed for CPT hardware. While key generation is handled by CPT microcode, the KEX
  profile is still required to validate and create keys from rte_flow patterns and actions.

* **Key Configuration**: The CPT-EM profile supports key extraction from multiple layers:
  - Layer 2: Destination MAC address (DMAC) - 6 bytes
  - Layer 3: Source IP address (SIP) for IPv4 - 4 bytes
  - Layer 3: Destination IP address (DIP) for IPv4 - 4 bytes
  - Layer 4: Source port (SPORT) for UDP - 2 bytes

* **Supported Protocols**: The CPT-EM profile supports Ethernet, VLAN, IPv4, IPv6, UDP,
  and TCP protocols for both RX and TX interfaces.

* **Table Capacity**: CPT-EM tables can support up to 4 million entries, providing
  scalability for high-flow-count scenarios.

CPT-EM Lookup Architecture
~~~~~~~~~~~~~~~~~~~~~~~~~~

When ``dao_flow_lookup()`` is called with CPT-EM, the lookup follows a hardware-accelerated
path:

1. For each packet in the burst, a CPT instruction (``cpt_inst_s``) is prepared with the
   extracted key from the packet headers.
2. The instructions are submitted to CPT hardware in bulk via ``rte_pmd_cnxk_crypto_submit``.
3. CPT hardware performs the exact match lookup using its microcode and writes results back
   to memory.
4. The results are polled and action processing (mark, count) is applied to matching packets.

This offloads the hash computation and table lookup entirely to CPT hardware, freeing
CPU cycles for other processing.

.. note::

   The maximum burst size for ``dao_flow_lookup()`` is 2048 packets. Passing a larger
   ``nb_objs`` value will return ``-EINVAL``.

Context Cache Warming
~~~~~~~~~~~~~~~~~~~~~

For optimal lookup performance, CPT-EM supports context cache warming, which converts
the EM table to big-endian format and loads it into CPT's on-chip SRAM cache. Once warmed,
subsequent lookups bypass external memory accesses for the table data.

.. code-block:: c

  /* After all rules are installed and before starting the data path */
  rc = dao_flow_ctx_cache_warm(port_id);
  if (rc) {
        dao_err("Context cache warm failed, err %d", rc);
  }

.. code-block:: c

 int dao_flow_ctx_cache_warm(uint16_t port_id);

Arguments:
 ``port_id``: Port identifier of Ethernet device

Return value:
 | 0 on success
 | ``-ENOTSUP`` if the current flow algorithm is not CPT-EM
 | ``-EINVAL`` if context caching was not enabled at init (``cpt_ctx_cache_enable``)

Prerequisites:

* ``cpt_ctx_cache_enable`` must be set to ``true`` in ``dao_flow_offload_config`` during
  initialization.
* All flow rules should be installed before warming the cache, as the table contents are
  converted to big-endian format for hardware consumption.
* Context cache warming is a one-time operation per port. After warming, newly added rules
  will still work but may not benefit from the cache until the next warm cycle.

Flow Creation
-------------

``dao_flow_create()`` is used to add a new flow to the flow table, which is maintained
per port. At this stage, the flow is added only to the flow table and nothing goes to
TCAM.

.. code-block:: c

 struct dao_flow *dao_flow_create(uint16_t port_id, const struct rte_flow_attr *attr,
                                  const struct rte_flow_item pattern[],
                                  const struct rte_flow_action actions[],
                                  struct rte_flow_error *error);

Arguments:
 | ``port_id``: Port identifier of Ethernet device
 | ``attr``: Flow rule attributes
 | ``pattern``: Pattern specification (list terminated by the END pattern item)
 | ``actions``: Associated actions (list terminated by the END action)
 | ``error``: Perform verbose error reporting if not NULL

Return value:
  A valid handle in case of success, NULL otherwise and errno is set

Flow Lookup
-----------

On the arrival of the first packet, the table is looked up via ``dao_flow_lookup()``.
If no rule is found, the packet takes the exception path (i.e., port representor to OVS
path in the case of OVS). If a rule is hit, the flow is installed to the HW TCAM
(provided port has requested for HW offload capability while dao_flow_init()). One hit is
enough to decide to push the rule to HW.

.. code-block:: c

 int dao_flow_lookup(uint16_t port_id, struct rte_mbuf **objs, uint16_t nb_objs);

Arguments:
 | ``port_id``: Port identifier of Ethernet device
 | ``objs``: Array of packet buffers
 | ``nb_objs``: No of packet buffers

Return value:
  0 on success, a negative errno value

Flow Destruction
----------------

Applications can call ``dao_flow_destroy()``. This function removes the rule from HW TCAM
(if installed) and the flow table.

.. code-block:: c

 int dao_flow_destroy(uint16_t port_id, struct dao_flow *flow, struct rte_flow_error *error);

Arguments:
 | ``port_id``: Port identifier of Ethernet device
 | ``flow``: Flow rule handle to destroy
 | ``error``: Perform verbose error reporting if not NULL

Return value:
  0 on success, a negative errno value

Flow Query
----------

This function enables the extraction of flow-specific data, such as counters, which is
accumulated through special actions that are integral to the flow rule definition.

.. code-block:: c

  int dao_flow_query(uint16_t port_id, struct dao_flow *flow, const struct rte_flow_action *action, void *data, struct rte_flow_error *error);

Arguments:
 | ``port_id``: Port identifier of Ethernet device
 | ``flow``: Flow rule handle to query
 | ``action``: Action definition as defined in original flow rule
 | ``data``: Pointer to storage for the associated query data type
 | ``error``: Perform verbose error reporting if not NULL

Return value:
  0 on success, a negative errno value otherwise and rte_errno is set

Flow Flush
----------

In the unlikely event of failure, there may be a requirement to destroy all flow rule
handles associated with a port.

.. code-block:: c

 int dao_flow_flush(uint16_t port_id, struct rte_flow_error *error);

Arguments:
 | ``port_id``: Port identifier of Ethernet device
 | ``error``: Perform verbose error reporting if not NULL

Return value:
 0 on success, a negative value otherwise.

Flow Information
----------------

Dumping internal information about a flow.

.. code-block:: c

 int dao_flow_dev_dump(uint16_t port_id, struct dao_flow *flow, FILE *file, struct rte_flow_error *error);

Arguments:
 | ``port_id``: The port identifier of the Ethernet device
 | ``flow``: The pointer of flow rule to dump. Dump all rules if NULL
 | ``file``: A pointer to a file for output
 | ``error``: Perform verbose error reporting if not NULL

Return value:
 0 on success, a negative value otherwise.

Installing flow directly into hardware
--------------------------------------

Install a flow rule on a given port which gets offloaded directly into the HW.

.. code-block:: c

 struct dao_flow *dao_flow_hw_install(uint16_t port_id, const struct rte_flow_attr *attr,
                                      const struct rte_flow_item pattern[],
                                      const struct rte_flow_action actions[],
                                      struct rte_flow_error *error);

Arguments:
 | ``port_id``: Port identifier of Ethernet device
 | ``attr``: Flow rule attributes
 | ``pattern``: Pattern specification (list terminated by the END pattern item)
 | ``actions``: Associated actions (list terminated by the END action)
 | ``error``: Perform verbose error reporting if not NULL

Return value:
  A valid handle in case of success, NULL otherwise and errno is set

Removing a flow from hardware
-----------------------------

Removing a flow rule on a given port which was directly offloaded to hardware.

.. code-block:: c

 int dao_flow_hw_uninstall(uint16_t port_id, struct dao_flow *flow,
                           struct rte_flow_error *error);

Arguments:
 | ``port_id``: Port identifier of Ethernet device
 | ``flow``: Pointer to flow which is to be removed.
 | ``error``: Perform verbose error reporting if not NULL

Return value:
 0 on success, a negative value otherwise.
