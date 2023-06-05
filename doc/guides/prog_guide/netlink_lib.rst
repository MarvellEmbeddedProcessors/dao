..  SPDX-License-Identifier: Marvell-MIT
    Copyright (c) 2024 Marvell.

******************
Netlink Library
******************

Introduction
============
Netlink library provides an abstraction on top of open source `libnl library
<https://www.infradead.org/~tgr/libnl/>`_ using which application gets
notified for a received netlink message from LINUX. Applications are notified
via function callback for the netlink protocols they have registered.

.. _Native_Netlink_Registration:

Native netlink registration
===========================
Registering for a netlink protocol via ``dao_netlink_register()`` is named
as *Native netlink registration*. ``dao_netlink_register()`` is a lowest level
abstraction API to get notifications for any netlink message that corresponds
to netlink protocol provided as an argument to it. ``dao_netlink_register()``
has following declaration:

.. code-block:: c

        int dao_netlink_register(int protocol, dao_netlink_parse_cb_t parse_cb,
                                 void *app_ops, void *app_cookie, ...);

        where,
        protocol eg: NETLINK_ROUTE, NETLINK_XFRM etc.
        parse_cb   : See documentation for more details
        app_ops    : Application specific function pointers
        app_cookie : Application cookie to identify received notification
        ...        : comma-separated netlink multicast groups. See documentation for more details

This registration is *native* in a sense that application is expected to parse
received netlink object (``struct nl_object *``) by itself, perhaps via `native
libnl APIs <https://www.infradead.org/~tgr/libnl/doc/core.html/>`_, which is
passed as an argument to :ref:`parse_cb<Native_Parse_Callback>`

Applications which does not wish to parse netlink object (``struct nl_object
*``) or rather work with any libnl APIs, please refer to :ref:`high level
netlink registration<HighLevel_Netlink_Registration>` section

Netlink protocols
-----------------
``dao_netlink_register()`` takes `netlink protocol or netlink family
<https://github.com/torvalds/linux/blob/master/include/uapi/linux/netlink.h#L9>`_
as a first argument. Examples of netlink protocols are: *NETLINK_ROUTE*,
*NETLINK_XFRM*, *NETLINK_GENERIC*

.. _Netlink_Object:

Netlink Object
~~~~~~~~~~~~~~
On successful return, ``dao_netlink_register()`` internally opens a netlink
socket for provided netlink ``protocol``. It also internally creates a
``netlink`` object for registered protocol. For a given netlink protocol,
exactly one ``netlink`` object is created which holds ``netlink`` socket and
file descriptor associated with it.

Application can perform following actions on a ``netlink`` object

Registered netlink object lookup
''''''''''''''''''''''''''''''''
Get netlink object corresponding registered netlink protocol

.. code-block:: c

   void *notifier = dao_netlink_lookup(NETLINK_ROUTE);

Get netlink file descriptor
'''''''''''''''''''''''''''
.. code-block:: c

   int fd = dao_netlink_fd_get(netlink);

Netlink object cleanup
''''''''''''''''''''''
Close netlink socket and free any associated memory including all ``notifier`` objects

.. code-block:: c

   dao_netlink_close(netlink);

.. _Native_Parse_Callback:

Native parse callbacks
----------------------
Function callbacks of type ``dao_netlink_parse_cb_t`` are called as native
parse callbacks which has following function declaration

.. code-block:: c

   typedef void (*dao_netlink_parse_cb_t) (struct nl_object *nl_obj, void *notifier);

Applications are expected to parse ``struct nl_object *`` by itself using
`libnl core APIs
<https://www.infradead.org/~tgr/libnl/doc/core.html/>`_.``notifier`` is
a :ref:`notifier object<Notifier_Object>`

.. _Multicast_Groups:

Netlink multicast groups
------------------------
Each netlink family or protocol has set of defined multicast groups.
Application should be able to provide specific multicast group it would like to
get notification for within a given protocol. Examples for multicast groups are

.. code-block:: c

   Protocol               Multicast Groups
   --------               ----------------
   NETLINK_ROUTE          RTNLGRP_LINK, RTNLGRP_IPV4_IFADDR, RTNLGRP_IPV4_ROUTE,
                          RTNLGRP_IPV4_RULE, RTNLGRP_IPV6_IFADDR, RTNLGRP_IPV6_ROUTE,
                          RTNLGRP_IPV6_RULE, RTNLGRP_NOTIFY, RTNLGRP_NEIGH etc..

   NETLINK_XFRM           XFRMGRP_SA, XFRMGRP_POLICY, XFRMGRP_EXPIRE

Multicast groups for a netlink protocol are provided as
comma-separated arguments to ``dao_netlink_register()``. For eg:

.. code-block:: c

   dao_netlink_register(NETLINK_ROUTE, route_parse_cb, NULL, NULL,
                        RTNLGRP_IPV4_ROUTE, RTNLGRP_LINK, RTNL_GRP_IPV4_IFADDR);

   dao_netlink_register(NETLINK_XFRM, xfrm_parse_cb, NULL, NULL,
                        XFRMGRP_SA, XFRMGRP_POLICY, XFRMGRP_EXPIRE);

It is possible to provide separate ``parse_cb()`` for each multicast group like
following

.. code-block:: c

   dao_netlink_register(NETLINK_ROUTE, parse_cb1, ops1, aux1, RTNLGRP_IPV4_ROUTE);
   dao_netlink_register(NETLINK_ROUTE, parse_cb2, ops2, aux2,, RTNLGRP_LINK);

In above case, parse_cb1() will be called once RTNLGRP_IPV4_ROUTE netlink
messages are received while parse_cb2() will be called if netlink messages
corresponding to RTNLGRP_LINK are received.

.. warning::

   Providing different parse callbacks for same multicast group is not
   supported

.. _Notifier_Object:

Notifier Object
---------------
As :ref:`described above<Multicast_Groups>`, ``dao_netlink_register()`` can be
called multiple times for each combination of *[protocol, multicast group]*.
For each multicast group, different specific cookies can be provided. For eg:

.. code-block:: c

   dao_netlink_register(NETLINK_ROUTE, parse_cb1, app_ops1, app_cookie1, RTNLGRP_IPV4_ROUTE);
   dao_netlink_register(NETLINK_ROUTE, parse_cb2, app_ops2, app_cookie2, RTNLGRP_LINK);

For each ``dao_netlink_register()`` successful registration, library internally
creates a ``notifier`` object which keep hold of all provided multicast groups,
application specific ``app_ops`` and ``app_cookie``.

``Notifier`` object is passed as an argument to :ref:`parse_cb(struct nl_object
*obj, void *netlink)<Native_Parse_Callback>`. Application specific cookies can
be retrieved in ``parse_cb()``

Application specific ops
~~~~~~~~~~~~~~~~~~~~~~~~
.. code-block:: c

   void *app_ops = dao_netlink_notifier_callback_ops_get(notifier);

Application specific cookie
~~~~~~~~~~~~~~~~~~~~~~~~~~~
.. code-block:: c

   void *app_cookie = dao_netlink_notifier_app_cookie_get(notifier);

Get notifier object for a given parse_cb
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
.. code-block:: c

   void *notifier = dao_netlink_notifier_lookup_by_parse_cb(netlink, parse_cb);

.. _HighLevel_Netlink_Registration:

High level netlink registration
===============================
High level netlink registrations are wrappers on top of :ref:`native netlink
registration<Native_Netlink_Registration>` where application does not deal
with libnl APIs or structures, instead this library defines function callbacks
for each of the netlink protocol supported for high level registration.

Following protocols are supported for high level netlink registration.

NETLINK_ROUTE
-------------
.. code-block:: c

   dao_netlink_route_notifier_register(dao_netlink_route_callback_ops_t *ops,
                                       const char *filter_prefix);

Refer to ``dao_netlink_route_callback_ops_t`` for getting route netlink message
notifications

NETLINK_XFRM
-------------
.. code-block:: c

   dao_netlink_xfrm_notifier_register(dao_netlink_xfrm_callback_ops_t *ops, void *app_cookie);

Refer to ``dao_netlink_xfrm_callback_ops_t`` for getting XFRM netlink message
notifications


Programming model
=================

Initialization
--------------
Either use :ref:`native<Native_Netlink_Registration>` or :ref:`high
level<HighLevel_Netlink_Registration>` registration mechanism for getting
netlink message notifications

Periodic Netlink polling
------------------------
A control core is supposed to poll all ``netlink`` objects for any new netlink
message arrival and hence ``recvmsg()`` like function must be invoked on all
opened netlink sockets.

For netlink polling, applications are required to call following APIs periodically
for getting any new netlink notifications

dao_netlink_poll()
~~~~~~~~~~~~~~~~~~
Periodically calls ``recvmsg()`` on all created netlink sockets and call
application specific function callback for any new netlink message

dao_netlink_poll_complete()
~~~~~~~~~~~~~~~~~~~~~~~~~~~
Once a notification is sent to application for a netlink message via
``dao_netlink_poll()``, library disables further polling on that specific
netlink socket until application does not call ``dao_netlink_poll_complete()``.
This API enables polling on all netlink sockets which are disabled temporarily
after new message notification

``dao_netlink_poll_complete()`` is useful in use-case where ``dao_netlink_poll()`` is
running in another thread context, perhaps in continuous loop, and current
thread wants to control its polling using ``dao_netlink_poll_complete()``

Pseudo-code
~~~~~~~~~~~
Following example shows how to receive route updates for LINUX tap interfaces:
``dtap0`` and ``dtap1``

.. code-block:: c

   /* Get application specific identifier or cookie for each interface name
    * which is passed in remaining function callbacks
    */
   int rops_app_interface_cookie (char *interface_name, int interface_name,
                                  uint32_t *cookie)
   {
       if(strstr(interface_name, "dtap0") {
           /* Return 0th index for tap0 interface */
           *cookie = 0;
           return 0;
       } else if (strstr (interface_name, "dptap1") {
           /* Return 1st index for tap1 interface */
           *cookie = 0;
           return 0;
       } else {
           /* interested only on dtap0 and dtap1 interface only */
           return -1;
       }
   }

   /* Set Local IP to interface */
   int rops_app_ip_local_addr_add_del(dao_netlink_route_ip_addr_t *addr, int is_add)
   {
       int interface_cookie = addr->app_if_cookie; /*< Set in get_app_interface_cookie() */

       if(interface_cookie == 0){
           /* Apply IP address to interface dtap0 */
       } else
           /* Apply IP address to interface dtap1 */
   }

   /* Update mac address */
   int rops_app_link_addr_add_del(dao_netlink_route_link_t *link, int is_add)
   {
       int interface_cookie = link->app_if_cookie; /*< Set in get_app_interface_cookie() */

       if(interface_cookie == 0){
           /* Update link "dtap0" */
       } else
           /* Update link "dtap1" *//
   }


   dao_netlink_route_callback_ops_t rops {
       .get_app_interface_cookie = rops_app_interface_cookie,
       .ip_local_addr_add_del = rops_app_ip_local_addr_add_del,
       .ip_route_add_del = rops_app_ip_route_add_del,
       .link_add_del = rops_app_link_add_del,
       .ip_neigh_add_del = rops_app_ip_neigh_add_del,
   };

    int __poll_function(void *obj, const int is_main)
    {
        rte_graph_t *graph = (rte_graph_t *)obj

        /* Get this worker core handle for graph */
        graph = graph + rte_lcore_id();

        while (1) {
           if (is_main) {

              dao_netlink_poll();

               ...
               ... Do other stuff
               ...

              dao_netlink_poll_complete();

            } else {
                rte_graph_walk(graph);
            }
        }
    }

    void poll_function(void *obj)
    {
        if (rte_lcore_id() == rte_get_main_lcore()) {
                __poll_function(obj, 1);
        } else {
                __poll_function(obj, 0);
        }
    }

    int main ()
    {
       rte_graph_t graph[RTE_LCORE_MAX];

       /* Use high level netlink registration method */
       if (dao_netlink_route_notifier_register(&rops, "dtap" /* prefix string for dtap0 and dtap1 */) < 0)
           return -1;

        /* Create rte_graph object for every lcore_id */
        ...
        ...
        ...

       rte_eal_remote_launch(poll_function, graph,  CALL_MAIN);
    }

Netlink Cleanup
---------------
Call ``dao_netlink_cleanup()`` to close all netlink sockets and notifier object including any associated memory
