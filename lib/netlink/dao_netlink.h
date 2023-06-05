/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2023 Marvell.
 */

#ifndef _DAO_LIB_NETLINK_H_
#define _DAO_LIB_NETLINK_H_

#include <dao_net.h>
#include <dao_util.h>

#include <linux/netlink.h>
#include <linux/xfrm.h>
#include <linux/if.h>
#include <netlink/socket.h>
#include <netlink/addr.h>

#include <dao_netlink_route.h>
#include <dao_netlink_xfrm.h>
#include <dao_log.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file
 *
 * DAO Netlink Notification Infra
 *
 * This file, using open-source libnl library, provides low-level APIs to get
 * netlink notifications in application. Application @ref dao_netlink_register
 * "registers" to receive notification for a netlink protocol (eg:
 * NETLINK_ROUTE, NETLINK_XFRM, etc..) and multicast groups (eg: RTM_IP4_ROUTE,
 * RTM_IP6_ADDR, etc..) with @ref dao_netlink_parse_cb_t "parse_cb" function
 * pointer which is called when a netlink message corresponding to [protocol,
 * multicast_group] is received.
 *
 * Multiple multicast groups, corresponding to a protocol, can be passed as
 * comma-separated arguments to @ref dao_netlink_register. In fact, calling
 * @ref dao_netlink_register() for each multicast group with same protocol but
 * different @ref dao_netlink_parse_cb_t "parse_cb" is a valid usage.
 *
 * Library does not support providing different @ref dao_netlink_parse_cb_t
 * "parse_cb" for unique combination of [protocol, multicast_group].
 *
 * On a very first call to @ref dao_netlink_register(@b protocol,... ), a
 * netlink socket is internally created(specific to @b protocol) which needs
 * to be periodically polled for any new message. Applications are required to
 * periodically call @ref dao_netlink_poll(), in control processing context,
 * which internally polls all opened netlink sockets. All @ref
 * dao_netlink_parse_cb_t "parse_cbs" are called in @ref dao_netlink_poll()
 * processing context.
 *
 * Once parse_cb() is called in @b dao_netlink_poll() context, further polling
 * to corresponding netlink socket is disabled temporarily until application
 * does
 * not enable it by calling @ref dao_netlink_poll_complete() in the same
 * control context in which @ref dao_netlink_poll() is called. This gives
 * flexibility to application to control when netlink socket should be polled
 * for new message
 *
 * <I> This file defines low-level netlink infrastructure APIs where
 * applications are supposed to parse nl_object in @ref dao_netlink_parse_cb_t
 * "parse_cb" using libnl library. However for NETLINK_ROUTE and NETLINK_XFRM,
 * high-level APIs are provided by this library. Please refer to @b
 * dao_netlink_route_notifier_register() and @b
 * dao_netlink_xfrm_notifier_register() for more information </I>
 */

#define DAO_NETLINK_NOTIFIER_MAX_MULTICAST_GROUPS 128

/**
 * Application specific parse callback function of this type passed to @ref
 * dao_netlink_register() as an argument
 *
 * @param nl_obj
 *   Libnl netlink object. Use libnl APIs to parse this objectk
 * @param notifier
 *   A netlink notifier object internally created by this library for
 *   registered [protocol, multicast_groups]. User can retrieve following from
 *   APIs
 *   - @ref dao_netlink_notifier_callback_ops_get() to receive app_callback_ops
 *   passed to @ref dao_netlink_register()
 *   - @ref dao_netlink_notifier_app_cookie_get() to receive app_cookie passed
 *   to @ref dao_netlink_register()
 *   - @ref dao_netlink_notifier_nl_msg_get() to receive netlink message of
 *   type <I> struct nl_msg </I>
 *
 * @return
 *  None
 */
typedef void (*dao_netlink_parse_cb_t) (struct nl_object *nl_obj, void *notifier);

/**
 * API to call recvmsg() on all created netlink sockets for any new netlink message
 * Must be periodically called by an application in control core context
 *
 * @return
 *  0: Success
 * <0: Failure
 */
int dao_netlink_poll(void);

/**
 * Enable polling to netlink sockets for getting new message. Required to be
 * called after @ref dao_netlink_poll() in control core context
 *
 * @return
 *  0: Success
 * <0: Failure
 */
int dao_netlink_poll_complete(void);

/**
 * Close all opened netlink sockets and free any associated memory which is
 * allocated by library internally
 *
 * @return
 *  0: Success
 * <0: Failure
 */
int dao_netlink_cleanup(void);

/**
 * Close netlink sockets and free any associated memory which is
 * allocated by library internally for netlink object
 *
 * @param netlink
 *  Netlink object created for a "netlink protocol". Can be retrieved from @ref
 *  dao_netlink_lookup()
 *
 * @return
 *  0: Success
 * <0: Failure
 */
int dao_netlink_close(void *netlink);

/**
 * Register to receive notification for netlink messages corresponding to
 * [protocol, multicast_groups].
 *
 * @param protocol
 *   Netlink Protocol like NETLINK_ROUTE, NETLINK_XFRM
 * @param parse_cb
 *   Parse callback of syntax @ref dao_netlink_parse_cb_t in which caller is
 *   supposed to parse @b nl_obj
 * @param app_callback_ops
 *   Caller specific callback_ops which can be retrieved in @ref
 *   dao_netlink_parse_cb_t "parse_cb" via @ref
 *   dao_netlink_notifier_callback_ops_get(@b notifier)
 * @param app_cookie
 *   Caller specific app_cookie which can be retrieved in @ref
 *   dao_netlink_parse_cb_t "parse_cb" via @ref
 *   dao_netlink_notifier_app_cookie_get(@b notifier)
 * @param ...
 *   Comma-separated multi-cast groups like
 *   dao_netlink_register(..., RTNL_IP4_ROUTE, RTNL_IP4_ADDR, RTNL_IP4_LINK, RTNL_IP6_LINK)
 *
 * @return
 *  0: Success
 * <0: Failure
 */
int dao_netlink_register(int protocol, dao_netlink_parse_cb_t parse_cb,
			 void *app_callback_ops, void *app_cookie, ...);

/**
 * Translate netlink address object to generic struct in6_addr
 *
 * @param[out] ip_addr
 *   Pointer to ip_addr object
 * @param nladdr
 *   Pointer to Netlink address object
 *
 * @return
 *  0: Success
 *  <0: Failure
 */
int dao_netlink_nl_addr_to_in6(struct in6_addr *ip_addr, struct nl_addr *nladdr);

/**
 * Retrieve netlink object specific to protocol
 *
 * @param protocol
 *   Netlink protocol like NETLINK_ROUTE, NETLINK_XFRM
 *
 * @return
 *  NULL: When no netlink object is found for "netlink protocol",
 *  NON-NULL: A valid internal netlink object on which following APIs are valid
 *
 *  @see
 *  @ref dao_netlink_socket_get(),
 *  @ref dao_netlink_fd_get(),
 *  @ref dao_netlink_has_poll_recv()
 */
void *dao_netlink_lookup(int protocol);

/**
 * Has netlink socket received any message from polling. Also dao_netlink_poll_complete() is
 * yet to be called by application after dao_netlink_poll()
 *
 * @param netlink
 *  Netlink object created for a "netlink protocol". Can be retrieved from @ref dao_netlink_lookup()
 */
int dao_netlink_has_poll_recv(void *netlink);

/**
 * Get pointer to internal netlink socket created.
 *
 * @param netlink
 *  Netlink object created for a "netlink protocol". Can be retrieved from @ref dao_netlink_lookup()
 */
void *dao_netlink_socket_get(void *netlink);

/**
 * Get file descriptor with respect to netlink object
 *
 * @param netlink
 *  Netlink object created for a "netlink protocol". Can be retrieved from @ref dao_netlink_lookup()
 */
int dao_netlink_fd_get(void *netlink);

/**
 * Retrieve internal netlink_notifier object, if any, for a given app-specific parse_cb
 *
 * A netlink notifier object corresponds to [protocol, multicast_groups]
 * holding application specific @ref dao_netlink_parse_cb_t "parse_cb",
 * <I> app_callback_ops and  app_cookie </I>
 *
 * @param netlink
 *  Netlink object created for a "netlink protocol". Can be retrieved from @ref dao_netlink_lookup()
 * @param parse_cb
 *  @ref dao_netlink_parse_cb_t passed by application to @ref dao_netlink_register()
 *
 * @return
 *  NULL: When no netlink notifier object is found for parse_cb
 *  NON-NULL: A valid internal netlink notifier object on which following APIs are valid
 *
 *  @see
 *  @ref dao_netlink_notifier_app_cookie_get(),
 *  @ref dao_netlink_notifier_callback_ops_get(),
 *  @ref dao_netlink_notifier_nl_msg_get()
 */
void *
dao_netlink_notifier_lookup_by_parse_cb(void *netlink, dao_netlink_parse_cb_t parse_cb);

/**
 * Retrieve internal netlink_notifier object, if any, for a given app-specific
 * [parse_cb, multicast_group].
 *
 * A netlink notifier object corresponds to [protocol, multicast_groups]
 * holding application specific @ref dao_netlink_parse_cb_t "parse_cb",
 * <I> app_callback_ops and app_cookie </I>
 *
 * @param netlink
 *  Netlink object created for a "netlink protocol". Can be retrieved from @ref dao_netlink_lookup()
 * @param parse_cb
 *  @ref dao_netlink_parse_cb_t passed by application to @ref dao_netlink_register()
 * @param multicast_group
 *  A multicast group which is passed as comma-separated argument to @ref dao_netlink_register()
 *
 * @return
 * NULL: if netlink notifier object is not found
 * NON_NULL: Valid internal netlink notifier object:
 *   - If parse_cb is passed as NULL, an internal netlink notifier object with
 *   matching multicast_group is returned.
 *   - If valid parse_cb is provided, an internal netlink notifier with matching
 *   [parse_cb, multicast_group] is returned
 *
 * Following APIs are valid on NON-NULL returned netlink notifier object
 *
 *  @see
 *  @ref dao_netlink_notifier_app_cookie_get(),
 *  @ref dao_netlink_notifier_callback_ops_get().
 *  @ref dao_netlink_notifier_nl_msg_get()
 */
void *
dao_netlink_notifier_lookup_by_multicast_group(void *netlink, dao_netlink_parse_cb_t parse_cb,
					       uint32_t multicast_group);

/**
 * Get app_callback_ops from netlink_notifier object which is passed to @ref
 * dao_netlink_register()
 *
 * @param netlink_notifier
 *   Netlink notifier object retrieved via
 *   - @ref dao_netlink_notifier_lookup_by_parse_cb()
 *   - @ref dao_netlink_notifier_lookup_by_multicast_group()
 *   - @ref dao_netlink_parse_cb_t "parse_cb" passed to @ref dao_netlink_register()
 *
 * @return
 *  app_callback_ops passed by application in @ref dao_netlink_register
 */
void *dao_netlink_notifier_callback_ops_get(void *netlink_notifier);

/**
 * Get app_cookie from netlink_notifier object which is passed to @ref
 * dao_netlink_register()
 *
 * @param netlink_notifier
 *   Netlink notifier object retrieved via
 *   - @ref dao_netlink_notifier_lookup_by_parse_cb()
 *   - @ref dao_netlink_notifier_lookup_by_multicast_group()
 *   - @ref dao_netlink_parse_cb_t "parse_cb" passed to @ref dao_netlink_register()
 *
 * @return
 *  app_cookie passed by application in @ref dao_netlink_register
 */
void *dao_netlink_notifier_app_cookie_get(void *netlink_notifier);

/**
 * Get netlink message of type "struct nl_msg", a libnl object, from netlink notifier object
 *
 * @param netlink_notifier
 *   Netlink notifier object received in @ref dao_netlink_parse_cb_t "parse_cb"
 *   which is passed to @ref dao_netlink_register()
 *
 * @return
 *  Pointer to Netlink message is valid only a netlink message is received and
 *  dao_netlink_parse_cb_t "parse_cb" has been called by library as part of its
 *  message notification action
 */
void *dao_netlink_notifier_nl_msg_get(void *netlink_notifier);

#ifdef __cplusplus
}
#endif
#endif
