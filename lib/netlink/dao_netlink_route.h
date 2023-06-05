/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2023 Marvell.
 */

/**
 * @file
 *
 * DAO Netlink file for route notifications
 */

#ifndef _DAO_LIB_NETLINK_ROUTE_H
#define _DAO_LIB_NETLINK_ROUTE_H

#include <linux/rtnetlink.h>
#include <netlink/cache.h>
#include <netlink/route/addr.h>
#include <netlink/route/link.h>
#include <netlink/route/neighbour.h>
#include <netlink/route/route.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Default initializer for interface app_cookie. Interface app_cookie is
 * retrieved via @ref dao_netlink_route_callback_ops
 * "dao_netlink_route_callback_ops.get_app_interface_cookie()"  during
 * @ref dao_netlink_route_notifier_register()
 */
#define DAO_NETLINK_APP_IF_COOKIE_INITIALIZER (~0u)

/** rtnl cache neighbor entry states */
#define dao_foreach_netlink_neigh_states                                                           \
	_(0, INCOMPLETE) /* NUD_INCOMPLETE */                                                      \
	_(1, REACHABLE)  /* NUD_REACHABLE */                                                       \
	_(2, STALE)      /* NUD_STALE */                                                           \
	_(3, DELAY)      /* NUD_DELAY */                                                           \
	_(4, PROBE)      /* NUD_PROBE */                                                           \
	_(5, FAILED)     /* NUD_FAILED */                                                          \
	_(6, NOARP)      /* NUD_NOARP */                                                           \
	_(7, NONE)       /* NUD_NONE */                                                            \
	_(8, PERMANENT)  /* NUD_PERMANENT */

/** Rtnetlink protocol */
#define dao_foreach_netlink_route_proto                                                            \
	_(0, UNSPEC)   /* RTPROT_UNSPEC */                                                         \
	_(1, REDIRECT) /* RTPROT_REDIRECT */                                                       \
	_(2, KERNEL)   /* RTPROT_KERNEL */                                                         \
	_(3, BOOT)     /* RTPROT_BOOT */                                                           \
	_(4, STATIC)   /* RTPROT_STATIC */

/** DAO IP Route Protocol enum */
typedef enum {
#define _(n, state) DAO_NETLINK_ROUTE_PROTO_##state = RTPROT_##state,

	dao_foreach_netlink_route_proto
#undef _
} dao_netlink_route_proto_t;

typedef enum dao_netlink_action {
	DAO_NETLINK_ACTION_DEL = 0,		/*< Netlink notification indicates delete object */
	DAO_NETLINK_ACTION_ADD = 1,		/*< Netlink notification indicates add object */
	DAO_NETLINK_ACTION_REPLACE = 2,		/*<Netlink notification indicates replace object */
	DAO_NETLINK_ACTION_UNKNOWN,		/* Netlink notification indicates unknown action */
} dao_netlink_action_t;

/**
 * Structure describing IP Address which is filled from RTM_NEWADDR,
 * RTM_DELADDR netlink messages
 */
typedef struct dao_netlink_route_ip_addr {
	/** 1 if IPv4 or 0 otherwise */
	int is_ipv4;

	/** prefixlen of address */
	int prefixlen;

	/** application specific interface cookie */
	int app_if_cookie;

	/** linux notion of interface. See if_nametoindex() */
	int linux_ifindex;

	/** local address of interface */
	struct in6_addr local_in6_addr;

	/** addr_flags */
	unsigned int addr_flags;
} dao_netlink_route_ip_addr_t;

/** rtnl route object route types */
#define dao_foreach_netlink_route_types                                                            \
	_(0, UNSPEC)      /* RTN_UNSPEC */                                                         \
	_(1, UNICAST)     /* RTN_UNICAST */                                                        \
	_(2, LOCAL)       /* RTN_LOCAL */                                                          \
	_(3, BROADCAST)   /* RTN_BROADCAST */                                                      \
	_(4, ANYCAST)     /* RTN_ANYCAST */                                                        \
	_(5, MULTICAST)   /* RTN_MULTICAST */                                                      \
	_(6, BLACKHOLE)   /* RTN_BLACKHOLE */                                                      \
	_(7, UNREACHABLE) /* RTN_UNREACHABLE */                                                    \
	_(8, PROHIBIT)    /* RTN_PROHIBIT */                                                       \
	_(9, THROW)       /* RTN_THROW */                                                          \
	_(10, NAT)        /* RTN_NAT */                                                            \
	_(11, XRESOLVE)   /* RTN_XRESOLVE */

/** IP Route Types */
typedef enum {
#define _(n, state) DAO_NETLINK_ROUTE_TYPES_##state = RTN_##state,

	dao_foreach_netlink_route_types
#undef _
} dao_netlink_route_types_t;

/**
 * Nexthop route attributes
 *
 * if dao_netlink_route_ip_route_t.is_next_hop, nh_attr variables holds
 * attributes
 */
typedef enum {
	/** Nexthop route holds IP encapsulation (RTA_ENCAP) */
	DAO_NETLINK_ROUTE_NH_ATTR_ENCAP,
	/** Nexthop route holds new destination IP (RTA_NEWDST)*/
	DAO_NETLINK_ROUTE_NH_ATTR_NEWDST,
	/** Nexthop route holds via IP address (RTA_VIA) */
	DAO_NETLINK_ROUTE_NH_ATTR_VIA,
	/** Nexthop route holds via gateway IP address (RTA_VIA_GW) */
	DAO_NETLINK_ROUTE_NH_ATTR_VIA_GW,
	/** Nexthop route holds Ifindex for routing */
	DAO_NETLINK_ROUTE_NH_ATTR_IFINDEX,
	/** Netlink route weights for load-balancing */
	DAO_NETLINK_ROUTE_NH_ATTR_WEIGHT,
	/** Nexthop route realms */
	DAO_NETLINK_ROUTE_NH_ATTR_REALMS,
	/** Nexthop route object holds valid flags (@ref dao_netlink_route_nh_flags_t) */
	DAO_NETLINK_ROUTE_NH_ATTR_FLAGS,
} dao_netlink_route_nh_attr_t;

/**
 * Nexthop route flags
 *
 * if dao_netlink_route_ip_route_t.is_next_hop, nh_flags variables holds
 * valid flags
 */
typedef enum {
	DAO_NETLINK_ROUTE_NH_F_DEAD = RTNH_F_DEAD,		/*< Nexthop os dead */
	DAO_NETLINK_ROUTE_NH_F_PERVASIVE = RTNH_F_PERVASIVE,	/*< Recursive gateway lookup */
	DAO_NETLINK_ROUTE_NH_F_ONLINK = RTNH_F_ONLINK,		/*< Gateway is forces on link */
} dao_netlink_route_nh_flags_t;

/**
 * Structure describing IP routes updates which is filled from RTM_NEWROUTE and
 * RTM_DELROUTE netlink messages
 */
typedef struct dao_netlink_route_ip_route {
	/** application specific interface cookie */
	int app_if_cookie;

	/** linux notion of interface. See if_nametoindex() */
	int linux_ifindex;

	/** 1 if IPv4 or 0 otherwise */
	int is_ipv4;

	/** does next_hop fields are valid */
	int is_next_hop;

	/** is route table, flags, proto, types are valid */
	int is_route_info_valid;

	/** prefixlen of dst_in6_addr */
	int prefixlen;
	struct in6_addr dst_in6_addr; /*< Route IP address for dst */

	/* If is_route_info_valid */
	struct {
		int is_default_route;
		uint32_t route_flags;                  /*< route flags */
		int route_table_id;                    /*< route table id */
		dao_netlink_route_proto_t route_proto; /*< Route proto */
		dao_netlink_route_types_t route_type;  /*< route type */
	};

	/* If is_next_hop == 1 */
	struct {
		int via_addr_prefixlen;
		struct in6_addr via_in6_addr;
		dao_netlink_route_nh_attr_t nh_attr;
		dao_netlink_route_nh_flags_t nh_flags;
		uint8_t nh_weights;      /*< If nh_attr == DAO_NETLINK_ROUTE_NH_ATTR_WEIGHT */
		uint16_t nh_from_realms; /*< If nh_attr == DAO_NETLINK_ROUTE_NH_ATTR_REALMS */
		uint16_t nh_to_realms;   /*< If nh_attr == DAO_NETLINK_ROUTE_NH_ATTR_REALMS */
	};
} dao_netlink_route_ip_route_t;

/** IP Neighbor states */
typedef enum {
#define _(n, state) DAO_NETLINK_NEIGHBOR_STATE_##state = NUD_##state,

	dao_foreach_netlink_neigh_states
#undef _
} dao_netlink_neigh_state_t;

#define DAO_NETLINK_NEIGHBOR_STATE_VALID                                                           \
	(DAO_NETLINK_NEIGHBOR_STATE_PERMANENT | DAO_NETLINK_NEIGHBOR_STATE_REACHABLE |             \
	 DAO_NETLINK_NEIGHBOR_STATE_NOARP)

/**
 * Structure describing IP neighbor updates which is filled from RTM_NEWNEIGH
 * RTM_DELNEIGH netlink messages
 */
typedef struct dao_netlink_route_ip_neigh {
	/** 1 if IPv4 or 0 otherwise */
	int is_ipv4;

	/** prefixlen of address */
	int prefixlen;

	/** application specific interface cookie */
	int app_if_cookie;

	/** linux notion of interface. See if_nametoindex() */
	int linux_ifindex;

	/**
	 * If >=0. valid vlan id
	 */
	int neigh_vlan_id;
	dao_netlink_neigh_state_t neigh_state; /*< Neigh state */
	dao_netlink_route_types_t neigh_type;
	struct in6_addr dst_in6_addr;              /*< Peer IP address */
	uint8_t neigh_ll_addr[RTE_ETHER_ADDR_LEN]; /*< Peer ether address */
} dao_netlink_route_ip_neigh_t;

/**
 * Structure describing Link updates which is filled from RTM_NEWLINK and
 * RTM_DELLINK netlink messages
 */
typedef struct dao_netlink_route_link {
	/** application specific interface cookie */
	int app_if_cookie;

	/** linux notion of interface. See if_nametoindex() */
	int linux_ifindex;

	/** IFF_UP or IFF_DOWN */
	int is_interface_up;

	/** local interface ether_address */
	uint8_t local_ll_addr[RTE_ETHER_ADDR_LEN];
} dao_netlink_route_link_t;

/**
 * High level route netlink ops for getting
 * - Route Updates (See @ref dao_netlink_route_callback_ops "ip_route_add_del")
 * - Link Updates (See @ref dao_netlink_route_callback_ops "link_local_add_del")
 * - Neighbor Updates (See @ref dao_netlink_route_callback_ops "ip_neigh_add_del")
 * - IP Addr Updates (See @ref dao_netlink_route_callback_ops "ip_local_addr_add_del")
 */
typedef struct dao_netlink_route_callback_ops {
	/**
	 * @brief Get application specific cookie for relevant LINUX tap
	 * interfaces. This helps application to work with its own notion of
	 * tap interface instead of something else defined by library. Cookie
	 * is passed to all subsequent function ops for any ip_addr, ip_route,
	 * ip_neigh and link updates. If application does not sets cookie,
	 * default value is DAO_NETLINK_APP_IF_COOKIE_INITIALIZER
	 *
	 * If "prefix_interface_name" is passed to @ref
	 * dao_netlink_route_notifier_register() API, it looks for all LINUX
	 * interface names and if LINUX interface name has
	 * "prefix_interface_name" string in its name (eg:
	 * prefix_interface_name: "dtap" and LINUX interface name: dtap0,
	 * dtap1,...), get_app_interface_cookie() is called for each
	 * matched LINUX interface with
	 * - Exact LINUX interface name
	 * - LINUX notion of ifindex <I>(See man page for if_nametoindex() information) </I>
	 *
	 * Application is supposed to set cookie value for any further function
	 * callbacks. Although linux_ifindex is also passed to all function
	 * callbacks for route, neigh, addr, and link updates
	 *
	 * @param interface_name
	 *  LINUX interface name that matched with "prefix_interface_name"
	 *  passed to @ref dao_netlink_route_notifier_register()
	 * @param linux_ifindex
	 *   LINUX notion of ifindex. See if_nametoindex() library function
	 * @param[out] cookie
	 *   Application specific cookie for interface for any subsequent function calls
	 *
	 * @return
	 *  0: Succese
	 * <0: Failure
	 */
	int (*get_app_interface_cookie)(const char *interface_name, int linux_ifindex,
					uint32_t *cookie);

	/**
	 * @brief Add or delete Local IP address to interface
	 *
	 * @param dao_ip_addr
	 *   See @ref dao_netlink_route_ip_addr_t
	 * @param is_add
	 *   Add addr if is_add == 1 else delete otherwise
	 *
	 * @return
	 *  0: Succese
	 * <0: Failure
	 */
	int (*ip_local_addr_add_del)(dao_netlink_route_ip_addr_t *dao_ip_addr, int is_add);

	/**
	 * Add or delete IP neighbor entry
	 *
	 * @param dao_ip_neigh
	 *   See @ref dao_netlink_route_ip_neigh_t
	 * @param is_add
	 *   Add neighbor if is_add == 1 else delete otherwise
	 *
	 * @return
	 *  0: Succese
	 * <0: Failure
	 */
	int (*ip_neigh_add_del)(dao_netlink_route_ip_neigh_t *dao_ip_neigh, int is_add);

	/**
	 * Add or delete Link HW address
	 *
	 * @param dao_link
	 *   See @ref dao_netlink_route_link_t
	 * @param is_add
	 *   Add link if is_add == 1 else delete otherwise
	 *
	 * @return
	 *  0: Succese
	 * <0: Failure
	 */
	int (*link_add_del)(dao_netlink_route_link_t *dao_link, int is_add);

	/**
	 * Add or delete IP route
	 *
	 * @param dao_ip_route
	 *   See @ref dao_netlink_route_ip_route_t
	 * @param action
	 *   Add, replace or delete based on action value
	 *
	 * @return
	 *  0: Succese
	 * <0: Failure
	 */
	int (*ip_route_add_del)(dao_netlink_route_ip_route_t *dao_ip_route,
				dao_netlink_action_t action);
} dao_netlink_route_callback_ops_t;

/* Function declaration */

/**
 * @brief Function to synchronize LINUX route tables with application
 *
 * @return
 *  0: Succese
 * <0: Failure
 */
int dao_netlink_route_notifier_run(void);

/**
 * @brief Register application callbacks for getting route updates.
 *
 * It uses low level @ref dao_netlink_register() API to register for
 * NETLINK_ROUTE protocol and multiple multicast_groups for IPv4. Netlink
 * messages are parsed in @ref dao_netlink_poll() processing context and passed
 * to application via registered @ref dao_netlink_route_callback_ops "ops", if
 * found relevant.
 *
 * @param ops
 *   Function callback ops set by application
 * @param prefix_interface_name
 *   String to filter out metlink messages and restrict them to those LINUX
 *   interfaces whose name has "prefix_interface_name" string.
 *
 * @return
 *  0: Succese
 * <0: Failure
 */
int dao_netlink_route_notifier_register(dao_netlink_route_callback_ops_t *ops,
					const char *prefix_interface_name);

#ifdef __cplusplus
}
#endif
#endif
