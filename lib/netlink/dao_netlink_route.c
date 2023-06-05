/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2023 Marvell.
 */

#include <dao_dynamic_string.h>
#include <dao_netlink.h>
#include <endian.h>

#define DAO_ROUTE_DBG dao_dbg

typedef struct relevant_ifindex {
	STAILQ_ENTRY(relevant_ifindex) next_link;
	int ifindex;
	uint32_t app_if_cookie;
	char interface_name[64];
} relevant_ifindex_t;

typedef struct {
	void *notifier;
	struct dao_ds *ds_str;
	int is_relevant_route;
	int is_route_suppressed;
	int is_msg_handling;
	int linux_ifindex;
	dao_netlink_action_t action;
	dao_netlink_route_ip_route_t *dao_ip_route;
} netlink_cb_arg_t;

typedef struct {
	struct nl_cache *link_cache;
	void *netlink;
	char *prefix_if_name;
	dao_netlink_route_callback_ops_t *ops;
} link_cb_arg_t;

static STAILQ_HEAD(, relevant_ifindex)
	relevant_ifindex_list = STAILQ_HEAD_INITIALIZER(relevant_ifindex_list);

static int dao_netlink_route_valid_flag;

static int
is_interface_relevant(int ifindex, relevant_ifindex_t **rel_link)
{
	relevant_ifindex_t *rifindex = NULL;

	if (!rel_link)
		return 0;

	STAILQ_FOREACH(rifindex, &relevant_ifindex_list, next_link) {
		if (rifindex->ifindex == ifindex) {
			*rel_link = rifindex;
			return 1;
		}
	}
	*rel_link = NULL;
	return 0;
}

static int
handle_addr_msg(struct nl_object *obj, void *arg, const char *str, int is_add)
{
	struct rtnl_addr *addr = (struct rtnl_addr *)obj;
	netlink_cb_arg_t *rcb = (netlink_cb_arg_t *)arg;
	unsigned int flags = rtnl_addr_get_flags(addr);
	dao_netlink_route_callback_ops_t *ops = NULL;
	int ifindex = rtnl_addr_get_ifindex(addr);
	relevant_ifindex_t *rifindex = NULL;
	dao_netlink_route_ip_addr_t _dao_ip_addr;
	struct dao_ds *lstr = rcb->ds_str;
	struct rtnl_link *link = NULL;
	char buf[64];

	rcb->is_relevant_route = is_interface_relevant(ifindex, &rifindex);

	if (rifindex) {
		dao_ds_put_cstr(lstr, str);
		dao_ds_put_format(lstr, " flags: %s ",
				  rtnl_addr_flags2str(flags, buf, sizeof(buf)));
		link = rtnl_addr_get_link(addr);
		if (link) {
			dao_ds_put_format(lstr, " addr_if: %s(%u) ", rtnl_link_get_name(link),
					  rtnl_link_get_ifindex(link));
		}
		dao_ds_put_format(lstr, " local: %s ",
				  nl_addr2str(rtnl_addr_get_local(addr), buf, sizeof(buf)));
		dao_ds_put_format(lstr, "ifindex: %d ", rtnl_addr_get_ifindex(addr));
		dao_ds_put_format(lstr, " %s(%d) ", rifindex->interface_name, ifindex);
		dao_ds_put_format(lstr, " cookie: %u ", rifindex->app_if_cookie);

		RTE_VERIFY(rifindex->ifindex == ifindex);

		if (rcb && rcb->notifier)
			ops = dao_netlink_notifier_callback_ops_get(rcb->notifier);

		if (ops && ops->ip_local_addr_add_del) {
			ops = dao_netlink_notifier_callback_ops_get(rcb->notifier);

			memset(&_dao_ip_addr, 0, sizeof(dao_netlink_route_ip_addr_t));

			_dao_ip_addr.prefixlen = rtnl_addr_get_prefixlen(addr);
			_dao_ip_addr.is_ipv4 = (rtnl_addr_get_family(addr) == AF_INET) ? 1 : 0;
			_dao_ip_addr.app_if_cookie = rifindex->app_if_cookie;
			_dao_ip_addr.linux_ifindex = rtnl_addr_get_ifindex(addr);
			_dao_ip_addr.addr_flags = flags;
			dao_netlink_nl_addr_to_in6(&_dao_ip_addr.local_in6_addr,
						   rtnl_addr_get_local(addr));
			return ops->ip_local_addr_add_del(&_dao_ip_addr, is_add);
		}
	}
	return 0;
}

static void
route_call_application(netlink_cb_arg_t *rcb, int is_suppressed)
{
	dao_netlink_route_callback_ops_t *ops = NULL;
	dao_netlink_route_ip_route_t *ip_rt = NULL;
	struct dao_ds *rstr = rcb->ds_str;

	if (!rcb)
		return;

	if (!rcb->dao_ip_route)
		return;

	if (rcb && rcb->notifier)
		ops = dao_netlink_notifier_callback_ops_get(rcb->notifier);

	ip_rt = rcb->dao_ip_route;

	if (rcb->is_msg_handling < 0) {
		if (rcb->is_relevant_route)
			DAO_ROUTE_DBG("%s", dao_ds_cstr(rcb->ds_str));
		dao_ds_clear(rstr);
	} else {
		/* don't print suppressed routes or nexthops. Remove this line
		 * is want to print all relevant notifications which are suppressed
		 */
		rcb->is_relevant_route = !is_suppressed;

		if (rcb->is_relevant_route && !is_suppressed) {
			if (ops && ops->ip_route_add_del)
				ops->ip_route_add_del(ip_rt, rcb->action);
		}
	}
}

static int
is_route_via(uint32_t flags)
{
	if ((flags && DAO_NETLINK_ROUTE_NH_ATTR_VIA) ||
	    (flags && DAO_NETLINK_ROUTE_NH_ATTR_VIA_GW) ||
	    (flags && DAO_NETLINK_ROUTE_NH_ATTR_NEWDST))
		return 1;
	else
		return 0;
}
static void
route_nexthop_cb(struct rtnl_nexthop *nh, void *arg)
{
	dao_netlink_route_ip_route_t local_route, *tmp = NULL;
	netlink_cb_arg_t *rcb = (netlink_cb_arg_t *)arg;
	relevant_ifindex_t *rifindex = NULL;
	struct dao_ds *rstr = rcb->ds_str;
	int is_nh_suppressed = 0;
	char buf[128];
	int ifindex;

	if (!rstr) {
		dao_err("route_str received NULL");
		return;
	}

	if (!rcb)
		return;

	if (rcb->dao_ip_route) {
		memcpy(&local_route, rcb->dao_ip_route, sizeof(dao_netlink_route_ip_route_t));
	} else {
		dao_ds_put_cstr(rstr, " (nh suppressed) rcb->dao_ip_route == NULL ");
		is_nh_suppressed = 1;
	}

	/* Reset fields */
	local_route.nh_attr = 0;
	local_route.nh_flags = 0;

	dao_ds_put_cstr(rstr, " nexthop ");
	if (rtnl_route_nh_get_via(nh)) {
		dao_ds_put_cstr(rstr, " via ");
		dao_ds_put_format(rstr, "%s ",
				  nl_addr2str(rtnl_route_nh_get_via(nh), buf, sizeof(buf)));

		dao_netlink_nl_addr_to_in6(&local_route.via_in6_addr, rtnl_route_nh_get_via(nh));
		local_route.via_addr_prefixlen = nl_addr_get_prefixlen(rtnl_route_nh_get_via(nh));
		local_route.nh_attr |= DAO_NETLINK_ROUTE_NH_ATTR_VIA;
	}
	if (rtnl_route_nh_get_gateway(nh)) {
		dao_ds_put_cstr(rstr, " via gw ");
		dao_ds_put_format(rstr, "%s ",
				  nl_addr2str(rtnl_route_nh_get_gateway(nh), buf, sizeof(buf)));
		dao_ds_put_format(rstr, "prefixlen %d ",
				  nl_addr_get_prefixlen(rtnl_route_nh_get_gateway(nh)));
		dao_netlink_nl_addr_to_in6(&local_route.via_in6_addr,
					   rtnl_route_nh_get_gateway(nh));
		local_route.via_addr_prefixlen =
			nl_addr_get_prefixlen(rtnl_route_nh_get_gateway(nh));
		local_route.nh_attr |= DAO_NETLINK_ROUTE_NH_ATTR_VIA_GW;
	}
	if (rtnl_route_nh_get_newdst(nh)) {
		dao_ds_put_cstr(rstr, " via newdst ");
		dao_ds_put_format(rstr, "%s ",
				  nl_addr2str(rtnl_route_nh_get_newdst(nh), buf, sizeof(buf)));
		dao_ds_put_format(rstr, "prefixlen %d ",
				  nl_addr_get_prefixlen(rtnl_route_nh_get_newdst(nh)));
		dao_netlink_nl_addr_to_in6(&local_route.via_in6_addr, rtnl_route_nh_get_newdst(nh));
		local_route.via_addr_prefixlen =
			nl_addr_get_prefixlen(rtnl_route_nh_get_newdst(nh));
		local_route.nh_attr |= DAO_NETLINK_ROUTE_NH_ATTR_NEWDST;
	}
	/* Make relevant route irrelevant by default */
	rcb->is_relevant_route = 0;

	ifindex = rtnl_route_nh_get_ifindex(nh);
	if (ifindex) {
		/* Check if device is relevant */
		rcb->is_relevant_route = is_interface_relevant(ifindex, &rifindex);

		/* Check if index is relevant to us */
		if (rifindex) {
			local_route.nh_attr |= DAO_NETLINK_ROUTE_NH_ATTR_IFINDEX;
			/* Check local route */
			rcb->linux_ifindex = ifindex;
			local_route.linux_ifindex = rcb->linux_ifindex;
			local_route.app_if_cookie = rifindex->app_if_cookie;
			dao_ds_put_format(rstr, " via dev %s(%d) ", rifindex->interface_name,
					  rcb->linux_ifindex);
			if (rifindex->app_if_cookie != DAO_NETLINK_APP_IF_COOKIE_INITIALIZER)
				dao_ds_put_format(rstr, "cookie: %u ", rifindex->app_if_cookie);
		} else {
			dao_ds_put_format(rstr, " (nh suppressed) via nodev");
			is_nh_suppressed = 1;
		}
	}
	if (rtnl_route_nh_get_flags(nh)) {
		dao_ds_put_format(
			rstr, " flags %s ",
			rtnl_route_nh_flags2str(rtnl_route_nh_get_flags(nh), buf, sizeof(buf)));
		local_route.nh_flags = rtnl_route_nh_get_flags(nh);
	}

	local_route.nh_weights = rtnl_route_nh_get_weight(nh);
	if (local_route.nh_weights) {
		local_route.nh_attr |= DAO_NETLINK_ROUTE_NH_ATTR_WEIGHT;
		dao_ds_put_format(rstr, " weight %u", rtnl_route_nh_get_weight(nh));
	}

	if (rtnl_route_nh_get_realms(nh)) {
		local_route.nh_attr |= DAO_NETLINK_ROUTE_NH_ATTR_REALMS;
		local_route.nh_from_realms = RTNL_REALM_FROM(rtnl_route_nh_get_realms(nh));
		local_route.nh_to_realms = RTNL_REALM_TO(rtnl_route_nh_get_realms(nh));
	}

	if (!is_route_via(local_route.nh_attr)) {
		dao_ds_put_format(rstr, " (nh suppressed) no via_addr ");
		is_nh_suppressed = 1;
	}

	/* call app */
	tmp = rcb->dao_ip_route;
	rcb->dao_ip_route = &local_route;
	rcb->dao_ip_route->is_next_hop = 1;

	route_call_application(rcb, rcb->is_route_suppressed || is_nh_suppressed);

	rcb->dao_ip_route = tmp;
}

static void
__link_cb(struct nl_object *obj, void *arg)
{
	struct rtnl_link *link = (struct rtnl_link *)obj;
	link_cb_arg_t *lcb = (link_cb_arg_t *)arg;
	relevant_ifindex_t *rifentry = NULL;
	char *name = NULL;
	char buf[64];
	int ifindex;

	ifindex = rtnl_link_get_ifindex(link);
	name = rtnl_link_i2name(lcb->link_cache, ifindex, buf, sizeof(buf));
	if (strstr(name, lcb->prefix_if_name)) {
		rifentry = malloc(sizeof(relevant_ifindex_t));
		strncpy(rifentry->interface_name, name, sizeof(rifentry->interface_name) - 1);
		rifentry->ifindex = ifindex;
		rifentry->app_if_cookie = DAO_NETLINK_APP_IF_COOKIE_INITIALIZER;
		if (lcb && lcb->ops && lcb->ops->get_app_interface_cookie) {
			lcb->ops->get_app_interface_cookie(rifentry->interface_name,
							   rifentry->ifindex,
							   &rifentry->app_if_cookie);
		}
		dao_info("dao_netlink_route: Tracking LINUX Interfaces: %s(%u). App cookie: %u",
			 rifentry->interface_name, rifentry->ifindex, rifentry->app_if_cookie);
		STAILQ_INSERT_TAIL(&relevant_ifindex_list, rifentry, next_link);
	}
}

static void
route_cb(struct nl_object *obj, void *arg)
{
	netlink_cb_arg_t *rcb = (netlink_cb_arg_t *)arg;
	struct rtnl_route *r = (struct rtnl_route *)obj;
	dao_netlink_route_ip_route_t _dao_ip_route;
	struct dao_ds *rstr = rcb->ds_str;
	int cache = 0, is_replace = 0;
	struct nlmsghdr *nlh = NULL;
	char buf[128];
	int msgtype;

	/* initialize first route entry and add to the list */
	memset(&_dao_ip_route, 0, sizeof(dao_netlink_route_ip_route_t));

	rcb->is_route_suppressed = 0;
	_dao_ip_route.is_route_info_valid = 0;

	rcb->action = DAO_NETLINK_ACTION_UNKNOWN;
	rcb->dao_ip_route = &_dao_ip_route;

	if (rtnl_route_get_flags(r) & RTM_F_CLONED)
		cache = 1;

	_dao_ip_route.route_flags = rtnl_route_get_flags(r);

	if (rcb->notifier && dao_netlink_notifier_nl_msg_get(rcb->notifier)) {
		nlh = nlmsg_hdr(dao_netlink_notifier_nl_msg_get(rcb->notifier));
		is_replace = (nlh->nlmsg_flags & NLM_F_REPLACE);
	}

	if (rcb->is_msg_handling >= 0) {
		dao_ds_put_cstr(rstr, "Msg ");
		if (rcb->is_msg_handling == RTM_DELROUTE) {
			dao_ds_put_cstr(rstr, "DELROUTE ");
			rcb->action = DAO_NETLINK_ACTION_DEL;
		} else {
			if (is_replace) {
				dao_ds_put_cstr(rstr, "REPLACEROUTE ");
				rcb->action = DAO_NETLINK_ACTION_REPLACE;
			} else {
				rcb->action = DAO_NETLINK_ACTION_ADD;
				if (rcb->is_msg_handling == RTM_NEWROUTE)
					dao_ds_put_cstr(rstr, "NEWROUTE ");
				else
					dao_ds_put_cstr(rstr, "UNKOWNROUTE ");
			}
		}
	} else {
		dao_ds_put_cstr(rstr, "rt-upd ");
	}
	msgtype = nl_object_get_msgtype(obj);

	dao_ds_put_format(rstr, "msgtype %d ", msgtype);
	dao_ds_put_format(rstr, "%s ", nl_af2str(rtnl_route_get_family(r), buf, sizeof(buf)));

	_dao_ip_route.is_ipv4 = (rtnl_route_get_family(r) == AF_INET) ? 1 : 0;
	if (!nl_addr_get_prefixlen(rtnl_route_get_dst(r)) &&
	    (nl_addr_get_len(rtnl_route_get_dst(r)) > 0) && nl_addr_iszero(rtnl_route_get_dst(r))) {
		_dao_ip_route.is_default_route = 1;
		dao_ds_put_cstr(rstr, "default ");
	}
	dao_ds_put_cstr(rstr, nl_addr2str(rtnl_route_get_dst(r), buf, sizeof(buf)));

	_dao_ip_route.prefixlen = nl_addr_get_prefixlen(rtnl_route_get_dst(r));
	dao_netlink_nl_addr_to_in6(&_dao_ip_route.dst_in6_addr, rtnl_route_get_dst(r));

	if (!cache) {

		/* Not worried about local table */
		if (rtnl_route_get_table(r) == 255) {
			rcb->is_route_suppressed = 1;
			dao_ds_put_format(
				rstr, " (suppressed) table %s ",
				rtnl_route_table2str(rtnl_route_get_table(r), buf, sizeof(buf)));
		} else {
			_dao_ip_route.is_route_info_valid = 1;
			_dao_ip_route.route_table_id = rtnl_route_get_table(r);
			dao_ds_put_format(
				rstr, " table(%u) %s ", rtnl_route_get_table(r),
				rtnl_route_table2str(rtnl_route_get_table(r), buf, sizeof(buf)));
		}
	}

	switch (rtnl_route_get_type(r)) {
	case RTN_UNICAST:
	case RTN_UNREACHABLE:
	case RTN_MULTICAST:
	case RTN_BLACKHOLE:
	case RTN_PROHIBIT:
		_dao_ip_route.route_type = rtnl_route_get_type(r);
		dao_ds_put_format(rstr, "type %s ",
				  nl_rtntype2str(rtnl_route_get_type(r), buf, sizeof(buf)));
		break;

	default:
		rcb->is_route_suppressed = 1;
		dao_ds_put_format(rstr, "(suppressed) type %s ",
				  nl_rtntype2str(rtnl_route_get_type(r), buf, sizeof(buf)));
	}

	if (RTPROT_KERNEL == rtnl_route_get_protocol(r)) {
		dao_ds_put_cstr(rstr, " (suppresed) proto kernel ");
		rcb->is_route_suppressed = 1;
	} else {
		_dao_ip_route.route_proto = rtnl_route_get_protocol(r);
		dao_ds_put_format(rstr, " proto %u ", _dao_ip_route.route_proto);
	}

	/* Call nexthops */
	if (rtnl_route_get_nnexthops(r))
		rtnl_route_foreach_nexthop(r, route_nexthop_cb, rcb);
}

static int
handle_neigh_msg(struct nl_object *nl_obj, netlink_cb_arg_t *rcb, const char *strmsg, int is_add)
{
	char dst[INET6_ADDRSTRLEN + 5], lladdr[INET6_ADDRSTRLEN + 5];
	struct rtnl_neigh *neigh = (struct rtnl_neigh *)nl_obj;
	dao_netlink_route_callback_ops_t *ops = NULL;
	dao_netlink_route_ip_neigh_t _dao_ip_neigh;
	relevant_ifindex_t *rifindex = NULL;
	struct dao_ds *rstr = rcb->ds_str;
	int is_relevant = 0;
	char buf[128];

	if (strmsg)
		dao_ds_put_format(rstr, "%s ", strmsg);

	dao_ds_put_format(rstr, "%s ", nl_af2str(rtnl_neigh_get_family(neigh), buf, sizeof(buf)));
	dao_ds_put_format(rstr, "state:%s ",
			  rtnl_neigh_state2str(rtnl_neigh_get_state(neigh), buf, sizeof(buf)));
	dao_ds_put_format(rstr, "flags:%s ",
			  rtnl_neigh_flags2str(rtnl_neigh_get_flags(neigh), buf, sizeof(buf)));

	rcb->is_relevant_route = is_interface_relevant(rtnl_neigh_get_ifindex(neigh), &rifindex);
	is_relevant = rcb->is_relevant_route;

	if (rifindex) {
		memset(&_dao_ip_neigh, 0, sizeof(dao_netlink_route_ip_neigh_t));

		_dao_ip_neigh.is_ipv4 = (AF_INET == rtnl_neigh_get_family(neigh)) ? 1 : 0;
		_dao_ip_neigh.app_if_cookie = rifindex->app_if_cookie;
		_dao_ip_neigh.linux_ifindex = rtnl_neigh_get_ifindex(neigh);
		_dao_ip_neigh.neigh_state = rtnl_neigh_get_state(neigh);

		dao_ds_put_format(rstr, "dev:%s ", rifindex->interface_name);

		if (rifindex->app_if_cookie != DAO_NETLINK_APP_IF_COOKIE_INITIALIZER)
			dao_ds_put_format(rstr, "cookie: %u ", rifindex->app_if_cookie);
		else
			dao_ds_put_format(rstr, "dev %d ", rtnl_neigh_get_ifindex(neigh));

		dao_ds_put_format(rstr, "%s ",
				  nl_rtntype2str(rtnl_neigh_get_type(neigh), buf, sizeof(buf)));

		_dao_ip_neigh.neigh_type = rtnl_neigh_get_type(neigh);

		if (rtnl_neigh_get_lladdr(neigh)) {
			dao_ds_put_format(
				rstr, "%s ",
				nl_addr2str(rtnl_neigh_get_lladdr(neigh), lladdr, sizeof(lladdr)));
			memcpy(_dao_ip_neigh.neigh_ll_addr,
			       nl_addr_get_binary_addr(rtnl_neigh_get_lladdr(neigh)),
			       RTE_ETHER_ADDR_LEN);
		} else {
			is_relevant = 0;
			dao_ds_put_cstr(rstr, " No hw addr ");
		}
		if (rtnl_neigh_get_vlan(neigh) >= 0) {
			dao_ds_put_format(rstr, "vlan %d ", rtnl_neigh_get_vlan(neigh));
			_dao_ip_neigh.neigh_vlan_id =
				nl_addr_get_prefixlen(rtnl_neigh_get_dst(neigh));
		}
		dao_ds_put_format(rstr, "master %d ", rtnl_neigh_get_master(neigh));

		if (rtnl_neigh_get_dst(neigh)) {
			dao_ds_put_cstr(rstr,
					nl_addr2str(rtnl_neigh_get_dst(neigh), dst, sizeof(dst)));

			dao_netlink_nl_addr_to_in6(&_dao_ip_neigh.dst_in6_addr,
						   rtnl_neigh_get_dst(neigh));
			_dao_ip_neigh.prefixlen = nl_addr_get_prefixlen(rtnl_neigh_get_dst(neigh));

			dao_ds_put_format(rstr, " prefix: %u ", _dao_ip_neigh.prefixlen);
		} else {
			is_relevant = 0;
			dao_ds_put_cstr(rstr, " No neigh IP ");
		}
		if (rcb && rcb->notifier)
			ops = dao_netlink_notifier_callback_ops_get(rcb->notifier);

		if (is_relevant && ops && ops->ip_neigh_add_del)
			return ops->ip_neigh_add_del(&_dao_ip_neigh, is_add);

		if (!is_relevant && rcb->is_relevant_route) {
			dao_ds_put_cstr(rstr, " neighbor suppressed ");
			dao_err("neighbor notification suppressed: valid: %d, %p, %p", is_relevant,
				rcb, ops);
			rcb->is_relevant_route = 1;
			return -1;
		}
	}
	return 0;
}

static void
dao_netlink_route_parse_cb(struct nl_object *nl_obj, void *notifier)
{
	char *name = (char *)dao_netlink_notifier_app_cookie_get(notifier);
	struct dao_ds route_str = DS_EMPTY_INITIALIZER;
	netlink_cb_arg_t cb;
	int rc = 0;

	switch (nl_object_get_msgtype(nl_obj)) {
	case RTM_NEWROUTE:
	case RTM_DELROUTE:
		dao_netlink_route_valid_flag = 0;
		break;
	default:
	}

	memset(&cb, 0, sizeof(netlink_cb_arg_t));

	cb.notifier = notifier;
	cb.is_msg_handling = nl_object_get_msgtype(nl_obj);
	cb.ds_str = &route_str;

	switch (nl_object_get_msgtype(nl_obj)) {
	case RTM_NEWLINK:
		break;

	case RTM_GETLINK:
		DAO_ROUTE_DBG("GET_LINK");
		break;

	case RTM_SETLINK:
		DAO_ROUTE_DBG("SET_LINK");
		break;

	case RTM_DELLINK:
		DAO_ROUTE_DBG("DEL_LINK");
		break;

	case RTM_NEWNEIGH:
		rc = handle_neigh_msg(nl_obj, &cb, "Newneigh", 1 /* is_add */);
		break;

	case RTM_GETNEIGH:
		DAO_ROUTE_DBG("GET_NEIGH");
		break;

	case RTM_DELNEIGH:
		rc = handle_neigh_msg(nl_obj, &cb, "Delneigh", 0 /* delete */);
		break;

	case RTM_NEWROUTE:
		route_cb(nl_obj, &cb);
		break;

	case RTM_GETROUTE:
		DAO_ROUTE_DBG("Get Route");
		break;

	case RTM_DELROUTE:
		route_cb(nl_obj, &cb);
		break;

	case RTM_NEWADDR:
		rc = handle_addr_msg(nl_obj, &cb, "NEWADDR", 1 /* is_add */);
		break;
	case RTM_GETADDR:
		DAO_ROUTE_DBG("GETADDR msgs: %d(%s)", rc, name);
		break;
	case RTM_DELADDR:
		rc = handle_addr_msg(nl_obj, &cb, "DELADDR", 0 /* is_add */);
		break;

	default:
		dao_err("Received invalid route notification: %d", nl_object_get_msgtype(nl_obj));
	}

	if (rc)
		dao_err("Failure rc: %d", rc);

	if (cb.is_relevant_route)
		DAO_ROUTE_DBG("%s", dao_ds_cstr(&route_str));

	dao_ds_destroy(&route_str);
}

int
dao_netlink_route_notifier_register(dao_netlink_route_callback_ops_t *ops,
				    const char *filter_prefix)
{
	struct nl_cache *link_cache = NULL;
	link_cb_arg_t link_cb_arg;
	void *netlink = NULL;
	char *name = NULL;
	int len = 64;

	if (filter_prefix) {
		RTE_VERIFY(strlen(filter_prefix) < (size_t)(len - 1));
		name = malloc(len - 1);
		dao_dbg("filter prefix: %s (len: %lu)", filter_prefix, strlen(filter_prefix));
		strcpy(name, filter_prefix);
	}
	if (dao_netlink_register(NETLINK_ROUTE, dao_netlink_route_parse_cb, (void *)ops, name,
				 RTNLGRP_LINK, RTNLGRP_IPV4_ROUTE, RTNLGRP_IPV4_IFADDR,
				 RTNLGRP_IPV4_RULE, RTNLGRP_NEIGH, RTNLGRP_NOTIFY, 0) < 0) {
		dao_err("failure for IPv4_route netlink_register");
		return -1;
	}
	if (!name)
		return 0;

	/* Get List of interface which are relevant */
	netlink = dao_netlink_lookup(NETLINK_ROUTE);

	/*
	 * Lookup cannot fail once NETLINK_ROUTE creation has passed. So crash it
	 */
	if (!netlink || !dao_netlink_socket_get(netlink))
		RTE_VERIFY(0);

	if (rtnl_link_alloc_cache(dao_netlink_socket_get(netlink), AF_INET, &link_cache) < 0) {
		dao_err("rtnl_link_alloc_cache failed");
		return -1;
	}
	memset(&link_cb_arg, 0, sizeof(link_cb_arg_t));

	link_cb_arg.netlink = netlink;
	link_cb_arg.prefix_if_name = name;
	link_cb_arg.link_cache = link_cache;
	link_cb_arg.ops = ops;
	nl_cache_foreach(link_cache, __link_cb, &link_cb_arg);

	nl_cache_put(link_cache);

	return 0;
}

int
dao_netlink_route_notifier_run(void)
{
	struct dao_ds route_str = DS_EMPTY_INITIALIZER;
	void *entry = NULL, *notifier = NULL;
	struct nl_cache *cache = NULL;
	netlink_cb_arg_t cb_arg = {0};

	/*
	 * Sync when route table is not valid i.e. Some update has happened
	 */
	if (!dao_netlink_route_valid_flag) {
		dao_netlink_route_valid_flag = 1;
		entry = dao_netlink_lookup(NETLINK_ROUTE);

		if (dao_netlink_has_poll_recv(entry))
			return 0;

		/* Check if we have any netlink notifier looking for routes */
		notifier = dao_netlink_notifier_lookup_by_multicast_group(entry, NULL,
									  RTNLGRP_IPV4_ROUTE);
		if (!notifier)
			return 0;

		/* Check if we have any netlink notifier looking for routes */
		if (rtnl_route_alloc_cache(dao_netlink_socket_get(entry), AF_INET,
					   ROUTE_CACHE_CONTENT, &cache) < 0) {
			dao_dbg("rtnl_route_alloc_cache failed");
			return -1;
		}
		cb_arg.notifier = notifier;
		cb_arg.is_msg_handling = -1;
		cb_arg.ds_str = &route_str;

		nl_cache_foreach(cache, route_cb, (void *)&cb_arg);
		/*
				params.dp_fd = stdout;
				params.dp_type = NL_DUMP_LINE;
				nl_cache_dump_filter(cache, &params, NULL);
		*/
		if (cache)
			nl_cache_put(cache);

		dao_ds_destroy(&route_str);
	}
	return 0;
}
