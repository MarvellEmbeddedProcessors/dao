/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#include <netlink/secgw_netlink.h>

typedef struct secgw_route_partial_entry {
	STAILQ_ENTRY(secgw_route_partial_entry) next_partial_entry;
	dao_netlink_route_ip_route_t partial_route;
} secgw_route_partial_entry_t;

/* Neighbor lists */
typedef STAILQ_HEAD(, secgw_neigh_entry) secgw_neigh_list_head_t;
static secgw_neigh_list_head_t secgw_neigh_list = STAILQ_HEAD_INITIALIZER(secgw_neigh_list);

/* Partial routes i.e. routes with no rewrite header */
typedef STAILQ_HEAD(, secgw_route_partial_entry) secgw_route_partial_list_head_t;

static secgw_route_partial_list_head_t secgw_route_partial_list =
	STAILQ_HEAD_INITIALIZER(secgw_route_partial_list);

int secgw_neigh_add_del(dao_netlink_route_ip_neigh_t *n, int is_add);
int secgw_link_add_del(dao_netlink_route_link_t *l, int is_add);
int secgw_addr_add_del(dao_netlink_route_ip_addr_t *a, int is_add);
int secgw_route_add_del(dao_netlink_route_ip_route_t *r, dao_netlink_action_t action);

static int
add_lpm_route(struct in6_addr *addr, int prefixlen, rte_edge_t edge, int route_index,
	      uint8_t *rewrite_data, size_t rewrite_length, int device_id,
	      struct dao_ds *caller_str)
{
	struct dao_ds *str = NULL;
	struct dao_ds _str = DS_EMPTY_INITIALIZER;
	int rc = 0;

	if (caller_str)
		str = caller_str;
	else
		str = &_str;

	if (addr) {
		dao_ds_put_cstr(str, "AddRoute: ");
		secgw_print_ip_addr(addr, prefixlen, str);
		dao_ds_put_format(str, " edge %u, route index %d", edge, route_index);

		dao_workers_barrier_sync(dao_workers_self_worker_get());
		if (secgw_ip4_route_add(htonl(dao_in6_addr_get_mapped_ipv4(addr)), prefixlen,
					route_index, edge)) {
			dao_ds_put_cstr(str, " failed ");
			rc = -1;
		} else {
			dao_ds_put_cstr(str, " added ");
		}
		if (!rc && rewrite_data && rewrite_length) {
			dao_ds_put_cstr(str, " rewrite ");
			dao_ds_put_format(str, " device %s ",
					  secgw_get_device(device_id)->dev_name);
			dao_ds_put_hex(str, rewrite_data, rewrite_length);
			if (secgw_ip4_rewrite_add(route_index, rewrite_data, rewrite_length,
						  device_id)) {
				dao_ds_put_cstr(str, " failed ");
				rc = -1;
			} else {
				dao_ds_put_cstr(str, " added ");
			}
		}
		dao_workers_barrier_release(dao_workers_self_worker_get());
	}
	if (!caller_str) {
		SECGW_NL_DBG("%s", dao_ds_cstr(str));
		dao_ds_destroy(str);
	}
	return rc;
}

int
secgw_neigh_find_and_add(struct in6_addr *addr, uint32_t prefixlen, uint8_t *mac, int32_t *_index,
			 uint16_t *edge, struct secgw_neigh_entry **_neigh, int is_add)
{
	struct secgw_neigh_entry *nentry = NULL;
	int found = 0, is_ipv4;
	rte_be32_t ip4, tmpip4;
	int32_t index = -1;

	is_ipv4 = IN6_IS_ADDR_V4MAPPED(addr);

	STAILQ_FOREACH(nentry, &secgw_neigh_list, next_neigh_entry) {
		index++;
		if (nentry->prefixlen != prefixlen)
			continue;

		if (is_ipv4 != IN6_IS_ADDR_V4MAPPED(&nentry->ip_addr))
			continue;

		if (mac && memcmp(nentry->dest_ll_addr, mac, RTE_ETHER_ADDR_LEN))
			continue;

		if (edge && (*edge != nentry->edge))
			continue;

		if (is_ipv4) {
			ip4 = dao_in6_addr_get_mapped_ipv4(&nentry->ip_addr);
			tmpip4 = dao_in6_addr_get_mapped_ipv4(addr);
			if (memcmp(&ip4, &tmpip4, sizeof(rte_be32_t)))
				continue;
		} else {
			if (memcmp(&nentry->ip_addr, addr, sizeof(struct in6_addr)))
				continue;
		}
		if (_index)
			*_index = index;

		if (_neigh)
			*_neigh = nentry;

		found = 1;
		break;
	}
	if (!found && is_add && mac && addr) {
		nentry = malloc(sizeof(*nentry));
		memset(nentry, 0, sizeof(*nentry));
		memcpy(nentry->dest_ll_addr, mac, RTE_ETHER_ADDR_LEN);
		memcpy(&nentry->ip_addr, addr, sizeof(struct in6_addr));
		nentry->prefixlen = prefixlen;
		if (edge)
			nentry->edge = *edge;

		if (_index)
			*_index = index + 1;
		if (_neigh)
			*_neigh = nentry;

		STAILQ_INSERT_TAIL(&secgw_neigh_list, nentry, next_neigh_entry);
	}

	return found;
}

static int
find_and_add_partial_route_addr(dao_netlink_route_ip_neigh_t *n, rte_edge_t edge, int is_add,
				struct dao_ds *str)
{
	uint8_t rewrite_data[2 * sizeof(struct rte_ether_addr)];
	struct secgw_route_partial_entry *pentry = NULL;
	dao_netlink_route_ip_route_t *r = NULL;
	struct rte_ether_addr *ether = NULL;
	struct in6_addr *addr = NULL;
	secgw_device_t *sdev = NULL;
	int32_t route_index = -1;
	int prefixlen, is_ipv4;
	rte_be32_t ip4, tmpip4;

	if (!n || !is_add)
		return -1;

	RTE_SET_USED(str);

	addr = &n->dst_in6_addr;
	prefixlen = n->prefixlen;
	is_ipv4 = IN6_IS_ADDR_V4MAPPED(addr);

	STAILQ_FOREACH(pentry, &secgw_route_partial_list, next_partial_entry) {
		if (!pentry->partial_route.is_next_hop)
			continue;

		if (pentry->partial_route.via_addr_prefixlen != prefixlen)
			continue;

		if (is_ipv4 != IN6_IS_ADDR_V4MAPPED(&pentry->partial_route.via_in6_addr))
			continue;

		if (is_ipv4) {
			ip4 = dao_in6_addr_get_mapped_ipv4(&pentry->partial_route.via_in6_addr);
			tmpip4 = dao_in6_addr_get_mapped_ipv4(addr);
			if (memcmp(&ip4, &tmpip4, sizeof(rte_be32_t)))
				continue;
		} else {
			if (memcmp(&pentry->partial_route.via_in6_addr, addr,
				   sizeof(struct in6_addr)))
				continue;
		}

		r = &pentry->partial_route;

		/* Return if partial route is already added with proper neigh entry */
		if (!secgw_neigh_find_and_add(&r->dst_in6_addr, r->prefixlen, n->neigh_ll_addr,
					      &route_index, NULL, NULL, 1)) {
			sdev = secgw_get_device(r->app_if_cookie);
			RTE_VERIFY(sdev->paired_device_index >= 0);
			sdev = secgw_get_device(sdev->paired_device_index);

			/* SRC MAC */
			ether = (struct rte_ether_addr *)(rewrite_data +
							  sizeof(struct rte_ether_addr));
			rte_eth_macaddr_get(sdev->dp_port_id, ether);

			/* DST MAC */
			ether = (struct rte_ether_addr *)rewrite_data;
			memcpy(ether->addr_bytes, n->neigh_ll_addr, sizeof(struct rte_ether_addr));

			add_lpm_route(&r->dst_in6_addr, r->prefixlen, edge, route_index,
				      rewrite_data, sizeof(rewrite_data), sdev->device_index, NULL);
		}
	}
	return 0;
}

static int
secgw_app_get_app_if_cookie(const char *ifname, int linux_ifindex, uint32_t *cookie)
{
	dao_port_group_t tdpg = DAO_PORT_GROUP_INITIALIZER;
	secgw_device_t *sdev = NULL;
	dao_port_t port;
	int32_t iter;

	if (dao_port_group_get_by_name(SECGW_TAP_PORT_GROUP_NAME, &tdpg) < 0)
		return -1;

	DAO_PORT_GROUP_FOREACH_PORT(tdpg, port, iter)
	{
		sdev = secgw_get_device(port);
		if (strstr(sdev->dev_name, ifname)) {
			sdev->linux_ifindex = linux_ifindex;
			if (cookie) {
				*cookie = port;
				return 0;
			}
		}
	}
	return -1;
}

int
secgw_route_add_del(dao_netlink_route_ip_route_t *r, dao_netlink_action_t action)
{
	uint8_t rewrite_data[2 * sizeof(struct rte_ether_addr)];
	rte_edge_t edge = SECGW_NODE_IP4_LOOKUP_NEXT_REWRITE;
	secgw_route_partial_entry_t *pentry = NULL;
	struct dao_ds str = DS_EMPTY_INITIALIZER;
	struct secgw_neigh_entry *nentry = NULL;
	struct rte_ether_addr *ether = NULL;
	secgw_device_t *sdev = NULL;
	int32_t route_index = -1;

	if (r && r->is_next_hop) {
		dao_ds_put_cstr(&str, "AddRoute partial: ");
		secgw_print_ip_addr(&r->dst_in6_addr, r->prefixlen, &str);
		dao_ds_put_cstr(&str, "via ");
		secgw_print_ip_addr(&r->via_in6_addr, r->via_addr_prefixlen, &str);

		/* Add complete route if via_address has valid neighbor entry,
		 * else put into partial route list to add later
		 */
		if (secgw_neigh_find_and_add(&r->via_in6_addr, r->via_addr_prefixlen, NULL,
					     &route_index, &edge, &nentry, 0) &&
		    nentry) {
			if (action == DAO_NETLINK_ACTION_ADD) {
				memset(&rewrite_data, 0, sizeof(rewrite_data));

				sdev = secgw_get_device(r->app_if_cookie);
				RTE_VERIFY(sdev->paired_device_index >= 0);
				sdev = secgw_get_device(sdev->paired_device_index);

				/* SRC MAC */
				ether = (struct rte_ether_addr *)(rewrite_data +
								  sizeof(struct rte_ether_addr));
				rte_eth_macaddr_get(sdev->dp_port_id, ether);

				/* DST MAC */
				ether = (struct rte_ether_addr *)rewrite_data;
				memcpy(ether->addr_bytes, nentry->dest_ll_addr,
				       sizeof(struct rte_ether_addr));
				dao_ds_put_cstr(&str, " ");

				add_lpm_route(&r->dst_in6_addr, r->prefixlen, edge, route_index,
					      rewrite_data, sizeof(rewrite_data),
					      sdev->device_index, &str);
			}
		} else {
			pentry = malloc(sizeof(*pentry));
			if (!pentry) {
				dao_ds_put_cstr(&str, " malloc failed ");
			} else {
				memcpy(&pentry->partial_route, r, sizeof(*r));
				STAILQ_INSERT_TAIL(&secgw_route_partial_list, pentry,
						   next_partial_entry);
				dao_ds_put_cstr(&str, " added ");
			}
		}
		SECGW_NL_DBG("%s", dao_ds_cstr(&str));
	}
	dao_ds_destroy(&str);

	return 0;
}

int
secgw_addr_add_del(dao_netlink_route_ip_addr_t *a, int is_add)
{
	uint16_t edge = SECGW_NODE_IP4_LOOKUP_NEXT_IP4_LOCAL;
	struct rte_ether_addr ether;
	struct dao_ds str = DS_EMPTY_INITIALIZER;
	secgw_device_t *sdev = NULL;
	int32_t route_index = -1;
	char buf[256];

	memset(ether.addr_bytes, 0, sizeof(struct rte_ether_addr));

	switch (is_add) {
	case 0:
		dao_ds_put_cstr(&str, "Deladdr ");
		break;

	case 1:
		dao_ds_put_cstr(&str, "Addaddr ");
		break;
	default:
		return -1;
	}
	secgw_print_ip_addr(&a->local_in6_addr, a->prefixlen, &str);

	if (is_add && a->is_ipv4) {
		dao_ds_put_format(&str, "%s ",
				  rtnl_addr_flags2str(a->addr_flags, buf, sizeof(buf)));
		sdev = secgw_get_device(a->app_if_cookie);
		if (sdev->paired_device_index < 0) {
			dao_ds_put_format(&str, "%s has no paired device...ignored ",
					  sdev->dev_name);
		} else {
			if (secgw_neigh_find_and_add(&a->local_in6_addr, a->prefixlen,
						     ether.addr_bytes, &route_index, &edge, NULL,
						     1)) {
				dao_ds_put_format(&str, "%s duplicate addr ", sdev->dev_name);
			} else {
				add_lpm_route(&a->local_in6_addr, a->prefixlen, edge, route_index,
					      NULL, 0 /* don't care */,
					      0 /*
		    don't care */, &str);
			}
		}
	} else {
		if (!a->is_ipv4)
			dao_ds_put_cstr(&str, " IPv6 not supported ");
		else
			dao_ds_put_cstr(&str, " ignored addr ");
	}
	SECGW_NL_DBG("%s", dao_ds_cstr(&str));
	dao_ds_destroy(&str);

	return 0;
}

int
secgw_link_add_del(dao_netlink_route_link_t *l, int is_add)
{
	RTE_SET_USED(l);
	RTE_SET_USED(is_add);

	return 0;
}

int
secgw_neigh_add_del(dao_netlink_route_ip_neigh_t *n, int is_add)
{
	uint8_t rewrite_data[2 * sizeof(struct rte_ether_addr)];
	uint16_t edge = SECGW_NODE_IP4_LOOKUP_NEXT_REWRITE;
	struct dao_ds str = DS_EMPTY_INITIALIZER;
	struct rte_ether_addr *ether = NULL;
	uint8_t *mac = NULL, rewrite_len;
	secgw_device_t *sdev = NULL;
	int32_t route_index = -1;
	char buf[256];

	switch (is_add) {
	case 1:
		dao_ds_put_cstr(&str, "AddNeigh ");
		break;
	case 0:
		dao_ds_put_cstr(&str, "DelNeigh ");
		break;
	}

	secgw_print_ip_addr(&n->dst_in6_addr, n->prefixlen, &str);
	if (is_add && n->is_ipv4) {
		dao_ds_put_format(&str, "%s ",
				  rtnl_neigh_state2str(n->neigh_state, buf, sizeof(buf)));
		mac = (uint8_t *)n->neigh_ll_addr;
		dao_ds_put_format(&str, "%02x:%02x:%02x:%02x:%02x:%02x ", mac[0], mac[1], mac[2],
				  mac[3], mac[4], mac[5]);

		if (!secgw_neigh_find_and_add(&n->dst_in6_addr, n->prefixlen, mac, &route_index,
					      &edge, NULL, 0)) {
			switch (n->neigh_state) {
			case DAO_NETLINK_NEIGHBOR_STATE_PERMANENT:
			case DAO_NETLINK_NEIGHBOR_STATE_REACHABLE:
			case DAO_NETLINK_NEIGHBOR_STATE_STALE:
				/* add now when state is valid*/
				secgw_neigh_find_and_add(&n->dst_in6_addr, n->prefixlen, mac,
							 &route_index, &edge, NULL, 1);

				memset(&rewrite_data, 0, sizeof(rewrite_data));

				sdev = secgw_get_device(n->app_if_cookie);
				RTE_VERIFY(sdev->paired_device_index >= 0);
				sdev = secgw_get_device(sdev->paired_device_index);

				/* SRC MAC */
				ether = (struct rte_ether_addr *)(rewrite_data +
								  sizeof(struct rte_ether_addr));
				rte_eth_macaddr_get(sdev->dp_port_id, ether);

				/* DST MAC */
				ether = (struct rte_ether_addr *)rewrite_data;
				memcpy(ether->addr_bytes, mac, sizeof(struct rte_ether_addr));

				rewrite_len = sizeof(rewrite_data);

				if (!add_lpm_route(&n->dst_in6_addr, n->prefixlen, edge,
						   route_index, rewrite_data, rewrite_len,
						   sdev->device_index, &str)) {
					find_and_add_partial_route_addr(n, edge, 1, &str);
				}
				break;
			default:
				dao_ds_put_cstr(&str, " ignore, invalid route state ");
				break;
			}
			SECGW_NL_DBG("%s", dao_ds_cstr(&str));
		} else {
			dao_ds_put_cstr(&str, " duplicate entry ");
		}
	} else {
		dao_ds_put_cstr(&str, " ignored ");
	}
	dao_ds_destroy(&str);

	return 0;
}

dao_netlink_route_callback_ops_t secgw_route_ops = {
	.get_app_interface_cookie = secgw_app_get_app_if_cookie,
	.link_add_del = secgw_link_add_del,
	.ip_route_add_del = secgw_route_add_del,
	.ip_neigh_add_del = secgw_neigh_add_del,
	.ip_local_addr_add_del = secgw_addr_add_del,
};

void
secgw_print_ip_addr(struct in6_addr *addr, int prefixlen, struct dao_ds *str)
{
	rte_be32_t ip4;
	char buf[256];

	if (IN6_IS_ADDR_V4MAPPED(addr)) {
		ip4 = dao_in6_addr_get_mapped_ipv4(addr);
		inet_ntop(AF_INET, (void *)&ip4, buf, sizeof(buf));
		if (prefixlen > 0)
			dao_ds_put_format(str, "%s/%d ", buf, prefixlen);
		else
			dao_ds_put_format(str, "%s ", buf);
	} else {
		inet_ntop(AF_INET6, (void *)addr, buf, sizeof(buf));
		dao_ds_put_format(str, "%s ", buf);
	}
}
