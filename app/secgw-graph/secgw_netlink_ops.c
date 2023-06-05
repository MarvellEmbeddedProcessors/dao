/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#include <secgw.h>
#include <rte_ipsec.h>
#include <rte_ipsec_sad.h>
#include <dao_dynamic_string.h>
#include <dao_port_group.h>
#include <arpa/inet.h>

int secgw_neigh_add_del(dao_netlink_route_ip_neigh_t *n, int is_add);
int secgw_link_add_del(dao_netlink_route_link_t *l, int is_add);
int secgw_addr_add_del(dao_netlink_route_ip_addr_t *a, int is_add);
int secgw_route_add_del(dao_netlink_route_ip_route_t *r, dao_netlink_action_t action);

static int
secgw_app_netlink_policy_create(dao_netlink_xfrm_policy_t *policy,
				dao_netlink_xfrm_sa_t *sa,
				dao_netlink_xfrm_op_type_t op_type, void *arg)
{
	dao_port_group_t port_group = DAO_PORT_GROUP_INITIALIZER;
	dao_worker_t *worker = dao_workers_self_worker_get();
	secgw_device_main_t *sdm = secgw_get_device_main();
	const struct rte_security_capability *caps, *cap;
	dao_port_t port = DAO_PORT_INVALID_VALUE;
	struct rte_crypto_sym_xform cipher, auth;
	struct rte_eth_dev_info dev_info;
	secgw_device_t *sdev = NULL;
	int ipsec_offload_flag = 0, i = 0;
	int32_t iter = -1;
	void *sec_ctx;

	if (dao_port_group_get_by_name(SECGW_ETHDEV_PORT_GROUP_NAME, &port_group) < 0) {
		dao_err("port_group_get by name for %s fails", SECGW_ETHDEV_PORT_GROUP_NAME);
		return -1;
	}

	if (dao_netlink_xfrm_sa_to_crypto_xform(sa, policy->policy_dir, &cipher, &auth) < 0) {
		dao_err("xfrm sa to crypto transforms fails");
		return -1;
	}

	dao_workers_barrier_sync(worker);
	DAO_PORT_GROUP_FOREACH_PORT(port_group, port, iter) {
		sdev = sdm->devices[iter];

		dao_info("Configuring IPsec on %s", sdev->dev_name);

		memset(&dev_info, 0, sizeof(struct rte_eth_dev_info));
		rte_eth_dev_info_get(sdev->dp_port_id, &dev_info);

		if (!(dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_SECURITY) ||
		    !(dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_SECURITY)) {
			dao_info("%s does not support rte_security offloadi.Skipping",
				 sdev->dev_name);
			continue;
		}
		sec_ctx = rte_eth_dev_get_sec_ctx(sdev->dp_port_id);
		caps = rte_security_capabilities_get(sec_ctx);

		ipsec_offload_flag = 0;

		while ((cap = &caps[i++])->action != RTE_SECURITY_ACTION_TYPE_NONE) {
			/*
			 * Check Rx support for inline ESP protocol offload in tunnel mode
			 */
			if ((cap->action == RTE_SECURITY_ACTION_TYPE_INLINE_PROTOCOL) &&
			    (cap->ipsec.proto == RTE_SECURITY_IPSEC_SA_PROTO_ESP) &&
			    (cap->ipsec.direction == RTE_SECURITY_IPSEC_SA_DIR_INGRESS) &&
			    (cap->ipsec.mode == RTE_SECURITY_IPSEC_SA_MODE_TUNNEL)) {
				ipsec_offload_flag++;
				dao_info("%s supports inline Rx ESP offload", sdev->dev_name);
			}
			/*
			 * Check Tx support for inline ESP protocol offload in tunnel mode
			 */
			if ((cap->action == RTE_SECURITY_ACTION_TYPE_INLINE_PROTOCOL) &&
			    (cap->ipsec.proto == RTE_SECURITY_IPSEC_SA_PROTO_ESP) &&
			    (cap->ipsec.direction == RTE_SECURITY_IPSEC_SA_DIR_EGRESS) &&
			    (cap->ipsec.mode == RTE_SECURITY_IPSEC_SA_MODE_TUNNEL)) {
				ipsec_offload_flag++;
				dao_info("%s supports inline Tx ESP offload", sdev->dev_name);
			}
		}
		if (ipsec_offload_flag != 2) {
			dao_dbg("%s does not support inline ipsec offload.Skipping",
				sdev->dev_name);
			continue;
		}
	}
	dao_workers_barrier_release(worker);

	RTE_SET_USED(arg);
	RTE_SET_USED(policy);
	RTE_SET_USED(sa);
	RTE_SET_USED(op_type);
	dao_dbg("secgw policy create");

	return 0;
}

static int
secgw_app_netlink_policy_destroy(dao_netlink_xfrm_policy_t *policy,
				 dao_netlink_xfrm_sa_t *sa,
				 dao_netlink_xfrm_op_type_t op_type, void *arg)
{
	RTE_SET_USED(arg);
	RTE_SET_USED(policy);
	RTE_SET_USED(sa);
	RTE_SET_USED(op_type);
	dao_err("secgw policy destroy");

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

	DAO_PORT_GROUP_FOREACH_PORT(tdpg, port, iter) {
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

static void print_ip_addr(struct in6_addr *addr, int prefixlen, struct dao_ds *str)
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

int secgw_route_add_del(dao_netlink_route_ip_route_t *r, dao_netlink_action_t action)
{
	RTE_SET_USED(r);
	RTE_SET_USED(action);

	return 0;
}

int secgw_addr_add_del(dao_netlink_route_ip_addr_t *a, int is_add)
{
	RTE_SET_USED(a);
	RTE_SET_USED(is_add);

	return 0;
}

int secgw_link_add_del(dao_netlink_route_link_t *l, int is_add)
{
	RTE_SET_USED(l);
	RTE_SET_USED(is_add);

	return 0;
}

int secgw_neigh_add_del(dao_netlink_route_ip_neigh_t *n, int is_add)
{
	struct dao_ds str = DS_EMPTY_INITIALIZER;
	char buf[256];

	switch (is_add) {
	case 1:
		dao_ds_put_cstr(&str, "AddNeigh ");
	break;
	case 0:
		dao_ds_put_cstr(&str, "DelNeigh ");
	break;
	}

	print_ip_addr(&n->dst_in6_addr, n->prefixlen, &str);
	dao_ds_put_format(&str, "%s ", rtnl_neigh_state2str(n->neigh_state, buf, sizeof(buf)));

	dao_info("%s", dao_ds_cstr(&str));
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

dao_netlink_xfrm_callback_ops_t secgw_xfrm_ops = {
	.xfrm_policy_create = secgw_app_netlink_policy_create,
	.xfrm_policy_destroy = secgw_app_netlink_policy_destroy,
};
