/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#include <netlink/secgw_netlink.h>
#include <rte_ipsec.h>
#include <rte_ipsec_sad.h>
#include <dao_dynamic_string.h>
#include <dao_port_group.h>
#include <arpa/inet.h>

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

		secgw_dbg("Configuring IPsec on %s", sdev->dev_name);

		memset(&dev_info, 0, sizeof(struct rte_eth_dev_info));
		rte_eth_dev_info_get(sdev->dp_port_id, &dev_info);

		if (!(dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_SECURITY) ||
		    !(dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_SECURITY)) {
			secgw_dbg("%s does not support rte_security offloadi.Skipping",
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
				secgw_dbg("%s supports inline Rx ESP offload", sdev->dev_name);
			}
			/*
			 * Check Tx support for inline ESP protocol offload in tunnel mode
			 */
			if ((cap->action == RTE_SECURITY_ACTION_TYPE_INLINE_PROTOCOL) &&
			    (cap->ipsec.proto == RTE_SECURITY_IPSEC_SA_PROTO_ESP) &&
			    (cap->ipsec.direction == RTE_SECURITY_IPSEC_SA_DIR_EGRESS) &&
			    (cap->ipsec.mode == RTE_SECURITY_IPSEC_SA_MODE_TUNNEL)) {
				ipsec_offload_flag++;
				secgw_dbg("%s supports inline Tx ESP offload", sdev->dev_name);
			}
		}
		if (ipsec_offload_flag != 2) {
			secgw_dbg("%s does not support inline ipsec offload.Skipping",
				  sdev->dev_name);
			continue;
		}
	}
	dao_workers_barrier_release(worker);

	RTE_SET_USED(arg);
	RTE_SET_USED(policy);
	RTE_SET_USED(sa);
	RTE_SET_USED(op_type);
	secgw_dbg("secgw policy create");

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

dao_netlink_xfrm_callback_ops_t secgw_xfrm_ops = {
	.xfrm_policy_create = secgw_app_netlink_policy_create,
	.xfrm_policy_destroy = secgw_app_netlink_policy_destroy,
};
