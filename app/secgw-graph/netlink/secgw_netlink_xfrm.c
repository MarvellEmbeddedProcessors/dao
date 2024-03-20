/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#include <netlink/secgw_netlink.h>
#include <nodes/node_api.h>

#define SECGW_IPSEC_NUM_SA       256
#define SECGW_IPSEC_NUM_POLICIES 256
static int
secgw_app_netlink_policy_create(dao_netlink_xfrm_policy_t *policy, dao_netlink_xfrm_sa_t *xsa,
				dao_netlink_xfrm_op_type_t op_type, void *arg)
{
	dao_port_group_t port_group = DAO_PORT_GROUP_INITIALIZER;
	dao_worker_t *worker = dao_workers_self_worker_get();
	secgw_device_main_t *sdm = secgw_get_device_main();
	dao_port_t port = DAO_PORT_INVALID_VALUE;
	int32_t iter = -1, sa_idx = -1;
	secgw_ipsec_main_t *sim = NULL;
	secgw_device_t *sdev = NULL;
	secgw_ipsec_t *ips = NULL;
	uint32_t ipsec_index = 0;

	RTE_SET_USED(op_type);
	RTE_SET_USED(arg);

	if (!worker)
		return -1;

	if (!sdm)
		return -1;

	if (dao_port_group_get_by_name(SECGW_ETHDEV_PORT_GROUP_NAME, &port_group) < 0) {
		dao_err("port_group_get by name for %s fails", SECGW_ETHDEV_PORT_GROUP_NAME);
		return -1;
	}

	dao_workers_barrier_sync(worker);
	DAO_PORT_GROUP_FOREACH_PORT(port_group, port, iter)
	{
		sdev = sdm->devices[iter];

		if (!(sdev->device_flags & SECGW_HW_RX_OFFLOAD_INLINE_IPSEC) ||
		    !(sdev->device_flags & SECGW_HW_TX_OFFLOAD_INLINE_IPSEC)) {
			dao_dbg("%s does not support inline ipsec offload.Skipping",
				sdev->dev_name);
			continue;
		}
		SECGW_NL_DBG("Configuring IPsec on %s", sdev->dev_name);
		/* Attach secgw ipsec instance for the first time */
		if (!(sdev->device_flags & SECGW_IPSEC_ATTACH)) {
			if (secgw_ipsec_attach("secgw", xsa, policy->policy_dir, sdev->dp_port_id,
					       SECGW_IPSEC_NUM_SA, SECGW_IPSEC_NUM_POLICIES,
					       &ipsec_index)) {
				SECGW_NL_DBG("ipsec_attach failed on %s(%u)", sdev->dev_name,
					     sdev->dp_port_id);
				continue;
			} else {
				RTE_VERIFY(!ip_feature_output_enable(
					secgw_ipsec_policy_output_node_get(), sdev->dp_port_id,
					(int64_t)ipsec_index));
				sdev->ipsec_instance_index = ipsec_index;
				sdev->device_flags |= SECGW_IPSEC_ATTACH;
				secgw_info("IPsec instance: %u attached to %s",
					   ipsec_index, sdev->dev_name);
			}
		}
		sim = secgw_ipsec_main_get();

		ips = secgw_ipsec_get(sim, sdev->ipsec_instance_index);
		sa_idx = -1;
		if (policy->policy_dir != DAO_NETLINK_XFRM_POLICY_DIR_FWD)
			if (secgw_ipsec_sad_sa_add_del(ips, ips->sadb_v4, xsa, sdev->dp_port_id,
						       policy->policy_dir, 1, &sa_idx))
				break;

		if (secgw_ipsec_policy_add_del(ips, policy, sa_idx, sdev->dp_port_id, 1) < 0)
			break;
	}
	dao_workers_barrier_release(worker);

	dao_dbg("secgw policy create");

	return 0;
}

static int
secgw_app_netlink_policy_destroy(dao_netlink_xfrm_policy_t *policy, dao_netlink_xfrm_sa_t *sa,
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
