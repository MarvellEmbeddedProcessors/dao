/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#ifndef __DAO_FLOW_OFFLOAD_H__
#define __DAO_FLOW_OFFLOAD_H__

/**
 * @file
 *
 * DAO Flow offload library
 */

#include <rte_flow.h>

/** Flow offloading configuration structure */
struct dao_flow_offload_config {
#define DAO_FLOW_OFFLOAD_HW_OFFLOAD BIT_ULL(0)
	/** Different features supported */
	uint32_t feature;
	/** Key exchange profiles supported */
	uint32_t kex_profile;
};

/** DAO flow handle */
struct dao_flow {
	/** ACL rule info */
	struct acl_rule_data *arule;
	/** ACL rule id */
	uint32_t acl_rule_id;
	/** Port ID for which rule is installed */
	uint16_t port_id;
	/** Table ID to which rule is installed */
	uint16_t tbl_id;
};

/**
 * Setting up the flow configurations based on input provided by user
 *
 * @param[in] config
 *    Flow offloading configuration
 * @return
 *   0 on success, otherwise a negative errno value.
 */
int dao_flow_init(struct dao_flow_offload_config *config);

/**
 * Global flow configuration cleanup
 *
 * @return
 *   0 on success, otherwise a negative errno value.
 */
int dao_flow_fini(void);

/**
 * Create a flow rule on a given port.
 *
 * @param[in] port_id
 *    Port identifier of Ethernet device.
 * @param[in] attr
 *    Flow rule attributes.
 * @param[in] pattern
 *   Pattern specification (list terminated by the END pattern item).
 * @param[in] actions
 *   Associated actions (list terminated by the END action).
 * @param[out] error
 *   Perform verbose error reporting if not NULL.
 * @return
 *   A valid handle in case of success, NULL otherwise and errno is set.
 */
struct dao_flow *dao_flow_create(uint16_t port_id, const struct rte_flow_attr *attr,
				 const struct rte_flow_item pattern[],
				 const struct rte_flow_action actions[],
				 struct rte_flow_error *error);

/**
 * Destroy a flow rule on a given port.
 *
 * @param[in] port_id
 *   Port identifier of Ethernet device.
 * @param[in] flow
 *   Flow rule handle to destroy.
 * @param[out] error
 *   Perform verbose error reporting if not NULL.
 *
 * @return
 *   0 on success, a negative errno value.
 */
int dao_flow_destroy(uint16_t port_id, struct dao_flow *flow, struct rte_flow_error *error);

/**
 * Lookup for a flow on a given port.
 *
 * Its a fast path API which takes buffer stream as an input and looks up for a flow
 * hit/miss. On hit appropriate action is performed based on the flow rule created.
 * Also if HW offloading is enabled, respective flow is installed in the HW CAM.
 *
 * @param[in] port_id
 *   Port identifier of Ethernet device.
 * @param[in] objs
 *   Array of packet buffers
 * @param[in] nb_objs
 *   No of packet buffers
 *
 * @return
 *   0 on success, a negative errno value.
 */
int dao_flow_lookup(uint16_t port_id, struct rte_mbuf **objs, uint16_t nb_objs);

#endif /* __DAO_FLOW_OFFLOAD_H__ */
