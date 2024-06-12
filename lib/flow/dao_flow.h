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

/** Key exchange profile name maximum length */
#define DAO_FLOW_PROFILE_NAME_MAX 60

/** Query structure to retrieve and reset flow rule counters */
struct dao_flow_query_count {
	/** Reset counters after query [in] */
	uint32_t reset : 1;
	/** hits field is set [out] */
	uint32_t hits_set : 1;
	/** bytes field is set [out] */
	uint32_t bytes_set : 1;
	/** Reserved, must be zero [in, out] */
	uint32_t reserved : 29;
	/** Number of hits for this rule [out] */
	uint64_t hits;
	/** Number of bytes through this rule [out] */
	uint64_t bytes;
	/** Number of hits for respective acl rule [out] */
	uint64_t acl_rule_hits;
};

/** Structure to retrieve no of flow at different stages per port */
struct dao_flow_count {
	/** Number of DAO flows per port */
	uint32_t dao_flow;
	/* Number of HW offload flows per port */
	uint32_t hw_offload_flow;
	/** Number of ACL rules per port */
	uint32_t acl_rule;
};

/** Flow offloading configuration structure */
struct dao_flow_offload_config {
#define DAO_FLOW_HW_OFFLOAD_ENABLE RTE_BIT64(0)
	/** Different features supported */
	uint32_t feature;
	/** Key exchange profiles supported */
	char parse_profile[DAO_FLOW_PROFILE_NAME_MAX];
	/** Flow aging timeout */
	uint32_t aging_tmo;
};

/** DAO flow handle */
struct dao_flow {
	/** ACL rule info */
	struct acl_rule_data *arule;
	/** ACL rule id */
	uint32_t acl_rule_id;
	/** HW offload rule info */
	struct hw_offload_flow *hflow;
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

/**
 * Query an existing flow rule.
 *
 * This function allows retrieving flow-specific data such as counters.
 * Data is gathered by special actions which must be present in the flow
 * rule definition.
 *
 * \see RTE_FLOW_ACTION_TYPE_COUNT
 *
 * @param port_id
 *   Port identifier of Ethernet device.
 * @param flow
 *   Flow rule handle to query.
 * @param action
 *   Action definition as defined in original flow rule.
 * @param[in, out] data
 *   Pointer to storage for the associated query data type.
 * @param[out] error
 *   Perform verbose error reporting if not NULL. PMDs initialize this
 *   structure in case of error only.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
int dao_flow_query(uint16_t port_id, struct dao_flow *flow, const struct rte_flow_action *action,
		   void *data, struct rte_flow_error *error);

/**
 * Dump internal representation information of dao flow to file.
 *
 * @param[in] port_id
 *    The port identifier of the Ethernet device.
 * @param[in] flow
 *   The pointer of flow rule to dump. Dump all rules if NULL.
 * @param[in] file
 *   A pointer to a file for output.
 * @param[out] error
 *   Perform verbose error reporting if not NULL. PMDs initialize this
 *   structure in case of error only.
 * @return
 *   0 on success, a negative value otherwise.
 */
int dao_flow_dev_dump(uint16_t port_id, struct dao_flow *flow, FILE *file,
		      struct rte_flow_error *error);

/**
 * Destroy all flow rules associated with a port.
 *
 * In the unlikely event of failure, handles are still considered destroyed
 * and no longer valid but the port must be assumed to be in an inconsistent
 * state.
 *
 * @param port_id
 *   Port identifier of Ethernet device.
 * @param[out] error
 *   Perform verbose error reporting if not NULL. PMDs initialize this
 *   structure in case of error only.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
int dao_flow_flush(uint16_t port_id, struct rte_flow_error *error);

/**
 * Get information of all flows associated with a port.
 *
 * Retrieving information about all flows associated with a port.
 *
 * @param port_id
 *   Port identifier of Ethernet device.
 * @param[in] file
 *   A pointer to a file for output.
 * @param[out] error
 *   Perform verbose error reporting if not NULL. PMDs initialize this
 *   structure in case of error only.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
int dao_flow_info(uint16_t port_id, FILE *file, struct rte_flow_error *error);

/**
 * Get flow count.
 * Retrieving no of flows associated with a port.
 *
 * @param port_id
 *   Port identifier of Ethernet device.
 * @param[out] count
 *   A pointer to a flow count structure.
 * @param[out] error
 *   Perform verbose error reporting if not NULL. PMDs initialize this
 *   structure in case of error only.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */

int dao_flow_count(uint16_t port_id, struct dao_flow_count *count, struct rte_flow_error *error);
#endif /* __DAO_FLOW_OFFLOAD_H__ */
