/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#ifndef _APP_SECGW_GRAPH_DEVICES_SECGW_DEVICE_H_
#define _APP_SECGW_GRAPH_DEVICES_SECGW_DEVICE_H_

/* External function declarations */
#define SECGW_REALLOC_NUM               4
#define SECGW_DEVICE_NAMELEN            128

#define SECGW_ETHDEV_PORT_GROUP_NAME    "ethdev"
#define SECGW_TAP_PORT_GROUP_NAME       "dtap"

typedef struct {
	const char *name;
	uint32_t num_rx_queues;
	uint32_t num_tx_queues;
	uint32_t num_rx_desc;
	uint32_t num_tx_desc;
	uint16_t dp_port_id;
	uint32_t device_index;
	uint32_t num_workers;
	uint32_t total_devices;
} secgw_device_register_conf_t;

typedef struct {
	/** fast path variable accesses */

	/* ifindex for LINUX tap devices. */
	int linux_ifindex;

	/** Index in device_main->devices[] */
	uint32_t device_index;
	/**
	 * Index in device_main->devices[] paired with each other
	 */
	int32_t paired_device_index;

	uint16_t dp_port_id;

	/** port group attached to this device */
	dao_port_group_t port_group;
	/** Index in port_group */
	int32_t port_index;

	/* portq group used for this device-rx node queue polling */
	dao_portq_group_t portq_group;

	/* tx node to be connected to interface-output node */
	struct rte_node_register *tx_node;

	/** device name */
	char dev_name[SECGW_DEVICE_NAMELEN];
} secgw_device_t;

typedef struct {
	int32_t n_devices;
	int32_t max_num_devices_allocated;
	secgw_device_t **devices;
} secgw_device_main_t;

int secgw_register_ethdev(secgw_device_t **ppdev, secgw_device_register_conf_t *conf);
int secgw_register_tap(secgw_device_t **ppdev, secgw_device_register_conf_t *conf);
int secgw_register_active_tap(secgw_device_t *sdev, uint32_t num_workers);
#endif
