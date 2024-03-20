/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#ifndef _APP_SECGW_GRAPH_DEVICES_SECGW_DEVICE_H_
#define _APP_SECGW_GRAPH_DEVICES_SECGW_DEVICE_H_

/* External function declarations */
#define SECGW_REALLOC_NUM    4
#define SECGW_DEVICE_NAMELEN 128

#define SECGW_ETHDEV_PORT_GROUP_NAME "ethdev"
#define SECGW_TAP_PORT_GROUP_NAME    "dtap"

#define foreach_octeon_device_bus_info		\
	_(0, "a063", "rpmpf")			\
	_(1, "a0f7", "sdpvf")			\
	_(2, "a065", "rvupf")

#define SECGW_PCI_DEV_STR "device_id=%s"
typedef enum {
	SECGW_HW_RX_OFFLOAD_INLINE_IPSEC = 1 << 0,
	SECGW_HW_TX_OFFLOAD_INLINE_IPSEC = 1 << 1,
	SECGW_IPSEC_ATTACH = 1 << 2,
} secgw_device_flags_t;

typedef struct {
	const char *name;
	const char *device_prefix_name;
	uint32_t num_rx_queues;
	uint32_t num_tx_queues;
	uint32_t num_rx_desc;
	uint32_t num_tx_desc;
	uint16_t dp_port_id;
	uint32_t device_index;
	uint32_t num_workers;
	uint32_t total_devices;
} secgw_device_register_conf_t;

typedef struct secgw_device_ip_addr {
	STAILQ_ENTRY(secgw_device_ip_addr) next_local_ip;

	struct in6_addr local_ip_addr;
} secgw_device_ip_addr_t;

typedef struct {
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

	/* ifindex for LINUX tap devices. */
	int linux_ifindex;

	int ipsec_instance_index;

	/* portq group used for this device-rx node queue polling */
	dao_portq_group_t portq_group;

	/* tx node to be connected to interface-output node */
	struct rte_node_register *tx_node;

	/* rx node for input feature */
	struct rte_node_register *rx_node;

	/** device name */
	char dev_name[SECGW_DEVICE_NAMELEN];

	uint64_t dpdk_rx_offload_flags;
	uint64_t dpdk_tx_offload_flags;

	secgw_device_flags_t device_flags;

	STAILQ_HEAD(, secgw_device_ip_addr) all_local_ips;
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
