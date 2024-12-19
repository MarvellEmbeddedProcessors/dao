/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */
#ifndef __ETH_TRS_PRIV_H__
#define __ETH_TRS_PRIV_H__

#define MAX_ETH_PORTS    64           /**< Maximum number of ports per device */
#define ETH_DEV_PMD_NAME "net_otx_ep" /**< Ethernet PMD driver name */

enum {
	ETH_TRS_DEV_STATE_DOWN = 0, /**< Device state DOWN */
	ETH_TRS_DEV_STATE_UP,       /**< Device state UP */
};

struct eth_trs_dev {
	uint8_t nb_ports;                /**< Number of ports per device */
	uint8_t qs_per_port;             /**< Number of RX/TX queues per port */
	uint8_t state;                   /**< Device state UP/DOWN */
	uint8_t promiscuous;             /**< Promiscuous mode enable */
	uint16_t nb_queues;              /**< Total number of RX/TX queues */
	uint16_t port_id[MAX_ETH_PORTS]; /**< Port IDs of the device */
};

struct eth_trs_info {
	uint8_t nb_devs;                 /**< Max number of Ethernet transport devices */
	uint8_t nb_ports;                /**< Max number of ports per device */
	uint16_t nb_queues;              /**< Max number of RX/TX queues per device */
	uint16_t port_id[MAX_ETH_PORTS]; /**< Port IDs that support Ethernet transport */
	struct eth_trs_dev **devs;       /**< Ethernet transport devices */
};

#endif /* __ETH_TRS_PRIV_H__ */
