/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */
#include <stdint.h>
#include <stdio.h>

#include <rte_ethdev.h>
#include <rte_malloc.h>

#include <dao_eth_trs.h>
#include <dao_log.h>

#include "eth_trs_priv.h"

static struct eth_trs_info *eth_trs;

int
dao_eth_trs_dev_start(uint8_t dev_id)
{
	struct rte_eth_link link;
	struct eth_trs_dev *dev;
	uint16_t i;
	int rc;

	if (eth_trs == NULL) {
		dao_err("Ethernet transport library is not initialized");
		return -1;
	}

	if (dev_id >= eth_trs->nb_devs) {
		dao_err("Invalid device ID %u", dev_id);
		return -1;
	}

	dev = eth_trs->devs[dev_id];
	if (dev == NULL) {
		dao_err("Device %u is not initialized", dev_id);
		return -1;
	}

	if (dev->state == ETH_TRS_DEV_STATE_UP) {
		dao_warn("Device %u is already UP", dev_id);
		return 0;
	}

	for (i = 0; i < dev->nb_ports; i++) {
		rc = rte_eth_dev_start(dev->port_id[i]);
		if (rc < 0) {
			dao_err("Failed to start ethernet device (port %u): %d", dev->port_id[i],
				rc);
			goto fail;
		}

		if (dev->promiscuous)
			rte_eth_promiscuous_enable(dev->port_id[i]);
	}

	rc = rte_eth_link_get_nowait(dev->port_id[0], &link);
	if (rc < 0) {
		dao_err("Failed to get ethernet link status: %d", rc);
		goto fail;
	}

	if (link.link_status == RTE_ETH_LINK_DOWN) {
		dao_err("Ethernet link is down");
		goto fail;
	}

	dev->state = ETH_TRS_DEV_STATE_UP;
	return 0;
fail:
	dao_eth_trs_dev_stop(dev_id);
	return rc;
}

int
dao_eth_trs_dev_stop(uint8_t dev_id)
{
	struct eth_trs_dev *dev;
	uint16_t i;
	int rc;

	if (eth_trs == NULL) {
		dao_err("Ethernet transport library is not initialized");
		return -1;
	}

	if (dev_id >= eth_trs->nb_devs) {
		dao_err("Invalid device ID %u", dev_id);
		return -1;
	}

	dev = eth_trs->devs[dev_id];
	if (dev == NULL) {
		dao_err("Device %u is not initialized", dev_id);
		return -1;
	}

	if (dev->state == ETH_TRS_DEV_STATE_DOWN) {
		dao_warn("Device %u is already DOWN", dev_id);
		return 0;
	}

	for (i = 0; i < dev->nb_ports; i++) {
		rc = rte_eth_dev_stop(dev->port_id[i]);
		if (rc < 0) {
			dao_err("Failed to stop ethernet device (port %u): %d", dev->port_id[i],
				rc);
			goto fail;
		}
	}

	dev->state = ETH_TRS_DEV_STATE_DOWN;
	return 0;
fail:
	return rc;
}

int
dao_eth_trs_dev_queue_configure(uint8_t dev_id, uint16_t dev_queue_id,
				struct dao_eth_trs_queue_config *conf)
{
	uint16_t port_id, queue_id;
	struct eth_trs_dev *dev;
	int rc;

	if (eth_trs == NULL) {
		dao_err("Ethernet transport library is not initialized");
		return -1;
	}

	if (dev_id >= eth_trs->nb_devs) {
		dao_err("Invalid device ID %u", dev_id);
		return -1;
	}

	if (conf == NULL) {
		dao_err("Invalid queue configuration");
		return -1;
	}

	if (conf->queue_size == 0) {
		dao_err("Invalid queue size");
		return -1;
	}

	if (conf->rx_mp == NULL) {
		dao_err("Invalid RX mempool");
		return -1;
	}

	dev = eth_trs->devs[dev_id];
	if (dev == NULL) {
		dao_err("Device %u is not initialized", dev_id);
		return -1;
	}

	if (dev_queue_id >= dev->nb_queues) {
		dao_err("Invalid device queue ID %u", dev_queue_id);
		return -1;
	}

	if (dev->state == ETH_TRS_DEV_STATE_UP) {
		dao_err("Device is in use, stop it first");
		return -1;
	}

	/* Get ethernet port ID and queue ID */
	port_id = dev->port_id[dev_queue_id / dev->qs_per_port];
	queue_id = dev_queue_id % dev->qs_per_port;

	rc = rte_eth_rx_queue_setup(port_id, queue_id, conf->queue_size,
				    rte_eth_dev_socket_id(port_id), NULL, conf->rx_mp);
	if (rc < 0) {
		dao_err("Failed to setup ethernet RX queue %u for port %u: %d", queue_id, port_id,
			rc);
		return rc;
	}

	rc = rte_eth_tx_queue_setup(port_id, queue_id, conf->queue_size,
				    rte_eth_dev_socket_id(port_id), NULL);
	if (rc < 0) {
		dao_err("Failed to setup ethernet TX queue %u for port %u: %d", queue_id, port_id,
			rc);
		return rc;
	}

	return 0;
}

int
dao_eth_trs_dev_queue_map(uint8_t dev_id, uint16_t dev_queue_id, uint16_t *port_id,
			  uint16_t *queue_id)
{
	struct eth_trs_dev *dev;

	if (eth_trs == NULL) {
		dao_err("Ethernet transport library is not initialized");
		return -1;
	}

	if (dev_id >= eth_trs->nb_devs) {
		dao_err("Invalid device ID %u", dev_id);
		return -1;
	}

	dev = eth_trs->devs[dev_id];
	if (dev == NULL) {
		dao_err("Device %u is not initialized", dev_id);
		return -1;
	}

	if (dev_queue_id >= dev->nb_queues) {
		dao_err("Invalid device queue ID %u", dev_queue_id);
		return -1;
	}

	/* Get ethernet port ID and queue ID */
	*port_id = dev->port_id[dev_queue_id / dev->qs_per_port];
	*queue_id = dev_queue_id % dev->qs_per_port;

	return 0;
}

int
dao_eth_trs_dev_alloc(uint8_t dev_id, struct dao_eth_trs_dev_config *conf)
{
	struct rte_eth_dev_info dev_info;
	struct rte_eth_conf eth_conf;
	uint16_t max_qs_per_port;
	struct eth_trs_dev *dev;
	char dev_name[32];
	uint8_t i;
	int rc;

	if (eth_trs == NULL) {
		dao_err("Ethernet transport library is not initialized");
		return -1;
	}

	if (dev_id >= eth_trs->nb_devs) {
		dao_err("Invalid device ID %u", dev_id);
		return -1;
	}

	if (conf->nb_queues == 0 || conf->nb_queues > eth_trs->nb_queues) {
		dao_err("Invalid number of device queues %u", conf->nb_queues);
		return -1;
	}

	sprintf(dev_name, "eth_trs_dev_%u", dev_id);
	dev = rte_zmalloc(dev_name, sizeof(struct eth_trs_dev), 0);
	if (dev == NULL) {
		dao_err("Failed to allocate memory for ethernet transport device");
		return -1;
	}

	/* Calculate the number of ports and queues per port */
	max_qs_per_port = eth_trs->nb_queues / eth_trs->nb_ports;
	dev->nb_ports = (conf->nb_queues + max_qs_per_port - 1) / max_qs_per_port;
	dev->qs_per_port = (conf->nb_queues + dev->nb_ports - 1) / dev->nb_ports;
	dev->nb_queues = conf->nb_queues;

	for (i = 0; i < dev->nb_ports; i++)
		dev->port_id[i] = eth_trs->port_id[i];

	dev->state = ETH_TRS_DEV_STATE_DOWN;
	dev->promiscuous = conf->promiscuous;
	eth_trs->devs[dev_id] = dev;

	/* Information is the same for all the ports */
	rc = rte_eth_dev_info_get(dev->port_id[0], &dev_info);
	if (rc < 0) {
		dao_err("Failed to get ethernet device info (port %u): %d", dev->port_id[0], rc);
		goto fail;
	}

	memset(&eth_conf, 0, sizeof(eth_conf));
	eth_conf.rxmode.mtu = dev_info.max_mtu;
	eth_conf.rxmode.mq_mode = RTE_ETH_MQ_RX_RSS;
	eth_conf.txmode.mq_mode = RTE_ETH_MQ_TX_NONE;

	/* Configure the ethernet ports */
	for (i = 0; i < dev->nb_ports; i++) {
		rc = rte_eth_dev_configure(dev->port_id[i], dev->qs_per_port, dev->qs_per_port,
					   &eth_conf);
		if (rc < 0) {
			dao_err("Failed to configure ethernet device (port %u): %d",
				dev->port_id[i], rc);
			goto fail;
		}
	}

	return 0;
fail:
	dao_eth_trs_dev_free(dev_id);
	return -1;
}

int
dao_eth_trs_dev_free(uint8_t dev_id)
{
	struct eth_trs_dev *dev;
	uint16_t i;
	int rc;

	if (eth_trs == NULL) {
		dao_err("Ethernet transport library is not initialized");
		return -1;
	}

	if (dev_id >= eth_trs->nb_devs) {
		dao_err("Invalid device ID %u", dev_id);
		return -1;
	}

	dev = eth_trs->devs[dev_id];
	if (dev == NULL) {
		dao_err("Device %u not initialized", dev_id);
		return -1;
	}

	if (dev->state == ETH_TRS_DEV_STATE_UP) {
		dao_err("Device is in use, stop it first");
		return -1;
	}

	for (i = 0; i < dev->nb_ports; i++) {
		rc = rte_eth_dev_close(dev->port_id[i]);
		if (rc < 0) {
			dao_err("Failed to close ethernet device (port %u): %d", dev->port_id[i],
				rc);
			return rc;
		}
	}

	rte_free(dev);
	eth_trs->devs[dev_id] = NULL;

	return 0;
}

int
dao_eth_trs_info(struct dao_eth_trs_info *info)
{
	struct rte_eth_dev_info dev_info;
	int rc;

	if (eth_trs == NULL) {
		dao_err("Ethernet transport library is not initialized");
		return -1;
	}

	/* Information is the same for all the ports */
	rc = rte_eth_dev_info_get(eth_trs->port_id[0], &dev_info);
	if (rc < 0) {
		dao_err("Failed to get ethernet device info (port %u): %d", eth_trs->port_id[0],
			rc);
		return rc;
	}

	info->nb_devs = eth_trs->nb_devs;
	info->nb_queues = eth_trs->nb_queues;
	info->min_queue_size = dev_info.rx_desc_lim.nb_min;
	info->max_queue_size = dev_info.rx_desc_lim.nb_max;
	info->min_buf_len = dev_info.min_rx_bufsize;
	info->max_pkt_len = dev_info.max_rx_pktlen;

	return 0;
}

int
dao_eth_trs_init(void)
{
	uint8_t i;
	int ret;

	if (eth_trs) {
		dao_warn("Ethernet transport already initialized");
		return 0;
	}

	eth_trs = rte_zmalloc(NULL, sizeof(struct eth_trs_info), 0);
	if (eth_trs == NULL) {
		dao_err("Failed to allocate memory for ethernet transport info");
		return -ENOMEM;
	}

	/* Coalesce all the ethernet devices as of now and expose as one */
	eth_trs->nb_devs = 1;
	for (i = 0; i < rte_eth_dev_count_avail(); i++) {
		struct rte_eth_dev_info dev_info;
		int rc;

		rc = rte_eth_dev_info_get(i, &dev_info);
		if (rc < 0)
			continue;

		if (strcmp(dev_info.driver_name, ETH_DEV_PMD_NAME) == 0) {
			eth_trs->nb_queues += dev_info.max_rx_queues;
			eth_trs->port_id[eth_trs->nb_ports] = i;
			eth_trs->nb_ports++;
		}
	}

	if (eth_trs->nb_ports == 0) {
		dao_err("No supported ethernet devices found");
		ret = -ENODEV;
		goto eth_trs_free;
	}

	eth_trs->devs = rte_zmalloc(NULL, sizeof(struct eth_trs_dev) * eth_trs->nb_devs, 0);
	if (eth_trs->devs == NULL) {
		dao_err("Failed to allocate memory for ethernet transport devices");
		ret = -ENOMEM;
		goto eth_trs_free;
	}

	return 0;

eth_trs_free:
	rte_free(eth_trs);
	eth_trs = NULL;
	return ret;
}

int
dao_eth_trs_fini(void)
{
	uint8_t i;

	if (eth_trs == NULL)
		return 0;

	for (i = 0; i < eth_trs->nb_devs; i++) {
		if (eth_trs->devs[i])
			dao_eth_trs_dev_free(i);
	}

	rte_free(eth_trs->devs);
	rte_free(eth_trs);
	eth_trs = NULL;

	return 0;
}
