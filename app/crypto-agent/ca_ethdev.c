/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_thash.h>

#include "ca_admin.h"
#include "ca_ethdev.h"
#include "crypto_agent.h"

#define CA_ETH_RSS_KEY_LEN 48

static uint32_t
rotate_bytes(uint32_t value)
{
	return (value << 8) | (value >> 24);
}

static uint32_t
swap_words(uint32_t value)
{
	return (value << 16) | (value >> 16);
}

static void
eth_rss_key_get(uint8_t *rss_key)
{
	/*
	 * This key matches the default hardware configuration.
	 * Setting it explicitly to ensure consistency and safety.
	 */

	static const uint8_t key[CA_ETH_RSS_KEY_LEN] = {
		0xfe, 0xed, 0x0b, 0xad, 0xfe, 0xed, 0x0b, 0xad, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	};

	memcpy(rss_key, key, CA_ETH_RSS_KEY_LEN);
}

static int
eth_rss_key_update(uint8_t port_id)
{
	static uint8_t rss_key[CA_ETH_RSS_KEY_LEN];
	struct rte_eth_rss_conf rss_conf;
	int ret;

	memset(&rss_conf, 0, sizeof(rss_conf));

	eth_rss_key_get(rss_key);

	rss_conf.rss_key = rss_key;
	rss_conf.rss_key_len = sizeof(rss_key);
	rss_conf.rss_hf = RTE_ETH_RSS_PORT;

	ret = rte_eth_dev_rss_hash_update(port_id, &rss_conf);
	if (ret)
		CA_ERR("Could not update RSS hash key: %d", port_id);

	return ret;
}

int
ca_eth_dev_init(uint8_t port_id, struct ca_dev_config *dev_config, struct rte_mempool *mp)
{
	uint16_t nb_queue, queue_id, nb_rxd, nb_txd, buf_sz;
	struct rte_ether_addr ports_eth_addr;
	struct rte_eth_rss_conf *rss_conf;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_conf port_conf;
	struct rte_eth_rxconf rx_conf;
	struct rte_eth_txconf tx_conf;
	struct rte_eth_link link;
	int ret;

	/* TODO - determine proper values */
	nb_rxd = 8192;
	nb_txd = 8192;

	buf_sz = dev_config->max_payload_size;

	CA_INFO("Initializing ethdev: %d", port_id);

	rss_conf = &port_conf.rx_adv_conf.rss_conf;

	rss_conf->rss_key = NULL;
	rss_conf->rss_key_len = 0;

	memset(&dev_info, 0, sizeof(dev_info));
	ret = rte_eth_dev_info_get(port_id, &dev_info);
	if (ret) {
		CA_ERR("Could not get ethdev info: %d.", port_id);
		return ret;
	}

	if (dev_info.max_rx_queues < dev_config->eth.nb_queue[port_id]) {
		CA_ERR("Requested queues %d > max rx queues %d", dev_config->eth.nb_queue[port_id],
		       dev_info.max_rx_queues);
		return -EINVAL;
	}

	if (dev_info.max_tx_queues < dev_config->eth.nb_queue[port_id]) {
		CA_ERR("Requested queues %d > max tx queues %d", dev_config->eth.nb_queue[port_id],
		       dev_info.max_tx_queues);
		return -EINVAL;
	}

	nb_queue = dev_config->eth.nb_queue[port_id];

	memset(&port_conf, 0, sizeof(port_conf));

	port_conf.rxmode.mtu = buf_sz;
	port_conf.rxmode.mq_mode = RTE_ETH_MQ_RX_RSS;
	port_conf.txmode.mq_mode = RTE_ETH_MQ_TX_NONE;
	port_conf.txmode.offloads = RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

	ret = rte_eth_dev_configure(port_id, nb_queue, nb_queue, &port_conf);
	if (ret) {
		CA_ERR("Could not configure ethdev: %d.", port_id);
		return ret;
	}

	ret = eth_rss_key_update(port_id);
	if (ret) {
		CA_ERR("Could not update RSS key: %d.", port_id);
		return ret;
	}

	ret = rte_eth_dev_adjust_nb_rx_tx_desc(port_id, &nb_rxd, &nb_txd);
	if (ret) {
		CA_ERR("Could not adjust nb rx/tx desc: %d.", port_id);
		return ret;
	}

	rte_eth_macaddr_get(port_id, &ports_eth_addr);
	CA_INFO("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 " %02" PRIx8
		" %02" PRIx8,
		port_id, ports_eth_addr.addr_bytes[0], ports_eth_addr.addr_bytes[1],
		ports_eth_addr.addr_bytes[2], ports_eth_addr.addr_bytes[3],
		ports_eth_addr.addr_bytes[4], ports_eth_addr.addr_bytes[5]);

	for (queue_id = 0; queue_id < nb_queue; queue_id++) {
		memset(&rx_conf, 0, sizeof(rx_conf));
		memset(&tx_conf, 0, sizeof(tx_conf));

		rx_conf.offloads = port_conf.rxmode.offloads;
		tx_conf.offloads = port_conf.txmode.offloads;

		ret = rte_eth_rx_queue_setup(port_id, queue_id, nb_rxd, 0, &rx_conf, mp);
		if (ret) {
			CA_ERR("Could not setup Rx queue: %d.", port_id);
			return ret;
		}

		ret = rte_eth_tx_queue_setup(port_id, queue_id, nb_txd, 0, &tx_conf);
		if (ret) {
			CA_ERR("Could not setup Tx queue: %d.", port_id);
			return ret;
		}
	}

	ret = rte_eth_promiscuous_enable(port_id);
	if (ret) {
		CA_ERR("Could not enable promiscuous mode: %d.", port_id);
		return ret;
	}

	ret = rte_eth_dev_start(port_id);
	if (ret) {
		CA_ERR("Could not start ethdev: %d.", port_id);
		return ret;
	}

	ret = rte_eth_link_get(port_id, &link);
	if (ret) {
		CA_ERR("Could not get link status: %d.", port_id);
		goto eth_dev_close;
	}

	if (link.link_status == RTE_ETH_LINK_UP) {
		CA_INFO("Port %u Link Up - speed %u Mbps - %s", port_id, link.link_speed,
			(link.link_duplex == RTE_ETH_LINK_FULL_DUPLEX) ? "full-duplex" :
									 "half-duplex");
	} else {
		CA_INFO("Port %u Link Down", port_id);
		goto eth_dev_close;
	}

	return 0;

eth_dev_close:
	rte_eth_dev_stop(port_id);
	rte_eth_dev_close(port_id);

	return -ENODEV;
}

void
ca_eth_dev_fini(struct ca_ethdev_ctx *eth_ctx)
{
	uint16_t port_id;

	port_id = eth_ctx->port_id;

	CA_INFO("Closing ethdev: %d", port_id);

	rte_eth_dev_stop(port_id);
	rte_eth_dev_close(port_id);
}

static int
eth_ingress_queue_mapping(uint8_t port_id, uint16_t *reta_tbl, uint16_t nb_queue)
{
	uint8_t rss_key[CA_ETH_RSS_KEY_LEN], rss_key_be[CA_ETH_RSS_KEY_LEN];
	uint32_t hash_val[CA_MAX_ETH_QUEUE];
	struct rte_eth_dev_info ethdev_info;
	uint16_t i, masked_hash;
	uint32_t chan, chan_be;
	uint64_t mask;
	int ret;

	if (reta_tbl == NULL) {
		CA_ERR("RETA table is NULL.");
		return -EINVAL;
	}

	if (!rte_is_power_of_2(nb_queue)) {
		CA_ERR("Total queues is not a power of 2.");
		return -EINVAL;
	}

	/* Mask is uin64_t to support up to 64 queues */
	if (nb_queue > 64) {
		CA_ERR("Number of queues exceeds the maximum supported queues.");
		return -EINVAL;
	}

	memset(&ethdev_info, 0, sizeof(ethdev_info));
	ret = rte_eth_dev_info_get(port_id, &ethdev_info);
	if (ret) {
		CA_ERR("Could not get ethdev info for port: %u", port_id);
		return ret;
	}

	mask = 0;

	for (i = 0; i < nb_queue; i++)
		reta_tbl[i] = 0;

	eth_rss_key_get(rss_key);

	/* Convert RSS key*/
	rte_convert_rss_key((uint32_t *)rss_key, (uint32_t *)rss_key_be, RTE_DIM(rss_key));

	/* Assumption: 8 queues per port */
	chan = port_id * CA_MAX_ETH_QUEUE;

	if (strcmp(ethdev_info.driver_name, ETH_DEV_PMD_NAME_CN9K) == 0) {
		/* Update starting channel number */
		chan += 0x708;

		/* Generate hash values for each channel */
		for (i = 0; i < CA_MAX_ETH_QUEUE; i++) {
			hash_val[i] = rte_softrss_be(&chan, 1, rss_key_be);
			hash_val[i] = swap_words(hash_val[i]);
			chan++;
		}
	} else {
		if (strcmp(ethdev_info.driver_name, ETH_DEV_PMD_NAME_CN10K) == 0) {
			/* Update starting channel number */
			chan += 0x88;
		} else {
			CA_ERR("Unsupported driver name: %s", ethdev_info.driver_name);
			return -EINVAL;
		}

		/* Generate hash values for each channel */
		for (i = 0; i < CA_MAX_ETH_QUEUE; i++) {
			chan_be = htobe32(chan);
			hash_val[i] = rte_softrss_be(&chan_be, 1, rss_key_be);
			hash_val[i] = rotate_bytes(hash_val[i]);
			chan++;
		}
	}

	for (i = 0; i < RTE_DIM(hash_val); i++) {
		/* Get the last bits to be used for indexing */
		masked_hash = hash_val[i] % nb_queue;

		/* Check for hash collision */
		if (mask & (1 << masked_hash)) {
			CA_ERR("Hash collision detected. Port [%d] Index: [%d] hash: [%x])",
			       port_id, i, masked_hash);
			return -EINVAL;
		}

		/* Set the bit for the hash value */
		mask |= 1 << masked_hash;

		/* Store the queue index for the hash value */
		reta_tbl[masked_hash] = i;
	}

	return 0;
}

int
ca_eth_flow_create(uint8_t port_id)
{
	struct rte_flow_action actions[2];
	uint16_t queue[CA_ETH_RETA_SIZE];
	struct rte_flow_item pattern[2];
	struct rte_flow_action_rss rss;
	struct rte_flow_error error;
	struct rte_flow_attr attr;
	struct rte_flow *flow;
	int ret;

	memset(&actions, 0, sizeof(actions));
	memset(&pattern, 0, sizeof(pattern));
	memset(&rss, 0, sizeof(rss));
	memset(&error, 0, sizeof(error));
	memset(&attr, 0, sizeof(attr));

	attr.ingress = 1;

	pattern[0].type = RTE_FLOW_ITEM_TYPE_ANY;
	pattern[1].type = RTE_FLOW_ITEM_TYPE_END;

	rss.types = RTE_ETH_RSS_PORT;
	rss.queue_num = CA_ETH_RETA_SIZE;
	rss.queue = queue;

	actions[0].type = RTE_FLOW_ACTION_TYPE_RSS;
	actions[0].conf = &rss;

	actions[1].type = RTE_FLOW_ACTION_TYPE_END;

	/* Populate queue_ids */
	ret = eth_ingress_queue_mapping(port_id, queue, CA_ETH_RETA_SIZE);
	if (ret) {
		CA_ERR("Could not populate ingress queue mapping");
		return ret;
	}

	flow = rte_flow_create(port_id, &attr, pattern, actions, &error);
	if (flow == NULL) {
		CA_ERR("Could not create flow on port %u: %s", port_id, error.message);
		return -EINVAL;
	}

	return 0;
}

void
ca_eth_flow_clear(uint8_t port_id)
{
	int ret;

	ret = rte_flow_flush(port_id, NULL);
	if (ret)
		CA_ERR("Could not flush flow on port %u", port_id);
}
