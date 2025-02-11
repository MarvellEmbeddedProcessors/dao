/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <rte_ethdev.h>
#include <rte_mempool.h>

#include "ca_admin.h"
#include "ca_ethdev.h"
#include "crypto_agent.h"

int
ca_eth_dev_init(uint8_t port_id, struct ca_dev_config *dev_config, struct rte_mempool *mp)
{
	uint16_t nb_queue, queue_id, nb_rxd, nb_txd, buf_sz;
	struct rte_ether_addr ports_eth_addr;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_conf port_conf;
	struct rte_eth_rxconf rx_conf;
	struct rte_eth_txconf tx_conf;
	struct rte_eth_link link;
	int ret;

	/* TODO - determine proper values */
	nb_rxd = 1024;
	nb_txd = 1024;

	buf_sz = dev_config->max_payload_size;

	CA_INFO("Initializing ethdev: %d", port_id);

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
	port_conf.rxmode.mq_mode = RTE_ETH_MQ_RX_NONE;
	port_conf.txmode.mq_mode = RTE_ETH_MQ_TX_NONE;
	port_conf.txmode.offloads = RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

	ret = rte_eth_dev_configure(port_id, nb_queue, nb_queue, &port_conf);
	if (ret) {
		CA_ERR("Could not configure ethdev: %d.", port_id);
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
