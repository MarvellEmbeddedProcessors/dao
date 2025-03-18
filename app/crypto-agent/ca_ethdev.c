/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_thash.h>

#include "ca_admin.h"
#include "ca_ethdev.h"
#include "crypto_agent.h"

#define CA_ETH_RSS_KEY_LEN   48
#define CNXK_NIX_L2_OVERHEAD 26
#define CNXK_NIX_MIN_MTU     64

static struct ca_eth_dev_queue_lcore_map eth_map[CA_MAX_LCORE];
extern struct lcore_conf lcore_conf[CA_MAX_LCORE];

/* Forward declarations */

static void ca_eth_flow_clear(uint8_t port_id);
static int ca_eth_flow_create(uint8_t port_id);

int
ca_eth_lcore_map_init(void)
{
	uint8_t nb_link_per_lcore, nb_eth_dev, extra_links, nb_link, port_id, nb_lcore;
	uint16_t queue_id, nb_queue_list[RTE_MAX_ETHPORTS];
	uint8_t port_id_list[RTE_MAX_ETHPORTS];
	struct ca_eth_dev_ctx *eth_ctx;
	uint16_t nb_tot_queue, i, j;

	nb_eth_dev = 0;
	nb_tot_queue = 0;

	nb_lcore = rte_lcore_count();
	nb_lcore = RTE_MIN(nb_lcore, CA_MAX_LCORE);
	if (nb_lcore == 0) {
		CA_ERR("No lcore found.");
		return -ENODEV;
	}

	/* Exclude main lcore */
	nb_lcore -= 1;

	for (i = 0; i < RTE_MAX_ETHPORTS; i++) {
		eth_ctx = ca_eth_dev_ctx_get(i);
		if (eth_ctx == NULL)
			continue;

		/* Found valid dev */
		port_id_list[nb_eth_dev] = eth_ctx->port_id;
		nb_queue_list[nb_eth_dev] = eth_ctx->nb_queue_avail;
		nb_eth_dev++;
		nb_tot_queue += eth_ctx->nb_queue_avail;
	}

	if (nb_eth_dev == 0) {
		CA_ERR("No valid ethdev found.");
		return -ENODEV;
	}

	if (nb_tot_queue == 0) {
		CA_ERR("No valid ethdev queue found.");
		return -ENODEV;
	}

	nb_link_per_lcore = nb_tot_queue / nb_lcore;
	extra_links = nb_tot_queue % nb_lcore;

	memset(eth_map, 0, sizeof(eth_map));

	for (i = 0; i < CA_MAX_LCORE; i++) {
		if (rte_lcore_is_enabled(i) == 0)
			continue;
		if (rte_get_main_lcore() == i)
			continue;

		eth_map[i].nb_links = nb_link_per_lcore;

		/* Give one extra link each to first 'extra_links' lcore. */
		if (extra_links) {
			eth_map[i].nb_links++;
			extra_links--;
		}
	}

	port_id = 0;
	queue_id = 0;

	for (i = 0; i < CA_MAX_LCORE; i++) {
		if (eth_map[i].nb_links == 0)
			continue;

		nb_link = 0;

		while (nb_link < eth_map[i].nb_links) {
			eth_map[i].link[nb_link].port_id = port_id_list[port_id];
			eth_map[i].link[nb_link].queue_id = queue_id;

			nb_link++;
			queue_id++;

			if (queue_id == nb_queue_list[port_id]) {
				queue_id = 0;
				port_id++;
			}
		}
	}

	/* Print the eth queue map */
	for (i = 0; i < CA_MAX_LCORE; i++) {
		if (rte_get_main_lcore() == i) {
			CA_INFO("Lcore %u: Main lcore", i);
			continue;
		}

		if (rte_lcore_is_enabled(i) == 0) {
			CA_INFO("Lcore %u: Not enabled", i);
			continue;
		}

		CA_INFO("Lcore %u: %u links", i, eth_map[i].nb_links);

		for (j = 0; j < eth_map[i].nb_links; j++) {
			CA_INFO("\t\tPort %u, Queue %u", eth_map[i].link[j].port_id,
				eth_map[i].link[j].queue_id);
		}
	}

	return 0;
}

void
ca_eth_lcore_map_fini(void)
{
	memset(eth_map, 0, sizeof(eth_map));
}

static int
ca_eth_lcore_map_pq_save(uint8_t port_id, uint16_t queue_id, struct pending_queue *pq)
{
	uint16_t i, j;

	for (i = 0; i < CA_MAX_LCORE; i++) {
		for (j = 0; j < eth_map[i].nb_links; j++) {
			if (eth_map[i].link[j].port_id == port_id &&
			    eth_map[i].link[j].queue_id == queue_id) {
				eth_map[i].link[j].pq = pq;
				pq->eth_port_id = port_id;
				pq->eth_queue_id = queue_id;
				return 0;
			}
		}
	}

	return -ENODEV;
}

static void
ca_eth_lcore_map_pq_remove(uint8_t port_id, uint16_t queue_id)
{
	uint16_t i, j;

	for (i = 0; i < CA_MAX_LCORE; i++) {
		for (j = 0; j < eth_map[i].nb_links; j++) {
			if (eth_map[i].link[j].port_id == port_id &&
			    eth_map[i].link[j].queue_id == queue_id) {
				eth_map[i].link[j].pq = NULL;
			}
		}
	}
}

struct ca_eth_dev_queue_lcore_map *
ca_eth_lcore_map_get(uint8_t lcore_id)
{
	if (lcore_id >= CA_MAX_LCORE)
		return NULL;

	return &eth_map[lcore_id];
}

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
ca_eth_dev_init(uint32_t port_id, uint32_t nb_queue)
{
	struct rte_ether_addr ports_eth_addr;
	struct rte_eth_rss_conf *rss_conf;
	struct ca_eth_dev_ctx *eth_ctx;
	struct rte_eth_conf port_conf;
	int ret;

	CA_INFO("Initializing ethdev: %d", port_id);

	eth_ctx = ca_eth_dev_ctx_get(port_id);
	if (eth_ctx == NULL) {
		CA_ERR("Could not get ethdev context: %d.", port_id);
		return -ENODEV;
	}

	rss_conf = &port_conf.rx_adv_conf.rss_conf;

	rss_conf->rss_key = NULL;
	rss_conf->rss_key_len = 0;

	if (eth_ctx->nb_queue_avail < nb_queue) {
		CA_ERR("Requested queues %d > available queues %d", nb_queue,
		       eth_ctx->nb_queue_avail);
		return -EINVAL;
	}

	memset(&port_conf, 0, sizeof(port_conf));

	/*
	 * Set a low MTU value during port config. Track the buffer sizes requested and update the
	 * value. After device is started, set to the expected value.
	 */
	port_conf.rxmode.mtu = CNXK_NIX_MIN_MTU;
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
		goto dev_close;
	}

	rte_eth_macaddr_get(port_id, &ports_eth_addr);
	CA_INFO("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 " %02" PRIx8
		" %02" PRIx8,
		port_id, ports_eth_addr.addr_bytes[0], ports_eth_addr.addr_bytes[1],
		ports_eth_addr.addr_bytes[2], ports_eth_addr.addr_bytes[3],
		ports_eth_addr.addr_bytes[4], ports_eth_addr.addr_bytes[5]);

	eth_ctx->mtu = port_conf.rxmode.mtu;
	eth_ctx->nb_queue = nb_queue;
	eth_ctx->is_configured = true;

	return 0;

dev_close:
	rte_eth_dev_close(port_id);

	return -ENODEV;
}

int
ca_eth_dev_fini(uint16_t port_id)
{
	struct ca_eth_dev_ctx *eth_ctx;
	int rc;

	CA_INFO("Closing ethdev: %d", port_id);

	eth_ctx = ca_eth_dev_ctx_get(port_id);
	if (eth_ctx == NULL) {
		CA_ERR("Could not get ethdev context: %d.", port_id);
		return -ENODEV;
	}

	if (!eth_ctx->is_configured)
		return -EINVAL;

	if (eth_ctx->is_started) {
		rc = ca_eth_dev_stop(port_id);
		if (rc) {
			CA_ERR("Could not stop ethdev: %d.", port_id);
			return rc;
		}
	}

	return rte_eth_dev_close(port_id);
}

static int
ca_eth_dev_q_name_get(uint32_t dev_id, uint32_t qp_id, char *name, size_t len)
{
	return snprintf(name, len, "ca_ethdev_%u_q_%u", dev_id, qp_id);
}

static int
cpt_pq_init(struct ca_eth_dev_ctx *eth_ctx, uint16_t qp_id, uint32_t nb_desc)
{
	const struct rte_memzone *pq_mem;
	char name[RTE_MEMZONE_NAMESIZE];
	struct pending_queue *pq;
	uint16_t port_id;
	void *req_queue;
	int len;

	port_id = eth_ctx->port_id;
	pq = &eth_ctx->cpt_pq[qp_id];

	nb_desc = rte_align32pow2(nb_desc);

	len = nb_desc * sizeof(struct cpt_inflight_req);

	ca_eth_dev_q_name_get(port_id, qp_id, name, sizeof(name));

	pq_mem = rte_memzone_reserve_aligned(name, len, SOCKET_ID_ANY, 0, RTE_CACHE_LINE_SIZE);
	if (pq_mem == NULL) {
		CA_ERR("Could not reserve memzone for pending queue: %d, %d", port_id, qp_id);
		return -ENOMEM;
	}

	req_queue = pq_mem->addr;

	memset(req_queue, 0, len);

	memset(pq, 0, sizeof(struct pending_queue));
	pq->req_queue = req_queue;
	pq->pq_mask = (len / sizeof(struct cpt_inflight_req)) - 1;

	return 0;
}

static int
cpt_pq_destroy(struct ca_eth_dev_ctx *eth_ctx, uint16_t qp_id)
{
	char name[RTE_MEMZONE_NAMESIZE];
	uint16_t port_id;

	port_id = eth_ctx->port_id;

	ca_eth_dev_q_name_get(port_id, qp_id, name, sizeof(name));

	rte_memzone_free(rte_memzone_lookup(name));

	memset(&eth_ctx->cpt_pq[qp_id], 0, sizeof(struct pending_queue));

	return 0;
}

int
ca_eth_dev_q_configure(struct dao_lc_eth_qconf *conf)
{
	char name[RTE_MEMZONE_NAMESIZE];
	struct ca_eth_dev_ctx *eth_ctx;
	struct rte_eth_rxconf rx_conf;
	struct rte_eth_txconf tx_conf;
	struct rte_mempool *mp;
	uint32_t buf_len;
	int ret;

	CA_INFO("Configuring QP: dev_id %u, qp_id %u", conf->dev_id, conf->qp_id);

	eth_ctx = ca_eth_dev_ctx_get(conf->dev_id);
	if (eth_ctx == NULL) {
		CA_ERR("Could not get ethdev context: %d.", conf->dev_id);
		return -ENODEV;
	}

	if (!eth_ctx->is_configured) {
		CA_ERR("Ethdev not configured: %d.", conf->dev_id);
		return -EINVAL;
	}

	if (eth_ctx->is_started) {
		CA_ERR("Ethdev already started: %d.", conf->dev_id);
		return -EINVAL;
	}

	if (conf->qp_id >= eth_ctx->nb_queue) {
		CA_ERR("Invalid queue id: %d, %d.", conf->dev_id, conf->qp_id);
		return -EINVAL;
	}

	if (eth_ctx->init_q_mask & (1 << conf->qp_id)) {
		CA_ERR("Queue already initialized: %d, %d.", conf->dev_id, conf->qp_id);
		return -EINVAL;
	}

	ret = rte_eth_dev_adjust_nb_rx_tx_desc(conf->dev_id, (uint16_t *)&conf->nb_desc,
					       (uint16_t *)&conf->nb_desc);
	if (ret) {
		CA_ERR("Could not adjust nb rx/tx desc: %d.", conf->dev_id);
		return ret;
	}

	ret = ca_eth_dev_q_name_get(conf->dev_id, conf->qp_id, name, sizeof(name));
	if (ret < 0) {
		CA_ERR("Could not get mempool name for ethdev: %u, q: %u", conf->dev_id,
		       conf->qp_id);
		return ret;
	}

	buf_len = conf->max_seg_size + RTE_PKTMBUF_HEADROOM + CNXK_NIX_L2_OVERHEAD;

	mp = rte_pktmbuf_pool_create(name, conf->nb_desc, 256, 0, buf_len, SOCKET_ID_ANY);
	if (mp == NULL) {
		CA_ERR("Could not create mempool for ethdev: %u, q: %u", conf->dev_id, conf->qp_id);
		return -ENOMEM;
	}

	memset(&rx_conf, 0, sizeof(rx_conf));
	memset(&tx_conf, 0, sizeof(tx_conf));

	rx_conf.offloads = 0;
	tx_conf.offloads = RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

	ret = rte_eth_rx_queue_setup(conf->dev_id, conf->qp_id, conf->nb_desc, 0, &rx_conf, mp);
	if (ret) {
		CA_ERR("Could not setup Rx queue: %d.", conf->dev_id);
		goto mp_free;
	}

	ret = rte_eth_tx_queue_setup(conf->dev_id, conf->qp_id, conf->nb_desc, 0, &tx_conf);
	if (ret) {
		CA_ERR("Could not setup Tx queue: %d.", conf->dev_id);
		goto mp_free;
	}

	ret = cpt_pq_init(eth_ctx, conf->qp_id, conf->nb_desc);
	if (ret) {
		CA_ERR("Could not initialize CPT PQ: %d, %d.", conf->dev_id, conf->qp_id);
		goto mp_free;
	}

	ret = ca_eth_lcore_map_pq_save(conf->dev_id, conf->qp_id, &eth_ctx->cpt_pq[conf->qp_id]);
	if (ret) {
		CA_ERR("Could not save PQ: %d, %d.", conf->dev_id, conf->qp_id);
		goto mp_free;
	}

	eth_ctx->mtu = RTE_MAX(eth_ctx->mtu, conf->max_seg_size);

	eth_ctx->init_q_mask |= (1 << conf->qp_id);

	return 0;

mp_free:
	rte_mempool_free(mp);
	return ret;
}

int
ca_eth_dev_q_destroy(uint32_t dev_id, uint32_t qp_id)
{
	char name[RTE_MEMZONE_NAMESIZE];
	struct ca_eth_dev_ctx *eth_ctx;
	int ret;

	CA_INFO("Destroying QP: dev_id %u, qp_id %u", dev_id, qp_id);

	eth_ctx = ca_eth_dev_ctx_get(dev_id);
	if (eth_ctx == NULL) {
		CA_ERR("Could not get ethdev context: %d.", dev_id);
		return -ENODEV;
	}

	if (eth_ctx->is_started) {
		CA_ERR("Ethdev already started: %d.", dev_id);
		return -EINVAL;
	}

	if (!(eth_ctx->init_q_mask & (1 << qp_id))) {
		CA_ERR("Queue not initialized: %d, %d.", dev_id, qp_id);
		return -EINVAL;
	}

	ret = ca_eth_dev_q_name_get(dev_id, qp_id, name, sizeof(name));
	if (ret < 0) {
		CA_ERR("Could not get mempool name for ethdev: %u, q: %u", dev_id, qp_id);
		return ret;
	}

	eth_ctx->init_q_mask &= ~(1 << qp_id);

	ca_eth_lcore_map_pq_remove(dev_id, qp_id);

	cpt_pq_destroy(eth_ctx, qp_id);

	rte_mempool_free(rte_mempool_lookup(name));

	return 0;
}

int
ca_eth_dev_start(uint32_t port_id)
{
	struct ca_eth_dev_queue_lcore_map *eth_map;
	struct ca_eth_dev_ctx *eth_ctx;
	struct lcore_conf *lconf;
	struct rte_eth_link link;
	unsigned int lcore_id, i;
	int ret;

	CA_INFO("Starting device %u", port_id);

	eth_ctx = ca_eth_dev_ctx_get(port_id);
	if (eth_ctx == NULL) {
		CA_ERR("Could not get ethdev context: %d.", port_id);
		return -ENODEV;
	}

	if (!eth_ctx->is_configured) {
		CA_ERR("Ethdev not configured: %d.", port_id);
		return -EINVAL;
	}

	if (eth_ctx->is_started) {
		CA_ERR("Ethdev already started: %d.", port_id);
		return -EINVAL;
	}

	if (eth_ctx->nb_queue != rte_popcount64(eth_ctx->init_q_mask)) {
		CA_ERR("Not all queues initialized: %d.", port_id);
		return -EINVAL;
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

	ret = ca_eth_flow_create(port_id);
	if (ret) {
		CA_ERR("Could not initialize flow rules for ethdev: %d", port_id);
		goto eth_dev_close;
	}

	/*
	 * Update the MTU to allow larger sized packets. CNXK driver internally enables scatter
	 * offload feature based on MTU and buffer pool of first queue. Since queues can be
	 * configured indepedently and the host ensures that bigger sized packets are not send,
	 * update the HW MTU to allow larger sized packets. Doing this after device start to skip
	 * the additional checks in the driver.
	 */
	ret = rte_eth_dev_set_mtu(port_id, eth_ctx->mtu);
	if (ret) {
		CA_ERR("Could not set MTU: %d", port_id);
		goto eth_dev_close;
	}

	eth_ctx->is_started = true;

	/* Prepare lcore conf */
	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		if (rte_lcore_is_enabled(lcore_id) == 0)
			continue;
		if (rte_get_main_lcore() == lcore_id)
			continue;

		eth_map = ca_eth_lcore_map_get(lcore_id);
		if (eth_map == NULL) {
			CA_ERR("Could not get eth map for lcore: %d", lcore_id);
			return -ENODEV;
		}
		lconf = &lcore_conf[lcore_id];

		lconf->nb_pq = eth_map->nb_links;
		for (i = 0; i < lconf->nb_pq; i++) {
			lconf->pq[i] = eth_map->link[i].pq;
			if (lconf->pq[i] == NULL) {
				CA_ERR("Could not get pending queue for lcore: %d, link: %d",
				       lcore_id, i);
				return -ENODEV;
			}
		}
	}

	return 0;

eth_dev_close:
	rte_eth_dev_stop(port_id);
	rte_eth_dev_close(port_id);

	return -ENODEV;
}

int
ca_eth_dev_stop(uint32_t dev_id)
{
	struct ca_eth_dev_ctx *eth_ctx;
	int ret;

	CA_INFO("Stopping device %u", dev_id);

	eth_ctx = ca_eth_dev_ctx_get(dev_id);
	if (eth_ctx == NULL) {
		CA_ERR("Could not get ethdev context: %d.", dev_id);
		return -ENODEV;
	}

	if (!eth_ctx->is_started) {
		CA_ERR("Ethdev not started: %d.", dev_id);
		return -EINVAL;
	}

	ca_eth_flow_clear(dev_id);

	rte_eth_dev_stop(dev_id);

	/* Restore min value */
	ret = rte_eth_dev_set_mtu(dev_id, CNXK_NIX_MIN_MTU);
	if (ret)
		CA_ERR("Could not set MTU: %d", dev_id);

	eth_ctx->is_started = false;

	return 0;
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

static int
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

static void
ca_eth_flow_clear(uint8_t port_id)
{
	int ret;

	ret = rte_flow_flush(port_id, NULL);
	if (ret)
		CA_ERR("Could not flush flow on port %u", port_id);
}
