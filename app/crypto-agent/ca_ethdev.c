/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_thash.h>

#include "ca_admin.h"
#include "ca_compress_dev.h"
#include "ca_ethdev.h"
#include "crypto_agent.h"

#define CA_ETH_RSS_KEY_LEN   48
#define CNXK_NIX_L2_OVERHEAD 26
#define CNXK_NIX_MIN_MTU     64

#define CPT_DEV  "CPT"
#define COMP_DEV "COMP"
#define LC_CARD  "LC"

static struct ca_eth_dev_queue_lcore_map eth_map[CA_MAX_LCORE];
extern struct lcore_conf lcore_conf[CA_MAX_LCORE];
extern bool is_compdev_enabled;

/* Forward declarations */

static void ca_eth_flow_clear(uint8_t port_id);
static int ca_eth_flow_create(uint8_t port_id, uint16_t nb_queue);

struct pair {
	uint8_t port;
	uint16_t q;
};

int
ca_eth_lcore_map_init(void)
{
	uint8_t main_lcore = rte_get_main_lcore();
	uint16_t nb_queue_list[RTE_MAX_ETHPORTS];
	uint8_t port_id_list[RTE_MAX_ETHPORTS];
	uint8_t worker_ids[CA_MAX_LCORE];
	struct ca_eth_dev_ctx *eth_ctx;
	uint32_t idx, k, total_pairs = 0;
	uint8_t worker_count = 0;
	uint8_t nb_eth_dev = 0;
	uint8_t lc, d;
	uint16_t p, q, min_q, max_q;
	struct pair *pairs;
	uint32_t wid, li, l;

	for (lc = 0; lc < CA_MAX_LCORE; lc++) {
		if (!rte_lcore_is_enabled(lc))
			continue;
		if (lc == main_lcore)
			continue;
		worker_ids[worker_count++] = lc;
	}
	if (worker_count == 0) {
		CA_ERR("No worker lcores available.");
		return -ENODEV;
	}

	for (p = 0; p < RTE_MAX_ETHPORTS; p++) {
		eth_ctx = ca_eth_dev_ctx_get(p);
		if (!eth_ctx || eth_ctx->nb_queue_avail == 0)
			continue;
		port_id_list[nb_eth_dev] = eth_ctx->port_id;
		nb_queue_list[nb_eth_dev] = eth_ctx->nb_queue_avail;
		total_pairs += eth_ctx->nb_queue_avail;
		nb_eth_dev++;
	}
	if (nb_eth_dev == 0 || total_pairs == 0) {
		CA_ERR("No usable ethdev queues found.");
		return -ENODEV;
	}

	memset(eth_map, 0, sizeof(eth_map));

	min_q = UINT16_MAX;
	for (d = 0; d < nb_eth_dev; d++)
		if (nb_queue_list[d] < min_q)
			min_q = nb_queue_list[d];

	pairs = calloc(total_pairs, sizeof(*pairs));
	if (!pairs)
		return -ENOMEM;

	max_q = 0;
	for (d = 0; d < nb_eth_dev; d++)
		if (nb_queue_list[d] > max_q)
			max_q = nb_queue_list[d];

	idx = 0;
	for (q = 0; q < max_q; q++) {
		for (d = 0; d < nb_eth_dev; d++) {
			if (q >= nb_queue_list[d])
				continue;
			pairs[idx].port = port_id_list[d];
			pairs[idx].q = q;
			idx++;
		}
	}
	if (idx != total_pairs)
		total_pairs = idx;
	for (k = 0; k < total_pairs; k++) {
		wid = worker_ids[k % worker_count];
		li = eth_map[wid].nb_links;
		if (li >= CA_MAX_QUEUE_PER_CORE) {
			CA_ERR("Capacity exceeded on lcore %u", wid);
			free(pairs);
			return -E2BIG;
		}
		eth_map[wid].link[li].port_id = pairs[k].port;
		eth_map[wid].link[li].queue_id = pairs[k].q;
		eth_map[wid].nb_links++;
	}
	free(pairs);

	for (lc = 0; lc < CA_MAX_LCORE; lc++) {
		if (lc == main_lcore) {
			CA_INFO("Lcore %u: Main lcore", lc);
			continue;
		}
		if (!rte_lcore_is_enabled(lc)) {
			CA_INFO("Lcore %u: Not enabled", lc);
			continue;
		}

		CA_INFO("Lcore %u: %u links", lc, eth_map[lc].nb_links);
		for (l = 0; l < eth_map[lc].nb_links; l++) {
			CA_INFO("\t\tPort %u, Queue %u", eth_map[lc].link[l].port_id,
				eth_map[lc].link[l].queue_id);
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
ca_eth_lcore_map_pq_save(uint8_t port_id, uint16_t queue_id, struct pending_queue *cpt_pq,
			 struct pending_queue *compdev_pq)
{
	uint16_t i, j;

	for (i = 0; i < CA_MAX_LCORE; i++) {
		for (j = 0; j < eth_map[i].nb_links; j++) {
			if (eth_map[i].link[j].port_id == port_id &&
			    eth_map[i].link[j].queue_id == queue_id) {
				eth_map[i].link[j].pq = cpt_pq;
				eth_map[i].link[j].compdev_pq = compdev_pq;
				cpt_pq->eth_port_id = port_id;
				cpt_pq->eth_queue_id = queue_id;
				compdev_pq->eth_port_id = port_id;
				compdev_pq->eth_queue_id = queue_id;
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
				eth_map[i].link[j].compdev_pq = NULL;
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
ca_eth_dev_close(uint32_t port_id)
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

	eth_ctx->is_configured = false;
	eth_ctx->is_started = false;

	return rte_eth_dev_reset(port_id);
}

void
ca_eth_dev_stop_reset(void)
{
	struct ca_eth_dev_ctx *eth_ctx;
	uint16_t i, j;
	int ret;

	for (i = 0; i < ca_glb_ctx.nb_valid_ethdevs; i++) {
		eth_ctx = &ca_glb_ctx.eth_ctx[i];
		if (eth_ctx->is_configured) {
			ret = ca_eth_dev_close(eth_ctx->port_id);
			if (ret)
				CA_ERR("Could not close ethdev: %d.", eth_ctx->port_id);
		}
	}

	/** Clear Queues on each device */
	for (i = 0; i < ca_glb_ctx.nb_valid_ethdevs; i++) {
		eth_ctx = &ca_glb_ctx.eth_ctx[i];
		for (j = 0; j < eth_ctx->nb_queue_avail; j++) {
			if ((eth_ctx->init_q_mask & (1ULL << j)) == 0)
				continue;
			ret = ca_eth_dev_q_destroy(eth_ctx->port_id, j);
			if (ret < 0)
				CA_ERR("Failed to destroy queue %d on port %d: %d", j,
				       eth_ctx->port_id, ret);
		}
	}
}

static int
ca_eth_dev_q_name_get(uint32_t dev_id, uint32_t qp_id, char *name, size_t len, const char *dev)
{
	return snprintf(name, len, "ca_ethdev_%s_%u_q_%u", dev, dev_id, qp_id);
}

static int
pq_init(struct ca_eth_dev_ctx *eth_ctx, uint16_t qp_id, uint32_t nb_desc)
{
	const struct rte_memzone *cpt_pq_mem, *compdev_pq_mem;
	char name[RTE_MEMZONE_NAMESIZE];
	struct pending_queue *pq;
	uint16_t infl_req_size;
	uint16_t port_id;
	void *req_queue;
	int len, rc;

	port_id = eth_ctx->port_id;

	nb_desc = rte_align32pow2(nb_desc);

	/* CPT specific pending queue */
	pq = &eth_ctx->cpt_pq[qp_id];
	infl_req_size = sizeof(struct cpt_inflight_req);
	len = nb_desc * infl_req_size;
	ca_eth_dev_q_name_get(port_id, qp_id, name, sizeof(name), CPT_DEV);

	cpt_pq_mem = rte_memzone_reserve_aligned(name, len, SOCKET_ID_ANY, 0, RTE_CACHE_LINE_SIZE);
	if (cpt_pq_mem == NULL) {
		CA_ERR("Could not reserve memzone for pending queue: %d, %d", port_id, qp_id);
		return -ENOMEM;
	}

	req_queue = cpt_pq_mem->addr;
	memset(req_queue, 0, len);
	memset(pq, 0, sizeof(struct pending_queue));

	pq->cpt_req_queue = req_queue;
	pq->pq_mask = (len / infl_req_size) - 1;
	pq->eth_port_id = port_id;
	pq->eth_queue_id = qp_id;

	/**
	 * Compress device specific pending queue memory is allocated regardless of whether the
	 * device is enabled or not. This is to avoid check in process_pkts function.
	 */
	pq = &eth_ctx->compdev_pq[qp_id];
	infl_req_size = sizeof(struct comp_dev_inflight_req);
	len = nb_desc * infl_req_size;
	ca_eth_dev_q_name_get(port_id, qp_id, name, sizeof(name), COMP_DEV);

	compdev_pq_mem =
		rte_memzone_reserve_aligned(name, len, SOCKET_ID_ANY, 0, RTE_CACHE_LINE_SIZE);
	if (compdev_pq_mem == NULL) {
		CA_ERR("Could not reserve memzone for pending queue: %d, %d", port_id, qp_id);
		rc = -ENOMEM;
		goto cpt_pq_mem_free;
	}
	req_queue = compdev_pq_mem->addr;
	memset(req_queue, 0, len);

	memset(pq, 0, sizeof(struct pending_queue));
	pq->compdev_req_queue = req_queue;
	pq->pq_mask = (len / infl_req_size) - 1;
	pq->eth_port_id = port_id;
	pq->eth_queue_id = qp_id;

	return 0;

cpt_pq_mem_free:
	rte_memzone_free(cpt_pq_mem);
	memset(&eth_ctx->cpt_pq[qp_id], 0, sizeof(struct pending_queue));
	return rc;
}

static int
pq_destroy(struct ca_eth_dev_ctx *eth_ctx, uint16_t qp_id)
{
	char name[RTE_MEMZONE_NAMESIZE];
	uint16_t port_id;

	port_id = eth_ctx->port_id;

	ca_eth_dev_q_name_get(port_id, qp_id, name, sizeof(name), CPT_DEV);

	rte_memzone_free(rte_memzone_lookup(name));

	memset(&eth_ctx->cpt_pq[qp_id], 0, sizeof(struct pending_queue));

	ca_eth_dev_q_name_get(port_id, qp_id, name, sizeof(name), COMP_DEV);

	rte_memzone_free(rte_memzone_lookup(name));

	memset(&eth_ctx->compdev_pq[qp_id], 0, sizeof(struct pending_queue));

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

	ret = ca_eth_dev_q_name_get(conf->dev_id, conf->qp_id, name, sizeof(name), LC_CARD);
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

	ret = pq_init(eth_ctx, conf->qp_id, conf->nb_desc);
	if (ret) {
		CA_ERR("Could not initialize CPT/Compress device PQ: %d, %d.", conf->dev_id,
		       conf->qp_id);
		goto pq_free;
	}

	/* Set dequeue function pointer based on configuration */
	eth_ctx->cpt_pq[conf->qp_id].out_of_order_delivery_en = conf->out_of_order_delivery_en;
	if (conf->out_of_order_delivery_en)
		eth_ctx->cpt_pq[conf->qp_id].cpt_deq_fn = ca_cpt_deq_ooo;
	else
		eth_ctx->cpt_pq[conf->qp_id].cpt_deq_fn = ca_cpt_deq;

	ret = ca_eth_lcore_map_pq_save(conf->dev_id, conf->qp_id, &eth_ctx->cpt_pq[conf->qp_id],
				       &eth_ctx->compdev_pq[conf->qp_id]);
	if (ret) {
		CA_ERR("Could not save CPT/Compress Dev PQ: %d, %d.", conf->dev_id, conf->qp_id);
		goto pq_free;
	}

	eth_ctx->mtu = RTE_MAX(eth_ctx->mtu, conf->max_seg_size);

	eth_ctx->init_q_mask |= (1 << conf->qp_id);

	return 0;
pq_free:
	pq_destroy(eth_ctx, conf->qp_id);

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

	ret = ca_eth_dev_q_name_get(dev_id, qp_id, name, sizeof(name), LC_CARD);
	if (ret < 0) {
		CA_ERR("Could not get mempool name for ethdev: %u, q: %u", dev_id, qp_id);
		return ret;
	}

	eth_ctx->init_q_mask &= ~(1 << qp_id);

	ca_eth_lcore_map_pq_remove(dev_id, qp_id);

	pq_destroy(eth_ctx, qp_id);

	rte_mempool_free(rte_mempool_lookup(name));

	return 0;
}

int
ca_eth_dev_start(uint32_t port_id)
{
	struct ca_eth_dev_queue_lcore_map *eth_map;
	struct ca_eth_dev_ctx *eth_ctx;
	struct rte_rcu_qsbr *qsbr;
	struct lcore_conf *lconf;
	struct rte_eth_link link;
	unsigned int lcore_id, i;
	uint16_t nb_pq;
	int ret;

	CA_INFO("Starting device %u", port_id);

	qsbr = ca_rcu_qsbr_get();
	if (qsbr == NULL) {
		CA_ERR("Could not get RCU QSBR.");
		return -ENODEV;
	}

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

	ret = ca_eth_flow_create(port_id, eth_ctx->nb_queue);
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
	for (lcore_id = 0; lcore_id < CA_MAX_LCORE; lcore_id++) {
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

		/* Get the number of valid links already in use */
		nb_pq = lconf->nb_pq;

		/* Iterate the eth map and check the links using same port_id */
		for (i = 0; i < eth_map->nb_links; i++) {
			/* Consider only the current ethdev */
			if (eth_map->link[i].port_id != port_id)
				continue;

			/* Skip if pq is not registered */
			if (eth_map->link[i].pq == NULL)
				continue;

			/* Save pq to lconf */
			lconf->pq[nb_pq] = eth_map->link[i].pq;
			lconf->compdev_pq[nb_pq] = eth_map->link[i].compdev_pq;
			nb_pq++;
		}

		rte_smp_wmb();
		lconf->nb_pq = nb_pq;
	}

	/* Synchronize RCU QSBR */
	rte_rcu_qsbr_synchronize(qsbr, RTE_QSBR_THRID_INVALID);

	return 0;

eth_dev_close:
	rte_eth_dev_stop(port_id);
	rte_eth_dev_close(port_id);

	return -ENODEV;
}

int
ca_eth_dev_stop(uint32_t dev_id)
{
	struct ca_eth_dev_queue_lcore_map *eth_map;
	struct ca_eth_dev_ctx *eth_ctx;
	uint16_t nb_pq, nb_pq_prev;
	struct rte_rcu_qsbr *qsbr;
	struct lcore_conf *lconf;
	unsigned int lcore_id, i;
	int ret;

	CA_INFO("Stopping device %u", dev_id);

	qsbr = ca_rcu_qsbr_get();
	if (qsbr == NULL) {
		CA_ERR("Could not get RCU QSBR.");
		return -ENODEV;
	}

	eth_ctx = ca_eth_dev_ctx_get(dev_id);
	if (eth_ctx == NULL) {
		CA_ERR("Could not get ethdev context: %d.", dev_id);
		return -ENODEV;
	}

	if (!eth_ctx->is_started) {
		CA_ERR("Ethdev not started: %d.", dev_id);
		return -EINVAL;
	}

	/* Clear from lcore mapping */
	for (lcore_id = 0; lcore_id < CA_MAX_LCORE; lcore_id++) {
		eth_map = ca_eth_lcore_map_get(lcore_id);
		if (eth_map == NULL) {
			CA_ERR("Could not get eth map for lcore: %d", lcore_id);
			return -ENODEV;
		}

		/* Skip is there are no links for this core */
		if (eth_map->nb_links == 0)
			continue;

		lconf = &lcore_conf[lcore_id];

		nb_pq_prev = lconf->nb_pq;

		lconf->nb_pq = 0;

		/* Synchronize RCU QSBR */
		rte_rcu_qsbr_synchronize(qsbr, RTE_QSBR_THRID_INVALID);

		/* Iterate through the links and clear pq corresponding to this ethdev */
		for (i = 0, nb_pq = 0; i < nb_pq_prev; i++) {
			/* Clear pq for the current ethdev */
			if (lconf->pq[i]->eth_port_id == dev_id) {
				lconf->pq[i] = NULL;
				lconf->compdev_pq[i] = NULL;
				continue;
			}

			lconf->pq[nb_pq] = lconf->pq[i];
			lconf->compdev_pq[nb_pq] = lconf->compdev_pq[i];
			nb_pq++;
		}

		rte_smp_wmb();
		lconf->nb_pq = nb_pq;
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

	if (nb_queue > CA_MAX_ETH_QUEUE) {
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

	memset(reta_tbl, 0, sizeof(uint16_t) * CA_ETH_RETA_SIZE);

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

	for (i = 0; i < nb_queue; i++) {
		/* Get the last bits to be used for indexing */
		masked_hash = hash_val[i] % CA_ETH_RETA_SIZE;

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
ca_eth_flow_create(uint8_t port_id, uint16_t nb_queue)
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
	ret = eth_ingress_queue_mapping(port_id, queue, nb_queue);
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

int
ca_eth_lcore_map_link_clear(void)
{
	struct ca_eth_dev_queue_lcore_map *eth_map;
	struct rte_rcu_qsbr *qsbr;
	struct lcore_conf *lconf;
	uint32_t lcore_id;

	qsbr = ca_rcu_qsbr_get();
	if (qsbr == NULL) {
		CA_ERR("Could not get RCU QSBR.");
		return -ENODEV;
	}

	/* Clear nb_pq on all worker lcores before any QSBR synchronize.*/
	for (lcore_id = 0; lcore_id < CA_MAX_LCORE; lcore_id++) {
		if (rte_lcore_is_enabled(lcore_id) == 0)
			continue;
		if (rte_get_main_lcore() == lcore_id)
			continue;

		eth_map = ca_eth_lcore_map_get(lcore_id);
		if (eth_map == NULL) {
			CA_ERR("Could not get eth map for lcore: %d", lcore_id);
			return -ENODEV;
		}

		/* Skip if there are no links for this core */
		if (eth_map->nb_links == 0)
			continue;

		lconf = &lcore_conf[lcore_id];
		lconf->nb_pq = 0;
		lconf->is_soft_reset = true;

		/* Reset the packet counters */
		lconf->rx_packets = 0;
		lconf->tx_packets = 0;
	}

	/* One publish point for all lcores */
	rte_smp_wmb();

	/* Single QSBR synchronize after all nb_pq stores are visible.*/
	rte_rcu_qsbr_synchronize(qsbr, RTE_QSBR_THRID_INVALID);

	return 0;
}

int
ca_eth_rx_queue_clear_all(struct lcore_conf *lcore_conf_arr)
{
	struct rte_mbuf *mb[CA_ETHDEV_RX_BURST];
	struct pending_queue *pq;
	struct lcore_conf *lconf;
	uint32_t lcore_id, i;
	uint16_t nb_rx;

	for (lcore_id = 0; lcore_id < CA_MAX_LCORE; lcore_id++) {
		if (!rte_lcore_is_enabled(lcore_id))
			continue;
		if (rte_get_main_lcore() == lcore_id)
			continue;

		lconf = &lcore_conf_arr[lcore_id];

		for (i = 0; i < lconf->nb_pq; i++) {
			pq = lconf->pq[i];

			do {
				nb_rx = rte_eth_rx_burst(pq->eth_port_id, pq->eth_queue_id, mb,
							 CA_ETHDEV_RX_BURST);

				if (nb_rx)
					rte_pktmbuf_free_bulk(mb, nb_rx);
			} while (nb_rx != 0);
		}
	}

	CA_INFO("Successfully drained all RX queues");
	return 0;
}
