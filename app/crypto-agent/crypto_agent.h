/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef __CRYPTO_AGENT_H__
#define __CRYPTO_AGENT_H__

#include <rte_compressdev.h>
#include <rte_cryptodev.h>
#include <rte_log.h>
#include <rte_mempool.h>
#include <rte_pmd_cnxk_crypto.h>
#include <rte_rcu_qsbr.h>
#include <rte_security.h>

#include "ca_crypto_queue.h"

/* Default command timeout in seconds */
#define DEFAULT_COMMAND_TIMEOUT 4

#define ETH_DEV_MIN_BUF_LEN 44ul
#define ETH_DEV_MAX_BUF_LEN 65531ul

#define CA_MAX_ETH_DEV        8
#define CA_MAX_ETH_QUEUE      8
#define CA_ETH_RETA_SIZE      64
#define CA_MAX_QUEUE_PER_CORE 64
#define CA_MAX_LCORE          24
#define CA_MAX_PAYLOAD_SIZE   5120
#define CA_MAX_HOST_DEV       1
#define CA_MAX_SYM_SESSIONS   8192
#define CA_ETHDEV_TX_BURST    64
#define CA_ETHDEV_RX_BURST    32
#define CA_CPT_MAX_TIMEOUT_MS 3000

#define CA_LC_DEV_ID          0
#define CA_LC_COMPRESS_DEV_ID 0

DAO_STATIC_ASSERT(CA_MAX_ETH_DEV <= RTE_MAX_ETHPORTS);
DAO_STATIC_ASSERT(CA_MAX_ETH_QUEUE <= RTE_MAX_QUEUES_PER_PORT);
DAO_STATIC_ASSERT(CA_MAX_LCORE <= RTE_MAX_LCORE);

/* Log type */
#define RTE_LOGTYPE_AGENT        RTE_LOGTYPE_USER1
#define CA_INFO(fmt, args...)    RTE_LOG(INFO, AGENT, fmt "\n", ##args)
#define CA_INFO_NH(fmt, args...) rte_log(RTE_LOG_INFO, RTE_LOGTYPE_AGENT, fmt "\n", ##args)
#define CA_WARN(fmt, args...)    RTE_LOG(WARNING, AGENT, fmt "\n", ##args)
#define CA_ERR(fmt, args...)     RTE_LOG(ERR, AGENT, fmt "\n", ##args)
#define CA_DEBUG(fmt, args...)   RTE_LOG(DEBUG, AGENT, fmt "\n", ##args)

#define COMP_DEV_HUFFMAN_TYPES      3
#define COMP_DEV_COMPRESSION_LEVELS 2 /* MIN and MAX only */

extern struct ca_global_ctx ca_glb_ctx;

struct ca_eth_dev_ctx {
	bool is_configured;
	bool is_started;
	uint16_t mtu;
	uint16_t port_id;
	uint16_t nb_queue;
	uint16_t nb_queue_avail;
	uint64_t init_q_mask;
	struct pending_queue cpt_pq[CA_MAX_ETH_QUEUE];
	struct pending_queue compdev_pq[CA_MAX_ETH_QUEUE];
};

struct ca_hostdev_ctx {
	uint16_t nb_sym_sess;
	struct rte_mempool *sess_mempool;
	/* Compress device operation memory pool */
	struct rte_mempool *comp_op_mempool;
	/* Pool for destination mbufs for compress operations */
	struct rte_mempool *comp_dst_mbuf_pool;
	/* Function pointer to compress device packet handler */
	int (*compress_dev_pkt_hdlr)(struct dao_eth_trs_pkt *pkt, struct rte_mbuf *mb,
				     struct comp_dev_inflight_req *infl_req,
				     struct rte_comp_op *comp_op);
};

DAO_STATIC_ASSERT(CA_MAX_ETH_QUEUE <= 64);

struct ca_cryptodev_ctx {
	struct rte_pmd_cnxk_crypto_qptr *cpt_qptr;
	uint32_t nb_allowed;
	uint32_t cpt_qp_id;
};

struct ca_compdev_ctx {
	uint8_t dev_id;
	uint8_t qp_id;
	uint32_t nb_allowed;
	/**
	 * Private xforms for compress operations.
	 * For compress operation, min & max level = 1 & 9
	 * Huffman encoding 2-types.
	 * For each level & huffman type one xform will be created.
	 */

	void *comp_priv_xform[COMP_DEV_COMPRESSION_LEVELS][COMP_DEV_HUFFMAN_TYPES];
	/**
	 * For decompress operation only one private xform is enough for deflate
	 * algorithm.
	 */
	void *decomp_priv_xform;
	/** Per-lcore compress request / response rings (indexed by lcore id). */
	struct rte_ring *comp_req_ring[CA_MAX_LCORE];
	struct rte_ring *comp_resp_ring[CA_MAX_LCORE];
};

struct ca_global_ctx {
	uint8_t cryptodev_ids[RTE_CRYPTO_MAX_DEVS];
	uint8_t nb_valid_ethdevs;
	struct ca_eth_dev_ctx eth_ctx[RTE_MAX_ETHPORTS];
	uint16_t nb_cpt_qp;
	struct ca_cryptodev_ctx cryptodev_ctx[CA_MAX_LCORE];
	struct rte_rcu_qsbr *qsbr;
	struct rte_pmd_cnxk_crypto_qptr *cpt_qptr[CA_MAX_LCORE];
	uint16_t nb_host_dev;
	struct ca_hostdev_ctx host_ctx[CA_MAX_HOST_DEV];
	uint16_t nb_ae_ec_max_entries;
	uint64_t *ca_ae_fpm_iova;
	struct rte_pmd_cnxk_crypto_ae_ec_group_params **ca_ec_grp;

	uint8_t compdev_ids[RTE_COMPRESS_MAX_DEVS];
	uint8_t nb_compdevs;
	uint16_t nb_compdev_qp;
	struct ca_compdev_ctx compdev_ctx[CA_MAX_LCORE];
};

struct lcore_conf {
	uint16_t nb_pq;
	bool is_soft_reset;
	/* For CPT */
	struct pending_queue *pq[CA_MAX_QUEUE_PER_CORE];
	struct pending_queue *compdev_pq[CA_MAX_QUEUE_PER_CORE];
	uint64_t rx_packets;
	uint64_t tx_packets;
	uint64_t comp_enq;
	uint64_t comp_deq;
	uint64_t comp_req_ring_enq;
	uint64_t comp_resp_ring_deq;
} __rte_cache_aligned;

/* Maintains available descriptors count */
struct dev_desc_cnt {
	uint16_t cpt;
	uint16_t compdev;
	uint16_t comp_req_ring_enq_cnt;
	uint16_t compdev_deq_cnt;
};

struct ca_eth_dev_ctx *ca_eth_dev_ctx_get(uint16_t port_id);
struct rte_rcu_qsbr *ca_rcu_qsbr_get(void);
struct rte_mempool *ca_host_sess_mempool_get(uint8_t dev_id);

#endif /* __CRYPTO_AGENT_H__ */
