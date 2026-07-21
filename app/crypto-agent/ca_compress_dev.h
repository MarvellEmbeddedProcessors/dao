/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2026 Marvell.
 */

#ifndef __CA_COMPRESS_DEV_H__
#define __CA_COMPRESS_DEV_H__

#include "crypto_agent.h"

/* Maximum VFs supported compress device */
#define CA_COMP_DEV_MAX_VFS 8

/* Minimum segment size (same as LIQUID_CRYPTO_BUF_SZ_MIN) */
#define CA_MIN_SEG_SIZE 64

/* Maximum number of compress (inflight) operations */
#define CA_MAX_COMP_OPERATIONS           8192
#define CA_COMP_DEV_MAX_NUM_INFLIGHT_OPS CA_MAX_COMP_OPERATIONS
#define CA_COMP_DEV_MBUF_SIZE            16384
/*
 * No.of xforms per compress device VF.
 * Compression levels : 2 (MIN & MAX)
 * Huffman types : 2 (Dynamic and Fixed)
 * For compression: 4 xforms and for decompression 1 xform
 */
#define CA_COMP_DEV_MAX_NUM_XFORMS 5
/* Compress PMD does not support stateful processing, keeping it as 0 */
#define CA_COMP_DEV_MAX_NUM_STREAMS 0
#define CA_COMP_DEV_MAX_NUM_SEG     4
#define CA_COMP_DEV_DRIVER_NAME     "compress_octeontx"

#define CA_COMP_DEV_CONSUMER_CORE_START 1
#define CA_COMP_DEV_CONSUMER_CORE_END   8
#define CA_COMP_DEV_REQ_RING_SIZE       CA_MAX_COMP_OPERATIONS

/* Max port-queue rings assigned to one consumer core */
#define MAX_RINGS_PER_CORE CA_MAX_ETH_QUEUE

#define CA_COMP_DEV_INVALID_NB_DESC UINT16_MAX

/**
 * Maps per port/queue compdev pending queues to dedicated consumer cores
 * 1..nb_compdevs using (queue * CA_MAX_ETH_DEV + port) % nb_compdevs.
 */
struct comp_dev_ring_map {
	uint8_t nb_pqs;
	struct pending_queue *pq[MAX_RINGS_PER_CORE];
};

/**
 * Checks whether the core is consumer core or not?
 *
 * Workers: Core which receives packets from eth port-queue pair, enqs to request rings.
 * And deqs finished compress requests from response rings and sends back to host.
 *
 * Consumer core: Core which deqs compress requests from workers request rings and submits to
 * compress devices. And enqs compress device response to resp rings.
 */
static inline bool
ca_is_compdev_consumer_core(uint8_t lcore_id)
{
	if (ca_glb_ctx.nb_compdevs == 0)
		return false;

	return lcore_id >= CA_COMP_DEV_CONSUMER_CORE_START &&
	       lcore_id < CA_COMP_DEV_CONSUMER_CORE_START + ca_glb_ctx.nb_compdevs;
}

/**
 * Returns the compress device consumer core for the given port-queue pair.
 *
 * Max 8 eth devices (ports) and for each device 8 queues, so total queues = 64.
 * Port-0 compress requests will be consumed by compress device-0
 * Port-1 compress requests will be consumed by compress device-1
 * Port-7 compress requests will be consumed by compress device-7
 *
 * Below table gives possible queue indices for different ports.
 * ==================================
 * Eth port index	-	Queue indices
 * ==================================
 *	0		-	0-7
 *	1		-	8-15
 *	2		-	16-23
 *	6		-	48-55
 *	7		-	56-63
 * ==================================
 *
 * First it gets the consumer compress device using below formula:
 * Consumer compress dev index = ((Queue_Index * 8) + Port_Index) % 8
 *
 * Consumer core = Consumer compress device + 1 (worker core starts from core-1)
 *
 * For ex: Eth Port:6 Queue index: 6
 * Consumer compress device = 6 [((6*8) + 1) % 8]
 * Packets from Eth Port-6:Q6 consumed by core-7 to compress device 6.
 *
 * Eth Port:4 Queue index: 0
 * Consumer compress device = 4 [4 % 8]
 * Packets from Eth Port-4:Q0 consumed by core-5 to compress device 4.
 */
static inline uint8_t
ca_compdev_consumer_core_from_port_queue(uint16_t port_id, uint16_t queue_id)
{
	uint8_t nb_compdevs = ca_glb_ctx.nb_compdevs;
	uint8_t comp_dev_idx;

	if (nb_compdevs == 0)
		return 0;

	comp_dev_idx = (queue_id * MAX_RINGS_PER_CORE + port_id) % nb_compdevs;

	return (comp_dev_idx + CA_COMP_DEV_CONSUMER_CORE_START);
}

uint16_t ca_enq_comp_req_ring_to_compdev(uint8_t pq_count, uint8_t lcore_id,
					 struct dev_desc_cnt *desc_cnt);
uint16_t ca_enq_comp_req_noop(uint8_t pq_count, uint8_t lcore_id, struct dev_desc_cnt *desc_cnt);
uint16_t ca_comp_dev_enq_noop(uint8_t pq_count, struct pending_queue **pqs,
			      struct dev_desc_cnt *desc_cnt);
typedef uint16_t (*compdev_enq_fn)(uint8_t pq_count, uint8_t lcore_id,
				   struct dev_desc_cnt *desc_cnt);
uint8_t prepare_comp_op(struct dao_eth_trs_pkt *req, struct comp_dev_inflight_req *infl_req,
			struct rte_comp_op *comp_op, struct rte_mbuf *rx_pkts);
int host_dev_comp_op_pool_init(uint8_t dev_id, uint32_t comp_op);
void host_dev_comp_op_pool_fini(uint8_t dev_id);
int host_dev_comp_dst_mbuf_pool_init(uint32_t max_seg_size, uint32_t nb_elements);
void host_dev_comp_dst_mbuf_pool_fini(uint8_t dev_id);
struct rte_mempool *ca_host_comp_dst_bufpool_get(void);
struct rte_mempool *ca_host_comp_op_mempool_get(void);
uint32_t ca_host_comp_dst_mbuf_size_get(void);
void host_dev_compress_pools_fini(uint8_t dev_id);
uint16_t ca_compdev_deq(struct pending_queue *pq);
int compress_devs_init(uint32_t nb_desc);
int decompression_priv_xform_init(void);
int compression_priv_xforms_init(void);
int decompress_priv_xform_fini(void);
void compress_priv_xforms_fini(void);
int compress_devs_validate(void);
void compress_devs_fini(void);

uint16_t ca_deq_comp_resp_ring_send_to_host(struct pending_queue *pq);
uint8_t get_compdev_pqs_for_core(uint16_t core_id, struct pending_queue **pqs);
void comp_dev_ring_map_fini(void);
void comp_dev_ring_map_init(void);
int comp_dev_ring_map_add(struct pending_queue *pq);
void comp_dev_ring_map_remove(struct pending_queue *pq);
void comp_dev_ring_map_remove_quiesce(struct pending_queue *pq);
void ca_refresh_comp_dev_pqs(void);
int ca_compdev_clear_inflight_reqs(void);

#endif /* __CA_COMPRESS_DEV_H__ */
