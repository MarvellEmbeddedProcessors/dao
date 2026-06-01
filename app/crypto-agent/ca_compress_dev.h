/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2026 Marvell.
 */

#ifndef __CA_COMPRESS_DEV_H__
#define __CA_COMPRESS_DEV_H__

#include "crypto_agent.h"

/* Maximum number of compress (inflight) operations */
#define CA_MAX_COMP_OPERATIONS           2048
#define CA_COMP_DEV_MAX_NUM_INFLIGHT_OPS CA_MAX_COMP_OPERATIONS
#define CA_COMP_DEV_MBUF_SIZE            16384
#define CA_COMP_DEV_MBUF_ELEMENTS        4095
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

/* Maximum VFs supported compress device */
#define CA_COMP_DEV_MAX_VFS             8
#define CA_COMP_DEV_CONSUMER_CORE_START 1
/* Effective consumer core end is (CONSUMER_CORE_START + nb_compdevs - 1); 1 VF = core 1, 2 VFs =
 * cores 1-2, etc. */
#define CA_COMP_DEV_CONSUMER_CORE_END 8
#define CA_COMP_DEV_REQ_RING_SIZE     4096

/* Consumer cores = nb_compdevs (cores 1..nb_compdevs); each can have up to 24 rings for single VF
 */
#define MAX_RINGS          CA_MAX_LCORE
#define MAX_RINGS_PER_CORE 24

/**
 * Maps per-lcore compdev req ring indices to each compress consumer core (1..nb_compdevs).
 */
struct comp_dev_ring_map {
	uint8_t nb_rings;
	uint8_t ring_id[MAX_RINGS_PER_CORE];
};

uint16_t ca_enq_comp_req_ring_to_compdev(struct pending_queue *pq, uint8_t ring_count,
					 uint8_t *rings, struct dev_desc_cnt *desc_cnt);
uint16_t ca_comp_dev_enq_noop(struct pending_queue *pq, uint8_t ring_count, uint8_t *rings,
			      struct dev_desc_cnt *desc_cnt);
typedef uint16_t (*compdev_enq_fn)(struct pending_queue *pq, uint8_t ring_count, uint8_t *rings,
				   struct dev_desc_cnt *desc_cnt);
uint8_t prepare_comp_op(struct dao_eth_trs_pkt *req, struct comp_dev_inflight_req *infl_req,
			struct rte_comp_op *comp_op, struct rte_mbuf *rx_pkts);
int host_dev_compressdev_pool_init(uint8_t dev_id, uint32_t comp_op);
struct rte_mempool *ca_host_comp_dst_bufpool_get(void);
struct rte_mempool *ca_host_comp_op_mempool_get(void);
void host_dev_compress_pools_fini(uint8_t dev_id);
uint16_t ca_compdev_deq(struct pending_queue *pq);
int compress_devs_init(uint32_t nb_desc);
int decompression_priv_xform_init(void);
int compression_priv_xforms_init(void);
int decompress_priv_xform_fini(void);
void compress_priv_xforms_fini(void);
int compress_devs_validate(void);
void compress_devs_fini(void);
void compress_devs_rings_fini(void);
int compress_devs_rings_init(void);

uint16_t ca_deq_comp_resp_ring_send_to_host(struct pending_queue *pq);
uint16_t get_rings_for_core(uint16_t core_id, uint8_t *rings);
void build_comp_dev_ring_map(struct comp_dev_ring_map *map, uint8_t comp_dev_count);
#endif /* __CA_COMPRESS_DEV_H__ */
