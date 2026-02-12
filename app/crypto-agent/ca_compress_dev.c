/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2026 Marvell.
 */

#include "ca_compress_dev.h"

#define CA_COMPRESS_DEFAULT_WINDOW_SZ 1

static const size_t comp_dev_resp_hdr_sz = sizeof(struct __dao_lc_resp_compdev_op);
static const size_t dao_lc_hdr_sz = sizeof(struct __dao_lc_hdr);

static uint8_t ca_compression_level[COMP_DEV_COMPRESSION_LEVELS] = {RTE_COMP_LEVEL_MIN,
								    RTE_COMP_LEVEL_MAX};

static enum rte_comp_huffman huffs[COMP_DEV_HUFFMAN_TYPES] = {RTE_COMP_HUFFMAN_FIXED,
							      RTE_COMP_HUFFMAN_DYNAMIC};

struct rte_mempool *
ca_host_comp_op_mempool_get(uint8_t dev_id)
{
	if (dev_id >= ca_glb_ctx.nb_host_dev) {
		CA_ERR("Invalid host dev id: %u", dev_id);
		return NULL;
	}

	return ca_glb_ctx.host_ctx[dev_id].comp_op_mempool;
}

struct rte_mempool *
ca_host_comp_dst_bufpool_get(uint8_t dev_id)
{
	if (dev_id >= ca_glb_ctx.nb_host_dev) {
		CA_ERR("Invalid host dev id: %u", dev_id);
		return NULL;
	}

	return ca_glb_ctx.host_ctx[dev_id].comp_dst_mbuf_pool;
}

int
compress_devs_validate(void)
{
	uint8_t enabled_cdevs[RTE_COMPRESS_MAX_DEVS];
	struct rte_compressdev_info comp_dev_info;
	uint16_t orig_max_qp, nb_valid_devs = 0;
	uint8_t enabled_comp_devs, qp;
	int i;

	enabled_comp_devs = rte_compressdev_devices_get(CA_COMP_DEV_DRIVER_NAME, enabled_cdevs,
							RTE_COMPRESS_MAX_DEVS);

	if (!enabled_comp_devs) {
		CA_ERR("No valid compress devices found");
		return -ENODEV;
	}

	CA_INFO("No. of compress devices enabled : %d", enabled_comp_devs);

	/* Update compress_device ids in ca_global_ctx */
	for (i = 0; i < enabled_comp_devs; i++) {
		ca_glb_ctx.compdev_ids[i] = enabled_cdevs[i];
		CA_INFO("Compress devices id : %d ", enabled_cdevs[i]);
		nb_valid_devs++;
	}

	if (nb_valid_devs > CA_COMP_DEV_MAX_VFS) {
		nb_valid_devs = CA_COMP_DEV_MAX_VFS;
		CA_INFO("Only %d compress devices are supported.", nb_valid_devs);
	}

	ca_glb_ctx.nb_compdevs = nb_valid_devs;
	qp = 0;
	for (i = 0; i < nb_valid_devs; i++) {
		memset(&comp_dev_info, 0, sizeof(comp_dev_info));
		rte_compressdev_info_get(ca_glb_ctx.compdev_ids[i], &comp_dev_info);
		CA_INFO("Compress device: %d ==> max queue pairs: %d", ca_glb_ctx.compdev_ids[i],
			comp_dev_info.max_nb_queue_pairs);

		if (comp_dev_info.max_nb_queue_pairs > rte_lcore_count()) {
			orig_max_qp = comp_dev_info.max_nb_queue_pairs;
			comp_dev_info.max_nb_queue_pairs = rte_lcore_count();
			CA_INFO("Compress dev %u supports %u queue pairs, limiting to %u to match %u lcores",
				ca_glb_ctx.compdev_ids[i], orig_max_qp, rte_lcore_count(),
				rte_lcore_count());
		}
		if (qp == 0) {
			qp = comp_dev_info.max_nb_queue_pairs;
			CA_INFO("Init QP[Core: %d] for device: %d with QP: %d", rte_lcore_id(),
				ca_glb_ctx.compdev_ids[i], qp);
		} else {
			qp = RTE_MIN(qp, comp_dev_info.max_nb_queue_pairs);
			CA_INFO("QP update[Core: %d] for device: %d with QP: %d", rte_lcore_id(),
				ca_glb_ctx.compdev_ids[i], qp);
		}
	}

	ca_glb_ctx.nb_compdev_qp = qp;
	CA_INFO("Using compress dev max queue pairs: %d", qp);

	return 0;
}

int
get_compdev_id(unsigned int core_id)
{
	/* core 0 is main core */
	if (core_id == 0)
		return -1;

	return (core_id - 1) & 7;
}

/* nb_desc will be taken from dao_card_config.crypto_nb_desc */
int
compress_devs_init(uint32_t nb_desc)
{
	uint8_t main_lcore = rte_get_main_lcore();
	struct rte_compressdev_config conf;
	uint16_t comp_dev_id, qp_id;
	int ret, j, i;

	CA_INFO("Configuring %d compress devices with %d QPs", ca_glb_ctx.nb_compdevs,
		ca_glb_ctx.nb_compdev_qp);

	/* Update nb_desc to next power of 2 to aid in pending queue checks */
	nb_desc = rte_align32pow2(nb_desc);

	if (nb_desc < CA_CPT_MIN_QUEUE_DEPTH) {
		nb_desc = CA_CPT_MIN_QUEUE_DEPTH;
		CA_INFO("Using minimum queue depth: %d", nb_desc);
	}

	for (i = 0; i < ca_glb_ctx.nb_compdevs; i++) {
		comp_dev_id = ca_glb_ctx.compdev_ids[i];
		memset(&conf, 0, sizeof(conf));
		conf.socket_id = SOCKET_ID_ANY;
		conf.nb_queue_pairs = ca_glb_ctx.nb_compdev_qp;
		conf.max_nb_priv_xforms = CA_COMP_DEV_MAX_NUM_XFORMS;
		conf.max_nb_streams = CA_COMP_DEV_MAX_NUM_STREAMS;
		CA_INFO("Configuring Compress dev: %d with QP: %d Xforms: %d Streams: %d",
			comp_dev_id, ca_glb_ctx.nb_compdev_qp, conf.max_nb_priv_xforms,
			conf.max_nb_streams);

		ret = rte_compressdev_configure(comp_dev_id, &conf);
		if (ret) {
			CA_ERR("Could not configure compressdev: %d.", comp_dev_id);
			return ret;
		}

		/* qp setup */
		for (j = 0; j < conf.nb_queue_pairs; j++) {
			ret = rte_compressdev_queue_pair_setup(comp_dev_id, j, nb_desc,
							       SOCKET_ID_ANY);
			if (ret) {
				CA_ERR("Could not setup queue [comp_dev_id: %d, qp: %d].",
				       comp_dev_id, j);
				return ret;
			}
			CA_INFO("Comp_dev_id: %d, qp: %d setup done", comp_dev_id, j);
		}

		ret = rte_compressdev_start(comp_dev_id);
		if (ret < 0) {
			CA_ERR("Could not start compress_dev: %d.", comp_dev_id);
			return ret;
		}

		CA_INFO("Compress Device[%d] started successfully", i);
	}

	/* As compress device supports single queue pair, using qp_id as 0 here. */
	qp_id = 0;
	for (i = 0; i < CA_MAX_LCORE; i++) {
		if (rte_lcore_is_enabled(i) == 0 || i == main_lcore)
			continue;
		/**
		 * Maximum 8 VFs are supported.
		 * Cores 1-8 will serve the compress devices 0 to 7.
		 * Cores 9-16 will use compress devices 0 to 7.
		 * Cores 17-23 will use compress devices 0 to 6.
		 * Core 0 is main core, so subtracting 1 to use from core 1 onwards.
		 */
		comp_dev_id = get_compdev_id(i);
		ca_glb_ctx.compdev_ctx[i].dev_id = ca_glb_ctx.compdev_ids[comp_dev_id];
		ca_glb_ctx.compdev_ctx[i].qp_id = qp_id;
		ca_glb_ctx.compdev_ctx[i].nb_allowed = nb_desc;
	}

	return 0;
}

void
compress_devs_fini(void)
{
	uint8_t comp_dev_id;
	int ret, i;

	for (i = 0; i < ca_glb_ctx.nb_compdevs; i++) {
		comp_dev_id = ca_glb_ctx.compdev_ids[i];

		rte_compressdev_stop(comp_dev_id);

		ret = rte_compressdev_close(comp_dev_id);
		if (ret)
			CA_ERR("Could not close compress dev: %d.", comp_dev_id);
	}
}

void
compress_priv_xforms_fini(void)
{
	int i, l, h, ret;
	uint8_t dev_id;
	void *xform;

	for (i = 0; i < ca_glb_ctx.nb_compdevs; i++) {
		dev_id = ca_glb_ctx.compdev_ids[i];
		for (l = 0; l < COMP_DEV_COMPRESSION_LEVELS; l++) {
			for (h = 0; h < COMP_DEV_HUFFMAN_TYPES; h++) {
				xform = ca_glb_ctx.compdev_ctx[dev_id].comp_priv_xform[l][h];
				if (xform) {
					ret = rte_compressdev_private_xform_free(dev_id, xform);
					if (ret < 0) {
						CA_ERR("Failed to free xform: level:%d Huffman: %d",
						       l, h);
						continue;
					}
				}
			}
		}
	}
}

int
compression_priv_xforms_init(void)
{
	struct rte_comp_xform xform;
	int i, l, h, ret;
	uint8_t dev_id;

	for (i = 0; i < ca_glb_ctx.nb_compdevs; i++) {
		dev_id = ca_glb_ctx.compdev_ids[i];
		for (l = 0; l < COMP_DEV_COMPRESSION_LEVELS; l++) {
			for (h = 0; h < COMP_DEV_HUFFMAN_TYPES; h++) {
				memset(&xform, 0, sizeof(xform));
				xform.type = RTE_COMP_COMPRESS;
				xform.compress.algo = RTE_COMP_ALGO_DEFLATE;
				xform.compress.level = ca_compression_level[l];
				xform.compress.window_size = CA_COMPRESS_DEFAULT_WINDOW_SZ;
				xform.compress.deflate.huffman = huffs[h];
				xform.compress.chksum = RTE_COMP_CHECKSUM_NONE;
				xform.compress.hash_algo = RTE_COMP_HASH_ALGO_NONE;
				ret = rte_compressdev_private_xform_create(
					dev_id, &xform,
					&ca_glb_ctx.compdev_ctx[dev_id].comp_priv_xform[l][h]);
				if (ret < 0) {
					CA_ERR("Compress xform creation failed for dev: %u",
					       dev_id);
					compress_priv_xforms_fini();
					return ret;
				}
			}
		}
	}
	return 0;
}

int
decompression_priv_xform_init(void)
{
	struct rte_comp_xform xform;
	uint8_t dev_id;
	int ret, i;

	for (i = 0; i < ca_glb_ctx.nb_compdevs; i++) {
		dev_id = ca_glb_ctx.compdev_ids[i];
		memset(&xform, 0, sizeof(xform));
		xform.type = RTE_COMP_DECOMPRESS;
		xform.decompress.algo = RTE_COMP_ALGO_DEFLATE;
		xform.decompress.window_size = CA_COMPRESS_DEFAULT_WINDOW_SZ;
		xform.decompress.chksum = RTE_COMP_CHECKSUM_NONE;
		xform.decompress.hash_algo = RTE_COMP_HASH_ALGO_NONE;
		ret = rte_compressdev_private_xform_create(
			dev_id, &xform, &ca_glb_ctx.compdev_ctx[dev_id].decomp_priv_xform);
		if (ret < 0) {
			CA_ERR("Decompress priv xform creation failed for dev: %u", dev_id);
			return ret;
		}
	}
	return 0;
}

int
decompress_priv_xform_fini(void)
{
	uint8_t dev_id;
	int ret = 0, i;

	for (i = 0; i < ca_glb_ctx.nb_compdevs; i++) {
		dev_id = ca_glb_ctx.compdev_ids[i];

		ret = rte_compressdev_private_xform_free(
			dev_id, ca_glb_ctx.compdev_ctx[dev_id].decomp_priv_xform);
		if (ret < 0)
			CA_ERR("Failed to free decompress xform for dev: %u", dev_id);
	}
	return ret;
}

void
host_dev_compress_pools_fini(uint8_t dev_id)
{
	rte_mempool_free(ca_glb_ctx.host_ctx[dev_id].comp_op_mempool);
	ca_glb_ctx.host_ctx[dev_id].comp_op_mempool = NULL;
	rte_mempool_free(ca_glb_ctx.host_ctx[dev_id].comp_dst_mbuf_pool);
	ca_glb_ctx.host_ctx[dev_id].comp_dst_mbuf_pool = NULL;
}

int
host_dev_compressdev_pool_init(uint8_t dev_id, uint32_t comp_op)
{
	char comp_dst_mbuf_pool_name[RTE_MEMZONE_NAMESIZE] = "\0";
	uint32_t decomp_mbuf_size = CA_COMP_DEV_MBUF_SIZE;
	uint32_t comp_mbuf_size = CA_COMP_DEV_MBUF_SIZE;
	uint32_t n_elements = CA_COMP_DEV_MBUF_ELEMENTS;
	char op_pool_name[RTE_MEMZONE_NAMESIZE] = "\0";
	struct rte_mempool *mp;

	CA_INFO("Initializing Pools for Compress Dev: %d", dev_id);
	CA_INFO("Compress Operations: %u, Mempool Element Size: %u, Comp Buf Size: %u, Decomp Buf Size: %u",
		comp_op, n_elements, comp_mbuf_size, decomp_mbuf_size);

	/* Create compression operation pool */
	snprintf(op_pool_name, sizeof(op_pool_name), "compdev_op_pool%u", dev_id);
	mp = rte_comp_op_pool_create(op_pool_name, comp_op, 0, 0, rte_socket_id());
	if (mp == NULL) {
		CA_ERR("Could not create comp op mempool for host dev: %u", dev_id);
		return -ENOMEM;
	}
	ca_glb_ctx.host_ctx[dev_id].comp_op_mempool = mp;

	/* Create destination mbuf pool for compression/decompression output */
	snprintf(comp_dst_mbuf_pool_name, sizeof(comp_dst_mbuf_pool_name), "compdev_dst_pool%u",
		 dev_id);
	mp = rte_pktmbuf_pool_create(comp_dst_mbuf_pool_name, n_elements, 0, /* cache size */
				     0, /* size of application private */
				     decomp_mbuf_size, rte_socket_id());
	if (mp == NULL) {
		CA_ERR("Could not create compdev decomp mbuf pool for host dev: %u", dev_id);
		goto cleanup;
	}
	ca_glb_ctx.host_ctx[dev_id].comp_dst_mbuf_pool = mp;
	return 0;

cleanup:
	rte_mempool_free(ca_glb_ctx.host_ctx[dev_id].comp_op_mempool);
	ca_glb_ctx.host_ctx[dev_id].comp_op_mempool = NULL;
	return -ENOMEM;
}

/**
 * When compress device is disabled, compdev_pkt_handler_t is initialized
 * with this noop function.
 */
uint16_t
ca_compdev_deq_noop(struct pending_queue *pq)
{
	RTE_SET_USED(pq);
	return 0;
}

uint16_t
ca_compdev_deq(struct pending_queue *pq)
{
	struct rte_comp_op *deq_ops[CA_ETHDEV_TX_BURST];
	struct rte_mbuf *dst_mbufs[CA_ETHDEV_TX_BURST];
	struct comp_dev_inflight_req *infl_req;
	struct __dao_lc_resp_compdev_op *resp;
	uint16_t nb_pending, nb_tx, nb_deq, i;
	const uint64_t mask = pq->pq_mask;
	uint8_t lcore_id, comp_dev_id;
	struct dao_eth_trs_pkt *trs;
	uint64_t head, tail;
	uint16_t free_idx;

	if (unlikely(pq == NULL)) {
		CA_ERR("Compress device pending queue is NULL!!");
		return 0;
	}

	head = pq->head;
	tail = pq->tail;

	lcore_id = rte_lcore_id();
	comp_dev_id = get_compdev_id(lcore_id);

	nb_pending = pending_queue_infl_cnt(head, tail, mask);
	if (nb_pending == 0)
		return 0;

	nb_pending = RTE_MIN(nb_pending, CA_ETHDEV_TX_BURST);

	nb_deq = rte_compressdev_dequeue_burst(ca_glb_ctx.compdev_ctx[comp_dev_id].dev_id,
					       ca_glb_ctx.compdev_ctx[comp_dev_id].qp_id, deq_ops,
					       nb_pending);
	if (nb_deq < nb_pending) {
		CA_WARN("All compress operations are not completed. Remaining: %d",
			nb_pending - nb_deq);
	}

	for (i = 0; i < nb_deq; i++) {
		infl_req = &pq->compdev_req_queue[tail & mask];
		trs = rte_pktmbuf_mtod(infl_req->mbuf, struct dao_eth_trs_pkt *);

		switch (trs->hdr.op_type) {
		case DAO_ETH_TRS_OP_TYPE_COMPRESS:
		case DAO_ETH_TRS_OP_TYPE_DECOMPRESS: {
			dst_mbufs[i] = infl_req->mbuf;
			resp = rte_pktmbuf_mtod(infl_req->mbuf, struct __dao_lc_resp_compdev_op *);
			resp->res.status = deq_ops[i]->status;

			if (deq_ops[i]->status != DAO_LC_COMP_OP_STATUS_SUCCESS) {
				CA_ERR("Compress operation status is failed: %u", resp->res.status);
				break;
			}

			resp->op_len = deq_ops[i]->produced;
			resp->res.consumed = deq_ops[i]->consumed;
			resp->res.produced = deq_ops[i]->produced;

			if (infl_req->op_buf_len < deq_ops[i]->produced) {
				resp->res.status = DAO_LC_COMP_OP_STATUS_RESP_BUF_SPACE_ISSUE;
				resp->res.required = deq_ops[i]->produced;
#ifdef CA_DEBUG_ENABLE
				CA_INFO(">>>>> destination buffer is not sufficient required: %u bytes provided: %u <<<<",
					resp->res.required, infl_req->op_buf_len);
#endif
			}
#ifdef CA_DEBUG_ENABLE
			if (deq_ops[i]->m_dst->nb_segs > 1) {
				CA_INFO("<===== Destination Segments: %u ====>",
					deq_ops[i]->m_dst->nb_segs);
				CA_INFO("<===== Destination Consumed: %u ====>",
					deq_ops[i]->consumed);
				CA_INFO("<===== Destination Produced: %u ====>",
					deq_ops[i]->produced);
				rte_pktmbuf_dump(stdout, deq_ops[i]->m_dst,
						 deq_ops[i]->m_dst->pkt_len);
			}
			if (deq_ops[i]->m_src->nb_segs > 1) {
				CA_INFO("<=============== Source mbuf exceeding MAX size =============>");
				rte_pktmbuf_dump(stdout, deq_ops[i]->m_src,
						 deq_ops[i]->m_src->pkt_len);
			}
#endif
			break;
		}
		default:
			CA_ERR("Invalid operation type: %d", trs->hdr.op_type);
			dst_mbufs[i] = infl_req->mbuf;
			break;
		}
		rte_pktmbuf_free(deq_ops[i]->m_src);
		rte_comp_op_free(deq_ops[i]);
		pending_queue_advance(&tail, mask);
	}

	if (unlikely(i == 0))
		return 0;

	nb_tx = rte_eth_tx_burst(pq->eth_port_id, pq->eth_queue_id, dst_mbufs, i);

	if (unlikely(nb_tx < i)) {
#ifdef CA_DEBUG_ENABLE
		CA_ERR("Could not transmit all packets");
#endif
		for (free_idx = nb_tx; free_idx < i; free_idx++)
			rte_pktmbuf_free(dst_mbufs[free_idx]);
	}
	pq->tail = tail;

	return nb_tx;
}

static inline int
ca_compression_level_to_index(uint8_t level)
{
	if (level == RTE_COMP_LEVEL_MIN)
		return 0;
	if (level == RTE_COMP_LEVEL_MAX)
		return 1;

	return -1;
}

/**
 * Allocates a new mbuf for to write compress device output (m_dst).
 * The same mbuf will be used to send the response back to host.
 * Updates LC header in beginning of mbuf and also updates total the
 * segments length in the destination mbuf. Initializes inflight request
 * to point to newly created mbuf and will be used in ca_compdev_deq to
 * send the response using the same mbuf.
 */
static inline struct rte_mbuf *
prepare_compress_resp_mbuf(struct rte_mbuf *rx_pkts, struct comp_dev_inflight_req *infl_req,
			   uint32_t src_len, uint32_t op_buf_len, void *priv_xform)
{
	uint16_t total_len = 0, op_buf_size;
	struct rte_mempool *dst_pool;
	struct rte_mbuf *prev_mb;
	struct rte_mbuf *resp_mb;
	struct rte_mbuf *mbuf;
	uint16_t nb_segs = 1;
	uint32_t remaining;
	uint32_t to_append;

	dst_pool = ca_host_comp_dst_bufpool_get(CA_LC_COMPRESS_DEV_ID);
	if (dst_pool == NULL)
		return NULL;

	op_buf_size = CA_COMP_DEV_MBUF_SIZE - comp_dev_resp_hdr_sz;

	if (op_buf_len <= op_buf_size) {
		/* Single segment: fits in one mbuf */
		resp_mb = rte_pktmbuf_alloc(dst_pool);
		if (unlikely(resp_mb == NULL)) {
			CA_ERR("Response buffer alloc failure");
			return NULL;
		}

		rte_memcpy(rte_pktmbuf_mtod(resp_mb, void *), rte_pktmbuf_mtod(rx_pkts, void *),
			   dao_lc_hdr_sz);
	} else {
		/* Multi-segment: create and add segments to initial mbuf */
		remaining = op_buf_len;
		if (remaining > (uint32_t)(op_buf_size +
					   (CA_COMP_DEV_MAX_NUM_SEG - 1) * CA_COMP_DEV_MBUF_SIZE)) {
			CA_ERR("op_buf_len %u exceeds max %u segments (max %u bytes)", op_buf_len,
			       CA_COMP_DEV_MAX_NUM_SEG,
			       (op_buf_size +
				(CA_COMP_DEV_MAX_NUM_SEG - 1) * CA_COMP_DEV_MBUF_SIZE));
			return NULL;
		}

		resp_mb = rte_pktmbuf_alloc(dst_pool);
		if (unlikely(resp_mb == NULL)) {
			CA_ERR("Response buffer alloc failure");
			return NULL;
		}

		rte_memcpy(rte_pktmbuf_mtod(resp_mb, void *), rte_pktmbuf_mtod(rx_pkts, void *),
			   dao_lc_hdr_sz);

		remaining = remaining - op_buf_size;
		prev_mb = resp_mb;

		while (remaining > 0 && nb_segs < CA_COMP_DEV_MAX_NUM_SEG) {
			mbuf = rte_pktmbuf_alloc(dst_pool);
			if (unlikely(mbuf == NULL)) {
				CA_ERR("<========= Multi segment response buffer alloc failure =====>");
				goto cleanup_chain;
			}

			to_append = RTE_MIN(remaining, (uint32_t)CA_COMP_DEV_MBUF_SIZE);

			prev_mb->next = mbuf;
			prev_mb = mbuf;
			remaining -= to_append;
			nb_segs++;
		}

		if (remaining > 0) {
			CA_ERR("op_buf_len %u exceeds max segments %u", op_buf_len,
			       CA_COMP_DEV_MAX_NUM_SEG);
			goto cleanup_chain;
		}
	}
	mbuf = resp_mb;
	while (mbuf) {
		mbuf->data_len = mbuf->buf_len - mbuf->data_off;
		total_len += mbuf->data_len;
		mbuf = mbuf->next;
	}
	resp_mb->pkt_len = total_len;
	resp_mb->nb_segs = nb_segs;

	infl_req->op_buf_len = op_buf_len;
	infl_req->src_len = src_len;
	infl_req->priv_xform = priv_xform;
	infl_req->mbuf = resp_mb;

	return resp_mb;

cleanup_chain:
	mbuf = resp_mb->next;
	while (mbuf) {
		prev_mb = mbuf->next;
		rte_pktmbuf_free(mbuf);
		mbuf = prev_mb;
	}
	resp_mb->next = NULL;
	rte_pktmbuf_free(resp_mb);
	return NULL;
}

uint8_t
prepare_comp_op(struct dao_eth_trs_pkt *req, struct comp_dev_inflight_req *infl_req,
		struct rte_comp_op **op, struct rte_mbuf *rx_pkts)
{
	struct __dao_lc_req_decomp_op *decomp_req_mbuf = NULL;
	struct __dao_lc_req_comp_op *comp_req_mbuf = NULL;
	struct __dao_lc_req_decomp_op *decomp_req = NULL;
	struct __dao_lc_req_comp_op *comp_req = NULL;
	struct rte_mbuf *new_resp_mb = NULL;
	uint8_t comp_dev_id, lcore_id;
	struct rte_mempool *mem_pool;
	struct rte_comp_op *comp_op;
	void *priv_xform = NULL;
	uint8_t *ext_buf;
	uint16_t offset;
	int level;

	mem_pool = ca_host_comp_op_mempool_get(CA_LC_COMPRESS_DEV_ID);
	if (mem_pool == NULL) {
		CA_ERR("Could not get compress op mempool.");
		return 0;
	}

	comp_op = rte_comp_op_alloc(mem_pool);
	if (!comp_op) {
		CA_ERR("%s: Could not get comp ops.", __func__);
		return 0;
	}

	lcore_id = rte_lcore_id();
	comp_dev_id = get_compdev_id(lcore_id);

	switch (req->hdr.op_type) {
	case DAO_ETH_TRS_OP_TYPE_COMPRESS:
		comp_req = (struct __dao_lc_req_comp_op *)req;
		level = ca_compression_level_to_index(comp_req->level);
		if (unlikely(level < 0)) {
			CA_ERR("%s: Invalid compression level %d", __func__, comp_req->level);
			goto cleanup;
		}
		if (unlikely(comp_req->huff_enc_type != RTE_COMP_HUFFMAN_FIXED &&
			     comp_req->huff_enc_type != RTE_COMP_HUFFMAN_DYNAMIC)) {
			CA_ERR("%s: Invalid Huffman encoding type %d", __func__,
			       comp_req->huff_enc_type);
			goto cleanup;
		}
		priv_xform = ca_glb_ctx.compdev_ctx[comp_dev_id]
				     .comp_priv_xform[level][comp_req->huff_enc_type];

		/* Allocate & copy the LC header to new mbuf for sending the response */
		new_resp_mb = prepare_compress_resp_mbuf(rx_pkts, infl_req, comp_req->src_len,
							 comp_req->op_buf_len, priv_xform);
		if (unlikely(new_resp_mb == NULL))
			goto cleanup;

		comp_req_mbuf = rte_pktmbuf_mtod(rx_pkts, struct __dao_lc_req_comp_op *);
		ext_buf = comp_req_mbuf->input;
		/* Offset for compress input data in rx_pkts */
		offset = (uint8_t *)ext_buf - rte_pktmbuf_mtod(rx_pkts, uint8_t *);

		/* Flush flag is applicable only in compress direction */
		comp_op->flush_flag = RTE_COMP_FLUSH_FINAL;
		comp_op->input_chksum = RTE_COMP_CHECKSUM_NONE;
		comp_op->src.length = comp_req->src_len;
		comp_op->private_xform = priv_xform;
		comp_op->src.offset = offset;
		comp_op->m_src = rx_pkts;

		/* Use response mbuf as comp dev destination to avoid copy in deq */
		comp_op->m_dst = new_resp_mb;
		comp_op->dst.offset = comp_dev_resp_hdr_sz;
		*op = comp_op;
		return 1;

	case DAO_ETH_TRS_OP_TYPE_DECOMPRESS:
		decomp_req = (struct __dao_lc_req_decomp_op *)req;
		priv_xform = ca_glb_ctx.compdev_ctx[comp_dev_id].decomp_priv_xform;

		/* Allocate & copy the LC header to new mbuf for sending the response */
		new_resp_mb = prepare_compress_resp_mbuf(rx_pkts, infl_req, decomp_req->src_len,
							 decomp_req->op_buf_len, priv_xform);
		if (unlikely(new_resp_mb == NULL))
			goto cleanup;

		decomp_req_mbuf = rte_pktmbuf_mtod(rx_pkts, struct __dao_lc_req_decomp_op *);
		ext_buf = decomp_req_mbuf->input;
		/* Offset for decompress input data */
		offset = (uint8_t *)ext_buf - rte_pktmbuf_mtod(rx_pkts, uint8_t *);

		comp_op->src.offset = offset;
		comp_op->m_src = rx_pkts;
		comp_op->input_chksum = RTE_COMP_CHECKSUM_NONE;
		comp_op->private_xform = priv_xform;
		comp_op->src.length = decomp_req->src_len;
		comp_op->m_dst = new_resp_mb;
		comp_op->dst.offset = comp_dev_resp_hdr_sz;
		*op = comp_op;
		return 1;
	default:
		CA_INFO("Invalid DAO ETH opcode %d", req->hdr.op_type);
		goto cleanup;
	}

cleanup:
	rte_comp_op_free(comp_op);
	rte_pktmbuf_free(rx_pkts);
	return 0;
}
