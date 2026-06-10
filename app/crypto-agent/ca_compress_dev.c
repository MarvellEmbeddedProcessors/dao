/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2026 Marvell.
 */

#include "ca_compress_dev.h"

#define CA_COMPRESS_DEFAULT_WINDOW_SZ 1

static const size_t comp_dev_resp_hdr_sz = sizeof(struct __dao_lc_resp_compdev_op);
static const size_t dao_lc_hdr_sz = sizeof(struct __dao_lc_hdr);

static uint8_t ca_compression_level[COMP_DEV_COMPRESSION_LEVELS] = {RTE_COMP_LEVEL_MIN,
								    RTE_COMP_LEVEL_MAX};

/**
 * Created shared xforms considering for huffman type fixed and dynamic only.
 */
static enum rte_comp_huffman huffs[COMP_DEV_HUFFMAN_TYPES] = {
	RTE_COMP_HUFFMAN_DEFAULT, RTE_COMP_HUFFMAN_FIXED, RTE_COMP_HUFFMAN_DYNAMIC};

/**
 * For 8-VFs case: Below are cores and ring index mapping used by each core
 * for different compress devices.
 * --------------------------------------------------------
 * Compress Device ID	Cores/ Ring Indexes	Worker Core
 * --------------------------------------------------------
 * 0			1, 9, 17		1
 * 1			2, 10, 18		2
 * 2			3, 11, 19		3
 * 3			4, 12, 20		4
 * 4			5, 13, 21		5
 * 5			6, 14, 22		6
 * 6			7, 15, 23		7
 * 7			8, 16			8
 * --------------------------------------------------------
 * Here ring index 1,9, 17 are served by compress device 0.
 * Core 1 enqueues compress requests from rings-1,9, 17 to compress device 0.
 * Similarly above table shows the mapping for remaining devices and rings-core
 * mapping.
 * Core: 0 is main core does not have access to any compress device.
 */
uint8_t comp_dev_core_map[CA_MAX_LCORE] = {9, /* Main core, should never access */
					   0, 1, 2, 3, 4, 5, 6, 7, /* Core 1 to 8 */
					   0, 1, 2, 3, 4, 5, 6, 7, /* Core 9 to 16 */
					   0, 1, 2, 3, 4, 5, 6};   /* Core 17 to 23*/

extern struct comp_dev_ring_map compdev_ring_map[CA_MAX_LCORE];

struct rte_mempool *
ca_host_comp_op_mempool_get(void)
{
	return ca_glb_ctx.host_ctx[CA_LC_COMPRESS_DEV_ID].comp_op_mempool;
}

struct rte_mempool *
ca_host_comp_dst_bufpool_get(void)
{
	return ca_glb_ctx.host_ctx[CA_LC_COMPRESS_DEV_ID].comp_dst_mbuf_pool;
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

		if (comp_dev_info.max_nb_queue_pairs > rte_lcore_count()) {
			orig_max_qp = comp_dev_info.max_nb_queue_pairs;
			comp_dev_info.max_nb_queue_pairs = rte_lcore_count();
			CA_INFO("Compress dev %u supports %u queue pairs, limiting to %u to match %u lcores",
				ca_glb_ctx.compdev_ids[i], orig_max_qp, rte_lcore_count(),
				rte_lcore_count());
		}
		if (qp == 0)
			qp = comp_dev_info.max_nb_queue_pairs;
		else
			qp = RTE_MIN(qp, comp_dev_info.max_nb_queue_pairs);
	}

	ca_glb_ctx.nb_compdev_qp = qp;
	CA_INFO("Using compress dev max queue pairs: %d", qp);

	return 0;
}

void
build_comp_dev_ring_map(struct comp_dev_ring_map *map, uint8_t comp_dev_count)
{
	uint8_t ring, core;
	unsigned int i;

	if (comp_dev_count == 0)
		return;

	/* Cores 1..nb_compdevs drain req rings; round-robin by comp_dev_count, max 24 per core.
	 * Rings 1..(CA_MAX_LCORE-1): 1 VF -> all 23 on core 1; 2 VFs -> 12 on core 1, 11 on core 2.
	 */
	for (i = 0; i < CA_MAX_LCORE; i++)
		map[i].nb_rings = 0;

	for (ring = CA_COMP_DEV_CONSUMER_CORE_START; ring <= CA_MAX_LCORE - 1; ring++) {
		core = ((ring - 1) % comp_dev_count) + CA_COMP_DEV_CONSUMER_CORE_START;
		if (map[core].nb_rings < MAX_RINGS_PER_CORE)
			map[core].ring_id[map[core].nb_rings++] = ring;
	}
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
		CA_INFO("Using minimum queue depth: %u for compress device", nb_desc);
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
		}

		ret = rte_compressdev_start(comp_dev_id);
		if (ret < 0) {
			CA_ERR("Could not start compress_dev: %d.", comp_dev_id);
			return ret;
		}

		CA_INFO("Compress Device[%d] started successfully", i);
	}

	/**
	 * As compress device supports single queue pair, using qp_id as 0 here.
	 * All cores 1..(CA_MAX_LCORE-1) get a compdev mapping using comp_dev_core_map
	 */
	qp_id = 0;
	for (i = 0; i < CA_MAX_LCORE; i++) {
		int dev_id;

		if (rte_lcore_is_enabled(i) == 0 || i == main_lcore)
			continue;
		if (i < CA_COMP_DEV_CONSUMER_CORE_START)
			continue;
		dev_id = comp_dev_core_map[i];
		/**
		 * Maximum 8 VFs are supported.
		 * Cores 1-8 will serve the compress devices 0 to 7.
		 * Cores 9-16 will use compress devices 0 to 7.
		 * Cores 17-23 will use compress devices 0 to 6.
		 * Core 0 is main core, so subtracting 1 to use from core 1 onwards.
		 */
		ca_glb_ctx.compdev_ctx[i].dev_id = ca_glb_ctx.compdev_ids[dev_id];
		ca_glb_ctx.compdev_ctx[i].qp_id = qp_id;
		ca_glb_ctx.compdev_ctx[i].nb_allowed = nb_desc;
	}

	return compress_devs_rings_init();
}

void
compress_devs_fini(void)
{
	uint8_t comp_dev_id;
	int ret, i;

	compress_devs_rings_fini();

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
				if (huffs[h] == RTE_COMP_HUFFMAN_DEFAULT)
					continue;
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
				if (huffs[h] == RTE_COMP_HUFFMAN_DEFAULT)
					continue;
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

	CA_INFO("Initializing Pools for Host Device : %d", dev_id);
	CA_INFO("Total compress devices: %u", ca_glb_ctx.nb_compdevs);
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

uint16_t
ca_deq_comp_resp_ring_send_to_host(struct pending_queue *pq)
{
	struct rte_mbuf *mbufs[CA_ETHDEV_RX_BURST];
	uint16_t nb_deq, nb_tx = 0, i;
	uint8_t lcore_id;

	lcore_id = rte_lcore_id();

	nb_deq = rte_ring_dequeue_burst(ca_glb_ctx.compdev_ctx[lcore_id].comp_resp_ring[lcore_id],
					(void **)mbufs, CA_ETHDEV_RX_BURST, NULL);
	if (nb_deq == 0)
		return 0;
	nb_tx = rte_eth_tx_burst(pq->eth_port_id, pq->eth_queue_id, mbufs, nb_deq);

	if (unlikely(nb_tx < nb_deq)) {
		CA_ERR("Could not transmit all packets from compdev resp ring on core: %u",
		       lcore_id);
		for (i = nb_tx; i < nb_deq; i++)
			rte_pktmbuf_free(mbufs[i]);
	}
	return nb_tx;
}

uint16_t
ca_compdev_deq(struct pending_queue *pq)
{
	struct rte_comp_op *deq_ops[CA_ETHDEV_TX_BURST];
	uint16_t nb_pending, nb_deq, i, tot_deq = 0;
	struct comp_dev_inflight_req *infl_req;
	struct __dao_lc_resp_compdev_op *resp;
	const uint64_t mask = pq->pq_mask;
	uint8_t lcore_id, comp_dev_id;
	uint64_t head, tail, pq_tail;
	struct dao_eth_trs_pkt *trs;
	uint16_t remaining;
	int rc;

	if (unlikely(pq == NULL)) {
		CA_ERR("Compress device pending queue is NULL!!");
		return 0;
	}

	lcore_id = rte_lcore_id();

	head = pq->head;
	tail = pq->tail;

	nb_pending = pending_queue_infl_cnt(head, tail, mask);
	if (nb_pending == 0)
		return 0;
	remaining = nb_pending;

	comp_dev_id = comp_dev_core_map[lcore_id];

	do {
		pq_tail = tail;
		nb_pending = RTE_MIN(nb_pending, CA_ETHDEV_RX_BURST);
		nb_deq = rte_compressdev_dequeue_burst(ca_glb_ctx.compdev_ctx[comp_dev_id].dev_id,
						       ca_glb_ctx.compdev_ctx[comp_dev_id].qp_id,
						       deq_ops, nb_pending);
		if (nb_deq == 0)
			break;

		if (nb_deq < nb_pending) {
			CA_WARN("All compress operations are not completed. Remaining: %d",
				nb_pending - nb_deq);
		}

		for (i = 0; i < nb_deq; i++) {
			infl_req = &pq->compdev_req_queue[(pq_tail + i) & mask];
			/**
			 * infl_req.mbuf is same as rte_comp_op.m_dst mbuf  to send response
			 * back to host. Ethernet transport headers are appended to this mbuf
			 * before sending response to host. Worker core can directly send this
			 * mbuf to host.
			 */
			trs = rte_pktmbuf_mtod(infl_req->mbuf, struct dao_eth_trs_pkt *);
			trs->hdr.op_len = deq_ops[i]->produced + comp_dev_resp_hdr_sz;

			resp = rte_pktmbuf_mtod(infl_req->mbuf, struct __dao_lc_resp_compdev_op *);
			resp->res.status = deq_ops[i]->status;
			resp->op_len = deq_ops[i]->produced;
			resp->res.consumed = deq_ops[i]->consumed;
			resp->res.produced = deq_ops[i]->produced;
			resp->res.required = 0;

			if (infl_req->op_buf_len < deq_ops[i]->produced) {
				resp->res.status = DAO_LC_COMP_OP_STATUS_RESP_BUF_SPACE_ISSUE;
				resp->res.required = deq_ops[i]->produced;
			}
			rc = rte_ring_enqueue(ca_glb_ctx.compdev_ctx[infl_req->ring_id]
						      .comp_resp_ring[infl_req->ring_id],
					      infl_req->mbuf);
			if (rc < 0) {
				CA_ERR("Failed to enq to compdev resp ring: %u from Core: %u",
				       infl_req->ring_id, lcore_id);
				rte_pktmbuf_free(infl_req->mbuf);
			}
			pending_queue_advance(&tail, mask);

			rte_pktmbuf_free(deq_ops[i]->m_src);
			rte_comp_op_free(deq_ops[i]);
		}
		tot_deq += nb_deq;
		pq->tail = tail;
		remaining -= nb_deq;
		nb_pending = remaining;
	} while (remaining > 0);

	return tot_deq;
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
	struct rte_mbuf *resp_mb;
	struct rte_mbuf *mbuf;

	dst_pool = ca_host_comp_dst_bufpool_get();
	if (dst_pool == NULL)
		return NULL;

	op_buf_size = CA_COMP_DEV_MBUF_SIZE - comp_dev_resp_hdr_sz;

	resp_mb = rte_pktmbuf_alloc(dst_pool);
	if (unlikely(resp_mb == NULL)) {
		CA_ERR("Response buffer alloc failure");
		return NULL;
	}

	if (op_buf_len > op_buf_size) {
		CA_ERR("op_buf_len %u exceeds max supported %u bytes", op_buf_len, op_buf_size);
		/* Limiting to supported size */
		op_buf_len = op_buf_size;
	}

	rte_memcpy(rte_pktmbuf_mtod(resp_mb, void *), rte_pktmbuf_mtod(rx_pkts, void *),
		   dao_lc_hdr_sz);
	mbuf = resp_mb;
	while (mbuf) {
		mbuf->data_len = mbuf->buf_len - mbuf->data_off;
		total_len += mbuf->data_len;
		mbuf = mbuf->next;
	}
	resp_mb->pkt_len = total_len;
	resp_mb->nb_segs = 1;

	infl_req->op_buf_len = op_buf_len;
	infl_req->src_len = src_len;
	infl_req->priv_xform = priv_xform;
	/* Uses resp_mb to send response back to host */
	infl_req->mbuf = resp_mb;

	return resp_mb;
}

uint8_t
prepare_comp_op(struct dao_eth_trs_pkt *req, struct comp_dev_inflight_req *infl_req,
		struct rte_comp_op *comp_op, struct rte_mbuf *rx_pkts)
{
	struct __dao_lc_req_decomp_op *decomp_req_mbuf = NULL;
	struct __dao_lc_req_comp_op *comp_req_mbuf = NULL;
	struct __dao_lc_req_decomp_op *decomp_req = NULL;
	struct __dao_lc_req_comp_op *comp_req = NULL;
	struct rte_mbuf *new_resp_mb = NULL;
	uint8_t comp_dev_id, lcore_id;
	void *priv_xform = NULL;
	uint8_t huff_type;
	uint8_t *ext_buf;
	uint16_t offset;
	int level;

	lcore_id = rte_lcore_id();
	comp_dev_id = comp_dev_core_map[lcore_id];

	switch (req->hdr.op_type) {
	case DAO_ETH_TRS_OP_TYPE_COMPRESS:
		comp_req = (struct __dao_lc_req_comp_op *)req;
		level = ca_compression_level_to_index(comp_req->level);
		if (unlikely(level < 0)) {
			CA_ERR("%s: Invalid compression level %d", __func__, comp_req->level);
			goto cleanup;
		}
		if (unlikely(comp_req->huff_enc_type < RTE_COMP_HUFFMAN_FIXED ||
			     comp_req->huff_enc_type > RTE_COMP_HUFFMAN_DYNAMIC)) {
			CA_ERR("%s: Invalid Huffman encoding type %d", __func__,
			       comp_req->huff_enc_type);
			goto cleanup;
		}
		huff_type = huffs[comp_req->huff_enc_type];
		priv_xform = ca_glb_ctx.compdev_ctx[comp_dev_id].comp_priv_xform[level][huff_type];

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

int
compress_devs_rings_init(void)
{
	unsigned int ring_size = CA_COMP_DEV_REQ_RING_SIZE;
	uint8_t main_lcore = rte_get_main_lcore();
	char name[RTE_RING_NAMESIZE];
	uint8_t i;

	for (i = 0; i < CA_MAX_LCORE; i++) {
		if (i == main_lcore) {
			ca_glb_ctx.compdev_ctx[i].comp_req_ring[i] = NULL;
			ca_glb_ctx.compdev_ctx[i].comp_resp_ring[i] = NULL;
			continue;
		}

		snprintf(name, sizeof(name), "ca_cdev_req_%u", i);
		ca_glb_ctx.compdev_ctx[i].comp_req_ring[i] = rte_ring_create(
			name, ring_size, SOCKET_ID_ANY, RING_F_SP_ENQ | RING_F_SC_DEQ);
		if (ca_glb_ctx.compdev_ctx[i].comp_req_ring[i] == NULL) {
			CA_ERR("Could not create compdev req ring for lcore %u", i);
			compress_devs_rings_fini();
			return -ENOMEM;
		}
		snprintf(name, sizeof(name), "ca_cdev_resp_%u", i);
		ca_glb_ctx.compdev_ctx[i].comp_resp_ring[i] = rte_ring_create(
			name, ring_size, SOCKET_ID_ANY, RING_F_SP_ENQ | RING_F_SC_DEQ);
		if (ca_glb_ctx.compdev_ctx[i].comp_resp_ring[i] == NULL) {
			CA_ERR("Could not create compdev resp ring for lcore %u", i);
			compress_devs_rings_fini();
			return -ENOMEM;
		}
	}
	CA_INFO("Compdev req/resp rings created for all lcores");
	return 0;
}

void
compress_devs_rings_fini(void)
{
	uint8_t main_lcore = rte_get_main_lcore();
	uint8_t i;

	for (i = 0; i < CA_MAX_LCORE; i++) {
		if (i == main_lcore)
			continue;
		if (ca_glb_ctx.compdev_ctx[i].comp_req_ring[i] != NULL) {
			rte_ring_free(ca_glb_ctx.compdev_ctx[i].comp_req_ring[i]);
			ca_glb_ctx.compdev_ctx[i].comp_req_ring[i] = NULL;
		}
		if (ca_glb_ctx.compdev_ctx[i].comp_resp_ring[i] != NULL) {
			rte_ring_free(ca_glb_ctx.compdev_ctx[i].comp_resp_ring[i]);
			ca_glb_ctx.compdev_ctx[i].comp_resp_ring[i] = NULL;
		}
	}
}

uint16_t
get_rings_for_core(uint16_t core_id, uint8_t *rings)
{
	uint8_t n, i;

	if (core_id >= CA_MAX_LCORE)
		return 0;
	n = compdev_ring_map[core_id].nb_rings;
	for (i = 0; i < n; i++)
		rings[i] = compdev_ring_map[core_id].ring_id[i];
	return n;
}

uint16_t
ca_comp_dev_enq_noop(struct pending_queue *pq, uint8_t ring_count, uint8_t *rings,
		     struct dev_desc_cnt *desc_cnt)
{
	RTE_SET_USED(pq);
	RTE_SET_USED(ring_count);
	RTE_SET_USED(rings);
	RTE_SET_USED(desc_cnt);
	return 0;
}

/**
 * Dequeue compress requests from core specific compress request ring,
 * prepare compress operation and finally enqueue to compress device.
 * Returns no.of successfully enqueued requests to compress device.
 */
static inline uint16_t
enq_to_compress_dev_from_comp_req_ring(struct pending_queue *pq, struct rte_ring *req_ring,
				       uint8_t ring_idx)
{
	struct rte_comp_op *comp_op[CA_ETHDEV_RX_BURST];
	struct rte_mbuf *mbufs[CA_ETHDEV_RX_BURST];
	struct comp_dev_inflight_req *infl_req;
	uint16_t tot_enq = 0, burst, req_count;
	uint16_t nb_deq, nb_comp_req = 0, i;
	const uint64_t mask = pq->pq_mask;
	uint8_t lcore_id, dev_id, idx;
	struct rte_mempool *mem_pool;
	struct dao_eth_trs_pkt *req;
	uint64_t head;
	int nb_ops;

	lcore_id = rte_lcore_id();
	head = pq->head;
	mem_pool = ca_host_comp_op_mempool_get();
	if (unlikely(mem_pool == NULL)) {
		CA_ERR("Could not get compress op mempool.");
		return 0;
	}

	req_count = rte_ring_count(req_ring);
	if (unlikely(req_count == 0))
		return 0;

	/**
	 * Cap per-iteration work: even if the ring contains more elements,
	 * dequeue at most CA_ETHDEV_RX_BURST at a time.
	 */
	req_count = RTE_MIN(CA_ETHDEV_RX_BURST, req_count);
	/**
	 * Allocate rte_comp_op in bulk based on req_count and prepare for
	 * compress device submission.
	 * rte_comp_op_bulk_alloc returns 0 if it cant allocate req_count.
	 * Returns req_count if allocation is success.
	 */
	nb_ops = rte_comp_op_bulk_alloc(mem_pool, comp_op, req_count);
	if (unlikely(nb_ops == 0)) {
		CA_ERR("Could not bulk alloc %u comp ops.", req_count);
		return 0;
	}

	nb_deq = rte_ring_dequeue_burst(req_ring, (void **)mbufs, req_count, NULL);
	if (nb_deq) {
		for (i = 0; i < nb_deq; i++) {
			req = rte_pktmbuf_mtod(mbufs[i], struct dao_eth_trs_pkt *);
			infl_req = &pq->compdev_req_queue[head];
			infl_req->ring_id = ring_idx;
			/* Returns 0 if comp_op preparation fails (frees comp_op[i]) */
			if (ca_glb_ctx.host_ctx[CA_LC_COMPRESS_DEV_ID].compress_dev_pkt_hdlr(
				    req, mbufs[i], infl_req, comp_op[i]) == 0) {
				CA_ERR("Core: %u Compress op prep failed: Ring: %u Packet Index: %u",
				       lcore_id, ring_idx, i);
				continue;
			}
			if (unlikely(nb_comp_req != i))
				comp_op[nb_comp_req] = comp_op[i];
			pending_queue_advance(&head, mask);
			nb_comp_req++;
		}
		pq->head = head;
	}

	if (nb_comp_req > 0) {
		dev_id = comp_dev_core_map[lcore_id];
		pq->time_out =
			rte_get_timer_cycles() + DEFAULT_COMMAND_TIMEOUT * rte_get_timer_hz();
		burst = nb_comp_req;

		tot_enq = rte_compressdev_enqueue_burst(ca_glb_ctx.compdev_ctx[dev_id].dev_id,
							ca_glb_ctx.compdev_ctx[dev_id].qp_id,
							comp_op, burst);

		if (unlikely(tot_enq < burst)) {
			CA_ERR("All compress ops were not enqueued (%u/%u)", tot_enq, burst);

			for (idx = tot_enq; idx < burst; idx++) {
				rte_pktmbuf_free(comp_op[idx]->m_dst);
				rte_pktmbuf_free(comp_op[idx]->m_src);
				rte_comp_op_free(comp_op[idx]);
			}
		}
		/* Roll back PQ head for operations that were never enqueued. */
		pq->head = (pq->head - (burst - tot_enq)) & mask;
	}
	return tot_enq;
}

uint16_t
ca_enq_comp_req_ring_to_compdev(struct pending_queue *pq, uint8_t ring_count, uint8_t *rings,
				struct dev_desc_cnt *desc_cnt)
{
	uint16_t tot_enq = 0, tot_deq = 0;
	uint8_t ring_idx, nb_rings;
	struct rte_ring *req_ring;

	for (nb_rings = 0; nb_rings < ring_count; nb_rings++) {
		ring_idx = rings[nb_rings];
		req_ring = ca_glb_ctx.compdev_ctx[ring_idx].comp_req_ring[ring_idx];
		tot_enq += enq_to_compress_dev_from_comp_req_ring(pq, req_ring, ring_idx);
		tot_deq += ca_compdev_deq(pq);
	}

	desc_cnt->compdev_deq_cnt = tot_deq;
	return tot_enq;
}
