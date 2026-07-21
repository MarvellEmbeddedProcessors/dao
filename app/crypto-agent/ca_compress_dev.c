/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2026 Marvell.
 */

#include <time.h>

#include "ca_compress_dev.h"

extern bool is_compdev_enabled;

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
 * For 8-VFs case: Below are the mapping for compress device to port-queue pairs.
 *
 * Consumer core: Core which deqs from request rings and submits to compress devices.
 * And enqs compress device response to resp rings.
 *
 * Workers: Core which receives packets from eth port-queue pair, enqs to request rings.
 * And deqs finished compress requests from response rings and sends back to host.
 *
 * For ex:
 * Port:0-Q0 packets will land on worker-1, consumed by core-1 to compress device 0.
 * Port:5-Q0 packets will land on worker-6, consumed by core-6 to compress device 5.
 * Port:6-Q6 packets will land on worker-9, consumed by core-7 to compress device 6.
 * --------------------------------------------------------
 * Compress	Eth Port	Consumer	Workers
 * Device ID	[Q0-Q7]		Core		[Q0-Q7]
 * --------------------------------------------------------
 * 0		0		1		1,9,17,2,10,18,3,11
 * 1		1		2		2,10,18,3,11,19,4,12
 * 2		2		3		3,11,19,4,12,20,5,13
 * 3		3		4		4,12,20,5,13,21,6,14
 * 4		4		5		5,13,21,6,14,22,7,15
 * 5		5		6		6,14,22,7,15,23,8,16
 * 6		6		7		7,15,23,8,16,1,9,17
 * 7		7		8		8,16,1,9,17,2,10,18
 * --------------------------------------------------------
 * Core: 0 is main core does not have access to any compress device.
 */

extern struct comp_dev_ring_map compdev_ring_map[CA_MAX_LCORE];

extern struct pending_queue *compdev_pqs[CA_MAX_LCORE][MAX_RINGS_PER_CORE];

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
comp_dev_ring_map_init(void)
{
	uint8_t i;

	for (i = 0; i < CA_MAX_LCORE; i++)
		compdev_ring_map[i].nb_pqs = 0;
}

void
comp_dev_ring_map_fini(void)
{
	comp_dev_ring_map_init();
}

/**
 * Calculates consumer compress device based on the PQ associated
 * port and queue pair and consumer core for PQ requests.
 * Updates no.of PQs and adds the PQ entry in the ring_map.
 */
int
comp_dev_ring_map_add(struct pending_queue *pq)
{
	uint8_t consumer_core, nb_compdevs;
	struct comp_dev_ring_map *map;
	unsigned int i, j;

	if (pq == NULL)
		return -EINVAL;

	nb_compdevs = ca_glb_ctx.nb_compdevs;
	if (nb_compdevs == 0)
		return -ENODEV;

	for (i = 0; i < CA_MAX_LCORE; i++) {
		for (j = 0; j < compdev_ring_map[i].nb_pqs; j++) {
			/* Return if PQ was already added in ring map */
			if (compdev_ring_map[i].pq[j] == pq)
				return 0;
		}
	}

	consumer_core = ca_compdev_consumer_core_from_port_queue(pq->eth_port_id, pq->eth_queue_id);
	map = &compdev_ring_map[consumer_core];
	if (map->nb_pqs >= MAX_RINGS_PER_CORE) {
		CA_ERR("Consumer core %u compdev PQ map full", consumer_core);
		return -ENOMEM;
	}

	map->pq[map->nb_pqs++] = pq;
	rte_smp_wmb();
	CA_DEBUG("Mapped compdev PQ port %u queue %u to consumer core: %u", pq->eth_port_id,
		 pq->eth_queue_id, consumer_core);
	return 0;
}

/**
 * Removes PQ entry from the ring map and decrements the no.of PQs associated
 * with the worker lcore.
 */
void
comp_dev_ring_map_remove(struct pending_queue *pq)
{
	uint8_t i, j;

	if (pq == NULL)
		return;

	for (i = 0; i < CA_MAX_LCORE; i++) {
		for (j = 0; j < compdev_ring_map[i].nb_pqs; j++) {
			if (compdev_ring_map[i].pq[j] != pq)
				continue;
			compdev_ring_map[i].nb_pqs--;
			if (j < compdev_ring_map[i].nb_pqs)
				compdev_ring_map[i].pq[j] =
					compdev_ring_map[i].pq[compdev_ring_map[i].nb_pqs];
			compdev_ring_map[i].pq[compdev_ring_map[i].nb_pqs] = NULL;
			rte_smp_wmb();
			return;
		}
	}
}

/**
 * Removes the ring mapping associated with the specified PQ and if a QSBR RCU
 * instance is available, waits for all registered readers to pass through a
 * quiescent state before returning. This ensures that no active readers are
 * still referencing the removed mapping.
 */
void
comp_dev_ring_map_remove_quiesce(struct pending_queue *pq)
{
	struct rte_rcu_qsbr *qsbr;

	comp_dev_ring_map_remove(pq);

	qsbr = ca_rcu_qsbr_get();
	if (qsbr != NULL)
		rte_rcu_qsbr_synchronize(qsbr, RTE_QSBR_THRID_INVALID);
}

/* nb_desc will be taken from dao_card_config.crypto_nb_desc */
int
compress_devs_init(uint32_t nb_desc)
{
	struct rte_compressdev_config conf;
	uint16_t comp_dev_id, qp_id;
	uint8_t dev_idx;
	int ret, j, i;

	CA_INFO("Configuring %d compress devices with %d QPs", ca_glb_ctx.nb_compdevs,
		ca_glb_ctx.nb_compdev_qp);

	/* Update nb_desc to next power of 2 to aid in pending queue checks */
	nb_desc = rte_align32pow2(nb_desc);

	if (nb_desc < CA_CPT_MIN_QUEUE_DEPTH) {
		nb_desc = CA_CPT_MIN_QUEUE_DEPTH;
		CA_INFO("Using minimum queue depth: %u for compress device", nb_desc);
	}

	if (nb_desc > CA_MAX_COMP_OPERATIONS) {
		nb_desc = CA_MAX_COMP_OPERATIONS;
		CA_INFO("Capping compress device queue depth to %u", nb_desc);
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
	 * Dedicated consumer cores 1..nb_compdevs each own one compress device (QP 0).
	 */
	qp_id = 0;
	for (i = CA_COMP_DEV_CONSUMER_CORE_START;
	     i < CA_COMP_DEV_CONSUMER_CORE_START + ca_glb_ctx.nb_compdevs; i++) {
		dev_idx = i - CA_COMP_DEV_CONSUMER_CORE_START;

		if (rte_lcore_is_enabled(i) == 0)
			continue;

		ca_glb_ctx.compdev_ctx[i].dev_id = ca_glb_ctx.compdev_ids[dev_idx];
		ca_glb_ctx.compdev_ctx[i].qp_id = qp_id;
		ca_glb_ctx.compdev_ctx[i].nb_allowed = nb_desc;
		CA_INFO("Consumer core %u -> compress dev %u", i, ca_glb_ctx.compdev_ids[dev_idx]);
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
host_dev_comp_op_pool_fini(uint8_t dev_id)
{
	rte_mempool_free(ca_glb_ctx.host_ctx[dev_id].comp_op_mempool);
	ca_glb_ctx.host_ctx[dev_id].comp_op_mempool = NULL;
}

void
host_dev_comp_dst_mbuf_pool_fini(uint8_t dev_id)
{
	rte_mempool_free(ca_glb_ctx.host_ctx[dev_id].comp_dst_mbuf_pool);
	ca_glb_ctx.host_ctx[dev_id].comp_dst_mbuf_pool = NULL;
	ca_glb_ctx.host_ctx[dev_id].comp_dst_mbuf_size = 0;
}

void
host_dev_compress_pools_fini(uint8_t dev_id)
{
	host_dev_comp_op_pool_fini(dev_id);
	host_dev_comp_dst_mbuf_pool_fini(dev_id);
}

static uint32_t
comp_dst_mbuf_buf_len_get(uint32_t max_seg_size)
{
	uint32_t buf_len;

	buf_len = RTE_MIN(max_seg_size, (uint32_t)CA_COMP_DEV_MBUF_SIZE);
	buf_len = buf_len + RTE_PKTMBUF_HEADROOM;
	buf_len = RTE_MAX(buf_len, (uint32_t)(comp_dev_resp_hdr_sz + CA_MIN_SEG_SIZE));

	return buf_len;
}

uint32_t
ca_host_comp_dst_mbuf_size_get(void)
{
	return ca_glb_ctx.host_ctx[CA_LC_COMPRESS_DEV_ID].comp_dst_mbuf_size;
}

int
host_dev_comp_op_pool_init(uint8_t dev_id, uint32_t comp_op)
{
	char op_pool_name[RTE_MEMZONE_NAMESIZE] = "\0";
	struct rte_mempool *mp;

	CA_INFO("Initializing comp op pool for host device %u (elements %u)", dev_id, comp_op);

	snprintf(op_pool_name, sizeof(op_pool_name), "compdev_op_pool%u", dev_id);
	mp = rte_comp_op_pool_create(op_pool_name, comp_op, 0, 0, rte_socket_id());
	if (mp == NULL) {
		CA_ERR("Could not create comp op mempool for host dev: %u", dev_id);
		return -ENOMEM;
	}
	ca_glb_ctx.host_ctx[dev_id].comp_op_mempool = mp;

	return 0;
}

/**
 * Refresh the compression device pending-queue mappings for all cores.
 * Clears the pending-queue information for each valid lcore and
 * repopulates it by querying the current compression device queue
 * assignments.
 */
void
ca_refresh_comp_dev_pqs(void)
{
	for (uint8_t i = 1; i < CA_MAX_LCORE; i++) {
		memset(compdev_pqs[i], 0, sizeof(compdev_pqs[i]));
		get_compdev_pqs_for_core(i, compdev_pqs[i]);
	}
}

int
host_dev_comp_dst_mbuf_pool_init(uint32_t max_seg_size, uint32_t nb_elements)
{
	char comp_dst_mbuf_pool_name[RTE_MEMZONE_NAMESIZE] = "\0";
	uint8_t dev_id = CA_LC_COMPRESS_DEV_ID;
	static uint32_t mbuf_nb_elements;
	struct ca_hostdev_ctx *host_ctx;
	struct rte_mempool *mp;
	uint32_t mbuf_size;

	if (max_seg_size == 0 || nb_elements == 0) {
		CA_ERR("Invalid comp dst pool params: max_seg_size %u nb_elements %u", max_seg_size,
		       nb_elements);
		return -EINVAL;
	}

	host_ctx = &ca_glb_ctx.host_ctx[dev_id];
	mbuf_size = comp_dst_mbuf_buf_len_get(max_seg_size);

	if (host_ctx->comp_dst_mbuf_pool != NULL) {
		if (mbuf_size <= host_ctx->comp_dst_mbuf_size && nb_elements <= mbuf_nb_elements) {
			CA_DEBUG("Comp dst mbuf pool already sized %u (requested %u)",
				 host_ctx->comp_dst_mbuf_size, mbuf_size);
			return 0;
		}
		CA_INFO("Recreating comp dst mbuf pool (size %u->%u, elems %u->%u)",
			host_ctx->comp_dst_mbuf_size, mbuf_size, host_ctx->comp_dst_mbuf_pool->size,
			nb_elements);
		host_dev_comp_dst_mbuf_pool_fini(dev_id);
	}

	CA_INFO("Initializing comp dst mbuf pool for device %u: elements %u max buf size %u",
		dev_id, nb_elements, mbuf_size);

	snprintf(comp_dst_mbuf_pool_name, sizeof(comp_dst_mbuf_pool_name), "compdev_dst_pool%u",
		 dev_id);
	mp = rte_pktmbuf_pool_create(comp_dst_mbuf_pool_name, nb_elements, 0, 0, mbuf_size,
				     rte_socket_id());
	if (mp == NULL) {
		CA_ERR("Could not create compdev dst mbuf pool for host dev: %u", dev_id);
		return -ENOMEM;
	}

	host_ctx->comp_dst_mbuf_pool = mp;
	host_ctx->comp_dst_mbuf_size = mbuf_size;
	mbuf_nb_elements = nb_elements;
	return 0;
}

uint16_t
ca_deq_comp_resp_ring_send_to_host(struct pending_queue *pq)
{
	struct rte_mbuf *mbufs[CA_ETHDEV_RX_BURST];
	uint16_t nb_deq, nb_tx = 0, i;

	if (unlikely(pq == NULL || pq->compdev_infl_queue == NULL ||
		     pq->compdev_infl_queue->comp_resp_ring == NULL))
		return 0;

	nb_deq = rte_ring_dequeue_burst(pq->compdev_infl_queue->comp_resp_ring, (void **)mbufs,
					CA_ETHDEV_RX_BURST, NULL);
	if (nb_deq == 0)
		return 0;
	nb_tx = rte_eth_tx_burst(pq->eth_port_id, pq->eth_queue_id, mbufs, nb_deq);

	if (unlikely(nb_tx < nb_deq)) {
		CA_ERR("Could not transmit all packets from compdev resp ring port %u queue %u",
		       pq->eth_port_id, pq->eth_queue_id);
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

	lcore_id = rte_lcore_id();

	head = pq->head;
	tail = pq->tail;

	nb_pending = pending_queue_infl_cnt(head, tail, mask);
	if (nb_pending == 0)
		return 0;
	remaining = nb_pending;

	comp_dev_id = lcore_id;

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
			infl_req = &pq->compdev_infl_queue->reqs[(pq_tail + i) & mask];
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
			rc = rte_ring_enqueue(pq->compdev_infl_queue->comp_resp_ring,
					      infl_req->mbuf);
			if (unlikely(rc < 0)) {
				CA_ERR("Failed to enq to compdev resp ring port %u queue %u from core %u",
				       pq->eth_port_id, pq->eth_queue_id, lcore_id);
				rte_pktmbuf_free(infl_req->mbuf);
			}

			infl_req->mbuf = NULL;
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

	op_buf_size = ca_host_comp_dst_mbuf_size_get();
	if (op_buf_size <= RTE_PKTMBUF_HEADROOM + comp_dev_resp_hdr_sz)
		return NULL;

	op_buf_size -= (RTE_PKTMBUF_HEADROOM + comp_dev_resp_hdr_sz);

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
	uint8_t comp_dev_id, lcore_id, dev_idx, rte_dev;
	struct __dao_lc_req_comp_op *comp_req = NULL;
	struct rte_mbuf *new_resp_mb = NULL;
	void *priv_xform = NULL;
	uint8_t huff_type;
	uint8_t *ext_buf;
	uint16_t offset;
	int level;

	lcore_id = rte_lcore_id();
	dev_idx = lcore_id - CA_COMP_DEV_CONSUMER_CORE_START;
	rte_dev = ca_glb_ctx.compdev_ids[dev_idx];
	comp_dev_id = rte_dev;

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

/**
 * Retrieves the list of pending queues mapped to the specified core and
 * returns number of PQs assigned to the specified core.
 */
uint8_t
get_compdev_pqs_for_core(uint16_t core_id, struct pending_queue **pqs)
{
	uint8_t n, i;

	if (core_id >= CA_MAX_LCORE)
		return 0;

	n = compdev_ring_map[core_id].nb_pqs;
	for (i = 0; i < n; i++)
		pqs[i] = compdev_ring_map[core_id].pq[i];

	return n;
}

uint16_t
ca_comp_dev_enq_noop(uint8_t pq_count, struct pending_queue **pqs, struct dev_desc_cnt *desc_cnt)
{
	RTE_SET_USED(pq_count);
	RTE_SET_USED(pqs);
	RTE_SET_USED(desc_cnt);
	return 0;
}

/**
 * Dequeue compress requests from port-queue compress request ring,
 * prepare compress operation and finally enqueue to compress device.
 * Returns no.of successfully enqueued requests to compress device.
 */
static inline uint16_t
enq_to_compress_dev_from_comp_req_ring(struct pending_queue *pq)
{
	struct rte_comp_op *comp_op[CA_ETHDEV_RX_BURST];
	struct rte_mbuf *mbufs[CA_ETHDEV_RX_BURST];
	struct comp_dev_inflight_req *infl_req;
	uint16_t tot_enq = 0, burst, req_count;
	uint16_t nb_deq, nb_comp_req = 0, i;
	const uint64_t mask = pq->pq_mask;
	struct rte_mempool *mem_pool;
	struct dao_eth_trs_pkt *req;
	struct ca_compdev_ctx *cdc;
	uint8_t lcore_id, idx;
	uint64_t head;
	int nb_ops;

	if (unlikely(pq == NULL || pq->compdev_infl_queue == NULL ||
		     pq->compdev_infl_queue->comp_req_ring == NULL))
		return 0;

	lcore_id = rte_lcore_id();
	head = pq->head;
	mem_pool = ca_host_comp_op_mempool_get();
	if (unlikely(mem_pool == NULL)) {
		CA_ERR("Could not get compress op mempool.");
		return 0;
	}

	req_count = rte_ring_count(pq->compdev_infl_queue->comp_req_ring);
	if (unlikely(req_count == 0))
		return 0;

	req_count = RTE_MIN(req_count, pending_queue_free_cnt(pq->head, pq->tail, mask));
	if (unlikely(req_count == 0))
		return 0;

	req_count = RTE_MIN(CA_ETHDEV_RX_BURST, req_count);
	nb_ops = rte_comp_op_bulk_alloc(mem_pool, comp_op, req_count);
	if (unlikely(nb_ops == 0)) {
		CA_ERR("Could not bulk alloc %u comp ops.", req_count);
		return 0;
	}

	nb_deq = rte_ring_dequeue_burst(pq->compdev_infl_queue->comp_req_ring, (void **)mbufs,
					req_count, NULL);
	if (unlikely(nb_deq < req_count)) {
		for (i = nb_deq; i < req_count; i++)
			rte_comp_op_free(comp_op[i]);
	}

	if (nb_deq) {
		for (i = 0; i < nb_deq; i++) {
			req = rte_pktmbuf_mtod(mbufs[i], struct dao_eth_trs_pkt *);
			infl_req = &pq->compdev_infl_queue->reqs[head];
			if (ca_glb_ctx.host_ctx[CA_LC_COMPRESS_DEV_ID].compress_dev_pkt_hdlr(
				    req, mbufs[i], infl_req, comp_op[i]) == 0) {
				CA_ERR("Core: %u Compress op prep failed: port %u queue %u pkt %u",
				       lcore_id, pq->eth_port_id, pq->eth_queue_id, i);
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
		cdc = &ca_glb_ctx.compdev_ctx[lcore_id];
		pq->time_out =
			rte_get_timer_cycles() + DEFAULT_COMMAND_TIMEOUT * rte_get_timer_hz();
		burst = nb_comp_req;

		tot_enq = rte_compressdev_enqueue_burst(cdc->dev_id, cdc->qp_id, comp_op, burst);

		if (unlikely(tot_enq < burst)) {
			CA_ERR("All compress ops were not enqueued (%u/%u)", tot_enq, burst);

			for (idx = tot_enq; idx < burst; idx++) {
				rte_pktmbuf_free(comp_op[idx]->m_dst);
				rte_pktmbuf_free(comp_op[idx]->m_src);
				rte_comp_op_free(comp_op[idx]);
			}
		}
		pq->head = (pq->head - (burst - tot_enq)) & mask;
	}
	return tot_enq;
}

uint16_t
ca_enq_comp_req_noop(uint8_t pq_count, uint8_t lcore_id, struct dev_desc_cnt *desc_cnt)
{
	RTE_SET_USED(pq_count);
	RTE_SET_USED(lcore_id);
	RTE_SET_USED(desc_cnt);
	return 0;
}

uint16_t
ca_enq_comp_req_ring_to_compdev(uint8_t pq_count, uint8_t lcore_id, struct dev_desc_cnt *desc_cnt)
{
	static __thread uint8_t req_ring_idx;
	uint16_t tot_enq = 0, tot_deq = 0;
	struct pending_queue **pqs;
	uint8_t i, start, idx;

	if (pq_count == 0)
		return 0;

	pqs = compdev_pqs[lcore_id];
	start = req_ring_idx % pq_count;
	for (i = 0; i < pq_count; i++) {
		idx = (start + i) % pq_count;
		if (unlikely(pqs[idx] == NULL || pqs[idx]->compdev_infl_queue == NULL ||
			     pqs[idx]->compdev_infl_queue->comp_req_ring == NULL))
			continue;
		if (rte_ring_count(pqs[idx]->compdev_infl_queue->comp_req_ring) != 0)
			tot_enq += enq_to_compress_dev_from_comp_req_ring(pqs[idx]);
		tot_deq += ca_compdev_deq(pqs[idx]);
	}
	req_ring_idx = (start + 1) % pq_count;

	desc_cnt->compdev_deq_cnt = tot_deq;
	return tot_enq;
}

static void
ca_compdev_clear_sw_ring(struct rte_ring *ring)
{
	struct rte_mbuf *mbufs[CA_ETHDEV_RX_BURST];
	uint16_t nb;

	if (ring == NULL)
		return;

	do {
		nb = rte_ring_dequeue_burst(ring, (void **)mbufs, CA_ETHDEV_RX_BURST, NULL);
		if (nb)
			rte_pktmbuf_free_bulk(mbufs, nb);
	} while (nb != 0);
}

static void
ca_compdev_clear_pq_sw_state(struct pending_queue *pq)
{
	struct comp_dev_inflight_req *infl_req;
	uint64_t head, tail, mask, nb;

	if (pq == NULL)
		return;

	head = pq->head;
	tail = pq->tail;
	mask = pq->pq_mask;
	nb = pending_queue_infl_cnt(head, tail, mask);

	for (; nb > 0; nb--) {
		infl_req = &pq->compdev_infl_queue->reqs[tail & mask];
		if (infl_req->mbuf != NULL)
			rte_pktmbuf_free(infl_req->mbuf);
		pending_queue_advance(&tail, mask);
	}

	pq->head = tail;
	pq->tail = tail;
}

static uint64_t
ca_compdev_consumer_inflight_count(uint8_t consumer_core)
{
	struct ca_eth_dev_ctx *eth_ctx;
	struct pending_queue *pq;
	uint8_t pq_consumer;
	uint64_t total = 0;
	uint16_t i, j;

	for (i = 0; i < ca_glb_ctx.nb_valid_ethdevs; i++) {
		eth_ctx = &ca_glb_ctx.eth_ctx[i];
		for (j = 0; j < eth_ctx->nb_queue_avail; j++) {
			if ((eth_ctx->init_q_mask & (1ULL << j)) == 0)
				continue;

			pq = &eth_ctx->compdev_pq[j];
			pq_consumer = ca_compdev_consumer_core_from_port_queue(pq->eth_port_id,
									       pq->eth_queue_id);
			if (pq_consumer != consumer_core)
				continue;

			total += pending_queue_infl_cnt(pq->head, pq->tail, pq->pq_mask);
		}
	}

	return total;
}

static bool
ca_compdev_drain_hw_queue(uint8_t consumer_core)
{
	struct rte_comp_op *deq_ops[CA_ETHDEV_TX_BURST];
	uint16_t qp_id, nb_deq, burst;
	struct timespec start, now;
	bool has_timeout = false;
	uint64_t elapsed_ms = 0;
	uint64_t remaining;
	uint8_t dev_id;
	uint16_t i;

	remaining = ca_compdev_consumer_inflight_count(consumer_core);
	if (remaining == 0)
		return false;

	dev_id = ca_glb_ctx.compdev_ctx[consumer_core].dev_id;
	qp_id = ca_glb_ctx.compdev_ctx[consumer_core].qp_id;

	clock_gettime(CLOCK_MONOTONIC, &start);

	while (remaining > 0) {
		burst = RTE_MIN(remaining, (uint32_t)CA_ETHDEV_TX_BURST);
		nb_deq = rte_compressdev_dequeue_burst(dev_id, qp_id, deq_ops, burst);

		if (nb_deq > 0) {
			for (i = 0; i < nb_deq; i++) {
				if (deq_ops[i]->m_src != NULL)
					rte_pktmbuf_free(deq_ops[i]->m_src);
				rte_comp_op_free(deq_ops[i]);
			}
			remaining -= nb_deq;
			clock_gettime(CLOCK_MONOTONIC, &start);
			elapsed_ms = 0;
			continue;
		}

		clock_gettime(CLOCK_MONOTONIC, &now);
		elapsed_ms = (now.tv_sec - start.tv_sec) * 1000 +
			     (now.tv_nsec - start.tv_nsec) / 1000000;

		if (elapsed_ms >= CA_CPT_MAX_TIMEOUT_MS) {
			has_timeout = true;
			break;
		}
	}

	return has_timeout;
}

static uint32_t
ca_compdev_nb_desc_get(void)
{
	if (rte_lcore_is_enabled(CA_COMP_DEV_CONSUMER_CORE_START))
		return ca_glb_ctx.compdev_ctx[CA_COMP_DEV_CONSUMER_CORE_START].nb_allowed;

	return CA_CPT_MIN_QUEUE_DEPTH;
}

static int
ca_compdev_reinit(void)
{
	uint32_t nb_desc;
	int ret;

	nb_desc = ca_compdev_nb_desc_get();

	compress_priv_xforms_fini();
	decompress_priv_xform_fini();
	compress_devs_fini();

	ret = compress_devs_init(nb_desc);
	if (ret) {
		CA_ERR("Could not reinitialize compress devices during soft reset");
		return ret;
	}

	ret = compression_priv_xforms_init();
	if (ret) {
		CA_ERR("Could not recreate compress private xforms during soft reset");
		compress_devs_fini();
		return ret;
	}

	ret = decompression_priv_xform_init();
	if (ret) {
		CA_ERR("Could not recreate decompress private xform during soft reset");
		compress_priv_xforms_fini();
		compress_devs_fini();
		return ret;
	}

	CA_INFO("Reinitialized compress devices (nb_desc %u) after soft reset timeout", nb_desc);

	return 0;
}

int
ca_compdev_clear_inflight_reqs(void)
{
	struct ca_eth_dev_ctx *eth_ctx;
	struct pending_queue *pq;
	bool has_timeout = false;
	uint8_t consumer_core;
	uint16_t i, j;

	for (i = 0; i < ca_glb_ctx.nb_valid_ethdevs; i++) {
		eth_ctx = &ca_glb_ctx.eth_ctx[i];
		for (j = 0; j < eth_ctx->nb_queue_avail; j++) {
			if ((eth_ctx->init_q_mask & (1ULL << j)) == 0)
				continue;

			pq = &eth_ctx->compdev_pq[j];
			if (pq->compdev_infl_queue == NULL)
				continue;
			ca_compdev_clear_sw_ring(pq->compdev_infl_queue->comp_req_ring);
			ca_compdev_clear_sw_ring(pq->compdev_infl_queue->comp_resp_ring);
		}
	}

	for (consumer_core = CA_COMP_DEV_CONSUMER_CORE_START;
	     consumer_core < CA_COMP_DEV_CONSUMER_CORE_START + ca_glb_ctx.nb_compdevs;
	     consumer_core++)
		has_timeout = ca_compdev_drain_hw_queue(consumer_core) || has_timeout;

	for (i = 0; i < ca_glb_ctx.nb_valid_ethdevs; i++) {
		eth_ctx = &ca_glb_ctx.eth_ctx[i];
		for (j = 0; j < eth_ctx->nb_queue_avail; j++) {
			if ((eth_ctx->init_q_mask & (1ULL << j)) == 0)
				continue;

			ca_compdev_clear_pq_sw_state(&eth_ctx->compdev_pq[j]);
		}
	}

	if (!has_timeout)
		return 0;

	/**
	 * As reset could not clear compress device requests, re-initialize compress
	 * device.
	 */
	return ca_compdev_reinit();
}
