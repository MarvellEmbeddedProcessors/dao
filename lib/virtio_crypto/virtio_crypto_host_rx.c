/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <rte_crypto.h>
#include <rte_malloc.h>

#include "dao_dma.h"
#include "dao_virtio_cryptodev.h"
#include "virtio_dev_priv.h"

#include "spec/virtio_crypto.h"
#include "virtio_crypto_akcipher.h"
#include "virtio_crypto_priv.h"

dao_virtio_crypto_deq_fn_t dao_virtio_crypto_deq_fns[VIRTIO_CRYPTO_DEQ_OFFLOAD_LAST << 1] = {
#define R(name, flags) [flags] = virtio_crypto_deq_##name,
	VIRTIO_CRYPTO_DEQ_FASTPATH_MODES
#undef R
};

static __rte_always_inline uint16_t
fetch_host_data(struct virtio_crypto_queue *q, struct dao_dma_vchan_state *dev2mem, uint16_t hint,
		struct rte_crypto_op **cops, const uint16_t flags)
{
	uint16_t dma_shadow_q_head, data_q_head, dma_data_q_head, nb_cache_buf_rx, nb_processed = 0;
	uintptr_t desc_base = (uintptr_t)q->sd_desc_base;
	uint16_t nb_buf_alloc, off, dma_length, i = 0;
	void *buf[DAO_VIRTIO_CRYPTO_RX_BUF_CACHE_SZ];
	struct dao_virtio_crypto_buffer *vc_buffer;
	struct virtio_crypto_op_data_req *req;
	struct vring_packed_desc *vio_desc;
	uint32_t nb_desc, nb_buf;
	struct rte_dma_sge cmd_dst;
	uint16_t q_sz = q->q_sz;

	RTE_SET_USED(flags);

	data_q_head = q->data_q_head;
	dma_data_q_head = q->dma_data_q_head;
	nb_cache_buf_rx = q->nb_cache_buf_rx;

	/* Check if there are pending DMAs */
	if (data_q_head != dma_data_q_head) {
		if (dao_dma_op_status(dev2mem, q->dev2mem_data_dma_idx)) {
			/* Pending DMAs are done. Process the buffers. */

			vc_buffer = q->buffer_cache_rx[0];

			/* Set metadata for next node in first buffer from the same queue. */
			vc_buffer->metadata.cnt = nb_cache_buf_rx;
			vc_buffer->metadata.cdev.id = q->cryptodev_id;
			vc_buffer->metadata.cdev.qp_id = q->cryptodev_qp_id;

			/* Process the DMAed buffers. */
			for (i = 0; i < nb_cache_buf_rx; i++) {
				vc_buffer = q->buffer_cache_rx[i];

				/* Convert to crypto op etc */

				cops[i] = &vc_buffer->cop;
				req = (struct virtio_crypto_op_data_req *)(&vc_buffer->reserved[0]);

				dao_dbg("OP_DATA_REQ: %x", req->header.opcode);
				dao_dbg("OP_DATA_ALG: %x", req->header.algo);
				dao_dbg("OP_DATA_SID: %lx", req->header.session_id);
				dao_dbg("OP_DATA_FLG: %x", req->header.flag);
				dao_dbg("OP_DATA AKCIPHER SRC LEN: %x",
					req->u.akcipher_req.para.src_data_len);
				dao_dbg("OP_DATA AKCIPHER DST LEN: %x",
					req->u.akcipher_req.para.dst_data_len);

				switch (req->header.opcode) {
				case VIRTIO_CRYPTO_AKCIPHER_ENCRYPT:
					virtio_crypto_akcipher_enc_op(cops[i], req,
								      &vc_buffer->output_addr,
								      &vc_buffer->output_len);
					break;
				case VIRTIO_CRYPTO_AKCIPHER_DECRYPT:
					virtio_crypto_akcipher_dec_op(cops[i], req,
								      &vc_buffer->output_addr,
								      &vc_buffer->output_len);
					break;
				case VIRTIO_CRYPTO_AKCIPHER_SIGN:
					virtio_crypto_akcipher_sign_op(cops[i], req,
								       &vc_buffer->output_addr,
								       &vc_buffer->output_len);
					break;
				case VIRTIO_CRYPTO_AKCIPHER_VERIFY:
					virtio_crypto_akcipher_verify_op(cops[i], req,
									 &vc_buffer->output_addr,
									 &vc_buffer->output_len);
					break;
				default:
					dao_err("Unsupported data request op code: %x",
						req->header.opcode);
				}
				q->buffer_cache_rx[i] = NULL;
			}

			nb_processed = nb_cache_buf_rx;
			nb_cache_buf_rx = 0;

			/* Update DMA data queue head to indicate that DMA is done. */
			dma_data_q_head = data_q_head;

		} else {
			/* DMA is pending. Skip for this iteration. */
			return 0;
		}
	}

	/*
	 * Nothing pending in DMA queue. Check DMA shadow queue to check if any descriptors are
	 * fetched.
	 */
	dma_shadow_q_head = __atomic_load_n(&q->dma_shadow_q_head, __ATOMIC_ACQUIRE);

	if (dma_shadow_q_head == data_q_head) {
		/* No new descriptors to be processed. */
		goto state_update;
	}

	nb_desc = desc_off_diff(dma_shadow_q_head, data_q_head, q_sz);
	nb_desc = RTE_MIN(nb_desc, hint);

	off = DESC_OFF(data_q_head);
	rte_prefetch0(DESC_PTR_OFF(desc_base, off, 0));

	/*
	 * Allocate memory for holding the descriptors. With virtio-crypto, each operation would
	 * have at least 2 descriptors. One for read and one for write. Assuming each operation
	 * consumes at least 2 descriptors, allocate half the number of descriptors to avoid
	 * extra alloc & free.
	 */
	nb_buf_alloc = RTE_MIN(nb_desc / 2, RTE_DIM(buf));
	if (unlikely(rte_mempool_get_bulk(q->mp, buf, nb_buf_alloc) != 0)) {
		dao_err("Couldn't allocate memory for holding %d descriptors", nb_desc);
		goto state_update;
	}

	for (i = 0, nb_buf = 0; i < nb_desc;) {
		dma_length = 0;
		/* Read the descriptor */
		do {
			vio_desc = (struct vring_packed_desc *)DESC_PTR_OFF(desc_base, off + i, 0);
			dao_dbg("VIO DESC addr: %lx", vio_desc->addr);
			dao_dbg("VIO DESC len: %x, id: %x, flags: %x", vio_desc->len, vio_desc->id,
				vio_desc->flags);
			if (!(vio_desc->flags & VRING_DESC_F_WRITE)) {
				dao_dma_enq_src_x1(dev2mem, vio_desc->addr, vio_desc->len);
				dma_length += vio_desc->len;
			}
			i++;
		} while (vio_desc->flags & VRING_DESC_F_NEXT);

		vc_buffer = buf[nb_buf];
		cmd_dst.addr = (rte_iova_t)(&vc_buffer->reserved[0]);
		cmd_dst.length = dma_length;

		dao_dma_enq_dst_x1(dev2mem, (uintptr_t)cmd_dst.addr, cmd_dst.length);

		if (!dao_dma_flush(dev2mem, DAO_VIRTIO_CRYPTO_MAX_CHAIN_READ_DESC))
			break;

		q->buffer_cache_rx[nb_buf] = buf[nb_buf];
		nb_buf++;
	}

	dao_dma_flush(dev2mem, DAO_DMA_MAX_POINTER);

	q->dev2mem_data_dma_idx = dev2mem->tail - 1;

	nb_cache_buf_rx = nb_buf;

	if (nb_buf < nb_buf_alloc)
		rte_mempool_put_bulk(q->mp, (void **)&buf[nb_buf], (nb_buf_alloc - nb_buf));

	data_q_head = desc_off_add(data_q_head, i, q_sz);

state_update:
	q->data_q_head = data_q_head;
	q->dma_data_q_head = dma_data_q_head;
	q->nb_cache_buf_rx = nb_cache_buf_rx;

	return nb_processed;
}

static __rte_always_inline uint16_t
virtio_crypto_deq(struct virtio_crypto_queue *q, struct rte_crypto_op **cops, uint16_t nb_cops,
		  const uint16_t flags)
{
	struct dao_dma_vchan_info *vchan_info = RTE_PER_LCORE(dao_dma_vchan_info);
	struct dao_dma_vchan_state *dev2mem;
	uint16_t dma_vchan = q->dma_vchan;
	int rc = 0;

	dev2mem = &vchan_info->dev2mem[dma_vchan];

	/* Update completed DMA ops */
	dao_dma_check_compl(dev2mem);

	/* Check shadow mbuf status and issue new DMA's for mbuf's */
	rc = fetch_host_data(q, dev2mem, nb_cops, cops, flags);

	if (rc < 0) {
		dao_err("Error: %d", rc);
		return 0;
	}

	return rc;
}

#define R(name, flags)                                                                             \
	uint16_t virtio_crypto_deq_##name(void *q, struct rte_crypto_op **cops, uint16_t nb_cops)  \
	{                                                                                          \
		return virtio_crypto_deq(q, cops, nb_cops, (flags));                               \
	}

VIRTIO_CRYPTO_DEQ_FASTPATH_MODES
#undef R
