/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <rte_crypto.h>
#include <rte_malloc.h>

#include "dao_virtio_cryptodev.h"
#include "virtio_dev_priv.h"

#include "spec/virtio_crypto.h"
#include "virtio_crypto_priv.h"

dao_virtio_crypto_enq_fn_t dao_virtio_crypto_enq_fns[VIRTIO_CRYPTO_ENQ_OFFLOAD_LAST << 1] = {
#define T(name, flags) [flags] = virtio_crypto_enq_##name,
	VIRTIO_CRYPTO_ENQ_FASTPATH_MODES
#undef T
};

static __rte_always_inline void
push_enq_data(struct virtio_crypto_queue *q, struct dao_dma_vchan_state *mem2dev,
	      struct rte_crypto_op **cops, uint16_t nb_cops, const uint16_t flags)
{
	uint16_t data_q_tail, dma_data_q_tail, nb_cache_buf_tx;
	uintptr_t desc_base = (uintptr_t)q->sd_desc_base;
	struct dao_virtio_crypto_buffer *buf;
	struct rte_dma_sge cmd_src, cmd_dst;
	struct vring_packed_desc *vio_desc;
	uint8_t i;

	data_q_tail = q->data_q_tail;
	dma_data_q_tail = q->dma_data_q_tail;
	nb_cache_buf_tx = q->nb_cache_buf_tx;

	if (data_q_tail != dma_data_q_tail) {
		if (dao_dma_op_status(mem2dev, q->mem2dev_data_dma_idx)) {
			/*
			 * Indicate to service core that descriptors are processed. Update
			 * shadow_q_tail.
			 */

#ifdef VIRTIO_CRYPTO_DEBUG
			if (unlikely(nb_cache_buf_tx == 0)) {
				dao_err("CRITICAL_ERR: nb_cache_buf_tx is 0");
				return;
			}
#endif
			/* Update state */
			__atomic_store_n(&q->shadow_q_tail, data_q_tail, __ATOMIC_RELEASE);
			rte_mempool_put_bulk(q->mp, q->buffer_cache_tx, nb_cache_buf_tx);
			nb_cache_buf_tx = 0;

			/* Update DMA data queue tail to indicate that DMA is done. */
			q->dma_data_q_tail = data_q_tail;
		}
	}

	/* Exit if there are no cops to be processed. */
	if (nb_cops == 0)
		goto state_update;

	/*
	 * Received n completions from rte_cryptodev.
	 * Translate rte_crypto_op output to virtio_crypto output.
	 * Update completion. Trigger DMA.
	 */

	for (i = 0; i < nb_cops; i++) {
		/*
		 * TODO: if flush is not complete, then the loop gets aborted. And all packets
		 * submitted won't be processed. Handle it
		 */
		if (!dao_dma_flush(mem2dev, DAO_VIRTIO_CRYPTO_MAX_CHAIN_WRITE_DESC))
			break;

		buf = RTE_PTR_SUB(cops[i], offsetof(struct dao_virtio_crypto_buffer, cop));
		cmd_src.addr = buf->output_addr;
		cmd_src.length = buf->output_len;

		/*
		 * Copy 1 byte of status after the output data to ensure only one DMA memory chunk.
		 * This will corrupt the crypto_op but it is anyway getting freed after DMA.
		 */
		if (cops[i]->status == RTE_CRYPTO_OP_STATUS_SUCCESS)
			((uint8_t *)(cmd_src.addr))[cmd_src.length] = VIRTIO_CRYPTO_OK;
		else
			((uint8_t *)(cmd_src.addr))[cmd_src.length] = VIRTIO_CRYPTO_ERR;

		cmd_src.length += 1;
		dao_dbg("VIO SRC len: %x", cmd_src.length);

		dao_dma_enq_src_x1(mem2dev, cmd_src.addr, cmd_src.length);

		do {
			vio_desc =
				(struct vring_packed_desc *)DESC_PTR_OFF(desc_base, data_q_tail, 0);
			/*
			 * Set VRING_PACKED_DESC_F_USED bit value to VRING_PACKED_DESC_F_AVAIL
			 * but retain the other bits.
			 */
			vio_desc->flags = (vio_desc->flags & ~VRING_PACKED_DESC_F_USED) |
					  (!!(vio_desc->flags & VRING_PACKED_DESC_F_AVAIL) << 15);
			if (vio_desc->flags & VRING_DESC_F_WRITE) {
				cmd_dst.addr = vio_desc->addr;
				cmd_dst.length = vio_desc->len;
				dao_dma_enq_dst_x1(mem2dev, cmd_dst.addr, cmd_dst.length);
			}

			dao_dbg("VIO DST[%d]DESC addr: %lx", data_q_tail, vio_desc->addr);
			dao_dbg("VIO DST DESC len: %x, id: %x, flags: %x", vio_desc->len,
				vio_desc->id, vio_desc->flags);

			data_q_tail = desc_off_add(data_q_tail, 1, q->q_sz);
		} while (vio_desc->flags & VRING_DESC_F_NEXT);

		q->buffer_cache_tx[nb_cache_buf_tx++] = buf;
	}

	dao_dma_flush(mem2dev, DAO_DMA_MAX_POINTER);

	q->mem2dev_data_dma_idx = mem2dev->tail - 1;

state_update:
	q->nb_cache_buf_tx = nb_cache_buf_tx;
	q->data_q_tail = data_q_tail;

	RTE_SET_USED(flags);
}

static __rte_always_inline uint16_t
virtio_crypto_host_tx(struct virtio_crypto_queue *q, struct rte_crypto_op **cops, uint16_t nb_cops,
		      const uint16_t flags)
{
	struct dao_dma_vchan_info *vchan_info = RTE_PER_LCORE(dao_dma_vchan_info);
	struct dao_dma_vchan_state *mem2dev;
	uint16_t dma_vchan = q->dma_vchan;

	mem2dev = &vchan_info->mem2dev[dma_vchan];

	/* Fetch mem2dev DMA completed status */
	dao_dma_check_compl(mem2dev);

	/* Validate descriptors */
	push_enq_data(q, mem2dev, cops, nb_cops, flags);

	return 0;
}

void
dao_virtio_crypto_tx_desc_dma_completion(uint16_t devid, uint16_t qid)
{
	struct dao_dma_vchan_info *vchan_info = RTE_PER_LCORE(dao_dma_vchan_info);
	struct dao_virtio_cryptodev *cryptodev = &dao_virtio_cryptodevs[devid];
	uint16_t data_q_tail, dma_data_q_tail, nb_cache_buf_tx;
	struct virtio_crypto_queue *q = cryptodev->qs[qid];
	struct dao_dma_vchan_state *mem2dev;
	uint16_t dma_vchan = q->dma_vchan;

	data_q_tail = q->data_q_tail;
	dma_data_q_tail = q->dma_data_q_tail;
	nb_cache_buf_tx = q->nb_cache_buf_tx;

	mem2dev = &vchan_info->mem2dev[dma_vchan];
	dao_dma_check_compl(mem2dev);

	if (data_q_tail != dma_data_q_tail) {
		if (dao_dma_op_status(mem2dev, q->mem2dev_data_dma_idx)) {
			/* Indicate to service core that descriptors are processed. Update
			 * shadow_q_tail. */

			__atomic_store_n(&q->shadow_q_tail, data_q_tail, __ATOMIC_RELEASE);
			rte_mempool_put_bulk(q->mp, q->buffer_cache_tx, nb_cache_buf_tx);
			nb_cache_buf_tx = 0;

			/* Update DMA data queue tail to indicate that DMA is done. */
			q->dma_data_q_tail = data_q_tail;
			q->nb_cache_buf_tx = nb_cache_buf_tx;
		}
	}
}

#define T(name, flags)                                                                             \
	uint16_t virtio_crypto_enq_##name(void *q, struct rte_crypto_op **cops, uint16_t nb_cops)  \
	{                                                                                          \
		return virtio_crypto_host_tx(q, cops, nb_cops, (flags));                           \
	}

VIRTIO_CRYPTO_ENQ_FASTPATH_MODES
#undef T
