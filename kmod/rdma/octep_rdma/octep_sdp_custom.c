/* SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2024 Marvell.
 */

#include <linux/kthread.h>
#include <linux/wait.h>

#include "octep_rdma.h"
#include "octep_sdp.h"
#include "octep_sdp_regs.h"

static int
__octep_oq_process_rx_custom(struct octep_sdp_dev *octep_dev, struct octep_oq *oq,
			     u16 pkts_to_process)
{
	struct octep_rx_buffer *buff_info;
	struct octep_oq_resp_hw *resp_hw;
	u32 pkt, rx_bytes, desc_used;
	u16 data_offset;
	struct page *page;
	u32 read_idx, i;

	read_idx = READ_ONCE(oq->host_read_idx);
	rx_bytes = 0;
	desc_used = 0;
	for (pkt = 0; pkt < pkts_to_process; pkt++) {
		buff_info = (struct octep_rx_buffer *)&oq->buff_info[read_idx];
		page = buff_info->page;
		dma_unmap_page(oq->dev, oq->desc_ring[read_idx].buffer_ptr, PAGE_SIZE,
			       DMA_FROM_DEVICE);
		resp_hw = page_address(buff_info->page);
		/* Memory barrier */
		smp_rmb();

		dev_dbg(oq->dev, "Allocated buffer[%d] @0x%llx page %p\n", read_idx,
			oq->desc_ring[read_idx].buffer_ptr, page);
		if (unlikely(*((volatile uint64_t *)&resp_hw->length) == 0)) {
			int retry = 100;

			dev_dbg(oq->dev,
				"OQ[%d]: host_read_idx: %d; Data not ready yet, "
				"Retry; pkt=%u, pkt_count=%u, pending=%u\n",
				oq->q_no, oq->host_read_idx, pkt, pkts_to_process,
				oq->pkts_pending);
			oq->stats.pkts_delayed_data++;
			while (retry-- && unlikely(*((volatile uint64_t *)&resp_hw->length) == 0))
				usleep_range(40, 60);
			if (unlikely(!resp_hw->length)) {
				dev_err(oq->dev, "OQ[%d]: ZERO_PKT_LEN pkt:%d SUSPENDED", oq->q_no,
					pkt);
				for (i = 0; i < octep_dev->num_oqs; i++) {
					octep_dev->oq[i]->suspend = true;
					octep_dev->hw_ops.disable_iq(octep_dev, i);
					octep_dev->hw_ops.disable_oq(octep_dev, i);
				}
				oq->desc_ring[read_idx].buffer_ptr =
					dma_map_page(oq->dev, page, 0, PAGE_SIZE, DMA_FROM_DEVICE);
				dev_err(oq->dev, "OQ[%d]: ZERO_PKT_LEN pkt:%d RESUMED", oq->q_no,
					pkt);
				return pkt;
			}
		}
		buff_info->page = NULL;

		/* Swap the length field that is in Big-Endian to CPU */
		buff_info->len = be64_to_cpu(resp_hw->length);
		/* Data is immediately after Hardware Rx response header. */
		data_offset = OCTEP_OQ_RESP_HW_SIZE;
		rx_bytes += buff_info->len;

		dev_dbg(oq->dev,
			"OQ[%d]: host_read_idx %d pkts_to_process %d pending %d "
			"pkt[%d]: len %lld data_off %d max_single_bufer %d\n",
			oq->q_no, read_idx, pkts_to_process, oq->pkts_pending, pkt, buff_info->len,
			data_offset, oq->max_single_buffer_size);

		if (buff_info->len <= oq->max_single_buffer_size) {
			read_idx++;
			desc_used++;
			if (read_idx == oq->max_count)
				read_idx = 0;
		} else {
			u16 data_len;

			read_idx++;
			desc_used++;
			if (read_idx == oq->max_count)
				read_idx = 0;

			data_len = buff_info->len - oq->max_single_buffer_size;
			while (data_len) {
				dma_unmap_page(oq->dev, oq->desc_ring[read_idx].buffer_ptr,
					       PAGE_SIZE, DMA_FROM_DEVICE);
				buff_info = (struct octep_rx_buffer *)&oq->buff_info[read_idx];
				if (data_len < oq->buffer_size) {
					buff_info->len = data_len;
					data_len = 0;
				} else {
					buff_info->len = oq->buffer_size;
					data_len -= oq->buffer_size;
				}

				buff_info->page = NULL;
				read_idx++;
				desc_used++;
				if (read_idx == oq->max_count)
					read_idx = 0;
			}
		}
	}

	WRITE_ONCE(oq->host_read_idx, read_idx);
	oq->refill_count += desc_used;
	oq->stats.packets += pkt;
	oq->stats.bytes += rx_bytes;
	dev_dbg(oq->dev, " OQ-%d: pkts=%d, bytes=%d\n", oq->q_no, pkt, rx_bytes);

	return pkt;
}

static int
octep_oq_process_rx_custom(struct octep_oq *oq, int budget)
{
	u32 pkts_available, pkts_processed, total_pkts_processed;
	struct octep_sdp_dev *octep_dev = oq->octep_dev;
	u32 pkts_pending;

	pkts_available = 0;
	pkts_processed = 0;
	total_pkts_processed = 0;
	while (total_pkts_processed < budget) {
		if (oq->suspend)
			return 0;

		/* update pending count only when current one exhausted */
		pkts_pending = READ_ONCE(oq->pkts_pending);
		if (pkts_pending == 0)
			octep_oq_check_hw_for_pkts(octep_dev, oq);
		pkts_available = min(budget - total_pkts_processed, oq->pkts_pending);
		if (!pkts_available)
			break;

		dev_dbg(oq->dev, "[%s] OQ-%u: pkts_available %u, pkts_pending %u\n", __func__,
			oq->q_no, pkts_available, pkts_pending);
		pkts_processed = __octep_oq_process_rx_custom(octep_dev, oq, pkts_available);
		pkts_pending = READ_ONCE(oq->pkts_pending);
		WRITE_ONCE(oq->pkts_pending, (pkts_pending - pkts_processed));
		total_pkts_processed += pkts_processed;

		if (oq->suspend)
			return 0;
	}

	if (oq->refill_count >= oq->refill_threshold) {
		u32 desc_refilled = octep_oq_refill(octep_dev, oq);

		/* flush pending writes before updating credits */
		smp_wmb();
		writel(desc_refilled, oq->pkts_credit_reg);
	}

	dev_dbg(oq->dev, "[%s] OQ-%u: pkts_processed %u, total_pkts_processed %u\n", __func__,
		oq->q_no, pkts_processed, total_pkts_processed);
	return total_pkts_processed;
}

static int
octep_iq_process_tx_completions_custom(struct octep_iq *iq)
{
	struct octep_sdp_dev *octep_dev = iq->octep_dev;
	u32 compl_pkts, compl_bytes, compl_sg;
	struct octep_tx_buffer *tx_buffer;
	u32 fi = iq->flush_index;
	unsigned long flags;
	void *data;
	u8 frags, i, j = 0;

	compl_pkts = 0;
	compl_sg = 0;
	compl_bytes = 0;
	spin_lock_irqsave(&iq->iq_lock, flags);
	iq->octep_read_index = octep_dev->hw_ops.update_iq_read_idx(iq);

	dev_dbg(&octep_dev->pdev->dev, "[%s] fi %d iq->octep_read_index %d\n", __func__, fi,
		iq->octep_read_index);
	while (likely(fi != iq->octep_read_index)) {
		tx_buffer = iq->buff_info + fi;
		data = tx_buffer->data;

		fi++;
		if (unlikely(fi == iq->max_count))
			fi = 0;
		compl_pkts++;

		if (!tx_buffer->gather) {
			dma_unmap_single(iq->dev, tx_buffer->dma, tx_buffer->nsegs, DMA_TO_DEVICE);
			kunmap(tx_buffer->sg_va_addr[0]);
			put_page(tx_buffer->pages[0]);
			continue;
		} else {
			/* Scatter/Gather */
			frags = tx_buffer->nsegs;

			dev_dbg(&octep_dev->pdev->dev,
				"Freeeing dma mapping %p length %d data %p\n",
				(void *)tx_buffer->sglist[0].dma_ptr[0],
				tx_buffer->sglist[0].len[3], tx_buffer->data);
			dma_unmap_single(iq->dev, tx_buffer->sglist[0].dma_ptr[0],
					 tx_buffer->sglist[0].len[3], DMA_TO_DEVICE);
			kfree(tx_buffer->data);
			tx_buffer->data = NULL;
			i = 1; /* entry 0 is main skb, unmapped above */
			j = 0;
			while (frags) {
				dev_dbg(&octep_dev->pdev->dev,
					"\bFreeing frags %d sg %d dma mapping %p "
					"length %d sg_va_addr %p tx_buffer->pages %p\n",
					frags, j, (void *)tx_buffer->sglist[i >> 2].dma_ptr[i & 3],
					tx_buffer->sglist[i >> 2].len[3 - (i & 3)],
					tx_buffer->sg_va_addr[j], tx_buffer->pages[j]);
				if (tx_buffer->sg_va_addr[j]) {
					dma_unmap_page(iq->dev,
						       tx_buffer->sglist[i >> 2].dma_ptr[i & 3],
						       tx_buffer->sglist[i >> 2].len[3 - (i & 3)],
						       DMA_TO_DEVICE);
					kunmap(tx_buffer->sg_va_addr[j]);
					put_page(tx_buffer->pages[j]);
					i++;
					j++;
					frags--;
				} else {
					dev_err(&octep_dev->pdev->dev,
						"########## Invalid sg_va_addr[%d] %p\n", j,
						tx_buffer->sg_va_addr[j]);
				}
			}
		}
	}

	iq->pkts_processed += compl_pkts;
	iq->flush_index = fi;
	spin_unlock_irqrestore(&iq->iq_lock, flags);

	return 0;
}

static void
octep_update_pkt_custom(struct octep_iq *iq, struct octep_oq *oq)
{
	u32 pkts_processed = READ_ONCE(iq->pkts_processed);
	u32 pkt_in_done = READ_ONCE(iq->pkt_in_done);
	u32 pkts_pend = READ_ONCE(oq->pkts_pending);
	u32 last_pkt_count = READ_ONCE(oq->last_pkt_count);

	if (pkts_processed) {
		writel(pkts_processed, iq->inst_cnt_reg);
		readl(iq->inst_cnt_reg);
		WRITE_ONCE(iq->pkt_in_done, (pkt_in_done - pkts_processed));
		WRITE_ONCE(iq->pkts_processed, 0);
	}
	if (last_pkt_count - pkts_pend) {
		writel(last_pkt_count - pkts_pend, oq->pkts_sent_reg);
		readl(oq->pkts_sent_reg);
		WRITE_ONCE(oq->last_pkt_count, pkts_pend);
	}
	/* Flush the previous wrties before writing to RESEND bit */
	smp_wmb();
}

static irqreturn_t
octep_ioq_intr_custom_handler(int irq, void *data)
{
	struct octep_ioq_vector *ioq_vector = data;
	struct octep_sdp_dev *octep_dev;

	if (!ioq_vector)
		return IRQ_HANDLED;

	octep_dev = ioq_vector->octep_dev;
	if (!octep_dev)
		return IRQ_HANDLED;

	octep_dev->wq_flag = OCTEP_WQ_POST;
	wake_up(&octep_dev->wait_queue);

	return IRQ_HANDLED;
}

static int
octep_register_irqs(struct octep_sdp_dev *octep_dev, int q_no)
{
	struct octep_ioq_vector *ioq_vector;
	struct msix_entry *msix_entry;
	int msix_ent, i, ret;

	msix_ent = octep_dev->iq[q_no]->msix_ent;
	ioq_vector = octep_dev->ioq_vector[q_no];
	msix_entry = &octep_dev->msix_entries[msix_ent];

	if (!msix_entry) {
		dev_err(&octep_dev->pdev->dev, "Invalid MSIX entry %d for Q-%d\n", msix_ent, q_no);
		return -EINVAL;
	}
	i = msix_ent - CFG_GET_NON_IOQ_MSIX(octep_dev->conf);
	snprintf(ioq_vector->name, sizeof(ioq_vector->name), "iovec-q%d", i);
	ret = request_irq(msix_entry->vector, octep_ioq_intr_custom_handler, 0, ioq_vector->name,
			  ioq_vector);
	if (ret) {
		dev_err(&octep_dev->pdev->dev, "request_irq failed for Q-%d; err=%d", i, ret);
		return ret;
	}

	cpumask_set_cpu(i % num_online_cpus(), &ioq_vector->affinity_mask);
	irq_set_affinity_hint(msix_entry->vector, &ioq_vector->affinity_mask);
	return 0;
}

static int
octep_alloc_ioq_vectors_custom(struct octep_sdp_dev *octep_dev, int q_no)
{
	struct octep_ioq_vector *ioq_vector;

	octep_dev->ioq_vector[q_no] = vzalloc(sizeof(*octep_dev->ioq_vector[q_no]));
	if (!octep_dev->ioq_vector[q_no])
		goto free_ioq_vector;

	ioq_vector = octep_dev->ioq_vector[q_no];
	ioq_vector->iq = octep_dev->iq[q_no];
	ioq_vector->oq = octep_dev->oq[q_no];
	ioq_vector->octep_dev = octep_dev;

	dev_info(&octep_dev->pdev->dev, "Allocated IOQ vector %p for q %d\n", ioq_vector, q_no);
	return 0;

free_ioq_vector:
	return -1;
}

static int
octep_update_msix_range(struct octep_sdp_dev *octep_dev, int q_no, bool add)
{
	octep_dev->iq[q_no]->msix_ent = octep_dev->num_irqs + q_no - 1;
	dev_info(&octep_dev->pdev->dev, "[%s %d]: msix_ent %d num_irqs %d\n", __func__, __LINE__,
		 octep_dev->iq[q_no]->msix_ent, octep_dev->num_irqs);

	return 0;
}

int
octep_oq_fill_ring_buffers_custom(struct octep_sdp_dev *octep_dev, int q_no,
				  union octep_rdma_rqe *rqe, int i)
{
	struct octep_oq_desc_hw *desc_ring;
	struct octep_oq_resp_hw *resp_hw;
	struct page *pages[4];
	struct octep_oq *oq;
	long nr_gup;
	void *buf;

	oq = octep_dev->oq[q_no];
	desc_ring = oq->desc_ring;

	buf = (void *)rqe->sges0[0].addr;
	if (!buf) {
		dev_err(oq->dev, "OQ-%d: Invalid buffer address\n", oq->q_no);
		goto dma_map_free;
	}
	nr_gup = get_user_pages_fast((unsigned long)buf, 1, FOLL_WRITE, pages);
	if (nr_gup < 0) {
		dev_err(oq->dev, "OQ-%d: get_user_pages_fast failed\n", oq->q_no);
		goto dma_map_free;
	}

	resp_hw = page_address(pages[0]);
	resp_hw->length = 0x0;

	desc_ring[i].buffer_ptr = dma_map_page(oq->dev, pages[0], 0, PAGE_SIZE, DMA_FROM_DEVICE);
	if (dma_mapping_error(oq->dev, desc_ring[i].buffer_ptr)) {
		dev_err(oq->dev, "OQ-%d buffer alloc: DMA mapping error!\n", oq->q_no);
		goto dma_map_sg_err;
	}
	oq->buff_info[i].page = pages[0];
	dev_dbg(oq->dev, "[%s] OQ-%d Allocated buffer[%d] @0x%llx page %p\n", __func__, oq->q_no, i,
		desc_ring[i].buffer_ptr, oq->buff_info[i].page);

	return 0;

dma_map_sg_err:
	put_page(pages[0]);
dma_map_free:

	return -1;
}

static int
octep_setup_oq_custom(struct octep_sdp_dev *octep_dev, int q_no, u16 rq_size)
{
	struct octep_oq *oq;
	u32 desc_ring_size;

	oq = vzalloc(sizeof(*oq));
	if (!oq)
		goto create_oq_fail;
	octep_dev->oq[q_no] = oq;

	oq->octep_dev = octep_dev;
	oq->dev = &octep_dev->pdev->dev;
	oq->q_no = q_no;
	oq->max_count = rq_size;
	oq->ring_size_mask = oq->max_count - 1;
	oq->buffer_size = CFG_GET_OQ_BUF_SIZE(octep_dev->conf);
	oq->max_single_buffer_size = oq->buffer_size - OCTEP_OQ_RESP_HW_SIZE;

	/* When the hardware/firmware supports additional capabilities,
	 * additional header is filled-in by Octeon after length field in
	 * Rx packets. this header contains additional packet information.
	 */
	if (octep_dev->conf->fw_info.rx_ol_flags)
		oq->max_single_buffer_size -= OCTEP_OQ_RESP_HW_EXT_SIZE;

	oq->refill_threshold = CFG_GET_OQ_REFILL_THRESHOLD(octep_dev->conf);

	desc_ring_size = oq->max_count * OCTEP_OQ_DESC_SIZE;
	oq->desc_ring = dma_alloc_coherent(oq->dev, desc_ring_size, &oq->desc_ring_dma, GFP_KERNEL);

	if (unlikely(!oq->desc_ring)) {
		dev_err(oq->dev, "Failed to allocate DMA memory for OQ-%d !!\n", q_no);
		goto desc_dma_alloc_err;
	}

	oq->buff_info = vzalloc(oq->max_count * OCTEP_OQ_RECVBUF_SIZE);
	if (unlikely(!oq->buff_info)) {
		dev_err(&octep_dev->pdev->dev, "Failed to allocate buffer info for OQ-%d\n", q_no);
		goto buf_list_err;
	}

	octep_oq_reset_indices(oq);
	if (octep_dev->hw_ops.setup_oq_regs(octep_dev, q_no))
		goto oq_fill_buff_err;

	return 0;

oq_fill_buff_err:
	vfree(oq->buff_info);
	oq->buff_info = NULL;
buf_list_err:
	dma_free_coherent(oq->dev, desc_ring_size, oq->desc_ring, oq->desc_ring_dma);
	oq->desc_ring = NULL;
desc_dma_alloc_err:
	vfree(oq);
	octep_dev->oq[q_no] = NULL;
create_oq_fail:
	return -1;
}

static int
octep_setup_iq_custom(struct octep_sdp_dev *octep_dev, int q_no, uint16_t sq_size)
{
	u32 desc_ring_size, buff_info_size, sglist_size;
	struct octep_iq *iq;
	int i;

	iq = vzalloc(sizeof(*iq));
	if (!iq)
		goto iq_alloc_err;
	octep_dev->iq[q_no] = iq;

	iq->octep_dev = octep_dev;
	iq->dev = &octep_dev->pdev->dev;
	iq->q_no = q_no;
	iq->max_count = sq_size;
	iq->ring_size_mask = iq->max_count - 1;
	iq->fill_threshold = CFG_GET_IQ_DB_MIN(octep_dev->conf);

	/* Allocate memory for hardware queue descriptors */
	desc_ring_size = OCTEP_IQ_DESC_SIZE * iq->max_count;

	dev_dbg(&octep_dev->pdev->dev, "IQ-%d: iq->dev %p desc_ring_size %d iq->max_count %d\n",
		q_no, iq->dev, desc_ring_size, iq->max_count);
	if (!desc_ring_size) {
		dev_err(iq->dev, "IQ-%d Invalid ring size %d - iq_num_desc %d\n", q_no,
			iq->max_count, iq->max_count);
		goto desc_dma_alloc_err;
	}
	iq->desc_ring = dma_alloc_coherent(iq->dev, desc_ring_size, &iq->desc_ring_dma, GFP_KERNEL);
	if (unlikely(!iq->desc_ring)) {
		dev_err(iq->dev, "Failed to allocate DMA memory for IQ-%d\n", q_no);
		goto desc_dma_alloc_err;
	}

	/* Allocate memory for hardware SGLIST descriptors */
	sglist_size = OCTEP_SGLIST_SIZE_PER_PKT * iq->max_count;
	iq->sglist = dma_alloc_coherent(iq->dev, sglist_size, &iq->sglist_dma, GFP_KERNEL);
	if (unlikely(!iq->sglist)) {
		dev_err(iq->dev, "Failed to allocate DMA memory for IQ-%d SGLIST\n", q_no);
		goto sglist_alloc_err;
	}

	/* allocate memory to manage Tx packets pending completion */
	buff_info_size = OCTEP_IQ_TXBUFF_INFO_SIZE * iq->max_count;
	iq->buff_info = vzalloc(buff_info_size);
	if (!iq->buff_info) {
		dev_err(iq->dev, "Failed to allocate buff info for IQ-%d\n", q_no);
		goto buff_info_err;
	}

	/* Setup sglist addresses in tx_buffer entries */
	for (i = 0; i < iq->max_count; i++) {
		struct octep_tx_buffer *tx_buffer;

		tx_buffer = &iq->buff_info[i];
		tx_buffer->sglist = &iq->sglist[i * OCTEP_SGLIST_ENTRIES_PER_PKT];
		tx_buffer->sglist_dma = iq->sglist_dma + (i * OCTEP_SGLIST_SIZE_PER_PKT);
	}

	octep_iq_reset_indices(iq);
	octep_dev->hw_ops.setup_iq_regs(octep_dev, q_no);
	spin_lock_init(&iq->iq_lock);

	return 0;

buff_info_err:
	dma_free_coherent(iq->dev, sglist_size, iq->sglist, iq->sglist_dma);
sglist_alloc_err:
	dma_free_coherent(iq->dev, desc_ring_size, iq->desc_ring, iq->desc_ring_dma);
desc_dma_alloc_err:
	vfree(iq);
	octep_dev->iq[q_no] = NULL;
iq_alloc_err:
	return -1;
}

static void
octep_iq_free_pending_custom(struct octep_iq *iq)
{
	struct octep_sdp_dev *octep_dev = iq->octep_dev;
	struct octep_tx_buffer *tx_buffer;
	u32 fi = iq->flush_index;
	void *data;
	u8 frags, i, j = 0;

	while (fi != iq->host_write_index) {
		tx_buffer = iq->buff_info + fi;
		data = tx_buffer->data;

		fi++;
		if (unlikely(fi == iq->max_count))
			fi = 0;

		if (!tx_buffer->gather) {
			dma_unmap_single(iq->dev, tx_buffer->dma, tx_buffer->nsegs, DMA_TO_DEVICE);
			kfree(data);
			kunmap(tx_buffer->sg_va_addr[0]);
			put_page(tx_buffer->pages[0]);
			continue;
		} else {
			/* Scatter/Gather */
			frags = tx_buffer->nsegs;

			dev_dbg(&octep_dev->pdev->dev,
				"Freeeing dma mapping %p length %d "
				"data %p\n",
				(void *)tx_buffer->sglist[0].dma_ptr[0],
				tx_buffer->sglist[0].len[3], tx_buffer->data);
			dma_unmap_single(iq->dev, tx_buffer->sglist[0].dma_ptr[0],
					 tx_buffer->sglist[0].len[3], DMA_TO_DEVICE);
			kfree(tx_buffer->data);
			i = 1; /* entry 0 is main skb, unmapped above */
			j = 0;
			while (frags) {
				dev_dbg(&octep_dev->pdev->dev,
					"\bFreeing frags %d sg %d "
					"dma mapping %p length %d sg_va_addr %p "
					"tx_buffer->pages %p\n",
					frags, j, (void *)tx_buffer->sglist[i >> 2].dma_ptr[i & 3],
					tx_buffer->sglist[i >> 2].len[3 - (i & 3)],
					tx_buffer->sg_va_addr[j], tx_buffer->pages[j]);

				if (!tx_buffer->sg_va_addr[j]) {
					dev_err(&octep_dev->pdev->dev,
						"########## Invalid sg_va_addr %p\n",
						tx_buffer->sg_va_addr[j]);
					return;
				}
				dma_unmap_page(iq->dev, tx_buffer->sglist[i >> 2].dma_ptr[i & 3],
					       tx_buffer->sglist[i >> 2].len[3 - (i & 3)],
					       DMA_TO_DEVICE);
				kunmap(tx_buffer->sg_va_addr[j]);
				put_page(tx_buffer->pages[j]);
				i++;
				j++;
				frags--;
			}
		}
	}

	iq->flush_index = fi;
}

static void
octep_unregister_irq(struct octep_sdp_dev *octep_dev, int q_no)
{
	struct octep_ioq_vector *ioq_vector;
	struct msix_entry *msix_entry;
	int msix_ent;

	msix_ent = octep_dev->iq[q_no]->msix_ent;
	ioq_vector = octep_dev->ioq_vector[q_no];
	msix_entry = &octep_dev->msix_entries[msix_ent];

	irq_set_affinity_hint(msix_entry->vector, NULL);
	free_irq(msix_entry->vector,
		 octep_dev->ioq_vector[msix_ent - CFG_GET_NON_IOQ_MSIX(octep_dev->conf)]);
}

static int
octep_free_oq_custom(struct octep_oq *oq)
{
	struct octep_sdp_dev *octep_dev = oq->octep_dev;
	int q_no = oq->q_no;

	octep_oq_free_ring_buffers(oq);

	vfree(oq->buff_info);

	if (oq->desc_ring)
		dma_free_coherent(oq->dev, oq->max_count * OCTEP_OQ_DESC_SIZE, oq->desc_ring,
				  oq->desc_ring_dma);

	vfree(oq);
	octep_dev->oq[q_no] = NULL;
	return 0;
}

static void
octep_free_iq_custom(struct octep_iq *iq)
{
	struct octep_sdp_dev *octep_dev = iq->octep_dev;
	u64 desc_ring_size, sglist_size;
	int q_no = iq->q_no;

	desc_ring_size = OCTEP_IQ_DESC_SIZE * iq->max_count;

	vfree(iq->buff_info);

	if (iq->desc_ring)
		dma_free_coherent(iq->dev, desc_ring_size, iq->desc_ring, iq->desc_ring_dma);

	sglist_size = OCTEP_SGLIST_SIZE_PER_PKT * iq->max_count;
	if (iq->sglist)
		dma_free_coherent(iq->dev, sglist_size, iq->sglist, iq->sglist_dma);

	vfree(iq);
	octep_dev->iq[q_no] = NULL;
}

static void
octep_worker_thread_exit(struct octep_sdp_dev *octep_dev)
{
	if (octep_dev->wq_state == OCTEP_WQ_UNINITIALIZED ||
	    octep_dev->wq_state == OCTEP_WQ_EXITED) {
		dev_err(&octep_dev->pdev->dev, "Worker thread not running\n");
		return;
	}

	/* Command the worker thread to stop and wait for it to exit */
	kthread_stop(octep_dev->thread);
	wake_up(&octep_dev->wait_queue);
	dev_info(&octep_dev->pdev->dev, "Worker thread stopped\n");
}

static int
octep_rdma_wq_thread(void *data)
{
	int ret;
	struct octep_sdp_dev *octep_dev = (struct octep_sdp_dev *)data;
	struct octep_iq *iq;
	struct octep_oq *oq;
	u32 tx_pending, rx_done = 0;

	octep_dev->wq_state = OCTEP_WQ_RUNNING;

	iq = octep_dev->iq[1];
	if (!iq) {
		dev_err(&octep_dev->pdev->dev, "IQ not initialized\n");
		goto fail;
	}

	oq = octep_dev->oq[1];
	if (!oq) {
		dev_err(&octep_dev->pdev->dev, "OQ not initialized\n");
		goto fail;
	}

	dev_info(&octep_dev->pdev->dev, "Worker thread started\n");
	while (!kthread_should_stop()) {
		/* Wait for new work requests to be posted */
		ret = wait_event_killable(octep_dev->wait_queue,
					  octep_dev->wq_flag != OCTEP_WQ_EMPTY ||
						  kthread_should_stop());
		if (ret) {
			dev_err(&octep_dev->pdev->dev, "Wait event killable failed\n");
			break;
		}

		/* Process all new work requests */
		octep_dev->wq_flag = OCTEP_WQ_EMPTY;

		tx_pending = octep_iq_process_tx_completions_custom(iq);
		rx_done = octep_oq_process_rx_custom(oq, 32);
		octep_update_pkt_custom(iq, oq);

		/* Resend the interrupt */
		writeq(1UL << OCTEP_OQ_INTR_RESEND_BIT, oq->pkts_sent_reg);
		writeq(1UL << OCTEP_IQ_INTR_RESEND_BIT, iq->inst_cnt_reg);
	}

	octep_dev->wq_state = OCTEP_WQ_EXITED;
	dev_info(&octep_dev->pdev->dev, "Worker thread exiting\n");

	return 0;
fail:
	octep_dev->wq_state = OCTEP_WQ_EXITED;
	return -1;
}

static int
octep_worker_thread_setup(struct octep_sdp_dev *octep_dev)
{
	/* Initialize wait queue */
	init_waitqueue_head(&octep_dev->wait_queue);
	octep_dev->wq_state = OCTEP_WQ_INITIALIZED;
	octep_dev->wq_flag = OCTEP_WQ_EMPTY;

	/* Create worker thread */
	octep_dev->thread =
		kthread_create(octep_rdma_wq_thread, (void *)octep_dev, "Oct WK Thread");
	if (!octep_dev->thread) {
		dev_err(&octep_dev->pdev->dev, "Failed to create worker thread\n");
		octep_dev->wq_state = OCTEP_WQ_UNINITIALIZED;
		return -EINVAL;
	}
	/* Start worker thread */
	wake_up_process(octep_dev->thread);
	return 0;
}

int
octep_device_qp_release(struct octep_sdp_dev *octep_dev, int q_no)
{
	struct msix_entry *msix_entry;
	int msix_ent, ret;

	octep_worker_thread_exit(octep_dev);
	ret = octep_dev->hw_ops.octep_update_config_active_io_ring(octep_dev, false);
	if (ret)
		dev_err(&octep_dev->pdev->dev, "Failed to update active io ring\n");

	octep_dev->hw_ops.enable_interrupts(octep_dev);
	msix_ent = octep_dev->iq[q_no]->msix_ent;
	msix_entry = &octep_dev->msix_entries[msix_ent];
	octep_unregister_irq(octep_dev, q_no);
	if (octep_dev->ioq_vector[q_no]) {
		vfree(octep_dev->ioq_vector[q_no]);
		octep_dev->ioq_vector[q_no] = NULL;
	}

	dev_dbg(&octep_dev->pdev->dev,
		"[%s] Freeing IOQ vector %p for q %d msix_ent %d vector %d\n", __func__,
		octep_dev->ioq_vector[q_no], q_no, msix_ent, msix_entry->vector);

	octep_iq_free_pending_custom(octep_dev->iq[q_no]);
	octep_iq_reset_indices(octep_dev->iq[q_no]);

	octep_dev->hw_ops.disable_iq(octep_dev, q_no);
	octep_dev->hw_ops.disable_oq(octep_dev, q_no);
	octep_dev->hw_ops.reset_iqueue(octep_dev, q_no);
	octep_free_oq_custom(octep_dev->oq[q_no]);
	octep_free_iq_custom(octep_dev->iq[q_no]);

	dev_info(&octep_dev->pdev->dev, "Device QP %d release successful\n", q_no);

	return 0;
}

int
octep_device_qp_setup(struct octep_sdp_dev *octep_dev, int q_no, uint16_t sq_size, uint16_t rq_size)
{
	int ret;

	ret = octep_setup_iq_custom(octep_dev, q_no, sq_size);
	if (ret)
		goto iq_setup_err;

	ret = octep_setup_oq_custom(octep_dev, q_no, rq_size);
	if (ret)
		goto oq_setup_err;

	ret = octep_alloc_ioq_vectors_custom(octep_dev, q_no);
	if (ret)
		goto ioq_vector_err;

	ret = octep_update_msix_range(octep_dev, q_no, true);
	if (ret)
		goto msix_range_err;

	ret = octep_register_irqs(octep_dev, q_no);
	if (ret)
		goto irq_reg_err;

	octep_dev->hw_ops.enable_iq(octep_dev, q_no);
	octep_dev->hw_ops.enable_oq(octep_dev, q_no);

	ret = octep_dev->hw_ops.octep_update_config_active_io_ring(octep_dev, true);
	if (ret) {
		dev_err(&octep_dev->pdev->dev, "Failed to update active io ring\n");
		goto disable_iq_err;
	}

	octep_dev->hw_ops.enable_interrupts(octep_dev);

	writel(octep_dev->oq[q_no]->max_count, octep_dev->oq[q_no]->pkts_credit_reg);
	ret = octep_worker_thread_setup(octep_dev);
	if (ret)
		goto disable_iq_err;

	return 0;
disable_iq_err:
	octep_dev->hw_ops.disable_iq(octep_dev, q_no);
	octep_dev->hw_ops.disable_oq(octep_dev, q_no);
irq_reg_err:
	octep_update_msix_range(octep_dev, q_no, false);
msix_range_err:
	vfree(octep_dev->ioq_vector[q_no]);
	octep_dev->ioq_vector[q_no] = NULL;
ioq_vector_err:
	octep_free_oq_custom(octep_dev->oq[q_no]);
oq_setup_err:
	octep_free_iq_custom(octep_dev->iq[q_no]);
iq_setup_err:
	return -1;
}

static int
prepare_tx_buffer(struct octep_tx_buffer *tx_buffer, struct octep_iq *iq, union octep_rdma_sqe *sqe)
{
	struct octep_sdp_dev *octep_dev = iq->octep_dev;
	struct octep_tx_sglist_desc *sglist;
	struct page *pages[10];
	void *virt_addr_ptr;
	void *buf, *data;
	int length, ret;
	long nr_gup;

	/* Scatter/Gather */
	u16 nsegs, si, j, nr_segs;
	dma_addr_t dma;

	sglist = tx_buffer->sglist;

	nsegs = 1;
	nr_segs = nsegs + 1;
	tx_buffer->gather = 1;

	virt_addr_ptr = (void *)sqe;
	length = sizeof(union octep_rdma_sqe);
	data = kmalloc(length, GFP_KERNEL);
	if (!data) {
		dev_err(&octep_dev->pdev->dev, "Failed to allocate data\n");
		return -1;
	}
	memcpy(data, virt_addr_ptr, length);
	dma = dma_map_single(iq->dev, data, length, DMA_TO_DEVICE);
	if (dma_mapping_error(iq->dev, dma)) {
		dev_err(&octep_dev->pdev->dev, "Failed to map dma length %d\n", length);
		goto dma_map_err;
	}
	dev_dbg(&octep_dev->pdev->dev, "Allocated dma mapping %p data %p length %d\n", (void *)dma,
		data, length);

	memset(sglist, 0, OCTEP_SGLIST_SIZE_PER_PKT);
	sglist[0].len[3] = length;
	sglist[0].dma_ptr[0] = dma;

	tx_buffer->data = data;
	tx_buffer->nsegs = nsegs;
	dev_dbg(&octep_dev->pdev->dev, "virt_addr_ptr %p length %d dma %p sqe->nr_segs %d\n",
		virt_addr_ptr, length, (void *)sglist[0].dma_ptr[0], sqe->num_sges);

	si = 1; /* entry 0 is main skb, mapped above */
	j = 0;
	while (nsegs--) {
		buf = (void *)sqe->sges0[j].addr;
		length = sqe->sges0[j].length;
		nr_gup = get_user_pages_fast((unsigned long)buf, 1, FOLL_WRITE, pages);
		if (nr_gup < 0) {
			dev_err(&octep_dev->pdev->dev,
				"[%s] get_user_pages_fast failed: j %d buf 0x%lx, err %ld\n",
				__func__, j, (unsigned long)buf, nr_gup);
			print_hex_dump(KERN_DEBUG, "SQE: ", DUMP_PREFIX_OFFSET, 16, 1, sqe,
				       sizeof(union octep_rdma_sqe), true);
			ret = nr_gup;
			goto dma_map_free;
		}

		virt_addr_ptr = kmap(pages[j]);
		if (!virt_addr_ptr) {
			dev_err(&octep_dev->pdev->dev, "Failed to map page\n");
			goto put_page;
		}
		dma = dma_map_single(iq->dev, virt_addr_ptr, length, DMA_TO_DEVICE);
		if (dma_mapping_error(iq->dev, tx_buffer->dma)) {
			dev_err(&octep_dev->pdev->dev, "Failed to map dma sg\n");
			goto dma_map_sg_err;
		}
		dev_dbg(&octep_dev->pdev->dev,
			"\bAllocated sg %d dma mapping %p length %d "
			"sg_va_addr %p pages %p\n",
			j, (void *)dma, length, virt_addr_ptr, pages[j]);

		sglist[si >> 2].len[3 - (si & 3)] = length;
		sglist[si >> 2].dma_ptr[si & 3] = dma;

		tx_buffer->pages[j] = pages[j];
		tx_buffer->sg_va_addr[j] = virt_addr_ptr;
		si++;
		j++;
	}

	return nr_segs;
dma_map_sg_err:
	kunmap(pages[0]);
put_page:
	put_page(pages[0]);
dma_map_free:
	dma_unmap_single(iq->dev, sglist[0].dma_ptr[0], sglist[0].len[0], DMA_TO_DEVICE);
	sglist[0].len[0] = 0;
dma_map_err:
	kfree(data);
	return ret;
}

int
octep_tx(struct octep_sdp_dev *octep_dev, int q_no, union octep_rdma_sqe *sqe)
{
	struct octep_tx_buffer *tx_buffer;
	struct octep_tx_desc_hw *hw_desc;
	struct octep_instr_hdr *ih;
	struct octep_iq *iq;
	unsigned long flags;
	int length, ret;
	u16 wi, nsegs;

	length = sqe->sges0[0].length + sizeof(union octep_rdma_sqe);
	iq = octep_dev->iq[q_no];

	spin_lock_irqsave(&iq->iq_lock, flags);
	wi = iq->host_write_index;
	hw_desc = &iq->desc_ring[wi];
	hw_desc->ih64 = 0;

	tx_buffer = iq->buff_info + wi;

	ih = &hw_desc->ih;
	/* TODO prefill */
	ih->pkind = octep_dev->conf->fw_info.pkind;
	ih->fsz = octep_dev->conf->fw_info.fsz;
	ih->tlen = length + ih->fsz;
	/* FIXME */
	ih->tlen = length;

	nsegs = prepare_tx_buffer(tx_buffer, iq, sqe);
	if (nsegs < 0) {
		dev_err(&octep_dev->pdev->dev, "Failed to prepare tx buffer\n");
		ret = nsegs;
		goto dma_map_err;
	}

	ih->gsz = nsegs;
	ih->gather = tx_buffer->gather;
	hw_desc->dptr = tx_buffer->sglist_dma;

	iq->fill_cnt++;
	wi++;
	iq->host_write_index = wi & iq->ring_size_mask;

	/* Flush the hw descriptors before writing to doorbell */
	smp_wmb();
	writel(iq->fill_cnt, iq->doorbell_reg);
	spin_unlock_irqrestore(&iq->iq_lock, flags);
	iq->stats.instr_posted += iq->fill_cnt;
	dev_dbg(&octep_dev->pdev->dev,
		"TxQ-%d: Addr 0x%llx tlen %d fsz %d Doorbell write %d iq->fill_cnt %d wi %d\n",
		q_no, hw_desc->dptr, ih->tlen, ih->fsz, iq->host_write_index, iq->fill_cnt, wi);
	iq->fill_cnt = 0;
	return 0;
dma_map_err:
	return ret;
}
