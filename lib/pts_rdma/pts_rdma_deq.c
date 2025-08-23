/* SPDX-License-Identifier: Marvell-Proprietary
 * Copyright(C) 2025 Marvell.
 */

#include <rte_common.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>

#include "pts_rdma_dev_priv.h"

#define PTS_RDMA_D2M_MASK                                                                          \
	(1 << DAO_PTS_RDMA_WRITE | 1 << DAO_PTS_RDMA_WRITE_WITH_IMM | 1 << DAO_PTS_RDMA_SEND |     \
	 1 << DAO_PTS_RDMA_SEND_WITH_IMM)

#define PTS_RDMA_M2D_MASK (1 << DAO_PTS_RDMA_READ)

#define PTS_RDMA_SQE_HDR_SZ offsetof(union dao_pts_rdma_sqe, sges0)
#define PTS_RDMA_DATA_OFF   (RTE_PKTMBUF_HEADROOM)

static __rte_always_inline uint16_t
post_process_data(uint16_t devid, struct pts_rdma_qp_sq *sq, struct rte_mbuf **d_mbufs,
		  uint16_t nb_mbufs, const uint16_t flags)
{
	const uint64_t rearm_data =
		(0x100010000ULL | PTS_RDMA_DATA_OFF | ((uint64_t)(devid + RTE_MAX_ETHPORTS) << 48));
	uintptr_t desc_base = (uintptr_t)sq->sd_desc_base;
	uint16_t sd_mbuf_dma_off = sq->sd_mbuf_dma_off;
	uint16_t q_sz = sq->q_sz;
	struct rte_mbuf **mbuf_arr;
	uint8_t opcode, next_desc;
	uint16_t off, num_sges;
	struct rte_mbuf *mbuf;
	uint64_t d_flags, len;
	void *mbuf_priv;
	int i = 0;

	RTE_SET_USED(flags);
	off = sq->last_off;
	mbuf_arr = sq->mbuf_arr;
	mbuf_arr += off;

	while (i < nb_mbufs) {
		d_flags = *SQ_DESC_PTR_OFF(desc_base, off, 0);
		opcode = d_flags & 0xFF;
		num_sges = (d_flags >> 24) & 0xFF;
		next_desc = num_sges > 2 ? RTE_ALIGN_CEIL(num_sges - 2, 4) / 4 : 0;

		/* Stop processing if not all data is not available */
		if (unlikely(desc_off_add(off, next_desc + 1, q_sz) > sd_mbuf_dma_off))
			break;

		mbuf = mbuf_arr[0];
		/* Copy SQE descriptor without SGEs to mbuf */
		mbuf_priv = rte_mbuf_to_priv(mbuf);
		rte_memcpy(mbuf_priv, SQ_DESC_PTR_OFF(desc_base, off, 0), PTS_RDMA_SQE_HDR_SZ);

		if (DAO_BIT(opcode) & PTS_RDMA_M2D_MASK) {
			/* Copy SGEs to mbuf */
			len = sizeof(struct dao_pts_rdma_sge) * num_sges;
			rte_memcpy((uint8_t *)((uintptr_t)mbuf_priv + PTS_RDMA_SQE_HDR_SZ),
				   SQ_DESC_PTR_OFF(desc_base, off, PTS_RDMA_SQE_HDR_SZ), len);
			/* Update mbuf length */
			*((uint64_t *)&mbuf->rearm_data) = rearm_data;
		}

		d_mbufs[i] = mbuf;
		i++;
		off = desc_off_add(off, next_desc + 1, q_sz);
		mbuf_arr += (next_desc + 1);
		if (off == sd_mbuf_dma_off)
			break;
	}

	__atomic_store_n(&sq->last_off, off, __ATOMIC_RELEASE);
	__atomic_store_n(sq->ci_addr, off, __ATOMIC_RELEASE);

	return nb_mbufs;
}

static __rte_always_inline uint16_t
fetch_host_data(uint16_t devid, struct pts_rdma_qp_sq *sq, struct dao_dma_vchan_state *vchan,
		uint16_t hint, const uint16_t flags)
{
	const uint64_t rearm_data =
		(0x100010000ULL | PTS_RDMA_DATA_OFF | ((uint64_t)(devid + RTE_MAX_ETHPORTS) << 48));
	uintptr_t desc_base = (uintptr_t)sq->sd_desc_base;
	struct rte_dma_sge *src = NULL, *dst = NULL;
	uint16_t sd_desc_dma_off, sd_mbuf_off, q_sz;
	uint16_t data_off = sq->data_off;
	uint16_t buf_len = sq->buf_len;
	struct rte_mbuf *mbuf, *mbuf2;
	uint16_t used = 0, num_sges;
	uint32_t nb_mbufs, nb_desc;
	uint32_t i = 0, slen, dlen;
	struct rte_mbuf **mbuf_arr;
	uint8_t opcode, next_desc;
	uint16_t off, mbuf_off;
	int last_idx = 0, j;
	uint64_t d_flags;

	RTE_SET_USED(flags);

	q_sz = sq->q_sz;
	sd_mbuf_off = sq->sd_mbuf_off;
	sd_desc_dma_off = __atomic_load_n(&sq->sd_desc_dma_off, __ATOMIC_ACQUIRE);
	nb_mbufs = desc_off_diff(sd_desc_dma_off, sd_mbuf_off, q_sz);

	/* Return if already something is pending DMA or there are no descriptors to process */
	if (unlikely(!nb_mbufs))
		return 0;

	nb_desc = RTE_MIN(nb_mbufs, hint);
	off = sd_mbuf_off;

	rte_prefetch0(SQ_DESC_PTR_OFF(desc_base, off, 0));
	mbuf_arr = sq->mbuf_arr;
	mbuf_arr += off;

	/* Flush to get minimum space */
	if (!dao_dma_flush(vchan, 1))
		return 0;

	i = 0;
	while (i < nb_desc) {
		d_flags = *SQ_DESC_PTR_OFF(desc_base, off, 0);
		opcode = d_flags & 0xFF;
		num_sges = (d_flags >> 24) & 0xFF;
		next_desc = num_sges > 2 ? RTE_ALIGN_CEIL(num_sges - 2, 4) / 4 : 0;
		/* Stop processing if not all descriptors are available */
		if (unlikely(desc_off_add(off, next_desc + 1, q_sz) > sd_desc_dma_off))
			break;

		/* Skip DMA if xfer is from device to host */
		if (DAO_BIT(opcode) & PTS_RDMA_M2D_MASK)
			continue;

		if (!dao_dma_flush(vchan, num_sges))
			goto exit;

		src = dao_dma_sge_src(vchan);
		dst = dao_dma_sge_dst(vchan);

		/* Copy source sgs */
		slen = *(uint32_t *)SQ_DESC_PTR_OFF(desc_base, off, 40);
		dlen = slen;
		mbuf = mbuf_arr[0];

		src[0].addr = *SQ_DESC_PTR_OFF(desc_base, off, 32) & PTS_RDMA_DEV_IOVA_MASK;
		src[0].length = slen;
		dst[0].addr = (((uintptr_t)mbuf) + data_off);
		dst[0].length = dlen;

		/* Update mbuf length */
		*((uint64_t *)&mbuf->rearm_data) = rearm_data;
		mbuf->pkt_len = slen;
		mbuf->data_len = dlen;
		mbuf->ol_flags = 0;

		/* Handle multi-seg */
		if (unlikely(num_sges > 1 || dlen > buf_len)) {
			struct rte_mbuf *mbuf_n;
			uint32_t len;

			for (j = 1; j < num_sges; j++) {
				src[j].addr = (*SQ_DESC_PTR_OFF(desc_base, off, 32 + 16 * j) &
					       PTS_RDMA_DEV_IOVA_MASK);
				len = *SQ_DESC_PTR_OFF(desc_base, off, 40 + 16 * j);
				src[j].length = len;
				slen += len;
			}
			mbuf->pkt_len = slen;

			/* All dst's required doesn't fit in a request */
			if (buf_len * dao_dma_dst_avail(vchan) < slen)
				goto exit;

			/* Enqueue all dst's */
			dlen = slen;
			len = RTE_MIN(dlen, buf_len);
			dst[0].length = len;
			dlen -= len;
			mbuf->data_len = len;
			j = 1;
			mbuf2 = mbuf;
			while (dlen) {
				len = RTE_MIN(dlen, buf_len);
				dlen -= len;
				if (j < num_sges) {
					mbuf2->next = mbuf_arr[j];
					mbuf2 = mbuf_arr[j];
				} else {
					if (unlikely(rte_mempool_get(sq->mp, (void **)&mbuf_n))) {
						/* Free all mbufs from end of num_sges */
						if (j > num_sges)
							rte_pktmbuf_free(mbuf_arr[num_sges]);
						goto exit;
					}
					mbuf2->next = mbuf_n;
					mbuf2 = mbuf_n;
				}
				dst[j].addr = (((uintptr_t)mbuf2) + data_off);
				dst[j].length = len;
				mbuf2->data_len = len;
				mbuf->nb_segs++;
				j++;
			}
			vchan->src_i += num_sges - 1;
			vchan->dst_i += j - 1;
		}
		vchan->src_i++;
		vchan->dst_i++;

		i += (next_desc + 1);
		off = (off + next_desc + 1) & (q_sz - 1);
		used = i;
		last_idx = vchan->tail;
		mbuf_arr += (next_desc + 1);
		if (!dao_dma_flush(vchan, 1))
			break;
	}

	mbuf_off = desc_off_add(sq->sd_mbuf_off, used, sq->q_sz);
	sq->sd_mbuf_off = mbuf_off;
	dao_dma_update_cmpl_meta_v2(vchan, &sq->sd_mbuf_dma_off, mbuf_off, last_idx);
exit:
	return 0;
}

static __rte_always_inline int
pts_rdma_dequeue_burst(uint16_t devid, struct pts_rdma_qp *qp, struct rte_mbuf **mbufs,
		       uint16_t nb_mbufs, const uint16_t flags)
{
	struct pts_rdma_qp_sq *sq = &qp->sq;
	struct dao_dma_vchan_info *vchan_info = RTE_PER_LCORE(dao_dma_vchan_info);
	uint16_t dma_vchan = sq->dma_vchan;
	struct dao_dma_vchan_state *vchan;
	uint16_t nb_avail, last_off;
	uint16_t sd_mbuf_dma_off;
	uint16_t q_sz;

	vchan = &vchan_info->dev2mem[dma_vchan];

	rte_prefetch0(&sq->last_off);
	/* Update completed DMA ops */
	dao_dma_check_meta_compl(vchan, 0 /* No ATOMIC update */);

	/* Check shadow mbuf status and issue new DMA's for mbuf's */
	fetch_host_data(devid, sq, vchan, 128, flags);
	sd_mbuf_dma_off = sq->sd_mbuf_dma_off;
	last_off = sq->last_off;

	q_sz = sq->q_sz;
	/* Check for available mbufs */
	nb_avail = desc_off_diff(sd_mbuf_dma_off, last_off, q_sz);

	nb_mbufs = RTE_MIN(nb_mbufs, nb_avail);

	/* Return if no mbuf's available */
	if (unlikely(!nb_mbufs))
		goto exit;

	/* Post process packets and fill buffers */
	nb_mbufs = post_process_data(devid, sq, mbufs, nb_mbufs, flags);
exit:
	return nb_mbufs;
}

int
dao_pts_rdma_dequeue_burst(uint16_t devid, int qp_id, struct rte_mbuf **mbufs, uint16_t nb_mbufs)
{
	struct pts_rdma_qp *qp = dao_pts_rdma_devs[devid].qps[qp_id];

	if (unlikely(!qp))
		return -EINVAL;

	return pts_rdma_dequeue_burst(devid, qp, mbufs, nb_mbufs, 0);
}
