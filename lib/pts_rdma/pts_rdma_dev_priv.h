/* SPDX-License-Identifier: Marvell-Proprietary
 * Copyright(C) 2025 Marvell.
 */
#ifndef __INCLUDE_RDMA_DEV_PRIV_H__
#define __INCLUDE_RDMA_DEV_PRIV_H__

#include <stddef.h>
#include <stdint.h>

#include <rte_bitmap.h>
#include <rte_dmadev.h>
#include <rte_eal.h>
#include <rte_malloc.h>
#include <rte_vect.h>

#include <dao_dma.h>
#include <dao_log.h>
#include <dao_pem.h>
#include <dao_util.h>

#include <dao_pts_rdma_dev.h>

#define PTS_RDMA_STATIC_ASSERT(s) _Static_assert(s, #s)

#define PTS_RDMA_DEV_PCI_CAP_PTR        0x34
#define PTS_RDMA_DEV_PCI_CAP_CFG_OFFSET PTS_RDMA_DEV_PCI_CAP_PTR + 1

#define PTS_RDMA_DEV_MAX_CB_INTRS 8

#define PCI_CAP_ID_VNDR 0x09
#define PCI_CAP_BAR     4

#define PTS_RDMA_DEV_CQE_SIZE 64
#define PTS_RDMA_DEV_RQE_SIZE 32
#define PTS_RDMA_DEV_SQE_SIZE 64

#define PTS_RDMA_MAX_READ_REQ 1024

PTS_RDMA_STATIC_ASSERT(PTS_RDMA_DEV_CQE_SIZE == sizeof(struct dao_pts_rdma_cqe));
PTS_RDMA_STATIC_ASSERT(PTS_RDMA_DEV_RQE_SIZE == sizeof(union dao_pts_rdma_rqe));
PTS_RDMA_STATIC_ASSERT(PTS_RDMA_DEV_SQE_SIZE == sizeof(union dao_pts_rdma_sqe));

#define PTS_RDMA_DEV_SGE_SIZE 16

#define SQ_DESC_SZ(x)            ((x) * PTS_RDMA_DEV_SQE_SIZE)
#define SQ_DESC_PTR_OFF(b, i, o) (uint64_t *)(((uintptr_t)b) + SQ_DESC_SZ(i) + (o))

#define RQ_DESC_SZ(x)            ((x) * PTS_RDMA_DEV_RQE_SIZE)
#define RQ_DESC_PTR_OFF(b, i, o) (uint64_t *)(((uintptr_t)b) + RQ_DESC_SZ(i) + (o))

#define CQ_DESC_SZ(x)            ((x) * PTS_RDMA_DEV_CQE_SIZE)
#define CQ_DESC_PTR_OFF(b, i, o) (uint64_t *)(((uintptr_t)b) + CQ_DESC_SZ(i) + (o))

/* TODO: Remove this */
#define PTS_RDMA_DEV_IOVA_MASK (DAO_BIT(39) - 1)

#define PTS_RDMA_DEV_CFG_OPAQUE_DATA_SIZE 48

enum pts_rdma_dev_pci_cfg_type {
	PTS_RDMA_DEV_PCI_CAP_NOTIFY_CFG = 1,
	PTS_RDMA_DEV_PCI_CAP_DEV_CFG = 2,
	PTS_RDMA_DEV_PCI_CAP_MBOX_CFG = 3,
};

enum pts_rdma_dev_qp_sts {
	PTS_RDMA_DEV_QP_STS_DISABLE = 0,
	PTS_RDMA_DEV_QP_STS_ENABLE,
};

/* This is the PCI capability header: */
struct pts_rdma_dev_pci_vndr_cap {
	uint8_t cap_vndr;   /* Generic PCI field: PCI_CAP_ID_VNDR */
	uint8_t cap_next;   /* Generic PCI field: next ptr. */
	uint8_t cap_len;    /* Generic PCI field: capability length */
	uint8_t cfg_type;   /* Identifies the structure. */
	uint16_t vendor_id; /* Identifies the vendor-specific format. */
	uint8_t id;         /* Multiple capabilities of the same type */
	uint8_t bar;        /* Where to find it. */
	union {
		uint64_t data; /* Data if bar space is not used. */
		struct {
			uint32_t offset; /* Offset within bar. */
			uint32_t length; /* Length of the structure, in bytes. */
		};
	};
	uint64_t data2;
};

struct pts_rdma_dev_cfg {
	uint32_t max_qps;
	uint32_t max_cqs;
	uint8_t device_status;
	uint8_t opaque_data[PTS_RDMA_DEV_CFG_OPAQUE_DATA_SIZE];
};

struct pts_rdma_cq {
	uintptr_t desc_base __rte_cache_aligned;
	uint16_t *pi_addr;
	uint16_t *ci_addr;
	uint16_t desc_off;
	uint16_t q_sz;
	uint16_t dma_vchan;
	uint16_t cq_id;
	uint16_t enable;
};

struct pts_rdma_cq_data {
	uint64_t *ring_base __rte_cache_aligned;
	uint16_t pi;
	uint16_t ci;
	uint16_t pi_data;
	uint16_t ci_data;
	uint16_t q_sz;
	uint16_t dma_vchan;

	struct pts_rdma_cq *cq;
};

struct pts_rdma_qp {
	struct pts_rdma_qp_sq {
		uintptr_t desc_base __rte_cache_aligned;
		uint16_t *pi_addr;
		uint16_t *ci_addr;
		uint16_t sd_desc_off;
		uint16_t sd_desc_dma_off;
		uint16_t sd_mbuf_off;
		uint16_t sd_mbuf_dma_off;
		uint16_t data_off;
		uint16_t mtu;
		uint16_t last_off;
		uint16_t q_sz;
		uint16_t buf_len;
		uint16_t dma_vchan;
		uint16_t port;
		uint64_t *sd_desc_base;
		struct rte_mempool *mp;
		struct rte_mbuf **mbuf_arr;

		uint16_t cq_id;
		struct pts_rdma_cq_data cq_data;
	} sq;

	struct pts_rdma_qp_rq {
		uintptr_t desc_base __rte_cache_aligned;
		uint16_t *pi_addr;
		uint16_t *ci_addr;
		uint16_t sd_desc_off;
		uint16_t sd_desc_dma_off;
		uint16_t sd_mbuf_off;
		uint16_t q_sz;
		uint16_t dma_vchan;
		uint32_t *sd_desc_base;

		uint16_t cq_id;
		struct pts_rdma_cq_data cq_data;
	} rq;
	struct rte_mbuf **r_mbuf_arr;
	uint16_t r_mbuf_dma_off;
	uint16_t r_mbuf_off;
	uint16_t r_last_off;
	uint16_t r_q_sz;
	uint16_t qp_id;
	uint8_t is_mgmt;
	uint64_t ibqp;
};

struct pts_rdma_dev {
	uint16_t dev_id;
	uint16_t dma_vchan;
	uint16_t pem_devid;
	uint16_t mac_port_id;
	uint64_t bar4;
	size_t bar4_sz;
	size_t host_page_sz;
	uint32_t notify_off_mltpr;
	uint32_t max_qps;
	uint32_t max_cqs;
	uint32_t max_qps_limit;
	uint32_t max_cqs_limit;
	uint32_t max_queues;
	struct rte_mempool *pool;

	volatile struct pts_rdma_dev_cfg *dev_cfg;
	uintptr_t mbox_mem;
	volatile struct dao_pts_rdma_mbox *mbox_h2d;
	volatile struct dao_pts_rdma_mbox *mbox_d2h;
	uintptr_t notify_base;
	uint8_t notify_qs_mltpr;

	uint64_t *cb_intr_addr[PTS_RDMA_DEV_MAX_CB_INTRS];
	uint64_t *cb_ack_addr[PTS_RDMA_DEV_MAX_CB_INTRS];
	uint8_t nb_cb_intrs;

	struct pts_rdma_cq *cqs[DAO_PTS_RDMA_MAX_CQS];

	struct rte_bitmap *qp_bmap;
	void *qp_bmap_mem;

	/* Management QP for non-RDMA (raw Ethernet) traffic, -1 = not configured */
	int32_t mgmt_qp_id;

#define MBOX_USR_RSP_SIZE 1024
	void *mbox_usr_rsp_mem;
};

static inline struct pts_rdma_dev *
pts_rdma_dev_priv(struct dao_pts_rdma_dev *ptsdev)
{
	return (struct pts_rdma_dev *)ptsdev->reserved;
}

static inline struct dao_pts_rdma_dev *
pts_rdma_ptsdev_to_dao(struct pts_rdma_dev *dev)
{
	return (struct dao_pts_rdma_dev *)((uintptr_t)dev -
					   offsetof(struct dao_pts_rdma_dev, reserved));
}

static __rte_always_inline uint16_t
desc_off_add(uint16_t a, uint16_t b, uint16_t q_sz)
{
	return (a + b) & (q_sz - 1);
}

static __rte_always_inline uint16_t
desc_off_diff(uint16_t a, uint16_t b, uint16_t q_sz)
{
	/* Normalize indexes of a and b */
	a = a & (q_sz - 1);
	b = b & (q_sz - 1);
	return a < b ? (q_sz - b + a) : (a - b);
}

static __rte_always_inline uint16_t
is_queue_full(uint16_t pi, uint16_t ci)
{
	return (pi + 1 == ci);
}

static __rte_always_inline uint16_t
alloc_mbufs(struct rte_mbuf **mbuf_arr, struct rte_mempool *mp, uint16_t off, uint16_t q_sz,
	    uint16_t nb_mbufs)
{
	uint16_t cnt;

	cnt = (off + nb_mbufs) > q_sz ? q_sz - off : nb_mbufs;
	if (rte_mempool_get_bulk(mp, (void **)(mbuf_arr + off), cnt))
		return 0;
	off = (off + cnt) & (q_sz - 1);
	cnt = nb_mbufs - cnt;
	if (cnt && rte_mempool_get_bulk(mp, (void **)(mbuf_arr + off), cnt))
		nb_mbufs -= cnt;
	return nb_mbufs;
}

static __rte_always_inline uint16_t
fetch_sq_desc_prep(struct pts_rdma_qp_sq *q, struct dao_dma_vchan_state *dev2mem,
		   struct rte_dma_sge *src, struct rte_dma_sge *dst)
{
	uintptr_t sd_desc_base = (uintptr_t)q->sd_desc_base;
	uintptr_t desc_base = q->desc_base;
	struct rte_mbuf **mbuf_arr;
	uint16_t q_sz = q->q_sz;
	int desc_count = 0;
	uint16_t pi, off;
	int i, j = 0;
	int nb_desc;

	pi = __atomic_load_n(q->pi_addr, __ATOMIC_RELAXED);
	off = q->sd_desc_off;

	nb_desc = desc_off_diff(pi, off, q->q_sz);
	if (unlikely(!nb_desc))
		return 0;

	/* Allocate required mbufs */
	mbuf_arr = q->mbuf_arr;

	nb_desc = alloc_mbufs(mbuf_arr, q->mp, off, q_sz, nb_desc);
	if (unlikely(!nb_desc))
		return 0;

	/* Start DMA of descriptors */
	i = 0;
	do {
		i = (off + nb_desc) > q_sz ? (q_sz - off) : nb_desc;
		src[j].addr = (rte_iova_t)SQ_DESC_PTR_OFF(desc_base, off, 0);
		dst[j].addr = (rte_iova_t)SQ_DESC_PTR_OFF(sd_desc_base, off, 0);
		src[j].length = SQ_DESC_SZ(i);
		dst[j].length = SQ_DESC_SZ(i);

		desc_count += i;
		off = (off + i) & (q_sz - 1);
		nb_desc -= i;
		j++;
	} while (nb_desc);

	q->sd_desc_off = off;
	dao_dma_update_cmpl_meta_v2(dev2mem, &q->sd_desc_dma_off, off, dev2mem->tail);
	return j;
}

static __rte_always_inline uint16_t
fetch_rq_desc_prep(struct pts_rdma_qp_rq *q, struct dao_dma_vchan_state *dev2mem,
		   struct rte_dma_sge *src, struct rte_dma_sge *dst)
{
	uintptr_t sd_desc_base = (uintptr_t)q->sd_desc_base;
	uintptr_t desc_base = q->desc_base;
	uint16_t q_sz = q->q_sz;
	int desc_count = 0;
	uint16_t pi, off;
	int i, j = 0;
	int nb_desc;

	pi = __atomic_load_n(q->pi_addr, __ATOMIC_RELAXED);
	off = q->sd_desc_off;

	nb_desc = desc_off_diff(pi, off, q->q_sz);
	if (unlikely(!nb_desc))
		return 0;

	/* Start DMA of descriptors */
	i = 0;
	do {
		i = (off + nb_desc) > q_sz ? (q_sz - off) : nb_desc;
		src[j].addr = (rte_iova_t)RQ_DESC_PTR_OFF(desc_base, off, 0);
		dst[j].addr = (rte_iova_t)RQ_DESC_PTR_OFF(sd_desc_base, off, 0);
		src[j].length = RQ_DESC_SZ(i);
		dst[j].length = RQ_DESC_SZ(i);

		desc_count += i;
		off = (off + i) & (q_sz - 1);
		nb_desc -= i;
		j++;
	} while (nb_desc);

	q->sd_desc_off = off;
	dao_dma_update_cmpl_meta_v2(dev2mem, &q->sd_desc_dma_off, off, dev2mem->tail);
	return j;
}

static __rte_always_inline uint16_t
push_cq_desc_prep(struct pts_rdma_cq_data *cq_data, struct dao_dma_vchan_state *mem2dev,
		  struct rte_dma_sge *src, struct rte_dma_sge *dst)
{
	uintptr_t ring_base = (uintptr_t)cq_data->ring_base;
	struct pts_rdma_cq *cq = cq_data->cq;
	uintptr_t desc_base = cq->desc_base;
	uint16_t nb_desc, space;
	uint16_t q_sz = cq->q_sz;
	uint16_t pi, ci, hci, hpi;
	int desc_count = 0;
	int i, j = 0;

	pi = __atomic_load_n(&cq_data->pi, __ATOMIC_RELAXED);
	ci = __atomic_load_n(&cq_data->ci_data, __ATOMIC_RELAXED);
	hpi = cq->desc_off;

	/* Skip if there is no desc in local cq ring */
	nb_desc = desc_off_diff(pi, ci, q_sz);
	if (unlikely(!nb_desc))
		return 0;

	/* Skip if there in no space to store the cq desc */
	hci = __atomic_load_n(cq->ci_addr, __ATOMIC_RELAXED);
	space = q_sz - desc_off_diff(hpi, hci, q_sz) - 1;
	if (unlikely(!space))
		return 0;
	nb_desc = RTE_MIN(nb_desc, space);

	/* Start DMA of descriptors */
	i = 0;
	do {
		i = (hpi + nb_desc) > q_sz ? (q_sz - hpi) : nb_desc;
		i = (ci + i) > q_sz ? (q_sz - ci) : i;
		src[j].addr = (rte_iova_t)CQ_DESC_PTR_OFF(ring_base, ci, 0);
		dst[j].addr = (rte_iova_t)CQ_DESC_PTR_OFF(desc_base, hpi, 0);
		src[j].length = i << 6;
		dst[j].length = i << 6;

		desc_count += i;
		hpi = (hpi + i) & (q_sz - 1);
		ci = (ci + i) & (q_sz - 1);
		nb_desc -= i;
		j++;
	} while (nb_desc);

	cq->desc_off = hpi;
	cq_data->ci_data = ci;
	dao_dma_update_cmpl_meta_v2(mem2dev, &cq_data->ci, ci, mem2dev->tail);
	dao_dma_update_cmpl_meta_v2(mem2dev, cq->pi_addr, hpi, mem2dev->tail);
	return j;
}

extern struct dao_pts_rdma_dev_cbs pts_rdma_dev_cbs;
extern struct dao_pts_rdma_dev dao_pts_rdma_devs[DAO_PTS_RDMA_MAX_DEVS];

void pts_rdma_clear_qp_info(struct pts_rdma_dev *dev);
void pts_rdma_sqe_dump(union dao_pts_rdma_sqe *sqe);

#endif /* __INCLUDE_RDMA_DEV_PRIV_H__ */
