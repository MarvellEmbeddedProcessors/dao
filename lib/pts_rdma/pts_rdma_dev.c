/* SPDX-License-Identifier: Marvell-Proprietary
 * Copyright(C) 2025 Marvell.
 */
#include <rte_ethdev.h>
#include <rte_io.h>
#include <rte_malloc.h>

#include "pts_rdma_dev_priv.h"
#include "pts_rdma_mbox.h"

#include "dao_pts_rdma_dev.h"

#define QUEUE_MULTIPLIER     1024
#define NOTIFY_QS_MULTIPLIER 3

struct dao_pts_rdma_dev_cbs pts_rdma_dev_cbs;
struct dao_pts_rdma_dev dao_pts_rdma_devs[DAO_PTS_RDMA_MAX_DEVS];

static int
pts_rdma_dev_dev_cfg_cb(void *ctx, uintptr_t shadow, uint32_t offset, uint64_t val,
			uint64_t shadow_val)
{
	RTE_SET_USED(ctx);
	RTE_SET_USED(shadow);
	RTE_SET_USED(offset);
	RTE_SET_USED(val);
	RTE_SET_USED(shadow_val);
	/* TODO */
	return 0;
}

static void
pts_rdma_dev_signature_add(struct pts_rdma_dev *dev)
{
	uint32_t signature[2];

	/* Add signature for each device at beginning of BAR,
	 * so that host can make sure the rdma firmware is
	 * initialized.
	 */
	signature[0] = 0xffaa5533;
	signature[1] = 0xfeedfeed;

	dao_dev_memcpy((void *)dev->bar4, signature, sizeof(signature));
}

static void
pts_rdma_dev_caps_populate(struct pts_rdma_dev *dev, volatile uint8_t *base)
{
	uint32_t config_base, notify_base, dev_cfg_base, mbox_base;
	volatile struct pts_rdma_dev_pci_vndr_cap *notify_cap;
	volatile struct pts_rdma_dev_pci_vndr_cap *dev_cfg_cap;
	volatile struct pts_rdma_dev_pci_vndr_cap *mbox_cap;
	struct pts_rdma_dev_pci_vndr_cap cap;
	uint32_t cap_end = 0;
	uint64_t off;

	/* Device common config cap */
	config_base = PTS_RDMA_DEV_PCI_CAP_CFG_OFFSET;
	config_base += sizeof(struct pts_rdma_dev_pci_vndr_cap); /* Notify config cap */
	config_base += sizeof(struct pts_rdma_dev_pci_vndr_cap); /* Device config cap */
	config_base += sizeof(struct pts_rdma_dev_pci_vndr_cap); /* Mbox cap */

	/* Device config aligned to 8B */
	dev_cfg_base = RTE_ALIGN(config_base, 8);
	dev->dev_cfg = (volatile struct pts_rdma_dev_cfg *)(base + dev_cfg_base);

	/* Mbox area */
	mbox_base = dev_cfg_base + sizeof(struct pts_rdma_dev_cfg);
	mbox_base = RTE_ALIGN(mbox_base, 8);
	dev->mbox_mem = (uintptr_t)(base + mbox_base);

	/* Notification area aligned to host page size is up to BAR4 end */
	notify_base = mbox_base + PTS_RDMA_DEV_MBOX_SIZE;
	notify_base = RTE_ALIGN(notify_base, dev->host_page_sz);
	dev->notify_base = (uintptr_t)(base + notify_base);

	RTE_ASSERT(notify_base == dev->host_page_sz);
	RTE_ASSERT((notify_base + (dev->max_queues) * dev->notify_off_mltpr) <= dev->bar4_sz);

	*(base + PTS_RDMA_DEV_PCI_CAP_PTR) = PTS_RDMA_DEV_PCI_CAP_CFG_OFFSET;
	cap_end = PTS_RDMA_DEV_PCI_CAP_CFG_OFFSET;

	/* Populate notify cap */
	dao_dbg("[dev %u] rdma_notify_base@%p, offset %u", dev->dev_id, (void *)dev->notify_base,
		notify_base);
	off = dev->notify_off_mltpr;
	dao_dev_memset((volatile void *)dev->notify_base, 0, dev->max_queues * off);
	notify_cap = (volatile struct pts_rdma_dev_pci_vndr_cap *)(base + cap_end);
	memset(&cap, 0, sizeof(cap));
	cap.cap_vndr = PCI_CAP_ID_VNDR;
	cap.cap_len = sizeof(struct pts_rdma_dev_pci_vndr_cap);
	cap.cap_next = cap_end + sizeof(struct pts_rdma_dev_pci_vndr_cap);
	cap.offset = notify_base;
	cap.cfg_type = PTS_RDMA_DEV_PCI_CAP_NOTIFY_CFG;
	cap.bar = PCI_CAP_BAR;
	cap.length = dev->max_qps * NOTIFY_QS_MULTIPLIER * off;
	cap.data2 = off;
	dao_dev_memcpy(notify_cap, &cap, sizeof(cap));
	cap_end += sizeof(struct pts_rdma_dev_pci_vndr_cap);

	/* Populate device config cap */
	dao_dbg("[dev %u] Device config@%p, offset %u", dev->dev_id, (void *)dev->dev_cfg,
		dev_cfg_base);
	dev_cfg_cap = (volatile struct pts_rdma_dev_pci_vndr_cap *)(base + cap_end);
	memset(&cap, 0, sizeof(cap));
	cap.cap_vndr = PCI_CAP_ID_VNDR;
	cap.cap_len = sizeof(struct pts_rdma_dev_pci_vndr_cap);
	cap.cap_next = cap_end + sizeof(struct pts_rdma_dev_pci_vndr_cap);
	cap.offset = dev_cfg_base;
	cap.cfg_type = PTS_RDMA_DEV_PCI_CAP_DEV_CFG;
	cap.bar = PCI_CAP_BAR;
	cap.length = sizeof(struct pts_rdma_dev_cfg);
	dao_dev_memcpy(dev_cfg_cap, &cap, sizeof(cap));
	cap_end += sizeof(struct pts_rdma_dev_pci_vndr_cap);

	/* Populate mbox config cap */
	dao_dbg("[dev %u] Mbox base @%p, offset %u", dev->dev_id, (void *)dev->mbox_mem, mbox_base);
	mbox_cap = (volatile struct pts_rdma_dev_pci_vndr_cap *)(base + cap_end);
	memset(&cap, 0, sizeof(cap));
	cap.cap_vndr = PCI_CAP_ID_VNDR;
	cap.cap_len = sizeof(struct pts_rdma_dev_pci_vndr_cap);
	cap.offset = mbox_base;
	cap.cfg_type = PTS_RDMA_DEV_PCI_CAP_MBOX_CFG;
	cap.bar = PCI_CAP_BAR;
	cap.length = PTS_RDMA_DEV_MBOX_SIZE;
	dao_dev_memcpy(mbox_cap, &cap, sizeof(cap));
	cap_end += sizeof(struct pts_rdma_dev_pci_vndr_cap);
}

static int
pts_rdma_dev_config_populate(struct pts_rdma_dev *dev, uint16_t mac_port_id)
{
	volatile struct pts_rdma_dev_cfg *cfg = (volatile struct pts_rdma_dev_cfg *)dev->dev_cfg;
	struct rte_ether_addr mac_buf = {0};

	cfg->device_status = 0;
	cfg->max_qps = dev->max_qps;
	cfg->max_cqs = dev->max_cqs;

	rte_eth_macaddr_get(mac_port_id, &mac_buf);

	/* Send to device config */
	dao_pts_rdma_dev_config_update(dev->dev_id, mac_buf.addr_bytes, RTE_ETHER_ADDR_LEN);

	return 0;
}

static uint16_t
pts_rdma_dev_max_qps(uint64_t bar4_sz, uint64_t notify_off_mltpr)
{
	uint16_t max_qps;

	/* Assume each queue needs a notify region. Divide the region equally for RQ, SQ & CQ
	 * leaving first page for mbox/capability region.
	 */
	max_qps = ((bar4_sz / notify_off_mltpr) - 1) / NOTIFY_QS_MULTIPLIER;

	return max_qps;
}

int
dao_pts_rdma_dev_init(uint16_t devid, struct dao_pts_rdma_dev_conf *conf)
{
	struct dao_pts_rdma_dev *ptsdev = &dao_pts_rdma_devs[devid];
	struct pts_rdma_dev *dev = pts_rdma_dev_priv(ptsdev);
	uint32_t bmap_mem_sz;
	uint16_t mac_port_id;
	uint16_t mbuf_priv;
	uint8_t *base;
	int rc;

	if (devid >= DAO_PTS_RDMA_MAX_DEVS) {
		dao_err("Invalid device id %u", devid);
		return -EINVAL;
	}

	if (!conf->data_pool) {
		dao_err("Invalid data pool");
		return -EINVAL;
	}

	mbuf_priv = rte_pktmbuf_priv_size(conf->data_pool);
	if (mbuf_priv < PTS_RDMA_DEV_SQE_SIZE * 2) {
		dao_err("Insufficient mbuf priv size %u. Minimum %u needed.", mbuf_priv,
			PTS_RDMA_DEV_SQE_SIZE * 2);
		return -EINVAL;
	}

	dev->dev_id = devid;
	dev->mgmt_qp_id = -1;
	dev->pem_devid = conf->pem_devid;
	dev->dma_vchan = conf->dma_vchan;
	dev->pool = conf->data_pool;

	/* Get BAR4 info for this device */
	rc = dao_pem_vf_region_info_get(dev->pem_devid, dev->dev_id, 4, &dev->bar4, &dev->bar4_sz);
	dao_dbg("dev->pem_devid %d, dev->dev_id %d dev->bar4 0x%lx dev->bar4_sz 0x%lx",
		dev->pem_devid, dev->dev_id, dev->bar4, dev->bar4_sz);
	if (rc) {
		dao_err("[dev %u] Failed to get bar4 region info, rc=%d", dev->dev_id, rc);
		return rc;
	}

	/* Get host page size */
	dev->host_page_sz = dao_pem_host_page_sz(dev->pem_devid);

	/*
	 * Assume each queue needs a notify region. Divide the region equally for RQ, SQ & CQ
	 * leaving first page for mbox/capability region.
	 */
	dev->notify_off_mltpr = QUEUE_MULTIPLIER;
	dev->max_qps = pts_rdma_dev_max_qps(dev->bar4_sz, dev->notify_off_mltpr);
	dev->max_cqs = dev->max_qps;
	dev->notify_qs_mltpr = NOTIFY_QS_MULTIPLIER;
	if (dev->max_qps_limit)
		dev->max_qps = RTE_MIN(dev->max_qps, dev->max_qps_limit);
	else
		dev->max_qps = RTE_MIN(dev->max_qps, DAO_PTS_RDMA_MAX_QPS);

	if (dev->max_cqs_limit)
		dev->max_cqs = RTE_MIN(dev->max_cqs, dev->max_cqs_limit);
	else
		dev->max_cqs = RTE_MIN(dev->max_cqs, DAO_PTS_RDMA_MAX_CQS);

	if (dev->max_cqs < 1 || dev->max_qps < 1) {
		dao_err("[dev %u] BAR4 space sz %luB insufficient for 1 QP, 1 CQ", dev->dev_id,
			dev->bar4_sz);
		return -ENOSPC;
	}

	/* Populate rdma ptsdev PCI cap */
	base = (uint8_t *)dev->bar4;
	pts_rdma_dev_caps_populate(dev, base);

	/* Populate default config */

	mac_port_id = conf->mac_port_id;
	dev->mac_port_id = mac_port_id;
	pts_rdma_dev_config_populate(dev, mac_port_id);

	/* Add signature for each device at beginning of BAR */
	pts_rdma_dev_signature_add(dev);

	/* Setup pts_rdma_dev device host interrupt for the vring call */
	dev->nb_cb_intrs = dao_pem_host_interrupt_setup(dev->pem_devid, dev->dev_id + 1,
							dev->cb_intr_addr, dev->cb_ack_addr);

	dev->mbox_usr_rsp_mem = rte_zmalloc("mbox_usr_rsp_mem", MBOX_USR_RSP_SIZE, 0);
	if (!dev->mbox_usr_rsp_mem)
		return -ENOMEM;

	/* Allocate bitmap to track enabled qps */
	bmap_mem_sz = rte_bitmap_get_memory_footprint(dev->max_qps);
	dev->qp_bmap_mem = rte_zmalloc("qp_bmap_mem", bmap_mem_sz, RTE_CACHE_LINE_SIZE);
	if (!dev->qp_bmap_mem) {
		rc = -ENOMEM;
		goto rsp_mem_free;
	}

	dev->qp_bmap = rte_bitmap_init(dev->max_qps, dev->qp_bmap_mem, bmap_mem_sz);
	if (!dev->qp_bmap) {
		rc = -1;
		goto bmap_mem_free;
	}
	ptsdev->qp_bmap = dev->qp_bmap;

	/* Register control register region */
	rc = dao_pem_ctrl_region_register(dev->pem_devid, (uintptr_t)dev->dev_cfg,
					  sizeof(struct pts_rdma_dev_cfg), pts_rdma_dev_dev_cfg_cb,
					  dev, true);
	if (rc)
		dao_err("[dev %u] Failed to register control region, rc=%d", dev->dev_id, rc);

	rc = pts_rdma_dev_mbox_init(dev);
	if (rc)
		goto unregister_dev_cfg;

	dao_dbg("[dev %u] Configured rdma ptsdev with max_qps=%d max_cqs=%d", dev->dev_id,
		dev->max_qps, dev->max_cqs);

	return 0;

unregister_dev_cfg:
	dao_pem_ctrl_region_unregister(dev->pem_devid, (uintptr_t)dev->dev_cfg,
				       sizeof(struct pts_rdma_dev_cfg), pts_rdma_dev_dev_cfg_cb,
				       dev);
bmap_mem_free:
	rte_free(dev->qp_bmap_mem);
rsp_mem_free:
	rte_free(dev->mbox_usr_rsp_mem);

	return rc;
}

int
dao_pts_rdma_dev_fini(uint16_t devid)
{
	struct dao_pts_rdma_dev *ptsdev = &dao_pts_rdma_devs[devid];
	struct pts_rdma_dev *dev = pts_rdma_dev_priv(ptsdev);
	dao_pts_rdma_dev_reset_cb_t dev_reset_cb;
	int rc;

	dev_reset_cb = pts_rdma_dev_cbs.dev_reset_cb;
	if (dev->dev_cfg->device_status != 0)
		dao_warn("[dev %u] Device not in reset state !! (%u)", dev->dev_id,
			 dev->dev_cfg->device_status);

	pts_rdma_dev_mbox_fini(dev);
	/* Unregister control region from polling */
	rc = dao_pem_ctrl_region_unregister(dev->pem_devid, (uintptr_t)dev->dev_cfg,
					    sizeof(struct pts_rdma_dev_cfg),
					    pts_rdma_dev_dev_cfg_cb, dev);

	/* Clear any pending queue data */
	dev_reset_cb(devid);
	pts_rdma_clear_qp_info(dev);
	rte_free(dev->qp_bmap_mem);
	rte_free(dev->mbox_usr_rsp_mem);

	dao_dev_memset(dev->dev_cfg, 0, sizeof(struct pts_rdma_dev_cfg));
	/* Clear the signature */
	dao_dev_memset((void *)dev->bar4, 0, 16);

	return rc;
}

void
dao_pts_rdma_dev_cb_register(struct dao_pts_rdma_dev_cbs *cbs)
{
	pts_rdma_dev_cbs = *cbs;
}

void
dao_pts_rdma_dev_cb_unregister(void)
{
	memset(&pts_rdma_dev_cbs, 0, sizeof(pts_rdma_dev_cbs));
}

int
dao_pts_rdma_qp_mtu_set(uint16_t devid, uint16_t qp_id, uint16_t mtu)
{
	struct pts_rdma_qp *qp = dao_pts_rdma_devs[devid].qps[qp_id];
	struct pts_rdma_qp_sq *sq;

	if (unlikely(!qp))
		return -EINVAL;

	sq = &qp->sq;
	sq->mtu = mtu;

	dao_dbg("dev[%d] QP%d mtu updated to %u", devid, qp_id, mtu);
	return 0;
}

int
dao_pts_rdma_rq_avail_get(uint16_t devid, uint16_t qp_id, uint16_t *avail)
{
	struct pts_rdma_qp *qp = dao_pts_rdma_devs[devid].qps[qp_id];
	struct pts_rdma_qp_rq *rq;

	if (unlikely(!qp))
		return -EINVAL;

	rq = &qp->rq;
	*avail = desc_off_diff(__atomic_load_n(&rq->sd_desc_dma_off, __ATOMIC_ACQUIRE),
			       rq->sd_mbuf_off, rq->q_sz);

	return 0;
}

int
dao_pts_rdma_dev_info_get(uint16_t pem_devid, uint16_t dev_id, struct dao_pts_rdma_dev_info *info)
{
	uint64_t bar4_sz, notify_off_mltpr;
	uint64_t bar4;
	int rc;

	/* Get BAR4 info for this device */
	rc = dao_pem_vf_region_info_get(pem_devid, dev_id, 4, &bar4, &bar4_sz);
	if (rc) {
		dao_err("[dev %u] Failed to get bar4 region info, rc=%d", dev_id, rc);
		return rc;
	}

	/* Get host page size */
	notify_off_mltpr = QUEUE_MULTIPLIER;

	info->max_qps = pts_rdma_dev_max_qps(bar4_sz, notify_off_mltpr);
	info->max_qps = RTE_MIN(info->max_qps, DAO_PTS_RDMA_MAX_QPS);
	info->max_cqs = info->max_qps;
	info->notify_off_mltpr = notify_off_mltpr;
	info->notify_qs_mltpr = NOTIFY_QS_MULTIPLIER;
	info->bar4_sz = bar4_sz;

	return 0;
}

int
dao_pts_rdma_dev_config_update(uint16_t devid, uint8_t *cfg, uint16_t cfg_len)
{
	struct dao_pts_rdma_dev *ptsdev = &dao_pts_rdma_devs[devid];
	struct pts_rdma_dev *dev = pts_rdma_dev_priv(ptsdev);
	volatile struct pts_rdma_dev_cfg *cfg_reg =
		(volatile struct pts_rdma_dev_cfg *)dev->dev_cfg;

	if (cfg_len > PTS_RDMA_DEV_CFG_OPAQUE_DATA_SIZE || !cfg || !cfg_reg)
		return -EINVAL;

	dao_dev_memcpy(&cfg_reg->opaque_data, cfg, cfg_len);
	dao_dbg("MAC address updated to %02x:%02x:%02x:%02x:%02x:%02x\n", cfg_reg->opaque_data[0],
		cfg_reg->opaque_data[1], cfg_reg->opaque_data[2], cfg_reg->opaque_data[3],
		cfg_reg->opaque_data[4], cfg_reg->opaque_data[5]);
	return 0;
}

int32_t
dao_pts_rdma_mgmt_qp_id_get(uint16_t devid)
{
	struct dao_pts_rdma_dev *dao_dev;
	struct pts_rdma_dev *dev;

	if (devid >= DAO_PTS_RDMA_MAX_DEVS)
		return -1;

	dao_dev = &dao_pts_rdma_devs[devid];
	dev = pts_rdma_dev_priv(dao_dev);

	return dev->mgmt_qp_id;
}

int
dao_pts_rdma_desc_manage(uint16_t devid)
{
	struct dao_pts_rdma_dev *dao_dev = &dao_pts_rdma_devs[devid];
	struct pts_rdma_dev *dev = pts_rdma_dev_priv(dao_dev);
	struct dao_dma_vchan_info *vchan_info = RTE_PER_LCORE(dao_dma_vchan_info);
	struct dao_dma_vchan_state *dev2mem, *mem2dev;
	struct pts_rdma_cq_data *cq_data;
	uint32_t i, cq_req_notify_state;
	struct rte_dma_sge *src, *dst;
	struct pts_rdma_qp *qp;
	struct pts_rdma_cq *cq;
	uint16_t dma_vchan;
	uint16_t sg_i = 0;

	dma_vchan = dev->dma_vchan;
	dev2mem = &vchan_info->dev2mem[dma_vchan];
	mem2dev = &vchan_info->mem2dev[dma_vchan];

	/* Fetch all DMA completed status */
	dao_dma_check_meta_compl_v2(dev2mem, 1 /* ATOMIC update */);
	dao_dma_check_meta_compl_v2(mem2dev, 1 /* ATOMIC update */);

	for (i = 0; i < dev->max_qps; i++) {
		if (!rte_bitmap_get(dev->qp_bmap, i))
			continue;
		if (!dao_dma_flush(dev2mem, DAO_DMA_MAX_POINTER))
			break;

		/* Populate pointers for Host send queue */
		qp = dao_dev->qps[i];
		src = dao_dma_sge_src(dev2mem);
		dst = dao_dma_sge_dst(dev2mem);
		sg_i = fetch_sq_desc_prep(&qp->sq, dev2mem, src, dst);
		dev2mem->src_i += sg_i;
		dev2mem->dst_i += sg_i;

		if (!dao_dma_flush(dev2mem, DAO_DMA_MAX_POINTER))
			break;

		/* Populate pointers for Host Receive queue */
		src = dao_dma_sge_src(dev2mem);
		dst = dao_dma_sge_dst(dev2mem);
		sg_i = fetch_rq_desc_prep(&qp->rq, dev2mem, src, dst);
		dev2mem->src_i += sg_i;
		dev2mem->dst_i += sg_i;

		if (!dao_dma_flush(mem2dev, DAO_DMA_MAX_POINTER))
			break;

		/* Populate pointers for Host Completion queue for send */
		cq_data = &qp->sq.cq_data;
		src = dao_dma_sge_src(mem2dev);
		dst = dao_dma_sge_dst(mem2dev);
		sg_i = push_cq_desc_prep(cq_data, mem2dev, src, dst);
		mem2dev->src_i += sg_i;
		mem2dev->dst_i += sg_i;

		if (!dao_dma_flush(mem2dev, DAO_DMA_MAX_POINTER))
			break;

		/* Populate pointers for Host Completion queue for recv */
		cq_data = &qp->rq.cq_data;
		src = dao_dma_sge_src(mem2dev);
		dst = dao_dma_sge_dst(mem2dev);
		sg_i = push_cq_desc_prep(cq_data, mem2dev, src, dst);
		mem2dev->src_i += sg_i;
		mem2dev->dst_i += sg_i;
	}
	for (i = 0; i < dev->max_cqs; i++) {
		cq = dev->cqs[i];

		if (!cq || !cq->enable)
			continue;

		if (cq->cb_intr_addr && cq->pend_dma &&
		    dao_dma_op_status(mem2dev, cq->pend_dma_idx)) {
			cq->pend_dma = 0;
			cq_req_notify_state =
				__atomic_load_n(cq->cb_cq_req_notify_addr, __ATOMIC_ACQUIRE);
			if (cq_req_notify_state == IB_CQ_NEXT_COMP)
				/* Default state - trigger interrupt for all completions */
				pts_rdma_cq_intr_trigger(cq);
			else if (cq_req_notify_state == IB_CQ_SOLICITED)
				/* FIXME:
				 * Only trigger, if CQE has solicited event bit */
				pts_rdma_cq_intr_trigger(cq);
		}
	}

	return 0;
}
