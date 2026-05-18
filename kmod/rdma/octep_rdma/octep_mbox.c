/* SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2024 Marvell.
 */

#include <linux/pci.h>
#include <linux/pci_regs.h>

#include "octep_mbox.h"
#include "octep_mbox_priv.h"
#ifdef CONFIG_OCTEP_RDMA_OCTTERM
#include "octterm_cdev.h" /* OCTTERM_DDR_REGION_SIZE for cap bounds */
#endif

#define OCTEP_MBOX_OP_WRITE 0x01
#define OCTEP_MBOX_OP_READ 0x02

/*
 * octep_process_mbox - Sleepable mbox command path.
 *
 * Uses mutex to serialize among the many sleepable callers (QP/CQ/MR/PD etc.)
 * so they queue on a sleeping lock instead of busy-spinning.  The mbox
 * availability wait uses the sleepable readx_poll_timeout (CPU-friendly,
 * longer timeout).
 *
 * EP mode: the spinlock is held for the entire MMIO round-trip (write cmd →
 * poll response → read response) to serialize against atomic-context AH
 * callers.  FW responds in <100us so this spin section is brief.
 *
 * Termination mode: DDR round-trip through the PEM polling thread takes
 * 200us+, and the mbox memory is dma_alloc_coherent DDR (non-cacheable on
 * kmod side, cacheable on FW side).  Holding a spinlock during the wait
 * forces atomic busy-poll which can miss FW writes due to the cache-attribute
 * mismatch.  Instead, hold the spinlock only around the write and read phases
 * and use the sleepable readx_poll_timeout for the response wait.  The mutex
 * prevents other sleepable callers from interleaving, and the mbox availability
 * flag (rsp=0 while in-flight) causes any concurrent AH atomic caller to
 * wait/timeout rather than overwrite the in-flight command.
 */
static int octep_process_mbox(struct octep_caps_region *oct_caps, u16 id, void *buffer,
			      u32 buf_size, uint8_t ops)
{
	struct octep_mbox __iomem *mbox = octep_get_mbox(oct_caps);
	struct pci_dev *pdev = oct_caps->pdev;
	u32 *p = (u32 *)buffer;
	u16 data_wds;
	int ret, i;
	u32 val;

	might_sleep();

	if (!IS_ALIGNED(buf_size, 4))
		return -EINVAL;

	mutex_lock(&oct_caps->mbox_lock);

	/* Sleepable wait for mbox to be free from a previous command */
	ret = octep_wait_for_mbox_avail(mbox);
	if (ret) {
		dev_warn(&pdev->dev, "Timeout waiting for mbox availability (id=%u)\n", id);
		goto out_mutex;
	}

	spin_lock(&oct_caps->mbox_atomic_lock);

	data_wds = buf_size / 4;
	octep_clear_mbox(mbox, data_wds);

	if (ops & OCTEP_MBOX_OP_WRITE) {
		for (i = 0; i < data_wds; i++) {
			octep_write32_word(mbox, i, *p);
			p++;
		}
	}
	octep_write_sts(mbox, 0);
	octep_write_hdr(mbox, id, MBOX_REQ_SIG);

#ifdef CONFIG_OCTEP_RDMA_OCTTERM
	spin_unlock(&oct_caps->mbox_atomic_lock);

	ret = octep_wait_for_mbox_rsp(mbox);
	if (ret) {
		dev_warn(&pdev->dev, "Timeout waiting for mbox response (id=%u)\n", id);
		goto out_mutex;
	}

	spin_lock(&oct_caps->mbox_atomic_lock);
#else
	ret = octep_wait_for_mbox_rsp_atomic(mbox);
	if (ret) {
		dev_warn(&pdev->dev, "Timeout waiting for mbox response (id=%u)\n", id);
		goto out_spin;
	}
#endif

	val = octep_read_sig(mbox);
	if ((val & 0xFFFF) != MBOX_RSP_SIG) {
		dev_warn(&pdev->dev, "Invalid mbox signature (id=%u)\n", id);
		ret = -EIO;
		goto out_spin;
	}

	val = octep_read_sts(mbox);
	if (val & MBOX_RC_MASK) {
		ret = MBOX_RSP_TO_ERR(val);
		dev_warn(&pdev->dev, "Mbox FW error (id=%u, err=%d)\n", id, ret);
		ret = -EINVAL;
		goto out_spin;
	}

	if (ops & OCTEP_MBOX_OP_READ) {
		memset(buffer, 0, buf_size);
		p = (u32 *)buffer;
		for (i = 0; i < data_wds; i++)
			*p++ = octep_read32_word(mbox, i);
	}
	ret = 0;

out_spin:
	spin_unlock(&oct_caps->mbox_atomic_lock);
out_mutex:
	mutex_unlock(&oct_caps->mbox_lock);
	return ret;
}

int octep_rdma_mbox_cq_create(struct octep_caps_region *oct_caps,
			      struct octep_rdma_cq_create_req *cq_req)
{
	int ret;

	ret = octep_process_mbox(oct_caps, OCTEP_RDMA_MBOX_MSG_SET_CQ_CONFIG, cq_req,
				 sizeof(struct octep_rdma_cq_create_req), OCTEP_MBOX_OP_WRITE);
	if (ret) {
		dev_err(&oct_caps->pdev->dev, "Failed to create CQ %d\n", cq_req->cq_id);
		return ret;
	}

	ret = octep_process_mbox(oct_caps, OCTEP_RDMA_MBOX_MSG_USER_CQ_CREATE, cq_req,
				 sizeof(struct octep_rdma_cq_create_req), OCTEP_MBOX_OP_WRITE);
	if (ret) {
		struct octep_rdma_cq_destroy_req cq_destroy;
		int cleanup_ret;

		dev_err(&oct_caps->pdev->dev, "Failed to create USER CQ %d\n", cq_req->cq_id);

		/* Clean up transport layer CQ configuration */
		cq_destroy.cq_id = cq_req->cq_id;
		cq_destroy.port_num = cq_req->port_num;
		cleanup_ret =
			octep_process_mbox(oct_caps, OCTEP_RDMA_MBOX_MSG_SET_CQ_CONFIG, &cq_destroy,
					   sizeof(cq_destroy), OCTEP_MBOX_OP_WRITE);
		if (cleanup_ret) {
			dev_warn(&oct_caps->pdev->dev,
				 "Failed to cleanup CQ %d after creation failure\n", cq_req->cq_id);
		}
	}

	return ret;
}

int
octep_rdma_mbox_cq_destroy(struct octep_caps_region *oct_caps,
			   struct octep_rdma_cq_destroy_req *cq_destroy)
{
	int ret;

	ret = octep_process_mbox(oct_caps, OCTEP_RDMA_MBOX_MSG_USER_CQ_DESTROY, cq_destroy,
				 sizeof(struct octep_rdma_cq_destroy_req), OCTEP_MBOX_OP_WRITE);
	if (ret)
		dev_err(&oct_caps->pdev->dev, "Failed to destroy CQ %d\n", cq_destroy->cq_id);

	return ret;
}

int
octep_rdma_mbox_cq_state(struct octep_caps_region *oct_caps,
			 struct octep_rdma_cq_state_req *cq_state)
{
	return octep_process_mbox(oct_caps, OCTEP_RDMA_MBOX_MSG_SET_CQ_STATE, cq_state,
				  sizeof(struct octep_rdma_cq_state_req), OCTEP_MBOX_OP_WRITE);
}

int
octep_rdma_mbox_qp_create(struct octep_caps_region *oct_caps,
			  struct octep_rdma_qp_create_req *qp_req)
{
	int ret;

	ret = octep_process_mbox(oct_caps, OCTEP_RDMA_MBOX_MSG_SET_QP_CONFIG, qp_req,
				 sizeof(struct octep_rdma_qp_create_req), OCTEP_MBOX_OP_WRITE);
	if (ret) {
		dev_err(&oct_caps->pdev->dev, "Failed to set QP %d config\n", qp_req->qp_id);
		return ret;
	}

	ret = octep_process_mbox(oct_caps, OCTEP_RDMA_MBOX_MSG_USER_QP_CREATE, qp_req,
				 sizeof(struct octep_rdma_qp_create_req), OCTEP_MBOX_OP_WRITE);
	if (ret) {
		struct octep_rdma_qp_destroy_req qp_destroy;
		int cleanup_ret;

		dev_err(&oct_caps->pdev->dev, "Failed to create USER QP %d\n", qp_req->qp_id);

		/* Clean up transport layer QP configuration */
		qp_destroy.qp_id = qp_req->qp_id;
		qp_destroy.port_num = qp_req->port_num;
		cleanup_ret =
			octep_process_mbox(oct_caps, OCTEP_RDMA_MBOX_MSG_SET_QP_CONFIG, &qp_destroy,
					   sizeof(qp_destroy), OCTEP_MBOX_OP_WRITE);
		if (cleanup_ret) {
			dev_warn(&oct_caps->pdev->dev,
				 "Failed to cleanup QP %d after creation failure\n", qp_req->qp_id);
		}
	}

	return ret;
}

int
octep_rdma_mbox_qp_state(struct octep_caps_region *oct_caps,
			 struct octep_rdma_qp_state_req *qp_state)
{
	int ret;

	ret = octep_process_mbox(oct_caps, OCTEP_RDMA_MBOX_MSG_SET_QP_STATE, qp_state,
				 sizeof(struct octep_rdma_qp_state_req), OCTEP_MBOX_OP_WRITE);
	if (ret) {
		dev_err(&oct_caps->pdev->dev, "Failed to set QP %d state\n", qp_state->qp_id);
		return ret;
	}

	return ret;
}

int
octep_rdma_mbox_qp_destroy(struct octep_caps_region *oct_caps,
			   struct octep_rdma_qp_destroy_req *qp_destroy)
{
	int ret;

	ret = octep_process_mbox(oct_caps, OCTEP_RDMA_MBOX_MSG_USER_QP_DESTROY, qp_destroy,
				 sizeof(struct octep_rdma_qp_destroy_req), OCTEP_MBOX_OP_WRITE);
	if (ret) {
		dev_err(&oct_caps->pdev->dev, "Failed to destroy QP %d\n", qp_destroy->qp_id);
		return ret;
	}

	return ret;
}

int
octep_rdma_mbox_user_qp_modify(struct octep_caps_region *oct_caps,
			       struct octep_rdma_user_qp_modify_req *qp_mod)
{
	int ret;

	ret = octep_process_mbox(oct_caps, OCTEP_RDMA_MBOX_MSG_USER_QP_MODIFY, qp_mod,
				 sizeof(struct octep_rdma_user_qp_modify_req), OCTEP_MBOX_OP_WRITE);
	if (ret) {
		dev_err(&oct_caps->pdev->dev, "Failed to set QP %d modify\n", qp_mod->qp_id);
		return ret;
	}

	return ret;
}

int
octep_rdma_mbox_pd_add(struct octep_caps_region *oct_caps, struct octep_rdma_pd_add_req *pd_req)
{
	int ret;

	ret = octep_process_mbox(oct_caps, OCTEP_RDMA_MBOX_MSG_USER_PD_ADD, pd_req,
				 sizeof(struct octep_rdma_pd_add_req), OCTEP_MBOX_OP_WRITE);
	if (ret)
		dev_err(&oct_caps->pdev->dev, "Failed to add PD %u\n", pd_req->pd_id);

	return ret;
}

int
octep_rdma_mbox_pd_delete(struct octep_caps_region *oct_caps,
			  struct octep_rdma_pd_delete_req *pd_req)
{
	int ret;

	ret = octep_process_mbox(oct_caps, OCTEP_RDMA_MBOX_MSG_USER_PD_DELETE, pd_req,
				 sizeof(struct octep_rdma_pd_delete_req), OCTEP_MBOX_OP_WRITE);
	if (ret)
		dev_err(&oct_caps->pdev->dev, "Failed to destroy PD %u\n", pd_req->pd_id);

	return ret;
}

int
octep_rdma_mbox_mr_register(struct octep_caps_region *oct_caps,
			    struct octep_rdma_mr_register_req *mr_req)
{
	int ret;

	ret = octep_process_mbox(oct_caps, OCTEP_RDMA_MBOX_MSG_USER_MR_REGISTER, mr_req,
				 sizeof(struct octep_rdma_mr_register_req), OCTEP_MBOX_OP_WRITE);
	if (ret)
		dev_err(&oct_caps->pdev->dev,
			"Failed to register MR: "
			"0x%llx key: %u pd: %u\n",
			mr_req->mr.va, mr_req->mr.key, mr_req->pd_id);

	return ret;
}

int
octep_rdma_mbox_mr_deregister(struct octep_caps_region *oct_caps,
			      struct octep_rdma_mr_deregister_req *mr_req)
{
	int ret;

	ret = octep_process_mbox(oct_caps, OCTEP_RDMA_MBOX_MSG_USER_MR_DEREGISTER, mr_req,
				 sizeof(struct octep_rdma_mr_deregister_req), OCTEP_MBOX_OP_WRITE);
	if (ret)
		dev_err(&oct_caps->pdev->dev,
			"Failed to deregister MR "
			"with key %u, pd id: %u\n",
			mr_req->key, mr_req->pd_id);

	return ret;
}

int
octep_rdma_mbox_ah_create(struct octep_caps_region *oct_caps, struct octep_rdma_ah_create_req *req)
{
	return octep_process_mbox(oct_caps, OCTEP_RDMA_MBOX_MSG_USER_AH_CREATE, req,
				  sizeof(struct octep_rdma_ah_create_req), OCTEP_MBOX_OP_WRITE);
}

int
octep_rdma_mbox_ah_modify(struct octep_caps_region *oct_caps, struct octep_rdma_ah_create_req *req)
{
	return octep_process_mbox(oct_caps, OCTEP_RDMA_MBOX_MSG_USER_AH_MODIFY, req,
				  sizeof(struct octep_rdma_ah_create_req), OCTEP_MBOX_OP_WRITE);
}

int
octep_rdma_mbox_ah_destroy(struct octep_caps_region *oct_caps,
			   struct octep_rdma_ah_destroy_req *req)
{
	return octep_process_mbox(oct_caps, OCTEP_RDMA_MBOX_MSG_USER_AH_DESTROY, req,
				  sizeof(struct octep_rdma_ah_destroy_req), OCTEP_MBOX_OP_WRITE);
}

int
octep_rdma_mbox_user_port_state(struct octep_caps_region *oct_caps,
				struct octep_rdma_port_state_req *req)
{
	int ret;

	ret = octep_process_mbox(oct_caps, OCTEP_RDMA_MBOX_MSG_USER_PORT_STATE, req,
				 sizeof(struct octep_rdma_port_state_req), OCTEP_MBOX_OP_WRITE);
	if (ret) {
		dev_err(&oct_caps->pdev->dev, "Failed to set port state event\n");
		return ret;
	}

	return ret;
}

int
octep_rdma_mbox_user_get_device_cap(struct octep_caps_region *oct_caps,
				    struct octep_rdma_get_device_cap_msg *msg)
{
	int ret;

	ret = octep_process_mbox(oct_caps, OCTEP_RDMA_MBOX_MSG_USER_QUERY_DEVICE_CAP, msg,
				 sizeof(struct octep_rdma_get_device_cap_msg),
				 OCTEP_MBOX_OP_WRITE | OCTEP_MBOX_OP_READ);

	if (ret) {
		dev_err(&oct_caps->pdev->dev, "Failed to get device capabilities\n");
		return ret;
	}

	return ret;
}

int
octep_rdma_mbox_user_get_port_attr(struct octep_caps_region *oct_caps,
				   struct octep_rdma_get_port_attr_msg *msg)
{
	int ret;

	ret = octep_process_mbox(oct_caps, OCTEP_RDMA_MBOX_MSG_USER_QUERY_PORT_ATTR, msg,
				 sizeof(struct octep_rdma_get_port_attr_msg),
				 OCTEP_MBOX_OP_WRITE | OCTEP_MBOX_OP_READ);
	if (ret) {
		dev_err(&oct_caps->pdev->dev, "Failed to get port attributes\n");
		return ret;
	}

	return ret;
}

/*
 * octep_process_mbox_atomic - Atomic-context mbox command path.
 *
 * Skips the mutex (cannot sleep) and uses spinlock + atomic busy-poll
 * wrappers throughout.  Serializes against sleepable callers via the
 * shared mbox_atomic_lock spinlock.  AH commands are write-only.
 */
static int octep_process_mbox_atomic(struct octep_caps_region *oct_caps, u16 id, void *buffer,
				     u32 buf_size)
{
	struct octep_mbox __iomem *mbox = octep_get_mbox(oct_caps);
	struct pci_dev *pdev = oct_caps->pdev;
	u32 *p = (u32 *)buffer;
	u16 data_wds;
	int ret, i;
	u32 val;

	if (!IS_ALIGNED(buf_size, 4))
		return -EINVAL;

	spin_lock(&oct_caps->mbox_atomic_lock);

	ret = octep_wait_for_mbox_avail_atomic(mbox);
	if (ret) {
		dev_warn(&pdev->dev, "Atomic mbox: timeout waiting for availability (id=%u)\n", id);
		goto out;
	}

	data_wds = buf_size / 4;
	octep_clear_mbox(mbox, data_wds);

	for (i = 0; i < data_wds; i++) {
		octep_write32_word(mbox, i, *p);
		p++;
	}
	octep_write_sts(mbox, 0);
	octep_write_hdr(mbox, id, MBOX_REQ_SIG);

	ret = octep_wait_for_mbox_rsp_atomic(mbox);
	if (ret) {
		dev_warn(&pdev->dev, "Atomic mbox: timeout waiting for response (id=%u)\n", id);
		goto out;
	}

	val = octep_read_sig(mbox);
	if ((val & 0xFFFF) != MBOX_RSP_SIG) {
		dev_warn(&pdev->dev, "Atomic mbox: invalid signature (id=%u)\n", id);
		ret = -EIO;
		goto out;
	}

	val = octep_read_sts(mbox);
	if (val & MBOX_RC_MASK) {
		ret = MBOX_RSP_TO_ERR(val);
		dev_warn(&pdev->dev, "Atomic mbox: FW error (id=%u, err=%d)\n", id, ret);
		ret = -EINVAL;
		goto out;
	}
	ret = 0;

out:
	spin_unlock(&oct_caps->mbox_atomic_lock);
	return ret;
}

int octep_rdma_mbox_ah_create_atomic(struct octep_caps_region *oct_caps,
				     struct octep_rdma_ah_create_req *req)
{
	return octep_process_mbox_atomic(oct_caps, OCTEP_RDMA_MBOX_MSG_USER_AH_CREATE, req,
					 sizeof(*req));
}

int octep_rdma_mbox_ah_modify_atomic(struct octep_caps_region *oct_caps,
				     struct octep_rdma_ah_create_req *req)
{
	return octep_process_mbox_atomic(oct_caps, OCTEP_RDMA_MBOX_MSG_USER_AH_MODIFY, req,
					 sizeof(*req));
}

int octep_rdma_mbox_ah_destroy_atomic(struct octep_caps_region *oct_caps,
				      struct octep_rdma_ah_destroy_req *req)
{
	return octep_process_mbox_atomic(oct_caps, OCTEP_RDMA_MBOX_MSG_USER_AH_DESTROY, req,
					 sizeof(*req));
}

static void octep_mbox_init(struct octep_mbox __iomem *mbox)
{
	octep_plat_write32(1, (void __iomem *)&mbox->sts);
}

static void octep_pci_caps_read(struct octep_caps_region *oct_caps, void *buf, size_t len,
				off_t offset)
{
	u8 __iomem *bar = oct_caps->base[OCTEP_HW_MBOX_BAR];
	u8 *p = buf;
	size_t i;

	for (i = 0; i < len; i++)
		*p++ = octep_plat_read8(bar + offset + i);
}

static int
octep_pci_signature_verify(struct octep_caps_region *oct_caps)
{
	u32 signature[2];

	octep_pci_caps_read(oct_caps, &signature, sizeof(signature), 0);

	dev_info(&oct_caps->pdev->dev, "Signature: [0]=0x%08x [1]=0x%08x\n",
		 signature[0], signature[1]);

	if (signature[0] != OCTEP_FW_READY_SIGNATURE0) {
		dev_err(&oct_caps->pdev->dev, "Invalid signature[0]: %x expected %x\n",
			signature[0], OCTEP_FW_READY_SIGNATURE0);
		return -EINVAL;
	}

	if (signature[1] != OCTEP_FW_READY_SIGNATURE1)
		return -EINVAL;

	return 0;
}

static void __iomem *
octep_get_cap_addr(struct octep_caps_region *oct_caps, struct octep_rdma_dev_pci_vndr_cap *cap)
{
	struct device *dev = &oct_caps->pdev->dev;
	u32 length = le32_to_cpu(cap->length);
	u32 offset = le32_to_cpu(cap->offset);
	u8 bar = cap->bar;
	u32 len;

	if (bar != OCTEP_HW_MBOX_BAR) {
		dev_err(dev, "Invalid bar: %u\n", bar);
		return NULL;
	}

	if (offset + length < offset) {
		dev_err(dev, "offset(%u) + length(%u) overflows\n", offset, length);
		return NULL;
	}
#ifdef CONFIG_OCTEP_RDMA_OCTTERM
	len = OCTTERM_DDR_REGION_SIZE;
#else
	len = pci_resource_len(oct_caps->pdev, bar);
#endif
	if (offset + length > len) {
		dev_err(dev, "invalid cap: overflows bar space: %u > %u\n", offset + length, len);
		return NULL;
	}
	return oct_caps->base[bar] + offset;
}

int
octep_device_caps_read(struct octep_caps_region *oct_caps, struct pci_dev *pdev)
{
	struct octep_mbox __iomem *mbox;
	struct device *dev = &pdev->dev;
	struct octep_rdma_dev_pci_vndr_cap cap;
	int ret;
	u8 pos;

	oct_caps->pdev = pdev;
	ret = octep_pci_signature_verify(oct_caps);
	if (ret) {
		dev_err(dev, "Octeon RDMA FW is not initialized\n");
		return -EIO;
	}

	octep_pci_caps_read(oct_caps, &pos, 1, PCI_CAPABILITY_LIST);

	while (pos) {
		octep_pci_caps_read(oct_caps, &cap, 2, pos);

		if (cap.cap_vndr != PCI_CAP_ID_VNDR) {
			dev_err(dev, "Found invalid capability vndr id: %d\n", cap.cap_vndr);
			break;
		}

		octep_pci_caps_read(oct_caps, &cap, sizeof(cap), pos);

		dev_info(dev, "[%2x] cfg type: %u, bar: %u, offset: %04x, len: %u\n", pos,
			 cap.cfg_type, cap.bar, cap.offset, cap.length);

		switch (cap.cfg_type) {
		case OCTEP_RDMA_DEV_PCI_CAP_NOTIFY_CFG:
			oct_caps->notify_base = octep_get_cap_addr(oct_caps, &cap);
			oct_caps->notify_bar = cap.bar;
#ifdef CONFIG_OCTEP_RDMA_OCTTERM
			{
				u32 cap_off = le32_to_cpu(cap.offset);
				u8 __iomem *notify_kva = oct_caps->base[cap.bar] + cap_off;
				unsigned long delta;

				if (!oct_caps->ddr_coherent_va) {
					dev_err(dev, "OCTTERM: notify cap before DDR coherent base set\n");
					return -EIO;
				}
				delta = (unsigned long)((void __force *)notify_kva -
						       (void *)oct_caps->ddr_coherent_va);
				oct_caps->notify_base_pa =
					(phys_addr_t)(oct_caps->ddr_coherent_dma + delta);
			}
#else
			oct_caps->notify_base_pa =
				pci_resource_start(pdev, cap.bar) + le32_to_cpu(cap.offset);
#endif
			oct_caps->notify_off_multiplier = cap.data2;
			oct_caps->notify_sz = cap.length;
			break;
		case OCTEP_RDMA_DEV_PCI_CAP_DEV_CFG:
			oct_caps->dev_cfg = octep_get_cap_addr(oct_caps, &cap);
			break;
		case OCTEP_RDMA_DEV_PCI_CAP_MBOX_CFG:
			oct_caps->mbox_base = octep_get_cap_addr(oct_caps, &cap);
			break;
		}

		pos = cap.cap_next;
	}

	if (!oct_caps->notify_base || !oct_caps->dev_cfg || !oct_caps->mbox_base) {
		dev_err(dev, "Incomplete PCI capabilities");
		return -EIO;
	}

	dev_info(dev, "notify base: %p, notify off multiplier: %u length %u\n",
		 oct_caps->notify_base, oct_caps->notify_off_multiplier, oct_caps->notify_sz);
	dev_info(dev, "device cfg mapped at: %p\n", oct_caps->dev_cfg);
	dev_info(dev, "mbox mapped at: %p\n", oct_caps->mbox_base);

	mbox = octep_get_mbox(oct_caps);
	octep_mbox_init(mbox);

	return 0;
}
