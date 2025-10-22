/* SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2025 Marvell.
 */
#ifndef __OCTEP_MBOX_PRIV_H__
#define __OCTEP_MBOX_PRIV_H__

#include "octep_dev_cap.h"

#include <linux/io.h>
#include <linux/iopoll.h>
#include <linux/types.h>

#define OCTEP_HW_REGS_BAR 0
#define OCTEP_HW_MBOX_BAR 4

#define OCTEP_DEV_READY_SIGNATURE 0xBABABABA

#define OCTEP_EPF_RINFO(x)         (0x000209f0 | ((x) << 25))
#define OCTEP_VF_MBOX_DATA(x)      (0x00010210 | ((x) << 17))
#define OCTEP_PF_MBOX_DATA(x)      (0x00022000 | ((x) << 4))
#define OCTEP_VF_IN_CTRL(x)        (0x00010000 | ((x) << 17))
#define OCTEP_VF_IN_CTRL_RPVF(val) (((val) >> 48) & 0xF)

#define OCTEP_FW_READY_SIGNATURE0 0xFFAA5533
#define OCTEP_FW_READY_SIGNATURE1 0xFEEDFEEd
#define OCTEP_MAX_CB_INTR         8

#define OCTEP_HW_TIMEOUT 300000

#define MBOX_RSP_MASK 0x00000001
#define MBOX_RC_MASK  0x0000FFFE

#define MBOX_RSP_TO_ERR(val) (-(((val) & MBOX_RC_MASK) >> 2))
#define MBOX_AVAIL(val)      (((val) & MBOX_RSP_MASK))
#define MBOX_RSP(val)        ((val) & (MBOX_RC_MASK | MBOX_RSP_MASK))

#define DEV_RST_ACK_BIT     7
#define FEATURE_SEL_ACK_BIT 15
#define QUEUE_SEL_ACK_BIT   15

struct octep_mbox_hdr {
	u8 ver;
	u8 rsvd1;
	u16 id;
	u16 rsvd2;
#define MBOX_REQ_SIG (0xdead)
#define MBOX_RSP_SIG (0xbeef)
	u16 sig;
};

struct octep_mbox_sts {
	u16 rsp : 1;
	u16 rc : 15;
	u16 rsvd;
};

struct octep_mbox {
	struct octep_mbox_hdr hdr;
	struct octep_mbox_sts sts;
	u64 rsvd;
	u32 data[];
};

enum octep_rdma_dev_status {
	OCTEP_RDMA_DEV_STATUS_INVALID,
	OCTEP_RDMA_DEV_STATUS_ALLOC,
	OCTEP_RDMA_DEV_STATUS_WAIT_FOR_BAR_INIT,
	OCTEP_RDMA_DEV_STATUS_INIT,
	OCTEP_RDMA_DEV_STATUS_NETDEV_REG,
	OCTEP_RDMA_DEV_STATUS_IBDEV_READY,
	OCTEP_RDMA_DEV_STATUS_UNINIT
};

enum octep_rdma_dev_pci_cfg_type {
	OCTEP_RDMA_DEV_PCI_CAP_NOTIFY_CFG = 1,
	OCTEP_RDMA_DEV_PCI_CAP_DEV_CFG = 2,
	OCTEP_RDMA_DEV_PCI_CAP_MBOX_CFG = 3,
};

enum octep_pci_vndr_cfg_type {
	OCTEP_PCI_VNDR_CFG_TYPE_VIRTIO_ID,
	OCTEP_PCI_VNDR_CFG_TYPE_MAX,
};

/* This is the PCI capability header: */
struct octep_rdma_dev_pci_vndr_cap {
	u8 cap_vndr;   /* Generic PCI field: PCI_CAP_ID_VNDR */
	u8 cap_next;   /* Generic PCI field: next ptr. */
	u8 cap_len;    /* Generic PCI field: capability length */
	u8 cfg_type;   /* Identifies the structure. */
	u16 vendor_id; /* Identifies the vendor-specific format. */
	u8 id;         /* Multiple capabilities of the same type */
	u8 bar;        /* Where to find it. */
	union {
		u64 data; /* Data if bar space is not used. */
		struct {
			u32 offset; /* Offset within bar. */
			u32 length; /* Length of the structure, in bytes. */
		};
	};
	u64 data2;
};

struct octep_caps_region {
	struct pci_dev *pdev;
	u8 __iomem *base[PCI_STD_NUM_BARS];
	struct virtio_pci_common_cfg __iomem *common_cfg;
	u8 __iomem *dev_cfg;
	u8 __iomem *mbox_base;
	u8 __iomem *isr;
	void __iomem *notify_base;
	phys_addr_t notify_base_pa;
	struct mutex mbox_lock; /* lock for synchronization */
	u32 notify_off_multiplier;
	u32 notify_sz;
	int nb_irqs;
	u8 notify_bar;
	u8 dev_id;
};

static inline struct octep_mbox __iomem *
octep_get_mbox(struct octep_caps_region *oct_caps)
{
	return (struct octep_mbox __iomem *)(oct_caps->mbox_base);
}

static inline int
octep_wait_for_mbox_avail(struct octep_mbox __iomem *mbox)
{
	u32 val;

	if (!mbox)
		return -EINVAL;

	return readx_poll_timeout(ioread32, &mbox->sts, val, MBOX_AVAIL(val), 10, OCTEP_HW_TIMEOUT);
}

static inline int
octep_wait_for_mbox_rsp(struct octep_mbox __iomem *mbox)
{
	u32 val;

	if (!mbox)
		return -EINVAL;

	return readx_poll_timeout(ioread32, &mbox->sts, val, MBOX_RSP(val), 10, OCTEP_HW_TIMEOUT);
}

static inline void
octep_write_hdr(struct octep_mbox __iomem *mbox, u16 id, u16 sig)
{
	if (!mbox)
		return;

	iowrite16(id, &mbox->hdr.id);
	iowrite16(sig, &mbox->hdr.sig);
}

static inline u32
octep_read_sig(struct octep_mbox __iomem *mbox)
{
	if (!mbox)
		return 0;

	return ioread16(&mbox->hdr.sig);
}

static inline void
octep_write_sts(struct octep_mbox __iomem *mbox, u32 sts)
{
	if (!mbox)
		return;

	iowrite32(sts, &mbox->sts);
}

static inline u32
octep_read_sts(struct octep_mbox __iomem *mbox)
{
	if (!mbox)
		return 0;

	return ioread32(&mbox->sts);
}

static inline u32
octep_read32_word(struct octep_mbox __iomem *mbox, u16 word_idx)
{
	if (!mbox)
		return 0;

	return ioread32(&mbox->data[word_idx]);
}

static inline void
octep_write32_word(struct octep_mbox __iomem *mbox, u16 word_idx, u32 word)
{
	if (!mbox)
		return;

	iowrite32(word, &mbox->data[word_idx]);
}

static inline void
octep_clear_mbox(struct octep_mbox __iomem *mbox, u16 data_wds)
{
	int i;

	if (!mbox)
		return;

	/* Clear mailbox header and status */
	memset_io(&mbox->hdr, 0, sizeof(struct octep_mbox_hdr));
	memset_io(&mbox->sts, 0, sizeof(struct octep_mbox_sts));

	/* Clear data words */
	for (i = 0; i < data_wds; i++)
		iowrite32(0, &mbox->data[i]);
}

int octep_device_caps_read(struct octep_caps_region *oct_caps, struct pci_dev *pdev);
int octep_rdma_mbox_qp_create(struct octep_caps_region *oct_caps,
			      struct octep_rdma_qp_create_req *qp_req);
int octep_rdma_mbox_qp_state(struct octep_caps_region *oct_caps,
			     struct octep_rdma_qp_state_req *qp_state);
int octep_rdma_mbox_ah_create(struct octep_caps_region *oct_caps,
			      struct octep_rdma_ah_create_req *req);
int octep_rdma_mbox_ah_modify(struct octep_caps_region *oct_caps,
			      struct octep_rdma_ah_create_req *req);
int octep_rdma_mbox_ah_destroy(struct octep_caps_region *oct_caps,
			       struct octep_rdma_ah_destroy_req *req);
int octep_rdma_mbox_cq_create(struct octep_caps_region *oct_caps,
			      struct octep_rdma_cq_create_req *cq_req);
int octep_rdma_mbox_cq_state(struct octep_caps_region *oct_caps,
			     struct octep_rdma_cq_state_req *cq_state);
int octep_rdma_mbox_cq_destroy(struct octep_caps_region *oct_caps,
			       struct octep_rdma_cq_destroy_req *cq_req);
int octep_rdma_mbox_user_qp_modify(struct octep_caps_region *oct_caps,
				   struct octep_rdma_user_qp_modify_req *qp_mod);
int octep_rdma_mbox_qp_destroy(struct octep_caps_region *oct_caps,
			       struct octep_rdma_qp_destroy_req *qp_destroy);
int octep_rdma_mbox_user_port_state(struct octep_caps_region *oct_caps,
				    struct octep_rdma_port_state_req *req);
int octep_rdma_mbox_user_get_device_cap(struct octep_caps_region *oct_caps,
					struct octep_rdma_get_device_cap_msg *msg);
int octep_rdma_mbox_user_get_port_attr(struct octep_caps_region *oct_caps,
				       struct octep_rdma_get_port_attr_msg *msg);
int octep_rdma_mbox_pd_add(struct octep_caps_region *oct_caps,
			   struct octep_rdma_pd_add_req *pd_req);
int octep_rdma_mbox_pd_delete(struct octep_caps_region *oct_caps,
			      struct octep_rdma_pd_delete_req *pd_req);
int octep_rdma_mbox_mr_register(struct octep_caps_region *oct_caps,
				struct octep_rdma_mr_register_req *mr_req);
int octep_rdma_mbox_mr_deregister(struct octep_caps_region *oct_caps,
				  struct octep_rdma_mr_deregister_req *mr_req);

#endif /* __OCTEP_MBOX_PRIV_H__ */
