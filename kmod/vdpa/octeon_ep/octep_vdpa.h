/* SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 Marvell.
 */
#ifndef __OCTEP_VDPA_H__
#define __OCTEP_VDPA_H__

#include <linux/interrupt.h>
#include <linux/pci.h>
#include <linux/pci_regs.h>
#include <linux/vdpa.h>
#include <linux/virtio_pci_modern.h>
#include <uapi/linux/vdpa.h>
#include <uapi/linux/virtio_blk.h>
#include <uapi/linux/virtio_config.h>
#include <uapi/linux/virtio_crypto.h>
#include <uapi/linux/virtio_net.h>
#include <uapi/linux/virtio_pci.h>

#define OCTEP_VDPA_DEVID_CN106K_PF 0xb900
#define OCTEP_VDPA_DEVID_CN106K_VF 0xb903
#define OCTEP_VDPA_DEVID_CN105K_PF 0xba00
#define OCTEP_VDPA_DEVID_CN105K_VF 0xba03
#define OCTEP_VDPA_DEVID_CN103K_PF 0xbd00
#define OCTEP_VDPA_DEVID_CN103K_VF 0xbd03

#define OCTEP_DEV_READY_SIGNATURE 0xBABABABA

#define OCTEP_EPF_RINFO(x) (0x000209f0 | ((x) << 25))
#define OCTEP_VF_MBOX_DATA(x) (0x00010210 | ((x) << 17))
#define OCTEP_PF_MBOX_DATA(x) (0x00022000 | ((x) << 4))
#define OCTEP_VF_EVENT_STATE(x) (0x00010030 | ((x) << 17))
#define OCTEP_VF_EVENT_REG(x) (0x00010060 | ((x) << 17))
#define OCTEP_VF_IN_CTRL(x)        (0x00010000 | ((x) << 17))
#define OCTEP_VF_IN_CTRL_RPVF(val) (FIELD_GET(GENMASK_ULL(51, 48), val))

#define OCTEP_FW_READY_SIGNATURE0  0xFEEDFEED
#define OCTEP_FW_READY_SIGNATURE1  0x3355ffaa
#define OCTEP_MAX_CB_INTR          8

enum octep_vdpa_dev_status {
	OCTEP_VDPA_DEV_STATUS_INVALID,
	OCTEP_VDPA_DEV_STATUS_ALLOC,
	OCTEP_VDPA_DEV_STATUS_WAIT_FOR_BAR_INIT,
	OCTEP_VDPA_DEV_STATUS_INIT,
	OCTEP_VDPA_DEV_STATUS_READY,
	OCTEP_VDPA_DEV_STATUS_ADDED,
	OCTEP_VDPA_DEV_STATUS_REMOVED,
	OCTEP_VDPA_DEV_STATUS_UNINIT
};

enum octep_vdpa_dev_event_state {
	OCTEP_VDPA_DEV_NO_EVENT,
	OCTEP_VDPA_DEV_NEW_EVENT,
	OCTEP_VDPA_DEV_EVENT_ACTIVE,
	OCTEP_VDPA_DEV_EVENT_DONE,
};

enum octep_vdpa_dev_event {
	OCTEP_VDPA_DEV_EVENT_NONE,
	OCTEP_VDPA_DEV_EVENT_ACK,
	OCTEP_VDPA_DEV_EVENT_NACK,
	OCTEP_VDPA_DEV_ADD_EVENT,
	OCTEP_VDPA_DEV_DEL_EVENT,
};

struct octep_vring_info {
	struct vdpa_callback cb;
	void __iomem *notify_addr;
	void __iomem *cb_notify_addr;
	phys_addr_t notify_pa;
};

enum octep_pci_vndr_cfg_type {
	OCTEP_PCI_VNDR_CFG_TYPE_VIRTIO_ID,
	OCTEP_PCI_VNDR_CFG_TYPE_MAX,
};

enum octep_dev_type {
	OCTEP_DEV_TYPE_PCI,
	OCTEP_DEV_TYPE_PLATFORM,
	OCTEP_DEV_TYPE_MAX,
};

struct octep_pci_vndr_data {
	u8 cap_vndr;
	u8 cap_next;
	u8 cap_len;
	u8 cfg_type;
	u16 vendor_id;
	u8 id;
	u8 bar;
	union {
		u64 data;
		struct {
			u32 offset;
			u32 length;
		};
	};
};

/* Forward declaration */
struct octep_hw;

struct octep_hw_ops {
	/* IRQ management */
	int (*request_irqs)(struct octep_hw *oct_hw, irqreturn_t (*handler)(int, void *),
			    int nb_irqs);
	void (*free_irqs)(struct octep_hw *oct_hw);

	/* Device events */
	irqreturn_t (*handle_event)(int irq, void *data);
};

struct octep_hw {
	struct device *dev;
	struct device *dma_dev;
	const struct octep_hw_ops *ops;
	u8 __iomem *base[PCI_STD_NUM_BARS];
	struct virtio_pci_common_cfg __iomem *common_cfg;
	u8 __iomem *dev_cfg;
	u8 __iomem *isr;
	void __iomem *notify_base;
	phys_addr_t notify_base_pa;
	u32 notify_off_multiplier;
	u8 notify_bar;
	u8 caps_bar;
	struct octep_vring_info *vqs;
	struct vdpa_callback config_cb;
	enum octep_dev_type dev_type;
	u64 features;
	u16 nr_vring;
	u32 config_size;
	int requested_irqs;
	int nb_irqs;
	int *irqs;
	u8 dev_id;
};

struct octep_vdpa_event_wk {
	struct work_struct work;
	void *ctxptr;
};

struct octep_vdpa {
	struct vdpa_device vdpa;
	struct octep_hw *oct_hw;
};

struct octep_vdpa_mgmt_dev {
	struct vdpa_mgmt_dev mdev;
	struct octep_hw oct_hw;
	/* Work entry to handle device setup */
	struct work_struct setup_task;
	/* Device status */
	atomic_t status;
	struct octep_vdpa *oct_vdpa;
	struct octep_vdpa_event_wk event_wk;
};

u8 octep_hw_get_status(struct octep_hw *oct_hw);
void octep_hw_set_status(struct octep_hw *dev, uint8_t status);
void octep_hw_reset(struct octep_hw *oct_hw);
void octep_write_queue_select(struct octep_hw *oct_hw, u16 queue_id);
void octep_notify_queue(struct octep_hw *oct_hw, u16 qid);
void octep_read_dev_config(struct octep_hw *oct_hw, u64 offset, void *dst, int length);
int octep_set_vq_address(struct octep_hw *oct_hw, u16 qid, u64 desc_area, u64 driver_area,
			 u64 device_area);
void octep_set_vq_num(struct octep_hw *oct_hw, u16 qid, u32 num);
void octep_set_vq_ready(struct octep_hw *oct_hw, u16 qid, bool ready);
bool octep_get_vq_ready(struct octep_hw *oct_hw, u16 qid);
int octep_set_vq_state(struct octep_hw *oct_hw, u16 qid, const struct vdpa_vq_state *state);
int octep_get_vq_state(struct octep_hw *oct_hw, u16 qid, struct vdpa_vq_state *state);
u16 octep_get_vq_size(struct octep_hw *oct_hw);
int octep_hw_caps_read(struct octep_hw *oct_hw);
u64 octep_hw_get_dev_features(struct octep_hw *oct_hw);
void octep_hw_set_drv_features(struct octep_hw *oct_hw, u64 features);
u64 octep_hw_get_drv_features(struct octep_hw *oct_hw);
int octep_verify_features(u64 features);

int octep_vdpa_dev_add(struct vdpa_mgmt_dev *mdev, const char *name,
		       const struct vdpa_dev_set_config *config);
void octep_vdpa_dev_del(struct vdpa_mgmt_dev *mdev, struct vdpa_device *vdpa_dev);
int octep_vdpa_mgmt_dev_register(struct octep_vdpa_mgmt_dev *mgmt_dev);
#endif /* __OCTEP_VDPA_H__ */
