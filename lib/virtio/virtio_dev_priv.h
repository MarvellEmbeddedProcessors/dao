/* SPDX-License-Identifier: Marvell-Proprietary
 * Copyright (c) 2024 Marvell.
 */
#ifndef __INCLUDE_DAO_VIRTIO_PRIV_H__
#define __INCLUDE_DAO_VIRTIO_PRIV_H__

#include <rte_dmadev.h>
#include <rte_eal.h>
#include <rte_vect.h>

#include <dao_dma.h>
#include <dao_log.h>
#include <dao_util.h>

#define VIRTIO_PCI_CAP_PTR               0x34
#define VIRTIO_PCI_CAP_COMMON_CFG_OFFSET VIRTIO_PCI_CAP_PTR + 1
#define VIRTIO_PCI_DEV_CFG_LENGTH        64

/* Common configuration */
#define VIRTIO_PCI_CAP_COMMON_CFG 1
/* Notifications */
#define VIRTIO_PCI_CAP_NOTIFY_CFG 2
/* ISR Status */
#define VIRTIO_PCI_CAP_ISR_CFG 3
/* Device specific configuration */
#define VIRTIO_PCI_CAP_DEVICE_CFG 4
/* PCI configuration access */
#define VIRTIO_PCI_CAP_PCI_CFG 5
/* Shared memory region */
#define VIRTIO_PCI_CAP_SHARED_MEMORY_CFG 8
/* Vendor-specific data */
#define VIRTIO_PCI_CAP_VENDOR_CFG 9

#define PCI_CAP_ID_VNDR 0x09
#define PCI_CAP_BAR     4

#define VIRTIO_DMA_TMO_MS 3000

enum virtio_dev_type {
	VIRTIO_DEV_TYPE_NET,
	VIRTIO_DEV_TYPE_MAX,
};

struct virtio_dev;
typedef void (*virtio_cq_cmd_process_cb_t)(struct virtio_dev *dev, struct rte_dma_sge *src,
					   struct rte_dma_sge *dst, uint16_t nb_desc);
typedef int (*virtio_dev_status_cb_t)(struct virtio_dev *dev, uint8_t status);
typedef uint16_t (*virtio_cq_id_get_cb_t)(struct virtio_dev *dev, uint64_t feature_bits);

struct virtio_dev_cbs {
	virtio_cq_cmd_process_cb_t cq_cmd_process;
	virtio_dev_status_cb_t dev_status;
	virtio_cq_id_get_cb_t cq_id_get;
};

struct virtio_pci_cap {
	uint8_t cap_vndr;   /* Generic PCI field: PCI_CAP_ID_VNDR */
	uint8_t cap_next;   /* Generic PCI field: next ptr. */
	uint8_t cap_len;    /* Generic PCI field: capability length */
	uint8_t cfg_type;   /* Identifies the structure. */
	uint8_t bar;        /* Where to find it. */
	uint8_t id;         /* Multiple capabilities of the same type */
	uint8_t padding[2]; /* Pad to full dword. */
	uint32_t offset;    /* Offset within bar. */
	uint32_t length;    /* Length of the structure, in bytes. */
};

struct virtio_pci_common_cfg {
	/* About the whole device. */
	union {
		uint64_t w0;
		struct {
			uint32_t device_feature_select; /* read-write */
			uint32_t device_feature;        /* read-only for driver */
		};
	};
	union {
		uint64_t w1;
		struct {
			uint32_t driver_feature_select; /* read-write */
			uint32_t driver_feature;        /* read-write */
		};
	};
	union {
		uint64_t w2;
		struct {
			uint16_t config_msix_vector; /* read-write */
			uint16_t num_queues;         /* read-only for driver */
			uint8_t device_status;       /* read-write */
			uint8_t config_generation;   /* read-only for driver */
			/* About a specific virtqueue. */
			uint16_t queue_select; /* read-write */
		};
	};
	union {
		uint64_t w3;
		struct {
			uint16_t queue_size;        /* read-write */
			uint16_t queue_msix_vector; /* read-write */
			uint16_t queue_enable;      /* read-write */
			uint16_t queue_notify_off;  /* read-only for driver */
		};
	};
	union {
		uint64_t w4;
		struct {
			uint32_t queue_desc_lo; /* read-write */
			uint32_t queue_desc_hi; /* read-write */
		};
	};
	union {
		uint64_t w5;
		struct {
			uint32_t queue_avail_lo; /* read-write */
			uint32_t queue_avail_hi; /* read-write */
		};
	};
	union {
		uint64_t w6;
		struct {
			uint32_t queue_used_lo; /* read-write */
			uint32_t queue_used_hi; /* read-write */
		};
	};
	union {
		uint64_t w7;
		struct {
			uint16_t queue_notify_data; /* read-only for driver */
			uint16_t queue_reset;       /* read-write */
		};
	};
};

struct virtio_pci_notify_cap {
	struct virtio_pci_cap cap;
	uint32_t notify_off_multiplier; /* Multiplier for queue_notify_off. */
};

struct virtio_queue_conf {
	uint16_t queue_select;      /* read-write */
	uint16_t queue_size;        /* read-write */
	uint16_t queue_msix_vector; /* read-write */
	uint16_t queue_enable;      /* read-write */
	uint16_t queue_notify_off;  /* read-only for driver */
	uint32_t queue_desc_lo;     /* read-write */
	uint32_t queue_desc_hi;     /* read-write */
	uint32_t queue_avail_lo;    /* read-write */
	uint32_t queue_avail_hi;    /* read-write */
	uint32_t queue_used_lo;     /* read-write */
	uint32_t queue_used_hi;     /* read-write */
	uint16_t queue_notify_data; /* read-only for driver */
	uint16_t queue_reset;       /* read-write */
};

struct virtio_dev {
	uint16_t dev_id;
	uint16_t dma_vchan;
	enum virtio_dev_type dev_type;
	uint16_t pem_devid;
	volatile struct virtio_pci_common_cfg *common_cfg;
	uint64_t bar4;
	size_t bar4_sz;
	size_t host_page_sz;
	size_t notify_off_mltpr;
	int max_virtio_queues;
	uintptr_t notify_base;
	uintptr_t isr;
	size_t isr_sz;
	uintptr_t dev_cfg;
	volatile uintptr_t mbox;
	struct virtio_ctrl_queue *cq;
	struct virtio_queue_conf queue_conf[DAO_VIRTIO_MAX_QUEUES];
	uint64_t dev_feature_bits;
	uint32_t drv_feature_bits_lo;
	uint32_t drv_feature_bits_hi;
	uint64_t feature_bits;
	uint16_t prev_queue_select;
	uint32_t prev_drv_feature_select;
	uint64_t *cb_intr_addr;

	uint8_t driver_ok_pend;
	uint8_t queue_select_pend;

	union {
		struct {
			uint64_t driver_ok : 1;
			uint64_t features_ok : 1;
			uint64_t acknowledge : 1;
			uint64_t driver : 1;
		};
		uint64_t device_state;
	};
};

extern struct virtio_dev_cbs dev_cbs[];

#define DESC_ENTRY_SZ 16UL

#define DESC_SZ(x) (((x) & ~RTE_BIT64(15)) * DESC_ENTRY_SZ)

#define DESC_PTR_OFF(b, i, o) (uint64_t *)(((uintptr_t)b) + DESC_SZ(i) + (o))

#define DESC_OFF(i) ((uint16_t)(i) & ~RTE_BIT64(15))

static __rte_always_inline uint16_t
desc_off_add(uint16_t a, uint16_t b, uint16_t q_sz)
{
	uint16_t sum = a + b;
	uint16_t mask = (~(q_sz - 1) & ~RTE_BIT64(15));

	sum += mask;
	sum = sum & ~mask;

	return sum;
}

static __rte_always_inline uint16_t
desc_off_diff_no_wrap(uint16_t a, uint16_t b, uint16_t q_sz)
{
	return (a & RTE_BIT64(15)) == (b & RTE_BIT64(15)) ? (uint16_t)(a - b) :
							    (q_sz - (b & (RTE_BIT64(15) - 1)));
}

static __rte_always_inline uint16_t
desc_off_diff(uint16_t a, uint16_t b, uint16_t q_sz)
{
	return (a & RTE_BIT64(15)) == (b & RTE_BIT64(15)) ?
		       ((uint16_t)(DESC_OFF(a) - DESC_OFF(b))) :
		       (q_sz - (b & (RTE_BIT64(15) - 1)) + DESC_OFF(a));
}

int virtio_dev_init(struct virtio_dev *dev);
int virtio_dev_fini(struct virtio_dev *dev);
void virtio_dev_feature_bits_set(struct virtio_dev *dev, uint64_t feature_bits);
int virtio_dev_max_virtio_queues(uint16_t pem_devid, uint16_t devid);

#endif /* __INCLUDE_DAO_VIRTIO_PRIV_H__ */
