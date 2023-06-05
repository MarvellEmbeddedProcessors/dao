/* SPDX-License-Identifier: Marvell-Proprietary
 * Copyright (c) 2023 Marvell
 */

#ifndef __INCLUDE_VIRTIO_H__
#define __INCLUDE_VIRTIO_H__

/** Device feature lower 32 bits */
#define VIRTIO_F_ANY_LAYOUT 27

/** Device feature higher 32 bits */
#define VIRTIO_F_VERSION_1         32
#define VIRTIO_F_IOMMU_PLATFORM    33
#define VIRTIO_F_RING_PACKED       34
#define VIRTIO_F_IN_ORDER          35
#define VIRTIO_F_ORDER_PLATFORM    36
#define VIRTIO_F_NOTIFICATION_DATA 38

/** This marks a buffer as continuing via the next field. */
#define VRING_DESC_F_NEXT 48
/** This marks a buffer as write-only (otherwise read-only). */
#define VRING_DESC_F_WRITE 50
/** This means the buffer contains a list of buffer descriptors. */
#define VRING_DESC_F_INDIRECT 52
/** This flag means the descriptor was made available by the driver */
#define VIRT_PACKED_RING_DESC_F_AVAIL (1UL << 55)
/** This flag means the descriptor was used by the device */
#define VIRT_PACKED_RING_DESC_F_USED (1UL << 63)
#define VIRT_PACKED_RING_DESC_F_AVAIL_USED                                                         \
	(VIRT_PACKED_RING_DESC_F_AVAIL | VIRT_PACKED_RING_DESC_F_USED)

#define RING_EVENT_FLAGS_ENABLE  0x0
#define RING_EVENT_FLAGS_DISABLE 0x1
#define RING_EVENT_FLAGS_DESC    0x2

/** Event suppression structure format */
struct vring_packed_desc_event {
	uint16_t desc_event_off_wrap;
	uint16_t desc_event_flags;
};

/** Virtio device status */
enum virtio_dev_status {
	/** Virtio device status reset */
	VIRTIO_DEV_RESET = 0,
	/** Virtio device status acknowledge */
	VIRTIO_DEV_ACKNOWLEDGE = 1,
	/** Virtio device status driver */
	VIRTIO_DEV_DRIVER = 2,
	/** Virtio device status OK */
	VIRTIO_DEV_DRIVER_OK = 4,
	/** Virtio device features OK */
	VIRTIO_DEV_FEATURES_OK = 8,
	/** Virtio device needs reset */
	VIRTIO_DEV_NEEDS_RESET = 64,
	/** Virtio device failed */
	VIRTIO_DEV_FAILED = 128,
};

/** Virtio packet descriptor */
struct vring_packed_desc {
	/** Buffer address */
	uint64_t addr;
	/** Length */
	uint32_t len;
	/** Buffer ID */
	uint16_t id;
	/** Descriptor flags */
	uint16_t flags;
};

#endif /* __INCLUDE_VIRTIO_H__ */
