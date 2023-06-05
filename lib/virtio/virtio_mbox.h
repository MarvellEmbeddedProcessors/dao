/* SPDX-License-Identifier: Marvell-Proprietary
 * Copyright (c) 2024 Marvell.
 */
#ifndef __INCLUDE_DAO_VIRTIO_MBOX_H__
#define __INCLUDE_DAO_VIRTIO_MBOX_H__

enum virtio_mbox_ids {
	MBOX_MSG_SET_VQ_STATE = 1,
	MBOX_MSG_GET_VQ_STATE,
};

struct virtio_vq_state {
	uint16_t last_avail_counter:1;
	uint16_t last_avail_idx:15;
	uint16_t last_used_counter:1;
	uint16_t last_used_idx:15;
};

struct virtio_mbox_hdr {
	uint8_t ver;
	uint8_t rsvd1;
	uint16_t id;
	uint16_t rsvd2;
#define MBOX_REQ_SIG (0xdead)
#define MBOX_RSP_SIG (0xbeef)
	uint16_t sig;
};

struct virtio_mbox_sts {
	uint16_t rsp:1;
	uint16_t rc:15;
	uint16_t rsvd;
};

struct virtio_mbox {
	struct virtio_mbox_hdr hdr;
	struct virtio_mbox_sts sts;
	uint64_t rsvd;
	uint32_t data[];
};

int virtio_mbox_init(struct virtio_dev *dev);
void virtio_mbox_fini(struct virtio_dev *dev);

#endif /* __INCLUDE_DAO_VIRTIO_MBOX_H__ */
