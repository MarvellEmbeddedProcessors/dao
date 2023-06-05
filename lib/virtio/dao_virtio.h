/* SPDX-License-Identifier: Marvell-Proprietary
 * Copyright (c) 2023 Marvell
 */

/**
 * @file
 *
 * DAO virtio library
 */

#ifndef __INCLUDE_DAO_VIRTIO_H__
#define __INCLUDE_DAO_VIRTIO_H__

#include <dao_pem.h>

#include <spec/virtio.h>

/** Max supported virtio devices */
#define DAO_VIRTIO_DEV_MAX 128
/** Max supported virtio queues per device including control queue */
#define DAO_VIRTIO_MAX_QUEUES 129U
/** Max supported virtio queue size */
#define DAO_VIRTIO_MAX_QUEUE_SZ 4096U

/** Virtio Status to String */
const char *dao_virtio_dev_status_to_str(uint8_t dev_status);

#endif /* __INCLUDE_DAO_VIRTIO_H__ */
