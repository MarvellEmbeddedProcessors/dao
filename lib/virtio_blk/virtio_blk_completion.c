/* SPDX-License-Identifier: Marvell-Proprietary
 * Copyright (c) 2025 Marvell.
 */

#include "dao_virtio_blkdev.h"
#include "virtio_dev_priv.h"

#include "spec/virtio_blk.h"
#include "virtio_blk_priv.h"

static __rte_always_inline int
virtio_blk_io_compl(struct virtio_blk_queue *q, const uint16_t flags)
{
	RTE_SET_USED(q);
	RTE_SET_USED(flags);

	return 0;
}
