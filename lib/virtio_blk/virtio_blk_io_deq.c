/* SPDX-License-Identifier: Marvell-Proprietary
 * Copyright (c) 2025 Marvell.
 */

#include "dao_virtio_blkdev.h"
#include "virtio_dev_priv.h"

#include "spec/virtio_blk.h"
#include "virtio_blk_priv.h"

static __rte_always_inline int
virtio_blk_io_deq(struct virtio_blk_queue *q, struct rte_mbuf **mbufs, uint16_t nb_mbufs,
	       const uint16_t flags)
{
	RTE_SET_USED(q);
	RTE_SET_USED(mbufs);
	RTE_SET_USED(nb_mbufs);
	RTE_SET_USED(flags);

	return 0;
}
