/* SPDX-License-Identifier: Marvell-Proprietary
 * Copyright (c) 2025 Marvell.
 */

#include <rte_trace_point_register.h>

#include "virtio_blk_trace.h"

RTE_TRACE_POINT_REGISTER(virtio_blk_trace_queue_context, virtio.blk.trace.queue_context);

RTE_TRACE_POINT_REGISTER(virtio_blk_trace_dma, virtio.blk.trace.dma);

RTE_TRACE_POINT_REGISTER(virtio_blk_trace_blob, virtio.blk.trace.blob);

RTE_TRACE_POINT_REGISTER(virtio_blk_trace_io_req, virtio.blk.trace.io_req);

RTE_TRACE_POINT_REGISTER(virtio_blk_trace_io_req_compl, virtio.blk.trace.io_req_compl);

RTE_TRACE_POINT_REGISTER(virtio_blk_trace_desc_flags, virtio.blk.trace.desc_flags);
