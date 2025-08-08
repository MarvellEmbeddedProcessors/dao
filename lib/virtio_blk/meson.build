# SPDX-License-Identifier: Marvell-Proprietary
# Copyright (c) 2025 Marvell.

if host_build
	skip_lib = true
endif

sources = files(
	'virtio_blkdev.c',
	'virtio_blk_io_deq.c',
	'virtio_blk_io_deq_ext.c',
	'virtio_blk_cmpl_ext.c',
	'virtio_blk_cmpl.c',
	'virtio_blk_trace_register.c',
)

headers = files(
	'dao_virtio_blkdev.h',
	'virtio_blk_trace.h',
)

if get_option('virtio_blk_debug')
  cflags += ['-DVIRTIO_BLK_DEBUG=1']
endif

deps += ['virtio']
