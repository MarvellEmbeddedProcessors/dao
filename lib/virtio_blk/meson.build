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
)

headers = files(
	'dao_virtio_blkdev.h',
)

deps += ['virtio']
