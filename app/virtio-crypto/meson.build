# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2025 Marvell.

if host_build
	skip_app = true
endif

sources = files(
	'vc_drop.c',
	'vc_offload.c',
	'vc_parser.c',
	'vc_virtio_rx.c',
	'vc_virtio_tx.c',
)

deps = ['virtio', 'virtio_crypto']

app_deps += DAO_EXT_DEPS_LIBDPDK
