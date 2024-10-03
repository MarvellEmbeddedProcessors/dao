# SPDX-License-Identifier: Marvell-Proprietary
# Copyright (c) 2023 Marvell.

sources = files(
	'virtio_dev.c',
	'virtio_mbox.c',
)

headers = files(
	'dao_virtio.h',
)

spec_headers = files(
	'spec/virtio.h',
	'spec/virtio_crypto.h',
	'spec/virtio_net.h',
)

install_headers(spec_headers, subdir: 'spec')

deps += ['common', 'pem']
