# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2023 Marvell.

if host_build
	skip_lib = true
endif

sources = files(
	'pem.c',
	'sdp.c',
	'iliad.c',
	'iliad_cdev.c'
)

headers = files(
	'dao_pem.h'
)

deps += ['common', 'vfio']
