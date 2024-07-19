# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2024 Marvell.

if not DAO_BUILD_CONF.has('DAO_LIBPCAP_DEP')
	message('libpcap not found. skipping connection tracking function test')
	skip_lib = true
	subdir_done()
endif

sources = files(
	'main.c',
)

deps = ['conntrack']
