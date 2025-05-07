# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2024 Marvell.

if not DAO_BUILD_CONF.has('DAO_LIBPCAP_DEP')
	message('libpcap for aarch64 not found. skipping connection tracking function test')
	build = false
	subdir_done()
endif

sources = files(
	'main.c',
)

deps = ['conntrack']

# Add libpcap dependency for this test only
test_deps = DAO_EXT_DEPS_LIBPCAP
