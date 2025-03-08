# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2025 Marvell.

sources = files(
	'lc_autotest.c',
	'lc_test_generic.c',
	'lc_test_asym.c',
	'test.c'
)

deps += ['liquid_crypto']

if get_option('buildtype').contains('debug')
	cflags += [ '-DTEST_LC_DEBUG_BUILD=1' ]
endif
