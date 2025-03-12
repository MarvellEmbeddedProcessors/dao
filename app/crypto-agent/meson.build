# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2025 Marvell.

if host_build
	skip_app = true
endif

sources = files(
	'ca_ethdev.c',
	'cpt_debug.c',
	'crypto_agent.c',
)

cflags += [ '-DCA_DEBUG_ENABLE_PERIODIC_PRINT' ]

deps += ['liquid_crypto']

app_deps += DAO_EXT_DEPS_LIBDPDK

# Link crypto_cnxk PMD as PMD APIs are used
if get_option('default_library') == 'shared' and not get_option('prefer_static')
	dpdk_libdir = libdpdk_dep.get_pkgconfig_variable('libdir')
	ldflags += ['-L' + dpdk_libdir, '-lrte_crypto_cnxk']
endif

if get_option('buildtype').contains('debug')
	cflags += [ '-DCA_DEBUG_ENABLE' ]
	cflags += [ '-DCPT_DEBUG_ENABLE' ]
endif
