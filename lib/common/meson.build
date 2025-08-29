# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2023 Marvell.

# Write the config file
configure_file(
	input: 'dao_config.h.in',
	output: 'dao_config.h',
	configuration: DAO_BUILD_CONF,
	install_dir: '.'
)

if host_build
	sources = files(
		'dao_log.c',
	)
else
	sources = files(
		'dma.c',
		'dao_bitmap.c',
		'dao_log.c',
		'dao_util.c',
		'dao_dynamic_string.c',
		'dao_platform.c'
	)
endif

headers = files(
	'dao_bitmap.h',
	'dao_dma.h',
	'dao_log.h',
	'dao_util.h',
	'dao_net.h',
	'dao_dynamic_string.h',
	'dao_version.h',
	'dao_assert.h',
	'dao_platform.h',
)
