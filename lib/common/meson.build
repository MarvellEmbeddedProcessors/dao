# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2023 Marvell.

# Write the config file
configure_file(
	input: 'dao_config.h.in',
	output: 'dao_config.h',
	configuration: DAO_BUILD_CONF,
	install_dir: '.'
)

sources = files(
	'dma.c',
	'dao_log.c',
	'dao_util.c',
	'dao_dynamic_string.c'
)

headers = files(
	'dao_dma.h',
	'dao_log.h',
	'dao_util.h',
	'dao_net.h',
	'dao_dynamic_string.h',
	'dao_version.h'
)
