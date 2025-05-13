# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2025 Marvell.

octep_cxl_quirk_mkfile = custom_target('octep_cxl_quirk_makefile',
		output: 'Makefile',
		command: ['touch', '@OUTPUT@'])

octep_cxl_quirk_sources = files(
		'octep_cxl_quirk.c',
		'Makefile',
		)

kmoddir = join_paths('kmod', 'iliad', 'octep_cxl_quirk')

custom_target('octep_cxl_quirk',
		input: octep_cxl_quirk_sources,
		output: 'octep_cxl_quirk.ko',
		command: ['make', '-j4', '-C', kernel_build_dir,
		'M=' + meson.current_build_dir(),
		'src=' + meson.current_source_dir(),
		'modules'] + cross_args,
		depends: octep_cxl_quirk_mkfile,
		build_by_default: false,
		install: true,
		install_dir: kmoddir)

enabled = ['octep_cxl_quirk']
DAO_MODULES_ENABLED += [['kmod', enabled]]

