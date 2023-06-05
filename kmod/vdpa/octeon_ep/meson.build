# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2023 Marvell.

octep_vdpa_mkfile = custom_target('octep_makefile',
		output: 'Makefile',
		command: ['touch', '@OUTPUT@'])

octep_vdpa_sources = files(
		'octep_vdpa_main.c',
		'octep_vdpa_hw.c',
		'Kbuild',
		)

kmoddir = join_paths('kmod', 'vdpa', 'octeon_ep')

custom_target('octeon_ep',
		input: octep_vdpa_sources,
		output: 'octep_vdpa.ko',
		command: ['make', '-j4', '-C', kernel_build_dir,
		'M=' + meson.current_build_dir(),
		'src=' + meson.current_source_dir(),
		'modules'] + cross_args,
		depends: octep_vdpa_mkfile,
		build_by_default: true,
		install: true,
		install_dir: kmoddir)

enabled = ['octep_vdpa']
DAO_MODULES_ENABLED += [['kmod', enabled]]
