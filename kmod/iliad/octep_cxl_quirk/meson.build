# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2025 Marvell.

octep_cxl_quirk_sources = files(
		'octep_cxl_quirk.c',
		'Makefile',
		)

kmoddir = join_paths('kmod', 'iliad', 'octep_cxl_quirk')

src_dir = meson.current_source_dir()
custom_target('octep_cxl_quirk',
		input: octep_cxl_quirk_sources,
		output: 'octep_cxl_quirk.ko',
		command: ['sh', '-c',
			'make -j4 -C ' + kernel_build_dir + ' M=' + src_dir + ' modules ' +
			' '.join(cross_args) + ' && ' +
			'cp ' + (src_dir / 'octep_cxl_quirk.ko') + ' @OUTPUT@'],
		build_by_default: false,
		install: true,
		install_dir: kmoddir)

enabled = ['octep_cxl_quirk']
DAO_MODULES_ENABLED += [['kmod', enabled]]

