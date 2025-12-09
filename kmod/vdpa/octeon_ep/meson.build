# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2023 Marvell.

octep_vdpa_sources = files(
		'octep_vdpa_main.c',
		'octep_vdpa_hw.c',
		'Kbuild',
		)

kmoddir = join_paths('kmod', 'vdpa', 'octeon_ep')

src_dir = meson.current_source_dir()
custom_target('octeon_ep',
		input: octep_vdpa_sources,
		output: 'octep_vdpa.ko',
		command: ['sh', '-c',
			'make -j4 -C ' + kernel_build_dir + ' M=' + src_dir + ' modules ' +
			' '.join(cross_args) + ' && ' +
			'cp ' + src_dir / 'octep_vdpa.ko' + ' @OUTPUT@'],
		build_by_default: true,
		install: true,
		install_dir: kmoddir)

enabled = ['octep_vdpa']
DAO_MODULES_ENABLED += [['kmod', enabled]]
