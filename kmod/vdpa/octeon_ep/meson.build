# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2023 Marvell.

octep_vdpa_sources = files(
		'octep_vdpa_main.c',
		'octep_vdpa_hw.c',
		'octep_pci.c',
		'octep_plat.c',
		'Kbuild',
		)

kmoddir = join_paths('kmod', 'vdpa', 'octeon_ep')

src_dir = meson.current_source_dir()
custom_target('octeon_ep_modules',
		input: octep_vdpa_sources,
		output: ['octep_vdpa_pci.ko', 'octep_vdpa_plat.ko'],
		command: ['sh', '-c',
			'make -j4 -C ' + kernel_build_dir + ' M=' + src_dir + ' modules ' +
			' '.join(cross_args) + ' && ' +
			'cp ' + src_dir / 'octep_vdpa_pci.ko' + ' @OUTPUT0@ && ' +
			'cp ' + src_dir / 'octep_vdpa_plat.ko' + ' @OUTPUT1@'],
		build_by_default: true,
		install: true,
		install_dir: kmoddir)

enabled = ['octep_vdpa']
DAO_MODULES_ENABLED += [['kmod', enabled]]
