# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2025 Marvell.

iliad_cdev_sources = files(
		'iliad_cdev.c',
		'Makefile',
		)

kmoddir = join_paths('kmod', 'iliad', 'iliad_cdev')

src_dir = meson.current_source_dir()
custom_target('iliad_cdev',
		input: iliad_cdev_sources,
		output: 'iliad_cdev.ko',
		command: ['sh', '-c',
			'make -j4 -C ' + kernel_build_dir + ' M=' + src_dir + ' modules ' +
			' '.join(cross_args) + ' && ' +
			'cp ' + (src_dir / 'iliad_cdev.ko') + ' @OUTPUT@'],
		build_by_default: false,
		install: true,
		install_dir: kmoddir)

enabled = ['iliad_cdev']
DAO_MODULES_ENABLED += [['kmod', enabled]]

