# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2025 Marvell.

iliad_cdev_mkfile = custom_target('iliad_cdev_makefile',
		output: 'Makefile',
		command: ['touch', '@OUTPUT@'])

iliad_cdev_sources = files(
		'iliad_cdev.c',
		'Makefile',
		)

kmoddir = join_paths('kmod', 'iliad', 'iliad_cdev')

	custom_target('iliad_cdev',
		input: iliad_cdev_sources,
		output: 'iliad_cdev.ko',
		command: ['make', '-C', kernel_build_dir,
		'M=' + meson.current_build_dir(),
		'src=' + meson.current_source_dir(),
		'modules'] + cross_args,
		depends: iliad_cdev_mkfile,
		build_by_default: false,
		install: true,
		install_dir: kmoddir)

enabled = ['iliad_cdev']
DAO_MODULES_ENABLED += [['kmod', enabled]]

