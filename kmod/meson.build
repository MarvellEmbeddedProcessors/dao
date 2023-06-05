# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2023 Marvell.

subdirs = ['vdpa']

kernel_build_dir = get_option('kernel_dir')
kernel_source_dir = get_option('kernel_dir')
cross_args = []

if not meson.is_cross_build()
	kernel_version = run_command('uname', '-r', check: true).stdout().strip()
	if kernel_source_dir != ''
		# Try kernel release from sources first
		r = run_command('make', '-s', '-C', kernel_source_dir, 'kernelrelease', \
				check: false)
		if r.returncode() == 0
			kernel_version = r.stdout().strip()
		endif
	else
		# use default path for native builds
		kernel_source_dir = '/lib/modules/' + kernel_version + '/source'
	endif
	kernel_install_dir = '/lib/modules/' + kernel_version + '/extra/dpdk'
	if kernel_build_dir == ''
		# use default path for native builds
		kernel_build_dir = '/lib/modules/' + kernel_version + '/build'
	endif

	# test running make in kernel directory, using "make kernelversion"
	make_returncode = run_command('make', '-sC', kernel_build_dir,
				      'kernelversion', check: true).returncode()
	if make_returncode != 0
	# backward compatibility:
        # the headers could still be in the 'build' subdir
	if not kernel_build_dir.endswith('build') and not kernel_build_dir.endswith('build/')
		kernel_build_dir = join_paths(kernel_build_dir, 'build')
		make_returncode = run_command('make', '-sC', kernel_build_dir,
					      'kernelversion', check: true).returncode()
	endif
	endif

	if make_returncode != 0
		error('Cannot compile kernel modules as requested - are kernel headers installed?')
	endif

	# DO ACTUAL MODULE BUILDING
	foreach d:subdirs
		subdir(d)
	endforeach

	subdir_done()
endif

# if we are cross-compiling we need kernel_build_dir specified
if kernel_build_dir != ''
	python3 = import('python').find_installation(required: false)
	if python3.found()
		py3 = [python3]
	else
		py3 = ['meson', 'runpython']
	endif

	cross_compiler = find_program('c').path()
	if cross_compiler.endswith('gcc')
		cross_prefix = run_command([py3, '-c', 'print("' + cross_compiler + \
					'"[:-3])'], check: false).stdout().strip()
	endif

	cross_arch = host_machine.cpu_family()
	if host_machine.cpu_family() == 'aarch64'
		cross_arch = 'arm64'
	endif

	cross_args += ['ARCH=@0@'.format(cross_arch), 'CROSS_COMPILE=@0@'.format(cross_prefix)]

	foreach d:subdirs
		subdir(d)
	endforeach
endif
