# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2023 Marvell.

subdirs = [
            'vdpa',
            'iliad',
]

if host_build
   rdma_build = get_option('rdma_build')
   if rdma_build
       if not meson.version().version_compare('>=1.8.0')
           warning('Meson version 1.8.0 or higher is required for RDMA host build.')
       else
           fs = import('fs')
           kernel_build_dir = get_option('kernel_dir')
           kernel_header_dst = kernel_build_dir + '/' + 'include/uapi/rdma/'
           rdma_core_compiled = meson.project_source_root() + '/' + \
            		'subprojects/rdma-core/build/bin/ibv_devinfo'
           if fs.exists(rdma_core_compiled)
               message('rdma-core already compiled')
           else
               message(kernel_header_dst)
	       message('build_host_dir: ' + meson.build_root())
	       if fs.is_dir(kernel_header_dst)
                   # rdma-core
                   rdma_core_dep = dependency(
                   'rdma-core',
                   default_options: [
                           'kernel_dir=' + get_option('kernel_dir'),
			   'build_host_dir=' + meson.build_root()
                   ],
                   )
	       else
	           warning('RDMA kernel headers not found in ' + kernel_header_dst)
	       endif
           endif

           # Build perftest against the rdma-core compiled above. Requesting it
           # here (after the rdma-core block) guarantees rdma-core is built first.
           rdma_core_build_dir = meson.project_source_root() + '/' + \
				 'subprojects/rdma-core/build'
           # perftest installs into its own subproject build/ tree (build/bin).
           # The subproject is wiped below on every (re)configure, so this tree
           # is rebuilt fresh each time rather than acting as a cache.
           perftest_build_dir = meson.project_source_root() + '/' + \
                               'subprojects/perftest/build'
           perftest_src_dir = meson.project_source_root() + '/' + \
                               'subprojects/perftest'
           # Force a fresh perftest checkout so the wrap packagefile patch (which
           # delivers build.sh/meson.build/meson.options into the subproject) is
           # always re-applied. Meson only applies wrap patches on the initial
           # extraction, so a previously-extracted subproject would otherwise keep
           # a stale build.sh even after the tracked patch is updated. Removing the
           # extracted source makes the dependency() below re-extract + re-patch.
           run_command('rm', '-rf', perftest_src_dir, check: false)
           perftest_compiled = perftest_build_dir + '/bin/ib_write_bw'
           if fs.exists(perftest_compiled)
               message('perftest already compiled')
           else
               perftest_dep = dependency(
                   'perftest',
                   default_options: [
                           'rdma_core_build=' + rdma_core_build_dir,
                           'perftest_prefix=' + perftest_build_dir,
                   ],
               )
           endif
           # Copy the freshly built perftest benchmark binaries into the deploy
           # prefix (build_root/rdma_prefix/bin) so they are rsynced to the test
           # host. build.sh does an in-tree autotools build + 'make install', so
           # the binaries are reliably staged under build/bin.
           perftest_deploy_bin = meson.build_root() + '/rdma_prefix/bin'
           run_command('mkdir', '-p', perftest_deploy_bin, check: true)
           run_command(
               'cp', '-a', perftest_build_dir + '/bin/.', perftest_deploy_bin,
               check: true,
           )
	   if fs.is_dir(kernel_header_dst)
               subdirs += ['rdma']
	   endif
       endif
   endif
endif

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

	# Skip kmod build for kernel versions < 6.5
	major_version = kernel_version.split('.')[0].to_int()
	minor_version = kernel_version.split('.')[1].to_int()
	if major_version < 6 or (major_version == 6 and minor_version < 5)
		message('Skipping kmod build, kernel version ' + kernel_version + ' < reqired 6.5')
		subdir_done()
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
