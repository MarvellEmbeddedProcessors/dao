# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2025 Marvell.

octep_rdma_mkfile = custom_target('octep_makefile',
		output: 'Makefile',
		command: ['touch', '@OUTPUT@'])

# Common source files (both x86 EP and Octeon termination)
octep_rdma_sources = files(
		'octep_rdma.c',
		'octep_rdma_netdev.c',
		'octep_verbs.c',
		'octep_mbox.c',
		'octep_qp.c',
		'octep_mr.c',
		'octep_cq.c',
		'octep_ah.c',
		'octep_pd.c',
		'Kbuild',
		)

# Mode-specific source files
octep_rdma_extra_args = []
if host_machine.cpu_family() == 'aarch64'
  octep_rdma_sources += files('octterm_cdev.c')
  octep_rdma_extra_args += ['MODULE_CFLAGS=-DCONFIG_OCTEP_RDMA_OCTTERM -I' + kernel_build_dir + '/include/uapi']
else
  octep_rdma_sources += files(
		'octep_ep.c',
		'octep_ep_regs.c',
		'octep_pfvf_mbox.c',
		)
endif

kmoddir = join_paths('kmod', 'rdma', 'octep_rdma')

custom_target('octep-rdma',
		input: octep_rdma_sources,
		output: 'octep-rdma.ko',
		command: ['make', '-j4', '-C', kernel_build_dir,
		'M=' + meson.current_build_dir(),
		'src=' + meson.current_source_dir(),
		'modules'] + cross_args + octep_rdma_extra_args,
		depends: octep_rdma_mkfile,
		build_by_default: true,
		install: true,
		install_dir: kmoddir)

enabled = ['octep-rdma']
DAO_MODULES_ENABLED += [['kmod', enabled]]
