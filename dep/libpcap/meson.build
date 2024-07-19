# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2024 Marvell.

libpcap_dep = dependency('libpcap', method : 'pkg-config', required:false, static:true)

if not libpcap_dep.found()
	message('libpcap pkgconfig not exported')
	subdir_done()
else
	DAO_BUILD_CONF.set('DAO_LIBPCAP_DEP', '1')
	libpcap_larg = ['-Wl,--whole-archive',
			libpcap_dep.get_variable(default_value:'',pkgconfig:'libdir') +
			'/libpcap.a', '-Wl,--no-whole-archive']
	libpcap_decl_dep = declare_dependency(link_args: libpcap_larg,
				include_directories: libpcap_dep.get_variable(default_value : '',
				pkgconfig: 'includedir'))
	DAO_EXT_DEPS_LIBPCAP += libpcap_decl_dep
endif
