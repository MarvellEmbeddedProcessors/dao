# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2023 Marvell.

libnl_dep_version = []
libnl_dep = dependency('libnl-3.0', method : 'pkg-config', version: '>=3.5.0', required:false, static:true)
libnlroute_dep = dependency('libnl-route-3.0', method : 'pkg-config', version: '>=3.5.0', required:false, static:true)
libnlxfrm_dep = dependency('libnl-xfrm-3.0', method : 'pkg-config', version: '>=3.5.0', required:false, static:true)

if not libnlroute_dep.found()
	message('libnlroute pkgconfig not exported')
	subdir_done()
endif

if not libnlxfrm_dep.found()
	message('libnlxfrm pkgconfig not exported')
	subdir_done()
endif

if not libnl_dep.found()
	message('libnl pkgconfig not exported')
	subdir_done()
else
	DAO_BUILD_CONF.set('DAO_LIBNL_DEP', '1')
	libnl_dep_version = libnl_dep.version()
	libnl_link_arg = ['-Wl,--whole-archive',
	                  libnl_dep.get_variable(default_value:'',pkgconfig:'libdir') + '/libnl-xfrm-3.a',
	                  libnl_dep.get_variable(default_value:'',pkgconfig:'libdir') + '/libnl-route-3.a',
	                  libnl_dep.get_variable(default_value:'',pkgconfig:'libdir') + '/libnl-3.a',
	                  '-Wl,--no-whole-archive']
	libnl_decl_dep = declare_dependency(
						link_args: libnl_link_arg,
						include_directories: libnl_dep.get_variable(default_value : '', pkgconfig: 'includedir') + '/libnl3'
					)
	DAO_DPDK_LIB_DEPS += libnl_decl_dep
endif
