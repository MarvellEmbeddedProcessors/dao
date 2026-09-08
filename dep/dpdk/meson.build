# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2023 Marvell.

# pkg-config resolves shared libraries by default. Honor Meson's built-in
# 'prefer_static' core option (set via --prefer-static / -Dprefer_static=true)
# as well as the project's own 'prefer_static_build' option, so that DPDK is
# resolved as a static library as well. If neither option is set, this
# falls back to shared linkage as before.
libdpdk_dep = dependency('libdpdk', method : 'pkg-config',
	static: get_option('prefer_static') or get_option('prefer_static_build'), required:false)
if libdpdk_dep.found()
	if libdpdk_dep.version().version_compare('<' + dpdk_version)
		error('DPDK version ' + libdpdk_dep.version() +  ' not supported need > ' + dpdk_version)
	endif
	dpdk_version = libdpdk_dep.version()

	DAO_BUILD_CONF.set('DAO_LIBDPDK_DEP', '1')
	DAO_EXT_DEPS_LIBDPDK += libdpdk_dep
else
	message('DPDK pkgconfig not exported')
	subdir_done()
endif
