# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2024 Marvell.

libpcap_dep = dependency('libpcap', method : 'pkg-config', required:false, static:true)

if not libpcap_dep.found()
	message('libpcap pkgconfig not exported')
	subdir_done()
else
	libpcap_path = libpcap_dep.get_variable(pkgconfig : 'libdir') + '/libpcap.so.1.11.0-PRE-GIT'
	libpcap_arch = run_command('file', libpcap_path, check: true).stdout().strip()
	if libpcap_arch.contains('aarch64')
		DAO_BUILD_CONF.set('DAO_LIBPCAP_DEP', '1')
		DAO_EXT_DEPS_LIBPCAP += libpcap_dep
	endif
endif
