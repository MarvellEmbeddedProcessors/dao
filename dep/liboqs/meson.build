# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2025 Marvell.

oqs_dep = dependency('liboqs', method : 'pkg-config', required: false)

if not oqs_dep.found()
	message('liboqs pkgconfig not exported')
	subdir_done()
endif

DAO_BUILD_CONF.set('DAO_LIBOQS_DEP', '1')
liboqs_deps = [oqs_dep]
DAO_EXT_DEPS_LIBOQS += liboqs_deps
