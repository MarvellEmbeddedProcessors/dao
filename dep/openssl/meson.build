# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2025 Marvell.

openssl_dep = dependency('openssl', method: 'pkg-config', required: true)

if not openssl_dep.found()
	message('openssl pkgconfig not exported')
	subdir_done()
endif

DAO_BUILD_CONF.set('DAO_OPENSSL_DEP', '1')
DAO_EXT_DEPS_OPENSSL += openssl_dep
