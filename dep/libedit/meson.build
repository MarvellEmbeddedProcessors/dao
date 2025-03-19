# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2025 Marvell.

edit_dep = dependency('libedit', method : 'pkg-config', required: true)
ncurses_dep = dependency('ncurses', method : 'pkg-config', required: true)

if not edit_dep.found()
	message('libedit pkgconfig not exported')
	subdir_done()
endif

if not ncurses_dep.found()
	message('ncurses pkgconfig not exported')
	subdir_done()
endif

DAO_BUILD_CONF.set('DAO_LIBEDIT_DEP', '1')
libedit_deps = [edit_dep, ncurses_dep]
DAO_EXT_DEPS_LIBEDIT += libedit_deps
