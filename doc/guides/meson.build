# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2024 Marvell.

sphinx = find_program(
	'sphinx-build-3',
	required: false
)

if not sphinx.found()
	sphinx = find_program(
		'sphinx-build',
		required: false
	)
endif

if not sphinx.found()
	subdir_done()
endif

docs_sources = [
	'index.rst',
]

htmldir = join_paths(get_option('datadir'), 'doc', 'DAO', 'user-guide')

custom_target(
	'End User Documentation',
	command: [sphinx, '-q', '-W', '-b', 'html', meson.current_source_dir(), '@OUTPUT@'],
	input: docs_sources,
	output: 'html',
	build_by_default: true,
	install: true,
	install_dir: htmldir
)

install_data(files('custom.css'), install_dir: join_paths(htmldir,'_static', 'css'))
