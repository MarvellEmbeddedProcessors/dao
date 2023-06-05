# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2024 Marvell.

doxygen = find_program(
	'doxygen',
	required: true
)

if not doxygen.found()
       subdir_done()
endif

# due to the CSS customisation script, which needs to run on a file that
# is in a subdirectory that is created at build time and thus it cannot
# be an individual custom_target, we need to wrap the doxygen call in a
# script to run the CSS modification afterwards
generate_doxygen = find_program('generate_doxygen.sh')

htmldir = join_paths(get_option('datadir'), 'doc', 'DAO', 'doxygen')

cdata = configuration_data()
cdata.set('OUTPUT', meson.current_build_dir())
cdata.set('HTML_OUTPUT', 'html')
cdata.set('TOPDIR', meson.current_source_dir())
cdata.set('STRIP_FROM_PATH', meson.current_source_dir())

doxy_conf = configure_file(
	input: 'doxy-api.conf.in',
	output: 'doxy-api.conf',
	configuration: cdata
)

custom_target(
	'doxygen',
	depend_files: 'doxy-api-index.md',
	input: doxy_conf,
	output: 'html',
	depfile: 'html.d',
	command: [generate_doxygen, '@INPUT@', '@OUTPUT@'],
	install: true,
	install_dir: htmldir,
	build_by_default: true)
