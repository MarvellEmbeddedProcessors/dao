# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2024 Marvell.

sources = files(
				'daoh_helper.c',
)

headers = files(
        'daoh_helper.h',
)

deps = []
deps += ['common', 'pem', 'virtio', 'virtio_net']

enabled = []
disabled = []
default_cflags = machine_args
default_cflags += ['-DALLOW_EXPERIMENTAL_API']
default_cflags += ['-DALLOW_INTERNAL_API', '-flax-vector-conversions' ]
default_cflags += ['-g']

build = true
name = l
headers = []
includes = []
includes += '.'
cflags = default_cflags
name = 'helper'
libname = 'dao_' + name
includes += DAO_INCLUDES
static_deps = []
foreach d:deps
	if not is_variable('static_dao_' + d)
	build = false
	reason = 'missing internal dependency, "@0@"'.format(d)
	message('Disabling @1@ [@2@]: missing internal dependency "@0@"'
		.format(d, name, 'lib/' + name))
	else
	static_deps += [get_variable('static_dao_' + d)]
	endif
endforeach

if not build
   set_variable(name.underscorify() + '_disable_reason', reason)
   disabled += [libname]
   continue
endif

	enabled += [libname]
install_headers(headers)

#build static lib
static_lib = static_library(libname,
	sources,
	c_args: cflags,
	include_directories: includes,
	dependencies: static_deps + DAO_DPDK_LIB_DEPS,
	install: true)
static_dep = declare_dependency(
	include_directories: includes,
	dependencies: static_deps)

	set_variable('static_dao_' + name, static_dep)

	DAO_STATIC_LIBS += static_lib

# Update global configuration
if enabled.length() > 0
    DAO_MODULES_ENABLED += [['Libraries', enabled]]
endif

if disabled.length() > 0
    DAO_MODULES_DISABLED += [['Libraries', disabled]]
endif
