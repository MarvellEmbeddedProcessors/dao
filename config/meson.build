# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2023 Marvell.

# Non Linux Systems Not supported
exec_env = host_machine.system()
if exec_env != 'linux'
	error('unsupported system type "@0@"'.format(exec_env))
endif

# Compiler Configuration
DAO_CC = meson.get_compiler('c')

soc_cn9k = {
	'machine_args': ['-mcpu=octeontx2+crc+crypto+lse']
}

soc_cn10k = {
	'machine_args': ['-mcpu=neoverse-n2+crypto+sve2']
}

socs = {
	'cn9k': soc_cn9k,
	'cn10k' : soc_cn10k,
}

machine_args = []
if meson.is_cross_build()
	args = meson.get_cross_property('machine_args')
	machine_args = args.split()
else
	platform = get_option('platform')
	if platform == '' or platform == 'native'
		machine_args = ['-march=native']
	else
		soc_config = socs.get(platform, {'not_supported': true})
		if soc_config.has_key('not_supported')
			error('SoC @0@ not supported.'.format(platform))
		endif
		machine_args = soc_config['machine_args']
	endif
endif
foreach ma : machine_args
	if not DAO_CC.has_argument(ma)
		error('Machine arg "' + ma + '" not supported by compiler')
	else
		add_project_arguments(ma, language: 'c')
	endif
endforeach


warning_flags = [
	# globally disabled warnings
	'-Wno-address-of-packed-member',
	'-Wno-packed-not-aligned',
	'-Wno-missing-field-initializers'
]

# "-Wall" is added by meson at warning level 1, and "-Wextra" at level 2.
# Add extra warnings at level 2 or above. (2 is default level).
if get_option('warning_level').to_int() >= 2
	warning_flags += [
		# additional warnings in alphabetical order
		'-Wcast-qual',
		'-Wdeprecated',
		'-Wformat-nonliteral',
		'-Wformat-security',
		'-Wmissing-declarations',
		'-Wmissing-prototypes',
		'-Wnested-externs',
		'-Wold-style-definition',
		'-Wpointer-arith',
		'-Wsign-compare',
		'-Wstrict-prototypes',
		'-Wundef',
		'-Wwrite-strings',
		'-Wno-zero-length-bounds'
	]
endif

foreach arg: warning_flags
	if DAO_CC.has_argument(arg)
		add_project_arguments(arg, language: 'c')
	endif
endforeach

# Set the library version
DAO_VERSION = meson.project_version()
version_list =  DAO_VERSION.split('.')
major_version = version_list[0]
minor_version = version_list[1]
point_version = version_list[2]

# Append DPDK version
if DAO_BUILD_CONF.has('DAO_LIBDPDK_DEP')
	DAO_VERSION += '-' + dpdk_version
endif

git_revision = ''
if run_command('git', 'rev-parse', '--is-inside-work-tree', check: false).stdout().strip() == 'true'
	git_revision = run_command('git', 'rev-parse', '--short', 'HEAD',
                                   check: false).stdout().strip()
	DAO_VERSION += '-' + git_revision
endif


DAO_BUILD_CONF.set('DAO_VERSION_MAJOR', major_version)
DAO_BUILD_CONF.set('DAO_VERSION_MINOR', minor_version)
DAO_BUILD_CONF.set('DAO_VERSION_POINT', point_version)
DAO_BUILD_CONF.set('DAO_VERSION_GIT', git_revision)
DAO_BUILD_CONF.set('DAO_VERSION', DAO_VERSION)

dma_stats = get_option('dma_stats')
if dma_stats == true
	DAO_BUILD_CONF.set('DAO_DMA_STATS', 1)
else
	DAO_BUILD_CONF.set('DAO_DMA_STATS', 0)
endif
DAO_BUILD_CONF.set('DAO_VIRTIO_DEBUG', get_option('virtio_debug'))
