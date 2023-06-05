# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2024 Marvell.

if not DAO_BUILD_CONF.has('DAO_LIBNL_DEP')
  message('libnl not found. skipping secgw-graph')
  skip_app = true
  subdir_done()
endif

# Application Sources
sources += files(
	'main.c',
	'secgw.c',
	'secgw_worker.c',
	'secgw_netlink_ops.c',
	'devices/secgw_ethdev.c',
	'devices/secgw_tap.c',
	'nodes/rxtx/ethdev-rx.c',
	'nodes/rxtx/tap-rx.c',
	'nodes/rxtx/ethdev-tx.c',
	'nodes/rxtx/tap-tx.c',
	'nodes/output/interface-output_priv.c',
	'nodes/output/interface-output.c',
	'nodes/net/error-drop.c',
	'nodes/net/portmapper/port-mapper.c',
)

# Mandatory dependency
if not DAO_BUILD_CONF.has('DAO_LIBDPDK_DEP')
	error('Missing mandatory dependency "libdpdk"')
endif

includes += include_directories(['.'])

deps = ['portgroup']
deps += ['workers']
deps += ['netlink']
