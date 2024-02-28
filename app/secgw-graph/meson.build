# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2024 Marvell.

if not DAO_BUILD_CONF.has('DAO_LIBNL_DEP')
  message('libnl not found. skipping secgw-graph')
  skip_app = true
  subdir_done()
endif

if not DAO_BUILD_CONF.has('DAO_LIBDPDK_DEP')
	message('libdpdk not found. skipping secgw-graph')
	skip_app = true
	subdir_done()
endif

subdir('cli')

# Application Sources
sources += files(
	'main.c',
	'secgw.c',
	'secgw_worker.c',
	'netlink/secgw_netlink_route.c',
	'netlink/secgw_netlink_xfrm.c',
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
	'nodes/net/ip_feature.c',
	'nodes/net/ip4/ip4_lookup.c',
	'nodes/net/ip4/ip4_local.c',
	'nodes/net/ip4/ip4_rewrite.c',
	'nodes/net/classifier/pkt_cls.c',
	'nodes/net/ipsec/ipsec.c',
	'nodes/net/ipsec/ipsec_policy_output.c',
)

includes += include_directories(['.'])

deps = ['portgroup']
deps += ['workers']
deps += ['netlink']
deps += ['featurearc']
