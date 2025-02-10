# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2024 Marvell.

if host_build
	skip_lib = true
endif

sources = files(
	'dao_flow.c',
        'default_profile.c',
        'em_profile.c',
	'flow_acl.c',
        'flow_dbg.c',
        'flow_em.c',
	'flow_hw_offload.c',
        'flow_parser.c',
        'ovs_profile.c',
)

headers = files(
	'dao_flow.h',
)

deps += ['common']
