# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2024 Marvell.

if host_build
        skip_lib = true
endif

sources = files(
	'dao_conntrack.c',
	'dao_conntrack_icmp.c',
	'dao_conntrack_tcp.c',
	'dao_conntrack_stats.c',
)

headers = files(
	'dao_conntrack.h',
)

deps += ['common']
