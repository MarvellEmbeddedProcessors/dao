# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2023 Marvell.

build = DAO_CC.has_header('sys/epoll.h')
if not build
    subdir_done()
endif

sources += files(
	'smc_cli.c',
	'smc_conn.c',
	'smc_ethdev.c',
	'smc_graph_cli.c',
	'smc_lcore.c',
	'smc_mempool.c',
	'smc_pipeline.c',
	'smc_port.c',
)

# Autogenerate the commands.h
cmd_h = custom_target('commands_hdr',
        output: 'smc_commands.h',
        input: files('smc_commands.list'),
        capture: true,
        command: [cmdline_gen_cmd, '--context-name=modules_ctx', '@INPUT@']
)
sources += cmd_h
