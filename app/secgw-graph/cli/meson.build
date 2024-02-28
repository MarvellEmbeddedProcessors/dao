# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2024 Marvell.

build = DAO_CC.has_header('sys/epoll.h')

if not build
    subdir_done()
endif

sources += files(
	'cli.c',
	'cli_conn.c',
	'secgw_cli.c',
)

includes += include_directories(['.'])

# Autogenerate the commands.h
cmd_h = custom_target('commands_hdr',
        output: 'secgw_commands.h',
        input: files('secgw.cli'),
        capture: true,
        command: [cmdline_gen_cmd, '--context-name=modules_ctx', '@INPUT@']
)
sources += cmd_h
