# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2024 Marvell.

# This executable is used as a workaround to make sure that the exe_wrapper gets
# called for scripts also. In the exe_wrapper, this executable is ignored.
dao_test_script_wrapper = executable(
    'dao-test-script-wrapper',
    files('dao_test_script_wrapper.c'),
    install: false)

# Helper command to copy files to build dir
copy_data = find_program('copy_data.py')

