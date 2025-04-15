# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2024 Marvell.

python3 = import('python').find_installation(required: false)
if python3.found()
    py3 = [python3]
else
    py3 = ['meson', 'runpython']
endif

list_dir_globs = py3 + files('list-dir-globs.py')
cmdline_gen_cmd = py3 + files('dpdk-cmdline-gen.py')
