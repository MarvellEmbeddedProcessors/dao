# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2024 Marvell.

# Test script
test_script = 'virtio_l2fwd_1c.sh'

# Test name
test_name = 'virtio_l2fwd_1c'

# Test arguments
test_args = ''

# Test directory name relative to build directory.
test_dir = meson.current_build_dir()

# Add the meson test
test(test_name,
    dao_test_script_wrapper,
    env : [['DAO_TEST=' + test_name], ['TEST_DIR=' + test_dir]],
    args : [[test_script], [test_args]],
    is_parallel : false, suite : 'dao-virtio-l2fwd')

