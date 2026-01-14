# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2025 Marvell.

# Test script
tests = [
    # Name, Script, Args
    ['rdma_ud_ping', 'rdma_ud_ping.sh', ''],
    ['rdma_rc_ping', 'rdma_rc_ping.sh', ''],
    ['rdma_cm_test', 'rdma_cm_test.sh', ''],
]

test_dir = meson.current_build_dir()
foreach t : tests
    test_name = t[0]
    test_script = t[1]
    test_args = t[2]
    test(test_name,
         dao_test_script_wrapper,
         env : [['DAO_TEST=' + test_name], ['TEST_DIR=' + test_dir]],
         args : [[test_script], [test_args]],
         is_parallel : false, suite : 'dao-rdma')
endforeach
