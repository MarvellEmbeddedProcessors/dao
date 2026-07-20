# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2025 Marvell.

# Test script
tests = [
    # Name, Script, Args
    ['rdma_ud_ping', 'rdma_ud_ping.sh', ''],
    ['rdma_rc_ping', 'rdma_rc_ping.sh', ''],
    ['rdma_cm_test', 'rdma_cm_test.sh', ''],
    ['rdma_perftest', 'rdma_perftest.sh', ''],
    ['rdma_mq_trf', 'rdma_mq_trf.sh', ''],
]

test_dir = meson.current_build_dir()
# Run every test per scenario: all Octeon<->Mellanox first, then all Octeon<->Octeon.
scenarios = ['mlx', 'octeon']
foreach scen : scenarios
    foreach t : tests
        test(t[0] + '_' + scen,
             dao_test_script_wrapper,
             # DAO_TEST carries the scenario so each variant gets a unique test-list
             # entry name; the script hardcodes its own function for test_run dispatch.
             env : [['DAO_TEST=' + t[0] + '_' + scen], ['TEST_DIR=' + test_dir], ['RDMA_SCENARIO=' + scen]],
             args : [[t[1]], [t[2]]],
             is_parallel : false, suite : 'dao-rdma')
    endforeach
endforeach
