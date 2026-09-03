# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2025 Marvell.

# Test script
tests = [
    # Name, Script, Args
    ['rdma_octterm_ud_ping', 'rdma_octterm_ud_ping.sh', ''],
    ['rdma_octterm_rc_ping', 'rdma_octterm_rc_ping.sh', ''],
    ['rdma_octterm_cm_test', 'rdma_octterm_cm_test.sh', ''],
    ['rdma_octterm_mq_trf', 'rdma_octterm_mq_trf.sh', ''],
]

test_dir = meson.current_build_dir()
scenarios = ['mlx', 'octeon']
foreach scen : scenarios
    foreach t : tests
        test(t[0] + '_' + scen,
             dao_test_script_wrapper,
             env : [['DAO_TEST=' + t[0] + '_' + scen], ['TEST_DIR=' + test_dir], ['RDMA_TOPO=' + scen]],
             args : [[t[1]], [t[2]]],
             is_parallel : false, suite : 'dao-rdma-octterm')
    endforeach
endforeach
