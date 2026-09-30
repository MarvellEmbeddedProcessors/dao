# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2025 Marvell.

benchmark_tests = [
    ['rdma_bench_perftest', 'rdma_perftest.sh', ''],
]

functionality_tests = [
    ['rdma_func_ud_ping', 'rdma_ud_ping.sh', ''],
    ['rdma_func_rc_ping', 'rdma_rc_ping.sh', ''],
    ['rdma_func_cm_test', 'rdma_cm_test.sh', ''],
    ['rdma_func_perftest', 'rdma_perftest.sh', ''],
    # ['rdma_func_perftest_enq_deq_ops', 'rdma_perftest.sh', ''],
    ['rdma_func_mq_trf', 'rdma_mq_trf.sh', ''],
]

test_dir = meson.current_build_dir()
topos = ['mlx', 'octeon']
foreach topo : topos
    foreach t : benchmark_tests
        test(t[0] + '_' + topo,
             dao_test_script_wrapper,
             env : [['DAO_TEST=' + t[0] + '_' + topo], ['TEST_DIR=' + test_dir],
                    ['RDMA_TOPO=' + topo], ['RDMA_CI_TEST_TYPE=benchmark']],
             args : [[t[1]], [t[2]]],
             is_parallel : false, suite : 'dao-rdma')
    endforeach
    foreach t : functionality_tests
        extra_env = [['DAO_TEST=' + t[0] + '_' + topo], ['TEST_DIR=' + test_dir],
                     ['RDMA_TOPO=' + topo], ['RDMA_CI_TEST_TYPE=functionality']]
        if t[0] == 'rdma_func_perftest_enq_deq_ops'
            extra_env += [['RDMA_DMA_OPS_MODE=1']]
        endif
        test(t[0] + '_' + topo,
             dao_test_script_wrapper,
             env : extra_env,
             args : [[t[1]], [t[2]]],
             is_parallel : false, suite : 'dao-rdma')
    endforeach
endforeach
