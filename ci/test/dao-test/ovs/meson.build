# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2024 Marvell.

# Test script
tests = [
    # Name, Script, Args
    ['ovs_plain_ping', 'ovs_ping.sh', ''],
    ['ovs_vlan_ping', 'ovs_ping.sh', ''],
    ['ovs_vxlan_ping', 'ovs_ping.sh', ''],
    ['ovs_plain_ping_hw_offload', 'ovs_ping.sh', ''],
    ['ovs_vlan_ping_hw_offload', 'ovs_ping.sh', ''],
    ['ovs_vxlan_ping_hw_offload', 'ovs_ping.sh', ''],
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
         is_parallel : false, suite : 'dao-ovs')
endforeach
