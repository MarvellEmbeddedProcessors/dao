# SPDX-License-Identifier: Marvell-Proprietary
# Copyright (c) 2025 Marvell.

includes = [include_directories('../../kmod/rdma/octep_rdma')]
sources = files(
	'rdma_fp.c',
	'rdma_sp.c',
	'rdma_qp.c',
	'rdma_opcode.c',
	'rdma_net.c',
	'rdma_av.c',
	'rdma_req.c',
	'rdma_resp.c',
	'rdma_utils.c',
	'rdma_mbox.c',
	'rdma_cq.c',
	'rdma_complete.c',
	'rdma_retransmit.c',
	'rdma_dev_cap.c',
	'rdma_eth_update.c',
	'rdma_port.c',
	'rdma_pd_mr.c',
	'rdma_dcqcn.c',
	'rdma_counter.c',
)

headers = files(
	'dao_rdma_fp.h',
	'dao_rdma_sp.h',
	'dao_rdma_mbox.h',
	'rdma_cq.h',
	'rdma_counter.h',
	'rdma_dcqcn.h'
)

deps += ['common', 'pem', 'pts_rdma']

# Enable RDMA debug flag if requested
if get_option('rdma_debug')
    cflags += ['-DRDMA_DEBUG']
endif
