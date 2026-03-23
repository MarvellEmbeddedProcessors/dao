/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include "rdma_dev_cap_priv.h"
#include "rdma_kernel_abi.h"
#include <dao_log.h>
#include <dao_pts_rdma_dev.h>
#include <rte_mbuf.h>
#define DEFAULT_PEM 0

/* default/initial device parameter */
struct rdma_device_cap dev_cap = {
	.vendor_id = RDMA_VENDOR_ID,
	.max_mr_size = RDMA_MAX_MR_SIZE,
	.page_size_cap = RDMA_PAGE_SIZE_CAP,
	.max_qp = RDMA_MAX_QP,
	.max_qp_wr = RDMA_MAX_QP_WR,
	.device_cap_flags = RDMA_DEVICE_CAP_FLAGS,
	.max_send_sge = RDMA_MAX_SGE,
	.max_recv_sge = RDMA_MAX_SGE,
	.max_sge_rd = RDMA_MAX_SGE_RD,
	.max_cq = RDMA_MAX_CQ,
	.max_cqe = (1 << RDMA_MAX_LOG_CQE) - 1,
	.max_mr = RDMA_MAX_MR,
	.max_pd = RDMA_MAX_PD,
	.max_qp_rd_atom = RDMA_MAX_QP_RD_ATOM,
	.max_res_rd_atom = RDMA_MAX_RES_RD_ATOM,
	.max_qp_init_rd_atom = RDMA_MAX_QP_INIT_RD_ATOM,
	.atomic_cap = RDMA_ATOMIC_NONE,
	.max_mcast_grp = RDMA_MAX_MCAST_GRP,
	.max_mcast_qp_attach = RDMA_MAX_MCAST_QP_ATTACH,
	.max_total_mcast_qp_attach = RDMA_MAX_TOT_MCAST_QP_ATTACH,
	.max_ah = RDMA_MAX_AH,
	.max_srq = RDMA_MAX_SRQ,
	.max_srq_wr = RDMA_MAX_SRQ_WR,
	.max_srq_sge = RDMA_MAX_SRQ_SGE,
	.max_fast_reg_page_list_len = RDMA_MAX_FMR_PAGE_LIST_LEN,
	.max_pkeys = RDMA_MAX_PKEYS,
	.local_ca_ack_delay = RDMA_LOCAL_CA_ACK_DELAY,
	//.num_ports = RDMA_NUM_PORT,
};

struct rdma_port_attr port_attr = {
	.state = RDMA_PORT_DOWN,
	.max_mtu = RDMA_MTU_4096,
	.active_mtu = RDMA_MTU_4096,
	.gid_tbl_len = RDMA_PORT_GID_TBL_LEN,
	.port_cap_flags = RDMA_PORT_PORT_CAP_FLAGS,
	.max_msg_sz = RDMA_PORT_MAX_MSG_SZ,
	.bad_pkey_cntr = RDMA_PORT_BAD_PKEY_CNTR,
	.pkey_tbl_len = RDMA_PORT_PKEY_TBL_LEN,
	.lid = RDMA_PORT_LID,
	.sm_lid = RDMA_PORT_SM_LID,
	.lmc = RDMA_PORT_LMC,
	.max_vl_num = RDMA_PORT_MAX_VL_NUM,
	.sm_sl = RDMA_PORT_SM_SL,
	.subnet_timeout = RDMA_PORT_SUBNET_TIMEOUT,
	.init_type_reply = RDMA_PORT_INIT_TYPE_REPLY,
	.active_width = RDMA_PORT_ACTIVE_WIDTH,
	.active_speed = RDMA_PORT_ACTIVE_SPEED,
	.phys_state = RDMA_PORT_PHYS_STATE,
	.subnet_prefix = RDMA_PORT_SUBNET_PREFIX,
};

int
rdma_query_device_cap(int port, void *cap)
{
	struct dao_pts_rdma_dev_info info = {0};
	struct rdma_device_cap *dev_cap_ptr = (struct rdma_device_cap *)cap;

	if (!dev_cap_ptr) {
		dao_err("Invalid argument");
		return -EINVAL;
	}

	dao_pts_rdma_dev_info_get(DEFAULT_PEM, port, &info);

	memcpy(dev_cap_ptr, &dev_cap, sizeof(dev_cap));

	dev_cap_ptr->max_qp = RTE_MIN((uint32_t)info.max_qps, (uint32_t)RDMA_MAX_QP_INDEX);
	dev_cap_ptr->max_cq = RTE_MIN((uint32_t)info.max_cqs, (uint32_t)RDMA_MAX_CQ);

	if (info.max_qps > (uint32_t)RDMA_MAX_QP_INDEX)
		dao_warn("PTS max_qps %u exceeds FW limit %u, capped",
			 info.max_qps, (uint32_t)RDMA_MAX_QP_INDEX);
	if (info.max_cqs > (uint32_t)RDMA_MAX_CQ)
		dao_warn("PTS max_cqs %u exceeds FW limit %u, capped",
			 info.max_cqs, (uint32_t)RDMA_MAX_CQ);

	dao_dbg("RDMA device capabilities for port %d: max_qp=%u, max_cq=%u", port,
		dev_cap_ptr->max_qp, dev_cap_ptr->max_cq);

	return sizeof(dev_cap);
}

int
rdma_query_port_attr(int port, void *attr)
{
	/* FIXME: once multi device support is added */
	RTE_SET_USED(port);

	struct rdma_port_attr *port_attr_ptr = (struct rdma_port_attr *)attr;

	if (!port_attr_ptr) {
		dao_err("Invalid argument");
		return -EINVAL;
	}

	memcpy(port_attr_ptr, &port_attr, sizeof(port_attr));
	return sizeof(port_attr);
}
