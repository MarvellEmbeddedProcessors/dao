/* SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2025 Marvell.
 */

#ifndef __OCTEP_DEV_CAP_H__
#define __OCTEP_DEV_CAP_H__

enum octep_rdma_atomic_cap {
	OCTEP_RDMA_ATOMIC_NONE,
	OCTEP_RDMA_ATOMIC_HCA,
	OCTEP_RDMA_ATOMIC_GLOB
};

struct octep_rdma_odp_caps {
	u64 general_caps;
	struct {
		u32 rc_odp_caps;
		u32 uc_odp_caps;
		u32 ud_odp_caps;
		u32 xrc_odp_caps;
	} per_transport_caps;
};

struct octep_rdma_rss_caps {
	/* Corresponding bit will be set if qp type from
	 * 'enum octep_qp_type' is supported, e.g.
	 * supported_qpts |= 1 << OCTEP_QPT_UD
	 **/
	u32 supported_qpts;
	u32 max_rwq_indirection_tables;
	u32 max_rwq_indirection_table_size;
};

struct octep_rdma_tm_caps {
	/* Max size of RNDV header */
	u32 max_rndv_hdr_size;
	/* Max number of entries in tag matching list */
	u32 max_num_tags;
	/* From enum octep_tm_cap_flags */
	u32 flags;
	/* Max number of outstanding list operations */
	u32 max_ops;
	/* Max number of SGE in tag matching entry */
	u32 max_sge;
};

struct octep_rdma_cq_caps {
	u16 max_cq_moderation_count;
	u16 max_cq_moderation_period;
};

struct octep_rdma_device_cap {
	u64 fw_ver;
	u64 node_guid;
	u64 max_mr_size;
	u64 page_size_cap;
	u32 vendor_id;
	u32 vendor_part_id;
	u32 hw_ver;
	int max_qp;
	int max_qp_wr;
	u64 device_cap_flags;
	u64 kernel_cap_flags;
	int max_send_sge;
	int max_recv_sge;
	int max_sge_rd;
	int max_cq;
	int max_cqe;
	int max_mr;
	int max_pd;
	int max_qp_rd_atom;
	int max_ee_rd_atom;
	int max_res_rd_atom;
	int max_qp_init_rd_atom;
	int max_ee_init_rd_atom;
	enum octep_rdma_atomic_cap atomic_cap;
	enum octep_rdma_atomic_cap masked_atomic_cap;
	int max_ee;
	int max_rdd;
	int max_mw;
	int max_raw_ipv6_qp;
	int max_raw_ethy_qp;
	int max_mcast_grp;
	int max_mcast_qp_attach;
	int max_total_mcast_qp_attach;
	int max_ah;
	int max_srq;
	int max_srq_wr;
	int max_srq_sge;
	unsigned int max_fast_reg_page_list_len;
	unsigned int max_pi_fast_reg_page_list_len;
	u16 max_pkeys;
	u8 local_ca_ack_delay;
	int sig_prot_cap;
	int sig_guard_cap;
	struct octep_rdma_odp_caps odp_caps;
	u64 timestamp_mask;
	u64 hca_core_clock; /* in KHZ */
	struct octep_rdma_rss_caps rss_caps;
	u32 max_wq_type_rq;
	u32 raw_packet_caps; /* No support */
	struct octep_rdma_tm_caps tm_caps;
	struct octep_rdma_cq_caps cq_caps;
	u64 max_dm_size;
	u32 max_msg_size;
};

enum octep_rdma_port_state {
	OCTEP_RDMA_PORT_NOP,
	OCTEP_RDMA_PORT_DOWN,
	OCTEP_RDMA_PORT_INIT,
	OCTEP_RDMA_PORT_ARMED,
	OCTEP_RDMA_PORT_ACTIVE,
	OCTEP_RDMA_PORT_ACTIVE_DEFER
};

enum octep_rdma_port_phys_state {
	OCTEP_RDMA_PORT_PHYS_STATE_SLEEP,
	OCTEP_RDMA_PORT_PHYS_STATE_POLLING,
	OCTEP_RDMA_PORT_PHYS_STATE_DISABLED,
	OCTEP_RDMA_PORT_PHYS_STATE_PORT_CONFIGURATION_TRAINING,
	OCTEP_RDMA_PORT_PHYS_STATE_LINK_UP,
	OCTEP_RDMA_PORT_PHYS_STATE_LINK_ERROR_RECOVERY,
	OCTEP_RDMA_PORT_PHYS_STATE_PHY_TEST
};

enum octep_rdma_mtu {
	OCTEP_RDMA_MTU_256 = 1,
	OCTEP_RDMA_MTU_512 = 2,
	OCTEP_RDMA_MTU_1024 = 3,
	OCTEP_RDMA_MTU_2048 = 4,
	OCTEP_RDMA_MTU_4096 = 5
};

struct octep_rdma_port_attr {
	u64 subnet_prefix;
	enum octep_rdma_port_state state;
	enum octep_rdma_mtu max_mtu;
	enum octep_rdma_mtu active_mtu;
	u32 phys_mtu;
	int gid_tbl_len;
	unsigned int ip_gids : 1;
	/* This is the value from PortInfo CapabilityMask, defined by IBA */
	u32 port_cap_flags;
	u32 max_msg_sz;
	u32 bad_pkey_cntr;
	u32 qkey_viol_cntr;
	u16 pkey_tbl_len;
	u32 sm_lid;
	u32 lid;
	u8 lmc;
	u8 max_vl_num;
	u8 sm_sl;
	u8 subnet_timeout;
	u8 init_type_reply;
	u8 active_width;
	u16 active_speed;
	u8 phys_state;
	u16 port_cap_flags2;
};

#endif /* __OCTEP_DEV_CAP_H__ */
