/* SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2025 Marvell.
 */

#ifndef __OCTEP_RDMA_PFVF_MBOX_H__
#define __OCTEP_RDMA_PFVF_MBOX_H__

/* Forward declaration to avoid circular dependencies */
struct octep_ep_dev;

/*
 * When a new command is implemented, VF Mbox version should be bumped.
 */
enum octep_rdma_pfvf_mbox_version {
	OCTEP_RDMA_PFVF_MBOX_VERSION_V0,
};

#define OCTEP_RDMA_PFVF_MBOX_VERSION_CURRENT OCTEP_RDMA_PFVF_MBOX_VERSION_V0

/* PF-VF mailbox commands for RDMA */
enum octep_rdma_pfvf_mbox_opcode {
	OCTEP_RDMA_PFVF_MBOX_CMD_VERSION,
	OCTEP_RDMA_PFVF_MBOX_NOTIF_LINK_STATUS,
	OCTEP_RDMA_PFVF_MBOX_NOTIF_HEARTBEAT,
	OCTEP_RDMA_PFVF_MBOX_CMD_MAX,
};

enum octep_rdma_pfvf_mbox_word_type {
	OCTEP_RDMA_PFVF_MBOX_TYPE_CMD,
	OCTEP_RDMA_PFVF_MBOX_TYPE_RSP_ACK,
	OCTEP_RDMA_PFVF_MBOX_TYPE_RSP_NACK,
};

enum octep_rdma_pfvf_mbox_cmd_status {
	OCTEP_RDMA_PFVF_MBOX_CMD_STATUS_NOT_SETUP = 1,
	OCTEP_RDMA_PFVF_MBOX_CMD_STATUS_TIMEDOUT = 2,
	OCTEP_RDMA_PFVF_MBOX_CMD_STATUS_NACK = 3,
	OCTEP_RDMA_PFVF_MBOX_CMD_STATUS_ERR = 5
};

/* Heartbeat status */
enum octep_rdma_pfvf_heartbeat_status {
	OCTEP_RDMA_PFVF_HEARTBEAT_STATUS_MISSED,
	OCTEP_RDMA_PFVF_HEARTBEAT_STATUS_TIMEOUT,
};

/* Link status */
enum octep_rdma_pfvf_link_status {
	OCTEP_RDMA_PFVF_LINK_STATUS_DOWN,
	OCTEP_RDMA_PFVF_LINK_STATUS_UP,
};

/* Constants */
#define OCTEP_HB_MISS_COUNT_THRESHOLD 3
#define OCTEP_RDMA_PFVF_MBOX_TIMEOUT_WAIT_COUNT 10000
#define OCTEP_RDMA_PFVF_MBOX_MAX_DATA_BUF_SIZE 320

/* PF-VF mailbox message word */
union octep_rdma_pfvf_mbox_word {
	u64 u64;

	struct {
		u64 opcode : 8;
		u64 type : 2;
		u64 rsvd : 6;
		u64 data : 48;
	} s;

	struct {
		u64 opcode : 8;
		u64 type : 2;
		u64 rsvd : 6;
		u64 version : 48;
	} s_version;

	struct {
		u64 opcode : 8;
		u64 type : 2;
		u64 rsvd : 6;
		u64 status : 8;
		u64 timestamp : 32;
	} s_heartbeat;

	struct {
		u64 opcode : 8;
		u64 type : 2;
		u64 rsvd : 6;
		u32 vf_id : 8;
		u64 status : 8;
		u64 reserved : 32;
	} s_link_status;
};

int octep_rdma_send_notification(struct octep_ep_dev *octep_dev, u32 vf_id,
				 union octep_rdma_pfvf_mbox_word cmd);
void octep_rdma_send_heartbeat_miss_to_all_vfs(struct octep_ep_dev *octep_dev, u32 miss_count);
void octep_rdma_send_link_status(struct octep_ep_dev *octep_dev, uint32_t vf, uint8_t link_status);
/* PF-VF mailbox functions */
int octep_setup_pfvf_mbox(struct octep_ep_dev *octep_dev);
void octep_delete_pfvf_mbox(struct octep_ep_dev *octep_dev);
void octep_pfvf_mbox_work(struct work_struct *work);

int octep_vf_setup_mbox(struct octep_ep_dev *octep_dev);
void octep_vf_delete_mbox(struct octep_ep_dev *octep_dev);
int octep_vf_mbox_version_check(struct octep_ep_dev *octep_dev);
void octep_vf_mbox_work(struct work_struct *work);
int octep_vf_mbox_send_cmd(struct octep_ep_dev *octep_dev, union octep_rdma_pfvf_mbox_word cmd,
			   union octep_rdma_pfvf_mbox_word *rsp);

#endif /* __OCTEP_RDMA_PFVF_MBOX_H__ */
