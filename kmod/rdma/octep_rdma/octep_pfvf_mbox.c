/* SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2025 Marvell.
 */

#include <linux/types.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/mutex.h>
#include <linux/jiffies.h>

#include "octep_sdp.h"
#include "octep_pfvf_mbox.h"
#include "octep_sdp_regs.h"

/*
 * When a new command is implemented, the below table should be updated
 * with new command and it's version info.
 */

static u32 pfvf_cmd_versions[OCTEP_RDMA_PFVF_MBOX_CMD_MAX] = {
	[0 ... OCTEP_RDMA_PFVF_MBOX_NOTIF_HEARTBEAT] = OCTEP_RDMA_PFVF_MBOX_VERSION_V0,
};

static void octep_pfvf_validate_version(struct octep_sdp_dev *octep_dev, u32 vf_id,
					union octep_rdma_pfvf_mbox_word cmd,
					union octep_rdma_pfvf_mbox_word *rsp)
{
	u32 vf_version = (u32)cmd.s_version.version;

	dev_info(&octep_dev->pdev->dev, "VF id:%d VF version:%d PF version:%d", vf_id, vf_version,
		 OCTEP_RDMA_PFVF_MBOX_VERSION_CURRENT);
	if (vf_version < OCTEP_RDMA_PFVF_MBOX_VERSION_CURRENT)
		rsp->s_version.version = vf_version;
	else
		rsp->s_version.version = OCTEP_RDMA_PFVF_MBOX_VERSION_CURRENT;

	octep_dev->vf_info[vf_id].mbox_version = rsp->s_version.version;
	dev_info(&octep_dev->pdev->dev, "VF id:%d negotiated VF version:%d\n", vf_id,
		 octep_dev->vf_info[vf_id].mbox_version);

	rsp->s_version.type = OCTEP_RDMA_PFVF_MBOX_TYPE_RSP_ACK;
}

/* Send a notification to a specific VF */
int octep_rdma_send_notification(struct octep_sdp_dev *octep_dev, u32 vf_id,
				 union octep_rdma_pfvf_mbox_word cmd)
{
	u32 max_rings_per_vf, vf_mbox_queue;
	struct octep_sdp_mbox *mbox;

	if (!octep_dev || !octep_dev->conf) {
		if (octep_dev)
			dev_err(&octep_dev->pdev->dev, "Mailbox not configured");
		return -EINVAL;
	}

	max_rings_per_vf = CFG_GET_MAX_RPVF(octep_dev->conf);
	vf_mbox_queue = vf_id * max_rings_per_vf;

	if (vf_mbox_queue >= OCTEP_MAX_VF * max_rings_per_vf) {
		dev_err(&octep_dev->pdev->dev, "Invalid VF ID %d", vf_id);
		return -EINVAL;
	}

	if (!octep_dev->mbox[vf_mbox_queue]) {
		dev_err(&octep_dev->pdev->dev, "Mbox not configured for VF %d", vf_id);
		return -EINVAL;
	}

	mbox = octep_dev->mbox[vf_mbox_queue];

	mutex_lock(&mbox->lock);
	dev_info(&octep_dev->pdev->dev, "PF sending to VF %d: raw=0x%llx opcode=%d type=%d\n",
		 vf_id, cmd.u64, cmd.s.opcode, cmd.s.type);
	writeq(cmd.u64, mbox->pf_vf_data_reg);
	mutex_unlock(&mbox->lock);
	return 0;
}

/* Send heartbeat miss notification to all VFs */
void octep_rdma_send_heartbeat_miss_to_all_vfs(struct octep_sdp_dev *octep_dev, u32 miss_count)
{
	union octep_rdma_pfvf_mbox_word heartbeat_cmd;
	u32 active_vfs, vf;
	int ret;

	if (!octep_dev || !octep_dev->conf) {
		if (octep_dev)
			dev_warn(&octep_dev->pdev->dev, "Device not properly configured");
		return;
	}

	active_vfs = CFG_GET_ACTIVE_VFS(octep_dev->conf);
	if (!active_vfs) {
		dev_dbg(&octep_dev->pdev->dev, "No active VFs to notify");
		return;
	}

	/* Prepare heartbeat miss notification */
	heartbeat_cmd.u64 = 0;
	heartbeat_cmd.s_heartbeat.opcode = OCTEP_RDMA_PFVF_MBOX_NOTIF_HEARTBEAT;
	heartbeat_cmd.s_heartbeat.type = OCTEP_RDMA_PFVF_MBOX_TYPE_CMD;
	heartbeat_cmd.s_heartbeat.status = (miss_count >= OCTEP_HB_MISS_COUNT_THRESHOLD) ?
						   OCTEP_RDMA_PFVF_HEARTBEAT_STATUS_TIMEOUT :
						   OCTEP_RDMA_PFVF_HEARTBEAT_STATUS_MISSED;
	heartbeat_cmd.s_heartbeat.timestamp = jiffies & 0xFFFFFFFF;

	dev_warn(&octep_dev->pdev->dev, "Sending heartbeat miss (%d) to %d VFs", miss_count,
		 active_vfs);

	/* Send heartbeat miss to each active VF */
	for (vf = 0; vf < active_vfs; vf++) {
		ret = octep_rdma_send_notification(octep_dev, vf, heartbeat_cmd);
		if (ret) {
			dev_warn(&octep_dev->pdev->dev,
				 "Failed to send heartbeat miss to VF %d: %d\n", vf, ret);
		} else {
			dev_dbg(&octep_dev->pdev->dev, "Heartbeat miss sent to VF %d", vf);
		}
	}

	dev_info(&octep_dev->pdev->dev, "Heartbeat miss notification sent to all VFs");
}

/* Send link status (UP or DOWN) to given VF */
void octep_rdma_send_link_status(struct octep_sdp_dev *octep_dev, uint32_t vf, uint8_t link_status)
{
	union octep_rdma_pfvf_mbox_word link_status_cmd;
	const char *status_str = (link_status == OCTEP_RDMA_PFVF_LINK_STATUS_UP) ? "UP" : "DOWN";
	int ret;

	if (!octep_dev || !octep_dev->conf) {
		if (octep_dev)
			dev_warn(&octep_dev->pdev->dev, "Device not properly configured");
		return;
	}

	/* Prepare link status notification */
	link_status_cmd.u64 = 0;
	link_status_cmd.s_link_status.opcode = OCTEP_RDMA_PFVF_MBOX_NOTIF_LINK_STATUS;
	link_status_cmd.s_link_status.type = OCTEP_RDMA_PFVF_MBOX_TYPE_CMD;
	link_status_cmd.s_link_status.vf_id = vf;
	link_status_cmd.s_link_status.status = link_status;

	dev_warn(&octep_dev->pdev->dev, "Sending link %s notification to VF %d", status_str, vf);

	/* Send link status notification to the specified VF */
	ret = octep_rdma_send_notification(octep_dev, vf, link_status_cmd);
	if (ret) {
		dev_warn(&octep_dev->pdev->dev,
			 "Failed to send link %s notification to VF %d: %d\n", status_str, vf, ret);
	} else {
		dev_dbg(&octep_dev->pdev->dev, "Link %s notification sent to VF %d", status_str,
			vf);
	}
}

/* Setup PF-VF mailbox infrastructure */
int octep_setup_pfvf_mbox(struct octep_sdp_dev *octep_dev)
{
	int i = 0, num_vfs = 0, rings_per_vf = 0;
	int ring = 0;

	dev_info(&octep_dev->pdev->dev, "Setting up octep PF VF mailbox");
	num_vfs = octep_dev->conf->sriov_cfg.max_vfs;
	rings_per_vf = octep_dev->conf->sriov_cfg.max_rings_per_vf;

	for (i = 0; i < num_vfs; i++) {
		/* TODO: FIXME: VSR: discuss about the usage of i and ring variables */
		ring = rings_per_vf * i;
		octep_dev->mbox[ring] = vzalloc(sizeof(*octep_dev->mbox[ring]));

		if (!octep_dev->mbox[ring])
			goto free_mbox;

		memset(octep_dev->mbox[ring], 0, sizeof(struct octep_mbox));
		memset(&octep_dev->vf_info[i], 0, sizeof(struct octep_pfvf_info));
		mutex_init(&octep_dev->mbox[ring]->lock);
		INIT_WORK(&octep_dev->mbox[ring]->wk.work, octep_pfvf_mbox_work);
		octep_dev->mbox[ring]->wk.ctxptr = octep_dev->mbox[ring];
		octep_dev->mbox[ring]->octep_dev = octep_dev;
		octep_dev->mbox[ring]->vf_id = i;
		octep_dev->hw_ops.setup_mbox_regs(octep_dev, ring);
	}
	return 0;

free_mbox:
	while (i) {
		i--;
		ring = rings_per_vf * i;
		cancel_work_sync(&octep_dev->mbox[ring]->wk.work);
		mutex_destroy(&octep_dev->mbox[ring]->lock);
		vfree(octep_dev->mbox[ring]);
		octep_dev->mbox[ring] = NULL;
	}
	return 1;
}

/* Delete PF-VF mailbox infrastructure */
void octep_delete_pfvf_mbox(struct octep_sdp_dev *octep_dev)
{
	int rings_per_vf = octep_dev->conf->sriov_cfg.max_rings_per_vf;
	int num_vfs = octep_dev->conf->sriov_cfg.active_vfs;
	int i = 0, ring = 0, vf_srn = 0;

	for (i = 0; i < num_vfs; i++) {
		ring = vf_srn + rings_per_vf * i;
		if (!octep_dev->mbox[ring])
			continue;

		if (work_pending(&octep_dev->mbox[ring]->wk.work))
			cancel_work_sync(&octep_dev->mbox[ring]->wk.work);

		mutex_destroy(&octep_dev->mbox[ring]->lock);
		vfree(octep_dev->mbox[ring]);
		octep_dev->mbox[ring] = NULL;
	}
}

/* Work function to handle PF-VF mailbox messages */
void octep_pfvf_mbox_work(struct work_struct *work)
{
	struct octep_pfvf_mbox_wk *wk = container_of(work, struct octep_pfvf_mbox_wk, work);
	union octep_rdma_pfvf_mbox_word cmd = { 0 };
	union octep_rdma_pfvf_mbox_word rsp = { 0 };
	struct octep_sdp_mbox *mbox = NULL;
	struct octep_sdp_dev *octep_dev = NULL;
	int vf_id;

	mbox = (struct octep_sdp_mbox *)wk->ctxptr;
	octep_dev = (struct octep_sdp_dev *)mbox->octep_dev;
	vf_id = mbox->vf_id;

	mutex_lock(&mbox->lock);
	cmd.u64 = readq(mbox->vf_pf_data_reg);
	if (unlikely(cmd.u64 == 0xFFFFFFFFFFFFFFFFU)) {
		mutex_unlock(&mbox->lock);
		return;
	}

	rsp.u64 = 0;
	dev_dbg(&octep_dev->pdev->dev, "Opcode sent from PF %d", cmd.s.opcode);
	switch (cmd.s.opcode) {
	case OCTEP_RDMA_PFVF_MBOX_CMD_VERSION:
		octep_pfvf_validate_version(octep_dev, vf_id, cmd, &rsp);
		break;
	default:
		dev_err(&octep_dev->pdev->dev, "PF-VF mailbox: invalid opcode %d", cmd.s.opcode);
		rsp.s.type = OCTEP_RDMA_PFVF_MBOX_TYPE_RSP_NACK;
		break;
	}
	writeq(rsp.u64, mbox->vf_pf_data_reg);
	mutex_unlock(&mbox->lock);
}

int octep_vf_setup_mbox(struct octep_sdp_dev *octep_dev)
{
	int ring = 0;

	octep_dev->vf_mbox = vzalloc(sizeof(*octep_dev->vf_mbox));
	if (!octep_dev->vf_mbox)
		return -1;

	mutex_init(&octep_dev->vf_mbox->lock);

	octep_dev->hw_ops.setup_mbox_regs(octep_dev, ring);
	INIT_WORK(&octep_dev->vf_mbox->wk.work, octep_vf_mbox_work);
	octep_dev->vf_mbox->wk.ctxptr = octep_dev;
	octep_dev->mbox_neg_ver = OCTEP_RDMA_PFVF_MBOX_VERSION_CURRENT;
	dev_info(&octep_dev->pdev->dev, "setup vf mbox successfully");
	return 0;
}

void octep_vf_delete_mbox(struct octep_sdp_dev *octep_dev)
{
	if (octep_dev->vf_mbox) {
		if (work_pending(&octep_dev->vf_mbox->wk.work))
			cancel_work_sync(&octep_dev->vf_mbox->wk.work);

		mutex_destroy(&octep_dev->vf_mbox->lock);
		vfree(octep_dev->vf_mbox);
		octep_dev->vf_mbox = NULL;
		dev_info(&octep_dev->pdev->dev, "Deleted vf mbox successfully");
	}
}

int octep_vf_mbox_version_check(struct octep_sdp_dev *octep_dev)
{
	union octep_rdma_pfvf_mbox_word cmd;
	union octep_rdma_pfvf_mbox_word rsp;
	int ret;

	cmd.u64 = 0;
	cmd.s_version.opcode = OCTEP_RDMA_PFVF_MBOX_CMD_VERSION;
	cmd.s_version.version = OCTEP_RDMA_PFVF_MBOX_VERSION_CURRENT;
	dev_info(&octep_dev->pdev->dev, "Sending opcode %d from VF %lld", cmd.s_version.opcode,
		 cmd.u64);
	ret = octep_vf_mbox_send_cmd(octep_dev, cmd, &rsp);

	if (ret == OCTEP_RDMA_PFVF_MBOX_CMD_STATUS_NACK) {
		dev_err(&octep_dev->pdev->dev, "VF Mbox version is incompatible with PF");
		return -EINVAL;
	}
	octep_dev->mbox_neg_ver = (u32)rsp.s_version.version;
	dev_info(&octep_dev->pdev->dev, "VF Mbox version:%u Negotiated VF version with PF:%u",
		 (u32)cmd.s_version.version, (u32)rsp.s_version.version);
	return 0;
}

void octep_vf_mbox_work(struct work_struct *work)
{
	struct octep_vf_mbox_wk *wk = container_of(work, struct octep_vf_mbox_wk, work);
	struct octep_sdp_dev *octep_dev = NULL;
	struct octep_sdp_vf_mbox *mbox = NULL;
	union octep_rdma_pfvf_mbox_word *notif;
	u64 pf_vf_data;

	octep_dev = (struct octep_sdp_dev *)wk->ctxptr;
	mbox = octep_dev->vf_mbox;
	pf_vf_data = readq(mbox->mbox_read_reg);
	if (unlikely(pf_vf_data == 0xFFFFFFFFFFFFFFFFU))
		return;

	/* Check for zero data - indicates no actual notification from PF */
	if (pf_vf_data == 0x0) {
		dev_dbg(&octep_dev->pdev->dev, "VF mailbox: received "
					       " zero data, ignoring spurious interrupt");
		return;
	}

	notif = (union octep_rdma_pfvf_mbox_word *)&pf_vf_data;

	dev_info(&octep_dev->pdev->dev, "VF received notification: raw=0x%llx opcode=%d type=%d\n",
		 pf_vf_data, notif->s.opcode, notif->s.type);

	switch (notif->s.opcode) {
	case OCTEP_RDMA_PFVF_MBOX_NOTIF_LINK_STATUS:
		if (notif->s_link_status.status == OCTEP_RDMA_PFVF_LINK_STATUS_UP) {
			netif_carrier_on(octep_dev->netdev);
			dev_info(&octep_dev->pdev->dev, "Link UP: netif_carrier_on for VF %d",
				 notif->s_link_status.vf_id);
		} else {
			netif_carrier_off(octep_dev->netdev);
			dev_info(&octep_dev->pdev->dev, "Link DOWN: netif_carrier_off for VF %d",
				 notif->s_link_status.vf_id);
		}
		break;
	case OCTEP_RDMA_PFVF_MBOX_NOTIF_HEARTBEAT:
		netif_carrier_off(octep_dev->netdev);
		dev_err(&octep_dev->pdev->dev, "Received RDMA Heartbeat miss notification");
		cancel_delayed_work_sync(&octep_dev->vf_hb_task);
		dev_info(&octep_dev->pdev->dev, "VF heartbeat timeout task stopped");
		break;
	default:
		dev_err(&octep_dev->pdev->dev, "Received unsupported notif %d", notif->s.opcode);
		break;
	}
}

static int __octep_vf_mbox_send_cmd(struct octep_sdp_dev *octep_dev,
				    union octep_rdma_pfvf_mbox_word cmd,
				    union octep_rdma_pfvf_mbox_word *rsp)
{
	struct octep_sdp_vf_mbox *mbox = octep_dev->vf_mbox;
	u64 reg_val = 0ull;
	int count = 0;

	if (!mbox)
		return OCTEP_RDMA_PFVF_MBOX_CMD_STATUS_NOT_SETUP;

	cmd.s.type = OCTEP_RDMA_PFVF_MBOX_TYPE_CMD;
	writeq(cmd.u64, mbox->mbox_write_reg);
	/* No response for notification messages */
	if (!rsp)
		return 0;

	for (count = 0; count < OCTEP_RDMA_PFVF_MBOX_TIMEOUT_WAIT_COUNT; count++) {
		usleep_range(1000, 1500);
		reg_val = readq(mbox->mbox_write_reg);
		if (unlikely(reg_val == 0xFFFFFFFFFFFFFFFFU)) {
			dev_err(&octep_dev->pdev->dev, "mbox send command err");
			return OCTEP_RDMA_PFVF_MBOX_CMD_STATUS_ERR;
		}
		if (reg_val != cmd.u64) {
			rsp->u64 = reg_val;
			break;
		}
	}
	if (count == OCTEP_RDMA_PFVF_MBOX_TIMEOUT_WAIT_COUNT) {
		dev_err(&octep_dev->pdev->dev, "mbox send command timed out");
		return OCTEP_RDMA_PFVF_MBOX_CMD_STATUS_TIMEDOUT;
	}
	if (rsp->s.type != OCTEP_RDMA_PFVF_MBOX_TYPE_RSP_ACK) {
		dev_err(&octep_dev->pdev->dev, "mbox_send: Received NACK");
		return OCTEP_RDMA_PFVF_MBOX_CMD_STATUS_NACK;
	}
	rsp->u64 = reg_val;
	return 0;
}

int octep_vf_mbox_send_cmd(struct octep_sdp_dev *octep_dev, union octep_rdma_pfvf_mbox_word cmd,
			   union octep_rdma_pfvf_mbox_word *rsp)
{
	struct octep_sdp_vf_mbox *mbox = octep_dev->vf_mbox;
	int ret;

	if (!mbox)
		return OCTEP_RDMA_PFVF_MBOX_CMD_STATUS_NOT_SETUP;
	mutex_lock(&mbox->lock);
	if (pfvf_cmd_versions[cmd.s.opcode] > octep_dev->mbox_neg_ver) {
		dev_info(&octep_dev->pdev->dev, "CMD:%d not supported in Version:%d\n",
			 cmd.s.opcode, octep_dev->mbox_neg_ver);
		mutex_unlock(&mbox->lock);
		return -EOPNOTSUPP;
	}
	ret = __octep_vf_mbox_send_cmd(octep_dev, cmd, rsp);
	mutex_unlock(&mbox->lock);
	return ret;
}
