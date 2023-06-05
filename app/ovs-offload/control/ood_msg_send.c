/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2023 Marvell.
 */

#include <stdint.h>

#include <rte_ethdev.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_hexdump.h>

#include <dao_log.h>

#include <ood_init.h>
#include <ood_msg_ctrl.h>
#include <ood_ctrl_chan.h>

#define CTRL_MSG_RCV_TIMEOUT_MS 2000

static int
receive_control_msg_resp(int sock_fd)
{
	uint32_t wait_us = CTRL_MSG_RCV_TIMEOUT_MS * 1000;
	uint32_t timeout = 0, sleep = 1;
	int sz = 0;
	int rc = -1;
	uint32_t len = BUFSIZ;
	void *msg_buf;

	msg_buf = rte_zmalloc("Response", len, 0);

	do {
		sz = ood_ctrl_msg_recv(sock_fd, msg_buf, len);
		if (sz != 0)
			break;

		/* Timeout after CTRL_MSG_RCV_TIMEOUT_MS */
		if (timeout >= wait_us)
			DAO_ERR_GOTO(-ETIMEDOUT, fail, "Control message wait timedout");

		rte_delay_us(sleep);
		timeout += sleep;
	} while ((sz == 0) || (timeout < wait_us));

	if (sz > 0) {
		dao_info("Received %d sized response packet", sz);
		rc = ood_process_control_packet(msg_buf, sz);
		rte_free(msg_buf);
	}

	return rc;
fail:
	return errno;
}

static int
send_message(void *message, uint32_t len)
{
	struct ood_main_cfg_data *ood_main_cfg;
	const struct rte_memzone *mz;
	int rc;

	mz = rte_memzone_lookup(OOD_MAIN_CFG_MZ_NAME);
	if (!mz)
		DAO_ERR_GOTO(-EINVAL, fail, "Failed to lookup for main_cfg, err %d", errno);

	ood_main_cfg = mz->addr;

	rte_spinlock_lock(&ood_main_cfg->ctrl_chan_prm->ctrl_chan_lock);
	rc = ood_ctrl_msg_send(ood_main_cfg->ctrl_chan_prm->sock_fd, message, len, 0);
	if (rc < 0)
		DAO_ERR_GOTO(rc, free, "Failed to send the message, err %d", rc);

	/* Get response of the command sent */
	rc = receive_control_msg_resp(ood_main_cfg->ctrl_chan_prm->sock_fd);
	if (rc < 0)
		DAO_ERR_GOTO(rc, free, "Failed to receive the response, err %d", rc);

	rte_spinlock_unlock(&ood_main_cfg->ctrl_chan_prm->ctrl_chan_lock);

	return rc;
free:
	rte_spinlock_unlock(&ood_main_cfg->ctrl_chan_prm->ctrl_chan_lock);
fail:
	return errno;
}

static void
populate_type(void *buffer, uint32_t *length, ood_type_t type, uint32_t sz)
{
	uint32_t len = *length;
	ood_type_data_t data;

	/* Prepare type data */
	memset(&data, 0, sizeof(ood_type_data_t));
	data.type = type;
	data.length = sz;

	/* Populate the type data */
	rte_memcpy(RTE_PTR_ADD(buffer, len), &data, sizeof(ood_type_data_t));
	len += sizeof(ood_type_data_t);

	*length = len;
}

static void
populate_header(void *buffer, uint32_t *length)
{
	ood_header_t hdr;
	int len;

	populate_type(buffer, length, OOD_TYPE_HEADER, sizeof(ood_header_t));

	len = *length;
	/* Prepare header data */
	memset(&hdr, 0, sizeof(ood_header_t));
	hdr.signature = OOD_SIGN;
	/* TODO nb_hops logic */

	/* Populate header data */
	rte_memcpy(RTE_PTR_ADD(buffer, len), &hdr, sizeof(ood_header_t));
	len += sizeof(ood_header_t);

	*length = len;
}

static void
populate_command(void *buffer, uint32_t *length, ood_msg_t type, uint32_t size)
{
	ood_msg_data_t msg_data;
	uint32_t len;
	uint16_t sz = sizeof(ood_msg_data_t);

	populate_type(buffer, length, OOD_TYPE_MSG, sz);

	len = *length;
	/* Prepare command data */
	memset(&msg_data, 0, sizeof(ood_type_data_t));
	msg_data.type = type;
	msg_data.length = size;

	/* Populate the command */
	rte_memcpy(RTE_PTR_ADD(buffer, len), &msg_data, sz);
	len += sz;

	*length = len;
}

static void
populate_ack_msg(void *buffer, uint32_t *length, ood_msg_ack_data_t *adata)
{
	uint32_t sz = adata->size;
	uint32_t len;

	populate_command(buffer, length, OOD_MSG_ACK, sz);

	len = *length;

	/* Populate ACK message data */
	if (sz == sizeof(uint64_t))
		rte_memcpy(RTE_PTR_ADD(buffer, len), &adata->u.data, sz);
	else
		rte_memcpy(RTE_PTR_ADD(buffer, len), adata->u.data, sz);
	len += sz;

	*length = len;
}

static void
populate_msg_end(void *buffer, uint32_t *length)
{
	populate_command(buffer, length, OOD_MSG_END, 0);
}

int
ood_send_ack_message(ood_msg_ack_data_t *adata)
{
	const struct rte_memzone *mz;
	struct ood_main_cfg_data *ood_main_cfg;
	int rc;
	void *buffer;
	uint32_t len = 0, size;

	/* Allocate memory for preparing a message */
	size = MAX_BUFFER_SIZE;
	buffer = rte_zmalloc("ACK msg", size, 0);
	if (!buffer) {
		dao_err("Failed to allocate mem");
		return -ENOMEM;
	}

	/* Prepare the ACK message */
	populate_header(buffer, &len);
	populate_ack_msg(buffer, &len, adata);
	populate_msg_end(buffer, &len);

	/* Send it to the peer */
	mz = rte_memzone_lookup(OOD_MAIN_CFG_MZ_NAME);
	if (!mz) {
		dao_err("Failed to lookup for main_cfg, err %d", rte_errno);
		return -rte_errno;
	}
	ood_main_cfg = mz->addr;

	rc = ood_ctrl_msg_send(ood_main_cfg->ctrl_chan_prm->sock_fd, buffer, len, 0);
	if (rc < 0)
		dao_err("Failed to send the message, err %d", rc);

	return 0;
}

static void
populate_ready_msg(struct ood_main_cfg_data *ood_main_cfg, void *buffer, uint32_t *length)
{
	uint32_t sz = sizeof(ood_msg_ready_data_t), total_sz;
	ood_ethdev_param_t *eth_prm;
	ood_msg_ready_data_t *rdata;
	uint32_t len;

	eth_prm = ood_main_cfg->eth_prm;
	total_sz = sz + (eth_prm->nb_ports * sizeof(uint16_t));
	populate_command(buffer, length, OOD_MSG_READY, total_sz);

	len = *length;
	/* Populate ready message data */
	rdata = rte_zmalloc("Ready", total_sz, 0);
	rdata->val = 1;
	rdata->nb_ports = eth_prm->nb_ports;
	rte_memcpy(rdata->data, eth_prm->hw_func, eth_prm->nb_ports * sizeof(uint16_t));

	rte_memcpy(RTE_PTR_ADD(buffer, len), rdata, total_sz);

	len += total_sz;

	*length = len;

	rte_free(rdata);
}

int
ood_send_ready_message(void)
{
	struct ood_main_cfg_data *ood_main_cfg;
	const struct rte_memzone *mz;
	uint32_t len = 0, size;
	void *buffer;

	mz = rte_memzone_lookup(OOD_MAIN_CFG_MZ_NAME);
	if (!mz) {
		dao_err("Failed to lookup for main_cfg, err %d", rte_errno);
		return -rte_errno;
	}
	ood_main_cfg = mz->addr;

	/* Allocate memory for preparing a message */
	size = MAX_BUFFER_SIZE;
	buffer = rte_zmalloc("Ready msg", size, 0);
	if (!buffer) {
		dao_err("Failed to allocate mem");
		return -ENOMEM;
	}

	/* Prepare the ACK message */
	populate_header(buffer, &len);
	populate_ready_msg(ood_main_cfg, buffer, &len);
	populate_msg_end(buffer, &len);

	/* Send it to the peer */
	send_message(buffer, len);

	return 0;
}

static void
populate_exit_msg(struct ood_main_cfg_data *ood_main_cfg, void *buffer, uint32_t *length)
{
	uint32_t sz = sizeof(ood_msg_exit_data_t), total_sz;
	ood_ethdev_param_t *eth_prm;
	ood_msg_exit_data_t *edata;
	uint32_t len;

	eth_prm = ood_main_cfg->eth_prm;
	total_sz = sz + (eth_prm->nb_ports * sizeof(uint16_t));
	populate_command(buffer, length, OOD_MSG_EXIT, total_sz);

	len = *length;

	/* Populate exit message data */
	edata = rte_zmalloc("Exit", total_sz, 0);
	edata->val = 1;
	edata->nb_ports = eth_prm->nb_ports;
	rte_memcpy(edata->data, eth_prm->hw_func, eth_prm->nb_ports * sizeof(uint16_t));
	rte_memcpy(RTE_PTR_ADD(buffer, len), edata, total_sz);

	len += total_sz;

	*length = len;

	rte_free(edata);
}

void
ood_send_exit_message(void)
{
	struct ood_main_cfg_data *ood_main_cfg;
	const struct rte_memzone *mz;
	uint32_t len = 0, size;
	void *buffer;

	mz = rte_memzone_lookup(OOD_MAIN_CFG_MZ_NAME);
	if (!mz) {
		dao_err("Failed to lookup for main_cfg, err %d", rte_errno);
		return;
	}
	ood_main_cfg = mz->addr;

	/* Allocate memory for preparing a message */
	size = MAX_BUFFER_SIZE;
	buffer = rte_zmalloc("Exit msg", size, 0);
	if (!buffer) {
		dao_err("Failed to allocate mem");
		return;
	}

	/* Prepare the ACK message */
	populate_header(buffer, &len);
	populate_exit_msg(ood_main_cfg, buffer, &len);
	populate_msg_end(buffer, &len);

	/* Send it to the peer */
	send_message(buffer, len);

	rte_free(buffer);
}
