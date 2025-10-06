/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#include <dao_rdma_sp.h>
#include <rte_ethdev.h>

#include "dao_log.h"
#include "dao_rdma_fp.h"
#include "dao_rdma_mbox.h"
#include "rdma_cq.h"
#include "rdma_kernel_abi.h"
#include "rdma_qp.h"

extern rdma_map_cb_t g_rdma_map_cb;

static inline volatile void *
mbox_memcpy(volatile void *d, const volatile void *s, size_t l)
{
	const volatile uint8_t *sb;
	volatile uint8_t *db;
	size_t i;

	if (!d || !s)
		return NULL;
	db = (volatile uint8_t *)d;
	sb = (const volatile uint8_t *)s;
	for (i = 0; i < l; i++)
		db[i] = sb[i];
	return d;
}

static int
mbox_msg_ah_create_handle(volatile void *data)
{
	volatile struct octep_rdma_ah_create_req *req =
		(volatile struct octep_rdma_ah_create_req *)data;
	struct rdma_av av = {0};
	int ret = 0;

	dao_dbg("index %d port_num %d network_type %d sip %x dip %x smac %2x:%2x:%2x:%2x:%2x:%2x "
		"dmac %2x:%2x:%2x:%2x:%2x:%2x",
		req->index, req->port_num, req->network_type, req->s_addr, req->d_addr,
		req->smac[0], req->smac[1], req->smac[2], req->smac[3], req->smac[4], req->smac[5],
		req->dmac[0], req->dmac[1], req->dmac[2], req->dmac[3], req->dmac[4], req->dmac[5]);

	mbox_memcpy(av.smac.addr_bytes, req->smac, sizeof(req->smac));
	mbox_memcpy(av.dmac.addr_bytes, req->dmac, sizeof(req->dmac));

	av.port_num = req->port_num;
	av.index = req->index;
	av.dgid_addr.ip4 = req->d_addr;
	av.sgid_addr.ip4 = req->s_addr;
	av.iph.hop_limit = 64;
	av.network_type = req->network_type;

	ret = dao_rdma_av_insert((void *)&av);
	if (ret) {
		dao_err("AV insert failed");
		return -1;
	}

	return 0;
}

static int
mbox_msg_av_modify(volatile void *data)
{
	volatile struct octep_rdma_ah_create_req *req =
		(volatile struct octep_rdma_ah_create_req *)data;
	struct rdma_av av = {0};
	int ret = 0;

	dao_dbg("index %d port_num %d network_type %d sip %x dip %x smac %2x:%2x:%2x:%2x:%2x:%2x "
		"dmac %2x:%2x:%2x:%2x:%2x:%2x",
		req->index, req->port_num, req->network_type, req->s_addr, req->d_addr,
		req->smac[0], req->smac[1], req->smac[2], req->smac[3], req->smac[4], req->smac[5],
		req->dmac[0], req->dmac[1], req->dmac[2], req->dmac[3], req->dmac[4], req->dmac[5]);

	mbox_memcpy(av.smac.addr_bytes, req->smac, sizeof(req->smac));
	mbox_memcpy(av.dmac.addr_bytes, req->dmac, sizeof(req->dmac));

	av.port_num = req->port_num;
	av.index = req->index;
	av.dgid_addr.ip4 = req->d_addr;
	av.sgid_addr.ip4 = req->s_addr;
	av.iph.hop_limit = 64;
	av.network_type = req->network_type;

	ret = dao_rdma_av_insert((void *)&av);
	if (ret) {
		dao_err("AV modify failed");
		return -1;
	}

	return 0;
}

static int
mbox_msg_av_remove(volatile void *data)
{
	volatile struct octep_rdma_ah_destroy_req *req =
		(volatile struct octep_rdma_ah_destroy_req *)data;
	struct rdma_av av = {0};
	int ret = 0;

	dao_dbg("index %d port_num %d", req->index, req->port_num);

	av.port_num = req->port_num;
	av.index = req->index;

	ret = dao_rdma_av_remove((void *)&av);
	if (ret) {
		dao_err("AV remove failed");
		return -1;
	}

	return 0;
}

static int
mbox_msg_qp_create_handle(volatile void *data)
{
	volatile struct octep_rdma_qp_create_req *req =
		(volatile struct octep_rdma_qp_create_req *)data;
	struct rdma_qp qp = {0};
	int ret;

	dao_dbg("qp_id %d sq_size %d rq_size %d send cq_id %d recv cq_id %d sq_base 0x%lx type %d",
		req->qp_id, req->sq_size, req->rq_size, req->send_cq_id, req->recv_cq_id,
		req->sq_base, req->type);

	qp.qid = req->qp_id;
	qp.pd_id = req->pd_id;
	qp.type = req->type;
	qp.port_id = req->port_num;
	qp.dev_id = req->port_num;
	qp.pkey = 0xFFFF;
	qp.state = QP_STATE_RESET;
	qp.qkey = 0x11111111;
	qp.sq_base = req->sq_base;
	qp.rq_base = req->rq_base;
	qp.sq_size = req->sq_size;
	qp.rq_size = req->rq_size;
	qp.sq_sig_type = req->sq_sig_type;
	qp.pd_id = req->pd_id;
	qp.dev_id = req->port_num;
	ret = dao_rdma_qp_create((void *)&qp);
	if (ret) {
		dao_err("qp create failed");
		return -1;
	}

	return 0;
}

static int
mbox_msg_cq_create_handle(volatile void *data)
{
	volatile struct octep_rdma_cq_create_req *req =
		(volatile struct octep_rdma_cq_create_req *)data;

	dao_dbg("cq_id %d cq_size %d cq_base 0x%lx", req->cq_id, req->size, req->cq_base);

	rdma_cq_insert(req->cq_base, req->cq_id);

	return 0;
}

static int
mbox_msg_cq_destroy_handle(volatile void *data)
{
	volatile struct octep_rdma_cq_destroy_req *req =
		(volatile struct octep_rdma_cq_destroy_req *)data;

	dao_dbg("cq_id %d", req->cq_id);

	rdma_cq_remove(req->cq_id);

	return 0;
}

static int
mbox_rdma_qp_destroy(volatile void *data)
{
	volatile struct octep_rdma_qp_destroy_req *req =
		(volatile struct octep_rdma_qp_destroy_req *)data;
	struct octep_rdma_qp_destroy_req qp_req = {0};
	int ret;

	dao_dbg("Destroy : port: %d qp_id %d\n", req->port_num, req->qp_id);
	mbox_memcpy(&qp_req, req, sizeof(struct octep_rdma_qp_destroy_req));
	ret = dao_rdma_qp_destroy(qp_req.port_num, qp_req.qp_id);

	if (ret) {
		dao_err("qp destroy failed, req->qp_id %d ireq->port_num %di\n", req->qp_id,
			req->port_num);
		return -1;
	}

	return 0;
}

static int
mbox_msg_port_state(volatile void *data)
{
	volatile struct octep_rdma_port_state_req *req =
		(volatile struct octep_rdma_port_state_req *)data;
	uint16_t mac_port = 0;
	int ret;

	dao_dbg("port_num %d event %d", req->port_num, req->event);

	if (req->event & OCTEP_RDMA_USER_PORT_LINK_STATE) {
		dao_dbg("link state %d", req->evt_data.link_state);
		ret = dao_rdma_port_link_state_update(req->port_num, req->evt_data.link_state);
	} else if (req->event & OCTEP_RDMA_USER_PORT_MTU_CHANGE) {
		uint8_t pause_flag = 1; /* Set to 1 to pause the graph */
		/* Get RPM port ID for this RDMA device and pause the graph */
		if (g_rdma_map_cb)
			mac_port = g_rdma_map_cb(req->port_num, &pause_flag);
		dao_dbg("mtu %d mac_port %u, graph paused", req->evt_data.mtu, mac_port);

		/* Update MTU while graph is paused */
		ret = dao_rdma_update_mtu(mac_port, req->evt_data.mtu);

		/* Unpause the graph after MTU update */
		pause_flag = 0; /* Set to 0 to unpause the graph */
		if (g_rdma_map_cb)
			g_rdma_map_cb(req->port_num, &pause_flag);
		dao_dbg("Graph unpaused after MTU update");
	} else {
		dao_err("Invalid event %d", req->event);
		return -1;
	}

	return ret;
}

static int
mbox_msg_get_device_cap(volatile void *data, uint8_t *rsp, uint16_t *rsp_len)
{
	volatile struct octep_rdma_get_device_cap_msg *msg =
		(volatile struct octep_rdma_get_device_cap_msg *)data;

	struct octep_rdma_get_device_cap_msg response = {0};
	uint16_t cap_len;

	cap_len =
		dao_rdma_get_device_cap(msg->port_num, (struct rdma_device_cap *)&response.dev_cap);

	if (cap_len == 0) {
		dao_err("Failed to get device capabilities");
		return -1;
	}

	*rsp_len = sizeof(struct octep_rdma_get_device_cap_msg);
	// TBD - mbox_memset
	mbox_memcpy(rsp, &response, *rsp_len);

	return 0;
}

static int
mbox_msg_get_port_attr(volatile void *data, uint8_t *rsp, uint16_t *rsp_len)
{
	volatile struct octep_rdma_get_port_attr_msg *msg =
		(volatile struct octep_rdma_get_port_attr_msg *)data;

	struct octep_rdma_get_port_attr_msg response = {0};
	uint16_t port_attr_len;

	port_attr_len = dao_rdma_get_port_attributes(msg->port_num,
						     (struct rdma_port_attr *)&response.port_attr);

	if (port_attr_len == 0) {
		dao_err("Failed to get port attributes");
		return -1;
	}

	*rsp_len = sizeof(struct octep_rdma_get_port_attr_msg);
	mbox_memcpy(rsp, &response, *rsp_len);

	return 0;
}

static int
mbox_rdma_qp_modify(volatile void *data)
{
	volatile struct octep_rdma_user_qp_modify_req *req =
		(volatile struct octep_rdma_user_qp_modify_req *)data;
	struct octep_rdma_user_qp_modify_req qp_req = {0};
	int ret;

	dao_dbg("Qp modify req qp_id %d mask %X", req->qp_id, req->modify_mask);

	mbox_memcpy(&qp_req, req, sizeof(struct octep_rdma_user_qp_modify_req));
	// FIXME
	ret = dao_rdma_qp_modify((void *)&qp_req);
	if (ret) {
		dao_err("qp modify of port_num %u and qpid %d failed", qp_req.port_num,
			qp_req.qp_id);
		return -1;
	}

	return 0;
}

static inline int
mbox_rdma_pd_add(volatile void *data)
{
	struct octep_rdma_pd_add_req req = {0};

	mbox_memcpy(&req, data, sizeof(struct octep_rdma_pd_add_req));
	dao_dbg("[PD ADD] pd_id %u port %u", req.pd_id, req.port_num);

	return dao_rdma_pd_add(&req);
}

static inline int
mbox_rdma_pd_delete(volatile void *data)
{
	struct octep_rdma_pd_delete_req req = {0};

	mbox_memcpy(&req, data, sizeof(struct octep_rdma_pd_delete_req));
	dao_dbg("[PD DEL] pd_id %u port %u", req.pd_id, req.port_num);

	return dao_rdma_pd_delete(&req);
}

static inline int
mbox_rdma_mr_register(volatile void *data)
{
	struct octep_rdma_mr_register_req req = {0};

	mbox_memcpy(&req, data, sizeof(struct octep_rdma_mr_register_req));
	dao_dbg("[mr reg] mr key %u pd_id %u va 0x%lx length %u access_flags %x", req.mr.key,
		req.pd_id, req.mr.va, req.mr.length, req.mr.access_flags);

	return dao_rdma_mr_register((void *)&req);
}

static inline int
mbox_rdma_mr_deregister(volatile void *data)
{
	struct octep_rdma_mr_deregister_req req = {0};

	mbox_memcpy(&req, data, sizeof(struct octep_rdma_mr_deregister_req));
	dao_dbg("[mr dreg] pd_id %u key %u port %u", req.pd_id, req.key, req.port_num);

	return dao_rdma_mr_deregister(&req);
}

int
dao_rdma_mbox_process(uint16_t devid, volatile struct dao_pts_rdma_mbox *mbox, uint8_t *rsp,
		      uint16_t *rsp_len)
{
	uint16_t rc = 0, rsplen = 0;

	RTE_SET_USED(devid);

	dao_dbg("mbox->hdr.sig %x mbox->hdr.id %x", mbox->hdr.sig, mbox->hdr.id);
	if (mbox->hdr.sig != MBOX_REQ_SIG) {
		dao_err("Invalid mbox signature %x", mbox->hdr.sig);
		rc = EINVAL;
		goto exit;
	}

	switch (mbox->hdr.id) {
	case MBOX_MSG_USER_QP_CREATE:
		/* API to QP create config */
		rc = mbox_msg_qp_create_handle(mbox->data);
		break;
	case MBOX_MSG_USER_QP_MODIFY:
		/* API to set QP modification */
		rc = mbox_rdma_qp_modify(mbox->data);
		break;

	case MBOX_MSG_USER_QP_DESTROY:
		rc = mbox_rdma_qp_destroy(mbox->data);
		break;

	case MBOX_MSG_USER_CQ_CREATE:
		rc = mbox_msg_cq_create_handle(mbox->data);
		/* API to CQ create config */
		break;
	case MBOX_MSG_USER_CQ_DESTROY:
		rc = mbox_msg_cq_destroy_handle(mbox->data);
		break;
	case MBOX_MSG_USER_AH_CREATE:
		rc = mbox_msg_ah_create_handle(mbox->data);
		break;
	case MBOX_MSG_USER_AH_MODIFY:
		/* API to set AH modification */
		rc = mbox_msg_av_modify(mbox->data);
		break;
	case MBOX_MSG_USER_AH_DESTROY:
		/* API to set AH destroy */
		rc = mbox_msg_av_remove(mbox->data);
		break;
	case MBOX_MSG_USER_PORT_STATE:
		/*API to set netdev events*/
		rc = mbox_msg_port_state(mbox->data);
		break;
	case MBOX_MSG_USER_QUERY_DEVICE_CAP:
		/* API to get device capabilities */
		rc = mbox_msg_get_device_cap(mbox->data, rsp, &rsplen);
		*rsp_len = rsplen;
		break;
	case MBOX_MSG_USER_QUERY_PORT_ATTR:
		/* API to get port attributes */
		rc = mbox_msg_get_port_attr(mbox->data, rsp, &rsplen);
		*rsp_len = rsplen;
		break;
	case MBOX_MSG_USER_PD_ADD:
		/* API to add protection domain */
		rc = mbox_rdma_pd_add(mbox->data);
		break;
	case MBOX_MSG_USER_PD_DELETE:
		/* API to delete protection domain */
		rc = mbox_rdma_pd_delete(mbox->data);
		break;
	case MBOX_MSG_USER_MR_REGISTER:
		/* API to register memory region */
		rc = mbox_rdma_mr_register(mbox->data);
		break;
	case MBOX_MSG_USER_MR_DEREGISTER:
		/* API to deregister memory region */
		rc = mbox_rdma_mr_deregister(mbox->data);
		break;
	default:
		rc = EINVAL;
		break;
	}

exit:
	return rc;
}
