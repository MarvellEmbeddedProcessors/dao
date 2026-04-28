/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <dao_log.h>
#include <stdint.h>

#include "rdma_av.h"
#include "rdma_dev_cap_priv.h"
#include "rdma_kernel_abi.h"
#include "rdma_pd_mr.h"
#include "rdma_port_priv.h"
#include "rdma_qp.h"

struct rdma_port *port;
uint8_t num_port;

int
rdma_port_alloc(int nport)
{
	if (port)
		return 0;

	if (!nport)
		nport = RDMA_PORT_MAX;

	port = rte_zmalloc("rdma_port", nport * sizeof(struct rdma_port), 0);
	if (!port) {
		dao_err("rdma port allocation failed\n");
		return -1;
	}
	num_port = nport;

	for (int i = 0; i < num_port; i++)
		port[i].portid = i;

	return 0;
}

/* Shall be called only when the FW is closing down. */
int
rdma_port_free(void)
{
	struct rdma_port *rport;
	int i;

	if (!port)
		return 0;

	for (i = 0; i < num_port; i++) {
		rport = &port[i];
		rdma_qp_free(rport->qp);
		rdma_av_free(rport->av);
		rdma_pd_free(rport->pd_array);
	}
	rte_free(port);
	port = NULL;

	dao_info("RDMA ports freed");
	return 0;
}

static int
rdma_port_attr_init(struct rdma_port *rport)
{
	struct rdma_device_cap cap = {0};

	if (rdma_query_device_cap(rport->portid, &cap) <= 0)
		return -1;

	rport->attr.num_max_qp = cap.max_qp;
	rport->attr.max_send_sge = cap.max_send_sge;
	rport->attr.max_recv_sge = cap.max_recv_sge;
	rport->attr.max_cq = cap.max_cq;
	rport->attr.max_cqe = cap.max_cqe;
	rport->attr.max_mr = cap.max_mr;
	rport->attr.max_pd = cap.max_pd;
	rport->attr.max_qp_rd_atom = cap.max_qp_rd_atom;
	rport->attr.max_ah = cap.max_ah;
	rport->attr.max_srq = cap.max_srq;
	rport->attr.max_srq_wr = cap.max_srq_wr;
	rport->attr.max_srq_sge = cap.max_srq_sge;

	return 0;
}

int
rdma_port_link_state_update(uint16_t port_num, uint16_t link_state)
{
	struct rdma_port *rport;

	if (port_num >= RDMA_PORT_MAX) {
		dao_err("Invalid port number %u", port_num);
		return -1;
	}

	rport = &port[port_num];

	if (rport->state == link_state)
		return 0;

	rport->state = link_state;
	if (rport->state != RDMA_PORT_ST_DOWN)
		rdma_port_attr_init(rport);

	dao_info("Port %u is %s", port_num,
		 rport->state == RDMA_PORT_ST_DOWN ? "RDMA_PORT_ST_DOWN" : "RDMA_PORT_ST_UP");

	return 0;
}

void
rdma_cleanup_resources(uint16_t port_num)
{
	struct octep_rdma_pd_delete_req pd = {0};
	struct rdma_av av = {0};
	struct rdma_port *rport;
	uint32_t i;

	if (port_num >= RDMA_PORT_MAX) {
		dao_err("Invalid port number %u", port_num);
		return;
	}

	for (i = 0; i < RDMA_QP_MAX; i++)
		rdma_qp_destroy(port_num, i);

	for (i = 0; i < RDMA_ADDR_VEC_MAX; i++) {
		av.port_num = port_num;
		av.index = i;
		rdma_av_remove(&av);
	}

	for (i = 0; i < RDMA_MAX_PD; i++) {
		pd.port_num = port_num;
		pd.pd_id = i;
		pd_delete(&pd);
	}

	// Make port state down
	rport = &port[port_num];
	rport->state = RDMA_PORT_ST_DOWN;

	dao_info("Port %u is %s", port_num,
		 rport->state == RDMA_PORT_ST_DOWN ? "RDMA_PORT_ST_DOWN" : "RDMA_PORT_ST_UP");
}

inline struct rdma_port *
rdma_port_lookup(uint8_t port_num)
{
	if (port_num >= RDMA_PORT_MAX)
		return NULL;

	if (port[port_num].state != RDMA_PORT_ST_ACTIVE)
		return NULL;

	return &port[port_num];
}

struct pd_entry **
rdma_port_get_pd_array(uint8_t port_num)
{
	struct rdma_port *rport;

	rport = rdma_port_lookup(port_num);
	if (!rport) {
		dao_err("Invalid port number %u", port_num);
		return NULL;
	}

	return rport->pd_array;
}
