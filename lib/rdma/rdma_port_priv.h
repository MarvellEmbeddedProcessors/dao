/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */
#ifndef __RDMA_PORT_PRIV_H__
#define __RDMA_PORT_PRIV_H__

#include "rdma_av.h"
#include "rdma_pd_mr.h"
#include "rdma_priv.h"
#include "rdma_qp.h"

enum port_state {
	RDMA_PORT_ST_NOP = 0,
	RDMA_PORT_ST_DOWN,
	RDMA_PORT_ST_INIT,
	RDMA_PORT_ST_ARMED,
	RDMA_PORT_ST_ACTIVE,
	RDMA_PORT_ST_ACTIVE_DEFER,

	RDMA_PORT_ST_MAX,
};

struct rdma_rport_attr {
	uint32_t num_max_qp;
	uint32_t max_send_wr;
	uint32_t max_recv_wr;
	uint32_t max_send_sge;
	uint32_t max_recv_sge;
	uint32_t max_cq;
	uint32_t max_cqe;
	uint32_t max_mr;
	uint32_t max_pd;
	uint32_t max_qp_rd_atom;
	uint32_t max_ah;
	uint32_t max_srq;
	uint32_t max_srq_wr;
	uint32_t max_srq_sge;
};

struct rdma_port {
	uint8_t portid;
	struct rdma_rport_attr attr;
	struct rdma_qp *qp[RDMA_QP_MAX];
	struct rdma_av *av[RDMA_ADDR_VEC_MAX];
	struct pd_entry *pd_array[RDMA_MAX_PD];
	uint32_t num_active_qp;
	uint16_t state;
	uint16_t mtu;
};

extern struct rdma_port *port;

int rdma_port_alloc(int nport);
int rdma_port_free(void);
struct rdma_port *rdma_port_lookup(uint8_t portid);
int rdma_port_link_state_update(uint16_t port_num, uint16_t link_state);

#endif /* __RDMA_PORT_PRIV_H__ */
