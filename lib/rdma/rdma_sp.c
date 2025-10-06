/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include "dao_rdma_sp.h"
#include "rdma_av.h"
#include "rdma_dev_cap_priv.h"
#include "rdma_port_priv.h"
#include "rdma_qp.h"

/* Address vector */
int
dao_rdma_av_insert(void *av_data)
{
	return rdma_av_insert(av_data);
}

int
dao_rdma_av_remove(void *av_data)
{
	return rdma_av_remove(av_data);
}

/* QP */

int
dao_rdma_qp_create(void *data)
{
	return rdma_qp_create(data);
}

int
dao_rdma_qp_destroy(uint8_t port_num, uint32_t qp_id)
{
	return rdma_qp_destroy(port_num, qp_id);
}

int
dao_rdma_qp_modify(void *data)
{
	return rdma_qp_modify(data);
}

int
dao_rdma_get_device_cap(int port, void *cap)
{
	return rdma_query_device_cap(port, cap);
}

int
dao_rdma_get_port_attributes(int port, void *attr)
{
	return rdma_query_port_attr(port, attr);
}

int
dao_rdma_port_link_state_update(uint16_t port, uint16_t link_state)
{
	return rdma_port_link_state_update(port, link_state);
}

int
dao_rdma_port_alloc(int nport)
{
	return rdma_port_alloc(nport);
}

int
dao_rdma_port_free(void)
{
	return rdma_port_free();
}

int
dao_rdma_pd_add(void *req)
{
	return pd_add(req);
}

int
dao_rdma_pd_delete(void *req)
{
	return pd_delete(req);
}

int
dao_rdma_mr_register(void *req)
{
	return mr_reg(req);
}

int
dao_rdma_mr_deregister(void *req)
{
	return mr_dereg(req);
}
