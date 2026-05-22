/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef __RDMA_SP_H__
#define __RDMA_SP_H__

#include <stdbool.h>

#include <rte_byteorder.h>
#include <rte_mbuf.h>

/* Address vector */
int dao_rdma_av_insert(void *av_data);
int dao_rdma_av_remove(void *av_data);

/* CQ */
int dao_rdma_cq_insert(uint64_t addr, uint8_t index);
int dao_rdma_cq_remove(uint8_t index);

/* QP */
int dao_rdma_qp_create(void *data);
int dao_rdma_qp_destroy(uint8_t port, uint32_t qid);
int dao_rdma_qp_modify(void *data);
int dao_rdma_qp_init(uint32_t num_qp, int port);
int dao_rdma_qp_free(int port);

/* Dev Cap */
int dao_rdma_get_device_cap(int port, void *cap);

/* Port Attr */
int dao_rdma_get_port_attributes(int port, void *attr);

/* Device */
int dao_rdma_port_link_state_update(uint16_t port, uint16_t link_state);

/* Cleanup Resources */
void dao_rdma_cleanup_resources(uint16_t port);

int dao_rdma_port_alloc(int nport);
int dao_rdma_port_free(void);
/* PD */
int dao_rdma_pd_add(void *req);
int dao_rdma_pd_delete(void *req);
/* MR */
int dao_rdma_mr_register(void *req);
int dao_rdma_mr_deregister(void *req);

/* Octeon Termination cleanup */
int dao_rdma_octterm_cleanup(uint32_t dev_mask, uint16_t pem_id);

#endif /* __RDMA_SP_H__ */
