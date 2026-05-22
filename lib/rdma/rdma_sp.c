/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <dao_log.h>

#include "dao_rdma_sp.h"
#include "dao_pts_rdma_dev.h"
#include "pts_rdma_dev_priv.h"
#include "dao_pem.h"
#include "rdma_av.h"
#include "rdma_cq.h"
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

/* CQ */
int
dao_rdma_cq_insert(uint64_t addr, uint8_t index)
{
	return rdma_cq_insert(addr, index);
}

int
dao_rdma_cq_remove(uint8_t index)
{
	return rdma_cq_remove(index);
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

void
dao_rdma_cleanup_resources(uint16_t port)
{
	rdma_cleanup_resources(port);
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

int
dao_rdma_octterm_cleanup(uint32_t dev_mask, uint16_t pem_id)
{
	struct dao_pts_rdma_dev *dao_dev;
	struct pts_rdma_dev *dev;
	uint16_t devid;
	int rc;

	dao_info("Octeon Termination cleanup: dev_mask=0x%x pem_id=%u", dev_mask, pem_id);

	/*
	 * Send the cleanup ioctl to kmod FIRST, before tearing down
	 * local state.  This ensures the kmod can tear down IB resources
	 * and reset to FW_READY-waiting state even if local cleanup
	 * encounters issues.
	 */
	rc = dao_pem_fw_cleanup_notify(pem_id);
	if (rc < 0)
		dao_err("FW_CLEANUP ioctl failed: %d", rc);

	for (devid = 0; devid < DAO_PTS_RDMA_MAX_DEVS; devid++) {
		if (!(dev_mask & (1 << devid)))
			continue;
		dao_rdma_cleanup_resources(devid);
	}

	for (devid = 0; devid < DAO_PTS_RDMA_MAX_DEVS; devid++) {
		if (!(dev_mask & (1 << devid)))
			continue;
		dao_dev = &dao_pts_rdma_devs[devid];
		dev = pts_rdma_dev_priv(dao_dev);
		pts_rdma_clear_qp_info(dev);
	}

	dao_info("Octeon Termination cleanup complete");
	return rc;
}
