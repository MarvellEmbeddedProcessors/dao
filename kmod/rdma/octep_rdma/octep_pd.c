/* SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2025 Marvell.
 */

#include "octep_verbs.h"

int
octep_rdma_prepare_pd_add_cmd(struct octep_rdma_dev *rdma_dev, u32 pdn)
{
	struct octep_rdma_pd_add_req *pd_req;
	int ret = 0;

	pd_req = kzalloc(sizeof(*pd_req), GFP_KERNEL);
	if (!pd_req)
		return -ENOMEM;

	pd_req->port_num = rdma_dev->port.port_num;
	pd_req->pd_id = pdn;

	ret = octep_rdma_mbox_pd_add(rdma_dev->caps_rgn, pd_req);
	if (ret) {
		ibdev_err(&rdma_dev->ibdev, "octep_rdma_mbox_pd_add failed, err %d\n", ret);
		goto done;
	}

	ibdev_info(&rdma_dev->ibdev, "[%s] mbox pd_id %d success\n", __func__, pd_req->pd_id);

done:
	kfree(pd_req);
	return ret;
}

int
octep_rdma_prepare_pd_del_cmd(struct octep_rdma_dev *rdma_dev, u32 pdn)
{
	struct octep_rdma_pd_delete_req *pd_req;
	int ret = 0;

	pd_req = kzalloc(sizeof(*pd_req), GFP_KERNEL);
	if (!pd_req)
		return -ENOMEM;

	pd_req->port_num = rdma_dev->port.port_num;
	pd_req->pd_id = pdn;

	ret = octep_rdma_mbox_pd_delete(rdma_dev->caps_rgn, pd_req);
	if (ret) {
		ibdev_err(&rdma_dev->ibdev, "octep_rdma_mbox_pd_delete failed, err %d\n", ret);
		goto done;
	}

	ibdev_info(&rdma_dev->ibdev, "[%s] mbox pd_id %d success\n", __func__, pd_req->pd_id);

done:
	kfree(pd_req);
	return ret;
}
