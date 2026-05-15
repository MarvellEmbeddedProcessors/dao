/* SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2024 Marvell.
 */

#include "octep_verbs.h"

static int
chk_attr(void *obj, struct rdma_ah_attr *attr, bool obj_is_ah)
{
	const struct ib_global_route *grh;
	struct octep_rdma_port *port;
	struct octep_rdma_dev *octep_rdma;
	struct octep_rdma_qp *qp;
	struct octep_rdma_ah *ah;
	int type;

	if (!obj || !attr) {
		pr_err("%s: NULL pointer - obj=%p attr=%p\n", __func__, obj, attr);
		return -EINVAL;
	}

	grh = rdma_ah_read_grh(attr);
	if (!grh) {
		pr_err("%s: Failed to read GRH from attr\n", __func__);
		return -EINVAL;
	}

	if (obj_is_ah) {
		ah = obj;
		if (!ah) {
			pr_err("%s: NULL AH object\n", __func__);
			return -EINVAL;
		}
		octep_rdma = to_octep_rdma_dev(ah->ibah.device);
	} else {
		qp = obj;
		if (!qp) {
			pr_err("%s: NULL QP object\n", __func__);
			return -EINVAL;
		}
		octep_rdma = to_octep_rdma_dev(qp->ibqp.device);
	}

	if (!octep_rdma) {
		pr_err("%s: Failed to get octep_rdma device\n", __func__);
		return -EINVAL;
	}

	port = &octep_rdma->port;

	if (rdma_ah_get_ah_flags(attr) & IB_AH_GRH) {
		if (grh->sgid_index >= port->attr.gid_tbl_len) {
			pr_debug("invalid sgid index = %d\n", grh->sgid_index);
			return -EINVAL;
		}

		type = rdma_gid_attr_network_type(grh->sgid_attr);
		if (type < RDMA_NETWORK_IPV4 || type > RDMA_NETWORK_IPV6) {
			pr_debug("invalid network type for rdma_octep_rdma = %d\n", type);
			return -EINVAL;
		}
	}

	return 0;
}

int
octep_rdma_ah_chk_attr(struct octep_rdma_ah *ah, struct rdma_ah_attr *attr)
{
	return chk_attr(ah, attr, true);
}

static void
octep_rdma_av_from_attr(u8 port_num, struct octep_rdma_av *av, struct rdma_ah_attr *attr)
{
	const struct ib_global_route *grh = rdma_ah_read_grh(attr);

	memset(av, 0, sizeof(*av));

	if (!grh) {
		pr_err("rdma_ah_read_grh returned NULL - invalid GRH\n");
		/* Set port_num and return early to prevent null pointer access */
		av->port_num = port_num;
		return;
	}

	memcpy(av->grh.dgid.raw, grh->dgid.raw, sizeof(grh->dgid.raw));
	av->grh.flow_label = grh->flow_label;
	av->grh.sgid_index = grh->sgid_index;
	av->grh.hop_limit = grh->hop_limit;
	av->grh.traffic_class = grh->traffic_class;
	av->port_num = port_num;
	pr_debug("av->grh.dgid.raw %pI6 av->grh.flow_label %d av->grh.sgid_index %d "
		 "av->grh.hop_limit %d av->grh.traffic_class %d\n",
		 av->grh.dgid.raw, av->grh.flow_label, av->grh.sgid_index, av->grh.hop_limit,
		 av->grh.traffic_class);
}

static void
octep_rdma_av_fill_ip_info(struct octep_rdma_av *av, struct rdma_ah_attr *attr)
{
	const struct ib_gid_attr *sgid_attr = attr->grh.sgid_attr;
	int ibtype;
	int type;

	if (!sgid_attr) {
		pr_err("sgid_attr is NULL in av_fill_ip_info\n");
		/* Set default to IPv4 and return early to avoid crash */
		av->network_type = 0; /* Assuming 0 is IPv4 default */
		return;
	}

	const struct ib_global_route *grh = rdma_ah_read_grh(attr);

	if (!grh) {
		pr_err("rdma_ah_read_grh returned NULL in av_fill_ip_info\n");
		/* Set default network type and return early */
		av->network_type = 0; /* Assuming 0 is default */
		return;
	}

	rdma_gid2ip((struct sockaddr *)&av->sgid_addr, &sgid_attr->gid);
	rdma_gid2ip((struct sockaddr *)&av->dgid_addr, &grh->dgid);

	ibtype = rdma_gid_attr_network_type(sgid_attr);

	switch (ibtype) {
	case RDMA_NETWORK_IPV4:
		type = OCTEP_RDMA_NETWORK_TYPE_IPV4;
		break;
	case RDMA_NETWORK_IPV6:
		type = OCTEP_RDMA_NETWORK_TYPE_IPV6;
		break;
	default:
		/* not reached - checked in octep_rdma_av_chk_attr */
		type = 0;
		break;
	}

	av->network_type = type;
}

void
octep_rdma_init_av(struct rdma_ah_attr *attr, struct octep_rdma_av *av)
{
	octep_rdma_av_from_attr(rdma_ah_get_port_num(attr), av, attr);
	octep_rdma_av_fill_ip_info(av, attr);
	memcpy(av->dmac, attr->roce.dmac, ETH_ALEN);
	pr_info("[%s:%d] sgid_addr %pI4 dgid_addr %pI4 dmac %pM\n", __func__, __LINE__,
		&av->sgid_addr._sockaddr_in.sin_addr.s_addr,
		&av->dgid_addr._sockaddr_in.sin_addr.s_addr, av->dmac);
}

int octep_rdma_prepare_ah_cmd(struct octep_rdma_dev *rdma_dev, struct octep_rdma_ah *ah,
			      struct octep_rdma_av *av, enum ah_cmd cmd, bool sleepable)
{
	struct octep_rdma_ah_create_req *req;
	gfp_t gfp = sleepable ? GFP_KERNEL : GFP_ATOMIC;
	int ret = -EINVAL;

	req = kzalloc(sizeof(*req), gfp);
	if (!req)
		return -ENOMEM;

	if (av->network_type == OCTEP_RDMA_NETWORK_TYPE_IPV6) {
		ibdev_err(&rdma_dev->ibdev,
			  "IPv6 AH not supported: firmware ABI lacks IPv6 address fields\n");
		kfree(req);
		return -EOPNOTSUPP;
	}

	req->index = ah->ah_num;
	req->port_num = rdma_dev->port.port_num;
	req->network_type = av->network_type;
	memcpy(req->dmac, av->dmac, ETH_ALEN);
	if (rdma_dev->netdev)
		memcpy(req->smac, rdma_dev->netdev->dev_addr, ETH_ALEN);
	req->s_addr = av->sgid_addr._sockaddr_in.sin_addr.s_addr;
	req->d_addr = av->dgid_addr._sockaddr_in.sin_addr.s_addr;

	if (cmd == AH_CREATE) {
		if (sleepable)
			ret = octep_rdma_mbox_ah_create(rdma_dev->caps_rgn, req);
		else
			ret = octep_rdma_mbox_ah_create_atomic(rdma_dev->caps_rgn, req);
		if (ret) {
			ibdev_err(ah->ibah.device, "Failed to create AH id %d, err = %d\n",
				  ah->ah_num, ret);
			goto fail;
		}
	} else if (cmd == AH_MODIFY) {
		if (sleepable)
			ret = octep_rdma_mbox_ah_modify(rdma_dev->caps_rgn, req);
		else
			ret = octep_rdma_mbox_ah_modify_atomic(rdma_dev->caps_rgn, req);
		if (ret) {
			ibdev_err(ah->ibah.device, "Failed to modify AH id %d, err = %d\n",
				  ah->ah_num, ret);
			goto fail;
		}
	} else {
		ibdev_err(ah->ibah.device, "Invalid AH command: %d\n", cmd);
		goto fail;
	}

	ret = 0;

fail:
	kfree(req);
	return ret;
}

int octep_rdma_prepare_ah_destroy_cmd(struct octep_rdma_dev *rdma_dev, struct octep_rdma_ah *ah,
				      bool sleepable)
{
	struct octep_rdma_ah_destroy_req *req;
	gfp_t gfp = sleepable ? GFP_KERNEL : GFP_ATOMIC;
	int ret;

	req = kzalloc(sizeof(*req), gfp);
	if (!req)
		return -ENOMEM;

	req->index = ah->ah_num;
	req->port_num = rdma_dev->port.port_num;

	if (sleepable)
		ret = octep_rdma_mbox_ah_destroy(rdma_dev->caps_rgn, req);
	else
		ret = octep_rdma_mbox_ah_destroy_atomic(rdma_dev->caps_rgn, req);
	if (ret)
		ibdev_err(ah->ibah.device, "Failed to destroy AH id %d, err = %d\n", ah->ah_num,
			  ret);

	kfree(req);
	return ret;
}

void
octep_rdma_av_to_attr(struct octep_rdma_av *av, struct rdma_ah_attr *attr)
{
	struct ib_global_route *grh;

	if (!av || !attr) {
		pr_err("%s: NULL pointer - av=%p attr=%p\n", __func__, av, attr);
		return;
	}

	grh = rdma_ah_retrieve_grh(attr);
	if (!grh) {
		pr_err("%s: Failed to retrieve GRH from attr\n", __func__);
		return;
	}

	attr->type = RDMA_AH_ATTR_TYPE_ROCE;

	memcpy(grh->dgid.raw, av->grh.dgid.raw, sizeof(av->grh.dgid.raw));
	grh->flow_label = av->grh.flow_label;
	grh->sgid_index = av->grh.sgid_index;
	grh->hop_limit = av->grh.hop_limit;
	grh->traffic_class = av->grh.traffic_class;

	rdma_ah_set_ah_flags(attr, IB_AH_GRH);
	rdma_ah_set_port_num(attr, av->port_num);
}
