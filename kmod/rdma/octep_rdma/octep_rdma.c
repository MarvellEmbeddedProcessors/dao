/* SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 Marvell.
 */

#include <linux/delay.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/types.h>
#include <linux/vmalloc.h>

#include "octep_qp.h"
#include "octep_rdma.h"
#include "octep_verbs.h"

#define MAC_OFFSET 9
static const struct ib_device_ops octep_rdma_device_ops = {
	.owner = THIS_MODULE,
	.driver_id = RDMA_DRIVER_OCTEP,
	.uverbs_abi_ver = OCTEP_RDMA_ABI_VERSION,

	.alloc_ucontext = octep_rdma_alloc_ucontext,
	.dealloc_ucontext = octep_rdma_dealloc_ucontext,
	.alloc_pd = octep_rdma_alloc_pd,
	.dealloc_pd = octep_rdma_dealloc_pd,
	.query_device = octep_rdma_query_device,
	.query_port = octep_rdma_query_port,
	.create_qp = octep_rdma_create_qp,
	.destroy_qp = octep_rdma_destroy_qp,
	.modify_qp = octep_rdma_modify_qp,
	.post_recv = octep_rdma_post_recv,
	.post_send = octep_rdma_post_send,
	.poll_cq = octep_rdma_poll_cq,
	.create_cq = octep_rdma_create_cq,
	.destroy_cq = octep_rdma_destroy_cq,
	.req_notify_cq = octep_rdma_req_notify_cq,
	.get_dma_mr = octep_rdma_get_dma_mr,
	.reg_user_mr = octep_rdma_reg_user_mr,
	.dereg_mr = octep_rdma_dereg_mr,
	.get_port_immutable = octep_rdma_get_port_immutable,
	.query_qp = octep_rdma_query_qp,
	.query_pkey = octep_rdma_query_pkey,
	.get_link_layer = octep_rdma_get_link_layer,
	.create_ah = octep_rdma_create_ah,
	.create_user_ah = octep_rdma_create_ah,
	.destroy_ah = octep_rdma_destroy_ah,
	.modify_ah = octep_rdma_modify_ah,
	.query_ah = octep_rdma_query_ah,
	.add_gid = octep_rdma_add_gid,
	.del_gid = octep_rdma_del_gid,
	.mmap = octep_rdma_mmap,
	.mmap_free = octep_rdma_mmap_free,
	.disassociate_ucontext = octep_rdma_disassociate_ucontext,
	INIT_RDMA_OBJ_SIZE(ib_pd, octep_rdma_pd, ibpd),
	INIT_RDMA_OBJ_SIZE(ib_ucontext, octep_rdma_ucontext, ibucontext),
	INIT_RDMA_OBJ_SIZE(ib_cq, octep_rdma_cq, ibcq),
	INIT_RDMA_OBJ_SIZE(ib_qp, octep_rdma_qp, ibqp),
	INIT_RDMA_OBJ_SIZE(ib_ah, octep_rdma_ah, ibah),
};

static enum ib_mtu
octep_rdma_mtu_to_ib(enum octep_rdma_mtu mtu)
{
	return (enum ib_mtu)mtu;
}

static enum ib_port_state
octep_rdma_port_state_to_ib(enum octep_rdma_port_state state)
{
	return (enum ib_port_state)state;
}

static enum ib_atomic_cap
octep_rdma_atomic_cap_to_ib(enum octep_rdma_atomic_cap cap)
{
	return (enum ib_atomic_cap)cap;
}

/* initialize octep_rdma device parameters */
static void
octep_rdma_device_attrs_init(struct octep_rdma_dev *octep_rdma)
{
	struct octep_caps_region *oct_caps;
	struct octep_rdma_get_device_cap_msg *msg;

	if (!octep_rdma) {
		pr_err("%s: NULL octep_rdma parameter\n", __func__);
		return;
	}

	oct_caps = octep_rdma->caps_rgn;
	if (!oct_caps) {
		dev_err(&octep_rdma->pdev->dev, "caps_rgn is NULL\n");
		return;
	}

	msg = kzalloc(sizeof(*msg), GFP_KERNEL);
	if (!msg)
		return;

	msg->port_num = octep_rdma->port.port_num;

	/* Get device capabilities */
	if (octep_rdma_mbox_user_get_device_cap(oct_caps, msg)) {
		dev_err(&octep_rdma->pdev->dev, "Failed to get device capabilities\n");
		kfree(msg);
		return;
	}

	octep_rdma->attr.vendor_id = msg->dev_cap.vendor_id;
	octep_rdma->attr.max_mr_size = msg->dev_cap.max_mr_size;
	octep_rdma->attr.page_size_cap = msg->dev_cap.page_size_cap;
	octep_rdma->attr.max_qp = msg->dev_cap.max_qp;
	octep_rdma->attr.max_qp_wr = msg->dev_cap.max_qp_wr;
	octep_rdma->attr.device_cap_flags = msg->dev_cap.device_cap_flags;
	octep_rdma->attr.kernel_cap_flags = msg->dev_cap.kernel_cap_flags;
	octep_rdma->attr.max_send_sge = msg->dev_cap.max_send_sge;
	octep_rdma->attr.max_recv_sge = msg->dev_cap.max_recv_sge;
	octep_rdma->attr.max_sge_rd = msg->dev_cap.max_sge_rd;
	octep_rdma->attr.max_cq = msg->dev_cap.max_cq;
	octep_rdma->attr.max_cqe = msg->dev_cap.max_cqe;
	octep_rdma->attr.max_mr = msg->dev_cap.max_mr;
	octep_rdma->attr.max_mw = msg->dev_cap.max_mw;
	octep_rdma->attr.max_pd = msg->dev_cap.max_pd;
	octep_rdma->attr.max_qp_rd_atom = msg->dev_cap.max_qp_rd_atom;
	octep_rdma->attr.max_res_rd_atom = msg->dev_cap.max_res_rd_atom;
	octep_rdma->attr.max_qp_init_rd_atom = msg->dev_cap.max_qp_init_rd_atom;
	octep_rdma->attr.max_ee_rd_atom = msg->dev_cap.max_ee_rd_atom;
	octep_rdma->attr.atomic_cap = octep_rdma_atomic_cap_to_ib(msg->dev_cap.atomic_cap);
	octep_rdma->attr.max_mcast_grp = msg->dev_cap.max_mcast_grp;
	octep_rdma->attr.max_mcast_qp_attach = msg->dev_cap.max_mcast_qp_attach;
	octep_rdma->attr.max_total_mcast_qp_attach = msg->dev_cap.max_total_mcast_qp_attach;
	octep_rdma->attr.max_ah = msg->dev_cap.max_ah;
	octep_rdma->attr.max_srq = msg->dev_cap.max_srq;
	octep_rdma->attr.max_srq_wr = msg->dev_cap.max_srq_wr;
	octep_rdma->attr.max_srq_sge = msg->dev_cap.max_srq_sge;
	octep_rdma->attr.max_fast_reg_page_list_len = msg->dev_cap.max_fast_reg_page_list_len;
	octep_rdma->attr.max_pkeys = msg->dev_cap.max_pkeys;
	octep_rdma->attr.local_ca_ack_delay = msg->dev_cap.local_ca_ack_delay;

	if (octep_rdma->netdev && octep_rdma->netdev->dev_addr) {
		addrconf_addr_eui48((unsigned char *)&octep_rdma->attr.sys_image_guid,
				    octep_rdma->netdev->dev_addr);
	} else {
		dev_warn(&octep_rdma->pdev->dev,
			 "netdev or dev_addr is NULL, using default GUID\n");
		octep_rdma->attr.sys_image_guid = 0;
	}

	octep_rdma->res_cb[OCTEP_RDMA_RES_TYPE_PD].max_cap = msg->dev_cap.max_pd;
	octep_rdma->res_cb[OCTEP_RDMA_RES_TYPE_STAG_IDX].max_cap = msg->dev_cap.max_mr;
	octep_rdma->res_cb[OCTEP_RDMA_RES_TYPE_QP].max_cap = msg->dev_cap.max_qp;
	octep_rdma->res_cb[OCTEP_RDMA_RES_TYPE_CQ].max_cap = msg->dev_cap.max_cq;
	octep_rdma->res_cb[OCTEP_RDMA_RES_TYPE_AH].max_cap = msg->dev_cap.max_ah;

	kfree(msg);
}

/* initialize port attributes */
static void
octep_rdma_port_attr_init(struct octep_rdma_dev *octep_rdma)
{
	struct octep_caps_region *oct_caps = octep_rdma->caps_rgn;
	struct octep_rdma_get_port_attr_msg *msg;
	struct octep_rdma_port *port;

	msg = kzalloc(sizeof(*msg), GFP_KERNEL);
	if (!msg)
		return;

	/* Get port attributes */
	if (octep_rdma_mbox_user_get_port_attr(oct_caps, msg)) {
		dev_err(&octep_rdma->pdev->dev, "Failed to get port attributes\n");
		kfree(msg);
		return;
	}

	port = &octep_rdma->port;

	port->attr.state = octep_rdma_port_state_to_ib(msg->port_attr.state);
	port->attr.max_mtu = octep_rdma_mtu_to_ib(msg->port_attr.max_mtu);
	port->attr.active_mtu = octep_rdma_mtu_to_ib(msg->port_attr.active_mtu);
	port->attr.gid_tbl_len = msg->port_attr.gid_tbl_len;
	port->attr.port_cap_flags = msg->port_attr.port_cap_flags;
	port->attr.max_msg_sz = msg->port_attr.max_msg_sz;
	port->attr.bad_pkey_cntr = msg->port_attr.bad_pkey_cntr;
	port->attr.pkey_tbl_len = msg->port_attr.pkey_tbl_len;
	port->attr.lid = msg->port_attr.lid;
	port->attr.sm_lid = msg->port_attr.sm_lid;
	port->attr.lmc = msg->port_attr.lmc;
	port->attr.max_vl_num = msg->port_attr.max_vl_num;
	port->attr.sm_sl = msg->port_attr.sm_sl;
	port->attr.subnet_timeout = msg->port_attr.subnet_timeout;
	port->attr.init_type_reply = msg->port_attr.init_type_reply;
	port->attr.active_width = msg->port_attr.active_width;
	port->attr.active_speed = msg->port_attr.active_speed;
	port->attr.phys_state = msg->port_attr.phys_state;
	port->mtu_cap = ib_mtu_enum_to_int(octep_rdma_mtu_to_ib(msg->port_attr.active_mtu));
	port->subnet_prefix = cpu_to_be64(msg->port_attr.subnet_prefix);
}

static int
octep_rdma_res_cb_init(struct octep_rdma_dev *dev)
{
	int i, j;

	for (i = 0; i < OCTEP_RDMA_RES_CNT; i++) {
		dev->res_cb[i].next_alloc_idx = dev->res_cb[i].start_idx;
		spin_lock_init(&dev->res_cb[i].lock);
		dev->res_cb[i].bitmap = bitmap_zalloc(dev->res_cb[i].max_cap, GFP_KERNEL);
		if (!dev->res_cb[i].bitmap)
			goto err;
	}

	return 0;

err:
	for (j = 0; j < i; j++)
		bitmap_free(dev->res_cb[j].bitmap);

	return -ENOMEM;
}

static void
octep_rdma_res_cb_free(struct octep_rdma_dev *dev)
{
	int i;

	for (i = 0; i < OCTEP_RDMA_RES_CNT; i++)
		bitmap_free(dev->res_cb[i].bitmap);
}

static int
octep_rdma_attrs_init(struct octep_rdma_dev *rdma_dev)
{
	int ret = 0;

	octep_rdma_device_attrs_init(rdma_dev);
	octep_rdma_port_attr_init(rdma_dev);

	return ret;
}

static void
octep_rdma_ib_device_remove(struct octep_rdma_dev *rdma_dev)
{
	unregister_netdevice_notifier(&rdma_dev->netdev_nb);
	xa_destroy(&rdma_dev->mem_xa);
	ib_unregister_device(&rdma_dev->ibdev);
	octep_rdma_res_cb_free(rdma_dev);
}

static void
octep_rdma_port_event(struct octep_rdma_dev *dev, enum ib_event_type reason)
{
	struct ib_event event;

	event.device = &dev->ibdev;
	event.element.port_num = 1;
	event.event = reason;

	ib_dispatch_event(&event);
}

static int
octep_rdma_netdev_event(struct notifier_block *nb, unsigned long event, void *arg)
{
	struct net_device *netdev;
	struct octep_rdma_dev *rdma_dev;
	struct octep_rdma_port_state_req *req;
	int ret;

	if (!nb || !arg) {
		pr_err("%s: NULL parameter\n", __func__);
		return NOTIFY_BAD;
	}

	netdev = netdev_notifier_info_to_dev(arg);
	if (!netdev) {
		pr_err("%s: Failed to get netdev from arg\n", __func__);
		return NOTIFY_BAD;
	}

	rdma_dev = container_of(nb, struct octep_rdma_dev, netdev_nb);
	if (!rdma_dev) {
		pr_err("%s: Failed to get rdma_dev\n", __func__);
		return NOTIFY_BAD;
	}

	if (!rdma_dev->netdev || rdma_dev->netdev != netdev)
		goto done;

	if (!rdma_dev->caps_rgn) {
		dev_err(&rdma_dev->pdev->dev, "caps_rgn is NULL\n");
		goto done;
	}

	req = kzalloc(sizeof(*req), GFP_KERNEL);
	if (!req)
		return NOTIFY_DONE;

	req->port_num = rdma_dev->port.port_num;

	switch (event) {
	case NETDEV_UP:
		dev_info(&rdma_dev->pdev->dev, "NETDEV_UP event received\n");
		req->event = OCTEP_RDMA_USER_PORT_LINK_STATE;
		req->evt_data.link_state = IB_PORT_ACTIVE;
		octep_rdma_port_event(rdma_dev, IB_EVENT_PORT_ACTIVE);
		ret = octep_rdma_mbox_user_port_state(rdma_dev->caps_rgn, req);
		if (ret)
			dev_err(&rdma_dev->pdev->dev, "Failed to send port UP state, ret=%d\n",
				ret);
		break;
	case NETDEV_DOWN:
		dev_info(&rdma_dev->pdev->dev, "NETDEV_DOWN event received\n");
		req->event = OCTEP_RDMA_USER_PORT_LINK_STATE;
		req->evt_data.link_state = IB_PORT_DOWN;
		octep_rdma_port_event(rdma_dev, IB_EVENT_PORT_ERR);
		ret = octep_rdma_mbox_user_port_state(rdma_dev->caps_rgn, req);
		if (ret)
			dev_err(&rdma_dev->pdev->dev, "Failed to send port DOWN state, ret=%d\n",
				ret);
		break;
	case NETDEV_CHANGEMTU:
		dev_info(&rdma_dev->pdev->dev, "NETDEV_CHANGEMTU: %d -> %d\n", rdma_dev->mtu,
			 rdma_dev->netdev->mtu);
		req->event = OCTEP_RDMA_USER_PORT_MTU_CHANGE;
		if (rdma_dev->mtu != rdma_dev->netdev->mtu) {
			req->evt_data.mtu = rdma_dev->netdev->mtu;
			ret = octep_rdma_mbox_user_port_state(rdma_dev->caps_rgn, req);
			if (ret) {
				dev_err(&rdma_dev->pdev->dev, "Failed to send MTU change, ret=%d\n",
					ret);
			} else {
				rdma_dev->mtu = rdma_dev->netdev->mtu;
			}
		}
		break;
	case NETDEV_REGISTER:
	case NETDEV_UNREGISTER:
	case NETDEV_CHANGEADDR:
	case NETDEV_GOING_DOWN:
	case NETDEV_CHANGE:
	default:
		dev_dbg(&rdma_dev->pdev->dev, "Unhandled netdev event %lu\n", event);
		break;
	}

	kfree(req);

done:
	return NOTIFY_OK;
}

static int
octep_rdma_device_register(struct octep_rdma_dev *rdma_dev)
{
	struct ib_device *ibdev = &rdma_dev->ibdev;
	int ret;

	ibdev->uverbs_cmd_mask |= BIT_ULL(IB_USER_VERBS_CMD_POST_SEND) |
				  BIT_ULL(IB_USER_VERBS_CMD_REQ_NOTIFY_CQ) |
				  BIT_ULL(IB_USER_VERBS_CMD_POST_RECV);

	/* FIXME */
	rdma_dev->mtu = rdma_dev->netdev->mtu;
	addrconf_addr_eui48((unsigned char *)&ibdev->node_guid, rdma_dev->netdev->dev_addr);
	ret = ib_device_set_netdev(ibdev, rdma_dev->netdev, 1);
	if (ret)
		return ret;

	if (!ibdev) {
		dev_err(&rdma_dev->pdev->dev, "ibdev is NULL.\n");
		return -EINVAL;
	}

	ret = ib_register_device(&rdma_dev->ibdev, "octep_rdma_%d", &rdma_dev->pdev->dev);
	if (ret) {
		dev_err(&rdma_dev->pdev->dev, "failed to register device.\n");
		return ret;
	}

	rdma_dev->netdev_nb.notifier_call = octep_rdma_netdev_event;
	ret = register_netdevice_notifier(&rdma_dev->netdev_nb);
	if (ret) {
		ibdev_err(ibdev, "failed to register notifier.\n");
		ib_unregister_device(ibdev);
	}

	return ret;
}

static int
octep_rdma_ib_device_add(struct octep_rdma_dev *rdma_dev)
{
	struct octep_caps_region *oct_caps = rdma_dev->caps_rgn;
	struct ib_device *ibdev = &rdma_dev->ibdev;
	int ret;

	mutex_init(&oct_caps->mbox_lock);

	ret = octep_rdma_attrs_init(rdma_dev);
	if (ret)
		return ret;

	memcpy(ibdev->node_desc, OCTEP_RDMA_NODE_DESC, sizeof(OCTEP_RDMA_NODE_DESC));

	ibdev->phys_port_cnt = 1;
	ibdev->num_comp_vectors = num_possible_cpus();
	ibdev->node_type = RDMA_NODE_IB_CA;
	ibdev->local_dma_lkey = 0;

	ib_set_device_ops(ibdev, &octep_rdma_device_ops);
	xa_init_flags(&rdma_dev->mem_xa, XA_FLAGS_ALLOC1);

	rdma_dev->res_cb[OCTEP_RDMA_RES_TYPE_PD].start_idx = 1;
	rdma_dev->res_cb[OCTEP_RDMA_RES_TYPE_CQ].start_idx = 1;
	rdma_dev->res_cb[OCTEP_RDMA_RES_TYPE_QP].start_idx = 2;
	rdma_dev->res_cb[OCTEP_RDMA_RES_TYPE_AH].start_idx = 1;
	ret = octep_rdma_res_cb_init(rdma_dev);
	if (ret)
		return ret;

	atomic_set(&rdma_dev->num_ctx, 0);
	ret = octep_rdma_device_register(rdma_dev);
	if (ret) {
		dev_err(&rdma_dev->pdev->dev, "failed to register rdma device.\n");
		return ret;
	}
	atomic_set(&rdma_dev->status, OCTEP_RDMA_DEV_STATUS_IBDEV_READY);

	return 0;
}

static void
octep_rdma_dev_release(struct octep_rdma_dev *rdma_dev)
{
	int status;

	if (!rdma_dev)
		return;

	dev_info(&rdma_dev->pdev->dev, "Removing RDMA device.\n");
	status = atomic_read(&rdma_dev->status);
	if (status <= OCTEP_RDMA_DEV_STATUS_ALLOC) {
		dev_err(&rdma_dev->pdev->dev, "Device not initialized.\n");
		return;
	}

	atomic_set(&rdma_dev->status, OCTEP_RDMA_DEV_STATUS_UNINIT);
	if (status == OCTEP_RDMA_DEV_STATUS_IBDEV_READY)
		octep_rdma_ib_device_remove(rdma_dev);
	if (status >= OCTEP_RDMA_DEV_STATUS_NETDEV_REG) {
		unregister_netdev(rdma_dev->octep_dev->netdev);
		octep_device_cleanup(rdma_dev->octep_dev);
	}
	ib_dealloc_device(&rdma_dev->ibdev);
}

static int
octep_iomap_region(struct pci_dev *pdev, u8 __iomem **tbl, u8 bar)
{
	int ret;

	ret = pci_request_region(pdev, bar, OCTEP_RDMA_DRV_NAME);
	if (ret) {
		dev_err(&pdev->dev, "Failed to request BAR:%u region\n", bar);
		return ret;
	}

	tbl[bar] = pci_iomap(pdev, bar, pci_resource_len(pdev, bar));
	if (!tbl[bar]) {
		dev_err(&pdev->dev, "Failed to iomap BAR:%u\n", bar);
		pci_release_region(pdev, bar);
		ret = -ENOMEM;
	}

	return ret;
}

static void
octep_iounmap_region(struct pci_dev *pdev, u8 __iomem **tbl, u8 bar)
{
	pci_iounmap(pdev, tbl[bar]);
	pci_release_region(pdev, bar);
}

static void
octep_rdma_vf_bar_shrink(struct pci_dev *pdev)
{
	struct resource *vf_res = pdev->resource + PCI_STD_RESOURCES + 4;

	memset(vf_res, 0, sizeof(*vf_res));
}

static void
octep_rdma_remove_vf(struct pci_dev *pdev)
{
	struct octep_rdma_dev *rdma_dev = pci_get_drvdata(pdev);
	struct octep_caps_region *caps_rgn = rdma_dev->caps_rgn;

	octep_rdma_dev_release(rdma_dev);

	if (caps_rgn->base[OCTEP_HW_MBOX_BAR])
		octep_iounmap_region(pdev, caps_rgn->base, OCTEP_HW_MBOX_BAR);

	if (caps_rgn->base[OCTEP_HW_REGS_BAR])
		octep_iounmap_region(pdev, caps_rgn->base, OCTEP_HW_REGS_BAR);

	pci_disable_device(pdev);
	octep_rdma_vf_bar_shrink(pdev);
	devm_kfree(&pdev->dev, rdma_dev->caps_rgn);
}

static bool
get_device_ready_status(u8 __iomem *addr)
{
	u32 signature = readl(addr + OCTEP_VF_MBOX_DATA(0));

	if (signature == OCTEP_DEV_READY_SIGNATURE) {
		writel(0, addr + OCTEP_VF_MBOX_DATA(0));
		return true;
	}

	return false;
}

static void
octep_rdma_setup_task(struct work_struct *work)
{
	struct octep_rdma_dev *rdma_dev;
	struct octep_caps_region *caps_rgn;
	struct pci_dev *pdev;
	struct device *dev;
	struct octep_sdp_dev *octep_dev;
	struct net_device *netdev = NULL;
	unsigned long timeout;
	u64 val;
	int ret;

	if (!work) {
		pr_err("%s: NULL work parameter\n", __func__);
		return;
	}

	rdma_dev = container_of(work, struct octep_rdma_dev, setup_task);
	if (!rdma_dev) {
		pr_err("%s: Failed to get rdma_dev\n", __func__);
		return;
	}

	caps_rgn = rdma_dev->caps_rgn;
	if (!caps_rgn) {
		dev_err(&rdma_dev->pdev->dev, "Caps region is NULL\n");
		return;
	}

	pdev = rdma_dev->pdev;
	if (!pdev) {
		pr_err("%s: pdev is NULL\n", __func__);
		return;
	}
	dev = &pdev->dev;

	if (!caps_rgn->base[OCTEP_HW_REGS_BAR]) {
		dev_err(dev, "Hardware registers base is NULL\n");
		return;
	}

	atomic_set(&rdma_dev->status, OCTEP_RDMA_DEV_STATUS_WAIT_FOR_BAR_INIT);
	/* Wait for a maximum of 5 sec */
	timeout = jiffies + msecs_to_jiffies(5000);
	while (!time_after(jiffies, timeout)) {
		if (get_device_ready_status(caps_rgn->base[OCTEP_HW_REGS_BAR])) {
			atomic_set(&rdma_dev->status, OCTEP_RDMA_DEV_STATUS_INIT);
			break;
		}

		if (atomic_read(&rdma_dev->status) >= OCTEP_RDMA_DEV_STATUS_IBDEV_READY) {
			dev_info(dev, "Stopping RDMA setup task\n");
			return;
		}

		usleep_range(1000, 1500);
	}

	if (atomic_read(&rdma_dev->status) != OCTEP_RDMA_DEV_STATUS_INIT) {
		dev_err(dev, "BAR initialization timed out\n");
		return;
	}

	ret = octep_iomap_region(pdev, caps_rgn->base, OCTEP_HW_MBOX_BAR);
	if (ret) {
		dev_err(dev, "Failed to map mbox region\n");
		return;
	}

	val = readq(caps_rgn->base[OCTEP_HW_REGS_BAR] + OCTEP_VF_IN_CTRL(0));
	caps_rgn->nb_irqs = OCTEP_VF_IN_CTRL_RPVF(val);
	if (!caps_rgn->nb_irqs || caps_rgn->nb_irqs > OCTEP_MAX_CB_INTR) {
		dev_err(dev, "Invalid number of interrupts %d\n", caps_rgn->nb_irqs);
		goto unmap_region;
	}

	if (octep_device_caps_read(caps_rgn, pdev)) {
		dev_err(dev, "Failed to read hardware capabilities\n");
		goto unmap_region;
	}

	netdev = alloc_etherdev_mq(sizeof(struct octep_sdp_dev), OCTEP_MAX_QUEUES);
	if (!netdev) {
		dev_err(&pdev->dev, "Failed to allocate netdev\n");
		ret = -ENOMEM;
		goto unmap_region;
	}
	SET_NETDEV_DEV(netdev, &pdev->dev);

	octep_dev = netdev_priv(netdev);
	if (!octep_dev) {
		dev_err(&pdev->dev, "Failed to get netdev private data\n");
		ret = -EINVAL;
		goto free_netdev;
	}

	octep_dev->netdev = netdev;
	if (rdma_dev->caps_rgn->dev_cfg) {
		memcpy(octep_dev->mac_addr, (u8 __iomem *)rdma_dev->caps_rgn->dev_cfg + MAC_OFFSET,
		       ETH_ALEN);
		dev_info(&pdev->dev, "MAC address: %pM\n", octep_dev->mac_addr);
	} else {
		dev_warn(&pdev->dev, "dev_cfg is NULL, using default MAC\n");
		eth_random_addr(octep_dev->mac_addr);
	}
	rdma_dev->octep_dev = octep_dev;
	rdma_dev->netdev = netdev;
	octep_dev->pdev = pdev;

	/* Probing underneath hardware device */
	ret = octep_rdma_probe_dev(octep_dev);
	if (ret) {
		dev_err(&pdev->dev, "Failed to probe octep device, ret=%d\n", ret);
		goto free_netdev;
	}
	atomic_set(&rdma_dev->status, OCTEP_RDMA_DEV_STATUS_NETDEV_REG);

	/* Registering ibdev */
	ret = octep_rdma_ib_device_add(rdma_dev);
	if (ret) {
		dev_err(&pdev->dev, "Failed to register ibdev, ret=%d\n", ret);
		goto err_probe_cleanup;
	}

	dev_info(&pdev->dev, "RDMA setup task completed successfully\n");
	return;

err_probe_cleanup:
	octep_rdma_dev_release(rdma_dev);
	goto unmap_region;
free_netdev:
	if (netdev) {
		rdma_dev->netdev = NULL;
		rdma_dev->octep_dev = NULL;
		free_netdev(netdev);
	}
unmap_region:
	atomic_set(&rdma_dev->status, OCTEP_RDMA_DEV_STATUS_INIT);
	if (caps_rgn->base[OCTEP_HW_MBOX_BAR]) {
		octep_iounmap_region(pdev, caps_rgn->base, OCTEP_HW_MBOX_BAR);
		caps_rgn->base[OCTEP_HW_MBOX_BAR] = NULL;
	}
}

static int
octep_rdma_probe_vf(struct pci_dev *pdev)
{
	struct octep_rdma_dev *rdma_dev;
	int vf_index;
	int ret;

	if (!pdev) {
		pr_err("%s: NULL pdev parameter\n", __func__);
		return -EINVAL;
	}

	ret = pci_enable_device(pdev);
	if (ret) {
		dev_err(&pdev->dev, "Failed to enable PCI device\n");
		return ret;
	}

	pci_set_master(pdev);

	rdma_dev = ib_alloc_device(octep_rdma_dev, ibdev);
	if (!rdma_dev) {
		dev_err(&pdev->dev, "ib_alloc_device failed\n");
		ret = -ENOMEM;
		goto err_disable_device;
	}

	pci_set_drvdata(pdev, rdma_dev);
	rdma_dev->pdev = pdev;

	vf_index = pci_iov_vf_id(pdev);
	if (vf_index < 0) {
		dev_err(&pdev->dev, "Failed to get VF index\n");
		ret = -EINVAL;
		goto err_free_device;
	}
	rdma_dev->port.port_num = vf_index;

	dev_info(&pdev->dev, "Assigned port %d to VF index %d\n", rdma_dev->port.port_num,
		 vf_index);

	ret = dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(64));
	if (ret) {
		dev_err(&pdev->dev, "Failed to set DMA mask\n");
		goto err_free_device;
	}

	dev_info(&rdma_dev->pdev->dev, "OCTEP_RDMA: Loading Octep RDMA driver\n");
	rdma_dev->caps_rgn = devm_kzalloc(&pdev->dev, sizeof(struct octep_caps_region), GFP_KERNEL);
	if (!rdma_dev->caps_rgn) {
		dev_err(&pdev->dev, "Failed to allocate caps region\n");
		ret = -ENOMEM;
		goto err_free_device;
	}

	ret = octep_iomap_region(pdev, rdma_dev->caps_rgn->base, OCTEP_HW_REGS_BAR);
	if (ret) {
		dev_err(&pdev->dev, "Failed to map mbox region\n");
		goto err_free_device;
	}

	atomic_set(&rdma_dev->status, OCTEP_RDMA_DEV_STATUS_ALLOC);
	INIT_WORK(&rdma_dev->setup_task, octep_rdma_setup_task);
	schedule_work(&rdma_dev->setup_task);
	dev_info(&pdev->dev, "octep rdma device setup task is queued\n");

	return 0;

err_free_device:
	ib_dealloc_device(&rdma_dev->ibdev);
err_disable_device:
	pci_disable_device(pdev);
	return ret;
}

static void
octep_rdma_pf_bar_shrink(struct octep_pf *octpf)
{
	struct pci_dev *pf_dev = octpf->pdev;
	struct resource *res = pf_dev->resource + PCI_STD_RESOURCES + 4;
	struct pci_bus_region bus_region;

	octpf->res.start = res->start;
	octpf->res.end = res->end;
	octpf->vf_base = res->start;

	bus_region.start = res->start;
	bus_region.end = res->start - 1;

	dev_dbg(&pf_dev->dev,
		"PF: %s, res->start %llx res->end %llx bus_region.start: 0x%llx, "
		"bus_region.end: 0x%llx\n",
		__func__, res->start, res->end, bus_region.start, bus_region.end);
	pcibios_bus_to_resource(pf_dev->bus, res, &bus_region);
}

static void
octep_rdma_pf_bar_expand(struct octep_pf *octpf)
{
	struct pci_dev *pf_dev = octpf->pdev;
	struct resource *res = pf_dev->resource + PCI_STD_RESOURCES + 4;
	struct pci_bus_region bus_region;

	bus_region.start = octpf->res.start;
	bus_region.end = octpf->res.end;

	dev_dbg(&pf_dev->dev,
		"PF: %s, res->start %llx res->end %llx bus_region.start: 0x%llx, "
		"bus_region.end: 0x%llx\n",
		__func__, res->start, res->end, bus_region.start, bus_region.end);
	pcibios_bus_to_resource(pf_dev->bus, res, &bus_region);
}

static void
octep_rdma_remove_pf(struct pci_dev *pdev)
{
	struct octep_pf *octpf = pci_get_drvdata(pdev);

	pci_disable_sriov(pdev);

	if (octpf->base[OCTEP_HW_MBOX_BAR])
		octep_iounmap_region(pdev, octpf->base, OCTEP_HW_MBOX_BAR);

	if (octpf->base[OCTEP_HW_REGS_BAR])
		octep_iounmap_region(pdev, octpf->base, OCTEP_HW_REGS_BAR);

	octep_rdma_pf_bar_expand(octpf);
}

static void
octep_rdma_remove(struct pci_dev *pdev)
{
	if (pdev->is_virtfn)
		octep_rdma_remove_vf(pdev);
	else
		octep_rdma_remove_pf(pdev);
}

static void
octep_rdma_assign_barspace(struct pci_dev *vf_dev, struct pci_dev *pf_dev, u8 idx)
{
	struct resource *vf_res = vf_dev->resource + PCI_STD_RESOURCES + 4;
	struct resource *pf_res = pf_dev->resource + PCI_STD_RESOURCES + 4;
	struct octep_pf *pf = pci_get_drvdata(pf_dev);
	struct pci_bus_region bus_region;

	vf_res->name = pci_name(vf_dev);
	vf_res->flags = pf_res->flags;
	vf_res->parent = (pf_dev->resource + PCI_STD_RESOURCES)->parent;

	bus_region.start = pf->vf_base + idx * pf->vf_stride;
	bus_region.end = bus_region.start + pf->vf_stride - 1;
	dev_dbg(&vf_dev->dev,
		"PF: %s, name %s res->start %llx res->end %llx "
		"bus_region.start: 0x%llx, bus_region.end: 0x%llx\n",
		__func__, vf_res->name, vf_res->start, vf_res->end, bus_region.start,
		bus_region.end);
	pcibios_bus_to_resource(vf_dev->bus, vf_res, &bus_region);
}

static int
octep_sriov_enable(struct pci_dev *pdev, int num_vfs)
{
	struct octep_pf *pf = pci_get_drvdata(pdev);
	u8 __iomem *addr = pf->base[OCTEP_HW_REGS_BAR];
	struct pci_dev *vf_pdev = NULL;
	bool done = false;
	int index = 0;
	int ret, i;
	u8 rpvf;
	u64 val;

	ret = pci_enable_sriov(pdev, num_vfs);
	if (ret)
		return ret;

	pf->enabled_vfs = num_vfs;

	while ((vf_pdev = pci_get_device(PCI_VENDOR_ID_CAVIUM, PCI_ANY_ID, vf_pdev))) {
		if (vf_pdev->device != pf->vf_devid)
			continue;

		octep_rdma_assign_barspace(vf_pdev, pdev, index);
		if (++index == num_vfs) {
			done = true;
			break;
		}
	}

	val = readq(addr + OCTEP_EPF_RINFO(0));
	rpvf = FIELD_GET(GENMASK_ULL(35, 32), val);
	if (done) {
		dev_dbg(&pdev->dev, "PF: %s, rpvf %d enabled_vfs %d\n", __func__, rpvf,
			pf->enabled_vfs);
		for (i = 0; i < pf->enabled_vfs; i++)
			writel(OCTEP_DEV_READY_SIGNATURE, addr + OCTEP_PF_MBOX_DATA(i * rpvf));
	}

	return num_vfs;
}

static int
octep_sriov_disable(struct pci_dev *pdev)
{
	struct octep_pf *pf = pci_get_drvdata(pdev);

	if (!pci_num_vf(pdev))
		return 0;

	pci_disable_sriov(pdev);
	pf->enabled_vfs = 0;

	return 0;
}

static int
octep_rdma_sriov_configure(struct pci_dev *pdev, int num_vfs)
{
	if (num_vfs > 0)
		return octep_sriov_enable(pdev, num_vfs);
	else
		return octep_sriov_disable(pdev);
}

static u16
octep_get_vf_devid(struct pci_dev *pdev)
{
	u16 did;

	switch (pdev->device) {
	case OCTEP_RDMA_DEVID_CN106K_PF:
		did = OCTEP_RDMA_DEVID_CN106K_VF;
		break;
	case OCTEP_RDMA_DEVID_CN105K_PF:
		did = OCTEP_RDMA_DEVID_CN105K_VF;
		break;
	case OCTEP_RDMA_DEVID_CN103K_PF:
		did = OCTEP_RDMA_DEVID_CN103K_VF;
		break;
	default:
		did = 0xFFFF;
		break;
	}

	return did;
}

static int
octep_rdma_pf_setup(struct octep_pf *octpf)
{
	u8 __iomem *addr = octpf->base[OCTEP_HW_REGS_BAR];
	struct pci_dev *pdev = octpf->pdev;
	int totalvfs;
	size_t len;
	u64 val;

	totalvfs = pci_sriov_get_totalvfs(pdev);
	if (unlikely(!totalvfs)) {
		dev_info(&pdev->dev, "Total VFs are %d in PF sriov configuration\n", totalvfs);
		return 0;
	}

	addr = octpf->base[OCTEP_HW_REGS_BAR];
	val = readq(addr + OCTEP_EPF_RINFO(0));
	if (val == 0) {
		dev_err(&pdev->dev, "Invalid device configuration\n");
		return -EINVAL;
	}

	len = pci_resource_len(pdev, OCTEP_HW_MBOX_BAR);

	octpf->vf_stride = len / totalvfs;
	octpf->vf_devid = octep_get_vf_devid(pdev);

	octep_rdma_pf_bar_shrink(octpf);

	return 0;
}

static int
octep_rdma_probe_pf(struct pci_dev *pdev)
{
	struct device *dev = &pdev->dev;
	struct octep_pf *octpf;
	int ret;

	ret = pcim_enable_device(pdev);
	if (ret) {
		dev_err(dev, "Failed to enable device\n");
		return ret;
	}

	ret = dma_set_mask_and_coherent(dev, DMA_BIT_MASK(64));
	if (ret) {
		dev_err(dev, "No usable DMA configuration\n");
		return ret;
	}
	octpf = devm_kzalloc(dev, sizeof(*octpf), GFP_KERNEL);
	if (!octpf)
		return -ENOMEM;

	ret = octep_iomap_region(pdev, octpf->base, OCTEP_HW_REGS_BAR);
	if (ret) {
		dev_err(dev, "Failed to map REGs BAR:%u\n", OCTEP_HW_REGS_BAR);
		return ret;
	}

	pci_set_master(pdev);
	pci_set_drvdata(pdev, octpf);
	octpf->pdev = pdev;

	ret = octep_rdma_pf_setup(octpf);
	if (ret)
		goto unmap_region;

	return 0;

unmap_region:
	octep_iounmap_region(pdev, octpf->base, OCTEP_HW_REGS_BAR);
	return ret;
}

static int
octep_rdma_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	if (pdev->is_virtfn)
		return octep_rdma_probe_vf(pdev);
	else
		return octep_rdma_probe_pf(pdev);
}

static struct pci_device_id octep_pci_rdma_map[] = {
	{PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, OCTEP_RDMA_DEVID_CN106K_PF)},
	{PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, OCTEP_RDMA_DEVID_CN106K_VF)},
	{PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, OCTEP_RDMA_DEVID_CN105K_PF)},
	{PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, OCTEP_RDMA_DEVID_CN105K_VF)},
	{PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, OCTEP_RDMA_DEVID_CN103K_PF)},
	{PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, OCTEP_RDMA_DEVID_CN103K_VF)},
	{0},
};

static struct pci_driver octep_pci_rdma = {.name = OCTEP_RDMA_DRV_NAME,
					   .id_table = octep_pci_rdma_map,
					   .probe = octep_rdma_probe,
					   .remove = octep_rdma_remove,
					   .sriov_configure = octep_rdma_sriov_configure};

module_pci_driver(octep_pci_rdma);
MODULE_DESCRIPTION(OCTEP_DRV_STRING);
MODULE_LICENSE("GPL");
