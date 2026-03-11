/* SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2025 Marvell.
 *
 * Management QP-based netdev for non-RDMA packet path.
 * Uses QP (max_qp - 1) as a dedicated management QP for raw Ethernet traffic.
 * TX: ndo_start_xmit → post_send on mgmt QP → FW extracts payload → NIC TX
 * RX: NIC RX → FW posts to mgmt QP RQ → CQ poll → skb → netif_rx
 */

#include <linux/pci.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/if_ether.h>
#include <linux/dma-mapping.h>
#include <linux/workqueue.h>

#include "octep_rdma_netdev.h"
#include "octep_rdma.h"
#include "octep_qp.h"
#include "octep_cq.h"
#include "octep_verbs.h"
#include "octep_ep.h"

#define MAC_OFFSET 9

static void mgmt_destroy_qp(struct octep_rdma_dev *rdma_dev, struct octep_rdma_qp *qp);

static inline void *mgmt_tx_buf(struct octep_rdma_mgmt_qp_ctx *ctx, u32 idx)
{
	return (u8 *)ctx->tx_bufs + (u64)idx * OCTEP_RDMA_MGMT_BUF_SIZE;
}

static inline dma_addr_t mgmt_tx_buf_dma(struct octep_rdma_mgmt_qp_ctx *ctx, u32 idx)
{
	return ctx->tx_bufs_dma + (dma_addr_t)idx * OCTEP_RDMA_MGMT_BUF_SIZE;
}

static inline void *mgmt_rx_buf(struct octep_rdma_mgmt_qp_ctx *ctx, u32 idx)
{
	return (u8 *)ctx->rx_bufs + (u64)idx * OCTEP_RDMA_MGMT_BUF_SIZE;
}

static inline dma_addr_t mgmt_rx_buf_dma(struct octep_rdma_mgmt_qp_ctx *ctx, u32 idx)
{
	return ctx->rx_bufs_dma + (dma_addr_t)idx * OCTEP_RDMA_MGMT_BUF_SIZE;
}

/* octep_flush_to_dram() is provided by octep_ep.h */

/* ---- Post one receive WQE with pre-allocated DMA buffer ---- */

static int mgmt_post_one_recv(struct octep_rdma_mgmt_qp_ctx *ctx, u32 buf_idx)
{
	struct ib_recv_wr wr, *bad_wr;
	struct ib_sge sge;

	sge.addr = mgmt_rx_buf_dma(ctx, buf_idx);
	sge.length = OCTEP_RDMA_MGMT_BUF_SIZE;
	sge.lkey = ctx->dma_lkey;

	memset(&wr, 0, sizeof(wr));
	wr.wr_id = buf_idx;
	wr.sg_list = &sge;
	wr.num_sge = 1;

	return octep_rdma_post_recv(&ctx->qp->ibqp, &wr, (const struct ib_recv_wr **)&bad_wr);
}

/* ---- TX ---- */

static netdev_tx_t octep_rdma_mgmt_xmit(struct sk_buff *skb, struct net_device *ndev)
{
	struct octep_ep_dev *octep_dev = netdev_priv(ndev);
	struct octep_rdma_mgmt_qp_ctx *ctx = octep_dev->mgmt_qp_ctx;
	struct ib_send_wr wr, *bad_wr;
	struct ib_sge sge;
	u32 idx, max_data;
	void *buf;

	if (!ctx || !ctx->running) {
		dev_kfree_skb_any(skb);
		return NETDEV_TX_OK;
	}

	max_data = OCTEP_RDMA_MGMT_BUF_SIZE;
	if (skb_put_padto(skb, ETH_ZLEN)) {
		ctx->stats.tx_dropped++;
		return NETDEV_TX_OK;
	}
	if (skb->len > max_data) {
		dev_kfree_skb_any(skb);
		ctx->stats.tx_dropped++;
		return NETDEV_TX_OK;
	}

	if (ctx->tx_head - READ_ONCE(ctx->tx_tail) >= OCTEP_RDMA_MGMT_SQ_DEPTH) {
		netif_stop_queue(ndev);
		return NETDEV_TX_BUSY;
	}

	idx = ctx->tx_head & (OCTEP_RDMA_MGMT_SQ_DEPTH - 1);

	buf = mgmt_tx_buf(ctx, idx);
	skb_copy_bits(skb, 0, buf, skb->len);
	octep_flush_to_dram(buf, skb->len);

	sge.addr = mgmt_tx_buf_dma(ctx, idx);
	sge.length = skb->len;
	sge.lkey = ctx->dma_lkey;

	memset(&wr, 0, sizeof(wr));
	wr.wr_id = idx;
	wr.opcode = IB_WR_SEND;
	wr.send_flags = IB_SEND_SIGNALED;
	wr.sg_list = &sge;
	wr.num_sge = 1;

	if (octep_rdma_post_send(&ctx->qp->ibqp, &wr,
				 (const struct ib_send_wr **)&bad_wr)) {
		ctx->stats.tx_dropped++;
		dev_kfree_skb_any(skb);
		return NETDEV_TX_OK;
	}

	ctx->tx_skbs[idx] = skb;
	WRITE_ONCE(ctx->tx_head, ctx->tx_head + 1);
	ctx->stats.tx_packets++;
	ctx->stats.tx_bytes += skb->len;

	if (ctx->tx_head - READ_ONCE(ctx->tx_tail) >= OCTEP_RDMA_MGMT_SQ_DEPTH)
		netif_stop_queue(ndev);

	return NETDEV_TX_OK;
}

/* ---- CQ poll (handles both TX completions and RX) ---- */

static void octep_rdma_mgmt_cq_poll(struct work_struct *work)
{
	struct octep_rdma_mgmt_qp_ctx *ctx =
		container_of(work, struct octep_rdma_mgmt_qp_ctx, rx_poll_work.work);
	struct net_device *ndev = ctx->ndev;
	struct ib_wc wc[8];
	int n, i;

	if (!ctx->running || !ndev)
		return;

	n = octep_rdma_poll_one_cqe(ctx->cq, wc, 8);

	for (i = 0; i < n; i++) {
		if (wc[i].status != IB_WC_SUCCESS) {
			if (wc[i].opcode == IB_WC_RECV) {
				mgmt_post_one_recv(ctx, wc[i].wr_id);
			} else {
				u32 idx = wc[i].wr_id;

				if (idx < OCTEP_RDMA_MGMT_SQ_DEPTH && ctx->tx_skbs[idx]) {
					dev_kfree_skb_any(ctx->tx_skbs[idx]);
					ctx->tx_skbs[idx] = NULL;
					WRITE_ONCE(ctx->tx_tail, ctx->tx_tail + 1);
				}
				ctx->stats.tx_errors++;
			}
			continue;
		}

		if (wc[i].opcode == IB_WC_RECV) {
			u32 buf_idx = wc[i].wr_id;
			u32 pkt_len = wc[i].byte_len;
			void *buf = mgmt_rx_buf(ctx, buf_idx);
			struct sk_buff *skb;

			octep_invalidate_cache(buf, pkt_len);

			if (pkt_len == 0 || pkt_len > OCTEP_RDMA_MGMT_BUF_SIZE) {
				ctx->stats.rx_errors++;
				mgmt_post_one_recv(ctx, buf_idx);
				continue;
			}

			skb = netdev_alloc_skb(ndev, pkt_len + NET_IP_ALIGN);
			if (!skb) {
				ctx->stats.rx_dropped++;
				mgmt_post_one_recv(ctx, buf_idx);
				continue;
			}

			skb_reserve(skb, NET_IP_ALIGN);
			skb_put_data(skb, buf, pkt_len);
			skb->protocol = eth_type_trans(skb, ndev);
			skb->ip_summed = CHECKSUM_NONE;

			ctx->stats.rx_packets++;
			ctx->stats.rx_bytes += pkt_len;

			netif_rx(skb);

			mgmt_post_one_recv(ctx, buf_idx);
		} else {
			u32 idx = wc[i].wr_id;

			if (idx < OCTEP_RDMA_MGMT_SQ_DEPTH && ctx->tx_skbs[idx]) {
				dev_kfree_skb_any(ctx->tx_skbs[idx]);
				ctx->tx_skbs[idx] = NULL;
				WRITE_ONCE(ctx->tx_tail, ctx->tx_tail + 1);
			}
		}
	}

	if (netif_queue_stopped(ndev) &&
	    READ_ONCE(ctx->tx_head) - ctx->tx_tail < OCTEP_RDMA_MGMT_SQ_DEPTH)
		netif_wake_queue(ndev);

	if (ctx->running)
		schedule_delayed_work(&ctx->rx_poll_work,
				      msecs_to_jiffies(OCTEP_RDMA_MGMT_RX_POLL_MS));
}

/* ---- Netdev ops ---- */

static int octep_rdma_mgmt_ndo_open(struct net_device *ndev)
{
	struct octep_ep_dev *octep_dev = netdev_priv(ndev);
	struct octep_rdma_mgmt_qp_ctx *ctx = octep_dev->mgmt_qp_ctx;

	if (!ctx)
		return -ENODEV;

	ctx->running = true;
	schedule_delayed_work(&ctx->rx_poll_work,
			      msecs_to_jiffies(OCTEP_RDMA_MGMT_RX_POLL_MS));
	netif_carrier_on(ndev);
	netif_tx_start_all_queues(ndev);

	netdev_info(ndev, "interface up (MAC %pM), mgmt QP %u\n",
		    ndev->dev_addr, ctx->mgmt_qpn);
	return 0;
}

static int octep_rdma_mgmt_ndo_stop(struct net_device *ndev)
{
	struct octep_ep_dev *octep_dev = netdev_priv(ndev);
	struct octep_rdma_mgmt_qp_ctx *ctx = octep_dev->mgmt_qp_ctx;

	if (!ctx)
		return 0;

	netif_tx_stop_all_queues(ndev);
	netif_carrier_off(ndev);
	ctx->running = false;
	cancel_delayed_work_sync(&ctx->rx_poll_work);
	return 0;
}

static void octep_rdma_mgmt_get_stats64(struct net_device *ndev,
					struct rtnl_link_stats64 *s)
{
	struct octep_ep_dev *octep_dev = netdev_priv(ndev);
	struct octep_rdma_mgmt_qp_ctx *ctx = octep_dev->mgmt_qp_ctx;

	if (!ctx)
		return;

	s->tx_packets = ctx->stats.tx_packets;
	s->tx_bytes   = ctx->stats.tx_bytes;
	s->tx_errors  = ctx->stats.tx_errors;
	s->tx_dropped = ctx->stats.tx_dropped;
	s->rx_packets = ctx->stats.rx_packets;
	s->rx_bytes   = ctx->stats.rx_bytes;
	s->rx_errors  = ctx->stats.rx_errors;
	s->rx_dropped = ctx->stats.rx_dropped;
}

static int octep_rdma_mgmt_set_mac(struct net_device *ndev, void *p)
{
	struct sockaddr *addr = p;

	if (!is_valid_ether_addr(addr->sa_data))
		return -EADDRNOTAVAIL;

	dev_addr_set(ndev, addr->sa_data);
	return 0;
}

static int octep_rdma_mgmt_change_mtu(struct net_device *ndev, int new_mtu)
{
	if (new_mtu + ETH_HLEN > OCTEP_RDMA_MGMT_BUF_SIZE) {
		netdev_err(ndev, "MTU %d exceeds mgmt QP buffer (%u)\n",
			   new_mtu, OCTEP_RDMA_MGMT_BUF_SIZE - ETH_HLEN);
		return -EINVAL;
	}

	ndev->mtu = new_mtu;
	return 0;
}

static const struct net_device_ops octep_rdma_mgmt_netdev_ops = {
	.ndo_open            = octep_rdma_mgmt_ndo_open,
	.ndo_stop            = octep_rdma_mgmt_ndo_stop,
	.ndo_start_xmit      = octep_rdma_mgmt_xmit,
	.ndo_get_stats64     = octep_rdma_mgmt_get_stats64,
	.ndo_set_mac_address = octep_rdma_mgmt_set_mac,
	.ndo_change_mtu      = octep_rdma_mgmt_change_mtu,
};

/* ---- Management QP / CQ creation ---- */

static struct octep_rdma_cq *
mgmt_create_cq(struct octep_rdma_dev *rdma_dev, u32 cqn, u32 depth)
{
	struct octep_rdma_cq *cq;
	int ret;

	cq = kzalloc(sizeof(*cq), GFP_KERNEL);
	if (!cq)
		return ERR_PTR(-ENOMEM);

	cq->ibcq.device = &rdma_dev->ibdev;
	cq->cqn = cqn;
	cq->depth = depth;
	cq->qmask = depth - 1;

	ret = octep_rdma_init_kernel_cq(cq);
	if (ret) {
		kfree(cq);
		return ERR_PTR(ret);
	}

	ret = octep_rdma_prepare_cq_cmd(rdma_dev, cq, false);
	if (ret) {
		octep_rdma_free_kernel_cq(rdma_dev, cq);
		kfree(cq);
		return ERR_PTR(ret);
	}

	return cq;
}

static void mgmt_destroy_cq(struct octep_rdma_dev *rdma_dev, struct octep_rdma_cq *cq)
{
	if (!cq)
		return;
	octep_rdma_prepare_cq_destroy_cmd(rdma_dev, cq);
	octep_rdma_free_kernel_cq(rdma_dev, cq);
	kfree(cq);
}

static struct octep_rdma_qp *
mgmt_create_qp(struct octep_rdma_dev *rdma_dev, u32 qpn,
	       struct octep_rdma_cq *cq, bool is_mgmt)
{
	struct octep_rdma_qp *qp;
	struct ib_qp_init_attr init_attr;
	int ret;

	qp = kzalloc(sizeof(*qp), GFP_KERNEL);
	if (!qp)
		return ERR_PTR(-ENOMEM);

	qp->ibqp.device = &rdma_dev->ibdev;
	qp->ibqp.qp_num = qpn;
	qp->ibqp.qp_type = IB_QPT_RAW_PACKET;
	qp->rdma_dev = rdma_dev;
	qp->scq = cq;
	qp->rcq = cq;
	spin_lock_init(&qp->lock);
	spin_lock_init(&qp->rq_lock);
	init_rwsem(&qp->state_lock);
	kref_init(&qp->ref);
	init_completion(&qp->safe_free);

	memset(&init_attr, 0, sizeof(init_attr));
	init_attr.cap.max_send_wr = OCTEP_RDMA_MGMT_SQ_DEPTH - 1;
	init_attr.cap.max_recv_wr = OCTEP_RDMA_MGMT_RQ_DEPTH - 1;
	init_attr.cap.max_send_sge = 1;
	init_attr.cap.max_recv_sge = 1;
	init_attr.sq_sig_type = IB_SIGNAL_ALL_WR;

	ret = init_kernel_qp(rdma_dev, qp, &init_attr);
	if (ret) {
		kfree(qp);
		return ERR_PTR(ret);
	}

	{
		struct octep_rdma_qp_create_req *qp_req;

		qp_req = kzalloc(sizeof(*qp_req), GFP_KERNEL);
		if (!qp_req) {
			free_kernel_qp(rdma_dev, qp);
			kfree(qp);
			return ERR_PTR(-ENOMEM);
		}

		qp_req->port_num = rdma_dev->port.port_num;
		qp_req->qp_id = qpn;
		qp_req->pd_id = 0;
		qp_req->sq_size = qp->attrs.sq_size;
		qp_req->rq_size = qp->attrs.rq_size;
		qp_req->send_cq_id = cq->cqn;
		qp_req->recv_cq_id = cq->cqn;
		qp_req->type = is_mgmt ? OCTEP_RDMA_QP_TYPE_MGMT : IB_QPT_RC;
		qp_req->sq_sig_type = IB_SIGNAL_ALL_WR;
		qp_req->sq_base = qp->kern_qp.sq.qbuf_dma_addr;
		qp_req->rq_base = qp->kern_qp.rq.qbuf_dma_addr;
		qp_req->ibqp = (u64)(uintptr_t)&qp->ibqp;

		ret = octep_rdma_mbox_qp_create(rdma_dev->caps_rgn, qp_req);
		kfree(qp_req);
		if (ret) {
			free_kernel_qp(rdma_dev, qp);
			kfree(qp);
			return ERR_PTR(ret);
		}
	}

	if (is_mgmt) {
		struct octep_rdma_user_qp_modify_req *qp_mod;

		ret = octep_rdma_prepare_qp_state_cmd(rdma_dev, qp, true);
		if (ret) {
			mgmt_destroy_qp(rdma_dev, qp);
			return ERR_PTR(ret);
		}

		qp_mod = kzalloc(sizeof(*qp_mod), GFP_KERNEL);
		if (!qp_mod) {
			mgmt_destroy_qp(rdma_dev, qp);
			return ERR_PTR(-ENOMEM);
		}

		qp_mod->port_num = rdma_dev->port.port_num;
		qp_mod->qp_id = qpn;
		qp_mod->modify_mask = IB_QP_STATE;
		qp_mod->new_qp_state = IB_QPS_RTS;
		qp_mod->cur_qp_state = IB_QPS_RESET;

		ret = octep_rdma_mbox_user_qp_modify(rdma_dev->caps_rgn, qp_mod);
		kfree(qp_mod);
		if (ret) {
			mgmt_destroy_qp(rdma_dev, qp);
			return ERR_PTR(ret);
		}
	}

	return qp;
}

static void mgmt_destroy_qp(struct octep_rdma_dev *rdma_dev, struct octep_rdma_qp *qp)
{
	struct octep_rdma_qp_destroy_req req;

	if (!qp)
		return;

	req.port_num = rdma_dev->port.port_num;
	req.qp_id = qp->ibqp.qp_num;
	octep_rdma_mbox_qp_destroy(rdma_dev->caps_rgn, &req);

	free_kernel_qp(rdma_dev, qp);
	kfree(qp);
}

/* ---- Init / Cleanup ---- */

int octep_rdma_mgmt_qp_netdev_init(struct octep_rdma_dev *rdma_dev,
				   struct octep_ep_dev *octep_dev,
				   struct octep_caps_region *caps_rgn)
{
	struct net_device *ndev = octep_dev->netdev;
	struct device *dma_dev = &octep_dev->pdev->dev;
	struct octep_rdma_mgmt_qp_ctx *ctx;
	u32 mgmt_qpn, mgmt_cqn;
	size_t tx_pool_sz, rx_pool_sz;
	int ret, i;

	if (!ndev || !caps_rgn) {
		dev_warn(dma_dev, "netdev or caps_rgn NULL\n");
		return -EINVAL;
	}

	if (!rdma_dev->attr.max_qp || !rdma_dev->attr.max_cq) {
		dev_err(dma_dev, "Device caps not initialized (max_qp=%u max_cq=%u)\n",
			rdma_dev->attr.max_qp, rdma_dev->attr.max_cq);
		return -EINVAL;
	}

	mgmt_qpn = rdma_dev->attr.max_qp - 1;
	mgmt_cqn = rdma_dev->attr.max_cq - 1;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	ctx->ndev = ndev;
	ctx->mgmt_qpn = mgmt_qpn;
	ctx->dma_lkey = 0;
	INIT_DELAYED_WORK(&ctx->rx_poll_work, octep_rdma_mgmt_cq_poll);

	/* Allocate TX buffer pool */
	tx_pool_sz = (size_t)OCTEP_RDMA_MGMT_SQ_DEPTH * OCTEP_RDMA_MGMT_BUF_SIZE;
	ctx->tx_bufs = dma_alloc_coherent(dma_dev, tx_pool_sz, &ctx->tx_bufs_dma, GFP_KERNEL);
	if (!ctx->tx_bufs) {
		ret = -ENOMEM;
		goto err_free_ctx;
	}

	ctx->tx_skbs = kcalloc(OCTEP_RDMA_MGMT_SQ_DEPTH, sizeof(struct sk_buff *), GFP_KERNEL);
	if (!ctx->tx_skbs) {
		ret = -ENOMEM;
		goto err_free_tx_bufs;
	}

	/* Allocate RX buffer pool */
	rx_pool_sz = (size_t)OCTEP_RDMA_MGMT_RQ_DEPTH * OCTEP_RDMA_MGMT_BUF_SIZE;
	ctx->rx_bufs = dma_alloc_coherent(dma_dev, rx_pool_sz, &ctx->rx_bufs_dma, GFP_KERNEL);
	if (!ctx->rx_bufs) {
		ret = -ENOMEM;
		goto err_free_tx_skbs;
	}

	/* Create management CQ */
	ctx->cq = mgmt_create_cq(rdma_dev, mgmt_cqn, OCTEP_RDMA_MGMT_CQ_DEPTH);
	if (IS_ERR(ctx->cq)) {
		ret = PTR_ERR(ctx->cq);
		ctx->cq = NULL;
		dev_err(dma_dev, "failed to create mgmt CQ: %d\n", ret);
		goto err_free_rx_bufs;
	}

	/* Create management QP with MGMT flag */
	ctx->qp = mgmt_create_qp(rdma_dev, mgmt_qpn, ctx->cq, true);
	if (IS_ERR(ctx->qp)) {
		ret = PTR_ERR(ctx->qp);
		ctx->qp = NULL;
		dev_err(dma_dev, "failed to create mgmt QP: %d\n", ret);
		goto err_destroy_cq;
	}

	/* Pre-post receive WQEs */
	for (i = 0; i < OCTEP_RDMA_MGMT_RQ_DEPTH - 1; i++) {
		ret = mgmt_post_one_recv(ctx, i);
		if (ret) {
			dev_err(dma_dev, "failed to post mgmt RQE %d: %d\n", i, ret);
			goto err_destroy_qp;
		}
	}

	/* Configure and register netdev */
	if (caps_rgn->dev_cfg) {
		u8 mac[ETH_ALEN];

		memcpy_fromio(mac, caps_rgn->dev_cfg + MAC_OFFSET, ETH_ALEN);
		if (is_valid_ether_addr(mac))
			dev_addr_set(ndev, mac);
	}

	ndev->netdev_ops = &octep_rdma_mgmt_netdev_ops;
	ndev->min_mtu = ETH_MIN_MTU;
	ndev->max_mtu = OCTEP_RDMA_MGMT_BUF_SIZE - ETH_HLEN;
	ndev->mtu = ETH_DATA_LEN;

	ret = register_netdev(ndev);
	if (ret) {
		dev_err(dma_dev, "register_netdev failed: %d\n", ret);
		goto err_destroy_qp;
	}

	octep_dev->mgmt_qp_ctx = ctx;
	dev_info(dma_dev, "mgmt QP %u netdev registered (CQ %u)\n", mgmt_qpn, mgmt_cqn);
	return 0;

err_destroy_qp:
	mgmt_destroy_qp(rdma_dev, ctx->qp);
err_destroy_cq:
	mgmt_destroy_cq(rdma_dev, ctx->cq);
err_free_rx_bufs:
	dma_free_coherent(dma_dev, rx_pool_sz, ctx->rx_bufs, ctx->rx_bufs_dma);
err_free_tx_skbs:
	kfree(ctx->tx_skbs);
err_free_tx_bufs:
	dma_free_coherent(dma_dev, tx_pool_sz, ctx->tx_bufs, ctx->tx_bufs_dma);
err_free_ctx:
	kfree(ctx);
	return ret;
}

void octep_rdma_mgmt_qp_netdev_cleanup(struct octep_rdma_dev *rdma_dev)
{
	struct octep_ep_dev *octep_dev = rdma_dev->octep_dev;
	struct octep_rdma_mgmt_qp_ctx *ctx;
	struct device *dma_dev;
	int i;

	if (!octep_dev)
		return;

	ctx = octep_dev->mgmt_qp_ctx;
	if (!ctx)
		return;

	dma_dev = &octep_dev->pdev->dev;

	unregister_netdev(ctx->ndev);

	ctx->running = false;
	cancel_delayed_work_sync(&ctx->rx_poll_work);

	/* Free any pending TX skbs */
	for (i = 0; i < OCTEP_RDMA_MGMT_SQ_DEPTH; i++) {
		if (ctx->tx_skbs[i]) {
			dev_kfree_skb_any(ctx->tx_skbs[i]);
			ctx->tx_skbs[i] = NULL;
		}
	}

	mgmt_destroy_qp(rdma_dev, ctx->qp);
	mgmt_destroy_cq(rdma_dev, ctx->cq);

	dma_free_coherent(dma_dev,
			  (size_t)OCTEP_RDMA_MGMT_RQ_DEPTH * OCTEP_RDMA_MGMT_BUF_SIZE,
			  ctx->rx_bufs, ctx->rx_bufs_dma);
	kfree(ctx->tx_skbs);
	dma_free_coherent(dma_dev,
			  (size_t)OCTEP_RDMA_MGMT_SQ_DEPTH * OCTEP_RDMA_MGMT_BUF_SIZE,
			  ctx->tx_bufs, ctx->tx_bufs_dma);

	octep_dev->mgmt_qp_ctx = NULL;
	kfree(ctx);

	dev_info(dma_dev, "mgmt QP netdev cleaned up\n");
}
