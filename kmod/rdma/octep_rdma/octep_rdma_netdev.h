/* SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2025 Marvell.
 *
 * Management QP-based netdev for non-RDMA packet path.
 * Uses the last QP (max_qp - 1) as a dedicated management QP.
 * TX: host posts send WQEs, firmware extracts raw Ethernet and sends to NIC.
 * RX: firmware receives non-RoCE packets, posts to management QP RQ, host CQ poll delivers.
 */

#ifndef __OCTEP_RDMA_NETDEV_H__
#define __OCTEP_RDMA_NETDEV_H__

#include <linux/netdevice.h>

struct octep_rdma_dev;
struct octep_rdma_qp;
struct octep_rdma_cq;
struct octep_ep_dev;
struct octep_caps_region;

#define OCTEP_RDMA_MGMT_SQ_DEPTH    256
#define OCTEP_RDMA_MGMT_RQ_DEPTH    256
#define OCTEP_RDMA_MGMT_CQ_DEPTH    512
#define OCTEP_RDMA_MGMT_BUF_SIZE    10000
#define OCTEP_RDMA_MGMT_RX_POLL_MS  1

#define OCTEP_MIN_MTU     ETH_MIN_MTU
#define OCTEP_MAX_MTU     (10000 - (ETH_HLEN + ETH_FCS_LEN))
#define OCTEP_DEFAULT_MTU 1500

struct octep_rdma_mgmt_qp_ctx {
	struct octep_rdma_qp *qp;
	struct octep_rdma_cq *cq;
	u32 mgmt_qpn;

	/* TX: DMA-coherent buffer pool + skb tracking */
	void *tx_bufs;
	dma_addr_t tx_bufs_dma;
	struct sk_buff **tx_skbs;
	u32 tx_head;
	u32 tx_tail;

	/* RX: DMA-coherent buffer pool */
	void *rx_bufs;
	dma_addr_t rx_bufs_dma;

	/* DMA MR lkey for all DMA addresses */
	u32 dma_lkey;

	/* RX poll work (until NAPI CQ interrupt support is available) */
	struct delayed_work rx_poll_work;
	bool running;

	/* Stats */
	struct net_device_stats stats;

	struct net_device *ndev;
};

int octep_rdma_mgmt_qp_netdev_init(struct octep_rdma_dev *rdma_dev,
				   struct octep_ep_dev *octep_dev,
				    struct octep_caps_region *caps_rgn);
void octep_rdma_mgmt_qp_netdev_cleanup(struct octep_rdma_dev *rdma_dev);

#endif /* __OCTEP_RDMA_NETDEV_H__ */
