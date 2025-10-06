/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef __RDMA_FP_H__
#define __RDMA_FP_H__

#include <rte_ether.h>
#include <rte_mbuf.h>
#include <rte_mbuf_core.h>
#include <rte_net.h>
#include <rte_udp.h>

/* UDP header starts at offset 34. Eth(14) + IP(20) */
#define IPV4_UDP_HDR_OFFSET           34
#define RDMA_ROCEV2_PORT              4791
#define APP_RDMA_PTS_DEQ_BURST_PER_QP 8

enum rdm_resp_ret {
	RDMA_RESPONDER_DONE = 1,
	RDMA_RESPONDER_MBUF_DROP,
	RDMA_RESPONDER_MBUF_UPDATED,
	RDMA_RESPONDER_MBUF_CONSUMED,
	RDMA_COMPLETION_DONE,
};

static __rte_always_inline bool
dao_rdma_pkt_check(struct rte_mbuf *mbuf)
{
	struct rte_udp_hdr *udp_hdr;
	uint16_t ptype;

	ptype = (mbuf->packet_type & RTE_PTYPE_L4_MASK);
	if (unlikely(ptype != RTE_PTYPE_L4_UDP))
		return false;

	udp_hdr = rte_pktmbuf_mtod_offset(mbuf, struct rte_udp_hdr *, IPV4_UDP_HDR_OFFSET);
	if (udp_hdr->dst_port == rte_be_to_cpu_16(RDMA_ROCEV2_PORT))
		return true;

	return false;
}

typedef int (*rdma_qp_status_cb_t)(uint16_t devid, uint16_t qp_id, bool enable);
typedef void (*rcu_cb_t)(void);
typedef uint16_t (*rdma_map_cb_t)(uint16_t port_num, uint8_t *pause_flag);

typedef struct rdma_cb {
	rdma_qp_status_cb_t qp_status_cb;
	rcu_cb_t rcu_cb;
	rdma_map_cb_t rdma_map_cb;
} rdma_cb_t;

int dao_rdma_rx_process(struct rte_mbuf **mbuf, uint16_t rx_queue, uint32_t *qpn, int devid);
int dao_rdma_tx_process(struct rte_mbuf *mbuf, uint32_t qp_id, int devid, struct rte_mbuf **mbufs,
			uint16_t *n_mbufs);
int dao_rdma_get_pvt_len(void);
int dao_rdma_lib_init(rdma_cb_t *cb);
void dao_rdma_lib_close(void);
int dump_few_bytes(struct rte_mbuf *mbuf);
void dao_rdma_register_rdma_map_cb(rdma_map_cb_t cb);
int dao_rdma_update_mtu(uint16_t port_id, uint16_t mtu);
uint16_t dao_rdma_get_retransmition_pkts(int qp_id, int dev_id, int num_pkts,
					 struct rte_mbuf *mbufs[]);
uint16_t dao_is_qp_stalled(uint32_t qp_id, int devid);
uint16_t dao_rdma_ack_dequeue_until_read(uint32_t qp_id, int devid, struct rte_mbuf **mbufs,
					 uint16_t max_pkts);

#endif /* __RDMA_FP_H__ */
