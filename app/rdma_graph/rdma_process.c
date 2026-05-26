/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <arpa/inet.h>
#include <sys/socket.h>

#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_malloc.h>

#include <dao_log.h>
#include <rte_bus_pci.h>
#include <rte_ethdev.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_hexdump.h>
#include <rte_mbuf_core.h>

#include "rdma_node_ctrl.h"
#include "rdma_priv.h"

#include "dao_rdma_fp.h"

#include "dao_pts_rdma_dev.h"

#define RDMA_MAX_FRAG_SIZE 32768

extern int node_mbuf_priv1_dynfield_queue;

#define RDMA_NODE_PRIV1_OFF(ctx) (((struct rdma_node_ctx *)ctx)->mbuf_priv1_off)

struct rdma_node_main *rdma_nm;

static inline void
flush_speculated(void ***to_next_ptr, void ***from_ptr, uint16_t *last_spec, uint16_t *held)
{
	void **to_next = *to_next_ptr;
	void **from = *from_ptr;

	rte_memcpy(to_next, from, (*last_spec) * sizeof(void *));
	to_next += *last_spec;
	from += *last_spec;
	*held += *last_spec;
	*last_spec = 0;

	*to_next_ptr = to_next;
	*from_ptr = from;
}

/* Common helpers for next edge selection */
static inline rte_edge_t
rdma_next_edge_for_host(struct rte_mbuf *mbuf)
{
	uint16_t dport = rdma_nm->nrml_fwd_tbl[mbuf->port];

	return rdma_nm->eth_tx_edge[dport];
}

static inline rte_edge_t
rdma_next_edge_for_rdma(struct rte_mbuf *mbuf)
{
	uint16_t dport = rdma_nm->rdma_fwd_tbl[mbuf->port];

	return rdma_nm->eth_tx_edge[dport];
}

/* Process node for ETH RX path: handles host->RDMA responder and normal forwarding */
static uint16_t
rdma_rx_node_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs)
{
	const int dyn = RDMA_NODE_PRIV1_OFF(node->ctx);
	void **to_next, **from = objs;
	rte_edge_t next_index, next;
	void *tx_next[APP_RDMA_ETH_DEQ_BURST_MAX] = {NULL};
	uint16_t last_spec = 0;
	struct rte_mbuf *mbuf;
	uint16_t held = 0;
	int i, ret;

	if (unlikely(nb_objs == 0))
		return 0;

	/* Speculate normal host forwarding edge based on first packet */
	next_index = rdma_next_edge_for_host((struct rte_mbuf *)objs[0]);
	to_next = tx_next;

	for (i = 0; i < nb_objs; i++) {
		mbuf = (struct rte_mbuf *)objs[i];
		next = rdma_next_edge_for_host(mbuf);

		if (!dao_rdma_pkt_check(mbuf)) {
			uint16_t dport = rdma_nm->rdma_fwd_tbl[mbuf->port];

			if (dport >= RTE_MAX_ETHPORTS) {
				uint16_t devid = dport - RTE_MAX_ETHPORTS;
				int32_t mgmt_qp = dao_pts_rdma_mgmt_qp_id_get(devid);

				if (mgmt_qp >= 0) {
					uint16_t enq_ret;

					mbuf->ol_flags |= DAO_PTS_RDMA_ENQ_M2D_RQE_WITH_CQE << 60;
					enq_ret = dao_pts_rdma_enqueue_burst(devid, mgmt_qp, &mbuf,
									     1);
					if (enq_ret == 0)
						rte_pktmbuf_free(mbuf);
				} else {
					rte_pktmbuf_free(mbuf);
				}
			} else {
				rte_pktmbuf_free(mbuf);
			}
			if (unlikely(last_spec))
				flush_speculated(&to_next, &from, &last_spec, &held);
			from += 1;
			continue;
		}

		{
			uint16_t queue = node_mbuf_priv1(mbuf, dyn)->queue;
			uint16_t dport = rdma_nm->rdma_fwd_tbl[mbuf->port];
			uint16_t devid = dport - RTE_MAX_ETHPORTS;

			node_mbuf_priv1(mbuf, dyn)->nb_pkts = 1;
			ret = dao_rdma_rx_process(&mbuf, queue, &node_mbuf_priv1(mbuf, dyn)->qp_id,
						  devid);
			if (ret < 0) {
				next = RDMA_NEXT_PKT_DROP;
			} else if (ret == RDMA_RESPONDER_MBUF_CONSUMED) {
				/* Responder consumed the mbuf, nothing to forward */
				if (unlikely(last_spec))
					flush_speculated(&to_next, &from, &last_spec, &held);
				from += 1;
				continue;
			} else if (ret == RDMA_RESPONDER_MBUF_UPDATED) {
				/* Responder updated mbuf for forwarding to RDMA path */
				objs[i] = mbuf;
				next = rdma_next_edge_for_rdma(mbuf);
			} else {
				/* RDMA_COMPLETION_DONE or RDMA_RESPONDER_MBUF_DROP: drop original
				 * mbuf */
				next = RDMA_NEXT_PKT_DROP;
			}
		}

		if (unlikely(next_index != next)) {
			if (unlikely(last_spec))
				flush_speculated(&to_next, &from, &last_spec, &held);
			rte_node_enqueue_x1(graph, node, next, from[0]);
			from += 1;
		} else {
			last_spec += 1;
		}
	}

	/* Home-run fast path: all frames went to speculative next */
	if (likely(last_spec == nb_objs)) {
		if (unlikely(next_index >= node->nb_edges))
			next_index = RDMA_NEXT_PKT_DROP;
		rte_node_enqueue(graph, node, next_index, objs, nb_objs);
		return nb_objs;
	}

	if (last_spec) {
		rte_memcpy(to_next, from, last_spec * sizeof(from[0]));
		held += last_spec;
	}
	if (held)
		rte_node_enqueue(graph, node, next_index, tx_next, held);
	return nb_objs;
}

/* Process node for PTS path: handles RDMA TX path using qp_id/devid metadata */
static uint16_t
rdma_pts_node_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs)
{
	struct rte_mbuf *frag_mbuf[RDMA_MAX_FRAG_SIZE];
	const int dyn = RDMA_NODE_PRIV1_OFF(node->ctx);
	struct rte_mbuf **mbufs = frag_mbuf;
	uint16_t last_spec = 0, n_segs = 0;
	void **to_next, **from = objs;
	rte_edge_t next_index, next;
	void *tx_next[nb_objs];
	struct rte_mbuf *mbuf;
	uint16_t held = 0;
	int i, ret;

	if (unlikely(nb_objs == 0 || node == NULL || graph == NULL))
		return 0;

	/* Speculate based on RDMA device mapping of first mbuf */
	{
		struct rte_mbuf *m0 = (struct rte_mbuf *)objs[0];
		uint16_t dport0 = rdma_nm->rdma_fwd_tbl[m0->port];

		next_index = (dport0 < RTE_MAX_ETHPORTS) ? rdma_nm->eth_tx_edge[dport0] :
							   RDMA_NEXT_PKT_DROP;
	}

	to_next = tx_next;
	for (i = 0; i < nb_objs;) {
		/* Consume a run produced by PTS dequeue: metadata on first mbuf */
		struct rte_mbuf *first = (struct rte_mbuf *)objs[i];
		uint16_t run = node_mbuf_priv1(first, dyn)->nb_pkts;

		if (unlikely(run == 0))
			run = 1;
		uint32_t qp_id = node_mbuf_priv1(first, dyn)->qp_id;
		uint16_t queue = node_mbuf_priv1(first, dyn)->queue;
		uint16_t devid = node_mbuf_priv1(first, dyn)->devid;

		for (uint16_t j = 0; j < run; j++) {
			n_segs = 0;
			mbuf = (struct rte_mbuf *)objs[i + j];
			{
				uint16_t dport_i;

				dport_i = rdma_nm->rdma_fwd_tbl[mbuf->port];
				mbuf->port = dport_i;
				next = (dport_i < RTE_MAX_ETHPORTS) ?
					       rdma_nm->eth_tx_edge[dport_i] :
					       RDMA_NEXT_PKT_DROP;
			}

			ret = dao_rdma_tx_process(mbuf, qp_id, devid, mbufs, &n_segs);
			if (ret < 0)
				next = RDMA_NEXT_PKT_DROP;
			node_mbuf_priv1(mbuf, dyn)->queue = queue;
			if (n_segs > 1) {
				if (unlikely(last_spec))
					flush_speculated(&to_next, &from, &last_spec, &held);
				rte_node_enqueue(graph, node, next, (void **)mbufs, n_segs);
				from += 1;
				continue;
			}

			if (unlikely(next_index != next)) {
				if (unlikely(last_spec))
					flush_speculated(&to_next, &from, &last_spec, &held);
				if (unlikely(next >= node->nb_edges))
					next = RDMA_NEXT_PKT_DROP;
				rte_node_enqueue_x1(graph, node, next, from[0]);
				from += 1;
			} else {
				last_spec += 1;
			}
		}
		i += run;
	}

	/* Home-run fast path: all frames went to speculative next */
	if (likely(last_spec == nb_objs)) {
		if (unlikely(next_index >= node->nb_edges))
			next_index = RDMA_NEXT_PKT_DROP;
		rte_node_enqueue(graph, node, next_index, objs, nb_objs);
		return nb_objs;
	}

	if (last_spec) {
		rte_memcpy(to_next, from, last_spec * sizeof(from[0]));
		held += last_spec;
	}
	if (held)
		rte_node_enqueue(graph, node, next_index, tx_next, held);
	return nb_objs;
}

int
rdma_setup_nrml_fwd_table(uint16_t *host_mac_map, uint16_t nb_ports)
{
	int i;

	if (!host_mac_map)
		DAO_ERR_GOTO(-EINVAL, fail, "Empty forwarding table input");

	if (!nb_ports)
		DAO_ERR_GOTO(-EINVAL, fail, "No of ports cant be zero");

	if (rdma_nm == NULL) {
		rdma_nm = rte_zmalloc("flow_mapper", sizeof(struct rdma_node_main),
				      RTE_CACHE_LINE_SIZE);
		if (rdma_nm == NULL)
			return -ENOMEM;
	}

	for (i = 0; i < RTE_MAX_ETHPORTS * 2; i++) {
		rdma_nm->nrml_fwd_tbl[i] = host_mac_map[i];
		dao_dbg("rdma_nm->nrml_fwd_tbl[%d] = %d", i, rdma_nm->nrml_fwd_tbl[i]);
	}

	return 0;
fail:
	return errno;
}

int
rdma_setup_rdma_fwd_table(uint16_t *rdma_port_map, uint16_t nb_ports)
{
	uint16_t port_id;

	if (!rdma_port_map)
		DAO_ERR_GOTO(-EINVAL, fail, "Empty RDMA forwarding table input");

	if (!nb_ports)
		DAO_ERR_GOTO(-EINVAL, fail, "No of ports cant be zero");

	if (rdma_nm == NULL) {
		rdma_nm = rte_zmalloc("flow_mapper", sizeof(struct rdma_node_main),
				      RTE_CACHE_LINE_SIZE);
		if (rdma_nm == NULL)
			return -ENOMEM;
	}

	for (port_id = 0; port_id < RTE_MAX_ETHPORTS * 2; port_id++) {
		rdma_nm->rdma_fwd_tbl[port_id] = rdma_port_map[port_id];
		dao_dbg("rdma_nm->rdma_fwd_tbl[%d] = %d", port_id, rdma_nm->rdma_fwd_tbl[port_id]);
	}

	return 0;
fail:
	return errno;
}

/* Setting up the next edge for the eth tx node . */
int
rdma_set_eth_tx_edge_idx(uint16_t port_id, uint16_t next_index)
{
	if (rdma_nm == NULL) {
		rdma_nm = rte_zmalloc("flow_mapper", sizeof(struct rdma_node_main),
				      RTE_CACHE_LINE_SIZE);
		if (rdma_nm == NULL)
			return -ENOMEM;
	}

	rdma_nm->eth_tx_edge[port_id] = next_index;
	dao_dbg("port_idx %d eth_tx_edge %d", port_id, next_index);

	return 0;
}

static int
rdma_node_init(const struct rte_graph *graph, struct rte_node *node)
{
	static bool init_once;

	RTE_SET_USED(graph);

	if (!init_once) {
		node_mbuf_priv1_dynfield_queue =
			rte_mbuf_dynfield_register(&node_mbuf_priv1_dynfield_desc);
		if (node_mbuf_priv1_dynfield_queue < 0)
			return -rte_errno;

		if (rdma_nm == NULL) {
			rdma_nm = rte_zmalloc("flow_mapper", sizeof(struct rdma_node_main),
					      RTE_CACHE_LINE_SIZE);
			if (rdma_nm == NULL)
				return -ENOMEM;
		}

		init_once = 1;
	}

	RDMA_NODE_PRIV1_OFF(node->ctx) = node_mbuf_priv1_dynfield_queue;

	return 0;
}

uint16_t
rdma_get_mac_port_from_rdevid(uint16_t rdevid)
{
	uint16_t port_id;

	if (rdevid >= RTE_MAX_ETHPORTS) {
		dao_err("Invalid RDMA device id %d", rdevid);
		return RTE_MAX_ETHPORTS;
	}

	port_id = rdma_nm->rdma_fwd_tbl[rdevid + RTE_MAX_ETHPORTS];

	dao_dbg("%s: rdevid %d, port_id %d", __func__, rdevid, port_id);
	return port_id;
}

static struct rte_node_register rdma_rx_node = {
	.name = "rdma_rx_process",
	.process = rdma_rx_node_process,
	.init = rdma_node_init,
	.nb_edges = RDMA_NEXT_MAX,
	.next_nodes = {
		[RDMA_NEXT_PKT_DROP] = "pkt_drop",
	},
};

static struct rte_node_register rdma_pts_node = {
	.name = "rdma_pts_process",
	.process = rdma_pts_node_process,
	.init = rdma_node_init,
	.nb_edges = RDMA_NEXT_MAX,
	.next_nodes = {
		[RDMA_NEXT_PKT_DROP] = "pkt_drop",
	},
};

struct rte_node_register *
rdma_node_get(void)
{
	/* Keep legacy API returning RX process node for control wiring that depends on it */
	return &rdma_rx_node;
}

RTE_NODE_REGISTER(rdma_rx_node);
RTE_NODE_REGISTER(rdma_pts_node);

struct rte_node_register *
rdma_pts_node_get(void)
{
	return &rdma_pts_node;
}
