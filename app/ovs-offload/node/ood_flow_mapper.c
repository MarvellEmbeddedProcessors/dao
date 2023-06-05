/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2023 Marvell.
 */

#include <arpa/inet.h>
#include <sys/socket.h>

#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_malloc.h>

#include <rte_graph.h>
#include <rte_graph_worker.h>

#include <dao_log.h>
#include <ood_node_ctrl.h>

#include "ood_flow_mapper_priv.h"

#define FLOW_MAPPER_NODE_PRIV1_OFF(ctx) (((struct flow_mapper_node_ctx *)ctx)->mbuf_priv1_off)

struct flow_mapper_node_main *flow_mapper_nm;

static uint16_t
vxlan_encap_forwarding(struct rte_node *node, struct rte_mbuf *mbuf, uint16_t mark_id)
{
	uint16_t next = 0, tnl_cfg_idx, act_cfg_idx;
	ood_node_action_config_t *act_cfg;

	act_cfg_idx = mark_id >> OOD_MARK_ID_SHIFT;
	act_cfg = ood_node_action_config_get(act_cfg_idx);
	if (!act_cfg || act_cfg->tnl_cfg_idx <= 0) {
		if (!act_cfg)
			dao_err("Dropping packet, act cfg is NULL");
		else
			dao_err("Dropping packet with invalid act cfg %p or tnl cfg idx %d",
				act_cfg, act_cfg->tnl_cfg_idx);
		next = FLOW_MAPPER_NEXT_PKT_DROP;
		goto exit;
	}
	tnl_cfg_idx = act_cfg->tnl_cfg_idx;
	dao_dbg("	Worker %d VXLAN ENCAP: mbuf->port %d, next %d, mark_id %x,"
		" act_cfg_idx %d tnl_cfg_idx %d",
		rte_lcore_id(), mbuf->port, next, mark_id, act_cfg_idx, tnl_cfg_idx);

	node_mbuf_priv1(mbuf, FLOW_MAPPER_NODE_PRIV1_OFF(node->ctx))->tnl_cfg_idx = tnl_cfg_idx;
	/* Update markid for return path */
	mbuf->hash.fdir.hi = NRML_FWD_MARK_ID;
	next = VXLAN_ENCAP_NEXT_PKT;

exit:
	return next;
}

static uint16_t
host_to_host_forwarding(uint16_t mark_id)
{
	uint16_t hst_cfg_idx, act_cfg_idx, dport = 0, next = 0;
	ood_node_action_config_t *act_cfg;

	act_cfg_idx = mark_id >> OOD_MARK_ID_SHIFT;
	act_cfg = ood_node_action_config_get(act_cfg_idx);
	if (!act_cfg || act_cfg->hst_cfg_idx <= 0) {
		if (!act_cfg)
			dao_err("Dropping packet, act cfg is NULL");
		else
			dao_err("Dropping packet with invalid act cfg %p or portid cfg idx %d",
				act_cfg, act_cfg->hst_cfg_idx);
		next = FLOW_MAPPER_NEXT_PKT_DROP;
		goto exit;
	}
	hst_cfg_idx = act_cfg->hst_cfg_idx;
	if (!flow_mapper_nm->host_to_host_fwd_tbl[hst_cfg_idx].in_use) {
		dao_err("Host config index %d not in use, dropping the packet", hst_cfg_idx);
		next = FLOW_MAPPER_NEXT_PKT_DROP;
		goto exit;
	}
	dport = flow_mapper_nm->host_to_host_fwd_tbl[hst_cfg_idx].dst_host_port;
	next = flow_mapper_nm->eth_tx_edge[dport];
	dao_dbg("	Worker %d HTH_FWD_MARK_ID: tbl idx %d src %d dport %d next %d",
		rte_lcore_id(), hst_cfg_idx,
		flow_mapper_nm->host_to_host_fwd_tbl[hst_cfg_idx].src_host_port, dport, next);

exit:
	return next;
}

static __rte_always_inline uint16_t
determine_next_hop(struct rte_node *node, struct rte_mbuf *mbuf, uint16_t mark_id)
{
	uint16_t next = 0, dport = 0, tnl_type;

	if (unlikely(flow_mapper_nm->repr_portid == mbuf->port)) {
		const int dyn = FLOW_MAPPER_NODE_PRIV1_OFF(node->ctx);

		/* Packet received from repr port, read the private data to know the
		 * queue which corresponds to index to host port packet
		 * should be diverted.
		 */

		dport = flow_mapper_nm->host_port_tbl[node_mbuf_priv1(mbuf, dyn)->nh];
		next = flow_mapper_nm->eth_tx_edge[dport];
		dao_dbg("	Worker %d Received on rep port %ld, forwarding to %d edge %d",
			rte_lcore_id(), node_mbuf_priv1(mbuf, dyn)->nh, dport, next);

		return next;
	}

	switch (mark_id & 0x3f) {
	case DEFAULT_MARK_ID:
		/* Case where packet is received from host port and to be
		 * diverted to corresponding repr tx node
		 */
		next = flow_mapper_nm->repr_tx_edge[mbuf->port];
		dao_dbg("	Worker %d DEFAULT_MARK_ID: mbuf->port %d next %d", rte_lcore_id(),
			mbuf->port, next);
		break;
	case NRML_FWD_MARK_ID:
		/* Case where packet received from host/mac port and to be sent
		 * to mac/host port respectively
		 */
		dport = flow_mapper_nm->nrml_fwd_tbl[mbuf->port];
		next = flow_mapper_nm->eth_tx_edge[dport];
		dao_dbg("	Worker %d NRML_FWD_MARK_ID: mbuf->port %d dport %d next %d",
			rte_lcore_id(), mbuf->port, dport, next);
		break;
	case HOST_TO_HOST_FWD_MARK_ID:
		next = host_to_host_forwarding(mark_id);
		break;
	case VXLAN_ENCAP_MARK_ID:
		next = vxlan_encap_forwarding(node, mbuf, mark_id);
		break;
	case TUNNEL_DECAP_MARK_ID:
		tnl_type = mark_id >> OOD_MARK_ID_SHIFT;
		dao_dbg("	Worker %d TUNNEL DECAP: mbuf->port %d, next %d, mark_id %x, tnl_type %x",
			rte_lcore_id(), mbuf->port, next, mark_id, tnl_type);

		node_mbuf_priv1(mbuf, FLOW_MAPPER_NODE_PRIV1_OFF(node->ctx))->tnl_type = tnl_type;
		/* Update markid for return path */
		mbuf->hash.fdir.hi = NRML_FWD_MARK_ID;
		next = TUNNEL_DECAP_NEXT_PKT;
		break;
	default:
		/* Packet mark ID unidentified, packet should be dropped */
		dao_dbg("	Worker %d Default case: mbuf->port %d dport %d next %d",
			rte_lcore_id(), mbuf->port, dport, next);
		next = FLOW_MAPPER_NEXT_PKT_DROP;
		break;
	};

	return next;
}

static __rte_always_inline uint16_t
get_markid(struct rte_mbuf *mbuf)
{
	int markid = 0;

	dao_dbg("Mbuf olflags %lx", mbuf->ol_flags);
	if (mbuf->ol_flags & RTE_MBUF_F_RX_FDIR_ID) {
		if (mbuf->ol_flags & RTE_MBUF_F_RX_FDIR_ID) {
			dao_dbg("ID=0x%x", mbuf->hash.fdir.hi);
			markid = mbuf->hash.fdir.hi;
		} else {
			if (mbuf->ol_flags & RTE_MBUF_F_RX_FDIR_FLX)
				dao_dbg("flex bytes=0x%08x %08x", mbuf->hash.fdir.hi,
					mbuf->hash.fdir.lo);
			else
				dao_dbg("hash=0x%x ID=0x%x", mbuf->hash.fdir.hash,
					mbuf->hash.fdir.id);
		}
	}

	return markid;
}

static uint16_t
flow_mapper_node_process(struct rte_graph *graph, struct rte_node *node, void **objs,
			 uint16_t nb_objs)
{
	uint16_t last_spec = 0, markid;
	rte_edge_t next_index, next;
	uint16_t held = 0, dport;
	void **to_next, **from;
	struct rte_mbuf **pkts;
	struct rte_mbuf *mbuf;
	int i;

	/* Drop node */
	from = objs;
	pkts = (struct rte_mbuf **)objs;
	/* Speculative next */
	dport = flow_mapper_nm->nrml_fwd_tbl[pkts[0]->port];
	next_index = flow_mapper_nm->eth_tx_edge[dport];
	dao_dbg("Source port %d next index dest port %d", pkts[0]->port, next_index);

	/* Get stream for the speculated next node */
	to_next = rte_node_next_stream_get(graph, node, next_index, nb_objs);
	from = objs;
	for (i = 0; i < nb_objs; i++) {
		mbuf = objs[i];
		/* Get the mark id from the packet */
		markid = get_markid(mbuf);
		next = determine_next_hop(node, mbuf, markid);
		dao_dbg("	Worker %d Packet %d markid %d source port %d  new dest %d, total pkts %d",
			rte_lcore_id(), i, markid, mbuf->port, next, nb_objs);
		if (unlikely(next_index != next)) {
			/* Copy things successfully speculated till now */
			rte_memcpy(to_next, from, last_spec * sizeof(from[0]));
			from += last_spec;
			to_next += last_spec;
			held += last_spec;
			last_spec = 0;

			rte_node_enqueue_x1(graph, node, next, from[0]);
			from += 1;
		} else {
			last_spec += 1;
		}
	}

	/* !!! Home run !!! */
	if (likely(last_spec == nb_objs)) {
		rte_node_next_stream_move(graph, node, next_index);
		return nb_objs;
	}
	held += last_spec;
	rte_memcpy(to_next, from, last_spec * sizeof(from[0]));
	rte_node_next_stream_put(graph, node, next_index, held);

	return nb_objs;
}

int
flow_mapper_setup_host_to_host_fwd_table(struct flow_mapper_host_to_host_fwd_cfg *hst_cfg)
{
	int hst_cfg_idx;

	if (!hst_cfg)
		DAO_ERR_GOTO(-EINVAL, fail, "Received empty host to host cfg");

	hst_cfg_idx = ood_node_config_index_alloc(flow_mapper_nm->hst_cfg_bmp);
	if (hst_cfg_idx <= 0)
		DAO_ERR_GOTO(errno, fail, "Invalid tnl index received %d", hst_cfg_idx);

	dao_dbg("Host to Host fwd index %d src port %d dst port %d", hst_cfg_idx,
		hst_cfg->src_host_port, hst_cfg->dst_host_port);
	rte_memcpy(&flow_mapper_nm->host_to_host_fwd_tbl[hst_cfg_idx], hst_cfg,
		   sizeof(struct flow_mapper_host_to_host_fwd_cfg));
	flow_mapper_nm->host_to_host_fwd_tbl[hst_cfg_idx].in_use = true;

	return hst_cfg_idx;
fail:
	return errno;
}

int
flow_mapper_host_to_host_fwd_tbl_index_free(uint16_t hst_cfg_idx)
{
	int rc;

	if (!flow_mapper_nm->host_to_host_fwd_tbl[hst_cfg_idx].in_use) {
		rc = -EINVAL;
		DAO_ERR_GOTO(rc, exit, "HTH config index %d not in use", hst_cfg_idx);
	}

	dao_dbg("Releasing HTH index %d, src port %d dst port %d", hst_cfg_idx,
		flow_mapper_nm->host_to_host_fwd_tbl[hst_cfg_idx].src_host_port,
		flow_mapper_nm->host_to_host_fwd_tbl[hst_cfg_idx].dst_host_port);
	memset(&flow_mapper_nm->host_to_host_fwd_tbl[hst_cfg_idx], 0,
	       sizeof(struct flow_mapper_host_to_host_fwd_cfg));
	rc = ood_node_config_index_free(flow_mapper_nm->hst_cfg_bmp, hst_cfg_idx);

exit:
	return rc;
}

int
flow_mapper_setup_nrml_fwd_table(uint16_t *port_arr, uint16_t nb_ports)
{
	int i;

	if (!port_arr)
		DAO_ERR_GOTO(-EINVAL, fail, "Empty forwarding table input");

	if (!nb_ports)
		DAO_ERR_GOTO(-EINVAL, fail, "No of ports cant be zero");

	if (flow_mapper_nm == NULL) {
		flow_mapper_nm = rte_zmalloc("flow_mapper", sizeof(struct flow_mapper_node_main),
					     RTE_CACHE_LINE_SIZE);
		if (flow_mapper_nm == NULL)
			return -ENOMEM;
	}

	for (i = 0; i < nb_ports; i++) {
		flow_mapper_nm->nrml_fwd_tbl[i] = port_arr[i];

		dao_dbg("mac_port_idx %d host port idx %d", i, flow_mapper_nm->nrml_fwd_tbl[i]);
	}
	return 0;
fail:
	return errno;
}

/* Setting up the next edge for the eth tx node . */
int
flow_mapper_set_eth_tx_edge_idx(uint16_t port_id, uint16_t next_index)
{
	if (flow_mapper_nm == NULL) {
		flow_mapper_nm = rte_zmalloc("flow_mapper", sizeof(struct flow_mapper_node_main),
					     RTE_CACHE_LINE_SIZE);
		if (flow_mapper_nm == NULL)
			return -ENOMEM;
	}

	flow_mapper_nm->eth_tx_edge[port_id] = next_index;
	dao_dbg("port_idx %d eth_tx_edge %d", port_id, next_index);

	return 0;
}

/* Determine mapping between representor port to host mapping. A representor
 * port is represented by a repr queue.
 */
int
flow_mapper_set_repr_tx_edge_idx(uint16_t queue_id, uint16_t next_index)
{
	uint16_t host_port_idx;

	if (flow_mapper_nm == NULL) {
		flow_mapper_nm = rte_zmalloc("flow_mapper", sizeof(struct flow_mapper_node_main),
					     RTE_CACHE_LINE_SIZE);
		if (flow_mapper_nm == NULL)
			return -ENOMEM;
	}

	host_port_idx = flow_mapper_nm->host_port_tbl[queue_id];
	flow_mapper_nm->repr_tx_edge[host_port_idx] = next_index;
	dao_dbg("queue_id %d host_port_idx %d repr_tx_edge %d", queue_id, host_port_idx,
		next_index);

	return 0;
}

int
flow_mapper_set_repr_portid(uint16_t port_id)
{
	if (flow_mapper_nm == NULL) {
		flow_mapper_nm = rte_zmalloc("flow_mapper", sizeof(struct flow_mapper_node_main),
					     RTE_CACHE_LINE_SIZE);
		if (flow_mapper_nm == NULL)
			return -ENOMEM;
	}

	flow_mapper_nm->repr_portid = port_id;

	return 0;
}

/* Setting up the host port to representor mapping */
int
flow_mapper_set_host_port_mapping(uint16_t host_port_idx, uint16_t queue_id)
{
	if (flow_mapper_nm == NULL) {
		flow_mapper_nm = rte_zmalloc("flow_mapper", sizeof(struct flow_mapper_node_main),
					     RTE_CACHE_LINE_SIZE);
		if (flow_mapper_nm == NULL)
			return -ENOMEM;
	}
	flow_mapper_nm->host_port_tbl[queue_id] = host_port_idx;
	dao_dbg("queue_id %d host_port_idx %d ", queue_id, host_port_idx);

	return 0;
}

static int
flow_mapper_node_init(const struct rte_graph *graph, struct rte_node *node)
{
	static bool init_once;

	RTE_SET_USED(graph);

	if (!init_once) {
		node_mbuf_priv1_dynfield_queue =
			rte_mbuf_dynfield_register(&node_mbuf_priv1_dynfield_desc);
		if (node_mbuf_priv1_dynfield_queue < 0)
			return -rte_errno;

		if (flow_mapper_nm == NULL) {
			flow_mapper_nm =
				rte_zmalloc("flow_mapper", sizeof(struct flow_mapper_node_main),
					    RTE_CACHE_LINE_SIZE);
			if (flow_mapper_nm == NULL)
				return -ENOMEM;
		}
		flow_mapper_nm->hst_cfg_bmp =
			ood_node_config_index_map_setup(FLOW_MAPPER_FWD_TBL_MAX_IDX);
		if (!flow_mapper_nm->hst_cfg_bmp)
			DAO_ERR_GOTO(-EFAULT, fail, "Failed to setup tunnel index config");

		flow_mapper_nm->host_to_host_fwd_tbl =
			rte_zmalloc("Host fwd tbl",
				    FLOW_MAPPER_FWD_TBL_MAX_IDX *
					    sizeof(struct flow_mapper_host_to_host_fwd_cfg),
				    RTE_CACHE_LINE_SIZE);
		init_once = 1;
	}

	FLOW_MAPPER_NODE_PRIV1_OFF(node->ctx) = node_mbuf_priv1_dynfield_queue;

	return 0;
fail:
	return errno;
}

static struct rte_node_register flow_mapper_node = {
	.name = "flow_mapper",
	.process = flow_mapper_node_process,
	.init = flow_mapper_node_init,
	.nb_edges = FLOW_MAPPER_NEXT_MAX,
	.next_nodes = {
			[VXLAN_ENCAP_NEXT_PKT] = "vxlan_encap",
			[TUNNEL_DECAP_NEXT_PKT] = "tunnel_decap",
			[FLOW_MAPPER_NEXT_PKT_DROP] = "pkt_drop",
		},
};

struct rte_node_register *
flow_mapper_node_get(void)
{
	return &flow_mapper_node;
}

RTE_NODE_REGISTER(flow_mapper_node);
