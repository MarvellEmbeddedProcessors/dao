/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2023 Marvell.
 */

#include <rte_debug.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_flow.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_hash_crc.h>
#include <rte_malloc.h>

#include <dao_log.h>

#include <ood_node_ctrl.h>

#include "ood_vxlan_encap_priv.h"

struct vxlan_encap_node_main *vxlan_encap_nm;
#define VXLAN_ENCAP_NODE_PRIV1_OFF(ctx) (((struct vxlan_encap_node_ctx *)ctx)->mbuf_priv1_off)

#define PORT_MIN   49152
#define PORT_MAX   65535
#define PORT_RANGE ((PORT_MAX - PORT_MIN) + 1)
#define IP_VHL_DEF (0x40 | 0x05)

static int
tunnel_encapsulation(struct rte_node *node, struct rte_mbuf *m)
{
	struct rte_ether_hdr *phdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
	const int dyn = VXLAN_ENCAP_NODE_PRIV1_OFF(node->ctx);
	struct vxlan_encap_node_tunnel_config *tnl_cfg;
	uint32_t old_len = m->pkt_len, hash;
	struct rte_ipv4_hdr app_ip_hdr[2] = {0};
	uint16_t tnl_cfg_idx;
	uint64_t ol_flags = 0;
	struct rte_ipv4_hdr *ip_tun;

	/*Allocate space for new ethernet, IPv4, UDP and VXLAN headers*/
	struct rte_ether_hdr *pneth = (struct rte_ether_hdr *)rte_pktmbuf_prepend(
		m, sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) +
			   sizeof(struct rte_udp_hdr) + sizeof(struct rte_vxlan_hdr));

	struct rte_ipv4_hdr *ip;
	struct rte_udp_hdr *udp;
	struct rte_vxlan_hdr *vxlan;

	if (!pneth)
		DAO_ERR_GOTO(-EINVAL, exit, "Fail to allocate space for headers");

	ip = (struct rte_ipv4_hdr *)&pneth[1];
	udp = (struct rte_udp_hdr *)&ip[1];
	vxlan = (struct rte_vxlan_hdr *)&udp[1];

	tnl_cfg_idx = node_mbuf_priv1(m, dyn)->tnl_cfg_idx;

	tnl_cfg = &vxlan_encap_nm->tnl_cfg_arr[tnl_cfg_idx];
	if (!tnl_cfg->in_use)
		DAO_ERR_GOTO(-EINVAL, exit, "Tunnel config index %d not in use", tnl_cfg_idx);

	dao_dbg("	tnl_cfg_idx %d vxlan %d", tnl_cfg_idx, tnl_cfg->vxlan.vni[2]);

	tnl_cfg->eth.ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

	ip_tun = &app_ip_hdr[0];
	ip_tun->version_ihl = IP_VHL_DEF;
	ip_tun->type_of_service = 0;
	ip_tun->total_length = 0;
	ip_tun->packet_id = 0;
	ip_tun->fragment_offset = 0x0040;
	ip_tun->time_to_live = 64;
	ip_tun->next_proto_id = IPPROTO_UDP;
	ip_tun->hdr_checksum = 0;
	ip_tun->src_addr = tnl_cfg->ipv4.src_addr;
	ip_tun->dst_addr = tnl_cfg->ipv4.dst_addr;

	/* replace original Ethernet header with ours */
	pneth = rte_memcpy(pneth, &tnl_cfg->eth, sizeof(struct rte_ether_hdr));

	/* copy in IP header */
	ip = rte_memcpy(ip, &app_ip_hdr[0], sizeof(struct rte_ipv4_hdr));
	ip->total_length = rte_cpu_to_be_16(m->pkt_len - sizeof(struct rte_ether_hdr));

	/* outer IP checksum */
	//	ol_flags |= RTE_MBUF_F_TX_OUTER_IP_CKSUM;

	ip->hdr_checksum = rte_ipv4_cksum(ip);

	m->outer_l2_len = sizeof(struct rte_ether_hdr);
	m->outer_l3_len = sizeof(struct rte_ipv4_hdr);

	ol_flags |= RTE_MBUF_F_TX_TUNNEL_VXLAN;

	m->ol_flags |= ol_flags;
	// m->tso_segsz = tx_offload.tso_segsz;
	m->tso_segsz = 0;

	/*VXLAN HEADER*/
	vxlan->vx_flags = rte_cpu_to_be_32(0x08000000);
	vxlan->vx_vni = tnl_cfg->vxlan.vx_vni;

	/*UDP HEADER*/
	udp->dgram_len = rte_cpu_to_be_16(old_len + sizeof(struct rte_udp_hdr) +
					  sizeof(struct rte_vxlan_hdr));

	udp->dst_port = tnl_cfg->udp.dst_port;
	//	udp->dgram_cksum = rte_ipv4_phdr_cksum(ip, ol_flags);

	hash = rte_hash_crc(phdr, 2 * RTE_ETHER_ADDR_LEN, phdr->ether_type);
	udp->src_port = rte_cpu_to_be_16((((uint64_t)hash * PORT_RANGE) >> 32) + PORT_MIN);

	return 0;
exit:
	return errno;
}

static uint16_t
vxlan_encap_node_process(struct rte_graph *graph, struct rte_node *node, void **objs,
			 uint16_t nb_objs)
{
	rte_edge_t next, next_index;
	void **to_next, **from;
	uint16_t last_spec = 0;
	struct rte_mbuf *mbuf;
	uint16_t held = 0;
	int i;

	/* Next flow mapper node */
	from = objs;
	next_index = VXLAN_ENCAP_NEXT_FLOW_MAPPER;
	/* Get stream for the speculated next node */
	to_next = rte_node_next_stream_get(graph, node, next_index, nb_objs);
	for (i = 0; i < nb_objs; i++) {
		mbuf = objs[i];
		if (tunnel_encapsulation(node, mbuf))
			next = VXLAN_ENCAP_NEXT_PKT_DROP;
		else
			next = VXLAN_ENCAP_NEXT_FLOW_MAPPER;
		/* Get the mark id from the packet */
		dao_dbg("	Worker %d Packet %d source port %d  new dest %d, total pkts %d",
			rte_lcore_id(), i, mbuf->port, next, nb_objs);
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

static int
vxlan_encap_node_init(const struct rte_graph *graph, struct rte_node *node)
{
	RTE_SET_USED(graph);
	static bool init_once;

	if (!init_once) {
		node_mbuf_priv1_dynfield_queue =
			rte_mbuf_dynfield_register(&node_mbuf_priv1_dynfield_desc);
		if (node_mbuf_priv1_dynfield_queue < 0)
			return -rte_errno;

		if (vxlan_encap_nm == NULL) {
			vxlan_encap_nm =
				rte_zmalloc("vxlan_encap", sizeof(struct vxlan_encap_node_main),
					    RTE_CACHE_LINE_SIZE);
			if (vxlan_encap_nm == NULL)
				return -ENOMEM;
		}

		vxlan_encap_nm->tnl_cfg_bmp =
			ood_node_config_index_map_setup(VXLAN_ENCAP_TNL_CFG_MAX_IDX);
		if (!vxlan_encap_nm->tnl_cfg_bmp)
			DAO_ERR_GOTO(-EFAULT, fail, "Failed to setup tunnel index config");

		vxlan_encap_nm->tnl_cfg_arr = rte_zmalloc(
			"Tnl cfg arr",
			VXLAN_ENCAP_TNL_CFG_MAX_IDX * sizeof(struct vxlan_encap_node_tunnel_config),
			RTE_CACHE_LINE_SIZE);
		init_once = 1;
	}

	VXLAN_ENCAP_NODE_PRIV1_OFF(node->ctx) = node_mbuf_priv1_dynfield_queue;
	dao_dbg("node_mbuf_priv1_dynfield_queue %d", node_mbuf_priv1_dynfield_queue);

	return 0;
fail:
	return errno;
}

int
vxlan_encap_node_tunnel_config_setup(struct vxlan_encap_node_tunnel_config *tnl_cfg)
{
	int tnl_cfg_idx;

	if (!tnl_cfg)
		DAO_ERR_GOTO(-EINVAL, fail, "Received empty encap action cfg");

	tnl_cfg_idx = ood_node_config_index_alloc(vxlan_encap_nm->tnl_cfg_bmp);
	if (tnl_cfg_idx <= 0)
		DAO_ERR_GOTO(errno, fail, "Invalid tnl index received %d", tnl_cfg_idx);

	dao_dbg("Tunnel cfg index %d allocated for VxLAN vni %x", tnl_cfg_idx,
		tnl_cfg->vxlan.vni[2]);
	rte_memcpy(&vxlan_encap_nm->tnl_cfg_arr[tnl_cfg_idx], tnl_cfg,
		   sizeof(struct vxlan_encap_node_tunnel_config));
	vxlan_encap_nm->tnl_cfg_arr[tnl_cfg_idx].in_use = true;

	return tnl_cfg_idx;
fail:
	return errno;
}

int
vxlan_encap_node_tunnel_config_index_free(uint16_t tnl_cfg_idx)
{
	int rc;

	if (!vxlan_encap_nm->tnl_cfg_arr[tnl_cfg_idx].in_use) {
		rc = -EINVAL;
		DAO_ERR_GOTO(rc, exit, "Tunnel config index %d not in use", tnl_cfg_idx);
	}

	dao_dbg("Releasing tunnel config index %d, VxLAN vni %x", tnl_cfg_idx,
		vxlan_encap_nm->tnl_cfg_arr[tnl_cfg_idx].vxlan.vni[2]);
	memset(&vxlan_encap_nm->tnl_cfg_arr[tnl_cfg_idx], 0,
	       sizeof(struct vxlan_encap_node_tunnel_config));
	rc = ood_node_config_index_free(vxlan_encap_nm->tnl_cfg_bmp, tnl_cfg_idx);

exit:
	return rc;
}

static struct rte_node_register vxlan_encap_node = {
	.process = vxlan_encap_node_process,
	.name = "vxlan_encap",

	.init = vxlan_encap_node_init,

	.nb_edges = VXLAN_ENCAP_NEXT_MAX,
	.next_nodes = {
			[VXLAN_ENCAP_NEXT_PKT_DROP] = "pkt_drop",
			[VXLAN_ENCAP_NEXT_FLOW_MAPPER] = "flow_mapper",
		},
};

struct rte_node_register *
vxlan_encap_node_get(void)
{
	return &vxlan_encap_node;
}

RTE_NODE_REGISTER(vxlan_encap_node);
