/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <nodes/net/ipsec/ipsec.h>
#include <rte_bitops.h>
#include <secgw.h>

#define IPSEC_DBG                dao_dbg
#define CRYPTO_SESSION_POOL_ELEM 4096

/* Global structure */
secgw_ipsec_main_t *secgw_ipsec_main;

#define foreach_l4_proto_configure_acl			\
	_(IPPROTO_TCP, "TCP")				\
	_(IPPROTO_ICMP, "ICMP")				\
	_(IPPROTO_UDP, "UDP")				\

static const char *
policy_to_str(dao_netlink_xfrm_policy_dir_t dir)
{
	switch (dir) {
	case DAO_NETLINK_XFRM_POLICY_DIR_IN:
		return "Inbound";
	break;
	case DAO_NETLINK_XFRM_POLICY_DIR_OUT:
		return "Outound";
	break;
	case DAO_NETLINK_XFRM_POLICY_DIR_FWD:
		return "Forward";
	break;
	}
	return NULL;
}

static void
fill_sa(secgw_ipsec_sa_t *ips_sa, dao_netlink_xfrm_sa_t *xsa, uint32_t sa_index)
{
	memset(ips_sa, 0, sizeof(secgw_ipsec_sa_t));

	ips_sa->sa_index = sa_index;
	ips_sa->xfrm_sa = xsa;

	if (xsa->ipsec_proto == DAO_NETLINK_XFRM_PROTO_ESP)
		ips_sa->sa_flags |= SECGW_IPSEC_SA_F_PROTO_ESP;

	if (xsa->sa_mode & DAO_NETLINK_XFRM_MODE_TUNNEL) {
		ips_sa->sa_flags |= SECGW_IPSEC_SA_F_MODE_TUNNEL;

		if (xsa->ip_tunnel_type == DAO_NETLINK_XFRM_TUNNEL_IPV4) {
			ips_sa->sa_flags |= SECGW_IPSEC_SA_F_TUNNEL_IPV4;
			ips_sa->v4_hdr.version_ihl =
				IPVERSION << 4 |
				((sizeof(struct rte_ipv4_hdr)) / RTE_IPV4_IHL_MULTIPLIER);
			ips_sa->v4_hdr.time_to_live = IPDEFTTL;
			ips_sa->v4_hdr.next_proto_id = IPPROTO_TCP; /* TODO: Hack for acl to work */
			ips_sa->v4_hdr.src_addr = dao_in6_addr_get_mapped_ipv4(&xsa->in6_src.addr);
			ips_sa->v4_hdr.dst_addr = dao_in6_addr_get_mapped_ipv4(&xsa->in6_dst.addr);
			// rte_hexdump(stdout, "sa:v4_hdr", &ips_sa->v4_hdr, sizeof(struct
			// rte_ipv4_hdr));
		} else {
			ips_sa->v6_hdr.vtc_flow = htonl(IPVERSION << 28);
			ips_sa->v6_hdr.proto = IPPROTO_ESP; /* TODO: Add udp, if udp_encap */
			memcpy(&(ips_sa->v6_hdr.src_addr), xsa->in6_src.addr.s6_addr,
			       sizeof(xsa->in6_src.addr));
			memcpy(&(ips_sa->v6_hdr.dst_addr), xsa->in6_dst.addr.s6_addr,
			       sizeof(xsa->in6_dst.addr));
		}
	}
	if (xsa->sa_flags & DAO_NETLINK_XFRM_SA_FLAG_USE_AR)
		ips_sa->sa_flags |= SECGW_IPSEC_SA_F_AR;

	if (xsa->sa_flags & DAO_NETLINK_XFRM_SA_FLAG_USE_ESN)
		ips_sa->sa_flags |= SECGW_IPSEC_SA_F_ESN;
}

static void
fill_libipsec_sa_param(dao_netlink_xfrm_sa_t *xsa, dao_netlink_xfrm_policy_dir_t policy_dir,
		       struct rte_ipv4_hdr *v4, struct rte_ipv6_hdr *v6,
		       struct rte_crypto_sym_xform *cipher, struct rte_ipsec_sa_prm *sa_param)
{
	memset(sa_param, 0, sizeof(struct rte_ipsec_sa_prm));

	if (v4)
		memset(v4, 0, sizeof(*v4));
	if (v6)
		memset(v6, 0, sizeof(*v6));

	sa_param->ipsec_xform.spi = xsa->spi;
	sa_param->ipsec_xform.salt = xsa->salt;
	sa_param->ipsec_xform.direction = (policy_dir & DAO_NETLINK_XFRM_POLICY_DIR_IN) ?
						  RTE_SECURITY_IPSEC_SA_DIR_INGRESS :
						  RTE_SECURITY_IPSEC_SA_DIR_EGRESS;
	sa_param->ipsec_xform.proto = (xsa->ipsec_proto == DAO_NETLINK_XFRM_PROTO_ESP) ?
					      RTE_SECURITY_IPSEC_SA_PROTO_ESP :
					      RTE_SECURITY_IPSEC_SA_PROTO_AH;
	sa_param->ipsec_xform.mode = (xsa->sa_mode & DAO_NETLINK_XFRM_MODE_TUNNEL) ?
					     RTE_SECURITY_IPSEC_SA_MODE_TUNNEL :
					     RTE_SECURITY_IPSEC_SA_MODE_TRANSPORT;
#ifdef TODO
	sa_param->ipsec_xform.options.esn = xsa->sa_flags & DAO_NETLINK_XFRM_SA_FLAG_USE_ESN;
	sa_param->ipsec_xform.esn.value = 0;
	sa_param->ipsec_xform.replay_win_sz =
		((sa->sa_flags & DAO_NETLINK_XFRM_SA_FLAG_USE_AR) ? sa->replay_window : 0);
#endif
	if (xsa->sa_mode & DAO_NETLINK_XFRM_MODE_TUNNEL) {
		if (xsa->ip_tunnel_type & DAO_NETLINK_XFRM_TUNNEL_IPV4) {
			if (v4) {
				v4->version_ihl =
					IPVERSION << 4 | sizeof(*v4) / RTE_IPV4_IHL_MULTIPLIER;
				v4->time_to_live = IPDEFTTL;
				v4->next_proto_id =
					IPPROTO_ESP; /* TODO: UDP protocol if udp_encap*/
				v4->src_addr = dao_in6_addr_get_mapped_ipv4(&xsa->in6_src.addr);
				v4->dst_addr = dao_in6_addr_get_mapped_ipv4(&xsa->in6_dst.addr);
			}
			sa_param->ipsec_xform.tunnel.type = RTE_SECURITY_IPSEC_TUNNEL_IPV4;
			sa_param->tun.hdr_len = sizeof(*v4);
			sa_param->tun.next_proto = IPPROTO_TCP; /* TODO: check*/
			sa_param->tun.hdr = v4;
		} else {
			if (v6) {
				v6->vtc_flow = htonl(IPVERSION << 28); /* TODO: IP6VERSION fails*/
				v6->proto = IPPROTO_ESP; /* TODO: Add udp, if udp_encap */
				memcpy(v6->src_addr, xsa->in6_src.addr.s6_addr,
				       sizeof(xsa->in6_src.addr));
				memcpy(v6->dst_addr, xsa->in6_dst.addr.s6_addr,
				       sizeof(xsa->in6_dst.addr));
			}
			sa_param->ipsec_xform.tunnel.type = RTE_SECURITY_IPSEC_TUNNEL_IPV6;
			sa_param->tun.hdr_len = sizeof(*v4);
			sa_param->tun.next_proto = IPPROTO_IPV6; /* TODOL check*/
			sa_param->tun.hdr = v4;
		}
	} else {
		sa_param->trs.proto = 0; /* TODO: check*/
	}
	sa_param->crypto_xform = cipher;
}

static int
ipsec4_spd_create(const char *spd_name, struct rte_acl_field_def *acl_defs, int num_policies,
		  int socket_id, secgw_ipsec4_policy_t *policy4)
{
	char name[SECGW_IPSEC_NAMELEN];
	struct rte_acl_ctx *ctx = NULL;
	struct rte_acl_param param;
	uint32_t bmap_size;

	if (!acl_defs || !num_policies)
		return -1;

	memset(&param, 0, sizeof(struct rte_acl_param));
	param.name = spd_name;
	param.socket_id = socket_id;
	param.rule_size = RTE_ACL_RULE_SZ(RTE_DIM(secgw_ipsec4_policy_fields_acl));
	param.max_rule_num = num_policies;

	ctx = rte_acl_create(&param);
	if (!ctx) {
		dao_err("rte_acl_create fails for spd: %s", spd_name);
		return -1;
	}
	if (policy4) {
		strncpy(policy4->spd_name, spd_name, SECGW_IPSEC_NAMELEN - 1);
		policy4->max_rules = num_policies;
		policy4->acl_ctx = ctx;
		/* Create bitmap */
		bmap_size = rte_bitmap_get_memory_footprint(num_policies);
		snprintf(name, sizeof(name) - 1, "%s_bmap", spd_name);
		policy4->bitmap_mem =
			rte_zmalloc_socket(name, bmap_size, RTE_CACHE_LINE_SIZE, socket_id);
		if (!policy4->bitmap_mem) {
			dao_err("policy bitmap alloc \"%s\" failed", name);
			rte_acl_free(ctx);
			return -1;
		}
		policy4->bmap =
			rte_bitmap_init_with_all_set(num_policies, policy4->bitmap_mem, bmap_size);
		/* alloc rules */
		snprintf(name, sizeof(name) - 1, "%s_rules", spd_name);
		policy4->rules =
			rte_zmalloc_socket(name, sizeof(secgw_ipsec4_rules_t) * num_policies,
					   RTE_CACHE_LINE_SIZE, socket_id);

		if (!policy4->rules) {
			dao_err("rules alloc \"%s\" fails", name);
			rte_acl_free(ctx);
			rte_free(policy4->bitmap_mem);
			return -1;
		}
	}
	return 0;
}

static int
ipsec4_sad_create(const char *sad_name, int num_sas, int sock_id, dao_netlink_xfrm_sa_t *xsa,
		  dao_netlink_xfrm_policy_dir_t policy_dir, secgw_ipsec_sad_t **ppsad)
{
	struct rte_crypto_sym_xform cipher, auth;
	struct rte_ipsec_sad_conf sa_conf;
	struct rte_ipsec_sa_prm sa_param;
	secgw_ipsec_sad_t *sad = NULL;
	struct rte_ipv4_hdr v4;
	struct rte_ipv6_hdr v6;
	uint32_t sad_size, bmap_size;
	int sa_size;

	dao_netlink_xfrm_sa_to_crypto_xform(xsa, policy_dir, &cipher, &auth);
	fill_libipsec_sa_param(xsa, policy_dir, &v4, &v6, &cipher, &sa_param);

	sa_size = rte_ipsec_sa_size(&sa_param);

	if (sa_size < 0) {
		dao_err("Invalid rte_ipsec_sa_size(): %d", sa_size);
		return sa_size;
	}

	sa_size += sizeof(secgw_ipsec_sa_t);
	sa_size = RTE_ALIGN_CEIL(sa_size, RTE_CACHE_LINE_SIZE);

	sad_size = sizeof(secgw_ipsec_sad_t) + (num_sas * sa_size);
	/* Allocate SAD */
	sad = rte_zmalloc_socket(NULL, sad_size, RTE_CACHE_LINE_SIZE, sock_id);

	if (!sad) {
		dao_err("sad creation for %s failed", sad_name);
		return -1;
	}
	sad->sad_size_in_bytes = sad_size;
	sad->socket_id = sock_id;
	sad->num_sas = num_sas;
	sad->lipsec_sa_size = sa_size;
	strncpy(sad->sad_name, sad_name, SECGW_IPSEC_NAMELEN);
	bmap_size = rte_bitmap_get_memory_footprint(num_sas);
	sad->bitmap_mem = rte_zmalloc_socket(sad_name, bmap_size, RTE_CACHE_LINE_SIZE, sock_id);
	if (!sad->bitmap_mem) {
		dao_err("sad bitmap alloc for %s failed", sad_name);
		rte_free(sad);
		return -1;
	}
	sad->bitmap = rte_bitmap_init_with_all_set(num_sas, sad->bitmap_mem, bmap_size);

	/* local sa_conf */
	sa_conf.socket_id = sock_id;
	sa_conf.flags = 0;
	sa_conf.max_sa[RTE_IPSEC_SAD_SPI_ONLY] = 0;
	sa_conf.max_sa[RTE_IPSEC_SAD_SPI_DIP] = 0;
	sa_conf.max_sa[RTE_IPSEC_SAD_SPI_DIP_SIP] = num_sas;

	sad->lipsec_sad = rte_ipsec_sad_create(sad_name, &sa_conf);

	if (!sad) {
		dao_err("SAD creation failed for : %s", sad_name);
		rte_free(sad);
		return -1;
	}

	IPSEC_DBG("created sad: %s with num_sas %u on socket_id: %d", sad->sad_name, num_sas,
		  sock_id);
	*ppsad = sad;

	return 0;
}

static int
ipsec4_sad_destroy(secgw_ipsec_sad_t *sad)
{
	RTE_SET_USED(sad);
	return 0;
}

static int
ipsec4_policy_add(secgw_ipsec_t *ips, secgw_ipsec4_policy_t *policy4,
		  dao_netlink_ip_addr_t *daddr, dao_netlink_ip_addr_t *saddr,
		  uint32_t sa_index, uint8_t l4_proto, const char *pol_name)
{
	struct rte_acl_config acl_build_param;
	struct rte_ipv4_hdr acl_f, buf_key;
	unsigned int prefixlen_s, prefixlen_d;
	secgw_ipsec4_rules_t *rule = NULL;
	const uint8_t *acl_key[1];
	struct in6_addr *s, *d;
	uint32_t acl_res[1];
	uint64_t slab = 0;
	uint32_t pos = 0;

	RTE_SET_USED(ips);

	memset(&acl_f, 0, sizeof(struct rte_ipv4_hdr));
	memset(&buf_key, 1, sizeof(struct rte_ipv4_hdr));

	if (1) {
		acl_f.next_proto_id = l4_proto; /* Starting from ICMP to all */
		prefixlen_s = saddr->prefixlen;
		prefixlen_d = daddr->prefixlen;

		acl_f.dst_addr = dao_in6_addr_get_mapped_ipv4(&daddr->addr);
		acl_f.src_addr = dao_in6_addr_get_mapped_ipv4(&saddr->addr);

		buf_key.src_addr = acl_f.src_addr;
		buf_key.dst_addr = acl_f.dst_addr;
		buf_key.next_proto_id = l4_proto;
		s = &saddr->addr;
		d = &daddr->addr;
	}
	// rte_hexdump(stdout, "acl_field  : ", &acl_f, sizeof(struct rte_ipv4_hdr));
	// rte_hexdump(stdout, "ipv4_buffer: ", &buf_key, sizeof(struct rte_ipv4_hdr));

	acl_key[0] = (uint8_t *)&buf_key.next_proto_id;
	/* Fill dummy result as 0 is reserved result */
	acl_res[0] = SECGW_IPSEC_POLICY_DISCARD;

	if (policy4->num_rules) {
		if (rte_acl_classify(policy4->acl_ctx, acl_key, acl_res, 1,
				     SECGW_ACL_CLASSIFY_ALGO) < 0) {
			dao_err("%s: acl_classify failed", pol_name);
			return -1;
		}
		/* We always program +1 incremented value */
		acl_res[0] -= 1;
	} else {
		/* First iteration, add the rule first by skipping classify() */
		acl_res[0] = SECGW_IPSEC_POLICY_DISCARD;
	}

	if (SECGW_IPSEC_POLICY_DISCARD == acl_res[0]) {
		dao_dbg("%s: acl_res: %d: No acl match for [%u:%u:%u:%u/%u]->[%u:%u:%u:%u/%u][%u]",
			pol_name, (int32_t)acl_res[0], s->s6_addr[12], s->s6_addr[13],
			s->s6_addr[14], s->s6_addr[15], prefixlen_s,
			d->s6_addr[12], d->s6_addr[13], d->s6_addr[14],
			d->s6_addr[15], prefixlen_d, l4_proto);

		/* TODO: Find free slot in SPD bitmap */
		if (!rte_bitmap_scan(policy4->bmap, &pos, &slab)) {
			dao_err("%s: bitmap of SPD: %s full", pol_name, policy4->spd_name);
			return -1;
		}
		pos = policy4->num_rules;
		rule = policy4->rules + pos;

		rule->data.category_mask = 1; /* Use single category*/
		rule->data.priority = 1;
		rule->data.userdata = sa_index + 1;

		rule->field[PROTO_FIELD_IPV4].value.u8 = acl_f.next_proto_id;
		rule->field[PROTO_FIELD_IPV4].mask_range.u8 = 0xff;
		rule->field[SRC_FIELD_IPV4].value.u32 = htonl(acl_f.src_addr);
		rule->field[SRC_FIELD_IPV4].mask_range.u32 = prefixlen_s;
		rule->field[DST_FIELD_IPV4].value.u32 = htonl(acl_f.dst_addr);
		rule->field[DST_FIELD_IPV4].mask_range.u32 = prefixlen_d;
#ifdef TODO
	union rte_acl_field_types mask_range;
	/**<
	 * depending on field type:
	 * mask -> 1.2.3.4/32 value=0x1020304, mask_range=32,
	 * range -> 0 : 65535 value=0, mask_range=65535,
	 * bitmask -> 0x06/0xff value=6, mask_range=0xff.
	 */

		rte_hexdump(stdout, "field[proto]  : ", &(rule->field[PROTO_FIELD_IPV4].value.u8),
			    sizeof(uint8_t));
		rte_hexdump(stdout, "field[src_ip]  : ", &(rule->field[SRC_FIELD_IPV4].value.u32),
			    sizeof(uint32_t));
		rte_hexdump(stdout, "field[dst_ip]  : ", &(rule->field[DST_FIELD_IPV4].value.u32),
			    sizeof(uint32_t));
#endif
		if (rte_acl_add_rules(policy4->acl_ctx, (const struct rte_acl_rule *)policy4->rules,
				      policy4->num_rules + 1) < 0) {
			dao_err("%s: rte_acl_add_rule() failed", pol_name);
			return -1;
		}

		memset(&acl_build_param, 0, sizeof(acl_build_param));
		acl_build_param.num_categories = 1;
		acl_build_param.num_fields = RTE_DIM(secgw_ipsec4_policy_fields_acl);
		memcpy(&acl_build_param.defs, secgw_ipsec4_policy_fields_acl,
		       sizeof(secgw_ipsec4_policy_fields_acl));

		if (rte_acl_build(policy4->acl_ctx, &acl_build_param) < 0) {
			dao_err("%s: rte_acl_build param failed", pol_name);
			return -1;
		}
		// rte_acl_dump(policy4->acl_ctx);
		rte_bitmap_clear(policy4->bmap, pos);
		policy4->num_rules++;

		secgw_dbg(
			   "%18s(%u) policy, sa_idx: %d "
			   "[%u:%u:%u:%u/%u] -> [%u:%u:%u:%u/%u][%u]", pol_name,
			   pos, (int32_t)sa_index, s->s6_addr[12],
			   s->s6_addr[13], s->s6_addr[14], s->s6_addr[15],
			   prefixlen_s, d->s6_addr[12], d->s6_addr[13],
			   d->s6_addr[14], d->s6_addr[15], prefixlen_d, l4_proto);
	} else {
		dao_err("%18s: ctx %p: acl exists(%d) for [%u:%u:%u:%u/%u] -> [%u:%u:%u:%u/%u][%u]",
			pol_name, policy4->acl_ctx, (int32_t)acl_res[0],
			s->s6_addr[12], s->s6_addr[13], s->s6_addr[14],
			s->s6_addr[15], prefixlen_s, d->s6_addr[12],
			d->s6_addr[13], d->s6_addr[14], d->s6_addr[15],
			prefixlen_d, l4_proto);
	}
	return 0;
}

int
secgw_ipsec_policy_add_del(secgw_ipsec_t *ips, dao_netlink_xfrm_policy_t *policy, int32_t sa_idx,
			   uint16_t port_id, int is_add)
{
	secgw_ipsec_sa_t *ips_sa = NULL;

	RTE_SET_USED(port_id);
	RTE_SET_USED(is_add);
	switch (policy->policy_dir) {
	case DAO_NETLINK_XFRM_POLICY_DIR_OUT:
		if (AF_INET == policy->dst_ip.family) {
			if (sa_idx >= 0)
				ips_sa = secgw_ipsec_sa_get(ips->sadb_v4, sa_idx);

			if (!ips_sa)
				return -1;
			RTE_VERIFY(sa_idx == ips_sa->sa_index);

			if (policy->is_sel) {
#define _(l4, str)		{								\
				/* Outbound Protect */						\
				ipsec4_policy_add(ips, &ips->spds.outbound4, &policy->sel.daddr,\
						  &policy->sel.saddr, sa_idx, l4,		\
					  "Outbound Protect");					\
				}

				foreach_l4_proto_configure_acl
#undef _

#define _(l4, str)		{								\
				/* Outbound Bypass */						\
				ipsec4_policy_add(ips, &ips->spds.outbound4, &policy->dst_ip,	\
						  &policy->src_ip,				\
						  SECGW_IPSEC_POLICY_BYPASS, l4,		\
						  "Outbound Bypass");				\
				}

				foreach_l4_proto_configure_acl
#undef _
			}
		} else {
			return -1;
		}
	break;
	case DAO_NETLINK_XFRM_POLICY_DIR_IN:
#ifdef SECGW_INLINE_IPSEC_DISABLE
		if (AF_INET == policy->dst_ip.family) {
			if (sa_idx >= 0)
				ips_sa = secgw_ipsec_sa_get(ips->sadb_v4, sa_idx);
			if (!ips_sa)
				return -1;
			RTE_VERIFY(sa_idx == ips_sa->sa_index);

			if (ips_sa && (ips_sa->sa_index == sa_idx) && policy->is_sel) {
#define _(l4, str)		{								\
				/* Inbound Bypass */						\
				ipsec4_policy_add(ips, &ips->spds.inbound4,			\
						  &policy->dst_ip, &policy->src_ip,		\
						  sa_idx, l4,					\
						  "Inbound Protect");				\
				}

				foreach_l4_proto_configure_acl
#undef _
			}
		}
#endif
	break;

	case DAO_NETLINK_XFRM_POLICY_DIR_FWD:
		if (policy->is_sel && (AF_INET == policy->sel.saddr.family)) {
#define _(l4, str)	{									\
			/* Inbound Bypass */							\
			ipsec4_policy_add(ips, &ips->spds.outbound4,				\
					  &policy->sel.daddr, &policy->sel.saddr,		\
					  SECGW_IPSEC_POLICY_BYPASS, l4,			\
					  "Outbound Bypass");					\
			}

			foreach_l4_proto_configure_acl
#undef _
		}
	}
	return 0;
}

/* Add xfrm_sa to SAD, create libIPsec SA, create rte_security_session */
int
secgw_ipsec_sad_sa_add_del(secgw_ipsec_t *ips, secgw_ipsec_sad_t *sad, dao_netlink_xfrm_sa_t *xsa,
			   uint16_t port_id, dao_netlink_xfrm_policy_dir_t policy_dir, bool is_add,
			   int32_t *sa_idx)
{
	struct rte_security_session_conf sess_conf;
	struct rte_crypto_sym_xform cipher, auth;
	union rte_ipsec_sad_key sad_key = {{0}};
	const union rte_ipsec_sad_key *pkey[1];
	uint32_t index = 0, ol_flags = 0;
	struct rte_ipsec_sa_prm sa_param;
	secgw_ipsec_sa_t *ips_sa = NULL;
	struct rte_ipv6_hdr v6;
	struct rte_ipv4_hdr v4;
	void *pindex = NULL;
	uint64_t slab = 0;
	int rc = -1;

	if (is_add) {
		if (dao_netlink_xfrm_sa_to_crypto_xform(xsa, policy_dir, &cipher, &auth) < 0) {
			dao_err("xfrm sa to crypto transforms fails");
			return -1;
		}
		if (xsa->ip_tunnel_type & DAO_NETLINK_XFRM_TUNNEL_IPV4) {
			sad_key.v4.spi = xsa->spi;
			sad_key.v4.sip = dao_in6_addr_get_mapped_ipv4(&xsa->in6_src.addr);
			sad_key.v4.dip = dao_in6_addr_get_mapped_ipv4(&xsa->in6_dst.addr);
		} else {
			sad_key.v6.spi = xsa->spi;
			memcpy(sad_key.v6.sip, xsa->in6_src.addr.s6_addr,
			       sizeof(xsa->in6_src.addr));
			memcpy(sad_key.v6.dip, xsa->in6_dst.addr.s6_addr,
			       sizeof(xsa->in6_dst.addr));
		}
		pkey[0] = &sad_key;
		/* Found if sa is already added or not */
		if (rte_ipsec_sad_lookup(sad->lipsec_sad, pkey, &pindex, 1 /* n_sa */) < 0) {
			dao_err("rte_ipsec_sad_lookup for %s failed [spi:%u|IP:\"%u:%u:%u:%u "
				"-> %u:%u:%u:%u\"]",
				sad->sad_name, xsa->spi, xsa->in6_src.addr.s6_addr[12],
				xsa->in6_src.addr.s6_addr[13], xsa->in6_src.addr.s6_addr[14],
				xsa->in6_src.addr.s6_addr[15], xsa->in6_dst.addr.s6_addr[12],
				xsa->in6_dst.addr.s6_addr[13], xsa->in6_dst.addr.s6_addr[14],
				xsa->in6_dst.addr.s6_addr[15]);
			return -1;
		}
		if (pindex) {
			index = ((secgw_ipsec_sa_t *)pindex)->sa_index;
			if (sa_idx)
				*sa_idx = (int32_t)index;
			IPSEC_DBG("SA already exist @ %u rte_ipsec_sad_lookup entry for "
				  "[spi:%u|IP:\"%u:%u:%u:%u -> %u:%u:%u:%u\"]",
				  index, xsa->spi, xsa->in6_src.addr.s6_addr[12],
				  xsa->in6_src.addr.s6_addr[13], xsa->in6_src.addr.s6_addr[14],
				  xsa->in6_src.addr.s6_addr[15], xsa->in6_dst.addr.s6_addr[12],
				  xsa->in6_dst.addr.s6_addr[13], xsa->in6_dst.addr.s6_addr[14],
				  xsa->in6_dst.addr.s6_addr[15]);
			return 0;
		}
		IPSEC_DBG("SA adding [spi:%u|IP:\"%u:%u:%u:%u -> %u:%u:%u:%u\"] "
			  "to %s",
			  xsa->spi, xsa->in6_src.addr.s6_addr[12], xsa->in6_src.addr.s6_addr[13],
			  xsa->in6_src.addr.s6_addr[14], xsa->in6_src.addr.s6_addr[15],
			  xsa->in6_dst.addr.s6_addr[12], xsa->in6_dst.addr.s6_addr[13],
			  xsa->in6_dst.addr.s6_addr[14], xsa->in6_dst.addr.s6_addr[15],
			  sad->sad_name);

		/* Find free slot in SAD bitmap to get SA index */
		if (!rte_bitmap_scan(sad->bitmap, &index, &slab)) {
			dao_err("bitmap of SAD: %s full", sad->sad_name);
			return -1;
		}
		ips_sa = secgw_ipsec_sa_get(sad, index);

		memset(ips_sa, 0, sizeof(secgw_ipsec_sa_t));

		/* Add key to libipsec SAD */
		if (rte_ipsec_sad_add(sad->lipsec_sad, &sad_key, RTE_IPSEC_SAD_SPI_DIP_SIP,
				      (void *)ips_sa)) {
			dao_err("rte_ipsec_sad_add fails for sad:%s"
				"[spi:%u|IP:%u:%u:%u:%u -> %u:%u:%u:%u]",
				sad->sad_name, xsa->spi, xsa->in6_src.addr.s6_addr[12],
				xsa->in6_src.addr.s6_addr[13], xsa->in6_src.addr.s6_addr[14],
				xsa->in6_src.addr.s6_addr[15], xsa->in6_dst.addr.s6_addr[12],
				xsa->in6_dst.addr.s6_addr[13], xsa->in6_dst.addr.s6_addr[14],
				xsa->in6_dst.addr.s6_addr[15]);
			return -1;
		}
		secgw_info("%8s SA added [spi:%u|IP:\"%u:%u:%u:%u -> %u:%u:%u:%u\"] "
			   "to %s @ index: %u", policy_to_str(policy_dir),
			   xsa->spi, xsa->in6_src.addr.s6_addr[12], xsa->in6_src.addr.s6_addr[13],
			   xsa->in6_src.addr.s6_addr[14], xsa->in6_src.addr.s6_addr[15],
			   xsa->in6_dst.addr.s6_addr[12], xsa->in6_dst.addr.s6_addr[13],
			   xsa->in6_dst.addr.s6_addr[14], xsa->in6_dst.addr.s6_addr[15],
			   sad->sad_name, index);

		fill_sa(ips_sa, xsa, index);

		/* Create security session, if not created */
		if (!ips_sa->lipsec_session.security.ses) {
			ol_flags = 0;
			secgw_ipsec_sec_session_conf_fill(&sess_conf, xsa, policy_dir,
							  RTE_SECURITY_ACTION_TYPE_INLINE_PROTOCOL);
			secgw_ipsec_verify_sec_capabilty(
				&sess_conf,
				(struct rte_security_ctx *)rte_eth_dev_get_sec_ctx(port_id),
				&ol_flags);
			sess_conf.crypto_xform = &cipher;
			ips_sa->lipsec_session.type = RTE_SECURITY_ACTION_TYPE_INLINE_PROTOCOL;
			ips_sa->lipsec_session.security.ol_flags = ol_flags;
			ips_sa->lipsec_session.security.ctx = rte_eth_dev_get_sec_ctx(port_id);
			ips_sa->lipsec_session.security.ses = rte_security_session_create(
				rte_eth_dev_get_sec_ctx(port_id), &sess_conf, ips->sess_pool);
			if (!ips_sa->lipsec_session.security.ses) {
				dao_err("session create failed");
				return -1;
			}
			IPSEC_DBG("Security session created with ol_flags: 0x%x, type: 0x%x",
				  ol_flags, ips_sa->lipsec_session.type);

			/* Create libIPsec SA */
			fill_libipsec_sa_param(xsa, policy_dir, &v4, &v6, &cipher, &sa_param);

			/* Assert if allocated ipsec SA is not sufficient for required one */
			RTE_VERIFY(sad->lipsec_sa_size >= rte_ipsec_sa_size(&sa_param));

			rc = rte_ipsec_sa_init((struct rte_ipsec_sa *)ips_sa->lipsec_sa, &sa_param,
					       rte_ipsec_sa_size(&sa_param));
			if (rc < 0) {
				dao_err("rte_ipsec_sa_init failed");
				return rc;
			}
			/* Fill IPsec session with SA*/
			ips_sa->lipsec_session.sa = (struct rte_ipsec_sa *)ips_sa->lipsec_sa;
			rc = rte_ipsec_session_prepare(&ips_sa->lipsec_session);
			if (rc != 0) {
				dao_err("rte_ipsec_session_prepare() failed: rc: %d", rc);
				return rc;
			}
			IPSEC_DBG("LibIPsec session created and initialized");
		}
		/* Mark SA index is used */
		rte_bitmap_clear(sad->bitmap, index);
		sad->num_sas++;
		if (sa_idx)
			*sa_idx = (int32_t)index;
		rc = 0;
	} else {
		/*TODO: Delete not yet supported */
		rc = -1;
	}
	return rc;
}

int
secgw_ipsec_sec_session_conf_fill(struct rte_security_session_conf *sess_conf,
				  dao_netlink_xfrm_sa_t *sa, dao_netlink_xfrm_policy_dir_t dir,
				  enum rte_security_session_action_type action_type)
{
	memset(sess_conf, 0, sizeof(*sess_conf));

	sess_conf->action_type = action_type;
	sess_conf->protocol = RTE_SECURITY_PROTOCOL_IPSEC;
	sess_conf->ipsec.spi = sa->spi;
	sess_conf->ipsec.salt = sa->salt;
	sess_conf->ipsec.replay_win_sz =
		((sa->sa_flags & DAO_NETLINK_XFRM_SA_FLAG_USE_AR) ? sa->replay_window : 0);
	sess_conf->ipsec.direction = (dir == DAO_NETLINK_XFRM_POLICY_DIR_IN) ?
					     RTE_SECURITY_IPSEC_SA_DIR_INGRESS :
					     RTE_SECURITY_IPSEC_SA_DIR_EGRESS;
	sess_conf->ipsec.proto = RTE_SECURITY_IPSEC_SA_PROTO_ESP;
	sess_conf->ipsec.mode = (sa->sa_mode & DAO_NETLINK_XFRM_MODE_TUNNEL) ?
					RTE_SECURITY_IPSEC_SA_MODE_TUNNEL :
					RTE_SECURITY_IPSEC_SA_MODE_TRANSPORT;
	/* Add SA tunnel endpoints */
	if (sa->ip_tunnel_type == DAO_NETLINK_XFRM_TUNNEL_IPV4) {
		assert(AF_INET == sa->in6_src.family);
		assert(AF_INET == sa->in6_dst.family);

		sess_conf->ipsec.tunnel.type = RTE_SECURITY_IPSEC_TUNNEL_IPV4;
		sess_conf->ipsec.tunnel.ipv4.ttl = 64;
		sess_conf->ipsec.tunnel.ipv4.src_ip.s_addr =
			dao_in6_addr_get_mapped_ipv4(&sa->in6_src.addr);
		sess_conf->ipsec.tunnel.ipv4.dst_ip.s_addr =
			dao_in6_addr_get_mapped_ipv4(&sa->in6_dst.addr);

	} else {
		dao_err("IPv6 not yet supported");
		return -1;

		assert(AF_INET6 == sa->in6_src.family);
		assert(AF_INET6 == sa->in6_dst.family);

		sess_conf->ipsec.tunnel.type = RTE_SECURITY_IPSEC_TUNNEL_IPV6;
		sess_conf->ipsec.tunnel.ipv6.hlimit = 64;
		sess_conf->ipsec.tunnel.ipv6.dscp = 0;
		sess_conf->ipsec.tunnel.ipv6.flabel = 0;
		memcpy(sess_conf->ipsec.tunnel.ipv6.src_addr.s6_addr, sa->in6_src.addr.s6_addr,
		       sizeof(sa->in6_src.addr));
		memcpy(sess_conf->ipsec.tunnel.ipv6.dst_addr.s6_addr, sa->in6_dst.addr.s6_addr,
		       sizeof(sa->in6_dst.addr));
	}
	/* Add ESN enable/disable */
	sess_conf->ipsec.options.esn = sa->sa_flags | DAO_NETLINK_XFRM_SA_FLAG_USE_ESN;
	sess_conf->ipsec.esn.value = 0;

	/*TODO: fill udp_encap, ecn, copy_dscp if required */

	return 0;
}

/* verify security capability with ipsec sa */
int
secgw_ipsec_verify_sec_capabilty(struct rte_security_session_conf *sess_conf,
				 struct rte_security_ctx *sec_ctx, uint32_t *out_flags)
{
	const struct rte_security_capability *sec_cap = NULL;
	struct rte_security_capability_idx sec_cap_idx;

	sec_cap_idx.action = sess_conf->action_type;
	sec_cap_idx.protocol = sess_conf->protocol;
	sec_cap_idx.ipsec.proto = sess_conf->ipsec.proto;
	sec_cap_idx.ipsec.mode = sess_conf->ipsec.mode;
	sec_cap_idx.ipsec.direction = sess_conf->ipsec.direction;

	sec_cap = rte_security_capability_get(sec_ctx, &sec_cap_idx);
	if (!sec_cap) {
		dao_err("rte_sec_capa failed");
		return -1;
	}
	if (out_flags)
		*out_flags = sec_cap->ol_flags;

	return 0;
}

static int
ipsec_lookup(const char *ipsec_instance_name, secgw_ipsec_t **_ips)
{
	secgw_ipsec_main_t *sim = secgw_ipsec_main_get();
	secgw_ipsec_t *ips = NULL;
	uint32_t i;

	if (!sim)
		return 0;

	if (!_ips || !ipsec_instance_name)
		return 0;

	for (i = 0; i < sim->num_ipsec_objs; i++) {
		ips = sim->ipsec_objs + i;
		if (!strncmp(ipsec_instance_name, ips->ipsec_name, strlen(ips->ipsec_name))) {
			*_ips = ips;
			return 1;
		}
	}

	return 0;
}

static int
add_default_esp_rule(uint16_t port_id)
{
	struct rte_flow_action action[2];
	struct rte_flow_item pattern[2];
	struct rte_flow_attr attr = {0};
	struct rte_flow_error err;
	struct rte_flow *flow;
	int ret;

	/* Add the default rte_flow to enable SECURITY for all ESP packets */

	pattern[0].type = RTE_FLOW_ITEM_TYPE_ESP;
	pattern[0].spec = NULL;
	pattern[0].mask = NULL;
	pattern[0].last = NULL;
	pattern[1].type = RTE_FLOW_ITEM_TYPE_END;

	action[0].type = RTE_FLOW_ACTION_TYPE_SECURITY;
	action[0].conf = NULL;
	action[1].type = RTE_FLOW_ACTION_TYPE_END;
	action[1].conf = NULL;

	attr.ingress = 1;

	ret = rte_flow_validate(port_id, &attr, pattern, action, &err);
	if (ret)
		return -1;

	flow = rte_flow_create(port_id, &attr, pattern, action, &err);
	if (flow == NULL)
		return -1;

	IPSEC_DBG("Created default flow enabling SECURITY for all ESP traffic on port %d\n",
		  port_id);
	return 0;
}

static int
ipsec_add(const char *ips_name, secgw_ipsec_t *ips, dao_netlink_xfrm_sa_t *xsa, int port_id,
	  struct rte_mempool *pool, dao_netlink_xfrm_policy_dir_t policy_dir, int num_sas,
	  int num_policies)
{
	char name[SECGW_IPSEC_NAMELEN];
	secgw_ipsec_sad_t *sadv4 = NULL;
	secgw_ipsec_main_t *sim = NULL;
	secgw_device_t *sdev = NULL;

	strncpy(ips->ipsec_name, ips_name, SECGW_IPSEC_NAMELEN - 1);

	snprintf(name, sizeof(name) - 1, "%s_sadv4", ips_name);

	if (ipsec4_sad_create(name, num_sas, rte_eth_dev_socket_id(port_id), xsa, policy_dir,
			      &sadv4)) {
		dao_err("ipsec4_sad_create: %s failed", name);
		return -1;
	}

	sim = secgw_ipsec_main_get();

	ips->sadb_v4 = sadv4;
	ips->sess_pool = pool;
	ips->ipsec_index = ips - sim->ipsec_objs;

	IPSEC_DBG("Added ipsec instance: \"%s\" at index: %u", ips_name, ips->ipsec_index);

	snprintf(name, sizeof(name) - 1, "%s_outb_spdv4", ips_name);
	if (ipsec4_spd_create(name, secgw_ipsec4_policy_fields_acl, num_policies,
			      rte_eth_dev_socket_id(port_id), &ips->spds.outbound4)) {
		dao_err("outbound ipsec4_spd_create failed");
		ipsec4_sad_destroy(sadv4);
		return -1;
	}
	snprintf(name, sizeof(name) - 1, "%s_inb_spdv4", ips_name);
	if (ipsec4_spd_create(name, secgw_ipsec4_policy_fields_acl, num_policies,
			      rte_eth_dev_socket_id(port_id), &ips->spds.inbound4)) {
		dao_err("inbound ipsec4_spd_create failed");
		rte_acl_free(ips->spds.outbound4.acl_ctx);
		ipsec4_sad_destroy(sadv4);
		return -1;
	}
	IPSEC_DBG("IPsec spd acl rules created");
	sdev = secgw_get_device(port_id);

	if (sdev->device_flags & SECGW_HW_RX_OFFLOAD_INLINE_IPSEC)
		return (add_default_esp_rule(port_id));
	return 0;
}

static int
create_ipsec_session_pool(const char *mp_name, struct rte_mempool **_mp, uint32_t nb_elem,
			  size_t elem_sz, int socket_id)
{
	struct rte_mempool *mempool = NULL;

	mempool = rte_cryptodev_sym_session_pool_create(mp_name, nb_elem, elem_sz,
							64 /* cache
					       size */, 0  /* user-data
							    */
							,
							socket_id);
	if (!mempool) {
		dao_err("Failure creating mempool: %s", mp_name);
		return -1;
	}
	IPSEC_DBG("%s mempool created with elements: %u of size: %lu", mp_name, nb_elem, elem_sz);

	if (_mp)
		*_mp = mempool;

	return 0;
}

/* Attach ipsec instance to device */
int
secgw_ipsec_attach(const char *ipsec_instance_name, dao_netlink_xfrm_sa_t *xsa,
		   dao_netlink_xfrm_policy_dir_t policy_dir, int secgw_port_id, int num_sas,
		   int num_policies, uint32_t *ipsec_index)
{
	char mempool_name[RTE_MEMPOOL_NAMESIZE];
	char local_name[RTE_MEMPOOL_NAMESIZE];
	struct rte_mempool *pool = NULL;
	secgw_ipsec_main_t *sim = NULL;
	secgw_device_t *sdev = NULL;
	secgw_ipsec_t *ips = NULL;
	void *ptr = NULL;
	int socket_id;

	socket_id = rte_eth_dev_socket_id(secgw_port_id);
	if (SOCKET_ID_ANY == socket_id)
		socket_id = 0;

	if (!ipsec_instance_name)
		return -1;

	sim = secgw_ipsec_main_get();
	if (!sim) {
		secgw_ipsec_main = malloc(sizeof(secgw_ipsec_main_t));

		if (!secgw_ipsec_main)
			DAO_ERR_GOTO(-ENOMEM, attach_fail, "secgw_ipsec_main alloc failed");

		memset(secgw_ipsec_main, 0, sizeof(secgw_ipsec_main_t));
		sim = secgw_ipsec_main_get();
		IPSEC_DBG("created ipsec main");
	}
	/* Create session mempool for socket_id */
	if (!(sim->socket_bitmask & RTE_BIT32((uint32_t)socket_id))) {
		ptr = realloc((void *)sim->crypto_sess_pool_by_socket,
			      (rte_popcount32(sim->socket_bitmask) + 1) *
				      sizeof(sim->crypto_sess_pool_by_socket[0]));

		if (!ptr)
			DAO_ERR_GOTO(-ENOMEM, realloc_fail, "sess pool memory alloc failed");

		sim->crypto_sess_pool_by_socket = (struct rte_mempool **)ptr;
		sdev = secgw_get_device(secgw_port_id);

		if (sdev->device_flags &
		    (SECGW_HW_RX_OFFLOAD_INLINE_IPSEC | SECGW_HW_TX_OFFLOAD_INLINE_IPSEC)) {
			memset(mempool_name, 0, RTE_MEMPOOL_NAMESIZE - 1);

			snprintf(mempool_name, RTE_MEMPOOL_NAMESIZE, "sess_pool_%u", socket_id);
			if (create_ipsec_session_pool(
				    mempool_name, sim->crypto_sess_pool_by_socket + socket_id,
				    CRYPTO_SESSION_POOL_ELEM,
				    rte_security_session_get_size(
					    rte_eth_dev_get_sec_ctx(secgw_port_id)),
				    socket_id))
				DAO_ERR_GOTO(-ENOMEM, pool_fail,
					     "ipsec session pool create failure");
		} else {
			DAO_ERR_GOTO(-EINVAL, pool_fail, "%s does not support inline device",
				     sdev->dev_name);
		}
		sim->socket_bitmask |= RTE_BIT32((uint32_t)socket_id);
	}
	pool = sim->crypto_sess_pool_by_socket[socket_id];

	snprintf(local_name, RTE_MEMPOOL_NAMESIZE, "%s_%d", ipsec_instance_name, socket_id);
	/* If not created, create IPsec instance */
	if (!ipsec_lookup(local_name, &ips)) {
		ptr = NULL;
		ptr = realloc((void *)sim->ipsec_objs,
			      (sim->num_ipsec_objs + 1) * sizeof(sim->ipsec_objs[0]));
		if (!ptr)
			DAO_ERR_GOTO(-ENOMEM, realloc_fail, "ipsec_objs realloc failed");

		sim->ipsec_objs = (secgw_ipsec_t *)ptr;
		ips = sim->ipsec_objs + sim->num_ipsec_objs;

		memset(ips, 0, sizeof(secgw_ipsec_t));

		if (ipsec_add(local_name, ips, xsa, secgw_port_id, pool, policy_dir, num_sas,
			      num_policies))
			dao_err("ipsec_add for %s failed %u", local_name, secgw_port_id);

		sim->num_ipsec_objs++;

		IPSEC_DBG("instance \"%s\" added for device: %u", local_name, secgw_port_id);
	}
	IPSEC_DBG("ipsec_obj: %s for device: %u at index: %u", local_name, secgw_port_id,
		  ips->ipsec_index);
	*ipsec_index = ips->ipsec_index;

	return 0;

pool_fail:
realloc_fail:
attach_fail:
	return -1;
}
