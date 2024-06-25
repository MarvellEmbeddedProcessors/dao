/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2023 Marvell.
 */

#include <dao_netlink.h>
#include <dao_dynamic_string.h>

#define XFRM_ESP_PROTO				50
#define DAO_XFRM_DBG				dao_dbg
#define DPDK_AEAD_IV_OFFSET			(sizeof(struct rte_crypto_op) + \
						 sizeof(struct rte_crypto_sym_op))
#define STR(x)					#x

static STAILQ_HEAD(, dao_netlink_xfrm_sa) ipsec_sad_list = STAILQ_HEAD_INITIALIZER(ipsec_sad_list);

void dao_netlink_xfrm_parse_cb(struct nl_object *nl_obj, void *arg);

static int
__netlink_xfrm_parse_sa_add(struct xfrmnl_sa *nlsa, void *arg, bool is_new, struct dao_ds *log_ds)
{
	struct dao_netlink_xfrm_sa_xform aead_xform, cipher_xform, auth_xform;
	struct dao_netlink_xfrm_sa_xform *axf = NULL, *bxf = NULL;
	struct dao_ds crypto_key_ds = DS_EMPTY_INITIALIZER;
	struct dao_ds crypto_alg_ds = DS_EMPTY_INITIALIZER;
	struct dao_netlink_xfrm_sa *sa = NULL;
	struct xfrmnl_sel *sel = NULL;
	struct nl_addr *nladdr = NULL;
	uint32_t req_id;
	int retval = -1;

	RTE_SET_USED(arg);

	req_id = xfrmnl_sa_get_reqid(nlsa);
	dao_ds_put_format(log_ds, "%s: %u ", "Reqid", req_id);

	if (is_new) {
		sa = malloc(sizeof(*sa));
		if (!sa)
			return retval;

		memset(sa, 0, sizeof(*sa));
		sa->req_id = req_id;
		sa->refcnt = 0;

		/* SPI, replay window, SA flags */
		sa->spi = xfrmnl_sa_get_spi(nlsa);
		dao_ds_put_format(log_ds, "SPI: %u(0x%x), ", sa->spi, sa->spi);

		/* SA IPs */
		nladdr = xfrmnl_sa_get_daddr(nlsa);
		dao_netlink_nl_addr_to_ip_addr(&sa->in6_dst, xfrmnl_sa_get_daddr(nlsa));
		if (AF_INET == nl_addr_get_family(nladdr)) {
			dao_ds_put_format(log_ds, "daddr: %u:%u:%u:%u/%u, ",
					  sa->in6_dst.addr.s6_addr[12],
					  sa->in6_dst.addr.s6_addr[13],
					  sa->in6_dst.addr.s6_addr[14],
					  sa->in6_dst.addr.s6_addr[15],
					  sa->in6_dst.prefixlen);
		}
		dao_netlink_nl_addr_to_ip_addr(&sa->in6_src, xfrmnl_sa_get_saddr(nlsa));
		nladdr = xfrmnl_sa_get_saddr(nlsa);
		if (AF_INET == nl_addr_get_family(nladdr))
			dao_ds_put_format(log_ds, "saddr: %u:%u:%u:%u/%u, ",
					  sa->in6_src.addr.s6_addr[12],
					  sa->in6_src.addr.s6_addr[13],
					  sa->in6_src.addr.s6_addr[14],
					  sa->in6_src.addr.s6_addr[15],
					  sa->in6_src.prefixlen);

		sa->replay_window = xfrmnl_sa_get_replay_window(nlsa);
		if (sa->replay_window) {
			dao_ds_put_format(log_ds, "AR: %u, ", sa->replay_window);
			sa->sa_flags |= DAO_NETLINK_XFRM_SA_FLAG_USE_AR;
		}

		if (xfrmnl_sa_get_flags(nlsa) & XFRM_STATE_ESN) {
			dao_ds_put_format(log_ds, "%s", "esn, ");
			sa->sa_flags |= DAO_NETLINK_XFRM_SA_FLAG_USE_ESN;
		}

		if (XFRM_ESP_PROTO == xfrmnl_sa_get_proto(nlsa)) {
			sa->ipsec_proto = DAO_NETLINK_XFRM_PROTO_ESP;
			dao_ds_put_format(log_ds, "%s", "esp, ");
		} else {
			sa->ipsec_proto = DAO_NETLINK_XFRM_PROTO_AH;
			dao_ds_put_format(log_ds, "%s", "ah, ");
		}

		if (AF_INET == xfrmnl_sa_get_family(nlsa)) {
			sa->ip_tunnel_type = DAO_NETLINK_XFRM_TUNNEL_IPV4;
			dao_ds_put_format(log_ds, "%s", "ip4, ");
		} else {
			sa->ip_tunnel_type = DAO_NETLINK_XFRM_TUNNEL_IPV6;
			dao_ds_put_format(log_ds, "%s", "ip6, ");
		}

		if (XFRM_MODE_TRANSPORT == xfrmnl_sa_get_mode(nlsa)) {
			sa->sa_mode = DAO_NETLINK_XFRM_MODE_TRANSPORT;
			dao_ds_put_format(log_ds, "%s", "transport, ");
		} else {
			sa->sa_mode = DAO_NETLINK_XFRM_MODE_TUNNEL;
			dao_ds_put_format(log_ds, "%s", "tunnel, ");
		}

		sel = xfrmnl_sa_get_sel(nlsa);
		if (sel) {
			sa->is_sel = 1;
			dao_ds_put_cstr(log_ds, "[Sel: ");
			dao_netlink_nl_addr_to_ip_addr(&sa->sel.saddr, xfrmnl_sel_get_saddr(sel));
			if (AF_INET == sa->sel.saddr.family)
				dao_ds_put_format(log_ds, "%u:%u:%u:%u/%u -> ",
						  sa->sel.saddr.addr.s6_addr[12],
						  sa->sel.saddr.addr.s6_addr[13],
						  sa->sel.saddr.addr.s6_addr[14],
						  sa->sel.saddr.addr.s6_addr[15],
						  sa->sel.saddr.prefixlen);

			dao_netlink_nl_addr_to_ip_addr(&sa->sel.daddr, xfrmnl_sel_get_daddr(sel));
			if (AF_INET == sa->sel.daddr.family)
				dao_ds_put_format(log_ds, "%u:%u:%u:%u/%u, ",
						  sa->sel.daddr.addr.s6_addr[12],
						  sa->sel.daddr.addr.s6_addr[13],
						  sa->sel.daddr.addr.s6_addr[14],
						  sa->sel.daddr.addr.s6_addr[15],
						  sa->sel.daddr.prefixlen);
			sa->sel.dport = xfrmnl_sel_get_dport(sel);
			sa->sel.sport = xfrmnl_sel_get_sport(sel);
			sa->sel.dport_mask = xfrmnl_sel_get_dportmask(sel);
			sa->sel.sport_mask = xfrmnl_sel_get_sportmask(sel);
			sa->sel.family = xfrmnl_sel_get_family(sel);
			sa->sel.prefixlen_d = xfrmnl_sel_get_prefixlen_d(sel);
				sa->sel.prefixlen_s = xfrmnl_sel_get_prefixlen_s(sel);
			sa->sel.proto = xfrmnl_sel_get_proto(sel);
			sa->sel.ifindex = xfrmnl_sel_get_ifindex(sel);
			sa->sel.user = xfrmnl_sel_get_userid(sel);
			dao_ds_put_format(log_ds, "dport: %u, sport: %u, dportmask: 0x%x, "
					  "sportmask: 0x%x, family: %u, proto: %u, ifindex: %u",
					  sa->sel.dport, sa->sel.sport,
					  sa->sel.dport_mask,
					  sa->sel.sport_mask, sa->sel.family,
					  sa->sel.proto, sa->sel.ifindex);
			dao_ds_put_cstr(log_ds, "], ");
		}

		/* aead/crypto/auth algorithms */
		sa->is_aead = !(xfrmnl_sa_get_aead_params(nlsa, aead_xform.algo,
							  &aead_xform.key_len, &aead_xform.icv_len,
							  aead_xform.key));

		sa->is_cipher = !(xfrmnl_sa_get_crypto_params(nlsa, cipher_xform.algo,
							      &cipher_xform.key_len,
							      cipher_xform.key));
		if (sa->is_aead) {
			axf = &aead_xform;
#define _(alg, kbi, kby, iv, dig, aad, xfrm, pretty)						\
				else if ((!strncmp(axf->algo, xfrm, strlen(xfrm))) &&		\
					(axf->key_len == (kbi))) {				\
					sa->aead_key.algo  = DAO_CRYPTO_##alg##_##kbi;		\
					sa->aead_key.key_len  = axf->key_len;			\
					sa->aead_key.icv_len  = axf->icv_len;			\
					memcpy(sa->aead_key.key, axf->key, axf->key_len / 8);	\
					dao_ds_put_cstr(&crypto_alg_ds,				\
							STR(DAO_CRYPTO_##alg##_##kbi));		\
				}
			if (0)
				;
			dao_netlink_foreach_crypto_cipher_aead_algorithm
#undef _
			dao_ds_put_hex(&crypto_key_ds, sa->aead_key.key, strlen(sa->aead_key.key));
			dao_ds_put_format(log_ds, "(%d)%s, keylen: %u, icvlen: %u, %s, ",
					  sa->aead_key.algo,
					  dao_ds_cstr(&crypto_alg_ds),
					  sa->aead_key.key_len,
					  sa->aead_key.icv_len,
					  dao_ds_cstr(&crypto_key_ds));

			dao_ds_init(&crypto_key_ds);
			dao_ds_init(&crypto_alg_ds);
		} else {
			axf = &cipher_xform;
#define _(alg, kbi, kby, iv, blk, xfrm, pretty)							\
				else if ((!strncmp(axf->algo, xfrm, strlen(xfrm))) &&		\
					(axf->key_len == (kbi))) {				\
					sa->cipher_key.algo = DAO_CRYPTO_##alg##_##kbi;		\
					sa->cipher_key.key_len = axf->key_len;			\
					sa->cipher_key.icv_len = 0;				\
					memcpy(sa->cipher_key.key, axf->key, axf->key_len / 8);	\
					dao_ds_put_cstr(&crypto_alg_ds,				\
							STR(DAO_CRYPTO_##alg##_##kbi));		\
				}
			if (0)
				;
			dao_netlink_foreach_crypto_cipher_algorithm
#undef _
			dao_ds_put_hex(&crypto_key_ds, sa->cipher_key.key,
				       strlen(sa->cipher_key.key));

			dao_ds_put_format(log_ds, "(%d)%s, keylen: %u, %s, ",
					  sa->cipher_key.algo,
					  dao_ds_cstr(&crypto_alg_ds),
					  sa->cipher_key.key_len,
					  dao_ds_cstr(&crypto_key_ds));

			dao_ds_init(&crypto_key_ds);
			dao_ds_init(&crypto_alg_ds);
		}

		sa->is_auth = !(xfrmnl_sa_get_auth_params(nlsa, auth_xform.algo,
							  &auth_xform.key_len,
							  &auth_xform.trunc_len,
							  auth_xform.key));

		if (sa->is_auth) {
			bxf = &auth_xform;
#define _(alg, kbi, iv, dig, xfrm, pretty)							\
				else if ((!strncmp(bxf->algo, xfrm, strlen(xfrm))) &&		\
					 (bxf->trunc_len == (kbi))) {				\
					sa->auth_key.algo = DAO_CRYPTO_##alg##_##kbi;		\
					sa->auth_key.key_len = bxf->key_len;			\
					sa->auth_key.trunc_len = bxf->trunc_len;		\
					memcpy(sa->auth_key.key, bxf->key, bxf->key_len / 8);	\
					dao_ds_put_cstr(&crypto_alg_ds,				\
							STR(DAO_CRYPTO_##alg##_##kbi));		\
				}
			if (0)
				;
			dao_netlink_foreach_crypto_auth_hmac_alg
#undef _
			dao_ds_put_hex(&crypto_key_ds, sa->auth_key.key, strlen(sa->auth_key.key));

			dao_ds_put_format(log_ds, "(%d)%s, keylen: %u, trunclen: %u, %s, ",
					  sa->auth_key.algo,
					  dao_ds_cstr(&crypto_alg_ds),
					  sa->auth_key.key_len,
					  sa->auth_key.trunc_len,
					  dao_ds_cstr(&crypto_key_ds));
		}

		dao_ds_destroy(&crypto_key_ds);
		dao_ds_destroy(&crypto_alg_ds);

		STAILQ_INSERT_TAIL(&ipsec_sad_list, sa, next_sa);

		dao_ds_put_format(log_ds, "SA added to list");
		retval = 0;
	}
	return retval;
}

static int
netlink_xfrm_parse_sa_add(struct xfrmnl_sa *nlsa, void *arg, bool is_new, struct dao_ds *log_ds)
{
	struct dao_netlink_xfrm_sa *sa = NULL;
	uint32_t req_id;

	if (is_new) {
		return __netlink_xfrm_parse_sa_add(nlsa, arg, 1, log_ds);
	} else {
		req_id = xfrmnl_sa_get_reqid(nlsa);
		STAILQ_FOREACH(sa, &ipsec_sad_list, next_sa) {
			if (sa->req_id == req_id) {
				dao_ds_put_format(log_ds, "Saved spi: %u found for req_id: %u",
						  sa->spi, sa->req_id);
				break;
			}
		}
	}
	return 0;
}

static struct dao_netlink_xfrm_sa *
ipsec_sad_search_reqid(uint32_t req_id, struct in6_addr *dst, struct in6_addr *src,
		       struct dao_ds *ds)
{
	struct dao_netlink_xfrm_sa *retsa = NULL;
	struct dao_netlink_xfrm_sa *sa = NULL;

	STAILQ_FOREACH(sa, &ipsec_sad_list, next_sa) {
		if (sa->req_id != req_id)
			continue;

		if (!IN6_ARE_ADDR_EQUAL(&sa->in6_src.addr, src))
			continue;

		if (!IN6_ARE_ADDR_EQUAL(&sa->in6_dst.addr, dst))
			continue;

		dao_ds_put_format(ds, "[Matched SA, SPI: %u]", sa->spi, req_id);
		retsa = sa;
		break;
	}
	return retsa;
}

static int netlink_xfrm_parse_policy_add(struct xfrmnl_sp *nlsp, void *arg,
					 int is_new, struct dao_ds *log_ds)
{
	dao_netlink_xfrm_callback_ops_t *cb_ops = NULL;
	struct dao_netlink_xfrm_policy *sp, policy;
	struct xfrmnl_user_tmpl *user_tmpl;
	dao_netlink_ip_addr_t in6_src, in6_dst;
	struct nl_addr *nl_src, *nl_dst;
	struct dao_netlink_xfrm_sa *sa;
	struct xfrmnl_sel *sel = NULL;
	int n_user_tmpl, dir;
	uint32_t reqid;

	/* Fill policy on stack */
	sp = &policy;
	memset(sp, 0, sizeof(struct dao_netlink_xfrm_policy));

	cb_ops = dao_netlink_notifier_callback_ops_get(arg);

	n_user_tmpl = xfrmnl_sp_get_nusertemplates(nlsp);
	if (!n_user_tmpl) {
		dao_err("Received 0th xfrm user template");
		return -1;
	}
	/* Get use template */
	user_tmpl = xfrmnl_sp_usertemplate_n(nlsp, n_user_tmpl - 1);

	/* Extract Reqid */
	reqid = xfrmnl_user_tmpl_get_reqid(user_tmpl);
	dao_ds_put_format(log_ds, "Reqid: %u ", reqid);

	dir = xfrmnl_sp_get_dir(nlsp);

	switch (dir) {
	case XFRM_POLICY_OUT:
		dao_ds_put_format(log_ds, "Outbound, ");
		sp->policy_dir = DAO_NETLINK_XFRM_POLICY_DIR_OUT;
	break;

	case XFRM_POLICY_IN:
		dao_ds_put_format(log_ds, "Inbound, ");
		sp->policy_dir = DAO_NETLINK_XFRM_POLICY_DIR_IN;
	break;

	case XFRM_POLICY_FWD:
		dao_ds_put_format(log_ds, "Forward, ");
		sp->policy_dir = DAO_NETLINK_XFRM_POLICY_DIR_FWD;
	break;
	default:
		sp->policy_dir = -1;
	return -1;
	}

	/* Extract srcaddr and dstaddr */
	nl_src = xfrmnl_user_tmpl_get_saddr(user_tmpl);
	dao_netlink_nl_addr_to_ip_addr(&in6_src, nl_src);

	dao_ds_put_format(log_ds, "%u:%u:%u:%u/%u -> ",
			  in6_src.addr.s6_addr[12], in6_src.addr.s6_addr[13],
			  in6_src.addr.s6_addr[14], in6_src.addr.s6_addr[15],
			  in6_src.prefixlen);

	nl_dst = xfrmnl_user_tmpl_get_daddr(user_tmpl);
	dao_netlink_nl_addr_to_ip_addr(&in6_dst, nl_dst);
	dao_ds_put_format(log_ds, "%u:%u:%u:%u/%u ",
			  in6_dst.addr.s6_addr[12], in6_dst.addr.s6_addr[13],
			  in6_dst.addr.s6_addr[14], in6_dst.addr.s6_addr[15],
			  in6_dst.prefixlen);

	/* Check if reqid is valid */
	sa = ipsec_sad_search_reqid(reqid, &in6_dst.addr, &in6_src.addr, log_ds);
	if (!sa) {
		dao_err("Policy req_id: %u does not match", reqid);
		return -1;
	}

	sp->req_id = reqid;
	sp->ips_sa = sa;
	sp->is_new = is_new;
	memcpy(&sp->src_ip, &in6_src, sizeof(sp->src_ip));
	memcpy(&sp->dst_ip, &in6_dst, sizeof(sp->dst_ip));
	sel = xfrmnl_sp_get_sel(nlsp);
	if (sel) {
		dao_ds_put_cstr(log_ds, "[Sel:");
		sp->is_sel = 1;

		dao_netlink_nl_addr_to_ip_addr(&sp->sel.saddr, xfrmnl_sel_get_saddr(sel));
		dao_ds_put_format(log_ds, "%u:%u:%u:%u/%u -> ",
				  sp->sel.saddr.addr.s6_addr[12],
				  sp->sel.saddr.addr.s6_addr[13],
				  sp->sel.saddr.addr.s6_addr[14],
				  sp->sel.saddr.addr.s6_addr[15],
				  sp->sel.saddr.prefixlen);

		dao_netlink_nl_addr_to_ip_addr(&sp->sel.daddr, xfrmnl_sel_get_daddr(sel));
		dao_ds_put_format(log_ds, "%u:%u:%u:%u/%u, ",
				  sp->sel.daddr.addr.s6_addr[12],
				  sp->sel.daddr.addr.s6_addr[13],
				  sp->sel.daddr.addr.s6_addr[14],
				  sp->sel.daddr.addr.s6_addr[15],
				  sp->sel.daddr.prefixlen);

		sp->sel.dport = xfrmnl_sel_get_dport(sel);
		sp->sel.sport = xfrmnl_sel_get_sport(sel);
		sp->sel.dport_mask = xfrmnl_sel_get_dportmask(sel);
		sp->sel.sport_mask = xfrmnl_sel_get_sportmask(sel);
		sp->sel.family = xfrmnl_sel_get_family(sel);
		sp->sel.prefixlen_d = xfrmnl_sel_get_prefixlen_d(sel);
		sp->sel.prefixlen_s = xfrmnl_sel_get_prefixlen_s(sel);
		sp->sel.proto = xfrmnl_sel_get_proto(sel);
		sp->sel.ifindex = xfrmnl_sel_get_ifindex(sel);
		sp->sel.user = xfrmnl_sel_get_userid(sel);
		dao_ds_put_format(log_ds, "dport: %u, sport: %u, dportmask:"
				  "0x%x, sportmask: 0x%x, family: %u, proto: %u, ifindex: %u",
				  sp->sel.dport, sp->sel.sport,
				  sp->sel.dport_mask, sp->sel.sport_mask,
				  sp->sel.family, sp->sel.proto,
				  sp->sel.ifindex);
		dao_ds_put_cstr(log_ds, "] ");
	}
	DAO_XFRM_DBG("%s", dao_ds_cstr(log_ds));
	dao_ds_clear(log_ds);

	/* Call notifiers */
	if (cb_ops && cb_ops->xfrm_policy_create) {
		if (is_new)
			cb_ops->xfrm_policy_create(sp, sa, DAO_NETLINK_XFRM_OP_POLICY_ADD,
						   dao_netlink_notifier_app_cookie_get(arg));
		else
			cb_ops->xfrm_policy_create(sp, sa, DAO_NETLINK_XFRM_OP_POLICY_UPD,
						   dao_netlink_notifier_app_cookie_get(arg));
	}
	return 0;
}

void
dao_netlink_xfrm_parse_cb(struct nl_object *nl_obj, void *arg)
{
	struct dao_ds log_ds = DS_EMPTY_INITIALIZER;
	int rc = -1;

	switch (nl_object_get_msgtype(nl_obj)) {
	case XFRM_MSG_NEWSA:
		dao_ds_put_cstr(&log_ds, "XFRM_MSG_NEWSA: ");
		rc = netlink_xfrm_parse_sa_add((struct xfrmnl_sa *)nl_obj, arg, 1, &log_ds);
	break;
	case XFRM_MSG_UPDSA:
		dao_ds_put_cstr(&log_ds, "XFRM_MSG_UPDSA: ");
		rc = netlink_xfrm_parse_sa_add((struct xfrmnl_sa *)nl_obj, arg, 1, &log_ds);
	break;

	case XFRM_MSG_DELSA:
		dao_ds_put_format(&log_ds, "%s", "Received XFRM MSG DELSA");
		rc = 0;
	break;

	case XFRM_MSG_UPDPOLICY:
		dao_ds_put_format(&log_ds, "%s", "XFRM_MSG_UPDPOLICY, ");
		rc = netlink_xfrm_parse_policy_add((struct xfrmnl_sp *)nl_obj, arg, 0, &log_ds);
	break;

	case XFRM_MSG_NEWPOLICY:
		dao_ds_put_format(&log_ds, "%s", "XFRM_MSG_NEWPOLICY, ");
		rc = netlink_xfrm_parse_policy_add((struct xfrmnl_sp *)nl_obj, arg, 1, &log_ds);
	break;

	case XFRM_MSG_DELPOLICY:
		dao_ds_put_format(&log_ds, "%s", "Received XFRM MSG DELPOLICY");
		rc = 0;
	break;

	default:
		dao_ds_put_format(&log_ds, "%s: %d", "Received invalid xfrm notification",
				  nl_object_get_msgtype(nl_obj));
	}
	if (rc)
		dao_err("Failure rc: %d, %s", rc, dao_ds_cstr(&log_ds));
	else
		if (log_ds.length)
			DAO_XFRM_DBG("%s", dao_ds_cstr(&log_ds));

	dao_ds_destroy(&log_ds);
}

int
dao_netlink_xfrm_sa_to_crypto_xform(struct dao_netlink_xfrm_sa *sa,
				    dao_netlink_xfrm_policy_dir_t dir,
				    struct rte_crypto_sym_xform *cipher,
				    struct rte_crypto_sym_xform *auth)
{
	struct dao_ds cipher_xform_ds = DS_EMPTY_INITIALIZER;
	struct dao_ds auth_xform_ds = DS_EMPTY_INITIALIZER;

	memset(cipher, 0, sizeof(struct rte_crypto_sym_xform));
	memset(auth, 0, sizeof(struct rte_crypto_sym_xform));

	if (sa->is_aead) {
#define _(alg, kbi, kby, _iv, dig, aad, xfrm, pretty)					\
		else if (sa->aead_key.algo == DAO_CRYPTO_##alg##_##kbi) {		\
			cipher->aead.algo = RTE_CRYPTO_##alg;				\
			cipher->aead.key.data = (const uint8_t *)sa->aead_key.key;	\
			cipher->aead.key.length = sa->aead_key.key_len / 8;		\
			cipher->aead.iv.length = _iv;					\
			cipher->aead.aad_length = aad;					\
			cipher->aead.digest_length = dig;				\
			cipher->aead.op = (dir == DAO_NETLINK_XFRM_POLICY_DIR_IN)	\
					 ? RTE_CRYPTO_AEAD_OP_DECRYPT			\
					 : RTE_CRYPTO_AEAD_OP_ENCRYPT;			\
			dao_ds_put_cstr(&cipher_xform_ds, "Algo: ");			\
			dao_ds_put_cstr(&cipher_xform_ds, STR(RTE_CRYPTO_##alg));	\
			dao_ds_put_cstr(&cipher_xform_ds, ", key: ");			\
			dao_ds_put_hex(&cipher_xform_ds,				\
				(const void *)cipher->aead.key.data,			\
				cipher->aead.key.length);				\
		}
		if (0)
			;
		dao_netlink_foreach_crypto_cipher_aead_algorithm
#undef _
		cipher->type = RTE_CRYPTO_SYM_XFORM_AEAD;
		cipher->aead.iv.offset = DPDK_AEAD_IV_OFFSET;
		cipher->next = NULL;
	} else if (sa->is_cipher) {
#define _(alg, kbi, kby, _iv, blk, xfrm, pretty)					\
		else if (sa->cipher_key.algo == DAO_CRYPTO_##alg##_##kbi) {		\
			cipher->cipher.algo = RTE_CRYPTO_##alg;				\
			cipher->cipher.key.data = (const uint8_t *)sa->cipher_key.key;	\
			cipher->cipher.key.length = sa->cipher_key.key_len / 8;		\
			cipher->cipher.iv.length = _iv;					\
			cipher->cipher.op = (dir == DAO_NETLINK_XFRM_POLICY_DIR_IN)	\
					   ?  RTE_CRYPTO_CIPHER_OP_DECRYPT		\
					   :  RTE_CRYPTO_CIPHER_OP_ENCRYPT;		\
			dao_ds_put_cstr(&cipher_xform_ds, "Algo: ");			\
			dao_ds_put_cstr(&cipher_xform_ds, STR(RTE_CRYPTO_##alg));	\
			dao_ds_put_cstr(&cipher_xform_ds, ", key: ");			\
			dao_ds_put_hex(&cipher_xform_ds,				\
				(const void *)cipher->cipher.key.data,			\
				cipher->cipher.key.length);				\
		}
		if (0)
			;
		dao_netlink_foreach_crypto_cipher_algorithm
#undef _
		cipher->type = RTE_CRYPTO_SYM_XFORM_CIPHER;
		cipher->next = NULL;
		cipher->cipher.iv.offset = DPDK_AEAD_IV_OFFSET;
	}
	if (sa->is_auth) {
#define _(alg, kbi, _iv, dig, xfrm, pretty)						\
		else if (sa->auth_key.algo == DAO_CRYPTO_##alg##_##kbi) {		\
			auth->auth.algo = RTE_CRYPTO_##alg;				\
			auth->auth.key.data = (const uint8_t *)sa->auth_key.key;	\
			auth->auth.key.length = sa->auth_key.key_len / 8;		\
			auth->auth.iv.length = _iv;					\
			auth->auth.digest_length = dig;					\
			auth->auth.op = (dir == DAO_NETLINK_XFRM_POLICY_DIR_IN)		\
					? RTE_CRYPTO_AUTH_OP_VERIFY			\
					: RTE_CRYPTO_AUTH_OP_GENERATE;			\
			dao_ds_put_cstr(&auth_xform_ds, "Algo: ");			\
			dao_ds_put_cstr(&auth_xform_ds, STR(RTE_CRYPTO_##alg));		\
			dao_ds_put_cstr(&auth_xform_ds, ", key: ");			\
			dao_ds_put_hex(&auth_xform_ds,					\
					(const void *)auth->auth.key.data,		\
					auth->auth.key.length);				\
		}
		if (0)
			;
		dao_netlink_foreach_crypto_auth_hmac_alg
#undef _
		auth->type = RTE_CRYPTO_SYM_XFORM_AUTH;
		auth->next = NULL;
		auth->auth.iv.offset = DPDK_AEAD_IV_OFFSET;
		if (sa->is_cipher)
			cipher->next = auth;
	}
	if (sa->is_aead) {
		DAO_XFRM_DBG("%s, key_len: %u, iv_len: %u, dig_len: %u, op: %d,aad: %u, ",
			     dao_ds_cstr(&cipher_xform_ds),
			     cipher->aead.key.length, cipher->aead.iv.length,
			     cipher->aead.digest_length, cipher->aead.op,
			     cipher->aead.aad_length);
	} else {
		DAO_XFRM_DBG("%s, key_len: %u, iv_len: %u, op: %s, cipher: %p->next: %p",
			     dao_ds_cstr(&cipher_xform_ds),
			     cipher->cipher.key.length,
			     cipher->cipher.iv.length,
			     ((RTE_CRYPTO_CIPHER_OP_DECRYPT == cipher->cipher.op)
			      ? "decrypt_op" : "encrypt_op"), cipher,
			     cipher->next);
	}

	if (sa->is_auth)
		DAO_XFRM_DBG("%s, key_len: %u, iv_len: %u, dig_len: %u, op: %s, auth: %p->next = %p",
			     dao_ds_cstr(&auth_xform_ds),
			     auth->auth.key.length, auth->auth.iv.length,
			     auth->auth.digest_length,
			     ((RTE_CRYPTO_AUTH_OP_VERIFY == auth->auth.op)
			     ? "verify_op" : "generate_op"), auth,
			     auth->next);

	dao_ds_destroy(&cipher_xform_ds);
	dao_ds_destroy(&auth_xform_ds);
	return 0;
}

int
dao_netlink_xfrm_notifier_register(dao_netlink_xfrm_callback_ops_t *ops, void *app_cookie)
{
	return (dao_netlink_register(NETLINK_XFRM, dao_netlink_xfrm_parse_cb,
				     (void *)ops, app_cookie, XFRMGRP_EXPIRE,
				     XFRMGRP_SA, XFRMGRP_POLICY, 0));
}
