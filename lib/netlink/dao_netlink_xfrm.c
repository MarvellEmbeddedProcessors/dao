/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2023 Marvell.
 */

#include <dao_netlink.h>
#include <dao_dynamic_string.h>

#define XFRM_ESP_PROTO				50
#define DAO_XFRM_DBG dao_info
#define DPDK_AEAD_IV_OFFSET			(sizeof(struct rte_crypto_op) + \
						 sizeof(struct rte_crypto_sym_op))
#define STR(x)					#x

static STAILQ_HEAD(, dao_netlink_xfrm_sa) ipsec_sad_list = STAILQ_HEAD_INITIALIZER(ipsec_sad_list);

void dao_netlink_xfrm_parse_cb(struct nl_object *nl_obj, void *arg);

static int
netlink_xfrm_parse_sa_add(struct xfrmnl_sa *nlsa, void *arg, bool is_new)
{
	struct dao_netlink_xfrm_sa_xform aead_xform, cipher_xform, auth_xform;
	struct dao_netlink_xfrm_sa_xform *axf = NULL, *bxf = NULL;
	struct dao_ds crypto_key_ds = DS_EMPTY_INITIALIZER;
	struct dao_ds crypto_alg_ds = DS_EMPTY_INITIALIZER;
	struct dao_netlink_xfrm_sa *sa = NULL;
	uint32_t req_id;
	int retval = -1;

	RTE_SET_USED(arg);

	req_id = xfrmnl_sa_get_reqid(nlsa);
	DAO_XFRM_DBG("Reqid: %u ", req_id);

	if (is_new) {
		sa = malloc(sizeof(*sa));
		if (!sa)
			return retval;

		memset(sa, 0, sizeof(*sa));
		sa->req_id = req_id;
		sa->refcnt = 0;
		/* SA IPs */
		dao_netlink_nl_addr_to_in6(&sa->in6_src, xfrmnl_sa_get_saddr(nlsa));
		dao_netlink_nl_addr_to_in6(&sa->in6_dst, xfrmnl_sa_get_daddr(nlsa));
		/* SPI, replay window, SA flags */
		sa->spi = xfrmnl_sa_get_spi(nlsa);
		sa->replay_window = xfrmnl_sa_get_replay_window(nlsa);

		sa->sa_flags |= (sa->replay_window)
				? DAO_NETLINK_XFRM_SA_FLAG_USE_AR
				: 0;

		sa->sa_flags |= (xfrmnl_sa_get_flags(nlsa) & XFRM_STATE_ESN)
					? DAO_NETLINK_XFRM_SA_FLAG_USE_ESN
					: 0;

		sa->ipsec_proto = (XFRM_ESP_PROTO == xfrmnl_sa_get_proto(nlsa))
					? DAO_NETLINK_XFRM_PROTO_ESP
					: DAO_NETLINK_XFRM_PROTO_AH;

		sa->ip_tunnel_type = (xfrmnl_sa_get_family(nlsa) == AF_INET)
						? DAO_NETLINK_XFRM_TUNNEL_IPV4
						: DAO_NETLINK_XFRM_TUNNEL_IPV6;

		sa->sa_mode = (XFRM_MODE_TRANSPORT == xfrmnl_sa_get_mode(nlsa))
						? DAO_NETLINK_XFRM_MODE_TRANSPORT
						: DAO_NETLINK_XFRM_MODE_TUNNEL;

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
					strncpy(sa->aead_key.key, axf->key,			\
						strlen(sa->aead_key.key));			\
					dao_ds_put_cstr(&crypto_alg_ds,				\
							STR(DAO_CRYPTO_##alg##_##kbi));		\
				}
			if (0)
				;
			dao_netlink_foreach_crypto_cipher_aead_algorithm
#undef _
			dao_ds_put_hex(&crypto_key_ds, sa->aead_key.key, strlen(sa->aead_key.key));
			DAO_XFRM_DBG("(%d)%s, keylen: %u, icvlen: %u, %s", sa->aead_key.algo,
				     dao_ds_cstr(&crypto_alg_ds), sa->aead_key.key_len,
				     sa->aead_key.icv_len, dao_ds_cstr(&crypto_key_ds));

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
					strncpy(sa->cipher_key.key, axf->key,			\
						strlen(sa->cipher_key.key));			\
					dao_ds_put_cstr(&crypto_alg_ds,				\
							STR(DAO_CRYPTO_##alg##_##kbi));		\
				}
			if (0)
				;
			dao_netlink_foreach_crypto_cipher_algorithm
#undef _
			dao_ds_put_hex(&crypto_key_ds, sa->cipher_key.key,
				       strlen(sa->cipher_key.key));

			DAO_XFRM_DBG("(%d)%s, keylen: %u, %s",
				     sa->cipher_key.algo, dao_ds_cstr(&crypto_alg_ds),
				     sa->cipher_key.key_len, dao_ds_cstr(&crypto_key_ds));

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
					 (bxf->key_len == (kbi))) {				\
					sa->auth_key.algo = DAO_CRYPTO_##alg;			\
					sa->auth_key.key_len = bxf->key_len;			\
					sa->auth_key.trunc_len = bxf->trunc_len;		\
					strncpy(sa->auth_key.key, bxf->key,			\
						strlen(sa->auth_key.key));			\
					dao_ds_put_cstr(&crypto_alg_ds,				\
							STR(DAO_CRYPTO_##alg##_##kbi));		\
				}
			if (0)
				;
			dao_netlink_foreach_crypto_auth_hmac_alg
#undef _
			dao_ds_put_hex(&crypto_key_ds, sa->auth_key.key, strlen(sa->auth_key.key));

			DAO_XFRM_DBG("(%d)%s, keylen: %u, trunclen: %u, %s",
				     sa->auth_key.algo, dao_ds_cstr(&crypto_alg_ds),
				     sa->auth_key.key_len, sa->auth_key.trunc_len,
				     dao_ds_cstr(&crypto_key_ds));
		}

		dao_ds_destroy(&crypto_key_ds);
		dao_ds_destroy(&crypto_alg_ds);

		STAILQ_INSERT_TAIL(&ipsec_sad_list, sa, next_sa);

		DAO_XFRM_DBG("Added spi; %u, reqid: %u", sa->spi, sa->req_id);
		retval = 0;
	} else {
		STAILQ_FOREACH(sa, &ipsec_sad_list, next_sa) {
			if (sa->req_id == req_id) {
				DAO_XFRM_DBG("Updated saved spi: %u for req_id: %u",
					     sa->spi, sa->req_id);
				retval = 0;
				break;
			}
		}
	}
	return retval;
}

static struct dao_netlink_xfrm_sa *ipsec_sad_search_reqid(uint32_t req_id)
{
	struct dao_netlink_xfrm_sa *retsa = NULL;
	struct dao_netlink_xfrm_sa *sa = NULL;

	STAILQ_FOREACH(sa, &ipsec_sad_list, next_sa) {
		if (sa->req_id == req_id) {
			DAO_XFRM_DBG("Found sa: %p for reqid: %u", sa, req_id);
			retsa = sa;
			break;
		}
	}
	return retsa;
}

static int netlink_xfrm_parse_policy_add(struct xfrmnl_sp *nlsp, void *arg, int is_new)
{
	dao_netlink_xfrm_callback_ops_t *cb_ops = NULL;
	struct xfrmnl_user_tmpl *user_tmpl;
	struct in6_addr in6_src, in6_dst;
	struct dao_netlink_xfrm_policy *sp, policy;
	struct nl_addr *nl_src, *nl_dst;
	struct dao_netlink_xfrm_sa *sa;
	int n_user_tmpl, dir;
	uint32_t reqid;

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
	DAO_XFRM_DBG("Received Policy Reqid: %u ", reqid);

	/* Extract srcaddr and dstaddr */
	nl_src = xfrmnl_user_tmpl_get_saddr(user_tmpl);
	dao_netlink_nl_addr_to_in6(&in6_src, nl_src);

	DAO_XFRM_DBG("SrcIP: %u:%u:%u:%u", in6_src.s6_addr[12], in6_src.s6_addr[13],
		     in6_src.s6_addr[14], in6_src.s6_addr[15]);

	nl_dst = xfrmnl_user_tmpl_get_daddr(user_tmpl);
	dao_netlink_nl_addr_to_in6(&in6_dst, nl_dst);
	DAO_XFRM_DBG("DstIP: %u:%u:%u:%u", in6_dst.s6_addr[12], in6_dst.s6_addr[13],
		     in6_dst.s6_addr[14], in6_dst.s6_addr[15]);

	/* Check if reqid is valid */
	sa = ipsec_sad_search_reqid(reqid);
	if (!sa) {
		dao_err("Policy req_id: %u does not match", reqid);
		return -1;
	}
	DAO_XFRM_DBG("Found sa: %p, spi: %u for policy req_id: %u", sa, sa->spi, sa->req_id);

	/* Fill policy on stack */
	sp = &policy;

	memset(sp, 0, sizeof(struct dao_netlink_xfrm_policy));
	sp->req_id = reqid;
	sp->ips_sa = sa;
	sp->is_new = is_new;
	memcpy(&sp->src_ip, &in6_src, sizeof(struct in6_addr));
	memcpy(&sp->dst_ip, &in6_dst, sizeof(struct in6_addr));

	dir = xfrmnl_sp_get_dir(nlsp);

	DAO_XFRM_DBG("Policy direction:%d", dir);

	switch (dir) {
	case XFRM_POLICY_OUT:
		sp->policy_dir = DAO_NETLINK_XFRM_POLICY_DIR_OUT;
	break;

	case XFRM_POLICY_IN:
		sp->policy_dir = DAO_NETLINK_XFRM_POLICY_DIR_IN;
	break;

	case XFRM_POLICY_FWD:
		sp->policy_dir = DAO_NETLINK_XFRM_POLICY_DIR_FWD;
	break;
	default:
		sp->policy_dir = -1;
	return -1;
	}
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
	int rc = -1;

	switch (nl_object_get_msgtype(nl_obj)) {
	case XFRM_MSG_NEWSA:
		rc = netlink_xfrm_parse_sa_add((struct xfrmnl_sa *)nl_obj, arg, 1);
		DAO_XFRM_DBG("XFRM_MSG_NEWSA processed: %d", rc);
	break;

	case XFRM_MSG_UPDSA:
		rc = netlink_xfrm_parse_sa_add((struct xfrmnl_sa *)nl_obj, arg, 1);
		DAO_XFRM_DBG("XFRM_MSG_UPDSA processed: %d", rc);
	break;

	case XFRM_MSG_DELSA:
		DAO_XFRM_DBG("Received XFRM MSG DELSA");
		rc = 0;
	break;

	case XFRM_MSG_UPDPOLICY:
		DAO_XFRM_DBG("Received XFRM MSG UPDPOLICY");
		rc = netlink_xfrm_parse_policy_add((struct xfrmnl_sp *)nl_obj, arg, 0);
	break;

	case XFRM_MSG_NEWPOLICY:
		DAO_XFRM_DBG("Received XFRM MSG NEW Policy");
		rc = netlink_xfrm_parse_policy_add((struct xfrmnl_sp *)nl_obj, arg, 1);
	break;

	case XFRM_MSG_DELPOLICY:
		DAO_XFRM_DBG("Received XFRM DEL policy");
		rc = 0;
	break;

	default:
		DAO_XFRM_DBG("Received invalid xfrm notification");
	}
	if (rc)
		dao_err("Failure rc: %d", rc);
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
			dao_ds_put_cstr(&cipher_xform_ds,				\
					(const char *)cipher->aead.key.data);		\
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
			dao_ds_put_cstr(&cipher_xform_ds,				\
					(const char *)cipher->cipher.key.data);		\
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
		else if (sa->auth_key.algo == DAO_CRYPTO_##alg) {			\
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
			dao_ds_put_cstr(&auth_xform_ds,					\
					(const char *)cipher->auth.key.data);		\
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
		dao_info("%s, key_len: %u, iv_len: %u, dig_len: %u, op: %d,aad: %u, ",
			 dao_ds_cstr(&cipher_xform_ds), cipher->aead.key.length,
			 cipher->aead.iv.length, cipher->aead.digest_length, cipher->aead.op,
			 cipher->aead.aad_length);
	} else {
		dao_info("%s, key_len: %u, iv_len: %u, op: %d",
			 dao_ds_cstr(&cipher_xform_ds),
			 cipher->cipher.key.length, cipher->cipher.iv.length,
			 cipher->cipher.op);
	}

	if (sa->is_auth)
		dao_info("%s, key_len: %u, iv_len: %u, dig_len: %u, op: %d",
			 dao_ds_cstr(&auth_xform_ds), auth->auth.key.length,
			 cipher->auth.iv.length, auth->auth.digest_length,
			 auth->auth.op);

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
