/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2023 Marvell.
 */

/**
 * @file
 *
 * DAO XFRM Netlink Notification management
 */

#ifndef _DAO_LIB_NETLINK_XFRM_H
#define _DAO_LIB_NETLINK_XFRM_H

#include "dao_netlink_crypto.h"

#include <rte_crypto.h>

#include <netlink/xfrm/sa.h>
#include <netlink/xfrm/sp.h>
#include <netlink/xfrm/ae.h>
#include <netlink/xfrm/template.h>
#include <netlink/xfrm/selector.h>
#include <netlink/xfrm/lifetime.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DAO_NETLINK_XFRM_NAME_LEN			64
#define DAO_NETLINK_XFRM_ALG_MAX_NAME			128

/** Policy directions from LINUX */
typedef enum {
	/** Inbound direction */
	DAO_NETLINK_XFRM_POLICY_DIR_IN,
	/** Outbound direction */
	DAO_NETLINK_XFRM_POLICY_DIR_OUT,
	/** Forward */
	DAO_NETLINK_XFRM_POLICY_DIR_FWD,
} dao_netlink_xfrm_policy_dir_t;

/** xfrm op type */
typedef enum {
	/** Add IPsec policy */
	DAO_NETLINK_XFRM_OP_POLICY_ADD,
	/** Update IPsec policy */
	DAO_NETLINK_XFRM_OP_POLICY_UPD,
} dao_netlink_xfrm_op_type_t;

/** IPsec protocol: ESP, AH */
typedef enum {
	/** ESP Tunnel */
	DAO_NETLINK_XFRM_PROTO_ESP,
	/** AH Tunnel */
	DAO_NETLINK_XFRM_PROTO_AH,
} dao_netlink_xfrm_proto_t;

/** IPsec SA mode */
typedef enum {
	/** Transport mode */
	DAO_NETLINK_XFRM_MODE_TRANSPORT,
	/** Tunnel mode */
	DAO_NETLINK_XFRM_MODE_TUNNEL,
} dao_netlink_xfrm_sa_mode_t;

/** IPsec tunnel type */
typedef enum {
	/** IPv4 */
	DAO_NETLINK_XFRM_TUNNEL_IPV4,
	/** IPv6 */
	DAO_NETLINK_XFRM_TUNNEL_IPV6,
} dao_netlink_xfrm_tunnel_type_t;

/** IPsec SA flags */
typedef enum {
	/** Extended sequence number is enabled */
	DAO_NETLINK_XFRM_SA_FLAG_USE_ESN = 1 << 0,
	/** Anti-Replay is enabled */
	DAO_NETLINK_XFRM_SA_FLAG_USE_AR = 1 << 1,
} dao_netlink_xfrm_sa_flags_t;

/** Crypto transform */
typedef struct dao_netlink_xfrm_sa_xform {
	/** Crypto key */
	dao_netlink_crypto_key_t crypto_key;
	/** Crypto key length */
	unsigned int key_len;
	union {
		/** Crypto ICV length */
		unsigned int icv_len;	/**< valid for aead*/
		/** Crypto truncation length */
		unsigned int trunc_len;
	};
	/** crypto key in string */
	char key[DAO_NETLINK_CRYPTO_KEY_MAX_NAME_LEN];
	/** Algo name in string */
	char algo[DAO_NETLINK_XFRM_ALG_MAX_NAME];
} dao_netlink_xfrm_sa_xform_t;

/** XFRM SA object */
typedef struct dao_netlink_xfrm_sa {
	/** list */
	STAILQ_ENTRY(dao_netlink_xfrm_sa)next_sa;
	/** Request Id in XFRM */
	uint32_t req_id;
	/** SPI */
	uint32_t spi;
	/** refcnt: keeping track of this SA attached to how many policies */
	int refcnt;
	/** aead_key is valid */
	int is_aead;
	/** cipher_key is valid */
	int is_cipher;
	/** auth_key is valid */
	int is_auth;
	/** IPsec salt */
	uint32_t salt;
	/** IPsec SA mode: Tunnel or Transport */
	dao_netlink_xfrm_sa_mode_t sa_mode;
	/** Anti-replay wondow: default value */
	uint32_t replay_window;
	/** IPsec SA flags like ESN, AR enabled/disabled */
	dao_netlink_xfrm_sa_flags_t sa_flags;
	/** XFRM Protocol: ESP, AH */
	dao_netlink_xfrm_proto_t ipsec_proto;
	/** SA Local IP address */
	struct in6_addr in6_src;
	/** SA Remote IP address */
	struct in6_addr in6_dst;
	/** IPsec Tunnel type: IPv4, IPv6 */
	dao_netlink_xfrm_tunnel_type_t ip_tunnel_type;
	/** crypto key. Valid if is_crypto is true */
	struct dao_netlink_crypto_key aead_key;
	/** Auth key. Valid if is_auth is true */
	struct dao_netlink_crypto_key auth_key;
	/** Cipher key. Valid if is_cipher is true */
	struct dao_netlink_crypto_key cipher_key;
} dao_netlink_xfrm_sa_t;

/** XFRM Policy object */
typedef struct dao_netlink_xfrm_policy {
	/** Request Id in XFRM */
	uint32_t req_id;
	/** is this new policy or updated one */
	int is_new;
	/** Pointer of already registered xfrm SA*/
	struct dao_netlink_xfrm_sa *ips_sa;
	/** Local policy IP address */
	struct in6_addr src_ip;
	/** Remote policy IP address */
	struct in6_addr dst_ip;
	/** IPsec Policy direction from netlink */
	dao_netlink_xfrm_policy_dir_t policy_dir;
} dao_netlink_xfrm_policy_t;

/** High level XFRM callback ops registered by application */
typedef struct dao_netlink_xfrm_callback_ops {
	/**
	 * Create IPsec policy. SA is provided as part of policy
	 *
	 * @param policy
	 *   IPsec Policy object
	 * @param sa
	 *   IPsec SA object
	 * @param op_type
	 *   Policy addition/deletaion
	 * @param app_cookie
	 *   Cookie provided in @ref dao_netlink_xfrm_notifier_register
	 */
	int (*xfrm_policy_create)(dao_netlink_xfrm_policy_t *policy, dao_netlink_xfrm_sa_t *sa,
				  dao_netlink_xfrm_op_type_t op_type, void *app_cookie);
	/**
	 * Delete IPsec policy.
	 */
	int (*xfrm_policy_destroy)(dao_netlink_xfrm_policy_t *policy, dao_netlink_xfrm_sa_t *sa,
				   dao_netlink_xfrm_op_type_t op_type, void *app_cookie);
} dao_netlink_xfrm_callback_ops_t;

/**
 * Translate Policy direction to string
 *
 * @param dir
 *   Policy direction
 *
 * @return
 *   const string
 */
static inline const char *
dao_netlink_ipsec_dir_to_str(dao_netlink_xfrm_policy_dir_t dir)
{
	switch (dir) {
	case DAO_NETLINK_XFRM_POLICY_DIR_IN:
		return "inb";
	break;

	case DAO_NETLINK_XFRM_POLICY_DIR_OUT:
		return "outb";
	break;

	case DAO_NETLINK_XFRM_POLICY_DIR_FWD:
		return "fwd";
	break;

	default:
		return NULL;
	}
}

/**
 * Tunnel type to String
 *
 * @param ip_proto
 *   XFRM tunnel type
 *
 * @return
 *   character string
 */
static inline const char *
dao_netlink_xfrm_tunnel_type_to_str(dao_netlink_xfrm_tunnel_type_t ip_proto)
{
	switch (ip_proto) {
	case DAO_NETLINK_XFRM_TUNNEL_IPV4:
		return "ipv4";
	break;

	case DAO_NETLINK_XFRM_TUNNEL_IPV6:
		return "ipv6";
	break;

	default:
		return NULL;
	}
}

/* Function declaration */

/**
 * Converts netlink xfrm transform to DPDK crypto xforms
 *
 * @param sa
 *   DAO netlink XFRM SA object received in @ref dao_netlink_xfrm_callback_ops_t
 * @param dir
 *   Policy direction
 * @param[out] cipher
 *   DPDK crypto xform for cipher key
 * @param[out] auth
 *   DPDK crypto xform for auth key
 *
 * @return
 *   0: Success
 *  <0: Failure
 */
int dao_netlink_xfrm_sa_to_crypto_xform(struct dao_netlink_xfrm_sa *sa,
					dao_netlink_xfrm_policy_dir_t dir,
					struct rte_crypto_sym_xform *cipher,
					struct rte_crypto_sym_xform *auth);

/**
 * High level registration function for NETLINK_XFRM
 *
 * @param xfrm_ops
 *   High level XFRM callback ops
 * @param app_cookie
 *  Application specific cookie for identifying netlink notification
 *
 * @return
 *  0: Success
 * <0: Failure
 */
int dao_netlink_xfrm_notifier_register(dao_netlink_xfrm_callback_ops_t *xfrm_ops, void *app_cookie);

#ifdef __cplusplus
}
#endif
#endif
