/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#ifndef _APP_SECGW_IPSEC_H_
#define _APP_SECGW_IPSEC_H_

#include <nodes/net/ip_node_priv.h>
#include <nodes/net/ipsec/ipsec_policy.h>
#include <rte_hexdump.h>
#include <rte_ipsec.h>
#include <rte_ipsec_sad.h>

#define SECGW_IPSEC_MAX_DEVICES   64
#define SECGW_IPSEC_MAX_INSTANCES 4
#define SECGW_IPSEC_MAX_SOCKETS   1

typedef enum {
	SECGW_IPSEC_SA_F_MODE_TUNNEL = 1 << 0,
	SECGW_IPSEC_SA_F_PROTO_ESP = 1 << 1,
	SECGW_IPSEC_SA_F_TUNNEL_IPV4 = 1 << 3,
	SECGW_IPSEC_SA_F_AR = 1 << 5,
	SECGW_IPSEC_SA_F_ESN = 1 << 6,
} secgw_ipsec_sa_flags_t;

typedef struct __rte_cache_aligned secgw_ipsec_sa {
	int32_t sa_index;
	secgw_ipsec_sa_flags_t sa_flags;
	union {
		struct rte_ipv4_hdr v4_hdr;
		struct rte_ipv6_hdr v6_hdr;
	};
	/* libIPsec session */
	struct rte_ipsec_session lipsec_session;

	/* Holding XFRM SA */
	dao_netlink_xfrm_sa_t *xfrm_sa;

	/* Holding IPsec SA*/
	RTE_MARKER cacheline1 __rte_cache_aligned;
	uint8_t lipsec_sa[];
} secgw_ipsec_sa_t;

typedef struct secgw_ipsec_sad {
	/* Name of SAD */
	char sad_name[SECGW_IPSEC_NAMELEN];

	/* size of this structure */
	uint64_t sad_size_in_bytes;

	/* socket_id from where memory is allocated for this SAD */
	int socket_id;

	void *bitmap_mem;

	/* Size of secgw_ipsec_sa_t->lipsec_sa[0] */
	int lipsec_sa_size;

	/* Number of ipsec_sas */
	uint32_t num_sas;

	/* Bitmap to keep track of which ipsec_sas[] is free */
	struct rte_bitmap *bitmap;

	/* libIPsec SAD object */
	struct rte_ipsec_sad *lipsec_sad;

	/* ipsec_sas */
	secgw_ipsec_sa_t ipsec_sas[];
} secgw_ipsec_sad_t;

/* dpdk ipsec object holding all SADs and SPDs */
typedef struct secgw_ipsec {
	char ipsec_name[SECGW_IPSEC_NAMELEN];

	/* Index of this object in ipsec_main->ipsec_objs */
	uint32_t ipsec_index;

	struct rte_mempool *sess_pool;

	/* SA database */
	struct secgw_ipsec_sad *sadb_v4;

	secgw_ipsec_policy_t spds;
} secgw_ipsec_t;

typedef struct secgw_ipsec_main {
	/* Number of secgw_ipsec_t instances */
	uint32_t num_ipsec_objs;
	/* crypto session pool by sockets */
	uint32_t socket_bitmask;

	/* IPsec instances */
	secgw_ipsec_t *ipsec_objs;

	struct rte_mempool **crypto_sess_pool_by_socket;
} secgw_ipsec_main_t;

extern secgw_ipsec_main_t *secgw_ipsec_main;

static inline secgw_ipsec_main_t *
secgw_ipsec_main_get(void)
{
	return secgw_ipsec_main;
}

static inline secgw_ipsec_sa_t *
secgw_ipsec_sa_get(secgw_ipsec_sad_t *sad, uint32_t index)
{
	RTE_VERIFY(index < sad->num_sas);

	return (sad->ipsec_sas + index);
}

static inline secgw_ipsec_t *
secgw_ipsec_get(secgw_ipsec_main_t *sim, uint32_t object_index)
{
	RTE_VERIFY(object_index < sim->num_ipsec_objs);

	return (sim->ipsec_objs + object_index);
}

int secgw_ipsec_attach(const char *ipsec_instance_name, dao_netlink_xfrm_sa_t *xsa,
		       dao_netlink_xfrm_policy_dir_t dir, int port_id, int num_sas,
		       int num_polocies, uint32_t *ipsec_index);

int secgw_ipsec_sad_sa_add_del(secgw_ipsec_t *ips, secgw_ipsec_sad_t *sad,
			       dao_netlink_xfrm_sa_t *xsa, uint16_t dp_port_id,
			       dao_netlink_xfrm_policy_dir_t policy_dir, bool is_add,
			       int32_t *sa_idx);

int secgw_ipsec_policy_add_del(secgw_ipsec_t *ips, dao_netlink_xfrm_policy_t *policy,
			       int32_t sa_idx, uint16_t port_id, int is_add);

int secgw_ipsec_sec_session_conf_fill(struct rte_security_session_conf *sess_conf,
				      dao_netlink_xfrm_sa_t *sa, dao_netlink_xfrm_policy_dir_t dir,
				      enum rte_security_session_action_type action_type);

int secgw_ipsec_verify_sec_capabilty(struct rte_security_session_conf *sess_conf,
				     struct rte_security_ctx *sec_ctx, uint32_t *out_flags);
#endif
