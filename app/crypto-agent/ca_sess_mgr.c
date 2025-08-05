/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <rte_malloc.h>
#include <rte_mempool.h>
#include <rte_spinlock.h>

#include <dao_eth_trs.h>
#include <hw/cpt.h>
#include <liquid_crypto_trs.h>

#include "ca_sess_mgr.h"
#include "crypto_agent.h"

TAILQ_HEAD(session_list, ca_sess_handle)
sess_handle_list_head = TAILQ_HEAD_INITIALIZER(sess_handle_list_head);
static rte_spinlock_t sess_handle_list_lock = RTE_SPINLOCK_INITIALIZER;

static int
ca_sess_handle_insert(uint64_t sess_id)
{
	struct ca_sess_handle *new_session;

	/* Allocate memory to hold session handle*/
	new_session = rte_malloc("ca_sess_handle", sizeof(struct ca_sess_handle), 0);
	if (new_session == NULL) {
		CA_INFO("Could not allocate memory for new session handle.");
		return -ENOMEM;
	}

	new_session->sess_id = sess_id;
	rte_spinlock_lock(&sess_handle_list_lock);
	TAILQ_INSERT_HEAD(&sess_handle_list_head, new_session, next);
	rte_spinlock_unlock(&sess_handle_list_lock);

	return 0;
}

static int
ca_sess_handle_lookup(uint64_t sess_id)
{
	struct ca_sess_handle *current_session;

	/* Iterate through the list to find the session */
	rte_spinlock_lock(&sess_handle_list_lock);
	TAILQ_FOREACH(current_session, &sess_handle_list_head, next) {
		if (current_session->sess_id == sess_id) {
			/* Session found, remove it from the list */
			TAILQ_REMOVE(&sess_handle_list_head, current_session, next);

			/* Free the memory allocated for the session*/
			rte_free(current_session);
			rte_spinlock_unlock(&sess_handle_list_lock);
			return 0;
		}
	}
	rte_spinlock_unlock(&sess_handle_list_lock);

	return -EINVAL;
}

int
ca_sess_handle_create(struct rte_mbuf *mb)
{
	struct __dao_lc_resp_sess_create *sess_create_resp;
	struct __dao_lc_req_sess_create *sess_create;
	struct rte_mempool *sess_mempool;
	void *sess_ptr = NULL;
	union cpt_inst_w7 w7;
	int rc;

	sess_create = rte_pktmbuf_mtod(mb, struct __dao_lc_req_sess_create *);
	sess_create_resp = rte_pktmbuf_mtod(mb, struct __dao_lc_resp_sess_create *);

	if ((sess_create->opcode == DAO_LC_SYM_OPCODE_HASH) ||
	    (sess_create->opcode == DAO_LC_SYM_OPCODE_HMAC)) {
		/* No need of context for HASH/HMAC operations */
		sess_create_resp->sess_id = DAO_LC_SESS_ID_HASH;
		rc = 0;
		goto exit;
	} else if (sess_create->opcode == DAO_LC_SYM_OPCODE_AES_KEY_WRAP) {
		/* No need of context for AES Key Wrap operations */
		sess_create_resp->sess_id = DAO_LC_SESS_ID_AES_KEY_WRAP;
		rc = 0;
		goto exit;
	}

	/* Get the session mempool. */
	/* TODO: use the right pool based on request host device */
	sess_mempool = ca_host_sess_mempool_get(0);
	if (sess_mempool == NULL) {
		CA_INFO("Could not get session mempool.");
		sess_create_resp->sess_id = DAO_LC_SESS_ID_INVALID;
		rc = -EINVAL;
		goto exit;
	}

	/* Allocate buffer for holding CPTR. */
	rc = rte_mempool_get(sess_mempool, &sess_ptr);
	if (rc || sess_ptr == NULL) {
		CA_INFO("Could not allocate memory for session.");
		sess_create_resp->sess_id = DAO_LC_SESS_ID_INVALID;
		rc = -ENOMEM;
		goto exit;
	}

	/* Copy the session context to the allocated buffer. */
	memcpy(sess_ptr, sess_create->cptr, sizeof(struct dao_lc_sym_fc_ctx));

	w7.u64 = 0;
	w7.s.egrp = ROC_LEGACY_CPT_DFLT_ENG_GRP_SE_IE;
	w7.s.cptr = (uint64_t)sess_ptr;

	sess_create_resp->sess_id = w7.u64;

	rc = ca_sess_handle_insert(w7.u64);
	if (rc != 0) {
		CA_INFO("Could not insert session handle.");
		goto put_sess;
	}

	return 0;

put_sess:
	rte_mempool_put(sess_mempool, sess_ptr);

exit:
	return rc;
}

int
ca_sess_handle_destroy(struct rte_mbuf *mb)
{
	struct __dao_lc_req_resp_sess_destroy *sess_destroy;
	struct rte_mempool *sess_mempool;
	union cpt_inst_w7 w7;
	void *sess_ptr;
	int rc = 0;

	sess_destroy = rte_pktmbuf_mtod(mb, struct __dao_lc_req_resp_sess_destroy *);

	if ((sess_destroy->sess_id == DAO_LC_SESS_ID_HASH) ||
	    (sess_destroy->sess_id == DAO_LC_SESS_ID_AES_KEY_WRAP)) {
		/* There is no context associated with HASH/keywrap operation to free! */
		rc = 0;
		goto exit;
	}

	rc = ca_sess_handle_lookup(sess_destroy->sess_id);
	if (rc != 0) {
		CA_INFO("Could not find session handle.");
		goto exit;
	}

	/* Get the session mempool. */
	sess_mempool = ca_host_sess_mempool_get(0);
	if (sess_mempool == NULL) {
		CA_INFO("Could not get session mempool.");
		rc = -EINVAL;
		goto exit;
	}

	w7.u64 = sess_destroy->sess_id;

	/* Get the session pointer from the session ID. */
	sess_ptr = (void *)(uint64_t)w7.s.cptr;

	/* Return the session buffer to the mempool. */
	rte_mempool_put(sess_mempool, sess_ptr);

	return 0;

exit:
	return rc;
}
