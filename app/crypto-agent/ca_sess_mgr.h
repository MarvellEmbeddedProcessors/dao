/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef __CA_SESS_MGR_H__
#define __CA_SESS_MGR_H__

#include <rte_mbuf.h>
#include <rte_tailq.h>

/* Defines related to session management */

struct ca_sess_handle {
	TAILQ_ENTRY(ca_sess_handle) next;
	uint64_t sess_id;
};

int ca_sess_handle_create(struct rte_mbuf *mb);
int ca_sess_handle_destroy(struct rte_mbuf *mb);

#endif /* __CA_SESS_MGR_H__ */
