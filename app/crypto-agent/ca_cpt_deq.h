/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef __CA_CPT_DEQ_H__
#define __CA_CPT_DEQ_H__

#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_graph.h>
#include <rte_mbuf.h>

#include <dao_liquid_crypto.h>

#include "ca_crypto_queue.h"
#include "ca_dp.h"
#include "crypto_agent.h"

static inline void
ca_cpt_deq(struct pending_queue *pq)
{
	struct cpt_inflight_req *infl_req;
	union dao_cpt_res_s res;
	uint16_t nb_pending, i;
	uint64_t head, tail;
	int nb_tx;

	const uint64_t pq_mask = pq->pq_mask;

	head = pq->head;
	tail = pq->tail;

	nb_pending = pending_queue_infl_cnt(head, tail, pq_mask);
	if (nb_pending == 0)
		return;

	for (i = 0; i < nb_pending; i++) {
		infl_req = &pq->req_queue[tail];

		res.u64[0] = __atomic_load_n(&infl_req->res.u64[0], __ATOMIC_RELAXED);

		if (unlikely(res.cn10k.compcode == CPT_COMP_NOT_DONE)) {
			if (unlikely(rte_get_timer_cycles() > pq->time_out)) {
				CA_ERR("Request timed out");
				pq->time_out = rte_get_timer_cycles() +
					       DEFAULT_COMMAND_TIMEOUT * rte_get_timer_hz();
			}
			break;
		}

		pending_queue_advance(&tail, pq_mask);
		/* Process the packet */
		nb_tx = rte_eth_tx_burst(0, 0, &infl_req->mbuf, 1);
		CA_ERR("%d packets sent to host", nb_tx);
	}

	pq->tail = tail;
}

#endif /* __CA_CPT_DEQ_H__ */
