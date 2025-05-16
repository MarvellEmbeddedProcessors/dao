/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef __CA_CRYPTO_QUEUE_H__
#define __CA_CRYPTO_QUEUE_H__

#include <rte_common.h>
#include <rte_cryptodev.h>
#include <rte_mbuf.h>

#include <dao_liquid_crypto.h>
#include <dao_util.h>
#include <hw/cpt.h>
#include <liquid_crypto_trs.h>

#define CA_CPT_MIN_QUEUE_DEPTH 2048

struct __rte_aligned(ROC_ALIGN) cpt_inflight_req
{
	union dao_cpt_res_s res;
	struct rte_mbuf *mbuf;
	uint8_t rsa_is_decrypt : 1;
	uint8_t is_hash_only : 1;
	uint16_t rsa_mod_len;
};

DAO_STATIC_ASSERT(sizeof(struct cpt_inflight_req) == 128);

struct pending_queue {
	/** Array of pending requests */
	struct cpt_inflight_req *req_queue;
	/** Head of the queue to be used for enqueue */
	uint64_t head;
	/** Tail of the queue to be used for dequeue */
	uint64_t tail;
	/** Pending queue mask */
	uint64_t pq_mask;
	/** Timeout to track h/w being unresponsive */
	uint64_t time_out;
	/** Ethdev port ID this pending queue is associated with */
	uint16_t eth_port_id;
	/** Ethdev queue ID this pending queue is associated with */
	uint16_t eth_queue_id;
};

static __rte_always_inline void
pending_queue_advance(uint64_t *index, const uint64_t mask)
{
	*index = (*index + 1) & mask;
}

static __rte_always_inline void
pending_queue_retreat(uint64_t *index, const uint64_t mask, uint64_t nb_entry)
{
	*index = (*index - nb_entry) & mask;
}

static __rte_always_inline uint64_t
pending_queue_infl_cnt(uint64_t head, uint64_t tail, const uint64_t mask)
{
	/*
	 * Mask is nb_desc - 1. Add nb_desc to head and mask to account for
	 * cases when tail > head, which happens during wrap around.
	 */
	return ((head + mask + 1) - tail) & mask;
}

static __rte_always_inline uint64_t
pending_queue_free_cnt(uint64_t head, uint64_t tail, const uint64_t mask)
{
	/* mask is nb_desc - 1 */
	return mask + 1 - pending_queue_infl_cnt(head, tail, mask);
}

#endif /* __CA_CRYPTO_QUEUE_H__ */
