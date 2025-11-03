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

/* Forward declarations */
struct rte_pmd_cnxk_crypto_qptr;

struct __rte_aligned(ROC_ALIGN) cpt_inflight_req
{
	union dao_cpt_res_s res;
	struct rte_mbuf *mbuf;
	enum lc_crypto_op_type op_type;
	uint16_t rsa_mod_len;
	uint16_t ec_prime_len;
	uint64_t sym_param2;
	bool is_gmac;
	uint8_t stage;
	uint8_t max_stage;
	union {
		uint16_t rsa_exp_len;
		uint16_t hash_type;
	} rsa_oaep;
	uint16_t oaep_label_len;
	uint8_t ooo_done;
	uint8_t padding[78];
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
	/** Enable out of order delivery */
	bool out_of_order_delivery_en;
	/** Dequeue function pointer - set at configuration time */
	uint16_t (*deq_fn)(struct pending_queue *pq, struct rte_pmd_cnxk_crypto_qptr *cpt_qptr);
};

/* Function declarations for dequeue function pointers */
uint16_t ca_cpt_deq(struct pending_queue *pq, struct rte_pmd_cnxk_crypto_qptr *cpt_qptr);
uint16_t ca_cpt_deq_ooo(struct pending_queue *pq, struct rte_pmd_cnxk_crypto_qptr *cpt_qptr);

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
	/* mask is nb_desc - 1. Reserve 1 slot to differentiate between queue full and empty */
	return mask - pending_queue_infl_cnt(head, tail, mask);
}

#endif /* __CA_CRYPTO_QUEUE_H__ */
