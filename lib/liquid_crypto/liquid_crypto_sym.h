/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef __LIQUID_CRYPTO_SYM_H__
#define __LIQUID_CRYPTO_SYM_H__

#include <rte_tailq.h>

#include <dao_liquid_crypto.h>

#define DAO_LC_SYM_META_GET_PTR(sess_opaque)                                                       \
	((struct dao_lc_sym_sess_meta *)((uintptr_t)(sess_opaque)))

/**
 * The liquid crypto symmetric context.
 */
struct dao_lc_sym_sess_meta {
	TAILQ_ENTRY(dao_lc_sym_sess_meta) next;

	/** CPT Instruction W7 */
	uint64_t w7;

	/** IV length */
	uint16_t iv_len;
};

int liquid_crypto_sym_sess_verify(const struct dao_lc_sym_ctx *ctx);

struct dao_lc_sym_sess_meta *liquid_crypto_sym_sess_meta_alloc(const struct dao_lc_sym_ctx *ctx);

void liquid_crypto_sym_sess_meta_insert(struct dao_lc_sym_sess_meta *sess_meta, uint64_t sess_id);

int liquid_crypto_sym_sess_meta_remove(uint64_t sess_id, uint64_t *sess_opaque);

void liquid_crypto_sym_sess_meta_free(struct dao_lc_sym_sess_meta *sess_meta);

#endif /* __LIQUID_CRYPTO_SYM_H__ */
