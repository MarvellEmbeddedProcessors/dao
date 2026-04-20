/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef __LIQUID_CRYPTO_DEBUG_H__
#define __LIQUID_CRYPTO_DEBUG_H__

#include <stdbool.h>

#include <dao_liquid_crypto.h>

static inline bool
lc_debug_enabled(void)
{
#ifdef DAO_LIQUID_CRYPTO_DEBUG
	return true;
#else
	return false;
#endif
}

static inline int
lc_buf_validate(struct dao_lc_buf *first_buf, bool is_zero_len_allowed)
{
	struct dao_lc_buf *buf;
	uint32_t pkt_len = 0;

	if (first_buf == NULL) {
		dao_err("Invalid buffer pointer.");
		return -EINVAL;
	}

	if (first_buf->total_len == 0) {
		if (!is_zero_len_allowed) {
			dao_err("Invalid buffer total length.");
			return -EINVAL;
		}

		if (first_buf->frag_len != 0 || first_buf->next != NULL) {
			dao_err("Fragment length should be zero when total length is zero."
				" Next buffer should also be NULL.");
			return -EINVAL;
		}

		return 0;
	}

	buf = first_buf;
	do {
		if (buf->data == NULL) {
			dao_err("Invalid buffer fragment data pointer.");
			return -EINVAL;
		}
		pkt_len += buf->frag_len;
		buf = buf->next;
	} while (buf != NULL);

	if (pkt_len != first_buf->total_len) {
		dao_err("buffer total length does not match fragment lengths.");
		return -EINVAL;
	}

	return 0;
}

#endif /* __LIQUID_CRYPTO_DEBUG_H__ */
