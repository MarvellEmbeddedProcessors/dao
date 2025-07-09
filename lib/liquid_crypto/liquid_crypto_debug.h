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

#endif /* __LIQUID_CRYPTO_DEBUG_H__ */
