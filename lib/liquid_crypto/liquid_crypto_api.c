/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <string.h>

#include <rte_eal.h>

#include <dao_liquid_crypto.h>
#include <dao_log.h>

static struct dao_liquid_crypto_info liquid_crypto_info;

int
dao_liquid_crypto_init(void)
{
	memset(&liquid_crypto_info, 0, sizeof(liquid_crypto_info));

	/* Call eth TRS API
	 * - Get the count of eth devices
	 */

	/* Save the info here. */

	return 0;
}

int
dao_liquid_crypto_fini(void)
{
	memset(&liquid_crypto_info, 0, sizeof(liquid_crypto_info));

	return 0;
}

int
dao_liquid_crypto_info_get(struct dao_liquid_crypto_info *info)
{
	if (info == NULL) {
		dao_err("Invalid argument.");
		return -EINVAL;
	}

	memcpy(info, &liquid_crypto_info, sizeof(liquid_crypto_info));

	return 0;
}
