/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <rte_malloc.h>
#include <rte_pmd_cnxk_crypto.h>

#include "ca_asym.h"

int
ca_ae_fpm_get(uint8_t dev_id)
{
	const uint64_t *fpm_iova;

	fpm_iova = rte_pmd_cnxk_ae_fpm_table_get(dev_id);
	if (fpm_iova == NULL) {
		CA_ERR("Could not get AE FPM table for device %d", dev_id);
		return -EINVAL;
	}

	ca_glb_ctx.ca_ae_fpm_iova = (uint64_t *)fpm_iova;

	return 0;
}

int
ca_ae_ec_grp_get(uint8_t dev_id)
{
	const struct rte_pmd_cnxk_crypto_ae_ec_group_params **ec_grp;
	uint16_t nb_ae_ec_max_entries;

	ec_grp = rte_pmd_cnxk_ae_ec_grp_table_get(dev_id, &nb_ae_ec_max_entries);
	if (ec_grp == NULL) {
		CA_ERR("Could not get AE EC group table for device %d", dev_id);
		return -EINVAL;
	}

	ca_glb_ctx.nb_ae_ec_max_entries = nb_ae_ec_max_entries;
	ca_glb_ctx.ca_ec_grp = (struct rte_pmd_cnxk_crypto_ae_ec_group_params **)ec_grp;

	return 0;
}
