/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef __LC_TEST_SYM_HASH_H__
#define __LC_TEST_SYM_HASH_H__

#include "lc_test_sym.h"

static const uint8_t plaintext_hash[] = {
	"What a lousy earth! He wondered how many people "
	"were destitute that same night even in his own "
	"prosperous country, how many homes were "
	"shanties, how many husbands were drunk and "
	"wives socked, and how many children were "
	"bullied, abused, or abandoned. How many "
	"families hungered for food they could not "
	"afford to buy? How many hearts were broken? How "
	"many suicides would take place that same night, "
	"how many people would go insane? How many "
	"cockroaches and landlords would triumph? How "
	"many winners were losers, successes failures, "
	"and rich men poor men? How many wise guys were "
	"stupid? How many happy endings were unhappy "
	"endings? How many honest men were liars, brave "
	"men cowards, loyal men traitors, how many "
	"sainted men were corrupt, how many people in "
	"positions of trust had sold their souls to "
	"bodyguards, how many had never had souls? How "
	"many straight-and-narrow paths were crooked "
	"paths? How many best families were worst "
	"families and how many good people were bad "
	"people? When you added them all up and then "
	"subtracted, you might be left with only the "
	"children, and perhaps with Albert Einstein and "
	"an old violinist or sculptor somewhere."
};

static const uint8_t digest_sha1[] = {
	0xA2, 0x8D, 0x40, 0x78, 0xDD, 0x9F, 0xBB, 0xD5,
	0x35, 0x62, 0xFB, 0xFA, 0x93, 0xFD, 0x7D, 0x70,
	0xA6, 0x7D, 0x45, 0xCA
};

static const struct test_sym_params
sha1_test_data = {
	.ctx = {
		.opcode = DAO_LC_SYM_OPCODE_HASH,
		.fc = {
			.iv_source = DAO_LC_FC_IV_SRC_OP,
			.hash_type = DAO_LC_FC_HASH_TYPE_SHA1,
			.auth_input_type = DAO_LC_FC_AUTH_INPUT_OPAD_IPAD,
			.mac_len = 20,
		},
	},
	.plaintext = {
		.data = plaintext_hash,
		.len = 512
	},
	.digest = {
		.data = digest_sha1,
		.len = 20,
	}
};

#endif /* __LC_TEST_SYM_HASH_H__ */
