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

static const uint8_t digest_sha224[] = {
	0x91, 0xE7, 0xCD, 0x75, 0x14, 0x9C, 0xA9, 0xE9,
	0x2E, 0x46, 0x12, 0x20, 0x22, 0xF9, 0x68, 0x28,
	0x39, 0x26, 0xDF, 0xB5, 0x78, 0x62, 0xB2, 0x6E,
	0x5E, 0x8F, 0x25, 0x84
};

static const struct test_sym_params
sha224_test_data = {
	.ctx = {
		.opcode = DAO_LC_SYM_OPCODE_HASH,
		.fc = {
			.iv_source = DAO_LC_FC_IV_SRC_OP,
			.hash_type = DAO_LC_FC_HASH_TYPE_SHA2_SHA224,
			.auth_input_type = DAO_LC_FC_AUTH_INPUT_OPAD_IPAD,
			.mac_len = 28,
		},
	},
	.plaintext = {
		.data = plaintext_hash,
		.len = 512
	},
	.digest = {
		.data = digest_sha224,
		.len = 28,
	}
};

static const uint8_t digest_sha256[] = {
	0x7F, 0xF1, 0x0C, 0xF5, 0x90, 0x97, 0x19, 0x0F,
	0x00, 0xE4, 0x83, 0x01, 0xCA, 0x59, 0x00, 0x2E,
	0x1F, 0xC7, 0x84, 0xEE, 0x76, 0xA6, 0x39, 0x15,
	0x76, 0x2F, 0x87, 0xF9, 0x01, 0x06, 0xF3, 0xB7
};

static const struct test_sym_params
sha256_test_data = {
	.ctx = {
		.opcode = DAO_LC_SYM_OPCODE_HASH,
		.fc = {
			.iv_source = DAO_LC_FC_IV_SRC_OP,
			.hash_type = DAO_LC_FC_HASH_TYPE_SHA2_SHA256,
			.auth_input_type = DAO_LC_FC_AUTH_INPUT_OPAD_IPAD,
			.mac_len = 32,
		},
	},
	.plaintext = {
		.data = plaintext_hash,
		.len = 512
	},
	.digest = {
		.data = digest_sha256,
		.len = 32,
	}
};

static const uint8_t digest_sha384[] = {
	0x1D, 0xE7, 0x3F, 0x55, 0x86, 0xFE, 0x48, 0x9F,
	0xAC, 0xC6, 0x85, 0x32, 0xFA, 0x8E, 0xA6, 0x77,
	0x25, 0x84, 0xA5, 0x98, 0x8D, 0x0B, 0x80, 0xF4,
	0xEB, 0x2C, 0xFB, 0x6C, 0xEA, 0x7B, 0xFD, 0xD5,
	0xAD, 0x41, 0xAB, 0x15, 0xB0, 0x03, 0x15, 0xEC,
	0x9E, 0x3D, 0xED, 0xCB, 0x80, 0x7B, 0xF4, 0xB6
};

static const struct test_sym_params
sha384_test_data = {
	.ctx = {
		.opcode = DAO_LC_SYM_OPCODE_HASH,
		.fc = {
			.iv_source = DAO_LC_FC_IV_SRC_OP,
			.hash_type = DAO_LC_FC_HASH_TYPE_SHA2_SHA384,
			.auth_input_type = DAO_LC_FC_AUTH_INPUT_OPAD_IPAD,
			.mac_len = 48,
		},
	},
	.plaintext = {
		.data = plaintext_hash,
		.len = 512
	},
	.digest = {
		.data = digest_sha384,
		.len = 48,
	}
};

static const uint8_t digest_sha512[] = {
	0xB9, 0xBA, 0x28, 0x48, 0x3C, 0xC2, 0xD3, 0x65,
	0x4A, 0xD6, 0x00, 0x1D, 0xCE, 0x61, 0x64, 0x54,
	0x45, 0x8C, 0x64, 0x0E, 0xED, 0x0E, 0xD8, 0x1C,
	0x72, 0xCE, 0xD2, 0x44, 0x91, 0xC8, 0xEB, 0xC7,
	0x99, 0xC5, 0xCA, 0x89, 0x72, 0x64, 0x96, 0x41,
	0xC8, 0xEA, 0xB2, 0x4E, 0xD1, 0x21, 0x13, 0x49,
	0x64, 0x4E, 0x15, 0x68, 0x12, 0x67, 0x26, 0x0F,
	0x2C, 0x3C, 0x83, 0x25, 0x27, 0x86, 0xF0, 0xDB
};

static const struct test_sym_params
sha512_test_data = {
	.ctx = {
		.opcode = DAO_LC_SYM_OPCODE_HASH,
		.fc = {
			.iv_source = DAO_LC_FC_IV_SRC_OP,
			.hash_type = DAO_LC_FC_HASH_TYPE_SHA2_SHA512,
			.auth_input_type = DAO_LC_FC_AUTH_INPUT_OPAD_IPAD,
			.mac_len = 64,
		},
	},
	.plaintext = {
		.data = plaintext_hash,
		.len = 512
	},
	.digest = {
		.data = digest_sha512,
		.len = 64,
	}
};

#endif /* __LC_TEST_SYM_HASH_H__ */
