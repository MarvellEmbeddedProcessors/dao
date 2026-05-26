/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <errno.h>
#include <stddef.h>

#include <rte_malloc.h>

#include <dao_liquid_crypto.h>
#include <dao_log.h>

#include "liquid_crypto_asym.h"
#include "liquid_crypto_priv.h"

const struct cpt_ae_ec_group cpt_ae_ec_groups[] = {
	{
		.prime = {.data = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
				   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
			  .length = 24},
		.order = {.data = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				   0xFF, 0xFF, 0xFF, 0xFF, 0x99, 0xDE, 0xF8, 0x36,
				   0x14, 0x6B, 0xC9, 0xB1, 0xB4, 0xD2, 0x28, 0x31},
			  .length = 24},
	},
	{
		.prime = {.data = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
				   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
			  .length = 28},
		.order = {.data = {0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF,
				   0XFF, 0XFF, 0XFF, 0XFF, 0X16, 0XA2, 0XE0, 0XB8, 0XF0, 0X3E,
				   0X13, 0XDD, 0X29, 0X45, 0X5C, 0X5C, 0X2A, 0X3D},
			  .length = 28},
	},
	{
		.prime = {.data = {0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
				   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF,
				   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
			  .length = 32},
		.order = {.data = {0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF,
				   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17,
				   0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51},
			  .length = 32},
	},
	{
		.prime = {.data = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				   0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
				   0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF},
			  .length = 48},
		.order = {.data = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				   0xFF, 0xFF, 0xFF, 0xFF, 0xC7, 0x63, 0x4D, 0x81, 0xF4, 0x37,
				   0x2D, 0xDF, 0x58, 0x1A, 0x0D, 0xB2, 0x48, 0xB0, 0xA7, 0x7A,
				   0xEC, 0xEC, 0x19, 0x6A, 0xCC, 0xC5, 0x29, 0x73},
			  .length = 48},
	},
	{
		.prime = {.data = {0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
			  .length = 66},
		.order = {.data = {0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				   0xFF, 0xFF, 0xFF, 0xFA, 0x51, 0x86, 0x87, 0x83, 0xBF, 0x2F,
				   0x96, 0x6B, 0x7F, 0xCC, 0x01, 0x48, 0xF7, 0x09, 0xA5, 0xD0,
				   0x3B, 0xB5, 0xC9, 0xB8, 0x89, 0x9C, 0x47, 0xAE, 0xBB, 0x6F,
				   0xB7, 0x1E, 0x91, 0x38, 0x64, 0x09},
			  .length = 66},
	},
};

int
cpt_ae_rsa_mod_len_check(uint16_t mod_len, bool is_crt)
{
	uint16_t min_len = LIQUID_CRYPTO_RSA_MOD_LEN_MIN;

	if (is_crt)
		min_len = LIQUID_CRYPTO_RSA_MOD_LEN_MIN * 2;

	if (mod_len == 0) {
		dao_err("Invalid modulus length. mod_len cannot be zero.");
		return -EINVAL;
	}

	if (is_crt && mod_len % 2 != 0) {
		dao_err("Invalid modulus length. mod_len must be even.");
		return -EINVAL;
	}

	if (mod_len < min_len || mod_len > LIQUID_CRYPTO_RSA_MOD_LEN_MAX) {
		dao_err("Invalid modulus length. mod_len should be at least %u and at most %u bytes.",
			min_len, LIQUID_CRYPTO_RSA_MOD_LEN_MAX);
		return -EINVAL;
	}

	return 0;
}

int
cpt_ae_rsa_msg_len_check(uint16_t mod_len, uint16_t msg_len)
{
	if (msg_len == 0) {
		dao_err("Invalid message length. msg_len cannot be zero.");
		return -EINVAL;
	}

	if (msg_len > mod_len - LIQUID_CRYPTO_RSA_MSG_LEN_PADDING) {
		dao_err("Invalid message length. msg_len should be at most %u bytes.",
			mod_len - LIQUID_CRYPTO_RSA_MSG_LEN_PADDING);
		return -EINVAL;
	}

	return 0;
}

int
cpt_ae_rsa_exp_len_check(uint16_t mod_len, uint16_t exp_len)
{
	if (exp_len == 0) {
		dao_err("Invalid exp_len length. exp_len cannot be zero.");
		return -EINVAL;
	}

	if (exp_len > mod_len) {
		dao_err("Invalid exp_len length. exp_len should be at most %u bytes.", mod_len);
		return -EINVAL;
	}

	return 0;
}

int
cpt_ae_rsa_msw_check(uint16_t plen, const uint8_t *p)
{
	uint8_t len = plen % 8;
	uint64_t msw;

	if (p == NULL || plen == 0)
		return -EINVAL;

	if (len)
		memcpy(&msw, p, len);
	else
		memcpy(&msw, p, 8);

	if (msw == 0)
		return -EINVAL;

	return 0;
}

int
cpt_ae_rsa_crt_params_check(uint16_t mod_len, const uint8_t *q, const uint8_t *dQ, const uint8_t *p,
			    const uint8_t *dP, const uint8_t *qInv)
{
	int i;

	if (q == NULL || dQ == NULL || p == NULL || dP == NULL || qInv == NULL) {
		dao_err("Invalid CRT parameters. None of the parameters can be NULL.");
		return -EINVAL;
	}

	if (q[mod_len / 2 - 1] % 2 == 0) {
		dao_err("Invalid CRT parameter. q must be odd.");
		return -EINVAL;
	}

	if (p[mod_len / 2 - 1] % 2 == 0) {
		dao_err("Invalid CRT parameter. p must be odd.");
		return -EINVAL;
	}

	/* Check if dQ is zero */
	for (i = 0; i < mod_len / 2; i++) {
		if (dQ[i] != 0)
			break;
	}
	if (i == mod_len / 2) {
		dao_err("Invalid CRT parameter. dQ cannot be zero.");
		return -EINVAL;
	}

	/* Check if dP is zero */
	for (i = 0; i < mod_len / 2; i++) {
		if (dP[i] != 0)
			break;
	}
	if (i == mod_len / 2) {
		dao_err("Invalid CRT parameter. dP cannot be zero.");
		return -EINVAL;
	}

	/* Check if qInv is zero */
	for (i = 0; i < mod_len / 2; i++) {
		if (qInv[i] != 0)
			break;
	}
	if (i == mod_len / 2) {
		dao_err("Invalid CRT parameter. qInv cannot be zero.");
		return -EINVAL;
	}

	return 0;
}

int
cpt_ae_rsa_oaep_hash_type_check(enum dao_lc_hash_type hash_type)
{
	switch (hash_type) {
	case DAO_LC_HASH_TYPE_SHA1:
	case DAO_LC_HASH_TYPE_SHA2_SHA256:
	case DAO_LC_HASH_TYPE_SHA2_SHA384:
	case DAO_LC_HASH_TYPE_SHA2_SHA512:
		break;
	default:
		dao_err("Invalid hash type. hash_type=%d (valid values: %d, %d, %d, %d).",
			hash_type, DAO_LC_HASH_TYPE_SHA1, DAO_LC_HASH_TYPE_SHA2_SHA256,
			DAO_LC_HASH_TYPE_SHA2_SHA384, DAO_LC_HASH_TYPE_SHA2_SHA512);
		return -EINVAL;
	}

	return 0;
}

int
cpt_ae_rsa_oaep_get_hash_len(enum dao_lc_hash_type hash_type)
{
	switch (hash_type) {
	case DAO_LC_HASH_TYPE_SHA1:
		return DAO_LC_HASH_DIGEST_SIZE_SHA1;
	case DAO_LC_HASH_TYPE_SHA2_SHA256:
		return DAO_LC_HASH_DIGEST_SIZE_SHA2_SHA256;
	case DAO_LC_HASH_TYPE_SHA2_SHA384:
		return DAO_LC_HASH_DIGEST_SIZE_SHA2_SHA384;
	case DAO_LC_HASH_TYPE_SHA2_SHA512:
		return DAO_LC_HASH_DIGEST_SIZE_SHA2_SHA512;
	default:
		return -EINVAL;
	}
}

int
cpt_ae_oaep_msg_and_mod_len_check(uint16_t mod_len, uint16_t msg_len,
				  enum dao_lc_hash_type hash_type)
{
	int hash_len;

	hash_len = cpt_ae_rsa_oaep_get_hash_len(hash_type);
	if (hash_len < 0) {
		dao_err("Invalid hash type. hash_type=%d (valid values: %d, %d, %d, %d).",
			hash_type, DAO_LC_HASH_TYPE_SHA1, DAO_LC_HASH_TYPE_SHA2_SHA256,
			DAO_LC_HASH_TYPE_SHA2_SHA384, DAO_LC_HASH_TYPE_SHA2_SHA512);
		return -EINVAL;
	}

	/* OAEP requires modulus length to be at least msg_len + 2 * hash_len + 2 */
	if (mod_len < msg_len + 2 * hash_len + 2) {
		dao_err("Invalid modulus length: mod_len=%u, msg_len=%u, hash_len=%u. Required minimum is %u bytes.",
			mod_len, msg_len, hash_len, msg_len + 2 * hash_len + 2);
		return -EINVAL;
	}

	if (msg_len > mod_len - 2 * hash_len - 2) {
		dao_err("Invalid message length. For the given modulus length (%u bytes) and hash type (%d), "
			"msg_len should be at most %u bytes.",
			mod_len, hash_type, mod_len - 2 * hash_len - 2);
		return -EINVAL;
	}

	return 0;
}

int
cpt_ae_rsa_oaep_mod_len_check(uint16_t mod_len, bool is_crt)
{
	uint16_t min_len = LIQUID_CRYPTO_RSA_MOD_LEN_MIN;

	if (is_crt)
		min_len = LIQUID_CRYPTO_RSA_MOD_LEN_MIN * 2;

	if (mod_len == 0) {
		dao_err("Invalid modulus length. mod_len cannot be zero.");
		return -EINVAL;
	}

	if (is_crt && mod_len % 2 != 0) {
		dao_err("Invalid modulus length. mod_len must be even.");
		return -EINVAL;
	}

	if (mod_len < min_len) {
		dao_err("Invalid modulus length. mod_len should be at least %u bytes", min_len);
		return -EINVAL;
	}

	return 0;
}

int
cpt_ae_rsa_oaep_label_validate(uint8_t *label, uint16_t label_len)
{
	if (label_len > 0 && label == NULL) {
		dao_err("Invalid label. If label_len > 0, label cannot be NULL.");
		return -EINVAL;
	} else if (label_len == 0 && label != NULL) {
		dao_err("Invalid label. If label_len is zero, label must be NULL.");
		return -EINVAL;
	}

	return 0;
}

int
cpt_ae_rsa_oaep_msg_len_max(uint16_t mod_len, enum dao_lc_hash_type hash_type)
{
	int hash_len;

	hash_len = cpt_ae_rsa_oaep_get_hash_len(hash_type);
	if (hash_len < 0) {
		dao_err("Invalid hash type. hash_type=%d (valid values: %d, %d, %d, %d).",
			hash_type, DAO_LC_HASH_TYPE_SHA1, DAO_LC_HASH_TYPE_SHA2_SHA256,
			DAO_LC_HASH_TYPE_SHA2_SHA384, DAO_LC_HASH_TYPE_SHA2_SHA512);
		return -EINVAL;
	}

	return mod_len - 2 * hash_len - 2;
}

int
cpt_ec_curve_id_validate(enum dao_liquid_crypto_ec_curve_type curve_id)
{
	if (curve_id < DAO_LC_AE_EC_ID_P192 || curve_id > DAO_LC_AE_EC_ID_P521) {
		dao_err("Invalid curve ID. curve_id=%d (valid range: %d to %d).", curve_id,
			DAO_LC_AE_EC_ID_P192, DAO_LC_AE_EC_ID_P521);
		return -EINVAL;
	}
	return 0;
}

int
cpt_ae_ecdsa_pkey_len_check(uint16_t prime_len, uint16_t pkey_len)
{
	if ((pkey_len == 0)) {
		dao_err("Invalid private key length. pkey_len cannot be zero.");
		return -EINVAL;
	}

	if (pkey_len > prime_len) {
		dao_err("Invalid private key length. pkey_len must be at most %u bytes.",
			prime_len);
		return -EINVAL;
	}

	return 0;
}

int
cpt_ae_ecdsa_pubkey_len_check(uint16_t prime_len, uint16_t pubkey_x_len, uint16_t pubkey_y_len)
{
	if (pubkey_x_len == 0 || pubkey_y_len == 0) {
		dao_err("Invalid public key length. pubkey_x_len and pubkey_y_len cannot be zero.");
		return -EINVAL;
	}
	if (pubkey_x_len > prime_len) {
		dao_err("Invalid public key x-coordinate length. pubkey_x_len must be at most %u bytes.",
			prime_len);
		return -EINVAL;
	}

	if (pubkey_y_len > prime_len) {
		dao_err("Invalid public key y-coordinate length. pubkey_y_len must be at most %u bytes.",
			prime_len);
		return -EINVAL;
	}

	return 0;
}

int
cpt_ae_ecdsa_sign_comp_len_check(uint16_t prime_len, uint16_t r_len, uint16_t s_len)
{
	if ((r_len == 0) || (s_len == 0)) {
		dao_err("Invalid sign component length. r_len and s_len cannot be zero.");
		return -EINVAL;
	}

	if (r_len > prime_len) {
		dao_err("Invalid r sign component length. r_len must be at most %u bytes.",
			prime_len);
		return -EINVAL;
	}

	if (s_len > prime_len) {
		dao_err("Invalid s sign component length. s_len must be at most %u bytes.",
			prime_len);
		return -EINVAL;
	}

	return 0;
}

int
cpt_ae_ecdsa_digest_len_check(uint16_t prime_len, uint16_t digest_len)
{
	if ((digest_len == 0) || (digest_len > prime_len)) {
		dao_err("Invalid digest length. digest_len must be in between 1 to %u length bytes.",
			prime_len);
		return -EINVAL;
	}

	return 0;
}

int
ecc_curve_id_to_prime_len(enum dao_liquid_crypto_ec_curve_type curve_id)
{
	switch (curve_id) {
	case DAO_LC_AE_EC_ID_P192:
		return DAO_LC_PRIME_LEN_P192;
	case DAO_LC_AE_EC_ID_P224:
		return DAO_LC_PRIME_LEN_P224;
	case DAO_LC_AE_EC_ID_P256:
		return DAO_LC_PRIME_LEN_P256;
	case DAO_LC_AE_EC_ID_P384:
		return DAO_LC_PRIME_LEN_P384;
	case DAO_LC_AE_EC_ID_P521:
		return DAO_LC_PRIME_LEN_P521;
	default:
		return -1;
	}
}

int
cpt_ae_ecdsa_pkey_validate(uint16_t pkey_len, const uint8_t *pkey,
			   enum dao_liquid_crypto_ec_curve_type curve_id)
{
	const uint8_t *order = cpt_ae_ec_groups[curve_id].order.data;
	uint16_t order_len = cpt_ae_ec_groups[curve_id].order.length;
	int cmp = -1;
	int i;

	for (i = 0; i < pkey_len; i++) {
		if (pkey[i] != 0)
			break;
	}

	if (i == pkey_len) {
		dao_err("Invalid ECC private key. Private key cannot be zero.");
		return -EINVAL;
	}

	if (pkey_len == order_len) {
		/* same length -> compare byte by byte (big-endian) */
		for (i = 0; i < pkey_len; i++) {
			if (pkey[i] < order[i]) {
				cmp = -1;
				break;
			} else if (pkey[i] > order[i]) {
				cmp = 1;
				break;
			}
		}
		/* exactly equal */
		if (i == pkey_len)
			cmp = 0;
	}

	/* If pkey_len < order_len, cmp stays -1 (always smaller) */
	if (cmp >= 0) {
		dao_err("Invalid ECC private key. Private key must be less than the order of the curve.");
		return -EINVAL;
	}

	return 0;
}

int
cpt_ae_ecdsa_pubkey_validate(uint16_t pubkey_x_len, const uint8_t *pubkey_x, uint16_t pubkey_y_len,
			     const uint8_t *pubkey_y, enum dao_liquid_crypto_ec_curve_type curve_id)
{
	const uint8_t *prime = cpt_ae_ec_groups[curve_id].prime.data;
	uint16_t prime_len = cpt_ae_ec_groups[curve_id].prime.length;
	int cmp = -1, i;

	/* Validate pubkey_x */
	if (pubkey_x_len == prime_len) {
		for (i = 0; i < prime_len; i++) {
			if (pubkey_x[i] < prime[i]) {
				cmp = -1;
				break;
			} else if (pubkey_x[i] > prime[i]) {
				cmp = 1;
				break;
			}
		}

		/* exactly equal */
		if (i == prime_len)
			cmp = 0;
	}

	if (cmp >= 0) {
		dao_err("Invalid ECC public key. pubkey_x must be in [0, p-1].");
		return -EINVAL;
	}

	/* Validate pubkey_y */
	cmp = -1;

	if (pubkey_y_len == prime_len) {
		for (i = 0; i < prime_len; i++) {
			if (pubkey_y[i] < prime[i]) {
				cmp = -1;
				break;
			} else if (pubkey_y[i] > prime[i]) {
				cmp = 1;
				break;
			}
		}

		if (i == prime_len)
			cmp = 0;
	}

	/* exactly equal */
	if (cmp >= 0) {
		dao_err("Invalid ECC public key. pubkey_y must be in [0, p-1].");
		return -EINVAL;
	}

	return 0;
}

int
cpt_ae_modex_msg_len_check(uint16_t mod_len, uint16_t msg_len)
{
	if ((msg_len == 0) || (msg_len > mod_len)) {
		dao_err("Invalid message length (%u). msg_len must be between 1 to %u bytes.",
			msg_len, mod_len);
		return -EINVAL;
	}

	return 0;
}

int
cpt_ae_modex_input_validate(const uint8_t *in, uint16_t in_len, const uint8_t *mod,
			    uint16_t mod_len)
{
	int cmp = -1;
	int i;

	if (!in || !mod || in_len == 0 || mod_len == 0) {
		dao_err("Invalid Modex input. NULL or zero length.");
		return -EINVAL;
	}

	if (in_len > mod_len) {
		dao_err("Invalid Modex input. Input length > modulus.");
		return -EINVAL;
	}

	if (in_len == mod_len) {
		for (i = 0; i < in_len; i++) {
			if (in[i] < mod[i]) {
				cmp = -1;
				break;
			} else if (in[i] > mod[i]) {
				cmp = 1;
				break;
			}
		}

		/* exactly equal */
		if (i == in_len)
			cmp = 0;
	}

	if (cmp >= 0) {
		dao_err("Invalid Modex input. Input must be less than modulus.");
		return -EINVAL;
	}

	return 0;
}
