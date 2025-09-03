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
		dao_err("Invalid message length. exp_len cannot be zero.");
		return -EINVAL;
	}

	if (exp_len > mod_len) {
		dao_err("Invalid message length. exp_len should be at most %u bytes.", mod_len);
		return -EINVAL;
	}

	return 0;
}

int
cpt_ae_rsa_msw_check(uint16_t plen, uint8_t *p)
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
cpt_ae_rsa_crt_params_check(uint16_t mod_len, uint8_t *q, uint8_t *dQ, uint8_t *p, uint8_t *dP,
			    uint8_t *qInv)
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
cpt_ec_curve_id_validate(enum dao_liquid_crypto_ec_curve_type curve_id)
{
	if (curve_id < DAO_LC_AE_EC_ID_P192 || curve_id > DAO_LC_AE_EC_ID_P512) {
		dao_err("Invalid curve ID. curve_id=%d (valid range: %d to %d).", curve_id,
			DAO_LC_AE_EC_ID_P192, DAO_LC_AE_EC_ID_P512);
		return -EINVAL;
	}
	return 0;
}

int
cpt_ae_ecdsa_nonce_len_check(uint16_t prime_len, uint16_t nonce_len)
{
	if (nonce_len == 0) {
		dao_err("Invalid nonce length. nonce_len cannot be zero.");
		return -EINVAL;
	}

	if (nonce_len != prime_len) {
		dao_err("Invalid nonce length. nonce_len should be  %u prime length bytes.",
			prime_len);
		return -EINVAL;
	}

	return 0;
}

int
cpt_ae_ecdsa_pkey_len_check(uint16_t prime_len, uint16_t pkey_len)
{
	if (pkey_len == 0) {
		dao_err("Invalid private key length. pkey_len cannot be zero.");
		return -EINVAL;
	}

	if (pkey_len != prime_len) {
		dao_err("Invalid private key length. pkey_len should be at most %u bytes.",
			prime_len);
		return -EINVAL;
	}

	return 0;
}

int
cpt_ae_ecdsa_pubkey_len_check(uint16_t prime_len, uint16_t pubkey_x_len, uint16_t pubkey_y_len)
{
	if ((pubkey_x_len == 0) || (pubkey_y_len == 0)) {
		dao_err("Invalid public key length. pubkey_x_len and pubkey_y_len cannot be zero.");
		return -EINVAL;
	}

	if ((pubkey_x_len > prime_len) || (pubkey_y_len > prime_len)) {
		dao_err("Invalid public key length. pubkey_x_len and pubkey_y_len should be at most %u bytes.",
			prime_len);
		return -EINVAL;
	}

	return 0;
}

int
cpt_ae_ecdsa_sign_comp_len_check(uint16_t prime_len, uint16_t r_len, uint16_t s_len)
{
	if ((r_len == 0) || (s_len == 0)) {
		dao_err("Invalid r and s sign components length. r and s canonot be zero.");
		return -EINVAL;
	}

	if ((r_len > prime_len) || (s_len > prime_len)) {
		dao_err("Invalid r and s sign components length. r and s should be at most %u bytes.",
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
	case DAO_LC_AE_EC_ID_P160:
		return DAO_LC_PRIME_LEN_P160;
	case DAO_LC_AE_EC_ID_P320:
		return DAO_LC_PRIME_LEN_P320;
	case DAO_LC_AE_EC_ID_P512:
		return DAO_LC_PRIME_LEN_P512;
	case DAO_LC_AE_EC_ID_SM2:
		return DAO_LC_PRIME_LEN_SM2;
	case DAO_LC_AE_EC_ID_ED25519:
		return DAO_LC_PRIME_LEN_ED25519;
	case DAO_LC_AE_EC_ID_ED448:
		return DAO_LC_PRIME_LEN_ED448;
	default:
		return -1;
	}
}
