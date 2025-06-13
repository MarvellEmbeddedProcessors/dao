/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef __LIQUID_CRYPTO_ASYM_H__
#define __LIQUID_CRYPTO_ASYM_H__

#include <stdbool.h>
#include <stdint.h>

/**
 * The liquid crypto supported elliptic curves
 */
enum dao_liquid_crypto_ec_curve_type {
	/* Elliptic curve identifier for P-192 (secp192r1) */
	DAO_LC_AE_EC_ID_P192 = 0,
	/* Elliptic curve identifier for P-224 (secpr224r1) */
	DAO_LC_AE_EC_ID_P224 = 1,
	/* Elliptic curve identifier for P-256 (secpr256r1) */
	DAO_LC_AE_EC_ID_P256 = 2,
	/* Elliptic curve identifier for P-384 (secpr384r1) */
	DAO_LC_AE_EC_ID_P384 = 3,
	/* Elliptic curve identifier for P-521 (secpr521r1) */
	DAO_LC_AE_EC_ID_P521 = 4,
	/** Elliptic curve identifier for P-160 (secp160r1) */
	DAO_LC_AE_EC_ID_P160 = 5,
	/** Elliptic curve identifier for P-320 (secp320r1) */
	DAO_LC_AE_EC_ID_P320 = 6,
	/** Elliptic curve identifier for P-512 (secp512r1) */
	DAO_LC_AE_EC_ID_P512 = 7,
	/** Elliptic curve identifier for SM2 */
	DAO_LC_AE_EC_ID_SM2 = 8,
	/** Elliptic curve identifier for Ed25519 */
	DAO_LC_AE_EC_ID_ED25519 = 9,
	/** Elliptic curve identifier for Ed448 */
	DAO_LC_AE_EC_ID_ED448 = 10,
	/** Maximum value for elliptic curve identifier */
	DAO_LC_AE_EC_ID_PMAX
};

/**
 * Prime length (in bytes) for each supported EC curve type.
 */
enum dao_lc_ec_curve_prime_len_bytes {
	/** Prime length for P-192 curve (24 bytes) */
	DAO_LC_PRIME_LEN_P192 = 24,
	/** Prime length for P-224 curve (28 bytes) */
	DAO_LC_PRIME_LEN_P224 = 28,
	/** Prime length for P-256 curve (32 bytes) */
	DAO_LC_PRIME_LEN_P256 = 32,
	/** Prime length for P-384 curve (48 bytes) */
	DAO_LC_PRIME_LEN_P384 = 48,
	/** Prime length for P-521 curve (66 bytes) */
	DAO_LC_PRIME_LEN_P521 = 66,
	/** Prime length for P-160 curve (20 bytes) */
	DAO_LC_PRIME_LEN_P160 = 20,
	/** Prime length for P-320 curve (40 bytes) */
	DAO_LC_PRIME_LEN_P320 = 40,
	/** Prime length for P-512 curve (64 bytes) */
	DAO_LC_PRIME_LEN_P512 = 64,
	/** Prime length for SM2 curve (32 bytes) */
	DAO_LC_PRIME_LEN_SM2 = 32,
	/** Prime length for Ed25519 curve (32 bytes) */
	DAO_LC_PRIME_LEN_ED25519 = 32,
	/** Prime length for Ed448 curve (56 bytes) */
	DAO_LC_PRIME_LEN_ED448 = 56,
};

/**
 * The liquid crypto ECDSA operation type.
 */
enum dao_lc_ecdsa_sign_type {
	/** ECDSA sign operation */
	DAO_LC_AE_ECDSA_SIGN = 1,
	/** ECDSA verify operation */
	DAO_LC_AE_ECDSA_VERIFY = 2,
};

int cpt_ae_rsa_mod_len_check(uint16_t mod_len, bool is_crt);

int cpt_ae_rsa_msg_len_check(uint16_t mod_len, uint16_t msg_len);

int cpt_ae_rsa_exp_len_check(uint16_t mod_len, uint16_t exp_len);

int cpt_ae_rsa_msw_check(uint16_t plen, uint8_t *p);

int cpt_ae_rsa_crt_params_check(uint16_t mod_len, uint8_t *q, uint8_t *dQ, uint8_t *p, uint8_t *dP,
				uint8_t *qInv);

int dao_liquid_crypto_ec_curve_id_valid(enum dao_liquid_crypto_ec_curve_type curve_id);

int cpt_ae_ecdsa_nonce_len_check(uint16_t prime_len, uint16_t nonce_len);

int cpt_ae_ecdsa_digest_len_check(uint16_t prime_len, uint16_t digest_len);

int cpt_ae_ecdsa_pkey_len_check(uint16_t prime_len, uint16_t pkey_len);

int cpt_ae_ecdsa_pubkey_len_check(uint16_t prime_len, uint16_t pubkey_x_len, uint16_t pubkey_y_len);

int ecc_curve_id_to_prime_len(enum dao_liquid_crypto_ec_curve_type curve_id);

void cpt_ae_modex_param_normalize(uint8_t **data, uint16_t *len);

#endif /* __LIQUID_CRYPTO_ASYM_H__ */
