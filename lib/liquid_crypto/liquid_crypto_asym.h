/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef __LIQUID_CRYPTO_ASYM_H__
#define __LIQUID_CRYPTO_ASYM_H__

#include <stdbool.h>
#include <stdint.h>

#define CPT_AE_EC_DATA_MAX                66
#define CPT_AE_RSA_OAEP_CONTROL_WORD_SIZE 8

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
};

struct cpt_ae_ec_group {
	struct {
		/* P521 maximum length */
		uint8_t data[CPT_AE_EC_DATA_MAX];
		unsigned int length;
	} prime;

	struct {
		/* P521 maximum length */
		uint8_t data[CPT_AE_EC_DATA_MAX];
		unsigned int length;
	} order;
};

int cpt_ae_rsa_mod_len_check(uint16_t mod_len, bool is_crt);

int cpt_ae_rsa_msg_len_check(uint16_t mod_len, uint16_t msg_len);

int cpt_ae_rsa_exp_len_check(uint16_t mod_len, uint16_t exp_len);

int cpt_ae_rsa_msw_check(uint16_t plen, const uint8_t *p);

int cpt_ae_rsa_crt_params_check(uint16_t mod_len, const uint8_t *q, const uint8_t *dQ,
				const uint8_t *p, const uint8_t *dP, const uint8_t *qInv);

int cpt_ec_curve_id_validate(enum dao_liquid_crypto_ec_curve_type curve_id);

int cpt_ae_ecdsa_pkey_len_check(uint16_t prime_len, uint16_t pkey_len);

int cpt_ae_ecdsa_pubkey_len_check(uint16_t prime_len, uint16_t pubkey_x_len, uint16_t pubkey_y_len);

int ecc_curve_id_to_prime_len(enum dao_liquid_crypto_ec_curve_type curve_id);

void cpt_ae_modex_param_normalize(uint8_t **data, uint16_t *len);

int cpt_ae_ecdsa_sign_comp_len_check(uint16_t prime_len, uint16_t r_len, uint16_t s_len);

int cpt_ae_ecdsa_digest_len_check(uint16_t prime_len, uint16_t digest_len);

int cpt_ae_ecdsa_pkey_validate(uint16_t pkey_len, const uint8_t *pkey,
			       enum dao_liquid_crypto_ec_curve_type curve_id);

int cpt_ae_ecdsa_pubkey_validate(uint16_t pubkey_x_len, const uint8_t *pubkey_x,
				 uint16_t pubkey_y_len, const uint8_t *pubkey_y,
				 enum dao_liquid_crypto_ec_curve_type curve_id);

int cpt_ae_oaep_msg_and_mod_len_check(uint16_t mod_len, uint16_t msg_len,
				      enum dao_lc_hash_type hash_type);

int cpt_ae_rsa_oaep_label_len_check(uint8_t *label, uint16_t label_len);

int cpt_ae_rsa_oaep_hash_type_check(enum dao_lc_hash_type hash_type);

int cpt_ae_rsa_oaep_get_hash_len(enum dao_lc_hash_type hash_type);

int cpt_ae_rsa_oaep_label_validate(uint8_t *label, uint16_t label_len);

int cpt_ae_rsa_oaep_msg_len_max(uint16_t mod_len, enum dao_lc_hash_type hash_type);

int cpt_ae_rsa_oaep_mod_len_check(uint16_t mod_len, bool is_crt);

int cpt_ae_modex_msg_len_check(uint16_t mod_len, uint16_t msg_len);

int cpt_ae_modex_input_validate(const uint8_t *in, uint16_t in_len, const uint8_t *mod,
				uint16_t mod_len);

#endif /* __LIQUID_CRYPTO_ASYM_H__ */
