/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef __DAO_LIQUID_CRYPTO_H__
#define __DAO_LIQUID_CRYPTO_H__

/**
 * @file dao_liquid_crypto.h
 *
 * This file contains the API for liquid crypto.
 */

#include <stdbool.h>
#include <stdint.h>

/** The maximum length of the version string. */
#define DAO_CRYPTO_VERSION_LEN 32
/** The maximum number of devices supported by the liquid crypto library. */
#define DAO_CRYPTO_MAX_NB_DEV 1
/** Use DAO_CMD_QP_IDX_INVALID as cmd_qp_idx value to disable command queue altogether. */
#define DAO_CMD_QP_IDX_INVALID 0xFFFF
/** Session ID returned as response if the session create request fails */
#define DAO_LC_SESS_ID_INVALID 0

/**
 * The liquid crypto buffer
 */
struct dao_lc_buf {
	/** The data buffer */
	void *data;
	/**< Total pkt len: sum of all segments. Need to be set only for the first segment. */
	uint32_t total_len;
	/** The length of the data buffer */
	uint32_t seg_len;
	/** Pointer to the next buffer */
	struct dao_lc_buf *next;
};

/**
 * The liquid crypto op structure.
 */
struct dao_lc_sym_op {
	/**
	 * The cookie to be associated with the operation. This cookie is returned in the
	 * *dao_crypto_res* structure when the operation is dequeued.
	 */
	uint64_t op_cookie;
	/** Session ID to be used. */
	uint64_t sess_id;
	/** Data buffer input for the operation */
	struct dao_lc_buf *in_buffer;
	/** Data buffer output for the operation. NULL value means in-place operation */
	struct dao_lc_buf *out_buffer;
	/** Cipher offset from beginning of buffer */
	uint32_t cipher_offset;
	/** Auth offset from beginning of buffer */
	uint32_t auth_offset;
	/** Cipher length */
	uint32_t cipher_len;
	/** Auth length */
	uint32_t auth_len;
	/** Cipher IV */
	uint8_t *cipher_iv;
	/** Auth IV */
	uint8_t *auth_iv;
	/** AAD. Ignored for non-AEAD operations. */
	uint8_t *aad;
	/** AAD length. Ignored for non-AEAD operations. */
	uint8_t aad_len;
	/** Digest. Ignored for non auth use cases. */
	uint8_t *digest;
	/** Operation. Whether the operation is Encrypt or Decrypt */
	bool encrypt;
};

/**
 * CPT hardware completion codes.
 */
enum dao_cpt_comp_code {
	/** Request not completed. */
	DAO_CPT_COMP_NOT_DONE = 0,
	/** Request completed successfully. */
	DAO_CPT_COMP_GOOD,
	/** CPT detected a memory fault. */
	DAO_CPT_COMP_FAULT,
	/** Microcode detected an illegal instruction. */
	DAO_CPT_COMP_SWERR,
	/** CPT detected an uncorrectable error. */
	DAO_CPT_COMP_HWERR,
	/** CPT detected an illegal instruction. */
	DAO_CPT_COMP_INSTERR,
	/** Request completed with a warning. */
	DAO_CPT_COMP_WARN
};

/**
 * CPT microcode completion codes.
 */
enum dao_uc_rsa_comp_code {
	/** Request completed. */
	DAO_UC_RSA_SUCCESS = 0x00,
	/** Scatter/Gather not supported. */
	DAO_UC_RSA_SG_NOT_SUPPORTED = 0x04,
	/** Invalid mod length. */
	DAO_UC_RSA_MOD_LEN_INVALID = 0x06,
	/** Mod length not even. */
	DAO_UC_RSA_MOD_LEN_NOT_EVEN = 0x09,
	/** PKCS decrypt incorrect. */
	DAO_UC_RSA_PKCS_DEC_INCORRECT = 0x0A
};

/**
 * The completion code returned by the CPT.
 */
union dao_cpt_res_s {
	/** CPT_RES_S for cn10k */
	struct cpt_cn10k_res_s {
		/**
		 * HW Completion code.
		 * @see enum dao_cpt_comp_code
		 */
		uint64_t compcode : 7;
		/** HW Done interrupt */
		uint64_t doneint : 1;
		/**
		 * Microcode Completion code.
		 * @see enum dao_uc_rsa_comp_code
		 */
		uint64_t uc_compcode : 8;
		/** Rlen */
		uint64_t rlen : 16;
		/** SPI from inbound IPsec operations */
		uint64_t spi : 32;

		/** ESN from inbound IPsec operations */
		uint64_t esn;
	} cn10k;

	/** CPT_RES_S for cn9k */
	struct cpt_cn9k_res_s {
		/**
		 * HW Completion code.
		 * @see enum dao_cpt_comp_code
		 */
		uint64_t compcode : 8;
		/**
		 * Microcode Completion code.
		 * @see enum dao_uc_rsa_comp_code
		 */
		uint64_t uc_compcode : 8;
		/** HW Done Interrupt */
		uint64_t doneint : 1;
		/** Reserved */
		uint64_t reserved_17_63 : 47;

		/** Reserved */
		uint64_t reserved_64_127;
	} cn9k;

	/** 2x 64-bit values */
	uint64_t u64[2];
};

/**
 * The liquid crypto information structure.
 */
struct dao_lc_info {
	/** The version of the liquid crypto library. */
	char version[DAO_CRYPTO_VERSION_LEN];
	/** The number of devices supported by the liquid crypto library. */
	uint8_t nb_dev;
	/** The number of queue pairs supported by the liquid crypto library. */
	uint16_t nb_qp[DAO_CRYPTO_MAX_NB_DEV];
};

/**
 * The liquid crypto device configuration structure.
 *
 * This structure is used to configure a liquid crypto device.
 */
struct dao_lc_dev_conf {
	/** The device identifier. Value must be between 0 and ``dao_lc_info.nb_dev`` - 1. */
	uint8_t dev_id;
	/** The number of queue pairs. */
	uint16_t nb_qp;
	/**
	 * Index of command queue pair.
	 * The application can disable the command queue by setting the cmd_qp_idx value
	 * to DAO_CMD_QP_IDX_INVALID.
	 */
	uint16_t cmd_qp_idx;
};

/**
 * The liquid crypto queue pair configuration structure.
 *
 * This structure is used to configure a liquid crypto queue pair.
 *
 */
struct dao_lc_qp_conf {
	/** Enable out of order delivery. */
	bool out_of_order_delivery_en;
	/**
	 * The number of descriptors in the queue pair. For performance benefits, the actual
	 * number of descriptors would be rounded up to a power of 2.
	 */
	uint16_t nb_desc;
	/** The maximum segment size. */
	uint16_t max_seg_size;
};

/**
 * The liquid crypto result structure.
 *
 * This structure is used to store the result of a liquid crypto operation.
 */
struct dao_lc_res {
	/** The result of the operation returned by CPT */
	union dao_cpt_res_s res;
	/** Additional metadata from the operation */
	union {
		/** Metadata associated with RSA operations */
		struct {
			/** The length of the output data */
			uint16_t data_out_len;
		} rsa;
		/** Generic 64-bit metadata */
		uint64_t u64;
	};
	/** The cookie associated with the operation */
	uint64_t op_cookie;
};

/**
 * The liquid crypto RSA key type.
 */
enum dao_liquid_crypto_rsa_key_type {
	/** Public key */
	DAO_LC_RSA_KEY_TYPE_PUBLIC,
	/** Private key */
	DAO_LC_RSA_KEY_TYPE_PRIVATE,
};

/**
 * The liquid crypto command event type.
 *
 * This enumeration defines the command event types supported by liquid crypto.
 * The command event type is used to indicate the type of command event.
 */
enum dao_lc_cmd_event_type {
	/** Event type for session create */
	DAO_LC_CMD_EVENT_SESS_CREATE = 0,
	/** Event type for session destroy */
	DAO_LC_CMD_EVENT_SESS_DESTROY = 1,
};

/**
 * The event structure for liquid crypto commands associated with a session.
 *
 * This structure defines the session event information.
 */
struct dao_lc_cmd_sess_event {
	/** The session ID */
	uint64_t sess_id;
	/** The cookie associated with the session operation */
	uint64_t sess_cookie;
};

/**
 * The liquid crypto command event structure.
 *
 * This structure defines the command event information.
 */
struct dao_lc_cmd_event {
	/** The event type */
	uint8_t event_type;
	union {
		/** Session event */
		struct dao_lc_cmd_sess_event sess_event;
	};
};

/**
 * The liquid crypto symmetric op code.
 *
 * This enumeration defines the symmetric operation codes supported by the microcode.
 */
enum dao_lc_sym_opcode {
	/** Opcode for Flexi Crypto */
	DAO_LC_SYM_OPCODE_FC = 0x33,
};

/**
 * The liquid crypto flexi crypto IV source.
 */
enum dao_lc_fc_iv_src {
	/** Flexi Crypto IV Source = CTX */
	DAO_LC_FC_IV_SRC_CTX = 0,
	/** Flexi Crypto IV Source = OP */
	DAO_LC_FC_IV_SRC_OP = 1
};

/**
 * The liquid crypto flexi crypto AES key length.
 */
enum dao_lc_fc_aes_key_len {
	/** Flexi Crypto AES Key Length = 128 */
	DAO_LC_FC_AES_KEY_LEN_128 = 1,
	/** Flexi Crypto AES Key Length = 192 */
	DAO_LC_FC_AES_KEY_LEN_192 = 2,
	/** Flexi Crypto AES Key Length = 256 */
	DAO_LC_FC_AES_KEY_LEN_256 = 3
};

/**
 * The liquid crypto flexi crypto encryption cipher.
 */
enum dao_lc_fc_enc_cipher {
	/** Flexi Crypto Encryption Cipher Type = NULL */
	DAO_LC_FC_ENC_CIPHER_NULL = 0,
	/** Flexi Crypto Encryption Cipher Type = 3DES-CBC */
	DAO_LC_FC_ENC_CIPHER_3DES_CBC = 1,
	/** Flexi Crypto Encryption Cipher Type = 3DES-ECB */
	DAO_LC_FC_ENC_CIPHER_3DES_ECB = 2,
	/** Flexi Crypto Encryption Cipher Type = AES-CBC */
	DAO_LC_FC_ENC_CIPHER_AES_CBC = 3,
	/** Flexi Crypto Encryption Cipher Type = AES-ECB */
	DAO_LC_FC_ENC_CIPHER_AES_ECB = 4,
	/** Flexi Crypto Encryption Cipher Type = AES-CFB */
	DAO_LC_FC_ENC_CIPHER_AES_CFB = 5,
	/** Flexi Crypto Encryption Cipher Type = AES-CTR */
	DAO_LC_FC_ENC_CIPHER_AES_CTR = 6,
	/** Flexi Crypto Encryption Cipher Type = AES-GCM */
	DAO_LC_FC_ENC_CIPHER_AES_GCM = 7,
	/** Flexi Crypto Encryption Cipher Type = AES-XTS */
	DAO_LC_FC_ENC_CIPHER_AES_XTS = 8,
	/** Flexi Crypto Encryption Cipher Type = ChaCha */
	DAO_LC_FC_ENC_CIPHER_CHACHA = 9,
	/** Flexi Crypto Encryption Cipher Type = AES-CCM */
	DAO_LC_FC_ENC_CIPHER_AES_CCM = 10,
};

/**
 * The liquid crypto flexi crypto authentication input type.
 */
enum dao_lc_fc_auth_input_type {
	/** Flexi Crypto Authentication Input Type = OPAD/IPAD */
	DAO_LC_FC_AUTH_INPUT_OPAD_IPAD = 0,
	/** Flexi Crypto Authentication Input Type = Key */
	DAO_LC_FC_AUTH_INPUT_KEY = 1
};

/**
 * The liquid crypto flexi crypto authentication key source.
 */
enum dao_lc_fc_auth_key_src {
	/** Flexi Crypto Authentication Key Source = CTX */
	DAO_LC_FC_AUTH_KEY_SRC_CTX = 0,
	/** Flexi Crypto Authentication Key Source = OP */
	DAO_LC_FC_AUTH_KEY_SRC_OP = 1,
};

/**
 * The liquid crypto flexi crypto hash type.
 */
enum dao_lc_fc_hash_type {
	/** Flexi Crypto Hash Type = NULL */
	DAO_LC_FC_HASH_TYPE_NULL = 0,
	/** Flexi Crypto Hash Type = MD5 */
	DAO_LC_FC_HASH_TYPE_MD5 = 1,
	/** Flexi Crypto Hash Type = SHA1 */
	DAO_LC_FC_HASH_TYPE_SHA1 = 2,
	/** Flexi Crypto Hash Type = SHA2-SHA224 */
	DAO_LC_FC_HASH_TYPE_SHA2_SHA224 = 3,
	/** Flexi Crypto Hash Type = SHA2-SHA256 */
	DAO_LC_FC_HASH_TYPE_SHA2_SHA256 = 4,
	/** Flexi Crypto Hash Type = SHA2-SHA384 */
	DAO_LC_FC_HASH_TYPE_SHA2_SHA384 = 5,
	/** Flexi Crypto Hash Type = SHA2-SHA512 */
	DAO_LC_FC_HASH_TYPE_SHA2_SHA512 = 6,
	/** Flexi Crypto Hash Type = GMAC */
	DAO_LC_FC_HASH_TYPE_GMAC = 7,
	/** Flexi Crypto Hash Type = POLY1305 */
	DAO_LC_FC_HASH_TYPE_POLY1305 = 8,
};

/**
 * The liquid crypto flexi crypto context.
 */
struct dao_lc_sym_fc_ctx {
	/**
	 * Encr_IV_Source: IV source for the operation.
	 * @see enum dao_lc_fc_iv_src
	 *
	 * Must be set to DAO_LC_FC_IV_SRC_OP
	 */
	uint64_t iv_source : 1;
	/**
	 * AES_key_len (when enc_cipher = AES*, else ignored)
	 * @see enum dao_lc_fc_aes_key_len
	 */
	uint64_t aes_key_len : 2;
	/** Reserved Bit 59 */
	uint64_t rsvd_59 : 1;
	/**
	 * Encr_cipher_type: Encryption cipher type
	 * @see enum dao_lc_fc_enc_cipher
	 */
	uint64_t enc_cipher : 4;
	/**
	 * Auth_input_type: Authentication key input type
	 * @see enum dao_lc_fc_auth_input_type
	 *
	 * Must be set to DAO_LC_FC_AUTH_INPUT_OPAD_IPAD
	 */
	uint64_t auth_input_type : 1;
	/**
	 * Auth_key_source: Authentication key source
	 * @see enum dao_lc_fc_auth_key_src
	 *
	 * Must be set to DAO_LC_FC_AUTH_KEY_SRC_CTX
	 */
	uint64_t auth_key_src : 1;
	/** Reserved Bit 50-51 */
	uint64_t rsvd_50_51 : 2;
	/**
	 * MAC_Select: Authentication algorithm
	 * @see enum dao_lc_fc_hash_type
	 */
	uint64_t hash_type : 4;
	/** MAC_Len (MAC_Len ranges from 1 to MAC length of the respective MAC algorithm) */
	uint64_t mac_len : 8;
	/** Reserved Bit 16-39 */
	uint64_t rsvd_16_39 : 24;
	/** HMAC_Key_Size: Key size (valid for HMAC only; auth_input_type must be 1). */
	uint64_t hmac_key_sz : 16;
	/** Encr_Key or KEY1 for AES-XTS or ChaCha key. */
	uint8_t encr_key[32];
	/** Encr_IV or Tweak for AES-XTS. Set to 0 when Encrypt_IV_Source == 1 and not AES_GCM. */
	uint8_t encr_iv[16];
	/** IPAD or KEY2 for AES-XTS. */
	uint8_t ipad[64];
	/**
	 * OPAD or Key (Authentication key; supported range is 1 to 64 bytes. Application should
	 * take care of padding with zeroes if the key is less than 64 bytes.)
	 */
	uint8_t opad[64];
};

/**
 * The liquid crypto symmetric context.
 */
struct dao_lc_sym_ctx {
	/** The operation code */
	enum dao_lc_sym_opcode opcode;
	union {
		/** Flexi Crypto context */
		struct dao_lc_sym_fc_ctx fc;
	};
};

/**
 * Initialize liquid crypto.
 *
 * This function initializes the liquid crypto library. This API must be called
 * before any other liquid crypto API and must be called after calling
 * rte_eal_init().
 *
 * @return
 * - On success, 0 is returned.
 * - On failure, a negative value is returned indicating the cause
 */
int dao_liquid_crypto_init(void);

/**
 * Cleanup liquid crypto.
 *
 * This function cleans up the liquid crypto library.
 *
 * @return
 * - On success, 0 is returned.
 * - On failure, a negative value is returned indicating the cause
 */
int dao_liquid_crypto_fini(void);

/**
 * Get liquid crypto information.
 *
 * This function retrieves the liquid crypto information.
 *
 * @param info [out]
 * A pointer to the liquid crypto information structure.
 *
 * @return
 * - On success, 0 is returned.
 * - On failure, a negative value is returned indicating the cause
 */
int dao_liquid_crypto_info_get(struct dao_lc_info *info);

/**
 * Create a liquid crypto device.
 *
 * This function creates a liquid crypto device.
 *
 * @param conf
 * A pointer to the liquid crypto device configuration structure.
 *
 * @return
 * - On success, 0 is returned.
 * - On failure, a negative value is returned indicating the cause
 */
int dao_liquid_crypto_dev_create(struct dao_lc_dev_conf *conf);

/**
 * Destroy a liquid crypto device.
 *
 * This function destroys a liquid crypto device. The device must be stopped
 * before it can be destroyed.
 *
 * @param dev_id
 * The device identifier.
 *
 * @return
 * - On success, 0 is returned.
 * - On failure, a negative value is returned indicating the cause
 */
int dao_liquid_crypto_dev_destroy(uint8_t dev_id);

/**
 * Configure a liquid crypto queue pair.
 *
 * This function configures a liquid crypto queue pair. Queue pairs can be
 * configured only when the device is stopped.
 *
 * @param dev_id
 * The device identifier. Value must between 0 and
 * ``dao_lc_info.nb_dev`` - 1.
 * @param qp_id
 * The queue pair identifier. Value must between 0 and
 * ``dao_lc_info.nb_qp[dev_id]`` - 1.
 * @param conf
 * A pointer to the liquid crypto queue pair configuration structure.
 * @return
 * - On success, 0 is returned.
 * - On failure, a negative value is returned indicating the cause
 */
int dao_liquid_crypto_qp_configure(uint8_t dev_id, uint16_t qp_id, struct dao_lc_qp_conf *conf);

/**
 * Start a liquid crypto device.
 *
 * This function starts a liquid crypto device. The device must be created
 * before it can be started.
 *
 * @param dev_id
 * The device identifier.
 * @return
 * - On success, 0 is returned.
 * - On failure, a negative value is returned indicating the cause
 */
int dao_liquid_crypto_dev_start(uint8_t dev_id);

/**
 * Stop a liquid crypto device.
 *
 * This function stops a liquid crypto device.
 *
 * @param dev_id
 * The device identifier.
 * @return
 * - On success, 0 is returned.
 * - On failure, a negative value is returned indicating the cause
 */
int dao_liquid_crypto_dev_stop(uint8_t dev_id);

/**
 * Enqueue passthrough operation to the liquid crypto device.
 *
 * @param dev_id
 * The identifier of the device.
 * @param qp_id
 * The index of the queue pair on which the operation is to be enqueued.
 * @param op_cookie
 * The cookie to be associated with the operation. This cookie is returned
 * in the *dao_lc_res* structure when the operation is dequeued.
 */
int dao_liquid_crypto_enqueue_op_passthrough(uint8_t dev_id, uint16_t qp_id, uint64_t op_cookie);

/**
 * Enqueue request to perform RSA encrypt operation on the crypto device.
 *
 * @param dev_id
 *  The identifier of the device.
 * @param qp_id
 *  The index of the queue pair on which the operation is to be enqueued.
 * @param key_type
 *  The type of RSA key to be used.
 * @param mod_len
 *  The length of the modulus.
 * @param exp_len
 *  The length of the exponent.
 * @param msg_len
 *  The length of the message.
 * @param mod
 *  The address of the buffer containing the modulus.
 * @param exp
 *  The address of the buffer containing the exponent.
 * @param msg
 *  The address of the buffer containing the message.
 * @param em
 *  The address of the buffer where the encrypted message is to be stored.
 * @param op_cookie
 *  The cookie to be associated with the operation. This cookie is returned
 *  in the *dao_crypto_res* structure when the operation is dequeued.
 *
 * @return
 *  0 on success, negative value on failure.
 */
int dao_crypto_enqueue_op_pkcs1v15enc(uint8_t dev_id, uint16_t qp_id,
				      enum dao_liquid_crypto_rsa_key_type key_type,
				      uint16_t mod_len, uint16_t exp_len, uint16_t msg_len,
				      uint8_t *mod, uint8_t *exp, uint8_t *msg, uint8_t *em,
				      uint64_t op_cookie);

/**
 * Enqueue request to perform RSA decrypt operation on the crypto device.
 *
 * @param dev_id
 *  The identifier of the device.
 * @param qp_id
 *  The index of the queue pair on which the operation is to be enqueued.
 * @param key_type
 *  The type of RSA key to be used.
 * @param mod_len
 *  The length of the modulus.
 * @param exp_len
 *  The length of the exponent.
 * @param mod
 *  The address of the buffer containing the modulus.
 * @param exp
 *  The address of the buffer containing the exponent.
 * @param em
 *  The address of the buffer containing the encrypted message. Length of this
 *  buffer must be at least *mod_len* bytes.
 * @param msg
 *  The address of the buffer where the decrypted message is to be stored.
 * @param op_cookie
 *  The cookie to be associated with the operation. This cookie is returned
 *  in the *dao_crypto_res* structure when the operation is dequeued.
 *
 * @return
 *  0 on success, negative value on failure.
 */
int dao_crypto_enqueue_op_pkcs1v15dec(uint8_t dev_id, uint16_t qp_id,
				      enum dao_liquid_crypto_rsa_key_type key_type,
				      uint16_t mod_len, uint16_t exp_len, uint8_t *mod,
				      uint8_t *exp, uint8_t *em, uint8_t *msg, uint64_t op_cookie);

/**
 * Enqueue request to perform RSA CRT encrypt operation on the crypto device.
 *
 * @param dev_id
 *  The identifier of the device.
 * @param qp_id
 *  The index of the queue pair on which the operation is to be enqueued.
 * @param mod_len
 *  The length of the modulus. Value must be even and should be at least 34 bytes
 *  and at most 1024 bytes.
 * @param msg_len
 *  The length of the message in bytes. Value must be at most mod_len - 11.
 * @param q
 *  The address of the buffer containing the first factor. Length of this buffer
 *  must be mod_len/2 bytes and the value must be odd.
 * @param dQ
 *  The address of the buffer containing the first factor's CRT exponent. Length
 *  of this buffer must be mod_len/2 bytes.
 * @param p
 *  The address of the buffer containing the second factor. Length of this
 *  buffer must be mod_len/2 bytes and the value must be odd.
 * @param dP
 *  The address of the buffer containing the second factor's CRT exponent.
 *  Length of this buffer must be mod_len/2 bytes.
 * @param qInv
 *  The address of the buffer containing the CRT coefficient. Length of this
 *  buffer must be mod_len/2 bytes.
 * @param msg
 *  The address of the buffer containing the message.
 * @param em
 *  The address of the buffer where the encrypted message is to be stored.
 * @param op_cookie
 *  The cookie to be associated with the operation. This cookie is returned
 *  in the *dao_crypto_res* structure when the operation is dequeued.
 *
 * @return
 *  0 on success, negative value on failure.
 */
int dao_crypto_enqueue_op_pkcs1v15enc_crt(uint8_t dev_id, uint16_t qp_id, uint16_t mod_len,
					  uint16_t msg_len, uint8_t *q, uint8_t *dQ, uint8_t *p,
					  uint8_t *dP, uint8_t *qInv, uint8_t *msg, uint8_t *em,
					  uint64_t op_cookie);

/**
 * Enqueue request to perform RSA CRT decrypt operation on the crypto device.
 *
 * @param dev_id
 *  The identifier of the device.
 * @param qp_id
 *  The index of the queue pair on which the operation is to be enqueued.
 * @param mod_len
 *  The length of the modulus in bytes. Value must be even and should be at least
 *  34 bytes and at most 1024 bytes.
 * @param q
 *  The address of the buffer containing the first factor. Length of this buffer
 *  must be mod_len/2 bytes and the value must be odd.
 * @param dQ
 *  The address of the buffer containing the first factor's CRT exponent. Length
 *  of this buffer must be mod_len/2 bytes.
 * @param p
 *  The address of the buffer containing the second factor. Length of this
 *  buffer must be mod_len/2 bytes and the value must be odd.
 * @param dP
 *  The address of the buffer containing the second factor's CRT exponent.
 *  Length of this buffer must be mod_len/2 bytes.
 * @param qInv
 *  The address of the buffer containing the CRT coefficient. Length of this
 *  buffer must be mod_len/2 bytes.
 * @param em
 *  The address of the buffer containing the encrypted message.
 * @param msg
 *  The address of the buffer where the decrypted message is to be stored.
 * @param op_cookie
 *  The cookie to be associated with the operation. This cookie is returned
 *  in the *dao_crypto_res* structure when the operation is dequeued.
 *
 * @return
 *  0 on success, negative value on failure.
 */
int dao_crypto_enqueue_op_pkcs1v15dec_crt(uint8_t dev_id, uint16_t qp_id, uint16_t mod_len,
					  uint8_t *q, uint8_t *dQ, uint8_t *p, uint8_t *dP,
					  uint8_t *qInv, uint8_t *em, uint8_t *msg,
					  uint64_t op_cookie);

/**
 * Enqueue a burst of requests to perform symmetric crypto operations on the
 * crypto device.
 *
 * @param dev_id
 *  The identifier of the device.
 * @param qp_id
 *  The index of the queue pair on which the operations are to be enqueued.
 * @param op
 *  The array of pointers to *dao_lc_sym_op* structures containing the operations
 *  to be enqueued.
 * @param nb_ops
 *  The number of operations to enqueue.
 *
 * @return
 *  The number of operations enqueued.
 */
uint16_t dao_liquid_crypto_sym_enqueue_burst(uint8_t dev_id, uint16_t qp_id,
					     struct dao_lc_sym_op *op, uint16_t nb_ops);

/**
 * Dequeue burst of crypto operations from the crypto device.
 *
 * @param dev_id
 * The identifier of the device.
 * @param qp_id
 * The index of the queue pair on which ops are to be dequeued.
 * @param res [out]
 * The array of pointers to *dao_lc_res* structures where the results
 * of the operations are stored.
 * @param nb_ops
 * The maximum number of operations to dequeue.
 *
 * @return
 * The number of operations dequeued.
 */
uint16_t dao_liquid_crypto_dequeue_burst(uint8_t dev_id, uint16_t qp_id, struct dao_lc_res *res,
					 uint16_t nb_ops);

/**
 * Create a symmetric session on the liquid crypto device.
 *
 * The session create request would be submitted via the command queue designated by cmd_qp_idx
 * of the device.
 *
 * @param dev_id
 * The identifier of the device.
 * @param ctx
 * The symmetric context.
 * @param sess_cookie
 * The cookie to be associated with the operation. This cookie is returned in the
 * *dao_lc_cmd_sess_event* structure when the operation is dequeued. The session ID of the session
 * created would be returned in the *dao_lc_cmd_sess_event* structure.
 *
 * @return
 * - On success, 0 is returned.
 * - On failure, a negative value is returned indicating the cause
 */
int dao_liquid_crypto_sym_sess_create(uint8_t dev_id, const struct dao_lc_sym_ctx *ctx,
				      uint64_t sess_cookie);

/**
 * Destroy a symmetric session on the liquid crypto device.
 *
 * The session destroy request would be submitted via the command queue designated by cmd_qp_idx
 * of the device.
 *
 * @param dev_id
 * The identifier of the device.
 * @param sess_id
 * The session identifier.
 * @param sess_cookie
 * The cookie to be associated with the operation. This cookie is returned in the
 * *dao_lc_sess_event* structure when the operation is dequeued.
 *
 * @return
 * - On success, 0 is returned.
 * - On failure, a negative value is returned indicating the cause
 */
int dao_liquid_crypto_sym_sess_destroy(uint8_t dev_id, uint64_t sess_id, uint64_t sess_cookie);

/**
 * Dequeue burst of command events from the command queue.
 *
 * @param dev_id
 * The identifier of the device.
 * @param events
 * The array of pointers to *dao_lc_cmd_event* structures where the command events
 * can be stored.
 * @param nb_events
 * The maximum number of command events to dequeue.
 * @return
 * The number of command events dequeued.
 */
uint16_t dao_liquid_crypto_cmd_event_dequeue(uint8_t dev_id, struct dao_lc_cmd_event *events,
					     uint16_t nb_events);

#endif /* __DAO_LIQUID_CRYPTO_H__ */
