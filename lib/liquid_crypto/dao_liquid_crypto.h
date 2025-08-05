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

#include <dao_eth_trs.h>

/** The version of the liquid crypto library */
#define DAO_LC_VERSION "25.09.1"
/** The maximum length of the version string. */
#define DAO_CRYPTO_VERSION_LEN 32
/** The maximum number of devices supported by the liquid crypto library. */
#define DAO_CRYPTO_MAX_NB_DEV 1
/** Use DAO_CMD_QP_IDX_INVALID as cmd_qp_idx value to disable command queue altogether. */
#define DAO_CMD_QP_IDX_INVALID 0xFFFF
/** Session ID returned as response if the session create request fails */
#define DAO_LC_SESS_ID_INVALID 0
/** Session ID returned as response if the session create is for HASH operation */
#define DAO_LC_SESS_ID_HASH 1
/** Session ID returned as response if the session create is for AES Key Wrap operation */
#define DAO_LC_SESS_ID_AES_KEY_WRAP 2
/** Maximum digest length */
#define DAO_LC_MAX_DIGEST_LEN 255
/** Maximum authentication key */
#define DAO_LC_MAX_AUTH_KEY_LEN 1024
/** Maximum key data supported for key wrap */
#define DAO_LC_AES_KEY_WRAP_MAX_KEY_DATA_LEN 3072
/** Maximum size of key encryption key for AES Key Wrap */
#define DAO_LC_AES_MAX_KEY_ENC_KEY_LEN 32
/** AES Key Wrap IV length */
#define DAO_LC_AES_KEY_WRAP_IV_LEN 8

/**
 * The liquid crypto buffer
 */
struct dao_lc_buf {
	/** The data buffer */
	void *data;
	/** Total pkt len: sum of all fragments. Need to be set only for the first fragment. */
	uint32_t total_len;
	/** The length of the data buffer */
	uint32_t frag_len;
	/** Pointer to the next buffer */
	struct dao_lc_buf *next;
};

/**
 * The liquid crypto op structure.
 */
/* Structure dao_lc_sym_op 8< */
struct dao_lc_sym_op {
	/**
	 * The cookie to be associated with the operation. This cookie is returned in the
	 * *dao_lc_res* structure when the operation is dequeued.
	 */
	uint64_t op_cookie;
	/** Session ID to be used. */
	uint64_t sess_id;
	/**
	 * Data buffer input for the operation. The memory pointed to by in_buffer must remain
	 * valid until the operation is completed and dequeued by the application using
	 * dao_liquid_crypto_dequeue_burst().
	 */
	struct dao_lc_buf *in_buffer;
	/**
	 * Data buffer output for the operation. NULL value means in-place operation.
	 * The memory pointed to by out_buffer must remain valid until the operation is
	 * completed and dequeued by the application using dao_liquid_crypto_dequeue_burst().
	 */
	struct dao_lc_buf *out_buffer;
	/**
	 * Starting point for cipher processing, specified as number of bytes from start of data in
	 * the input buffer. The result of the cipher operation will be written back into the
	 * output buffer starting at this location.
	 */
	uint32_t cipher_offset;
	/**
	 * Length of data to be ciphered, specified as number of bytes from the cipher_offset
	 * in the input buffer.
	 *
	 * For block ciphers, the cipher length must be aligned with the block size of the
	 * cipher type. It is the application's responsibility to ensure the cipher length
	 * meets this alignment requirement.
	 */
	uint32_t cipher_len;
	/**
	 * Starting point for auth processing, specified as number of bytes from start of data in
	 * the input buffer.
	 */
	uint32_t auth_offset;
	/**
	 * Length of data to be authenticated, specified as number of bytes from the
	 * auth_offset in the input buffer.
	 */
	uint32_t auth_len;
	/** Cipher IV */
	uint8_t *cipher_iv;
	/** Auth IV */
	uint8_t *auth_iv;
	/** AAD. Ignored for non-AEAD operations. */
	uint8_t *aad;
	/** AAD length. Ignored for non-AEAD operations. */
	uint16_t aad_len;
	/** Digest. Ignored for non auth use cases. */
	uint8_t *digest;
	/**
	 * Length of the key data to be wrapped or unwrapped in bytes.
	 * For AES Key Wrap operations:
	 * - Must be a multiple of 8 bytes for standard AES-KW
	 * - Can be any length for AES-KWP (with padding)
	 * - Must not be zero length bytes
	 * - Must not exceed DAO_LC_AES_KEY_WRAP_MAX_KEY_DATA_LEN
	 * Ignored for non-key wrap operations.
	 */
	uint32_t wrap_unwrap_key_len;
	/** Type of operation */
	union {
		/** Is encrypt operation or decrypt operation. */
		bool encrypt;
		/** Is auth generate or auth verify. Used in case of auth-only operations. */
		bool auth_gen;
		/** Is key wrap or unwrap operation. */
		bool is_wrap;
	};
};
/* >8 End of structure dao_lc_sym_op. */

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
 * Completion codes returned by CPT microcode.
 */
enum dao_uc_comp_code {
	/** Request completed with no error. */
	DAO_UC_SUCCESS = 0x00,
	/** Scatter/Gather not supported. */
	DAO_UC_RSA_SG_NOT_SUPPORTED = 0x04,
	/** Invalid mod length. */
	DAO_UC_RSA_MOD_LEN_INVALID = 0x06,
	/** Mod length not even. */
	DAO_UC_RSA_MOD_LEN_NOT_EVEN = 0x09,
	/** PKCS decrypt incorrect. */
	DAO_UC_RSA_PKCS_DEC_INCORRECT = 0x0A,

	/** ECDSA sign/verify error codes */
	/** Invalid private and hash and random key length */
	DAO_UC_ECC_DATA_LEN_INVALID = 0x08,
	/** ECC point at infinity */
	DAO_UC_ECC_PAI = 0x0b,
	/** Invalid ECC curve */
	DAO_UC_ECC_CURVE_INVALID = 0x0c,
	/** Invalid ECDSA sign r component */
	DAO_UC_ECC_SIGN_R_INVALID = 0x0d,
	/** Invalid ECDSA sign s component */
	DAO_UC_ECC_SIGN_S_INVALID = 0x0e,
	/** ECC signature mismatch */
	DAO_UC_ECC_VERIFY_MISMATCH = 0x0f,
	/** Public key point not on curve */
	DAO_UC_ECC_PUB_KEY_INVALID = 0x11,

	/** SE GC */
	/** Invalid data length. */
	DAO_UC_ERR_GC_DATA_LEN_INVALID = 0x43,
	/** Invalid context length. */
	DAO_UC_ERR_GC_CTX_LEN_INVALID = 0x45,
	/** Unsupported cipher select or, if CRC32 is enabled, cipher_type must be NULL. */
	DAO_UC_ERR_GC_CIPHER_UNSUPPORTED = 0x46,
	/**
	 * Unsupported auth type or, if CRC32 is enabled, auth_type must be NULL, or when
	 * auth_type is Poly1305, cipher select is other than ChaCha or Null.
	 */
	DAO_UC_ERR_GC_AUTH_UNSUPPORTED = 0x47,
	/** Invalid offset. */
	DAO_UC_ERR_GC_OFFSET_INVALID = 0x48,
	/** Authentication data (MAC) or CRC32 mismatch. */
	DAO_UC_ERR_GC_ICV_MISCOMPARE = 0x4c,
	/** Encrypt length unaligned when MAC_Select is valid. */
	DAO_UC_ERR_GC_DATA_UNALIGNED = 0x4d,
	/** Invalid key length; Applicable for HMAC and AES-KW and AES-KWP */
	DAO_UC_ERR_GC_KEY_LEN_INVALID = 0x4e
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
		 * @see enum dao_uc_comp_code.
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
		 * @see enum dao_uc_comp_code
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
	/**
	 * The maximum segment size. Sum of size of all buffers passed to the API must not
	 * exceed this value.
	 *
	 * In case of symmetric crypto operations, the maximum segment size is calculated based on
	 * the following parameters:
	 * - Total length of all fragments in the input buffer.
	 * - Length of IV (if applicable).
	 * - Length of AAD (if applicable).
	 * - Length of digest (if applicable).
	 */
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
		/** Metadata associated with ECDSA operations */
		struct {
			/**< Length of the ECDSA r and s components */
			uint16_t ecc_rs_out_len;
		} ecdsa;
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
	/** Opcode for HASH */
	DAO_LC_SYM_OPCODE_HASH = 0x34,
	/** Opcode for HMAC */
	DAO_LC_SYM_OPCODE_HMAC = 0x35,
	/** Opcode for AES Key Wrap */
	DAO_LC_SYM_OPCODE_AES_KEY_WRAP = 0x1D,
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
	/**
	 * Flexi Crypto Encryption Cipher Type = ChaCha
	 * Cipher Type ChaCha exclusively supports 256-bit keys only.
	 */
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
 * The liquid crypto hash type.
 */
enum dao_lc_hash_type {
	/** Hash Type = NULL */
	DAO_LC_HASH_TYPE_NULL = 0,
	/** Hash Type = MD5 */
	DAO_LC_HASH_TYPE_MD5 = 1,
	/** Hash Type = SHA1 */
	DAO_LC_HASH_TYPE_SHA1 = 2,
	/** Hash Type = SHA2-SHA224 */
	DAO_LC_HASH_TYPE_SHA2_SHA224 = 3,
	/** Hash Type = SHA2-SHA256 */
	DAO_LC_HASH_TYPE_SHA2_SHA256 = 4,
	/** Hash Type = SHA2-SHA384 */
	DAO_LC_HASH_TYPE_SHA2_SHA384 = 5,
	/** Hash Type = SHA2-SHA512 */
	DAO_LC_HASH_TYPE_SHA2_SHA512 = 6,
	/** Hash Type = GMAC */
	DAO_LC_HASH_TYPE_GMAC = 7,
	/** Hash Type = POLY1305 */
	DAO_LC_HASH_TYPE_POLY1305 = 8,
	/** Hash Type = SM3 */
	DAO_LC_HASH_TYPE_SM3 = 9,
	/** Hash Type = SHA3-SHA224 */
	DAO_LC_HASH_TYPE_SHA3_SHA224 = 10,
	/** Hash Type = SHA3-SHA256 */
	DAO_LC_HASH_TYPE_SHA3_SHA256 = 11,
	/** Hash Type = SHA3-SHA384 */
	DAO_LC_HASH_TYPE_SHA3_SHA384 = 12,
	/** Hash Type = SHA3-SHA512 */
	DAO_LC_HASH_TYPE_SHA3_SHA512 = 13,
	/** Hash Type = SHA3-SHAKE128 */
	DAO_LC_HASH_TYPE_SHA3_SHAKE128 = 14,
	/** Hash Type = SHA3-SHAKE256 */
	DAO_LC_HASH_TYPE_SHA3_SHAKE256 = 15,
	/** Hash Type = CMAC */
	DAO_LC_HASH_TYPE_CMAC = 16,
};

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
	/** Maximum value for elliptic curve identifier */
	DAO_LC_AE_EC_ID_PMAX
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
	 * @see enum dao_lc_hash_type
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
 * Liquid Crypto Feature Parameters.
 *
 * This structure is used to store the feature parameters of the liquid crypto device.
 * The feature parameters are used to calculate the size of the maximum segment size.
 */
struct dao_lc_feature_params {
	/**
	 * Symmetric parameters. The parameters are used to calculate the size of the maximum
	 * segment size for symmetric operations.
	 *
	 * For using following opcodes the corresponding parameters must be set:
	 * - `DAO_LC_SYM_OPCODE_FC`: Flexi Crypto @see DAO_LC_SYM_FC_CTX
	 */
	struct {
		/**
		 * Cipher and auth payload length.
		 * - Cipher only: length of cipher text.
		 * - Auth only: length of data to be authenticated.
		 * - Cipher and auth: length of data with possible overlap.
		 * - AEAD: length of data for authenticated encryption.
		 * - Key wrap: length of key data to be wrapped.
		 */
		uint16_t cipher_auth_payload_len;
		/** IV length */
		uint16_t iv_len;
		/** AAD length */
		uint16_t aad_len;
		/** Digest length */
		uint16_t digest_len;
		/** Key wrap length */
		uint16_t key_wrap_len;
		/** KEK length */
		uint16_t kek_len;
	} sym;
	/**
	 * RSA asymmetric parameters. The parameters are used to calculate the size of the maximum
	 * segment size for asymmetric operations.
	 *
	 * For using following APIs the corresponding parameters must be set:
	 * - `dao_liquid_crypto_enq_op_pkcs1v15enc()`
	 * - `dao_liquid_crypto_enq_op_pkcs1v15dec()`
	 * - `dao_liquid_crypto_enq_op_pkcs1v15enc_crt()`
	 * - `dao_liquid_crypto_enq_op_pkcs1v15dec_crt()`
	 */
	struct {
		/** Modulus length */
		uint16_t mod_len;
		/** Exponent length */
		uint16_t exp_len;
		/** Message length */
		uint16_t msg_len;
	} rsa;
	/**
	 * Random number generation parameters.
	 * The parameters are used to calculate the size of the maximum segment size for random
	 * number generation operations.
	 */
	struct {
		/** Random data length */
		uint32_t rand_len;
	} rng;

	/**
	 * ECDSA asymmetric parameters. The parameters are used to calculate the size of the maximum
	 * segment size for ECDSA operations.
	 *
	 * For using following APIs the corresponding parameters must be set:
	 * - `dao_liquid_crypto_enq_op_ecdsa_sign()`
	 * - `dao_liquid_crypto_enq_op_ecdsa_verify()`
	 */
	struct {
		/** Specifies whether ECC enabled or not */
		bool is_ecc_enabled;
		/** Curve ID */
		enum dao_liquid_crypto_ec_curve_type curve_id;
		/** Private key length */
		uint16_t pkey_len;
		/** Public key x coordinate length */
		uint16_t pubkey_x_len;
		/** Public key y coordinate length */
		uint16_t pubkey_y_len;
		/** Digest length */
		uint16_t digest_len;
		/** Nonce length */
		uint16_t nonce_len;
		/** r sign component length */
		uint16_t sign_r_len;
		/** s sign component length */
		uint16_t sign_s_len;
	} ecc;

	/**
	 * Specifies whether the size calculation is for the command queue pair.
	 * If true, the size is calculated specifically for the command queue pair, ignoring
	 * the symmetric and RSA asymmetric parameters.
	 * If false, the size is calculated for the data queue pair using the symmetric and RSA
	 * asymmetric parameters provided above.
	 */
	bool cmd_qp;
};

/**
 * The liquid crypto HMAC hash context.
 */
struct dao_lc_hmac_hash_ctx {
	/** Hash type */
	enum dao_lc_hash_type hmac_hash_type;
	/** Digest length */
	uint8_t digest_len;
	/** HMAC key length*/
	uint16_t hmac_key_len;
	/** HMAC Authentication Key */
	uint8_t hmac_auth_key[DAO_LC_MAX_AUTH_KEY_LEN];
};

/**
 * The liquid crypto AES key wrap context.
 * This structure is used to store the context for AES key wrap operations.
 * It contains the key length and the key encryption key (KEK).
 */
struct dao_lc_aes_key_wrap_ctx {
	/** Set to true for key wrap operation, false for unwrap operation. */
	bool is_wrap;
	/** The AES key type (128, 192, or 256 bits) */
	enum dao_lc_fc_aes_key_len aes_kek_type;
	/** Length of the Key Encryption Key in bytes (must be 16, 24, or 32) */
	uint16_t kek_len;
	/** The key encryption key (KEK) */
	uint8_t kek[DAO_LC_AES_MAX_KEY_ENC_KEY_LEN];
};

/**
 * The liquid crypto symmetric context.
 */
struct dao_lc_sym_ctx {
	/** The operation code */
	enum dao_lc_sym_opcode opcode;
	/** IV length */
	uint16_t iv_len;
	union {
		/** Flexi Crypto context */
		struct dao_lc_sym_fc_ctx fc;
		/** HMAC Hash context */
		struct dao_lc_hmac_hash_ctx hash;
		/** AES Key Wrap context */
		struct dao_lc_aes_key_wrap_ctx aes_key_wrap;
	};
};

/**
 * Parameters for random number generation operation.
 *
 * This structure encapsulates all parameters required for both hardware RNG and X9.17 (3DES-based)
 * RNG.
 *
 * For hardware RNG:
 *   - Set type = DAO_LC_RANDOM_TYPE_HW
 *   - Only out_buf, rand_len, and op_cookie are required.
 *
 * For X9.17 RNG:
 *   - Set type = DAO_LC_RANDOM_TYPE_X9_17
 *   - key, datetime, seed, out_seed must be provided as specified.
 */
enum dao_lc_random_type {
	/** Use hardware RNG */
	DAO_LC_RANDOM_TYPE_HW = 0,
	/** Use X9.17 (3DES-based) RNG */
	DAO_LC_RANDOM_TYPE_X9_17 = 1
};

/**
 * Parameters for X9.17 (3DES-based) RNG.
 *
 * This structure contains the parameters required for the X9.17 RNG operation.
 * The key, datetime, seed, and out_seed fields must be set appropriately.
 */
struct dao_lc_random_op_x9_17 {
	/** The 3DES key (24 bytes) */
	uint8_t *key;
	/** The date-time (8 bytes) */
	uint8_t *datetime;
	/** The input seed (8 bytes) */
	uint8_t *seed;
	/** The output seed (8 bytes) */
	uint8_t *out_seed;
};

struct dao_lc_random_op {
	/** RNG type to use */
	enum dao_lc_random_type type;
	/** Output buffer for random data */
	struct dao_lc_buf *out_buf;
	/** Number of random bytes to generate */
	uint32_t rand_len;
	/** Operation cookie */
	uint64_t op_cookie;

	union {
		/** X9.17-specific fields (must be set if type == DAO_LC_RANDOM_TYPE_X9_17) */
		struct dao_lc_random_op_x9_17 x9_17;
	};
};

/**
 * The liquid crypto AES key length in bytes.
 */
enum dao_lc_aes_key_len_bytes {
	/** AES key length = 16 bytes */
	DAO_LC_AES_KEY_LEN_16_BYTES = 16,
	/** AES key length = 24 bytes */
	DAO_LC_AES_KEY_LEN_24_BYTES = 24,
	/** AES key length = 32 bytes */
	DAO_LC_AES_KEY_LEN_32_BYTES = 32
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
 * - On failure, a negative value is returned indicating the cause.
 * -  -EINVAL, indicating an invalid argument.
 * -  -ENOMEM, indicating an out of memory error.
 * -  -ENODEV, indicating that the device is not available.
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
 *   -EINVAL, indicating an invalid argument.
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
 *   -EINVAL, indicating an invalid argument.
 * - -ENOMEM, indicating an out of memory error.
 * - -EEXIST, indicating that the device already exists.
 */
int dao_liquid_crypto_dev_create(struct dao_lc_dev_conf *conf);

/**
 * Destroy a liquid crypto device.
 *
 * This function destroys a liquid crypto device. The device must be stopped
 * before it can be destroyed. Once destroyed, the device cannot be used.
 *
 * @param dev_id
 * The device identifier.
 *
 * @return
 * - On success, 0 is returned.
 * - On failure, a negative value is returned indicating the cause
 *   -EINVAL, indicating an invalid argument.
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
 * - -EINVAL, indicating an invalid argument.
 * - -ENOMEM, indicating an out of memory error.
 */
int dao_liquid_crypto_qp_configure(uint8_t dev_id, uint16_t qp_id, struct dao_lc_qp_conf *conf);

/**
 * Start a liquid crypto device.
 *
 * This function starts a liquid crypto device. The device must be created
 * before it can be started.
 *
 * Note: For performance benefits, the actual number of descriptors would
 * be rounded up to a power of 2.
 *
 * @param dev_id
 * The device identifier.
 * @return
 * - On success, 0 is returned.
 * - On failure, a negative value is returned indicating the cause
 *   -EINVAL, indicating an invalid argument.
 *   -EEXIST, indicating that the file exists.
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
 *   -EINVAL, indicating an invalid argument.
 */
int dao_liquid_crypto_dev_stop(uint8_t dev_id);

/**
 * Calculate the size of the maximum segment size.
 *
 * This function calculates the size of the maximum segment size for the liquid crypto device to
 * support the given feature parameters.
 *
 * This value can be passed to the *max_seg_size* field of the *dao_lc_qp_conf* structure
 * when configuring a queue pair.
 *
 * @param params
 * A pointer to the liquid crypto feature parameters structure.
 * @return
 * - On success, the size of the maximum segment size is returned.
 * - On failure, 0 is returned.
 */
uint16_t dao_liquid_crypto_seg_size_calc(struct dao_lc_feature_params *params);

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
 *
 * @return
 * - 0 on success, negative value on failure.
 * -  -EINVAL, indicating an invalid argument.
 * -  -ENOSPC, indicating that there is no space left on the device.
 * -  -ENOMEM, indicating an out of memory error.
 * -  -EIO, indicating an I/O error.
 *
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
 *  The length of the modulus. Value should be at least 17 bytes
 *  and at most 1024 bytes.
 * @param exp_len
 *  The length of the exponent.
 * @param msg_len
 *  The length of the message. Value must be at most *mod_len* - 11.
 * @param mod
 *  The address of the buffer containing the modulus.
 *  Length of this buffer must be at most *mod_len* bytes.
 * @param exp
 *  The address of the buffer containing the exponent.
 * @param msg
 *  The address of the buffer containing the message.
 * @param em
 *  The address of the buffer where the encrypted message is to be stored.
 *  Length of this buffer must be at least *mod_len* bytes.
 * @param op_cookie
 *  The cookie to be associated with the operation. This cookie is returned
 *  in the *dao_lc_res* structure when the operation is dequeued.
 *
 * @return
 *  - 0 on success, negative value on failure.
 *  -  -EINVAL, indicating an invalid argument.
 *  -  -ENOMEM, indicating an out of memory error.
 *  -  -ENOSPC, indicating that there is no space left on the device.
 *  -  -EIO, indicating an I/O error.
 */
int dao_liquid_crypto_enq_op_pkcs1v15enc(uint8_t dev_id, uint16_t qp_id,
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
 *  The length of the modulus. Value should be at least 17 bytes
 *  and at most 1024 bytes.
 * @param exp_len
 *  The length of the exponent.
 * @param mod
 *  The address of the buffer containing the modulus.
 *  Length of this buffer must be *mod_len* bytes.
 * @param exp
 *  The address of the buffer containing the exponent.
 * @param em
 *  The address of the buffer containing the encrypted message. Length of this
 *  buffer must be *mod_len* bytes.
 * @param msg
 *  The address of the buffer where the decrypted message is to be stored.
 *  Length of this buffer must be at least *mod_len* - 11 bytes.
 * @param op_cookie
 *  The cookie to be associated with the operation. This cookie is returned
 *  in the *dao_lc_res* structure when the operation is dequeued.
 *
 * @return
 *  - 0 on success, negative value on failure.
 *  -  -EINVAL, indicating an invalid argument.
 *  -  -ENOMEM, indicating an out of memory error.
 *  -  -ENOSPC, indicating that there is no space left on the device.
 *  -  -EIO, indicating an I/O error.
 */
int dao_liquid_crypto_enq_op_pkcs1v15dec(uint8_t dev_id, uint16_t qp_id,
					 enum dao_liquid_crypto_rsa_key_type key_type,
					 uint16_t mod_len, uint16_t exp_len, uint8_t *mod,
					 uint8_t *exp, uint8_t *em, uint8_t *msg,
					 uint64_t op_cookie);

/**
 * Enqueue request to perform RSA CRT encrypt operation on the crypto device.
 *
 * @param dev_id
 *  The identifier of the device.
 * @param qp_id
 *  The index of the queue pair on which the operation is to be enqueued.
 * @param mod_len
 *  The length of the modulus. Value must be even and should be at least 34
 *  bytes and at most 1024 bytes.
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
 *  Length of this buffer must be *mod_len* bytes.
 * @param op_cookie
 *  The cookie to be associated with the operation. This cookie is returned
 *  in the *dao_lc_res* structure when the operation is dequeued.
 *
 * @return
 *  - 0 on success, negative value on failure.
 *  -  -EINVAL, indicating an invalid argument.
 *  -  -ENOMEM, indicating an out of memory error.
 *  -  -ENOSPC, indicating that there is no space left on the device.
 *  -  -EIO, indicating an I/O error.
 */
int dao_liquid_crypto_enq_op_pkcs1v15enc_crt(uint8_t dev_id, uint16_t qp_id, uint16_t mod_len,
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
 *  The length of the modulus in bytes. Value must be even and should be at
 *  least 34 bytes and at most 1024 bytes.
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
 *  Length of this buffer must be *mod_len* bytes.
 * @param msg
 *  The address of the buffer where the decrypted message is to be stored.
 *  Length of this buffer must be at least *mod_len* - 11 bytes.
 * @param op_cookie
 *  The cookie to be associated with the operation. This cookie is returned
 *  in the *dao_lc_res* structure when the operation is dequeued.
 *
 * @return
 *  - 0 on success, negative value on failure.
 *  - -EINVAL, indicating an invalid argument.
 *  - -ENOMEM, indicating an out of memory error.
 *  - -ENOSPC, indicating that there is no space left on the device.
 *  - -EIO, indicating an I/O error.
 */
int dao_liquid_crypto_enq_op_pkcs1v15dec_crt(uint8_t dev_id, uint16_t qp_id, uint16_t mod_len,
					     uint8_t *q, uint8_t *dQ, uint8_t *p, uint8_t *dP,
					     uint8_t *qInv, uint8_t *em, uint8_t *msg,
					     uint64_t op_cookie);

/**
 * Enqueue request to generate random data.
 *
 * Select the RNG type and provide parameters via the op structure.
 * @see struct dao_lc_random_op for details.
 *
 * @param dev_id
 *  The identifier of the device.
 * @param qp_id
 *  The index of the queue pair on which the operation is to be enqueued.
 * @param op
 *  Pointer to the random operation parameter structure.
 *
 * @return
 *  - 0 on success, negative value on failure.
 *  -  -EINVAL, indicating an invalid argument.
 *  -  -ENOMEM, indicating an out of memory error.
 *  -  -ENOSPC, indicating that there is no space left on the device.
 *  -  -EIO, indicating an I/O error.
 */
int dao_liquid_crypto_enq_op_random(uint8_t dev_id, uint16_t qp_id, struct dao_lc_random_op *op);

/**
 * Enqueue a burst of requests to perform symmetric crypto operations on the
 * crypto device.
 *
 * Note: The max number of requests that can be enqueued at once is 128.
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
 *  The number of operations enqueued. The return value can be less than
 *  the number of operations requested to be enqueued if the queue is full or
 *  if there are any errors in the operations. In case of errors, 'rte_errno'
 *  will be set to indicate the cause.
 *   - EINVAL, indicating an invalid argument.
 *   - ENOMEM, indicating an out of memory error.
 *   - ENOSPC, indicating that there is no space left on the device.
 *   - EIO, indicating an I/O error.
 */
uint16_t dao_liquid_crypto_sym_enqueue_burst(uint8_t dev_id, uint16_t qp_id,
					     struct dao_lc_sym_op *op, uint16_t nb_ops);

/**
 * Dequeue burst of crypto operations from the crypto device.
 *
 * Note: The max number of requests that can be dequeued at once is 128.
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
 * The number of operations dequeued. The return value can be less than
 * the number of operations requested to be dequeued if the queue is empty or
 * if there are any errors in the operations. In case of errors, 'rte_errno'
 * will be set to indicate the cause.
 *  - EINVAL, indicating an invalid argument.
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
 * *dao_lc_cmd_sess_event* structure when the operation is dequeued.
 *
 * @return
 * - On success, 0 is returned.
 * - On failure, a negative value is returned indicating the cause
 */
int dao_liquid_crypto_sym_sess_destroy(uint8_t dev_id, uint64_t sess_id, uint64_t sess_cookie);

/**
 * Dequeue burst of command events from the command queue.
 *
 * Note: The max number of requests that can be dequeued at once is 128.
 *
 * @param dev_id
 * The identifier of the device.
 * @param events
 * The array of pointers to *dao_lc_cmd_event* structures where the command events
 * can be stored.
 * @param nb_events
 * The maximum number of command events to dequeue.
 * @return
 * The number of command events dequeued. The return value can be less than
 * the number of command events requested to be dequeued if the queue is empty
 * or if there are no command events available. In case of errors, 'rte_errno'
 * will be set to indicate the cause.
 * - EINVAL, indicating an invalid argument.
 */
uint16_t dao_liquid_crypto_cmd_event_dequeue(uint8_t dev_id, struct dao_lc_cmd_event *events,
					     uint16_t nb_events);

/**
 * Enqueue request to perform ECDSA sign operation on the crypto device.
 *
 * @param dev_id
 *  The identifier of the device.
 * @param qp_id
 *  The index of the queue pair on which the operation is to be enqueued.
 * @param curve_id
 *  The identifier of the elliptic curve to be used for ECDSA signing.
 *  Supported curve types are:
 *    - DAO_LC_AE_EC_ID_P192
 *    - DAO_LC_AE_EC_ID_P224
 *    - DAO_LC_AE_EC_ID_P256
 *    - DAO_LC_AE_EC_ID_P384
 *    - DAO_LC_AE_EC_ID_P521
 * @param nonce_len
 *  The length of the ECDSA per-message secret number in bytes. nonce_len is between 1 to prime
 * length bytes.
 * @param pkey_len
 *  The length of the ECDSA private key data  in bytes. pkey_len is between 1 to prime length bytes.
 * @param digest_len
 *  The length of the message digest e in bytes. digest_len is between 1 to prime length bytes.
 * @param nonce
 *  The address of the buffer containing the per-message secret number (nonce).
 *  The nonce is an integer in the interval [1, n-1], where n is the order of the base point G of
 * the elliptic curve. Length must be equal to the prime length of the curve.
 * @param pkey
 *  The address of the buffer containing the private key data.
 *  The private key is an integer in the interval [1, n-1], where n is the order of the base point G
 * of the elliptic curve. Length must be equal to the prime length of the curve.
 * @param digest_data
 *  The address of the buffer containing the message digest.
 * @param rs_outdata
 * The address of the buffer where the ECDSA signature (containing both r and s components) is to be
 * stored. The buffer must be large enough to hold both components, with a length of at least twice
 * the length of the order of the elliptic curve. The signature is stored as a single contiguous
 * block, with the r component followed immediately by the s component.
 * @param op_cookie
 * The cookie to be associated with the operation. This cookie is returned
 * in the *dao_lc_res* structure when the operation is dequeued.
 * @return
 *  0 on success, negative value on failure.
 *   -EINVAL, indicating an invalid argument.
 *   -ENOMEM, indicating an out of memory error.
 *   -ENOSPC, indicating that there is no space left on the device.
 */
int dao_liquid_crypto_enq_op_ecdsa_sign(uint8_t dev_id, uint16_t qp_id,
					enum dao_liquid_crypto_ec_curve_type curve_id,
					uint16_t nonce_len, uint16_t pkey_len, uint16_t digest_len,
					uint8_t *nonce, uint8_t *pkey, uint8_t *digest_data,
					uint8_t *rs_outdata, uint64_t op_cookie);

/**
 * Enqueue request to perform ECDSA verify operation on the crypto device.
 *
 * @param dev_id
 *  The identifier of the device.
 * @param qp_id
 *  The index of the queue pair on which the operation is to be enqueued.
 * @param curve_id
 *  The identifier of the elliptic curve to be used for ECDSA verify.
 *  Supported curve types are:
 *    - DAO_LC_AE_EC_ID_P192
 *    - DAO_LC_AE_EC_ID_P224
 *    - DAO_LC_AE_EC_ID_P256
 *    - DAO_LC_AE_EC_ID_P384
 *    - DAO_LC_AE_EC_ID_P521
 * @param r_len
 *  The length of the ECDSA r sign component in bytes and r_len is prime length bytes.
 * @param s_len
 *  The length of the ECDSA s sign component in bytes and s_len is prime length bytes.
 * @param digest_len
 *  The length of the message digest in bytes and digest_len is between 1 to prime length bytes.
 * @param qx_len
 *  The length of the x-coordinate of the public key in bytes and qx_len is between 1 to prime
 * length bytes.
 * @param qy_len
 *  The length of the y-coordinate of the public key in bytes and qy_len is between 1 to prime
 * length bytes.
 * @param r_data
 *  The address of the buffer containing the ECDSA r component.
 * @param s_data
 *  The address of the buffer containing the ECDSA s component.
 * @param digest
 *  The address of the buffer containing the message digest.
 * @param qx_data
 *  The address of the buffer containing the x-coordinate of the public key.
 *  The public_x key is an integer in the interval [0, q-1], where q is prime number
 * @param qy_data
 *  The address of the buffer containing the y-coordinate of the public key.
 *  The public_y key is an integer in the interval [0, q-1], where q is prime number
 * @param op_cookie
 *  The cookie to be associated with the operation. This cookie is returned
 *  in the *dao_lc_res* structure when the operation is dequeued.
 *
 * @return
 *  0 on success, negative value on failure.
 *   -EINVAL, indicating an invalid argument.
 *   -ENOMEM, indicating an out of memory error.
 *   -ENOSPC, indicating that there is no space left on the device.
 */
int dao_liquid_crypto_enq_op_ecdsa_verify(uint8_t dev_id, uint16_t qp_id,
					  enum dao_liquid_crypto_ec_curve_type curve_id,
					  uint16_t r_len, uint16_t s_len, uint16_t digest_len,
					  uint16_t qx_len, uint16_t qy_len, uint8_t *r_data,
					  uint8_t *s_data, uint8_t *digest, uint8_t *qx_data,
					  uint8_t *qy_data, uint64_t op_cookie);

/**
 * Enqueue request to perform RSA OAEP public encrypt operation on the crypto device.
 *
 * @param dev_id
 *  The identifier of the device.
 * @param qp_id
 *  The index of the queue pair on which the operation is to be enqueued.
 * @param label
 *  Optional label to be associated with the message. In RSA OAEP, this label is
 *  used as an input to the mask generation function (MGF) and can provide additional
 *  binding context for the encryption operation. If not required, it can be set to NULL.
 * @param label_len
 *  The length of the label in bytes. If no label is used, this should be set to 0.
 * @param hash_type
 *  The hash algorithm to be used in the OAEP padding scheme. Supported hash types are:
 *   -DAO_LC_HASH_TYPE_SHA1
 *   -DAO_LC_HASH_TYPE_SHA2_SHA256
 *   -DAO_LC_HASH_TYPE_SHA2_SHA384
 *   -DAO_LC_HASH_TYPE_SHA2_SHA512
 * @param mod_len
 *  The length of the modulus. Value should be at least 17 bytes
 *  and at most 1024 bytes.
 * @param exp_len
 *  The length of the exponent.
 * @param msg_len
 *  The length of the message. .
 * @param mod
 *  The address of the buffer containing the modulus.
 *  Length of this buffer must be at most *mod_len* bytes.
 * @param exp
 *  The address of the buffer containing the exponent.
 * @param msg
 *  The address of the buffer containing the message. The length of the message (msg_len)
 *  must satisfy: msg_len <= (mod_len - (2 * hlen) - 2), where hlen is the
 *  length of the hash output used in OAEP.
 * @param em
 *  The address of the buffer where the encrypted message is to be stored.
 *  Length of this buffer must be at least *mod_len* bytes.
 * @param op_cookie
 *  The cookie to be associated with the operation. This cookie is returned
 *  in the *dao_lc_res* structure when the operation is dequeued.
 *
 * @return
 *  - 0 on success, negative value on failure.
 *  -  -EINVAL, indicating an invalid argument.
 *  -  -ENOMEM, indicating an out of memory error.
 *  -  -ENOSPC, indicating that there is no space left on the device.
 *  -  -EIO, indicating an I/O error.
 */
int dao_liquid_crypto_enq_op_rsa_oaep_enc(uint8_t dev_id, uint16_t qp_id, uint8_t *label,
					  uint16_t label_len, enum dao_lc_hash_type hash_type,
					  uint16_t mod_len, uint16_t exp_len, uint16_t msg_len,
					  uint8_t *mod, uint8_t *exp, uint8_t *msg, uint8_t *em,
					  uint64_t op_cookie);

/**
 * Enqueue request to perform RSA OAEP private decrypt operation on the crypto device.
 *
 * @param dev_id
 *  The identifier of the device.
 * @param qp_id
 *  The index of the queue pair on which the operation is to be enqueued.
 * @param label
 *  Optional label to be associated with the message. In RSA OAEP, this label is
 *  used as an input to the mask generation function (MGF) and can provide additional
 *  binding context for the decryption operation. If not required, it can be set to NULL.
 * @param label_len
 *  The length of the label in bytes. If no label is used, this should be set to 0.
 * @param hash_type
 *  The hash algorithm to be used in the OAEP padding scheme. Supported hash types are:
 *   -DAO_LC_HASH_TYPE_SHA1
 *   -DAO_LC_HASH_TYPE_SHA2_SHA256
 *   -DAO_LC_HASH_TYPE_SHA2_SHA384
 *   -DAO_LC_HASH_TYPE_SHA2_SHA512
 * @param mod_len
 *  The length of the modulus. Value should be at least 17 bytes
 * and at most LIQUID_CRYPTO_RSA_MOD_LEN_MAX bytes.
 * @param exp_len
 *  The length of the exponent.
 * @param mod
 *  The address of the buffer containing the modulus.
 *  Length of this buffer must be *mod_len* bytes.
 * @param exp
 *  The address of the buffer containing the exponent.
 * @param em
 *  The address of the buffer containing the encrypted message. Length of this
 *  buffer must be *mod_len* bytes.
 *  @param em_len
 *  The length of the encrypted message. This should be equal to *mod_len* bytes.
 * @param msg
 *  The address of the buffer where the decrypted message is to be stored.
 * @param op_cookie
 *  The cookie to be associated with the operation. This cookie is returned
 *  in the *dao_lc_res* structure when the operation is dequeued.
 * @return
 *  - 0 on success, negative value on failure.
 *  -  -EINVAL, indicating an invalid argument.
 *  -  -ENOMEM, indicating an out of memory error.
 *  -  -ENOSPC, indicating that there is no space left on the device.
 *  -  -EIO, indicating an I/O error.
 */
int dao_liquid_crypto_enq_op_rsa_oaep_exp_dec(uint8_t dev_id, uint16_t qp_id, uint8_t *label,
					      uint16_t label_len, enum dao_lc_hash_type hash_type,
					      uint16_t mod_len, uint16_t exp_len, uint16_t em_len,
					      uint8_t *mod, uint8_t *exp, uint8_t *em, uint8_t *msg,
					      uint64_t op_cookie);

#endif /* __DAO_LIQUID_CRYPTO_H__ */
