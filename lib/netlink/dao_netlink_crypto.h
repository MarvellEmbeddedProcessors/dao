/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2023 Marvell.
 */

/**
 * @file
 *
 * DAO Netlink crypto file (required for netlink-xfrm)
 *
 * Contains macros for LINUX supported crypto algorithms with various crypto
 * key attributes like: algo_name, key_lenght, block_size, hmac details, ivlen etc
 */

#ifndef _DAO_LIB_NETLINK_CRYPTO_H
#define _DAO_LIB_NETLINK_CRYPTO_H

#define DAO_NETLINK_CRYPTO_KEY_MAX_NAME_LEN 1024

/**
 * Cipher algorithms
 *_(ALGO, KeylenBits, KeylenBytes, IVLEN, BLKSZ, LINUX_ALG_NAME, "PRETTY_NAME")
 */
#define dao_netlink_foreach_crypto_cipher_algorithm				\
	_(CIPHER_DES_CBC, 56, 8, 8, 8, "cbc(des)", "des-cbc")			\
	_(CIPHER_3DES_CBC, 192, 24, 8, 8, "cbc(des3-cede)", "3des-cbc")		\
	_(CIPHER_AES_CBC, 128, 16, 16, 16, "cbc(aes)", "aes-cbc-128")		\
	_(CIPHER_AES_CBC, 192, 24, 16, 16, "cbc(aes)", "aes-cbc-192")		\
	_(CIPHER_AES_CBC, 256, 32, 16, 16, "cbc(aes)", "aes-cbc-256")		\
	_(CIPHER_AES_CTR, 128, 16, 16, 16, "ctr(aes)", "aes-ctr-128")		\
	_(CIPHER_AES_CTR, 192, 24, 16, 16, "ctr(aes)", "aes-ctr-192")		\
	_(CIPHER_AES_CTR, 256, 32, 16, 16, "ctr(aes)", "aes-ctr-256")

/**
 *  AEAD algorithms
 *
 *_(ALGO, KeylenBits, KeylenBytes, IVLEN, DIGEST, AADLEN, "LINUX_ALG_NAME", "PRETTY_NAME")
 */
#define dao_netlink_foreach_crypto_cipher_aead_algorithm					\
	_(AEAD_AES_GCM, 128, 16, 12/*TODO*/, 16, 8, "rfc4106(gcm(aes))", "aes-gcm-128-aad8")	\
	_(AEAD_AES_GCM, 192, 24, 12, 16, 8, "rfc4106(gcm(aes))", "aes-gcm-19-aad8")		\
	_(AEAD_AES_GCM, 256, 32, 12, 16, 8, "rfc4106(gcm(aes))", "aes-gcm-256-aad8")		\
	_(AEAD_CHACHA20_POLY1305, 256, 32, 12, 16, 8,						\
	  "rfc7539esp(chacha20,poly1305)", "chacha20-poly1305-aad8")

/* @internal */
#define __dao_netlink_foreach_crypto_auth_hash_alg				\
	_(AUTH_SHA1, 160, "sha-1")						\
	_(AUTH_SHA224, 224, "sha-224")						\
	_(AUTH_SHA256, 256, "sha-256")						\
	_(AUTH_SHA384, 384, "sha-384")						\
	_(AUTH_SHA512, 512, "sha-512")

/* Auth enum, key bit length, iv, digest_len, ip-xfrm-name, simple-name */
#define dao_netlink_foreach_crypto_auth_hmac_alg				\
	_(AUTH_MD5_HMAC, 128, 0, 12, "hmac(md5)", "hmac-md5")			\
	_(AUTH_SHA1_HMAC, 160, 0, 12, "hmac(sha1)", "hmac-sha1")		\
	_(AUTH_SHA256_HMAC, 256, 0, 16, "hmac(sha256)", "hmac-sha2-256")	\
	_(AUTH_SHA384_HMAC, 384, 0, 24, "hmac(sha384)", "hmac-sha2-384")	\
	_(AUTH_SHA512_HMAC, 512, 0, 32, "hmac(sha512)", "hmac-sha2-512")

/** Crypto Algorithm macros DAO_CRYPTO_XXX */
typedef enum {
#define _(macro, keybits, key, iv, blksize, xfrm_name, name)		\
						DAO_CRYPTO_##macro##_##keybits,
	dao_netlink_foreach_crypto_cipher_algorithm
#undef _
#define _(cipher, keybits, key, iv, blksize, aad, xfrm_name, name)	\
						DAO_CRYPTO_##cipher##_##keybits,
	dao_netlink_foreach_crypto_cipher_aead_algorithm
#undef _

#define _(macro, keybits, iv, dig, xfrm_name, name)	DAO_CRYPTO_##macro,
	dao_netlink_foreach_crypto_auth_hmac_alg
#undef _
} dao_netlink_crypto_algo_t;

/** Object representing crypto key */
typedef struct dao_netlink_crypto_key {
	dao_netlink_crypto_algo_t algo;		/**< Algo Name */
	uint32_t key_len;	/**< Length of the crypto key */
	union {
		uint32_t trunc_len;	/**< Turncate len */
		uint32_t icv_len;	/**< ICV length */
	};
	char key[DAO_NETLINK_CRYPTO_KEY_MAX_NAME_LEN];	/**< Crypto key as string */
} dao_netlink_crypto_key_t;

#endif /* _DAO_LIB_NETLINK_CRYPTO_H */
