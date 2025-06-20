/* SPDX-License-Identifier: Marvell-MIT
 * Copyright(C) 2025 Marvell.
 */

#ifndef __INCLUDE_DAO_CARD_GRPC_SERVICE_H__
#define __INCLUDE_DAO_CARD_GRPC_SERVICE_H__

#ifdef __cplusplus
extern "C" {
#endif

/** The version of the crypto agent */
#define DAO_CARD_VERSION "25.06.1"
/** The maximum length of the version string. */
#define DAO_CARD_VERSION_LEN 32

/**
 * Liquid crypto card information.
 */
struct dao_card_info {
	/** Version of the liquid crypto card */
	char version[DAO_CARD_VERSION_LEN];
	/** Number of Ethernet devices on card */
	uint32_t nb_devs;
	/** Maximum number of sessions supported on card */
	uint32_t max_sessions;
};

/**
 * Configuration for the liquid crypto card.
 */
struct dao_card_config {
	/** Number of EAL arguments */
	uint32_t argc;
	/** EAL Arguments */
	char **argv;
	/** Crypto device queue depth */
	uint32_t crypto_nb_desc;
};

/**
 * Request structure for DAO App update.
 */
struct dao_card_app_update_req {
	char *filename;
	char *filepath;
};

#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_DAO_CARD_GRPC_SERVICE_H__ */
