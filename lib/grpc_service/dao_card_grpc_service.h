/* SPDX-License-Identifier: Marvell-MIT
 * Copyright(C) 2025 Marvell.
 */

#ifndef __INCLUDE_DAO_CARD_GRPC_SERVICE_H__
#define __INCLUDE_DAO_CARD_GRPC_SERVICE_H__

#define CA_MAX_WORKER_CORES 23

#ifdef __cplusplus
extern "C" {
#endif

/** The version of the crypto agent */
#define DAO_CARD_VERSION "25.08.0"
/** The maximum length of the version string. */
#define DAO_CARD_VERSION_LEN 32

enum dao_card_update_type {
	DAO_CARD_APP_UPDATE,
	DAO_CARD_FW_UPDATE,
	DAO_CARD_FAILSAFE_UPDATE
};

enum dao_card_boot_source {
	DAO_CARD_BOOT_SOURCE_UNKNOWN,
	DAO_CARD_BOOT_SOURCE_MMC,
	DAO_CARD_BOOT_SOURCE_SPI,
};

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
	/** Card boot source */
	enum dao_card_boot_source boot_source;
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
 * Liquid crypto card stats.
 */
struct dao_card_stats {
	/** Number of packets received on each core */
	uint64_t rx_packets[CA_MAX_WORKER_CORES];
	/** Number of packets sent by each core */
	uint64_t tx_packets[CA_MAX_WORKER_CORES];
};

/**
 * Request structure for DAO Image update.
 */
struct dao_card_update_req {
	char *filename;
	char *filepath;
};

#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_DAO_CARD_GRPC_SERVICE_H__ */
