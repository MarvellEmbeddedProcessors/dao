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
#define DAO_CARD_VERSION "26.06.0"
/** The maximum length of the version string. */
#define DAO_CARD_VERSION_LEN 32

enum dao_card_update_type {
	DAO_CARD_APP_UPDATE,
	DAO_CARD_FW_UPDATE,
	DAO_CARD_FAILSAFE_UPDATE,
	DAO_CARD_MCU_UPDATE
};

enum dao_card_boot_source {
	DAO_CARD_BOOT_SOURCE_UNSUPPORTED = 0,
	DAO_CARD_BOOT_SOURCE_SCRIPT_FAILURE = 2,
	DAO_CARD_BOOT_SOURCE_MMC = 11,
	DAO_CARD_BOOT_SOURCE_SPI = 12,
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
	/** Flag for compress device status */
	uint8_t comp_dev_enabled;
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
	/** Number of packets enqueued to compress device on each core */
	uint64_t comp_enq[CA_MAX_WORKER_CORES];
	/** Number of packets dequeued from compress device to each core */
	uint64_t comp_deq[CA_MAX_WORKER_CORES];
	/** Number of packets enqueued from core to ring for compress device enqueue */
	uint64_t comp_req_ring_enq[CA_MAX_WORKER_CORES];
	/** Number of packets dequeued from compress device to core specific ring */
	uint64_t comp_resp_ring_deq[CA_MAX_WORKER_CORES];
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
