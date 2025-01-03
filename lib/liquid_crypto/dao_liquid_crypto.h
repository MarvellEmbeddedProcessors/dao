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

/**
 * The liquid crypto information structure.
 */
struct dao_liquid_crypto_info {
	/** The version of the liquid crypto library. */
	char version[DAO_CRYPTO_VERSION_LEN];
	/** The number of devices supported by the liquid crypto library. */
	uint8_t nb_dev;
	/** The number of queue pairs supported by the liquid crypto library. */
	uint16_t nb_qp[DAO_CRYPTO_MAX_NB_DEV];
};

/**
 * The liquid crypto queue pair configuration structure.
 *
 * This structure is used to configure a liquid crypto queue pair.
 *
 */
struct dao_liquid_crypto_qp_conf {
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
int dao_liquid_crypto_info_get(struct dao_liquid_crypto_info *info);

/**
 * Create a liquid crypto device.
 *
 * This function creates a liquid crypto device.
 *
 * @param dev_id
 * The device identifier. Value must between 0 and
 * ``dao_liquid_crypto_info.nb_dev`` - 1.
 * @param nb_qp
 * The number of queue pairs.
 *
 * @return
 * - On success, 0 is returned.
 * - On failure, a negative value is returned indicating the cause
 */
int dao_liquid_crypto_dev_create(uint8_t dev_id, uint16_t nb_qp);

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
 * ``dao_liquid_crypto_info.nb_dev`` - 1.
 * @param qp_id
 * The queue pair identifier. Value must between 0 and
 * ``dao_liquid_crypto_info.nb_qp[dev_id]`` - 1.
 * @param conf
 * A pointer to the liquid crypto queue pair configuration structure.
 * @return
 * - On success, 0 is returned.
 * - On failure, a negative value is returned indicating the cause
 */
int dao_liquid_crypto_qp_configure(uint8_t dev_id, uint16_t qp_id,
				   struct dao_liquid_crypto_qp_conf *conf);

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

#endif /* __DAO_LIQUID_CRYPTO_H__ */
