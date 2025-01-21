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
		/** Metadata associated with RSA decrypt operation */
		struct {
			/** The length of the message */
			uint16_t msg_len;
		} rsa_dec;
		/** Generic 64-bit metadata */
		uint64_t u64;
	};
	/** The cookie associated with the operation */
	uint64_t op_cookie;
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
 * @param dev_id
 * The device identifier. Value must between 0 and
 * ``dao_lc_info.nb_dev`` - 1.
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

#endif /* __DAO_LIQUID_CRYPTO_H__ */
