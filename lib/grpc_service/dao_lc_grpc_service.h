/* SPDX-License-Identifier: Marvell-MIT
 * Copyright(C) 2025 Marvell.
 */

#ifndef __INCLUDE_DAO_LC_GRPC_SERVICE_H__
#define __INCLUDE_DAO_LC_GRPC_SERVICE_H__

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Queue configuration for an ethdev on the liquid crypto card.
 */
struct dao_lc_eth_qconf {
	/** Ethdev id */
	uint32_t dev_id;
	/** Queue id */
	uint32_t qp_id;
	/** Number of descriptors */
	uint32_t nb_desc;
	/** Maximum segment size */
	uint32_t max_seg_size;
	/** Enable out of order delivery */
	bool out_of_order_delivery_en;
};

/**
 * Device capabilities structure.
 *
 * Intentionally kept identical to ``dao_lc_dev_caps`` in lib/liquid_crypto/dao_liquid_crypto.h.
 */
struct dao_dev_caps {
	union {
		/** Bitfield representation of capabilities */
		struct {
			/** PQC support bit */
			uint64_t pqc_en : 1;
			/** Compress device enable bit */
			uint64_t compdev_en : 1;
		};
		/** 64-bit representation of capabilities */
		uint64_t feature_mask0;
	};
};

#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_DAO_LC_GRPC_SERVICE_H__ */
