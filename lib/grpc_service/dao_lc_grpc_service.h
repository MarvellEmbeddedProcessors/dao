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
 * Ethdev information on the liquid crypto card.
 */
struct dao_lc_eth_info {
	/** Number of queues on a device */
	uint32_t nb_queues;
};

#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_DAO_LC_GRPC_SERVICE_H__ */
