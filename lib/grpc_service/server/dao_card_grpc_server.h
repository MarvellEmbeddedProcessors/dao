/* SPDX-License-Identifier: Marvell-MIT
 * Copyright(C) 2025 Marvell.
 */

#ifndef __INCLUDE_DAO_CARD_GRPC_SERVER_H__
#define __INCLUDE_DAO_CARD_GRPC_SERVER_H__

#include "../dao_card_grpc_service.h"
#include "../dao_lc_grpc_service.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Run the gRPC server.
 *
 * @return: 0 on success, negative value on failure
 */
int dao_card_grpc_server_run(void);

/**
 * Stop the gRPC server.
 */
void dao_card_grpc_server_stop(void);

/**
 * Function pointer for initializing the card.
 * @param config: Pointer to card configuration
 * @return: 0 on success, negative value on failure
 */
typedef int (*dao_card_init_cb)(struct dao_card_config *config);

/**
 * Function pointer for card information.
 * @param info: Pointer to card information
 * @return: 0 on success, negative value on failure
 */
typedef int (*dao_card_info_cb)(struct dao_card_info *info);

/**
 * Function pointer for finalizing the card.
 */
typedef void (*dao_card_fini_cb)(void);

/**
 * Function pointer for card stats.
 * @param info: Pointer to card stats
 * @return: 0 on success, negative value on failure
 */
typedef int (*dao_card_stats_cb)(struct dao_card_stats *stats);

/**
 * Function pointer for getting eth device information.
 * @param dev_id: Device ID
 * @param info: Pointer to eth device information
 * @return: 0 on success, negative value on failure
 */
typedef int (*dao_lc_get_dev_info_cb)(uint32_t dev_id, struct dao_lc_eth_info *info);

/**
 * Function pointer for creating a device.
 * @param dev_id: Device ID
 * @param nb_qp: Number of queue pairs
 * @return: 0 on success, negative value on failure
 */
typedef int (*dao_lc_dev_create_cb)(uint32_t dev_id, uint32_t nb_qp);

/**
 * Function pointer for destroying a device.
 * @param dev_id: Device ID
 * @return: 0 on success, negative value on failure
 */
typedef int (*dao_lc_dev_destroy_cb)(uint32_t dev_id);

/**
 * Function pointer for starting a device.
 * @param dev_id: Device ID
 * @return: 0 on success, negative value on failure
 */
typedef int (*dao_lc_dev_start_cb)(uint32_t dev_id);

/**
 * Function pointer for stopping a device.
 * @param dev_id: Device ID
 * @return: 0 on success, negative value on failure
 */
typedef int (*dao_lc_dev_stop_cb)(uint32_t dev_id);

/**
 * Function pointer for configuring a queue.
 * @param conf: Pointer to queue configuration
 * @return: 0 on success, negative value on failure
 */
typedef int (*dao_lc_q_configure_cb)(struct dao_lc_eth_qconf *conf);

/**
 * Function pointer for destroying a queue.
 * @param dev_id: Device ID
 * @param qp_id: Queue pair ID
 * @return: 0 on success, negative value on failure
 */
typedef int (*dao_lc_q_destroy_cb)(uint32_t dev_id, uint32_t qp_id);

/**
 * Structure for server callbacks.
 */
struct dao_card_server_cbs {
	/** DAO Card init callback */
	dao_card_init_cb init_cb;
	/** DAO Card fini callback */
	dao_card_fini_cb fini_cb;
	/** DAO Card info callback */
	dao_card_info_cb card_info_cb;
	/** DAO Card stats callback */
	dao_card_stats_cb card_stats_cb;

	/** DAO LC get dev info callback */
	dao_lc_get_dev_info_cb dev_info_cb;
	/** DAO LC dev create callback */
	dao_lc_dev_create_cb dev_create_cb;
	/** DAO LC dev destroy callback */
	dao_lc_dev_destroy_cb dev_destroy_cb;
	/** DAO LC queue configure callback */
	dao_lc_q_configure_cb q_configure_cb;
	/** DAO LC queue destroy callback */
	dao_lc_q_destroy_cb q_destroy_cb;
	/** DAO LC dev start callback */
	dao_lc_dev_start_cb dev_start_cb;
	/** DAO LC dev stop callback */
	dao_lc_dev_stop_cb dev_stop_cb;
};

/**
 * Register the server callbacks.
 * @param cbs: Pointer to callbacks structure for registering
 * @return: 0 on success, negative value on failure
 */
int dao_card_register_server_cbs(struct dao_card_server_cbs *cbs);

#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_DAO_CARD_GRPC_SERVER_H__ */
