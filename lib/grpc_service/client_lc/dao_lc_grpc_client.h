/* SPDX-License-Identifier: Marvell-MIT
 * Copyright(C) 2025 Marvell.
 */

#ifndef __INCLUDE_DAO_LC_GRPC_CLIENT_H__
#define __INCLUDE_DAO_LC_GRPC_CLIENT_H__

#include "../dao_lc_grpc_service.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Liquid Crypto GRPC APIs */

/**
 * gRPC client context.
 */
struct dao_lc_grpc_ctx;

/**
 * Initialize the gRPC client.
 *
 * @param server_ip: IP address of the server
 * @param server_port: Port number of the server
 * @return: A pointer to the gRPC client context
 */
struct dao_lc_grpc_ctx *dao_lc_grpc_client_init(const char *server_ip, uint16_t server_port);

/**
 * Finalize the gRPC client.
 *
 * @param ctx: gRPC client context
 */
void dao_lc_grpc_client_fini(struct dao_lc_grpc_ctx *ctx);

/**
 * Create an ethdev on the liquid crypto card.
 *
 * @param ctx: gRPC client context
 * @param dev_id: ethdev id
 * @param nb_queues: number of queues to be created
 * @return: 0 on success, negative value on failure
 */
int dao_lc_ethdev_create(struct dao_lc_grpc_ctx *ctx, uint32_t dev_id, uint32_t nb_queues);

/**
 * Get the capabilities of the liquid crypto card.
 *
 * @param ctx: gRPC client context
 * @param caps: pointer to store the capabilities
 * @return: 0 on success, negative value on failure
 */
int dao_lc_capabilities_get(struct dao_lc_grpc_ctx *ctx, uint64_t *caps);

/**
 * Destroy an ethdev on the liquid crypto card.
 *
 * @param ctx: gRPC client context
 * @param dev_id: ethdev id
 * @return: 0 on success, negative value on failure
 */
int dao_lc_ethdev_destroy(struct dao_lc_grpc_ctx *ctx, uint32_t dev_id);

/**
 * Configure an ethdev queue on the liquid crypto card.
 *
 * @param ctx: gRPC client context
 * @param qconf: queue configuration
 * @return: 0 on success, negative value on failure
 */
int dao_lc_ethdev_queue_configure(struct dao_lc_grpc_ctx *ctx, struct dao_lc_eth_qconf *qconf);

/**
 * Destroy an ethdev queue on the liquid crypto card.
 *
 * @param ctx: gRPC client context
 * @param dev_id: ethdev id
 * @param queue_id: queue id
 * @return: 0 on success, negative value on failure
 */
int dao_lc_ethdev_queue_destroy(struct dao_lc_grpc_ctx *ctx, uint32_t dev_id, uint32_t queue_id);

/**
 * Start an ethdev on the liquid crypto card.
 *
 * @param ctx: gRPC client context
 * @param dev_id: ethdev id
 * @return: 0 on success, negative value on failure
 */
int dao_lc_ethdev_start(struct dao_lc_grpc_ctx *ctx, uint32_t dev_id);

/**
 * Stop an ethdev on the liquid crypto card.
 *
 * @param ctx: gRPC client context
 * @param dev_id: ethdev id
 * @return: 0 on success, negative value on failure
 */
int dao_lc_ethdev_stop(struct dao_lc_grpc_ctx *ctx, uint32_t dev_id);

#ifdef __cplusplus
}
#endif
#endif /* __INCLUDE_DAO_LC_GRPC_CLIENT_H__ */
