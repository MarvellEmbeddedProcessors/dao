/* SPDX-License-Identifier: Marvell-MIT
 * Copyright(C) 2025 Marvell.
 */

#ifndef __INCLUDE_DAO_CARD_GRPC_CLIENT_H__
#define __INCLUDE_DAO_CARD_GRPC_CLIENT_H__

#include "../dao_card_grpc_service.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file dao_card_grpc_client.h
 *
 * This file contains the API for liquid crypto card.
 */

#include <stdint.h>

/**
 * gRPC client context.
 */
struct dao_card_grpc_ctx;

/**
 * Initialize the gRPC client.
 *
 * @param server_ip: IP address of the server
 * @param server_port: Port number of the server
 * @return: A pointer to the gRPC client context
 */
struct dao_card_grpc_ctx *dao_card_grpc_client_init(const char *server_ip, uint16_t server_port);

/**
 * Finalize the gRPC client.
 *
 * @param ctx: gRPC client context
 */
void dao_card_grpc_client_fini(struct dao_card_grpc_ctx *ctx);

/**
 * Initialize liquid crypto card.
 *
 * This function need to be called from management daemon.
 * It will initialize EAL and crypto device on the liquid crypto card.
 * It will also launch worker threads which will wait till ethdev are created.
 *
 * @param ctx: gRPC client context
 * @param config: configuration for the card
 * @return: 0 on success, negative value on failure
 */
int dao_card_init(struct dao_card_grpc_ctx *ctx, struct dao_card_config *config);

/**
 * Finalize liquid crypto card.
 *
 * This function need to be called from management daemon.
 * It will wait for all the worker threads to finish processing and
 * stop the crypto device and perform eal cleanup on the liquid crypto card.
 *
 * @param ctx: gRPC client context
 */
void dao_card_fini(struct dao_card_grpc_ctx *ctx);

/**
 * Get the card information.
 *
 * It will get the card information like number of ethdevs and max number of sessions supported.
 *
 * @param ctx: gRPC client context
 * @param info [out]: card information
 * @return: 0 on success, negative value on failure
 */
int dao_card_info_get(struct dao_card_grpc_ctx *ctx, struct dao_card_info *info);

#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_DAO_CARD_GRPC_CLIENT_H__ */
