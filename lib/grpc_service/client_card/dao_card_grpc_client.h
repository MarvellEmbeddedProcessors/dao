/* SPDX-License-Identifier: Marvell-MIT
 * Copyright(C) 2025 Marvell.
 */

#ifndef __INCLUDE_DAO_CARD_GRPC_CLIENT_H__
#define __INCLUDE_DAO_CARD_GRPC_CLIENT_H__

#include "../dao_card_grpc_service.h"

#include <stddef.h>

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

/**
 * Fallback the application to working one or older one.
 *
 * This function should be called to switch the application older or working one when updated
 * application fails to start.
 * Card should be booted in failsafe mode for this command to work.
 *
 * @param ctx: gRPC client context
 * @return: 0 on success, negative value on failure
 */
int dao_card_app_fallback(struct dao_card_grpc_ctx *ctx);

/**
 * Get the card stats.
 *
 * It will get the card stats like packets received or sent by each active core on liquid crypto
 * card.
 *
 * @param ctx: gRPC client context
 * @param stats [out]: card information
 * @return: 0 on success, negative value on failure
 */
int dao_card_stats_get(struct dao_card_grpc_ctx *ctx, struct dao_card_stats *stats);

/**
 * Get sensors/temperature and voltage information collected via lm-sensors on the card.
 * The returned output is a multi-line string; caller prints/logs as needed.
 *
 * @param ctx gRPC client context
 * @param buf output buffer to fill (null-terminated)
 * @param len size of output buffer
 * @return 0 on success, negative errno style value on failure
 */
int dao_card_sensors_get(struct dao_card_grpc_ctx *ctx, char *buf, size_t len);

/**
 * Get recent dmesg logs from the card.
 * @param ctx: gRPC client context
 * @param buf: destination buffer
 * @param len: buffer length
 * @return: number of bytes copied (>=0) or negative errno-style value
 */
int dao_card_dmesg_get(struct dao_card_grpc_ctx *ctx, char *buf, size_t len);

/**
 * Get recent application (crypto agent) logs from the card.
 * @param ctx gRPC client context
 * @param buf destination buffer (null-terminated on success)
 * @param len buffer length
 * @return number of bytes copied (>=0) or negative errno-style value
 */
int dao_card_applogs_get(struct dao_card_grpc_ctx *ctx, char *buf, size_t len);

/**
 * Get both rootfs and app version from the card via gRPC
 *
 * @param ctx - gRPC context
 * @param image_ver_buf - Buffer to store main image version
 * @param image_ver_len - Size of image version buffer
 * @param app_ver_buf - Buffer to store app version
 * @param app_ver_len - Size of app version buffer
 * @return 0 on success, negative error code on failure
 */
int dao_card_image_version_get(struct dao_card_grpc_ctx *ctx, char *image_ver_buf,
			       size_t image_ver_len, char *app_ver_buf, size_t app_ver_len);

/**
 * Update the image in liquid crypto card.
 *
 * This function need to be called from management daemon.
 * It will update the provided image on to the DAO card based on update type.
 * For update type as:
 * APP_UPDATE, it will copy or update the application.
 * FW_UPDATE, it will update the firmware, rootfs kernel image and application.
 * FAIL_SAFE_UPDATE, It will update the failsafe image.
 *
 * @param ctx: gRPC client context
 * @param req: Request with file details
 * @param type: Request with file details
 * @return: 0 on success, negative value on failure
 */
int dao_card_file_update(struct dao_card_grpc_ctx *ctx, struct dao_card_update_req *req,
			 enum dao_card_update_type type);

#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_DAO_CARD_GRPC_CLIENT_H__ */
