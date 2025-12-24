/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <dao_card_grpc_client.h>

#include "../lock/lock.h"
#include "../utils/file_utils.h"
#include "../utils/logging.h"
#include "mcu_update.h"
#include "update_manager.h"

int
dao_card_mgr_mcu_update(cli_args *cmd)
{
	struct dao_card_update_req update_req = {0};
	int rc;

	/* Start operation tracking */
	rc = dao_card_operation_start("mcu_update");
	if (rc < 0)
		return rc;

	DAO_CARD_INFO("Starting MCU firmware update (estimated 2-4 minutes)");
	DAO_CARD_INFO("Do not interrupt or power off the system during update");

	rc = validate_file(cmd, &update_req, NULL);
	if (rc != 0)
		goto cleanup;

	DAO_CARD_INFO("Writing MCU firmware to card...");
	rc = dao_card_file_update(card_ctx, &update_req, DAO_CARD_MCU_UPDATE);
	if (rc != 0) {
		if (rc == -ETIMEDOUT || rc == -110) {
			DAO_CARD_ERR("Network timeout during MCU update");
			DAO_CARD_ERR("Check card status and retry after cooldown");
		} else if (rc == -ECONNRESET || rc == -104) {
			DAO_CARD_ERR("Connection lost to card during MCU update");
			DAO_CARD_ERR("Check network connection and card status");
		} else {
			DAO_CARD_ERR("MCU update failed: %s", strerror(-rc));
		}
		goto cleanup;
	}

	DAO_CARD_INFO("MCU firmware update completed successfully");

cleanup:
	/* Only remove marker on success; keep it on failure for cooldown */
	dao_card_operation_end(rc == 0);

	if (update_req.filename)
		free(update_req.filename);
	if (update_req.filepath)
		free(update_req.filepath);

	return rc;
}
