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
#include "../utils/module_utils.h"
#include "failsafe_update.h"
#include "update_manager.h"

int
dao_card_mgr_failsafe_update(cli_args *cmd)
{
	struct dao_card_update_req update_req = {0};
	char *boot_bin_path = NULL;
	int boot_rc;
	int rc;

	/* Early validation: Check OCTEON_EP_KO_PATH before any time-consuming operations */
	rc = validate_octeon_ep_ko_path();
	if (rc != 0)
		return rc;

	rc = validate_file(cmd, &update_req, &boot_bin_path);
	if (rc != 0)
		goto exit;

	rc = validate_boot_path(boot_bin_path);
	if (rc != 0)
		goto exit;

	/* Start operation tracking */
	rc = dao_card_operation_start("failsafe_update");
	if (rc < 0)
		goto exit;

	DAO_CARD_INFO("Starting failsafe image update (estimated 10-12 minutes)");
	DAO_CARD_INFO("WARNING: This operation takes significant time");
	DAO_CARD_INFO("Do not interrupt or power off the system during update");

	DAO_CARD_INFO("Writing failsafe image to card flash (this will take several minutes)...");
	rc = dao_card_file_update(card_ctx, &update_req, DAO_CARD_FAILSAFE_UPDATE);
	if (rc != 0) {
		if (rc == -ETIMEDOUT || rc == -110) {
			DAO_CARD_ERR("Network timeout during failsafe update");
			DAO_CARD_ERR("CRITICAL: Failsafe may be partially written");
			DAO_CARD_ERR("Boot from existing failsafe and retry after cooldown");
		} else if (rc == -ECONNRESET || rc == -104) {
			DAO_CARD_ERR("Connection lost to card during failsafe update");
			DAO_CARD_ERR("Check network connection and card console");
		} else {
			DAO_CARD_ERR("Failsafe update failed: %s", strerror(-rc));
		}
		goto cleanup;
	}

	DAO_CARD_INFO("Failsafe image write completed successfully");
	if (boot_bin_path != NULL) {
		DAO_CARD_INFO("Rebooting card from new failsafe image...");
		boot_rc = reload_and_bringup_octeon_ep(boot_bin_path, "spi", DAO_CARD_MGR_BOOT_IP);
		if (boot_rc != 0) {
			DAO_CARD_ERR("Card failed to boot from new failsafe image");
			DAO_CARD_ERR("CRITICAL: Card may not be bootable");
			DAO_CARD_ERR("Contact support for recovery procedure");
			rc = boot_rc;
		} else {
			DAO_CARD_INFO("Card rebooted successfully from failsafe - update complete");
		}
	}

cleanup:
	/* Only remove marker on success; keep it on failure for cooldown */
	dao_card_operation_end(rc == 0);

exit:
	free(update_req.filename);
	free(update_req.filepath);
	if (boot_bin_path)
		free(boot_bin_path);
	return rc;
}
