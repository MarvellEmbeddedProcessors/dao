/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#include <dao_card_grpc_client.h>

#include "../lock/lock.h"
#include "../utils/file_utils.h"
#include "../utils/logging.h"
#include "app_update.h"
#include "update_manager.h"

int
dao_card_mgr_app_fallback(void)
{
	int rc = 0;

	rc = dao_card_app_fallback(card_ctx);
	if (rc < 0)
		DAO_CARD_ERR("gRPC error in card_app_fallback: %d", rc);
	return rc;
}

int
dao_card_mgr_app_update(cli_args *cmd)
{
	struct dao_card_update_req update_req = {0};
	char image_version[IMAGE_VERSION_LEN_MAX];
	char *boot_bin_path = NULL;
	char fullpath[PATH_MAX];
	int boot_rc;
	int rc;

	/* Start operation tracking */
	rc = dao_card_operation_start("app_update");
	if (rc < 0)
		return rc;

	DAO_CARD_INFO("Starting application update (estimated 1-3 minutes)");
	DAO_CARD_INFO("Do not interrupt or power off the system during update");

	rc = validate_file(cmd, &update_req, &boot_bin_path);
	if (rc != 0)
		goto cleanup;

	/* Get current image version from card via gRPC */
	rc = image_version_get(image_version, sizeof(image_version));
	if (rc != 0) {
		DAO_CARD_ERR("Failed to get image version for compatibility check: %d", rc);
		goto cleanup;
	}

	/* Special handling for backward compatibility mode */
	if (strcmp(image_version, "unknown-image-version") == 0 ||
	    strcmp(image_version, "unknown") == 0) {
		DAO_CARD_ERR("Image version is unknown. Aborting app update");
		rc = -EINVAL;
		goto cleanup;
	}

	/* Check version compatibility before proceeding with update */
	if (update_req.filepath == NULL || update_req.filename == NULL) {
		DAO_CARD_ERR("Internal error: invalid file paths from validation");
		rc = -EINVAL;
		goto cleanup;
	}

	int path_len =
		snprintf(fullpath, PATH_MAX, "%s/%s", update_req.filepath, update_req.filename);
	if (path_len < 0 || path_len >= PATH_MAX) {
		DAO_CARD_ERR("File path too long or formatting error: %s/%s", update_req.filepath,
			     update_req.filename);
		rc = -ENAMETOOLONG;
		goto cleanup;
	}

	/* Only check compatibility if the file is a tar archive */
	if (strstr(update_req.filename, ".tar") != NULL ||
	    strstr(update_req.filename, ".tgz") != NULL ||
	    strstr(update_req.filename, ".tar.gz") != NULL) {
		rc = image_compatibility_check(fullpath, image_version);
		if (rc != 0) {
			DAO_CARD_ERR("App update rejected due to version incompatibility");
			goto cleanup;
		}
	} else {
		DAO_CARD_ERR("Provided file is not a tar file");
		rc = -EINVAL;
		goto cleanup;
	}

	DAO_CARD_INFO("Writing application firmware to card...");
	rc = dao_card_file_update(card_ctx, &update_req, DAO_CARD_APP_UPDATE);
	if (rc != 0) {
		if (rc == -ETIMEDOUT || rc == -110) {
			DAO_CARD_ERR("Network timeout during firmware update");
			DAO_CARD_ERR(
				"Card may be partially updated - boot from failsafe if card not responding");
		} else if (rc == -ECONNRESET || rc == -104) {
			DAO_CARD_ERR("Connection lost to card during update");
			DAO_CARD_ERR("Check network connection and card status");
		} else {
			DAO_CARD_ERR("Firmware update failed: %s", strerror(-rc));
		}
		goto cleanup;
	}

	DAO_CARD_INFO("Firmware write completed successfully");

	if (boot_bin_path != NULL) {
		DAO_CARD_INFO("Rebooting card from new firmware...");

		boot_rc = reload_and_bringup_octeon_ep(boot_bin_path, "mmc", DAO_CARD_MGR_BOOT_IP);

		if (boot_rc != 0) {
			DAO_CARD_ERR("Card failed to boot from new firmware");
			DAO_CARD_ERR(
				"Recovery: Boot from failsafe using 'card_boot failsafe /path/to/boot'");
			rc = boot_rc;
		} else {
			DAO_CARD_INFO("Card rebooted successfully - update complete");
		}
	}

cleanup:
	/* Only remove marker on success; keep it on failure for cooldown */
	dao_card_operation_end(rc == 0);

	if (update_req.filename)
		free(update_req.filename);
	if (update_req.filepath)
		free(update_req.filepath);
	if (boot_bin_path)
		free(boot_bin_path);
	return rc;
}
