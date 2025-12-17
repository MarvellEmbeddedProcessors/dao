/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#include <dao_card_grpc_client.h>

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
	char image_version[IMAGE_VERSION_LEN_MAX];
	struct dao_card_update_req update_req;
	char *boot_bin_path = NULL;
	char fullpath[PATH_MAX];
	int boot_rc;
	int rc;

	rc = validate_file(cmd, &update_req, &boot_bin_path);
	if (rc != 0)
		goto req_free;

	/* Get current image version from card via gRPC */
	rc = image_version_get(image_version, sizeof(image_version));
	if (rc != 0) {
		DAO_CARD_ERR("Failed to get image version for compatibility check: %d", rc);
		goto req_free;
	}

	/* Special handling for backward compatibility mode */
	if (strcmp(image_version, "unknown-image-version") == 0 ||
	    strcmp(image_version, "unknown") == 0) {
		DAO_CARD_ERR("Image version is unknown. Aborting app update");
		rc = -EINVAL;
		goto req_free;
	}

	/* Check version compatibility before proceeding with update */
	snprintf(fullpath, PATH_MAX, "%s/%s", update_req.filepath, update_req.filename);

	/* Only check compatibility if the file is a tar archive */
	if (strstr(update_req.filename, ".tar") != NULL ||
	    strstr(update_req.filename, ".tgz") != NULL ||
	    strstr(update_req.filename, ".tar.gz") != NULL) {
		rc = image_compatibility_check(fullpath, image_version);
		if (rc != 0) {
			DAO_CARD_ERR("App update rejected due to version incompatibility");
			goto req_free;
		}
	} else {
		DAO_CARD_ERR("Provided file is not a tar file");
		rc = -EINVAL;
		goto req_free;
	}

	rc = dao_card_file_update(card_ctx, &update_req, DAO_CARD_APP_UPDATE);
	if (rc == 0 && boot_bin_path != NULL) {
		boot_rc = reload_and_bringup_octeon_ep(boot_bin_path, "mmc", DAO_CARD_MGR_BOOT_IP);

		if (boot_rc != 0) {
			DAO_CARD_ERR("Boot exec / readiness failed after app update: %d", boot_rc);
			rc = boot_rc;
		}
	}

req_free:
	free(update_req.filename);
	free(update_req.filepath);
	if (boot_bin_path)
		free(boot_bin_path);
	return rc;
}
