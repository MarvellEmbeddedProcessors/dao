/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <stdint.h>
#include <stdlib.h>

#include <dao_card_grpc_client.h>

#include "../utils/file_utils.h"
#include "../utils/logging.h"
#include "fw_update.h"
#include "update_manager.h"

int
dao_card_mgr_fw_update(cli_args *cmd)
{
	struct dao_card_update_req update_req;
	char *boot_bin_path = NULL;
	int boot_rc;
	int rc;

	rc = validate_file(cmd, &update_req, &boot_bin_path);
	if (rc != 0)
		goto req_free;

	rc = dao_card_file_update(card_ctx, &update_req, DAO_CARD_FW_UPDATE);
	if (rc == 0 && boot_bin_path != NULL) {
		boot_rc = reload_and_bringup_octeon_ep(boot_bin_path, "mmc", DAO_CARD_MGR_BOOT_IP);

		if (boot_rc != 0)
			DAO_CARD_ERR("Boot exec / readiness failed after fw update: %d", boot_rc);
	}

req_free:
	free(update_req.filename);
	free(update_req.filepath);
	if (boot_bin_path)
		free(boot_bin_path);
	return rc;
}
