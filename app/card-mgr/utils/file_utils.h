/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef FILE_UTILS_H
#define FILE_UTILS_H

#include "../card_mgr.h"
#include <dao_card_grpc_client.h>

/* File utility functions */
int split_path_filename(const char *input, char **out_path, char **out_file);
int validate_file(cli_args *cmd, struct dao_card_update_req *req, char **bootpath);

#endif /* FILE_UTILS_H */
