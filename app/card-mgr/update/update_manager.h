/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef UPDATE_MANAGER_H
#define UPDATE_MANAGER_H

#include "../card_mgr.h"

/* Update management functions */
int dao_card_mgr_update_init_args(cli_args *cmd, const char **new_argv, unsigned long *nb_desc);
int image_version_get(char *image_ver_buf, size_t image_ver_len);
int image_compatibility_check(const char *tar_file_path, const char *image_ver_buf);
int dao_card_mgr_get_image_version(char *image_ver_buf, size_t image_ver_len, char *app_ver_buf,
				   size_t app_ver_len, char *combined_buf, size_t combined_len);

/* Boot management functions */
int dao_card_mgr_boot_exec(const char *boot_path, const char *boot_arg);
int reload_and_bringup_octeon_ep(const char *boot_bin_path, const char *boot_arg,
				 const char *ip_addr);
int dao_card_mgr_boot(cli_args *cmd);
int dao_card_mgr_reboot(void);
int dao_card_wait_ready(int timeout_ms, int interval_ms);

#endif /* UPDATE_MANAGER_H */
