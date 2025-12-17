/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef MODULE_UTILS_H
#define MODULE_UTILS_H

#include "../card_mgr.h"

/* Module management functions */
int reload_octeon_ep_module(const char *boot_arg, octeon_ep_module_op operation);
int module_present(const char *name);
int wait_for_module_absent(const char *name, int timeout_ms);
int wait_for_module_present(const char *name, int timeout_ms);
int sanitize_module_path(const char *p);
int run_cmd(const char *cmd);
void bring_up_octeon_ep_interface(const char *ip_addr);

#endif /* MODULE_UTILS_H */
