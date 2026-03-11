/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef APP_UPDATE_H
#define APP_UPDATE_H

#include "../card_mgr.h"

/* Application update functions */
int dao_card_mgr_app_update(cli_args *cmd);
int dao_card_mgr_app_fallback(cli_args *cmd);

#endif /* APP_UPDATE_H */
