/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef CARD_MGR_LOCK_H
#define CARD_MGR_LOCK_H

#include <stdbool.h>

/**
 * Simple operation tracking to prevent immediate retry after crash
 *
 * This module provides a lightweight mechanism to:
 * 1. Detect if a previous operation was interrupted (crash/kill)
 * 2. Enforce a cooldown period before allowing retry
 * 3. Log operation start/end for audit trail
 */

/**
 * Start an update operation
 *
 * @param operation Name of operation (e.g., "app_update", "fw_update")
 * @return 0 on success
 *         -EAGAIN if previous operation interrupted, cooldown active
 *         -errno on other errors
 *
 * Thread Safety: Single-threaded server, no mutex needed
 */
int dao_card_operation_start(const char *operation);

/**
 * End an update operation
 *
 * @param success true if operation completed successfully, false if failed
 *
 * If success=true:  Removes marker file (no cooldown for next operation)
 * If success=false: Keeps marker file (enforces 12-min cooldown)
 *
 * Thread Safety: Single-threaded server, no mutex needed
 */
void dao_card_operation_end(bool success);

#endif /* CARD_MGR_LOCK_H */
