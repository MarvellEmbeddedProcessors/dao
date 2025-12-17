/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef LOGGING_H
#define LOGGING_H

#include <stddef.h>

/* Error context management */
void dao_card_err_ctx_set(char *buf, size_t len);
void dao_card_err_ctx_clear(void);
void dao_card_log_err_internal(const char *fmt, ...);

/* Error logging macro */
#define DAO_CARD_ERR(fmt, ...) dao_card_log_err_internal((fmt), ##__VA_ARGS__)

#endif /* LOGGING_H */
