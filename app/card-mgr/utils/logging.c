/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <syslog.h>

#include <dao_log.h>

#include "../card_mgr.h"
#include "logging.h"

static __thread char *dao_card_err_buf;
static __thread size_t dao_card_err_buf_len;

void
dao_card_err_ctx_set(char *buf, size_t len)
{
	dao_card_err_buf = buf;
	dao_card_err_buf_len = len;
	if (buf && len)
		buf[0] = '\0';
}

void
dao_card_err_ctx_clear(void)
{
	dao_card_err_buf = NULL;
	dao_card_err_buf_len = 0;
}

void
dao_card_log_err_internal(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsyslog(LOG_ERR, fmt, ap);
	va_end(ap);

	if (dao_card_err_buf && dao_card_err_buf_len && dao_card_err_buf[0] == '\0') {
		va_start(ap, fmt);
		vsnprintf(dao_card_err_buf, dao_card_err_buf_len, fmt, ap);
		va_end(ap);
	}
}

void
dao_card_log_info_internal(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsyslog(LOG_INFO, fmt, ap);
	va_end(ap);

	/* Also capture info messages to error buffer if empty */
	if (dao_card_err_buf && dao_card_err_buf_len && dao_card_err_buf[0] == '\0') {
		va_start(ap, fmt);
		vsnprintf(dao_card_err_buf, dao_card_err_buf_len, fmt, ap);
		va_end(ap);
	}
}

void
dao_card_signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		/* Only use async-signal-safe operations in signal handlers.
		 * atomic_store_explicit is safe. The main event loop will detect
		 * dao_card_force_quit and exit cleanly without additional cleanup required.
		 */
		atomic_store_explicit(&dao_card_force_quit, true, memory_order_release);
	}
}
