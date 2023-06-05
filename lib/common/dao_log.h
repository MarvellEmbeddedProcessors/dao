/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2023 Marvell.
 */

/**
 * @file
 *
 * DAO Log
 *
 * DAO logger APIs contains wrappers over DPDK based rte logger. It has API for
 * different log levels.
 */

#ifndef __DAO_LOG_H__
#define __DAO_LOG_H__

#include <errno.h>

#include <rte_log.h>
#include <rte_lcore.h>

extern int rte_dao_logtype;

#define dao_log(level, ...)                                                                        \
	rte_log(RTE_LOG_##level, rte_dao_logtype,                                                  \
		RTE_FMT("[lcore %2ld] DAO_" #level ": " RTE_FMT_HEAD(__VA_ARGS__,) "\n",          \
			rte_lcore_id() == LCORE_ID_ANY ? -1 : (int64_t)rte_lcore_id(),             \
			RTE_FMT_TAIL(__VA_ARGS__,)))

/**
 * @def dao_err
 * Log generic error with function name and line number prefix.
 */
#define dao_err(...)  dao_log(ERR, __VA_ARGS__)

/**
 * @def dao_warn
 * Log generic warning with function name and line number prefix.
 */
#define dao_warn(...) dao_log(WARNING, __VA_ARGS__)

/**
 * @def dao_info
 * Log generic info without function name and line number.
 */
#define dao_info(...) dao_log(INFO, __VA_ARGS__)

/**
 * @def dao_dbg
 * Log generic debug message with function name and line number prefix.
 */
#define dao_dbg(...)                                                                               \
	rte_log(RTE_LOG_DEBUG, rte_dao_logtype,                                                    \
		RTE_FMT("[lcore %2ld] DAO_DBG: %s():%d " RTE_FMT_HEAD(__VA_ARGS__,) "\n",         \
			rte_lcore_id() == LCORE_ID_ANY ? -1 : (int64_t)rte_lcore_id(), __func__,   \
			__LINE__, RTE_FMT_TAIL(__VA_ARGS__,)))

/**
 * @def dao_print
 * Log generic print without function name and line number.
 */
#define dao_print(...)                                                                             \
	rte_log(RTE_LOG_INFO, rte_dao_logtype,                                                     \
		RTE_FMT(RTE_FMT_HEAD(__VA_ARGS__,) "\n", RTE_FMT_TAIL(__VA_ARGS__, )))

/**
 * @def DAO_ERR_GOTO
 *
 * Jump to label with errno set.
 *
 */
#define DAO_ERR_GOTO(err, label, fmt, ...)                                                         \
	do {                                                                                       \
		dao_err(fmt, ##__VA_ARGS__);                                                       \
		errno = err;                                                                       \
		goto label;                                                                        \
	} while (0)

#endif /* __DAO_LOG_H__ */
