/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef __LC_AUTOTEST_H__
#define __LC_AUTOTEST_H__

#include <rte_log.h>

/* Log type */
#define RTE_LOGTYPE_TEST              RTE_LOGTYPE_USER1
#define TEST_LC_INFO(fmt, args...)    RTE_LOG(INFO, TEST, fmt "\n", ##args)
#define TEST_LC_INFO_NH(fmt, args...) rte_log(RTE_LOG_INFO, RTE_LOGTYPE_AGENT, fmt "\n", ##args)
#define TEST_LC_ERR(fmt, args...)     RTE_LOG(ERR, TEST, fmt "\n", ##args)

#endif /* __LC_AUTOTEST_H__ */
