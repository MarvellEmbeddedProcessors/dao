/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef _VC_OFFLOAD_H_
#define _VC_OFFLOAD_H_

#include <rte_log.h>

/* Log type */
#define RTE_LOGTYPE_VC_OFFLOAD    RTE_LOGTYPE_USER1
#define APP_INFO(fmt, args...)    RTE_LOG(INFO, VC_OFFLOAD, fmt, ##args)
#define APP_INFO_NH(fmt, args...) rte_log(RTE_LOG_INFO, RTE_LOGTYPE_VC_OFFLOAD, fmt, ##args)
#define APP_ERR(fmt, args...)     RTE_LOG(ERR, VC_OFFLOAD, fmt, ##args)

#endif /* _VC_OFFLOAD_H_ */
