/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2023 Marvell.
 */

/**
 * @file
 *
 * DPU Accelerator Offloads Version header
 *
 */

#ifndef __DAO_VERSION_H__
#define __DAO_VERSION_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <dao_config.h>

/**
 * DPU Accelerator Offloads get version
 *
 * @retval   DPU Accelerator Offloads a Version String format:
 *	     SDK version-DPDK version-git_commit
 */
static inline const char *
dao_version(void)
{
	return DAO_VERSION;
}

#ifdef __cplusplus
}
#endif

#endif /* __DAO_VERSION_H__ */
