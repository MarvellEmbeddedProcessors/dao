/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

/**
 * @file
 *
 * DAO Platform Detection
 *
 * Platform detection utilities for identifying hardware platforms.
 */

#ifndef __DAO_PLATFORM_H__
#define __DAO_PLATFORM_H__

/** Types of platforms */
enum dao_platform {
	DAO_PLATFORM_INVALID = -1, /* Invalid platform */
	DAO_PLATFORM_CN10K = 0,    /* CN10K with SDP DPI */
	DAO_PLATFORM_ILIAD = 1,    /* Iliad with ODM */
};

/**
 * Detect platform by checking PCI subsystem_device and ODM device
 *
 * Detection mechanism:
 * - If subsystem_device is 0xc100, it is Iliad
 * - If subsystem_device is 0xb900, it is CN10K
 * - If ODM device is present (device_id bits <7:0> = 0x8b), it is Iliad
 *
 * @return
 *   Detected platform type or DAO_PLATFORM_INVALID if not detected
 */
enum dao_platform dao_platform_detect(void);

#endif /* __DAO_PLATFORM_H__ */
