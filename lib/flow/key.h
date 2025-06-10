/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef __KEY_H__
#define __KEY_H__

#include <stddef.h>
#include <stdint.h>

#define NPC_MAX_LIDS           7
#define NPC_MAX_LTYPES_PER_LID 16
#define NPC_MAX_EXT_PER_LTYPE  2

struct key_config {
	uint8_t ltype;
	uint8_t lid;
	uint8_t offset_in_ltype;
	uint8_t offset_in_key;
	uint8_t size;
};

struct key_ext_opaque {
	struct ld_info {
		uint8_t offset_in_ltype;
		uint8_t offset_in_key;
		uint8_t size;
		uint8_t reserved;
	} ext_info[NPC_MAX_LIDS][NPC_MAX_LTYPES_PER_LID][NPC_MAX_EXT_PER_LTYPE];
};

enum table_type {
	TABLE_TYPE_EM,
	TABLE_TYPE_LPM,
	TABLE_TYPE_ACL,
};

#endif /* __KEY_H__ */
