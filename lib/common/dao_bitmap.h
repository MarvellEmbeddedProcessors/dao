/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

/**
 * @file
 *
 * DAO Bitmap helper
 */

#ifndef __DAO_BITMAP_H__
#define __DAO_BITMAP_H__

#include <rte_bitmap.h>

/**
 * Setting up a bitmap of the user required size
 *
 * @param bmap_max_sz
 *    Max size of the bitmap
 * @return
 *    bitmap handle on success, NULL on failure.
 */
struct rte_bitmap *dao_bmap_index_map_setup(uint32_t bmap_max_sz);

/**
 * Return bitmap index
 *
 * @param bmp
 *    Bitmap handle
 * @param index
 *    Index to be freed
 * @return
 *    0 on success, negative on failure.
 */
int dao_bmap_index_free(struct rte_bitmap *bmp, uint16_t index);

/**
 * Get a free bitmap index
 *
 * @param bmp
 *    Bitmap handle
 * @return
 *    Index on success, negative on failure.
 */
int dao_bmap_index_alloc(struct rte_bitmap *bmp);

#endif /* __DAO_BITMAP_H__ */
