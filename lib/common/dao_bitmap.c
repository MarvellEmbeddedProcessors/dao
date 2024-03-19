/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#include <rte_malloc.h>

#include "dao_bitmap.h"
#include "dao_log.h"

static inline int
bitmap_ctzll(uint64_t slab)
{
	if (slab == 0)
		return 0;

	return __builtin_ctzll(slab);
}

int
dao_bmap_index_free(struct rte_bitmap *bmp, uint16_t index)
{
	if (!bmp)
		DAO_ERR_GOTO(-EINVAL, fail, "Bitmap is not setup properly");

	if (rte_bitmap_get(bmp, index))
		DAO_ERR_GOTO(-EINVAL, fail, "Index %d was not allocated", index);

	rte_bitmap_set(bmp, index);

	return 0;
fail:
	return errno;
}

int
dao_bmap_index_alloc(struct rte_bitmap *bmp)
{
	uint16_t idx, rc;
	uint64_t slab;
	uint32_t pos;

	if (!bmp)
		DAO_ERR_GOTO(-EINVAL, fail, "Bitmap is not setup properly");

	pos = 0;
	slab = 0;
	/* Scan from the beginning */
	__rte_bitmap_scan_init(bmp);
	/* Scan bitmap to get the free pool */
	rc = rte_bitmap_scan(bmp, &pos, &slab);
	/* Empty bitmap */
	if (rc == 0)
		DAO_ERR_GOTO(-EINVAL, fail, "Empty bitmap");

	idx = pos + bitmap_ctzll(slab);
	rte_bitmap_clear(bmp, idx);

	return idx;
fail:
	return errno;
}

struct rte_bitmap *
dao_bmap_index_map_setup(uint32_t bmap_max_sz)
{
	struct rte_bitmap *bmp;
	uint32_t bmap_sz, id;
	void *bmap_mem;

	if (!bmap_max_sz)
		DAO_ERR_GOTO(-EINVAL, fail, "Bitmap size cannot be zero");

	bmap_sz = rte_bitmap_get_memory_footprint(bmap_max_sz);

	/* Allocate memory for bitmap */
	bmap_mem = rte_zmalloc("bmap_mem", bmap_sz, RTE_CACHE_LINE_SIZE);
	if (bmap_mem == NULL)
		DAO_ERR_GOTO(-ENOMEM, fail, "Failed to allocate memory for bmap");

	/* Initialize bitmap */
	bmp = rte_bitmap_init(bmap_max_sz, bmap_mem, bmap_sz);
	if (!bmp)
		DAO_ERR_GOTO(-EIO, fail, "Failed to initialize bitmap");

	/* Set all the queue initially */
	for (id = 1; id < bmap_max_sz; id++)
		rte_bitmap_set(bmp, id);

	return bmp;
fail:
	return NULL;
}
