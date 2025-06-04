/* SPDX-License-Identifier: Marvell-Proprietary
 * Copyright (c) 2025 Marvell
 */

#ifndef __INCLUDE_RAMDISK_H__
#define __INCLUDE_RAMDISK_H__

#include <stdint.h>
#include <rte_malloc.h>
#include <dao_util.h>

#define RDISK_IS_REQ_CROSSING_LIMIT(rdisk, offset, len)		\
		(((offset) + (len)) > ((rdisk)->capacity * (rdisk)->sector_size))

#define RDISK_NAME_STR_LEN		(64)

typedef struct {
	/** Data buffer of ramdisk */
	uint8_t *data;
	/** Ram disk name identifier */
	char name[RDISK_NAME_STR_LEN];
	/** Disk capacity in terms of sectors/blocks */
	uint64_t capacity;
	/** Features supported on the block device */
	uint64_t feat;
	/** Disk statistics */
	dao_blkdev_stats_t stats;
	/** Sector size of ramdisk */
	uint32_t sector_size;
} ramdisk_dev_t;

int ramdisk_read(uint16_t devid, uint64_t sector, dao_blk_io_vec_t *iov, size_t len);
int ramdisk_write(uint16_t devid, uint64_t sector, dao_blk_io_vec_t *iov, size_t len);
int ramdisk_flush(uint16_t devid);
int ramdisk_reset(uint16_t devid);
int ramdisk_unmap(uint16_t devid, uint64_t sector, size_t len);
int ramdisk_write_zeroes(uint16_t devid, uint64_t sector, size_t len,
			 __rte_unused uint8_t unmap);
int ramdisk_get_blk_id(uint16_t devid, char *name, size_t max_len);
void ramdisk_get_stats(uint16_t devid, dao_blkdev_stats_t *stats);
void ramdisk_clear_stats(uint16_t devid);
void ramdisk_get_features(uint16_t devid, uint64_t *feat);

int ramdisk_create(uint16_t devid, struct dao_blkdev_conf *conf);
int ramdisk_destroy(uint16_t devid);
#endif
