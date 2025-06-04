/* SPDX-License-Identifier: Marvell-Proprietary
 * Copyright (c) 2025 Marvell
 */

#ifndef __INCLUDE_DAO_BLK_DEV_H__
#define __INCLUDE_DAO_BLK_DEV_H__

#include <stdint.h>
#include <stdio.h>

#define DAO_BLKDEV_MAX			(128)
#define DAO_MAX_BLKDEV_ID_STRLEN	(20)

/** Type of block device */
typedef enum dao_blkdev_type {
	/** Block Device is ramdisk */
	DAO_BLK_DEV_RAMDISK = 1,
} dao_blkdev_type_t;

/** Stats structure of a block device */
typedef struct {
	/** Number of read operations on the block device */
	uint64_t read_ops;
	/** Number of write operations on the block device */
	uint64_t write_ops;
	/** Number of bytes read from the block device */
	uint64_t bytes_read;
	/** Number of bytes written on the block device */
	uint64_t bytes_written;
	/** Number of flush operations on the block device */
	uint64_t flush_ops;
	/** Number of reset operations on the block device */
	uint64_t reset_ops;
	/** Number of unmap operations on the block device */
	uint64_t unmap_ops;
	/** Number of write zeroes operations on the block device */
	uint64_t write_zeroes_ops;
} dao_blkdev_stats_t;

/** iobuf structure for data */
typedef struct blk_iobuf_ptr {
	void *data;
	uint32_t size;
} blk_iobuf_ptr_t;

/** Structure for vector of IO bufs */
typedef struct dao_blk_io_vec {
	uint32_t buf_cnt;
	blk_iobuf_ptr_t *bufs;
} dao_blk_io_vec_t;

/** Block device configuration */
struct dao_blkdev_conf {
	/** Block device capacity in sectors/blocks */
	uint64_t capacity;
	/** Block size */
	uint32_t blk_size;
	/** block device type */
	uint8_t dev_type;
};

/** Callback handlers exposed by block device */
typedef struct {
	int (*read)(uint16_t devid, uint64_t sector, dao_blk_io_vec_t *iov, size_t len);
	int (*write)(uint16_t devid, uint64_t sector, dao_blk_io_vec_t *iov, size_t len);
	int (*flush)(uint16_t devid);
	int (*reset)(uint16_t devid);
	int (*unmap)(uint16_t devid, uint64_t sector, size_t len);
	int (*write_zeroes)(uint16_t devid, uint64_t sector, size_t len, uint8_t unmap);
	int (*get_id)(uint16_t devid, char *name, size_t max_len);
	int (*discard)(uint16_t devid, uint64_t sector, size_t len);
	void (*get_stats)(uint16_t devid, dao_blkdev_stats_t *stats);
	void (*clear_stats)(uint16_t devid);
	void (*get_features)(uint16_t devid, uint64_t *feat);
} dao_blkdev_handlers_t;

/** Block device structure  */
typedef struct dao_blkdev {
	/** Various block device operation handlers */
	dao_blkdev_handlers_t *handlers;
	/** Private data for the underlying block device implementation */
	void *priv_data;
	/** Sector/blk size of the device */
	uint32_t sector_size;
	/** Device identifier for block device */
	uint32_t dev_id;
	/** Block device type as defined by dao_blkdev_type */
	uint8_t dev_type;
} dao_blkdev_t;

extern struct dao_blkdev dao_blkdevs[];

/** Status of Block device request */
typedef enum dao_blkdev_req_status {
	/** Block device request completed successfully */
	DAO_BLK_DEV_REQ_COMPGOOD,
	/** Block device request failed */
	DAO_BLK_DEV_REQ_FAIL,
	/** Unsupported block device request */
	DAO_BLK_DEV_REQ_UNSUPPORTED,
	/** Block device request is still in progress */
	DAO_BLK_DEV_REQ_IN_PROCESS
} dao_blkdev_req_status_t;

/**
 * DAO block device API to create a block device.
 *
 * @param dev_id
 *    Block device identifier
 * @param conf
 *    Block device config parameters
 * @param name
 *    Name/String identifier for the block device type
 *
 * @return
 *    0 on Success
 *
 */
int dao_blkdev_create(uint16_t dev_id, struct dao_blkdev_conf *conf,
		      const char *name);

/**
 * DAO block device API to destroy a block device.
 *
 * @param dev_id
 *    Block device identifier
 *
 * @return
 *    0 on Success
 */
int dao_blkdev_destroy(uint16_t devid);

/**
 * DAO block device API to read data from a block device.
 *
 * @param devid
 *    Block device identifier
 * @param sector
 *    start sector to read from
 * @param iov
 *    IO vector pointing to read buffers
 * @param len
 *    Read length
 *
 * @return
 *    Number of bytes read on Success
 */

int dao_blkdev_read(uint16_t devid, uint64_t sector, dao_blk_io_vec_t *iov, size_t len);

/**
 * DAO block device API to write data to a block device.
 *
 * @param devid
 *    Block device identifier
 * @param sector
 *    start sector to write into
 * @param iov
 *    IO vector pointing to write buffers
 * @param len
 *    Write length
 *
 * @return
 *    0 on Success
 */
int dao_blkdev_write(uint16_t devid, uint64_t sector, dao_blk_io_vec_t *iov, size_t len);

/**
 * DAO block device API to flush a block device.
 *
 * @param devid
 *    Block device identifier
 *
 * @return
 *    0 on Success
 */
int dao_blkdev_flush(uint16_t devid);

/**
 * DAO block device API to reset a block device.
 *
 * @param devid
 *    Block device identifier
 *
 * @return
 *    0 on Success
 */
int dao_blkdev_reset(uint16_t devid);

/**
 * DAO block device API to unmap a sector on a block device.
 *
 * @param devid
 *    Block device identifier
 * @param sector
 *    start sector to for unmap
 * @param len
 *    length in bytes to unmap
 *
 * @return
 *    0 on Success
 */
int dao_blkdev_unmap(uint16_t devid, uint64_t sector, size_t len);

/**
 * DAO block device API to write zeroes on to a block device.
 *
 * @param devid
 *    Block device identifier
 * @param sector
 *    start sector to write zeroes
 * @param len
 *    Write length
 * @param unmap
 *    flag to unmap the memory region
 *
 * @return
 *    0 on Success
 */
int dao_blkdev_write_zeroes(uint16_t devid, uint64_t sector, size_t len, uint8_t unmap);

/**
 * DAO block device API to get device identifier a block device in string form.
 *
 * @param devid
 *    Block device identifier
 * @param name
 *    Buffer to write the device ID string
 * @param max_len
 *    Maximum buffer length
 *
 * @return
 *    0 on Success
 */
int dao_blkdev_get_id(uint16_t devid, char *name, size_t max_len);

/**
 * DAO block device API to discard data in a sector of a block device
 *
 * @param devid
 *    Block device identifier
 * @param sector
 *    start sector to discard the data
 * @param len
 *    Length in bytes to discard
 *
 * @return
 *    0 on Success
 */
int dao_blkdev_discard(uint16_t devid, uint64_t sector, size_t len);

/**
 * DAO block device API to get device statistics of a block device
 *
 * @param devid
 *    Block device identifier
 * @param stats
 *    output where block device stats are updated
 */
void dao_blkdev_get_stats(uint16_t devid, dao_blkdev_stats_t *stats);

/**
 * DAO block device API to clear device statistics of a block device
 *
 * @param devid
 *    Block device identifier
 */
void dao_blkdev_clear_stats(uint16_t devid);

/**
 * DAO block device API to convert block device string to a block device enum
 * as defined in dao_blkdev_type
 *
 * @param type
 *    Block device type as a string
 *
 * @return
 *    block device enum type on Success
 */
int dao_blkdev_type_from_str(const char *type);

/**
 * DAO block device API to convert block device enum type to a block device
 * type string
 *
 * @param type
 *    Block device type as a enum
 *
 * @return
 *    block device type in string format on Success
 */
const char *dao_blkdev_type_to_str(int type);
#endif
