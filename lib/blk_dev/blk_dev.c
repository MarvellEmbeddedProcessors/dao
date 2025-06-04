/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include "dao_blk_dev.h"
#include "ramdisk.h"

struct dao_blkdev dao_blkdevs[DAO_BLKDEV_MAX + 1];

const char *
dao_blkdev_type_to_str(int type)
{
	switch (type) {
	case DAO_BLK_DEV_RAMDISK:
		return "RAMDISK";
	default:
		return "UNKNOWN";
	}
}

int
dao_blkdev_type_from_str(const char *name)
{
	if (!name)
		return -1;

	if (strncmp(name, "ramdisk", 7) == 0)
		return DAO_BLK_DEV_RAMDISK;
	else
		return -1;
}

int
dao_blkdev_create(uint16_t dev_id, struct dao_blkdev_conf *conf,
		  const char *name)
{
	struct dao_blkdev *dev;
	int type;

	if (dev_id > DAO_BLKDEV_MAX)
		return -1;

	dev = &dao_blkdevs[dev_id];
	type = dao_blkdev_type_from_str(name);

	switch (type) {
	case DAO_BLK_DEV_RAMDISK:
		dev->dev_type = DAO_BLK_DEV_RAMDISK;
		return ramdisk_create(dev_id, conf);

	default:
		return -1;
	}
}

int
dao_blkdev_destroy(uint16_t dev_id)
{
	struct dao_blkdev *dev;
	int type;

	if (dev_id > DAO_BLKDEV_MAX)
		return -1;

	dev = &dao_blkdevs[dev_id];
	type = dev->dev_type;

	switch (type) {
	case DAO_BLK_DEV_RAMDISK:
		return ramdisk_destroy(dev_id);
	default:
		return -1;
	}
}

int dao_blkdev_read(uint16_t devid, uint64_t sector, dao_blk_io_vec_t *iov, size_t len)
{
	struct dao_blkdev *dev = &dao_blkdevs[devid];

	if (!dev || !dev->handlers || !dev->handlers->read)
		return DAO_BLK_DEV_REQ_UNSUPPORTED;

	return dev->handlers->read(devid, sector, iov, len);
}

int dao_blkdev_write(uint16_t devid, uint64_t sector, dao_blk_io_vec_t *iov, size_t len)
{
	struct dao_blkdev *dev = &dao_blkdevs[devid];

	if (!dev || !dev->handlers || !dev->handlers->write)
		return DAO_BLK_DEV_REQ_UNSUPPORTED;

	return dev->handlers->write(devid, sector, iov, len);
}

int dao_blkdev_flush(uint16_t devid)
{
	struct dao_blkdev *dev = &dao_blkdevs[devid];

	if (!dev || !dev->handlers || !dev->handlers->flush)
		return DAO_BLK_DEV_REQ_UNSUPPORTED;

	return dev->handlers->flush(devid);
}

int dao_blkdev_reset(uint16_t devid)
{
	struct dao_blkdev *dev = &dao_blkdevs[devid];

	if (!dev || !dev->handlers || !dev->handlers->reset)
		return DAO_BLK_DEV_REQ_UNSUPPORTED;

	return dev->handlers->reset(devid);
}

int dao_blkdev_unmap(uint16_t devid, uint64_t sector, size_t len)
{
	struct dao_blkdev *dev = &dao_blkdevs[devid];

	if (!dev || !dev->handlers || !dev->handlers->unmap)
		return DAO_BLK_DEV_REQ_UNSUPPORTED;

	return dev->handlers->unmap(devid, sector, len);
}

int dao_blkdev_write_zeroes(uint16_t devid, uint64_t sector, size_t len,
			    uint8_t unmap)
{
	struct dao_blkdev *dev = &dao_blkdevs[devid];

	if (!dev || !dev->handlers || !dev->handlers->write_zeroes)
		return DAO_BLK_DEV_REQ_UNSUPPORTED;

	return dev->handlers->write_zeroes(devid, sector, len, unmap);
}

int dao_blkdev_get_id(uint16_t devid, char *name, size_t max_len)
{
	struct dao_blkdev *dev = &dao_blkdevs[devid];

	if (!dev || !dev->handlers || !dev->handlers->get_id)
		return DAO_BLK_DEV_REQ_UNSUPPORTED;

	return dev->handlers->get_id(devid, name, max_len);
}

int dao_blkdev_discard(uint16_t devid, uint64_t sector, size_t len)
{
	struct dao_blkdev *dev = &dao_blkdevs[devid];

	if (!dev || !dev->handlers || !dev->handlers->discard)
		return DAO_BLK_DEV_REQ_UNSUPPORTED;

	return dev->handlers->discard(devid, sector, len);
}

void dao_blkdev_get_stats(uint16_t devid, dao_blkdev_stats_t *stats)
{
	struct dao_blkdev *dev = &dao_blkdevs[devid];

	if (dev && dev->handlers && dev->handlers->get_stats)
		dev->handlers->get_stats(devid, stats);
}

void dao_blkdev_clear_stats(uint16_t devid)
{
	struct dao_blkdev *dev = &dao_blkdevs[devid];

	if (dev && dev->handlers && dev->handlers->clear_stats)
		dev->handlers->clear_stats(devid);
}
