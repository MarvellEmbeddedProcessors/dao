/* SPDX-License-Identifier: Marvell-Proprietary
 * Copyright (c) 2025 Marvell
 */

#include "dao_blk_dev.h"
#include "ramdisk.h"

extern struct dao_blkdev dao_blkdevs[];

int ramdisk_read(uint16_t devid, uint64_t sector, dao_blk_io_vec_t *iov, size_t len)
{
	struct dao_blkdev *dev = &dao_blkdevs[devid];
	ramdisk_dev_t *rdisk = dev->priv_data;
	uint64_t offset = sector * rdisk->sector_size;
	int64_t tot_len = len, cur_len, i;

	if (RDISK_IS_REQ_CROSSING_LIMIT(rdisk, offset, len))
		return DAO_BLK_DEV_REQ_FAIL;

	for (i = 0; (i < iov->buf_cnt && (tot_len > 0)); i++) {
		cur_len = RTE_MIN(iov->bufs[i].size, tot_len);
		memcpy(iov->bufs[i].data, rdisk->data + offset, cur_len);
		offset += cur_len;
		tot_len -= cur_len;
	}
	rdisk->stats.read_ops++;
	rdisk->stats.bytes_read += len;
	return DAO_BLK_DEV_REQ_COMPGOOD;
}

int ramdisk_write(uint16_t devid, uint64_t sector, dao_blk_io_vec_t *iov, size_t len)
{
	struct dao_blkdev *dev = &dao_blkdevs[devid];
	ramdisk_dev_t *rdisk = dev->priv_data;
	uint64_t offset = sector * rdisk->sector_size;
	int64_t tot_len = len, cur_len, i;

	if (RDISK_IS_REQ_CROSSING_LIMIT(rdisk, offset, len))
		return DAO_BLK_DEV_REQ_FAIL;

	for (i = 0; (i < iov->buf_cnt && (tot_len > 0)); i++) {
		cur_len = RTE_MIN(iov->bufs[i].size, tot_len);
		memcpy(rdisk->data + offset, iov->bufs[i].data, cur_len);
		offset += cur_len;
		tot_len -= cur_len;
	}

	rdisk->stats.write_ops++;
	rdisk->stats.bytes_written += len;
	return DAO_BLK_DEV_REQ_COMPGOOD;
}

int ramdisk_flush(uint16_t devid)
{
	struct dao_blkdev *dev = &dao_blkdevs[devid];
	ramdisk_dev_t *rdisk = dev->priv_data;

	/** RAM disk doesn't need flushing */
	rdisk->stats.flush_ops++;
	return DAO_BLK_DEV_REQ_COMPGOOD;
}

int ramdisk_reset(uint16_t devid)
{
	struct dao_blkdev *dev = &dao_blkdevs[devid];
	ramdisk_dev_t *rdisk = dev->priv_data;

	memset(rdisk->data, 0, rdisk->capacity * rdisk->sector_size);
	rdisk->stats.reset_ops++;
	return DAO_BLK_DEV_REQ_COMPGOOD;
}

int ramdisk_unmap(uint16_t devid, uint64_t sector, size_t len)
{
	struct dao_blkdev *dev = &dao_blkdevs[devid];
	ramdisk_dev_t *rdisk = dev->priv_data;
	uint64_t offset = sector * rdisk->sector_size;

	if (RDISK_IS_REQ_CROSSING_LIMIT(rdisk, offset, len))
		return DAO_BLK_DEV_REQ_FAIL;

	memset(rdisk->data + offset, 0, len);
	rdisk->stats.unmap_ops++;
	return DAO_BLK_DEV_REQ_COMPGOOD;
}

int ramdisk_write_zeroes(uint16_t devid, uint64_t sector, size_t len,
			 __rte_unused uint8_t unmap)
{
	return ramdisk_unmap(devid, sector, len);
}

int ramdisk_get_blk_id(uint16_t devid, char *name, size_t max_len)
{
	struct dao_blkdev *dev = &dao_blkdevs[devid];
	ramdisk_dev_t *rdisk = dev->priv_data;

	if (!rdisk)
		return DAO_BLK_DEV_REQ_FAIL;

	if (max_len > sizeof(rdisk->name))
		memcpy(name, rdisk->name, sizeof(rdisk->name));
	else
		memcpy(name, rdisk->name, max_len);

	return DAO_BLK_DEV_REQ_COMPGOOD;
}

void ramdisk_get_stats(uint16_t devid, dao_blkdev_stats_t *stats)
{
	struct dao_blkdev *dev = &dao_blkdevs[devid];
	ramdisk_dev_t *rdisk = dev->priv_data;

	*stats = rdisk->stats;
}

void ramdisk_clear_stats(uint16_t devid)
{
	struct dao_blkdev *dev = &dao_blkdevs[devid];
	ramdisk_dev_t *rdisk = dev->priv_data;

	memset(&rdisk->stats, 0, sizeof(dao_blkdev_stats_t));
}

void ramdisk_get_features(uint16_t devid, uint64_t *feat)
{
	struct dao_blkdev *dev = &dao_blkdevs[devid];
	ramdisk_dev_t *rdisk = dev->priv_data;

	/* If no ramdisk is attached to devid, no feature bits will be set */
	if (!rdisk)
		return;
	*feat = rdisk->feat;
}

dao_blkdev_handlers_t ramdisk_handlers = {
	.read = ramdisk_read,
	.write = ramdisk_write,
	.flush = ramdisk_flush,
	.reset = ramdisk_reset,
	.unmap = ramdisk_unmap,
	.write_zeroes = ramdisk_write_zeroes,
	.get_id = ramdisk_get_blk_id,
	.get_stats = ramdisk_get_stats,
	.clear_stats = ramdisk_clear_stats,
	.get_features = ramdisk_get_features
};

int ramdisk_create(uint16_t devid, struct dao_blkdev_conf *conf)
{
	struct dao_blkdev *dev;
	ramdisk_dev_t *rdisk;
	char rdisk_i[RDISK_NAME_STR_LEN + 1];
	char rd_name[DAO_MAX_BLKDEV_ID_STRLEN];

	snprintf(rdisk_i, sizeof(rdisk_i), "rdisk_info_%d", (int)devid);
	snprintf(rd_name, sizeof(rd_name), "ramdisk_%d", (int)devid);
	rdisk = rte_zmalloc(rdisk_i, sizeof(ramdisk_dev_t), RTE_CACHE_LINE_SIZE);
	if (!rdisk)
		return -ENOMEM;

	rdisk->data = rte_zmalloc(rd_name, conf->capacity * conf->blk_size, conf->blk_size);
	if (!rdisk->data) {
		rte_free(rdisk);
		return -ENOMEM;
	}

	memcpy(rdisk->name, rd_name,
	       RTE_MIN(sizeof(rd_name), sizeof(rdisk->name)));
	rdisk->capacity = conf->capacity;
	rdisk->sector_size = conf->blk_size;

	dev = &dao_blkdevs[devid];
	dev->handlers = &ramdisk_handlers;
	dev->dev_type = DAO_BLK_DEV_RAMDISK;
	dev->priv_data = rdisk;
	return 0;
}

int ramdisk_destroy(uint16_t devid)
{
	struct dao_blkdev *dev = &dao_blkdevs[devid];
	ramdisk_dev_t *rdisk;
	int ret = -1;

	if (dev) {
		rdisk = dev->priv_data;
		if (rdisk) {
			rte_free(rdisk->data);
			rte_free(rdisk);
			ret = 0;
		}
	}
	return ret;
}
