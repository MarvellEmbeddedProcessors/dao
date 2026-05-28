/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2026 Marvell.
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <dao_log.h>

#include "cn10k_cdev.h"

#define CN10K_CDEV_PATH         "/dev"
#define CN10K_CDEV_NODE_PFX     "octterm"
#define CN10K_CDEV_NODE_PFX_LEN 7
#define CN10K_CDEV_NAME_MAX     32

#define OCTEON_CDEV_IOC_MAGIC   'O'
#define OCTEON_CDEV_GET_SIZE    _IOR(OCTEON_CDEV_IOC_MAGIC, 1, size_t)
#define OCTEON_CDEV_GET_STRM_ID _IOR(OCTEON_CDEV_IOC_MAGIC, 2, uint32_t)
#define OCTEON_CDEV_GET_MAX_VFS _IOR(OCTEON_CDEV_IOC_MAGIC, 3, uint32_t)

/* Keep at the end  */
#define OCTEON_CDEV_FW_READY   _IO(OCTEON_CDEV_IOC_MAGIC, 4)
#define OCTEON_CDEV_FW_CLEANUP _IO(OCTEON_CDEV_IOC_MAGIC, 5)

int dao_pem_fw_ready_notify(uint16_t pem_devid);

int
cn10k_cdev_name_get(char *name, size_t len)
{
	char path[PATH_MAX];
	struct dirent *e;
	unsigned int idx;
	DIR *dir;
	int end, n;
	int rc = -1;

	if (!name || len < CN10K_CDEV_NAME_MAX)
		return -EINVAL;

	dir = opendir(CN10K_CDEV_PATH);
	if (dir == NULL) {
		dao_err("Failed to open %s", CN10K_CDEV_PATH);
		return -1;
	}

	while ((e = readdir(dir)) != NULL) {
		struct stat st;

		if (strncmp(e->d_name, CN10K_CDEV_NODE_PFX, CN10K_CDEV_NODE_PFX_LEN))
			continue;

		end = 0;
		if (sscanf(e->d_name, "octterm%u%n", &idx, &end) != 1)
			continue;
		if (e->d_name[end] != '\0')
			continue;

		n = snprintf(path, sizeof(path), "%s/%s", CN10K_CDEV_PATH, e->d_name);
		if (n < 0 || (size_t)n >= sizeof(path))
			continue;

		if (stat(path, &st) != 0)
			continue;
		if (!S_ISCHR(st.st_mode))
			continue;

		if (snprintf(name, len, "%s", path) >= (int)len)
			continue;

		rc = 0;
		break;
	}

	closedir(dir);
	return rc;
}

static int
cn10k_cdev_find_dev_path(char *path, size_t pathlen)
{
	if (cn10k_cdev_name_get(path, pathlen) < 0)
		return -ENOENT;
	return 0;
}

int
cn10k_cdev_init(struct cn10k_cdev_device *dev)
{
	char devpath[CN10K_CDEV_NAME_MAX];
	uint32_t sec_strm_id = 0;
	uint32_t max_vfs = 0;
	size_t map_size = 0;
	int fd, rc;

	if (!dev) {
		dao_err("Invalid device");
		return -EINVAL;
	}
	memset(dev, 0, sizeof(struct cn10k_cdev_device));
	dev->fd = -1;

	if (cn10k_cdev_find_dev_path(devpath, sizeof(devpath)) < 0) {
		dao_err("Unable to find character device ");
		return -ENOENT;
	}
	fd = open(devpath, O_RDWR | O_SYNC);
	if (fd < 0) {
		dao_err("Failed to open %s: %s", devpath, strerror(errno));
		return -errno;
	}
	rc = ioctl(fd, OCTEON_CDEV_GET_SIZE, &map_size);
	if (rc < 0) {
		dao_err("Failed to get size from %s: %s", devpath, strerror(errno));
		close(fd);
		return -errno;
	}
	rc = ioctl(fd, OCTEON_CDEV_GET_STRM_ID, &sec_strm_id);
	if (rc < 0) {
		dao_err("Failed to get stream ID from %s: %s", devpath, strerror(errno));
		close(fd);
		return -errno;
	}

	rc = ioctl(fd, OCTEON_CDEV_GET_MAX_VFS, &max_vfs);
	if (rc < 0 || max_vfs == 0) {
		dao_err("Failed to get max_vfs from kernel: rc=%d, max_vfs=%u", rc, max_vfs);
		close(fd);
		return -EINVAL;
	}
	dev->base = mmap(NULL, map_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (dev->base == MAP_FAILED) {
		dao_err("Failed to mmap %s: %s", devpath, strerror(errno));
		close(fd);
		return -errno;
	}
	dev->fd = fd;
	dev->size = map_size;
	dev->size_per_dev = map_size / max_vfs;
	dev->sec_strm_id = (uint8_t)sec_strm_id;
	dev->max_vfs = (uint8_t)max_vfs;

	dao_info("CN10K character device initialized successfully");
	dao_info("  fd=%d, addr=%p, size=%zu, per_dev=%zu, max_vfs=%u, sec_strm_id=%u", fd,
		 dev->base, map_size, dev->size_per_dev, max_vfs, sec_strm_id);

	return 0;
}

int
cn10k_cdev_fw_ready_notify(struct cn10k_cdev_device *dev)
{
	size_t arg = 0;
	int rc;

	if (!dev || dev->fd < 0)
		return -EINVAL;

	rc = ioctl(dev->fd, OCTEON_CDEV_FW_READY, &arg);
	if (rc < 0) {
		dao_err("OCTEON_CDEV_FW_READY ioctl failed: %s", strerror(errno));
		return -errno;
	}
	return 0;
}

int
cn10k_cdev_fw_cleanup_notify(struct cn10k_cdev_device *dev)
{
	size_t arg = 0;
	int rc;

	if (!dev || dev->fd < 0)
		return -EINVAL;

	rc = ioctl(dev->fd, OCTEON_CDEV_FW_CLEANUP, &arg);
	if (rc < 0) {
		dao_err("OCTEON_CDEV_FW_CLEANUP ioctl failed: %s", strerror(errno));
		return -errno;
	}
	return 0;
}

void
cn10k_cdev_fini(struct cn10k_cdev_device *dev)
{
	if (!dev)
		return;

	if (dev->base && dev->base != MAP_FAILED) {
		munmap(dev->base, dev->size);
		dev->base = NULL;
	}

	if (dev->fd >= 0) {
		close(dev->fd);
		dev->fd = -1;
	}
}

void *
cn10k_cdev_base_get(struct cn10k_cdev_device *dev)
{
	return dev ? dev->base : NULL;
}

size_t
cn10k_cdev_size_get(struct cn10k_cdev_device *dev)
{
	return dev ? dev->size : 0;
}

uint8_t
cn10k_cdev_sec_strm_id_get(struct cn10k_cdev_device *dev)
{
	return dev ? dev->sec_strm_id : 0;
}

uint16_t
cn10k_cdev_max_vfs_get(struct cn10k_cdev_device *dev)
{
	return dev ? dev->max_vfs : 0;
}

int
cn10k_cdev_sec_strm_id_get_early(uint8_t *sec_strm_id)
{
	char devpath[CN10K_CDEV_NAME_MAX];
	uint32_t id = 0;
	int fd, rc;

	if (!sec_strm_id)
		return -EINVAL;

	if (cn10k_cdev_find_dev_path(devpath, sizeof(devpath)) < 0)
		return -ENOENT;

	fd = open(devpath, O_RDONLY);
	if (fd < 0)
		return -errno;

	rc = ioctl(fd, OCTEON_CDEV_GET_STRM_ID, &id);
	close(fd);

	if (rc < 0)
		return -errno;

	*sec_strm_id = (uint8_t)id;
	return 0;
}

int
cn10k_cdev_max_vfs_get_early(uint16_t *max_vfs)
{
	char devpath[CN10K_CDEV_NAME_MAX];
	uint32_t vfs = 0;
	int fd, rc;

	if (!max_vfs)
		return -EINVAL;

	if (cn10k_cdev_find_dev_path(devpath, sizeof(devpath)) < 0)
		return -ENOENT;

	fd = open(devpath, O_RDONLY);
	if (fd < 0)
		return -errno;

	rc = ioctl(fd, OCTEON_CDEV_GET_MAX_VFS, &vfs);
	close(fd);

	if (rc < 0)
		return -errno;

	*max_vfs = (uint8_t)vfs;
	return 0;
}
