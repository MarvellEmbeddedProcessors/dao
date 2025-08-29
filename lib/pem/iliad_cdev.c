/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <rte_common.h>
#include <rte_log.h>

#include "dao_log.h"
#include "iliad_cdev.h"
#include "pem.h"

#define ILIAD_CDEV_PATH        "/dev/iliad_cdev"
#define ILIAD_CDEV_ODM_SIZE    (1ULL << 20) /* 1MB */
#define ILIAD_CDEV_BAR4_OFFSET 0            /* BAR4 memory region */
#define ILIAD_CDEV_ODM_OFFSET  1            /* ODM PF memory region */

int
iliad_cdev_init(struct iliad_cdev_device *dev)
{
	void *bar4_mem, *odm_mem;
	size_t bar4_size;
	struct stat st;
	int fd = -1;

	if (!dev) {
		dao_err("Invalid device pointer");
		return -EINVAL;
	}

	memset(dev, 0, sizeof(struct iliad_cdev_device));

	if (stat(ILIAD_CDEV_PATH, &st) != 0) {
		dao_err("Character device %s not found: %s", ILIAD_CDEV_PATH, strerror(errno));
		return -ENOENT;
	}

	if (!S_ISCHR(st.st_mode)) {
		dao_err("%s is not a character device", ILIAD_CDEV_PATH);
		return -ENOTTY;
	}

	fd = open(ILIAD_CDEV_PATH, O_RDWR);
	if (fd < 0) {
		dao_err("Failed to open %s: %s", ILIAD_CDEV_PATH, strerror(errno));
		return -errno;
	}

	/* Map BAR4 memory region */
	bar4_size = PEM_BAR4_INDEX_SIZE * PEM_BAR4_NUM_INDEX;
	bar4_mem = mmap(NULL, bar4_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd,
			(off_t)ILIAD_CDEV_BAR4_OFFSET * getpagesize());
	if (bar4_mem == MAP_FAILED) {
		dao_err("Failed to mmap BAR4 memory: %s", strerror(errno));
		goto err_close;
	}

	/* Map ODM PF memory region */
	odm_mem = mmap(NULL, ILIAD_CDEV_ODM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd,
		       (off_t)ILIAD_CDEV_ODM_OFFSET * getpagesize());
	if (odm_mem == MAP_FAILED) {
		dao_err("Failed to mmap ODM memory: %s", strerror(errno));
		goto err_unmap_bar4;
	}

	dev->fd = fd;
	dev->bar4_base = bar4_mem;
	dev->odm_base = odm_mem;

	dao_info("Iliad character device initialized successfully");
	dao_info("  BAR4: %p (size: 0x%lx)", dev->bar4_base,
		 (unsigned long)(PEM_BAR4_INDEX_SIZE * PEM_BAR4_NUM_INDEX));
	dao_info("  ODM:  %p (size: 0x%lx)", dev->odm_base, (unsigned long)ILIAD_CDEV_ODM_SIZE);

	return 0;

err_unmap_bar4:
	munmap(bar4_mem, bar4_size);
err_close:
	close(fd);
	return -errno;
}

void
iliad_cdev_fini(struct iliad_cdev_device *dev)
{
	if (!dev)
		return;

	if (dev->bar4_base) {
		munmap(dev->bar4_base, PEM_BAR4_INDEX_SIZE * PEM_BAR4_NUM_INDEX);
		dev->bar4_base = NULL;
	}

	if (dev->odm_base) {
		munmap(dev->odm_base, ILIAD_CDEV_ODM_SIZE);
		dev->odm_base = NULL;
	}

	if (dev->fd >= 0) {
		close(dev->fd);
		dev->fd = -1;
	}

	dao_info("Iliad character device finalized");
}
