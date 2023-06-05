/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#include <fcntl.h>
#include <linux/limits.h>
#include <linux/vfio.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#include <dao_log.h>
#include <dao_vfio_platform.h>

#define VFIO_MAX_GROUPS           8
#define VFIO_GROUP_FMT            "/dev/vfio/%u"
#define PLATFORM_BUS_DEVICES_PATH "/sys/bus/platform/devices"

struct vfio_group {
	int group_num;
	int group_fd;
	int devices;
};

struct vfio_config {
	int container_fd;
	int active_groups;
	struct vfio_group groups[VFIO_MAX_GROUPS];
};

static struct vfio_config vfio_cfg = {.container_fd = -1};

int
dao_vfio_platform_init(void)
{
	int i;

	if (vfio_cfg.container_fd != -1) {
		dao_dbg("VFIO platform has already been initialized.");
		return 0;
	}

	vfio_cfg.container_fd = open("/dev/vfio/vfio", O_RDWR);
	if (vfio_cfg.container_fd < 0) {
		dao_err("Failed to open VFIO file descriptor");
		return -1;
	}

	vfio_cfg.active_groups = 0;
	for (i = 0; i < VFIO_MAX_GROUPS; i++) {
		vfio_cfg.groups[i].group_num = -1;
		vfio_cfg.groups[i].group_fd = -1;
		vfio_cfg.groups[i].devices = 0;
	}

	return 0;
}

static int
vfio_get_group_num(const char *sysfs_base, const char *dev_name, int *group_num)
{
	char linkname[PATH_MAX], filename[PATH_MAX];
	char *tok, *group_tok;
	int rc;

	memset(linkname, 0, sizeof(linkname));
	memset(filename, 0, sizeof(filename));

	snprintf(linkname, sizeof(linkname), "%s/%s/iommu_group", sysfs_base, dev_name);
	rc = readlink(linkname, filename, sizeof(filename));
	if (rc < 0)
		return -1;

	/* IOMMU group is always the last token */
	tok = strtok(filename, "/");
	if (!tok) {
		dao_err("Token not found");
		return -1;
	}

	group_tok = tok;
	while (tok) {
		group_tok = tok;
		tok = strtok(NULL, "/");
	}

	*group_num = strtol(group_tok, NULL, 10);

	return 0;
}

static int
vfio_get_group_fd(const char *dev_name)
{
	int group_fd, group_num, i, rc;
	char filename[PATH_MAX];

	rc = vfio_get_group_num(PLATFORM_BUS_DEVICES_PATH, dev_name, &group_num);
	if (rc < 0) {
		dao_err("%s: failed to get group number", dev_name);
		return -1;
	}

	for (i = 0; i < VFIO_MAX_GROUPS; i++) {
		if (vfio_cfg.groups[i].group_num == group_num) {
			vfio_cfg.groups[i].devices++;
			return vfio_cfg.groups[i].group_fd;
		}
	}

	snprintf(filename, sizeof(filename), VFIO_GROUP_FMT, group_num);
	group_fd = open(filename, O_RDWR);
	if (group_fd < 0) {
		dao_err("%s: failed to open %s", dev_name, filename);
		return -1;
	}

	for (i = 0; i < VFIO_MAX_GROUPS; i++) {
		if (vfio_cfg.groups[i].group_num == -1) {
			vfio_cfg.groups[i].group_num = group_num;
			vfio_cfg.groups[i].group_fd = group_fd;
			vfio_cfg.groups[i].devices = 1;
			vfio_cfg.active_groups++;
			return group_fd;
		}
	}

	dao_err("%s: Number of active groups surpasses the maximum supported limit", dev_name);
	close(group_fd);

	return -1;
}

static void
vfio_platform_device_mem_free(struct dao_vfio_platform_device *pdev)
{
	unsigned int i;

	for (i = 0; i < pdev->num_resource; i++)
		munmap(pdev->mem[i].addr, pdev->mem[i].len);

	free(pdev->mem);
}

static void
vfio_clear_group(int group_fd)
{
	int i;

	for (i = 0; i < VFIO_MAX_GROUPS; i++) {
		if (vfio_cfg.groups[i].group_fd == group_fd) {
			vfio_cfg.groups[i].devices--;
			if (!vfio_cfg.groups[i].devices) {
				close(group_fd);
				vfio_cfg.groups[i].group_num = -1;
				vfio_cfg.groups[i].group_fd = -1;
				vfio_cfg.active_groups--;
			}
		}
	}
}

int
dao_vfio_platform_device_setup(const char *dev_name, struct dao_vfio_platform_device *pdev)
{
	struct vfio_group_status group_status = {.argsz = sizeof(group_status)};
	struct vfio_device_info device_info = {.argsz = sizeof(device_info)};
	int group_fd, device_fd, rc;
	unsigned int i;

	group_fd = vfio_get_group_fd(dev_name);
	if (group_fd < 0)
		return -1;

	rc = ioctl(group_fd, VFIO_GROUP_GET_STATUS, &group_status);
	if (rc < 0) {
		dao_err("%s: failed to get group status", dev_name);
		goto clear_group;
	}

	if (!(group_status.flags & VFIO_GROUP_FLAGS_VIABLE)) {
		dao_err("%s: VFIO group is not viable! "
			"Not all devices in IOMMU group bound to VFIO or unbound",
			dev_name);
		goto clear_group;
	}

	if (!(group_status.flags & VFIO_GROUP_FLAGS_CONTAINER_SET)) {
		if (ioctl(group_fd, VFIO_GROUP_SET_CONTAINER, &vfio_cfg.container_fd)) {
			dao_err("%s: failed to add VFIO group to container", dev_name);
			goto clear_group;
		}
	}

	if (vfio_cfg.active_groups == 1) {
		/* Configured only once after the assignment of the first group. */
		rc = ioctl(vfio_cfg.container_fd, VFIO_SET_IOMMU, VFIO_TYPE1_IOMMU);
		if (rc) {
			dao_err("%s: failed to set IOMMU type", dev_name);
			goto clear_group;
		}
	}

	device_fd = ioctl(group_fd, VFIO_GROUP_GET_DEVICE_FD, dev_name);
	if (device_fd < 0) {
		dao_err("%s: failed to get device fd", dev_name);
		goto clear_group;
	}

	rc = ioctl(device_fd, VFIO_DEVICE_GET_INFO, &device_info);
	if (rc) {
		dao_err("%s: failed to get device info", dev_name);
		goto close_device_fd;
	}

	pdev->device_fd = device_fd;
	pdev->group_fd = group_fd;
	snprintf(pdev->name, sizeof(pdev->name), "%s", dev_name);
	pdev->num_resource = device_info.num_regions;
	pdev->mem = calloc(device_info.num_regions, sizeof(*pdev->mem));
	if (!pdev->mem) {
		dao_err("%s: failed to allocate memory for region info", dev_name);
		goto close_device_fd;
	}

	for (i = 0; i < device_info.num_regions; i++) {
		struct vfio_region_info reg = {.argsz = sizeof(reg)};

		reg.index = i;
		rc = ioctl(device_fd, VFIO_DEVICE_GET_REGION_INFO, &reg);
		if (rc) {
			dao_err("%s: failed to get region info", dev_name);
			goto device_mem_free;
		}

		pdev->mem[i].addr = mmap(NULL, reg.size, PROT_READ | PROT_WRITE, MAP_SHARED,
					 device_fd, reg.offset);
		pdev->mem[i].len = reg.size;
	}

	dao_dbg("%s: enabled VFIO platform device", dev_name);
	return 0;

device_mem_free:
	vfio_platform_device_mem_free(pdev);
close_device_fd:
	close(device_fd);
clear_group:
	vfio_clear_group(group_fd);
	return -1;
}

void
dao_vfio_platform_device_free(struct dao_vfio_platform_device *pdev)
{
	vfio_platform_device_mem_free(pdev);
	vfio_clear_group(pdev->group_fd);
	close(pdev->device_fd);
}

void
dao_vfio_platform_fini(void)
{
	int i;

	/* Return if any active group */
	for (i = 0; i < VFIO_MAX_GROUPS; i++) {
		if (vfio_cfg.groups[i].group_num != -1)
			return;
	}

	vfio_cfg.active_groups = 0;
	close(vfio_cfg.container_fd);
	vfio_cfg.container_fd = -1;
}
