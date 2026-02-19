/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <dirent.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include <dao_log.h>
#include <dao_platform.h>

#define CN10K_SUBSYS_DEVICE_ID_106 0xb900
#define CN10K_SUBSYS_DEVICE_ID_105 0xba00
#define CN10K_SUBSYS_DEVICE_ID_103 0xbd00
#define ILIAD_SUBSYS_DEVICE_ID     0xc100
#define ODM_DEVICE_ID_LOW_BYTE     0x8b /* Bits <7:0> = 0x8b */
#define PCI_SYSFS_PATH             "/sys/bus/pci/devices"
#define PCI_VENDOR_ID_MARVELL      0x177d

enum dao_platform
dao_platform_detect(void)
{
	uint16_t vendor_id, device_id, subsystem_device;
	bool found_iliad_subsys = false;
	bool found_cn10k_subsys = false;
	bool found_odm_device = false;
	char path[PATH_MAX];
	struct dirent *e;
	DIR *dir;
	FILE *f;

	/* Check PCI devices via sysfs */
	dir = opendir(PCI_SYSFS_PATH);
	if (dir == NULL) {
		dao_err("Cannot access PCI sysfs, platform detection failed");
		return DAO_PLATFORM_INVALID;
	}

	while ((e = readdir(dir)) != NULL) {
		if (e->d_name[0] == '.')
			continue;

		/* Read vendor ID */
		snprintf(path, sizeof(path), "%s/%s/vendor", PCI_SYSFS_PATH, e->d_name);
		f = fopen(path, "r");
		if (!f)
			continue;

		if (fscanf(f, "%hx", &vendor_id) != 1) {
			fclose(f);
			continue;
		}
		fclose(f);

		if (vendor_id != PCI_VENDOR_ID_MARVELL)
			continue;

		/* Read device ID */
		snprintf(path, sizeof(path), "%s/%s/device", PCI_SYSFS_PATH, e->d_name);
		f = fopen(path, "r");
		if (!f)
			continue;

		if (fscanf(f, "%hx", &device_id) != 1) {
			fclose(f);
			continue;
		}
		fclose(f);

		/* Check for ODM device (device_id bits <7:0> = 0x8b) */
		if ((device_id & 0xff) == ODM_DEVICE_ID_LOW_BYTE) {
			found_odm_device = true;
			dao_dbg("Detected ODM device with device ID %04x", device_id);
			break;
		}

		/* Read subsystem_device */
		snprintf(path, sizeof(path), "%s/%s/subsystem_device", PCI_SYSFS_PATH, e->d_name);
		f = fopen(path, "r");
		if (!f)
			continue;

		if (fscanf(f, "%hx", &subsystem_device) != 1) {
			fclose(f);
			continue;
		}
		fclose(f);

		if (subsystem_device == ILIAD_SUBSYS_DEVICE_ID) {
			found_iliad_subsys = true;
			dao_dbg("Detected Iliad platform via subsystem_device %04x",
				subsystem_device);
			break;
		} else if (subsystem_device == CN10K_SUBSYS_DEVICE_ID_106 ||
			   subsystem_device == CN10K_SUBSYS_DEVICE_ID_105 ||
			   subsystem_device == CN10K_SUBSYS_DEVICE_ID_103) {
			found_cn10k_subsys = true;
			dao_dbg("Detected CN10K platform via subsystem_device %04x",
				subsystem_device);
			break;
		}
	}

	closedir(dir);

	if (found_iliad_subsys || found_odm_device)
		return DAO_PLATFORM_ILIAD;

	if (found_cn10k_subsys)
		return DAO_PLATFORM_CN10K;

	dao_err("Platform detection failed - no matching devices found");
	return DAO_PLATFORM_INVALID;
}
