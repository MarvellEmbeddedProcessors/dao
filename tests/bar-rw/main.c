/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */
#include <dirent.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_hexdump.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>

#include "dao_log.h"
#include "dao_version.h"
#include "dao_vfio_platform.h"

#define DT_SOC_PATH "/proc/device-tree/soc@0"

static int
pem_bar4_pdev_name_get(char *pdev_name)
{
	struct dirent *e;
	uint64_t addr;
	int rc = -1;
	DIR *dir;

	dir = opendir(DT_SOC_PATH);
	if (dir == NULL) {
		dao_err("Failed to open %s", DT_SOC_PATH);
		return -1;
	}

	while (((e = readdir(dir)) != NULL)) {
		if (strncmp(e->d_name, "pem0-bar4-mem", 13))
			continue;

		if (sscanf(e->d_name, "%*[^@]@%lx", &addr) == 1) {
			snprintf(pdev_name, VFIO_DEV_NAME_MAX_LEN, "%lx.%s", addr, "pem0-bar4-mem");
			rc = 0;
		}

		break;
	}

	closedir(dir);
	return rc;
}

int
main(int argc, char *argv[])
{
	char bar4_pdev_name[VFIO_DEV_NAME_MAX_LEN];
	struct dao_vfio_platform_device bar4_pdev;
	uint8_t *va;
	size_t sz;
	int rc;

	/* Initializion the Environment Abstraction Layer (EAL). 8< */
	rc = rte_eal_init(argc, argv);
	if (rc < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

	rc = dao_vfio_platform_init();
	if (rc < 0)
		rte_exit(EXIT_FAILURE, "Failed to initialize VFIO platform\n");

	rc = pem_bar4_pdev_name_get(bar4_pdev_name);
	if (rc < 0)
		rte_exit(EXIT_FAILURE, "Failed to find PEM platform device\n");

	rc = dao_vfio_platform_device_setup(bar4_pdev_name, &bar4_pdev);
	if (rc < 0)
		rte_exit(EXIT_FAILURE, "Failed to setup PEM BAR4 platform device\n");

	va = bar4_pdev.mem[0].addr;
	sz = bar4_pdev.mem[0].len;
	printf("BAR2 mapped at %p (sz %lu)\n", va, sz);

	rte_hexdump(stdout, "Existing BAR4 data", va, 128);
	printf("Overwriting existing data with new data 0x%x\n", (uint8_t)getpid());
	memset(va, getpid(), sz);

	dao_vfio_platform_device_free(&bar4_pdev);
	dao_vfio_platform_fini();

	/* clean up the EAL */
	rte_eal_cleanup();

	return 0;
}
