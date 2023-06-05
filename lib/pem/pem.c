/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */
#include <rte_malloc.h>

#include <dirent.h>

#include "dao_pem.h"
#include "dao_vfio_platform.h"
#include "pem.h"
#include "sdp.h"

#define DT_PATH            "/proc/device-tree/soc@0"
#define RVU_SDP_NUM_VF_FMT "/proc/device-tree/soc@0/%s/rvu-sdp@%u/num-sdp-vfs"

#define PEM_DT_PFX_FMT "pem%u-bar4-mem"
#define PEM_DT_PFX_LEN 13
#define PEM_CTRL_POLL_DELAY_US 100

struct pem pem_devices[DAO_PEM_DEV_ID_MAX];

static uint32_t
dt_max_vfs_get(struct pem *pem)
{
	uint32_t max_vfs = 0;
	char path[PATH_MAX];
	struct dirent *e;
	DIR *dir;
	FILE *f;

	RTE_SET_USED(pem);

	/* Read device tree to find out max SDP VF's */
	dir = opendir(DT_PATH);
	if (dir == NULL) {
		dao_err("opendir(%s) failed: %s\n", DT_PATH, strerror(errno));
		return 0;
	}

	while (((e = readdir(dir)) != NULL)) {
		if (e->d_name[0] == '.')
			continue;

		/* Find pci@ directory */
		if (strncmp(e->d_name, "pci@", 4))
			continue;

		/* Get RVU SDP entry */
		snprintf(path, sizeof(path), RVU_SDP_NUM_VF_FMT, e->d_name, pem->pem_id);
		f = fopen(path, "r");
		if (f)
			break;
	}

	closedir(dir);
	if (!f) {
		dao_err("Unable to find rvu-sdp@/num-sdp-vfs DT file");
		return 0;
	}

	/* Read max VF's value */
	if (fread(&max_vfs, 4, 1, f) != 1) {
		dao_err("Unable to read data from %s file", path);
		max_vfs = 0;
	}
	max_vfs = rte_be_to_cpu_32(max_vfs);

	fclose(f);
	return max_vfs;
}

static void
check_ctrl_reg(struct pem_region *region)
{
	volatile uint64_t *reg_base;
	uint64_t val, shd_val;
	size_t i;

	if (region == NULL)
		return;

	reg_base = (volatile uint64_t *)region->reg_base;
	/* Walk through every word and compare against shadow region */
	for (i = 0; i < region->sz; i += 1) {
		val = reg_base[i];
		shd_val = region->shadow[i];
		if (val != shd_val)
			region->cb(region->ctx, (uintptr_t)region->shadow, i, val, shd_val);
	}
}

static uint32_t
pem_ctrl_reg_poll(void *arg)
{
	struct pem *pem = (struct pem *)arg;
	uint64_t mask, base;
	int i = 0;

	/* Poll on registered regions */
	while (!pem->ctrl_done) {
		mask = pem->region_mask[i];
		base = i * 64;
		/* Walk through regions within a mask */
		while (mask) {
			if (mask & 0x1)
				check_ctrl_reg(pem->regions[base]);
			base++;
			mask = mask >> 1;
		}

		i++;
		if (i >= DAO_PEM_CTRL_REGION_MASK_MAX) {
			/* Delay before next iteration */
			rte_delay_us_block(PEM_CTRL_POLL_DELAY_US);
			i = 0;
		}
	}

	return 0;
}

static int
pem_update_bar4_info(struct pem *pem)
{
	uint32_t signature[4];

	/* Add signature at beginning of BAR4, FIXME */
	signature[0] = 0xfeedfeed;
	signature[1] = 0x3355ffaa;
	signature[2] = (pem->host_pages_per_dev * pem->host_page_sz);
	signature[3] = pem->max_vfs;
	dao_dev_memcpy((void *)pem->bar4_pdev.mem[0].addr, signature, sizeof(signature));

	return 0;
}

static void
release_vfio_platform_devices(struct pem *pem)
{
	sdp_fini(&pem->sdp_pdev);
	dao_vfio_platform_device_free(&pem->bar4_pdev);
	dao_vfio_platform_fini();
}

static int
pem_bar4_pdev_name_get(struct pem *pem, char *pdev_name)
{
	char node_name[32];
	struct dirent *e;
	uint64_t addr;
	int rc = -1;
	DIR *dir;

	dir = opendir(DT_PATH);
	if (dir == NULL) {
		dao_err("Failed to open %s", DT_PATH);
		return -1;
	}

	snprintf(node_name, sizeof(node_name), PEM_DT_PFX_FMT, pem->pem_id);
	while (((e = readdir(dir)) != NULL)) {
		if (strncmp(e->d_name, node_name, PEM_DT_PFX_LEN))
			continue;

		if (sscanf(e->d_name, "%*[^@]@%lx", &addr) == 1) {
			snprintf(pdev_name, VFIO_DEV_NAME_MAX_LEN, "%lx.%s", addr, node_name);
			rc = 0;
		}

		break;
	}

	closedir(dir);
	return rc;
}

static int
setup_vfio_platform_devices(struct pem *pem)
{
	char bar4_pdev_name[VFIO_DEV_NAME_MAX_LEN];
	int rc;

	rc = dao_vfio_platform_init();
	if (rc < 0) {
		dao_err("Failed to initialize VFIO platform");
		return -1;
	}

	rc = sdp_init(&pem->sdp_pdev);
	if (rc < 0) {
		dao_err("Failed to initialize SDP platform device");
		return -1;
	}

	rc = pem_bar4_pdev_name_get(pem, bar4_pdev_name);
	if (rc < 0) {
		dao_err("Failed to get PEM platform device name");
		return -1;
	}

	rc = dao_vfio_platform_device_setup(bar4_pdev_name, &pem->bar4_pdev);
	if (rc < 0) {
		dao_err("Failed to initialize PEM BAR4 platform device");
		return -1;
	}

	return 0;
}

int
dao_pem_dev_init(uint16_t pem_devid, struct dao_pem_dev_conf *conf)
{
	struct pem *pem = &pem_devices[pem_devid];
	size_t sz;
	void *bar4;
	int rc;

	pem->pem_id = pem_devid;

	if (conf->host_page_sz && !rte_is_power_of_2(conf->host_page_sz)) {
		dao_err("Invalid host page size, not power of 2");
		return -1;
	}

	rc = setup_vfio_platform_devices(pem);
	if (rc < 0)
		return -1;

	bar4 = pem->bar4_pdev.mem[0].addr;
	sz = pem->bar4_pdev.mem[0].len;

	/* Clear bar 4 */
	if (sz % 8 == 0)
		dao_dev_memzero(bar4, sz / 8);
	else
		dao_dev_memset(bar4, 0, sz);

	/* Divide host pages among all VF's equally */
	pem->max_vfs = dt_max_vfs_get(pem);
	if (!pem->max_vfs)
		goto err;

	dao_info("Setting up %u VFs for PEM%u", pem->max_vfs, pem->pem_id);

	pem->host_page_sz = conf->host_page_sz;
	if (!pem->host_page_sz)
		pem->host_page_sz = DAO_PEM_DEFAULT_HOST_PAGE_SZ;

	pem->host_pages_per_dev = ((sz / pem->host_page_sz) / pem->max_vfs);
	if (!pem->host_pages_per_dev) {
		dao_err("BAR4 space insufficient for %u devices", pem->max_vfs);
		goto err;
	}

	/* Update BAR4 info to host */
	pem_update_bar4_info(pem);

	dao_dbg("Configured to allow %u VF's with %lu host pages of BAR4 per VF", pem->max_vfs,
		pem->host_pages_per_dev);

	/* Create control thread to poll on registered regions */
	rc = rte_thread_create_control(&pem->ctrl_thread, "ctrl_reg_poll", pem_ctrl_reg_poll, pem);
	if (rc) {
		dao_err("Failed to create ctrl thread, rc=%d\n", rc);
		goto err;
	}

	return 0;
err:
	release_vfio_platform_devices(pem);
	return -EFAULT;
}

int
dao_pem_dev_fini(uint16_t pem_devid)
{
	struct pem *pem = &pem_devices[pem_devid];
	uint32_t i;

	/* Wait for control thread exit */
	pem->ctrl_done = true;
	rte_thread_join(pem->ctrl_thread, NULL);

	/* Cleanup registered control regions */
	for (i = 0; i < DAO_PEM_CTRL_REGION_MAX; i++) {
		rte_free(pem->regions[i]);
		pem->regions[i] = NULL;
	}

	release_vfio_platform_devices(pem);
	return 0;
}

int
dao_pem_ctrl_region_register(uint16_t pem_devid, uintptr_t base, uint32_t len,
			     dao_pem_ctrl_region_cb_t cb, void *ctx, bool sync_shadow)
{
	struct pem *pem = &pem_devices[pem_devid];
	struct pem_region *region;
	bool found = false;
	uint32_t i, j;
	uint64_t mask;

	j = 0;
	for (i = 0; i < DAO_PEM_CTRL_REGION_MASK_MAX; i++) {
		mask = pem->region_mask[i];
		do {
			if ((mask & 0x1) == 0) {
				found = true;
				break;
			}
			j++;
			mask >>= 1;
		} while (j % 64 != 0);
		if (found)
			break;
	}
	if (!found)
		return -ENOMEM;

	region = rte_zmalloc(NULL, sizeof(struct pem_region) + len, 0);
	if (region == NULL)
		return -ENOMEM;

	region->reg_base = base;
	region->sz = len / sizeof(uint64_t);
	region->cb = cb;
	region->ctx = ctx;
	pem->region_mask[i] |= 1UL << (j % 64);
	pem->regions[j] = region;
	if (sync_shadow)
		dao_dev_memcpy(region->shadow, (void *)base, len);

	dao_dbg("Registered pem ctrl region %u @ %p len %u", j, (void *)base, len);
	return 0;
}

int
dao_pem_ctrl_region_unregister(uint16_t pem_devid, uintptr_t base, uint32_t len,
			       dao_pem_ctrl_region_cb_t cb, void *ctx)
{
	struct pem *pem = &pem_devices[pem_devid];
	struct pem_region *region;
	int rc = -ENOENT;
	uint32_t i;

	for (i = 0; i < DAO_PEM_CTRL_REGION_MAX; i++) {
		/* Find matching region */
		region = pem->regions[i];
		if (region && region->reg_base == base && (region->sz * sizeof(uint64_t)) == len &&
		    region->cb == cb && region->ctx == ctx) {
			pem->region_mask[i / 64] &= ~RTE_BIT64(i % 64);
			rte_free(region);
			pem->regions[i] = NULL;
			rc = 0;
			break;
		}
	}

	return rc;
}

int
dao_pem_vf_region_info_get(uint16_t pem_devid, uint16_t dev_id, uint8_t bar_idx, uint64_t *addr,
			   uint64_t *size)
{
	uint16_t pf = (dev_id & PEM_PFVF_DEV_ID_PF_MASK) >> PEM_PFVF_DEV_ID_PF_SHIFT;
	uint16_t vf = (dev_id & PEM_PFVF_DEV_ID_VF_MASK) >> PEM_PFVF_DEV_ID_VF_SHIFT;
	struct pem *pem = &pem_devices[pem_devid];

	/* Currently only BAR4 is supported */
	if (bar_idx != 4)
		return -ENOENT;

	/* Check if we support that device */
	if (pf > 0 || vf >= pem->max_vfs)
		return -ENOTSUP;

	*addr = (uintptr_t)pem->bar4_pdev.mem[0].addr +
		(vf * pem->host_pages_per_dev * pem->host_page_sz);
	*size = pem->host_pages_per_dev * pem->host_page_sz;
	return 0;
}

size_t
dao_pem_host_page_sz(uint16_t pem_devid)
{
	struct pem *pem = &pem_devices[pem_devid];

	return pem->host_page_sz;
}

void
dao_pem_host_interrupt_setup(uint16_t pem_devid, int vfid, uint64_t **intr_addr)
{
	struct pem *pem = &pem_devices[pem_devid];
	int ring_idx = vfid - 1;

	sdp_reg_write(&pem->sdp_pdev, SDP_EPVF_RINGX(ring_idx), vfid);
	sdp_reg_write(&pem->sdp_pdev, SDP_RX_OUT_ENABLE(ring_idx), 0x1);
	sdp_reg_write(&pem->sdp_pdev, SDP_RX_OUT_CNTS(ring_idx), 0x1);
	sdp_reg_write(&pem->sdp_pdev, SDP_RX_OUT_INT_LEVELS(ring_idx), ~0xfUL);

	__atomic_store_n(intr_addr, sdp_reg_addr(&pem->sdp_pdev, SDP_RX_OUT_CNTS(ring_idx)),
			 __ATOMIC_RELAXED);
}
