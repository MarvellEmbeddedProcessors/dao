/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */
#include <rte_malloc.h>

#include <dirent.h>

#include "cn10k_cdev.h"
#include "dao_pem.h"
#include "dao_platform.h"
#include "dao_vfio.h"
#include "iliad.h"
#include "pem.h"
#include "sdp.h"

#define DT_PATH            "/proc/device-tree/soc@0"
#define RVU_SDP_NUM_VF_FMT "/proc/device-tree/soc@0/%s/rvu-sdp@%u/num-sdp-vfs"

#define PEM_DT_PFX_FMT         "pem%u-bar4-mem"
#define PEM_DT_PFX_LEN         13
#define PEM_CTRL_POLL_DELAY_US 100

struct pem pem_devices[DAO_PEM_DEV_ID_MAX];

static uint32_t
dt_max_vfs_get(void)
{
	uint32_t max_vfs = 0;
	char path[PATH_MAX];
	struct dirent *e;
	DIR *dir;
	FILE *f;

	/* Read device tree to find out max SDP VF's for CN10K */
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
		snprintf(path, sizeof(path), RVU_SDP_NUM_VF_FMT, e->d_name, 0);
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

static void *
cn10k_dev_bar4_base_get(struct cn10k_device *cn10k_dev)
{
	if (!cn10k_dev)
		return NULL;

	switch (cn10k_dev->device_type) {
	case CN10K_DEVICE_TYPE_PLAT:
		return cn10k_dev->plat.bar4_pdev.mem[cn10k_dev->plat.bar4_pdev.mbar].addr;
	case CN10K_DEVICE_TYPE_CDEV:
		return cn10k_cdev_base_get(&cn10k_dev->cdev);
	default:
		return NULL;
	}
}

static size_t
cn10k_dev_bar4_size_get(struct cn10k_device *cn10k_dev)
{
	if (!cn10k_dev)
		return 0;

	switch (cn10k_dev->device_type) {
	case CN10K_DEVICE_TYPE_PLAT:
		return cn10k_dev->plat.bar4_pdev.mem[cn10k_dev->plat.bar4_pdev.mbar].len;
	case CN10K_DEVICE_TYPE_CDEV:
		return cn10k_cdev_size_get(&cn10k_dev->cdev);
	default:
		return 0;
	}
}

static void *
pem_bar4_base_get(struct pem *pem)
{
	switch (pem->platform) {
	case DAO_PLATFORM_CN10K:
		return cn10k_dev_bar4_base_get(&pem->cn10k);
	case DAO_PLATFORM_ILIAD:
		return iliad_dev_bar4_base_get(&pem->ili);
	default:
		return NULL;
	}
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
	dao_dev_memcpy(pem_bar4_base_get(pem), signature, sizeof(signature));
	return 0;
}

static void
cn10k_dev_fini(struct pem *pem)
{
	struct cn10k_device *cn10k_dev = &pem->cn10k;

	switch (cn10k_dev->device_type) {
	case CN10K_DEVICE_TYPE_PLAT:
		sdp_fini(&pem->cn10k.plat.sdp_pdev);
		if (pem->cn10k.plat.bar4_pdev.type == DAO_VFIO_DEV_PLATFORM)
			dao_vfio_device_free(&pem->cn10k.plat.bar4_pdev);
		dao_vfio_fini();
		break;
	case CN10K_DEVICE_TYPE_CDEV:
		cn10k_cdev_fini(&cn10k_dev->cdev);
		break;
	default:
		break;
	}
}

static void
pem_devices_release(struct pem *pem)
{
	enum dao_platform platform = pem->platform;

	switch (platform) {
	case DAO_PLATFORM_CN10K:
		cn10k_dev_fini(pem);
		break;
	case DAO_PLATFORM_ILIAD:
		iliad_dev_fini(&pem->ili);
		break;
	default:
		break;
	}
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
cn10k_plat_dev_init(struct pem *pem)
{
	struct cn10k_device *cn10k_dev = &pem->cn10k;
	char bar4_pdev_name[VFIO_DEV_NAME_MAX_LEN];
	int rc;

	rc = dao_vfio_init();
	if (rc < 0) {
		dao_err("Failed to initialize VFIO for CN10K, rc=%d", (int)rc);
		return -1;
	}

	if (pem->pem_id == 0)
		cn10k_dev->plat.sdp_pdev.prime = 1;

	rc = sdp_init(&cn10k_dev->plat.sdp_pdev, pem->sdp_inuse);
	if (rc < 0) {
		dao_err("Failed to initialize SDP device");
		return -1;
	}

	/* If SDP is exposed as PCIe device, BAR4 is part of it */
	if (cn10k_dev->plat.sdp_pdev.type == DAO_VFIO_DEV_PCIE) {
		memcpy(&cn10k_dev->plat.bar4_pdev, &cn10k_dev->plat.sdp_pdev,
		       sizeof(struct dao_vfio_device));
		cn10k_dev->device_type = CN10K_DEVICE_TYPE_PLAT;
		return 0;
	}

	/* If SDP is exposed as platform device, get PEM BAR4 platform device */
	rc = pem_bar4_pdev_name_get(pem, bar4_pdev_name);
	if (rc < 0) {
		dao_err("Failed to get PEM device name");
		return -1;
	}

	rc = dao_vfio_device_setup(bar4_pdev_name, &cn10k_dev->plat.bar4_pdev);
	if (rc < 0) {
		dao_err("Failed to initialize PEM BAR4 device");
		return -1;
	}

	cn10k_dev->plat.bar4_pdev.mbar = DAO_VFIO_DEV_BAR0;
	cn10k_dev->plat.bar4_pdev.type = DAO_VFIO_DEV_PLATFORM;
	cn10k_dev->device_type = CN10K_DEVICE_TYPE_PLAT;

	return 0;
}

static int
cn10k_cdev_dev_init(struct pem *pem)
{
	struct cn10k_device *cn10k_dev = &pem->cn10k;
	int rc;

	rc = cn10k_cdev_init(&cn10k_dev->cdev);
	if (rc < 0) {
		dao_err("Failed to initialize CN10K character device");
		return -1;
	}

	cn10k_dev->device_type = CN10K_DEVICE_TYPE_CDEV;
	return 0;
}

static int
cn10k_dev_init(struct pem *pem)
{
	if (pem->cdev_inuse)
		return cn10k_cdev_dev_init(pem);
	else
		return cn10k_plat_dev_init(pem);
}

static int
pem_devices_init(struct pem *pem)
{
	switch (pem->platform) {
	case DAO_PLATFORM_CN10K:
		return cn10k_dev_init(pem);
	case DAO_PLATFORM_ILIAD:
		return iliad_dev_init(&pem->ili);
	default:
		return -1;
	}
}

int
dao_pem_dev_init(uint16_t pem_devid, struct dao_pem_dev_conf *conf)
{
	struct pem *pem = &pem_devices[pem_devid];
	size_t sz;
	void *bar4;
	int rc;

	pem->pem_id = pem_devid;
	pem->cdev_inuse = conf->cdev_inuse;
	pem->platform = dao_platform_detect();
	if (pem->platform == DAO_PLATFORM_INVALID) {
		dao_err("Failed to detect platform");
		return -1;
	}

	if (conf->host_page_sz && !rte_is_power_of_2(conf->host_page_sz)) {
		dao_err("Host page size must be power of 2");
		return -1;
	}

	pem->sdp_inuse = conf->sdp_inuse;
	rc = pem_devices_init(pem);
	if (rc < 0)
		return -1;

	bar4 = pem_bar4_base_get(pem);
	if (pem->platform == DAO_PLATFORM_ILIAD) {
		sz = iliad_dev_bar4_size_get();
	} else {
		sz = cn10k_dev_bar4_size_get(&pem->cn10k);
	}

	/* Clear bar 4 */
	if (sz % 8 == 0)
		dao_dev_memzero(bar4, sz / 8);
	else
		dao_dev_memset(bar4, 0, sz);

	pem->host_page_sz = conf->host_page_sz;
	if (!pem->host_page_sz)
		pem->host_page_sz = DAO_PEM_DEFAULT_HOST_PAGE_SZ;

	if (pem->platform == DAO_PLATFORM_ILIAD) {
		uint16_t dev_count = conf->virtio_dev_count;

		if (!dev_count || dev_count > ILIAD_MAX_DEVS) {
			dao_err("Invalid virtio_dev_count %u", dev_count);
			goto err;
		}
		pem->max_vfs = dev_count;
		pem->host_pages_per_dev =
			(sz / pem->host_page_sz) / ILIAD_RESOURCE_DIVISOR(pem->max_vfs);
	} else {
		if (pem->cn10k.device_type == CN10K_DEVICE_TYPE_CDEV) {
			pem->max_vfs = cn10k_cdev_max_vfs_get(&pem->cn10k.cdev);
			pem->host_pages_per_dev = (sz / pem->host_page_sz) / pem->max_vfs;
		} else {
			pem->max_vfs = dao_pem_max_vfs_get(pem_devid);
			pem->host_pages_per_dev = (sz / pem->host_page_sz) / pem->max_vfs;
		}
	}
	if (!pem->max_vfs)
		goto err;

	dao_info("Setting up %u VFs for PEM%u", pem->max_vfs, pem->pem_id);

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
	pem_devices_release(pem);
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

	pem_devices_release(pem);
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
	uint16_t max_vfs, pf, vf;

	max_vfs = dao_pem_max_vfs_get(pem_devid);
	pf = dev_id / max_vfs;
	vf = dev_id % max_vfs;
	struct pem *pem = &pem_devices[pem_devid];

	/* Currently only BAR4 is supported */
	if (bar_idx != 4)
		return -ENOENT;

	dao_dbg("PF %u VF %u", pf, vf);
	if (pf > 1 || vf >= pem->max_vfs) {
		dao_err("Invalid PF %u or VF %u", pf, vf);
		return -ENOTSUP;
	}

	*addr = (uint64_t)pem_bar4_base_get(pem) +
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

static uint8_t
cn10k_sdp_host_interrupt_setup(struct pem *pem, int vfid, uint64_t **intr_addr, uint64_t **ack_addr)
{
	struct dao_vfio_device *sdp_pdev = &pem->cn10k.plat.sdp_pdev;
	int idx, ring_idx;
	uint64_t reg_val;
	uint8_t rpvf;

	if (pem->cdev_inuse)
		return 0;

	reg_val = sdp_reg_read(sdp_pdev, SDP_VF_MBOX_DATA(0));
	rpvf = (reg_val >> SDP_EPFX_RINFO_RPVF_SHIFT) & 0xf;
	pem->rpvf = rpvf;

	if (!rpvf) {
		dao_err("No rings configured per VF, host interrupts unsupported");
		return 0;
	}

	for (idx = 0; idx < rpvf; idx++) {
		ring_idx = idx + (vfid - 1) * rpvf;

		sdp_reg_write(sdp_pdev, SDP_RX_OUT_ENABLE(ring_idx), 0x1);
		sdp_reg_write(sdp_pdev, SDP_RX_OUT_CNTS(ring_idx), 0x1);
		sdp_reg_write(sdp_pdev, SDP_RX_OUT_INT_LEVELS(ring_idx), ~0xfUL);
		sdp_reg_write(sdp_pdev, SDP_VF_EVENT_STATE(ring_idx), 0x0);
		sdp_reg_write(sdp_pdev, SDP_VF_EVENT_REG(ring_idx), 0x0);

		__atomic_store_n(intr_addr, sdp_reg_addr(sdp_pdev, SDP_RX_OUT_CNTS(ring_idx)),
				 __ATOMIC_RELAXED);
		__atomic_store_n(ack_addr, NULL, __ATOMIC_RELAXED); /* ACK not needed */
		intr_addr++;
		ack_addr++;
	}

	return rpvf;
}

static void
pem_get_host_dev_addrs(struct pem *pem, int vfid, uint64_t **intr_addr, uint64_t **event_addr,
		       uint64_t **event_state_addr)
{
	struct dao_vfio_device *sdp_pdev = &pem->cn10k.plat.sdp_pdev;
	uint16_t rpvf = pem->rpvf;

	*intr_addr = sdp_reg_addr(sdp_pdev, SDP_RX_OUT_CNTS(vfid * rpvf));
	*event_addr = sdp_reg_addr(sdp_pdev, SDP_VF_EVENT_REG(vfid * rpvf));
	*event_state_addr = sdp_reg_addr(sdp_pdev, SDP_VF_EVENT_STATE(vfid * rpvf));
}

static inline int
pem_wait_for_event_state(uint64_t *event_addr, uint64_t timeout,
			 enum pem_host_dev_event_state state)
{
	uint64_t reg_val;

	do {
		reg_val = __atomic_load_n(event_addr, __ATOMIC_ACQUIRE);
		if ((reg_val & PEM_EVENT_MASK) == state)
			return 0;

		rte_delay_us_sleep(5000);
		if (rte_get_timer_cycles() > timeout)
			return -EBUSY;
	} while (true);

	return 0;
}

static int
pem_host_dev_add_del(uint16_t pem_devid, int vfid, uint64_t event)
{
	uint64_t timeout = rte_get_timer_cycles() + rte_get_timer_hz() * 10;
	uint64_t *intr_addr, *event_state_addr, *event_addr, reg_val;
	struct pem *pem = &pem_devices[pem_devid];
	int rc;

	pem_get_host_dev_addrs(pem, vfid, &intr_addr, &event_addr, &event_state_addr);

	rc = pem_wait_for_event_state(event_state_addr, timeout, PEM_HOST_DEV_NO_EVENT);
	if (rc) {
		/* Check if it's in DONE state due to previous event timeout */
		reg_val = __atomic_load_n(event_state_addr, __ATOMIC_ACQUIRE);
		if ((reg_val & PEM_EVENT_MASK) == PEM_HOST_DEV_EVENT_DONE) {
			__atomic_store_n(event_state_addr, PEM_HOST_DEV_NO_EVENT, __ATOMIC_RELAXED);
		} else {
			dao_err("Could not send host device add/del request, retry!!");
			return rc;
		}
	}

	__atomic_store_n(event_addr, event & PEM_EVENT_MASK, __ATOMIC_RELAXED);
	__atomic_store_n(event_state_addr, PEM_HOST_DEV_NEW_EVENT, __ATOMIC_RELAXED);
	__atomic_store_n(intr_addr, (1UL << SDP_RX_OUT_INTERRUPT_SHIFT), __ATOMIC_RELAXED);

	timeout = rte_get_timer_cycles() + rte_get_timer_hz() * 15;
	rc = pem_wait_for_event_state(event_state_addr, timeout, PEM_HOST_DEV_EVENT_DONE);
	if (rc) {
		dao_err("Timed out to process host device add/del request");
		goto clear_event_state;
	}

	reg_val = __atomic_load_n(event_addr, __ATOMIC_RELAXED);
	if ((reg_val & PEM_EVENT_MASK) != PEM_HOST_DEV_EVENT_ACK) {
		dao_err("Failed to process host device add/del request");
		rc = -EIO;
	}

clear_event_state:
	__atomic_store_n(event_state_addr, PEM_HOST_DEV_NO_EVENT, __ATOMIC_RELAXED);

	return rc;
}

int
dao_pem_host_dev_add(uint16_t pem_devid, int vfid)
{
	return pem_host_dev_add_del(pem_devid, vfid, PEM_HOST_DEV_ADD_EVENT);
}

int
dao_pem_host_dev_del(uint16_t pem_devid, int vfid)
{
	return pem_host_dev_add_del(pem_devid, vfid, PEM_HOST_DEV_DEL_EVENT);
}

uint8_t
dao_pem_host_interrupt_setup(uint16_t pem_devid, int vfid, uint64_t **intr_addr,
			     uint64_t **ack_addr)
{
	struct pem *pem = &pem_devices[pem_devid];
	enum dao_platform platform = pem->platform;

	switch (platform) {
	case DAO_PLATFORM_CN10K:
		return cn10k_sdp_host_interrupt_setup(pem, vfid, intr_addr, ack_addr);
	case DAO_PLATFORM_ILIAD:
		return iliad_dev_host_interrupt_setup(pem, vfid, intr_addr, ack_addr);
	default:
		return 0;
	}
}

uint16_t
dao_pem_max_vfs_get(uint16_t pem_devid)
{
	enum dao_platform platform;
	struct pem *pem;
	uint16_t max_vfs;

	if (pem_devid >= DAO_PEM_DEV_ID_MAX)
		return 0;

	pem = &pem_devices[pem_devid];
	if (pem->max_vfs)
		return pem->max_vfs;

	platform = dao_platform_detect();
	if (platform == DAO_PLATFORM_INVALID)
		return 0;

	/* For Iliad, return the already-computed max_vfs from the pem struct */
	if (platform == DAO_PLATFORM_ILIAD)
		return pem_devices[pem_devid].max_vfs ? pem_devices[pem_devid].max_vfs :
							ILIAD_MAX_DEVS;

	/* If using character device, use IOCTL to get number of vfs */
	if (platform == DAO_PLATFORM_CN10K && pem->cdev_inuse) {
		if (cn10k_cdev_max_vfs_get_early(&max_vfs) == 0 && max_vfs > 0)
			return max_vfs;
		return 1;
	}
	max_vfs = dt_max_vfs_get();
	if (max_vfs != 1)
		max_vfs >>= 1;

	return max_vfs;
}

int
dao_pem_sdp_reg_write(uint16_t pem_devid, uint64_t offset, uint64_t value)
{
	struct pem *pem;

	if (pem_devid >= DAO_PEM_DEV_ID_MAX) {
		dao_err("Invalid PEM device ID %d", pem_devid);
		return -EINVAL;
	}

	pem = &pem_devices[pem_devid];
	if (!pem) {
		dao_err("PEM device %d not initialized", pem_devid);
		return -ENODEV;
	}

	if (pem->cdev_inuse)
		return 0;

	sdp_reg_write(&pem->cn10k.plat.sdp_pdev, offset, value);

	return 0;
}

int
dao_pem_sdp_reg_read(uint16_t pem_devid, uint64_t offset, uint64_t *value)
{
	struct pem *pem;

	if (pem_devid >= DAO_PEM_DEV_ID_MAX) {
		dao_err("Invalid PEM device ID %d", pem_devid);
		return -EINVAL;
	}

	if (!value) {
		dao_err("Invalid value pointer");
		return -EINVAL;
	}

	pem = &pem_devices[pem_devid];
	if (!pem) {
		dao_err("PEM device %d not initialized", pem_devid);
		return -ENODEV;
	}

	if (pem->cdev_inuse)
		return -EINVAL;

	*value = sdp_reg_read(&pem->cn10k.plat.sdp_pdev, offset);

	return 0;
}

uint8_t dao_pem_sec_strm_id_get(uint16_t pem_devid);
void dao_pem_cdev_mode_set(uint16_t pem_devid, bool is_cdev_pem);

uint8_t
dao_pem_sec_strm_id_get(uint16_t pem_devid)
{
	struct pem *pem;

	if (pem_devid >= DAO_PEM_DEV_ID_MAX)
		return 0;

	pem = &pem_devices[pem_devid];
	if (pem->platform != DAO_PLATFORM_CN10K || pem->cn10k.device_type != CN10K_DEVICE_TYPE_CDEV)
		return 0;

	return cn10k_cdev_sec_strm_id_get(&pem->cn10k.cdev);
}

void
dao_pem_cdev_mode_set(uint16_t pem_devid, bool is_cdev_pem)
{
	if (pem_devid < DAO_PEM_DEV_ID_MAX)
		pem_devices[pem_devid].cdev_inuse = is_cdev_pem;
}

int
dao_pem_fw_ready_notify(uint16_t pem_devid)
{
	struct pem *pem;

	if (pem_devid >= DAO_PEM_DEV_ID_MAX)
		return -EINVAL;

	pem = &pem_devices[pem_devid];
	if (pem->platform != DAO_PLATFORM_CN10K || !pem->cdev_inuse)
		return 0;
	if (pem->cn10k.device_type != CN10K_DEVICE_TYPE_CDEV)
		return 0;

	if (pem->cn10k.cdev.fd < 0)
		return -ENODEV;

	return cn10k_cdev_fw_ready_notify(&pem->cn10k.cdev);
}

int
dao_pem_fw_cleanup_notify(uint16_t pem_devid)
{
	struct pem *pem;

	if (pem_devid >= DAO_PEM_DEV_ID_MAX)
		return -EINVAL;

	pem = &pem_devices[pem_devid];
	if (pem->platform != DAO_PLATFORM_CN10K || !pem->cdev_inuse)
		return 0;
	if (pem->cn10k.device_type != CN10K_DEVICE_TYPE_CDEV)
		return 0;

	if (pem->cn10k.cdev.fd < 0)
		return -ENODEV;

	return cn10k_cdev_fw_cleanup_notify(&pem->cn10k.cdev);
}

int
dao_pem_get_sec_strm_id(uint8_t *sec_strm_id)
{
	if (!sec_strm_id)
		return -EINVAL;

	return cn10k_cdev_sec_strm_id_get_early(sec_strm_id);
}
