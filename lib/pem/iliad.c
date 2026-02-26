/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <inttypes.h>

#include <dao_log.h>
#include <dao_vfio.h>
#include <rte_memzone.h>

#include "iliad.h"
#include "pem.h"

#define ODM_MSIX_VEC_ENA_MASK 0xFF00U /**< Vectors 8-15 (enabled mask) */
#define ODM_MSIX_VEC_COUNT    __builtin_popcount(ODM_MSIX_VEC_ENA_MASK)

#define ODM_EPF0_GENX_INT(x)         (0x0 | (x) << 5)
#define ODM_EPF0_GENX_INT_W1S(x)     (0x8 | (x) << 5)
#define ODM_EPF0_GENX_INT_ENA_W1C(x) (0x10 | (x) << 5)
#define ODM_EPF0_GENX_INT_ENA_W1S(x) (0x18 | (x) << 5)

#define ILI_PLAT_DEV_NAME "MRVL0012:00"
#define ILI_PEM_BAR_INDEX 0 /* PEM PF BAR0 index */
#define ILI_ODM_BAR_INDEX 1 /* ODM PF BAR0 index */

static int
ili_pem_reg_write(struct dao_vfio_device *ili_pdev, uint64_t offset, uint64_t val)
{
	*((volatile uint64_t *)(ili_pdev->mem[ILI_PEM_BAR_INDEX].addr + offset)) = val;
	return 0;
}

static int
ili_odm_reg_write(void *odm_base, uint64_t offset, uint64_t val)
{
	*((volatile uint64_t *)((char *)odm_base + offset)) = val;
	return 0;
}

static uint64_t *
ili_odm_reg_addr(void *odm_base, uint64_t offset)
{
	return (uint64_t *)((char *)odm_base + offset);
}

static void *
ili_odm_base_get(struct iliad_device *ili_dev)
{
	if (!ili_dev)
		return NULL;

	switch (ili_dev->device_type) {
	case ILIAD_DEVICE_TYPE_PLAT:
		return ili_dev->plat.pdev.mem[ILI_ODM_BAR_INDEX].addr;
	case ILIAD_DEVICE_TYPE_CDEV:
		return ili_dev->cdev.odm_base;
	default:
		return NULL;
	}
}

void *
iliad_dev_bar4_base_get(struct iliad_device *ili_dev)
{
	if (!ili_dev)
		return NULL;

	switch (ili_dev->device_type) {
	case ILIAD_DEVICE_TYPE_PLAT:
		return ili_dev->plat.bar4_memzone ? ili_dev->plat.bar4_memzone->addr : NULL;
	case ILIAD_DEVICE_TYPE_CDEV:
		return ili_dev->cdev.bar4_base;
	default:
		return NULL;
	}
}

size_t
iliad_dev_bar4_size_get(void)
{
	return PEM_BAR4_INDEX_SIZE * PEM_BAR4_NUM_INDEX;
}

uint8_t
iliad_dev_host_interrupt_setup(struct pem *pem, int vfid, uint64_t **intr_addr, uint64_t **ack_addr)
{
	struct iliad_device *ili_dev = &pem->ili;
	int vecs_per_dev, vec_start, vec_end;
	int dev_count = pem->max_vfs;
	uint8_t intr_cnt = 0;
	void *odm_base;
	int i;

	if (!intr_addr || !ack_addr || vfid < 1 || dev_count < 1) {
		dao_err("Invalid parameters for interrupt setup");
		return 0;
	}

	odm_base = ili_odm_base_get(ili_dev);
	if (!odm_base) {
		dao_err("Failed to get ODM base address");
		return 0;
	}

	/* Split ODM_MSIX_VEC_COUNT vectors equally among dev_count slots. */
	vecs_per_dev = ODM_MSIX_VEC_COUNT / ILIAD_RESOURCE_DIVISOR(dev_count);
	vec_start = __builtin_ctz(ODM_MSIX_VEC_ENA_MASK) + (vfid - 1) * vecs_per_dev;
	vec_end = vec_start + vecs_per_dev - 1;

	for (i = vec_start; i <= vec_end; i++) {
		ili_odm_reg_write(odm_base, ODM_EPF0_GENX_INT_ENA_W1S(i), 0x1);
		__atomic_store_n(intr_addr, ili_odm_reg_addr(odm_base, ODM_EPF0_GENX_INT_W1S(i)),
				 __ATOMIC_RELAXED);
		__atomic_store_n(ack_addr, ili_odm_reg_addr(odm_base, ODM_EPF0_GENX_INT(i)),
				 __ATOMIC_RELAXED);
		intr_addr++;
		ack_addr++;
		intr_cnt++;
	}

	if (!intr_cnt) {
		dao_err("No interrupts configured for ODM device, host interrupts unsupported");
		return 0;
	}

	return intr_cnt;
}

int
iliad_dev_init(struct iliad_device *ili_dev)
{
	const struct rte_memzone *bar4_mem = NULL;
	uint64_t bar4_base;
	uint64_t reg_val;
	int rc, i;

	/* Try character device first */
	rc = iliad_cdev_init(&ili_dev->cdev);
	if (rc == 0) {
		ili_dev->device_type = ILIAD_DEVICE_TYPE_CDEV;
		dao_info("Using Iliad character device interface");
		return 0;
	} else if (rc == -ENOENT) {
		dao_info("Character device not available, checking platform device");
	} else {
		dao_err("Failed to initialize Iliad character device, rc=%d", (int)rc);
		return rc;
	}

	rc = dao_vfio_init();
	if (rc < 0) {
		dao_err("Failed to initialize VFIO for Iliad, rc=%d", (int)rc);
		return rc;
	}

	/* Reserve aligned memory for BAR4 */
	bar4_mem = rte_memzone_reserve_aligned("pem_bar4_mem",
					       PEM_BAR4_INDEX_SIZE * PEM_BAR4_NUM_INDEX, 0,
					       RTE_MEMZONE_IOVA_CONTIG, PEM_BAR4_INDEX_SIZE);
	if (!bar4_mem || ((uintptr_t)bar4_mem->iova & (PEM_BAR4_INDEX_SIZE - 1))) {
		rc = -ENOMEM;
		goto err_vfio_fini;
	}
	bar4_base = bar4_mem->iova;

	rc = dao_vfio_device_setup(ILI_PLAT_DEV_NAME, &ili_dev->plat.pdev);
	if (rc < 0)
		goto err_memzone_free;

	/* Verify both memory regions are mapped */
	if ((ili_dev->plat.pdev.mem[ILI_PEM_BAR_INDEX].addr == NULL) ||
	    (ili_dev->plat.pdev.mem[ILI_ODM_BAR_INDEX].addr == NULL)) {
		rc = -ENOMEM;
		goto err_vfio_device_free;
	}

	/* Configure PEM EPF BAR4 memory */
	for (i = PEM_BAR4_INDEX_START; i <= PEM_BAR4_INDEX_END; i++) {
		uint64_t bar4_iova = (uintptr_t)bar4_base + ((uint64_t)i * PEM_BAR4_INDEX_SIZE);

		reg_val = PEM_BAR4_INDEX_ADDR_IDX(bar4_iova >> 22) | PEM_BAR4_INDEX_ADDR_V;
		rc = ili_pem_reg_write(&ili_dev->plat.pdev, PEM_BAR4_INDEX(i), reg_val);
		if (rc < 0)
			goto err_vfio_device_free;
	}

	/* Enable PEM port */
	ili_pem_reg_write(&ili_dev->plat.pdev, PEM_DIS_PORT, 1);

	ili_dev->plat.pdev.type = DAO_VFIO_DEV_PLATFORM;
	ili_dev->device_type = ILIAD_DEVICE_TYPE_PLAT;
	ili_dev->plat.bar4_memzone = bar4_mem;

	dao_info("Using Iliad platform device interface");
	return 0;

err_vfio_device_free:
	dao_vfio_device_free(&ili_dev->plat.pdev);
err_memzone_free:
	rte_memzone_free(bar4_mem);
err_vfio_fini:
	dao_vfio_fini();
	return rc;
}

void
iliad_dev_fini(struct iliad_device *ili_dev)
{
	if (!ili_dev)
		return;

	switch (ili_dev->device_type) {
	case ILIAD_DEVICE_TYPE_PLAT:
		dao_vfio_device_free(&ili_dev->plat.pdev);
		if (ili_dev->plat.bar4_memzone) {
			rte_memzone_free(ili_dev->plat.bar4_memzone);
			ili_dev->plat.bar4_memzone = NULL;
		}
		dao_vfio_fini();
		break;
	case ILIAD_DEVICE_TYPE_CDEV:
		iliad_cdev_fini(&ili_dev->cdev);
		break;
	default:
		break;
	}
}
