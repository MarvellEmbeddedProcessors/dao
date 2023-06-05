/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2023 Marvell.
 */

/**
 * @file
 *
 * DAO PEM library
 */

#ifndef __INCLUDE_DAO_PEM_H__
#define __INCLUDE_DAO_PEM_H__

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

/** PEM device conf */
struct dao_pem_dev_conf {
	/** Host page size */
	size_t host_page_sz;
};

/* End of structure dao_pem_dev_conf. */

/** PEM control region max */
#define DAO_PEM_CTRL_REGION_MAX 384

/** PEM control region mask */
#define DAO_PEM_CTRL_REGION_MASK_MAX (RTE_ALIGN(DAO_PEM_CTRL_REGION_MAX, 64) / 64)

/** Default PEM Host page size */
#define DAO_PEM_DEFAULT_HOST_PAGE_SZ (64 * 1024UL)
/** Max VF's supported */
#define DAO_PEM_MAX_VFS 128

/** PFVF DEV ID PF mask */
#define PEM_PFVF_DEV_ID_PF_MASK 0xF000
/** PFVF DEV ID PF shift */
#define PEM_PFVF_DEV_ID_PF_SHIFT 12
/** PFVF DEV ID VF mask */
#define PEM_PFVF_DEV_ID_VF_MASK 0x0FFF
/** PFVF DEV ID VF shift */
#define PEM_PFVF_DEV_ID_VF_SHIFT 0

/** PEM device ID max */
#define DAO_PEM_DEV_ID_MAX 2

/**
 * PEM device init
 *
 * @param pem_devid
 *    PEM device ID to init.
 * @param conf
 *    PEM device configuration.
 * @return
 *    Zero on success.
 */
int dao_pem_dev_init(uint16_t pem_devid, struct dao_pem_dev_conf *conf);

/**
 * PEM device fini
 *
 * @param pem_devid
 *    PEM device ID to cleanup.
 * @return
 *    Zero on success.
 */
int dao_pem_dev_fini(uint16_t pem_devid);

/** Callback for region changes */
typedef int (*dao_pem_ctrl_region_cb_t)(void *ctx, uintptr_t shadow, uint32_t off, uint64_t val,
					uint64_t shadow_val);

/**
 * PEM control region register.
 *
 * Registers a portion of BAR region to be polled on and get notification
 * if something changes in the area.
 *
 * @param pem_devid
 *    PEM device ID
 * @param base
 *    BAR region base address.
 * @param len
 *    BAR region len.
 * @param cb
 *    Callback to receive for changes in the region.
 * @param ctx
 *    Context pointer passed to callback.
 * @param sync_shadow
 *    Flag to indicate whether to sync shadow at time this API return.
 * @return
 *    Zero on success.
 */
int dao_pem_ctrl_region_register(uint16_t pem_devid, uintptr_t base, uint32_t len,
				 dao_pem_ctrl_region_cb_t cb, void *ctx, bool sync_shadow);
/**
 * PEM control region unregister.
 *
 * @param pem_devid
 *    PEM device ID
 * @param base
 *    region base address.
 * @param len
 *    region len.
 * @param cb
 *    Callback.
 * @param ctx
 *    Context pointer passed to callback.
 * @return
 *    Zero on success.
 */
int dao_pem_ctrl_region_unregister(uint16_t pem_devid, uintptr_t base, uint32_t len,
				   dao_pem_ctrl_region_cb_t cb, void *ctx);

/**
 * PEM VF region info get.
 *
 * @param pem_devid
 *    PEM device ID
 * @param dev_id
 *    PF/VF device ID.
 * @param bar_idx
 *    BAR index to get info.
 * @param addr
 *    Pointer to store BAR address.
 * @param size
 *    Pointer to store BAR size..
 * @return
 *    Zero on success.
 */
int dao_pem_vf_region_info_get(uint16_t pem_devid, uint16_t dev_id, uint8_t bar_idx,
			       uint64_t *addr, uint64_t *size);

/**
 * PEM host page size get.
 *
 * @param pem_devid
 *    PEM device ID
 * @return
 *    Non-Zero value on success.
 */
size_t dao_pem_host_page_sz(uint16_t pem_devid);

/**
 * PEM VF host interrupt setup.
 *
 * @param pem_devid
 *    PEM device ID.
 * @param vfid
 *    VF device ID.
 * @param intr_addr
 *    Pointer to the address that triggers host interrupt upon write.
 */
void dao_pem_host_interrupt_setup(uint16_t pem_devid, int vfid, uint64_t **intr_addr);
#endif /* __INCLUDE_DAO_PEM_H__ */
