/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef _VC_OFFLOAD_H_
#define _VC_OFFLOAD_H_

#include <rte_log.h>

#include <dao_virtio.h>

/* Log type */
#define RTE_LOGTYPE_VC_OFFLOAD    RTE_LOGTYPE_USER1
#define APP_INFO(fmt, args...)    RTE_LOG(INFO, VC_OFFLOAD, fmt, ##args)
#define APP_INFO_NH(fmt, args...) rte_log(RTE_LOG_INFO, RTE_LOGTYPE_VC_OFFLOAD, fmt, ##args)
#define APP_ERR(fmt, args...)     RTE_LOG(ERR, VC_OFFLOAD, fmt, ##args)

/* Mask of enabled virtio devs */
extern uint64_t virtio_mask_ena[2];
extern uint16_t nb_virtiodevs;
extern uint64_t lcore_virtio_mask[DAO_VIRTIO_DEV_MAX];

/* Mask of enabled crypto devs */
extern uint64_t crypto_mask_ena;
extern uint16_t nb_cryptodevs;
extern uint64_t lcore_crypto_mask[RTE_CRYPTO_MAX_DEVS];

extern struct vc_cdev_ctx vc_cdev_ctx;

#define VC_NB_SYM_SESSION  4096
#define VC_NB_ASYM_SESSION 4096
#define VC_NB_QP_MAX       64
#define VC_NB_DESC_DEFAULT 4096
#define VC_NB_DESC_MIN     1024
#define VC_NB_DESC_MAX     16384

/* FIXME - get buffer size using an API */
#define VC_MEMPOOL_CACHE_SIZE 512
#define VC_MEMPOOL_BUF_SIZE   2048

struct vc_cdev_ctx {
	/*
	 * Primary cryptodevs - Hardware cryptodevs that is used for enq-deq from main worker cores.
	 */
	uint8_t nb_primary_cryptodevs;
	uint8_t enabled_primary_cdevs[RTE_CRYPTO_MAX_DEVS];

	struct rte_mempool *sym_sess_pool;
	struct rte_mempool *asym_sess_pool;

	uint16_t nb_qp;
	struct rte_mempool *qp_pool[VC_NB_QP_MAX];

	uint16_t nb_desc;
};

#endif /* _VC_OFFLOAD_H_ */
