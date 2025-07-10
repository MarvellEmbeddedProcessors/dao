/* SPDX-License-Identifier: Marvell-Proprietary
 * Copyright (c) 2025 Marvell.
 */

#ifndef __INCLUDE_VIRTIO_BLKIO_H__
#define __INCLUDE_VIRTIO_BLKIO_H__

/* Log type */
#define RTE_LOGTYPE_VIRTIO_BLK_IO RTE_LOGTYPE_USER1

#define MAX_VIRTIO_DEV_PER_LCORE 128

/* 64 could suffice most use cases. 64 is just application limit and comes from
 * 64-bit virt_q_map in struct blkdev_ctx. To support beyond 64 queues, use map
 * big enough to hold all. Real max queue limit comes from virtio lib (check
 * virtio_dev_init() in virtio_dev.c).
 */
#define MAX_VIRTIO_BLK_QUEUES 64

#define MEMPOOL_CACHE_SIZE 512

#define IO_BURST 32

#define NUM_STASH_PER_QUEUE 2 /* process_compl_stash, process_pend_stash */

/* Default block device attributes */
#define BLK_CAPACITY ((100 << 20) >> 9) /* 100MiB in units of 512B sectors */

#define MAX_SEG_SIZE 4096 /* As big as block size used by kernel IO stack */

#define BLK_SIZE 512 /* Sector size of the block device */

#define MAX_SEGS 8 /* As many segs as pointer pairs per DMA request. < 15 */

#define APP_INFO(fmt, args...) RTE_LOG(INFO, VIRTIO_BLK_IO, fmt, ##args)

#define APP_INFO_NH(fmt, args...) rte_log(RTE_LOG_INFO, RTE_LOGTYPE_VIRTIO_BLK_IO, fmt, ##args)

#define APP_ERR(fmt, args...) RTE_LOG(ERR, VIRTIO_BLK_IO, fmt, ##args)

#define TAILQ_FOREACH_SAFE(var, head, field, tmp)                                                  \
	for ((var) = TAILQ_FIRST((head)); (var) && ((tmp) = TAILQ_NEXT((var), field), 1);          \
	     (var) = (tmp))

#define RAMDISK_FEATURE_BITS                                                                       \
	(VIRTIO_BLK_F_SIZE_MAX | VIRTIO_BLK_F_SEG_MAX | VIRTIO_BLK_F_BLK_SIZE |                    \
	 VIRTIO_BLK_F_FLUSH | VIRTIO_BLK_F_DISCARD | VIRTIO_BLK_F_TOPOLOGY |                       \
	 VIRTIO_BLK_F_WRITE_ZEROES | VIRTIO_BLK_F_MQ)

struct blkdev_ctx {
	struct stash_head *stash; /* to park in-complete, in-progess requests */
	uint64_t virt_q_map;
	uint16_t virt_q_count;
	uint16_t devid;
};

struct stash_entry {
	void *vbuf; /* Pointer to the buffer containing BIO req */

	TAILQ_ENTRY(stash_entry) link;
};

TAILQ_HEAD(stash_head, stash_entry);

/* Lcore conf */
struct lcore_conf {
	/* Fast path accessed */
	uint64_t blkdev_map;
	uint16_t blkdev_q_count[DAO_VIRTIO_DEV_MAX];

	uint16_t nb_blkdev;
	struct blkdev_ctx blkdev_ctx[MAX_VIRTIO_DEV_PER_LCORE];
	uint32_t weight;

	bool service_lcore;
	int dev2mem_id;
	int mem2dev_id;
	int nb_vchans;
	struct rte_rcu_qsbr *qs_v;
} __rte_cache_aligned;

/* Virtio blkdev conf */
struct blkdev_conf {
#define BLKDEV_NAME_MAX 64
	char name[BLKDEV_NAME_MAX];
	uint64_t lcore_mask;
	uint64_t capacity;
	uint32_t blk_size;
	uint32_t seg_size_max;
	uint32_t seg_max;
	uint16_t max_queues; /* Limit the max virtio queues for this device */
};

/* Static global variables used within this file. */
static struct lcore_conf lcore_conf[RTE_MAX_LCORE];
static uint16_t lcore_list_wt_sorted[RTE_MAX_LCORE];
static struct blkdev_conf blkdev_conf[DAO_VIRTIO_DEV_MAX];

static int per_dev_pool;
static int in_order = 1; /* Enable by default till blk lib supports out-of-order */
static volatile bool force_quit;

/* Mask of enabled virtio devs */
static uint64_t virtio_mask_ena[2];
static uint16_t nb_virtio_blkdevs;

static int16_t dev2mem_ids[32];
static int16_t mem2dev_ids[32];
static uint16_t dev2mem_cnt;
static uint16_t mem2dev_cnt;
static int wrkr_dma_devs;
static uint16_t dma_flush_thr;
static uint32_t extmbuf_count = 128 * 1024;

static bool override_dma_vfid;
static uint16_t dma_vfid;

static struct rte_mempool *v_extmbuf_pool[DAO_VIRTIO_DEV_MAX];

static uint16_t virtio_blkdev_dma_vchans[DAO_VIRTIO_DEV_MAX];
static bool virtio_blkdev_autofree = true;
static uint16_t pem_devid;

/* RCU QSBR variable */
static struct rte_rcu_qsbr *qs_v;

static void *(*vbuf_to_stash_entry)(uint8_t dev_id, void *vbuf);
static uint16_t global_pool_data_room_sz;
#endif
