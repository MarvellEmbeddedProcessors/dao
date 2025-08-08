/* SPDX-License-Identifier: Marvell-Proprietary
 * Copyright (c) 2025 Marvell
 */

/**
 * @file
 *
 * DAO virtio blk library
 */

#ifndef __INCLUDE_DAO_VIRTIO_BLK_H__
#define __INCLUDE_DAO_VIRTIO_BLK_H__

#include <dao_virtio.h>
#include <dao_util.h>

#include <spec/virtio_blk.h>

/** Virtio blk device configuration */
struct dao_virtio_blkdev_conf {
	/** PEM device ID */
	uint16_t pem_devid;
	/** Block device capacity in sectors */
	uint64_t capacity;
	/** Block size */
	uint32_t blk_size;
	/** Max segment size */
	uint32_t seg_size_max;
	/** Max segments */
	uint32_t seg_max;
	/** Vchan to use for this virtio dev */
	uint16_t dma_vchan;
#define DAO_VIRTIO_BLKDEV_EXTBUF	DAO_BIT_ULL(0)
	/* Config flags */
	uint16_t flags;
	union {
		struct {
			/** Default dequeue mempool */
			struct rte_mempool *pool;
		};
		/** Valid when DOS_VIRTIO_BLKDEV_EXTBUF is set in flags */
		struct {
			uint16_t dataroom_size;
		};
	};
	/** Max virt_queues */
	uint16_t max_virt_queues;
	/** Feature bits */
	uint64_t feat_bits;
	/** Auto free enabled/disabled */
	bool auto_free_en;
};

/* End of structure dao_virtio_blkdev_conf. */

/** Virtio blk header for external buffers */
struct dao_virtio_blk_hdr {
	/** Array of virtio descriptor data */
	union {
		struct vring_packed_desc vio_desc;
		uint64_t desc_data[2];
	};

	/** Link to next buffer in IO request chain */
	struct dao_virtio_blk_hdr *next;
	/** blk request status byte's address */
	uint8_t *status;
	/** Total length of data written by device in read request */
	uint32_t write_buf_len;
	/** length of data in `hdr_data` array */
	uint32_t cur_len;
	/** Total number of segments in blk request */
	uint32_t tot_segs;
	/** Total number of ext buffers in the chain */
	uint32_t tot_bufs;
	/** Virtio blk header, data */
	uint8_t hdr_data[];
} __rte_packed;

/** Virtio blk device data */
typedef struct dao_virtio_blkdev {
	/** Array of virtio queue pointers */
	void *qs[DAO_VIRTIO_MAX_QUEUES] __rte_cache_aligned;
	/** Dequeue function id */
	uint16_t deq_fn_id;
	/** Completion function id */
	uint16_t compl_fn_id;
	/** Descriptors management function id */
	uint16_t mgmt_fn_id;

#define DAO_VIRTIO_BLKDEV_MEM_SZ 8192
	uint8_t reserved[DAO_VIRTIO_BLKDEV_MEM_SZ];
} dao_virtio_blkdev_t;

/** Virtio Block request status  */
typedef enum {
	/** VirtIO block request is complete */
	DAO_VIRTIO_BLK_REQ_COMPLETE,
	/** VirtIO block request is still in progress */
	DAO_VIRTIO_BLK_REQ_IN_PROGRESS
} dao_virtio_blk_req_status_t;

/** Virtio blk devices */
extern struct dao_virtio_blkdev dao_virtio_blkdevs[];

/* Fast path data */
/** IO request dequeue function */
typedef uint16_t (*dao_virtio_blk_deq_fn_t)(void *q, void **mbufs,
						uint16_t nb_mbufs);
/** Dequeue external buf function */
typedef uint16_t (*dao_virtio_blk_deq_ext_fn_t)(void *q, void **vbufs,
						uint16_t nb_bufs);
/** IO request completion function */
typedef uint16_t (*dao_virtio_blk_process_compl_fn_t)(void *q,
			void **mbufs, uint16_t nb_compl);
/** IO request completion function */
typedef uint16_t (*dao_virtio_blk_process_compl_ext_fn_t)(void *q, void **vbufs,
							uint16_t nb_compl);
/** Management function */
typedef int (*dao_virtio_blk_desc_manage_fn_t)(uint16_t devid, uint16_t qp_count);
/** Management function */
typedef int (*dao_virtio_blk_desc_manage_ext_fn_t)(uint16_t devid, uint16_t qp_count);

/** Array of dequeue functions */
extern dao_virtio_blk_deq_fn_t dao_virtio_blk_deq_fns[];
/** Array of dequeue functions */
extern dao_virtio_blk_deq_ext_fn_t dao_virtio_blk_deq_ext_fns[];
/** Array of completion functions */
extern dao_virtio_blk_process_compl_fn_t dao_virtio_blk_process_compl_fns[];
/** Array of completion functions */
extern dao_virtio_blk_process_compl_ext_fn_t dao_virtio_blk_process_compl_ext_fns[];
/** Array of management functions */
extern dao_virtio_blk_desc_manage_fn_t dao_blk_desc_manage_fns[];
/** Array of management functions */
extern dao_virtio_blk_desc_manage_ext_fn_t dao_blk_desc_manage_ext_fns[];

/** Device status callback */
typedef int (*dao_virtio_blkdev_status_cb_t)(uint16_t devid, uint8_t status);
/** Multi queue configure callback */
typedef int (*dao_virtio_blkdev_mq_cfg_t)(uint16_t devid, bool qmap_set);
/** callback to get the ext buffers from the pool */
typedef int (*dao_virtio_blkdev_extbuf_get)(uint16_t devid, void *buffs[],
					uint16_t nb_buffs);
/** callback to put the ext buffers into the pool */
typedef int (*dao_virtio_blkdev_extbuf_put)(uint16_t devid, void *buffs[],
					uint16_t nb_buffs);

/** Virtio blk device callbacks */
struct dao_virtio_blkdev_cbs {
	/** Device status callback */
	dao_virtio_blkdev_status_cb_t status_cb;
	/** Alloc extbuf */
	dao_virtio_blkdev_extbuf_get extbuf_get;
	/** Free extbuf */
	dao_virtio_blkdev_extbuf_put extbuf_put;
};

/* End of structure dao_virtio_blkdev_cbs. */

/**
 * Virtio blk device initialize.
 *
 * @param devid
 *    Virtio blk device ID
 * @param conf
 *    Virtio blk device config.
 * @return
 *    Zero on success.
 */
int dao_virtio_blkdev_init(uint16_t devid, struct dao_virtio_blkdev_conf *conf);

/**
 * Virtio blk device cleanup.
 *
 * @param devid
 *    Virtio blk device ID
 *
 * @return
 *    Zero on success.
 */
int dao_virtio_blkdev_fini(uint16_t devid);

/**
 * Virtio blk device callback register
 *
 * @param cbs
 *    Application callbacks for virtio blk devices
 */
void dao_virtio_blkdev_cb_register(struct dao_virtio_blkdev_cbs *cbs);

/**
 * Virtio blk device callback unregister
 */
void dao_virtio_blkdev_cb_unregister(void);

/**
 * Get blk device queue count.
 *
 * @param devid
 *    Virtio blk device ID.
 * @return
 *    Number of virtio queues configured on success. Negative on failure.
 */
int dao_virtio_blkdev_queue_count(uint16_t devid);

/**
 * Get blk device feature bits.
 *
 * @param devid
 *    Virtio blk device ID.
 * @return
 *    Configured feature bits on success. Zero on failure.
 */
uint64_t dao_virtio_blkdev_feature_bits_get(uint16_t devid);

/**
 * Get blk device queue count max.
 *
 * API can be called before initializing virtio device.
 *
 * @param pem_devid
 *    PEM device ID.
 * @param devid
 *    Virtio blk device ID.
 * @return
 *    Max support virtio queue count on this device on success. Negative on failure.
 */
int dao_virtio_blkdev_queue_count_max(uint16_t pem_devid, uint16_t devid);

/**
 * Fetch virtio blkdev descriptors and acknowledge completions.
 *
 * To be called from service core as frequently as possible to
 * shadow descriptors between Host and Octeon memory.
 *
 * @param devid
 *    Virtio blk device ID.
 * @param q_count
 *    Number of queues to manage.
 * @return
 *    Zero on success.
 */
static __rte_always_inline int
dao_virtio_blk_io_desc_manage(uint16_t devid, uint16_t q_count)
{
	struct dao_virtio_blkdev *blkdev = &dao_virtio_blkdevs[devid];
	dao_virtio_blk_desc_manage_fn_t mgmt_fn;

	mgmt_fn = dao_blk_desc_manage_fns[blkdev->mgmt_fn_id];

	return (*mgmt_fn)(devid, q_count);
}

/**
 * Virtio blkdev process IO request completions
 *
 * @param devid
 *    Virtio blk device ID.
 * @param qid
 *    Virtio queue id.
 * @param mbufs
 *    pointer to array of buffer pointers to process IO completions
 * @param nb_compl
 *    Number of completions to process
 * @return
 *    Number of completions submitted to host
 */
static __rte_always_inline uint16_t
dao_virtio_blk_process_compl(uint16_t devid, uint16_t qid,
			     void **mbufs, uint16_t nb_compl)
{
	struct dao_virtio_blkdev *blkdev = &dao_virtio_blkdevs[devid];
	dao_virtio_blk_process_compl_fn_t compl_fn;
	void *q = blkdev->qs[qid];

	if (unlikely(!q))
		return 0;

	compl_fn = dao_virtio_blk_process_compl_fns[blkdev->compl_fn_id];

	return (*compl_fn)(q, mbufs, nb_compl);
}

/**
 * Virtio blkdev process IO request completions in ext buf mode
 *
 * @param devid
 *    Virtio blk device ID.
 * @param qid
 *    Virtio queue id.
 * @param vbufs
 *    pointer to array of ext buffers to process IO completions
 * @param nb_compl
 *    Number of completions to process
 * @return
 *    Number of completions submitted to host
 */
static __rte_always_inline uint16_t
dao_virtio_blk_process_compl_ext(uint16_t devid, uint16_t qid, void **vbufs,
				 uint16_t nb_compl)
{
	struct dao_virtio_blkdev *blkdev = &dao_virtio_blkdevs[devid];
	dao_virtio_blk_process_compl_ext_fn_t compl_fn;
	void *q = blkdev->qs[qid];

	if (unlikely(!q))
		return 0;

	compl_fn = dao_virtio_blk_process_compl_ext_fns[blkdev->compl_fn_id];

	return (*compl_fn)(q, vbufs, nb_compl);
}

/**
 * Virtio blkdev receive from Host
 *
 * @param devid
 *    Virtio blk device ID.
 * @param qid
 *    Virtio queue id.
 * @param mbufs
 *    Array to store buffer pointers of received pkts.
 * @param nb_mbufs
 *    Size of buffer array.
 * @return
 *    Number of mbufs received from host.
 */
static __rte_always_inline uint16_t
dao_virtio_blk_dequeue_burst(uint16_t devid, uint16_t qid,
			     void **mbufs, uint16_t nb_mbufs)
{
	struct dao_virtio_blkdev *blkdev = &dao_virtio_blkdevs[devid];
	dao_virtio_blk_deq_fn_t deq_fn;
	void *q = blkdev->qs[qid];

	if (unlikely(!q))
		return 0;

	deq_fn = dao_virtio_blk_deq_fns[blkdev->deq_fn_id];

	return (*deq_fn)(q, mbufs, nb_mbufs);
}

/**
 * Virtio blkdev receive raw buffers from Host
 *
 * @param devid
 *    Virtio blk device ID.
 * @param qid
 *    Virtio queue id.
 * @param vbufs
 *    Array to store buffer pointers of received packets.
 * @param nb_bufs
 *    Size of buffer array.
 * @return
 *    Number of buffers received from host.
 */
static __rte_always_inline uint16_t
dao_virtio_blk_dequeue_burst_ext(uint16_t devid, uint16_t qid, void **vbufs,
				 uint16_t nb_bufs)
{
	struct dao_virtio_blkdev *blkdev = &dao_virtio_blkdevs[devid];
	dao_virtio_blk_deq_ext_fn_t deq_fn;
	void *q = blkdev->qs[qid];

	if (unlikely(!q))
		return 0;

	deq_fn = dao_virtio_blk_deq_ext_fns[blkdev->deq_fn_id];

	return (*deq_fn)(q, vbufs, nb_bufs);
}

#endif /* __INCLUDE_DAO_VIRTIO_BLK_H__ */
