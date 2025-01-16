/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell
 */

/**
 * @file
 *
 * DAO virtio crypto library
 */

#ifndef __INCLUDE_DAO_VIRTIO_CRYPTO_H__
#define __INCLUDE_DAO_VIRTIO_CRYPTO_H__

#include <rte_common.h>
#include <rte_crypto.h>
#include <rte_crypto_asym.h>

#include <dao_virtio.h>

#define DAO_VIRTIO_CRYPTO_DEV_MAX 1
/* TODO - should be 64 */
#define DAO_VIRTIO_CRYPTO_QP_MAX 128

#define DAO_VIRTIO_INVALID_ID 0xFFFF

#define DAO_VIRTIO_CRYPTO_RX_BUF_CACHE_SZ 128
#define DAO_VIRTIO_CRYPTO_TX_BUF_CACHE_SZ 512

#define DAO_VIRTIO_CRYPTO_MAX_CHAIN_READ_DESC  4
#define DAO_VIRTIO_CRYPTO_MAX_CHAIN_WRITE_DESC 4

/** Virtio crypto device configuration */
struct dao_virtio_cryptodev_conf {
	/** PEM device ID */
	uint16_t pem_devid;
	/** Vchan to use for this virtio dev */
	uint16_t dma_vchan;
	/** Default dequeue mempool */
	struct rte_mempool *pool;
	/** ID of crypto device associated with this virtio device */
	uint16_t cdev_id;
};

/** Virtio crypto device data */
struct dao_virtio_cryptodev {
	/** Array of virtio queue pointers */
	void *qs[DAO_VIRTIO_MAX_QUEUES] __rte_cache_aligned;
	/** Dequeue function id */
	uint16_t deq_fn_id;
	/** Enqueue function id */
	uint16_t enq_fn_id;
	/** Descriptors management function id */
	uint16_t mgmt_fn_id;
	/** Cryptodev ID */
	uint16_t cdev_id;
	/** Cryptodev QP ID mapping. Each index corresponds to one virtio queue */
	uint8_t cdev_qp_id_map[DAO_VIRTIO_CRYPTO_QP_MAX];
#define DAO_VIRTIO_CRYPTODEV_MEM_SZ 8192
	uint8_t reserved[DAO_VIRTIO_CRYPTODEV_MEM_SZ];
};

/** Virtio crypto buffer */
struct dao_virtio_crypto_buffer {
	/** Metadata for carrying common information for batch of packets from a queue. */
	struct {
		union {
			/** Cryptodev */
			struct {
				/** Device ID */
				uint16_t id;
				/** Queue pair ID */
				uint16_t qp_id;
			} cdev;
			/** Virtio device  */
			struct {
				/** Device ID */
				uint16_t dev_id;
				/** Queue ID  */
				uint16_t q_id;
			} virt;
		};
		/* Count of packets from same queue */
		uint16_t cnt;
	} metadata;

	uint32_t output_len;
	rte_iova_t output_addr;
	struct rte_crypto_op cop;
	struct rte_crypto_asym_op asym;
	uint8_t reserved[];
};

/** Virtio dev - queue */
struct dao_virtio_cryptodev_vdev_q {
	uint16_t virtio_dev_id;
	uint16_t virtio_queue_id;
};

/** Virtio crypto devices */
extern struct dao_virtio_cryptodev dao_virtio_cryptodevs[];

/* Fast path data */
/** Dequeue function */
typedef uint16_t (*dao_virtio_crypto_deq_fn_t)(void *q, struct rte_crypto_op **cops,
					       uint16_t nb_cops);
/** Enqueue function */
typedef uint16_t (*dao_virtio_crypto_enq_fn_t)(void *q, struct rte_crypto_op **cops,
					       uint16_t nb_cops);
/** Management function */
typedef int (*dao_crypto_desc_manage_fn_t)(uint16_t devid, uint16_t qp_count);

/** Array of dequeue functions */
extern dao_virtio_crypto_deq_fn_t dao_virtio_crypto_deq_fns[];
/** Array of enqueue functions */
extern dao_virtio_crypto_enq_fn_t dao_virtio_crypto_enq_fns[];
/** Array of management functions */
extern dao_crypto_desc_manage_fn_t dao_crypto_desc_manage_fns[];

/** Device status callback */
typedef int (*dao_virtio_cryptodev_status_cb_t)(uint16_t devid, uint8_t status);

/** Crypto symmetric session create callback */
typedef uint64_t (*dao_virtio_cryptodev_sym_sess_create_cb_t)(uint16_t dev_id,
							      struct rte_crypto_sym_xform *x);
/** Crypto asymmetric session create callback */
typedef uint64_t (*dao_virtio_cryptodev_asym_sess_create_cb_t)(uint16_t dev_id,
							       struct rte_crypto_asym_xform *x);
/** Crypto session destroy callback */
typedef void (*dao_virtio_cryptodev_session_destroy_cb_t)(uint16_t dev_id, uint64_t session_id);

/** Virtio crypto device callbacks */
struct dao_virtio_cryptodev_cbs {
	/** Device status callback */
	dao_virtio_cryptodev_status_cb_t status_cb;
	/** Crypto symmetric session create callback */
	dao_virtio_cryptodev_sym_sess_create_cb_t sym_sess_create_cb;
	/** Crypto session destroy callback */
	dao_virtio_cryptodev_session_destroy_cb_t sym_sess_destroy_cb;
	/** Crypto asymmetric session create callback */
	dao_virtio_cryptodev_asym_sess_create_cb_t asym_sess_create_cb;
	/** Crypto session destroy callback */
	dao_virtio_cryptodev_session_destroy_cb_t asym_sess_destroy_cb;
};

/**
 * Virtio crypto device initialize.
 *
 * @param devid
 *    Virtio crypto device ID
 * @param conf
 *    Virtio crypto device config.
 * @return
 *    Zero on success.
 */
int dao_virtio_cryptodev_init(uint16_t devid, struct dao_virtio_cryptodev_conf *conf);

/**
 * Virtio crypto device cleanup.
 *
 * @param devid
 *    Virtio crypto device ID
 *
 * @return
 *    Zero on success.
 */
int dao_virtio_cryptodev_fini(uint16_t devid);

/**
 * Virtio crypto device callback register
 *
 * @param cbs
 *    Application callbacks for virtio crypto devices
 */
void dao_virtio_cryptodev_cb_register(struct dao_virtio_cryptodev_cbs *cbs);

/**
 * Virtio crypto device callback unregister
 */
void dao_virtio_cryptodev_cb_unregister(void);

/**
 * Get number of data queues for a virtio crypto device
 *
 * @param dev_id
 *   Virtio crypto device ID
 * @return
 *  Number of data queues
 */
uint16_t dao_virtio_cryptodev_data_queue_cnt_get(uint16_t dev_id);

/**
 * Get max number of data queues for a virtio crypto device
 *
 * @param dev_id
 *   Virtio crypto device ID
 * @return
 *  Max number of data queues
 */
uint16_t dao_virtio_cryptodev_max_dataqueue_cnt_get(uint16_t dev_id);

/**
 * Initialize common configuration for virtio crypto devices.
 */
void dao_virtio_cryptodev_common_cfg_init(void);

/**
 * Add crypto device to the map.
 *
 * @param dev_id
 *    Virtio crypto device ID.
 * @param qp_count
 *    Number of queue pairs.
 * @param mempool
 *   Array of mempools for each queue pair.
 * @return
 *    Zero on success.
 */
int dao_virtio_cryptodev_cdev_add(uint16_t dev_id, uint16_t qp_count,
				  struct rte_mempool *mempool[]);

/**
 * Remove crypto device from the map.
 *
 * @param dev_id
 *    Virtio crypto device ID.
 * @return
 *    Zero on success.
 */
int dao_virtio_cryptodev_cdev_remove(uint16_t dev_id);

/**
 * Assign a crypto queue for a virtio device ID and queue ID.
 *
 * @param virt_dev_id
 *    Virtio device ID.
 * @param virt_queue_id
 *    Virtio queue ID.
 * @return
 *    Zero on success.
 */
int dao_virtio_cryptodev_cdev_queue_assign(uint16_t virt_dev_id, uint16_t virt_queue_id);

/**
 * Release a crypto queue for a virtio device ID and queue ID.
 *
 * @param virt_dev_id
 *    Virtio device ID.
 * @param virt_queue_id
 *    Virtio queue ID.
 * @return
 *    Zero on success.
 */
int dao_virtio_cryptodev_cdev_queue_release(uint16_t virt_dev_id, uint16_t virt_queue_id);

/**
 * Get crypto device ID and queue ID from virtio device ID and queue ID.
 *
 * @param virt_dev_id
 *    Virtio device ID.
 * @param virt_queue_id
 *    Virtio queue ID.
 * @param cdev_id [out]
 *    Crypto device ID.
 * @param cdev_qp_id [out]
 *    Crypto queue ID.
 * @param mempool [out]
 *   Mempool for the queue.
 * @return
 *    Zero on success.
 */
int dao_virtio_cryptodev_cdev_map_queue_get(uint16_t virt_dev_id, uint16_t virt_queue_id,
					    uint16_t *cdev_id, uint16_t *cdev_qp_id,
					    struct rte_mempool **mempool);

/**
 * Get virtio device ID and queue ID from crypto device ID and queue ID.
 *
 * @param cdev_id
 *    Crypto device ID.
 * @param cdev_qp_id
 *    Crypto queue ID.
 * @param virt_dev_id [out]
 *    Virtio device ID.
 * @param virt_queue_id [out]
 *    Virtio queue ID.
 * @return
 *    Zero on success.
 */
int dao_virtio_cryptodev_virt_dev_map_queue_get(uint16_t cdev_id, uint16_t cdev_qp_id,
						uint16_t *virt_dev_id, uint16_t *virt_queue_id);
/**
 * Get all queues for a crypto device.
 * This is used to get all the virtio queues mapped to a cryptodev.
 *
 * @param cdev_id
 *   Crypto device ID.
 *
 * @return
 *  Array of virtio queues mapped to the cryptodev.
 */
const struct dao_virtio_cryptodev_vdev_q *
dao_virtio_cryptodev_cdev_map_all_queues_get(uint16_t cdev_id);

/**
 * Fetch virtio cryptodev descriptors and acknowledge completions.
 *
 * To be called from service core as frequently as possible to
 * shadow descriptors between Host and Octeon memory.
 *
 * @param devid
 *    Virtio crypto device ID.
 * @param qp_count
 *    Number of queue pairs to manage.
 * @return
 *    Zero on success.
 */
static __rte_always_inline int
dao_virtio_crypto_desc_manage(uint16_t devid, uint16_t qp_count)
{
	struct dao_virtio_cryptodev *cryptodev = &dao_virtio_cryptodevs[devid];
	dao_crypto_desc_manage_fn_t mgmt_fn;

	mgmt_fn = dao_crypto_desc_manage_fns[cryptodev->mgmt_fn_id];

	return (*mgmt_fn)(devid, qp_count);
}

/**
 * Virtio cryptodev receive from host
 *
 * @param devid
 *    Virtio crypto device ID.
 * @param qid
 *    Virtio queue id.
 * @param cops
 *    Array to store cops pointers of received crypto ops.
 * @param nb_cops
 *    Size of cop array.
 * @return
 *    Number of cops received from host.
 */
static __rte_always_inline uint16_t
dao_virtio_crypto_host_rx(uint16_t devid, uint16_t qid, struct rte_crypto_op **cops,
			  uint16_t nb_cops)
{
	struct dao_virtio_cryptodev *cryptodev = &dao_virtio_cryptodevs[devid];
	dao_virtio_crypto_deq_fn_t deq_fn;
	void *q = cryptodev->qs[qid];

	if (unlikely(!q))
		return 0;

	deq_fn = dao_virtio_crypto_deq_fns[cryptodev->deq_fn_id];

	return (*deq_fn)(q, cops, nb_cops);
}

/**
 * Virtio cryptodev transmit to host
 *
 * @param devid
 *    Virtio crypto device ID.
 * @param qid
 *    Virtio queue id.
 * @param cops
 *    Array of cop pointers of crypto operation to send to host.
 * @param nb_cops
 *    Number of cops to send.
 * @return
 *    Number of cops sent to host.
 */
static __rte_always_inline uint16_t
dao_virtio_crypto_host_tx(uint16_t devid, uint16_t qid, struct rte_crypto_op **cops,
			  uint16_t nb_cops)
{
	struct dao_virtio_cryptodev *cryptodev = &dao_virtio_cryptodevs[devid];
	dao_virtio_crypto_enq_fn_t enq_fn;
	void *q = cryptodev->qs[qid];

	if (unlikely(q == NULL))
		return 0;

	enq_fn = dao_virtio_crypto_enq_fns[cryptodev->enq_fn_id];

	return (*enq_fn)(q, cops, nb_cops);
}

/**
 * Get crypto device ID from virtio device ID.
 * This is used to get the cryptodev ID for a virtio device.
 *
 * @param virt_dev_id
 *    Virtio device ID.
 *
 * @return
 *    Crypto device ID.
 */
static __rte_always_inline uint16_t
dao_virtio_cdev_id_get(uint16_t virt_dev_id)
{
	struct dao_virtio_cryptodev *cryptodev = &dao_virtio_cryptodevs[virt_dev_id];

	return cryptodev->cdev_id;
}

/**
 * Get crypto device queue pair ID from virtio device ID and queue ID.
 * This is used to get the cryptodev queue pair ID for a virtio queue.
 *
 * @param virt_dev_id
 *    Virtio device ID.
 * @param virt_q_id
 *    Virtio queue ID.
 *
 * @return
 *    Crypto device queue pair ID.
 */
static __rte_always_inline uint16_t
dao_virtio_cdev_qp_id_get(uint16_t virt_dev_id, uint16_t virt_q_id)
{
	struct dao_virtio_cryptodev *cryptodev = &dao_virtio_cryptodevs[virt_dev_id];

	return cryptodev->cdev_qp_id_map[virt_q_id];
}

#endif /* __INCLUDE_DAO_VIRTIO_CRYPTO_H__ */
