/* SPDX-License-Identifier: Marvell-Proprietary
 * Copyright (c) 2023 Marvell
 */

/**
 * @file
 *
 * DAO virtio net library
 */

#ifndef __INCLUDE_DAO_VIRTIO_NET_H__
#define __INCLUDE_DAO_VIRTIO_NET_H__

#include <dao_virtio.h>

#include <spec/virtio_net.h>

/** Virtio net device link info */
struct dao_virtio_netdev_link_info {
	/** Link status */
	uint16_t status;
	/**
	 * Link speed.
	 *
	 * Speed contains the device speed, in units of 1 MBit per second,
	 * 0 to 0x7fffffff, or 0xffffffff for unknown speed.
	 */
	uint32_t speed;
	/**
	 * Link mode.
	 *
	 * 0x00 - half duplex
	 * 0x01 - full duplex
	 * Any other value stands for unknown.
	 */
	uint8_t duplex;
};

/** Virtio net device configuration */
struct dao_virtio_netdev_conf {
	/** PEM device ID */
	uint16_t pem_devid;
	/** Default dequeue mempool */
	struct rte_mempool *pool;
	/** Vchan to use for this virtio dev */
	uint16_t dma_vchan;
	/** Auto free enabled/disabled */
	bool auto_free_en;
	/** RETA size supported */
	uint16_t reta_size;
	/** HASH key size supported */
	uint16_t hash_key_size;
	/** Default MTU */
	uint16_t mtu;
	/** Default MAC address */
	uint8_t mac[VIRTIO_NET_ETHER_ADDR_LEN];
	/** Link info */
	struct dao_virtio_netdev_link_info link_info;
};

/* End of structure dao_virtio_netdev_conf. */

/** Virtio net device data */
struct dao_virtio_netdev {
	/** Array of virtio queue pointers */
	void *qs[DAO_VIRTIO_MAX_QUEUES] __rte_cache_aligned;
	/** Dequeue function id */
	uint16_t deq_fn_id;
	/** Enqueue function id */
	uint16_t enq_fn_id;
	/** Descriptors management function id */
	uint16_t mgmt_fn_id;
#define DAO_VIRTIO_NETDEV_MEM_SZ 8192
	uint8_t reserved[DAO_VIRTIO_NETDEV_MEM_SZ];
};

/** Virtio net devices */
extern struct dao_virtio_netdev dao_virtio_netdevs[];

/* Fast path data */
/** Dequeue function */
typedef uint16_t (*dao_virtio_net_deq_fn_t)(void *q, struct rte_mbuf **mbufs, uint16_t nb_mbufs);
/** Enqueue function */
typedef uint16_t (*dao_virtio_net_enq_fn_t)(void *q, struct rte_mbuf **mbufs, uint16_t nb_mbufs);
/** Management function */
typedef int (*dao_net_desc_manage_fn_t)(uint16_t devid, uint16_t qp_count);

/** Array of dequeue functions */
extern dao_virtio_net_deq_fn_t dao_virtio_net_deq_fns[];
/** Array of enqueue functions */
extern dao_virtio_net_enq_fn_t dao_virtio_net_enq_fns[];
/** Array of management functions */
extern dao_net_desc_manage_fn_t dao_net_desc_manage_fns[];

/** Device status callback */
typedef int (*dao_virtio_netdev_rss_cb_t)(uint16_t devid, struct virtio_net_ctrl_rss *rss);
/** RSS setup callback */
typedef int (*dao_virtio_netdev_status_cb_t)(uint16_t devid, uint8_t status);
/** Promisc mode callback */
typedef int (*dao_virtio_netdev_promisc_cb_t)(uint16_t devid, uint8_t enable);
/** All multi callback */
typedef int (*dao_virtio_netdev_allmulti_cb_t)(uint16_t devid, uint8_t enable);
/** Mac set callback */
typedef int (*dao_virtio_netdev_mac_set_cb_t)(uint16_t devid, uint8_t *mac);
/** Mac filter callback */
typedef int (*dao_virtio_netdev_mac_add_cb_t)(uint16_t devid, struct virtio_net_ctrl_mac *mac_tbl,
					      uint8_t type);
/** Multi queue configure callback */
typedef int (*dao_virtio_netdev_mq_cfg_t)(uint16_t devid, bool qmap_set);
/** VLAN filter add callback */
typedef int (*dao_virtio_netdev_vlan_t)(uint16_t devid, uint16_t vlan_tci);

/** Virtio net device callbacks */
struct dao_virtio_netdev_cbs {
	/** Device status callback */
	dao_virtio_netdev_status_cb_t status_cb;
	/** RSS setup callback */
	dao_virtio_netdev_rss_cb_t rss_cb;
	/** Promisc mode callback */
	dao_virtio_netdev_promisc_cb_t promisc_cb;
	/** All multi callback */
	dao_virtio_netdev_allmulti_cb_t allmulti_cb;
	/** Mac set callback */
	dao_virtio_netdev_mac_set_cb_t mac_set;
	/** Mac filter callback */
	dao_virtio_netdev_mac_add_cb_t mac_add;
	/** Multi queue configure callback */
	dao_virtio_netdev_mq_cfg_t mq_configure;
	/** VLAN filter add callback */
	dao_virtio_netdev_vlan_t vlan_add;
	/** VLAN filter del callback */
	dao_virtio_netdev_vlan_t vlan_del;
};

/* End of structure dao_virtio_netdev_cbs. */

/**
 * Virtio net device initialize.
 *
 * @param devid
 *    Virtio net device ID
 * @param conf
 *    Virtio net device config.
 * @return
 *    Zero on success.
 */
int dao_virtio_netdev_init(uint16_t devid, struct dao_virtio_netdev_conf *conf);

/**
 * Virtio net device cleanup.
 *
 * @param devid
 *    Virtio net device ID
 *
 * @return
 *    Zero on success.
 */
int dao_virtio_netdev_fini(uint16_t devid);

/**
 * Virtio net device callback register
 *
 * @param cbs
 *    Application callbacks for virtio net devices
 */
void dao_virtio_netdev_cb_register(struct dao_virtio_netdev_cbs *cbs);

/**
 * Virtio net device callback unregister
 */
void dao_virtio_netdev_cb_unregister(void);

/**
 * Get net device queue count.
 *
 * @param devid
 *    Virtio net device ID.
 * @return
 *    Number of virtio queues configured on success. Negative on failure.
 */
int dao_virtio_netdev_queue_count(uint16_t devid);

/**
 * Get net device feature bits.
 *
 * @param devid
 *    Virtio net device ID.
 * @return
 *    Configured feature bits on success. Zero on failure.
 */
uint64_t dao_virtio_netdev_feature_bits_get(uint16_t devid);

/**
 * Get net device queue count max.
 *
 * API can be called before initializing virtio device.
 *
 * @param pem_devid
 *    PEM device ID.
 * @param devid
 *    Virtio net device ID.
 * @return
 *    Max support virtio queue count on this device on success. Negative on failure.
 */
int dao_virtio_netdev_queue_count_max(uint16_t pem_devid, uint16_t devid);

/**
 * Update link status of netdev.
 *
 * @param devid
 *    Virtio net device ID.
 * @param info
 *    Virtio net device link info.
 * @return
 *    Zero on success. Negative on failure.
 */
int dao_virtio_netdev_link_sts_update(uint16_t devid, struct dao_virtio_netdev_link_info *info);

/* Fast path routines */

/**
 * Fetch virtio netdev descriptors and acknowledge completions.
 *
 * To be called from service core as frequently as possible to
 * shadow descriptors between Host and Octeon memory.
 *
 * @param devid
 *    Virtio net device ID.
 * @param qp_count
 *    Number of queue pairs to manage.
 * @return
 *    Zero on success.
 */
static __rte_always_inline int
dao_virtio_net_desc_manage(uint16_t devid, uint16_t qp_count)
{
	struct dao_virtio_netdev *netdev = &dao_virtio_netdevs[devid];
	dao_net_desc_manage_fn_t mgmt_fn;
	mgmt_fn = dao_net_desc_manage_fns[netdev->mgmt_fn_id];

	return (*mgmt_fn)(devid, qp_count);
}

/**
 * Virtio netdev receive from Host
 *
 * @param devid
 *    Virtio net device ID.
 * @param qid
 *    Virtio queue id in range of { 1, 3, 5, ... N + 1} as they are host Tx queue id's.
 * @param mbufs
 *    Array to store mbuf pointers of received pkts.
 * @param nb_mbufs
 *    Size of mbuf array.
 * @return
 *    Number of mbufs received from host.
 */
static __rte_always_inline uint16_t
dao_virtio_net_dequeue_burst(uint16_t devid, uint16_t qid,
			     struct rte_mbuf **mbufs, uint16_t nb_mbufs)
{
	struct dao_virtio_netdev *netdev = &dao_virtio_netdevs[devid];
	dao_virtio_net_deq_fn_t deq_fn;
	void *q = netdev->qs[qid];

	if (unlikely(!q))
		return 0;

	deq_fn = dao_virtio_net_deq_fns[netdev->deq_fn_id];

	return (*deq_fn)(q, mbufs, nb_mbufs);
}

/**
 * Virtio netdev send to Host
 *
 * @param devid
 *    Virtio net device ID.
 * @param qid
 *    Virtio queue id in range of { 0, 2, 4, ... N } as they are host Rx queue id's.
 * @param mbufs
 *    Array of mbuf pointers of pkts to send to host.
 * @param nb_mbufs
 *    Number of pkts to send.
 * @return
 *    Number of mbufs sent to host.
 */
static __rte_always_inline uint16_t
dao_virtio_net_enqueue_burst(uint16_t devid, uint16_t qid,
			     struct rte_mbuf **mbufs, uint16_t nb_mbufs)
{
	struct dao_virtio_netdev *netdev = &dao_virtio_netdevs[devid];
	dao_virtio_net_enq_fn_t enq_fn;
	void *q = netdev->qs[qid];

	if (unlikely(!q))
		return 0;

	enq_fn = dao_virtio_net_enq_fns[netdev->enq_fn_id];

	return (*enq_fn)(q, mbufs, nb_mbufs);
}

#endif /* __INCLUDE_DAO_VIRTIO_NET_H__ */
