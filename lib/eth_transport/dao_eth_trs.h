/* SPDX-License-Identifier: Marvell-Proprietary
 * Copyright (c) 2025 Marvell
 */
#ifndef __DAO_ETH_TRANSPORT_H__
#define __DAO_ETH_TRANSPORT_H__

#include <rte_common.h>

/**
 * @file dao_eth_trs.h
 *
 * This file contains the API for ethernet transport library.
 *
 * Ethernet transport is a mechanism to transport data over ethernet devices
 * using a common API. It is designed to be used by protocols that need to
 * transport data over ethernet devices without having to deal with the
 * configuration of the underlying devices. The ethernet transport device is
 * an encapsulation of one or more ethernet devices. Mapping of the transport
 * device to the underlying ethernet devices is done by the ethernet transport
 * library.
 *
 * The APIs can be invoked in the following order:
 * 1. Initialize the ethernet transport library using dao_eth_trs_init().
 * 2. Retrieve information about the ethernet transport devices using
 *    dao_eth_trs_info().
 * 3. Allocate the ethernet transport device using dao_eth_trs_dev_alloc().
 * 4. Configure the ethernet transport device queues using
 *    dao_eth_trs_dev_queue_configure().
 * 5. Get the ethernet transport device queue map
 *    using dao_eth_trs_dev_queue_map() to get actual ethernet port ID and queue
 *    ID corresponding to the transport device ID and queue ID.
 * 6. Start the ethernet transport device using dao_eth_trs_dev_start().
 * 7. Transmit/receive data using dao_eth_trs_tx() and dao_eth_trs_rx() using
 *    port ID and queue ID got from dao_eth_trs_dev_queue_map().
 * 8. Stop the ethernet transport device using dao_eth_trs_dev_stop().
 * 9. Close the ethernet transport device using dao_eth_trs_dev_free().
 * 10. Finalize the ethernet transport library using dao_eth_trs_fini().
 */

#include <stdint.h>

#include <rte_ethdev.h>
#include <rte_mempool.h>

/**
 * DAO ethernet transport op type based on the class of operation.
 * @see dao_eth_trs_hdr
 */
enum dao_eth_trs_op_type {
	/** Return the packet unchanged to the same queue */
	DAO_ETH_TRS_OP_TYPE_REFLECT = 0x0,
	/** OP type crypto start */
	DAO_ETH_TRS_OP_TYPE_CRYPTO_START = 0x1000,
	/** Misc crypto ops (passthrough etc) */
	DAO_ETH_TRS_OP_TYPE_CRYPTO_MISC,
	/** Symmetric crypto ops (FC etc) */
	DAO_ETH_TRS_OP_TYPE_CRYPTO_SYM,
	/** Asymmetric crypto ops (RSA etc) */
	DAO_ETH_TRS_OP_TYPE_CRYPTO_ASYM,
	/** Random Number Generator ops (HW RNG etc) */
	DAO_ETH_TRS_OP_TYPE_CRYPTO_RNG,
	/** Session create */
	DAO_ETH_TRS_OP_TYPE_SYM_SESSION_CREATE,
	/** Session destroy */
	DAO_ETH_TRS_OP_TYPE_SYM_SESSION_DESTROY,
	/** OP type crypto end */
	DAO_ETH_TRS_OP_TYPE_CRYPTO_END = 0x1fff,
};

/** DAO ethernet transport header */
/* Structure dao_eth_trs_hdr 8< */
struct __rte_packed dao_eth_trs_hdr {
	/** Packet op type. @see dao_eth_trs_op_type */
	uint16_t op_type;
	/** Packet length */
	uint16_t op_len;
};
/* >8 End of structure dao_eth_trs_hdr. */

/** DAO ethernet transport packet */
/* Structure dao_eth_trs_pkt 8< */
struct __rte_packed dao_eth_trs_pkt {
	/** Packet header */
	struct dao_eth_trs_hdr hdr;
	/** Packet data */
	uint8_t data[];
};
/* >8 End of structure dao_eth_trs_pkt. */

/** Ethernet transport device configuration */
struct dao_eth_trs_dev_config {
	uint16_t nb_queues;  /**< Number of RX/TX queues per device */
	uint8_t promiscuous; /**< Set to 1 to enable promiscuous mode */
};

/** Ethernet transport queue configuration */
struct dao_eth_trs_queue_config {
	uint16_t queue_size;       /**< RX/TX descriptors per queue */
	struct rte_mempool *rx_mp; /**< RX mempool to use per queue */
};

/** Ethernet transport information */
struct dao_eth_trs_info {
	uint8_t nb_devs;         /**< Max number of ethernet transport devices */
	uint16_t nb_queues;      /**< Max number of RX/TX queues per device */
	uint16_t min_queue_size; /**< Min number of RX/TX descriptors per queue */
	uint16_t max_queue_size; /**< Max number of RX/TX descriptors per queue */
	uint32_t min_buf_len;    /**< Minimum configurable length of packet data */
	uint32_t max_pkt_len;    /**< Maximum configurable length of a packet */
};

#define dao_eth_trs_tx rte_eth_tx_burst /**< Alias for rte_eth_tx_burst */
#define dao_eth_trs_rx rte_eth_rx_burst /**< Alias for rte_eth_rx_burst */

/**
 * Initialize ethernet transport.
 *
 * This function initializes the ethernet transport library and sets up the
 * necessary resources. It must be called after EAL initialization and
 * before any other ethernet transport API is invoked. If no supported
 * ethernet devices are found, this function returns an error.
 *
 * @return
 *  0 on success, negative on error.
 */
int dao_eth_trs_init(void);

/**
 * Finalize ethernet transport.
 *
 * This function finalizes the ethernet transport library and frees the
 * resources allocated during initialization.
 *
 * @return
 *  0 on success, negative on error.
 */
int dao_eth_trs_fini(void);

/**
 * Get information about the ethernet transport devices.
 *
 * This function retrieves information about the ethernet transport devices.
 *
 * @param info
 *  Pointer to the structure to store the information.
 *
 * @return
 *  - 0 on success
 *  - -EINVAL if the ethernet transport library is not initialized
 */
int dao_eth_trs_info(struct dao_eth_trs_info *info);

/**
 * Allocate an ethernet transport device.
 *
 * This function initializes the necessary resources for the ethernet transport
 * device for a given device ID and configuration. The device is an
 * encapsulation of one or more ethernet devices.
 *
 * @param dev_id
 *  Device ID of the ethernet transport device to allocate.
 * @param config
 *  Configuration parameters for the ethernet transport device.
 *
 * @return
 *  0 on success, negative on error.
 */
int dao_eth_trs_dev_alloc(uint8_t dev_id, struct dao_eth_trs_dev_config *config);

/**
 * Configure an ethernet transport device queue.
 *
 * This function configures the RX/TX queue of the ethernet transport device
 * with the configuration parameters provided by the caller.
 *
 * @param dev_id
 *  Device ID of the ethernet transport device.
 * @param queue_id
 *  Queue ID of the RX/TX queue.
 * @param conf
 *  Configuration parameters for the RX/TX queue.
 *
 * @return
 *  0 on success, negative on error.
 */
int dao_eth_trs_dev_queue_configure(uint8_t dev_id, uint16_t queue_id,
				    struct dao_eth_trs_queue_config *conf);

/**
 * Get ethernet port ID and queue ID for a transport device ID and queue ID.
 *
 * This function retrieves the ethernet port ID and queue ID corresponding to the
 * transport device ID and queue ID. It can be used to transmit/receive packets
 * using the APIs dao_eth_trs_tx() and dao_eth_trs_rx().
 *
 * @param dev_id
 *  Device ID of the ethernet transport device.
 * @param dev_queue_id
 *  Queue ID of the ethernet transport device.
 * @param port_id [out]
 *  Pointer to store the ethernet port ID.
 * @param queue_id [out]
 *  Pointer to store the queue ID of the ethernet port.
 *
 * @return
 *  0 on success, negative on error.
 */
int dao_eth_trs_dev_queue_map(uint8_t dev_id, uint16_t dev_queue_id, uint16_t *port_id,
			      uint16_t *queue_id);

/**
 * Start ethernet transport device.
 *
 * This function starts the ethernet transport device and sets it up for data
 * transfer. The device must be configured before starting it using
 * dao_eth_trs_dev_alloc() and dao_eth_trs_dev_queue_conf().
 *
 * @param dev_id
 *  Device ID of the ethernet transport device.
 *
 * @return
 *  0 on success, negative on error.
 */
int dao_eth_trs_dev_start(uint8_t dev_id);

/**
 * Stop ethernet transport device.
 *
 * This function stops the ethernet transport device and marks it as inactive.
 *
 * @param dev_id
 *  Device ID of the ethernet transport device.
 *
 * @return
 *  0 on success, negative on error.
 */
int dao_eth_trs_dev_stop(uint8_t dev_id);

/**
 * Close the ethernet transport device.
 *
 * This function closes the ethernet transport device and frees the resources
 * allocated during allocation. The device must be stopped before closing it
 * using dao_eth_trs_dev_stop().
 *
 * @param dev_id
 *  Device ID of the ethernet transport device.
 *
 * @return
 * 0 on success, negative on error.
 */
int dao_eth_trs_dev_free(uint8_t dev_id);
#endif /*  __DAO_ETH_TRANSPORT_H__ */
