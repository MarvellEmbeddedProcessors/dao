/* SPDX-License-Identifier: Marvell-Proprietary
 * Copyright (c) 2025 Marvell
 */
#ifndef __DAO_ETH_TRANSPORT_H__
#define __DAO_ETH_TRANSPORT_H__

#include <rte_common.h>

/**
 * @file dao_eth_trs.h
 *
 * This file contains the API for Ethernet transport.
 *
 * Ethernet transport is a mechanism to transport data over ethernet devices
 * using a common API. It is designed to be used by protocols that need to
 * transport data over ethernet devices without having to deal with the
 * configuration of the device and track the context of each data transfer.
 */

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
	/** OP type crypto end */
	DAO_ETH_TRS_OP_TYPE_CRYPTO_END = 0x1fff,
};

/** DAO ethernet transport header */
struct __rte_packed dao_eth_trs_hdr {
	uint16_t op_type; /**< Packet op type. @see dao_eth_trs_op_type */
	/** Packet length */
	uint16_t op_len;
};

/** DAO ethernet transport packet */
struct __rte_packed dao_eth_trs_pkt {
	/** Packet header */
	struct dao_eth_trs_hdr hdr;
	/** Packet data */
	uint8_t data[];
};

#endif /*  __DAO_ETH_TRANSPORT_H__ */
