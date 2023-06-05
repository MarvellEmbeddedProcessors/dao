/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2023 Marvell.
 */

#ifndef __OOD_MSG_CTRL_H__
#define __OOD_MSG_CTRL_H__

#include <rte_ethdev.h>

#define OOD_SIGN            0xcdacdeadbeefcadc
#define MAX_BUFFER_SIZE     1500

/*
 * Control message format
 *
 *        +---------------------------------+
 *        |          TYPE (8B) - HEADER     |
 *        +---------------------------------+
 *        |          HEADER DATA (10B)      |
 *        +---------------------------------+
 *        |          TYPE (4B) - MSG        |
 *        +---------------------------------+
 *        |          MSG TYPE (8B)          |
 *        +---------------------------------+
 *        |          MSG TYPE DATA          |
 *        +---------------------------------+
 *
 * Example - Flow create command format
 *
 *        +------------------------------------------------------------------------------+
 *        |          TYPE (8B) - HEADER                                                  |
 *        +------------------------------------------------------------------------------+
 *        |          HEADER DATA (10B)  - Signature                                      |
 *        +------------------------------------------------------------------------------+
 *        |          TYPE (4B) - MSG                                                     |
 *        +------------------------------------------------------------------------------+
 *        |          MSG TYPE (8B) - FLOW CREATE                                         |
 *        +------------------------------------------------------------------------------+
 *        |          FLOW CREATE DATA (8B)  - portid, no of patterns/actions             |
 *        +------------------------------------------------------------------------------+
 *        |          TYPE (8B) - ATTR                                                    |
 *        +------------------------------------------------------------------------------+
 *        |          ATTR DATA (12B)                                                     |
 *        +------------------------------------------------------------------------------+
 *        |          TYPE (8B) - PATTERN                                                 |
 *        +------------------------------------------------------------------------------+
 *        |          PATTERN DATA (variable sz)                                          |
 *        +------------------------------------------------------------------------------+
 *        |          TYPE (8B) - ACTION                                                  |
 *        +------------------------------------------------------------------------------+
 *        |          ACTION DATA (variable sz)                                           |
 *        +------------------------------------------------------------------------------+
 *        |          TYPE (4B) - MSG                                                     |
 *        +------------------------------------------------------------------------------+
 *        |          MSG TYPE (8B) - END                                                 |
 *        +------------------------------------------------------------------------------+
 *
 */

typedef enum OOD_NACK_CODE {
	OOD_MSG_NACK_INV_RDY_DATA   = 0x501,
	OOD_MSG_NACK_INV_REP_CNT    = 0x502,
	OOD_MSG_NACK_REPE_STP_FAIL = 0x503
} ood_nack_code_t;

typedef enum OOD_TYPE {
	OOD_TYPE_HEADER = 0,
	OOD_TYPE_MSG,
	OOD_TYPE_ATTR,
	OOD_TYPE_PATTERN,
	OOD_TYPE_ACTION,
	OOD_TYPE_FLOW
} ood_type_t;

typedef enum OOD_MSG {
	/* General sync messages */
	OOD_MSG_READY = 0,
	OOD_MSG_ACK,
	OOD_MSG_EXIT,
	/* Ethernet operation msgs */
	OOD_MSG_ETH_SET_MAC,
	OOD_MSG_ETH_STATS_GET,
	OOD_MSG_ETH_STATS_CLEAR,
	/* Flow operation msgs */
	OOD_MSG_FLOW_CREATE,
	OOD_MSG_FLOW_DESTROY,
	OOD_MSG_FLOW_VALIDATE,
	OOD_MSG_FLOW_FLUSH,
	OOD_MSG_FLOW_DUMP,
	OOD_MSG_FLOW_QUERY,
	/* End of messaging sequence */
	OOD_MSG_END,
} ood_msg_t;

/* Types */
typedef struct ood_type_data {
	ood_type_t type;
	uint32_t length;
	uint64_t data[];
} __rte_packed ood_type_data_t;

/* Header */
typedef struct ood_header {
	uint64_t signature;
	uint16_t nb_hops;
} __rte_packed ood_header_t;

/* Message meta */
typedef struct ood_msg_data {
	ood_msg_t type;
	uint32_t length;
	uint64_t data[];
} __rte_packed ood_msg_data_t;

/* Ack msg */
typedef struct ood_msg_ack_data {
	ood_msg_t type;
	uint32_t size;
	union {
		void *data;
		uint64_t val;
		int64_t sval;
	} u;
} __rte_packed ood_msg_ack_data_t;

/* Ack msg */
typedef struct ood_msg_ack_data1 {
	ood_msg_t type;
	uint32_t size;
	uint64_t data[];
} __rte_packed ood_msg_ack_data1_t;

/* Ready msg */
typedef struct ood_msg_ready_data {
	uint8_t val;
	uint16_t nb_ports;
	uint16_t data[];
} __rte_packed ood_msg_ready_data_t;

/* Exit msg */
typedef struct ood_msg_exit_data {
	uint8_t val;
	uint16_t nb_ports;
	uint16_t data[];
} __rte_packed ood_msg_exit_data_t;

/* Ethernet op - set mac */
typedef struct ood_msg_eth_mac_set_meta {
	uint16_t portid;
	uint8_t addr_bytes[RTE_ETHER_ADDR_LEN];
} __rte_packed ood_msg_eth_set_mac_meta_t;

/* Ethernet op - get/clear stats */
typedef struct ood_msg_eth_stats_meta {
	uint16_t portid;
} __rte_packed ood_msg_eth_stats_meta_t;

/* Flow create msg meta */
typedef struct ood_msg_flow_create_meta {
	uint16_t portid;
	uint16_t nb_pattern;
	uint16_t nb_action;
} __rte_packed ood_msg_flow_create_meta_t;

/* Flow destroy msg meta */
typedef struct ood_msg_flow_destroy_meta {
	uint64_t flow;
	uint16_t portid;
} __rte_packed ood_msg_flow_destroy_meta_t;

/* Flow flush msg meta */
typedef struct ood_msg_flow_flush_meta {
	uint16_t portid;
} __rte_packed ood_msg_flow_flush_meta_t;

/* Flow dump msg meta */
typedef struct ood_msg_flow_dump_meta {
	uint64_t flow;
	uint16_t portid;
	uint8_t is_stdout;
} __rte_packed ood_msg_flow_dump_meta_t;

/* Flow query msg meta */
typedef struct ood_msg_flow_query_meta {
	uint64_t flow;
	uint16_t portid;
	uint8_t reset;
	uint32_t action_data_sz;
	uint8_t action_data[];
} __rte_packed ood_msg_flow_query_meta_t;

/* Type pattern meta */
typedef struct ood_pattern_meta {
	uint16_t type;
	uint16_t spec_sz;
	uint16_t last_sz;
	uint16_t mask_sz;
} __rte_packed ood_pattern_meta_t;

/* Type action meta */
typedef struct ood_action_hdr {
	uint16_t type;
	uint16_t conf_sz;
} __rte_packed ood_action_meta_t;

int ood_process_control_packet(void *msg_buf, uint32_t sz);
int ood_send_ack_message(ood_msg_ack_data_t *adata);
int ood_send_ready_message(void);
void ood_send_exit_message(void);

#endif /* __OOD_MSG_CTRL_H__ */
