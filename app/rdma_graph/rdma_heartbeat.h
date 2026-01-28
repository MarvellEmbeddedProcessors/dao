/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef _RDMA_HEARTBEAT_H_
#define _RDMA_HEARTBEAT_H_

#include "rdma_graph.h"
#include "rdma_init.h"

/* External global variable */
extern struct rdma_main_cfg_data *rdma_main_cfg;

/* Device status */
enum rdma_dev_status {
	RDMA_DEV_STATUS_INVALID,
	RDMA_DEV_STATUS_ALLOC,
	RDMA_DEV_STATUS_WAIT_FOR_FW,
	RDMA_DEV_STATUS_INIT,
	RDMA_DEV_STATUS_READY,
	RDMA_DEV_STATUS_UNINIT
};

/* RDMA event types */
enum rdma_event_type { RDMA_EVENT_TYPE_HEARTBEAT, RDMA_EVENT_TYPE_LINK_STATUS };

/* RDMA event info structure */
struct rdma_event_info {
	enum rdma_event_type e;
	union {
		struct {
			int dev_id;
			int status;
		} hbeat;
		struct {
			int port_id;
			int status;
		} link_status;
	} u;
};

/* Heartbeat state machine for ACK*/
enum hb_state {
	HB_STATE_WAIT_HOST_UP, /* Continuously poll for value 1 (host up) */
	HB_STATE_WAIT_ACK      /* Timer-based poll for value 2 (heartbeat ACK) */
};

/* Heartbeat management functions */
int rdma_heartbeat_init(void);
void rdma_heartbeat_cleanup(void);
void rdma_handle_heartbeat_alarm(void);
int rdma_send_event_to_host(struct rdma_event_info *info);

/* Link status management functions */
int rdma_link_status_init(void);
void rdma_link_status_cleanup(void);
int rdma_link_status_callback(uint16_t port_id, enum rte_eth_event_type type, void *param,
			      void *ret_param);

/* Heartbeat processing */
int rdma_send_heartbeat(void);

/* RDMA resource cleanup */
void rdma_abrupt_cleanup_resources(void);

/* EAL alarm callback and starter function */
void heartbeat_alarm_cb(void *arg);
void rdma_start_heartbeat_eal_alarm(uint32_t ms);

#endif /* _RDMA_HEARTBEAT_H_ */
