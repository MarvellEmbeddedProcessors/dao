/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2023 Marvell.
 */

#ifndef __OOD_CTRL_CHAN_H__
#define __OOD_CTRL_CHAN_H__

#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <ood_flow_ctrl.h>

#define OOD_CTRL_CHAN_SRV_SOCK      "/tmp/cxk_rep_ctrl_msg_sock"

/* Forward declaration */
struct ood_main_cfg_data;

typedef struct ood_ctrl_chan_param {
	/* Flow operations array */
	representor_mapping_t rep_map[RTE_MAX_ETHPORTS];
	/* Server sock fd */
	int sock_fd;
	/* Control chan thread */
	rte_thread_t ctrl_chan_thrd;
	/* Spinlock */
	rte_spinlock_t ctrl_chan_lock;
	bool ctrl_msg_polling_enabled;
} ood_ctrl_chan_param_t;

int ood_control_channel_init(struct ood_main_cfg_data *ood_main_cfg);
representor_mapping_t *ood_representor_mapping_get(uint16_t repr_qid);
ssize_t ood_ctrl_msg_send(int socketfd, void *data, uint32_t len, int afd);
int ood_ctrl_msg_recv(int socketfd, void *data, uint32_t len);

#endif /* __OOD_CTRL_CHAN_H__ */
