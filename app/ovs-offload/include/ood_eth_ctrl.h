/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2023 Marvell.
 */

#ifndef __OOD_ETH_CTRL_H__
#define __OOD_ETH_CTRL_H__

#include <ood_msg_ctrl.h>

int ood_set_mac_address(uint16_t rep_portid, uint8_t *mac_addr);
int ood_eth_stats_get_clear(uint16_t rep_portid, ood_msg_t msg, ood_msg_ack_data_t *adata);
#endif /* __OOD_ETH_CTRL_H__ */
