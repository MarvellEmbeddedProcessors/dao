/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2023 Marvell.
 */

#ifndef __SMC_NODE_CTRL_H__
#define __SMC_NODE_CTRL_H__

int smc_node_ctrl_init(void);
/**
 * Control API for configuring Eth nodes
 *
 * @param graph_prm
 *   Graph parameters
 *
 * @return
 *   0 on successful initialization, negative otherwise.
 */
int smc_node_eth_ctrl(smc_graph_param_t *graph_prm);
int smc_node_link_unlink_ports(uint16_t portid_rx, uint16_t portid_tx, bool link);
int smc_node_context_save(struct lcore_conf *qconf);
int smc_node_add_del_port(uint16_t portid, bool enable);
#endif /* __SMC_NODE_CTRL_H__ */
