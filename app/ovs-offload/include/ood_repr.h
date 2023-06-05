/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2023 Marvell.
 */

#ifndef __OOD_REPR_H__
#define __OOD_REPR_H__

#define OOD_MAX_REPR_RX_QUEUE_PER_LCORE 64
#define OOD_TX_DESC_PER_QUEUE           512
#define OOD_RX_DESC_PER_QUEUE           256
#define OOD_NB_REPR_MBUF                2048

/* Forward declaration */
struct ood_main_cfg_data;

typedef struct ood_repr_param {
	/* Port ID of repr */
	uint8_t portid;
	/* No of representor ports */
	uint16_t nb_repr;
	/* representor id map */
	uint16_t repr_map[RTE_MAX_ETHPORTS];
	/* Mempool handle */
	struct rte_mempool *repr_pool;
} ood_repr_param_t;

int ood_representor_eswitch_dev_init(struct ood_main_cfg_data *ood_main_cfg);
int ood_repr_set_nb_representors(struct ood_main_cfg_data *ood_main_cfg, uint16_t count);
uint16_t ood_repr_get_eswitch_portid(struct ood_main_cfg_data *ood_main_cfg);
int ood_repr_populate_node_config(struct ood_main_cfg_data *ood_main_cfg,
				  ood_node_repr_ctrl_conf_t *repr_cfg);
#endif /* __OOD_REPR_H__ */
