/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#ifndef _APP_SECGW_GRAPH_SECGW_H_
#define _APP_SECGW_GRAPH_SECGW_H_

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <signal.h>
#include <assert.h>

#include <rte_config.h>
#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_spinlock.h>
#include <rte_eal.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_memcpy.h>
#include <rte_memory.h>
#include <rte_memzone.h>
#include <rte_per_lcore.h>
#include <rte_prefetch.h>
#include <rte_ethdev.h>
#include <rte_crypto_sym.h>
#include <rte_security.h>

#include <dao_log.h>
#include <dao_util.h>

#include <dao_port_group.h>
#include <dao_portq_group_worker.h>
#include <dao_workers.h>
#include <dao_netlink.h>
#include <dao_dynamic_string.h>

#include <devices/secgw_device.h>

typedef struct secgw_numa_id {
	STAILQ_ENTRY(secgw_numa_id) next_numa_id;
	int numa_id;
	void *user_arg; /* TODO: temporary save for now */
} secgw_numa_id_t;

typedef struct {
	RTE_MARKER c0 __rte_cache_aligned;
	volatile int datapath_exit_requested;

	RTE_MARKER c1 __rte_cache_aligned;
	secgw_device_main_t device_main;

	/* List of numa nodes supported by system */
	STAILQ_HEAD(, secgw_numa_id)secgw_main_numa_list;
} secgw_main_t;

/* External function declarations */
extern secgw_main_t *__secgw_main;
extern dao_netlink_route_callback_ops_t secgw_route_ops;
extern dao_netlink_xfrm_callback_ops_t secgw_xfrm_ops;

/* Function declarations */
int secgw_main_init(int argc, char **argv, size_t app_sz);
int secgw_main_exit(void);

/* Static inline functions */
static inline int
secgw_main_exit_requested(secgw_main_t *em)
{
	return em->datapath_exit_requested;
}

static inline secgw_main_t *secgw_get_main(void)
{
	return __secgw_main;
}

static inline secgw_device_main_t *secgw_get_device_main(void)
{
	secgw_main_t *em = __secgw_main;

	if (em)
		return &em->device_main;

	return NULL;
}

static inline int32_t secgw_num_devices_get(void)
{
	secgw_device_main_t *sdm = secgw_get_device_main();

	return sdm->n_devices;
}

static inline secgw_device_t *secgw_get_device(uint32_t index_in_device_main)
{
	secgw_device_main_t *sdm = secgw_get_device_main();

	RTE_VERIFY(index_in_device_main < (uint32_t)sdm->n_devices);

	return sdm->devices[index_in_device_main];
}
#endif
