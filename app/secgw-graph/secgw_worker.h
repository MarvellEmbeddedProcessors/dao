/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#ifndef _APP_SECGW_GRAPH_SECGW_WORKER_H_
#define _APP_SECGW_GRAPH_SECGW_WORKER_H_

#include <secgw.h>
#define SECGW_WORKER_NAME           (64)
#define SECGW_GRAPH_NAME            (SECGW_WORKER_NAME + RTE_GRAPH_NAMESIZE)

/* secgw_worker_main */
typedef struct secgw_worker {
	RTE_MARKER c0 __rte_cache_aligned;

	char worker_name[SECGW_WORKER_NAME];

	char graph_name[SECGW_GRAPH_NAME];

	char **node_patterns;

	/* return of rte_graph_create() */
	rte_graph_t graph_id;

	/* per core graph*/
	struct rte_graph *graph;
} secgw_worker_t __rte_cache_aligned;

int secgw_thread_cb(void *_em);
int secgw_app_register_ethdevs(void);
#endif
