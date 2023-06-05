/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#include <nodes/node_priv.h>
#include <dao_netlink.h>

const char *graph_node_patterns[] = {
	"secgw_*",
};

/* worker loop */
static inline int
secgw_worker_loop(dao_worker_t *worker, int is_main)
{
	secgw_main_t *elm = secgw_get_main();
	struct rte_graph_param *pgp = NULL;
	struct rte_graph_param graph_conf;
	secgw_worker_t *spcm = NULL;

	pgp = &graph_conf;

	/* Get per core secgw main */
	RTE_VERIFY(!dao_workers_app_data_get(worker, (void **)&spcm, NULL));

	RTE_VERIFY(spcm);

	/* set wrker/graph name */
	if (is_main)
		snprintf(spcm->worker_name, SECGW_WORKER_NAME, "%s-%d", "main",
			 worker->core_index);
	else
		snprintf(spcm->worker_name, SECGW_WORKER_NAME, "%s-%d", "secgw-wrkr",
			 worker->core_index);

	snprintf(spcm->graph_name, SECGW_GRAPH_NAME, "%s-%s", "graph", spcm->worker_name);

	/* prepare graph param for worker cores */
	if (!is_main) {
		memset(pgp, 0, sizeof(*pgp));
		pgp->node_patterns = graph_node_patterns;
		pgp->nb_node_patterns = RTE_DIM(graph_node_patterns);
		pgp->socket_id = dao_workers_numa_get(worker);
		spcm->graph_id = rte_graph_create(spcm->graph_name, pgp);
		if (spcm->graph_id == RTE_GRAPH_ID_INVALID)
			DAO_ERR_GOTO(-EINVAL, skip_worker_loop,
				     "%s: rte_graph_create() failed", spcm->graph_name);

		spcm->graph = rte_graph_lookup(spcm->graph_name);
		dao_dbg("C%d: graph %s created(%p)",
			worker->core_index, spcm->graph_name, spcm->graph);
		//rte_graph_dump(stdout, spcm->graph_id);
	}

	while (!secgw_main_exit_requested(elm)) {
		if (is_main) {
			dao_netlink_poll();
			dao_netlink_poll_complete();
		} else {
			dao_workers_barrier_check(worker);
			rte_graph_walk(spcm->graph);
		}
	}

skip_worker_loop:
	if (is_main) {
		dao_info("Lcore-%d: Main core exiting", rte_lcore_id());
		secgw_main_exit();
		dao_info("Lcore-%d: Main core exited", rte_lcore_id());
	} else {
		rte_graph_destroy(spcm->graph_id);
		dao_info("Lcore-%d: Worker loop exited: %d", rte_lcore_id(), worker->core_index);
	}
	return 0;
}

int secgw_thread_cb(void *_em)
{
	dao_worker_t *worker = NULL;

	RTE_SET_USED(_em);

	worker = dao_workers_self_worker_get();

	if (!worker) {
		dao_err("lcore-%d: dao_workers_self_worker_get() failed", rte_lcore_id());
		return -1;
	}

	if (dao_workers_is_control_worker(worker))
		secgw_worker_loop(worker, 1);
	else
		secgw_worker_loop(worker, 0);

	return 0;
}
