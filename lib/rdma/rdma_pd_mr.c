#include <stdlib.h>

#include "rdma_kernel_abi.h"
#include <dao_log.h>
#include <rdma_qp.h>

extern rcu_cb_t rcu_cb;

struct pd_entry *
pd_find_by_id(uint32_t pd_id, uint32_t port_num)
{
	struct pd_entry **pd_array = rdma_port_get_pd_array(port_num);

	if (!pd_array) {
		return NULL;
	}

	if (pd_id >= RDMA_MAX_PD) {
		return NULL;
	}

	return pd_array[pd_id];
}

int
pd_add(void *add)
{
	struct octep_rdma_pd_add_req *req = (struct octep_rdma_pd_add_req *)add;
	struct pd_entry **pd_array = NULL;
	struct pd_entry *pd = NULL;
	uint32_t pd_id = req->pd_id;

	if (pd_id >= RDMA_MAX_PD)
		return -1;

	pd_array = rdma_port_get_pd_array(req->port_num);
	if (!pd_array) {
		dao_err("pd_array not initialized");
		return -1;
	}

	if (pd_array[pd_id]) {
		dao_err("PD with id %u already exists", pd_id);
		return -1;
	}

	pd = (struct pd_entry *)rte_zmalloc("pd_entry", sizeof(struct pd_entry), 0);
	if (!pd) {
		dao_err("Failed to allocate memory for PD entry");
		return -1;
	}
	memset(pd, 0, sizeof(struct pd_entry));

	pd->pd_id = pd_id;
	pd_array[pd_id] = pd;
	dao_dbg("Added PD with id %u for port %u pd->mr_pool %p", pd_id, req->port_num,
		pd->mr_pool);
	return 0;
}

int
pd_delete(void *del)
{
	struct octep_rdma_pd_delete_req *req = (struct octep_rdma_pd_delete_req *)del;
	struct octep_rdma_mr_data *mr = NULL;
	struct pd_entry **pd_array = NULL;
	struct pd_entry *pd = NULL;

	if (req->pd_id >= RDMA_MAX_PD) {
		dao_err("Invalid PD id: %u", req->pd_id);
		return -1;
	}

	pd_array = rdma_port_get_pd_array(req->port_num);
	if (!pd_array) {
		dao_err("pd_array not initialized");
		return -1;
	}
	pd = pd_array[req->pd_id];
	if (!pd) {
		dao_err("PD with id %u not found", req->pd_id);
		return -1;
	}

	pd_array[req->pd_id] = NULL;

	rcu_cb();

	for (uint32_t i = 0; i < RDMA_MAX_MR; ++i) {
		if (pd->mr_pool[i]) {
			mr = pd->mr_pool[i];
			dao_dbg("PD DELETE with MR delete with key %u from PD %u mr %p", mr->key,
				req->pd_id, mr);
			pd->mr_pool[i] = NULL;
			rcu_cb();
			rte_free(mr);
		}
	}
	rte_free(pd);

	dao_dbg("Deleted PD with id %u for port %u", req->pd_id, req->port_num);
	return 0;
}

int
mr_reg(void *reg)
{
	struct octep_rdma_mr_register_req *req = (struct octep_rdma_mr_register_req *)reg;
	struct pd_entry **pd_array = NULL;
	struct pd_entry *pd = NULL;
	uint32_t index;
	struct octep_rdma_mr_data *new_mr = NULL;

	if (!req) {
		dao_err("Invalid request or PD array not initialized");
		return -1;
	}

	pd_array = rdma_port_get_pd_array(req->port_num);
	if (!pd_array) {
		dao_err("PD array not initialized");
		return -1;
	}

	pd = pd_array[req->pd_id];
	if (!pd) {
		dao_err("PD with id %u not found", req->pd_id);
		return -1;
	}

	index = req->mr.key >> RDMA_MR_KEY_SHIFT;
	if (index >= RDMA_MAX_MR) {
		dao_err("Invalid MR key: %u", req->mr.key);
		return -1;
	}

	if (pd->mr_pool[index]) {
		dao_err("MR with key %u already exists in PD %u", req->mr.key, req->pd_id);
		return -1;
	}

	new_mr = rte_zmalloc("mr_entry", sizeof(struct octep_rdma_mr_data), 0);
	if (!new_mr) {
		dao_err("Failed to allocate memory for MR entry");
		return -1;
	}
	*new_mr = req->mr;
	pd->mr_pool[index] = new_mr;
	dao_dbg("Registered MR with key %u in PD %u addre %lu index %u", req->mr.key, req->pd_id,
		new_mr->va, index);
	return 0;
}

int
mr_dereg(void *dreg)
{
	struct octep_rdma_mr_deregister_req *req = (struct octep_rdma_mr_deregister_req *)dreg;
	struct pd_entry **pd_array = NULL;
	struct pd_entry *pd = NULL;
	struct octep_rdma_mr_data *mr = NULL;
	uint32_t index;

	if (!req) {
		dao_err("Invalid request for MR deregistration");
		return -1;
	}

	pd_array = rdma_port_get_pd_array(req->port_num);
	if (!pd_array) {
		dao_err("PD array not initialized");
		return -1;
	}

	pd = pd_array[req->pd_id];
	if (!pd) {
		dao_err("PD with id %u not found", req->pd_id);
		return -1;
	}

	index = req->key >> RDMA_MR_KEY_SHIFT;
	if (index >= RDMA_MAX_MR) {
		dao_err("Invalid MR key: %u", req->key);
		return -1;
	}

	if (!pd->mr_pool[index]) {
		dao_err("MR with key %u not found in PD %u", req->key, req->pd_id);
		return -1;
	}

	mr = pd->mr_pool[index];
	pd->mr_pool[index] = NULL;
	rcu_cb();
	rte_free(mr);
	dao_dbg("Deregistered MR with key %u from PD %u index %u", req->key, req->pd_id, index);
	return 0;
}

void
rdma_pd_free(struct pd_entry **pd_array)
{
	if (!pd_array) {
		dao_err("PD array is NULL");
		return;
	}

	for (uint32_t i = 0; i < RDMA_MAX_PD; ++i) {
		if (pd_array[i]) {
			struct pd_entry *pd = pd_array[i];

			for (uint32_t j = 0; j < RDMA_MAX_MR; ++j) {
				if (pd->mr_pool[j]) {
					rte_free(pd->mr_pool[j]);
					pd->mr_pool[j] = NULL;
				}
			}
			rte_free(pd);
			pd_array[i] = NULL;
		}
	}
}
