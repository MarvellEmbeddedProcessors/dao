/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#include "dao_dma.h"

#include <rte_malloc.h>
#include <rte_mempool.h>

/* DMA device to used for worker cores */
RTE_DEFINE_PER_LCORE(struct dao_dma_vchan_info *, dao_dma_vchan_info);

struct dao_dma_vchan_info *vchan_info_p[RTE_MAX_LCORE];

static int16_t dma_ctrl_dev2mem_id = -1;
static int16_t dma_ctrl_mem2dev_id = -1;

static uint16_t
resolve_flush_thr(int16_t dma_devid, uint16_t flush_thr)
{
	struct rte_dma_info dev_info = {0};

	if (rte_dma_info_get(dma_devid, &dev_info)) {
		dao_err("Failed to get DMA device info for devid %d", dma_devid);
		return 0;
	}

	if (!dev_info.max_sges) {
		dao_err("DMA device reports max_sges 0");
		return 0;
	}

	/* Calculate default flush threshold if not specified. */
	if (!flush_thr) {
		flush_thr = RTE_MIN((dev_info.max_sges + 1) / 2, (uint16_t)DAO_DMA_MAX_POINTER);
	} else {
		if (flush_thr > DAO_DMA_MAX_POINTER) {
			dao_err("Unsupported flush threshold %u (must be 1..%u)", flush_thr,
				DAO_DMA_MAX_POINTER);
			return 0;
		}
		if (flush_thr > dev_info.max_sges) {
			dao_warn("Limiting flush_thr to device max_sges %u from requested %u",
				 dev_info.max_sges, flush_thr);
			flush_thr = dev_info.max_sges;
		}
	}

	return flush_thr;
}

int
dao_dma_lcore_dev2mem_set(int16_t dma_devid, uint16_t nb_vchans, uint16_t flush_thr)
{
	struct dao_dma_vchan_info *vchan_info = RTE_PER_LCORE(dao_dma_vchan_info);
	uint16_t vchan_idx, i;

	if (!rte_dma_is_valid(dma_devid)) {
		dao_err("Invalid dma device for worker cores");
		return -1;
	}

	flush_thr = resolve_flush_thr(dma_devid, flush_thr);
	if (!flush_thr)
		return -1;

	if (!vchan_info) {
		vchan_info = rte_zmalloc("vchan_info", sizeof(struct dao_dma_vchan_info),
					 RTE_CACHE_LINE_SIZE);
		if (!vchan_info)
			return -ENOMEM;
		RTE_PER_LCORE(dao_dma_vchan_info) = vchan_info;

		vchan_info_p[rte_lcore_id()] = vchan_info;
	}

	vchan_idx = vchan_info->nb_dev2mem;
	if (vchan_idx + nb_vchans >= DAO_DMA_MAX_VCHAN_PER_LCORE) {
		dao_err("Cannot have more than %u dma rings per lcore",
			DAO_DMA_MAX_VCHAN_PER_LCORE);
		return -1;
	}

	for (i = 0; i < nb_vchans; i++) {
		vchan_info->dev2mem[vchan_idx + i].devid = dma_devid;
		vchan_info->dev2mem[vchan_idx + i].vchan = i;
		vchan_info->dev2mem[vchan_idx + i].flush_thr = flush_thr;
	}
	vchan_info->nb_dev2mem += nb_vchans;

	dao_dbg("Lcore=%u, dev2mem_id=%d, vchans=%u, flush_thr=%d", rte_lcore_id(), dma_devid,
		nb_vchans, flush_thr);
	return 0;
}

int
dao_dma_lcore_mem2dev_set(int16_t dma_devid, uint16_t nb_vchans, uint16_t flush_thr)
{
	struct dao_dma_vchan_info *vchan_info = RTE_PER_LCORE(dao_dma_vchan_info);
	uint16_t vchan_idx, i;

	if (!rte_dma_is_valid(dma_devid)) {
		dao_err("Invalid dma device for worker cores");
		return -1;
	}

	flush_thr = resolve_flush_thr(dma_devid, flush_thr);
	if (!flush_thr)
		return -1;

	if (!vchan_info) {
		vchan_info = rte_zmalloc("vchan_info", sizeof(struct dao_dma_vchan_info),
					 RTE_CACHE_LINE_SIZE);
		if (!vchan_info)
			return -ENOMEM;
		RTE_PER_LCORE(dao_dma_vchan_info) = vchan_info;

		vchan_info_p[rte_lcore_id()] = vchan_info;
	}

	vchan_idx = vchan_info->nb_mem2dev;
	if (vchan_idx + nb_vchans >= DAO_DMA_MAX_VCHAN_PER_LCORE) {
		dao_err("Cannot have more than %u dma rings per lcore",
			DAO_DMA_MAX_VCHAN_PER_LCORE);
		return -1;
	}

	for (i = 0; i < nb_vchans; i++) {
		vchan_info->mem2dev[vchan_idx + i].devid = dma_devid;
		vchan_info->mem2dev[vchan_idx + i].vchan = i;
		vchan_info->mem2dev[vchan_idx + i].flush_thr = flush_thr;
	}
	vchan_info->nb_mem2dev += nb_vchans;

	dao_dbg("Lcore=%u, mem2dev_id=%d, vchans=%u, flush_thr=%d", rte_lcore_id(), dma_devid,
		nb_vchans, flush_thr);
	return 0;
}

int
dao_dma_lcore_mem2dev_set_ops(int16_t dma_devid, uint16_t nb_vchans, uint16_t flush_thr,
			      uint16_t nb_ops)
{
	struct dao_dma_vchan_info *vchan_info = RTE_PER_LCORE(dao_dma_vchan_info);
	struct dao_dma_vchan_state *state;
	uint16_t vchan_idx, i, j, ring_sz;
	uint32_t elem_sz, mem_sz, arr_sz, rsz;
	uintptr_t op_addr;

	if (!rte_dma_is_valid(dma_devid)) {
		dao_err("Invalid dma device for worker cores");
		return -1;
	}

	flush_thr = resolve_flush_thr(dma_devid, flush_thr);
	if (!flush_thr)
		return -1;

	if (!vchan_info) {
		vchan_info = rte_zmalloc("vchan_info", sizeof(struct dao_dma_vchan_info),
					 RTE_CACHE_LINE_SIZE);
		if (!vchan_info)
			return -ENOMEM;
		RTE_PER_LCORE(dao_dma_vchan_info) = vchan_info;

		vchan_info_p[rte_lcore_id()] = vchan_info;
	}

	vchan_idx = vchan_info->nb_mem2dev;
	if (vchan_idx + nb_vchans > DAO_DMA_MAX_VCHAN_PER_LCORE) {
		dao_err("Cannot have more than %u dma rings per lcore",
			DAO_DMA_MAX_VCHAN_PER_LCORE);
		return -1;
	}

	elem_sz =
		sizeof(struct rte_dma_op) + (sizeof(struct rte_dma_sge) * DAO_DMA_MAX_POINTER * 2);
	elem_sz = RTE_ALIGN_CEIL(elem_sz, RTE_CACHE_LINE_SIZE);

	/* Ring needs ceil(nb_ops/flush_thr) entries (each op packs flush_thr SGEs) */
	rsz = ((uint32_t)nb_ops + (uint32_t)flush_thr - 1U) / (uint32_t)flush_thr;
	if (rsz == 0U)
		rsz = 1U;
	ring_sz = (uint16_t)rte_align32pow2(rsz);

	for (i = 0; i < nb_vchans; i++) {
		state = &vchan_info->mem2dev[vchan_idx + i];
		state->devid = dma_devid;
		state->vchan = i;
		state->flush_thr = flush_thr;

		/* Allocate ops memory buffer */
		mem_sz = elem_sz * ring_sz;
		state->ops_mem = rte_zmalloc_socket("dao_dma_ops_mem", mem_sz, RTE_CACHE_LINE_SIZE,
						    rte_socket_id());
		if (!state->ops_mem) {
			dao_err("Failed to alloc dma ops mem for lcore %u", rte_lcore_id());
			goto err_free;
		}

		/* Allocate ops pointer array - 2x size to avoid wrap-around handling */
		arr_sz = sizeof(struct rte_dma_op *) * ring_sz * 2;
		state->dma_ops = rte_zmalloc_socket("dao_dma_ops_arr", arr_sz, RTE_CACHE_LINE_SIZE,
						    rte_socket_id());
		if (!state->dma_ops) {
			dao_err("Failed to alloc dma ops array for lcore %u", rte_lcore_id());
			rte_free(state->ops_mem);
			state->ops_mem = NULL;
			goto err_free;
		}

		/* Precompute all op pointers */
		op_addr = (uintptr_t)state->ops_mem;
		for (j = 0; j < ring_sz; j++) {
			state->dma_ops[j] = (struct rte_dma_op *)op_addr;
			op_addr += elem_sz;
		}
		/* Duplicate pointers for wrap-around free access */
		for (j = 0; j < ring_sz; j++)
			state->dma_ops[ring_sz + j] = state->dma_ops[j];

		state->ops_head = ring_sz; /* Start with full ring */
		state->ops_tail = 0;
		state->ops_mask = ring_sz - 1;

		dao_dbg("Lcore=%u vchan=%u mem2dev dma_ops=%p ring_sz=%u elem_sz=%u",
			rte_lcore_id(), vchan_idx + i, state->dma_ops, ring_sz, elem_sz);
	}
	vchan_info->nb_mem2dev += nb_vchans;

	dao_dbg("Lcore=%u, mem2dev_id=%d, vchans=%u, flush_thr=%d", rte_lcore_id(), dma_devid,
		nb_vchans, flush_thr);
	return 0;

err_free:
	/* Free any allocations made before the failure */
	while (i > 0) {
		i--;
		state = &vchan_info->mem2dev[vchan_idx + i];
		rte_free(state->dma_ops);
		state->dma_ops = NULL;
		rte_free(state->ops_mem);
		state->ops_mem = NULL;
	}
	return -ENOMEM;
}

int
dao_dma_lcore_mem2dev_autofree_set(int16_t mem2dev_id, uint16_t vchan, bool enable)
{
	struct dao_dma_vchan_info *vchan_info = RTE_PER_LCORE(dao_dma_vchan_info);
	int i;

	if (!vchan_info)
		return -ENOMEM;

	for (i = 0; i < vchan_info->nb_mem2dev; i++) {
		if (vchan_info->mem2dev[i].devid == mem2dev_id &&
		    vchan_info->mem2dev[i].vchan == vchan) {
			vchan_info->mem2dev[i].auto_free = enable;
			break;
		}
	}

	if (i == vchan_info->nb_mem2dev)
		return -ENOENT;
	return 0;
}

int
dao_dma_ctrl_dev_set(int16_t dev2mem_id, int16_t mem2dev_devid)
{
	dma_ctrl_dev2mem_id = dev2mem_id;
	dma_ctrl_mem2dev_id = mem2dev_devid;
	dao_dbg("dma_ctrl_dev2mem_id=%d, dma_ctrl_mem2dev_id=%d", dma_ctrl_dev2mem_id,
		dma_ctrl_mem2dev_id);
	return 0;
}

int16_t
dao_dma_ctrl_dev2mem(void)
{
	return dma_ctrl_dev2mem_id;
}

int16_t
dao_dma_ctrl_mem2dev(void)
{
	return dma_ctrl_mem2dev_id;
}

int
dao_dma_stats_get(uint16_t lcore_id, struct dao_dma_stats *stats)
{
	struct dao_dma_vchan_info *vchan_info;

	memset(stats, 0, sizeof(*stats));
	if (!dao_dma_has_stats_feature())
		return 0;

	if (lcore_id < RTE_MAX_LCORE && vchan_info_p[lcore_id]) {
		vchan_info = vchan_info_p[lcore_id];
		int i;

		stats->nb_dev2mem = vchan_info->nb_dev2mem;
		for (i = 0; i < vchan_info->nb_dev2mem; i++) {
			stats->dev2mem[i].ptrs = vchan_info->dev2mem[i].ptrs;
			stats->dev2mem[i].ops = vchan_info->dev2mem[i].ops;
			stats->dev2mem[i].dbells = vchan_info->dev2mem[i].dbells;
			stats->dev2mem[i].enq_errs = vchan_info->dev2mem[i].dma_enq_errs;
		}
		stats->nb_mem2dev = vchan_info->nb_mem2dev;
		for (i = 0; i < vchan_info->nb_mem2dev; i++) {
			stats->mem2dev[i].ptrs = vchan_info->mem2dev[i].ptrs;
			stats->mem2dev[i].ops = vchan_info->mem2dev[i].ops;
			stats->mem2dev[i].dbells = vchan_info->mem2dev[i].dbells;
			stats->mem2dev[i].enq_errs = vchan_info->mem2dev[i].dma_enq_errs;
		}
	} else {
		return -ENOENT;
	}
	return 0;
}

int
dao_dma_flush_submit(void)
{
	struct dao_dma_vchan_info *vchan_info = RTE_PER_LCORE(dao_dma_vchan_info);
	uint16_t i = 0, nb_dev2mem, nb_mem2dev;
	struct dao_dma_vchan_state *state;

	nb_dev2mem = vchan_info->nb_dev2mem;
	nb_mem2dev = vchan_info->nb_mem2dev;

	for (i = 0; i < nb_dev2mem; i++) {
		state = &vchan_info->dev2mem[i];

		dao_dma_flush(state, DAO_DMA_MAX_POINTER);

		if (likely(state->pend_ops)) {
			rte_dma_submit(state->devid, state->vchan);
			state->pend_ops = 0;
			if (dao_dma_has_stats_feature())
				state->dbells++;
		}
		dao_dma_check_meta_compl(state, 0 /* ATOMIC update */);
	}

	for (i = 0; i < nb_mem2dev; i++) {
		state = &vchan_info->mem2dev[i];
		dao_dma_flush(state, DAO_DMA_MAX_POINTER);

		if (likely(state->pend_ops)) {
			rte_dma_submit(state->devid, state->vchan);
			state->pend_ops = 0;
			if (dao_dma_has_stats_feature())
				state->dbells++;
		}
		dao_dma_check_meta_compl(state, 1 /* ATOMIC update */);
	}

	return 0;
}

int
dao_dma_flush_submit_v2(void)
{
	struct dao_dma_vchan_info *vchan_info = RTE_PER_LCORE(dao_dma_vchan_info);
	uint16_t i = 0, nb_dev2mem, nb_mem2dev;
	struct dao_dma_vchan_state *state;

	nb_dev2mem = vchan_info->nb_dev2mem;
	nb_mem2dev = vchan_info->nb_mem2dev;

	for (i = 0; i < nb_dev2mem; i++) {
		state = &vchan_info->dev2mem[i];

		dao_dma_flush(state, DAO_DMA_MAX_POINTER);

		if (likely(state->pend_ops)) {
			rte_dma_submit(state->devid, state->vchan);
			state->pend_ops = 0;
			if (dao_dma_has_stats_feature())
				state->dbells++;
		}
		dao_dma_check_meta_compl_v2(state, 0 /* ATOMIC update */);
	}

	for (i = 0; i < nb_mem2dev; i++) {
		state = &vchan_info->mem2dev[i];
		dao_dma_flush(state, DAO_DMA_MAX_POINTER);

		if (likely(state->pend_ops)) {
			rte_dma_submit(state->devid, state->vchan);
			state->pend_ops = 0;
			if (dao_dma_has_stats_feature())
				state->dbells++;
		}
		dao_dma_check_meta_compl_v2(state, 1 /* ATOMIC update */);
	}

	return 0;
}

int
dao_dma_flush_submit_ops(void)
{
	struct dao_dma_vchan_info *vchan_info = RTE_PER_LCORE(dao_dma_vchan_info);
	uint16_t i = 0, nb_dev2mem, nb_mem2dev;
	struct dao_dma_vchan_state *state;

	nb_dev2mem = vchan_info->nb_dev2mem;
	nb_mem2dev = vchan_info->nb_mem2dev;

	if (nb_dev2mem)
		rte_prefetch0(&vchan_info->dev2mem[0]);
	if (nb_mem2dev)
		rte_prefetch0(&vchan_info->mem2dev[0]);

	for (i = 0; i < nb_dev2mem; i++) {
		state = &vchan_info->dev2mem[i];

		dao_dma_flush(state, DAO_DMA_MAX_POINTER);

		if (likely(state->pend_ops)) {
			rte_dma_submit(state->devid, state->vchan);
			state->pend_ops = 0;
			if (dao_dma_has_stats_feature())
				state->dbells++;
		}
		dao_dma_check_meta_compl(state, 0 /* ATOMIC update */);
	}

	for (i = 0; i < nb_mem2dev; i++) {
		state = &vchan_info->mem2dev[i];
		if (i + 1 < nb_mem2dev)
			rte_prefetch0(&vchan_info->mem2dev[i + 1]);
		dao_dma_check_meta_compl_ops(state, 1 /* ATOMIC update */);
	}

	return 0;
}

void
dao_dma_compl_wait(uint16_t vchan)
{
	struct dao_dma_vchan_state *dev2mem, *mem2dev;
	struct dao_dma_vchan_info *vchan_info;
	uint32_t lcore_id;

	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		if (rte_lcore_is_enabled(lcore_id) == 0 || lcore_id == rte_get_main_lcore())
			continue;

		vchan_info = vchan_info_p[lcore_id];
		if (!vchan_info)
			continue;
		/* All queues use same vchan */
		dev2mem = &vchan_info->dev2mem[vchan];
		mem2dev = &vchan_info->mem2dev[vchan];
		while (dev2mem->head != dev2mem->tail)
			dao_dma_check_compl(dev2mem);

		while (mem2dev->head != mem2dev->tail)
			dao_dma_check_compl(mem2dev);
	}
	rte_io_wmb();
}

void
dao_dma_compl_wait_ops(uint16_t vchan)
{
	struct dao_dma_vchan_state *dev2mem, *mem2dev;
	struct dao_dma_vchan_info *vchan_info;
	uint32_t lcore_id;

	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		if (rte_lcore_is_enabled(lcore_id) == 0 || lcore_id == rte_get_main_lcore())
			continue;

		vchan_info = vchan_info_p[lcore_id];
		if (!vchan_info)
			continue;
		/* All queues use same vchan */
		dev2mem = &vchan_info->dev2mem[vchan];
		mem2dev = &vchan_info->mem2dev[vchan];
		while (dev2mem->head != dev2mem->tail)
			dao_dma_check_meta_compl_ops(dev2mem, 1);

		while (mem2dev->head != mem2dev->tail)
			dao_dma_check_meta_compl_ops(mem2dev, 1);
	}
	rte_io_wmb();
}

void
dao_dma_compl_wait_sp(uint16_t vchan)
{
	struct dao_dma_vchan_state *dev2mem, *mem2dev;
	struct dao_dma_vchan_info *vchan_info;
	uint32_t self = rte_lcore_id();
	uint32_t lcore_id;

	/* Drain the calling lcore's own inflight ops first (safe — we own it).
	 * Skip when called from a non-EAL thread (e.g. ctrl_reg_poll) where
	 * rte_lcore_id() returns LCORE_ID_ANY.
	 */
	if (self != LCORE_ID_ANY) {
		vchan_info = vchan_info_p[self];
		if (vchan_info) {
			dev2mem = &vchan_info->dev2mem[vchan];
			mem2dev = &vchan_info->mem2dev[vchan];
			while (dev2mem->head != dev2mem->tail) {
				if (dev2mem->dma_ops)
					dao_dma_check_meta_compl_ops(dev2mem, 1);
				else
					dao_dma_check_compl(dev2mem);
			}
			while (mem2dev->head != mem2dev->tail) {
				if (mem2dev->dma_ops)
					dao_dma_check_meta_compl_ops(mem2dev, 1);
				else
					dao_dma_check_compl(mem2dev);
			}
		}
	}

	/* Spin-wait on other lcores (they drain their own completions) */
	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		if (rte_lcore_is_enabled(lcore_id) == 0 || lcore_id == rte_get_main_lcore() ||
		    lcore_id == self)
			continue;

		vchan_info = vchan_info_p[lcore_id];
		if (!vchan_info)
			continue;
		/* All queues use same vchan */
		dev2mem = &vchan_info->dev2mem[vchan];
		mem2dev = &vchan_info->mem2dev[vchan];

		while (__atomic_load_n(&dev2mem->head, __ATOMIC_ACQUIRE) !=
		       __atomic_load_n(&dev2mem->tail, __ATOMIC_ACQUIRE))
			rte_delay_us(1);

		while (__atomic_load_n(&mem2dev->head, __ATOMIC_ACQUIRE) !=
		       __atomic_load_n(&mem2dev->tail, __ATOMIC_ACQUIRE))
			rte_delay_us(1);
	}
	rte_io_wmb();
}
