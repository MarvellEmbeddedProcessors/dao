/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#include "dao_dma.h"

#include <rte_malloc.h>

/* DMA device to used for worker cores */
RTE_DEFINE_PER_LCORE(struct dao_dma_vchan_info *, dao_dma_vchan_info);

struct dao_dma_vchan_info *vchan_info_p[RTE_MAX_LCORE];

static int16_t dma_ctrl_dev2mem_id = -1;
static int16_t dma_ctrl_mem2dev_id = -1;

int
dao_dma_lcore_dev2mem_set(int16_t dma_devid, uint16_t nb_vchans, uint16_t flush_thr)
{
	struct dao_dma_vchan_info *vchan_info = RTE_PER_LCORE(dao_dma_vchan_info);
	uint16_t vchan_idx, i;

	if (!rte_dma_is_valid(dma_devid)) {
		dao_err("Invalid dma device for worker cores");
		return -1;
	}

	if (!flush_thr)
		flush_thr = DAO_DMA_MAX_POINTER_THR_DFLT;

	if (flush_thr > DAO_DMA_MAX_POINTER) {
		dao_err("Unsupported flush threshold %u\n", flush_thr);
		return -1;
	}

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

	if (!flush_thr)
		flush_thr = DAO_DMA_MAX_POINTER_THR_DFLT;

	if (flush_thr > DAO_DMA_MAX_POINTER) {
		dao_err("Unsupported flush threshold %u\n", flush_thr);
		return -1;
	}

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
dao_dma_lcore_mem2dev_autofree_set(int16_t mem2dev_id, uint16_t vchan, bool enable)
{
	struct dao_dma_vchan_info *vchan_info = RTE_PER_LCORE(dao_dma_vchan_info);
	int i;

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
