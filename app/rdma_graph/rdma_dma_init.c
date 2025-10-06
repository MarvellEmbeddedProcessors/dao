/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <stdlib.h>

#include <dao_dma.h>
#include <dao_log.h>
#include <dao_util.h>

#include "rdma_dma_init.h"
#include "rdma_init.h"

static int16_t dev2mem_ids[32];
static int16_t mem2dev_ids[32];
static uint16_t dev2mem_idx;
static uint16_t mem2dev_idx;
static uint16_t dev2mem_cnt;
static uint16_t mem2dev_cnt;
uint8_t rdma_dma_vchans[RDMA_MAX_DEVS];

/* XXX - DAO_DMA
 * Currently facing an issue where DMA is not working and there is kernel
 * error log getting printed.
 *
 * Kernel error log:
 * vfio-pci 0000:06:00.1: VF token incorrectly provided, PF not bound to vfio-pci
 */
int
rdma_dma_init(struct rdma_main_cfg_data *rdma_main_cfg)
{
	struct rte_dma_vchan_conf dma_qconf;
	rdma_config_param_t *cfg_prm;
	struct rte_dma_info dma_info;
	struct rte_dma_conf dma_conf;
	uint32_t enabled_dev_mask;
	int16_t dma_devid = 0;
	uint16_t nb_dma_devs;
	uint16_t rdma_devid;
	uint16_t vchan = 0;
	uint8_t num_rport;
	uint32_t mask;
	int i;

	nb_dma_devs = rte_dma_count_avail();

	cfg_prm = rdma_main_cfg->cfg_prm;
	num_rport = cfg_prm->num_rport;
	if (!num_rport)
		num_rport = RDMA_MAX_DEVS; /* XXX: Shall get max rdma port from rdma lib. */

	enabled_dev_mask = cfg_prm->enabled_dev_mask;
	dao_info("Enabled dev mask: %x", enabled_dev_mask);

	dma_devid = 0;
	/* Prepare half of the worker DMA devices half as dev2mem and half as mem2dev */
	for (i = 0; i < nb_dma_devs; i += 2) {
		/* Setup Inbound dma device with one vchan per rdma device */
		dma_devid = rte_dma_next_dev(dma_devid);
		if (dma_devid == -1)
			break;

		rte_dma_info_get(dma_devid, &dma_info);
		dao_info("Setting up dmadev %s(%d)", dma_info.dev_name, dma_devid);

		memset(&dma_conf, 0, sizeof(dma_conf));
		dma_conf.nb_vchans = num_rport;

		if (rte_dma_configure(dma_devid, &dma_conf) != 0)
			DAO_ERR_GOTO(-EINVAL, fail, "Error with rte_dma_configure()\n");

		mask = enabled_dev_mask;

		for (vchan = 0; vchan < num_rport; vchan++) {
			rdma_devid = __builtin_ffsl(mask);
			if (rdma_devid == 0)
				dao_err("No RDMA device found for vchan %u", vchan);
			rdma_devid -= 1;
			rdma_dma_vchans[rdma_devid] = vchan;

			memset(&dma_qconf, 0, sizeof(dma_qconf));
			dma_qconf.direction = RTE_DMA_DIR_DEV_TO_MEM;
			dma_qconf.nb_desc = cfg_prm->dma_nb_desc ? cfg_prm->dma_nb_desc : 2048;
			dma_qconf.src_port.pcie.coreid = 0; /* TODO PEM id */
			dma_qconf.src_port.pcie.vfen = 1;
			dma_qconf.src_port.pcie.vfid = rdma_devid + 1;
			dma_qconf.src_port.port_type = RTE_DMA_PORT_PCIE;

			dao_dbg("Devid: %u, vchan: %u vfid %u", dma_devid, vchan,
				dma_qconf.src_port.pcie.vfid);
			if (rte_dma_vchan_setup(dma_devid, vchan, &dma_qconf) != 0)
				DAO_ERR_GOTO(-EINVAL, fail, "Error with inbound configuration\n");

			mask &= ~RTE_BIT64(rdma_devid);
		}

		if (rte_dma_start(dma_devid) != 0)
			DAO_ERR_GOTO(-EINVAL, fail, "Error with rte_dma_start()\n");

		dev2mem_ids[dev2mem_cnt++] = dma_devid;
		dma_devid++;

		/* Setup Outbound dma device with one vchan per rdma device */
		dma_devid = rte_dma_next_dev(dma_devid);
		if (dma_devid == -1)
			break;

		rte_dma_info_get(dma_devid, &dma_info);
		dao_info("Setting up dmadev %s(%d)", dma_info.dev_name, dma_devid);

		memset(&dma_conf, 0, sizeof(dma_conf));
		dma_conf.nb_vchans = num_rport;

		if (rte_dma_configure(dma_devid, &dma_conf) != 0)
			DAO_ERR_GOTO(-EINVAL, fail, "Error with rte_dma_configure()\n");

		mask = enabled_dev_mask;

		for (vchan = 0; vchan < num_rport; vchan++) {
			/* Get next rdma device id */
			rdma_devid = __builtin_ffsl(mask);
			if (rdma_devid == 0)
				dao_err("No rdma device found for vchan %u", vchan);
			rdma_devid -= 1;
			rdma_dma_vchans[rdma_devid] = vchan;
			memset(&dma_qconf, 0, sizeof(dma_qconf));
			dma_qconf.direction = RTE_DMA_DIR_MEM_TO_DEV;
			dma_qconf.nb_desc = cfg_prm->dma_nb_desc ? cfg_prm->dma_nb_desc : 2048;
			dma_qconf.dst_port.pcie.coreid = 0; /* TODO PEM id */
			dma_qconf.dst_port.pcie.vfen = 1;
			dma_qconf.dst_port.pcie.vfid = rdma_devid + 1;
			dma_qconf.dst_port.port_type = RTE_DMA_PORT_PCIE;

			/* Provide mempool for auto free after mem2dev */
			/* TODO: Support per port pool. */
			dma_qconf.auto_free.m2d.pool = rdma_main_cfg->eth_prm->pktmbuf_pool[1][0];
			if (dma_qconf.auto_free.m2d.pool == NULL)
				dma_qconf.auto_free.m2d.pool =
					rdma_main_cfg->eth_prm->pktmbuf_pool[0][0];
			if (rte_dma_vchan_setup(dma_devid, vchan, &dma_qconf) != 0)
				DAO_ERR_GOTO(-EINVAL, fail, "Error with outbound chan config\n");

			dao_dbg("Devid: %u, vchan: %u vfid %u", dma_devid, vchan,
				dma_qconf.dst_port.pcie.vfid);

			mask &= ~RTE_BIT64(rdma_devid);
		}
		if (rte_dma_start(dma_devid) != 0)
			DAO_ERR_GOTO(-EINVAL, fail, "Error with rte_dma_start()\n");
		mem2dev_ids[mem2dev_cnt++] = dma_devid;
		dma_devid++;
	}

	if (!dev2mem_cnt || !mem2dev_cnt)
		DAO_ERR_GOTO(-EINVAL, fail, "Not enough dma devices for workers\n");

	/* Provide DMA devices for RDMA control */
	if (dao_dma_ctrl_dev_set(dev2mem_ids[dev2mem_idx++], mem2dev_ids[mem2dev_idx++]))
		DAO_ERR_GOTO(-EINVAL, fail, "Failed to set RDMA control DMA dev\n");

	return 0;
fail:
	return errno;
}

int
rdma_dma_dev_assign(struct rdma_main_cfg_data *rdma_main_cfg, uint16_t lcore_id)
{
	struct lcore_conf *qconf = &rdma_main_cfg->lcore_prm->lcore_conf[lcore_id];

	if (dev2mem_idx >= dev2mem_cnt || mem2dev_idx >= mem2dev_cnt) {
		dao_err("Not enough DMA devices for workers\n");
		return -1;
	}
	dao_info("dev2mem_id %d lcore_id %d\n", dev2mem_idx, mem2dev_idx);

	qconf->dev2mem_id = dev2mem_ids[dev2mem_idx];
	qconf->mem2dev_id = mem2dev_ids[mem2dev_idx];

	qconf->nb_vchans = rdma_main_cfg->cfg_prm->num_rport;

	dev2mem_idx++;
	mem2dev_idx++;

	dao_info("\tlcore %u ... dev2mem=%u mem2dev=%u", lcore_id, qconf->dev2mem_id,
		 qconf->mem2dev_id);
	return 0;
}
