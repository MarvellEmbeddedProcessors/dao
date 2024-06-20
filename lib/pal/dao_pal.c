/* SPDX-License-Identifier: Marvell-Proprietary
 * Copyright (c) 2024 Marvell.
 */

#include "dao_pal.h"

static uint8_t pem_devid;
static uint16_t nb_vfio_devs;
static uint16_t nb_dma_devs;
static dao_pal_lcore_dma_id_t dma_ids[DAOH_MAX_WORKERS];
static uint64_t worker_mask;

int
daoh_openlog_stream(FILE *f)
{
	return rte_openlog_stream(f);
}

enum rte_iova_mode
daoh_iova_mode(void)
{
	return rte_eal_iova_mode();
}

int
dao_pal_vfio_dma_map(uint64_t vaddr, uint64_t iova, uint64_t len)
{
	int rv = 0;

	if (len == 0) {
		dao_err("Invalid leangth %lu\n", len);
		return -1;
	}

	rv = rte_vfio_container_dma_map(RTE_VFIO_DEFAULT_CONTAINER_FD, vaddr, iova, len);
	if (rv < 0) {
		dao_err("Memory map filed for container %d, vaddr %lx, iova %lx , len %lu\n",
			RTE_VFIO_DEFAULT_CONTAINER_FD, vaddr, iova, len);
		return -1;
	}
	return 0;
}

int
dao_pal_dma_lcore_mem2dev_autofree_set(uint32_t wrk_id, bool enable)
{
	int i = 0;
	int rc = 0;

	if (wrk_id >= DAOH_MAX_WORKERS) {
		dao_err("Invalid wrk_id id %u", wrk_id);
		return -1;
	}

	for (i = 0; i < nb_vfio_devs; i++)
		rc |= dao_dma_lcore_mem2dev_autofree_set(dma_ids[wrk_id].m2d_dma_devid, i, enable);

	return rc;
}

int
dao_pal_thread_init(uint32_t wrk_id)
{
	int rc;

	rte_thread_register();

	if (wrk_id >= DAOH_MAX_WORKERS) {
		dao_err("Invalid wrk_id id %u", wrk_id);
		return -1;
	}

	rc = dao_dma_lcore_dev2mem_set(dma_ids[wrk_id].d2m_dma_devid, nb_vfio_devs, 0);

	rc |= dao_dma_lcore_mem2dev_set(dma_ids[wrk_id].m2d_dma_devid, nb_vfio_devs, 0);

	if (rc) {
		dao_err("Error in setting DMA device on wrk_id\n");
		return -1;
	}

	return 0;
}

int
dao_pal_thread_fini(uint32_t wrk_id)
{
	RTE_SET_USED(wrk_id);
	rte_thread_unregister();

	return 0;
}

int
dao_pal_dma_vchan_setup(uint32_t devid, uint16_t dma_vchan, void *pool)
{
	int16_t i = 0;
	uint64_t wrk_mask = worker_mask;
	struct rte_dma_vchan_conf dma_qconf;

	dao_dbg("[%s],devid %u, dma_vchan %u, wrk_mask %lu , pool %p\n", __func__, devid, dma_vchan,
		wrk_mask, pool);

	for (i = 0; wrk_mask; i++) {
		if (!(RTE_BIT64(i) & wrk_mask))
			continue;
		wrk_mask &= ~(RTE_BIT64(i));

		memset(&dma_qconf, 0, sizeof(dma_qconf));
		dma_qconf.direction = RTE_DMA_DIR_DEV_TO_MEM;
		dma_qconf.nb_desc = 2048;
		dma_qconf.src_port.pcie.coreid = pem_devid;
		dma_qconf.src_port.pcie.vfen = 1;
		dma_qconf.src_port.pcie.vfid = devid + 1;
		dma_qconf.src_port.port_type = RTE_DMA_PORT_PCIE;

		rte_dma_stop(dma_ids[i].d2m_dma_devid);

		if (rte_dma_vchan_setup(dma_ids[i].d2m_dma_devid, dma_vchan, &dma_qconf) != 0) {
			dao_err("Error with inbound configuration\n");
			return -1;
		}

		rte_dma_start(dma_ids[i].d2m_dma_devid);

		memset(&dma_qconf, 0, sizeof(dma_qconf));
		dma_qconf.direction = RTE_DMA_DIR_MEM_TO_DEV;
		dma_qconf.nb_desc = 2048;
		dma_qconf.dst_port.pcie.coreid = pem_devid;
		dma_qconf.dst_port.pcie.vfen = 1;
		dma_qconf.dst_port.pcie.vfid = devid + 1;
		dma_qconf.dst_port.port_type = RTE_DMA_PORT_PCIE;

		if (pool)
			dma_qconf.auto_free.m2d.pool = (struct rte_mempool *)pool;

		rte_dma_stop(dma_ids[i].m2d_dma_devid);

		if (rte_dma_vchan_setup(dma_ids[i].m2d_dma_devid, dma_vchan, &dma_qconf) != 0) {
			dao_err("Error with outbound configuration\n");
			return -1;
		}

		rte_dma_start(dma_ids[i].m2d_dma_devid);
	}

	return 0;
}

int
dao_pal_dma_dev_setup(uint64_t wrk_mask)
{
	struct rte_dma_conf dma_conf;
	int16_t dma_devid;
	int i = 0;

	dma_devid = 0;
	/* Update global data */
	worker_mask = wrk_mask;

	dao_info("Lcore DMA map...\n");
	for (i = 0; wrk_mask; i++) {
		if (!(RTE_BIT64(i) & wrk_mask))
			continue;
		wrk_mask &= ~(RTE_BIT64(i));
		/* Setup Inbound dma device with one vchan per virtio netdev */
		dma_devid = rte_dma_next_dev(dma_devid);
		if (dma_devid == -1)
			break;

		memset(&dma_conf, 0, sizeof(dma_conf));
		dma_conf.nb_vchans = nb_vfio_devs;

		if (rte_dma_configure(dma_devid, &dma_conf) != 0) {
			dao_err("Error rte_dma_configure devid %d\n", dma_devid);
			return -1;
		}

		dma_ids[i].d2m_dma_devid = dma_devid;
		dma_devid++;

		/* Setup Outbound dma device with one vchan per virtio netdev */
		dma_devid = rte_dma_next_dev(dma_devid);
		if (dma_devid == -1)
			break;

		memset(&dma_conf, 0, sizeof(dma_conf));
		dma_conf.nb_vchans = nb_vfio_devs;

		if (rte_dma_configure(dma_devid, &dma_conf) != 0) {
			dao_err("Error rte_dma_configure dma_devid %d\n", dma_devid);
			return -1;
		}

		dma_ids[i].m2d_dma_devid = dma_devid;
		dma_ids[i].wrk_id = i;

		dao_info("\tlcore %u ... dev2mem=%u mem2dev=%u\n", i, dma_ids[i].d2m_dma_devid,
			 dma_ids[i].m2d_dma_devid);
		dma_devid++;
	}

	return 0;
}

int
dao_pal_dma_ctrl_dev_set(uint32_t wrk_id)
{
	if (wrk_id >= DAOH_MAX_WORKERS) {
		dao_err("Invalid wrk_id id %u", wrk_id);
		return -1;
	}
	dao_info("[%s] dev2mem=%u mem2dev=%u\n", __func__, dma_ids[wrk_id].d2m_dma_devid,
		 dma_ids[wrk_id].m2d_dma_devid);

	if (dao_dma_ctrl_dev_set(dma_ids[wrk_id].d2m_dma_devid, dma_ids[wrk_id].m2d_dma_devid)) {
		dao_err("Failed to set virtio control DMA dev wrk_id %u\n", wrk_id);
		return -1;
	}
	return 0;
}

int
dao_pal_global_init(dao_pal_global_conf_t *conf)
{
	int rc = 0;
	int argc;
	char **argv;
	char *last_strptr;
	int i = 0, j = 0;
	struct dao_pem_dev_conf pem_dev_conf = {0};

	argc = conf->nb_dma_devs * 2 + conf->nb_misc_devices * 2 + 1;

	argv = calloc(argc, sizeof(*argv));
	if (argv == NULL)
		return -1;

	argv[j++] = strdup("dao");

	for (i = 0; i < conf->nb_dma_devs; i++) {
		argv[j++] = strdup("-a");
		argv[j++] = strdup(conf->dma_devices[i]);
	}

	nb_dma_devs = conf->nb_dma_devs;
	nb_vfio_devs = conf->nb_virtio_devs;
	pem_devid = conf->pem_devid;

	for (i = 0; i < conf->nb_misc_devices; i++) {
		argv[j++] = strdup("-a");
		argv[j++] = strdup(conf->misc_devices[i]);
	}
	last_strptr = argv[j - 1];

	/* Init EAL */
	rc = rte_eal_init(argc, argv);
	if (rc < 0) {
		dao_err("Invalid EAL parameters\n");
		goto exit;
	}

	rc = dao_pem_dev_init(conf->pem_devid, &pem_dev_conf);
	if (rc)
		dao_err("Error with pem init, rc=%d\n", rc);

exit:
	for (i = 0; i < (j - 1); i++)
		if (argv[i])
			free(argv[i]);
	free(argv);
	free(last_strptr);

	return rc;
}

void
dao_pal_global_fini(void)
{
	uint64_t wrk_mask = worker_mask;
	int16_t i = 0;
	int rc;

	for (i = 0; wrk_mask; i++) {
		if (!(RTE_BIT64(i) & wrk_mask))
			continue;
		wrk_mask &= ~(RTE_BIT64(i));

		rc = rte_dma_stop(dma_ids[i].d2m_dma_devid);
		if (rc)
			dao_err("Inbound DMA device stop failed dma_id =%d\n",
				dma_ids[i].m2d_dma_devid);

		rc = rte_dma_close(dma_ids[i].d2m_dma_devid);
		if (rc)
			dao_err("Inbound DMA device close failed dma_id =%d\n",
				dma_ids[i].d2m_dma_devid);

		rc = rte_dma_stop(dma_ids[i].m2d_dma_devid);
		if (rc)
			dao_err("Outbound DMA device stop failed dma_id =%d\n",
				dma_ids[i].m2d_dma_devid);

		rc = rte_dma_close(dma_ids[i].m2d_dma_devid);
		if (rc)
			dao_err("Outbound DMA device close failed dma_id =%d\n",
				dma_ids[i].m2d_dma_devid);
	}

	/* Close PEM */
	dao_pem_dev_fini(pem_devid);

	/* clean up the EAL */
	rte_eal_cleanup();
}
