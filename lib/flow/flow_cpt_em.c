/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include "rte_byteorder.h"
#include "rte_cryptodev.h"
#include <endian.h>
#include <errno.h>
#include <error.h>
#include <getopt.h>
#include <locale.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

#include <fcntl.h>
#include <sys/mman.h>

#include <rte_ethdev.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_pmd_cnxk_crypto.h>
#include <rte_vfio.h>

#include "cpt_em_profile.h"
#include "dao_log.h"
#include "dao_util.h"
#include "flow_cpt_em_priv.h"
#include "flow_em_priv.h"
#include "flow_gbl_priv.h"
#include "hw/cpt.h"
#include "key.h"

struct key_config cpt_em_kcfg[] = {
	{RTE_PTYPE_L2_ETHER_VLAN, 0, 0, 0, 6},
	{(RTE_PTYPE_L3_IPV4 >> 4), 1, 12, 6, 4},
	{(RTE_PTYPE_L3_IPV4 >> 4), 1, 16, 10, 4},
	{(RTE_PTYPE_L4_UDP >> 8), 2, 0, 14, 2},
};

/* clang-format off */
struct flow_parser_tcam_kex cpt_em_kex_profile = {
	.mkex_sign = MKEX_SIGN,
	.name = "cpt-em",
	.prfl_version = FLOW_PARSER_PROFILE_VER,
	.keyx_cfg = {
			[NIX_INTF_RX] = ((uint64_t)PROFILE_TCAM_KEY_X2 << 32) |
					PARSE_NIBBLE_INTF_RX | (uint64_t)PROFILE_EXACT_NIBBLE_HIT,
			[NIX_INTF_TX] =
				((uint64_t)PROFILE_TCAM_KEY_X2 << 32) | PARSE_NIBBLE_INTF_TX,
		},
	.intf_lid_lt_ld = {
			[NIX_INTF_RX] = {
					[PROFILE_LID_LA] = {
							[PROFILE_LT_LA_ETHER] = {
									KEX_LD_CFG(0x05, 0x0, 0x1,
										   0x0, 0x5),
								},
						},
					[PROFILE_LID_LC] = {
							[PROFILE_LT_LC_IP] = {
									KEX_LD_CFG(0x07, 0xc, 0x1,
										   0x0, 0xB),
								},
						},
					[PROFILE_LID_LD] = {
							[PROFILE_LT_LD_UDP] = {
									KEX_LD_CFG(0x3, 0x0, 0x1,
										   0x0, 0x13),
								},
						},
				},

			[NIX_INTF_TX] = {
					[PROFILE_LID_LA] = {
							[PROFILE_LT_LA_IH_NIX_ETHER] = {
									KEX_LD_CFG(0x01, 0x0, 0x1,
										   0x0, 0x4),
									KEX_LD_CFG(0x05, 0x8, 0x1,
										   0x0, 0xa),
								},
							[PROFILE_LT_LA_IH_NIX_HIGIG2_ETHER] = {
									KEX_LD_CFG(0x01, 0x0, 0x1,
										   0x0, 0x4),
									KEX_LD_CFG(0x01, 0x10,
										   0x1, 0x0, 0xa),
								},
						},
					[PROFILE_LID_LB] = {
							[PROFILE_LT_LB_CTAG] = {
									KEX_LD_CFG(0x01, 0x2, 0x1,
										   0x0, 0x6),
									KEX_LD_CFG(0x01, 0x4, 0x1,
										   0x0, 0x8),
								},
							[PROFILE_LT_LB_STAG_QINQ] = {
									KEX_LD_CFG(0x01, 0x2, 0x1,
										   0x0, 0x6),
									KEX_LD_CFG(0x01, 0x8, 0x1,
										   0x0, 0x8),
								},
						},
					[PROFILE_LID_LC] = {
							[PROFILE_LT_LC_IP] = {
									KEX_LD_CFG(0x07, 0xc, 0x1,
										   0x0, 0x10),
								},
							[PROFILE_LT_LC_IP6] = {
									KEX_LD_CFG(0x07, 0x0, 0x1,
										   0x0, 0x10),
								},
						},
					[PROFILE_LID_LD] = {
							[PROFILE_LT_LD_UDP] = {
									KEX_LD_CFG(0x3, 0x0, 0x1,
										   0x0, 0x18),
								},
							[PROFILE_LT_LD_TCP] = {
									KEX_LD_CFG(0x3, 0x0, 0x1,
										   0x0, 0x18),
								},
						},
				},
		},
};

/* clang-format on */

static struct flow_parser cpt_em_parser;

#define BURST_SIZE_MAX           2048
#define CPT_RES_ALIGN            sizeof(union cpt_res_s)
#define CPT_EM_MAX_TABLE_ENTRIES (4 * 1024 * 1024)
#define MAX_KEY_LEN              64
#define KEY_LEN                  16
#define CTX_CACHE_WORDS          (896 / 8)

#define HUGEPAGE_512M_SIZE (512UL * 1024 * 1024)
#define HUGEPAGE_512M_PATH "/dev/hugepages"

static struct {
	void *addr;
	size_t size;
	char path[256];
	int allocated;
} g_512m_alloc[RTE_MAX_ETHPORTS];

static void *
alloc_from_512mb_hugepage(size_t size, int port_id)
{
	char path[256];
	size_t alloc_size;
	int num_pages, fd;
	void *addr;

	num_pages = (size + HUGEPAGE_512M_SIZE - 1) / HUGEPAGE_512M_SIZE;
	if (num_pages > 2)
		return NULL;

	alloc_size = (size_t)num_pages * HUGEPAGE_512M_SIZE;

	snprintf(path, sizeof(path), "%s/cpt_em_table_p%d_%d",
		 HUGEPAGE_512M_PATH, port_id, getpid());

	fd = open(path, O_CREAT | O_RDWR, 0600);
	if (fd < 0)
		return NULL;

	if (ftruncate(fd, alloc_size) < 0) {
		close(fd);
		unlink(path);
		return NULL;
	}

	addr = mmap(NULL, alloc_size, PROT_READ | PROT_WRITE,
		    MAP_SHARED | MAP_POPULATE, fd, 0);
	close(fd);

	if (addr == MAP_FAILED) {
		unlink(path);
		return NULL;
	}

	if (rte_extmem_register(addr, alloc_size, NULL, 0,
				HUGEPAGE_512M_SIZE) < 0) {
		munmap(addr, alloc_size);
		unlink(path);
		return NULL;
	}

	if (rte_vfio_container_dma_map(RTE_VFIO_DEFAULT_CONTAINER_FD,
				       (uint64_t)(uintptr_t)addr,
				       (uint64_t)(uintptr_t)addr,
				       alloc_size) < 0) {
		rte_extmem_unregister(addr, alloc_size);
		munmap(addr, alloc_size);
		unlink(path);
		return NULL;
	}

	memset(addr, 0, size);

	g_512m_alloc[port_id].addr = addr;
	g_512m_alloc[port_id].size = alloc_size;
	snprintf(g_512m_alloc[port_id].path, sizeof(g_512m_alloc[port_id].path),
		 "%s", path);
	g_512m_alloc[port_id].allocated = 1;

	printf("512M-HP: port %d: allocated %zu bytes (%d pages) at %p\n",
	       port_id, size, num_pages, addr);

	return addr;
}

static void
free_512mb_hugepage(int port_id)
{
	if (!g_512m_alloc[port_id].allocated)
		return;

	rte_vfio_container_dma_unmap(RTE_VFIO_DEFAULT_CONTAINER_FD,
				     (uint64_t)(uintptr_t)g_512m_alloc[port_id].addr,
				     (uint64_t)(uintptr_t)g_512m_alloc[port_id].addr,
				     g_512m_alloc[port_id].size);
	rte_extmem_unregister(g_512m_alloc[port_id].addr,
			      g_512m_alloc[port_id].size);
	munmap(g_512m_alloc[port_id].addr, g_512m_alloc[port_id].size);
	unlink(g_512m_alloc[port_id].path);
	g_512m_alloc[port_id].allocated = 0;
	g_512m_alloc[port_id].addr = NULL;
}

struct lcore_conf {
	uint8_t dev_id;
	uint8_t qp_id;
};

struct cpt_dev_info {
	struct lcore_conf lconf[RTE_MAX_LCORE];
	uint8_t nb_cryptodevs;
	uint8_t enabled_cdevs[RTE_CRYPTO_MAX_DEVS];
};

static struct cpt_dev_info ctx;

static int
key_ext_init(struct key_config key[], uint16_t nkey_fields, uint16_t key_size,
	     struct key_ext_opaque *opq)
{
	int i, j;

	memset(opq, 0, sizeof(struct key_ext_opaque));

	for (i = 0; i < nkey_fields; i++) {
		uint16_t lid = key[i].lid;
		uint16_t ltype = key[i].ltype;
		uint16_t offset_in_ltype = key[i].offset_in_ltype;
		uint16_t offset_in_key = key[i].offset_in_key;
		uint16_t size = key[i].size;

		if (key[i].offset_in_key >= key_size || key[i].size == 0)
			return -1;
		if ((key[i].offset_in_key + key[i].size) > key_size)
			return -1;

		for (j = 0; j < 2; j++) {
			if (opq->ext_info[lid][ltype][j].size == 0) {
				opq->ext_info[lid][ltype][j].offset_in_key = offset_in_key;
				opq->ext_info[lid][ltype][j].offset_in_ltype = offset_in_ltype;
				opq->ext_info[lid][ltype][j].size = size;
				break;
			}
		}
		if (j == 2)
			return -1;
	}
	return 0;
}

static bool table_uses_hugepage[RTE_MAX_ETHPORTS];


static __rte_always_inline uint32_t
bitreverse(uint32_t x)
{
	x = ((x >> 1) & 0x55555555) | ((x << 1) & 0xAAAAAAAA);
	x = ((x >> 2) & 0x33333333) | ((x << 2) & 0xCCCCCCCC);
	x = ((x >> 4) & 0x0F0F0F0F) | ((x << 4) & 0xF0F0F0F0);
	x = ((x >> 8) & 0x00FF00FF) | ((x << 8) & 0xFF00FF00);
	x = (x >> 16) | (x << 16);
	return x;
}

static __rte_always_inline uint64_t
get_hash(uint8_t *key, uint32_t key_size)
{
	uint32_t iv_upper = 0xFFFFFFFF;
	uint32_t crc, byte, temp, k;

	for (uint32_t i = 0; i < key_size; i++) {
		temp = key[i];
		byte = 0;
		for (k = 0; k < 8; k++)
			byte = (byte << 1) | ((temp >> k) & 1);
		iv_upper ^= (byte << 24);
		for (k = 0; k < 8; k++) {
			if (iv_upper >> 31)
				iv_upper = (iv_upper << 1) ^ 0x04C11DB7;
			else
				iv_upper <<= 1;
		}
	}

	iv_upper ^= 0xFFFFFFFF;
	crc = bitreverse(iv_upper);
	crc = htobe32(crc);
	return (crc & 0x3FFFFF);
}

static void *
cpt_em_table_init(uint32_t table_size, uint16_t action_size, bool enable_ctx_caching,
		  int port_id)
{
	uint32_t num_key_fields = 0, offset_in_key = 0;
	struct cpt_em_table *table = NULL;
	struct cpt_em_entry *entry = NULL;
	uint64_t memory_base = 0;
	uint16_t key_size = 0;
	size_t alloc_size;
	void *base_alloc = NULL;
	int rc = 0;

	flow_parser_init(&cpt_em_parser, &cpt_em_kex_profile);

	alloc_size = sizeof(struct cpt_em_table) +
		     (table_size * sizeof(struct cpt_em_entry)) + (table_size * 8);

	if (enable_ctx_caching)
		alloc_size += 8;

	if (port_id >= 0 && port_id < (int)RTE_MAX_ETHPORTS)
		base_alloc = alloc_from_512mb_hugepage(alloc_size, port_id);

	if (base_alloc) {
		table_uses_hugepage[port_id] = true;
	} else {
		base_alloc = rte_malloc(NULL, alloc_size, 128);
		if (!base_alloc)
			return NULL;
		memset(base_alloc, 0, alloc_size);
		if (port_id >= 0 && port_id < (int)RTE_MAX_ETHPORTS)
			table_uses_hugepage[port_id] = false;
	}

	if (enable_ctx_caching)
		table = (struct cpt_em_table *)((uint8_t *)base_alloc + 8);
	else
		table = (struct cpt_em_table *)base_alloc;

	memory_base = (uint64_t)table;
	memory_base += sizeof(struct cpt_em_table) + (table_size * sizeof(struct cpt_em_entry));
	if (memory_base & (0xfULL << 60)) {
		printf("Memory allocation failed\n");
		if (port_id >= 0 && port_id < (int)RTE_MAX_ETHPORTS && table_uses_hugepage[port_id])
			free_512mb_hugepage(port_id);
		else
			rte_free(base_alloc);
		return NULL;
	}

	table->key_fields = rte_malloc(NULL, sizeof(struct key_config_int), 0);
	if (!table->key_fields) {
		if (port_id >= 0 && port_id < (int)RTE_MAX_ETHPORTS && table_uses_hugepage[port_id])
			free_512mb_hugepage(port_id);
		else
			rte_free(base_alloc);
		return NULL;
	}

	num_key_fields = sizeof(cpt_em_kcfg) / sizeof(struct key_config);
	table->key_fields->num_fields = num_key_fields;

	for (uint32_t i = 0; i < num_key_fields; i++) {
		offset_in_key += cpt_em_kcfg[i].size;
		if (offset_in_key & 0x1) {
			offset_in_key++;
			key_size++;
		}
		table->key_fields->kinfo[i].user_key = cpt_em_kcfg[i].offset_in_key;
		table->key_fields->kinfo[i].alg_key = cpt_em_kcfg[i].offset_in_key;
		table->key_fields->kinfo[i].size = cpt_em_kcfg[i].size;
		key_size += cpt_em_kcfg[i].size;
	}

	key_size = key_size + cpt_em_kcfg[0].offset_in_key;

	rc = key_ext_init(cpt_em_kcfg, num_key_fields, key_size, &table->ext_opaque);
	if (rc < 0) {
		rte_free(table->key_fields);
		if (port_id >= 0 && port_id < (int)RTE_MAX_ETHPORTS && table_uses_hugepage[port_id])
			free_512mb_hugepage(port_id);
		else
			rte_free(base_alloc);
		return NULL;
	}
	table->tbl.table_type = TABLE_TYPE_EM;
	table->tbl.table_size = table_size;
	table->tbl.key_size = key_size;
	table->tbl.action_size = action_size;
	entry = table->entries;

	for (uint64_t i = 0; i < table_size; i++) {
		entry->prev = htobe64(i - 1);
		entry->next = htobe64(i + 1);
		entry->id = i;
		entry->index = i;
		entry++;
	}
	table->free_index = 0;
	table->entries[table_size - 1].next = CPT_EM_INVALID_INDEX;

	memset(table->ptype_len, 0, sizeof(table->ptype_len));
	table->ptype_len[0][RTE_PTYPE_L2_ETHER] = 14;
	table->ptype_len[0][RTE_PTYPE_L2_ETHER_VLAN] = 18;
	table->ptype_len[0][RTE_PTYPE_L2_ETHER_QINQ] = 20;

	table->ptype_len[1][RTE_PTYPE_L3_IPV4 >> 4] = 20;
	table->ptype_len[1][RTE_PTYPE_L3_IPV6 >> 4] = 40;

	table->ptype_len[2][RTE_PTYPE_L4_TCP >> 8] = 20;
	table->ptype_len[2][RTE_PTYPE_L4_UDP >> 8] = 8;

	table->ptype_len[3][RTE_PTYPE_TUNNEL_VXLAN >> 12] = 8;

	table->ptype_len[4][RTE_PTYPE_L2_ETHER] = 14;
	table->ptype_len[4][RTE_PTYPE_L2_ETHER_VLAN] = 18;
	table->ptype_len[4][RTE_PTYPE_L2_ETHER_QINQ] = 20;

	table->ptype_len[5][RTE_PTYPE_L3_IPV4 >> 4] = 20;
	table->ptype_len[5][RTE_PTYPE_L3_IPV6 >> 4] = 40;

	table->tbl.reserved = enable_ctx_caching;

	return table;
}

static struct cpt_em_lcore_ctx *
cpt_em_lcore_ctx_create(uint16_t port_id, unsigned int lcore_id)
{
	struct cpt_em_lcore_ctx *lctx;
	char name[64];
	int len, ret;

	lctx = rte_zmalloc(NULL, sizeof(*lctx), RTE_CACHE_LINE_SIZE);
	if (!lctx)
		return NULL;

	snprintf(name, sizeof(name), "cpt_dptr_p%u_c%u", port_id, lcore_id);
	len = sizeof(union cpt_res_s) + 128 + 8;
	lctx->mempool = rte_mempool_create(name, CPT_LKP_RING_SZ * 2, len,
					   RTE_MEMPOOL_CACHE_MAX_SIZE, 0,
					   NULL, NULL, NULL, NULL, SOCKET_ID_ANY, 0);
	if (!lctx->mempool) {
		rte_free(lctx);
		return NULL;
	}

	lctx->inst_mem = rte_malloc(NULL,
				    CPT_LKP_RING_SZ * sizeof(struct cpt_inst_s),
				    RTE_CACHE_LINE_SIZE);
	if (!lctx->inst_mem) {
		rte_mempool_free(lctx->mempool);
		rte_free(lctx);
		return NULL;
	}

	ret = rte_mempool_get_bulk(lctx->mempool, lctx->data_ptrs, CPT_LKP_RING_SZ);
	if (ret) {
		rte_free(lctx->inst_mem);
		rte_mempool_free(lctx->mempool);
		rte_free(lctx);
		return NULL;
	}

	return lctx;
}

static void
cpt_em_lcore_ctx_destroy(struct cpt_em_lcore_ctx *lctx)
{
	if (!lctx)
		return;

	rte_free(lctx->inst_mem);
	rte_mempool_free(lctx->mempool);
	rte_free(lctx);
}

static bool cpt_cryptodev_initialized;

static int
cryptodev_init(struct cpt_em_config_per_port *cpt_em_cfg)
{
	struct rte_cryptodev_qp_conf qp_conf;
	struct rte_cryptodev_info dev_info;
	struct rte_cryptodev_config config;
	unsigned int j, nb_qp, qps_reqd;
	uint8_t socket_id, nb_lcores;
	int ret, core_id;
	uint32_t dev_cnt;
	void *table;
	uint64_t i;

	nb_lcores = rte_lcore_count();

	if (cpt_cryptodev_initialized)
		goto skip_crypto_init;

	dev_cnt = rte_cryptodev_devices_get("crypto_cn10k", ctx.enabled_cdevs, RTE_CRYPTO_MAX_DEVS);
	if (dev_cnt == 0) {
		printf("No crypto devices found\n");
		return -1;
	}

	socket_id = rte_socket_id();
	qps_reqd = nb_lcores;
	core_id = 0;
	i = 0;

	do {
		uint8_t dev_id = ctx.enabled_cdevs[i];

		rte_cryptodev_info_get(dev_id, &dev_info);
		qps_reqd = RTE_MIN(dev_info.max_nb_queue_pairs, qps_reqd);
		rte_cryptodev_stop(dev_id);

		for (j = 0; j < qps_reqd; j++) {
			ctx.lconf[core_id].dev_id = dev_id;
			ctx.lconf[core_id].qp_id = j;
			core_id++;
			if (core_id == RTE_MAX_LCORE)
				break;
		}

		nb_qp = j;

		memset(&config, 0, sizeof(config));
		config.nb_queue_pairs = nb_qp;
		config.socket_id = socket_id;

		ret = rte_cryptodev_configure(dev_id, &config);
		if (ret < 0) {
			RTE_LOG(ERR, USER1, "Could not configure cryptodev - %u\n", dev_id);
			return -1;
		}

		memset(&qp_conf, 0, sizeof(qp_conf));
		qp_conf.nb_descriptors = NB_DESC;

		for (j = 0; j < nb_qp; j++) {
			ret = rte_cryptodev_queue_pair_setup(dev_id, j, &qp_conf, socket_id);
			if (ret < 0) {
				RTE_LOG(ERR, USER1,
					"Could not configure queue pair: %u - %d\n", dev_id, j);
				return -1;
			}
		}

		ret = rte_cryptodev_start(dev_id);
		if (ret < 0) {
			RTE_LOG(ERR, USER1, "Could not start cryptodev\n");
			return -1;
		}

		i++;
		qps_reqd -= j;

	} while (i < dev_cnt && core_id < RTE_MAX_LCORE);

	ctx.nb_cryptodevs = i;
	cpt_cryptodev_initialized = true;

skip_crypto_init:
	table = cpt_em_table_init(CPT_EM_MAX_TABLE_ENTRIES, 8,
				  cpt_em_cfg->dao_cpt_em_tbl.enable_ctx_cache,
				  cpt_em_cfg->dao_cpt_em_tbl.port_id);
	if (table == NULL) {
		printf("Table init failed\n");
		return 1;
	}
	printf("Table init success\n");

	cpt_em_cfg->dao_cpt_em_tbl.cpt_em_table = table;
	if (cpt_em_cfg->dao_cpt_em_tbl.enable_ctx_cache)
		cpt_em_cfg->dao_cpt_em_tbl.base_alloc = (uint8_t *)table - 8;
	else
		cpt_em_cfg->dao_cpt_em_tbl.base_alloc = table;
	cpt_em_cfg->dao_cpt_em_tbl.kf_ptr_save =
		cpt_em_cfg->dao_cpt_em_tbl.cpt_em_table->key_fields;

	memcpy(&cpt_em_cfg->dao_cpt_em_tbl.key_fields,
	       cpt_em_cfg->dao_cpt_em_tbl.cpt_em_table->key_fields,
	       sizeof(cpt_em_cfg->dao_cpt_em_tbl.key_fields));

	cpt_em_cfg->dao_cpt_em_tbl.tbl_info = cpt_em_cfg->dao_cpt_em_tbl.cpt_em_table->tbl;

	cpt_em_cfg->dao_cpt_em_tbl.tbl_val = true;

	return 0;
}

static int
cpt_em_global_config_init(uint16_t port_id, void **gcfg)
{
	struct cpt_em_global_config *cpt_em_gbl = (struct cpt_em_global_config *)*gcfg;
	struct cpt_em_config_per_port *cpt_em_cfg_prt;
	int rc = 0;

	if (!cpt_em_gbl) {
		cpt_em_gbl = rte_zmalloc("cpt_em_global_config",
					 sizeof(struct cpt_em_global_config), RTE_CACHE_LINE_SIZE);
		if (!cpt_em_gbl) {
			rc = -ENOMEM;
			DAO_ERR_GOTO(rc, fail, "Failed to allocate memory");
		}

		*gcfg = (void *)cpt_em_gbl;
	}
	/* Initialize global CPT-EM configuration */
	if (port_id >= RTE_MAX_ETHPORTS) {
		rc = -EINVAL;
		DAO_ERR_GOTO(rc, fail, "Invalid port_id %d", port_id);
	}
	cpt_em_cfg_prt = &cpt_em_gbl->cpt_em_cfg_prt[port_id];

	cpt_em_cfg_prt->dao_cpt_em_tbl.port_id = port_id;
	cpt_em_cfg_prt->dao_cpt_em_tbl.egrp = gbl_cfg->cpt_egrp;
	cpt_em_cfg_prt->dao_cpt_em_tbl.enable_ctx_cache = gbl_cfg->cpt_ctx_cache_enable;

	rc = cryptodev_init(cpt_em_cfg_prt);
	if (rc)
		goto fail;
	cpt_em_cfg_prt->dao_cpt_em_tbl.prfl_ops = gbl_cfg->flow_cfg[port_id].prfl_ops;

	return 0;
fail:
	return rc;
}

static int
cpt_em_table_delete_rule(void *table, uint64_t rule_id)
{
	struct cpt_em_entry *entry = NULL, *next_entry = NULL, *free_entry = NULL;
	struct cpt_em_table *em_table = table;
	uint64_t free_index = em_table->free_index;
	uint64_t *delete_ptr = NULL;
	uint64_t tid;

	if (rule_id == CPT_EM_INVALID_INDEX)
		return -1;

	delete_ptr = cpt_em_delete_ptr(em_table);

	entry = &em_table->entries[delete_ptr[rule_id]];
	if (!entry->valid)
		return -1;

	if (entry->direct) {
		if (entry->next != CPT_EM_INVALID_INDEX) {
			next_entry = &em_table->entries[be64toh(entry->next)];
			memcpy(entry->key, next_entry->key, CPT_EM_ENTRY_DATA_SIZE);
			memcpy(entry->action, next_entry->action, CPT_EM_ACTION_DATA_SIZE);
			entry->next = next_entry->next;
			entry->prev = CPT_EM_INVALID_INDEX;
			delete_ptr[next_entry->id] = entry->index;
			tid = entry->id;
			entry->id = next_entry->id;
			next_entry->id = tid;
			entry = next_entry;
		}
	}

	if (entry->prev != CPT_EM_INVALID_INDEX)
		em_table->entries[be64toh(entry->prev)].next = entry->next;
	if (entry->next != CPT_EM_INVALID_INDEX)
		em_table->entries[be64toh(entry->next)].prev = entry->prev;

	free_entry = &em_table->entries[free_index];
	free_entry->prev = entry->prev;
	free_entry->next = entry->next;
	entry->valid = 0;
	entry->direct = 0;
	em_table->free_index = entry->index;

	return 0;
}

static int
cpt_em_delete_rule(void *cpt_em_cfg, uint16_t port_id, uint32_t tbl_id, void *arule)
{
	struct cpt_em_global_config *cpt_em_gbl = (struct cpt_em_global_config *)cpt_em_cfg;
	struct cpt_em_config_per_port *cpt_em_port_cfg;
	struct dao_cpt_em_table *dao_cpt_em_tbl;
	struct cpt_em_rule_data *prule = (struct cpt_em_rule_data *)arule;
	int tid;

	RTE_SET_USED(tbl_id);

	cpt_em_port_cfg = &cpt_em_gbl->cpt_em_cfg_prt[port_id];
	dao_cpt_em_tbl = &cpt_em_port_cfg->dao_cpt_em_tbl;

	rte_spinlock_lock(&dao_cpt_em_tbl->ctx_lock);

	tid = dao_cpt_em_tbl->action[0].index;
	dao_cpt_em_tbl->action[0].index = prule->act_idx;

	memset(&dao_cpt_em_tbl->action[prule->act_idx], 0, sizeof(struct cpt_em_actions));
	dao_cpt_em_tbl->action[prule->act_idx].index = tid;

	dao_dbg("       After deleted - index made free %d, earlier free index was %d",
		dao_cpt_em_tbl->action[0].index, tid);
	dao_dbg("[%s]: Removed CPT-EM rule data %p rule %d", __func__, prule, prule->act_idx);

	{
		struct cpt_em_rule_data *iter, *tmp;

		DAO_TAILQ_FOREACH_SAFE(iter, &dao_cpt_em_tbl->flow_list, next, tmp) {
			if ((uintptr_t)iter == (uintptr_t)arule) {
				cpt_em_table_delete_rule(dao_cpt_em_tbl->cpt_em_table,
							 iter->rule_idx);
				TAILQ_REMOVE(&dao_cpt_em_tbl->flow_list, iter, next);
				break;
			}
		}
	}

	cpt_em_port_cfg->num_rules_per_prt--;
	rte_spinlock_unlock(&dao_cpt_em_tbl->ctx_lock);

	rte_free(arule);

	return 0;
}

static int
cpt_em_table_rule_flush(struct dao_cpt_em_table *tbl)
{
	struct cpt_em_table *em_table = tbl->cpt_em_table;
	struct cpt_em_rule_data *prule;
	void *tmp;
	int rc, tid;

	if (!tbl->tbl_val)
		return 0;

	if (!tbl->num_rules)
		return 0;

	DAO_TAILQ_FOREACH_SAFE(prule, &tbl->flow_list, next, tmp)
	{
		rc = cpt_em_table_delete_rule(em_table, prule->rule_idx);
		if (rc)
			DAO_ERR_GOTO(-rc, fail, "Failed to delete rule %p", prule);

		tid = tbl->action[0].index;
		tbl->action[0].index = prule->act_idx;

		memset(&tbl->action[prule->act_idx], 0, sizeof(struct cpt_em_actions));
		tbl->action[prule->act_idx].index = tid;

		TAILQ_REMOVE(&tbl->flow_list, prule, next);

		dao_dbg("       After deleted - index made free %d, earlier free index was %d",
			tbl->action[0].index, tid);
		dao_dbg("[%s]: Removed CPT-EM rule data %p rule %ld", __func__, prule,
			prule->rule_idx);
		rte_free(prule);
	}

	return 0;
fail:
	return errno;
}

static int
cpt_em_table_cleanup(struct dao_cpt_em_table *cpt_em_tbl)
{
	int pid = cpt_em_tbl->port_id;

	if (cpt_em_tbl->ctx_cache_active && cpt_em_tbl->cpt_em_table) {
		uint64_t *uc_ctx = (uint64_t *)cpt_em_tbl->cpt_em_table;
		uint32_t ctx_words = sizeof(struct cpt_em_table) / sizeof(uint64_t);
		uint32_t i;

		if (ctx_words > CTX_CACHE_WORDS)
			ctx_words = CTX_CACHE_WORDS;

		for (i = 0; i < ctx_words; i++)
			uc_ctx[i] = be64toh(uc_ctx[i]);
		cpt_em_tbl->ctx_cache_active = false;
	}

	if (cpt_em_table_rule_flush(cpt_em_tbl))
		DAO_ERR_GOTO(errno, fail, "Failed to flush cpt em rules list for table %d",
			     cpt_em_tbl->tbl_id);

	{
		uint32_t lc;

		for (lc = 0; lc < RTE_MAX_LCORE; lc++) {
			cpt_em_lcore_ctx_destroy(cpt_em_tbl->lcore_ctx[lc]);
			cpt_em_tbl->lcore_ctx[lc] = NULL;
		}
	}
	rte_free(cpt_em_tbl->kf_ptr_save);
	rte_free(cpt_em_tbl->action);

	if (pid >= 0 && pid < (int)RTE_MAX_ETHPORTS && table_uses_hugepage[pid])
		free_512mb_hugepage(pid);
	else if (cpt_em_tbl->base_alloc)
		rte_free(cpt_em_tbl->base_alloc);

	return 0;
fail:
	return errno;
}

static int
cpt_em_global_config_fini(uint16_t port_id, void *gcfg)
{
	struct cpt_em_global_config *cpt_em_gbl = (struct cpt_em_global_config *)gcfg;
	struct cpt_em_config_per_port *cpt_em_cfg_prt;
	int i, ret = 0;

	if (!cpt_em_gbl)
		DAO_ERR_GOTO(-EINVAL, fail, "Invalid cpt_em_gbl handle");

	cpt_em_cfg_prt = &cpt_em_gbl->cpt_em_cfg_prt[port_id];
	if (!cpt_em_cfg_prt)
		DAO_ERR_GOTO(-EINVAL, fail, "Failed to get per cpt em tables for port %d", port_id);

	if (cpt_em_table_cleanup(&cpt_em_cfg_prt->dao_cpt_em_tbl))
		DAO_ERR_GOTO(-ENOENT, fail, "Failed to cleanup cpt em tables for port %d", port_id);

	for (i = 0; i < ctx.nb_cryptodevs && i < RTE_CRYPTO_MAX_DEVS; i++) {
		rte_cryptodev_stop(ctx.enabled_cdevs[i]);
		ret = rte_cryptodev_close(ctx.enabled_cdevs[i]);
		if (ret)
			DAO_ERR_GOTO(-ENOENT, fail, "Could not close device [err: %d]\n", ret);
	}

	return 0;
fail:
	return errno;
}

static int
cpt_em_get_entry_dump(void *cfg, uint16_t port_id, uint32_t tbl_id, void *rule_data, FILE *file)
{
	struct cpt_em_global_config *cpt_em_gbl = (struct cpt_em_global_config *)cfg;
	struct cpt_em_config_per_port *cpt_em_port_cfg;
	struct dao_cpt_em_table *dao_cpt_em_tbl;
	struct cpt_em_table_info *tbl_info;
	struct cpt_em_actions em_act;
	struct cpt_em_entry *entry;
	int i;

	RTE_SET_USED(tbl_id);
	RTE_SET_USED(rule_data);
	RTE_SET_USED(file);

	memset(&em_act, 0, sizeof(em_act));

	cpt_em_port_cfg = &cpt_em_gbl->cpt_em_cfg_prt[port_id];
	dao_cpt_em_tbl = &cpt_em_port_cfg->dao_cpt_em_tbl;

	if (!dao_cpt_em_tbl)
		return -1;

	tbl_info = &dao_cpt_em_tbl->tbl_info;

	for (i = 0; i < CPT_EM_MAX_TABLE_ENTRIES; i++) {
		entry = &dao_cpt_em_tbl->cpt_em_table->entries[i];
		if (!entry->valid)
			continue;

		printf("prev = 0x%lx, next = 0x%lx, id = 0x%lx, direct = %d, valid = %d\n",
		       (entry->prev), (entry->next), (entry->id), entry->direct, entry->valid);
		printf("Key:");
		for (int j = 0; j < tbl_info->key_size; j++)
			printf("0x%02x ", entry->key[j]);
		printf("\nAction:");
		for (int j = 0; j < tbl_info->action_size; j++)
			printf("0x%02x ", entry->action[j]);
		printf("\n");
	}

	return 0;
}

#define CPT_EM_PKT_OFF_ETH   0
#define CPT_EM_PKT_OFF_IP   (14 + 4)
#define CPT_EM_PKT_OFF_UDP  (14 + 4 + 20)
#define CPT_EM_KEY_OFF_DMAC 0
#define CPT_EM_KEY_OFF_IP   6
#define CPT_EM_KEY_OFF_SPORT 14

static __rte_always_inline void
cpt_em_extract_key_from_pkt(const uint8_t *p, uint8_t *key_out)
{
	memcpy(key_out, p, 6);

	memcpy(key_out + 6, p + CPT_EM_PKT_OFF_IP + 12, 8);

	memcpy(key_out + 14, p + CPT_EM_PKT_OFF_UDP, 2);
}

static __rte_always_inline uint32_t
cpt_em_sw_lookup_at(struct cpt_em_entry *entry, const uint8_t *key,
		    uint16_t key_size, struct cpt_em_entry *entries,
		    uint32_t table_size)
{
	uint64_t idx;

	while (entry->valid) {
		if (memcmp(entry->key, key, key_size) == 0)
			return *(uint32_t *)entry->action;
		idx = entry->next;
		if (idx == CPT_EM_INVALID_INDEX)
			return 0;
		idx = rte_be_to_cpu_64(idx);
		if (idx >= table_size)
			return 0;
		entry = &entries[idx];
	}
	return 0;
}

static uint64_t
cpt_em_table_add_entry(struct dao_cpt_em_table *dao_cpt_em_tbl, uint8_t okey[], uint8_t action[])
{
	struct cpt_em_table *em_table = dao_cpt_em_tbl->cpt_em_table;
	struct cpt_em_entry *entry = NULL, *free_entry = NULL;
	struct key_config_int *key_fields;
	struct cpt_em_table_info *tbl_info = &dao_cpt_em_tbl->tbl_info;
	uint64_t hash;
	uint64_t *delete_ptr = NULL;
	uint8_t key[CPT_EM_ENTRY_DATA_SIZE] = {0};

	if (!em_table)
		return -1;

	key_fields = &dao_cpt_em_tbl->key_fields;

	delete_ptr = cpt_em_delete_ptr(em_table);
	dao_cpt_em_tbl->delete_ptr = delete_ptr;
	for (int i = 0; i < key_fields->num_fields; i++) {
		uint8_t offset_in_key = key_fields->kinfo[i].user_key;
		uint8_t offset_in_alg_key = key_fields->kinfo[i].alg_key;
		uint8_t size = key_fields->kinfo[i].size;

		memcpy(key + offset_in_alg_key, okey + offset_in_key, size);
	}

	hash = get_hash(key, em_table->tbl.key_size);
	entry = &em_table->entries[hash];

	if (!entry->valid) {
		memcpy(entry->key, key, tbl_info->key_size);
		memcpy(entry->action, action, tbl_info->action_size);
		entry->valid = 1;
		entry->direct = 1;
		if (em_table->free_index == hash)
			em_table->free_index = be64toh(entry->next);

		if (entry->prev != CPT_EM_INVALID_INDEX)
			em_table->entries[be64toh(entry->prev)].next = entry->next;
		if (entry->next != CPT_EM_INVALID_INDEX)
			em_table->entries[be64toh(entry->next)].prev = entry->prev;
		entry->prev = CPT_EM_INVALID_INDEX;
		entry->next = CPT_EM_INVALID_INDEX;
		delete_ptr[entry->id] = entry->index;
		return entry->id;
	}

	if (entry->valid && entry->direct) {
		uint64_t index = em_table->free_index;

		dao_dbg("collision, direct, index = %lu", index);
		if (index == CPT_EM_INVALID_INDEX)
			return -1;
		free_entry = &em_table->entries[index];
		memcpy(free_entry->key, key, tbl_info->key_size);
		memcpy(free_entry->action, action, tbl_info->action_size);
		free_entry->valid = 1;
		free_entry->direct = 0;
		em_table->free_index = be64toh(free_entry->next);
		if (free_entry->prev != CPT_EM_INVALID_INDEX)
			em_table->entries[be64toh(free_entry->prev)].next = free_entry->next;
		if (free_entry->next != CPT_EM_INVALID_INDEX)
			em_table->entries[be64toh(free_entry->next)].prev = free_entry->prev;
		free_entry->prev = htobe64(hash);
		free_entry->next = entry->next;
		if (entry->next != CPT_EM_INVALID_INDEX)
			em_table->entries[be64toh(entry->next)].prev = htobe64(index);
		entry->next = htobe64(index);
		delete_ptr[free_entry->id] = free_entry->index;
		return free_entry->id;
	}

	if (entry->valid && !entry->direct) {
		uint64_t index = em_table->free_index;
		uint64_t tid;

		if (index == CPT_EM_INVALID_INDEX)
			return -1;
		free_entry = &em_table->entries[index];
		em_table->free_index = be64toh(free_entry->next);

		memcpy(free_entry->key, entry->key, CPT_EM_ENTRY_DATA_SIZE);
		memcpy(free_entry->action, entry->action, CPT_EM_ACTION_DATA_SIZE);
		free_entry->valid = 1;
		free_entry->direct = 0;
		if (free_entry->prev != CPT_EM_INVALID_INDEX)
			em_table->entries[be64toh(free_entry->prev)].next = free_entry->next;
		if (free_entry->next != CPT_EM_INVALID_INDEX)
			em_table->entries[be64toh(free_entry->next)].prev = free_entry->prev;
		free_entry->prev = entry->prev;
		free_entry->next = entry->next;
		tid = free_entry->id;
		free_entry->id = entry->id;
		delete_ptr[free_entry->id] = free_entry->index;
		if (entry->prev != CPT_EM_INVALID_INDEX)
			em_table->entries[be64toh(entry->prev)].next = htobe64(index);

		memcpy(entry->key, key, tbl_info->key_size);
		memcpy(entry->action, action, tbl_info->action_size);
		entry->valid = 1;
		entry->direct = 1;
		entry->prev = CPT_EM_INVALID_INDEX;
		entry->next = CPT_EM_INVALID_INDEX;
		entry->id = tid;
		delete_ptr[entry->id] = entry->index;
		return entry->id;
	}

	return -1;
}

static int
cpt_em_populate_action(const struct rte_flow_action actions[], struct cpt_em_actions *em_act)
{
	const struct rte_flow_action_mark *act_mark;
	const struct rte_flow_action_jump *act_jmp;
	uint16_t mark = 0;

	for (; actions->type != RTE_FLOW_ACTION_TYPE_END; actions++) {
		switch (actions->type) {
		case RTE_FLOW_ACTION_TYPE_VOID:
			break;
		case RTE_FLOW_ACTION_TYPE_MARK:
			act_mark = (const struct rte_flow_action_mark *)actions->conf;
			mark = act_mark->id;
			em_act->in_use = true;
			em_act->act_map |= CPT_EM_ACTION_MARK;
			em_act->u.rx_action = (uint64_t)mark;
			break;
		case RTE_FLOW_ACTION_TYPE_COUNT:
			em_act->counter_enable = true;
			em_act->act_map |= CPT_EM_ACTION_COUNT;
			break;
		case RTE_FLOW_ACTION_TYPE_JUMP:
			act_jmp = (const struct rte_flow_action_jump *)actions->conf;
			em_act->in_use = true;
			em_act->n_tblid = act_jmp->group;
			em_act->act_map |= CPT_EM_ACTION_JUMP;
			break;
		default:
			return -1;
		}
	}

	return 0;
}

static int
cpt_em_parse_action(const struct rte_flow_action actions[], struct dao_cpt_em_table *cpt_em_tbl)
{
	uint32_t action;
	uint32_t i;

	if (cpt_em_tbl->action[0].index == (uint32_t)~0x0) {
		uint32_t new_size = cpt_em_tbl->size * 2;

		cpt_em_tbl->action =
			rte_realloc(cpt_em_tbl->action,
				    sizeof(struct cpt_em_actions) * new_size,
				    RTE_CACHE_LINE_SIZE);
		if (cpt_em_tbl->action == NULL)
			DAO_ERR_GOTO(-ENOMEM, fail, "Failed to expand action array");
		for (i = cpt_em_tbl->size; i < new_size - 1; i++)
			cpt_em_tbl->action[i].index = i + 1;
		cpt_em_tbl->action[i].index = (uint32_t)~0x0;
		cpt_em_tbl->action[0].index = cpt_em_tbl->size;
		cpt_em_tbl->size = new_size;
	}
	action = cpt_em_tbl->action[0].index;
	cpt_em_tbl->action[0].index = cpt_em_tbl->action[action].index;
	cpt_em_tbl->action[action].index = action;

	dao_dbg("       New action index %d allotted, earlier free action index was %d", action,
		cpt_em_tbl->action[0].index);
	if (cpt_em_populate_action(actions, &cpt_em_tbl->action[action]))
		DAO_ERR_GOTO(-EINVAL, fail, "Failed to populate action");

	return action;
fail:
	return errno;
}

static void
cpt_em_rule_prepare_from_pattern(struct cpt_em_rule_data *rule_data,
				 const struct rte_flow_item pattern[])
{
	uint8_t *key = (uint8_t *)rule_data->parsed_flow_data;

	memset(rule_data->parsed_flow_data, 0, sizeof(rule_data->parsed_flow_data));

	for (; pattern->type != RTE_FLOW_ITEM_TYPE_END; pattern++) {
		switch (pattern->type) {
		case RTE_FLOW_ITEM_TYPE_ETH: {
			const struct rte_flow_item_eth *eth = pattern->spec;
			if (eth)
				memcpy(key + 0, eth->hdr.dst_addr.addr_bytes, 6);
			break;
		}
		case RTE_FLOW_ITEM_TYPE_IPV4: {
			const struct rte_flow_item_ipv4 *ip = pattern->spec;
			if (ip) {
				memcpy(key + 6, &ip->hdr.src_addr, 4);
				memcpy(key + 10, &ip->hdr.dst_addr, 4);
			}
			break;
		}
		case RTE_FLOW_ITEM_TYPE_UDP: {
			const struct rte_flow_item_udp *udp = pattern->spec;
			if (udp)
				memcpy(key + 14, &udp->hdr.src_port, 2);
			break;
		}
		default:
			break;
		}
	}
}

static void *
cpt_em_rule_create(void *cpt_em_cfg, const struct rte_flow_attr *attr,
		   const struct rte_flow_item pattern[], const struct rte_flow_action actions[],
		   uint16_t port_id, uint32_t *rule_idx, struct rte_flow_error *error)
{
	struct cpt_em_global_config *cpt_em_gbl = (struct cpt_em_global_config *)cpt_em_cfg;
	struct cpt_em_config_per_port *cpt_em_port_cfg;
	struct dao_cpt_em_table *dao_cpt_em_tbl;
	struct cpt_em_rule_data *rule_data;
	struct cpt_em_actions em_act;
	struct parsed_flow *flow;
	int act_idx = 0, i;
	uint64_t rule_id = 0;

	RTE_SET_USED(error);
	RTE_SET_USED(attr);

	memset(&em_act, 0, sizeof(em_act));

	cpt_em_port_cfg = &cpt_em_gbl->cpt_em_cfg_prt[port_id];
	dao_cpt_em_tbl = &cpt_em_port_cfg->dao_cpt_em_tbl;
	dao_cpt_em_tbl->port_id = port_id;

	if (!dao_cpt_em_tbl->init_done) {
		if (!dao_cpt_em_tbl->action) {
#define CPT_EM_INIT_ACTION_SIZE 4096
			dao_cpt_em_tbl->action = rte_zmalloc("cpt_em_action",
							     sizeof(struct cpt_em_actions) *
								     CPT_EM_INIT_ACTION_SIZE,
							     RTE_CACHE_LINE_SIZE);
			if (dao_cpt_em_tbl->action == NULL)
				return NULL;

			for (i = 0; i < CPT_EM_INIT_ACTION_SIZE - 1; i++)
				dao_cpt_em_tbl->action[i].index = i + 1;
			dao_cpt_em_tbl->action[i].index = (uint32_t)~0x0;
		}

		dao_cpt_em_tbl->size = CPT_EM_INIT_ACTION_SIZE;

		/* Synchronizing EM context */
		rte_spinlock_init(&dao_cpt_em_tbl->ctx_lock);

		TAILQ_INIT(&dao_cpt_em_tbl->flow_list);
		dao_cpt_em_tbl->init_done = true;
	}

	flow = flow_parse(&gbl_cfg->flow_cfg[dao_cpt_em_tbl->port_id].parser, attr, pattern,
			  actions);
	if (flow == NULL) {
		dao_info("Flow create failed..");
		return NULL;
	}

	rule_data =
		rte_zmalloc("em_rule_data", sizeof(struct cpt_em_rule_data), RTE_CACHE_LINE_SIZE);
	if (!rule_data) {
		rte_free(flow);
		dao_info("Failed to allocate rule_data memory");
		return NULL;
	}

	cpt_em_rule_prepare_from_pattern(rule_data, pattern);
	rte_free(flow);
	flow = NULL;

	rte_spinlock_lock(&dao_cpt_em_tbl->ctx_lock);

	act_idx = cpt_em_parse_action(actions, dao_cpt_em_tbl);
	if (act_idx < 0) {
		rte_spinlock_unlock(&dao_cpt_em_tbl->ctx_lock);
		rte_free(rule_data);
		DAO_ERR_GOTO(-EINVAL, fail, "Failed to parse actions %d", act_idx);
	}

	rule_id = cpt_em_table_add_entry(dao_cpt_em_tbl, (uint8_t *)rule_data->parsed_flow_data,
					 (uint8_t *)&act_idx);

	dao_cpt_em_tbl->action[act_idx].rule_data = rule_data;
	dao_cpt_em_tbl->action[act_idx].index = act_idx;
	rule_data->rule_idx = rule_id;
	rule_data->act_idx = act_idx;
	dao_cpt_em_tbl->num_rules++;

	rte_spinlock_unlock(&dao_cpt_em_tbl->ctx_lock);

	TAILQ_INSERT_TAIL(&dao_cpt_em_tbl->flow_list, rule_data, next);
	dao_dbg("Added new CPT-EM rule data %p ", rule_data);

	cpt_em_port_cfg->num_rules_per_prt++;
	*rule_idx = rule_data->rule_idx;

	return (void *)rule_data;
fail:
	rte_free(flow);
	return NULL;
}


static __rte_cache_aligned struct rte_pmd_cnxk_crypto_qptr *cached_qptr[RTE_MAX_LCORE];

static void
cpt_em_init_templates(struct dao_cpt_em_table *tbl, struct cpt_em_lcore_ctx *lctx)
{
	const uint32_t rptr_off = sizeof(union cpt_res_s) + 128;
	struct cpt_inst_s *inst;
	union cpt_inst_w4 w4;
	union cpt_inst_w7 w7;
	uint16_t ks, as;
	uint32_t i;

	ks = tbl->tbl_info.key_size;
	as = tbl->tbl_info.action_size;

	w4.u64 = 0;
	w4.s.opcode_major = 0x7;
	w4.s.dlen = 128;
	w4.s.param2 = ((((ks + 7) >> 3) & 0xf) << 4) | (((as + 7) >> 3) & 0xf);

	w7.u64 = 0;
	w7.s.egrp = tbl->egrp;
	if (tbl->tbl_info.reserved && tbl->ctx_cache_active) {
		uint8_t *base_ptr = (uint8_t *)tbl->cpt_em_table - 8;

		w7.s.ctx_val = 1;
		w7.s.cptr = (uint64_t)base_ptr;
	} else {
		w7.s.ctx_val = 0;
		w7.s.cptr = (uint64_t)tbl->cpt_em_table;
	}

	for (i = 0; i < CPT_LKP_RING_SZ; i++) {
		inst = &lctx->inst_mem[i];

		lctx->res_ptrs[i] = RTE_PTR_ALIGN_CEIL(lctx->data_ptrs[i], CPT_RES_ALIGN);
		lctx->rptr_ptrs[i] = (uint8_t *)lctx->data_ptrs[i] + rptr_off;

		inst->w0.u64 = 0;
		inst->res_addr = (uint64_t)lctx->res_ptrs[i];
		inst->w2.u64 = 0;
		inst->w3.u64 = 0;
		inst->w3.s.qord = (tbl->ctx_cache_active) ? 1 : 0;
		inst->w4.u64 = w4.u64;
		inst->rptr = (uint64_t)lctx->rptr_ptrs[i];
		inst->w7.u64 = w7.u64;
	}

	lctx->templates_ready = true;
}

#define CPT_EM_BURST_SZ  256
#define CPT_EM_RING_MASK (CPT_LKP_RING_SZ - 1)

static int
cpt_em_lookup_process(struct dao_cpt_em_table *dao_cpt_em_tbl, struct rte_mbuf **pkts,
		      uint32_t nb_objs, uint32_t *result)
{
	struct cpt_em_lcore_ctx *lctx;
	struct cpt_inst_s *inst_mem;
	union cpt_res_s **res_ptrs;
	uint8_t **rptr_ptrs;
	struct rte_pmd_cnxk_crypto_qptr *qptr;
	uint32_t submitted, completed, pending;
	uint32_t head, tail;
	uint64_t t0, timeout;
	uint32_t polls;
	unsigned int lid;

	lid = rte_lcore_id();

	if (unlikely(!cached_qptr[lid])) {
		uint8_t dev = ctx.lconf[lid].dev_id;
		uint8_t qp = ctx.lconf[lid].qp_id;

		cached_qptr[lid] = rte_pmd_cnxk_crypto_qptr_get(dev, qp);
		if (!cached_qptr[lid]) {
			RTE_LOG(ERR, USER1, "Core %u: no QPTR for dev %u qp %u, "
				"falling back to dev 0 qp 0\n", lid, dev, qp);
			cached_qptr[lid] = rte_pmd_cnxk_crypto_qptr_get(0, 0);
			if (!cached_qptr[lid])
				return -ENODEV;
		}
	}

	lctx = dao_cpt_em_tbl->lcore_ctx[lid];
	if (unlikely(!lctx)) {
		lctx = cpt_em_lcore_ctx_create(dao_cpt_em_tbl->port_id, lid);
		if (!lctx)
			return -ENOMEM;
		dao_cpt_em_tbl->lcore_ctx[lid] = lctx;
	}
	if (unlikely(!lctx->templates_ready))
		cpt_em_init_templates(dao_cpt_em_tbl, lctx);

	qptr = cached_qptr[lid];
	inst_mem = lctx->inst_mem;
	res_ptrs = lctx->res_ptrs;
	rptr_ptrs = lctx->rptr_ptrs;

	head = 0;
	tail = 0;
	submitted = 0;
	completed = 0;

	while (completed < nb_objs) {
		while (submitted < nb_objs) {
			pending = (tail - head) & CPT_EM_RING_MASK;
			if (pending >= CPT_LKP_RING_SZ - 1)
				break;

			uint32_t avail = CPT_LKP_RING_SZ - 1 - pending;
			uint32_t remaining = nb_objs - submitted;
			uint32_t count = RTE_MIN(avail, RTE_MIN(remaining, (uint32_t)CPT_EM_BURST_SZ));
			uint32_t i;

			if (count == 0)
				break;

			uint32_t first = count;
			uint32_t tail_idx = tail & CPT_EM_RING_MASK;

			if (tail_idx + count > CPT_LKP_RING_SZ)
				first = CPT_LKP_RING_SZ - tail_idx;

			for (i = 0; i < first; i++) {
				struct rte_mbuf *m = pkts[submitted + i];

				if (i + 4 < first)
					rte_prefetch0(pkts[submitted + i + 4]);
				inst_mem[tail_idx + i].w4.s.param1 = m->packet_type;
				inst_mem[tail_idx + i].dptr =
					(uint64_t)((uint8_t *)m->buf_addr + m->data_off);
				*(uint32_t *)rptr_ptrs[tail_idx + i] = 0;
				res_ptrs[tail_idx + i]->u64[0] = CPT_COMP_NOT_DONE;
			}

			rte_pmd_cnxk_crypto_submit(qptr, &inst_mem[tail_idx], first);

			if (count > first) {
				uint32_t wrap = count - first;

				for (i = 0; i < wrap; i++) {
					struct rte_mbuf *m = pkts[submitted + first + i];

					inst_mem[i].w4.s.param1 = m->packet_type;
					inst_mem[i].dptr =
						(uint64_t)((uint8_t *)m->buf_addr + m->data_off);
					*(uint32_t *)rptr_ptrs[i] = 0;
					res_ptrs[i]->u64[0] = CPT_COMP_NOT_DONE;
				}

				rte_pmd_cnxk_crypto_submit(qptr, &inst_mem[0], wrap);
			}

			submitted += count;
			tail += count;
		}

		t0 = 0;
		timeout = 0;
		polls = 0;
		pending = (tail - head) & CPT_EM_RING_MASK;

		while (pending > 0) {
			uint32_t head_idx = head & CPT_EM_RING_MASK;
			volatile union cpt_res_s *rp = res_ptrs[head_idx];

			if (rp->cn10k.compcode == CPT_COMP_NOT_DONE) {
				if (unlikely(++polls > 10000)) {
					polls = 0;
					if (!t0) {
						t0 = rte_get_timer_cycles();
						timeout = rte_get_timer_hz();
					} else if ((rte_get_timer_cycles() - t0) > timeout) {
						printf("CPT poll timeout at pkt %u "
						       "(submitted=%u completed=%u "
						       "head=%u tail=%u)\n",
						       completed, submitted,
						       completed, head, tail);
						return -ETIMEDOUT;
					}
				}
				if (submitted < nb_objs && pending < CPT_LKP_RING_SZ - 1)
					break;
				continue;
			}

			if (likely(rp->cn10k.compcode == 1 && rp->cn10k.uc_compcode == 0))
				result[completed] = *(uint32_t *)rptr_ptrs[head_idx];
			else
				result[completed] = UINT32_MAX;

			completed++;
			head++;
			pending--;
			polls = 0;

			if (submitted < nb_objs && (completed % CPT_EM_BURST_SZ) == 0)
				break;
		}
	}

	return 0;
}

static int
cpt_em_flow_lookup(void *em_cfg, uint16_t port_id, struct rte_mbuf **objs, uint16_t nb_objs,
		   uint32_t *result, uint8_t depth)
{
	struct cpt_em_global_config *em_gbl = (struct cpt_em_global_config *)em_cfg;
	struct cpt_em_config_per_port *em;
	struct dao_cpt_em_table *tbl;
	int rc, i;

	RTE_SET_USED(depth);

	em = &em_gbl->cpt_em_cfg_prt[port_id];

	if (!em)
		return EM_RULE_TBL_INVALID;
	if (!em->num_rules_per_prt)
		return EM_RULE_EMPTY;
	if (!objs)
		return EM_RULE_OBJ_INVALID;

	tbl = &em->dao_cpt_em_tbl;

	rc = cpt_em_lookup_process(tbl, objs, nb_objs, result);
	if (rc)
		return rc;

	for (i = 0; i < nb_objs; i++) {
		struct cpt_em_actions *act;
		uint32_t r = result[i];

		if (r == UINT32_MAX || (objs[i]->ol_flags & RTE_MBUF_F_RX_FDIR_ID))
			continue;

		if (unlikely(r >= tbl->size)) {
			result[i] = UINT32_MAX;
			continue;
		}

		if (i + 4 < nb_objs) {
			uint32_t r_pf = result[i + 4];

			if (r_pf != UINT32_MAX && r_pf < tbl->size)
				rte_prefetch0(&tbl->action[r_pf]);
		}

		act = &tbl->action[r];

		if (likely(act->in_use && act->index == r)) {
			if (act->act_map & CPT_EM_ACTION_MARK) {
				objs[i]->ol_flags |= RTE_MBUF_F_RX_FDIR_ID;
				objs[i]->hash.fdir.hi = (uint64_t)act->u.rx_action & 0xFFFF;
			}
			if ((act->counter_enable) && (act->act_map & CPT_EM_ACTION_COUNT))
				__atomic_add_fetch(&act->rule_data->rule_hits,
						   1, __ATOMIC_RELAXED);
		}
	}

	return 0;
}

int
cpt_em_ctx_cache_warm(void *gcfg, uint16_t port_id)
{
	struct cpt_em_global_config *em_gbl = (struct cpt_em_global_config *)gcfg;
	struct cpt_em_config_per_port *em;
	struct dao_cpt_em_table *tbl;

	if (!em_gbl)
		return -EINVAL;

	if (port_id >= RTE_MAX_ETHPORTS) {
		dao_err("Invalid port_id %u (max %u)", port_id, RTE_MAX_ETHPORTS);
		return -EINVAL;
	}

	em = &em_gbl->cpt_em_cfg_prt[port_id];
	tbl = &em->dao_cpt_em_tbl;

	if (!tbl->enable_ctx_cache) {
		dao_info("port %u: ctx cache not enabled, skipping warm\n", port_id);
		return 0;
	}

	if (!tbl->cpt_em_table) {
		dao_warn("port %u: table not allocated\n", port_id);
		return -EINVAL;
	}

	if (!tbl->tbl_info.reserved) {
		dao_warn("port %u: table not allocated for ctx caching (no 8B header)\n",
			 port_id);
		return -EINVAL;
	}

	{
		uint8_t *base_ptr = (uint8_t *)tbl->cpt_em_table - 8;
		uint64_t *uc_ctx = (uint64_t *)tbl->cpt_em_table;
		union ctx_hdr hwctx;
		uint16_t ctx_words = sizeof(struct cpt_em_table) / sizeof(uint64_t);
		uint32_t i;

		if (ctx_words > CTX_CACHE_WORDS)
			ctx_words = CTX_CACHE_WORDS;

		for (i = 0; i < ctx_words; i++)
			uc_ctx[i] = htobe64(uc_ctx[i]);

		hwctx.u64 = 0;
		hwctx.s.ctx_hdr_size = 0;
		hwctx.s.ctx_push_size = (1 + hwctx.s.ctx_hdr_size) + ctx_words;
		hwctx.s.aop_valid = 1;
		hwctx.s.ctx_size =
			((8 * (ctx_words + (1 + hwctx.s.ctx_hdr_size)) + 127) / 128);

		memcpy(base_ptr, &hwctx, 8);

		dao_info("port %u: ctx_val=1 hwctx=0x%016lx push=%u size=%u"
			 " cptr=%p (128B aligned: %s) table=%p\n",
			 port_id, hwctx.u64,
			 hwctx.s.ctx_push_size, hwctx.s.ctx_size,
			 (void *)base_ptr,
			 ((uintptr_t)base_ptr & 127) == 0 ? "YES" : "NO",
			 (void *)tbl->cpt_em_table);
	}

	tbl->ctx_cache_active = true;

	{
		uint32_t lc;

		for (lc = 0; lc < RTE_MAX_LCORE; lc++) {
			if (tbl->lcore_ctx[lc])
				tbl->lcore_ctx[lc]->templates_ready = false;
		}
	}

	dao_info("port %u: ctx cache warmed (ctx_val=1, data in BE)\n", port_id);
	return 0;
}

static int
cpt_em_flow_flush(void *cfg, uint16_t port_id)
{
	struct cpt_em_global_config *cpt_em_gbl = (struct cpt_em_global_config *)cfg;
	struct cpt_em_config_per_port *cpt_em_port_cfg;

	cpt_em_port_cfg = &cpt_em_gbl->cpt_em_cfg_prt[port_id];

	return cpt_em_table_rule_flush(&cpt_em_port_cfg->dao_cpt_em_tbl);
}

static int
cpt_em_flow_count(void *cfg, uint16_t port_id)
{
	struct cpt_em_global_config *cpt_em_gbl = (struct cpt_em_global_config *)cfg;
	struct cpt_em_config_per_port *cpt_em_port_cfg;

	cpt_em_port_cfg = &cpt_em_gbl->cpt_em_cfg_prt[port_id];

	return cpt_em_port_cfg->num_rules_per_prt;
}

static int
cpt_em_rule_query(void *cpt_em_cfg, uint16_t port_id, uint32_t tbl_id, void *arule,
		  struct dao_flow_query_count *query)
{
	struct cpt_em_rule_data *rule_data = (struct cpt_em_rule_data *)arule;
	uint32_t hits;

	RTE_SET_USED(cpt_em_cfg);
	RTE_SET_USED(port_id);
	RTE_SET_USED(tbl_id);

	if (!rule_data || !query)
		return -EINVAL;

	hits = __atomic_load_n(&rule_data->rule_hits, __ATOMIC_RELAXED);
	query->rule_hits = hits;

	if (query->reset)
		__atomic_store_n(&rule_data->rule_hits, 0, __ATOMIC_RELAXED);

	return 0;
}

static int
cpt_em_rule_info(void *rule_data, FILE *file, bool is_hw_offloaded)
{
	struct cpt_em_rule_data *arule = (struct cpt_em_rule_data *)rule_data;

	if (!arule || !file)
		return -EINVAL;

	fprintf(file, "\tCPT-EM Rule handle: %p\n", arule);
	fprintf(file, "\tCPT-EM Rule Index: %lu\n", arule->rule_idx);
	fprintf(file, "\tCPT-EM Action Index: %u\n", arule->act_idx);
	fprintf(file, "\tCPT-EM rule hits: %u\n",
		__atomic_load_n(&arule->rule_hits, __ATOMIC_RELAXED));
	fprintf(file, "\tCPT-EM rule HW offloaded: %s\n", is_hw_offloaded ? "true" : "false");
	fprintf(file, "\n");

	return 0;
}

struct flow_fops_t cpt_em_flow_ops = {
	.init = cpt_em_global_config_init,
	.fini = cpt_em_global_config_fini,
	.create = cpt_em_rule_create,
	.destroy = cpt_em_delete_rule,
	.lookup = cpt_em_flow_lookup,
	.query = cpt_em_rule_query,
	.dump = cpt_em_get_entry_dump,
	.flush = cpt_em_flow_flush,
	.info = cpt_em_rule_info,
	.count = cpt_em_flow_count,
};
