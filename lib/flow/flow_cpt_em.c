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

#include <rte_ethdev.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_pmd_cnxk_crypto.h>

#include "cpt_em_profile.h"
#include "dao_util.h"
#include "flow_cpt_em_priv.h"
#include "hw/cpt.h"
#include "key.h"

struct flow_parser cpt_em_parser;

#define BURST_SIZE_MAX           2048
#define CPT_RES_ALIGN            sizeof(union cpt_res_s)
#define CPT_EM_MAX_TABLE_ENTRIES (4 * 1024 * 1024)
#define MAX_KEY_LEN              64
#define KEY_LEN                  16

uint8_t key[CPT_EM_MAX_TABLE_ENTRIES][MAX_KEY_LEN];
uint8_t action[CPT_EM_MAX_TABLE_ENTRIES][CPT_EM_ACTION_DATA_SIZE];

struct lcore_conf {
	uint8_t dev_id;
	uint8_t qp_id;
};

struct cpt_dev_info {
	struct lcore_conf lconf[RTE_MAX_LCORE];
	uint8_t nb_cryptodevs;
	uint8_t enabled_cdevs[RTE_CRYPTO_MAX_DEVS];
};

struct cpt_dev_info ctx;

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

static int
cpt_em_key_size_get(struct key_config *kcfg)
{
	uint32_t key_size = 0, offset_in_key = 0;
	uint32_t num_key_fields;

	num_key_fields = sizeof(cpt_em_kcfg) / sizeof(struct key_config);

	for (uint32_t i = 0; i < num_key_fields; i++) {
		offset_in_key += kcfg[i].size;
		if (offset_in_key & 0x1) {
			offset_in_key++;
			key_size++;
		}
		key_size += kcfg[i].size;
	}
	return key_size;
}

static void *
cpt_em_table_init(uint32_t table_size, uint16_t action_size, bool enable_ctx_caching)
{
	uint32_t num_key_fields = 0, offset_in_key = 0;
	struct cpt_em_table *table = NULL;
	struct cpt_em_entry *entry = NULL;
	uint64_t memory_base = 0;
	uint16_t key_size = 0;
	int rc = 0;

	flow_parser_init(&cpt_em_parser, &cpt_em_kex_profile);

	table = rte_malloc(NULL,
			   sizeof(struct cpt_em_table) +
				   (table_size * sizeof(struct cpt_em_entry)) + (table_size * 8),
			   0);
	if (!table)
		return NULL;

	memory_base = (uint64_t)table;
	memory_base += sizeof(struct cpt_em_table) + (table_size * sizeof(struct cpt_em_entry));
	if (memory_base & (0xfULL << 60)) {
		printf("Memory allocation failed\n");
		rte_free(table);
		return NULL;
	}

	memset(table, 0,
	       sizeof(struct cpt_em_table) + (table_size * sizeof(struct cpt_em_entry)) +
		       (table_size * 8));

	table->key_fields = rte_malloc(NULL, sizeof(struct key_config_int), 0);
	if (!table->key_fields) {
		rte_free(table);
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
	table->key_fields->num_fields = num_key_fields;

	key_size = key_size + cpt_em_kcfg[0].offset_in_key;

	rc = key_ext_init(cpt_em_kcfg, num_key_fields, key_size, &table->ext_opaque);
	if (rc < 0) {
		rte_free(table->key_fields);
		rte_free(table);
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
		entry->direct = 0;
		entry->valid = 0;
		memset(entry->key, 0, CPT_EM_ENTRY_DATA_SIZE);
		memset(entry->action, 0, CPT_EM_ACTION_DATA_SIZE);
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

	table->tbl.reserved = enable_ctx_caching;

	return table;
}

static void *
cpt_em_table_enable_ctx_caching(void *table)
{
	struct cpt_em_table *em_table = table;
	uint64_t *ctx_data = table;
	int i;

	if (!em_table->tbl.reserved)
		return ((uint8_t *)table + 8);

	em_table->w0.u64 = 0;
	em_table->w0.s.ctx_size = 7;
	em_table->w0.s.aop_valid = 1;
	em_table->w0.s.ctx_hdr_size = 0;
	em_table->w0.s.ctx_push_size = 125;

	for (i = 1; i < 125; i++)
		ctx_data[i] = rte_cpu_to_be_64(ctx_data[i]);

	return table;
}

static int
cryptodev_init(struct cpt_em_config_per_port *cpt_em_cfg)
{
	struct rte_cryptodev_qp_conf qp_conf;
	struct rte_cryptodev_info dev_info;
	struct rte_cryptodev_config config;
	unsigned int j, nb_qp, qps_reqd;
	uint8_t socket_id, nb_lcores;
	int ret, core_id, len = 0;
	uint32_t dev_cnt;
	void *table;
	uint64_t i;
	char name[64];

	nb_lcores = rte_lcore_count();

	snprintf(name, 63, "dptr_mp_%d", cpt_em_cfg->dao_cpt_em_tbl.port_id);

	len = sizeof(union cpt_res_s) + 2048;
	cpt_em_cfg->dao_cpt_em_tbl.mempool =
		rte_mempool_create(name, NB_DESC, len, RTE_MEMPOOL_CACHE_MAX_SIZE, 0, NULL, NULL,
				   NULL, NULL, SOCKET_ID_ANY, 0);
	if (cpt_em_cfg->dao_cpt_em_tbl.mempool == NULL) {
		RTE_LOG(ERR, USER1, "Could not create DPTR mempool\n");
		return -1;
	}

	cpt_em_cfg->dao_cpt_em_tbl.inst_mem =
		rte_malloc(NULL, BURST_SIZE_MAX * sizeof(struct cpt_inst_s), 0);
	if (cpt_em_cfg->dao_cpt_em_tbl.inst_mem == NULL) {
		printf("Could not allocate instruction memory\n");
		return -1;
	}

	ret = rte_mempool_get_bulk(cpt_em_cfg->dao_cpt_em_tbl.mempool,
				   cpt_em_cfg->dao_cpt_em_tbl.data_ptrs, BURST_SIZE_MAX);
	if (ret) {
		printf("Could not allocate data buffers\n");
		return -1;
	}

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
		rte_cryptodev_info_get(i, &dev_info);
		qps_reqd = RTE_MIN(dev_info.max_nb_queue_pairs, qps_reqd);
		rte_cryptodev_stop(i);

		for (j = 0; j < qps_reqd; j++) {
			ctx.lconf[core_id].dev_id = i;
			ctx.lconf[core_id].qp_id = j;
			core_id++;
			if (core_id == RTE_MAX_LCORE)
				break;
		}

		nb_qp = j;

		memset(&config, 0, sizeof(config));
		config.nb_queue_pairs = nb_qp;
		config.socket_id = socket_id;

		ret = rte_cryptodev_configure(i, &config);
		if (ret < 0) {
			RTE_LOG(ERR, USER1, "Could not configure cryptodev - %" PRIu64 "\n", i);
			return -1;
		}

		memset(&qp_conf, 0, sizeof(qp_conf));
		qp_conf.nb_descriptors = NB_DESC;

		for (j = 0; j < nb_qp; j++) {
			ret = rte_cryptodev_queue_pair_setup(i, j, &qp_conf, socket_id);
			if (ret < 0) {
				RTE_LOG(ERR, USER1,
					"Could not configure queue pair: %" PRIu64 " - %d\n", i, j);
				return -1;
			}
		}

		ret = rte_cryptodev_start(i);
		if (ret < 0) {
			RTE_LOG(ERR, USER1, "Could not start cryptodev\n");
			return -1;
		}

		i++;
		qps_reqd -= j;

	} while (i < dev_cnt && core_id < RTE_MAX_LCORE);

	ctx.nb_cryptodevs = i;

	// table = cpt_em_table_init(CPT_EM_MAX_TABLE_ENTRIES, CPT_EM_ACTION_DATA_SIZE, 1);
	table = cpt_em_table_init(CPT_EM_MAX_TABLE_ENTRIES, 8, 1);
	if (table == NULL) {
		printf("Table init failed\n");
		return 1;
	}
	printf("Table init success\n");

	cpt_em_cfg->dao_cpt_em_tbl.cpt_em_table = table;
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
		if (!cpt_em_gbl)
			DAO_ERR_GOTO(-ENOMEM, fail, "Failed to allocate memory");

		*gcfg = (void *)cpt_em_gbl;
	}
	/* Initialize global ACL configuration */
	cpt_em_cfg_prt = &cpt_em_gbl->cpt_em_cfg_prt[port_id];
	if (!cpt_em_cfg_prt)
		DAO_ERR_GOTO(-EINVAL, fail, "Failed to get per cpt em tables for port %d", port_id);

	cpt_em_cfg_prt->dao_cpt_em_tbl.port_id = port_id;

	rc = cryptodev_init(cpt_em_cfg_prt);
	if (rc)
		goto fail;
	cpt_em_cfg_prt->dao_cpt_em_tbl.prfl_ops = gbl_cfg->flow_cfg[port_id].prfl_ops;

	return 0;
fail:
	return errno;
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

	delete_ptr = (uint64_t *)((uint8_t *)table +
				  (sizeof(struct cpt_em_table) +
				   (em_table->tbl.table_size * sizeof(struct cpt_em_entry))));

	entry = &em_table->entries[delete_ptr[rule_id]];
	if (!entry->valid)
		return -1;

	if (entry->direct) {
		if (entry->next != CPT_EM_INVALID_INDEX) {
			next_entry = &em_table->entries[htobe64(entry->next)];
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
		em_table->entries[htobe64(entry->prev)].next = entry->next;
	if (entry->next != CPT_EM_INVALID_INDEX)
		em_table->entries[htobe64(entry->next)].prev = entry->prev;

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
	dao_dbg("[%s]: Removed ACL rule data %p rule %d", __func__, prule, prule->act_idx);

	/* Add rules back to context except the one to be deleted */
	TAILQ_FOREACH(prule, &dao_cpt_em_tbl->flow_list, next) {
		if ((uintptr_t)prule == (uintptr_t)arule) {
			cpt_em_table_delete_rule(dao_cpt_em_tbl->cpt_em_table, prule->rule_idx);
			TAILQ_REMOVE(&dao_cpt_em_tbl->flow_list, prule, next);
		}
	}

	cpt_em_port_cfg->num_rules_per_prt--;
	rte_spinlock_unlock(&dao_cpt_em_tbl->ctx_lock);

	rte_free(prule);

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
		dao_dbg("[%s]: Removed ACL rule data %p rule %ld", __func__, prule,
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
	if (cpt_em_table_rule_flush(cpt_em_tbl))
		DAO_ERR_GOTO(errno, fail, "Failed to flush cpt em rules list for table %d",
			     cpt_em_tbl->tbl_id);

	rte_mempool_free(cpt_em_tbl->mempool);
	rte_free(cpt_em_tbl->inst_mem);
	rte_free(cpt_em_tbl->kf_ptr_save);
	rte_free(cpt_em_tbl->action);

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
		for (int i = 0; i < tbl_info->key_size; i++)
			printf("0x%02x ", entry->key[i]);
		printf("\nAction:");
		for (int i = 0; i < tbl_info->action_size; i++)
			printf("0x%02x ", entry->action[i]);
		printf("\n");
	}

	return 0;
}

// Function to reverse the bits of a 32-bit unsigned integer
static uint32_t
bitreverse(uint32_t x)
{
	x = ((x >> 1) & 0x55555555) | ((x << 1) & 0xAAAAAAAA);
	x = ((x >> 2) & 0x33333333) | ((x << 2) & 0xCCCCCCCC);
	x = ((x >> 4) & 0x0F0F0F0F) | ((x << 4) & 0xF0F0F0F0);
	x = ((x >> 8) & 0x00FF00FF) | ((x << 8) & 0xFF00FF00);
	x = (x >> 16) | (x << 16);
	return x;
}

// Function to calculate the CRC
static void
calculate_crc(uint32_t *iv, unsigned char *ptr, uint32_t len, bool flip)
{
	uint32_t iv_upper = *iv;
	uint32_t byte, temp, k;

	for (uint32_t i = 0; i < len; i++) {
		byte = (uint32_t)*ptr;
		ptr++;
		temp = byte;

		if (flip) {
			for (k = 0; k < 8; k++)
				byte = (byte << 1) | ((temp >> k) & 1);
		}

		iv_upper = iv_upper ^ (byte << 24);

		for (k = 0; k < 8; k++) {
			if (iv_upper >> 31)
				iv_upper = (iv_upper << 1) ^ 0x04C11DB7;
			else
				iv_upper = iv_upper << 1;
		}
	}
	iv_upper = iv_upper ^ 0xFFFFFFFF;
	*iv = iv_upper;
	*(iv + 1) = bitreverse(iv_upper);
}

static uint64_t
get_hash(uint8_t *key, uint32_t key_size)
{
	uint32_t iv[2] = {0xFFFFFFFF, 0}, crc;

	calculate_crc(iv, key, key_size, true); // get 4 bytes crc
	crc = iv[1];
	crc = htobe32(crc);
	// printf("CRC32 of key = 0x%x,\n", crc);
	// return crc & (table_size-1);
	// return (crc % table_size); //if the number of entries is 4194304
	return (crc & 0x3FFFFF); // if the number of entries is 4194304
}

uint32_t count;
static uint64_t
cpt_em_table_add_entry(struct dao_cpt_em_table *dao_cpt_em_tbl, uint8_t okey[], uint8_t action[])
{
	struct cpt_em_table *em_table = dao_cpt_em_tbl->cpt_em_table;
	struct cpt_em_entry *entry = NULL, *free_entry = NULL;
	struct key_config_int *key_fields;
	struct cpt_em_table_info *tbl_info = &dao_cpt_em_tbl->tbl_info;
	uint64_t hash;
	uint64_t *delete_ptr = NULL;
	uint8_t key[CPT_EM_ENTRY_DATA_SIZE];

	if (!em_table)
		return -1;

	key_fields = &dao_cpt_em_tbl->key_fields;

	delete_ptr = (uint64_t *)((uint8_t *)em_table +
				  (sizeof(struct cpt_em_table) +
				   (em_table->tbl.table_size * sizeof(struct cpt_em_entry))));
	dao_cpt_em_tbl->delete_ptr = delete_ptr;
	for (int i = 0; i < key_fields->num_fields; i++) {
		uint8_t offset_in_key = key_fields->kinfo[i].user_key;
		uint8_t offset_in_alg_key = key_fields->kinfo[i].alg_key;
		uint8_t size = key_fields->kinfo[i].size;

		memcpy(key + offset_in_alg_key, okey + offset_in_key, size);
	}

	hash = get_hash(key, em_table->tbl.key_size); //, em_table->tbl.table_size);
	entry = &em_table->entries[hash];
	// printf("entries start:%p, count = %d hash = 0x%lx\n", em_table->entries, count++, hash);

	if (!entry->valid) {
		// printf("new location, index = 0x%lx\n", hash);
		memcpy(entry->key, key, tbl_info->key_size);
		memcpy(entry->action, action, tbl_info->action_size);
		entry->valid = 1;
		entry->direct = 1;
		if (em_table->free_index == hash)
			em_table->free_index = htobe64(entry->next);

		em_table->entries[htobe64(entry->prev)].next = entry->next;
		em_table->entries[htobe64(entry->next)].prev = entry->prev;
		entry->prev = CPT_EM_INVALID_INDEX;
		entry->next = CPT_EM_INVALID_INDEX;
		delete_ptr[entry->id] = entry->index;
		return entry->id;
	}

	if (entry->valid && entry->direct) {
		uint64_t index = em_table->free_index;

		printf("collision, direct, index = %lu\n", index);
		if (index == CPT_EM_INVALID_INDEX)
			return -1;
		free_entry = &em_table->entries[index];
		memcpy(free_entry->key, key, tbl_info->key_size);
		memcpy(free_entry->action, action, tbl_info->action_size);
		free_entry->valid = 1;
		free_entry->direct = 0;
		em_table->free_index = htobe64(free_entry->next);
		if (free_entry->prev != CPT_EM_INVALID_INDEX)
			em_table->entries[htobe64(free_entry->prev)].next = free_entry->next;
		if (free_entry->next != CPT_EM_INVALID_INDEX)
			em_table->entries[htobe64(free_entry->next)].prev = free_entry->prev;
		free_entry->prev = htobe64(hash);
		free_entry->next = entry->next;
		em_table->entries[htobe64(entry->next)].prev = htobe64(index);
		entry->next = htobe64(index);
		delete_ptr[free_entry->id] = free_entry->index;
		return free_entry->id;
	}

	if (entry->valid && !entry->direct) {
		uint64_t index = em_table->free_index;
		uint64_t tid;

		// printf("collision, non direct, index = %lu\n", index);
		if (index == CPT_EM_INVALID_INDEX)
			return -1;
		free_entry = &em_table->entries[index];
		em_table->free_index = htobe64(free_entry->next);

		memcpy(free_entry->key, entry->key, CPT_EM_ENTRY_DATA_SIZE);
		memcpy(free_entry->action, entry->action, CPT_EM_ACTION_DATA_SIZE);
		free_entry->valid = 1;
		free_entry->direct = 0;
		if (free_entry->prev != CPT_EM_INVALID_INDEX)
			em_table->entries[htobe64(free_entry->prev)].next = free_entry->next;
		if (free_entry->next != CPT_EM_INVALID_INDEX)
			em_table->entries[htobe64(free_entry->next)].prev = free_entry->prev;
		free_entry->prev = entry->prev;
		free_entry->next = entry->next;
		tid = free_entry->id;
		free_entry->id = entry->id;
		delete_ptr[free_entry->id] = free_entry->index;
		em_table->entries[htobe64(entry->prev)].next = htobe64(index);

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
			em_act->act_map |= ACL_ACTION_MARK;
			em_act->u.rx_action = (uint64_t)mark;
			break;
		case RTE_FLOW_ACTION_TYPE_COUNT:
			em_act->counter_enable = true;
			em_act->act_map |= ACL_ACTION_COUNT;
			break;
		case RTE_FLOW_ACTION_TYPE_JUMP:
			act_jmp = (const struct rte_flow_action_jump *)actions->conf;
			em_act->in_use = true;
			em_act->n_tblid = act_jmp->group;
			em_act->act_map |= ACL_ACTION_JUMP;

		case RTE_FLOW_ACTION_TYPE_END:
			break;
		default:
			return -1;
		}
	}
	/* Enabling count action for all */
	em_act->counter_enable = true;
	em_act->act_map |= ACL_ACTION_COUNT;

	return 0;
}

static int
cpt_em_parse_action(const struct rte_flow_action actions[], struct dao_cpt_em_table *cpt_em_tbl)
{
	uint32_t action;
	uint32_t i;

	/* Out of space, expand the array */
	if (cpt_em_tbl->action[0].index == (uint32_t)~0x0) {
		cpt_em_tbl->action =
			rte_realloc(cpt_em_tbl->action, cpt_em_tbl->size * 2, RTE_CACHE_LINE_SIZE);
		for (i = cpt_em_tbl->size; i < (cpt_em_tbl->size * 2) - 1; i++)
			cpt_em_tbl->action[i].index = i + 1;
		cpt_em_tbl->action[i].index = (uint32_t)~0x0;
		cpt_em_tbl->action[0].index = cpt_em_tbl->size;
		cpt_em_tbl->size = (cpt_em_tbl->size * 2);
	}
	/* Get free action index */
	action = cpt_em_tbl->action[0].index;
	/* Point free index to next free location */
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
cpt_em_rule_prepare(struct cpt_em_rule_data *rule_data, struct parsed_flow *flow)
{
	int i, offset, key_size;
	uint8_t *buf = (uint8_t *)flow->parsed_data;

	key_size = cpt_em_key_size_get(cpt_em_kcfg);
	offset = 5; // Skip parse nibbles.

	//	memset((uint8_t *)flow->parsed_data, 0, cpt_em_kcfg[0].offset_in_key);
	memmove(buf, &buf[offset], key_size);
	memset(&buf[key_size], 0, offset);

	for (i = 0; i < FLOW_PARSER_MAX_MCAM_WIDTH_DWORDS; i++) {
		rule_data->parsed_flow_data[i] = flow->parsed_data[i];
		rule_data->parsed_flow_data_mask[i] = flow->parsed_data_mask[i];
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
			/* Allocate space for action data */
			dao_cpt_em_tbl->action = rte_zmalloc("cpt_em_action",
							     sizeof(struct cpt_em_actions) *
								     CPT_EM_MAX_TABLE_ENTRIES,
							     RTE_CACHE_LINE_SIZE);
			if (dao_cpt_em_tbl->action == NULL)
				return NULL;

			/* MRU mechanism, action[0] holds next free index */
			for (i = 0; i < CPT_EM_MAX_TABLE_ENTRIES - 1; i++)
				dao_cpt_em_tbl->action[i].index = i + 1;
			dao_cpt_em_tbl->action[i].index = (uint32_t)~0x0;
		}

		dao_cpt_em_tbl->size = CPT_EM_MAX_TABLE_ENTRIES;

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
	/* Parse action */
	act_idx = cpt_em_parse_action(actions, dao_cpt_em_tbl);

	if (act_idx < 0)
		DAO_ERR_GOTO(-EINVAL, fail, "Failed to parse actions %d", act_idx);

	rule_data =
		rte_zmalloc("em_rule_data", sizeof(struct cpt_em_rule_data), RTE_CACHE_LINE_SIZE);
	if (!rule_data) {
		dao_info("Failed to allocate rule_data memory");
		return NULL;
	}

	cpt_em_rule_prepare(rule_data, flow);

	rte_spinlock_lock(&dao_cpt_em_tbl->ctx_lock);

	rule_id = cpt_em_table_add_entry(dao_cpt_em_tbl, (uint8_t *)rule_data->parsed_flow_data,
					 (uint8_t *)&act_idx);

	/* Parse action */
	dao_cpt_em_tbl->action[act_idx].rule_data = rule_data;
	dao_cpt_em_tbl->action[act_idx].index = act_idx;
	rule_data->rule_idx = rule_id;
	rule_data->act_idx = act_idx;
	dao_cpt_em_tbl->num_rules++;
	rte_spinlock_unlock(&dao_cpt_em_tbl->ctx_lock);

	TAILQ_INSERT_TAIL(&dao_cpt_em_tbl->flow_list, rule_data, next);
	dao_dbg("Added new ACL rule data %p ", rule_data);

	cpt_em_port_cfg->num_rules_per_prt++;
	*rule_idx = rule_data->rule_idx;

	return (void *)rule_data;
fail:
	return NULL;
}

static int
cpt_em_action_mark_id(uint64_t rx_action, struct rte_mbuf *mbuf)
{
	RTE_SET_USED(mbuf);

	uint16_t mark;

	if (!rx_action)
		DAO_ERR_GOTO(-EINVAL, fail, "Mark ID not received");

	//        mark = ((uint64_t)rx_action >> 40) & 0xFFFF;
	mark = (uint64_t)rx_action & 0xFFFF;

	dao_dbg("Action Mark id is %d", mark);

	mbuf->ol_flags |= RTE_MBUF_F_RX_FDIR_ID;
	mbuf->hash.fdir.hi = mark;

	return 0;
fail:
	return errno;
}

static int
cpt_em_flow_action_execute(struct cpt_em_config_per_port *em, uint32_t index, struct rte_mbuf *obj)
{
	struct cpt_em_actions *em_act = NULL;

	if (!em)
		DAO_ERR_GOTO(-EINVAL, fail, "Invalid em table");

	em_act = &em->dao_cpt_em_tbl.action[index];
	if (em_act->index != index)
		DAO_ERR_GOTO(-EINVAL, fail, "Invalid action index mismatch %d and %d",
			     em_act->index, index);

	RTE_SET_USED(obj);

	if (!em_act->in_use)
		DAO_ERR_GOTO(-EINVAL, fail, "Action %d marked unused", em_act->index);

	if (em_act->act_map & EM_ACTION_MARK)
		if (cpt_em_action_mark_id(em_act->u.rx_action, obj))
			goto fail;

	if ((em_act->counter_enable) && (em_act->act_map & EM_ACTION_COUNT))
		em_act->rule_data->rule_hits++;

	return 0;
fail:
	return errno;
}

static int
cpt_em_lookup_process(struct dao_cpt_em_table *dao_cpt_em_tbl, struct rte_mbuf **pkts,
		      uint32_t nb_objs, uint32_t *result)
{
	struct cpt_inst_s *inst, *inst_mem = dao_cpt_em_tbl->inst_mem;
	struct rte_pmd_cnxk_crypto_qptr *qptr = 0;
	union cpt_res_s res, *hw_res = 0;
	uint8_t *result_buf;
	uint32_t len;
	uint64_t i;
	const union cpt_res_s res_init = {
		.cn10k.compcode = CPT_COMP_NOT_DONE,
	};

	len = sizeof(union cpt_res_s) + 2048;

	qptr = rte_pmd_cnxk_crypto_qptr_get(0, 0);
	if (qptr == NULL) {
		printf("Could not get QPTR\n");
		return -1;
	}

	dao_cpt_em_tbl->ttable_ctx = cpt_em_table_enable_ctx_caching(dao_cpt_em_tbl->cpt_em_table);
	for (i = 0; i < nb_objs;) {
		memset(dao_cpt_em_tbl->data_ptrs[i], 0, len);
		inst = RTE_PTR_ADD(inst_mem, i * sizeof(struct cpt_inst_s));
		hw_res = RTE_PTR_ALIGN_CEIL(dao_cpt_em_tbl->data_ptrs[i], CPT_RES_ALIGN);
		memset(hw_res, 0, sizeof(union cpt_res_s));
		memset(inst, 0, sizeof(struct cpt_inst_s));
		inst->w3.s.qord = 1;
		inst->w4.s.opcode_major = 0x7;
		inst->w4.s.opcode_minor = 0;
		uint16_t ptypes = pkts[i]->packet_type;

		inst->w4.s.param1 = ptypes;
		inst->w4.s.param2 = ((16 << 8) | 8);
		uint16_t dlen = pkts[i]->pkt_len;

		if (dlen > 256)
			dlen = 256;
		inst->w4.s.dlen = dlen;
		uint8_t *dptr = (uint8_t *)pkts[i]->buf_addr + pkts[i]->data_off;

		inst->dptr = ((uintptr_t)dptr);
		result_buf = (uint8_t *)dao_cpt_em_tbl->data_ptrs[i];
		inst->rptr = (uint64_t)&result_buf[sizeof(union cpt_res_s) + 128];
		inst->w7.s.ctx_val = 1;
		inst->w7.s.egrp = ROC_CPT_DFLT_ENG_GRP_SE;
		inst->w7.s.cptr = (uint64_t)dao_cpt_em_tbl->ttable_ctx;
		inst->res_addr = (uint64_t)hw_res;
		__atomic_store_n(&hw_res->u64[0], res_init.u64[0], __ATOMIC_RELAXED);
		i++;
	}
	inst = inst_mem;
	rte_pmd_cnxk_crypto_submit(qptr, inst, i);
	do {
		hw_res = RTE_PTR_ALIGN_CEIL(dao_cpt_em_tbl->data_ptrs[i - 1], CPT_RES_ALIGN);
		res.u64[0] = __atomic_load_n(&hw_res->u64[0], __ATOMIC_RELAXED);
	} while (res.cn10k.compcode == CPT_COMP_NOT_DONE);

	for (uint64_t j = 0; j < i; j++) {
		hw_res = RTE_PTR_ALIGN_CEIL(dao_cpt_em_tbl->data_ptrs[j], CPT_RES_ALIGN);
		res.u64[0] = __atomic_load_n(&hw_res->u64[0], __ATOMIC_RELAXED);
		result_buf = (uint8_t *)dao_cpt_em_tbl->data_ptrs[j];
		if (res.cn10k.compcode != 1 || res.cn10k.uc_compcode != 0) {
			printf("compcode: 0x%x, uc_compcode = 0x%x\n", res.cn10k.compcode,
			       res.cn10k.uc_compcode);
			return -1;
		}
		// memcpy(&result[j], &result_buf[sizeof(union cpt_res_s) + 128],
		// CPT_EM_ACTION_DATA_SIZE);
		memcpy(&result[j], &result_buf[sizeof(union cpt_res_s) + 128], 4);
	}
	return 0;
}

static int
cpt_em_flow_lookup(void *em_cfg, uint16_t port_id, struct rte_mbuf **objs, uint16_t nb_objs,
		   uint32_t *result, uint8_t depth)
{
	struct cpt_em_global_config *em_gbl = (struct cpt_em_global_config *)em_cfg;
	struct cpt_em_config_per_port *em;
	int i;

	RTE_SET_USED(depth);

	em = &em_gbl->cpt_em_cfg_prt[port_id];

	if (!em)
		return EM_RULE_TBL_INVALID;
	if (!em->num_rules_per_prt)
		return EM_RULE_EMPTY;
	if (!objs)
		return EM_RULE_OBJ_INVALID;

	cpt_em_lookup_process(&em->dao_cpt_em_tbl, objs, nb_objs, result);
	for (i = 0; i < nb_objs; i++) {
		if (objs[i]->ol_flags & RTE_MBUF_F_RX_FDIR_ID)
			continue;
		if ((result[i] != UINT32_MAX) && em->num_rules_per_prt)
			cpt_em_flow_action_execute(em, result[i], objs[i]);
	}

	return 0;
}

/*
struct flow_fops_t {
...
	int (*query)(void *cfg, uint16_t port_id, uint32_t tbl_id, void *rule_data,
		     struct dao_flow_query_count *query);
	int (*flush)(void *cfg, uint16_t port_id);
	int (*info)(void *rule_data, FILE *file, bool is_hw_offloaded);
	int (*count)(void *cfg, uint16_t port_id);
};*/

struct flow_fops_t cpt_em_flow_ops = {
	.init = cpt_em_global_config_init,
	.fini = cpt_em_global_config_fini,
	.create = cpt_em_rule_create,
	.destroy = cpt_em_delete_rule,
	.lookup = cpt_em_flow_lookup,
	.dump = cpt_em_get_entry_dump,
	/*        .query = acl_rule_query,
		.flush = acl_rule_flush,
		.info = acl_rule_info,
		.count = acl_port_rule_count,*/
};
