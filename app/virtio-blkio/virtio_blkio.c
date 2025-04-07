/* SPDX-License-Identifier: Marvell-Proprietary
 * Copyright (c) 2025 Marvell.
 */

#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <sys/types.h>
#include <unistd.h>

#include <rte_branch_prediction.h>
#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_dmadev.h>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_mempool.h>
#include <rte_per_lcore.h>
#include <rte_rcu_qsbr.h>
#include <rte_string_fns.h>

#include <cmdline_parse.h>
#include <dao_blk_dev.h>
#include <dao_dma.h>
#include <dao_virtio_blkdev.h>

#include "virtio_blkio.h"

static bool
is_virtio_dev_enabled(uint16_t virtio_devid)
{
	uint64_t i = virtio_devid / 64;
	uint64_t j = virtio_devid % 64;

	if (i > 1)
		return false;
	return virtio_mask_ena[i] & RTE_BIT64(j);
}

/* Check that lcore bit mask configured for each enabled virtio dev is valid */
static int
check_lcore_params(void)
{
	uint8_t lcore;
	uint16_t i;

	for (i = 0; i < DAO_VIRTIO_DEV_MAX; ++i) {
		if (!is_virtio_dev_enabled(i))
			continue;

		for (lcore = 0; lcore < RTE_MAX_LCORE; lcore++) {
			if (!(RTE_BIT64(lcore) & blkdev_conf[i].lcore_mask))
				continue;

			if (!rte_lcore_is_enabled(lcore)) {
				APP_ERR("Error: lcore %hhu is not enabled in lcore mask\n", lcore);
				return -1;
			}

			if (lcore == rte_get_main_lcore()) {
				APP_ERR("Error: lcore %u is main lcore\n", lcore);
				return -1;
			}
		}
	}
	return 0;
}

static int
check_virtio_config(void)
{
	uint16_t nb_lcores = 0, nb_dma_devs;
	uint16_t lcore;

	nb_dma_devs = rte_dma_count_avail();

	/* Check if we have enough DMA devices one per lcore */
	for (lcore = 0; lcore < RTE_MAX_LCORE; lcore++)
		if (lcore_conf[lcore].nb_blkdev)
			nb_lcores++;

	/* Service lcore */
	nb_lcores += 1;

	/* 2 dma devices for control */
	wrkr_dma_devs = 2 + (nb_lcores * 2);
	if (nb_dma_devs < wrkr_dma_devs) {
		APP_INFO("%u DMA devices not enough, need at least %u for %u lcores,"
			 " 1 ctrl thread, 1 service core\n",
			 nb_dma_devs, wrkr_dma_devs, nb_lcores - 1);
		return -1;
	}

	return 0;
}

static int
init_lcore_virtio_dev(void)
{
	uint16_t virtio_devid, nb_blkdev;
	uint8_t lcore;

	for (virtio_devid = 0; virtio_devid < DAO_VIRTIO_DEV_MAX; ++virtio_devid) {
		if (!is_virtio_dev_enabled(virtio_devid))
			continue;

		for (lcore = 0; lcore < RTE_MAX_LCORE; lcore++) {
			if (!(RTE_BIT64(lcore) & blkdev_conf[virtio_devid].lcore_mask))
				continue;

			nb_blkdev = lcore_conf[lcore].nb_blkdev;

			lcore_conf[lcore].blkdev_ctx[nb_blkdev].devid = virtio_devid;
			lcore_conf[lcore].nb_blkdev++;
		}
	}

	/* Initialize lcore list */
	for (lcore = 0; lcore < RTE_MAX_LCORE; lcore++)
		lcore_list_wt_sorted[lcore] = lcore;

	return 0;
}

static int
lcore_wt_cmp(const void *a, const void *b)
{
	uint16_t lcore_a = *(const uint16_t *)a;
	uint16_t lcore_b = *(const uint16_t *)b;

	if (lcore_conf[lcore_a].weight < lcore_conf[lcore_b].weight)
		return -1;

	if (lcore_conf[lcore_a].weight == lcore_conf[lcore_b].weight)
		return 0;

	return 1;
}

static void
dump_lcore_info(void)
{
	struct blkdev_ctx *blkdev_ctx;
	struct lcore_conf *qconf;
	uint32_t lcore_id;
	uint16_t i, q_id;
	uint64_t map;

	APP_INFO("\n");
	APP_INFO("Lcore info...\n");
	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		if (rte_lcore_is_enabled(lcore_id) == 0 || lcore_id == rte_get_main_lcore())
			continue;

		qconf = &lcore_conf[lcore_id];
		if (!qconf->nb_blkdev && !qconf->service_lcore)
			continue;

		if (qconf->service_lcore) {
			APP_INFO("\tService lcore %u\n", lcore_id);
			continue;
		}

		APP_INFO("\tBlk dev queues on lcore %u ... ", lcore_id);
		fflush(stdout);

		map = 0;
		for (i = 0; i < qconf->nb_blkdev; i++) {
			blkdev_ctx = &qconf->blkdev_ctx[i];
			map = blkdev_ctx->virt_q_map;
			q_id = 0;
			while (map) {
				if (map & 0x1)
					APP_INFO_NH("virtio_io_q=%d,%d ", blkdev_ctx->devid, q_id);
				q_id++;
				map = map >> 1;
			}
		}

		fflush(stdout);

		APP_INFO_NH("\n");
	}
	APP_INFO("\n");
}

static int
setup_lcore_queue_mapping(uint16_t virtio_devid, uint16_t virt_q_count)
{
	struct blkdev_ctx *blkdev_ctx;
	struct lcore_conf *qconf;
	uint32_t lcore_id, idx;
	uint16_t i, q_id;

	/* Create a sorted lcore list based on its weight */
	qsort(lcore_list_wt_sorted, RTE_MAX_LCORE, sizeof(lcore_list_wt_sorted[0]), lcore_wt_cmp);
	/* Equally distribute queues among all the subscribed lcores */
	q_id = 0;
	while (q_id < virt_q_count) {
		for (idx = 0; idx < RTE_MAX_LCORE && q_id < virt_q_count; idx++) {
			lcore_id = lcore_list_wt_sorted[idx];
			if (rte_lcore_is_enabled(lcore_id) == 0)
				continue;

			qconf = &lcore_conf[lcore_id];

			/* Skip Lcore if not needed */
			if (!qconf->nb_blkdev)
				continue;

			for (i = 0; i < qconf->nb_blkdev; i++) {
				/* Check for matching virtio devid */
				if (qconf->blkdev_ctx[i].devid != virtio_devid)
					continue;
				/* Add queue to valid virtio queue map */
				blkdev_ctx = &qconf->blkdev_ctx[i];

				if (!blkdev_ctx->stash) {
					blkdev_ctx->stash = rte_zmalloc(NULL,
									sizeof(struct stash_head) *
										virt_q_count *
										NUM_STASH_PER_QUEUE,
									0);
					if (!blkdev_ctx->stash) {
						APP_ERR("Failed to allocate stash for lcore %u, blkdev %u\n",
							lcore_id, virtio_devid);
						return -1;
					}
				}

				/* Initialize tailq list in stash corresponding
				 * to q_id. Note that stash is a flat array
				 * with virt_q_count x NUM_STASH_PER_QUEUE
				 * elements. Each queue occupies
				 * NUM_STASH_PER_QUEUE consecutive entries in
				 * this array, hence indexed as q_id *
				 * NUM_STASH_PER_QUEUE.
				 */
				TAILQ_INIT(&blkdev_ctx->stash[q_id * NUM_STASH_PER_QUEUE]);
				TAILQ_INIT(&blkdev_ctx->stash[q_id * NUM_STASH_PER_QUEUE + 1]);
				rte_wmb();
				blkdev_ctx->virt_q_map |= RTE_BIT64(q_id);
				blkdev_ctx->virt_q_count++;
				/* Update lcore weight */
				qconf->weight++;
				q_id++;
				break;
			}
		}
		if (!q_id) {
			APP_INFO("Skipping virtio %u IO, no lcore mapping found\n", virtio_devid);
			break;
		}
	}

	/* Add virtio device to service lcore */
	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		if (rte_lcore_is_enabled(lcore_id) == 0)
			continue;
		qconf = &lcore_conf[lcore_id];

		if (qconf->service_lcore) {
			qconf->blkdev_map |= RTE_BIT64(virtio_devid);
			qconf->blkdev_q_count[virtio_devid] = virt_q_count;
			break;
		}
	}

	dump_lcore_info();
	return 0;
}

/* Display usage */
static void
print_usage(const char *prgname)
{
	fprintf(stderr,
		"%s [EAL options] --"
		" -v VIRTIOMASK_L[,VIRTIOMASK_H]"
		" [-d DMA_FLUSH_THR]"
		" [-f]"
		" [-y DMA_VFID]"
		"  -v VIRTIOMASK_L[,VIRTIOMASK_H]: Hexadecimal bitmask of virtio to configure\n"
		"  -d DMA_FLUSH_THR: Number of SGE's before DMA is flushed(1..15). Default is 8.\n"
		"  -f : Disable auto free with virtio Tx do sw freeing\n"
		"  -y : DMA_VFID: Value to override DMA VCHAN VFID\n"
		"  --virtio-blkconfig (dev_id[,[lcore_mask=val],[capacity=val],[blk_sz=val],[max_segs=val],[max_seg_sz=val]]) : Configure block device attributes\n\n",
		prgname);
}

static uint64_t
parse_uint(const char *str)
{
	char *end = NULL;
	unsigned long val;

	/* Parse hexadecimal string */
	val = strtoul(str, &end, 0);
	if ((str[0] == '\0') || (end == NULL) || (*end != '\0'))
		return 0;

	return val;
}

static int
parse_virtio_config(const char *q_arg)
{
	uint32_t max_seg_sz = MAX_SEG_SIZE;
	uint64_t capacity = BLK_CAPACITY;
	uint32_t max_segs = MAX_SEGS;
	uint32_t blk_sz = BLK_SIZE;
	char *token, *key, *value;
	char *saveptr1, *saveptr2;
	uint64_t lcore_mask = 0;
	uint32_t max_queues = 0; /* whatever libvirtio derives from host_page_sz */
	uint16_t dev_id;
	char s[256];
	char *end;
	int i;

	enum valid_keys {
		KEY_CAPACITY,
		KEY_BLK_SZ,
		KEY_MAX_QUEUES,
		KEY_MAX_SEGS,
		KEY_MAX_SEG_SZ,
		KEY_LCORE_MASK,
		KEY_INVALID
	};

	static const char * const valid_key_names[] = {
		[KEY_CAPACITY] = "capacity",     [KEY_BLK_SZ] = "blk_sz",
		[KEY_MAX_QUEUES] = "max_queues", [KEY_MAX_SEGS] = "max_segs",
		[KEY_MAX_SEG_SZ] = "max_seg_sz", [KEY_LCORE_MASK] = "lcore_mask",
	};

	/* Ensure the argument starts with '(' and ends with ')' */
	if (q_arg[0] != '(' || q_arg[strlen(q_arg) - 1] != ')') {
		APP_ERR("Invalid format: argument must be enclosed in parentheses\n");
		return -1;
	}

	if (strlen(q_arg) >= sizeof(s)) {
		APP_ERR("Invalid format: argument too long\n");
		return -1;
	}
	/* Copy the input string to a buffer for tokenization, excluding the parentheses */
	strncpy(s, q_arg + 1, sizeof(s) - 2);
	s[strlen(q_arg) - 2] = '\0';

	/* Parse the device_id (first token) */
	token = strtok_r(s, ",", &saveptr1);
	if (!token) {
		APP_ERR("Invalid format: missing device_id\n");
		return -1;
	}

	errno = 0;
	/* 0 is valid dev_id, so don't use parse_uint() */
	dev_id = strtoul(token, &end, 0);
	if (errno != 0 || *end != '\0' || dev_id >= DAO_VIRTIO_DEV_MAX) {
		APP_ERR("Invalid device_id: %s\n", token);
		return -1;
	}

	/* Parse key-value pairs */
	while ((token = strtok_r(NULL, ",", &saveptr1)) != NULL) {
		key = strtok_r(token, "=", &saveptr2);
		value = strtok_r(NULL, "=", &saveptr2);

		if (!key || !value) {
			APP_ERR("Invalid key-value pair: %s\n", token);
			return -1;
		}

		for (i = 0; i < KEY_INVALID; i++) {
			if (strcmp(key, valid_key_names[i]) == 0) {
				errno = 0;
				switch (i) {
				case KEY_CAPACITY:
					capacity = parse_uint(value);
					if (capacity == 0) {
						APP_ERR("Invalid value for capacity: %s\n", value);
						return -1;
					}
					break;
				case KEY_BLK_SZ:
					blk_sz = parse_uint(value);
					if (blk_sz == 0 || blk_sz & (blk_sz - 1)) {
						APP_ERR("Invalid value for blk_sz: %s\n", value);
						return -1;
					}
					break;
				case KEY_MAX_QUEUES:
					max_queues = parse_uint(value);
					if (max_queues == 0) {
						APP_ERR("Invalid value for max_queues: %s\n",
							value);
						return -1;
					}
					break;
				case KEY_MAX_SEGS:
					max_segs = parse_uint(value);
					if (max_segs == 0) {
						APP_ERR("Invalid value for max_segs: %s\n", value);
						return -1;
					}
					break;
				case KEY_MAX_SEG_SZ:
					max_seg_sz = parse_uint(value);
					if (max_seg_sz == 0) {
						APP_ERR("Invalid value for max_seg_sz: %s\n",
							value);
						return -1;
					}
					break;
				case KEY_LCORE_MASK:
					lcore_mask = parse_uint(value);
					if (lcore_mask == 0) {
						APP_ERR("Invalid value for lcore_mask: %s\n",
							value);
						return -1;
					}
					break;
				default:
					break;
				}
				break;
			}
		}

		if (i == KEY_INVALID) {
			APP_ERR("Unknown key: %s\n", key);
			return -1;
		}
	}

	if (max_seg_sz % blk_sz != 0) {
		APP_ERR("Invalid configuration for device_id %u\n", dev_id);
		return -1;
	}

	snprintf(blkdev_conf[dev_id].name, BLKDEV_NAME_MAX, "ramdisk_%u", dev_id);
	blkdev_conf[dev_id].capacity = capacity;
	blkdev_conf[dev_id].blk_size = blk_sz;
	blkdev_conf[dev_id].max_queues = max_queues;
	blkdev_conf[dev_id].seg_max = max_segs;
	blkdev_conf[dev_id].seg_size_max = max_seg_sz;
	if (lcore_mask)
		blkdev_conf[dev_id].lcore_mask = lcore_mask;

	APP_INFO(
		"Parsed config for device_id %u: capacity=%lu, blk_sz=%u, max_queues=%u, max_segs=%u, max_seg_sz=%u\n",
		dev_id, capacity, blk_sz, max_queues, max_segs, max_seg_sz);

	return 0;
}

static const char short_options[] = "v:" /* virt dev mask */
				    "d:" /* DMA flush threshold */
				    "f"  /* Disable auto free */
				    "y:" /* Override DMA vfid */
				    "o"  /* Enable in-order processing */
	;

#define CMD_LINE_OPT_VIRTIO_CONFIG "virtio-blkconfig"
#define CMD_LINE_OPT_PER_DEV_POOL  "per-dev-pool"
#define CMD_LINE_OPT_IN_ORDER      "in-order"
enum {
	/* Long options mapped to a short option */

	/* First long only option value must be >= 256, so that we won't
	 * conflict with short options
	 */
	CMD_LINE_OPT_MIN_NUM = 256,
	CMD_LINE_OPT_VIRTIO_CONFIG_NUM,
	CMD_LINE_OPT_PER_DEV_POOL_NUM,
	CMD_LINE_OPT_IN_ORDER_NUM,
};

static const struct option lgopts[] = {
	{CMD_LINE_OPT_VIRTIO_CONFIG, 1, 0, CMD_LINE_OPT_VIRTIO_CONFIG_NUM},
	{CMD_LINE_OPT_PER_DEV_POOL, 0, 0, CMD_LINE_OPT_PER_DEV_POOL_NUM},
	{CMD_LINE_OPT_IN_ORDER, 0, 0, CMD_LINE_OPT_IN_ORDER_NUM},
	{NULL, 0, 0, 0},
};

/* Parse the argument given in the command line of the application */
static int
parse_args(int argc, char **argv)
{
	uint64_t virtio_mask_dflt = 0;
	uint16_t service_lcore = 0;
	char *prgname = argv[0];
	char *str, *saveptr;
	int option_index;
	char **argvopt;
	uint8_t lcore;
	int opt, rc;
	int i;

	/* Setup lcore mask of virtio dev to default
	 * One for service lcore, one for main lcore and rest for virtio.
	 */
	for (lcore = 0; lcore < RTE_MAX_LCORE; lcore++) {
		if (!rte_lcore_is_enabled(lcore) || (lcore == rte_get_main_lcore()))
			continue;

		service_lcore = lcore;
		break;
	}

	for (lcore = 0; lcore < RTE_MAX_LCORE; lcore++) {
		if (!rte_lcore_is_enabled(lcore) || (lcore == rte_get_main_lcore()) ||
		    lcore == service_lcore)
			continue;

		virtio_mask_dflt |= RTE_BIT64(lcore);
	}

	if (!virtio_mask_dflt) {
		APP_ERR("At least 1 core is required, please increase the cores\n");
		return -1;
	}

	for (i = 0; i < DAO_VIRTIO_DEV_MAX; i++)
		blkdev_conf[i].lcore_mask = virtio_mask_dflt;

	argvopt = argv;

	/* Error or normal output strings. */
	while ((opt = getopt_long(argc, argvopt, short_options, lgopts, &option_index)) != EOF) {
		switch (opt) {
		case 'v':
			str = strtok_r(optarg, ",", &saveptr);
			if (str)
				virtio_mask_ena[0] = parse_uint(str);
			str = strtok_r(NULL, ",", &saveptr);
			if (str)
				virtio_mask_ena[1] = parse_uint(str);

			if (virtio_mask_ena[0] == 0 && virtio_mask_ena[1] == 0) {
				APP_ERR("Invalid portmask\n");
				print_usage(prgname);
				return -1;
			}
			nb_virtio_blkdevs = __builtin_popcountl(virtio_mask_ena[0]);
			nb_virtio_blkdevs += __builtin_popcountl(virtio_mask_ena[1]);
			break;
		case 'd':
			dma_flush_thr = parse_uint(optarg);
			if (dma_flush_thr < 1 || dma_flush_thr > 15) {
				APP_ERR("Invalid dma flush threshold\n");
				print_usage(prgname);
				return -1;
			}
			break;

		case 'f':
			virtio_blkdev_autofree = false;
			break;
		case 'y':
			override_dma_vfid = true;
			dma_vfid = parse_uint(optarg);
			break;
		case CMD_LINE_OPT_VIRTIO_CONFIG_NUM:
			rc = parse_virtio_config(optarg);
			if (rc) {
				APP_ERR("Invalid virt config\n");
				print_usage(prgname);
				return -1;
			}
			break;

		case CMD_LINE_OPT_PER_DEV_POOL_NUM:
			APP_INFO("Per device buffer pool is enabled\n");
			per_dev_pool = 1;
			break;

		case 'o':
		case CMD_LINE_OPT_IN_ORDER_NUM:
			/* Enable in-order processing */
			APP_INFO("In-order processing enabled\n");
			in_order = 1;
			break;
		default:
			print_usage(prgname);
			return -1;
		}
	}

	if (optind >= 0)
		argv[optind - 1] = prgname;
	rc = optind - 1;
	optind = 1; /* Reset getopt lib */

	if (!nb_virtio_blkdevs) {
		APP_ERR("Need at least one virtio dev\n");
		return -1;
	}
	return rc;
}

static void
signal_handler(int signum)
{
	APP_INFO("\n");
	if (signum == SIGINT || signum == SIGTERM) {
		APP_INFO("Signal %d received, preparing to exit...\n", signum);
		force_quit = true;
	}
}

static inline int
decode_virtio_blk_request(virtio_blk_hdr_t *req, uint32_t *req_type, uint64_t *start_sector)
{
	if (req == NULL || req_type == NULL || start_sector == NULL)
		return -1;

	// Extract request type
	*req_type = req->type;
	*start_sector = req->sector;

	switch (*req_type) {
	case VIRTIO_BLK_T_IN: // Read
		break;
	case VIRTIO_BLK_T_OUT: // Write
		break;
	case VIRTIO_BLK_T_FLUSH: // Flush
		break;
	case VIRTIO_BLK_T_DISCARD:
	case VIRTIO_BLK_T_WRITE_ZEROES:
		break;
	case VIRTIO_BLK_T_GET_ID:
		break;
	case VIRTIO_BLK_T_SECURE_ERASE:
		break;
	default:
		return -2; // Unsupported request type
	}

	return 0; // Success
}

static inline void
decode_virtio_blk_buf_addr_len(struct dao_virtio_blk_hdr *dv_hdr, void **buf, uint32_t *len)
{
	/* Next dao blk segment */
	struct dao_virtio_blk_hdr *dv_hdr1 = (struct dao_virtio_blk_hdr *)dv_hdr->desc_data[0];
	*buf = (void *)dv_hdr1->hdr_data;
	/* total size of data[] for read/write req */
	*len = dv_hdr1->tot_len - sizeof(virtio_blk_hdr_t) - sizeof(uint8_t);
}

static inline void
build_iov_buf_list(struct dao_virtio_blk_hdr *dv_hdr0, dao_blk_io_vec_t *iov, uint32_t *len)
{
	uint32_t i;
	struct dao_virtio_blk_hdr *dv_hdr;

	iov->bufs = rte_malloc(NULL, (dv_hdr0->tot_bufs - 2) * sizeof(blk_iobuf_ptr_t), 0);
	/* Skip the first virtio block header buffer */
	dv_hdr = (struct dao_virtio_blk_hdr *)dv_hdr0->desc_data[0];

	for (i = 0; i < dv_hdr0->tot_bufs - 2; i++) {
		iov->bufs[i].data = dv_hdr->hdr_data;
		iov->bufs[i].size = dv_hdr->desc_data[1];
		*len += iov->bufs[i].size;
		dv_hdr = (struct dao_virtio_blk_hdr *)dv_hdr->desc_data[0];
	}

	/** status is pointing to the trailer of blk request */
	// iov->status = dv_hdr->desc_data[0];
	/** buf_cnt is set such that blk header and trailer buffers are skipped */
	iov->buf_cnt = dv_hdr0->tot_bufs - 2;
}

static inline void
free_iov_buf_list(dao_blk_io_vec_t *iov)
{
	if (iov->bufs)
		rte_free(iov->bufs);
}

static inline int
virtio_blk_io_process_request(uint16_t devid, void *vbuf)
{
	dao_virtio_blk_req_status_t req_stat = DAO_VIRTIO_BLK_REQ_COMPLETE;
	struct dao_blkdev *dev = &dao_blkdevs[devid];
	struct virtio_blk_discard_write_zeroes *disc_wr_z;
	struct dao_virtio_blk_hdr *dv_hdr, *dv_hdr1;
	virtio_blk_hdr_t *request;
	uint64_t start_sector;
	uint32_t data_len = 0;
	uint32_t req_type;
	dao_blk_io_vec_t iov;
	int ret, result;
	uint8_t unmap;

	dv_hdr = (struct dao_virtio_blk_hdr *)vbuf;
	request = (virtio_blk_hdr_t *)dv_hdr->hdr_data;
	result = decode_virtio_blk_request(request, &req_type, &start_sector);

	if (result == 0) {
		// Process the request based on type
		switch (req_type) {
		case VIRTIO_BLK_T_IN:
			build_iov_buf_list(dv_hdr, &iov, &data_len);
			ret = dao_blkdev_read(devid, start_sector, &iov, data_len);
			free_iov_buf_list(&iov);
			break;
		case VIRTIO_BLK_T_OUT:
			build_iov_buf_list(dv_hdr, &iov, &data_len);
			ret = dao_blkdev_write(devid, start_sector, &iov, data_len);
			free_iov_buf_list(&iov);
			break;
		case VIRTIO_BLK_T_WRITE_ZEROES:
			/* Go to first buffer after blk header */
			dv_hdr1 = (struct dao_virtio_blk_hdr *)dv_hdr->desc_data[0];
			disc_wr_z = (struct virtio_blk_discard_write_zeroes *)dv_hdr1->hdr_data;
			unmap = disc_wr_z->flags.unmap;
			ret = dao_blkdev_write_zeroes(devid, disc_wr_z->sector,
						      disc_wr_z->num_sectors * dev->sector_size,
						      unmap);
			break;
		case VIRTIO_BLK_T_DISCARD:
			/* Go to first buffer after blk header */
			dv_hdr1 = (struct dao_virtio_blk_hdr *)dv_hdr->desc_data[0];
			disc_wr_z = (struct virtio_blk_discard_write_zeroes *)dv_hdr->hdr_data;
			ret = dao_blkdev_discard(devid, disc_wr_z->sector,
						 disc_wr_z->num_sectors * dev->sector_size);
			break;
		case VIRTIO_BLK_T_FLUSH:
			ret = dao_blkdev_flush(devid);
			break;
		case VIRTIO_BLK_T_GET_ID:
			dv_hdr1 = (struct dao_virtio_blk_hdr *)dv_hdr->desc_data[0];
			ret = dao_blkdev_get_id(devid, (char *)dv_hdr1->hdr_data,
						MAX_VIRTIO_BLK_ID_STRLEN);
			break;
		default:
			ret = DAO_BLK_DEV_REQ_UNSUPPORTED; // Unsupported operation
			break;
		}

	} else {
		*dv_hdr->status = (result == -1) ? VIRTIO_BLK_S_IOERR : VIRTIO_BLK_S_UNSUPP;
		goto err;
	}

	switch (ret) {
	case DAO_BLK_DEV_REQ_COMPGOOD:
		*dv_hdr->status = VIRTIO_BLK_S_OK;
		break;
	case DAO_BLK_DEV_REQ_FAIL:
		*dv_hdr->status = VIRTIO_BLK_S_IOERR;
		break;
	case DAO_BLK_DEV_REQ_UNSUPPORTED:
		*dv_hdr->status = VIRTIO_BLK_S_UNSUPP;
		break;
	case DAO_BLK_DEV_REQ_IN_PROCESS:
		/* No change in dv_hdr->status when req is in progress */
		req_stat = DAO_VIRTIO_BLK_REQ_IN_PROGRESS;
		break;
	default:
		printf("Unknown error in blk device req processing\n");
	}
	/** For in DAO_BLK_DEV_REQ_IN_PROCESS, the status needs
	    to be updated when the request is done. May be in callback function
	    passed by the application to blk dev library
	 */
err:
	return req_stat;
}

/**
 *  This API returns
 *	 DAO_VIRTIO_BLK_REQ_COMPLETE, if request is finished
 *       DAO_VIRTIO_BLK_REQ_IN_PROGRESS, if request is still pending
 */
static inline int
virtio_blk_request_get_status(uint16_t devid, void *vbuf)
{
	struct dao_virtio_blk_hdr *dv_hdr;
	uint8_t *status;

	RTE_SET_USED(devid);
	dv_hdr = (struct dao_virtio_blk_hdr *)vbuf;
	status = dv_hdr->status;

	if (*status <= VIRTIO_BLK_S_UNSUPP)
		return DAO_VIRTIO_BLK_REQ_COMPLETE;
	else
		return DAO_VIRTIO_BLK_REQ_IN_PROGRESS;
}

static __rte_always_inline uint16_t
blkio_virtio_desc_process(uint64_t blkdev_map, uint16_t *blkdev_q_count)
{
	uint16_t dev_id = 0;

	while (blkdev_map) {
		if (!(blkdev_map & 0x1)) {
			blkdev_map >>= 1;
			dev_id++;
			continue;
		}
		dao_virtio_blk_io_desc_manage(dev_id, blkdev_q_count[dev_id]);
		blkdev_map >>= 1;
		dev_id++;
	}

	return 0;
}

static int
service_main_loop(void *conf)
{
	struct rte_rcu_qsbr *qs_v;
	struct lcore_conf *qconf;
	uint32_t lcore_id;
	int rc;

	RTE_SET_USED(conf);

	lcore_id = rte_lcore_id();
	qconf = &lcore_conf[lcore_id];
	qs_v = qconf->qs_v;

	/* Set per lcore DMA device id */
	rc = dao_dma_lcore_dev2mem_set(qconf->dev2mem_id, qconf->nb_vchans, dma_flush_thr);
	rc |= dao_dma_lcore_mem2dev_set(qconf->mem2dev_id, qconf->nb_vchans, dma_flush_thr);
	if (rc) {
		APP_ERR("Error in setting DMA device on lcore\n");
		return -1;
	}

	/* Register this thread to rdaort quiescent state */
	rte_rcu_qsbr_thread_register(qs_v, lcore_id);
	rte_rcu_qsbr_thread_online(qs_v, lcore_id);

	APP_INFO("Entering service main loop on lcore %u\n", lcore_id);

	while (likely(!force_quit)) {
		/* Process virtio descriptors */
		blkio_virtio_desc_process(qconf->blkdev_map, qconf->blkdev_q_count);

		/* Flush and submit DMA ops */
		dao_dma_flush_submit();

		/* Update quiescent state */
		rte_rcu_qsbr_quiescent(qs_v, lcore_id);
	}

	rte_rcu_qsbr_thread_offline(qs_v, lcore_id);
	rte_rcu_qsbr_thread_unregister(qs_v, lcore_id);
	return 0;
}

static __rte_always_inline void
process_completed_requests(uint8_t dev_id, uint8_t q_id, struct stash_head *compl_reqs_stash)
{
	struct stash_entry *entry, *next_entry;
	int num_compl, num_compl_vbufs;
	void *compl_vbufs[IO_BURST];

	while (!TAILQ_EMPTY(compl_reqs_stash)) {
		num_compl_vbufs = 0;

		TAILQ_FOREACH(entry, compl_reqs_stash, link) {
			if (num_compl_vbufs >= IO_BURST)
				break;
			compl_vbufs[num_compl_vbufs++] = entry->vbuf;
		}

		num_compl = dao_virtio_blk_process_compl(dev_id, q_id, compl_vbufs,
							 num_compl_vbufs);
		if (!num_compl)
			break;

		TAILQ_FOREACH_SAFE(entry, compl_reqs_stash, link, next_entry) {
			if (num_compl) {
				TAILQ_REMOVE(compl_reqs_stash, entry, link);
				rte_free(entry);
				num_compl--;
			} else {
				break;
			}
		}
	}
}

static __rte_always_inline void
process_pending_requests(uint8_t dev_id, uint8_t q_id, struct stash_head *pend_reqs_stash,
			 struct stash_head *compl_reqs_stash)
{
	struct stash_entry *entry, *next_entry, *last_inprogress_job;
	int num_compl, num_compl_vbufs = 0, status;
	void *compl_vbufs[IO_BURST];

	if (!TAILQ_EMPTY(compl_reqs_stash) || TAILQ_EMPTY(pend_reqs_stash))
		return;

	last_inprogress_job = TAILQ_FIRST(pend_reqs_stash);
	status = virtio_blk_request_get_status(dev_id, last_inprogress_job->vbuf);

	if (status != DAO_VIRTIO_BLK_REQ_COMPLETE)
		return;

	compl_vbufs[num_compl_vbufs++] = last_inprogress_job->vbuf;
	TAILQ_REMOVE(pend_reqs_stash, last_inprogress_job, link);
	rte_free(last_inprogress_job);

	while (!TAILQ_EMPTY(pend_reqs_stash)) {
		TAILQ_FOREACH_SAFE(entry, pend_reqs_stash, link, next_entry) {
			if (num_compl_vbufs >= IO_BURST)
				break;

			status = virtio_blk_io_process_request(dev_id, entry->vbuf);
			if (status != DAO_VIRTIO_BLK_REQ_COMPLETE)
				break;

			TAILQ_REMOVE(pend_reqs_stash, entry, link);
			compl_vbufs[num_compl_vbufs++] = entry->vbuf;
			rte_free(entry);
		}

		num_compl = dao_virtio_blk_process_compl(dev_id, q_id, compl_vbufs,
							 num_compl_vbufs);

		for (int i = num_compl; i < num_compl_vbufs; i++) {
			struct stash_entry *new_entry =
				rte_malloc(NULL, sizeof(struct stash_entry), 0);
			if (unlikely(new_entry == NULL)) {
				APP_ERR("rte_malloc failed at %s:%d\n", __func__, __LINE__);
				force_quit = true;
				return;
			}
			new_entry->vbuf = compl_vbufs[i];
			TAILQ_INSERT_TAIL(compl_reqs_stash, new_entry, link);
		}
	}
}

static __rte_always_inline void
process_new_requests(uint8_t dev_id, uint8_t q_id, struct stash_head *pend_reqs_stash,
		     struct stash_head *compl_reqs_stash)
{
	int i, num_deq, num_compl, num_vbufs, status, num_compl_vbufs = 0;
	struct stash_entry *new_entry;
	void *compl_vbufs[IO_BURST];
	void *vbufs[IO_BURST];

	/* Invoking library call to dequeue_burst with 0 vbuf count helps to
	   check the status of any previously submitted DMA Jobs and enables
	   service core to do its job. And also helps to fetch data of any new
	   IO requests that service core made available to device shadow
	   ring. */
	num_vbufs = (TAILQ_EMPTY(compl_reqs_stash) && TAILQ_EMPTY(pend_reqs_stash)) ? IO_BURST : 0;

	num_deq = dao_virtio_blk_dequeue_burst(dev_id, q_id, vbufs, num_vbufs);

	for (i = 0; i < num_deq; i++) {
		status = virtio_blk_io_process_request(dev_id, vbufs[i]);
		/* Stop processing further if the request is not complete */
		if (unlikely(status != DAO_VIRTIO_BLK_REQ_COMPLETE))
			break;

		compl_vbufs[num_compl_vbufs++] = vbufs[i];
	}

	num_compl = dao_virtio_blk_process_compl(dev_id, q_id, compl_vbufs, num_compl_vbufs);

	/* Park requests which library not able perform completion process */
	for (int j = num_compl; j < num_compl_vbufs; j++) {
		new_entry = rte_malloc(NULL, sizeof(struct stash_entry), 0);
		if (unlikely(new_entry == NULL)) {
			APP_ERR("rte_malloc failed at %s:%d\n", __func__, __LINE__);
			force_quit = true;
			return;
		}

		new_entry->vbuf = compl_vbufs[j];
		TAILQ_INSERT_TAIL(compl_reqs_stash, new_entry, link);
	}

	/* unlikely case. Park IO requests which are dequeued but not serviced. */
	for (; i < num_deq; i++) {
		new_entry = rte_malloc(NULL, sizeof(struct stash_entry), 0);
		if (unlikely(new_entry == NULL)) {
			APP_ERR("rte_malloc failed at %s:%d\n", __func__, __LINE__);
			force_quit = true;
			return;
		}
		new_entry->vbuf = vbufs[i];
		TAILQ_INSERT_TAIL(pend_reqs_stash, new_entry, link);
	}
}

static __rte_always_inline void
virtio_blkio_main(uint8_t dev_id, uint8_t q_id)
{
	struct blkdev_ctx *bctx = &lcore_conf[rte_lcore_id()].blkdev_ctx[dev_id];
	struct stash_head *compl_reqs_stash = &bctx->stash[q_id * 2];
	struct stash_head *pend_reqs_stash = &bctx->stash[q_id * 2 + 1];

	process_completed_requests(dev_id, q_id, compl_reqs_stash);
	process_pending_requests(dev_id, q_id, pend_reqs_stash, compl_reqs_stash);
	process_new_requests(dev_id, q_id, pend_reqs_stash, compl_reqs_stash);
}

static int
worker_main_loop(void *conf)
{
	struct rte_rcu_qsbr *qs_v;
	struct lcore_conf *qconf;
	uint16_t dev_id, q_id;
	uint32_t lcore_id;
	uint8_t q_count;
	uint64_t q_map;
	int rc, i;

	RTE_SET_USED(conf);

	lcore_id = rte_lcore_id();
	qconf = &lcore_conf[lcore_id];
	qs_v = qconf->qs_v;

	/* Set per lcore DMA device id */
	rc = dao_dma_lcore_dev2mem_set(qconf->dev2mem_id, qconf->nb_vchans, dma_flush_thr);
	rc |= dao_dma_lcore_mem2dev_set(qconf->mem2dev_id, qconf->nb_vchans, dma_flush_thr);
	for (i = 0; i < qconf->nb_vchans; i++)
		rc |= dao_dma_lcore_mem2dev_autofree_set(qconf->mem2dev_id, i,
							 virtio_blkdev_autofree);

	if (rc) {
		APP_ERR("Error in setting DMA device on lcore\n");
		return -1;
	}

	/* Register this thread to rdaort quiescent state */
	rte_rcu_qsbr_thread_register(qs_v, lcore_id);
	rte_rcu_qsbr_thread_online(qs_v, lcore_id);

	APP_INFO("Entering worker main loop on lcore %u\n", lcore_id);

	while (likely(!force_quit)) {
		for (int i = 0; i < qconf->nb_blkdev; i++) {
			q_map = qconf->blkdev_ctx[i].virt_q_map;
			dev_id = qconf->blkdev_ctx[i].devid;
			/* Device reset callback logic relies on resetting
			 * blkdev_ctx[dev]->virt_q_count and then rcu sync +
			 * cleanup of any inflight/pending IO requests parked
			 * in stash. If you ever has to change the below
			 * condition on q_count ensure that the reset logic is
			 * not broken.
			 */
			q_count = qconf->blkdev_ctx[i].virt_q_count;
			while (q_count) {
				q_id = __builtin_ctzll(q_map);
				virtio_blkio_main(dev_id, q_id);
				q_map &= ~(1 << q_id);
				q_count--;
			}
		}
		/* Flush and submit DMA ops */
		dao_dma_flush_submit();

		/* Update quiescent state */
		rte_rcu_qsbr_quiescent(qs_v, lcore_id);
	}

	rte_rcu_qsbr_thread_offline(qs_v, lcore_id);
	rte_rcu_qsbr_thread_unregister(qs_v, lcore_id);
	return 0;
}

static __rte_always_inline void
stash_memory_cleanup(struct stash_head *head)
{
	struct stash_entry *entry, *tmp;

	if (!head || TAILQ_EMPTY(head))
		return;

	TAILQ_FOREACH_SAFE(entry, head, link, tmp) {
		TAILQ_REMOVE(head, entry, link);
		rte_free(entry);
	}
}

static void
reset_lcore_queue_count(uint16_t virtio_devid)
{
	struct lcore_conf *qconf;

	for (uint16_t lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		if (rte_lcore_is_enabled(lcore_id) == 0)
			continue;
		qconf = &lcore_conf[lcore_id];

		/* Skip Lcore if not needed */
		if (!qconf->nb_blkdev && !qconf->service_lcore)
			continue;

		for (int i = 0; i < qconf->nb_blkdev; i++) {
			/* Check for matching virtio devid */
			if (qconf->blkdev_ctx[i].devid != virtio_devid)
				continue;

			/* Reset virtio queue count. */
			qconf->blkdev_ctx[i].virt_q_count = 0;
		}

		if (qconf->service_lcore)
			qconf->blkdev_map &= ~RTE_BIT64(virtio_devid);
	}
	rte_wmb();
}

static void
clear_lcore_queue_mapping(uint16_t virtio_devid)
{
	struct blkdev_ctx *blkdev_ctx;
	struct lcore_conf *qconf;
	struct stash_head *stash;
	uint32_t lcore_id;
	uint64_t q_map;
	uint16_t q_id;

	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		if (rte_lcore_is_enabled(lcore_id) == 0)
			continue;
		qconf = &lcore_conf[lcore_id];

		/* Skip Lcore if not needed */
		if (!qconf->nb_blkdev && !qconf->service_lcore)
			continue;

		for (int i = 0; i < qconf->nb_blkdev; i++) {
			/* Check for matching virtio devid */
			if (qconf->blkdev_ctx[i].devid != virtio_devid)
				continue;

			blkdev_ctx = &qconf->blkdev_ctx[i];
			qconf->weight -= blkdev_ctx->virt_q_count;
			q_map = blkdev_ctx->virt_q_map;
			stash = blkdev_ctx->stash;
			blkdev_ctx->virt_q_map = 0;
			blkdev_ctx->virt_q_count = 0;
			blkdev_ctx->stash = NULL;

			for (; q_map; q_map &= ~(1 << q_id)) {
				q_id = __builtin_ctzll(q_map);
				stash_memory_cleanup(&stash[q_id * NUM_STASH_PER_QUEUE]);
			}
			rte_free(stash);
		}
	}
	rte_wmb();
	dump_lcore_info();
}

static int
virtio_dev_status_cb(uint16_t virtio_devid, uint8_t status)
{
	bool reset_blkdev = false;
	uint16_t virt_q_count;
	int rc;

	APP_INFO("virtio_dev=%d: status=%s\n", virtio_devid, dao_virtio_dev_status_to_str(status));

	switch (status) {
	case VIRTIO_DEV_RESET:
	case VIRTIO_DEV_NEEDS_RESET:
		reset_lcore_queue_count(virtio_devid);
		reset_blkdev = true;
		break;
	case VIRTIO_DEV_DRIVER_OK:

		/* Get active virt queue count */
		virt_q_count = dao_virtio_blkdev_queue_count(virtio_devid);

		if (virt_q_count <= 0 || virt_q_count >= (DAO_VIRTIO_MAX_QUEUES - 1)) {
			APP_ERR("virtio_dev=%d: invalid virt_q_count=%d\n", virtio_devid,
				virt_q_count);
			return -EIO;
		}
		rc = setup_lcore_queue_mapping(virtio_devid, virt_q_count);
		if (rc)
			APP_ERR("virtio_dev=%d: failed to setup lcore queue mapping, rc=%d\n",
				virtio_devid, rc);
		break;
	default:
		break;
	};

	/* Synchronize RCU */
	rte_rcu_qsbr_synchronize(qs_v, RTE_QSBR_THRID_INVALID);
	/* After this point, all the core's see updated queue mapping */

	if (reset_blkdev) {
		/* At this point it safe to free any inflight/pending stash entries */
		clear_lcore_queue_mapping(virtio_devid);
		/* dump packet pool available count */
		if (!per_dev_pool)
			APP_ERR("Intermediate buffer pool avail buff_cnt=%d\n",
				rte_mempool_avail_count(v_extmbuf_pool[0]));
		else
			APP_ERR("Intermediate buffer pool avail buff_cnt=%d\n",
				rte_mempool_avail_count(v_extmbuf_pool[virtio_devid]));
	}
	return 0;
}

static int
virtio_blkdev_extbuf_get(uint16_t devid, void *buffs[], uint16_t nb_buffs)
{
	int rv;

	if (!per_dev_pool)
		rv = rte_mempool_get_bulk(v_extmbuf_pool[0], buffs, nb_buffs);
	else
		rv = rte_mempool_get_bulk(v_extmbuf_pool[devid], buffs, nb_buffs);

	if (rv) {
		APP_ERR("rte_mempool_get_bulk failed. req buff_cnt=%hu, avail "
			"buff_cnt=%d\n",
			nb_buffs, rte_mempool_avail_count(v_extmbuf_pool[0]));
		return -1;
	}

	return 0;
}

static int
virtio_blkdev_extbuf_put(uint16_t devid, void *buffs[], uint16_t nb_buffs)
{
	if (!per_dev_pool)
		rte_mempool_put_bulk(v_extmbuf_pool[0], buffs, nb_buffs);
	else
		rte_mempool_put_bulk(v_extmbuf_pool[devid], buffs, nb_buffs);

	return 0;
}

static int
init_virtio_mempool(uint16_t devid, uint32_t nb_mbuf)
{
	uint32_t lcore_id;
	int rc;
	char s[64];

	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		if (rte_lcore_is_enabled(lcore_id) == 0)
			continue;

		if (v_extmbuf_pool[devid] == NULL) {
			snprintf(s, sizeof(s), "extmbuf_pool_v%d", devid);
			/* Create a pool with priv size of a cacheline */
			v_extmbuf_pool[devid] =
				rte_mempool_create_empty(s, nb_mbuf,
							 MAX_SEG_SIZE +
							 sizeof(struct dao_virtio_blk_hdr),
							 MEMPOOL_CACHE_SIZE, 0, SOCKET_ID_ANY, 0);
			if (v_extmbuf_pool[devid] == NULL)
				rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");

			// TODO: use get registered mempool ops and search for the one that matches
			rc = rte_mempool_set_ops_byname(v_extmbuf_pool[devid], "cn10k_mempool_ops",
							NULL);
			if (rc)
				rte_exit(EXIT_FAILURE, "Cannot set mempool ops\n");

			rc = rte_mempool_populate_default(v_extmbuf_pool[devid]);
			if (rc < 0)
				rte_exit(EXIT_FAILURE, "Cannot populate mbuf pool\n");

			APP_INFO("Created virtio_dev mbuf pool for devid=%d with %d buffers\n",
				 devid, rc);
		}
	}

	return 0;
}

static void
setup_mempools(void)
{
	uint32_t virtio_devid;
	int rc;

	for (virtio_devid = 0; virtio_devid < DAO_VIRTIO_DEV_MAX; virtio_devid++) {
		if (!is_virtio_dev_enabled(virtio_devid))
			continue;

		if (!per_dev_pool)
			rc = init_virtio_mempool(0, extmbuf_count);
		else
			rc = init_virtio_mempool(virtio_devid, extmbuf_count);

		if (rc < 0)
			rte_exit(EXIT_FAILURE, "init_virtio_mempool() failed\n");
	}
}

static void
setup_dma_devices(void)
{
	struct rte_dma_vchan_conf dma_qconf;
	uint16_t dev2mem_idx, mem2dev_idx;
	struct rte_dma_info dma_info;
	struct rte_dma_conf dma_conf;
	struct lcore_conf *qconf;
	uint32_t virtio_devid;
	uint32_t lcore_id;
	int16_t dma_devid;
	uint16_t vchan;
	uint64_t mask;
	int i, base;

	APP_INFO("\n");

	dma_devid = 0;
	/* Prepare half of the worker DMA devices half as dev2mem and half as mem2dev */
	for (i = 0; i < wrkr_dma_devs; i += 2) {
		/* Setup Inbound dma device with one vchan per virtio blkdev */
		dma_devid = rte_dma_next_dev(dma_devid);
		if (dma_devid == -1)
			break;

		rte_dma_info_get(dma_devid, &dma_info);
		APP_INFO("Setting up dmadev %s(%d)\n", dma_info.dev_name, dma_devid);

		memset(&dma_conf, 0, sizeof(dma_conf));
		dma_conf.nb_vchans = nb_virtio_blkdevs;

		if (rte_dma_configure(dma_devid, &dma_conf) != 0)
			rte_exit(EXIT_FAILURE, "Error with rte_dma_configure()\n");

		mask = virtio_mask_ena[0];
		base = 0;
		for (vchan = 0; vchan < nb_virtio_blkdevs; vchan++) {
			/* Get next virtio device id */
			virtio_devid = __builtin_ffsl(mask);
			if (virtio_devid == 0)
				rte_exit(EXIT_FAILURE, "Error no virtio device\n");
			virtio_devid -= 1;
			virtio_devid += base;
			virtio_blkdev_dma_vchans[virtio_devid] = vchan;

			memset(&dma_qconf, 0, sizeof(dma_qconf));
			dma_qconf.direction = RTE_DMA_DIR_DEV_TO_MEM;
			dma_qconf.nb_desc = 2048;
			dma_qconf.src_port.pcie.coreid = 0; /* TODO PEM id */
			dma_qconf.src_port.pcie.vfen = 1;
			dma_qconf.src_port.pcie.vfid = virtio_devid + 1;
			dma_qconf.src_port.port_type = RTE_DMA_PORT_PCIE;

			/* Override DMA VFID if needed */
			if (override_dma_vfid) {
				dma_qconf.src_port.pcie.vfen = dma_vfid ? 1 : 0;
				dma_qconf.src_port.pcie.vfid = dma_vfid;
			}

			if (rte_dma_vchan_setup(dma_devid, vchan, &dma_qconf) != 0)
				rte_exit(EXIT_FAILURE, "Error with inbound configuration\n");
			mask &= ~RTE_BIT64(virtio_devid);
			if (!mask) {
				base += 64;
				mask = virtio_mask_ena[1];
			}
		}

		if (rte_dma_start(dma_devid) != 0)
			rte_exit(EXIT_FAILURE, "Error with rte_dma_start()\n");

		dev2mem_ids[dev2mem_cnt++] = dma_devid;
		dma_devid++;

		/* Setup Outbound dma device with one vchan per virtio blkdev */
		dma_devid = rte_dma_next_dev(dma_devid);
		if (dma_devid == -1)
			break;

		rte_dma_info_get(dma_devid, &dma_info);
		APP_INFO("Setting up dmadev %s(%d)\n", dma_info.dev_name, dma_devid);

		memset(&dma_conf, 0, sizeof(dma_conf));
		dma_conf.nb_vchans = nb_virtio_blkdevs;

		if (rte_dma_configure(dma_devid, &dma_conf) != 0)
			rte_exit(EXIT_FAILURE, "Error with rte_dma_configure()\n");

		mask = virtio_mask_ena[0];
		base = 0;
		for (vchan = 0; vchan < nb_virtio_blkdevs; vchan++) {
			/* Get next virtio device id */
			virtio_devid = __builtin_ffsl(mask);
			if (virtio_devid == 0)
				rte_exit(EXIT_FAILURE, "Error no virtio device\n");
			virtio_devid -= 1;
			virtio_devid += base;

			memset(&dma_qconf, 0, sizeof(dma_qconf));
			dma_qconf.direction = RTE_DMA_DIR_MEM_TO_DEV;
			dma_qconf.nb_desc = 2048;
			dma_qconf.dst_port.pcie.coreid = 0; /* TODO PEM id */
			dma_qconf.dst_port.pcie.vfen = 1;
			dma_qconf.dst_port.pcie.vfid = virtio_devid + 1;
			dma_qconf.dst_port.port_type = RTE_DMA_PORT_PCIE;

			dma_qconf.auto_free.m2d.pool =
				per_dev_pool ? v_extmbuf_pool[virtio_devid] : v_extmbuf_pool[0];
			/* Override DMA VFID if needed */
			if (override_dma_vfid) {
				dma_qconf.dst_port.pcie.vfen = dma_vfid ? 1 : 0;
				dma_qconf.dst_port.pcie.vfid = dma_vfid;
			}

			if (rte_dma_vchan_setup(dma_devid, vchan, &dma_qconf) != 0)
				rte_exit(EXIT_FAILURE, "Error with outbound chan configuration\n");
			mask &= ~RTE_BIT64(virtio_devid);
			if (!mask) {
				base += 64;
				mask = virtio_mask_ena[1];
			}
		}

		if (rte_dma_start(dma_devid) != 0)
			rte_exit(EXIT_FAILURE, "Error with rte_dma_start()\n");
		mem2dev_ids[mem2dev_cnt++] = dma_devid;
		dma_devid++;
	}

	if (!dev2mem_cnt || !mem2dev_cnt)
		rte_exit(EXIT_FAILURE, "Not enough dma devices for workers\n");

	dev2mem_idx = 0;
	mem2dev_idx = 0;

	/* Provide DMA devices for virtio control */
	if (dao_dma_ctrl_dev_set(dev2mem_ids[dev2mem_idx++], mem2dev_ids[mem2dev_idx++]))
		rte_exit(EXIT_FAILURE, "Failed to set virtio control DMA dev\n");

	/* Setup two DMA devices per active DPDK lcore */
	APP_INFO("Lcore DMA map...\n");
	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		if (rte_lcore_is_enabled(lcore_id) == 0)
			continue;
		qconf = &lcore_conf[lcore_id];

		/* Skip Lcore if not needed */
		if (!qconf->nb_blkdev && !qconf->service_lcore)
			continue;

		if (dev2mem_idx == dev2mem_cnt || mem2dev_idx == mem2dev_cnt)
			rte_exit(EXIT_FAILURE, "Not enough dma devices for workers\n");

		/* Assign DMA device id */
		qconf->dev2mem_id = dev2mem_ids[dev2mem_idx++];
		qconf->mem2dev_id = mem2dev_ids[mem2dev_idx++];
		qconf->nb_vchans = nb_virtio_blkdevs;

		APP_INFO("\tlcore %u ... dev2mem=%u mem2dev=%u\n", lcore_id, qconf->dev2mem_id,
			 qconf->mem2dev_id);
	}
	APP_INFO("\n");
}

static void
setup_pem_device(void)
{
	struct dao_pem_dev_conf pem_dev_conf;
	int rc;

	/* Setup pem0 */
	memset(&pem_dev_conf, 0, sizeof(pem_dev_conf));
	rc = dao_pem_dev_init(pem_devid, &pem_dev_conf);
	if (rc)
		rte_exit(EXIT_FAILURE, "Error with pem init, rc=%d\n", rc);
}

static void
setup_virtio_devices(void)
{
	struct dao_virtio_blkdev_cbs cbs;
	uint16_t virtio_devid;
	int rc;

	APP_INFO("\n");

	/* Setup Virtio devices */
	for (virtio_devid = 0; virtio_devid < DAO_VIRTIO_DEV_MAX; virtio_devid++) {
		struct dao_virtio_blkdev_conf conf;
		struct dao_blkdev_conf bd_conf;

		if (!is_virtio_dev_enabled(virtio_devid))
			continue;

		/* Populate blkdev conf */
		memset(&conf, 0, sizeof(conf));

		if (per_dev_pool)
			conf.pool = v_extmbuf_pool[virtio_devid];
		else
			conf.pool = v_extmbuf_pool[0];
		conf.dma_vchan = virtio_blkdev_dma_vchans[virtio_devid];
		conf.capacity = blkdev_conf[virtio_devid].capacity;
		conf.blk_size = blkdev_conf[virtio_devid].blk_size;
		conf.seg_size_max = MAX_SEG_SIZE;
		conf.seg_max = MAX_SEGS;
		conf.auto_free_en = virtio_blkdev_autofree;
		conf.pem_devid = pem_devid;
		conf.feat_bits = RAMDISK_FEATURE_BITS;
		conf.max_virt_queues = blkdev_conf[virtio_devid].max_queues;

		bd_conf.capacity = blkdev_conf[virtio_devid].capacity;
		bd_conf.blk_size = blkdev_conf[virtio_devid].blk_size;

		/* Register blk device ops with doa blk library */
		rc = dao_blkdev_create(virtio_devid, &bd_conf, blkdev_conf[virtio_devid].name);
		if (rc)
			rte_exit(EXIT_FAILURE, "Failed to register block device ops\n");

		/* Initialize virtio blk device */
		rc = dao_virtio_blkdev_init(virtio_devid, &conf);
		if (rc)
			rte_exit(EXIT_FAILURE, "Failed to init virtio device\n");
	}

	memset(&cbs, 0, sizeof(cbs));
	cbs.status_cb = virtio_dev_status_cb;
	cbs.extbuf_get = virtio_blkdev_extbuf_get;
	cbs.extbuf_put = virtio_blkdev_extbuf_put;
	/* Register virtio dev callback register */
	dao_virtio_blkdev_cb_register(&cbs);

	APP_INFO("\n");
	for (virtio_devid = 0; virtio_devid < DAO_VIRTIO_DEV_MAX; virtio_devid++) {
		if (!is_virtio_dev_enabled(virtio_devid))
			continue;

		APP_INFO("LCORE_MAP: virtiodev[%u] (lcores 0x%lX)\n", virtio_devid,
			 blkdev_conf[virtio_devid].lcore_mask);
	}
}

static void
release_virtio_devices(void)
{
	uint32_t virtio_devid;
	int rc;

	/* Close virtio devices */
	for (virtio_devid = 0; virtio_devid < DAO_VIRTIO_DEV_MAX; virtio_devid++) {
		if (!is_virtio_dev_enabled(virtio_devid))
			continue;

		rc = dao_virtio_blkdev_fini(virtio_devid);
		if (rc)
			APP_ERR("Failed to stop virtio device %u: %s\n", virtio_devid,
				rte_strerror(-rc));
	}
}

static void
release_blkdevs(void)
{
	uint32_t virtio_devid;
	int rc;

	/* Close block devices */
	for (virtio_devid = 0; virtio_devid < DAO_VIRTIO_DEV_MAX; virtio_devid++) {
		if (!is_virtio_dev_enabled(virtio_devid))
			continue;

		rc = dao_blkdev_destroy(virtio_devid);
		if (rc)
			APP_ERR("Failed to stop block device %u: %s\n", virtio_devid,
				rte_strerror(-rc));
	}
}

static void
release_pem_device(void)
{
	/* Close PEM */
	dao_pem_dev_fini(pem_devid);
}

static void
release_dma_devices(void)
{
	int16_t dma_devid;
	int rc;

	/* stop DMA devices */
	RTE_DMA_FOREACH_DEV(dma_devid)
	{
		rc = rte_dma_stop(dma_devid);
		if (rc)
			APP_ERR("Failed to stop dma dev %u: %s\n", dma_devid, rte_strerror(-rc));

		rc = rte_dma_close(dma_devid);
		if (rc)
			APP_ERR("Failed to close dma dev %u: %s\n", dma_devid, rte_strerror(-rc));
	}
}

int
main(int argc, char **argv)
{
	bool service_lcore_flag = false;
	struct lcore_conf *qconf;
	uint32_t lcore_id;
	size_t sz;
	int rc;

	/* Init EAL */
	rc = rte_eal_init(argc, argv);
	if (rc < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL parameters\n");
	argc -= rc;
	argv += rc;

	force_quit = false;
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	/* Parse application arguments (after the EAL ones) */
	rc = parse_args(argc, argv);
	if (rc < 0)
		rte_exit(EXIT_FAILURE, "Invalid VIRTIO_L2FWD parameters\n");

	if (check_lcore_params() < 0)
		rte_exit(EXIT_FAILURE, "check_lcore_params() failed\n");

	rc = init_lcore_virtio_dev();
	if (rc < 0)
		rte_exit(EXIT_FAILURE, "init_lcore_virtio_dev() failed\n");

	if (check_virtio_config() < 0)
		rte_exit(EXIT_FAILURE, "check_virtio_config() failed\n");

	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		if (rte_lcore_is_enabled(lcore_id) == 0 || lcore_id == rte_get_main_lcore())
			continue;

		/* Pick one non FP lcore for misc */
		if (lcore_conf[lcore_id].nb_blkdev == 0) {
			lcore_conf[lcore_id].service_lcore = true;
			service_lcore_flag = true;
			break;
		}
	}

	if (!service_lcore_flag)
		rte_exit(EXIT_FAILURE, "LCORE not available for service lcore\n");

	/* Alloc mempools */
	setup_mempools();

	/* Initialize DMA devices */
	setup_dma_devices();

	/* Initialize PEM device */
	setup_pem_device();

	/* Setup RCU QSBR variable */
	sz = rte_rcu_qsbr_get_memsize(RTE_MAX_LCORE);
	qs_v = (struct rte_rcu_qsbr *)rte_zmalloc_socket(NULL, sz, RTE_CACHE_LINE_SIZE,
							 SOCKET_ID_ANY);
	if (!qs_v)
		rte_exit(EXIT_FAILURE, "Failed to alloc rcu_qsbr variable\n");

	rc = rte_rcu_qsbr_init(qs_v, RTE_MAX_LCORE);
	if (rc)
		rte_exit(EXIT_FAILURE, "rte_rcu_qsbr_init(): failed to init, rc=%d\n", rc);

	/* Initialize virtio devices */
	setup_virtio_devices();

	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		qconf = &lcore_conf[lcore_id];

		if (rte_lcore_is_enabled(lcore_id) == 0)
			continue;

		/* Skip Lcore if not needed */
		if (!qconf->nb_blkdev && !qconf->service_lcore)
			continue;

		qconf->qs_v = qs_v;
	}

	APP_INFO("\n");

	/* Launch per-lcore init on every worker lcore */
	RTE_LCORE_FOREACH_WORKER(lcore_id)
	{
		qconf = &lcore_conf[lcore_id];
		if (qconf->service_lcore)
			rte_eal_remote_launch(service_main_loop, NULL, lcore_id);
		else if (qconf->nb_blkdev)
			rte_eal_remote_launch(worker_main_loop, NULL, lcore_id);
	}

	/* Wait for worker cores to exit */
	rc = 0;
	RTE_LCORE_FOREACH_WORKER(lcore_id)
	{
		rc = rte_eal_wait_lcore(lcore_id);
	}

	/* Close virtio devices */
	release_virtio_devices();

	/*block device destroy */
	release_blkdevs();

	/* Close dma devices */
	release_dma_devices();

	/* Close pem device */
	release_pem_device();

	/* clean up the EAL */
	rte_eal_cleanup();
	APP_INFO("Bye...\n");

	return rc;
}
