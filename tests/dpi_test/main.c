/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <setjmp.h>
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

#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_debug.h>
#include <rte_dmadev.h>
#include <rte_eal.h>
#include <rte_interrupts.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_mbuf_pool_ops.h>
#include <rte_memcpy.h>
#include <rte_memory.h>
#include <rte_mempool.h>
#include <rte_per_lcore.h>
#include <rte_prefetch.h>
#include <rte_random.h>

#define DPI_MAX_DATA_SZ_PER_PTR 16777216 /* 65535 */
#define DPI_NB_DESCS            1024
#define DPI_BURST_REQ           64
#define DPI_MAX_VFS             32
#define MAX_POINTERS            15

#define RING_OFF(x)    ((x) & (DPI_BURST_REQ - 1))
#define DESC_DATA_SIZE (sizeof(cmd_t))
#define RING_DATA_SIZE (DPI_BURST_REQ * DESC_DATA_SIZE)

static volatile bool force_quit;

static char tranfer_type[3][32] = {"Internal-only", "Inbound", "Outbound"};

struct dpi_test_dev_s {
	int dev_id;
	struct rte_dma_info dev_info;
	struct rte_dma_vchan_conf vchan_conf[4];
};

struct dpi_test_dev_s dpi_test[DPI_MAX_VFS];
rte_iova_t raddr = 0, laddr;
int mode, n_iter = 1, perf_mode = 0;
int ptrs_per_instr = 1;
int burst_size = 64;
uint16_t done_count = 8;
uint16_t nb_ports;
uint16_t pem_id;
uint64_t data_size = 128;

uint64_t dma_submit_cnt[DPI_MAX_VFS] = {0};
uint64_t last_dma_submit_cnt[DPI_MAX_VFS] = {0};
uint64_t desc_submit_cnt[DPI_MAX_VFS] = {0};
uint64_t last_desc_submit_cnt[DPI_MAX_VFS] = {0};
uint64_t compl_submit_cnt[DPI_MAX_VFS] = {0};
uint64_t last_compl_submit_cnt[DPI_MAX_VFS] = {0};
uint64_t total_dma_cnt;
static uint64_t timer_period = 1; /* default period is 1 seconds */
FILE *stats_fp;
char stats_file_name[256] = "/dpi_perf_num.txt";
int dump_to_file;
uint64_t cc_head[DPI_MAX_VFS], cf_head[DPI_MAX_VFS], cc_tail[DPI_MAX_VFS], cf_tail[DPI_MAX_VFS];
uint64_t last_desc_avail[DPI_MAX_VFS], desc_avail[DPI_MAX_VFS], compl_idx[DPI_MAX_VFS];
uint64_t req_compl[DPI_MAX_VFS], last_req_compl[DPI_MAX_VFS];
typedef struct {
	uint64_t pkt_ptr;
	uint64_t metadata;
} dcmd_t;

typedef struct {
	dcmd_t d[16];
} cmd_t;

cmd_t *cmd_buf[DPI_MAX_VFS];
uint64_t *compl_buf[DPI_MAX_VFS];

static void
signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		printf("\n\nSignal %d received, preparing to exit...\n", signum);
		force_quit = true;
	}
}

static uint8_t
buffer_fill(uint8_t *addr, int len, uint8_t val)
{
	int j = 0;

	memset(addr, 0, len);
	for (j = 0; j < len; j++)
		*(addr + j) = val++;

	return val;
}

static inline void
dump_buffer(uint8_t *addr, int len)
{
	int i;

	for (i = 0; i < len; i++) {
		if (!i || (i % 16) == 0)
			printf("\n%04x ", i);
		printf("%02x ", addr[i]);
	}
	printf("\n");
}

static inline void
dump_stats(void)
{
	static int iter = 1;
	int i, np = nb_ports - 1;
	uint64_t tot = 0, d_cnt = 0, c_cnt, cnt[2] = {0, 0};

	d_cnt = (desc_submit_cnt[0] - last_desc_submit_cnt[0]);
	c_cnt = (compl_submit_cnt[0] - last_compl_submit_cnt[0]);
	last_desc_submit_cnt[0] = desc_submit_cnt[0];
	last_compl_submit_cnt[0] = compl_submit_cnt[0];

	if (++iter == n_iter)
		force_quit = 1;

	if (mode == 3)
		goto hybrid;

	for (i = 1; i < nb_ports; i++) {
		cnt[0] += (dma_submit_cnt[i] - last_dma_submit_cnt[i]);
		tot += dma_submit_cnt[i];
		last_dma_submit_cnt[i] = dma_submit_cnt[i];
	}
	if (dump_to_file) {
		fprintf(stats_fp,
			"Size %ld Segs %d Cores %d Desc %2.2f Gbps Compl %2.2f Gbps %s PPS %ld "
			"%2.2f Gbps\n",
			data_size, ptrs_per_instr, np,
			(d_cnt * ptrs_per_instr * 16 * 8) / 1000000000.0,
			(c_cnt * 64) / 1000000000.0, (mode == 1) ? "Inb" : "Out", cnt[0],
			(cnt[0] * data_size * ptrs_per_instr * 8) / 1000000000.0);
		fprintf(stats_fp, "\ntot %ld tot_dma %ld Total: %ld Perf:%2.2f Gbps\n", tot,
			total_dma_cnt, (tot - total_dma_cnt),
			((tot - total_dma_cnt) * data_size * ptrs_per_instr * 8) / 1000000000.0);
	} else {
		printf("Size %ld Segs %d Cores %d Desc %2.2f Gbps Compl %2.2f Gbps %s PPS %ld "
		       "%2.2f Gbps\n",
		       data_size, ptrs_per_instr, np,
		       (d_cnt * ptrs_per_instr * 16 * 8) / 1000000000.0,
		       (c_cnt * 64) / 1000000000.0, (mode == 1) ? "Inb" : "Out", cnt[0],
		       (cnt[0] * data_size * ptrs_per_instr * 8) / 1000000000.0);
		printf("\ntot %ld tot_dma %ld Total: %ld Perf:%2.2f Gbps\n", tot, total_dma_cnt,
		       (tot - total_dma_cnt),
		       ((tot - total_dma_cnt) * data_size * ptrs_per_instr * 8) / 1000000000.0);
	}

	total_dma_cnt = tot;
	return;
hybrid:
	for (i = 1; i < nb_ports; i++) {
		cnt[i % 2] += (dma_submit_cnt[i] - last_dma_submit_cnt[i]);
		tot += dma_submit_cnt[i];
		last_dma_submit_cnt[i] = dma_submit_cnt[i];
	}
	if (dump_to_file) {
		fprintf(stats_fp,
			"Size %ld Segs %d Cores %d Desc %2.2f Gbps Compl %2.2f Gbps Inb PPS %ld "
			"%2.2f Gbps Out PPS %ld %2.2f Gbps\n",
			data_size, ptrs_per_instr, np,
			(d_cnt * ptrs_per_instr * 16 * 8) / 1000000000.0,
			(c_cnt * 64) / 1000000000.0, cnt[0],
			(cnt[0] * data_size * ptrs_per_instr * 8) / 1000000000.0, cnt[1],
			(cnt[1] * data_size * ptrs_per_instr * 8) / 1000000000.0);
		fprintf(stats_fp, "\ntot %ld tot_dma %ld Total: %ld Perf:%2.2f Gbps\n", tot,
			total_dma_cnt, (tot - total_dma_cnt),
			((tot - total_dma_cnt) * data_size * ptrs_per_instr * 8) / 1000000000.0);
	} else {
		printf("Size %ld Segs %d Cores %d Desc %2.2f Gbps Compl %2.2f Gbps Inb PPS %ld "
		       "%2.2f Gbps Out PPS %ld %2.2f Gbps\n",
		       data_size, ptrs_per_instr, np,
		       (d_cnt * ptrs_per_instr * 16 * 8) / 1000000000.0,
		       (c_cnt * 64) / 1000000000.0, cnt[0],
		       (cnt[0] * data_size * ptrs_per_instr * 8) / 1000000000.0, cnt[1],
		       (cnt[1] * data_size * ptrs_per_instr * 8) / 1000000000.0);
		printf("\ntot %ld tot_dma %ld Total: %ld Perf:%2.2f Gbps\n", tot, total_dma_cnt,
		       (tot - total_dma_cnt),
		       ((tot - total_dma_cnt) * data_size * ptrs_per_instr * 8) / 1000000000.0);
	}

	total_dma_cnt = tot;
}

static inline int
dma_test_rw_commands(void)
{
	unsigned int dma_port = rte_lcore_id() - 1;
	int ret = 0, i, j, cnt;
	const int dsize = ptrs_per_instr * 16;
	struct rte_dma_vchan_conf *desc_vconf;
	struct rte_dma_vchan_conf *compl_vconf;
	uint8_t num_req[DPI_MAX_VFS];
	uint8_t *desc_base[DPI_MAX_VFS];
	uint8_t *compl_base[DPI_MAX_VFS];
	uint64_t *compl_ptr;
	struct rte_dma_sge ring_src[DPI_BURST_REQ][MAX_POINTERS];
	struct rte_dma_sge ring_dst[DPI_BURST_REQ][MAX_POINTERS];
	uint64_t prev_tsc = 0, diff_tsc = 0, cur_tsc = 0;
	uint16_t nb_done = 0, last_idx = 0, d_last_idx = 0, desc_done, compl_done;
	bool dma_error = false;

	printf("dma_port %d nb_ports %d\n", dma_port, nb_ports);

	for (j = 1; j < nb_ports; j++) {
		desc_base[j] = (uint8_t *)raddr + (j * 0x8000000ull);
		compl_base[j] = (uint8_t *)raddr + (j * 0x8000000ull) + 0x10000ull;
		printf("DMA port %d desc_base %p compl_base %p\n", j, desc_base[j], compl_base[j]);
		desc_avail[j] = 0x0ull;
		req_compl[j] = 0x0ull;
		compl_idx[j] = 0x0ull;
		cmd_buf[j] = (cmd_t *)rte_malloc("cmd_block", RING_DATA_SIZE, 128);
		if (!cmd_buf[j]) {
			printf("Unable to allocate command memory\n");
			return -ENOMEM;
		}
		compl_buf[j] = (uint64_t *)rte_malloc("compl_block", (DPI_BURST_REQ * 8), 128);
		if (!compl_buf[j]) {
			printf("Unable to allocate completion memory\n");
			return -ENOMEM;
		}
		compl_ptr = (uint64_t *)compl_buf[j];
		for (i = 0; i < DPI_BURST_REQ; i++)
			compl_ptr[i] = 0x1ull;
	}
	desc_vconf = &dpi_test[dma_port].vchan_conf[0];
	desc_vconf->direction = RTE_DMA_DIR_DEV_TO_MEM; /* Always Inbound to fetch pkt pointers */
	desc_vconf->nb_desc = DPI_NB_DESCS;
	desc_vconf->src_port.port_type = RTE_DMA_PORT_PCIE;
	desc_vconf->src_port.pcie.coreid = pem_id;

	compl_vconf = &dpi_test[dma_port].vchan_conf[1];
	compl_vconf->direction = RTE_DMA_DIR_MEM_TO_DEV; /* Always Inbound to fetch pkt pointers */
	compl_vconf->nb_desc = DPI_NB_DESCS;
	compl_vconf->dst_port.port_type = RTE_DMA_PORT_PCIE;
	compl_vconf->dst_port.pcie.coreid = pem_id;

	ret = rte_dma_vchan_setup(dma_port, 0, desc_vconf);
	if (ret < 0) {
		printf("DMA descriptor vchan setup failed with err %d\n", ret);
		goto free_buf;
	}

	ret = rte_dma_vchan_setup(dma_port, 1, compl_vconf);
	if (ret < 0) {
		printf("DMA completion vchan setup failed with err %d\n", ret);
		goto free_buf;
	}

	rte_dma_start(dma_port);

	/* First fetch all descriptors */
	for (j = 1; j < nb_ports; j++) {
		/* Do Inbound to get remote addresses from host ring */
		uint8_t *ring = desc_base[j] + (RING_OFF(desc_avail[j]) * dsize);

		ring_src[0][0].addr = (rte_iova_t)ring;
		ring_src[0][0].length = (burst_size * dsize);
		ring_dst[0][0].addr = (rte_malloc_virt2iova)(cmd_buf[j]);
		ring_dst[0][0].length = (burst_size * dsize);
		ret = rte_dma_copy_sg(dma_port, 0, ring_src[0], ring_dst[0], 1, 1,
				      RTE_DMA_OP_FLAG_SUBMIT);
		if (ret < 0) {
			printf("dmadev copy ring pointer failed, ret=%d\n", ret);
			goto free_buf;
		}
		do {
			if (unlikely(force_quit)) {
				printf("dma_port %d quitting.\n", dma_port);
				sleep(3);
				goto free_buf;
			}

			nb_done = rte_dma_completed(dma_port, 0, 1, &last_idx, &dma_error);
			if (nb_done == 1) {
				desc_submit_cnt[dma_port] += nb_done;
				break;
			}
		} while (1);
		desc_avail[j] = burst_size;
		last_desc_avail[j] = burst_size;
	}

	do {
		cnt = 0;
		if (unlikely(dma_port == rte_get_main_lcore())) {
			cur_tsc = rte_rdtsc();
			diff_tsc = cur_tsc - prev_tsc;
			if ((timer_period > 0) && (diff_tsc > timer_period)) {
				dump_stats();
				prev_tsc = cur_tsc;
			}
		}

		if (unlikely(force_quit)) {
			printf("dma_port %d quitting.\n", dma_port);
			sleep(3);
			goto free_buf;
		}
		for (j = 1; j < nb_ports; j++) {
			uint16_t off = RING_OFF(desc_avail[j]), rcnt, csize;
			uint8_t *ring = desc_base[j] + (off * dsize);
			rte_iova_t cmd_ptr = rte_malloc_virt2iova(cmd_buf[j]);
			uint64_t req_cnt = req_compl[j];

			num_req[j] = 0;
			/* Fetch for new request and submit the completions */
			if (req_cnt <= last_req_compl[j])
				continue;

			num_req[j] = req_cnt - last_req_compl[j];
			cmd_ptr += (off * dsize);
			last_req_compl[j] += num_req[j];

			rcnt = (off + num_req[j]) > burst_size ? (burst_size - off) : num_req[j];
			ring_src[0][0].addr = (rte_iova_t)ring;
			ring_src[0][0].length = (rcnt * dsize);
			ring_dst[0][0].addr = cmd_ptr;
			ring_dst[0][0].length = (rcnt * dsize);
			ret = rte_dma_copy_sg(dma_port, 0, ring_src[0], ring_dst[0], 1, 1,
					      RTE_DMA_OP_FLAG_SUBMIT);
			if (ret < 0) {
				printf("dmadev copy ring pointer failed, ret=%d\n", ret);
				goto free_buf;
			}

			ring = compl_base[j] + (RING_OFF(compl_idx[j]) << 3);
			cmd_ptr = rte_malloc_virt2iova(compl_buf[j]);
			cmd_ptr += (off << 3);

			csize = (rcnt << 3);
			if (j % 2)
				csize = (rcnt * ptrs_per_instr) << 4;
			ring_dst[0][0].addr = (rte_iova_t)ring;
			ring_dst[0][0].length = csize;
			ring_src[0][0].addr = cmd_ptr;
			ring_src[0][0].length = csize;
			ret = rte_dma_copy_sg(dma_port, 1, ring_src[0], ring_dst[0], 1, 1,
					      RTE_DMA_OP_FLAG_SUBMIT);
			if (ret < 0) {
				printf("dmadev copy ring pointer failed, ret=%d\n", ret);
				goto free_buf;
			}
			rcnt = num_req[j] - rcnt;
			cnt++;
			/* Submit one more DMA to handle wrap case */
			if (rcnt) {
				ring_src[0][0].addr = (rte_iova_t)desc_base[j];
				ring_src[0][0].length = (rcnt * dsize);
				ring_dst[0][0].addr = (rte_malloc_virt2iova)(cmd_buf[j]);
				ring_dst[0][0].length = (rcnt * dsize);
				ret = rte_dma_copy_sg(dma_port, 0, ring_src[0], ring_dst[0], 1, 1,
						      RTE_DMA_OP_FLAG_SUBMIT);
				if (ret < 0) {
					printf("dmadev copy ring pointer failed, ret=%d\n", ret);
					goto free_buf;
				}
				csize = (rcnt << 3);
				if (j % 2)
					csize = (rcnt * ptrs_per_instr) << 4;
				ring_dst[0][0].addr = (rte_iova_t)compl_base[j];
				ring_dst[0][0].length = csize;
				ring_src[0][0].addr = (rte_malloc_virt2iova)(compl_buf[j]);
				ring_src[0][0].length = csize;
				ret = rte_dma_copy_sg(dma_port, 1, ring_src[0], ring_dst[0], 1, 1,
						      RTE_DMA_OP_FLAG_SUBMIT);
				if (ret < 0) {
					printf("dmadev copy ring pointer failed, ret=%d\n", ret);
					goto free_buf;
				}
				cnt++;
			}
		}
		desc_done = 0;
		compl_done = 0;
		do {
			if (unlikely(force_quit)) {
				printf("dma_port %d quitting. cnt %d\n", dma_port, cnt);
				sleep(3);
				goto free_buf;
			}

			desc_done += rte_dma_completed(dma_port, 0, cnt, &last_idx, &dma_error);
			compl_done += rte_dma_completed(dma_port, 1, cnt, &d_last_idx, &dma_error);
		} while (!((desc_done == cnt) && (compl_done == cnt)));
		for (j = 1; j < nb_ports; j++) {
			compl_submit_cnt[dma_port] += num_req[j];
			desc_submit_cnt[dma_port] += num_req[j];
			desc_avail[j] += num_req[j];
			compl_idx[j] += num_req[j];
		}
	} while (1);

free_buf:
	printf("freeing buffers\n");
	for (j = 1; j < nb_ports; j++) {
		if (cmd_buf[j])
			rte_free(cmd_buf[j]);
		if (compl_buf[j])
			rte_free(compl_buf[j]);
	}

	return 0;
}

static inline int
dma_test_xfer_perf(void)
{
	int ret = 0, vchan = 0, i, j;
	struct rte_dma_vchan_conf *vconf;
	unsigned int dma_port = rte_lcore_id() - 1;
	uint8_t num_req, max_ptr = ptrs_per_instr;
	uint8_t *fptr[DPI_BURST_REQ][MAX_POINTERS];
	uint8_t *lptr[DPI_BURST_REQ][MAX_POINTERS];
	uint64_t *cmd_ptr;
	rte_iova_t src_ptr;
	rte_iova_t dst_ptr;
	struct rte_dma_sge src[DPI_BURST_REQ][MAX_POINTERS], dst[DPI_BURST_REQ][MAX_POINTERS];
	int xfer_mode, direction;
	uint16_t nb_done = 0, last_idx = 0, off = 0, rcnt, num_desc;
	bool dma_error = false;
	uint64_t desc_cnt;

	printf("dma_port %d nb_ports %d\n", dma_port, nb_ports);
	if (nb_ports < 2) {
		printf("At least two DMA ports needed to continue\n");
		return 0;
	}
	if ((mode == 3) && nb_ports < 3) {
		printf("At least three DMA ports needed to continue dual mode\n");
		return 0;
	}
	if (!dma_port)
		return dma_test_rw_commands();

	/* If lcore >= nb_ports skip processing */
	if (dma_port >= nb_ports)
		return 0;

	/* for dual mode use even ports for inbound DMA
	 * and odd ports for outbound DMA
	 */
	if (mode == 3)
		xfer_mode = (dma_port % 2) ? 2 : 1;
	else
		xfer_mode = mode;

	if (xfer_mode == 1)
		direction = RTE_DMA_DIR_DEV_TO_MEM;
	else if (xfer_mode == 2)
		direction = RTE_DMA_DIR_MEM_TO_DEV;
	else
		direction = RTE_DMA_DIR_MEM_TO_MEM;

	printf("dma_port %d, mode %d, xmode %d dir %d\n", dma_port, mode, xfer_mode, direction);

	vconf = &dpi_test[dma_port].vchan_conf[0];
	vconf->direction = direction;
	vconf->nb_desc = DPI_NB_DESCS;

	switch (direction) {
	/* outbound */
	case RTE_DMA_DIR_MEM_TO_DEV:
		vconf->dst_port.port_type = RTE_DMA_PORT_PCIE;
		vconf->dst_port.pcie.coreid = pem_id;
		break;
	/* inbound */
	case RTE_DMA_DIR_DEV_TO_MEM:
		vconf->src_port.port_type = RTE_DMA_PORT_PCIE;
		vconf->src_port.pcie.coreid = pem_id;
		break;
	/* internal_only */
	case RTE_DMA_DIR_MEM_TO_MEM:
		break;
	};

	vchan = rte_dma_vchan_setup(dma_port, vchan, vconf);
	if (vchan < 0) {
		ret = vchan;
		printf("DMA vchan setup failed with err %d\n", ret);
		goto free_buf;
	}
	rte_dma_start(dma_port);

	do {
		sleep(1);
	} while ((int)desc_avail[dma_port] != burst_size);

	cmd_ptr = (uint64_t *)(&cmd_buf[dma_port][0]);
	/* Alloc ptrs */
	for (i = 0; i < burst_size; i++) {
		for (j = 0; j < max_ptr; j++) {
			fptr[i][j] = (uint8_t *)rte_malloc("xfer_block", data_size, 128);
			if (!fptr[i][j]) {
				printf("Unable to allocate internal memory\n");
				return -ENOMEM;
			}
			buffer_fill(fptr[i][j], data_size, 0);
			src_ptr = rte_malloc_virt2iova(fptr[i][j]);

			/* alloc for internal-only DMA */
			if (!xfer_mode) {
				lptr[i][j] = (uint8_t *)rte_malloc("xfer_block", data_size, 128);
				if (!lptr[i][j]) {
					printf("Unable to allocate internal memory\n");
					return -ENOMEM;
				}
				buffer_fill(lptr[i][j], data_size, 0);
				dst_ptr = rte_malloc_virt2iova(lptr[i][j]);
			} else {
				lptr[i][j] = (uint8_t *)*(cmd_ptr + (j << 1));
				dst_ptr = src_ptr;
			}

			switch (direction) {
			/* outbound */
			case RTE_DMA_DIR_MEM_TO_DEV:
				src[i][j].addr = src_ptr;
				src[i][j].length = data_size;
				dst[i][j].addr = (rte_iova_t)lptr[i][j];
				dst[i][j].length = data_size;
				break;
			/* inbound */
			case RTE_DMA_DIR_DEV_TO_MEM:
				src[i][j].addr = (rte_iova_t)lptr[i][j];
				src[i][j].length = data_size;
				dst[i][j].addr = dst_ptr;
				dst[i][j].length = data_size;
				break;
			/* internal_only */
			case RTE_DMA_DIR_MEM_TO_MEM:
				src[i][j].addr = src_ptr;
				src[i][j].length = data_size;

				dst[i][j].addr = dst_ptr;
				dst[i][j].length = data_size;
				break;
			};
		}
		/* Skip meata data words along packet pointers */
		cmd_ptr += (max_ptr << 1);
	}

	for (i = 0; i < burst_size; i++) {
		ret = rte_dma_copy_sg(dma_port, vchan, src[i], dst[i], max_ptr, max_ptr,
				      RTE_DMA_OP_FLAG_SUBMIT);
		if (ret < 0) {
			printf("dmadev copy op failed, ret=%d\n", ret);
			goto free_buf;
		}
	}
	num_req = i;

	do {
		if (unlikely(force_quit)) {
			printf("dma_port %d quitting.\n", dma_port);
			sleep(3);
			goto free_buf;
		}

		nb_done = 0;
		nb_done = rte_dma_completed(dma_port, vchan, num_req, &last_idx, &dma_error);

		dma_submit_cnt[dma_port] += nb_done;
		req_compl[dma_port] += nb_done;
		desc_cnt = desc_avail[dma_port];
		off = RING_OFF(desc_cnt);

		/* Fetch for new request and submit the completions */
		if (desc_cnt <= last_desc_avail[dma_port])
			continue;

		num_desc = desc_cnt - last_desc_avail[dma_port];

		rcnt = (off + num_desc) > burst_size ? (burst_size - off) : num_desc;
		cmd_ptr = (uint64_t *)(&cmd_buf[dma_port][0]);
		cmd_ptr += (off * (max_ptr << 1));
		for (i = 0; i < rcnt; i++) {
			for (j = 0; j < max_ptr; j++)
				if (direction == RTE_DMA_DIR_DEV_TO_MEM)
					src[i][j].addr = (rte_iova_t)*(cmd_ptr + (j << 1));
				else if (direction == RTE_DMA_DIR_MEM_TO_DEV)
					dst[i][j].addr = (rte_iova_t)*(cmd_ptr + (j << 1));
			cmd_ptr += (max_ptr << 1);
		}
		if (rcnt != num_desc) {
			cmd_ptr = (uint64_t *)(&cmd_buf[dma_port][0]);
			for (i = rcnt; i < num_desc; i++) {
				for (j = 0; j < max_ptr; j++)
					if (direction == RTE_DMA_DIR_DEV_TO_MEM)
						src[i][j].addr =
							(rte_iova_t)*(cmd_ptr + (j << 1));
					else if (direction == RTE_DMA_DIR_MEM_TO_DEV)
						dst[i][j].addr =
							(rte_iova_t)*(cmd_ptr + (j << 1));
				cmd_ptr += (max_ptr << 1);
			}
		}
		for (i = 0; i < num_desc; i++) {
			ret = rte_dma_copy_sg(dma_port, vchan, src[i], dst[i], max_ptr, max_ptr, 0);
			if (ret < 0) {
				printf("dmadev copy_sg op failed, ret=%d\n", ret);
				force_quit = 1;
				sleep(3);
				dump_stats();
				goto free_buf;
			}
		}
		rte_dma_submit(dma_port, vchan);
		last_desc_avail[dma_port] += num_desc;
	} while (1);

free_buf:
	printf("dma_port %d freeing memory.\n", dma_port);
	for (i = 0; i < burst_size; i++) {
		for (j = 0; j < max_ptr; j++) {
			if (fptr[i][j])
				rte_free(fptr[i][j]);
			if (!xfer_mode && lptr[i][j])
				rte_free(lptr[i][j]);
		}
	}

	return 0;
}

static inline int
dma_test_mstream_tx(int dma_port, int buf_size, int direction)
{
	uint8_t *fptr[2];
	rte_iova_t alloc_ptr[2];
	rte_iova_t src = 0, dst = 0;
	int ret = 0, vchan = 0, i, retries = 10;
	struct rte_dma_vchan_conf *vconf;
	enum rte_dma_status_code status;
	char *xfer_str;

	printf("--dma_port %d-- raddr %lx\n", dma_port, raddr);

	while (!raddr) {
		usleep(1);
		printf("raddr : %lx\n", raddr);
	}

	for (i = 0; i < 2; i++) {
		fptr[i] = (uint8_t *)rte_malloc("xfer_block", buf_size, 128);
		if (!fptr[i]) {
			printf("Unable to allocate internal memory\n");
			return -ENOMEM;
		}
		memset(fptr[i], 0, buf_size);
		alloc_ptr[i] = rte_malloc_virt2iova(fptr[i]);
	}

	vconf = &dpi_test[dma_port].vchan_conf[0];
	vconf->direction = direction;
	vconf->nb_desc = 1;

	switch (direction) {
	/* outbound */
	case RTE_DMA_DIR_MEM_TO_DEV:
		buffer_fill(fptr[0], buf_size, 0);
		vconf->dst_port.port_type = RTE_DMA_PORT_PCIE;
		vconf->dst_port.pcie.coreid = pem_id;
		src = alloc_ptr[0];
		dst = raddr;
		xfer_str = tranfer_type[2];
		break;
	/* inbound */
	case RTE_DMA_DIR_DEV_TO_MEM:
		vconf->src_port.port_type = RTE_DMA_PORT_PCIE;
		vconf->src_port.pcie.coreid = pem_id;
		src = raddr;
		dst = alloc_ptr[0];
		xfer_str = tranfer_type[1];
		break;
	/* internal_only */
	case RTE_DMA_DIR_MEM_TO_MEM:
		buffer_fill(fptr[0], buf_size, 0);
		src = alloc_ptr[0];
		dst = raddr;
		xfer_str = tranfer_type[0];
		break;
	default:
		printf("wrong direction %d selected\n", direction);
		return -EINVAL;
	};

	vchan = rte_dma_vchan_setup(dma_port, vchan, vconf);
	if (vchan < 0) {
		ret = vchan;
		printf("DMA vchan setup failed with err %d\n", ret);
		goto free_buf;
	}

	rte_dma_start(dma_port);
	ret = rte_dma_copy(dma_port, vchan, src, dst, buf_size, RTE_DMA_OP_FLAG_SUBMIT);
	if (ret < 0) {
		printf("dmadev copy op failed, ret=%d\n", ret);
		goto free_buf;
	}

	do {
		// sleep(1);
		rte_delay_us_sleep(10);
		rte_dma_completed_status(dma_port, vchan, 1, NULL, &status);
		if (!status || !retries || force_quit)
			break;
		retries--;
	} while (1);

	if (status)
		printf("%s DMA transfer failed, status = %d\n", xfer_str, status);
	else
		printf("%s DMA transfer success\n", xfer_str);

	rte_dma_stop(dma_port);

free_buf:
	for (i = 0; i < 2; i++) {
		if (fptr[i])
			rte_free(fptr[i]);
	}

	return ret;
}

static inline int
dma_test_mstream_rx(int dma_port, int buf_size, int direction)
{
	uint8_t *fptr[2];
	rte_iova_t alloc_ptr[2];
	int ret = 0, vchan = 0, i;
	rte_iova_t src, dst;
	struct rte_dma_vchan_conf *vconf;

	printf("--dma_port %d--\n", dma_port);
	for (i = 0; i < 2; i++) {
		fptr[i] = (uint8_t *)rte_malloc("xfer_block", buf_size, 128);
		if (!fptr[i]) {
			printf("Unable to allocate internal memory\n");
			return -ENOMEM;
		}
		memset(fptr[i], 0, buf_size);
		alloc_ptr[i] = rte_malloc_virt2iova(fptr[i]);
	}
	raddr = alloc_ptr[1];
	printf("RADDR : %lx ap : %lx\n", raddr, alloc_ptr[1]);
	vconf = &dpi_test[dma_port].vchan_conf[0];
	vconf->direction = direction;
	vconf->nb_desc = 1;

	RTE_SET_USED(src);
	RTE_SET_USED(dst);

	switch (direction) {
	/* outbound */
	case RTE_DMA_DIR_MEM_TO_DEV:
		buffer_fill(fptr[0], buf_size, 0);
		vconf->dst_port.port_type = RTE_DMA_PORT_PCIE;
		vconf->dst_port.pcie.coreid = pem_id;
		src = alloc_ptr[0];
		dst = raddr;
		break;
	/* inbound */
	case RTE_DMA_DIR_DEV_TO_MEM:
		vconf->src_port.port_type = RTE_DMA_PORT_PCIE;
		vconf->src_port.pcie.coreid = pem_id;
		src = raddr;
		dst = alloc_ptr[0];
		break;
	/* internal_only */
	case RTE_DMA_DIR_MEM_TO_MEM:
		buffer_fill(fptr[0], buf_size, 0);
		src = alloc_ptr[0];
		dst = alloc_ptr[1];
		break;
	};

	vchan = rte_dma_vchan_setup(dma_port, vchan, vconf);
	if (vchan < 0) {
		ret = vchan;
		printf("DMA vchan setup failed with err %d\n", ret);
		goto free_buf;
	}

	while (!force_quit) {
		dump_buffer(fptr[1], buf_size);
		sleep(1);
	}
free_buf:
	for (i = 0; i < 2; i++) {
		if (fptr[i])
			rte_free(fptr[i]);
	}

	return ret;
}

static inline int
dma_test_xfer_mstream(void)
{
	unsigned int dma_port = rte_lcore_id();

	/* If lcore >= nb_ports skip processing */
	if (dma_port >= 2) {
		/* printf("dma port : %d stopping.\n", dma_port); */
		return 0;
	}

	if (dma_port == 0)
		return dma_test_mstream_tx(dma_port, 16, RTE_DMA_DIR_MEM_TO_MEM);

	return dma_test_mstream_rx(dma_port, 16, RTE_DMA_DIR_MEM_TO_MEM);
}

static inline int
dma_test_queue_priority(void)
{
	unsigned int dma_port = rte_lcore_id();
	uint8_t *fptr[MAX_POINTERS];
	rte_iova_t alloc_ptr[MAX_POINTERS];
	struct rte_dma_sge src[MAX_POINTERS], dst[MAX_POINTERS];
	int ret = 0, vchan = 0, i;
	struct rte_dma_vchan_conf *vconf;
	enum rte_dma_status_code status;
	char *xfer_str;
	int ptr_sz = data_size / ptrs_per_instr;
	int b, num_ptrs = ptrs_per_instr;
	uint64_t s_tsc, e_tsc = 0, latency = 0, bs_tsc, be_tsc;
	int xtype = RTE_DMA_DIR_DEV_TO_MEM;

	/* If lcore >= nb_ports skip processing */
	if (dma_port >= nb_ports)
		return 0;

	printf("dma_port %d, raddr 0x%lx\n", dma_port, raddr);

	for (i = 0; i < num_ptrs; i++) {
		fptr[i] = (uint8_t *)rte_malloc("xfer_block", ptr_sz, 128);
		if (!fptr[i]) {
			printf("Unable to allocate internal memory\n");
			return -ENOMEM;
		}
		memset(fptr[i], 0, ptr_sz);
		alloc_ptr[i] = rte_malloc_virt2iova(fptr[i]);
		if (xtype == RTE_DMA_DIR_MEM_TO_DEV) {
			buffer_fill(fptr[i], ptr_sz, 0);
			src[i].addr = alloc_ptr[i];
			dst[i].addr = raddr + (i * ptr_sz);
		} else {
			src[i].addr = raddr + (i * ptr_sz);
			dst[i].addr = alloc_ptr[i];
		}
		src[i].length = ptr_sz;
		dst[i].length = ptr_sz;
	}

	vconf = &dpi_test[dma_port].vchan_conf[0];
	vconf->direction = xtype;
	vconf->nb_desc = 1;

	switch (xtype) {
	/* outbound */
	case RTE_DMA_DIR_MEM_TO_DEV:
		vconf->dst_port.port_type = RTE_DMA_PORT_PCIE;
		vconf->dst_port.pcie.coreid = pem_id;
		xfer_str = tranfer_type[2];
		break;
	/* inbound */
	case RTE_DMA_DIR_DEV_TO_MEM:
		vconf->src_port.port_type = RTE_DMA_PORT_PCIE;
		vconf->src_port.pcie.coreid = pem_id;
		xfer_str = tranfer_type[1];
		break;
	default:
		printf("Wrong xtype %d selected\n", xtype);
		return -EINVAL;
	};

	printf("\n%s latency.\n", xfer_str);
	vchan = rte_dma_vchan_setup(dma_port, vchan, vconf);
	if (vchan < 0) {
		ret = vchan;
		printf("DMA vchan setup failed with err %d\n", ret);
		goto free_bufs;
	}

	rte_dma_start(dma_port);

	bs_tsc = rte_rdtsc();
	for (b = 0; b < n_iter; b++) {
		s_tsc = rte_rdtsc();

		ret = rte_dma_copy_sg(dma_port, vchan, src, dst, num_ptrs, num_ptrs,
				      RTE_DMA_OP_FLAG_SUBMIT);
		if (ret < 0) {
			printf("dmadev copy op failed, ret=%d\n", ret);
			goto free_bufs;
		}
		do {
			rte_dma_completed_status(dma_port, vchan, 1, NULL, &status);
			if (!status || force_quit)
				break;
		} while (1);

		e_tsc = rte_rdtsc();

		latency += (e_tsc - s_tsc);
	}
	be_tsc = rte_rdtsc();
	printf("Port %d : Avg. burst: [%06ld cycles][%04ld usecs]\n"
	       "Total     : [%06ld cycles][%04ld usecs]\n",
	       dma_port, latency / n_iter, ((latency / n_iter) * 1000000) / timer_period,
	       be_tsc - bs_tsc, ((be_tsc - bs_tsc) * 1000000) / timer_period);

free_bufs:
	for (i = 0; i < ptrs_per_instr; i++) {
		if (fptr[i])
			rte_free(fptr[i]);
	}
	return 0;
}

static int
launch_one_lcore(void *dummy)
{
	RTE_SET_USED(dummy);

	dma_test_xfer_perf();

	return 0;
}

static inline int
dma_test_xfer_once(int dma_port, int buf_size, int direction)
{
	uint8_t *fptr[2];
	rte_iova_t alloc_ptr[2];
	rte_iova_t src, dst;
	int ret = 0, vchan = 0, i, retries = 10;
	struct rte_dma_vchan_conf *vconf;
	enum rte_dma_status_code status;
	char *xfer_str;

	printf("--dma_port %d--\n", dma_port);
	for (i = 0; i < 2; i++) {
		fptr[i] = (uint8_t *)rte_malloc("xfer_block", buf_size, 128);
		if (!fptr[i]) {
			printf("Unable to allocate internal memory\n");
			return -ENOMEM;
		}
		memset(fptr[i], 0, buf_size);
		alloc_ptr[i] = rte_malloc_virt2iova(fptr[i]);
	}

	vconf = &dpi_test[dma_port].vchan_conf[0];
	vconf->direction = direction;
	vconf->nb_desc = 1;

	switch (direction) {
	/* outbound */
	case RTE_DMA_DIR_MEM_TO_DEV:
		buffer_fill(fptr[0], buf_size, 0);
		vconf->dst_port.port_type = RTE_DMA_PORT_PCIE;
		vconf->dst_port.pcie.coreid = pem_id;
		src = alloc_ptr[0];
		dst = raddr;
		xfer_str = tranfer_type[2];
		break;
	/* inbound */
	case RTE_DMA_DIR_DEV_TO_MEM:
		vconf->src_port.port_type = RTE_DMA_PORT_PCIE;
		vconf->src_port.pcie.coreid = pem_id;
		src = raddr;
		dst = alloc_ptr[0];
		xfer_str = tranfer_type[1];
		break;
	/* internal_only */
	case RTE_DMA_DIR_MEM_TO_MEM:
		buffer_fill(fptr[0], buf_size, 0);
		src = alloc_ptr[0];
		dst = alloc_ptr[1];
		xfer_str = tranfer_type[0];
		break;
	default:
		printf("Wrong direction %d selected\n", direction);
		return -EINVAL;
	};

	vchan = rte_dma_vchan_setup(dma_port, vchan, vconf);
	if (vchan < 0) {
		ret = vchan;
		printf("DMA vchan setup failed with err %d\n", ret);
		goto free_buf;
	}

	rte_dma_start(dma_port);
	ret = rte_dma_copy(dma_port, vchan, src, dst, buf_size, RTE_DMA_OP_FLAG_SUBMIT);
	if (ret < 0) {
		printf("dmadev copy op failed, ret=%d\n", ret);
		goto free_buf;
	}

	do {
		/* sleep(1); */
		rte_delay_us_sleep(10);
		rte_dma_completed_status(dma_port, vchan, 1, NULL, &status);
		if (!status || !retries || force_quit)
			break;
		retries--;
	} while (1);

	if (status)
		printf("%s DMA transfer failed, status = %d\n", xfer_str, status);
	else
		printf("%s DMA transfer success\n", xfer_str);

free_buf:
	for (i = 0; i < 2; i++) {
		if (fptr[i])
			rte_free(fptr[i]);
	}

	return ret;
}

static inline int
dma_test_roundtrip_latency(int dma_port, int xtype)
{
	uint8_t *fptr_in[MAX_POINTERS];
	rte_iova_t alloc_ptr_in[MAX_POINTERS];
	uint8_t *fptr_out[MAX_POINTERS];
	rte_iova_t alloc_ptr_out[MAX_POINTERS];
	struct rte_dma_sge src_in[MAX_POINTERS], dst_in[MAX_POINTERS];
	struct rte_dma_sge src_out[MAX_POINTERS], dst_out[MAX_POINTERS];
	int ret = 0, vchan = 0, i;
	struct rte_dma_vchan_conf vconf = {0};
	enum rte_dma_status_code status = -1;
	int ptr_sz = data_size / ptrs_per_instr;
	int b, num_ptrs = ptrs_per_instr;
	uint64_t s_tsc, e_tsc = 0, latency = 0, bs_tsc, be_tsc;

	for (i = 0; i < num_ptrs; i++) {
		fptr_in[i] = (uint8_t *)rte_malloc("xfer_block", ptr_sz, 128);
		if (!fptr_in[i]) {
			printf("Unable to allocate internal memory\n");
			return -ENOMEM;
		}
		alloc_ptr_in[i] = rte_malloc_virt2iova(fptr_in[i]);

		fptr_out[i] = (uint8_t *)rte_malloc("xfer_block", ptr_sz, 128);
		if (!fptr_out[i]) {
			printf("Unable to allocate internal memory\n");
			return -ENOMEM;
		}
		alloc_ptr_out[i] = rte_malloc_virt2iova(fptr_out[i]);

		if (xtype == RTE_DMA_DIR_MEM_TO_DEV) {
			buffer_fill(fptr_out[i], ptr_sz, 0);
			src_out[i].addr = alloc_ptr_out[i];
			dst_out[i].addr = raddr + (i * ptr_sz);
		} else {
			src_in[i].addr = raddr + (i * ptr_sz);
			dst_in[i].addr = alloc_ptr_in[i];
		}
		src_in[i].length = ptr_sz;
		dst_in[i].length = ptr_sz;
	}

	printf("\n%s roundtrip latency.\n",
	       (xtype == RTE_DMA_DIR_DEV_TO_MEM) ? "Inbound" : "Outbound");

	if (xtype == RTE_DMA_DIR_DEV_TO_MEM) {
		bs_tsc = rte_rdtsc();
		for (b = 0; b < n_iter; b++) {
			s_tsc = rte_rdtsc();

			/* configure DMA for inbound xfer */
			// vconf = &dpi_test[dma_port].vchan_conf;
			vconf.direction = xtype;
			vconf.nb_desc = 1;
			vconf.src_port.port_type = RTE_DMA_PORT_PCIE;
			vconf.src_port.pcie.coreid = pem_id;

			vchan = rte_dma_vchan_setup(dma_port, vchan, &vconf);
			if (vchan < 0) {
				ret = vchan;
				printf("DMA vchan setup failed with err %d\n", ret);
				goto free_bufs;
			}
			rte_dma_start(dma_port);
			printf("IN src ddr = 0x%lx\n", src_in[0].addr);
			printf("IN dst addr = 0x%lx\n", dst_in[0].addr);
			ret = rte_dma_copy_sg(dma_port, vchan, src_in, dst_in, num_ptrs, num_ptrs,
					      RTE_DMA_OP_FLAG_SUBMIT);
			if (ret < 0) {
				printf("dmadev copy op failed, ret=%d\n", ret);
				goto free_bufs;
			}
			do {
				rte_dma_completed_status(dma_port, vchan, 1, NULL, &status);
				if (!status || force_quit)
					break;
			} while (1);

			printf("--one way done--\n");
			/* configure DMA for outbound xfer */
			rte_dma_stop(dma_port);
			status = -1;
			// vconf = &dpi_test[dma_port].vchan_conf;
			memset(&vconf, 0, sizeof(vconf));
			vconf.direction = RTE_DMA_DIR_MEM_TO_DEV;
			vconf.nb_desc = 1;
			vconf.dst_port.port_type = RTE_DMA_PORT_PCIE;
			vconf.dst_port.pcie.coreid = pem_id;

			vchan = rte_dma_vchan_setup(dma_port, vchan, &vconf);
			if (vchan < 0) {
				ret = vchan;
				printf("DMA vchan setup failed with err %d\n", ret);
				goto free_bufs;
			}

			rte_dma_start(dma_port);
			printf("OUT src ddr = 0x%lx\n", src_out[0].addr);
			printf("OUT dst addr = 0x%lx\n", dst_out[0].addr);
			ret = rte_dma_copy_sg(dma_port, vchan, src_out, dst_out, num_ptrs, num_ptrs,
					      RTE_DMA_OP_FLAG_SUBMIT);
			if (ret < 0) {
				printf("dmadev copy op failed, ret=%d\n", ret);
				goto free_bufs;
			}
			do {
				rte_dma_completed_status(dma_port, vchan, 1, NULL, &status);
				if (!status || force_quit)
					break;
			} while (1);
			/* run_dpi_cmd(dma_port, bufp_in, &ctx_in); */
			/* run_dpi_cmd(dma_port, bufp_out, &ctx_out); */
			e_tsc = rte_rdtsc();
			if (force_quit) {
				printf("Test abandoned.\n");
				goto free_bufs;
			}

			latency += (e_tsc - s_tsc);
		}
		be_tsc = rte_rdtsc();
	} else {
		bs_tsc = rte_rdtsc();
		for (b = 0; b < n_iter; b++) {
			s_tsc = rte_rdtsc();

			/* configure DMA for outbound xfer */
			// vconf = &dpi_test[dma_port].vchan_conf;
			vconf.direction = xtype;
			vconf.nb_desc = 1;
			vconf.dst_port.port_type = RTE_DMA_PORT_PCIE;
			vconf.dst_port.pcie.coreid = pem_id;

			vchan = rte_dma_vchan_setup(dma_port, vchan, &vconf);
			if (vchan < 0) {
				ret = vchan;
				printf("DMA vchan setup failed with err %d\n", ret);
				goto free_bufs;
			}

			rte_dma_start(dma_port);
			ret = rte_dma_copy_sg(dma_port, vchan, src_out, dst_out, num_ptrs, num_ptrs,
					      RTE_DMA_OP_FLAG_SUBMIT);
			if (ret < 0) {
				printf("dmadev copy op failed, ret=%d\n", ret);
				goto free_bufs;
			}
			do {
				rte_dma_completed_status(dma_port, vchan, 1, NULL, &status);
				if (!status || force_quit)
					break;
			} while (1);

			printf("--one way done--\n");
			/* configure DMA for inbound xfer */
			rte_dma_stop(dma_port);
			status = -1;
			// vconf = &dpi_test[dma_port].vchan_conf;
			memset(&vconf, 0, sizeof(vconf));
			vconf.direction = RTE_DMA_DIR_DEV_TO_MEM;
			vconf.nb_desc = 1;
			vconf.src_port.port_type = RTE_DMA_PORT_PCIE;
			vconf.src_port.pcie.coreid = pem_id;

			vchan = rte_dma_vchan_setup(dma_port, vchan, &vconf);
			if (vchan < 0) {
				ret = vchan;
				printf("DMA vchan setup failed with err %d\n", ret);
				goto free_bufs;
			}
			rte_dma_start(dma_port);
			ret = rte_dma_copy_sg(dma_port, vchan, src_in, dst_in, num_ptrs, num_ptrs,
					      RTE_DMA_OP_FLAG_SUBMIT);
			if (ret < 0) {
				printf("dmadev copy op failed, ret=%d\n", ret);
				goto free_bufs;
			}
			do {
				rte_dma_completed_status(dma_port, vchan, 1, NULL, &status);
				if (!status || force_quit)
					break;
			} while (1);

			/*  run_dpi_cmd(dma_port, bufp_out, &ctx_out);
			 *  run_dpi_cmd(dma_port, bufp_in, &ctx_in);
			 */
			e_tsc = rte_rdtsc();
			if (force_quit) {
				printf("Test abandoned.\n");
				goto free_bufs;
			}

			latency += (e_tsc - s_tsc);
		}
		be_tsc = rte_rdtsc();
	}
	printf("Avg. burst: [%06ld cycles][%04ld usecs]\n"
	       "Total     : [%06ld cycles][%04ld usecs]\n",
	       latency / n_iter, ((latency / n_iter) * 1000000) / timer_period, be_tsc - bs_tsc,
	       ((be_tsc - bs_tsc) * 1000000) / timer_period);

free_bufs:
	for (i = 0; i < ptrs_per_instr; i++) {
		if (fptr_in[i])
			rte_free(fptr_in[i]);
		if (fptr_out[i])
			rte_free(fptr_out[i]);
	}

	return ret;
}

static inline int
dma_test_latency(int dma_port, int xtype)
{
	uint8_t *fptr[MAX_POINTERS];
	rte_iova_t alloc_ptr[MAX_POINTERS];
	struct rte_dma_sge src[MAX_POINTERS], dst[MAX_POINTERS];
	int ret = 0, vchan = 0, i;
	struct rte_dma_vchan_conf *vconf;
	enum rte_dma_status_code status;
	char *xfer_str;
	int ptr_sz = data_size / ptrs_per_instr;
	int b, num_ptrs = ptrs_per_instr;
	uint64_t s_tsc, e_tsc = 0, latency = 0, bs_tsc, be_tsc;

	for (i = 0; i < num_ptrs; i++) {
		fptr[i] = (uint8_t *)rte_malloc("xfer_block", ptr_sz, 128);
		if (!fptr[i]) {
			printf("Unable to allocate internal memory\n");
			return -ENOMEM;
		}
		memset(fptr[i], 0, ptr_sz);
		alloc_ptr[i] = rte_malloc_virt2iova(fptr[i]);
		if (xtype == RTE_DMA_DIR_MEM_TO_DEV) {
			buffer_fill(fptr[i], ptr_sz, 0);
			src[i].addr = alloc_ptr[i];
			dst[i].addr = raddr + (i * ptr_sz);
		} else {
			src[i].addr = raddr + (i * ptr_sz);
			dst[i].addr = alloc_ptr[i];
		}
		src[i].length = ptr_sz;
		dst[i].length = ptr_sz;
	}

	vconf = &dpi_test[dma_port].vchan_conf[0];
	vconf->direction = xtype;
	vconf->nb_desc = 1;

	switch (xtype) {
	/* outbound */
	case RTE_DMA_DIR_MEM_TO_DEV:
		vconf->dst_port.port_type = RTE_DMA_PORT_PCIE;
		vconf->dst_port.pcie.coreid = pem_id;
		xfer_str = tranfer_type[2];
		break;
	/* inbound */
	case RTE_DMA_DIR_DEV_TO_MEM:
		vconf->src_port.port_type = RTE_DMA_PORT_PCIE;
		vconf->src_port.pcie.coreid = pem_id;
		xfer_str = tranfer_type[1];
		break;
	default:
		printf("Wrong xtype %d selected\n", xtype);
		return -EINVAL;
	};

	printf("\n%s latency.\n", xfer_str);
	vchan = rte_dma_vchan_setup(dma_port, vchan, vconf);
	if (vchan < 0) {
		ret = vchan;
		printf("DMA vchan setup failed with err %d\n", ret);
		goto free_bufs;
	}

	rte_dma_start(dma_port);

	bs_tsc = rte_rdtsc();
	for (b = 0; b < n_iter; b++) {
		s_tsc = rte_rdtsc();

		ret = rte_dma_copy_sg(dma_port, vchan, src, dst, num_ptrs, num_ptrs,
				      RTE_DMA_OP_FLAG_SUBMIT);
		if (ret < 0) {
			printf("dmadev copy op failed, ret=%d\n", ret);
			goto free_bufs;
		}
		do {
			rte_dma_completed_status(dma_port, vchan, 1, NULL, &status);
			if (!status || force_quit)
				break;
		} while (1);

		e_tsc = rte_rdtsc();
		if (force_quit) {
			printf("Test abandoned.\n");
			goto free_bufs;
		}

		latency += (e_tsc - s_tsc);
	}
	be_tsc = rte_rdtsc();
	printf("Avg. burst: [%06ld cycles][%04ld usecs]\n"
	       "Total     : [%06ld cycles][%04ld usecs]\n",
	       latency / n_iter, ((latency / n_iter) * 1000000) / timer_period, be_tsc - bs_tsc,
	       ((be_tsc - bs_tsc) * 1000000) / timer_period);

free_bufs:
	for (i = 0; i < ptrs_per_instr; i++) {
		if (fptr[i])
			rte_free(fptr[i]);
	}

	return ret;
}

static uint64_t
dpi_parse_addr(const char *q_arg)
{
	char *end = NULL;
	uint64_t n;

	/* parse number string */
	n = strtoul(q_arg, &end, 0);
	if ((q_arg[0] == '\0') || (end == NULL) || (*end != '\0'))
		return 0;

	return n;
}

/* display usage */
static void
dpi_usage(const char *prgname)
{
	printf("%s [EAL options] --\n"
	       "  -r <remote address>: Remote pointer\n"
	       "  -l <first address>: This is also remote address valid for external only mode\n"
	       "  -m <mode>: Mode of transfer\n"
	       "             0: Internal Only\n"
	       "             1: Inbound\n"
	       "             2: Outbound\n"
	       "             3: Dual - both inbound and outbound (supported only in perf test)\n"
	       "             4: Inbound Latency\n"
	       "             5: Outbound Latency\n"
	       "             6: Inbound roundtrip Latency\n"
	       "             7: Outbound roundtrip Latency\n"
	       "             8: All modes 4, 5, 6, 7\n"
	       "		Max data size for latency tests :\n"
	       "			(65535*15) = 983025 bytes\n"
	       "  -i <iteration>: No.of iterations\n"
	       "  -f <file_name>: File to dump statistics\n"
	       "  -s <data size>: Size of data to be DMA'ed (Default is 256)\n"
	       "  -z <pem number>: PEM connected to host\n"
	       "  -b <burst size>: Initial number of packets submitted to the DMA\n"
	       "  -d <done count>: Min numbers of completions to wait for before resubmission\n"
	       "  -p: Performance test\n"
	       "  -t <num>: Number of pointers per instruction (Default is 1)\n"
	       "  --inb_sz <data size>: Size of Inbound data size in mode 3\n"
	       "  --outb_sz <data size>: Size of Outbound data size in mode 3\n",
	       prgname);
}

/* Parse the argument given in the command line of the application */
static int
dpi_parse_args(int argc, char **argv)
{
	int opt, ret, opt_idx;
	char **argvopt;
	char *prgname = argv[0];

	static struct option lgopts[] = {
		{"inb_sz", 1, 0, 0},
		{"outb_sz", 1, 0, 0},
		{0, 0, 0, 0},
	};

	argvopt = argv;

	while ((opt = getopt_long(argc, argvopt, "r:s:l:m:i:f:pb:z:t:d:", lgopts, &opt_idx)) !=
	       EOF) {
		switch (opt) {
		/* portmask */
		case 'r':
			raddr = dpi_parse_addr(optarg);
			if ((long)raddr == 0) {
				printf("invalid remote address\n");
				dpi_usage(prgname);
				return -1;
			}
			printf("raddr: 0x%lx\n", raddr);
			break;
		case 's':
			data_size = dpi_parse_addr(optarg);
			if ((long)data_size == 0) {
				printf("invalid data Size\n");
				dpi_usage(prgname);
				return -1;
			}
			printf("data_size: 0x%lx\n", data_size);
			break;
		case 'l':
			laddr = dpi_parse_addr(optarg);
			if ((long)laddr < 0) {
				printf("invalid local address\n");
				dpi_usage(prgname);
				return -1;
			}
			break;
		case 'm':
			mode = atoi(optarg);
			printf("Mode: %d\n", mode);
			break;
		case 'i':
			n_iter = atoi(optarg);
			break;
		case 'f':
			dump_to_file = 1;
			strcpy(stats_file_name, optarg);
			break;
		case 'z':
			pem_id = atoi(optarg);
			if (pem_id)
				pem_id = 1;
			break;
		case 'b':
			burst_size = atoi(optarg);
			printf("Burst size:: %d\n", burst_size);
			break;
		case 'd':
			done_count = atoi(optarg);
			break;
		case 'p':
			perf_mode = 1;
			break;
		case 't':
			ptrs_per_instr = atoi(optarg);
			printf("Pointers per instr: %d\n", ptrs_per_instr);
			break;
		case 0: /* long options */
			if (!strcmp(lgopts[opt_idx].name, "inb_sz")) {
				printf("This option is not yet supported\n");
				return -1;
			}
			if (!strcmp(lgopts[opt_idx].name, "outb_sz")) {
				printf("This option is not yet supported\n");
				return -1;
			}
			break;
		default:
			dpi_usage(prgname);
			return -1;
		}
	}

	if (optind >= 0)
		argv[optind - 1] = prgname;

	ret = optind - 1;
	optind = 1; /* reset getopt lib */
	return ret;
}

int
main(int argc, char **argv)
{
	int ret, i, size = 1024;
	struct rte_dma_conf dev_conf;
	unsigned int lcore_id;

	/* init EAL */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");
	argc -= ret;
	argv += ret;

	force_quit = false;
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);
	signal(SIGUSR1, signal_handler);

	total_dma_cnt = 0;
	pem_id = 0;
	/* parse application arguments (after the EAL ones) */
	ret = dpi_parse_args(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid App arguments\n");

	nb_ports = rte_dma_count_avail();
	if (nb_ports == 0 || nb_ports > DPI_MAX_VFS)
		rte_exit(EXIT_FAILURE, "Wrong dmadev ports (%d) selected - bye\n", nb_ports);

	/* convert to number of cycles */
	timer_period *= rte_get_timer_hz();

	printf("%d dmadev ports detected\n", nb_ports);

	if (burst_size < done_count || burst_size > 64)
		rte_exit(EXIT_FAILURE, "Burst_size must be between %u to 64\n", done_count);
	if (dump_to_file) {
		stats_fp = fopen(stats_file_name, "a");
		if (stats_fp == NULL)
			rte_exit(EXIT_FAILURE, "unable to open dump file\n");
	}

	/* Configure dmadev ports */
	for (i = 0; i < nb_ports; i++) {
		dpi_test[i].dev_id = i;
		rte_dma_info_get(i, &dpi_test[i].dev_info);
		if (ptrs_per_instr > dpi_test[i].dev_info.max_sges) {
			printf("Max pointers can be only %d\n", dpi_test[i].dev_info.max_sges);
			goto err_exit;
		}
		dev_conf.nb_vchans = 4;
		dev_conf.enable_silent = 0;
		ret = rte_dma_configure(i, &dev_conf);
		if (ret)
			rte_exit(EXIT_FAILURE, "Unable to configure DPIVF %d\n", i);
		printf("dmadev %d configured successfully\n", i);
	}

	if (!perf_mode) {
		if (mode >= 4 && mode <= 8) {
			ptrs_per_instr = data_size / DPI_MAX_DATA_SZ_PER_PTR;
			if (data_size % DPI_MAX_DATA_SZ_PER_PTR)
				ptrs_per_instr++;
			if (ptrs_per_instr > MAX_POINTERS) {
				printf("Data too big.\n"
				       "Max data size: (%d bytes/ptr * "
				       "%d ptrs) = %d bytes\n",
				       DPI_MAX_DATA_SZ_PER_PTR, MAX_POINTERS,
				       DPI_MAX_DATA_SZ_PER_PTR * MAX_POINTERS);
				goto close_devs;
			}

			printf("\nData size: %ld, bursts: %d, "
			       "ptrs/burst: %d, sz/ptr: %ld\n",
			       data_size, n_iter, ptrs_per_instr, data_size / ptrs_per_instr);

			for (i = 0; i < nb_ports; i++) {
				printf("\nPort %d\n", i);
				if (mode == 4) {
					dma_test_latency(i, RTE_DMA_DIR_DEV_TO_MEM);
				} else if (mode == 5) {
					dma_test_latency(i, RTE_DMA_DIR_MEM_TO_DEV);
				} else if (mode == 6) {
					dma_test_roundtrip_latency(i, RTE_DMA_DIR_DEV_TO_MEM);
				} else if (mode == 7) {
					dma_test_roundtrip_latency(i, RTE_DMA_DIR_MEM_TO_DEV);
				} else {
					dma_test_latency(i, RTE_DMA_DIR_DEV_TO_MEM);
					dma_test_roundtrip_latency(i, RTE_DMA_DIR_DEV_TO_MEM);
					dma_test_latency(i, RTE_DMA_DIR_MEM_TO_DEV);
					dma_test_roundtrip_latency(i, RTE_DMA_DIR_MEM_TO_DEV);
				}
				if (force_quit)
					break;
			}
			goto close_devs;
		} else if (mode >= 1 && mode <= 3) {
			for (i = 0; i < nb_ports; i++) {
				int j;

				for (j = 0; j < n_iter; j++) {
					int dir = 0;

					if (mode == 0) {
						dir = RTE_DMA_DIR_MEM_TO_MEM;
					} else if (mode == 1) {
						dir = RTE_DMA_DIR_DEV_TO_MEM;
					} else if (mode == 2) {
						dir = RTE_DMA_DIR_MEM_TO_DEV;
					} else if (mode == 3) {
						printf("Dual mode only supported in perf test\n");
						return 0;
					}
					ret = dma_test_xfer_once(dpi_test[i].dev_id, size, dir);
					if (ret) {
						printf("DMA transfer (mode: %d) "
						       "failed for queue %d\n",
						       mode, i);
					}
					rte_dma_stop(i);
				}
				/* break; */
			}
		} else if (mode == 10) {
			dma_test_mstream_rx(dpi_test[1].dev_id, size, RTE_DMA_DIR_MEM_TO_MEM);
		} else if (mode == 11) {
			dma_test_mstream_tx(dpi_test[0].dev_id, size, RTE_DMA_DIR_MEM_TO_MEM);
		}
	}

	if (perf_mode) {
		/* launch per-lcore init on every lcore */
		rte_eal_mp_remote_launch(launch_one_lcore, NULL, SKIP_MAIN);
		RTE_LCORE_FOREACH_WORKER(lcore_id)
		{
			if (rte_eal_wait_lcore(lcore_id) < 0) {
				ret = -1;
				break;
			}
		}
	}

close_devs:
err_exit:
	if (stats_fp)
		fclose(stats_fp);

	for (i = 0; i < nb_ports; i++) {
		rte_dma_stop(i);
		if (rte_dma_close(i))
			printf("Dev close failed for port %d\n", i);
	}

	rte_eal_cleanup();
	return ret;
}
