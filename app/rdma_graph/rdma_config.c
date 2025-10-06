/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <getopt.h>
#include <stdlib.h>

#include "rdma_config.h"
#include "rdma_init.h"
#include "rdma_lcore.h"

#include <dao_log.h>

#define MAX_PARAMS 128

#define CMD_LINE_OPT_RDMA_MAP_NUM       "rdma-map"
#define CMD_LINE_OPT_PER_PORT_POOL      "per-port-pool"
#define CMD_LINE_OPT_MAX_PKT_LEN        "max-pkt-len"
#define CMD_LINE_OPT_PCAP_ENABLE        "pcap-enable"
#define CMD_LINE_OPT_NUM_PKT_CAP        "pcap-num-cap"
#define CMD_LINE_OPT_PCAP_FILENAME      "pcap-file-name"
#define CMD_LINE_OPT_ENABLE_DEBUG       "enable-debug"
#define CMD_LINE_OPT_ENABLE_GRAPH_STATS "enable-graph-stats"
#define CMD_LINE_OPT_MBUF_DATA_SIZE     "mbuf-data-size"
#define CMD_LINE_OPT_NUM_MBUFS          "num-mbufs"
#define CMD_LINE_OPT_DMA_FLUSH_THR      "dma-flush-thr"
#define CMD_LINE_OPT_DMA_NB_DESC        "dma-nb-desc"

static const char short_options[] = "p:" /* portmask */
				    "P"  /* promiscuous */
				    "n:" /* Num rdma port */
				    "r:" /* RDMA dev mask */
	;
enum {
	/* long options mapped to a short option */

	/* first long only option value must be >= 256, so that we won't
	 * conflict with short options */
	CMD_LINE_OPT_PARSE_RDMA_MAP_NUM = 256,
	CMD_LINE_OPT_PARSE_PER_PORT_POOL,
	CMD_LINE_OPT_MAX_PKT_LEN_NUM,
	CMD_LINE_OPT_PARSE_PCAP_ENABLE,
	CMD_LINE_OPT_PARSE_NUM_PKT_CAP,
	CMD_LINE_OPT_PCAP_FILENAME_CAP,
	CMD_LINE_OPT_PARSE_ENABLE_DEBUG,
	CMD_LINE_OPT_PARSE_ENABLE_GRAPH_STATS,
	CMD_LINE_OPT_PARSE_MBUF_DATA_SIZE,
	CMD_LINE_OPT_PARSE_NUM_MBUFS,
	CMD_LINE_OPT_PARSE_DMA_FLUSH_THR,
	CMD_LINE_OPT_PARSE_DMA_NB_DESC,
};

enum fld_type {
	INT_FLD = 0,
	STR_FLD,
};

static const struct option lgopts[] = {
	{CMD_LINE_OPT_RDMA_MAP_NUM, 1, 0, CMD_LINE_OPT_PARSE_RDMA_MAP_NUM},
	{CMD_LINE_OPT_PER_PORT_POOL, 0, 0, CMD_LINE_OPT_PARSE_PER_PORT_POOL},
	{CMD_LINE_OPT_MAX_PKT_LEN, 1, 0, CMD_LINE_OPT_MAX_PKT_LEN_NUM},
	{CMD_LINE_OPT_PCAP_ENABLE, 0, 0, CMD_LINE_OPT_PARSE_PCAP_ENABLE},
	{CMD_LINE_OPT_NUM_PKT_CAP, 1, 0, CMD_LINE_OPT_PARSE_NUM_PKT_CAP},
	{CMD_LINE_OPT_PCAP_FILENAME, 1, 0, CMD_LINE_OPT_PCAP_FILENAME_CAP},
	{CMD_LINE_OPT_ENABLE_DEBUG, 0, 0, CMD_LINE_OPT_PARSE_ENABLE_DEBUG},
	{CMD_LINE_OPT_ENABLE_GRAPH_STATS, 0, 0, CMD_LINE_OPT_PARSE_ENABLE_GRAPH_STATS},
	{CMD_LINE_OPT_MBUF_DATA_SIZE, 1, 0, CMD_LINE_OPT_PARSE_MBUF_DATA_SIZE},
	{CMD_LINE_OPT_NUM_MBUFS, 1, 0, CMD_LINE_OPT_PARSE_NUM_MBUFS},
	{CMD_LINE_OPT_DMA_FLUSH_THR, 1, 0, CMD_LINE_OPT_PARSE_DMA_FLUSH_THR},
	{CMD_LINE_OPT_DMA_NB_DESC, 1, 0, CMD_LINE_OPT_PARSE_DMA_NB_DESC},
	{NULL, 0, 0, 0}};

/* display usage */
void
rdma_print_usage(const char *prgname)
{
	dao_info(
		"%s [EAL options] -- -p PORTMASK [-P] [-q NQ]"
		"  -p PORTMASK: hexadecimal bitmask of ports to configure\n"
		"  -r RDMA DEV MASK: hexadecimal bitmask of rdma devices to configure\n"
		"  -n : Number of rdma devices\n"
		"  -P : Enable promiscuous mode\n"
		"  --config (port,queue,lcore): Rx queue configuration\n"
		"  --no-mac-updating: Disable MAC addresses updating (enabled by default)\n"
		"      When enabled:\n"
		"       - The source MAC address is replaced by the TX port MAC address\n"
		"       - The destination MAC address is replaced by 02:00:00:00:00:TX_PORT_ID\n"
		"  --rdma-map (port,dev)[,(port,dev)]: RDMA port mapping\n"
		"  --max-pkt-len PKTLEN: maximum packet length in decimal (64-9600)\n"
		"  --per-port-pool: Use separate buffer pool per port\n"
		"  --pcap-enable: Enables pcap capture\n"
		"  --pcap-num-cap NUMPKT: Number of packets to capture\n"
		"  --pcap-file-name NAME: Pcap file name\n\n"
		"  --mbuf-data-size BYTES: mbuf data room size (e.g., 2176, 4096). Default 4160.\n"
		"  --num-mbufs N: number of mbufs per mempool (overrides auto sizing).\n\n"
		"  --enable-debug: Enable debug mode\n\n"
		"  --enable-graph-stats: Enable graph statistics\n\n"
		"  --dma-flush-thr N : DMA flush threshold per vchan (1-15, default from library)\n"
		"  --dma-nb-desc N   : DMA vchan ring descriptors (default 2048)\n\n",
		prgname);
}

static int
parse_portmask(const char *portmask)
{
	char *end = NULL;
	unsigned long pm;

	/* parse hexadecimal string */
	pm = strtoul(portmask, &end, 16);
	if ((portmask[0] == '\0') || (end == NULL) || (*end != '\0'))
		return 0;

	return pm;
}

static int
parse_device_mask(const char *devmask)
{
	char *end = NULL;
	unsigned long dm;

	/* parse hexadecimal string */
	dm = strtoul(devmask, &end, 16);
	if ((devmask[0] == '\0') || (end == NULL) || (*end != '\0'))
		return 0;

	return dm;
}

static int
parse_num_rdma_port(const char *nport)
{
	unsigned long num_port;
	char *end = NULL;

	/* Parse decimal string */
	num_port = strtoul(nport, &end, 10);
	if ((nport[0] == '\0') || (end == NULL) || (*end != '\0'))
		return -1;

	if (num_port == 0)
		return -1;

	return num_port;
}

static int
parse_rdma_map_config(const char *q_arg)
{
	enum fieldnames { FLD_PORTA = 0, FLD_PORTB, _NUM_FLD };
	unsigned long int_fld[_NUM_FLD];
	const char *p, *p0 = q_arg;
	char *str_fld[_NUM_FLD];
	uint32_t size;
	char s[256];
	char *end;
	int i;

	while ((p = strchr(p0, '(')) != NULL) {
		++p;
		p0 = strchr(p, ')');
		if (p0 == NULL)
			return -1;

		size = p0 - p;
		if (size >= sizeof(s))
			return -1;

		memcpy(s, p, size);
		s[size] = '\0';
		if (rte_strsplit(s, sizeof(s), str_fld, _NUM_FLD, ',') != _NUM_FLD)
			return -1;
		for (i = 0; i < _NUM_FLD; i++) {
			errno = 0;
			int_fld[i] = strtoul(str_fld[i] + 1, &end, 0);
			if (errno != 0 || end == str_fld[i])
				return -1;
		}

		if (int_fld[FLD_PORTA] >= RTE_MAX_ETHPORTS) {
			dao_err("Invalid port\n");
			return -1;
		}

		if (int_fld[FLD_PORTB] >= RTE_MAX_ETHPORTS) {
			dao_err("Invalid rdma devid\n");
			return -1;
		}

		if (*str_fld[FLD_PORTA] == 'r') {
			rdma_map[int_fld[FLD_PORTA]].id = int_fld[FLD_PORTB];
			if (*str_fld[FLD_PORTB] == 'e') {
				eth_map[int_fld[FLD_PORTB]].id = int_fld[FLD_PORTA];
			} else {
				dao_err("Invalid port type, not 'r' or 'e'\n");
				return -1;
			}
		} else if (*str_fld[FLD_PORTA] == 'e') {
			eth_map[int_fld[FLD_PORTA]].id = int_fld[FLD_PORTB];
			if (*str_fld[FLD_PORTB] == 'r') {
				rdma_map[int_fld[FLD_PORTB]].id = int_fld[FLD_PORTA];
			} else {
				dao_err("Invalid port type, not 'r' or 'e'\n");
				return -1;
			}
		} else {
			dao_err("Invalid port type, not 'r' or 'e'\n");
			return -1;
		}
	}

	return 0;
}

static int
parse_max_pkt_len(const char *pktlen)
{
	unsigned long len;
	char *end = NULL;

	/* Parse decimal string */
	len = strtoul(pktlen, &end, 10);
	if ((pktlen[0] == '\0') || (end == NULL) || (*end != '\0'))
		return -1;

	if (len == 0)
		return -1;

	return len;
}

static uint32_t
parse_u32_decimal(const char *val)
{
	unsigned long v;
	char *end = NULL;

	v = strtoul(val, &end, 10);
	if ((val[0] == '\0') || (end == NULL) || (*end != '\0'))
		return 0;
	return (uint32_t)v;
}

static uint64_t
parse_num_pkt_cap(const char *num_pkt_cap)
{
	uint64_t num_pkt;
	char *end = NULL;

	/* Parse decimal string */
	num_pkt = strtoull(num_pkt_cap, &end, 10);
	if ((num_pkt_cap[0] == '\0') || (end == NULL) || (*end != '\0'))
		return 0;

	if (num_pkt == 0)
		return 0;

	return num_pkt;
}

/* Parse the argument given in the command line of the application */
int
rdma_parse_args(int argc, char **argv, struct rdma_main_cfg_data *rdma_main_cfg)
{
	rdma_config_param_t *cfg_prm;
	char *prgname = argv[0];
	int option_index;
	char **argvopt;
	int opt, rc;

	argvopt = argv;

	cfg_prm = rdma_main_cfg->cfg_prm;
	cfg_prm->dma_flush_thr = 0;
	cfg_prm->dma_nb_desc = 2048; /* default */
	while ((opt = getopt_long(argc, argvopt, short_options, lgopts, &option_index)) != EOF) {
		switch (opt) {
		/* portmask */
		case 'p':
			cfg_prm->enabled_port_mask = parse_portmask(optarg);
			if (cfg_prm->enabled_port_mask == 0) {
				dao_err("invalid portmask");
				rdma_print_usage(prgname);
				return -1;
			}
			break;

		case 'r':
			cfg_prm->enabled_dev_mask = parse_device_mask(optarg);
			if (cfg_prm->enabled_dev_mask == 0) {
				dao_err("invalid device mask");
				rdma_print_usage(prgname);
				return -1;
			}
			dao_info("Enabled device mask: 0x%x", cfg_prm->enabled_dev_mask);
			break;

		case 'n':
			cfg_prm->num_rport = parse_num_rdma_port(optarg);
			dao_info("Number of rdma port: %u\n", cfg_prm->num_rport);
			break;
		case 'P':
			cfg_prm->promiscuous_on = 1;
			break;

		case CMD_LINE_OPT_PARSE_RDMA_MAP_NUM:
			rc = parse_rdma_map_config(optarg);
			if (rc) {
				dao_err("Invalid eth config\n");
				rdma_print_usage(prgname);
				return -1;
			}
			cfg_prm->rdma_map_config_enable = 1;
			dao_info("RDMA port mapping is enabled");
			break;
		case CMD_LINE_OPT_PARSE_PER_PORT_POOL:
			dao_info("Per port buffer pool is enabled");
			cfg_prm->per_port_pool = 1;
			break;

		case CMD_LINE_OPT_MAX_PKT_LEN_NUM: {
			cfg_prm->max_pkt_len = parse_max_pkt_len(optarg);
			break;
		}

		case CMD_LINE_OPT_PARSE_PCAP_ENABLE:
			dao_info("Packet capture enabled");
			cfg_prm->pcap_trace_enable = 1;
			break;

		case CMD_LINE_OPT_PARSE_NUM_PKT_CAP:
			cfg_prm->packet_to_capture = parse_num_pkt_cap(optarg);
			dao_info("Number of packets to capture: %" PRIu64 "",
				 cfg_prm->packet_to_capture);
			break;

		case CMD_LINE_OPT_PCAP_FILENAME_CAP:
			rte_strlcpy(cfg_prm->pcap_filename, optarg, sizeof(cfg_prm->pcap_filename));
			dao_info("Pcap file name: %s", cfg_prm->pcap_filename);
			break;

		case CMD_LINE_OPT_PARSE_ENABLE_DEBUG:
			dao_info("Packet capture enabled");
			cfg_prm->enable_debug = 1;
			break;

		case CMD_LINE_OPT_PARSE_ENABLE_GRAPH_STATS:
			dao_info("Graph stats enabled");
			cfg_prm->enable_graph_stats = 1;
			break;

		case CMD_LINE_OPT_PARSE_MBUF_DATA_SIZE: {
			uint32_t sz = parse_u32_decimal(optarg);

			cfg_prm->mbuf_data_size = sz;
			dao_info("mbuf data size: %u", cfg_prm->mbuf_data_size);
			break;
		}

		case CMD_LINE_OPT_PARSE_NUM_MBUFS: {
			uint32_t n = parse_u32_decimal(optarg);

			cfg_prm->num_mbufs = n;
			dao_info("num mbufs: %u", cfg_prm->num_mbufs);
			break;
		}
		case CMD_LINE_OPT_PARSE_DMA_FLUSH_THR: {
			long thr;
			char *end = NULL;

			thr = strtol(optarg, &end, 10);
			if ((optarg[0] == '\0') || (end == NULL) || (*end != '\0') || thr < 0 ||
			    thr > 15) {
				dao_err("invalid dma-flush-thr (0-15)");
				rdma_print_usage(prgname);
				return -1;
			}
			cfg_prm->dma_flush_thr = (uint16_t)thr;
			dao_info("DMA flush threshold set to %u", cfg_prm->dma_flush_thr);
			break;
		}
		case CMD_LINE_OPT_PARSE_DMA_NB_DESC: {
			long ndesc;
			char *end = NULL;

			ndesc = strtol(optarg, &end, 10);
			if ((optarg[0] == '\0') || (end == NULL) || (*end != '\0') || ndesc <= 0 ||
			    ndesc > 65535) {
				dao_err("invalid dma-nb-desc (1-65535)");
				rdma_print_usage(prgname);
				return -1;
			}
			cfg_prm->dma_nb_desc = (uint16_t)ndesc;
			dao_info("DMA nb_desc set to %u", cfg_prm->dma_nb_desc);
			break;
		}
		default:
			rdma_print_usage(prgname);
			return -1;
		}
	}

	/* If not using rdma_map_config_enable,
	 * map each enabled RDMA device to the
	 * next enabled eth port */
	if (cfg_prm->rdma_map_config_enable == 0) {
		int eth_idx = 0;

		for (int rdma_devid = 0; rdma_devid < RDMA_MAX_DEVS; rdma_devid++) {
			if (cfg_prm->enabled_dev_mask & (1 << rdma_devid)) {
				rdma_map[rdma_devid].id = eth_idx;
				eth_map[eth_idx].id = rdma_devid;
				eth_idx++;
			}
		}
	}

	if (optind >= 0)
		argv[optind - 1] = prgname;

	rc = optind - 1;
	optind = 1; /* reset getopt lib */
	return rc;
}
