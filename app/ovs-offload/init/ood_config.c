/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2023 Marvell.
 */

#include <getopt.h>
#include <stdlib.h>

#include <ood_config.h>
#include <ood_init.h>
#include <ood_lcore.h>

#include <dao_log.h>

#define MAX_PARAMS 128

#define CMD_LINE_OPT_NO_MAC_UPDATING    "no-mac-updating"
#define CMD_LINE_OPT_CONFIG             "config"
#define CMD_LINE_OPT_PORTMAP_CONFIG     "portmap"
#define CMD_LINE_OPT_PER_PORT_POOL      "per-port-pool"
#define CMD_LINE_OPT_MAX_PKT_LEN        "max-pkt-len"
#define CMD_LINE_OPT_PCAP_ENABLE        "pcap-enable"
#define CMD_LINE_OPT_NUM_PKT_CAP        "pcap-num-cap"
#define CMD_LINE_OPT_PCAP_FILENAME      "pcap-file-name"
#define CMD_LINE_OPT_ENABLE_DEBUG       "enable-debug"
#define CMD_LINE_OPT_ENABLE_GRAPH_STATS "enable-graph-stats"

static const char short_options[] = "p:" /* portmask */
				    "P"  /* promiscuous */
	;
enum {
	/* long options mapped to a short option */

	/* first long only option value must be >= 256, so that we won't
	 * conflict with short options */
	CMD_LINE_OPT_NO_MAC_UPDATING_NUM = 256,
	CMD_LINE_OPT_CONFIG_NUM,
	CMD_LINE_OPT_PORTMAP_NUM,
	CMD_LINE_OPT_PARSE_PER_PORT_POOL,
	CMD_LINE_OPT_MAX_PKT_LEN_NUM,
	CMD_LINE_OPT_PARSE_PCAP_ENABLE,
	CMD_LINE_OPT_PARSE_NUM_PKT_CAP,
	CMD_LINE_OPT_PCAP_FILENAME_CAP,
	CMD_LINE_OPT_PARSE_ENABLE_DEBUG,
	CMD_LINE_OPT_PARSE_ENABLE_GRAPH_STATS,
};

enum fld_type {
	INT_FLD = 0,
	STR_FLD,
};

static const struct option lgopts[] = {
	{CMD_LINE_OPT_NO_MAC_UPDATING, no_argument, 0, CMD_LINE_OPT_NO_MAC_UPDATING_NUM},
	{CMD_LINE_OPT_CONFIG, 1, 0, CMD_LINE_OPT_CONFIG_NUM},
	{CMD_LINE_OPT_PORTMAP_CONFIG, 1, 0, CMD_LINE_OPT_PORTMAP_NUM},
	{CMD_LINE_OPT_PER_PORT_POOL, 0, 0, CMD_LINE_OPT_PARSE_PER_PORT_POOL},
	{CMD_LINE_OPT_MAX_PKT_LEN, 1, 0, CMD_LINE_OPT_MAX_PKT_LEN_NUM},
	{CMD_LINE_OPT_PCAP_ENABLE, 0, 0, CMD_LINE_OPT_PARSE_PCAP_ENABLE},
	{CMD_LINE_OPT_NUM_PKT_CAP, 1, 0, CMD_LINE_OPT_PARSE_NUM_PKT_CAP},
	{CMD_LINE_OPT_PCAP_FILENAME, 1, 0, CMD_LINE_OPT_PCAP_FILENAME_CAP},
	{CMD_LINE_OPT_ENABLE_DEBUG, 0, 0, CMD_LINE_OPT_PARSE_ENABLE_DEBUG},
	{CMD_LINE_OPT_ENABLE_GRAPH_STATS, 0, 0, CMD_LINE_OPT_PARSE_ENABLE_GRAPH_STATS},
	{NULL, 0, 0, 0}};

/* display usage */
void
ood_print_usage(const char *prgname)
{
	dao_info("%s [EAL options] -- -p PORTMASK [-P] [-q NQ]\n"
		 "  -p PORTMASK: hexadecimal bitmask of ports to configure\n"
		 "  -P : Enable promiscuous mode\n"
		 "  --config (port,queue,lcore): Rx queue configuration\n"
		 "  --no-mac-updating: Disable MAC addresses updating (enabled by default)\n"
		 "      When enabled:\n"
		 "       - The source MAC address is replaced by the TX port MAC address\n"
		 "       - The destination MAC address is replaced by 02:00:00:00:00:TX_PORT_ID\n"
		 "  --portmap: Configure forwarding port pair mapping\n"
		 "	      Default: alternate port pairs\n\n"
		 "  --max-pkt-len PKTLEN: maximum packet length in decimal (64-9600)\n"
		 "  --per-port-pool: Use separate buffer pool per port\n"
		 "  --pcap-enable: Enables pcap capture\n"
		 "  --pcap-num-cap NUMPKT: Number of packets to capture\n"
		 "  --pcap-file-name NAME: Pcap file name\n\n"
		 "  --enable-debug: Enable debug mode\n\n"
		 "  --enable-graph-stats: Enable graph statistics\n\n",
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

static int
parse_config(const char *q_arg, uint64_t **fields, uint8_t nb_flds, enum fld_type ft)
{
	const char *p, *p0 = q_arg;
	char *str_fld[MAX_PARAMS];
	uint16_t nb_params = 0, portid;
	uint32_t size;
	char s[256];
	char *end = NULL;
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
		if (rte_strsplit(s, sizeof(s), str_fld, nb_flds, ',') != nb_flds)
			return -1;
		if (fields) {
			for (i = 0; i < nb_flds; i++) {
				errno = 0;
				if (ft == INT_FLD) {
					fields[nb_params][i] = strtoul(str_fld[i], &end, 0);
				} else {
					rte_eth_dev_get_port_by_name(str_fld[i], &portid);
					fields[nb_params][i] = portid;
				}
				if (errno != 0 || end == str_fld[i])
					return -1;
			}
		}
		nb_params++;
	}

	return nb_params;
}

static int
parse_lcore_config(ood_lcore_param_t *lcore_prm, const char *q_arg)
{
	enum fieldnames { FLD_PORT = 0, FLD_QUEUE, FLD_LCORE, _NUM_FLD };
	int nb_lcore_params;
	uint64_t **int_fld;
	int i, rc = 0;

	nb_lcore_params = parse_config(q_arg, NULL, _NUM_FLD, INT_FLD);
	if (nb_lcore_params < 0) {
		dao_err("no of lcore params parsing failed");
		return -1;
	}

	int_fld = calloc(1, nb_lcore_params * sizeof(uint64_t *));
	if (int_fld) {
		for (i = 0; i < nb_lcore_params; i++) {
			int_fld[i] = calloc(1, _NUM_FLD * sizeof(uint64_t));
			if (!int_fld[i]) {
				free(int_fld);
				return -1;
			}
		}
	} else {
		return -1;
	}
	nb_lcore_params = parse_config(q_arg, int_fld, _NUM_FLD, INT_FLD);
	if (nb_lcore_params >= OOD_MAX_LCORE_PARAMS) {
		dao_err("Exceeded max number of lcore params: %u\n", nb_lcore_params);
		rc = -1;
		goto error;
	}

	for (i = 0; i < nb_lcore_params; i++) {
		if (int_fld[i][FLD_PORT] >= RTE_MAX_ETHPORTS ||
		    int_fld[i][FLD_LCORE] >= RTE_MAX_LCORE) {
			dao_err("Invalid port %ld OR lcore id %ld", int_fld[i][FLD_PORT],
				int_fld[i][FLD_LCORE]);
			rc = -1;
			goto error;
		}

		lcore_prm->lcore_params_array[i].port_id = (uint8_t)int_fld[i][FLD_PORT];
		lcore_prm->lcore_params_array[i].queue_id = (uint8_t)int_fld[i][FLD_QUEUE];
		lcore_prm->lcore_params_array[i].lcore_id = (uint8_t)int_fld[i][FLD_LCORE];
	}

	lcore_prm->nb_lcore_params = nb_lcore_params;
error:
	for (i = 0; i < nb_lcore_params; i++)
		free(int_fld[i]);
	free(int_fld);

	return rc;
}

static int
parse_port_pair_config(ood_config_param_t *cfg_prm, const char *q_arg)
{
	enum fieldnames { FLD_PORT1 = 0, FLD_PORT2, _NUM_FLD };
	int nb_port_pair_params;
	unsigned long **int_fld;
	int i;

	nb_port_pair_params = parse_config(q_arg, NULL, _NUM_FLD, STR_FLD);
	if (nb_port_pair_params < 0) {
		dao_err("no of port pairs parsing failed");
		return -1;
	}

	if (nb_port_pair_params >= RTE_MAX_ETHPORTS / 2) {
		dao_err("exceeded max number of port pair params: %u\n", nb_port_pair_params);
		return -1;
	}

	int_fld = calloc(1, nb_port_pair_params * sizeof(uint64_t *));
	if (int_fld) {
		for (i = 0; i < nb_port_pair_params; i++) {
			int_fld[i] = calloc(1, _NUM_FLD * sizeof(uint64_t));
			if (!int_fld[i]) {
				free(int_fld);
				return -1;
			}
		}
	} else {
		return -1;
	}

	nb_port_pair_params = parse_config(q_arg, int_fld, _NUM_FLD, STR_FLD);
	for (i = 0; i < nb_port_pair_params; i++) {
		cfg_prm->port_pair_param[i].port[0] = (uint16_t)int_fld[i][FLD_PORT1];
		cfg_prm->port_pair_param[i].port[1] = (uint16_t)int_fld[i][FLD_PORT2];
	}

	cfg_prm->nb_port_pair_params = nb_port_pair_params;
	for (i = 0; i < nb_port_pair_params; i++)
		free(int_fld[i]);
	free(int_fld);

	return 0;
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
ood_parse_args(int argc, char **argv, struct ood_main_cfg_data *ood_main_cfg)
{
	ood_config_param_t *cfg_prm;
	char *prgname = argv[0];
	int option_index;
	char **argvopt;
	int opt, rc;

	argvopt = argv;

	cfg_prm = ood_main_cfg->cfg_prm;
	cfg_prm->mac_updating = 1;
	while ((opt = getopt_long(argc, argvopt, short_options, lgopts, &option_index)) != EOF) {
		switch (opt) {
		/* portmask */
		case 'p':
			cfg_prm->enabled_port_mask = parse_portmask(optarg);
			if (cfg_prm->enabled_port_mask == 0) {
				dao_err("invalid portmask");
				ood_print_usage(prgname);
				return -1;
			}
			break;
		case 'P':
			cfg_prm->promiscuous_on = 1;
			break;

		/* long options */
		case CMD_LINE_OPT_CONFIG_NUM:
			rc = parse_lcore_config(ood_main_cfg->lcore_prm, optarg);
			if (rc) {
				dao_err("Invalid config");
				ood_print_usage(prgname);
				return -1;
			}
			break;

		case CMD_LINE_OPT_PORTMAP_NUM:
			rc = parse_port_pair_config(ood_main_cfg->cfg_prm, optarg);
			if (rc) {
				dao_err("Invalid config");
				ood_print_usage(prgname);
				return -1;
			}
			break;

		case CMD_LINE_OPT_PARSE_PER_PORT_POOL:
			dao_info("Per port buffer pool is enabled\n");
			cfg_prm->per_port_pool = 1;
			break;

		case CMD_LINE_OPT_MAX_PKT_LEN_NUM: {
			cfg_prm->max_pkt_len = parse_max_pkt_len(optarg);
			break;
		}

		case CMD_LINE_OPT_NO_MAC_UPDATING_NUM:
			cfg_prm->mac_updating = 0;
			break;

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
			dao_info("Pcap file name: %s\n", cfg_prm->pcap_filename);
			break;

		case CMD_LINE_OPT_PARSE_ENABLE_DEBUG:
			dao_info("Packet capture enabled\n");
			cfg_prm->enable_debug = 1;
			break;

		case CMD_LINE_OPT_PARSE_ENABLE_GRAPH_STATS:
			printf("Packet capture enabled\n");
			cfg_prm->enable_graph_stats = 1;
			break;

		default:
			ood_print_usage(prgname);
			return -1;
		}
	}

	if (optind >= 0)
		argv[optind - 1] = prgname;

	rc = optind - 1;
	optind = 1; /* reset getopt lib */
	return rc;
}
