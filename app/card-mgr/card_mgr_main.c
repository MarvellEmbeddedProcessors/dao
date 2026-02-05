/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <arpa/inet.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <dao_log.h>

#include "card_mgr.h"
#include "card_mgr_client.h"
#include "card_mgr_server.h"
#include "utils/logging.h"

/* Global state */
atomic_bool dao_card_force_quit;
struct dao_card_grpc_ctx *card_ctx;
char remote_card_ip[INET_ADDRSTRLEN] = "192.168.1.1"; /* target card IP */

static struct option long_options[] = {
	{"help", no_argument, 0, 'h'},     {"client", no_argument, 0, 'c'},
	{"server", no_argument, 0, 's'},   {"server_cli", no_argument, 0, 'f'},
	{"ip", required_argument, 0, 'i'}, {0, 0, 0, 0}};

/* Command specifications table */
const struct dao_card_cmd_spec dao_card_cmd_specs[] = {
	{DAO_CARD_MGR_CARD_INIT, 1, 2, "[enable-compress-dev]", "Initialize card"},
	{DAO_CARD_MGR_CARD_FINI, 1, 1, "", "Stop card and free resources"},
	{DAO_CARD_MGR_CARD_INFO, 1, 1, "", "Show card information"},
	{DAO_CARD_MGR_IMAGE_VERSION, 1, 1, "", "Show rootfs and app version from card"},
	{DAO_CARD_MGR_CARD_STATS, 1, 1, "", "Show aggregated packet stats"},
	{DAO_CARD_MGR_DMESG, 1, 1, "", "Fetch recent kernel dmesg lines"},
	{DAO_CARD_MGR_APPLOG, 1, 1, "", "Fetch recent application log tail"},
	{DAO_CARD_MGR_CARD_TEMPERATURE, 1, 1, "", "Show voltage/temperature sensors"},
	{DAO_CARD_MGR_APP_FALLBACK, 2, 2, "<absolute_path/mrvl-oct-boot>",
	 "Fallback to previous working application"},
	{DAO_CARD_MGR_BOOT_SOURCE, 3, 3, "<main|failsafe> <absolute_path/mrvl-oct-boot>",
	 "Reboot the card from the specified boot source"},
	{DAO_CARD_MGR_CARD_REBOOT, 1, 1, "", "Reboot the card using current boot source"},
	{DAO_CARD_MGR_MCU_UPDATE, 2, 2, "<absolute_path/file>", "Update MCU firmware"},
	{DAO_CARD_MGR_APP_UPDATE, 3, 3, "<absolute_path/file> <absolute_path/mrvl-oct-boot>",
	 "Update application image"},
	{DAO_CARD_MGR_FW_UPDATE, 3, 3, "<absolute_path/file> <absolute_path/mrvl-oct-boot>",
	 "Update firmware image"},
	{DAO_CARD_MGR_FAILSAFE_UPDATE, 3, 3, "<absolute_path/file> <absolute_path/mrvl-oct-boot>",
	 "Update failsafe image"},
	{DAO_CARD_MGR_SOFT_RESET, 1, 1, "",
	 "Perform a soft reset on the card and re-initialize without rebooting"},
	{"help", 1, 1, "", "Show this help/command list"},
};

const size_t dao_card_cmd_specs_count = ARRAY_SIZE(dao_card_cmd_specs);

const struct dao_card_cmd_spec *
dao_card_lookup_cmd(const char *cmd)
{
	if (cmd == NULL)
		return NULL;

	for (size_t i = 0; i < dao_card_cmd_specs_count; i++) {
		if (strcmp(cmd, dao_card_cmd_specs[i].name) == 0)
			return &dao_card_cmd_specs[i];
	}
	return NULL;
}

/* display usage */
static void
dao_card_mgr_usage_print(void)
{
	fprintf(stderr, "Usage: dao_card_mgr [--help] [--client] [--server --ip <IP address>]"
			" [--server_cli]\n");
	fprintf(stderr, "-h, --help Display the usage\n");
	fprintf(stderr, "-c, --client Run the manager as client mode\n");
	fprintf(stderr, "-s, --server Run the manager as server mode\n");
	fprintf(stderr, "-f, --server_cli Run the manager as server in cli mode\n");
}

int
main(int argc, char **argv)
{
	dao_card_mgr_instance mgr_instance = DAO_CARD_MGR_INVALID;
	int option, index = 0;
	const char *ip_str = NULL;
	int ret;

	atomic_init(&dao_card_force_quit, false);
	if (signal(SIGINT, dao_card_signal_handler) == SIG_ERR) {
		dao_err("Failed to register SIGINT handler");
		return EXIT_FAILURE;
	}
	if (signal(SIGTERM, dao_card_signal_handler) == SIG_ERR) {
		dao_err("Failed to register SIGTERM handler");
		return EXIT_FAILURE;
	}

	while ((option = getopt_long(argc, argv, "hcsfi:", long_options, &index)) != -1) {
		switch (option) {
		case 'c':
			mgr_instance = DAO_CARD_MGR_AS_CLIENT;
			break;
		case 's':
			mgr_instance = DAO_CARD_MGR_AS_SERVER;
			break;
		case 'f':
			mgr_instance = DAO_CARD_MGR_AS_SERVER_CLI;
			break;
		case 'i': {
			struct sockaddr_in sa;

			ip_str = optarg;
			/* Validate IP address format */
			if (inet_pton(AF_INET, ip_str, &(sa.sin_addr)) != 1) {
				dao_err("Invalid IP address format: %s", ip_str);
				dao_card_mgr_usage_print();
				return EXIT_FAILURE;
			}
			break;
		}
		case 'h':
			dao_card_mgr_usage_print();
			return EXIT_SUCCESS;
		default:
			dao_err("Invalid option. exiting");
			dao_card_mgr_usage_print();
			return EXIT_FAILURE;
		}
	}

	/* Require root privileges (simplified check) */
	if (geteuid() != 0) {
		dao_err("module reload & interface operations require root privilege");
		return EXIT_FAILURE;
	}

	ret = EXIT_SUCCESS;

	switch (mgr_instance) {
	case DAO_CARD_MGR_AS_CLIENT:
		dao_info("Starting as client");
		ret = dao_card_mgr_client();
		if (ret != 0)
			dao_err("Client mode failed with error: %d", ret);
		break;
	case DAO_CARD_MGR_AS_SERVER:
		dao_info("Starting as server");
		ret = dao_card_mgr_server(ip_str);
		if (ret != 0)
			dao_err("Server mode failed with error: %d", ret);
		break;
	case DAO_CARD_MGR_AS_SERVER_CLI:
		dao_err("Server CLI mode not yet implemented");
		ret = EXIT_FAILURE;
		break;
	default:
		dao_err("No valid mode specified");
		dao_card_mgr_usage_print();
		ret = EXIT_FAILURE;
		break;
	}
	return ret;
}
