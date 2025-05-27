/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <arpa/inet.h>
#include <editline/readline.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <histedit.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>

#include <dao_card_grpc_client.h>
#include <dao_log.h>

#define DAO_CARD_NB_DESC         1024
#define DAO_CARD_MGR_PORT        50055
#define DAO_CARD_GRPC_PORT       50051
#define DAO_CARD_MGR_MAX_CLIENTS 10
#define BUFFER_SIZE              1024

typedef enum dao_card_mgr_instance {
	DAO_CARD_MGR_AS_SERVER,
	DAO_CARD_MGR_AS_CLIENT,
	DAO_CARD_MGR_AS_SERVER_CLI,
	DAO_CARD_MGR_INVALID,
} dao_card_mgr_instance;

typedef struct {
	int argc;
	char **argv;
} cli_args;

static struct dao_card_grpc_ctx *card_ctx;

const char *dao_card_mgr_cmds[] = {"card_init", "card_fini", "card_info"};

static struct option long_options[] = {
		{"help", no_argument, 0, 'h'},
		{"client", no_argument, 0, 'c'},
		{"server", no_argument, 0, 's'},
		{"server_cli", no_argument, 0, 'f'},
		{"ip", required_argument, 0, 'i'},
		{0, 0, 0, 0}};

static volatile bool force_quit;

static void
signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		dao_info("Signal %d received, preparing to exit...", signum);
		force_quit = true;
	}
}

static void
dao_card_cmd_usage_print(void)
{
	fprintf(stderr, "Supported commands:\n");
	fprintf(stderr, " help: Display the usage\n");
	fprintf(stderr,
		" card_init [--nb_desc <number of descriptors>] [EAL args]:  Initializes the DAO card\n");
	fprintf(stderr, " card_fini: Frees any allocated resources and stops the DAO card\n");
	fprintf(stderr, " card_info: Gets the information from the DAO card\n");
	fprintf(stderr, " quit: Exit the application\n");
}

static void
dao_card_mgr_send_to_server(int cli_fd, const char *line)
{
	struct dao_card_info card_info;
	int resp;

	if (strstr(line, "help") != NULL) {
		dao_card_cmd_usage_print();
		return;
	}

	/* Send command to server */
	if (send(cli_fd, line, strlen(line), 0) == -1) {
		dao_err("sending cmd to server failed");
		return;
	}

	/* Wait for the response */
	recv(cli_fd, &resp, sizeof(int), 0);
	if (resp) {
		dao_err("Received error for the command");
		return;
	}

	/* Dump the received info, if the cmd is to get the info */
	if (!resp && strstr(line, "card_info") != NULL) {
		recv(cli_fd, &card_info, sizeof(struct dao_card_info), 0);
		dao_info("Card info: num SDP devices: %d, max_sessions: %d", card_info.nb_devs,
			 card_info.max_sessions);
	}
}

static int
dao_card_mgr_client_init(void)
{
	struct sockaddr_in server_addr;
	int cli_fd;

	cli_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (cli_fd < 0) {
		dao_err("socket failed");
		return -1;
	}

	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	server_addr.sin_port = htons(DAO_CARD_MGR_PORT);

	if (connect(cli_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
		dao_err("connect failed");
		close(cli_fd);
		return -1;
	}

	return cli_fd;
}

static int
dao_card_mgr_editline_init(History **hist, EditLine **el, HistEvent *ev)
{
	/* Initialize editline */
	*el = el_init("dao_card_mgr_cli", stdin, stdout, stderr);

	/* Initialize history */
	*hist = history_init();
	if (*hist == 0) {
		fprintf(stderr, "history could not be initialized\n");
		return -1;
	}

	/*  Set history size to 100 */
	history(*hist, ev, H_SETSIZE, 100);

	/* Set editline to use history */
	el_set(*el, EL_HIST, history, *hist);

	return 0;
}

static void
dao_card_mgr_editline_fini(History *hist, EditLine *el)
{
	history_end(hist);
	el_end(el);
}

static void
dao_card_mgr_client(void)
{
	int count, cli_fd;
	const char *line;
	History *hist;
	EditLine *el;
	HistEvent ev;

	if (dao_card_mgr_editline_init(&hist, &el, &ev)) {
		dao_err("Editline initialization failed");
		return;
	}

	cli_fd = dao_card_mgr_client_init();
	if (cli_fd < 0) {
		dao_err("client socket initialization failed");
		goto editline_fini;
	}

	while (!force_quit) {
		line = el_gets(el, &count);
		if (line != NULL && count > 0) {
			if (count == 1 && line[0] == '\n')
				continue;

			if (strstr(line, "quit") != NULL)
				break;

			/* Add line to history */
			history(hist, &ev, H_ENTER, line);
			dao_card_mgr_send_to_server(cli_fd, line);
		}
	}

editline_fini:
	dao_card_mgr_editline_fini(hist, el);
	close(cli_fd);
}

/* display usage */
static void
dao_card_mgr_usage_print(void)
{
	fprintf(stderr,
		"Usage: dao_card_mgr [--help] [--client] [--server --ip <IP address>] [--server_cli]\n");
	fprintf(stderr, "-h, --help Display the usage\n");
	fprintf(stderr, "-c, --client Run the manager as client mode\n");
	fprintf(stderr, "-s, --server Run the manager as server mode\n");
	fprintf(stderr, "-f, --server_cli Run the manager as server in cli mode\n");
}

static void
dao_card_mgr_process_cmd(int cli_fd, cli_args *cmd)
{
	struct dao_card_config card_cfg;
	struct dao_card_info card_info;
	int rc = 0;

	if (strcmp(cmd->argv[0], dao_card_mgr_cmds[0]) == 0) {
		int skip_args = 1;

		card_cfg.crypto_nb_desc = DAO_CARD_NB_DESC;

		if ((cmd->argc > 1) && (strcmp(cmd->argv[1], "--nb_desc") == 0)) {
			card_cfg.crypto_nb_desc = atoi(cmd->argv[3]);
			skip_args += 2;
		}

		card_cfg.argc = cmd->argc - skip_args;
		if (card_cfg.argc)
			card_cfg.argv = cmd->argv + skip_args;
		else
			card_cfg.argv = NULL;

		rc = dao_card_init(card_ctx, &card_cfg);
	} else if (strcmp(cmd->argv[0], dao_card_mgr_cmds[1]) == 0) {
		dao_card_fini(card_ctx);
	} else if (strcmp(cmd->argv[0], dao_card_mgr_cmds[2]) == 0) {
		rc = dao_card_info_get(card_ctx, &card_info);
	} else {
		syslog(LOG_ERR, "Unsupported command");
		rc = -1;
	}
	send(cli_fd, &rc, sizeof(rc), 0);

	if (!rc && strcmp(cmd->argv[0], dao_card_mgr_cmds[2]) == 0)
		send(cli_fd, &card_info, sizeof(struct dao_card_info), 0);
}

static void
dao_card_mgr_parse_args(const char *line, cli_args *cmd_args)
{
	char *token;

	cmd_args->argc = 0;
	cmd_args->argv = NULL;

	token = strtok(strdup(line), " \t\n");
	while (token != NULL) {
		cmd_args->argv = realloc(cmd_args->argv, sizeof(char *) * (cmd_args->argc + 1));
		cmd_args->argv[cmd_args->argc++] = token;
		token = strtok(NULL, " \t\n");
	}

	if (cmd_args->argc == 0)
		free(cmd_args->argv);
}

static void
dao_card_mgr_listen(int cli_socket)
{
	cli_args cmd_args;
	ssize_t recv_len;

	while (!force_quit) {
		char buffer[1024];

		recv_len = recv(cli_socket, buffer, sizeof(buffer), 0);
		if (recv_len <= 0) {
			syslog(LOG_INFO, "Client closed the connection");
			break;
		}

		if (recv_len < 0) {
			dao_err("Could not receive command from client");
			continue;
		}

		buffer[recv_len] = '\0';
		dao_card_mgr_parse_args(buffer, &cmd_args);
		dao_card_mgr_process_cmd(cli_socket, &cmd_args);

		free(cmd_args.argv);
	}
}

static int
dao_card_mgr_server_init(const char *ip_str)
{
	struct sockaddr_in sock_addr;
	int rc = -1;
	int srv_fd;

	srv_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (srv_fd == 0) {
		syslog(LOG_ERR, "Could not create server socket");
		return -1;
	}

	sock_addr.sin_family = AF_INET;
	sock_addr.sin_addr.s_addr = INADDR_ANY;
	sock_addr.sin_port = htons(DAO_CARD_MGR_PORT);

	if (bind(srv_fd, (struct sockaddr *)&sock_addr, sizeof(struct sockaddr_in)) < 0) {
		syslog(LOG_ERR, "Could not bind the socket");
		goto srv_fini;
	}

	if (ip_str == NULL)
		card_ctx = dao_card_grpc_client_init("192.168.1.1", DAO_CARD_GRPC_PORT);
	else
		card_ctx = dao_card_grpc_client_init(ip_str, DAO_CARD_GRPC_PORT);

	if (card_ctx == NULL) {
		syslog(LOG_ERR, "gRPC client init failed");
		goto srv_fini;
	}
	if (listen(srv_fd, 3) < 0) {
		syslog(LOG_ERR, "error on listen");
		goto grpc_fini;
	}
	return srv_fd;

grpc_fini:
	dao_card_grpc_client_fini(card_ctx);
srv_fini:
	close(srv_fd);
	return rc;
}

static void
dao_card_mgr_server(const char *ip_str)
{
	int addrlen = sizeof(struct sockaddr_in);
	struct sockaddr_in sock_addr;
	int srv_fd, cli_fd;
	int flags;

	srv_fd = dao_card_mgr_server_init(ip_str);
	if (srv_fd < 0) {
		dao_err("Could not initialize the server");
		return;
	}
	flags = fcntl(srv_fd, F_GETFL, 0);
	fcntl(srv_fd, F_SETFL, flags | O_NONBLOCK);

	while (!force_quit) {
		cli_fd = accept(srv_fd, (struct sockaddr *)&sock_addr, (socklen_t *)&addrlen);
		if (cli_fd < 0)
			continue;

		dao_card_mgr_listen(cli_fd);
		close(cli_fd);
	}

	dao_card_grpc_client_fini(card_ctx);
	close(srv_fd);
}

int
main(int argc, char **argv)
{
	dao_card_mgr_instance mgr_instance = DAO_CARD_MGR_INVALID;
	const char *ip_str = NULL;
	int option, index = 0;

	force_quit = false;
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

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
		case 'i':
			ip_str = optarg;
			break;
		case 'h':
			dao_card_mgr_usage_print();
			break;
		default:
			dao_err("Invalid option. exiting");
			dao_card_mgr_usage_print();
			break;
		}
	}

	switch (mgr_instance) {
	case DAO_CARD_MGR_AS_CLIENT:
		dao_info("Starting as client");
		dao_card_mgr_client();
		break;
	case DAO_CARD_MGR_AS_SERVER:
		dao_info("Starting as server");
		dao_card_mgr_server(ip_str);
		break;
	case DAO_CARD_MGR_AS_SERVER_CLI:
		dao_info("Support need to be added");
		break;
	default:
		dao_info("Unsupported mode");
		break;
	}
	return 0;
}
