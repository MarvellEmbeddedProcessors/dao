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

#define DAO_CARD_CFG_NB_DESC 1024

#define DAO_CARD_MGR_PORT        50055
#define DAO_CARD_GRPC_PORT       50051
#define DAO_CARD_MGR_MAX_CLIENTS 10
#define BUFFER_SIZE              1024
#define CA_MAX_WORKER_CORES      23

#define DAO_CARD_MGR_CARD_INIT  "card_init"
#define DAO_CARD_MGR_CARD_FINI  "card_fini"
#define DAO_CARD_MGR_CARD_INFO  "card_info"
#define DAO_CARD_MGR_APP_UPDATE "card_app_update"
#define DAO_CARD_MGR_CARD_STATS "card_stats"
#define DAO_CARD_MGR_FW_UPDATE  "card_fw_update"

typedef enum dao_card_mgr_instance {
	DAO_CARD_MGR_AS_SERVER,
	DAO_CARD_MGR_AS_CLIENT,
	DAO_CARD_MGR_AS_SERVER_CLI,
	DAO_CARD_MGR_INVALID,
} dao_card_mgr_instance;

typedef struct {
	int argc;
	char **argv;
	char *line;
} cli_args;

static struct dao_card_grpc_ctx *card_ctx;

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
	fprintf(stderr, " card_init [--nb_desc <number of descriptors>] [EAL args]:"
			"Initializes the DAO card\n");
	fprintf(stderr, " card_fini: Frees any allocated resources and stops the DAO card\n");
	fprintf(stderr, " card_info: Gets the information from the DAO card\n");
	fprintf(stderr,
		" card_app_update [absolute path of file]: Update the given file on to the card\n");
	fprintf(stderr, " card_stats: Gets the stats from the DAO card\n");
	fprintf(stderr,
		" card_fw_update: [absolute path of file]: Update the image on to the DAO card.\n");
	fprintf(stderr, " quit: Exit the application\n");
}

static int
split_path_filename(const char *input, char **out_path, char **out_file)
{
	char *last_slash = strrchr(input, '/');
	*out_path = NULL;
	*out_file = NULL;

	if (last_slash != NULL) {
		size_t path_len = last_slash - input;

		*out_path = (char *)malloc(path_len + 1);
		if (!*out_path)
			return -ENOMEM;
		if (path_len > 0) {
			strncpy(*out_path, input, path_len);
			(*out_path)[path_len] = '\0';
		} else {
			(*out_path)[0] = '\0';
		}
		*out_file = strdup(last_slash + 1);
		if (!*out_file) {
			free(*out_path);
			*out_path = NULL;
			return -ENOMEM;
		}
	} else {
		char cwd[1024];

		if (getcwd(cwd, sizeof(cwd)) == NULL)
			return -EFAULT;
		*out_path = strdup(cwd);
		if (!*out_path)
			return -ENOMEM;
		*out_file = strdup(input);
		if (!*out_file) {
			free(*out_path);
			*out_path = NULL;
			return -ENOMEM;
		}
	}
	return 0;
}

static void
dao_card_mgr_send_to_server(int cli_fd, const char *line)
{
	struct dao_card_stats card_stats;
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
		if (resp == ENOTSUP)
			dao_err("Command is not supported");
		else
			dao_err("Received error for the command: %d", resp);
		return;
	}

	/* Dump the received info, if the cmd is to get the info */
	if (!resp && strstr(line, "card_info") != NULL) {
		recv(cli_fd, &card_info, sizeof(struct dao_card_info), 0);
		dao_info("Card info: version: %s, num SDP devices: %d, max_sessions: %d",
			 card_info.version, card_info.nb_devs, card_info.max_sessions);
	}

	/* Dump the stats info */
	if (!resp && strstr(line, "card_stats") != NULL) {
		int i = 0;
		uint64_t total_rx_pkts = 0, total_tx_pkts = 0;

		recv(cli_fd, &card_stats, sizeof(struct dao_card_stats), 0);

		dao_info("LC stats:");
		dao_info("--------------------------------------------------");
		dao_info("| Core |      RX Packets      |      TX Packets      |");
		dao_info("--------------------------------------------------");

		for (i = 0; i < CA_MAX_WORKER_CORES; i++) {
			dao_info("| %4u | %20lu | %20lu |", i + 1, card_stats.rx_packets[i],
				 card_stats.tx_packets[i]);
			total_rx_pkts += card_stats.rx_packets[i];
			total_tx_pkts += card_stats.tx_packets[i];
		}

		dao_info("--------------------------------------------------");
		dao_info("| Total| %20lu | %20lu |", total_rx_pkts, total_tx_pkts);
		dao_info("--------------------------------------------------");
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
	fprintf(stderr, "Usage: dao_card_mgr [--help] [--client] [--server --ip <IP address>]"
			" [--server_cli]\n");
	fprintf(stderr, "-h, --help Display the usage\n");
	fprintf(stderr, "-c, --client Run the manager as client mode\n");
	fprintf(stderr, "-s, --server Run the manager as server mode\n");
	fprintf(stderr, "-f, --server_cli Run the manager as server in cli mode\n");
}

static int
dao_card_mgr_app_update(cli_args *cmd)
{
	struct dao_card_app_update_req update_req;
	int rc = 0;

	if (cmd->argc < 2) {
		syslog(LOG_ERR, "card_app_update command requires file to update");
		return -EINVAL;
	}

	update_req.filename = NULL;
	update_req.filepath = NULL;

	rc = split_path_filename(cmd->argv[1], &update_req.filepath, &update_req.filename);
	if (rc != 0) {
		syslog(LOG_ERR, "Failed to split path/filename for app update: %s", strerror(-rc));
		return rc;
	}

	rc = dao_card_app_update(card_ctx, &update_req);

	free(update_req.filename);
	free(update_req.filepath);
	return rc;
}

static int
dao_card_mgr_fw_update(cli_args *cmd)
{
	struct dao_card_fw_update_req update_req;
	char fullpath[PATH_MAX];
	int rc = 0;

	if (cmd->argc < 2) {
		syslog(LOG_ERR, "card_fw_update command requires file to update");
		return -EINVAL;
	}

	update_req.filename = NULL;
	update_req.filepath = NULL;

	rc = split_path_filename(cmd->argv[1], &update_req.filepath, &update_req.filename);
	if (rc != 0) {
		syslog(LOG_ERR, "Failed to split path/filename for app update: %s", strerror(-rc));
		return rc;
	}

	snprintf(fullpath, PATH_MAX, "%s/%s", update_req.filepath, update_req.filename);
	if (access(fullpath, F_OK | R_OK) != 0) {
		rc = -errno;
		syslog(LOG_ERR, "Firmware update file '%s' does not exist or is not accessible: %s",
		       fullpath, strerror(errno));
		free(update_req.filename);
		free(update_req.filepath);
		return rc;
	}
	rc = dao_card_fw_update(card_ctx, &update_req);

	free(update_req.filename);
	free(update_req.filepath);
	return rc;
}

static int
dao_card_mgr_update_init_args(cli_args *cmd, const char **new_argv, unsigned long *nb_desc)
{
	const char *app_name = "dao-crypto-agent";
	int has_c = 0, has_l = 0;
	int insert_index = -1;
	int eal_end, j = 1;
	int i;

	/* Prepend the application name */
	new_argv[0] = app_name;

	eal_end = cmd->argc;
	for (i = 1; i < cmd->argc; i++) {
		if (strcmp(cmd->argv[i], "--") == 0) {
			eal_end = i;
			break;
		}
	}

	/* Copy the original argv elements skipping the first argument and "nb_desc" */
	for (i = 1; i < cmd->argc; i++) {
		if (i < eal_end) {
			if (strcmp(cmd->argv[i], "--nb-desc") == 0) {
				if (i + 1 < cmd->argc) {
					char *endptr;

					errno = 0;
					unsigned long val = strtoul(cmd->argv[i + 1], &endptr, 0);

					if (errno == ERANGE || *endptr != '\0')
						return -EINVAL;

					*nb_desc = val;
					i++;
				}
				continue;
			}

			if (strcmp(cmd->argv[i], "-c") == 0)
				has_c = 1;

			if (strcmp(cmd->argv[i], "-l") == 0)
				has_l = 1;
		}

		if (strcmp(cmd->argv[i], "--") == 0 && insert_index == -1)
			insert_index = j;

		new_argv[j++] = cmd->argv[i];
	}

	/* Append "-c 0xffffff" if neither -c nor -l is present */
	if (!has_c && !has_l) {
		/* Append to the end if there are no application arguments */
		if (insert_index == -1) {
			new_argv[j++] = "-c";
			new_argv[j++] = "0xffffff";
		} else {
			/* Shift elements to the right to make space for "-c 0xffffff" */
			for (int i = j - 1; i >= insert_index; i--)
				new_argv[i + 2] = new_argv[i];

			new_argv[insert_index] = "-c";
			new_argv[insert_index + 1] = "0xffffff";
			j += 2;
		}
	}

	new_argv[j] = NULL;
	return j;
}

static void
dao_card_mgr_process_cmd(int cli_fd, cli_args *cmd)
{
	struct dao_card_stats card_stats;
	struct dao_card_config card_cfg;
	struct dao_card_info card_info;
	int rc = 0;

	if (strcmp(cmd->argv[0], DAO_CARD_MGR_CARD_INIT) == 0) {
		const char **new_argv = malloc((cmd->argc + 2) * sizeof(char *));
		unsigned long nb_desc = 0;

		if (new_argv == NULL) {
			rc = -ENOMEM;
			goto send_resp;
		}

		card_cfg.crypto_nb_desc = DAO_CARD_CFG_NB_DESC;
		rc = dao_card_mgr_update_init_args(cmd, new_argv, &nb_desc);
		if (rc > 0) {
			card_cfg.crypto_nb_desc = nb_desc;
			card_cfg.argc = rc;
			card_cfg.argv = (char **)new_argv;
			rc = dao_card_init(card_ctx, &card_cfg);
		}
		free(new_argv);
	} else if (strcmp(cmd->argv[0], DAO_CARD_MGR_CARD_FINI) == 0) {
		dao_card_fini(card_ctx);
	} else if (strcmp(cmd->argv[0], DAO_CARD_MGR_CARD_INFO) == 0) {
		rc = dao_card_info_get(card_ctx, &card_info);
	} else if (strcmp(cmd->argv[0], DAO_CARD_MGR_APP_UPDATE) == 0) {
		rc = dao_card_mgr_app_update(cmd);
	} else if (strcmp(cmd->argv[0], DAO_CARD_MGR_CARD_STATS) == 0) {
		rc = dao_card_stats_get(card_ctx, &card_stats);
	} else if (strcmp(cmd->argv[0], DAO_CARD_MGR_FW_UPDATE) == 0) {
		rc = dao_card_mgr_fw_update(cmd);
	} else {
		rc = -ENOTSUP;
	}

send_resp:
	send(cli_fd, &rc, sizeof(rc), 0);

	if (!rc && strcmp(cmd->argv[0], DAO_CARD_MGR_CARD_INFO) == 0)
		send(cli_fd, &card_info, sizeof(struct dao_card_info), 0);

	if (!rc && strcmp(cmd->argv[0], DAO_CARD_MGR_CARD_STATS) == 0)
		send(cli_fd, &card_stats, sizeof(struct dao_card_stats), 0);
}

static void
dao_card_mgr_parse_args(const char *line, cli_args *cmd_args)
{
	char *line_copy = strdup(line);
	char *token;

	if (line_copy == NULL)
		return;

	cmd_args->line = line_copy;
	cmd_args->argc = 0;
	cmd_args->argv = NULL;

	token = strtok(line_copy, " \t\n");
	while (token != NULL) {
		char **new_argv = realloc(cmd_args->argv, sizeof(char *) * (cmd_args->argc + 1));

		if (!new_argv) {
			syslog(LOG_ERR, "realloc failed in parse_args");
			free(cmd_args->argv);
			free(cmd_args->line);
			cmd_args->argv = NULL;
			cmd_args->line = NULL;
			cmd_args->argc = 0;
			return;
		}
		cmd_args->argv = new_argv;

		cmd_args->argv[cmd_args->argc++] = token;
		token = strtok(NULL, " \t\n");
	}

	if (cmd_args->argc == 0) {
		free(cmd_args->line);
		free(cmd_args->argv);
	}
}

static void
dao_card_mgr_listen(int cli_socket)
{
	cli_args cmd_args;
	ssize_t recv_len;

	while (!force_quit) {
		char buffer[BUFFER_SIZE];

		recv_len = recv(cli_socket, buffer, sizeof(buffer) - 1, 0);
		if (recv_len <= 0) {
			if (recv_len == 0)
				syslog(LOG_INFO, "Client closed the connection");
			else
				syslog(LOG_ERR, "Could not receive command from client");
			break;
		}

		buffer[recv_len] = '\0';
		dao_card_mgr_parse_args(buffer, &cmd_args);
		dao_card_mgr_process_cmd(cli_socket, &cmd_args);

		free(cmd_args.line);
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
