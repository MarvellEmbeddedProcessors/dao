/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <dao_card_grpc_client.h>
#include <dao_log.h>

#include "card_mgr_client.h"
#include "utils/logging.h"

/* Receive exactly len bytes (blocking) unless peer closes or a fatal error occurs.
 * Returns 0 on success, -ECONNRESET if peer closed, or -errno on failure.
 */
int
recv_all(int fd, void *buf, size_t len)
{
	uint8_t *p = buf;
	size_t off = 0;
	ssize_t rc;

	while (off < len) {
		rc = recv(fd, p + off, len - off, 0);

		if (rc == 0)
			return -ECONNRESET; /* peer closed */
		if (rc < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				continue; /* unexpected in blocking mode but retry */
			return -errno;
		}
		off += (size_t)rc;
	}
	return 0;
}

void
dao_card_print_help(void)
{
	fprintf(stderr, "Supported commands:\n");
	for (size_t i = 0; i < dao_card_cmd_specs_count; i++) {
		const struct dao_card_cmd_spec *s = &dao_card_cmd_specs[i];

		fprintf(stderr, "  %-20s %-50s %s\n", s->name, s->usage, s->desc);
	}
}

bool
dao_card_client_cmd_valid(const char *line, size_t *trimmed_len)
{
	const struct dao_card_cmd_spec *spec;
	int needs_file_check = 0;
	char *argv_local[128];
	size_t len, argc = 0;
	char *save = NULL;
	char *tmp;
	char *tok;

	if (!line)
		return false;

	len = strlen(line);
	while (len && (line[len - 1] == '\n' || line[len - 1] == '\r'))
		len--;

	if (len == 0)
		return false;

	tmp = strndup(line, len);
	if (!tmp)
		return false;

	tok = strtok_r(tmp, " \t", &save);
	while (tok && argc < ARRAY_SIZE(argv_local)) {
		argv_local[argc++] = tok;
		tok = strtok_r(NULL, " \t", &save);
	}
	if (argc == 0) {
		free(tmp);
		return false;
	}

	spec = dao_card_lookup_cmd(argv_local[0]);
	if (!spec) {
		fprintf(stderr, "Invalid command: %s\n", argv_local[0]);
		fprintf(stderr, "Type 'help' for list of commands.\n");
		free(tmp);
		return false;
	}

	if (strcmp(spec->name, "help") == 0) {
		dao_card_print_help();
		free(tmp);
		return false;
	}

	if (spec->min_args > 0 && (int)argc < spec->min_args) {
		fprintf(stderr, "Error: '%s' missing arguments.\n Usage: %s %s -> %s\n", spec->name,
			spec->name, spec->usage, spec->desc);
		free(tmp);
		return false;
	}

	if (spec->max_args != DAO_CMD_ARGS_ANY && (int)argc > spec->max_args) {
		fprintf(stderr, "Error: '%s' too many arguments.\n Usage: %s %s -> %s\n",
			spec->name, spec->name, spec->usage, spec->desc);
		free(tmp);
		return false;
	}

	if (strcmp(spec->name, DAO_CARD_MGR_CARD_INIT) == 0) {
		if (argc != 1) {
			fprintf(stderr,
				"Error: '%s' requires no additional arguments.\n Usage: %s %s -> %s\n",
				spec->name, spec->name, spec->usage, spec->desc);
			free(tmp);
			return false;
		}
	}

	/* File argument validation for update-like commands */
	if (strcmp(spec->name, DAO_CARD_MGR_APP_UPDATE) == 0 ||
	    strcmp(spec->name, DAO_CARD_MGR_FW_UPDATE) == 0 ||
	    strcmp(spec->name, DAO_CARD_MGR_FAILSAFE_UPDATE) == 0 ||
	    strcmp(spec->name, DAO_CARD_MGR_MCU_UPDATE) == 0) {
		needs_file_check = 1;
	}

	if (needs_file_check) {
		const char *file_arg = argv_local[1];
		struct stat st;

		if (file_arg[0] != '/') {
			fprintf(stderr, "Error: file path must be absolute: %s\n", file_arg);
			free(tmp);
			return false;
		}

		if (stat(file_arg, &st) != 0) {
			fprintf(stderr, "Error: cannot access file '%s': %s\n", file_arg,
				strerror(errno));
			free(tmp);
			return false;
		}

		if (!S_ISREG(st.st_mode)) {
			fprintf(stderr, "Error: path is not a regular file: %s\n", file_arg);
			free(tmp);
			return false;
		}

		if (access(file_arg, R_OK) != 0) {
			fprintf(stderr, "Error: file not readable: %s (%s)\n", file_arg,
				strerror(errno));
			free(tmp);
			return false;
		}
	}

	/* second file (boot-bin) for some updates */
	if (strcmp(spec->name, DAO_CARD_MGR_APP_UPDATE) == 0 ||
	    strcmp(spec->name, DAO_CARD_MGR_FW_UPDATE) == 0 ||
	    strcmp(spec->name, DAO_CARD_MGR_FAILSAFE_UPDATE) == 0) {
		const char *boot_arg = argv_local[2];
		struct stat st;

		if (boot_arg[0] != '/') {
			fprintf(stderr, "Error: boot-bin path must be absolute: %s\n", boot_arg);
			free(tmp);
			return false;
		}

		if (stat(boot_arg, &st) != 0) {
			fprintf(stderr, "Error: cannot access boot file '%s': %s\n", boot_arg,
				strerror(errno));
			free(tmp);
			return false;
		}

		if (!S_ISREG(st.st_mode)) {
			fprintf(stderr, "Error: boot path is not a regular file: %s\n", boot_arg);
			free(tmp);
			return false;
		}

		if (access(boot_arg, R_OK) != 0) {
			fprintf(stderr, "Error: boot file not readable: %s (%s)\n", boot_arg,
				strerror(errno));
			free(tmp);
			return false;
		}
	}

	*trimmed_len = len;
	free(tmp);
	return true;
}

/* Handle a response error code from server, optionally reading an extended
 * error message that may follow on the socket.
 */
static void
dao_card_mgr_process_error(int cli_fd, int resp)
{
	uint32_t err_len = 0;

	/* Attempt to receive an optional error message length when rc < 0 */
	if (resp < 0) {
		ssize_t ln = recv(cli_fd, &err_len, sizeof(err_len), 0);

		if (ln == (ssize_t)sizeof(err_len) && err_len > 0 &&
		    err_len < DAO_CARD_MGR_MAX_ERR_MSG_LEN) {
			char emsg[DAO_CARD_MGR_MAX_ERR_MSG_LEN];
			ssize_t rn = recv(cli_fd, emsg, err_len, 0);

			if (rn == (ssize_t)err_len) {
				emsg[err_len < DAO_CARD_MGR_MAX_ERR_MSG_LEN ?
					     err_len :
					     (DAO_CARD_MGR_MAX_ERR_MSG_LEN - 1)] = '\0';
				/* Prefer server-provided message */
				dao_err("%s", emsg);
				return;
			}
			/* Fall through to generic handling if payload read failed */
		}

		/* Specific negative codes */
		if (resp == ENOTSUP || resp == -ENOTSUP)
			dao_err("Command not supported by card (UNIMPLEMENTED)");
		else if (resp == -EAGAIN)
			dao_info("Card is not ready: %s", strerror(-resp));
		else if (resp == -EALREADY)
			dao_info("Card is already initialized");
		else
			dao_err("Received error for the command: (%s)", strerror(-resp));
		return;
	}

	/* Positive resp treated as generic error */
	dao_err("Received unexpected error for the command");
}

static void
dao_card_mgr_recv_card_info(int cli_fd)
{
	struct dao_card_info card_info;

	if (recv(cli_fd, &card_info, sizeof(struct dao_card_info), 0) !=
	    (ssize_t)sizeof(struct dao_card_info)) {
		dao_err("Failed to receive card info struct");
		return;
	}

	dao_info("Card info: version: %s, num SDP devices: %d, max_sessions: %d", card_info.version,
		 card_info.nb_devs, card_info.max_sessions);
	if (card_info.boot_source == DAO_CARD_BOOT_SOURCE_SPI)
		dao_info("Card boot source: SPI");
	else if (card_info.boot_source == DAO_CARD_BOOT_SOURCE_MMC)
		dao_info("Card boot source: MMC");
	else if (card_info.boot_source == DAO_CARD_BOOT_SOURCE_SCRIPT_FAILURE)
		dao_info("Card boot source: SCRIPT FAILURE (missing or failed script)");
	else if (card_info.boot_source == DAO_CARD_BOOT_SOURCE_UNSUPPORTED)
		dao_info("Card boot source: UNSUPPORTED by dao-crypto-agent");
}

static void
dao_card_mgr_recv_card_stats(int cli_fd)
{
	uint64_t total_rx_pkts = 0, total_tx_pkts = 0;
	struct dao_card_stats card_stats;
	int i;

	if (recv(cli_fd, &card_stats, sizeof(struct dao_card_stats), 0) !=
	    (ssize_t)sizeof(struct dao_card_stats)) {
		dao_err("Failed to receive card stats struct");
		return;
	}

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

static void
dao_card_mgr_recv_card_dmesg(int cli_fd)
{
	uint32_t blen = 0;
	uint32_t got = 0;
	ssize_t chunk;
	ssize_t rn;
	char *buf;

	rn = recv(cli_fd, &blen, sizeof(blen), 0);

	if (rn != (ssize_t)sizeof(blen))
		return; /* nothing */

	if (blen == 0) {
		dao_info("dmesg: (empty)");
		return;
	}

	buf = malloc(blen + 1);
	if (!buf) {
		uint32_t remaining = blen;
		char tmp[512];

		dao_err("OOM receiving dmesg (%u bytes)", blen);
		while (remaining) {
			chunk = recv(cli_fd, tmp, remaining > sizeof(tmp) ? sizeof(tmp) : remaining,
				     0);
			if (chunk <= 0)
				break;
			remaining -= (uint32_t)chunk;
		}
		return;
	}

	while (got < blen) {
		chunk = recv(cli_fd, buf + got, blen - got, 0);
		if (chunk <= 0)
			break;
		got += (uint32_t)chunk;
	}
	buf[(got < blen ? got : blen)] = '\0';
	if (got < blen)
		dao_err("Truncated dmesg reception (%u/%u)", got, blen);

	char *saveptr = NULL;
	char *linep = strtok_r(buf, "\n", &saveptr);

	while (linep) {
		dao_info("dmesg: %s", linep);
		linep = strtok_r(NULL, "\n", &saveptr);
	}
	free(buf);
}

static void
dao_card_mgr_recv_card_sensors(int cli_fd)
{
	uint32_t len = 0;
	ssize_t r;

	r = recv(cli_fd, &len, sizeof(len), 0);
	if (r != (ssize_t)sizeof(len)) {
		/* Length header not received fully; silently ignore */
		return;
	} else if (len == 0) {
		/* Empty output, nothing to print */
		return;
	} else if (len >= DAO_CARD_MGR_MAX_SENSORS_LEN) {
		dao_err("Sensors output too large (%u)", len);
	} else {
		char *buf = malloc(len + 1);

		if (!buf) {
			dao_err("Allocation failed for sensors output (%u bytes)", len);
			return; /* stop processing this command */
		}
		r = recv(cli_fd, buf, len, 0);
		if (r != (ssize_t)len) {
			dao_err("Failed to receive full sensors output");
			free(buf);
			return;
		}
		buf[len] = '\0';
		dao_info("Card sensors output:\n%s", buf);
		free(buf);
	}
}

void
dao_card_mgr_send_to_server(int cli_fd, const char *line)
{
	const char *send_line = line;
	size_t trimmed_len = 0;
	int rc, resp = 0;
	size_t send_len;

	if (!dao_card_client_cmd_valid(line, &trimmed_len))
		return;

	send_len = trimmed_len;
	send_line = line;

	if (send(cli_fd, send_line, send_len, 0) == -1) {
		dao_err("sending cmd to server failed (server may have exited)");
		atomic_store(&dao_card_force_quit, true);
		return;
	}

	rc = recv_all(cli_fd, &resp, sizeof(resp));
	if (rc != 0) {
		if (rc == -ECONNRESET)
			dao_err("Server closed the connection. Exiting client.");
		else
			dao_err("Failed to receive response from server");
		atomic_store(&dao_card_force_quit, true);
		return;
	}

	if (resp) {
		dao_card_mgr_process_error(cli_fd, resp);
		return;
	}

	/* Success (resp == 0): Handle successful command responses */

	/* Print success messages for update operations */
	if (strstr(send_line, DAO_CARD_MGR_APP_UPDATE) != NULL)
		dao_info("App update completed successfully");
	else if (strstr(send_line, DAO_CARD_MGR_FW_UPDATE) != NULL)
		dao_info("Firmware update completed successfully");
	else if (strstr(send_line, DAO_CARD_MGR_FAILSAFE_UPDATE) != NULL)
		dao_info("Failsafe update completed successfully");
	else if (strstr(send_line, DAO_CARD_MGR_MCU_UPDATE) != NULL)
		dao_info("MCU update completed successfully");
	else if (strstr(send_line, DAO_CARD_MGR_APP_FALLBACK) != NULL)
		dao_info("App fallback completed successfully");
	else if (strstr(send_line, DAO_CARD_MGR_CARD_REBOOT) != NULL)
		dao_info("Card reboot initiated successfully");

	/* Receive and display response payloads */
	if (strstr(send_line, "card_info") != NULL)
		dao_card_mgr_recv_card_info(cli_fd);
	if (strstr(send_line, "card_image_version") != NULL) {
		/* Receive version string from server */
		char version_buf[160];
		ssize_t n = recv(cli_fd, version_buf, sizeof(version_buf), 0);

		if (n > 0) {
			version_buf[sizeof(version_buf) - 1] = '\0';
			dao_info("Card image version - %s", version_buf);
		} else {
			dao_err("Failed to receive image version from server");
		}
	}
	if (strstr(send_line, "card_stats") != NULL)
		dao_card_mgr_recv_card_stats(cli_fd);
	if (strstr(send_line, "card_dmesg") != NULL)
		dao_card_mgr_recv_card_dmesg(cli_fd);
	if (strstr(send_line, "card_applog") != NULL)
		dao_card_mgr_recv_card_dmesg(cli_fd); /* same framing */
	if (strstr(send_line, "card_temperature") != NULL)
		dao_card_mgr_recv_card_sensors(cli_fd);
}

int
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

int
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

void
dao_card_mgr_editline_fini(History *hist, EditLine *el)
{
	history_end(hist);
	el_end(el);
}

char *
dao_card_mgr_prompt(EditLine *el)
{
	static char prompt[] = "> ";
	(void)el;

	return prompt;
}

int
dao_card_mgr_client(void)
{
	int count, cli_fd;
	const char *line;
	History *hist;
	EditLine *el;
	HistEvent ev;
	int rc = 0;

	if (dao_card_mgr_editline_init(&hist, &el, &ev)) {
		dao_err("Editline initialization failed");
		return -1;
	}

	el_set(el, EL_PROMPT, dao_card_mgr_prompt);

	cli_fd = dao_card_mgr_client_init();
	if (cli_fd < 0) {
		dao_err("client socket initialization failed");
		rc = -1;
		goto editline_fini;
	}

	while (!atomic_load(&dao_card_force_quit)) {
		line = el_gets(el, &count);
		if (line != NULL && count > 0) {
			if (count == 1 && line[0] == '\n')
				continue;

			if (strstr(line, "quit") != NULL)
				break;

			/* Add line to history */
			history(hist, &ev, H_ENTER, line);
			dao_card_mgr_send_to_server(cli_fd, line);
			if (atomic_load(&dao_card_force_quit)) {
				printf("\nClient exiting due to server disconnect.\n");
				break;
			}
		}
	}

editline_fini:
	dao_card_mgr_editline_fini(hist, el);
	if (cli_fd >= 0)
		close(cli_fd);
	return rc;
}
