/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <syslog.h>
#include <unistd.h>

#include <dao_card_grpc_client.h>
#include <dao_log.h>

#include "card_mgr_server.h"
#include "update/app_update.h"
#include "update/failsafe_update.h"
#include "update/fw_update.h"
#include "update/mcu_update.h"
#include "update/update_manager.h"
#include "utils/file_utils.h"
#include "utils/logging.h"

void
dao_card_mgr_process_error(int cli_fd, int resp)
{
	uint32_t err_len = 0;

	/* Attempt to send error message length */
	/* This is a placeholder - error context is set in each function */
	(void)cli_fd;
	(void)resp;
	(void)err_len;
}

void
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

void
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

void
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

void
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
dao_card_mgr_process_cmd(int cli_fd, cli_args *cmd)
{
	char sensors_output[DAO_CARD_MGR_MAX_SENSORS_LEN];
	char err_msg[DAO_CARD_MGR_MAX_ERR_MSG_LEN] = {0};
	struct dao_card_stats card_stats;
	struct dao_card_config card_cfg;
	struct dao_card_info card_info;
	char version_buf[160] = {0};
	uint32_t sensors_len = 0;
	int rc = 0;

	/* Set thread-local error capture buffer */
	dao_card_err_ctx_set(err_msg, sizeof(err_msg));

	if (strcmp(cmd->argv[0], DAO_CARD_MGR_CARD_INIT) == 0) {
		unsigned long nb_desc = 0;
		const char **new_argv;

		/* Skip card_init if boot source is SPI */
		rc = dao_card_info_get(card_ctx, &card_info);
		if (rc != 0) {
			snprintf(err_msg, sizeof(err_msg),
				 "Failed to get card info prior to init (error: %d)", rc);
			goto send_resp;
		}

		if (card_info.boot_source == DAO_CARD_BOOT_SOURCE_SPI) {
			snprintf(err_msg, sizeof(err_msg),
				 "card_init command not supported from SPI boot source");
			rc = -ENOTSUP;
			goto send_resp;
		}

		new_argv = malloc((cmd->argc + 4) * sizeof(char *));

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
			/* Add specific error message for EALREADY */
			if (rc == -EALREADY) {
				strncpy(err_msg, "Card is already initialized",
					sizeof(err_msg) - 1);
				err_msg[sizeof(err_msg) - 1] = '\0';
			}
		}
		free(new_argv);
	} else if (strcmp(cmd->argv[0], DAO_CARD_MGR_CARD_FINI) == 0) {
		dao_card_fini(card_ctx);
	} else if (strcmp(cmd->argv[0], DAO_CARD_MGR_SOFT_RESET) == 0) {
		rc = dao_card_soft_reset(card_ctx);
		if (rc == -EAGAIN) {
			strncpy(err_msg, "Card is not initialized yet", sizeof(err_msg) - 1);
			err_msg[sizeof(err_msg) - 1] = '\0';
		}
	} else if (strcmp(cmd->argv[0], DAO_CARD_MGR_CARD_INFO) == 0) {
		rc = dao_card_info_get(card_ctx, &card_info);
	} else if (strcmp(cmd->argv[0], DAO_CARD_MGR_IMAGE_VERSION) == 0) {
		/* Get image version using reusable function */
		char image_ver_buf[64];
		char app_ver_buf[64];

		rc = dao_card_mgr_get_image_version(image_ver_buf, sizeof(image_ver_buf),
						    app_ver_buf, sizeof(app_ver_buf), version_buf,
						    sizeof(version_buf));
		if (rc != 0) {
			if (rc == -ENOTSUP) {
				snprintf(
					err_msg, sizeof(err_msg),
					"Image version command not supported by card firmware (server needs update)");
			} else {
				snprintf(err_msg, sizeof(err_msg),
					 "Failed to get image version from card (error: %d)", rc);
			}
		}
	} else if (strcmp(cmd->argv[0], DAO_CARD_MGR_APP_UPDATE) == 0) {
		rc = dao_card_mgr_app_update(cmd);
	} else if (strcmp(cmd->argv[0], DAO_CARD_MGR_APP_FALLBACK) == 0) {
		rc = dao_card_mgr_app_fallback(cmd);
	} else if (strcmp(cmd->argv[0], DAO_CARD_MGR_CARD_STATS) == 0) {
		rc = dao_card_stats_get(card_ctx, &card_stats);
	} else if (strcmp(cmd->argv[0], DAO_CARD_MGR_DMESG) == 0) {
		/* Defer actual fetch to post-send phase; just probe availability now */
		char tmp[4];
		int n = dao_card_dmesg_get(card_ctx, tmp, sizeof(tmp));

		if (n >= 0) {
			rc = 0; /* supported */
		} else {
			rc = n;
			if (rc == -ENOTSUP)
				strncpy(err_msg, "card does not support dmesg RPC (older server)",
					sizeof(err_msg));
		}
	} else if (strcmp(cmd->argv[0], DAO_CARD_MGR_APPLOG) == 0) {
		char tmp[4];
		int n = dao_card_applogs_get(card_ctx, tmp, sizeof(tmp));

		if (n >= 0) {
			rc = 0; /* supported */
		} else {
			rc = n;
			if (rc == -ENOTSUP)
				strncpy(err_msg, "card does not support applog RPC (older server)",
					sizeof(err_msg));
		}
	} else if (strcmp(cmd->argv[0], DAO_CARD_MGR_FW_UPDATE) == 0) {
		rc = dao_card_mgr_fw_update(cmd);
	} else if (strcmp(cmd->argv[0], DAO_CARD_MGR_MCU_UPDATE) == 0) {
		rc = dao_card_mgr_mcu_update(cmd);
	} else if (strcmp(cmd->argv[0], DAO_CARD_MGR_BOOT_SOURCE) == 0) {
		rc = dao_card_mgr_boot(cmd);
	} else if (strcmp(cmd->argv[0], DAO_CARD_MGR_CARD_REBOOT) == 0) {
		rc = dao_card_mgr_reboot();
	} else if (strcmp(cmd->argv[0], DAO_CARD_MGR_FAILSAFE_UPDATE) == 0) {
		rc = dao_card_mgr_failsafe_update(cmd);
	} else if (strcmp(cmd->argv[0], DAO_CARD_MGR_CARD_TEMPERATURE) == 0) {
		rc = dao_card_sensors_get(card_ctx, sensors_output, sizeof(sensors_output));
		if (rc == 0)
			sensors_len = (uint32_t)strnlen(sensors_output, sizeof(sensors_output));
	} else {
		rc = -ENOTSUP;
	}

send_resp:
	send(cli_fd, &rc, sizeof(rc), 0);
	if (rc < 0) {
		uint32_t len = 0;

		if (err_msg[0] != '\0')
			len = (uint32_t)strnlen(err_msg, sizeof(err_msg));
		send(cli_fd, &len, sizeof(len), 0);
		if (len)
			send(cli_fd, err_msg, len, 0);
	}

	/* Clear context after we are done */
	dao_card_err_ctx_clear();

	if (!rc) {
		if (strcmp(cmd->argv[0], DAO_CARD_MGR_CARD_INFO) == 0) {
			send(cli_fd, &card_info, sizeof(struct dao_card_info), 0);
		} else if (strcmp(cmd->argv[0], DAO_CARD_MGR_IMAGE_VERSION) == 0) {
			/* Send the version string to client */
			send(cli_fd, version_buf, strlen(version_buf) + 1, 0);
		} else if (strcmp(cmd->argv[0], DAO_CARD_MGR_CARD_STATS) == 0) {
			send(cli_fd, &card_stats, sizeof(struct dao_card_stats), 0);
		} else if (strcmp(cmd->argv[0], DAO_CARD_MGR_DMESG) == 0) {
			char dmesg_buf[65536];
			int n = dao_card_dmesg_get(card_ctx, dmesg_buf, sizeof(dmesg_buf));

			if (n < 0) {
				uint32_t zero = 0;

				send(cli_fd, &zero, sizeof(zero), 0);
			} else {
				uint32_t blen = (uint32_t)n;

				send(cli_fd, &blen, sizeof(blen), 0);
				if (blen)
					send(cli_fd, dmesg_buf, blen, 0);
			}
		} else if (strcmp(cmd->argv[0], DAO_CARD_MGR_APPLOG) == 0) {
			char app_buf[65536];
			int n = dao_card_applogs_get(card_ctx, app_buf, sizeof(app_buf));

			if (n < 0) {
				uint32_t zero = 0;

				send(cli_fd, &zero, sizeof(zero), 0);
			} else {
				uint32_t blen = (uint32_t)n;

				send(cli_fd, &blen, sizeof(blen), 0);
				if (blen)
					send(cli_fd, app_buf, blen, 0);
			}
		} else if (!rc && strcmp(cmd->argv[0], DAO_CARD_MGR_CARD_TEMPERATURE) == 0) {
			send(cli_fd, &sensors_len, sizeof(sensors_len), 0);
			if (sensors_len > 0)
				send(cli_fd, sensors_output, sensors_len, 0);
		}
	}
}

void
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
			DAO_CARD_ERR("realloc failed in parse_args");
			cmd_args->argc = 0;
			goto free_line;
		}
		cmd_args->argv = new_argv;

		cmd_args->argv[cmd_args->argc++] = token;
		token = strtok(NULL, " \t\n");
	}

free_line:
	if (cmd_args->argc == 0) {
		free(cmd_args->argv);
		cmd_args->argv = NULL;
		free(cmd_args->line);
		cmd_args->line = NULL;
	}
}

int
dao_card_mgr_server_init(const char *ip_str)
{
	struct sockaddr_in sock_addr;
	int optval = 1;
	int rc = -1;
	int srv_fd;

	srv_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (srv_fd < 0) {
		DAO_CARD_ERR("Could not create server socket");
		return -1;
	}

	/* Allow address reuse for immediate restart */
	if (setsockopt(srv_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
		DAO_CARD_ERR("setsockopt SO_REUSEADDR failed");
		close(srv_fd);
		return -1;
	}

	sock_addr.sin_family = AF_INET;
	sock_addr.sin_addr.s_addr = INADDR_ANY;
	sock_addr.sin_port = htons(DAO_CARD_MGR_PORT);

	if (bind(srv_fd, (struct sockaddr *)&sock_addr, sizeof(struct sockaddr_in)) < 0) {
		DAO_CARD_ERR("Could not bind the socket");
		goto srv_fini;
	}

	if (ip_str != NULL) {
		strncpy(remote_card_ip, ip_str, INET_ADDRSTRLEN - 1);
		remote_card_ip[INET_ADDRSTRLEN - 1] = '\0';
	}
	card_ctx = dao_card_grpc_client_init(remote_card_ip, DAO_CARD_GRPC_PORT);

	if (card_ctx == NULL) {
		DAO_CARD_ERR("gRPC client init failed");
		goto srv_fini;
	}
	if (listen(srv_fd, 3) < 0) {
		DAO_CARD_ERR("error on listen");
		goto grpc_fini;
	}
	return srv_fd;

grpc_fini:
	dao_card_grpc_client_fini(card_ctx);
srv_fini:
	close(srv_fd);
	return rc;
}

int
dao_card_mgr_server(const char *ip_str)
{
	int client_fds[DAO_CARD_MGR_MAX_CLIENTS];
	int addrlen = sizeof(struct sockaddr_in);
	struct sockaddr_in sock_addr;
	char buffer[BUFFER_SIZE];
	int srv_fd, flags;
	ssize_t recv_len;
	fd_set readfds;
	int max_fd;
	int rc = 0;
	int i;

	for (i = 0; i < DAO_CARD_MGR_MAX_CLIENTS; i++)
		client_fds[i] = -1;

	srv_fd = dao_card_mgr_server_init(ip_str);
	if (srv_fd < 0) {
		dao_err("Could not initialize the server");
		return -1;
	}
	flags = fcntl(srv_fd, F_GETFL, 0);
	fcntl(srv_fd, F_SETFL, flags | O_NONBLOCK);

	while (!atomic_load(&dao_card_force_quit)) {
		FD_ZERO(&readfds);
		FD_SET(srv_fd, &readfds);
		max_fd = srv_fd;
		for (i = 0; i < DAO_CARD_MGR_MAX_CLIENTS; i++) {
			if (client_fds[i] > 0) {
				FD_SET(client_fds[i], &readfds);
				if (client_fds[i] > max_fd)
					max_fd = client_fds[i];
			}
		}

		int activity = select(max_fd + 1, &readfds, NULL, NULL, NULL);

		if (activity < 0 && errno != EINTR) {
			dao_err("select error");
			rc = -1;
			break;
		}
		if (atomic_load(&dao_card_force_quit))
			break;

		/* New connection */
		if (FD_ISSET(srv_fd, &readfds)) {
			int new_fd = accept(srv_fd, (struct sockaddr *)&sock_addr,
					    (socklen_t *)&addrlen);

			if (new_fd >= 0) {
				for (i = 0; i < DAO_CARD_MGR_MAX_CLIENTS; i++) {
					if (client_fds[i] < 0) {
						client_fds[i] = new_fd;
						break;
					}
				}
				if (i == DAO_CARD_MGR_MAX_CLIENTS) {
					dao_err("Too many clients, rejecting connection");
					close(new_fd);
				}
			}
		}

		/* Check all clients for data */
		for (i = 0; i < DAO_CARD_MGR_MAX_CLIENTS; i++) {
			int fd = client_fds[i];

			if (fd > 0 && FD_ISSET(fd, &readfds)) {
				recv_len = recv(fd, buffer, sizeof(buffer) - 1, 0);
				if (recv_len <= 0) {
					if (recv_len == 0)
						syslog(LOG_INFO, "Client %d closed the connection",
						       fd);
					else
						DAO_CARD_ERR(
							"Could not receive command from client %d",
							fd);
					close(fd);
					client_fds[i] = -1;
					continue;
				}
				buffer[recv_len] = '\0';

				cli_args cmd_args;

				dao_card_mgr_parse_args(buffer, &cmd_args);
				dao_card_mgr_process_cmd(fd, &cmd_args);

				if (cmd_args.argv != NULL)
					free(cmd_args.argv);
				if (cmd_args.line != NULL)
					free(cmd_args.line);
			}
		}
	}

	for (i = 0; i < DAO_CARD_MGR_MAX_CLIENTS; i++) {
		if (client_fds[i] > 0) {
			close(client_fds[i]);
			client_fds[i] = -1;
		}
	}
	dao_card_grpc_client_fini(card_ctx);
	close(srv_fd);
	return rc;
}
