/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#ifndef _APP_SECGW_CLI_CONN_H_
#define _APP_SECGW_CLI_CONN_H_

#define SCLI_CONN_WELCOME_LEN_MAX 1024
#define SCLI_CONN_PROMPT_LEN_MAX  16

typedef void (*scli_conn_msg_handle_t)(char *msg_in, char *msg_out, size_t msg_out_len_max,
				       void *arg);

struct scli_conn {
	char *welcome;
	char *prompt;
	char *buf;
	char *msg_in;
	char *msg_out;
	size_t buf_size;
	size_t msg_in_len_max;
	size_t msg_out_len_max;
	size_t msg_in_len;
	int fd_server;
	int fd_client_group;
	scli_conn_msg_handle_t msg_handle;
	void *msg_handle_arg;
};

struct scli_conn_params {
	const char *welcome;
	const char *prompt;
	const char *addr;
	uint16_t port;
	size_t buf_size;
	size_t msg_in_len_max;
	size_t msg_out_len_max;
	scli_conn_msg_handle_t msg_handle;
	void *msg_handle_arg;
};

struct scli_conn *scli_conn_init(struct scli_conn_params *p);
void scli_conn_free(struct scli_conn *conn);
int scli_conn_req_poll(struct scli_conn *conn);
int scli_conn_msg_poll(struct scli_conn *conn);

#endif
