/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef CARD_MGR_SERVER_H
#define CARD_MGR_SERVER_H

#include "card_mgr.h"

/* Server mode functions */
int dao_card_mgr_server(const char *ip_str);
int dao_card_mgr_server_init(const char *ip_str);
void dao_card_mgr_process_cmd(int cli_fd, cli_args *cmd);
void dao_card_mgr_parse_args(const char *line, cli_args *cmd_args);

/* Response handling functions */
void dao_card_mgr_process_error(int cli_fd, int resp);
void dao_card_mgr_recv_card_info(int cli_fd);
void dao_card_mgr_recv_card_stats(int cli_fd);
void dao_card_mgr_recv_card_dmesg(int cli_fd);
void dao_card_mgr_recv_card_sensors(int cli_fd);

#endif /* CARD_MGR_SERVER_H */
