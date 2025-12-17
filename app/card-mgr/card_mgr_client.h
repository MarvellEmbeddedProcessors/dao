/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef CARD_MGR_CLIENT_H
#define CARD_MGR_CLIENT_H

#include "card_mgr.h"
#include <histedit.h>
#include <stdbool.h>

/* Client mode functions */
int dao_card_mgr_client(void);
int dao_card_mgr_client_init(void);
void dao_card_mgr_send_to_server(int cli_fd, const char *line);
bool dao_card_client_cmd_valid(const char *line, size_t *trimmed_len);
void dao_card_print_help(void);

/* Editline functions */
int dao_card_mgr_editline_init(History **hist, EditLine **el, HistEvent *ev);
void dao_card_mgr_editline_fini(History *hist, EditLine *el);
char *dao_card_mgr_prompt(EditLine *el);

/* Helper functions */
int recv_all(int fd, void *buf, size_t len);

#endif /* CARD_MGR_CLIENT_H */
