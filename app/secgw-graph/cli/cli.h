/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#ifndef _APP_SECGW_CLI_H_
#define _APP_SECGW_CLI_H_

/* Macros */
#define SCLI_OUT_OF_MEMORY   "Not enough memory.\n"
#define SCLI_CMD_UNKNOWN     "Unknown command \"%s\".\n"
#define SCLI_CMD_UNIMPLEM    "Command \"%s\" not implemented.\n"
#define SCLI_ARG_NOT_ENOUGH  "Not enough arguments for command \"%s\".\n"
#define SCLI_ARG_TOO_MANY    "Too many arguments for command \"%s\".\n"
#define SCLI_ARG_MISMATCH    "Wrong number of arguments for command \"%s\".\n"
#define SCLI_ARG_NOT_FOUND   "Argument \"%s\" not found.\n"
#define SCLI_ARG_INVALID     "Invalid value for argument \"%s\".\n"
#define SCLI_FILE_ERR        "Error in file \"%s\" at line %u.\n"
#define SCLI_FILE_NOT_ENOUGH "Not enough rules in file \"%s\".\n"
#define SCLI_MSG_CMD_FAIL    "Command \"%s\" failed.\n"

#define SCLI_CMD_NAME_SIZE 64

void scli_init(void);

void scli_exit(void);

void scli_process(char *in, char *out, size_t out_size, void *arg);

int scli_script_process(const char *file_name, size_t msg_in_len_max, size_t msg_out_len_max,
			void *arg);

#endif
