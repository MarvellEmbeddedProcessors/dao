/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#include <cli_api.h>
#include <cli.h>

static struct cmdline *cl;

static int
scli_is_comment(char *in)
{
	if ((strlen(in) && index("!#%;", in[0])) || (strncmp(in, "//", 2) == 0) ||
	    (strncmp(in, "--", 2) == 0))
		return 1;

	return 0;
}

void
scli_init(void)
{
	cl = cmdline_stdin_new(modules_ctx, "");
}

void
scli_exit(void)
{
	cmdline_stdin_exit(cl);
}

void
scli_process(char *in, char *out, size_t out_size, __rte_unused void *obj)
{
	int rc;

	if (scli_is_comment(in))
		return;

	rc = cmdline_parse(cl, in);
	if (rc == CMDLINE_PARSE_AMBIGUOUS)
		snprintf(out, out_size, SCLI_MSG_CMD_FAIL, "Ambiguous command");
	else if (rc == CMDLINE_PARSE_NOMATCH)
		snprintf(out, out_size, SCLI_MSG_CMD_FAIL, "Command mismatch");
	else if (rc == CMDLINE_PARSE_BAD_ARGS)
		snprintf(out, out_size, SCLI_MSG_CMD_FAIL, "Bad arguments");
}

int
scli_script_process(const char *file_name, size_t msg_in_len_max, size_t msg_out_len_max, void *obj)
{
	char *msg_in = NULL, *msg_out = NULL;
	int rc = -EINVAL;
	FILE *f = NULL;

	/* Check input arguments */
	if ((file_name == NULL) || (strlen(file_name) == 0) || (msg_in_len_max == 0) ||
	    (msg_out_len_max == 0))
		return rc;

	msg_in = malloc(msg_in_len_max + 1);
	msg_out = malloc(msg_out_len_max + 1);
	if ((msg_in == NULL) || (msg_out == NULL)) {
		rc = -ENOMEM;
		goto exit;
	}

	/* Open input file */
	f = fopen(file_name, "r");
	if (f == NULL) {
		rc = -EIO;
		goto exit;
	}

	/* Read file */
	while (fgets(msg_in, msg_in_len_max, f) != NULL) {
		msg_out[0] = 0;

		scli_process(msg_in, msg_out, msg_out_len_max, obj);

		if (strlen(msg_out))
			printf("%s", msg_out);
	}

	/* Close file */
	fclose(f);
	rc = 0;

exit:
	free(msg_out);
	free(msg_in);
	return rc;
}
