/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#include "file_utils.h"
#include "logging.h"

int
split_path_filename(const char *input, char **out_path, char **out_file)
{
	char *last_slash;

	if (!input || !out_path || !out_file)
		return -EINVAL;

	last_slash = strrchr(input, '/');
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
		char cwd[PATH_MAX];

		if (getcwd(cwd, sizeof(cwd)) == NULL) {
			int err = errno;

			DAO_CARD_ERR("Failed to get current working directory: %s", strerror(err));
			return -err;
		}
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

int
validate_file(cli_args *cmd, struct dao_card_update_req *req, char **bootpath)
{
	char fullpath[PATH_MAX];
	struct stat st;
	int rc;

	/* Validate parameters */
	if (!cmd || !req) {
		DAO_CARD_ERR("NULL parameter passed to %s", __func__);
		return -EINVAL;
	}

	/* Arguments format: <cmd> <file-to-update> <boot-binary-path> */
	if (cmd->argc < 3 || !cmd->argv || !cmd->argv[1] || !cmd->argv[2]) {
		DAO_CARD_ERR("Command requires: <file-to-update> <boot-binary-path>");
		return -EINVAL;
	}

	if (bootpath)
		*bootpath = NULL;

	req->filename = NULL;
	req->filepath = NULL;

	rc = split_path_filename(cmd->argv[1], &req->filepath, &req->filename);
	if (rc != 0) {
		DAO_CARD_ERR("Failed to split path/filename: %s", strerror(-rc));
		return rc;
	}

	/* Verify allocations succeeded */
	if (!req->filepath || !req->filename) {
		DAO_CARD_ERR("Internal error: split_path_filename succeeded but output is NULL");
		rc = -EFAULT;
		goto cleanup;
	}

	/* Allocate boot path */
	if (bootpath) {
		*bootpath = strdup(cmd->argv[2]);
		if (!*bootpath) {
			rc = -ENOMEM;
			goto cleanup;
		}
	}

	snprintf(fullpath, PATH_MAX, "%s/%s", req->filepath, req->filename);

	if (access(fullpath, F_OK | R_OK) != 0) {
		rc = -errno;
		DAO_CARD_ERR("file '%s' not accessible: %s", fullpath, strerror(errno));
		goto cleanup;
	}

	if (stat(fullpath, &st) != 0) {
		rc = -errno;
		DAO_CARD_ERR("Cannot stat file '%s': %s", fullpath, strerror(errno));
		goto cleanup;
	}

	if (S_ISDIR(st.st_mode)) {
		DAO_CARD_ERR("'%s' is a directory, not a file", fullpath);
		rc = -EISDIR;
		goto cleanup;
	}

	return 0;

cleanup:
	if (bootpath && *bootpath) {
		free(*bootpath);
		*bootpath = NULL;
	}
	if (req->filepath) {
		free(req->filepath);
		req->filepath = NULL;
	}
	if (req->filename) {
		free(req->filename);
		req->filename = NULL;
	}
	return rc;
}
