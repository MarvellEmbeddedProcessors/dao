/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#include <dao_card_grpc_client.h>
#include <dao_log.h>

#include "../lock/lock.h"
#include "../utils/logging.h"
#include "../utils/module_utils.h"
#include "update_manager.h"

int
dao_card_mgr_update_init_args(cli_args *cmd, const char **new_argv, unsigned long *nb_desc)
{
	const char *app_name = "dao-crypto-agent";
	int has_c = 0, has_l = 0;
	int insert_index = -1;
	int eal_end, j = 1;
	unsigned long val;
	char *endptr;
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
					errno = 0;
					val = strtoul(cmd->argv[i + 1], &endptr, 0);

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
			for (int k = j - 1; k >= insert_index; k--)
				new_argv[k + 2] = new_argv[k];

			new_argv[insert_index] = "-c";
			new_argv[insert_index + 1] = "0xffffff";
			j += 2;
		}
	}

	new_argv[j] = NULL;
	return j;
}

/* Validate image version get has card_ctx */
static int
validate_card_ctx_ready(void)
{
	if (card_ctx == NULL) {
		DAO_CARD_ERR("card_ctx is NULL - card not initialized");
		return -EINVAL;
	}
	return 0;
}

/* Get image version from card via gRPC */
int
image_version_get(char *image_ver_buf, size_t image_ver_len)
{
	char app_ver_buf[IMAGE_VERSION_LEN_MAX] = {0};
	int rc;

	/* Validate input */
	if (!image_ver_buf || image_ver_len == 0)
		return -EINVAL;

	/* Validate card context */
	rc = validate_card_ctx_ready();
	if (rc != 0)
		return rc;

	/* Initialize version string */
	image_ver_buf[0] = '\0';

	/* Get both versions from card via gRPC, but only use image version */
	rc = dao_card_image_version_get(card_ctx, image_ver_buf, image_ver_len, app_ver_buf,
					sizeof(app_ver_buf));
	if (rc == 0)
		return 0;

	/* Backward compatibility: If gRPC fails, assume image version is not implemented */
	/* Use a placeholder version for backward compatibility */
	strncpy(image_ver_buf, "unknown-image-version", image_ver_len - 1);
	image_ver_buf[image_ver_len - 1] = '\0';

	return 0; /* Return success for backward compatibility */
}

/* Check compatibility between new app_version (from tar) and image */
int
image_compatibility_check(const char *tar_file_path, const char *image_ver_buf)
{
	char extract_cmd[PATH_MAX + IMAGE_VERSION_LEN_MAX];
	char temp_dir[] = "/tmp/app_update_XXXXXX";
	char version_file_path[PATH_MAX];
	int found_image_section = 0;
	FILE *version_file = NULL;
	int image_compatible = 0;
	int rc = -EINVAL;
	char line[512];

	/* Create temporary directory */
	if (!mkdtemp(temp_dir))
		return -errno;

	/* Validate paths don't contain shell metacharacters to prevent injection */
	if (strpbrk(tar_file_path, ";|&$<>(){}[]!#`'\"\\") != NULL) {
		DAO_CARD_ERR("Invalid characters in tar file path");
		rc = -EINVAL;
		goto cleanup;
	}
	if (strpbrk(temp_dir, ";|&$<>(){}[]!#`'\"\\") != NULL) {
		DAO_CARD_ERR("Invalid temporary directory path");
		rc = -EINVAL;
		goto cleanup;
	}

	/* Extract tar file to temporary directory */
	snprintf(extract_cmd, sizeof(extract_cmd), "tar -xf %s -C %s", tar_file_path, temp_dir);
	rc = run_cmd(extract_cmd);
	if (rc != 0)
		goto cleanup;

	/* Look for compatibility matrix file in the extracted tar */
	snprintf(version_file_path, sizeof(version_file_path),
		 "%s/lc_service/compatibility_matrix.txt", temp_dir);
	version_file = fopen(version_file_path, "r");

	/* Backward compatibility: If compatibility matrix is missing, allow update with
	 * warning */
	if (!version_file) {
		DAO_CARD_ERR(
			"Compatibility matrix not found. Proceeding app update in backward compatibility");
		rc = 0;
		goto cleanup;
	}

	/* Parse the compatibility matrix file */
	while (fgets(line, sizeof(line), version_file)) {
		/* Trim leading whitespace */
		char *p = line;

		while (*p && (*p == ' ' || *p == '\t'))
			p++;

		/* Trim trailing whitespace */
		char *end = p + strlen(p) - 1;

		while (end > p && (*end == '\n' || *end == '\r' || *end == ' ' || *end == '\t')) {
			*end = '\0';
			end--;
		}

		/* Skip empty lines and comments */
		if (!*p || *p == '#')
			continue;

		/* Check for IMAGE_VERSIONS section */
		if (strncmp(p, "[IMAGE_VERSIONS]", 17) == 0) {
			found_image_section = 1;
			continue;
		} else if (*p == '[') {
			/* Other section found, exit image section */
			found_image_section = 0;
			continue;
		}

		/* Check if current image version is listed in the IMAGE_VERSIONS section */
		if (found_image_section && strcmp(p, image_ver_buf) == 0) {
			image_compatible = 1;
			break;
		}
	}

	fclose(version_file);
	version_file = NULL;

	/* Determine compatibility result */
	if (found_image_section) {
		if (image_compatible) {
			rc = 0;
		} else {
			DAO_CARD_ERR(
				"The app update package is not compatible with the current image version");
			rc = -EINVAL;
		}
	} else {
		/* Compatibility matrix exists but no IMAGE_VERSIONS section found - FAIL */
		DAO_CARD_ERR("The compatibility matrix file is invalid or malformed");
		rc = -EINVAL;
	}

cleanup:
	if (version_file)
		fclose(version_file);

	/* Clean up temporary directory */
	/* Validate temp_dir before using in shell command */
	if (strpbrk(temp_dir, ";|&$<>(){}[]!#`'\"\\") == NULL) {
		snprintf(extract_cmd, sizeof(extract_cmd), "rm -rf %s", temp_dir);
		run_cmd(extract_cmd);
	} else {
		DAO_CARD_ERR("Skipping cleanup - invalid characters in temp_dir path");
	}

	return rc;
}

int
dao_card_mgr_get_image_version(char *image_ver_buf, size_t image_ver_len, char *app_ver_buf,
			       size_t app_ver_len, char *combined_buf, size_t combined_len)
{
	int rc;

	/* Validate inputs */
	if (!image_ver_buf || image_ver_len == 0 || !app_ver_buf || app_ver_len == 0)
		return -EINVAL;

	/* Check if card_ctx is initialized */
	if (card_ctx == NULL) {
		dao_err("card_ctx is NULL - card may not be initialized. Run card_init first.");
		return -EINVAL;
	}

	/* Get both rootfs and app version from card via single gRPC call */
	rc = dao_card_image_version_get(card_ctx, image_ver_buf, image_ver_len, app_ver_buf,
					app_ver_len);
	if (rc != 0) {
		const char *error_type = "unknown";

		switch (rc) {
		case -EINVAL:
			error_type = "invalid argument";
			break;
		case -ENOENT:
			error_type = "rootfs version file not found on card";
			break;
		case -EAGAIN:
			error_type = "service unavailable (card may not be ready)";
			break;
		case -ETIMEDOUT:
			error_type = "request timed out";
			break;
		case -ENOTSUP:
			error_type = "operation not supported by card";
			break;
		}

		dao_err("Failed to get image versions: %d (%s)", rc, error_type);
		return rc;
	}

	/* Optionally combine both versions into a single string */
	if (combined_buf && combined_len > 0) {
		snprintf(combined_buf, combined_len, "Main Image: %s, App: %s", image_ver_buf,
			 app_ver_buf);
	}

	return 0;
}

int
dao_card_mgr_boot_exec(const char *boot_path, const char *boot_arg)
{
	int rc = 0;
	pid_t pid;

	if (strpbrk(boot_path, ";|&$<>(){}[]!#") != NULL) {
		DAO_CARD_ERR("Invalid characters \";|&$<>(){}[]!#\" in boot binary path");
		return -EINVAL;
	}

	if (access(boot_path, X_OK) != 0) {
		DAO_CARD_ERR("Boot binary not found or not executable: %s", boot_path);
		return -ENOENT;
	}

	pid = fork();

	if (pid == 0) {
		execlp(boot_path, boot_path, boot_arg, (char *)NULL);
		_exit(127);
	} else if (pid > 0) {
		int status = 0;

		if (waitpid(pid, &status, 0) == -1)
			rc = -errno;
		else if (!WIFEXITED(status))
			rc = -EIO;
		else
			rc = WEXITSTATUS(status);
	} else {
		rc = -errno;
	}

	return rc;
}

/* Poll the gRPC card_info until ready or timeout.
 * Returns 0 when ready, -ETIMEDOUT if timeout exceeded, or another negative
 * error code if a non-transient failure occurs.
 */
int
dao_card_wait_ready(int timeout_ms, int interval_ms)
{
	struct dao_card_info info;
	int waited = 0;
	int rc;

	/* Validate card context */
	rc = validate_card_ctx_ready();
	if (rc != 0)
		return rc;

	if (timeout_ms <= 0)
		return 0;

	/* Validate interval to prevent overflow */
	if (interval_ms <= 0 || interval_ms > 1000000) {
		DAO_CARD_ERR("Invalid interval_ms: %d", interval_ms);
		return -EINVAL;
	}
	if (interval_ms > INT_MAX / 1000) {
		DAO_CARD_ERR("interval_ms too large, would overflow");
		return -EINVAL;
	}

	dao_info("Waiting for card to become ready (timeout=%d ms)...", timeout_ms);

	while (waited < timeout_ms) {
		rc = dao_card_info_get(card_ctx, &info);
		if (rc == 0) {
			dao_info("Card is ready (nb_devs=%d, max_sessions=%d)", info.nb_devs,
				 info.max_sessions);
			return 0;
		}
		if (rc != -EAGAIN) {
			dao_err("Card readiness check failed: %s", strerror(-rc));
			return rc;
		}
		usleep(interval_ms * 1000);
		waited += interval_ms;
	}
	dao_err("Timed out waiting for card readiness after %d ms", timeout_ms);
	return -ETIMEDOUT;
}

int
reload_and_bringup_octeon_ep(const char *boot_bin_path, const char *boot_arg, const char *ip_addr)
{
	const char *unload_before_boot = getenv(OCTEON_EP_UNLOAD_BEFORE_BOOT_ENV);
	int boot_rc = 0;

	/* For some Linux distributions, unload the module before boot exec */
	if (unload_before_boot) {
		boot_rc = reload_octeon_ep_module(boot_arg, OCTEON_EP_MODULE_UNLOAD_ONLY);
		if (boot_rc != 0) {
			DAO_CARD_ERR("Failed to unload network driver (octeon_ep)");
			DAO_CARD_ERR("Check if driver is in use or check system logs");
			return boot_rc;
		}
	}

	if (boot_bin_path) {
		boot_rc = dao_card_mgr_boot_exec(boot_bin_path, boot_arg);
		if (boot_rc != 0) {
			DAO_CARD_ERR("Failed to execute card boot binary");
			DAO_CARD_ERR("Verify boot binary path and card state");
			return boot_rc;
		}
	}

	/* If we unloaded before boot, reload the module in load-only mode */
	if (unload_before_boot) {
		boot_rc = reload_octeon_ep_module(boot_arg, OCTEON_EP_MODULE_LOAD_ONLY);
		if (boot_rc != 0) {
			DAO_CARD_ERR("Failed to load network driver (octeon_ep)");
			DAO_CARD_ERR("Card may not be accessible over network");
			DAO_CARD_ERR("Check system logs: dmesg | grep octeon_ep");
			return boot_rc;
		}
	} else {
		/* Normal reload behavior when no pre-boot unload was done */
		boot_rc = reload_octeon_ep_module(boot_arg, OCTEON_EP_MODULE_RELOAD);
		if (boot_rc != 0) {
			DAO_CARD_ERR("Failed to reload network driver (octeon_ep)");
			DAO_CARD_ERR("Card may not be accessible over network");
			DAO_CARD_ERR("Check system logs: dmesg | grep octeon_ep");
			return boot_rc;
		}
	}

	bring_up_octeon_ep_interface(ip_addr);

	/* Integrated readiness wait */
	DAO_CARD_INFO("Waiting for card to become ready (timeout: 20 seconds)...");
	int wrc = dao_card_wait_ready(20000, 250);

	if (wrc) {
		DAO_CARD_ERR("Card did not respond within timeout period");
		DAO_CARD_ERR("Card may be booting (wait longer) or failed to boot");
		DAO_CARD_ERR("Check card console logs for boot status");
		return wrc;
	}
	return 0;
}

int
dao_card_mgr_boot(cli_args *cmd)
{
	const char *boot_path;
	const char *boot_arg = NULL;
	const char *arg;
	int rc = 0;

	if (!cmd || !cmd->argv) {
		DAO_CARD_ERR("Invalid command structure");
		return -EINVAL;
	}

	if (cmd->argc < 3) {
		DAO_CARD_ERR(
			"card_boot command requires arguments: <main|failsafe> <path-to-mrvl-oct-boot>");
		return -EINVAL;
	}

	if (!cmd->argv[1] || !cmd->argv[2]) {
		DAO_CARD_ERR("Missing required arguments");
		return -EINVAL;
	}

	boot_path = cmd->argv[2];
	arg = cmd->argv[1];

	if (strcmp(arg, "main") == 0) {
		boot_arg = "mmc";
	} else if (strcmp(arg, "failsafe") == 0) {
		boot_arg = "spi";
	} else {
		DAO_CARD_ERR("Invalid argument to card_boot: %s", arg);
		return -EINVAL;
	}

	rc = reload_and_bringup_octeon_ep(boot_path, boot_arg, DAO_CARD_MGR_BOOT_IP);
	if (rc != 0) {
		DAO_CARD_ERR("Boot exec / readiness failed in card_boot: %d", rc);
		return rc;
	}
	return 0;
}

int
dao_card_mgr_reboot(void)
{
	int rc;

	/* Start operation tracking */
	rc = dao_card_operation_start("card_reboot");
	if (rc < 0)
		return rc;

	DAO_CARD_INFO("Rebooting card from failsafe...");
	rc = reload_and_bringup_octeon_ep(NULL, "spi", DAO_CARD_MGR_BOOT_IP);
	if (rc != 0) {
		DAO_CARD_ERR("Card failed to reboot");
		DAO_CARD_ERR("Check card console and power cycle if necessary");
	} else {
		DAO_CARD_INFO("Card rebooted successfully");
	}

	/* Only remove marker on success; keep it on failure for cooldown */
	dao_card_operation_end(rc == 0);

	return rc;
}
