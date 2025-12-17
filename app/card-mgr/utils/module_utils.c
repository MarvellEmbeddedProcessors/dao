/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include <dao_log.h>

#include "logging.h"
#include "module_utils.h"

/* Validate path for insmod: allow only a safe subset */
int
sanitize_module_path(const char *p)
{
	if (!p || !*p)
		return -EINVAL;
	for (const char *c = p; *c; c++) {
		if (!((*c >= 'a' && *c <= 'z') || (*c >= 'A' && *c <= 'Z') ||
		      (*c >= '0' && *c <= '9') || *c == '_' || *c == '.' || *c == '/' || *c == '-'))
			return -EINVAL;
	}
	return 0;
}

/* Run a shell command and normalize return codes to 0 / -errno / -EIO */
int
run_cmd(const char *cmd)
{
	const char *p;
	int r;

	if (!cmd || !*cmd)
		return -EINVAL;

	/* Defense in depth: validate for shell metacharacters that could
	 * enable command injection. While callers should sanitize inputs,
	 * this provides an additional security layer since system() executes
	 * commands via shell.
	 *
	 * Reject commands containing dangerous shell metacharacters.
	 */
	if (strpbrk(cmd, ";|&$<>(){}[]!#`'\"\\*?~") != NULL) {
		/* Find and report the first dangerous character */
		for (p = cmd; *p != '\0'; p++) {
			if (strchr(";|&$<>(){}[]!#`'\"\\*?~", *p) != NULL) {
				DAO_CARD_ERR("Dangerous shell metacharacter '%c' detected in command", *p);
				break;
			}
		}
		return -EINVAL;
	}

	r = system(cmd);

	if (r == -1)
		return -errno; /* fork/exec error */
	if (WIFEXITED(r)) {
		int st = WEXITSTATUS(r);

		return st == 0 ? 0 : -EIO;
	}
	return -EIO;
}

/* Check if module is present in /proc/modules */
int
module_present(const char *name)
{
	char line[256];
	size_t n;
	FILE *f;

	if (!name || !*name)
		return 0;

	f = fopen("/proc/modules", "r");
	n = strlen(name);

	if (!f)
		return 0; /* can't verify -> assume not present */
	while (fgets(line, sizeof(line), f)) {
		if (strncmp(line, name, n) == 0 && line[n] == ' ') {
			fclose(f);
			return 1;
		}
	}
	fclose(f);
	return 0;
}

int
wait_for_module_absent(const char *name, int timeout_ms)
{
	int waited = 0;

	while (module_present(name)) {
		if (waited >= timeout_ms)
			return -ETIMEDOUT;
		usleep(OCTEON_EP_POLL_INTERVAL_US);
		waited += OCTEON_EP_POLL_INTERVAL_US / 1000;
	}
	return 0;
}

int
wait_for_module_present(const char *name, int timeout_ms)
{
	int waited = 0;

	while (!module_present(name)) {
		if (waited >= timeout_ms)
			return -ETIMEDOUT;
		usleep(OCTEON_EP_POLL_INTERVAL_US);
		waited += OCTEON_EP_POLL_INTERVAL_US / 1000;
	}
	return 0;
}

/* Reload the octeon_ep module. The caller provides the boot_arg ("mmc" or "spi")
 * that was used to invoke the boot binary so we can pick an appropriate settle
 * wait after unload instead of relying on an environment variable.
 */
int
reload_octeon_ep_module(const char *boot_arg, octeon_ep_module_op operation)
{
	const char *ko_path = getenv("OCTEON_EP_KO_PATH");
	const char *name = OCTEON_EP_MODULE_NAME;
	int did_unload = 0;
	char cmd[512];
	int rc;

	if (atomic_load(&dao_card_force_quit))
		return -EINTR;

	/* Handle unload operation (for UNLOAD_ONLY and RELOAD) */
	if (operation == OCTEON_EP_MODULE_UNLOAD_ONLY || operation == OCTEON_EP_MODULE_RELOAD) {
		/* If present, attempt to remove */
		if (module_present(name)) {
			rc = run_cmd("rmmod " OCTEON_EP_MODULE_NAME);
			if (rc != 0) {
				DAO_CARD_ERR("rmmod %s failed (rc=%d)", name, rc);
				return rc;
			}
			rc = wait_for_module_absent(name, OCTEON_EP_RMMOD_TIMEOUT_MS);
			if (rc != 0) {
				DAO_CARD_ERR("Module %s did not unload in time (rc=%d)", name, rc);
				return rc;
			}
			did_unload = 1;
		}
	}

	/* Handle reload wait period */
	if (did_unload) {
		int target_ms = OCTEON_EP_RELOAD_WAIT_MMC_MS;
		int waited = 0;

		if (boot_arg && strcmp(boot_arg, "spi") == 0)
			target_ms = OCTEON_EP_RELOAD_WAIT_SPI_MS;
		while (waited < target_ms) {
			if (atomic_load(&dao_card_force_quit))
				return -EINTR;
			usleep(200000); /* 200ms */
			waited += 200;
		}
	}

	/* If this was unload-only operation, we're done */
	if (operation == OCTEON_EP_MODULE_UNLOAD_ONLY)
		return 0;

	/* Handle load operation (for LOAD_ONLY and RELOAD) */
	if (operation == OCTEON_EP_MODULE_LOAD_ONLY || operation == OCTEON_EP_MODULE_RELOAD) {
		if (!ko_path || *ko_path == '\0') {
			DAO_CARD_ERR("OCTEON_EP_KO_PATH not set; falling back to modprobe");
			goto fallback_modprobe;
		}

		if (sanitize_module_path(ko_path) != 0) {
			DAO_CARD_ERR(
				"Invalid characters in OCTEON_EP_KO_PATH: %s; falling back to modprobe",
				ko_path);
			goto fallback_modprobe;
		}

		snprintf(cmd, sizeof(cmd), "insmod %s", ko_path);
		rc = run_cmd(cmd);
		if (rc != 0) {
			DAO_CARD_ERR("insmod %s failed (rc=%d) path=%s; falling back to modprobe",
				     name, rc, ko_path);
			goto fallback_modprobe;
		}
		goto wait_for_module;

	fallback_modprobe:
		rc = run_cmd("modprobe " OCTEON_EP_MODULE_NAME);
		if (rc != 0) {
			DAO_CARD_ERR("modprobe failed (rc=%d)", rc);
			return rc;
		}

	wait_for_module:
		rc = wait_for_module_present(name, OCTEON_EP_INSMOD_TIMEOUT_MS);
		if (rc != 0) {
			DAO_CARD_ERR("Module %s not present after load (rc=%d)", name, rc);
			return rc;
		}

		/* Insmod of a custom module needs time for full device probe.
		 * Wait 2 seconds for device probe and interface creation.
		 */
		if (ko_path) {
			dao_info("Waiting for custom module device initialization...");
			usleep(2000000);
		}
	}

	return 0;
}

/* Validate IP address format (digits, dots, colons only) */
static int
validate_ip_address(const char *ip)
{
	const char *c;

	if (!ip || !*ip)
		return -EINVAL;

	for (c = ip; *c; c++) {
		if (!((*c >= '0' && *c <= '9') || *c == '.' || *c == ':'))
			return -EINVAL;
	}
	return 0;
}

void
bring_up_octeon_ep_interface(const char *ip_addr)
{
	int max_retries = 10; /* Try for up to 5 seconds */
	char iface[32] = {0};
	int retry_count = 0;
	int found = 0;

	/* Validate IP address to prevent command injection */
	if (validate_ip_address(ip_addr) != 0) {
		dao_warn("Invalid IP address format: %s", ip_addr);
		return;
	}

	/* Wait for the interface to appear and be renamed */
	while (retry_count < max_retries && !found) {
		FILE *fp = popen("dmesg | grep 'octeon_ep' | grep 'renamed from' | tail -1", "r");

		if (!fp) {
			usleep(500000); /* Wait 500ms before retry */
			retry_count++;
			continue;
		}

		char buf[256];

		if (fgets(buf, sizeof(buf), fp)) {
			/* Example line: octeon_ep 0000:01:00.0 enp1s0f0: renamed from eth0 */
			char *p = strstr(buf, ": renamed from");

			if (p) {
				/* Find the interface name before ': renamed from' */
				char *end = p;
				size_t len;

				while (end > buf && *(end - 1) != ' ')
					end--;
				len = p - end;
				if (len < sizeof(iface) - 1) {
					strncpy(iface, end, len);
					iface[len] = '\0';
					found = 1;
				}
			}
		}
		pclose(fp);

		if (!found) {
			usleep(500000); /* Wait 500ms before retry */
			retry_count++;
		}
	}

	if (!iface[0]) {
		dao_warn("Failed to find octeon_ep interface after %d retries", retry_count);
		return;
	}

	/* Verify the interface actually exists before trying to configure it */
	char check_cmd[128];

	snprintf(check_cmd, sizeof(check_cmd), "ip link show %s > /dev/null 2>&1", iface);

	retry_count = 0;
	while (retry_count < max_retries) {
		if (system(check_cmd) == 0) {
			/* Interface exists, configure it */
			char cmd[128];

			snprintf(cmd, sizeof(cmd), "ifconfig %s %s up", iface, ip_addr);
			if (system(cmd) != 0)
				dao_warn("%s execution failed", cmd);
			else
				dao_info("Successfully configured interface %s with IP %s", iface,
					 ip_addr);
			return;
		}
		usleep(500000); /* Wait 500ms before retry */
		retry_count++;
	}

	dao_warn("Interface %s not found after %d retries", iface, retry_count);
}
