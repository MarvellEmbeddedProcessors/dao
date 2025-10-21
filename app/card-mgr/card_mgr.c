/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <arpa/inet.h>
#include <editline/readline.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <histedit.h>
#include <ifaddrs.h>
#include <limits.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <syslog.h>
#include <unistd.h>

#include <dao_card_grpc_client.h>
#include <dao_log.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#if defined(__FreeBSD__)
#ifndef EREMOTEIO
#define EREMOTEIO 121
#endif
#endif

#define DAO_CARD_CFG_NB_DESC     1024
#define DAO_CARD_MGR_PORT        50055
#define DAO_CARD_GRPC_PORT       50051
#define DAO_CARD_MGR_MAX_CLIENTS 10
#define BUFFER_SIZE              1024
#define CA_MAX_WORKER_CORES      23

#define DAO_CARD_MGR_CARD_INIT        "card_init"
#define DAO_CARD_MGR_CARD_FINI        "card_fini"
#define DAO_CARD_MGR_CARD_INFO        "card_info"
#define DAO_CARD_MGR_APP_UPDATE       "card_app_update"
#define DAO_CARD_MGR_APP_FALLBACK     "card_app_fallback"
#define DAO_CARD_MGR_CARD_STATS       "card_stats"
#define DAO_CARD_MGR_FW_UPDATE        "card_fw_update"
#define DAO_CARD_MGR_BOOT_SOURCE      "card_boot_source"
#define DAO_CARD_MGR_CARD_REBOOT      "card_reboot"
#define DAO_CARD_MGR_FAILSAFE_UPDATE  "card_failsafe_update"
#define DAO_CARD_MGR_MCU_UPDATE       "card_mcu_update"
#define DAO_CARD_MGR_DMESG            "card_dmesg"
#define DAO_CARD_MGR_APPLOG           "card_applog"
#define DAO_CARD_MGR_CARD_TEMPERATURE "card_temperature"
#define DAO_CMD_ARGS_ANY              -1 /* variable args */

#define DAO_CARD_MGR_MAX_ERR_MSG_LEN 256
#define DAO_CARD_MGR_MAX_SENSORS_LEN 4096

/* Module reload helpers */
#define DAO_CARD_MGR_BOOT_IP        "192.168.1.2"
#define OCTEON_EP_MODULE_NAME       "octeon_ep"
#define OCTEON_EP_RMMOD_TIMEOUT_MS  5000
#define OCTEON_EP_INSMOD_TIMEOUT_MS 5000
#define OCTEON_EP_POLL_INTERVAL_US  100000 /* 100ms */

/* Environment variable to control module unload before boot exec.
 * When set, unloads octeon_ep module before dao_card_mgr_boot_exec and
 * reloads it after. Required for some Linux distributions.
 */
#define OCTEON_EP_UNLOAD_BEFORE_BOOT_ENV "OCTEON_EP_UNLOAD_BEFORE_BOOT"

/* Time to wait after successful module unload before attempting re-load.
 * Different settle windows depending on boot source:
 *  - MMC (main image):  60s
 *  - SPI (failsafe):   120s (slower bring-up path / extra init)
 */
#define OCTEON_EP_RELOAD_WAIT_MMC_MS 60000  /* 60 seconds */
#define OCTEON_EP_RELOAD_WAIT_SPI_MS 120000 /* 120 seconds */

static __thread char *dao_card_err_buf;
static __thread size_t dao_card_err_buf_len;

/* Global state */
static volatile bool force_quit;
static struct dao_card_grpc_ctx *card_ctx;                   /* actual definition */
static char remote_card_ip[INET_ADDRSTRLEN] = "192.168.1.1"; /* target card IP */

#define DAO_CARD_ERR(fmt, ...) dao_card_log_err_internal((fmt), ##__VA_ARGS__)

typedef enum dao_card_mgr_instance {
	DAO_CARD_MGR_AS_SERVER,
	DAO_CARD_MGR_AS_CLIENT,
	DAO_CARD_MGR_AS_SERVER_CLI,
	DAO_CARD_MGR_INVALID,
} dao_card_mgr_instance;

typedef enum octeon_ep_module_op {
	OCTEON_EP_MODULE_UNLOAD_ONLY,
	OCTEON_EP_MODULE_LOAD_ONLY,
	OCTEON_EP_MODULE_RELOAD, /* unload then load */
} octeon_ep_module_op;

typedef struct {
	int argc;
	char **argv;
	char *line;
} cli_args;

static struct dao_card_grpc_ctx *card_ctx;

static struct option long_options[] = {
	{"help", no_argument, 0, 'h'},
	{"client", no_argument, 0, 'c'},
	{"server", no_argument, 0, 's'},
	{"server_cli", no_argument, 0, 'f'},
	{"ip", required_argument, 0, 'i'},
	{0, 0, 0, 0}
};

/* Command specification */
struct dao_card_cmd_spec {
	const char *name;  /* command string */
	int min_args;      /* minimum argc (including command itself) */
	int max_args;      /* maximum argc (including command itself), -1 for unlimited */
	const char *usage; /* brief usage string (arguments only) */
	const char *desc;  /* short description */
};

static const struct dao_card_cmd_spec dao_card_cmd_specs[] = {
	{DAO_CARD_MGR_CARD_INIT, 1, DAO_CMD_ARGS_ANY, "[EAL args...]",
	 "Initialize card (passes optional EAL args)"},
	{DAO_CARD_MGR_CARD_FINI, 1, 1, "", "Stop card and free resources"},
	{DAO_CARD_MGR_CARD_INFO, 1, 1, "", "Show card information"},
	{DAO_CARD_MGR_CARD_STATS, 1, 1, "", "Show aggregated packet stats"},
	{DAO_CARD_MGR_DMESG, 1, 1, "", "Fetch recent kernel dmesg lines"},
	{DAO_CARD_MGR_APPLOG, 1, 1, "", "Fetch recent application log tail"},
	{DAO_CARD_MGR_CARD_TEMPERATURE, 1, 1, "", "Show voltage/temperature sensors"},
	{DAO_CARD_MGR_APP_FALLBACK, 1, 1, "", "Fallback to previous working application"},
	{DAO_CARD_MGR_BOOT_SOURCE, 3, 3, "<main|failsafe> <absolute_path/mrv-oct-boot>",
	 "Reboot the card from the specified boot source"},
	{DAO_CARD_MGR_CARD_REBOOT, 1, 1, "Reboot the card using current boot source"},
	{DAO_CARD_MGR_MCU_UPDATE, 2, 2, "<absolute_path/file>", "Update MCU firmware"},
	{DAO_CARD_MGR_APP_UPDATE, 3, 3, "<absolute_path/file> <absolute_path/mrv-oct-boot>",
	 "Update application image"},
	{DAO_CARD_MGR_FW_UPDATE, 3, 3, "<absolute_path/file> <absolute_path/mrv-oct-boot>",
	 "Update firmware image"},
	{DAO_CARD_MGR_FAILSAFE_UPDATE, 3, 3, "<absolute_path/file> <absolute_path/mrv-oct-boot>",
	 "Update failsafe image"},
	{"help", 1, 1, "", "Show this help/command list"},
};

static const struct dao_card_cmd_spec *
dao_card_lookup_cmd(const char *cmd)
{
	for (size_t i = 0; i < (sizeof(dao_card_cmd_specs) / sizeof(dao_card_cmd_specs[0])); i++) {
		if (strcmp(cmd, dao_card_cmd_specs[i].name) == 0)
			return &dao_card_cmd_specs[i];
	}
	return NULL;
}

/* Validate path for insmod: allow only a safe subset */
static int
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
static int
run_cmd(const char *cmd)
{
	int r = system(cmd);

	if (r == -1)
		return -errno; /* fork/exec error */
	if (WIFEXITED(r)) {
		int st = WEXITSTATUS(r);

		return st == 0 ? 0 : -EIO;
	}
	return -EIO;
}

/* Check if module is present in /proc/modules */
static int
module_present(const char *name)
{
	FILE *f = fopen("/proc/modules", "r");
	char line[256];
	size_t n = strlen(name);

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

static int
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

static int
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

static inline void
dao_card_err_ctx_set(char *buf, size_t len)
{
	dao_card_err_buf = buf;
	dao_card_err_buf_len = len;
	if (buf && len)
		buf[0] = '\0';
}

static inline void
dao_card_err_ctx_clear(void)
{
	dao_card_err_buf = NULL;
	dao_card_err_buf_len = 0;
}

static void
dao_card_log_err_internal(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsyslog(LOG_ERR, fmt, ap);
	va_end(ap);

	if (dao_card_err_buf && dao_card_err_buf_len && dao_card_err_buf[0] == '\0') {
		va_start(ap, fmt);
		vsnprintf(dao_card_err_buf, dao_card_err_buf_len, fmt, ap);
		va_end(ap);
	}
}

static void
signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		dao_info("Signal %d received, preparing to exit...", signum);

		dao_card_err_ctx_clear();
		force_quit = true;
	}
}

static int
split_path_filename(const char *input, char **out_path, char **out_file)
{
	char *last_slash = strrchr(input, '/');
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
		char cwd[1024];

		if (getcwd(cwd, sizeof(cwd)) == NULL)
			return -EFAULT;
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

static int
validate_file(cli_args *cmd, struct dao_card_update_req *req, char **bootpath)
{
	char fullpath[PATH_MAX];
	struct stat st;
	int rc;

	/* Arguments format updated: <cmd> <file-to-update> <boot-binary-path>
	 * Enforce presence of both file and boot path when a bootpath pointer is supplied.
	 */
	if (cmd->argc < 3) {
		DAO_CARD_ERR("Command requires: <file-to-update> <boot-binary-path>");
		return -EINVAL;
	}
	if (bootpath)
		*bootpath = NULL;

	req->filename = NULL;
	req->filepath = NULL;

	rc = split_path_filename(cmd->argv[1], &req->filepath, &req->filename);
	if (rc != 0) {
		DAO_CARD_ERR("Failed to split path/filename for app update: %s", strerror(-rc));
		return rc;
	}
	/* Now mandatory (checked above) when bootpath != NULL */
	if (bootpath) {
		*bootpath = strdup(cmd->argv[2]);
		if (!*bootpath)
			return -ENOMEM;
	}

	snprintf(fullpath, PATH_MAX, "%s/%s", req->filepath, req->filename);
	if (access(fullpath, F_OK | R_OK) != 0) {
		rc = -errno;
		DAO_CARD_ERR("file '%s' does not exist or is not accessible: %s", fullpath,
			     strerror(errno));
		return rc;
	}
	if (stat(fullpath, &st) == 0 && S_ISDIR(st.st_mode)) {
		DAO_CARD_ERR(" '%s' is a directory, not a file", fullpath);
		return -EISDIR;
	}
	return 0;
}

/* Reload the octeon_ep module. The caller provides the boot_arg ("mmc" or "spi")
 * that was used to invoke the boot binary so we can pick an appropriate settle
 * wait after unload instead of relying on an environment variable.
 */
static int
reload_octeon_ep_module(const char *boot_arg, octeon_ep_module_op operation)
{
	const char *ko_path = getenv("OCTEON_EP_KO_PATH");
	const char *name = OCTEON_EP_MODULE_NAME;
	int did_unload = 0;
	char cmd[512];
	int rc;

	if (force_quit)
		return -EINTR;

	/* Handle unload operation (for UNLOAD_ONLY and RELOAD) */
	if (operation == OCTEON_EP_MODULE_UNLOAD_ONLY || operation == OCTEON_EP_MODULE_RELOAD) {
		/* If present, attempt to remove */
		if (module_present(name)) {
			rc = run_cmd("rmmod " OCTEON_EP_MODULE_NAME);
			if (rc != 0) {
				DAO_CARD_ERR("rmmod %s failed (rc=%d)", name, rc);
				return rc;
			} else {
				rc = wait_for_module_absent(name, OCTEON_EP_RMMOD_TIMEOUT_MS);
				if (rc != 0) {
					DAO_CARD_ERR("Module %s did not unload in time (rc=%d)",
						     name, rc);
					return rc;
				}
				did_unload = 1;
			}
		}
	}

	/* Handle reload wait period */
	if (did_unload) {
		int target_ms = OCTEON_EP_RELOAD_WAIT_MMC_MS;
		int waited = 0;

		if (boot_arg && strcmp(boot_arg, "spi") == 0)
			target_ms = OCTEON_EP_RELOAD_WAIT_SPI_MS;
		while (waited < target_ms) {
			if (force_quit)
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
		if (!ko_path) {
			DAO_CARD_ERR("OCTEON_EP_KO_PATH not set; falling back to modprobe");
			rc = run_cmd("modprobe " OCTEON_EP_MODULE_NAME);
			if (rc != 0) {
				DAO_CARD_ERR("modprob failed (rc=%d)", rc);
				return rc;
			}
			goto wait_for_module;
		}

		if (sanitize_module_path(ko_path) != 0) {
			DAO_CARD_ERR("Invalid characters in OCTEON_EP_KO_PATH: %s", ko_path);
			return -EINVAL;
		}
		snprintf(cmd, sizeof(cmd), "insmod %s", ko_path);
		rc = run_cmd(cmd);
		if (rc != 0) {
			DAO_CARD_ERR("insmod %s failed (rc=%d) path=%s", name, rc, ko_path);
			return rc;
		}

	wait_for_module:
		rc = wait_for_module_present(name, OCTEON_EP_INSMOD_TIMEOUT_MS);
		if (rc != 0) {
			DAO_CARD_ERR("Module %s not present after load (rc=%d)", name, rc);
			return rc;
		}
	}

	return 0;
}

static int
dao_card_mgr_boot_exec(const char *boot_path, const char *boot_arg)
{
	int rc = 0;

	if (strpbrk(boot_path, ";|&$<>(){}[]!#") != NULL) {
		DAO_CARD_ERR("Invalid characters \";|&$<>(){}[]!#\" in boot binary path");
		return -EINVAL;
	}

	if (access(boot_path, X_OK) != 0) {
		DAO_CARD_ERR("Boot binary not found or not executable: %s", boot_path);
		return -ENOENT;
	}

	pid_t pid = fork();

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

static void
bring_up_octeon_ep_interface(const char *ip_addr)
{
	FILE *fp = popen("dmesg | grep 'octeon_ep' | grep 'renamed from' | tail -1", "r");

	if (!fp)
		return;

	char iface[32] = {0};
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
			if (len < sizeof(iface)) {
				strncpy(iface, end, len);
				iface[len] = '\0';
			}
		}
	}
	pclose(fp);

	if (iface[0]) {
		char cmd[128];

		snprintf(cmd, sizeof(cmd), "ifconfig %s %s up", iface, ip_addr);
		if (system(cmd) != 0)
			dao_warn("%s execution failed", cmd);
	}
}

/* Poll the gRPC card_info until ready or timeout.
 * Returns 0 when ready, -ETIMEDOUT if timeout exceeded, or another negative
 * error code if a non-transient failure occurs.
 */
static int
dao_card_wait_ready(int timeout_ms, int interval_ms)
{
	struct dao_card_info info;
	int waited = 0;
	int rc;

	if (timeout_ms <= 0)
		return 0;

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

static int
reload_and_bringup_octeon_ep(const char *boot_bin_path, const char *boot_arg, const char *ip_addr)
{
	const char *unload_before_boot = getenv(OCTEON_EP_UNLOAD_BEFORE_BOOT_ENV);
	int boot_rc = 0;

	/* For some Linux distributions, unload the module before boot exec */
	if (unload_before_boot) {
		boot_rc = reload_octeon_ep_module(boot_arg, OCTEON_EP_MODULE_UNLOAD_ONLY);
		if (boot_rc != 0) {
			DAO_CARD_ERR("unload of octeon_ep failed: %d", boot_rc);
			return boot_rc;
		}
	}

	if (boot_bin_path) {
		boot_rc = dao_card_mgr_boot_exec(boot_bin_path, boot_arg);
		if (boot_rc != 0) {
			DAO_CARD_ERR("Boot exec failed in %s: %d", __func__, boot_rc);
			return boot_rc;
		}
	}

	/* If we unloaded before boot, reload the module in load-only mode */
	if (unload_before_boot) {
		boot_rc = reload_octeon_ep_module(boot_arg, OCTEON_EP_MODULE_LOAD_ONLY);
		if (boot_rc != 0) {
			DAO_CARD_ERR("load of octeon_ep failed: %d", boot_rc);
			return boot_rc;
		}
	} else {
		/* Normal reload behavior when no pre-boot unload was done */
		boot_rc = reload_octeon_ep_module(boot_arg, OCTEON_EP_MODULE_RELOAD);
		if (boot_rc != 0) {
			DAO_CARD_ERR("unload and reload of octeon_ep failed: %d", boot_rc);
			return boot_rc;
		}
	}

	bring_up_octeon_ep_interface(ip_addr);

	/* Integrated readiness wait */
	int wrc = dao_card_wait_ready(20000, 250);

	if (wrc) {
		DAO_CARD_ERR("Card did not become ready after reload: %d", wrc);
		return wrc;
	}
	return 0;
}

/* Handle a response error code from server, optionally reading an extended
 * error message that may follow on the socket. This preserves previous
 * behaviour while keeping the send function slimmer.
 */
static void
dao_card_mgr_process_error(int cli_fd, int resp)
{
	uint32_t err_len = 0;

	/* Attempt to receive an optional error message length when rc < 0 */
	if (resp < 0) {
		ssize_t ln = recv(cli_fd, &err_len, sizeof(err_len), MSG_DONTWAIT);

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
	struct dao_card_stats card_stats;
	uint64_t total_rx_pkts = 0, total_tx_pkts = 0;
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

/* Receive exactly len bytes (blocking) unless peer closes or a fatal error occurs.
 * Returns 0 on success, -ECONNRESET if peer closed, or -errno on failure.
 */
static int
recv_all(int fd, void *buf, size_t len)
{
	uint8_t *p = buf;
	size_t off = 0;

	while (off < len) {
		ssize_t rc = recv(fd, p + off, len - off, 0);

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

/* --- Client command validation helper --- */
static void
dao_card_print_help(void)
{
	fprintf(stderr, "Supported commands:\n");
	for (size_t i = 0; i < (sizeof(dao_card_cmd_specs) / sizeof(dao_card_cmd_specs[0])); i++) {
		const struct dao_card_cmd_spec *s = &dao_card_cmd_specs[i];

		fprintf(stderr, "  %-20s %-50s %s\n", s->name, s->usage, s->desc);
	}
}

static bool
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
	while (tok && argc < (sizeof(argv_local) / sizeof(argv_local[0]))) {
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

static void
dao_card_mgr_send_to_server(int cli_fd, const char *line)
{
	size_t trimmed_len = 0;
	int rc, resp = 0;

	if (!dao_card_client_cmd_valid(line, &trimmed_len))
		return;

	size_t send_len = trimmed_len;
	const char *send_line = line;

	if (send(cli_fd, send_line, send_len, 0) == -1) {
		dao_err("sending cmd to server failed (server may have exited)");
		force_quit = true;
		return;
	}

	rc = recv_all(cli_fd, &resp, sizeof(resp));
	if (rc != 0) {
		if (rc == -ECONNRESET)
			dao_err("Server closed the connection. Exiting client.");
		else
			dao_err("Failed to receive response from server");
		force_quit = true;
		return;
	}

	if (resp) {
		dao_card_mgr_process_error(cli_fd, resp);
		return;
	}

	/* Success payload handling */
	if (strstr(send_line, "card_info") != NULL)
		dao_card_mgr_recv_card_info(cli_fd);
	if (strstr(send_line, "card_stats") != NULL)
		dao_card_mgr_recv_card_stats(cli_fd);
	if (strstr(send_line, "card_dmesg") != NULL)
		dao_card_mgr_recv_card_dmesg(cli_fd);
	if (strstr(send_line, "card_applog") != NULL)
		dao_card_mgr_recv_card_dmesg(cli_fd); /* same framing */
	if (strstr(send_line, "card_temperature") != NULL)
		dao_card_mgr_recv_card_sensors(cli_fd);
}

static int
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

static int
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

static void
dao_card_mgr_editline_fini(History *hist, EditLine *el)
{
	history_end(hist);
	el_end(el);
}

static char *
dao_card_mgr_prompt(EditLine *el)
{
	static char prompt[] = "> ";
	(void)el;

	return prompt;
}

static void
dao_card_mgr_client(void)
{
	int count, cli_fd;
	const char *line;
	History *hist;
	EditLine *el;
	HistEvent ev;

	if (dao_card_mgr_editline_init(&hist, &el, &ev)) {
		dao_err("Editline initialization failed");
		return;
	}

	el_set(el, EL_PROMPT, dao_card_mgr_prompt);

	cli_fd = dao_card_mgr_client_init();
	if (cli_fd < 0) {
		dao_err("client socket initialization failed");
		goto editline_fini;
	}

	while (!force_quit) {
		line = el_gets(el, &count);
		if (line != NULL && count > 0) {
			if (count == 1 && line[0] == '\n')
				continue;

			if (strstr(line, "quit") != NULL)
				break;

			/* Add line to history */
			history(hist, &ev, H_ENTER, line);
			dao_card_mgr_send_to_server(cli_fd, line);
			if (force_quit) {
				printf("\nClient exiting due to server disconnect.\n");
				break;
			}
		}
	}

editline_fini:
	dao_card_mgr_editline_fini(hist, el);
	close(cli_fd);
}

/* display usage */
static void
dao_card_mgr_usage_print(void)
{
	fprintf(stderr, "Usage: dao_card_mgr [--help] [--client] [--server --ip <IP address>]"
			" [--server_cli]\n");
	fprintf(stderr, "-h, --help Display the usage\n");
	fprintf(stderr, "-c, --client Run the manager as client mode\n");
	fprintf(stderr, "-s, --server Run the manager as server mode\n");
	fprintf(stderr, "-f, --server_cli Run the manager as server in cli mode\n");
}

static int
dao_card_mgr_app_fallback(void)
{
	int rc = 0;

	rc = dao_card_app_fallback(card_ctx);
	if (rc < 0)
		DAO_CARD_ERR("gRPC error in card_app_fallback: %d", rc);
	return rc;
}

static int
dao_card_mgr_app_update(cli_args *cmd)
{
	struct dao_card_update_req update_req;
	char *boot_bin_path = NULL;
	int rc;

	rc = validate_file(cmd, &update_req, &boot_bin_path);
	if (rc != 0)
		goto req_free;

	rc = dao_card_file_update(card_ctx, &update_req, DAO_CARD_APP_UPDATE);
	if (rc == 0 && boot_bin_path != NULL) {
		int boot_rc =
			reload_and_bringup_octeon_ep(boot_bin_path, "mmc", DAO_CARD_MGR_BOOT_IP);

		if (boot_rc != 0)
			DAO_CARD_ERR("Boot exec / readiness failed after app update: %d", boot_rc);
	}

req_free:
	free(update_req.filename);
	free(update_req.filepath);
	if (boot_bin_path)
		free(boot_bin_path);
	return rc;
}

static int
dao_card_mgr_fw_update(cli_args *cmd)
{
	struct dao_card_update_req update_req;
	char *boot_bin_path = NULL;
	int rc;

	rc = validate_file(cmd, &update_req, &boot_bin_path);
	if (rc != 0)
		goto req_free;

	rc = dao_card_file_update(card_ctx, &update_req, DAO_CARD_FW_UPDATE);
	if (rc == 0 && boot_bin_path != NULL) {
		int boot_rc =
			reload_and_bringup_octeon_ep(boot_bin_path, "mmc", DAO_CARD_MGR_BOOT_IP);

		if (boot_rc != 0)
			DAO_CARD_ERR("Boot exec / readiness failed after fw update: %d", boot_rc);
	}

req_free:
	free(update_req.filename);
	free(update_req.filepath);
	if (boot_bin_path)
		free(boot_bin_path);
	return rc;
}

static int
dao_card_mgr_boot(cli_args *cmd)
{
	int rc = 0;

	if (cmd->argc < 3) {
		DAO_CARD_ERR(
			"card_boot command requires arguments: <main|failsafe> <path-to-mrvl-oct-boot>");
		return -EINVAL;
	}

	const char *boot_path = cmd->argv[2];
	const char *arg = cmd->argv[1];
	const char *boot_arg = NULL;

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

static int
dao_card_mgr_reboot(void)
{
	int rc;

	rc = reload_and_bringup_octeon_ep(NULL, "spi", DAO_CARD_MGR_BOOT_IP);
	if (rc != 0) {
		DAO_CARD_ERR("Boot exec / readiness failed in card_reboot: %d", rc);
		return rc;
	}

	return 0;
}

static int
dao_card_mgr_failsafe_update(cli_args *cmd)
{
	struct dao_card_update_req update_req;
	char *boot_bin_path = NULL;
	int rc;

	rc = validate_file(cmd, &update_req, &boot_bin_path);
	if (rc != 0)
		goto req_free;

	rc = dao_card_file_update(card_ctx, &update_req, DAO_CARD_FAILSAFE_UPDATE);
	if (rc == 0 && boot_bin_path != NULL) {
		int boot_rc =
			reload_and_bringup_octeon_ep(boot_bin_path, "spi", DAO_CARD_MGR_BOOT_IP);

		if (boot_rc != 0)
			DAO_CARD_ERR("Boot exec / readiness failed after failsafe update: %d",
				     boot_rc);
	}

req_free:
	free(update_req.filename);
	free(update_req.filepath);
	if (boot_bin_path)
		free(boot_bin_path);
	return rc;
}

static int
dao_card_mgr_update_init_args(cli_args *cmd, const char **new_argv, unsigned long *nb_desc)
{
	const char *app_name = "dao-crypto-agent";
	int has_c = 0, has_l = 0;
	int insert_index = -1;
	int eal_end, j = 1;
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
					char *endptr;

					errno = 0;
					unsigned long val = strtoul(cmd->argv[i + 1], &endptr, 0);

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
			for (int i = j - 1; i >= insert_index; i--)
				new_argv[i + 2] = new_argv[i];

			new_argv[insert_index] = "-c";
			new_argv[insert_index + 1] = "0xffffff";
			j += 2;
		}
	}

	new_argv[j] = NULL;
	return j;
}

static void
dao_card_mgr_process_cmd(int cli_fd, cli_args *cmd)
{
	char sensors_output[DAO_CARD_MGR_MAX_SENSORS_LEN];
	struct dao_card_stats card_stats;
	struct dao_card_config card_cfg;
	struct dao_card_info card_info;
	uint32_t sensors_len = 0;
	int rc = 0;
	char err_msg[DAO_CARD_MGR_MAX_ERR_MSG_LEN];

	/* Set thread-local error capture buffer */
	dao_card_err_ctx_set(err_msg, sizeof(err_msg));

	if (strcmp(cmd->argv[0], DAO_CARD_MGR_CARD_INIT) == 0) {
		const char **new_argv = malloc((cmd->argc + 4) * sizeof(char *));
		unsigned long nb_desc = 0;

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
	} else if (strcmp(cmd->argv[0], DAO_CARD_MGR_CARD_INFO) == 0) {
		rc = dao_card_info_get(card_ctx, &card_info);
	} else if (strcmp(cmd->argv[0], DAO_CARD_MGR_APP_UPDATE) == 0) {
		rc = dao_card_mgr_app_update(cmd);
	} else if (strcmp(cmd->argv[0], DAO_CARD_MGR_APP_FALLBACK) == 0) {
		rc = dao_card_mgr_app_fallback();
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
		struct dao_card_update_req update_req;
		int mrc = validate_file(cmd, &update_req, NULL);

		if (mrc == 0)
			mrc = dao_card_file_update(card_ctx, &update_req, DAO_CARD_MCU_UPDATE);
		free(update_req.filename);
		free(update_req.filepath);
		rc = mrc;
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

static void
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

static int
dao_card_mgr_server_init(const char *ip_str)
{
	struct sockaddr_in sock_addr;
	int optval = 1;
	int rc = -1;
	int srv_fd;

	srv_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (srv_fd == 0) {
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
		strncpy(remote_card_ip, ip_str, sizeof(remote_card_ip));
		remote_card_ip[sizeof(remote_card_ip) - 1] = '\0';
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

static void
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
	int i;

	for (i = 0; i < DAO_CARD_MGR_MAX_CLIENTS; i++)
		client_fds[i] = -1;

	srv_fd = dao_card_mgr_server_init(ip_str);
	if (srv_fd < 0) {
		dao_err("Could not initialize the server");
		return;
	}
	flags = fcntl(srv_fd, F_GETFL, 0);
	fcntl(srv_fd, F_SETFL, flags | O_NONBLOCK);

	while (!force_quit) {
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
			break;
		}
		if (force_quit)
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
}

int
main(int argc, char **argv)
{
	dao_card_mgr_instance mgr_instance = DAO_CARD_MGR_INVALID;
	const char *ip_str = NULL;
	int option, index = 0;

	force_quit = false;
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	while ((option = getopt_long(argc, argv, "hcsfi:", long_options, &index)) != -1) {
		switch (option) {
		case 'c':
			mgr_instance = DAO_CARD_MGR_AS_CLIENT;
			break;
		case 's':
			mgr_instance = DAO_CARD_MGR_AS_SERVER;
			break;
		case 'f':
			mgr_instance = DAO_CARD_MGR_AS_SERVER_CLI;
			break;
		case 'i':
			ip_str = optarg;
			break;
		case 'h':
			dao_card_mgr_usage_print();
			break;
		default:
			dao_err("Invalid option. exiting");
			dao_card_mgr_usage_print();
			break;
		}
	}

	/* Require root privileges (simplified check) */
	if (geteuid() != 0) {
		dao_err("module reload & interface operations require root privilege)");
		return EXIT_FAILURE;
	}

	switch (mgr_instance) {
	case DAO_CARD_MGR_AS_CLIENT:
		dao_info("Starting as client");
		dao_card_mgr_client();
		break;
	case DAO_CARD_MGR_AS_SERVER:
		dao_info("Starting as server");
		dao_card_mgr_server(ip_str);
		break;
	case DAO_CARD_MGR_AS_SERVER_CLI:
		dao_info("Support need to be added");
		break;
	default:
		dao_info("Unsupported mode");
		break;
	}
	return 0;
}
