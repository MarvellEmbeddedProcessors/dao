/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef CARD_MGR_H
#define CARD_MGR_H

#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

/* Utility macros */
#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

/* Port definitions */
#define DAO_CARD_CFG_NB_DESC     1024
#define DAO_CARD_MGR_PORT        50055
#define DAO_CARD_GRPC_PORT       50051
#define DAO_CARD_MGR_MAX_CLIENTS 10
#define BUFFER_SIZE              1024
#define CA_MAX_WORKER_CORES      23

/* Command string definitions */
#define DAO_CARD_MGR_CARD_INIT        "card_init"
#define DAO_CARD_MGR_CARD_FINI        "card_fini"
#define DAO_CARD_MGR_CARD_INFO        "card_info"
#define DAO_CARD_MGR_IMAGE_VERSION    "card_image_version"
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
#define DAO_CARD_MGR_SOFT_RESET       "card_soft_reset"
#define DAO_CMD_ARGS_ANY              -1 /* variable args */

#define DAO_CARD_MGR_MAX_ERR_MSG_LEN 256
#define DAO_CARD_MGR_MAX_SENSORS_LEN 4096

/* Module reload helpers */
#define DAO_CARD_MGR_BOOT_IP        "192.168.1.2"
#define OCTEON_EP_MODULE_NAME       "octeon_ep"
#define OCTEON_EP_RMMOD_TIMEOUT_MS  5000
#define OCTEON_EP_INSMOD_TIMEOUT_MS 5000
#define OCTEON_EP_POLL_INTERVAL_US  100000 /* 100ms */

#define OCTEON_EP_UNLOAD_BEFORE_BOOT_ENV "OCTEON_EP_UNLOAD_BEFORE_BOOT"
#define OCTEON_EP_RELOAD_WAIT_MMC_MS     60000  /* 60 seconds */
#define OCTEON_EP_RELOAD_WAIT_SPI_MS     120000 /* 120 seconds */

#define IMAGE_VERSION_LEN_MAX 64

/* Manager instance types */
typedef enum dao_card_mgr_instance {
	DAO_CARD_MGR_AS_SERVER,
	DAO_CARD_MGR_AS_CLIENT,
	DAO_CARD_MGR_AS_SERVER_CLI,
	DAO_CARD_MGR_INVALID,
} dao_card_mgr_instance;

/* Module operation types */
typedef enum octeon_ep_module_op {
	OCTEON_EP_MODULE_UNLOAD_ONLY,
	OCTEON_EP_MODULE_LOAD_ONLY,
	OCTEON_EP_MODULE_RELOAD, /* unload then load */
} octeon_ep_module_op;

/* CLI arguments structure */
typedef struct {
	int argc;
	char **argv;
	char *line;
} cli_args;

/* Command specification */
struct dao_card_cmd_spec {
	const char *name;  /* command string */
	int min_args;      /* minimum argc (including command itself) */
	int max_args;      /* maximum argc (including command itself), -1 for unlimited */
	const char *usage; /* brief usage string (arguments only) */
	const char *desc;  /* short description */
};

/* Global state */
extern atomic_bool dao_card_force_quit;
extern struct dao_card_grpc_ctx *card_ctx;
extern char remote_card_ip[];

/* Command specifications table */
extern const struct dao_card_cmd_spec dao_card_cmd_specs[];
extern const size_t dao_card_cmd_specs_count;

/* Command lookup */
const struct dao_card_cmd_spec *dao_card_lookup_cmd(const char *cmd);

/* Signal handler */
void dao_card_signal_handler(int signum);

#endif /* CARD_MGR_H */
