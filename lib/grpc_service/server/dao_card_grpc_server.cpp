/* SPDX-License-Identifier: Marvell-MIT
 * Copyright(C) 2025 Marvell.
 */

#include <chrono>
#include <fstream>
#include <mutex>
#include <sstream>
#include <thread>
#include <arpa/inet.h>

#include <grpc/grpc.h>
#include <grpcpp/server.h>
#include <grpcpp/server_builder.h>
#include <grpcpp/server_context.h>

#include <sys/wait.h>
#include <sys/stat.h>

#include "dao_card_grpc_server.h"
#include <dao_card.grpc.pb.h>

#include <dao_lc.grpc.pb.h>

#define APP_BASE_DIR "/tmp"
#define FW_BASE_DIR "/mnt/new_root"
#define LC_SCRIPT_BASE_MMC "/mnt/app/lc_service/scripts"
#define LC_SCRIPT_BASE_ROOT "/root/lc_service/scripts"
#define APP_UPDATE_SCRIPT "lc_app_update.sh"
#define APP_FALLBACK_SCRIPT "lc_app_fallback.sh"
#define BOOT_SRC_GET_SCRIPT "lc_boot_src_get.sh"
#define FW_UPDATE_SCRIPT "lc_fw_update.sh"
#define FW_MOUNT_SCRIPT "lc_fw_mount.sh"
#define FAILSAFE_UPDATE_SCRIPT "lc_failsafe_update.sh"
#define MCU_UPDATE_SCRIPT "lc_mcu_update.sh"
#define MCU_ALL_CLEAR_SCRIPT "mcu_all_clear_signal.sh"

#define LC_IP_ADDRESS_ENV_VAR "LC_IP_ADDRESS"
#define LC_DEFAULT_PORT 50051
#define LC_DEFAULT_IP_ADDRESS "192.168.1.1"

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::Status;
using grpc::StatusCode;
using grpc::ServerInitializer;

using dao_card_manager::DaoCardService;
using dao_card_manager::CardConfig;
using dao_card_manager::CardInfo;
using dao_card_manager::CardResponse;
using dao_card_manager::FileUpdateReq;
using dao_card_manager::FileTransferType;
using dao_card_manager::CardStats;
using dao_card_manager::Emp;
using dao_card_manager::DmesgLogs;
using dao_card_manager::CardSensors;
using dao_card_manager::AppLogs;

using lc_manager::DaoLCService;
using lc_manager::DeviceId;
using lc_manager::QueuePairId;
using lc_manager::QpConf;
using lc_manager::Response;
using lc_manager::Empty;

struct dao_card_server_cbs *server_cbs;

static inline StatusCode
status_code_from_rc(int rc)
{
	if (rc >= 0)
		return StatusCode::OK;

	rc = -rc; /* make positive errno */
	switch (rc) {
	case EINVAL:
		return StatusCode::INVALID_ARGUMENT;
	case ENOTSUP:
		return StatusCode::UNIMPLEMENTED;
	case EAGAIN:
	case EINPROGRESS:
		return StatusCode::UNAVAILABLE;
	case ENOENT:
		return StatusCode::NOT_FOUND;
	case ENODEV:
		return StatusCode::NOT_FOUND;
	case EBUSY:
		return StatusCode::FAILED_PRECONDITION; /* or ABORTED */
	case EPERM:
	case EACCES:
		return StatusCode::PERMISSION_DENIED;
	case ENOMEM:
		return StatusCode::RESOURCE_EXHAUSTED;
	case EEXIST:
		return StatusCode::ALREADY_EXISTS;
	case ETIMEDOUT:
		return StatusCode::DEADLINE_EXCEEDED;
	case ECONNRESET:
	case EPIPE:
		return StatusCode::UNAVAILABLE;
	case ENOSPC:
		return StatusCode::RESOURCE_EXHAUSTED;
	default:
		return StatusCode::INTERNAL;
	}
}

static inline Status
status_from_rc(int rc, const char *msg)
{
	if (rc == 0)
		return Status::OK;
	return Status(status_code_from_rc(rc), msg ? msg : "error");
}

static bool
is_mmc_boot()
{
	std::ifstream f("/proc/cmdline");
	if (!f.is_open())
		return false;
	std::string line;
	std::getline(f, line);
	return line.find("root=/dev/mmcblk") != std::string::npos;
}

static inline std::string
script_full_path(const std::string &script_name, bool prefer_mmc)
{
	/* Scripts that logically reside under MMC when available */
	bool mmc_boot = is_mmc_boot();
	std::string base;
	if (mmc_boot && prefer_mmc)
		base = LC_SCRIPT_BASE_MMC;
	else
		base = LC_SCRIPT_BASE_ROOT;
	return base + "/" + script_name;
}

class DaoCardServiceImpl final : public DaoCardService::Service
{
	Status Init(ServerContext *context, const CardConfig *config, CardResponse *response) override
	{
		struct dao_card_config cfg;
		(void)(context);
		int rc;

		cfg.argc = config->argc();
		cfg.argv = new char *[cfg.argc];
		for (unsigned int i = 0; i < cfg.argc; i++) {
			cfg.argv[i] = new char[config->argv(i).length() + 1];
			std::strcpy(cfg.argv[i], config->argv(i).c_str());
		}
		cfg.crypto_nb_desc = config->crypto_nb_desc();

		rc = server_cbs->init_cb(&cfg);
		if (rc) {
			response->set_err(rc);
			StatusCode code = StatusCode::INTERNAL;
			if (rc == -EINVAL)
				code = StatusCode::INVALID_ARGUMENT;
			else if (rc == -EAGAIN)
				code = StatusCode::UNAVAILABLE;
			else if (rc == -ENOTSUP)
				code = StatusCode::UNIMPLEMENTED;
			return Status(code, "Failed to initialize card");
		}
		response->set_err(0);

		return Status::OK;
	}

	Status Fini(ServerContext *context, const Emp *empty, Emp *resp) override
	{
		(void)(context);
		(void)(empty);
		(void)(resp);

		server_cbs->fini_cb();

		return Status::OK;
	}

	Status Info(ServerContext *context, const Emp *empty, CardInfo *response) override
	{
		struct dao_card_info info;
		int status, exit_code;
		(void)(context);
		(void)(empty);

		auto boot_source_to_string = [](dao_card_manager::BootSource s) -> const char * {
			switch (s) {
			case dao_card_manager::BOOT_SOURCE_MMC:
				return "MMC";
			case dao_card_manager::BOOT_SOURCE_SPI:
				return "SPI";
			case dao_card_manager::BOOT_SOURCE_SCRIPT_FAILURE:
			default:
				return "SCRIPT_FAILURE";
			}
		};

		server_cbs->card_info_cb(&info);

		response->set_version(DAO_CARD_VERSION);
		response->set_nb_devs(info.nb_devs);
		response->set_max_sessions(info.max_sessions);

		std::string command = std::string(". ") + script_full_path(BOOT_SRC_GET_SCRIPT, false);
		status = system(command.c_str());
		if (status == -1 || !WIFEXITED(status)) {
			std::cerr << "Failed to execute get boot source script" << std::endl;
			response->set_boot_source(dao_card_manager::BOOT_SOURCE_SCRIPT_FAILURE);
		} else {
			exit_code = WEXITSTATUS(status);
			if (exit_code == 11) {
				response->set_boot_source(dao_card_manager::BOOT_SOURCE_MMC);
			} else if (exit_code == 12) {
				response->set_boot_source(dao_card_manager::BOOT_SOURCE_SPI);
			} else if (exit_code == 2) {
				std::cerr << "Script failed. Unable to determine boot source" << std::endl;
				response->set_boot_source(dao_card_manager::BOOT_SOURCE_SCRIPT_FAILURE);
			}
		}

		std::cout << "Card Info: version: " << response->version()
			  << ", nb_devs: " << response->nb_devs()
			  << ", max_sessions: " << response->max_sessions()
			  << ", boot source: " << boot_source_to_string(response->boot_source())
			  << std::endl;

		return Status::OK;
	}

	Status Stats(ServerContext *context, const Emp *empty, CardStats *response) override
	{
		struct dao_card_stats stats;
		(void)(context);
		(void)(empty);

		server_cbs->card_stats_cb(&stats);
		for (int i = 0; i < CA_MAX_WORKER_CORES; ++i) {
			response->add_rx_packets(stats.rx_packets[i]);
			response->add_tx_packets(stats.tx_packets[i]);
		}

		return Status::OK;
	}

	Status Sensors(ServerContext *context, const Emp *empty, CardSensors *response) override
	{
		std::string out;
		char buf[256];
		(void)context;
		(void)empty;

		FILE *fp = popen("sensors", "r");
		if (!fp)
			return Status(StatusCode::INTERNAL, "Failed to execute sensors");

		while (fgets(buf, sizeof(buf), fp)) {
			out.append(buf);
			if (out.size() > 16384) { /* arbitrary safety cap */
				out.append("\n[truncated]\n");
				break;
			}
		}
		pclose(fp);

		response->set_output(out);
		return Status::OK;
	}

	Status AppFallback(ServerContext *context, const Emp *empty, CardResponse *response) override
	{
		(void)(context);
		(void)(empty);

		std::string command = std::string(". ") + script_full_path(APP_FALLBACK_SCRIPT, false);
		if (system(command.c_str()) != 0) {
			std::cerr << "AppFallback: Script failed" << std::endl;
			return Status(StatusCode::FAILED_PRECONDITION, "Fallback script failed");
		}
		response->set_err(0);
		return Status::OK;
	}

	Status FileUpdate(ServerContext *context, const FileUpdateReq *req, CardResponse *response) override
	{
		(void)(context);
		std::string base_dir;
		static bool is_mounted = false;

		switch (req->transfer_type()) {
		case FileTransferType::APP_UPDATE:
			if (!is_mmc_boot()) {
				std::cerr << "APP_UPDATE denied: not booted from Main image" << std::endl;
				return Status(StatusCode::PERMISSION_DENIED, "APP_UPDATE requires MMC boot");
			}
			base_dir = APP_BASE_DIR;
			break;
		case FileTransferType::FW_UPDATE:
			if (is_mmc_boot()) {
				std::cerr << "FW_UPDATE denied: not booted from Failsafe" << std::endl;
				return Status(StatusCode::PERMISSION_DENIED, "FW_UPDATE requires failsafe boot");
			}
			base_dir = FW_BASE_DIR;
			if (!is_mounted) {
				std::string command = std::string(". ") + script_full_path(FW_MOUNT_SCRIPT, false);
				if (system(command.c_str()) != 0) {
					std::cerr << "Failed to mount" << std::endl;
					return Status(StatusCode::FAILED_PRECONDITION, "Mount failed");
				}
				is_mounted = true;
			}
			break;
		case FileTransferType::FAILSAFE_UPDATE:
			if (!is_mmc_boot()) {
				std::cerr << "FAILSAFE_UPDATE denied: not booted from Main image" << std::endl;
				return Status(StatusCode::PERMISSION_DENIED, "FAILSAFE_UPDATE requires MMC boot");
			}
			base_dir = APP_BASE_DIR;
			break;
		case FileTransferType::MCU_UPDATE:
			if (!is_mmc_boot()) {
				std::cerr << "MCU_UPDATE denied: not booted from Main image" << std::endl;
				return Status(StatusCode::PERMISSION_DENIED, "MCU_UPDATE requires MMC boot");
			}
			base_dir = APP_BASE_DIR;
			break;
		default:
			return Status(StatusCode::INVALID_ARGUMENT, "Unknown transfer type");
		}

		std::string file_full_path = base_dir + '/' + req->file_name();
		static std::unordered_map<std::string, std::ofstream> file_map;
		auto it = file_map.find(file_full_path);
		if (it == file_map.end()) {
			std::ofstream output_file(file_full_path, std::ios::binary | std::ios::app);
			if (!output_file.is_open()) {
				std::cerr << "Failed to open the file" << std::endl;
				response->set_err(errno ? -errno : 1);
				StatusCode sc = (errno == EACCES || errno == EPERM) ? StatusCode::PERMISSION_DENIED : StatusCode::INTERNAL;
				return Status(sc, "Failed to open file");
			}
			file_map[file_full_path] = std::move(output_file);
		}

		std::ofstream& output_file = file_map[file_full_path];
		output_file.write(req->file_content().data(), req->file_content().size());
		if (output_file.fail()) {
			std::cerr << "Failed to write to file" << std::endl;
			response->set_err(errno ? -errno : 1);
			StatusCode sc = (errno == ENOSPC) ? StatusCode::RESOURCE_EXHAUSTED : StatusCode::INTERNAL;
			return Status(sc, "Failed to write file");
		}

		if (req->is_last_chunk()) {
			std::cerr << "last chunk received" << std::endl;
			output_file.close();
			file_map.erase(file_full_path);

			std::string file_name = req->file_name();
			for (char c : file_name) {
				if (!std::isalnum(static_cast<unsigned char>(c)) && c != '.' && c != '-' && c != '_') {
					std::cerr << "Invalid character in filename" << std::endl;
					response->set_err(-EINVAL);
					return Status(StatusCode::INVALID_ARGUMENT, "Invalid character in filename");
				}
			}

			std::string command;
			if (req->transfer_type() == FileTransferType::APP_UPDATE) {
				command = std::string(". ") + script_full_path(APP_UPDATE_SCRIPT, true) + " " + file_name;
			} else if (req->transfer_type() == FileTransferType::FW_UPDATE) {
				command = std::string(". ") + script_full_path(FW_UPDATE_SCRIPT, false) + " " + file_name;
				is_mounted = false;
			} else if (req->transfer_type() == FileTransferType::FAILSAFE_UPDATE) {
				std::string checksum = req->checksum();
				command = std::string(". ") + script_full_path(FAILSAFE_UPDATE_SCRIPT, true) + " " + file_name + " " + checksum;
			} else if (req->transfer_type() == FileTransferType::MCU_UPDATE) {
				command = std::string(". ") + script_full_path(MCU_UPDATE_SCRIPT, true) + " " + file_name;
			}
			if (system(command.c_str()) != 0) {
				std::cerr << "Failed to execute update script" << std::endl;
				std::remove(file_full_path.c_str());
				return Status(StatusCode::ABORTED, "Update script failed");
			}
		}
		return Status::OK;
	}

	Status Dmesg(ServerContext *context, const Emp *empty, DmesgLogs *response) override
	{
		( void)(context); (void)(empty);
		/* Capture dmesg (recent portion). Limit to 64KB to avoid huge responses */
		FILE *fp = popen("dmesg | tail -n 512", "r");
		if (!fp) {
			return Status(StatusCode::INTERNAL, "Failed to run dmesg");
		}
		std::string out;
		char line[512];
		while (fgets(line, sizeof(line), fp)) {
			if (out.size() + strlen(line) > 65535) {
				/* Truncate */
				break;
			}
			out += line;
		}
		pclose(fp);
		response->set_text(out);
		return Status::OK;
	}

	Status AppLog(ServerContext *context, const Emp *empty, AppLogs *response) override
	{
		(void)context; (void)empty;
		/* Tail application log file. Limit to 64KB. */
		const char *log_path = "/mnt/log/crypto_agent.log";
		FILE *fp = fopen(log_path, "r");
		if (!fp) {
			/* If missing, return empty (not an INTERNAL error) */
			response->set_text("");
			return Status::OK;
		}
		/* Seek to last ~64KB to avoid reading huge files */
		if (fseek(fp, 0, SEEK_END) == 0) {
			long sz = ftell(fp);
			long back = 65536; /* 64KB */
			if (sz > back)
				fseek(fp, -back, SEEK_END);
			else
				fseek(fp, 0, SEEK_SET);
		}
		std::string out;
		char buf[512];
		while (fgets(buf, sizeof(buf), fp)) {
			if (out.size() + strlen(buf) > 65535) {
				break; /* truncate */
			}
			out += buf;
		}
		fclose(fp);
		response->set_text(out);
		return Status::OK;
	}
};

class DaoLCServiceImpl final : public DaoLCService::Service
{
	Status CreateDev(ServerContext *context, const DeviceId *request, Response *response) override
	{
		(void)(context);
		(void)response; // unused
		int rc;

		rc = server_cbs->dev_create_cb(request->dev_id(), request->nb_queues());

		return status_from_rc(rc, "Failed to create device");
	}

	Status DestroyDev(ServerContext *context, const DeviceId *request, Response *response) override
	{
		(void)(context);
		(void)response; // unused
		int rc;

		rc = server_cbs->dev_destroy_cb(request->dev_id());

		return status_from_rc(rc, "Failed to destroy device");
	}

	Status StartDev(ServerContext *context, const DeviceId *request, Response *response) override
	{
		(void)(context);
		(void)response; // unused
		int rc;

		rc = server_cbs->dev_start_cb(request->dev_id());

		return status_from_rc(rc, "Failed to start device");
	}

	Status StopDev(ServerContext *context, const DeviceId *request, Response *response) override
	{
		(void)(context);
		(void)response; // unused
		int rc;

		rc = server_cbs->dev_stop_cb(request->dev_id());

		return status_from_rc(rc, "Failed to stop device");
	}

	Status ConfigureQP(ServerContext *context, const QpConf *q_conf, Response *response) override
	{
		struct dao_lc_eth_qconf conf;
		(void)(context);
		(void)response; // unused
		int rc;

		conf.dev_id = q_conf->dev_id();
		conf.qp_id = q_conf->qp_id();
		conf.out_of_order_delivery_en = q_conf->out_of_order_delivery_en();
		conf.nb_desc = q_conf->nb_desc();
		conf.max_seg_size = q_conf->max_seg_size();

		rc = server_cbs->q_configure_cb(&conf);

		return status_from_rc(rc, "Failed to configure QP");
	}

	Status DestroyQP(ServerContext *context, const QueuePairId *request, Response *response) override
	{
		(void)(context);
		(void)response; // unused
		int rc;

		rc = server_cbs->q_destroy_cb(request->dev_id(), request->qp_id());

		return status_from_rc(rc, "Failed to destroy QP");
	}
};

static std::unique_ptr<DaoCardServiceImpl> card_service;
static std::unique_ptr<DaoLCServiceImpl> lc_service;
static std::unique_ptr<Server> server;

int
dao_card_register_server_cbs(struct dao_card_server_cbs *cbs)
{
	if (cbs == NULL)
		return -EINVAL;

	server_cbs = cbs;
	std::cout << "Registered server callbacks" << std::endl;
	return 0;
}

bool
validate_ip_address(const std::string &ip) {
	struct in_addr inaddr;
	return inet_pton(AF_INET, ip.c_str(), &inaddr) != 0;
}

int
dao_card_grpc_server_run(void)
{
	char *ip_env = getenv(LC_IP_ADDRESS_ENV_VAR);
	std::string server_ip;
	if (ip_env == NULL) {
		fprintf(stderr, "Environment variable %s is not set, continue with default: %s\n",
			LC_IP_ADDRESS_ENV_VAR, LC_DEFAULT_IP_ADDRESS);
		server_ip = LC_DEFAULT_IP_ADDRESS;
	} else {
		server_ip = std::string(ip_env);
		if (server_ip.empty() || !validate_ip_address(server_ip)) {
			fprintf(stderr, "Env: %s is not a valid IPv4 address, continue with default: %s\n",
				LC_IP_ADDRESS_ENV_VAR, LC_DEFAULT_IP_ADDRESS);
			server_ip = LC_DEFAULT_IP_ADDRESS;
		}
	}

	std::string server_address = absl::StrFormat("%s:%d", server_ip, LC_DEFAULT_PORT);

	card_service = std::make_unique<DaoCardServiceImpl>();
	lc_service = std::make_unique<DaoLCServiceImpl>();
	int selected_port = -1;

	ServerBuilder builder;
	builder.AddListeningPort(server_address, grpc::InsecureServerCredentials(), &selected_port);
	builder.RegisterService(card_service.get());
	builder.RegisterService(lc_service.get());
	server = builder.BuildAndStart();
	if (!server) {
		fprintf(stderr, "Failed to start gRPC server\n");
		return -ENXIO;
	}
	std::cout << "Server listening on " << server_address << std::endl;
	std::cout << "Selected port: " << selected_port << std::endl;

	/* Invoke MCU all-clear signal script before entering wait */
	{
		std::string base = is_mmc_boot() ? LC_SCRIPT_BASE_MMC : LC_SCRIPT_BASE_ROOT;
		std::string full = base + "/" + MCU_ALL_CLEAR_SCRIPT;
		struct stat st;
		if (stat(full.c_str(), &st) == 0 && (st.st_mode & S_IXUSR)) {
			int rc = system(full.c_str());
			if (rc != 0)
				std::cerr << "Warning: script " << full << " exited with code " << rc << std::endl;
		} else {
			std::cerr << "Info: script " << full << " not found or not executable" << std::endl;
		}
	}

	server->Wait();

	return 0;
}

void
dao_card_grpc_server_stop(void)
{
	if (server)
		server->Shutdown();
}
