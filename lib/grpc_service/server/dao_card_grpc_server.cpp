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

#include "dao_card_grpc_server.h"
#include <dao_card.grpc.pb.h>

#include <dao_lc.grpc.pb.h>

#define APP_BASE_DIR "/tmp"
#define FW_BASE_DIR "/mnt/new_root"
#define APP_UPDATE_SCRIPT "/mnt/app/lc_service/scripts/lc_app_update.sh"
#define APP_FALLBACK_SCRIPT "/root/lc_service/scripts/lc_app_fallback.sh"
#define FW_UPDATE_SCRIPT "/root/lc_service/scripts/lc_fw_update.sh"
#define FW_MOUNT_SCRIPT "/root/lc_service/scripts/lc_fw_mount.sh"
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
using dao_card_manager::UpdateReq;
using dao_card_manager::CardStats;
using dao_card_manager::Emp;

using lc_manager::DaoLCService;
using lc_manager::DevInfo;
using lc_manager::DeviceId;
using lc_manager::QueuePairId;
using lc_manager::QpConf;
using lc_manager::Response;
using lc_manager::Empty;

struct dao_card_server_cbs *server_cbs;

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
			return Status(StatusCode::INTERNAL, "Failed to initialize card");
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
		(void)(context);
		(void)(empty);

		server_cbs->card_info_cb(&info);

		response->set_version(DAO_CARD_VERSION);
		response->set_nb_devs(info.nb_devs);
		response->set_max_sessions(info.max_sessions);

		std::cout << "Card Info: version: " << response->version()
			  << ", nb_devs: " << response->nb_devs()
			  << ", max_sessions: " << response->max_sessions() << std::endl;

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


	Status AppUpdate(ServerContext *context, const UpdateReq *req, CardResponse *response)
	{
		(void)(context);

		std::string base_dir = APP_BASE_DIR;
		std::string file_full_path = base_dir + '/' + req->file_name();

		static std::unordered_map<std::string, std::ofstream> file_map;
		auto it = file_map.find(file_full_path);
		if (it == file_map.end()) {
			std::ofstream output_file(file_full_path, std::ios::binary | std::ios::app);
			if (!output_file.is_open()) {
				std::cerr << "Failed to open the file"<< std::endl;
				response->set_err(1);
				return grpc::Status::CANCELLED;
			}
			file_map[file_full_path] = std::move(output_file);
		}

		std::ofstream& output_file = file_map[file_full_path];
		output_file.write(req->file_content().data(), req->file_content().size());
		if (output_file.fail()) {
			std::cerr << "Failed to write to file" << std::endl;
			response->set_err(1);
			return grpc::Status::CANCELLED;
		}

		if (req->is_last_chunk()) {
			std::cerr << "last chunk received" << std::endl;
			output_file.close();
			file_map.erase(file_full_path);

			std::string file_name = req->file_name();
			for (char c : file_name) {
				if (!std::isalnum(c) && c != '.' && c != '-' && c != '_') {
					std::cerr << "Invalid character in filename" << std::endl;
					response->set_err(1);
					return grpc::Status::CANCELLED;
				}
			}

			std::string command = std::string(". ") + APP_UPDATE_SCRIPT + " " +
					      file_name;
			if (system(command.c_str()) != 0) {
				std::cerr << "Failed to execute lc_app_update.sh" << std::endl;
				std::remove(file_full_path.c_str());
				response->set_err(1);
				return grpc::Status::CANCELLED;
			}
		}

		return Status::OK;
	}

	Status AppFallback(ServerContext *context, const Emp *empty, CardResponse *response) override
	{
		(void)(context);
		(void)(empty);

		std::string command = std::string(". ") + APP_FALLBACK_SCRIPT;
		if (system(command.c_str()) != 0) {
			std::cerr << "AppFallback: Script failed" << std::endl;
			response->set_err(1);
			return Status(StatusCode::INTERNAL, "Script failed");
		}
		response->set_err(0);
		return Status::OK;
	}

	Status FwUpdate(ServerContext *context, const UpdateReq *req, CardResponse *response)
	{
		(void)(context);
		static bool is_mounted = false;
		if (is_mounted == false) {
			std::string command = std::string(". ")  + FW_MOUNT_SCRIPT;
			if (system(command.c_str()) != 0) {
				std::cerr << "Failed to mount"<< std::endl;
				response->set_err(1);
				return grpc::Status::CANCELLED;
			}
			is_mounted = true;
		}

		std::string base_dir = FW_BASE_DIR;
		std::string file_full_path = base_dir + '/' + req->file_name();

		static std::unordered_map<std::string, std::ofstream> file_map;
		auto it = file_map.find(file_full_path);
		if (it == file_map.end()) {
			std::ofstream output_file(file_full_path, std::ios::binary | std::ios::app);
			if (!output_file.is_open()) {
				std::cerr << "Failed to open the file"<< std::endl;
				response->set_err(1);
				return grpc::Status::CANCELLED;
			}
			file_map[file_full_path] = std::move(output_file);
		}

		std::ofstream& output_file = file_map[file_full_path];
		output_file.write(req->file_content().data(), req->file_content().size());
		if (output_file.fail()) {
			std::cerr << "Failed to write to file" << std::endl;
			response->set_err(1);
			return grpc::Status::CANCELLED;
		}

		if (req->is_last_chunk()) {
			std::cerr << "last chunk received" << std::endl;
			output_file.close();
			file_map.erase(file_full_path);

			std::string file_name = req->file_name();
			for (char c : file_name) {
				if (!std::isalnum(c) && c != '.' && c != '-' && c != '_') {
					std::cerr << "Invalid character in filename" << std::endl;
					response->set_err(1);
					return grpc::Status::CANCELLED;
				}
			}

			std::string command = std::string(". ") + FW_UPDATE_SCRIPT + " " +
					      file_name;
			if (system(command.c_str()) != 0) {
				std::cerr << "Failed to update firmware" << std::endl;
				std::remove(file_full_path.c_str());
				response->set_err(1);
				return grpc::Status::CANCELLED;
			}

			is_mounted = false;
		}
		return Status::OK;
	}
};

class DaoLCServiceImpl final : public DaoLCService::Service
{
	Status GetDevInfo(ServerContext *context, const DeviceId *request, DevInfo *dev_info) override
	{
		struct dao_lc_eth_info info;
		(void)(context);

		server_cbs->dev_info_cb(request->dev_id(), &info);
		dev_info->set_nb_queues(info.nb_queues);

		std::cout << "Device " << request->dev_id() << ": nb_queues: " << dev_info->nb_queues() << std::endl;

		return Status::OK;
	}

	Status CreateDev(ServerContext *context, const DeviceId *request, Response *response) override
	{
		(void)(context);
		int rc;

		rc = server_cbs->dev_create_cb(request->dev_id(), request->nb_queues());
		if (rc) {
			response->set_err(rc);
			return Status(StatusCode::INTERNAL, "Failed to create device");
		}
		response->set_err(0);

		return Status::OK;
	}

	Status DestroyDev(ServerContext *context, const DeviceId *request, Response *response) override
	{
		(void)(context);
		int rc;

		rc = server_cbs->dev_destroy_cb(request->dev_id());
		if (rc) {
			response->set_err(rc);
			return Status(StatusCode::INTERNAL, "Failed to destroy device");
		}
		response->set_err(0);

		return Status::OK;
	}

	Status StartDev(ServerContext *context, const DeviceId *request, Response *response) override
	{
		(void)(context);
		int rc;

		rc = server_cbs->dev_start_cb(request->dev_id());
		if (rc) {
			response->set_err(rc);
			return Status(StatusCode::INTERNAL, "Failed to start device");
		}
		response->set_err(0);

		return Status::OK;
	}

	Status StopDev(ServerContext *context, const DeviceId *request, Response *response) override
	{
		(void)(context);
		int rc;

		rc = server_cbs->dev_stop_cb(request->dev_id());
		if (rc) {
			response->set_err(rc);
			return Status(StatusCode::INTERNAL, "Failed to stop device");
		}
		response->set_err(0);

		return Status::OK;
	}

	Status ConfigureQP(ServerContext *context, const QpConf *q_conf, Response *response) override
	{
		struct dao_lc_eth_qconf conf;
		(void)(context);
		int rc;

		conf.dev_id = q_conf->dev_id();
		conf.qp_id = q_conf->qp_id();
		conf.out_of_order_delivery_en = q_conf->out_of_order_delivery_en();
		conf.nb_desc = q_conf->nb_desc();
		conf.max_seg_size = q_conf->max_seg_size();

		rc = server_cbs->q_configure_cb(&conf);
		if (rc) {
			response->set_err(rc);
			return Status(StatusCode::INTERNAL, "Failed to configure QP");
		}
		response->set_err(0);

		return Status::OK;
	}

	Status DestroyQP(ServerContext *context, const QueuePairId *request, Response *response) override
	{
		(void)(context);
		int rc;

		rc = server_cbs->q_destroy_cb(request->dev_id(), request->qp_id());
		if (rc) {
			response->set_err(rc);
			return Status(StatusCode::INTERNAL, "Failed to destroy QP");
		}
		response->set_err(0);

		return Status::OK;
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

	server->Wait();

	return 0;
}

void
dao_card_grpc_server_stop(void)
{
	if (server)
		server->Shutdown();
}
