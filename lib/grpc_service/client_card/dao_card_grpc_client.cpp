/* SPDX-License-Identifier: Marvell-MIT
 * Copyright(C) 2025 Marvell.
 */

#include <stdio.h>
#include <fstream>
#include <string>
#include <vector>

#include <grpcpp/grpcpp.h>
#include <grpcpp/channel.h>
#include <grpcpp/client_context.h>
#include <grpcpp/create_channel.h>
#include <grpcpp/security/credentials.h>
#include <openssl/evp.h>

#include "dao_card_grpc_client.h"
#include "dao_card.grpc.pb.h"

/* Set max chunk size as 3MB for file transfer */
#define MAX_CHUNK_SIZE 3 * 1024 * 1024

using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;

using dao_card_manager::DaoCardService;
using dao_card_manager::CardConfig;
using dao_card_manager::CardInfo;
using dao_card_manager::CardResponse;
using dao_card_manager::Emp;
using dao_card_manager::FileUpdateReq;
using dao_card_manager::FileTransferType;
using dao_card_manager::BootSource;
using dao_card_manager::CardStats;

struct dao_card_grpc_ctx {
	std::unique_ptr<DaoCardService::Stub> stub;
};

struct dao_card_grpc_ctx *
dao_card_grpc_client_init(const char *server_ip, uint16_t server_port)
{
	auto ctx = new dao_card_grpc_ctx();
	std::string server_addr = server_ip;

	server_addr += ":";
	server_addr += std::to_string(server_port);

	auto channel = grpc::CreateChannel(server_addr, grpc::InsecureChannelCredentials());

	ctx->stub = DaoCardService::NewStub(channel);

	return ctx;
}

void
dao_card_grpc_client_fini(struct dao_card_grpc_ctx *ctx)
{
	delete ctx;
}

int
dao_card_init(struct dao_card_grpc_ctx *ctx, struct dao_card_config *cfg)
{
	ClientContext context;
	grpc::Status status;
	CardConfig config;
	CardResponse resp;

	if (cfg == NULL || ctx == NULL)
		return -EINVAL;

	config.set_argc(cfg->argc);
	for (unsigned int i = 0; i < cfg->argc; ++i)
		config.add_argv(cfg->argv[i]);

	config.set_crypto_nb_desc(cfg->crypto_nb_desc);

	status = ctx->stub->Init(&context, config, &resp);
	if (!status.ok()) {
		if (status.error_code() == grpc::StatusCode::UNAVAILABLE) {
			fprintf(stderr, "Card is not ready yet\n");
			return -EAGAIN;
		}

		fprintf(stderr, "Failed to initialize card: %s\n", status.error_message().c_str());
		return resp.err();
	}

	return 0;
}

void
dao_card_fini(struct dao_card_grpc_ctx *ctx)
{
	ClientContext context;
	Emp empty;

	ctx->stub->Fini(&context, empty, &empty);
}

int
dao_card_info_get(struct dao_card_grpc_ctx *ctx, struct dao_card_info *info)
{
	ClientContext context;
	grpc::Status status;
	CardInfo resp;
	Emp empty;

	if (ctx == NULL || info == NULL)
		return -EINVAL;

	status = ctx->stub->Info(&context, empty, &resp);
	if (!status.ok()) {
		if (status.error_code() == grpc::StatusCode::UNAVAILABLE) {
			fprintf(stderr, "Card is not ready yet\n");
			return -EAGAIN;
		}

		fprintf(stderr, "Failed to get card info: %s\n", status.error_message().c_str());
		return -1;
	}

	strncpy(info->version, resp.version().c_str(), sizeof(info->version) - 1);
	info->version[sizeof(info->version) - 1] = '\0';
	info->nb_devs = resp.nb_devs();
	info->max_sessions = resp.max_sessions();

	switch (resp.boot_source()) {
	case BootSource::BOOT_SOURCE_SPI:
		info->boot_source = DAO_CARD_BOOT_SOURCE_SPI;
		break;
	case BootSource::BOOT_SOURCE_MMC:
		info->boot_source = DAO_CARD_BOOT_SOURCE_MMC;
		break;
	case BootSource::BOOT_SOURCE_UNKNOWN:
	default:
		info->boot_source = DAO_CARD_BOOT_SOURCE_UNKNOWN;
	}

	return 0;
}

int
dao_card_app_fallback(struct dao_card_grpc_ctx *ctx)
{
	if (ctx == NULL)
		return -EINVAL;

	grpc::ClientContext context;
	Emp empty;
	CardResponse resp;
	grpc::Status status = ctx->stub->AppFallback(&context, empty, &resp);
	if (!status.ok()) {
		fprintf(stderr, "Failed to perform app fallback: %s\n", status.error_message().c_str());
		return resp.err();
	}
	return 0;
}

int
dao_card_stats_get(struct dao_card_grpc_ctx *ctx, struct dao_card_stats *stats)
{
	ClientContext context;
	grpc::Status status;
	CardStats resp;
	Emp empty;

	if (ctx == NULL || stats == NULL)
		return -EINVAL;

	status = ctx->stub->Stats(&context, empty, &resp);
	if (!status.ok()) {
		fprintf(stderr, "Failed to get card stats: %s (code=%d)\n", status.error_message().c_str(), status.error_code());
		return -EIO;
	}

	for (int i = 0; i < CA_MAX_WORKER_CORES; ++i) {
		stats->rx_packets[i] = resp.rx_packets(i);
		stats->tx_packets[i] = resp.tx_packets(i);
	}
	return 0;
}

int
dao_card_file_update(struct dao_card_grpc_ctx *ctx, struct dao_card_update_req *update_req,
		     enum dao_card_update_type type)
{
	const size_t chunk_size = MAX_CHUNK_SIZE;
	const char *checksum = nullptr;

	if (update_req->filename == NULL || update_req->filepath == NULL || ctx == NULL)
		return -EINVAL;

	std::string full_path = std::string(update_req->filepath) + "/" + std::string(update_req->filename);
	std::ifstream file(full_path, std::ios::binary);
	if (!file.is_open()) {
		fprintf(stderr, "Failed to open file: %s\n", update_req->filename);
		return -ENOENT;
	}

	FileTransferType proto_type = FileTransferType::APP_UPDATE;
	std::vector<char> buffer(chunk_size);

	switch (type) {
	case DAO_CARD_APP_UPDATE:
		proto_type = FileTransferType::APP_UPDATE;
		break;
	case DAO_CARD_FW_UPDATE:
		proto_type = FileTransferType::FW_UPDATE;
		break;
	case DAO_CARD_FAILSAFE_UPDATE:
		proto_type = FileTransferType::FAILSAFE_UPDATE;
		break;
	default:
		file.close();
		return -EINVAL;
	}

	while (file.read(buffer.data(), buffer.size()) || file.gcount() > 0) {
		grpc::ClientContext context;
		grpc::Status status;
		FileUpdateReq req;
		CardResponse resp;

		req.set_file_name(update_req->filename);
		req.set_file_content(buffer.data(), file.gcount());
		req.set_is_last_chunk(file.eof());
		req.set_transfer_type(proto_type);
		if (type == DAO_CARD_FAILSAFE_UPDATE && checksum)
			req.set_checksum(checksum);

		status = ctx->stub->FileUpdate(&context, req, &resp);
		if (!status.ok()) {
			fprintf(stderr, "Failed to upload chunk: %s\n",
				status.error_message().c_str());
			file.close();
			return -EIO;
		}
	}

	file.close();
	return 0;
}

