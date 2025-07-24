/* SPDX-License-Identifier: Marvell-MIT
 * Copyright(C) 2025 Marvell.
 */

#include <stdio.h>
#include <fstream>

#include <grpcpp/grpcpp.h>
#include <grpcpp/channel.h>
#include <grpcpp/client_context.h>
#include <grpcpp/create_channel.h>
#include <grpcpp/security/credentials.h>
#include <openssl/evp.h>

#include "dao_card_grpc_client.h"
#include "dao_card.grpc.pb.h"

using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;

using dao_card_manager::DaoCardService;
using dao_card_manager::CardConfig;
using dao_card_manager::CardInfo;
using dao_card_manager::CardResponse;
using dao_card_manager::Emp;
using dao_card_manager::UpdateReq;
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
		fprintf(stderr, "Failed to get card info: %s\n", status.error_message().c_str());
		return -1;
	}

	strncpy(info->version, resp.version().c_str(), sizeof(info->version) - 1);
	info->version[sizeof(info->version) - 1] = '\0';
	info->nb_devs = resp.nb_devs();
	info->max_sessions = resp.max_sessions();

	return 0;
}

int
dao_card_app_update(struct dao_card_grpc_ctx *ctx, struct dao_card_app_update_req *update_req)
{

	if (update_req->filename == NULL || update_req->filepath == NULL || ctx == NULL)
		return -EINVAL;

	std::string full_path = std::string(update_req->filepath) + "/" + std::string(update_req->filename);
	std::ifstream file(full_path, std::ios::binary);
	if (!file.is_open()) {
		fprintf(stderr, "Failed to open file: %s\n", update_req->filename);
		return -ENOENT;
	}

	const size_t chunk_size = 3 * 1024 * 1024;
	std::vector<char> buffer(chunk_size);

	while (file.read(buffer.data(), buffer.size()) || file.gcount() > 0) {
		grpc::ClientContext context;
		grpc::Status status;
		UpdateReq req;
		CardResponse resp;

		req.set_file_name(update_req->filename);
		req.set_file_content(buffer.data(), file.gcount());
		req.set_is_last_chunk(file.eof());

		status = ctx->stub->AppUpdate(&context, req, &resp);
		if (!status.ok()) {
			fprintf(stderr, "Failed to upload chunk: %s\n", status.error_message().c_str());
			file.close();
			return -EIO;
		}
	}

	file.close();
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
dao_card_fw_update(struct dao_card_grpc_ctx *ctx, struct dao_card_fw_update_req *update_req)
{
	if (update_req->filename == NULL || update_req->filepath == NULL || ctx == NULL)
		return -EINVAL;

	std::string full_path = std::string(update_req->filepath) + "/" + std::string(update_req->filename);
	std::ifstream file(full_path, std::ios::binary);
	if (!file.is_open()) {
		fprintf(stderr, "Failed to open file: %s\n", update_req->filename);
		return -ENOENT;
	}

	const size_t chunk_size = 3 * 1024 * 1024;
	std::vector<char> buffer(chunk_size);

	while (file.read(buffer.data(), buffer.size()) || file.gcount() > 0) {
		grpc::ClientContext context;
		grpc::Status status;
		UpdateReq req;
		CardResponse resp;

		req.set_file_name(update_req->filename);
		req.set_file_content(buffer.data(), file.gcount());
		req.set_is_last_chunk(file.eof());

		status = ctx->stub->FwUpdate(&context, req, &resp);
		if (!status.ok()) {
			fprintf(stderr, "Failed to upload chunk: %s\n", status.error_message().c_str());
			file.close();
			return -EIO;
		}
	}

	file.close();
	return 0;
}

int
dao_card_failsafe_update(struct dao_card_grpc_ctx *ctx, struct dao_card_failsafe_update_req *update_req)
{
	const size_t chunk_size = 3 * 1024 * 1024;
	unsigned int hash_len = 0;
	unsigned char hash[32];

	if (update_req->filename == NULL || update_req->filepath == NULL || ctx == NULL)
		return -EINVAL;

	std::string full_path = std::string(update_req->filepath) + "/" +
				std::string(update_req->filename);
	std::ifstream file(full_path, std::ios::binary);
	if (!file.is_open()) {
		fprintf(stderr, "Failed to open file: %s\n", update_req->filename);
		return -ENOENT;
	}

	file.seekg(0, std::ios::end);
	std::streamsize file_size = file.tellg();
	file.seekg(0, std::ios::beg);
	std::vector<char> file_data(file_size);
	if (!file.read(file_data.data(), file_size)) {
		fprintf(stderr, "Failed to read file for checksum: %s\n", update_req->filename);
		file.close();
		return -EIO;
	}
	file.clear();
	file.seekg(0, std::ios::beg);

	EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
	if (mdctx == NULL) {
		file.close();
		return -ENOMEM;
	}

	if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1) {
		EVP_MD_CTX_free(mdctx);
		file.close();
		return -EIO;
	}

	std::vector<char> buffer(chunk_size);
	while (file.read(buffer.data(), buffer.size()) || file.gcount() > 0) {
		if (EVP_DigestUpdate(mdctx, buffer.data(), file.gcount()) != 1) {
			EVP_MD_CTX_free(mdctx);
			file.close();
			return -EIO;
		}
	}

	if (EVP_DigestFinal_ex(mdctx, hash, &hash_len) != 1) {
		EVP_MD_CTX_free(mdctx);
		file.close();
		return -EIO;
	}

	EVP_MD_CTX_free(mdctx);
	file.clear();
	file.seekg(0, std::ios::beg);

	std::string checksum_str;
	checksum_str.reserve(64);
	for (int i = 0; i < 32; ++i) {
		char hex[3];
		snprintf(hex, sizeof(hex), "%02x", hash[i]);
		checksum_str.append(hex);
	}

	while (file.read(buffer.data(), buffer.size()) || file.gcount() > 0) {
		grpc::ClientContext context;
		grpc::Status status;
		UpdateReq req;
		CardResponse resp;

		req.set_file_name(update_req->filename);
		req.set_file_content(buffer.data(), file.gcount());
		req.set_is_last_chunk(file.eof());
		req.set_checksum(checksum_str);

		status = ctx->stub->FailsafeUpdate(&context, req, &resp);
		if (!status.ok()) {
			fprintf(stderr, "Failed to upload failsafe chunk: %s\n",
				status.error_message().c_str());
			file.close();
			return -EIO;
		}
	}

	file.close();
	return 0;
}

