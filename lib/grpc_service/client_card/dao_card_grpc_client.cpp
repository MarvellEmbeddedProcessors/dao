/* SPDX-License-Identifier: Marvell-MIT
 * Copyright(C) 2025 Marvell.
 */

#include <chrono>
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
#include <errno.h>

#include "dao_card_grpc_client.h"
#include "dao_card.grpc.pb.h"

/* Set max chunk size as 3MB for file transfer */
#define MAX_CHUNK_SIZE 3 * 1024 * 1024
/* gRPC timeout in milliseconds */
#define GRPC_TIMEOUT_MS 5000

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
using dao_card_manager::DmesgLogs;
using dao_card_manager::CardSensors;
using dao_card_manager::AppLogs;
using dao_card_manager::ImageVersionInfo;

/* Helper function to set gRPC context timeout */
static void set_context_timeout(ClientContext *context, int timeout_ms)
{
	std::chrono::system_clock::time_point deadline =
		std::chrono::system_clock::now() + std::chrono::milliseconds(timeout_ms);
		context->set_deadline(deadline);
}

static int grpc_status_to_errno(const grpc::Status &status)
{
	switch (status.error_code()) {
	case grpc::StatusCode::UNIMPLEMENTED:
		return -ENOTSUP;
	case grpc::StatusCode::UNAVAILABLE:
		return -EAGAIN;
	case grpc::StatusCode::DEADLINE_EXCEEDED:
		return -ETIMEDOUT;
	case grpc::StatusCode::PERMISSION_DENIED:
		return -EACCES;
	case grpc::StatusCode::INVALID_ARGUMENT:
		return -EINVAL;
	case grpc::StatusCode::NOT_FOUND:
		return -ENOENT;
	case grpc::StatusCode::ALREADY_EXISTS:
		return -EALREADY;
	case grpc::StatusCode::RESOURCE_EXHAUSTED:
		return -ENOSPC;
	case grpc::StatusCode::FAILED_PRECONDITION:
		return -EIO;
	case grpc::StatusCode::ABORTED:
		return -EFAULT;
	case grpc::StatusCode::OUT_OF_RANGE:
		return -ERANGE;
	case grpc::StatusCode::UNAUTHENTICATED:
		return -EACCES;
	default:
		return -EIO;
	}
}

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
		if (status.error_code() == grpc::StatusCode::UNAVAILABLE)
			fprintf(stderr, "Card is not ready yet\n");
		fprintf(stderr, "Failed to initialize card: %s (code=%d)\n",
			status.error_message().c_str(), status.error_code());
		return grpc_status_to_errno(status);
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
dao_card_soft_reset(struct dao_card_grpc_ctx *ctx)
{
	ClientContext context;
	grpc::Status status;
	CardResponse resp;
	Emp empty;

	if (ctx == NULL)
		return -EINVAL;

	status = ctx->stub->SoftReset(&context, empty, &resp);
	if (!status.ok()) {
		if (status.error_code() == grpc::StatusCode::UNAVAILABLE)
			fprintf(stderr, "Card is not initialized yet\n");
		fprintf(stderr, "Failed to perform soft reset: %s (code=%d)\n",
			status.error_message().c_str(), status.error_code());
		return grpc_status_to_errno(status);
	}

	return 0;
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
		if (status.error_code() == grpc::StatusCode::UNAVAILABLE)
			fprintf(stderr, "Card is not ready yet\n");
		fprintf(stderr, "Failed to get card info: %s (code=%d)\n",
			status.error_message().c_str(), status.error_code());
		return grpc_status_to_errno(status);
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
	case BootSource::BOOT_SOURCE_SCRIPT_FAILURE:
		info->boot_source = DAO_CARD_BOOT_SOURCE_SCRIPT_FAILURE;
		break;
	case BootSource::BOOT_SOURCE_UNSUPPORTED:
	default:
		info->boot_source = DAO_CARD_BOOT_SOURCE_UNSUPPORTED;
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
		fprintf(stderr, "Failed to perform app fallback: %s (code=%d)\n",
			status.error_message().c_str(), status.error_code());
		return grpc_status_to_errno(status);
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
		fprintf(stderr, "Failed to get card stats: %s (code=%d)\n",
			status.error_message().c_str(), status.error_code());
		return grpc_status_to_errno(status);
	}

	for (int i = 0; i < CA_MAX_WORKER_CORES; ++i) {
		stats->rx_packets[i] = resp.rx_packets(i);
		stats->tx_packets[i] = resp.tx_packets(i);
	}
	return 0;
}

int
dao_card_dmesg_get(struct dao_card_grpc_ctx *ctx, char *buf, size_t len)
{
	ClientContext context;
	grpc::Status status;
	DmesgLogs resp;
	Emp empty;

	if (!ctx || !buf || len == 0)
		return -EINVAL;

	status = ctx->stub->Dmesg(&context, empty, &resp);
	if (!status.ok()) {
		fprintf(stderr, "Failed to get dmesg: %s (code=%d)\n",
			status.error_message().c_str(), status.error_code());
		return grpc_status_to_errno(status);
	}
	std::string text = resp.text();
	if (text.size() >= len) {
		/* Truncate */
		memcpy(buf, text.data(), len - 1);
		buf[len - 1] = '\0';
		return (int)(len - 1);
	}
	memcpy(buf, text.data(), text.size());
	buf[text.size()] = '\0';
	return (int)text.size();
}

int
dao_card_applogs_get(struct dao_card_grpc_ctx *ctx, char *buf, size_t len)
{
	ClientContext context;
	grpc::Status status;
	AppLogs resp;
	Emp empty;

	if (!ctx || !buf || len == 0)
		return -EINVAL;

	set_context_timeout(&context, GRPC_TIMEOUT_MS);
	status = ctx->stub->AppLog(&context, empty, &resp);
	if (!status.ok()) {
		fprintf(stderr, "Failed to get application logs: %s (code=%d)\n",
			status.error_message().c_str(), status.error_code());
		return grpc_status_to_errno(status);
	}
	std::string text = resp.text();
	if (text.size() >= len) {
		memcpy(buf, text.data(), len - 1);
		buf[len - 1] = '\0';
		return (int)(len - 1);
	}
	memcpy(buf, text.data(), text.size());
	buf[text.size()] = '\0';
	return (int)text.size();
}

int
dao_card_image_version_get(struct dao_card_grpc_ctx *ctx,
			   char *image_ver_buf, size_t image_ver_len,
			   char *app_ver_buf, size_t app_ver_len)
{
	ClientContext context;
	grpc::Status status;
	ImageVersionInfo resp;
	Emp empty;

	if (!ctx) {
		fprintf(stderr, "dao_card_image_version_get: ctx is NULL\n");
		return -EINVAL;
	}
	if (!image_ver_buf || image_ver_len == 0) {
		fprintf(stderr, "dao_card_image_version_get: Invalid image version buffer (buf=%p, len=%zu)\n",
			image_ver_buf, image_ver_len);
		return -EINVAL;
	}
	if (!app_ver_buf || app_ver_len == 0) {
		fprintf(stderr, "dao_card_image_version_get: Invalid app version buffer (buf=%p, len=%zu)\n",
			app_ver_buf, app_ver_len);
		return -EINVAL;
	}

	set_context_timeout(&context, GRPC_TIMEOUT_MS);
	status = ctx->stub->ImageVersion(&context, empty, &resp);
	if (!status.ok()) {
		/* Only print detailed errors for non-UNIMPLEMENTED cases */
		if (status.error_code() != grpc::StatusCode::UNIMPLEMENTED) {
			fprintf(stderr, "Failed to get image version: %s (code=%d)\n",
				status.error_message().c_str(), status.error_code());
		}
		return grpc_status_to_errno(status);
	}

	/* Copy main image version */
	std::string image_version = resp.version();
	if (image_version.size() >= image_ver_len) {
		memcpy(image_ver_buf, image_version.data(), image_ver_len - 1);
		image_ver_buf[image_ver_len - 1] = '\0';
	} else {
		memcpy(image_ver_buf, image_version.data(), image_version.size());
		image_ver_buf[image_version.size()] = '\0';
	}

	/* Copy app version */
	std::string app_version = resp.app_version();
	if (app_version.size() >= app_ver_len) {
		memcpy(app_ver_buf, app_version.data(), app_ver_len - 1);
		app_ver_buf[app_ver_len - 1] = '\0';
	} else {
		memcpy(app_ver_buf, app_version.data(), app_version.size());
		app_ver_buf[app_version.size()] = '\0';
	}

	return 0;
}

int
dao_card_sensors_get(struct dao_card_grpc_ctx *ctx, char *buf, size_t len)
{
	ClientContext context;
	grpc::Status status;
	CardSensors resp;
	Emp empty;

	if (ctx == NULL || buf == NULL || len == 0)
		return -EINVAL;

	status = ctx->stub->Sensors(&context, empty, &resp);
	if (!status.ok()) {
		fprintf(stderr, "Failed to get sensors output: %s (code=%d)\n",
			status.error_message().c_str(), status.error_code());
		return grpc_status_to_errno(status);
	}

	strncpy(buf, resp.output().c_str(), len - 1);
	buf[len - 1] = '\0';
	return 0;
}

int
dao_card_file_update(struct dao_card_grpc_ctx *ctx, struct dao_card_update_req *update_req,
		     enum dao_card_update_type type)
{
	const size_t chunk_size = MAX_CHUNK_SIZE;
	std::string checksum_str;

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
	case DAO_CARD_MCU_UPDATE:
		proto_type = FileTransferType::MCU_UPDATE;
		break;
	default:
		file.close();
		return -EINVAL;
	}

	if (type == DAO_CARD_FAILSAFE_UPDATE) {
		unsigned int hash_len = 0;
		unsigned char hash[32];

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

		checksum_str.reserve(64);
		for (int i = 0; i < 32; ++i) {
			char hex[3];
			snprintf(hex, sizeof(hex), "%02x", hash[i]);
			checksum_str.append(hex);
		}
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
		if (type == DAO_CARD_FAILSAFE_UPDATE)
			req.set_checksum(checksum_str);

		status = ctx->stub->FileUpdate(&context, req, &resp);
		if (!status.ok()) {
			fprintf(stderr, "Failed to upload chunk: %s (code=%d)\n",
				status.error_message().c_str(), status.error_code());
			file.close();
			return grpc_status_to_errno(status);
		}
	}

	file.close();
	return 0;
}

