/* SPDX-License-Identifier: Marvell-MIT
 * Copyright(C) 2025 Marvell.
 */

#include <stdio.h>

#include <grpcpp/grpcpp.h>
#include <grpcpp/channel.h>
#include <grpcpp/client_context.h>
#include <grpcpp/create_channel.h>
#include <grpcpp/security/credentials.h>

#include "dao_lc_grpc_client.h"
#include "dao_lc.grpc.pb.h"

using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;

using lc_manager::DaoLCService;
using lc_manager::DeviceId;
using lc_manager::QueuePairId;
using lc_manager::Response;
using lc_manager::QpConf;
using lc_manager::Empty;

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
		return -EEXIST;
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

struct dao_lc_grpc_ctx {
	std::unique_ptr<DaoLCService::Stub> stub;
};

struct dao_lc_grpc_ctx *
dao_lc_grpc_client_init(const char *server_ip, uint16_t server_port)
{
	auto ctx = new dao_lc_grpc_ctx();
	std::string server_addr = server_ip;

	if (server_ip == NULL)
		return NULL;

	server_addr += ":";
	server_addr += std::to_string(server_port);

	auto channel = grpc::CreateChannel(server_addr, grpc::InsecureChannelCredentials());

	ctx->stub = DaoLCService::NewStub(channel);

	return ctx;
}

void
dao_lc_grpc_client_fini(struct dao_lc_grpc_ctx *ctx)
{
	if (ctx == NULL)
		return;
	delete ctx;
}

int
dao_lc_ethdev_create(struct dao_lc_grpc_ctx *ctx, uint32_t dev_id, uint32_t nb_queues)
{
	ClientContext context;
	grpc::Status status;
	DeviceId dev_id_msg;
	Response resp;

	if (ctx == NULL)
		return -EINVAL;

	dev_id_msg.set_dev_id(dev_id);
	dev_id_msg.set_nb_queues(nb_queues);
	status = ctx->stub->CreateDev(&context, dev_id_msg, &resp);
	if (!status.ok()) {
		fprintf(stderr, "Failed to create device: %s (code=%d)\n", status.error_message().c_str(), status.error_code());
		return grpc_status_to_errno(status);
	}

	return 0;
}

int
dao_lc_ethdev_destroy(struct dao_lc_grpc_ctx *ctx, uint32_t dev_id)
{
	ClientContext context;
	grpc::Status status;
	DeviceId dev_id_msg;
	Response resp;

	if (ctx == NULL)
		return -EINVAL;

	dev_id_msg.set_dev_id(dev_id);
	status = ctx->stub->DestroyDev(&context, dev_id_msg, &resp);
	if (!status.ok()) {
		fprintf(stderr, "Failed to destroy device: %s (code=%d)\n", status.error_message().c_str(), status.error_code());
		return grpc_status_to_errno(status);
	}

	return 0;
}

int
dao_lc_ethdev_start(struct dao_lc_grpc_ctx *ctx, uint32_t dev_id)
{
	ClientContext context;
	grpc::Status status;
	DeviceId dev_id_msg;
	Response resp;

	if (ctx == NULL)
		return -EINVAL;

	dev_id_msg.set_dev_id(dev_id);
	status = ctx->stub->StartDev(&context, dev_id_msg, &resp);
	if (!status.ok()) {
		fprintf(stderr, "Failed to start device: %s (code=%d)\n", status.error_message().c_str(), status.error_code());
		return grpc_status_to_errno(status);
	}

	return 0;
}

int
dao_lc_ethdev_stop(struct dao_lc_grpc_ctx *ctx, uint32_t dev_id)
{
	ClientContext context;
	grpc::Status status;
	DeviceId dev_id_msg;
	Response resp;

	if (ctx == NULL)
		return -EINVAL;

	dev_id_msg.set_dev_id(dev_id);
	status = ctx->stub->StopDev(&context, dev_id_msg, &resp);
	if (!status.ok()) {
		fprintf(stderr, "Failed to stop device: %s (code=%d)\n", status.error_message().c_str(), status.error_code());
		return grpc_status_to_errno(status);
	}

	return 0;
}

int
dao_lc_ethdev_queue_configure(struct dao_lc_grpc_ctx *ctx, struct dao_lc_eth_qconf *q_conf)
{
	ClientContext context;
	grpc::Status status;
	QpConf qp_conf_msg;
	Response resp;

	if (ctx == NULL || q_conf == NULL)
		return -EINVAL;

	qp_conf_msg.set_dev_id(q_conf->dev_id);
	qp_conf_msg.set_qp_id(q_conf->qp_id);
	qp_conf_msg.set_nb_desc(q_conf->nb_desc);
	qp_conf_msg.set_max_seg_size(q_conf->max_seg_size);
	qp_conf_msg.set_out_of_order_delivery_en(q_conf->out_of_order_delivery_en);
	status = ctx->stub->ConfigureQP(&context, qp_conf_msg, &resp);
	if (!status.ok()) {
		fprintf(stderr, "Failed to configure QP: %s (code=%d)\n", status.error_message().c_str(), status.error_code());
		return grpc_status_to_errno(status);
	}

	return 0;
}

int
dao_lc_ethdev_queue_destroy(struct dao_lc_grpc_ctx *ctx, uint32_t dev_id, uint32_t qp_id)
{
	QueuePairId qp_conf_msg;
	ClientContext context;
	grpc::Status status;
	Response resp;

	if (ctx == NULL)
		return -EINVAL;

	qp_conf_msg.set_dev_id(dev_id);
	qp_conf_msg.set_qp_id(qp_id);
	status = ctx->stub->DestroyQP(&context, qp_conf_msg, &resp);
	if (!status.ok()) {
		fprintf(stderr, "Failed to destroy QP: %s (code=%d)\n", status.error_message().c_str(), status.error_code());
		return grpc_status_to_errno(status);
	}

	return 0;
}
