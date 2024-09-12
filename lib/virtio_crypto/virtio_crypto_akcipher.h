/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef _VIRTIO_CRYPTO_AKCIPHER_H_
#define _VIRTIO_CRYPTO_AKCIPHER_H_

#include <spec/virtio_crypto.h>
#include <virtio_crypto_priv.h>

int virtio_crypto_akcipher_rsa_xform_prepare(struct virtio_crypto_op_ctrl_req *ctrl_req,
					     struct rte_crypto_asym_xform *xform);

static inline void
virtio_crypto_akcipher_enc_op(struct rte_crypto_op *cop,
			      struct virtio_crypto_op_data_req *op_data_req,
			      rte_iova_t *output_addr, uint32_t *output_len)
{
	cop->type = RTE_CRYPTO_OP_TYPE_ASYMMETRIC;
	cop->status = RTE_CRYPTO_OP_STATUS_NOT_PROCESSED;
	cop->sess_type = RTE_CRYPTO_OP_WITH_SESSION;
	cop->asym->session = (void *)op_data_req->header.session_id;
	cop->asym->rsa.op_type = RTE_CRYPTO_ASYM_OP_ENCRYPT;
	cop->asym->rsa.message.data =
		RTE_PTR_ADD((uint8_t *)op_data_req, sizeof(struct virtio_crypto_op_data_req));
	cop->asym->rsa.message.length = op_data_req->u.akcipher_req.para.src_data_len;
	cop->asym->rsa.cipher.data = RTE_PTR_ADD(
		(uint8_t *)op_data_req, sizeof(struct virtio_crypto_op_data_req) +
						op_data_req->u.akcipher_req.para.src_data_len);
	cop->asym->rsa.cipher.length = op_data_req->u.akcipher_req.para.dst_data_len;
	*output_addr = (rte_iova_t)cop->asym->rsa.cipher.data;
	*output_len = cop->asym->rsa.cipher.length;
#ifdef DEBUG
	rte_hexdump(stdout, "message", cop->asym->rsa.message.data, cop->asym->rsa.message.length);
	rte_hexdump(stdout, "cipher", cop->asym->rsa.cipher.data, cop->asym->rsa.cipher.length);
#endif
}

static inline void
virtio_crypto_akcipher_dec_op(struct rte_crypto_op *cop,
			      struct virtio_crypto_op_data_req *op_data_req,
			      rte_iova_t *output_addr, uint32_t *output_len)
{
	cop->type = RTE_CRYPTO_OP_TYPE_ASYMMETRIC;
	cop->status = RTE_CRYPTO_OP_STATUS_NOT_PROCESSED;
	cop->sess_type = RTE_CRYPTO_OP_WITH_SESSION;
	cop->asym->session = (void *)op_data_req->header.session_id;
	cop->asym->rsa.op_type = RTE_CRYPTO_ASYM_OP_DECRYPT;
	cop->asym->rsa.message.data = RTE_PTR_ADD(
		(uint8_t *)op_data_req, sizeof(struct virtio_crypto_op_data_req) +
						op_data_req->u.akcipher_req.para.src_data_len);
	cop->asym->rsa.message.length = op_data_req->u.akcipher_req.para.dst_data_len;
	cop->asym->rsa.cipher.data =
		RTE_PTR_ADD((uint8_t *)op_data_req, sizeof(struct virtio_crypto_op_data_req));
	cop->asym->rsa.cipher.length = op_data_req->u.akcipher_req.para.src_data_len;
	*output_addr = (rte_iova_t)cop->asym->rsa.message.data;
	*output_len = cop->asym->rsa.message.length;
}

static inline void
virtio_crypto_akcipher_sign_op(struct rte_crypto_op *cop,
			       struct virtio_crypto_op_data_req *op_data_req,
			       rte_iova_t *output_addr, uint32_t *output_len)
{
	cop->type = RTE_CRYPTO_OP_TYPE_ASYMMETRIC;
	cop->status = RTE_CRYPTO_OP_STATUS_NOT_PROCESSED;
	cop->sess_type = RTE_CRYPTO_OP_WITH_SESSION;
	cop->asym->session = (void *)op_data_req->header.session_id;
	cop->asym->rsa.op_type = RTE_CRYPTO_ASYM_OP_SIGN;
	cop->asym->rsa.message.data =
		RTE_PTR_ADD((uint8_t *)op_data_req, sizeof(struct virtio_crypto_op_data_req));
	cop->asym->rsa.message.length = op_data_req->u.akcipher_req.para.src_data_len;
	cop->asym->rsa.sign.data = RTE_PTR_ADD(
		(uint8_t *)op_data_req, sizeof(struct virtio_crypto_op_data_req) +
						op_data_req->u.akcipher_req.para.src_data_len);
	cop->asym->rsa.sign.length = op_data_req->u.akcipher_req.para.dst_data_len;
	*output_addr = (rte_iova_t)cop->asym->rsa.sign.data;
	*output_len = cop->asym->rsa.sign.length;
#ifdef DEBUG
	rte_hexdump(stdout, "message", cop->asym->rsa.message.data, cop->asym->rsa.message.length);
	rte_hexdump(stdout, "sign", cop->asym->rsa.sign.data, cop->asym->rsa.sign.length);
#endif
}

static inline void
virtio_crypto_akcipher_verify_op(struct rte_crypto_op *cop,
				 struct virtio_crypto_op_data_req *op_data_req,
				 rte_iova_t *output_addr, uint32_t *output_len)
{
	cop->type = RTE_CRYPTO_OP_TYPE_ASYMMETRIC;
	cop->status = RTE_CRYPTO_OP_STATUS_NOT_PROCESSED;
	cop->sess_type = RTE_CRYPTO_OP_WITH_SESSION;
	cop->asym->session = (void *)op_data_req->header.session_id;
	cop->asym->rsa.op_type = RTE_CRYPTO_ASYM_OP_VERIFY;
	cop->asym->rsa.message.data = RTE_PTR_ADD(
		(uint8_t *)op_data_req, sizeof(struct virtio_crypto_op_data_req) +
						op_data_req->u.akcipher_req.para.src_data_len);
	cop->asym->rsa.message.length = op_data_req->u.akcipher_req.para.dst_data_len;
	cop->asym->rsa.sign.data =
		RTE_PTR_ADD((uint8_t *)op_data_req, sizeof(struct virtio_crypto_op_data_req));
	cop->asym->rsa.sign.length = op_data_req->u.akcipher_req.para.src_data_len;
	*output_addr = (rte_iova_t)&cop->status;
	*output_len = 0;
}

#endif /* _VIRTIO_CRYPTO_AKCIPHER_H_ */
