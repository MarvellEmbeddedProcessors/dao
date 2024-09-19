/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <rte_crypto_asym.h>

#include <spec/virtio_crypto.h>

#include "virtio_crypto_akcipher.h"
#include "virtio_crypto_priv.h"

static int
tlv_decode(uint8_t *tlv, uint8_t type, uint8_t **data, size_t *data_len)
{
	size_t tlen = -EINVAL, len;

	if (tlv[0] != type)
		return -EINVAL;

	if (tlv[1] == 0x82) {
		len = (tlv[2] << 8) | tlv[3];
		*data = &tlv[4];
		tlen = len + 4;
	} else if (tlv[1] == 0x81) {
		len = tlv[2];
		*data = &tlv[3];
		tlen = len + 3;
	} else {
		len = tlv[1];
		*data = &tlv[2];
		tlen = len + 2;
	}

	*data_len = len;
	return tlen;
}

static int
virtio_crypto_asym_rsa_der_to_xform(uint8_t *der, size_t der_len,
				    struct rte_crypto_asym_xform *xform)
{
	uint8_t *n = NULL, *e = NULL, *d = NULL, *p = NULL, *q = NULL, *dp = NULL, *dq = NULL,
		*qinv = NULL, *v = NULL, *tlv;
	size_t nlen, elen, dlen, plen, qlen, dplen, dqlen, qinvlen, vlen;
	int len, i;

	RTE_SET_USED(der_len);

	for (i = 0; i < 8; i++) {
		if (der[i] == 0x30) {
			der = &der[i];
			break;
		}
	}

	if (der[0] != 0x30)
		return -EINVAL;

	if (der[1] == 0x82)
		tlv = &der[4];
	else if (der[1] == 0x81)
		tlv = &der[3];
	else
		return -EINVAL;

	len = tlv_decode(tlv, 0x02, &v, &vlen);
	if (len < 0 || v[0] != 0x0 || vlen != 1)
		return -EINVAL;

	tlv = tlv + len;
	len = tlv_decode(tlv, 0x02, &n, &nlen);
	if (len < 0)
		return len;

	tlv = tlv + len;
	len = tlv_decode(tlv, 0x02, &e, &elen);
	if (len < 0)
		return len;

	tlv = tlv + len;
	len = tlv_decode(tlv, 0x02, &d, &dlen);
	if (len < 0)
		return len;

	tlv = tlv + len;
	len = tlv_decode(tlv, 0x02, &p, &plen);
	if (len < 0)
		return len;

	tlv = tlv + len;
	len = tlv_decode(tlv, 0x02, &q, &qlen);
	if (len < 0)
		return len;

	tlv = tlv + len;
	len = tlv_decode(tlv, 0x02, &dp, &dplen);
	if (len < 0)
		return len;

	tlv = tlv + len;
	len = tlv_decode(tlv, 0x02, &dq, &dqlen);
	if (len < 0)
		return len;

	tlv = tlv + len;
	len = tlv_decode(tlv, 0x02, &qinv, &qinvlen);
	if (len < 0)
		return len;

	xform->rsa.n.data = n;
	xform->rsa.n.length = nlen;
	xform->rsa.e.data = e;
	xform->rsa.e.length = elen;
	xform->rsa.d.data = d;
	xform->rsa.d.length = dlen;
	xform->rsa.qt.p.data = p;
	xform->rsa.qt.p.length = plen;
	xform->rsa.qt.q.data = q;
	xform->rsa.qt.q.length = qlen;
	xform->rsa.qt.dP.data = dp;
	xform->rsa.qt.dP.length = dplen;
	xform->rsa.qt.dQ.data = dq;
	xform->rsa.qt.dQ.length = dqlen;
	xform->rsa.qt.qInv.data = qinv;
	xform->rsa.qt.qInv.length = qinvlen;

	RTE_ASSERT(tlv + len == der + der_len);
	return 0;
}

static int
virtio_crypto_asym_rsa_public_der_to_xform(uint8_t *der, size_t der_len,
					   struct rte_crypto_asym_xform *xform)
{
	uint8_t *n = NULL, *e = NULL, *tlv;
	size_t nlen, elen;
	int len, i;

	RTE_SET_USED(der_len);

	for (i = 0; i < 8; i++) {
		if (der[i] == 0x30) {
			der = &der[i];
			break;
		}
	}

	if (der[0] != 0x30)
		return -EINVAL;

	if (der[1] == 0x82)
		tlv = &der[4];
	else if (der[1] == 0x81)
		tlv = &der[3];
	else
		return -EINVAL;

	len = tlv_decode(tlv, 0x02, &n, &nlen);
	if (len < 0)
		return len;

	tlv = tlv + len;
	len = tlv_decode(tlv, 0x02, &e, &elen);
	if (len < 0)
		return len;

	xform->rsa.n.data = ++n;
	xform->rsa.n.length = nlen - 1;
	xform->rsa.e.data = e;
	xform->rsa.e.length = elen;

	RTE_ASSERT(tlv + len == der + der_len);
	return 0;
}

int
virtio_crypto_akcipher_rsa_xform_prepare(struct virtio_crypto_op_ctrl_req *ctrl_req,
					 struct rte_crypto_asym_xform *xform)
{
	uint8_t *key = (uint8_t *)ctrl_req + sizeof(struct virtio_crypto_op_ctrl_req);
	struct virtio_crypto_akcipher_session_para *para;
	struct virtio_crypto_ctrl_header *ctrl_cmd;
	int rc = 0;

	ctrl_cmd = &ctrl_req->header;
	dao_dbg("CTRL_CMD ALGO : %u", ctrl_cmd->algo);
	dao_dbg("CTRL_CMD OP_TYPE: %u", ctrl_cmd->opcode);
	dao_dbg("CTRL_CMD OP_FLAG: %u", ctrl_cmd->flag);
	dao_dbg("CTRL_CMD OP_QUEUE: %u", ctrl_cmd->queue_id);

	para = &ctrl_req->u.akcipher_create_session.para;
	dao_dbg("AKCIPHER ALGO : %u", para->algo);
	dao_dbg("AKCIPHER KEY_TYPE: %u", para->keytype);
	dao_dbg("AKCIPHER KEY_LEN: %u", para->keylen);

	if (para->keytype == VIRTIO_CRYPTO_AKCIPHER_KEY_TYPE_PRIVATE) {
		rc = virtio_crypto_asym_rsa_der_to_xform(key, para->keylen, xform);
		if (rc) {
			dao_err("Private key to xform create failed");
			return rc;
		}

		/*
		 * DPDK supports both EXP and QT keys, but virtio provides both.
		 * QT components overwrite EXP components. Therefore, the key type is set to QT.
		 */
		xform->rsa.key_type = RTE_RSA_KEY_TYPE_QT;

	} else if (para->keytype == VIRTIO_CRYPTO_AKCIPHER_KEY_TYPE_PUBLIC) {
		rc = virtio_crypto_asym_rsa_public_der_to_xform(key, para->keylen, xform);
		if (rc) {
			dao_err("Public key to xform create failed");
			return rc;
		}
	} else {
		dao_err("Invalid key type");
		return -EINVAL;
	}

	switch (para->u.rsa.padding_algo) {
	case VIRTIO_CRYPTO_RSA_RAW_PADDING:
		xform->rsa.padding.type = RTE_CRYPTO_RSA_PADDING_NONE;
		break;
	case VIRTIO_CRYPTO_RSA_PKCS1_PADDING:
		xform->rsa.padding.type = RTE_CRYPTO_RSA_PADDING_PKCS1_5;
		break;
	default:
		return -EINVAL;
	}

	xform->xform_type = RTE_CRYPTO_ASYM_XFORM_RSA;

	return rc;
}
