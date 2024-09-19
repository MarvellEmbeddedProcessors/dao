/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef _VIRTIO_CRYPTO_AKCIPHER_H_
#define _VIRTIO_CRYPTO_AKCIPHER_H_

#include <spec/virtio_crypto.h>
#include <virtio_crypto_priv.h>

int virtio_crypto_akcipher_rsa_xform_prepare(struct virtio_crypto_op_ctrl_req *ctrl_req,
					     struct rte_crypto_asym_xform *xform);

#endif /* _VIRTIO_CRYPTO_AKCIPHER_H_ */
