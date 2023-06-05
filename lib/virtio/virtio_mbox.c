/* SPDX-License-Identifier: Marvell-Proprietary
 * Copyright (c) 2024 Marvell.
 */
#include "dao_virtio.h"
#include "virtio_dev_priv.h"
#include "virtio_mbox.h"

static void
virtio_mbox_process(struct virtio_dev *dev)
{
	struct virtio_mbox *mbox = (struct virtio_mbox *)dev->mbox;
	uint32_t *data = mbox->data + 1;
	struct virtio_vq_state state;
	int rc;

	if (mbox->hdr.sig != MBOX_REQ_SIG) {
		rc = EINVAL;
		goto exit;
	}
	switch (mbox->hdr.id) {
	case MBOX_MSG_GET_VQ_STATE:
		state.last_avail_counter = 1;
		state.last_used_counter = 1;
		state.last_avail_idx = 0;
		state.last_used_idx = 0;

		memcpy(data, &state, sizeof(struct virtio_vq_state));
		rte_wmb();
		rc = 0;
		break;
	case MBOX_MSG_SET_VQ_STATE:
		rc = 0;
		break;
	default:
		rc = EINVAL;
		break;
	}

exit:
	mbox->sts.rc = rc;
	mbox->sts.rsp = 1;
	mbox->hdr.sig = MBOX_RSP_SIG;
	mbox->hdr.id = 0;
	rte_wmb();
}

static int
virtio_mbox_process_cb(void *ctx, uintptr_t shadow, uint32_t offset, uint64_t val,
		       uint64_t shadow_val)
{
	struct virtio_dev *dev = ctx;

	RTE_SET_USED(offset);
	RTE_SET_USED(shadow_val);

	*((uint64_t *)shadow) = val;
	virtio_mbox_process(dev);
	memcpy((void *)shadow, (void *)dev->mbox, 8);

	return 0;
}

int
virtio_mbox_init(struct virtio_dev *dev)
{
	int rc;

	memset((void *)dev->mbox, 0, 8);
	/* Register MBOX region */
	rc = dao_pem_ctrl_region_register(dev->pem_devid, (uintptr_t)dev->mbox,
					  8, virtio_mbox_process_cb, dev, false);
	if (rc)
		dao_err("[dev %u] Failed to register mbox region, rc=%d", dev->dev_id, rc);

	return rc;
}

void
virtio_mbox_fini(struct virtio_dev *dev)
{
	dao_pem_ctrl_region_unregister(dev->pem_devid, (uintptr_t)dev->mbox,
				       8, virtio_mbox_process_cb, dev);
}
