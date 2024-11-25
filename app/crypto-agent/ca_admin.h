/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef __CA_ADMIN_H__
#define __CA_ADMIN_H__

/* Defines related to Admin Device */

#define CA_ADMIN_MAX_ETHDEV 8

struct ca_dev_config {
	struct {
		uint16_t nb_desc;
	} crypto;
	struct {
		uint16_t nb_devs;
		uint16_t nb_queue[CA_ADMIN_MAX_ETHDEV];
	} eth;
	uint16_t max_payload_size;
};

#endif /* __CA_ADMIN_H__ */
