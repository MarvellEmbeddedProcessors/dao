/* SPDX-License-Identifier: Marvell-Proprietary
 * Copyright (c) 2025 Marvell
 */

#ifndef __LC_TRANSPORT_H__
#define __LC_TRANSPORT_H__

#include <rte_common.h>

#include <../../lib/eth_transport/dao_eth_trs.h>

struct __rte_packed __dao_lc_req_sym {
	struct dao_eth_trs_hdr hdr;
	uint32_t rsvd_align;
	uint64_t w4;
	uint64_t w7;
	uint8_t dptr[];
};

struct __rte_packed __dao_lc_req_asym {
	struct dao_eth_trs_hdr hdr;
	uint32_t rsvd_align;
	uint64_t w4;
	uint8_t dptr[];
};

#endif /*  __LC_TRANSPORT_H__ */
