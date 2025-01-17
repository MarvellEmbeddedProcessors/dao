/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <dao_liquid_crypto.h>

#include "ca_crypto_queue.h"
#include "cpt_debug.h"
#include "crypto_agent.h"

void
cpt_debug_res_print(struct cpt_inflight_req *req)
{
	union dao_cpt_res_s res;
	char log_str[256];

	res.u64[0] = __atomic_load_n(&req->res.u64[0], __ATOMIC_RELAXED);
	res.u64[1] = __atomic_load_n(&req->res.u64[1], __ATOMIC_RELAXED);

	CA_INFO("Result: %lx %lx", res.u64[0], res.u64[1]);

	switch (res.cn10k.compcode) {
	case CPT_COMP_GOOD:
		snprintf(log_str, sizeof(log_str), "CPT_COMP_GOOD");
		break;
	case CPT_COMP_FAULT:
		snprintf(log_str, sizeof(log_str), "CPT_COMP_FAULT");
		break;
	case CPT_COMP_SWERR:
		snprintf(log_str, sizeof(log_str), "CPT_COMP_SWERR");
		break;
	case CPT_COMP_HWERR:
		snprintf(log_str, sizeof(log_str), "CPT_COMP_HWERR");
		break;
	case CPT_COMP_INSTERR:
		snprintf(log_str, sizeof(log_str), "CPT_COMP_INSTERR");
		break;
	case CPT_COMP_WARN:
		snprintf(log_str, sizeof(log_str), "CPT_COMP_WARN");
		break;
	default:
		snprintf(log_str, sizeof(log_str), "Unknown");
		break;
	}

	CA_INFO("Completion code: %s", log_str);
	rte_pktmbuf_dump(stdout, req->mbuf, rte_pktmbuf_pkt_len(req->mbuf));
}
