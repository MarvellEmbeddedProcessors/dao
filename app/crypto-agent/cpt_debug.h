/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef __CPT_DEBUG_H__
#define __CPT_DEBUG_H__

#include "ca_crypto_queue.h"

void cpt_debug_inst_print(struct cpt_inst_s *inst);
void cpt_debug_res_print(struct cpt_inflight_req *req);

#endif /* __CPT_DEBUG_H__ */
