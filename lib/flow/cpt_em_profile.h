/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef _CPT_EM_PROFILE_H_
#define _CPT_EM_PROFILE_H_

#include "key.h"
#include "profile_priv.h"

#define L2L3_BCAST_NIB 0

#define MAX_CPT_KCFG_FIELDS 32

extern struct key_config cpt_em_kcfg[];
extern struct flow_parser_tcam_kex cpt_em_kex_profile;

#endif /* _CPT_EM_PROFILE_H_ */
