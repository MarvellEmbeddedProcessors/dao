/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#ifndef __FLOW_GBL_PRIV_H__
#define __FLOW_GBL_PRIV_H__

#include "flow_acl_priv.h"

#define FLOW_GBL_CFG_MZ_NAME "flow_global_cfg"

struct flow_global_cfg {
	struct acl_global_config *acl_gbl;
};

extern struct flow_global_cfg *gbl_cfg;

#endif /* __FLOW_GBL_PRIV_H__ */
