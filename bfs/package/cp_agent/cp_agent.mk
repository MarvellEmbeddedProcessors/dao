# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2025 Marvell.

################################################################################
# CP AGENT
################################################################################

CP_AGENT_VERSION = pcie_ep_octeon_target-release
CP_AGENT_SITE = https://github.com/MarvellEmbeddedProcessors/pcie_ep_octeon_target.git
CP_AGENT_SITE_METHOD = git
CP_AGENT_SOURCE = cp_agent-$(CP_AGENT_VERSION).tar.gz

CP_AGENT_INSTALL_STAGING = YES
CP_AGENT_LICENSE = \
	BSD-3-Clause, \
	MIT

CP_AGENT_DEPENDENCIES = libconfig

CP_AGENT_CONFIG = $(call qstrip,$(BR2_PACKAGE_CP_AGENT_CONFIG))
CP_AGENT_CONF_OPTS= --host=aarch64-marvell-linux-gnu --prefix=$(TARGET_DIR)/usr

define CP_AGENT_BUILD_CMDS
	$(MAKE) CC="$(TARGET_CC)" LD="$(TARGET_LD)" -C $(@D)/target/libs/octep_cp_lib

	$(MAKE) CC="$(TARGET_CC)" LD="$(TARGET_LD)" -C $(@D)/target/apps/octep_cp_agent \
		CFLAGS="-I$(STAGING_DIR)/usr/include -I$(LIB_DIR)/bin/include -I$(@D)/target/libs/octep_cp_lib/bin/include" \
		LDFLAGS="-L$(LIB_DIR)/ -L$(STAGING_DIR)/usr/lib -L$(@D)/target/libs/octep_cp_lib/bin/lib"
endef

define CP_AGENT_INSTALL_TARGET_CMDS
	$(INSTALL) $(@D)/target/apps/octep_cp_agent/bin/* $(TARGET_DIR)/usr/bin/
	$(INSTALL) $(@D)/target/libs/octep_cp_lib/bin/lib/* $(TARGET_DIR)/usr/lib/
	$(INSTALL) $(@D)/target/apps/octep_cp_agent/*.cfg $(TARGET_DIR)/etc/
endef

$(eval $(generic-package))
