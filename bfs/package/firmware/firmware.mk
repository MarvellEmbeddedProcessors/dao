# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2025 Marvell.

################################################################################
# Firmware
################################################################################
FIRMWARE_VERSION = main
FIRMWARE_SITE = https://github.com/MarvellEmbeddedProcessors/marvell-firmware.git
FIRMWARE_SITE_METHOD = git

FIRMWARE_CONFIG = $(call qstrip,$(BR2_PACKAGE_FIRMWARE_CONFIG))

define FIRMWARE_INSTALL_TARGET_CMDS
	mkdir -p $(TARGET_DIR)/root/lib/firmware/mrvl
	rsync -a $(@D)/ $(TARGET_DIR)/root/lib/firmware/mrvl/
endef

$(eval $(generic-package))
