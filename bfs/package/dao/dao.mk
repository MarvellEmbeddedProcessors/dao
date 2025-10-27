# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2025 Marvell.

################################################################################
# DAO
################################################################################
DAO_VERSION = 25.01.0
DAO_SITE = $(BR2_EXTERNAL_MRVL_PATH)/..
DAO_SITE_METHOD = local
DAO_INSTALL_STAGING = YES

BR_NO_CHECK_HASH_FOR += $(DAO_SOURCE)
DAO_CONFIG = $(call qstrip,$(BR2_PACKAGE_DAO_CONFIG))

ifeq ($(BR2_PACKAGE_DAO_DEBUG_BUILD),y)
DAO_CONF_OPTS +=--buildtype=debug
endif

ifneq ($(BR2_MARVELL_MESON_PROPERTIES_PLATFORM),)
DAO_MESON_EXTRA_PROPERTIES += platform='$(BR2_MARVELL_MESON_PROPERTIES_PLATFORM)'
else
DAO_CONF_OPTS += -Dcpu_instruction_set=$(BR2_GCC_TARGET_ARCH)
endif

ifneq ($(BR2_MARVELL_MESON_PROPERTIES_MACHINE_ARGS),)
DAO_MESON_EXTRA_PROPERTIES += machine_args='-mcpu=$(BR2_MARVELL_MESON_PROPERTIES_MACHINE_ARGS)'
endif

ifeq ($(BR2_PACKAGE_DAO_BUILD_MINIMAL_CRYPTO_AGENT),y)
DAO_CONF_OPTS += -Denable_libs=common,eth_transport,grpc_service/server
DAO_CONF_OPTS += -Denable_apps=crypto-agent
endif

# Add DAO dependencies

ifeq ($(BR2_PACKAGE_MARVELL_DPDK),y)
DAO_DEPENDENCIES += marvell-dpdk
endif

ifeq ($(BR2_PACKAGE_GRPC),y)
DAO_DEPENDENCIES += grpc
endif

ifeq ($(BR2_PACKAGE_LIBOQS),y)
DAO_DEPENDENCIES += liboqs
endif

$(eval $(meson-package))
