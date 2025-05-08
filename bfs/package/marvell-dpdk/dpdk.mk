# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2025 Marvell.

################################################################################
# marvell-dpdk
################################################################################

MARVELL_DPDK_VERSION = dpdk-24.11-release
MARVELL_DPDK_SITE = https://github.com/MarvellEmbeddedProcessors/marvell-dpdk.git
MARVELL_DPDK_SITE_METHOD=git
MARVELL_DPDK_LICENSE = \
	BSD-3-Clause, \
	MIT

BR_NO_CHECK_HASH_FOR += $(MARVELL_DPDK_SOURCE)
MARVELL_DPDK_CONFIG = $(call qstrip,$(BR2_PACKAGE_MARVELL_DPDK_CONFIG))
MARVELL_DPDK_INSTALL_STAGING = YES

MARVELL_DPDK_LICENSE_FILES = \
	license/README \
	license/bsd-3-clause.txt \
	license/exceptions.txt \
	license/mit.txt

MARVELL_DPDK_DEPENDENCIES = \
	host-pkgconf \
	host-python-pyelftools

ifeq ($(BR2_PACKAGE_MARVELL_DPDK_BUILD_MINIMAL),y)
MARVELL_DPDK_CONF_OPTS += -Denable_libs=cryptodev,dmadev,eventdev,security,timer
MARVELL_DPDK_CONF_OPTS += -Denable_drivers=common/cnxk,crypto/cnxk,mempool/cnxk,dma/cnxk,net/cnxk,event/cnxk
endif

ifeq ($(BR2_PACKAGE_MARVELL_DPDK_DEBUG_BUILD),y)
MARVELL_DPDK_CONF_OPTS +=--buildtype=debug
endif

ifeq ($(BR2_PACKAGE_MARVELL_DPDK_ENABLE_FPIC),y)
MARVELL_DPDK_CFLAGS += -fPIC
endif

ifeq ($(BR2_PACKAGE_MARVELL_DPDK_EXAMPLES),y)
MARVELL_DPDK_CONF_OPTS += -Dexamples=all
else
MARVELL_DPDK_CONF_OPTS += -Dexamples=
endif

ifeq ($(BR2_PACKAGE_MARVELL_DPDK_TESTS),y)
MARVELL_DPDK_CONF_OPTS += -Dtests=true
else
MARVELL_DPDK_CONF_OPTS += -Dtests=false
endif

ifeq ($(BR2_PACKAGE_LIBBSD),y)
MARVELL_DPDK_DEPENDENCIES += libbsd
endif

ifeq ($(BR2_PACKAGE_JANSSON),y)
MARVELL_DPDK_DEPENDENCIES += jansson
endif

ifeq ($(BR2_PACKAGE_LIBPCAP),y)
MARVELL_DPDK_DEPENDENCIES += libpcap
endif

ifeq ($(BR2_PACKAGE_ZLIB),y)
MARVELL_DPDK_DEPENDENCIES += zlib
endif

ifeq ($(BR2_PACKAGE_LIBEXECINFO),y)
MARVELL_DPDK_DEPENDENCIES += libexecinfo
endif

ifeq ($(BR2_PACKAGE_NUMACTL),y)
MARVELL_DPDK_DEPENDENCIES += numactl
endif

ifeq ($(BR2_PACKAGE_LIBARCHIVE),y)
MARVELL_DPDK_DEPENDENCIES += libarchive
endif

ifeq ($(BR2_PACKAGE_LIBBPF),y)
MARVELL_DPDK_DEPENDENCIES += libbpf
endif

ifeq ($(BR2_PACKAGE_RDMA_CORE),y)
MARVELL_DPDK_DEPENDENCIES += rdma-core
endif


# DPDK meson detects arch specific cflags based on platform parameter defined in config file
ifneq ($(BR2_MARVELL_MESON_PROPERTIES_PLATFORM),)
MARVELL_DPDK_MESON_EXTRA_PROPERTIES += platform='$(BR2_MARVELL_MESON_PROPERTIES_PLATFORM)'
else
MARVELL_DPDK_CONF_OPTS += -Dcpu_instruction_set=$(BR2_GCC_TARGET_ARCH)
endif

$(eval $(meson-package))
