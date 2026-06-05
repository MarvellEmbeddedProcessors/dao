# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2023 Marvell.

subdir('dpdk')
if host_build and not meson.is_cross_build()
  subdir('libedit')
  subdir('openssl')
endif
subdir('grpc')
subdir('libnl')
subdir('libpcap')
subdir('liboqs')
