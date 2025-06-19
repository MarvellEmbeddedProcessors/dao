# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2025 Marvell.

sources = files(
  'card_mgr.c',
)

if not DAO_BUILD_CONF.has('DAO_LIBEDIT_DEP')
	message('libedit not found. skipping card-mgr')
	skip_app = true
	subdir_done()
endif

app_deps += DAO_EXT_DEPS_LIBEDIT

deps += ['common', 'grpc_service_client_card']
