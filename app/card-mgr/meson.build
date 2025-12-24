# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2025 Marvell.

sources = files(
  'card_mgr_main.c',
  'card_mgr_server.c',
  'card_mgr_client.c',
  'update/update_manager.c',
  'update/app_update.c',
  'update/fw_update.c',
  'update/failsafe_update.c',
  'update/mcu_update.c',
  'lock/lock.c',
  'utils/module_utils.c',
  'utils/file_utils.c',
  'utils/logging.c',
)

if not DAO_BUILD_CONF.has('DAO_LIBEDIT_DEP')
	message('libedit not found. skipping card-mgr')
	skip_app = true
	subdir_done()
endif

app_deps += DAO_EXT_DEPS_LIBEDIT

deps += ['common', 'grpc_service_client_card']
