# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2025 Marvell.

sources = files(
	'liquid_crypto_api.c',
	'liquid_crypto_sym.c',
)

headers = files(
	'dao_liquid_crypto.h',
)

deps += ['common', 'eth_transport', 'grpc_service_client_lc', 'grpc_service_client_card']

if get_option('buildtype').contains('debug')
	cflags += [ '-DDAO_LIQUID_CRYPTO_DEBUG=1' ]
endif
