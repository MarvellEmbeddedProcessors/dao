# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2025 Marvell.

if not DAO_BUILD_CONF.has('DAO_GRPC_DEP')
	skip_lib = true
	subdir_done()
endif

if host_build
	skip_lib = true
	subdir_done()
endif

lib_deps += DAO_EXT_DEPS_GRPC

protoc=find_program('protoc')
grpc_cpp_plugin_path = find_program('grpc_cpp_plugin').full_path()
out_dir = meson.current_build_dir()

dao_card_proto_dir = meson.current_source_dir() / '../client_card'
dao_card_proto = dao_card_proto_dir / 'dao_card.proto'

grpc_card_service_gen_sources = custom_target('protoc-dao-card-compile',
	input: [dao_card_proto],
	output: [
		'dao_card.pb.cc',
		'dao_card.pb.h',
		'dao_card.grpc.pb.cc',
		'dao_card.grpc.pb.h',
	],
	command: [
		protoc,
		'--grpc_out', out_dir,
		'--cpp_out', out_dir,
		'--proto_path', dao_card_proto_dir,
		f'--plugin=protoc-gen-grpc=@grpc_cpp_plugin_path@',
		'@INPUT@'
	],
)

dao_lc_proto_dir = meson.current_source_dir() / '../client_lc'
dao_lc_proto = dao_lc_proto_dir / 'dao_lc.proto'
grpc_lc_service_gen_sources = custom_target('protoc-dao-lc-compile',
	input: [dao_lc_proto],
	output: [
		'dao_lc.pb.cc',
		'dao_lc.pb.h',
		'dao_lc.grpc.pb.cc',
		'dao_lc.grpc.pb.h',
	],
	command: [
		protoc,
		'--grpc_out', out_dir,
		'--cpp_out', out_dir,
		'--proto_path', dao_lc_proto_dir,
		f'--plugin=protoc-gen-grpc=@grpc_cpp_plugin_path@',
		'@INPUT@'
	],
)

headers = files(
	'dao_card_grpc_server.h',
	'../dao_card_grpc_service.h',
	'../dao_lc_grpc_service.h'
)

sources = files(
	'dao_card_grpc_server.cpp',
)

sources += [
	grpc_card_service_gen_sources,
	grpc_lc_service_gen_sources,
]
