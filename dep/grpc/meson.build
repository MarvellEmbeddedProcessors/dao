# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2025 Marvell.

protoc = find_program('protoc', required:false)
grpc_cpp_plugin = find_program('grpc_cpp_plugin', required:false)
# pkg-config resolves shared libraries by default. Honor Meson's built-in
# 'prefer_static' core option (set via --prefer-static / -Dprefer_static=true)
# as well as the project's own 'prefer_static_build' option, so that
# gRPC/protobuf (and their transitive deps) are resolved as static
# libraries as well, e.g. for a fully static dao-card-mgr binary. If neither
# option is set, this falls back to shared linkage as before.
grpcplus_dep = dependency('grpc++', method : 'pkg-config', version: '>=1.65.0', required:false,
	static: get_option('prefer_static') or get_option('prefer_static_build'))
protobuf_dep = dependency('protobuf', method : 'pkg-config', version:'>=27.2.0', required:false,
	static: get_option('prefer_static') or get_option('prefer_static_build'))

if not protoc.found()
	message('protobuf compiler (protoc) not found')
	subdir_done()
endif

if not grpc_cpp_plugin.found()
	message('grpc_cpp_plugin not found')
	subdir_done()
endif

if not protobuf_dep.found()
	message('protobuf pkgconfig not exported')
	subdir_done()
endif

if not grpcplus_dep.found()
	message('grpcplus pkgconfig not exported')
	subdir_done()
endif

DAO_BUILD_CONF.set('DAO_GRPC_DEP', '1')
DAO_EXT_DEPS_GRPC += grpcplus_dep
DAO_EXT_DEPS_GRPC += protobuf_dep
