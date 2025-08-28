#!/bin/bash
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2025 Marvell.

set -euo pipefail
shopt -s extglob

function fetch_dep() {
	local url=$1
	local cache_dir=${PKG_CACHE_DIR:-}
	local fname

	fname=$(basename $url)

	if [ ! -z "$cache_dir" ]; then
		if [ -e "$cache_dir/$fname" ]; then
			echo "Copying from: $cache_dir/$fname."
			cp $cache_dir/$fname .
		else
			mkdir -p "$cache_dir"
			echo "Downloading $url"
			wget $url
			echo "Copying $fname to $cache_dir/"
			cp $fname $cache_dir/
		fi
	else
		echo "Downloading $url"
		wget $url
	fi
}

if [ "$#" -lt 2 ]; then
  echo "Syntax: build-deps.sh <build-dir> <plat> <deps_to_build> <verbose>"
  exit 1
fi

CROSS_COMPILE=${CROSS_COMPILE:-aarch64-none-linux-gnu}
PLAT=$2
MAKE_J=4
VERBOSE=${4:-}
BUILD_ROOT=$(realpath $1)
BUILD_DEPS_ROOT=$BUILD_ROOT/deps
DEPS_INSTALL_DIR=$BUILD_DEPS_ROOT/deps-prefix
EP_DEPS_INSTALL_DIR=$DEPS_INSTALL_DIR/ep
HOST_DEPS_INSTALL_DIR=$DEPS_INSTALL_DIR/host
DEPS_ENV=$(realpath ci/build/env/deps)
DPDK_DIR=$BUILD_DEPS_ROOT/dpdk
DPDK_ENV=$DEPS_ENV/dpdk.env
BUILD_DPDK_DIR=$DPDK_DIR/build
PREFIX_DPDK_DIR=$DPDK_DIR/out
PKG_CACHE_DIR=${PKG_CACHE_DIR:-}
HOST_DPDK_DIR=$BUILD_DEPS_ROOT/host/dpdk
HOST_BUILD_DPDK_DIR=$HOST_DPDK_DIR/build
HOST_DPDK_BRANCH="v25.11"
ALL_DEPS="dpdk libnl liboqs libpcap openssl grpc libconfig"
DEPS_TO_BUILD=${3:-$ALL_DEPS}
PKGCONFIG=${PKGCONFIG:-aarch64-linux-gnu-pkg-config}

# Set CROSS_COMPILE as "aarch64-marvell-linux-gnu" while building for cn9k.
if [ ${PLAT} == "cn9k" ] ; then
  CROSS_COMPILE=aarch64-marvell-linux-gnu
fi

# libnl variables
LIBNL_BUILD_DIR=$BUILD_DEPS_ROOT/libnl
LIBNL_PREFIX_DIR=$EP_DEPS_INSTALL_DIR
LIBNL_INSTALL_DIR=$LIBNL_PREFIX_DIR
LIBNL_TARBALL=libnl-3.7.0

# libconfig variables
LIBCONFIG_BUILD_DIR=$BUILD_DEPS_ROOT/libconfig
LIBCONFIG_PREFIX_DIR=$EP_DEPS_INSTALL_DIR
LIBCONFIG_INSTALL_DIR=$LIBCONFIG_PREFIX_DIR
LIBCONFIG_TARBALL=libconfig-1.8

# libpcap variables
LIBPCAP_BUILD_DIR=$BUILD_DEPS_ROOT/libpcap
LIBPCAP_PREFIX_DIR=$EP_DEPS_INSTALL_DIR
LIBPCAP_INSTALL_DIR=$LIBPCAP_PREFIX_DIR

# libcrypto variables
OPENSSL_BUILD_DIR=$BUILD_DEPS_ROOT/openssl
OPENSSL_PREFIX_DIR=$EP_DEPS_INSTALL_DIR
OPENSSL_INSTALL_DIR=$OPENSSL_PREFIX_DIR

#grpc variables
GRPC_SRC_TAG=v1.66.0
GRPC_SRC_URL=https://github.com/grpc/grpc
GRPC_SRC_DIR=$BUILD_DEPS_ROOT/host/grpc
GRPC_HOST_INSTALL_PREFIX=$HOST_DEPS_INSTALL_DIR/
GRPC_HOST_CONFIG_LIBDIR=$GRPC_HOST_INSTALL_PREFIX/lib/pkgconfig
GRPC_HOST_BUILD_DIR=$GRPC_SRC_DIR/cmake/build_host
GRPC_OCT_BUILD_DIR=$GRPC_SRC_DIR/cmake/build_aarch64
GRPC_OCT_INSTALL_PREFIX=$EP_DEPS_INSTALL_DIR/
GRPC_CXX_ABI_STANDARD=17
GRPC_CMAKE_CROSS_FILE=$(mktemp)
GRPC_CXX_CROSS_COMPILER=
GRPC_C_CROSS_COMPILER=

# liboqs variables
LIBOQS_SRC_TAG=0.13.0-rc1
LIBOQS_SRC_URL=https://github.com/open-quantum-safe/liboqs.git
LIBOQS_SRC_DIR=$BUILD_DEPS_ROOT/host/liboqs
LIBOQS_HOST_INSTALL_PREFIX=$HOST_DEPS_INSTALL_DIR/
LIBOQS_OCT_BUILD_DIR=$LIBOQS_SRC_DIR/build_aarch64
LIBOQS_OCT_INSTALL_PREFIX=$EP_DEPS_INSTALL_DIR/
LIBOQS_CXX_ABI_STANDARD=17
LIBOQS_CMAKE_CROSS_FILE=$(mktemp)
LIBOQS_CXX_CROSS_COMPILER=
LIBOQS_C_CROSS_COMPILER=

# fall back to pkg-config if specified one does not exist
if [ ! -x ${PKGCONFIG} ]; then
  PKGCONFIG=pkg-config
fi
export PKG_CONFIG_LIBDIR=$EP_DEPS_INSTALL_DIR/lib/pkgconfig

if [[ $DEPS_TO_BUILD == "all" ]]; then
	DEPS_TO_BUILD=$ALL_DEPS
fi

function build_dpdk() {
	local plat=$1
	local verbose=

	if [[ "$DEPS_TO_BUILD" != *"dpdk"* ]]; then
		return
	fi

	# Source dpdk env
	source $DPDK_ENV

	# Cloning the repositories
	mkdir -p $DPDK_DIR
	cd $DPDK_DIR
	git clone $DPDK_REPO --single-branch --branch $DPDK_BRANCH .
	git checkout $DPDK_COMMIT

	# enable verbose
	if [[ -n $VERBOSE ]]; then
		verbose='-v'
	fi

	# Select cross file based on platform arg
	if [ "$plat"  == "cn10k" ] ; then
		DPDK_CROSS_FILE="--cross config/arm/arm64_cn10k_linux_arm_gcc"
	else if [ "$plat"  == "cn9k" ] ; then
		DPDK_CROSS_FILE="--cross config/arm/arm64_cn9k_linux_gcc"
	fi
	fi

	cd $DPDK_DIR
	meson $BUILD_DPDK_DIR-$plat --prefix $EP_DEPS_INSTALL_DIR $DPDK_CROSS_FILE \
		--default-library=static -Denable_iova_as_pa=false

	ninja -C $BUILD_DPDK_DIR-$plat -j $MAKE_J $verbose
	ninja -C $BUILD_DPDK_DIR-$plat -j $MAKE_J $verbose install
}

function build_dpdk_host() {
	local verbose=
	local saved_pkg_config_libdir="${PKG_CONFIG_LIBDIR-}"
	local saved_pkg_config_path="${PKG_CONFIG_PATH-}"

	if [[ "$DEPS_TO_BUILD" != *"dpdk"* ]]; then
		return
	fi

	# Host DPDK build must not consume ARM pkg-config metadata/libraries.
	unset PKG_CONFIG_LIBDIR
	unset PKG_CONFIG_PATH

	# Cloning the repositories
	mkdir -p $HOST_DPDK_DIR
	cd $HOST_DPDK_DIR
	git clone https://github.com/DPDK/dpdk.git --single-branch --branch $HOST_DPDK_BRANCH .

	# enable verbose
	if [[ -n $VERBOSE ]]; then
		verbose='-v'
	fi

	cd $HOST_DPDK_DIR
	meson $HOST_BUILD_DPDK_DIR --prefix $HOST_DEPS_INSTALL_DIR --default-library=static \

	ninja -C $HOST_BUILD_DPDK_DIR -j $MAKE_J $verbose
	ninja -C $HOST_BUILD_DPDK_DIR -j $MAKE_J $verbose install

	# Restore cross/target pkg-config environment for subsequent ARM deps.
	if [[ -n "$saved_pkg_config_libdir" ]]; then
		export PKG_CONFIG_LIBDIR="$saved_pkg_config_libdir"
	fi

	if [[ -n "$saved_pkg_config_path" ]]; then
		export PKG_CONFIG_PATH="$saved_pkg_config_path"
	fi
}

function build_libconfig() {
	local libconfig_is_enabled=1
	if [[ "$DEPS_TO_BUILD" != *"libconfig"* ]]; then
		return
	fi

	if ($PKGCONFIG --exists libconfig); then
		echo "libconfig found with pkg-config. Skipping..."
		libconfig_is_enabled=0
	fi

	if [ $libconfig_is_enabled == 1 ]; then
		mkdir -p $LIBCONFIG_BUILD_DIR
		cd $LIBCONFIG_BUILD_DIR
		if [ ! -f $LIBCONFIG_TARBALL.tar.gz ]; then
			fetch_dep https://hyperrealm.github.io/libconfig/dist/$LIBCONFIG_TARBALL.tar.gz
		fi
		tar xvf $LIBCONFIG_TARBALL.tar.gz --strip-components=1
		set -x
		./configure --host=${CROSS_COMPILE} --prefix=$LIBCONFIG_PREFIX_DIR --enable-static=no
		make;
		make install;
	fi
}
function build_libnl() {
	local libnl_is_enabled=1
	if [[ "$DEPS_TO_BUILD" != *"libnl"* ]]; then
		return
	fi

	if ($PKGCONFIG --modversion libnl-xfrm-3.0); then
		echo "libnl-xfrm-3.0 found with $PKGCONFIG($PKG_CONFIG_LIBDIR). Skipping..."
		if ($PKGCONFIG --modversion libnl-route-3.0); then
			echo "libnl-route-3.0 found with $PKGCONFIG($PKG_CONFIG_LIBDIR). Skipping..."
			if ($PKGCONFIG --modversion libnl-3.0); then
				echo "libnl-3.0 found with $PKGCONFIG($PKG_CONFIG_LIBDIR). Skipping..."
				libnl_is_enabled=0
			fi
		fi
	fi

	if [ $libnl_is_enabled == 1 ]; then
		mkdir -p $LIBNL_BUILD_DIR
		cd $LIBNL_BUILD_DIR
		if [ ! -f $LIBNL_TARBALL.tar.gz ]; then
			fetch_dep https://github.com/thom311/libnl/releases/download/libnl3_7_0/$LIBNL_TARBALL.tar.gz
		fi
		tar xvf $LIBNL_TARBALL.tar.gz --strip-components=1
		./configure --host=${CROSS_COMPILE} --prefix=$LIBNL_PREFIX_DIR --enable-static=no
		make;
		make install;
		set +x
		if ($PKGCONFIG --modversion libnl-xfrm-3.0); then
			echo "libnl-xfrm-3.0 installed."
			if ($PKGCONFIG --modversion libnl-route-3.0); then
				echo "libnl-route-3.0 installed."
				if ($PKGCONFIG --modversion libnl-3.0); then
					echo "libnl-3.0 installed."
					return 0
				fi
			fi
		fi
		return 1
	fi
}

function build_grpc_host() {
	if [[ "$DEPS_TO_BUILD" != *"grpc"* ]]; then
		return 1
	fi

	# Cloning the repository
	if [[ ! -d $GRPC_SRC_DIR ]]; then
		mkdir -p $GRPC_SRC_DIR
		cd $GRPC_SRC_DIR
		git clone --recurse-submodules -b $GRPC_SRC_TAG --depth 1 --shallow-submodules $GRPC_SRC_URL .
	fi

	#compile_grpc_host
	GRPC_CMAKE_CMD_VERBOSE=
	if [[ -n $VERBOSE ]]; then
		GRPC_CMAKE_CMD_VERBOSE="-DCMAKE_VERBOSE_MAKEFILE:BOOL=ON"
	fi

	if [[ ! -d $GRPC_HOST_BUILD_DIR ]]; then
		mkdir -p $GRPC_HOST_BUILD_DIR
		pushd $GRPC_HOST_BUILD_DIR
		GRPC_HOST_CMAKE_CMD="-DCMAKE_CXX_STANDARD=$GRPC_CXX_ABI_STANDARD
			-DCMAKE_INSTALL_PREFIX=$GRPC_HOST_INSTALL_PREFIX \
			-DCMAKE_BUILD_TYPE=Release -DgRPC_INSTALL=ON -DgRPC_BUILD_TESTS=OFF \
			-DgRPC_SSL_PROVIDER=module -DBUILD_SHARED_LIBS=ON"
		cmake $GRPC_HOST_CMAKE_CMD $GRPC_CMAKE_CMD_VERBOSE $GRPC_SRC_DIR
		make -j $MAKE_J
		make install
		popd
	fi
	return 0
}

function build_grpc() {
	if [[ "$DEPS_TO_BUILD" != *"grpc"* ]]; then
		return
	fi

	build_grpc_host || return

	if [ "$GRPC_CXX_CROSS_COMPILER" = "" ]; then
		if command -v ${CROSS_COMPILE}-g++ >/dev/null 2>&1; then
			GRPC_CXX_CROSS_COMPILER=${CROSS_COMPILE}-g++
		elif command -v aarch64-linux-gnu-g++ >/dev/null 2>&1; then
			GRPC_CXX_CROSS_COMPILER=aarch64-linux-gnu-g++
		else
			echo "ERROR: Unable to find suitable aarch64 cross compiler"
			return 1
		fi
	fi
	if [ "$GRPC_C_CROSS_COMPILER" = "" ]; then
		if command -v ${CROSS_COMPILE}-gcc >/dev/null 2>&1; then
			GRPC_C_CROSS_COMPILER=${CROSS_COMPILE}-gcc
		else
			echo "ERROR: Unable to find suitable aarch64 cross compiler"
			return 1
		fi
	fi

	echo "Using cross compiler: $GRPC_CXX_CROSS_COMPILER / $GRPC_C_CROSS_COMPILER"

	GRPC_CROSS_COMPILER_PATH=$(dirname $(which $GRPC_CXX_CROSS_COMPILER))

	#Create cmake cross fille
	echo "set(CMAKE_SYSTEM_NAME Linux)" >$GRPC_CMAKE_CROSS_FILE
	echo "set(CMAKE_SYSTEM_PROCESSOR aarch64)" >>$GRPC_CMAKE_CROSS_FILE
	echo "set(CMAKE_C_COMPILER $GRPC_CROSS_COMPILER_PATH/$GRPC_C_CROSS_COMPILER)" >> $GRPC_CMAKE_CROSS_FILE
	echo "set(CMAKE_CXX_COMPILER $GRPC_CROSS_COMPILER_PATH/$GRPC_CXX_CROSS_COMPILER)" >> $GRPC_CMAKE_CROSS_FILE
	echo "set(CMAKE_CXX_STANDARD $GRPC_CXX_ABI_STANDARD)" >> $GRPC_CMAKE_CROSS_FILE
	if [[ "$GRPC_C_CROSS_COMPILER" == *"marvell"* ]]; then
		echo "set(CMAKE_SYSROOT $GRPC_CROSS_COMPILER_PATH/../${CROSS_COMPILE}/sys-root)" >> $GRPC_CMAKE_CROSS_FILE
	else
		echo "set(CMAKE_SYSROOT $GRPC_CROSS_COMPILER_PATH/../${CROSS_COMPILE}/libc)" >> $GRPC_CMAKE_CROSS_FILE
	fi
	if [[ -n $VERBOSE ]]; then
		echo "set(CMAKE_VERBOSE_MAKEFILE ON CACHE BOOL \"Verbose Makefile\" FORCE)" \
			>> $GRPC_CMAKE_CROSS_FILE
	fi
	echo "set(ENV{PATH} \"$GRPC_HOST_INSTALL_PREFIX/bin:\$ENV{PATH}\")" >> $GRPC_CMAKE_CROSS_FILE
	echo "set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)" >>$GRPC_CMAKE_CROSS_FILE
	echo "set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)" >>$GRPC_CMAKE_CROSS_FILE
	echo "set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)" >>$GRPC_CMAKE_CROSS_FILE
	echo "set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)" >>$GRPC_CMAKE_CROSS_FILE

	export LD_LIBRARY_PATH=${LD_LIBRARY_PATH:-}:$GRPC_HOST_INSTALL_PREFIX/lib

	#Compile grpc for octeon
	if [[ ! -d $GRPC_OCT_BUILD_DIR ]]; then
		mkdir -p $GRPC_OCT_BUILD_DIR
		pushd $GRPC_OCT_BUILD_DIR
		GRPC_OCT_CMAKE_CMD="-DCMAKE_TOOLCHAIN_FILE=$GRPC_CMAKE_CROSS_FILE \
			-DCMAKE_CXX_STANDARD=$GRPC_CXX_ABI_STANDARD \
			-DCMAKE_INSTALL_PREFIX=$GRPC_OCT_INSTALL_PREFIX \
			-DCMAKE_BUILD_TYPE=Release -DgRPC_SSL_PROVIDER=module"
		cmake $GRPC_OCT_CMAKE_CMD $GRPC_SRC_DIR
		make -j $MAKE_J
		make install
		popd
	fi
}

function build_liboqs() {
	if [[ "$DEPS_TO_BUILD" != *"liboqs"* ]]; then
		return
	fi

	# Cloning the repository
	if [[ ! -d $LIBOQS_SRC_DIR ]]; then
		mkdir -p $LIBOQS_SRC_DIR
		cd $LIBOQS_SRC_DIR
		git clone -b $LIBOQS_SRC_TAG --depth 1 $LIBOQS_SRC_URL .
	fi

	if [ "$LIBOQS_CXX_CROSS_COMPILER" = "" ]; then
		if command -v ${CROSS_COMPILE}-g++ >/dev/null 2>&1; then
			LIBOQS_CXX_CROSS_COMPILER=${CROSS_COMPILE}-g++
		elif command -v aarch64-linux-gnu-g++ >/dev/null 2>&1; then
			LIBOQS_CXX_CROSS_COMPILER=aarch64-linux-gnu-g++
		else
			echo "ERROR: Unable to find suitable aarch64 cross compiler"
			return 1
		fi
	fi
	if [ "$LIBOQS_C_CROSS_COMPILER" = "" ]; then
		if command -v ${CROSS_COMPILE}-gcc >/dev/null 2>&1; then
			LIBOQS_C_CROSS_COMPILER=${CROSS_COMPILE}-gcc
		elif command -v aarch64-linux-gnu-gcc >/dev/null 2>&1; then
			LIBOQS_C_CROSS_COMPILER=aarch64-linux-gnu-gcc
		else
			echo "ERROR: Unable to find suitable aarch64 cross compiler"
			return 1
		fi
	fi

	echo "Using cross compiler: $LIBOQS_CXX_CROSS_COMPILER / $LIBOQS_C_CROSS_COMPILER"

	LIBOQS_CROSS_COMPILER_PATH=$(dirname $(which $LIBOQS_CXX_CROSS_COMPILER))

	# Create cmake cross file
	echo "set(CMAKE_SYSTEM_NAME Linux)" >$LIBOQS_CMAKE_CROSS_FILE
	echo "set(CMAKE_SYSTEM_PROCESSOR aarch64)" >>$LIBOQS_CMAKE_CROSS_FILE
	echo "set(CMAKE_C_COMPILER $LIBOQS_CROSS_COMPILER_PATH/$LIBOQS_C_CROSS_COMPILER)" \
		>> $LIBOQS_CMAKE_CROSS_FILE
	echo "set(CMAKE_CXX_COMPILER $LIBOQS_CROSS_COMPILER_PATH/$LIBOQS_CXX_CROSS_COMPILER)" \
		>> $LIBOQS_CMAKE_CROSS_FILE
	echo "set(CMAKE_CXX_STANDARD $LIBOQS_CXX_ABI_STANDARD)" >> $LIBOQS_CMAKE_CROSS_FILE
	if [[ "$LIBOQS_C_CROSS_COMPILER" == *"marvell"* ]]; then
		echo "set(CMAKE_SYSROOT $LIBOQS_CROSS_COMPILER_PATH/../${CROSS_COMPILE}/sys-root)" \
		>> $LIBOQS_CMAKE_CROSS_FILE
	else
		echo "set(CMAKE_SYSROOT $LIBOQS_CROSS_COMPILER_PATH/../${CROSS_COMPILE}/libc)" \
		>> $LIBOQS_CMAKE_CROSS_FILE
	fi
	if [[ -n $VERBOSE ]]; then
		echo "set(CMAKE_VERBOSE_MAKEFILE ON CACHE BOOL \"Verbose Makefile\" FORCE)" \
		>> $LIBOQS_CMAKE_CROSS_FILE
	fi
	echo "set(ENV{PATH} \"$LIBOQS_HOST_INSTALL_PREFIX/bin:\$ENV{PATH}\")" \
		>> $LIBOQS_CMAKE_CROSS_FILE
	echo "set(ENV{PKG_CONFIG_PATH} \"$LIBOQS_HOST_INSTALL_PREFIX/lib/pkgconfig/:\$ENV{PKG_CONFIG_PATH}\")" \
		>> $LIBOQS_CMAKE_CROSS_FILE
	echo "set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)" >> $LIBOQS_CMAKE_CROSS_FILE
	echo "set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)" >> $LIBOQS_CMAKE_CROSS_FILE
	echo "set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)" >> $LIBOQS_CMAKE_CROSS_FILE
	echo "set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)" >> $LIBOQS_CMAKE_CROSS_FILE

	# Compile liboqs for octeon
	if [[ ! -d $LIBOQS_OCT_BUILD_DIR ]]; then
		mkdir -p $LIBOQS_OCT_BUILD_DIR
		pushd $LIBOQS_OCT_BUILD_DIR
		LIBOQS_OCT_CMAKE_CMD="-DCMAKE_TOOLCHAIN_FILE=$LIBOQS_CMAKE_CROSS_FILE \
			-DCMAKE_CXX_STANDARD=$LIBOQS_CXX_ABI_STANDARD \
			-DCMAKE_INSTALL_PREFIX=$LIBOQS_OCT_INSTALL_PREFIX \
			-DCMAKE_BUILD_TYPE=Release \
			-DBUILD_SHARED_LIBS=ON \
			-DOQS_USE_OPENSSL=OFF \
			-DOQS_DIST_BUILD=ON \
			-GNinja"
		cmake $LIBOQS_OCT_CMAKE_CMD $LIBOQS_SRC_DIR
		ninja -j $MAKE_J
		ninja install
		popd
	fi
	return 0
}

function build_libpcap() {
	local libpcap_is_enabled=1
	if [[ "$DEPS_TO_BUILD" != *"libpcap"* ]]; then
		return
		mkdir -p $LIBPCAP_BUILD_DIR
	fi

	if [ $libpcap_is_enabled == 1 ]; then
		mkdir -p $LIBPCAP_BUILD_DIR
		cd $LIBPCAP_BUILD_DIR
		git clone https://github.com/the-tcpdump-group/libpcap.git
		cd libpcap
		git checkout master
		./autogen.sh
		./configure --host=${CROSS_COMPILE} --prefix=$LIBPCAP_PREFIX_DIR --without-libnl
		make;
		make install;
			if ($PKGCONFIG --modversion libpcap); then
				echo "libpcap installed."
				return 0
			fi
		return 1
	fi
}

function build_openssl() {
	local openssl_is_enabled=1
	if [[ "$DEPS_TO_BUILD" != *"openssl"* ]]; then
		return
	fi

	if [ $openssl_is_enabled == 1 ]; then
		rm -rf $OPENSSL_BUILD_DIR
		mkdir -p $OPENSSL_BUILD_DIR
		cd $OPENSSL_BUILD_DIR
		git clone --branch OpenSSL_1_1_1-stable --depth 1 \
		https://github.com/openssl/openssl.git
		cd openssl
		./Configure linux-aarch64 shared --cross-compile-prefix=$CROSS_COMPILE- \
			    --prefix=$OPENSSL_PREFIX_DIR --libdir=lib --openssldir=etc/ssl
		make -j $MAKE_J;
		make install;
		if [[ -f "$OPENSSL_PREFIX_DIR/include/openssl/ssl.h" && \
		      -f "$OPENSSL_PREFIX_DIR/lib/libcrypto.so" ]]; then
			echo "OpenSSL (libcrypto) installed."
			return 0
		fi
		return 1
	fi
}

# Building DPDK
build_dpdk $PLAT
build_libnl $@
build_libconfig
build_openssl
build_grpc

# Building DPDK for host
build_dpdk_host

# Building liboqs
build_liboqs

# Building LIBPCAP
build_libpcap
