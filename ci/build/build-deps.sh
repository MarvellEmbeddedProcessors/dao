#!/bin/bash
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2025 Marvell.

set -euo pipefail
shopt -s extglob
#set -x
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

if [ "$#" -lt 3 ]; then
  echo "Syntax: build-deps.sh <build-dir> <git-user> <plat> <deps_to_build> <verbose>"
  exit 1
fi

PLAT=$3
MAKE_J=4
VERBOSE=${5:-}
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
HOST_DPDK_BRANCH="v24.11"
GIT_USER=${2}
ALL_DEPS="dpdk libnl"
DEPS_TO_BUILD=${4:-$ALL_DEPS}
PKGCONFIG=${PKGCONFIG:-aarch64-linux-gnu-pkg-config}

# libnl variables
LIBNL_BUILD_DIR=$BUILD_DEPS_ROOT/libnl
LIBNL_PREFIX_DIR=$EP_DEPS_INSTALL_DIR
LIBNL_INSTALL_DIR=$LIBNL_PREFIX_DIR
LIBNL_TARBALL=libnl-3.7.0

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
	git clone ssh://$GIT_USER@$DPDK_REPO --single-branch --branch $DPDK_BRANCH .
	git checkout $DPDK_COMMIT

	# enable verbose
	if [[ -n $VERBOSE ]]; then
		verbose='-v'
	fi

	# Select cross file based on platform arg
	if [ "$plat"  == "cn10k" ] ; then
		DPDK_CROSS_FILE="--cross config/arm/arm64_cn10k_linux_gcc"
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

	if [[ "$DEPS_TO_BUILD" != *"dpdk"* ]]; then
		return
	fi

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
		./configure --host=aarch64-marvell-linux-gnu --prefix=$LIBNL_PREFIX_DIR --enable-static=no
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

	# Source dpdk env
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
		GRPC_HOST_CMAKE_CMD="-DCMAKE_CXX_STANDARD=$GRPC_CXX_ABI_STANDARD -DCMAKE_INSTALL_PREFIX=$GRPC_HOST_INSTALL_PREFIX \
			-DCMAKE_BUILD_TYPE=Release -DgRPC_INSTALL=ON -DgRPC_BUILD_TESTS=OFF -DgRPC_SSL_PROVIDER=package "
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

	[[ $GRPC_CXX_CROSS_COMPILER='' ]] && GRPC_CXX_CROSS_COMPILER="aarch64-marvell-linux-gnu-g++"
	[[ $GRPC_C_CROSS_COMPILER='' ]] && GRPC_C_CROSS_COMPILER="aarch64-marvell-linux-gnu-gcc"

	if [[ -z $(which $GRPC_CXX_CROSS_COMPILER) ]]; then
		echo "Unable to find $GRPC_CXX_CROSS_COMPILER compiler"
		return
	fi

	if [[ -z $(which $GRPC_C_CROSS_COMPILER) ]]; then
		echo "Unable to find $GRPC_C_CROSS_COMPILER compiler"
		return
	fi

	GRPC_CROSS_COMPILER_PATH=$(dirname $(which $GRPC_CXX_CROSS_COMPILER))

	#Create cmake cross fille
	echo "set(CMAKE_SYSTEM_NAME Linux)" >$GRPC_CMAKE_CROSS_FILE
	echo "set(CMAKE_SYSTEM_PROCESSOR aarch64)" >>$GRPC_CMAKE_CROSS_FILE
	echo "set(CMAKE_C_COMPILER $GRPC_CROSS_COMPILER_PATH/$GRPC_C_CROSS_COMPILER)" >> $GRPC_CMAKE_CROSS_FILE
	echo "set(CMAKE_CXX_COMPILER $GRPC_CROSS_COMPILER_PATH/$GRPC_CXX_CROSS_COMPILER)" >> $GRPC_CMAKE_CROSS_FILE
	echo "set(CMAKE_CXX_STANDARD $GRPC_CXX_ABI_STANDARD)" >> $GRPC_CMAKE_CROSS_FILE
	if [[ "$GRPC_C_CROSS_COMPILER" == *"marvell"* ]]; then
		echo "set(CMAKE_SYSROOT $GRPC_CROSS_COMPILER_PATH/../aarch64-marvell-linux-gnu/sys-root)" >> $GRPC_CMAKE_CROSS_FILE
	fi
	if [[ -n $VERBOSE ]]; then
		echo "set(CMAKE_VERBOSE_MAKEFILE ON CACHE BOOL "Verbose Makefile" FORCE)" >> $GRPC_CMAKE_CROSS_FILE
	fi
	echo "set(ENV{PATH} \"$GRPC_HOST_INSTALL_PREFIX/bin:\$ENV{PATH}\")" >> $GRPC_CMAKE_CROSS_FILE
	echo "set(ENV{PKG_CONFIG_PATH} \"$GRPC_HOST_INSTALL_PREFIX/lib/pkgconfig/:\$ENV{PKG_CONFIG_PATH}\")" >> $GRPC_CMAKE_CROSS_FILE
	echo "set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)" >>$GRPC_CMAKE_CROSS_FILE
	echo "set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)" >>$GRPC_CMAKE_CROSS_FILE
	echo "set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)" >>$GRPC_CMAKE_CROSS_FILE
	echo "set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)" >>$GRPC_CMAKE_CROSS_FILE

	#Compile grpc for octeon
	if [[ ! -d $GRPC_OCT_BUILD_DIR ]]; then
		mkdir -p $GRPC_OCT_BUILD_DIR
		pushd $GRPC_OCT_BUILD_DIR
		GRPC_OCT_CMAKE_CMD="-DCMAKE_TOOLCHAIN_FILE=$GRPC_CMAKE_CROSS_FILE -DCMAKE_CXX_STANDARD=$GRPC_CXX_ABI_STANDARD \
					-DCMAKE_INSTALL_PREFIX=$GRPC_OCT_INSTALL_PREFIX -DCMAKE_BUILD_TYPE=Release"
		cmake $GRPC_OCT_CMAKE_CMD $GRPC_SRC_DIR
		make -j $MAKE_J
		make install
		popd
	fi
}

# Building DPDK
build_dpdk $PLAT
build_libnl $@
build_grpc

# Building DPDK for host
build_dpdk_host
