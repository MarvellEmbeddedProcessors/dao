#!/bin/bash
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2023 Marvell.

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
DEPS_ENV=$(realpath ci/build/env/deps)
DPDK_DIR=$BUILD_DEPS_ROOT/dpdk
DPDK_ENV=$DEPS_ENV/dpdk.env
BUILD_DPDK_DIR=$DPDK_DIR/build
PREFIX_DPDK_DIR=$DPDK_DIR/out
PKG_CACHE_DIR=${PKG_CACHE_DIR:-}
GIT_USER=${2}
ALL_DEPS="dpdk"
DEPS_TO_BUILD=${4:-$ALL_DEPS}
if [[ $DEPS_TO_BUILD == "all" ]]; then
	DEPS_TO_BUILD=$ALL_DEPS
fi

# DPDK
function clone_dpdk() {
	# Source dpdk env
	mkdir -p $DPDK_DIR
	cd $DPDK_DIR
	git clone ssh://$GIT_USER@$DPDK_REPO --single-branch --branch $DPDK_BRANCH .
	git checkout $DPDK_COMMIT
}

function build_dpdk() {
	set -x
	local plat=$1
	local verbose=

	if [[ "$DEPS_TO_BUILD" != *"dpdk"* ]]; then
		return
	fi

	# Source dpdk env
	source $DPDK_ENV

	# Cloning the repositories
	clone_dpdk

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
	meson $BUILD_DPDK_DIR-$plat --prefix $DEPS_INSTALL_DIR $DPDK_CROSS_FILE --default-library=static \

	ninja -C $BUILD_DPDK_DIR-$plat -j $MAKE_J $verbose
	ninja -C $BUILD_DPDK_DIR-$plat -j $MAKE_J $verbose install
	set +x
}

# Building DPDK
build_dpdk $PLAT
