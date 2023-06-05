#!/bin/bash
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2023 Marvell.

set -e

PROJECT_ROOT=${PROJECT_ROOT:-$PWD}
cd $PROJECT_ROOT
export CXK_CHECKPATCH_CODESPELL=$PROJECT_ROOT/ci/checkpatch/dictionary.txt
export CXK_CHECKPATCH_PATH=$PROJECT_ROOT/ci/checkpatch/checkpatch.pl
git format-patch -n1 -s -q -o patch
./ci/checkpatch/checkpatch.pl patch/*
