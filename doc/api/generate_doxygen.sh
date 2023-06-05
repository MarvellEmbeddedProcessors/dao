#!/bin/sh -e
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2024 Marvell.

DOXYCONF=$1
OUTDIR=$2

OUT_FILE=$(dirname $OUTDIR)/doxygen.out

# run doxygen, capturing all the header files it processed
doxygen ${DOXYCONF} > $OUT_FILE
