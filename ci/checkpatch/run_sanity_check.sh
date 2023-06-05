#!/bin/bash
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2024 Marvell.

NONCIFILES=$(git show HEAD --stat=10000 --oneline --name-only | tail -n +2 | grep -v "^ci/")
CIFILES=$(git show HEAD --stat=10000 --oneline --name-only | tail -n +2 | grep "^ci/")

set -xe

if [[ $CIFILES != "" && $NONCIFILES != "" ]]; then
	echo "Changes in ci/ directory should be done in a separate commit"
	exit 1
fi
