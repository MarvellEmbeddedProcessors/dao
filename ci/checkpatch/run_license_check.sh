#!/bin/bash
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2023 Marvell.

IGNORE_FILES=(
	".checkpatch.conf"
	".gitignore"
	".gitreview"
	"ci/klocwork/kw_override.h"
	"ci/klocwork/local.kb"
	"ci/checkpatch/dictionary.txt"
	"ci/checkpatch/const_structs.checkpatch"
	"ci/checkpatch/spelling.txt"
	"ci/checkpatch/checkpatch.conf"
	"ci/checkpatch/checkpatch.pl"
	".clang-format"
	"doc/_static/css/custom.css"
	"TODO.txt"
	"DPDK_VERSION"
	"VERSION"
	"doc/guides/custom.css"
)

IGNORE_DIRECTORIES=(
	"doc/guides/applications/img/"
	"doc/guides/img/"
	"doc/guides/logo/"
	"doc/guides/prog_guide/img/"
	"patches/"
	"ci/build/config/"
	"ci/groovy/"
	"config/"
	"license/"
	".github/"
)

FAILED=""
IGNORED=""
FILES=$(git ls-files)

for F in $FILES; do
	IGNORE=""
	if [[ ! -f $F ]]; then
		IGNORE="Skip Deleted File"
		echo -n "Skipping Deleted File $F"
		continue
	fi
	for ID in "${IGNORE_DIRECTORIES[@]}"; do
		if echo "$F" | grep "$ID" > /dev/null; then
			IGNORE="Skip Directory $ID"
			break
		fi
	done
	if [[ $IGNORE == "" ]]; then
		for IF in "${IGNORE_FILES[@]}"; do
			if [[ $IF == $F ]]; then
				IGNORE="Ignore"
				break
			fi
		done
	fi

	echo
	if [[ $IGNORE != "" ]]; then
		IGNORED+="$F\n"
		echo -n "Checking $F ... $IGNORE"
		continue
	fi

	echo -n "Checking $F"
	# MIT License Check
	grep ' SPDX-License-Identifier: Marvell-MIT$' $F 2>&1 >/dev/null
	C1=$?
	grep ' Copyright (c) 202[[:digit:]] Marvell.$' $F 2>&1 >/dev/null
	C2=$?
	if [[ $C1 == "0" ]] || [[ $C2 == "0" ]]; then
		echo -n " ... OK"
		continue
	fi

	# Proprietary License Check
	grep ' SPDX-License-Identifier: Marvell-Proprietary$' $F 2>&1 >/dev/null
	C1=$?
	grep ' Copyright (c) 202[[:digit:]] Marvell.$' $F 2>&1 >/dev/null
	C2=$?
	if [[ $C1 == "0" ]] || [[ $C2 == "0" ]]; then
		echo -n " ... OK"
		continue
	fi

	# GPL-2.0 License Check
	grep ' SPDX-License-Identifier: GPL-2.0$' $F 2>&1 >/dev/null
	C1=$?
	grep ' Copyright (c) 202[[:digit:]] Marvell.$' $F 2>&1 >/dev/null
	C2=$?
	if [[ $C1 == "0" ]] || [[ $C2 == "0" ]]; then
		echo -n " ... OK"
		continue
	fi

	FAILED+="$F\n"
	echo -n " ... FAIL"
done

if [[ $FAILED != "" ]]; then
	echo -e "\n================================"
	echo -e "License Check Failed for \n$FAILED"
	echo "================================"
	exit 1
else
	echo -e "\n================================"
	echo "License Check Passed"
	echo "================================"
fi
