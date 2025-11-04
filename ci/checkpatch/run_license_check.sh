#!/bin/bash
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2023 Marvell.

IGNORE_FILES=(
	".checkpatch.conf"
	".clang-format"
	".gitignore"
	".gitreview"
	"DPDK_VERSION"
	"README.md"
	"TODO.txt"
	"VERSION"
	"bfs/README.md"
	"bfs/board/octeon_cn9k/lc/octeon_cn9k_defconfig_extra"
	"bfs/board/octeon_cn9k/lc/rootfs_overlay/root/lc_service/README.md"
	"bfs/board/octeon_cn9k/lc/rootfs_overlay/root/lc_service/config/dma_config.ini"
	"bfs/board/octeon_cn9k/lc/rootfs_overlay/root/lc_service/config/lc_env"
	"bfs/board/octeon_cn9k/lc/rootfs_overlay/etc/fw_mmc_env.config"
	"bfs/board/octeon_cn9k/lc/rootfs_overlay/etc/fw_spi_env.config"
	"bfs/board/octeon_cn9k/lc/rootfs_overlay/etc/image_version"
	"bfs/external.desc"
	"ci/build/env/deps/dpdk.env"
	"ci/checkpatch/checkpatch.conf"
	"ci/checkpatch/checkpatch.pl"
	"ci/checkpatch/const_structs.checkpatch"
	"ci/checkpatch/dictionary.txt"
	"ci/checkpatch/spelling.txt"
	"ci/klocwork/kw_override.h"
	"ci/klocwork/local.kb"
	"doc/guides/_static/tab_logo.jpg"
	"doc/guides/_static/versions.json"
	"tests/ct-func/ct_test.pcap"
)

IGNORE_DIRECTORIES=(
	".github/"
	"ci/build/config/"
	"ci/groovy/"
	"ci/test/dao-test/virtio/l2fwd/pcap/"
	"config/"
	"configs/"
	"doc/guides/_static/css/"
	"doc/guides/_static/demo/"
	"doc/guides/_static/js/"
	"doc/guides/_templates/"
	"doc/guides/applications/img/"
	"doc/guides/contributing/img/"
	"doc/guides/gsg/img/"
	"doc/guides/img/"
	"doc/guides/logo/"
	"doc/guides/platform/img/"
	"doc/guides/prog_guide/img/"
	"doc/guides/tools/img/"
        "doc/guides/white_papers/img"
	"license/"
	"patches/"
	"subprojects/"
)

BSD_LICENSE_FILES=(
	"lib/virtio/spec/virtio_crypto.h"
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
	grep ' SPDX-License-Identifier: Marvell-MIT$' $F &> /dev/null
	C1=$?
	grep ' Copyright (c) 202[[:digit:]] Marvell.$' $F &> /dev/null
	C2=$?
	if [[ $C1 == "0" ]] || [[ $C2 == "0" ]]; then
		echo -n " ... OK"
		continue
	fi

	# Proprietary License Check
	grep ' SPDX-License-Identifier: Marvell-Proprietary$' $F &> /dev/null
	C1=$?
	grep ' Copyright (c) 202[[:digit:]] Marvell.$' $F &> /dev/null
	C2=$?
	if [[ $C1 == "0" ]] || [[ $C2 == "0" ]]; then
		echo -n " ... OK"
		continue
	fi

	# GPL-2.0 License Check
	grep ' SPDX-License-Identifier: GPL-2.0$' $F &> /dev/null
	C1=$?
	grep ' Copyright (c) 202[[:digit:]] Marvell.$' $F &> /dev/null
	C2=$?
	if [[ $C1 == "0" ]] || [[ $C2 == "0" ]]; then
		echo -n " ... OK"
		continue
	fi

	CHECK_BSD=""
	for B in "${BSD_LICENSE_FILES[@]}"; do
		if [[ $B == $F ]]; then
			CHECK_BSD="1"
			break
		fi
	done

	if [[ $CHECK_BSD == "1" ]]; then
		# BSD-3 License Check
		grep ' SPDX-License-Identifier: BSD-3-Clause$' $F &> /dev/null
		C1=$?
		grep ' Copyright (c) 202[[:digit:]] Marvell.$' $F &> /dev/null
		C2=$?
		if [[ $C1 == "0" ]] || [[ $C2 == "0" ]]; then
			echo -n " ... OK"
			continue
		fi
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
