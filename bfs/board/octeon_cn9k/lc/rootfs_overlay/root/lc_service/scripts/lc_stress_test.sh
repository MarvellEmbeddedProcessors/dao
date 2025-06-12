#!/bin/sh
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2025 Marvell.

APP_HOME=$1
BIN="$APP_HOME/bin"
CFG="$APP_HOME/config"

# Check if the number of iterations is provided
if [ -z "$1" ]; then
	echo "Usage: $0 <number_of_iterations>"
	exit 1
fi

iterations=$2
i=1

while [ $i -le $iterations ]; do
	echo "Iteration $i"

	# Launch application 1
	$BIN/dpdk-test-crypto-perf -l 0-1 --file-prefix=crypto_asym -a 0002:10:00.1 -- --devtype crypto_cn9k --ptest throughput --optype modex  --pool-sz 32768 --total-ops 40000000 --burst-sz 32 &
        pid1=$!

	# Launch application 2
	$BIN/dpdk-test-crypto-perf -l 2-6 --file-prefix=crypto_sym -a 0002:10:00.2 -- --devtype crypto_cn9k --ptest throughput --optype cipher-only --cipher-algo aes-cbc --pool-sz 32768 --cipher-op encrypt --cipher-key-sz 32 --cipher-iv-sz 16  --buffer-sz 768 --total-ops 100000000 --burst-sz 32 &
	pid2=$!

	# Launch application 3
	$BIN/dpdk-test-dma-perf --config $CFG/dma_config.ini --file-prefix=dma_app -l 7-22 &
	pid3=$!

	# Wait for the first two applications to complete
	wait $pid1
	wait $pid2

	# Kill the third application
	wait $pid3

	echo "First two applications completed, third application killed."
	i=$((i+1))
done
