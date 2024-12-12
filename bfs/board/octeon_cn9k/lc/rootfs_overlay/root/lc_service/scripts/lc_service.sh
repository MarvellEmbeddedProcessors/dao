#!/bin/sh
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2025 Marvell.

APP_HOME="/root"
SCRIPTS="$APP_HOME/lc_service/scripts"
CFG="$APP_HOME/lc_service/config"

# Setup the env
$SCRIPTS/lc_env_setup.sh
echo "Env set up done ..."

source $CFG/lc_env
echo "ARGUMENT is set to: $ARGUMENT"

if [ "$ARGUMENT" = "run_agent" ]; then
	echo "Starting dao-crypto-agent..."
	$SCRIPTS/lc_crypto_agent.sh
elif [ "$ARGUMENT" = "run_stress_test" ]; then
	echo "Starting stress test..."
	$SCRIPTS/lc_stress_test.sh $NUM_ITR
else
	echo "Exiting the daemon ..."
fi
