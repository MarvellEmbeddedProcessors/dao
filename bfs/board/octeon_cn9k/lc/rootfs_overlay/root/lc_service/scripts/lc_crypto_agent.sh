#!/bin/sh
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2025 Marvell.

APP_HOME="/root"
BIN="$APP_HOME/lc_service/bin"

function run_crypto_agent() {
	$BIN/dao-crypto-agent
}

run_crypto_agent
