#!/bin/sh
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2025 Marvell.

APP_HOME=$1
BIN="$APP_HOME/bin"

function run_crypto_agent() {
	$BIN/dao-crypto-agent
}

run_crypto_agent
