#!/bin/sh
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2025 Marvell.

APP_HOME=$1
SCRIPTS="$APP_HOME/scripts"
CFG="$APP_HOME/config"

# Logging helpers (merged from former lc_logging.sh)
LOG_MAX_BYTES=${LOG_MAX_BYTES:-10485760}
LOG_TAIL_BYTES=${LOG_TAIL_BYTES:-8388608}
LOG_DIR_BASE=${LOG_DIR_BASE:-/mnt/log}

ensure_log_dir() { mkdir -p "$LOG_DIR_BASE"; }

# Detect MMC boot by examining /proc/cmdline root= token; returns 0 (true) if MMC.
is_mmc_boot() {
    CMDLINE=$(cat /proc/cmdline 2>/dev/null)
    echo "$CMDLINE" | grep -q 'root=/dev/mmcblk'
}

start_logged_process() {
    _LOG_NAME=$1; shift
    ensure_log_dir
    _LOG_FILE="$LOG_DIR_BASE/$_LOG_NAME"
    if [ -f "$_LOG_FILE" ]; then
        _SZ=$(wc -c < "$_LOG_FILE" 2>/dev/null || echo 0)
        [ "$_SZ" -gt "$LOG_MAX_BYTES" ] && : > "$_LOG_FILE"
    fi
    echo "$(date -Iseconds) [launcher] starting $_LOG_NAME -> $*" >> "$_LOG_FILE"
    "$@" >> "$_LOG_FILE" 2>&1 &
    _PID=$!
    echo "$_PID"
    (
        while kill -0 $_PID 2>/dev/null; do
            if [ -f "$_LOG_FILE" ]; then
                _CSZ=$(wc -c < "$_LOG_FILE" 2>/dev/null || echo 0)
                if [ "$_CSZ" -gt "$LOG_MAX_BYTES" ]; then
                    _TMPF="${_LOG_FILE}.tmp.$$"
                    tail -c "$LOG_TAIL_BYTES" "$_LOG_FILE" > "$_TMPF" 2>/dev/null && mv "$_TMPF" "$_LOG_FILE"
                    echo "$(date -Iseconds) [log-rotate] truncated log (was ${_CSZ} bytes)" >> "$_LOG_FILE"
                fi
            fi
            sleep 5
        done
    ) &
}

launch_crypto_agent() {
    _APP_HOME=$1
    if is_mmc_boot; then
        AGENT_PID=$(start_logged_process \
            crypto_agent.log \
            "$SCRIPTS/lc_crypto_agent.sh" \
            "$_APP_HOME")
        echo "Crypto agent PID $AGENT_PID (logs: /mnt/log/crypto_agent.log)"
    else
        "$SCRIPTS/lc_crypto_agent.sh" "$_APP_HOME" &
        AGENT_PID=$!
        echo "Crypto agent PID $AGENT_PID (no persistent log; non-MMC boot)"
    fi
}

launch_stress_test() {
    _APP_HOME=$1; shift; _ITR=$1
    if is_mmc_boot; then
        STRESS_PID=$(start_logged_process \
            crypto_stress_test.log \
            "$SCRIPTS/lc_stress_test.sh" \
            "$_APP_HOME" \
            "$_ITR")
        echo "Stress test PID $STRESS_PID (logs: /mnt/log/crypto_stress_test.log)"
    else
        "$SCRIPTS/lc_stress_test.sh" "$_APP_HOME" "$_ITR" &
        STRESS_PID=$!
        echo "Stress test PID $STRESS_PID (no persistent log; non-MMC boot)"
    fi
}

# Setup the env
$SCRIPTS/lc_env_setup.sh $APP_HOME
echo "Env set up done ..."

source $CFG/lc_env
echo "ARGUMENT is set to: $ARGUMENT"

if [ "$ARGUMENT" = "run_agent" ]; then
    echo "Starting dao-crypto-agent..."; launch_crypto_agent "$APP_HOME"
elif [ "$ARGUMENT" = "run_stress_test" ]; then
    echo "Starting stress test..."; launch_stress_test "$APP_HOME" "$NUM_ITR"
else
    echo "Exiting the daemon ..."
fi
