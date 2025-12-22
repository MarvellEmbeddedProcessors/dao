#!/bin/bash
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2025 Marvell.

# Cleanup function to ensure lock is released
cleanup_lock() {
    if [ -n "$LOCK_FD" ]; then
        logger -t card_mgr_audit "LOCK_RELEASED: pid=$$ operation=app_fallback duration=$(($(date +%s) - START_TIME))"
        flock -u "$LOCK_FD" 2>/dev/null
    fi
}

# Trap to ensure cleanup on exit/signal
trap cleanup_lock EXIT INT TERM

app_fallback() {
    START_TIME=$(date +%s)

    # Acquire exclusive lock to prevent concurrent updates that modify U-Boot environment
    # Lock file descriptor 201 will be held for the entire duration of this function
    exec 201>/var/lock/app_fallback.lock
    LOCK_FD=201

    if ! flock -n 201; then
        echo "Error: Another update or fallback operation is already in progress."
        echo "Please wait for the current operation to complete before trying again."
        logger -t card_mgr_audit "LOCK_BUSY: pid=$$ operation=app_fallback"
        exit 1
    fi

    # Write PID and timestamp to lock file
    echo "$$ $(date +%s)" > /var/lock/app_fallback.lock
    logger -t card_mgr_audit "LOCK_ACQUIRED: pid=$$ operation=app_fallback"

    cmdline=$(cat /proc/cmdline)
    # Check if booted from SPI, if not report error
    if echo "$cmdline" | grep -q "root="; then
        echo "App fallback is supported from failsafe image"
        logger -t card_mgr_audit "APP_FALLBACK_FAILED: pid=$$ reason=not_booted_from_failsafe"
        exit 1
    fi

    app_env=$(fw_printenv -c /etc/fw_mmc_env.config app_env | cut -d'=' -f2)
    if [ -z "$app_env" ]; then
        echo "FAIL: app_env not set"
        exit 1
    fi

    if [ "$app_env" = "p3" ]; then
        new_env="p5"
    elif [ "$app_env" = "p5" ]; then
        new_env="p3"
    else
        echo "FAIL: Unknown app_env value: $app_env"
        exit 1
    fi

    fw_setenv -c /etc/fw_mmc_env.config app_env "$new_env"
    if [ $? -ne 0 ]; then
        echo "FAIL: Could not set app_env to $new_env"
        exit 1
    fi
    echo "app_env switched from $app_env to $new_env"
    exit 0
}

app_fallback
