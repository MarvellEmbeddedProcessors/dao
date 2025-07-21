#!/bin/bash
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2025 Marvell.

app_fallback() {
    cmdline=$(cat /proc/cmdline)
    # Check if booted from SPI, if not report error
    if echo "$cmdline" | grep -q "root="; then
        echo "App fallback is supported from failsafe image"
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
