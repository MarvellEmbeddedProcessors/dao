#!/bin/sh
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2025 Marvell.

boot_src_get() {
    # Return codes expected by gRPC service / client:
    #   0  -> UNSUPPORTED (crypto-agent does not support boot source detection)
    #   2  -> SCRIPT FAILURE (this script missing / cannot read required data)
    #   11 -> MMC
    #   12 -> SPI

    if [ ! -r /proc/cmdline ]; then
        return 2
    fi

    cmdline=$(cat /proc/cmdline 2>/dev/null)
    if [ -z "$cmdline" ]; then
        return 2
    fi

    # Heuristic: presence of a root= argument implies MMC (main) boot.
    if echo "$cmdline" | grep -q "root="; then
        return 11
    else
        return 12
    fi
}

boot_src_get
