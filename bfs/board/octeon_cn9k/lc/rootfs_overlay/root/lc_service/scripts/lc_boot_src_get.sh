#!/bin/sh
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2025 Marvell.

boot_src_get() {
    cmdline=$(cat /proc/cmdline)
    # Check if booted from MMC. Return value for the script are as below:
    #   MMC: 1
    #   SPI: 2
    if echo "$cmdline" | grep -q "root="; then
        return 1
    else
        return 2
    fi
}

boot_src_get
