#!/bin/bash
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2025 Marvell.

fw_mount() {
    cmdline=$(cat /proc/cmdline)
    # Check if booted from SPI, if not report error
    if echo "$cmdline" | grep -q "root="; then
        echo "Image update is not supported from mmc"
        exit 1
    fi

   # Mount the mmc root partition
   [ -d /mnt/new_root ] || mkdir /mnt/new_root
   mountpoint -q /mnt/new_root || mount /dev/mmcblk0p2 /mnt/new_root
   if [ $? -ne 0 ]; then
        echo "Failed to mount the mmc root partition"
        exit 1
    fi
}

fw_mount
