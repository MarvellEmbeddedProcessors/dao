#!/bin/sh
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2025 Marvell.

update_failsafe() {
    img_file=$1
    expected_chksum=$2

   cmdline=$(cat /proc/cmdline)
    # Allow update only if booted from SPI (root= present)
    if ! echo "$cmdline" | grep -q "root="; then
        echo "Failsafe image update is not supported when not booted from SPI"
        exit 1
    fi

    # Check if file exists
    if [ ! -f "/tmp/$img_file" ]; then
        echo "Error: File $img_file does not exist in /tmp."
        exit 1
    fi

    # Calculate SHA256 checksum
    actual_chksum=$(sha256sum "/tmp/$img_file" | awk '{print $1}')

    if [ "$expected_chksum" != "$actual_chksum" ]; then
        echo "Checksum mismatch."
        exit 1
    else
        echo "Checksum matched."
    fi


    # Backup complete U-Boot environment
    fw_printenv -c /etc/fw_mmc_env.config > /tmp/mmc_env_backup.txt


    dd if=/tmp/$img_file bs=1M count=160 of=/dev/mtd0

    # Restore complete U-Boot environment
    fw_setenv -c /etc/fw_mmc_env.config -s /tmp/mmc_env_backup.txt

    rm /tmp/$img_file
    rm /tmp/mmc_env_backup.txt
}

update_failsafe $1 $2

