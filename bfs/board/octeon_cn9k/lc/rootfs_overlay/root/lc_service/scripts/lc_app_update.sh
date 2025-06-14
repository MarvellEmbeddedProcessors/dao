#!/bin/bash
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2025 Marvell.

CONFIG_FILE="/etc/fw_mmc_env.config"

update_app() {
    app_file="lc_service.tar"
    app_folder="lc_service"

    # Check for the presence of lc_service.tar in /tmp
    if [ ! -f /tmp/$app_file ]; then
        echo "File $app_file not found in /tmp"
        exit 1
    fi

    # Extract the app env
    app_env=$(fw_printenv -c $CONFIG_FILE "app_env" | cut -d'=' -f2)
    if [ $? -ne 0 ]; then
        echo "Error executing fw_printenv"
        exit 1
    fi

    if [ "$app_env" = "p3" ]; then
        new_env="p5"
    elif [ "$app_env" = "p5" ]; then
        new_env="p3"
    fi

    # Mount the new app partition
    new_partition="mmcblk0$new_env"

    mkdir /mnt/new_app
    mount /dev/$new_partition /mnt/new_app
    if [ $? -ne 0 ]; then
        echo "Failed to mount partition" "$new_partition"
        exit 1
    fi

    # Remove the existing app folder and extract the new one
    rm -rf /mnt/new_app/lc_service
    if [ $? -ne 0 ]; then
        echo "Failed to remove folder lc_service"
        exit 1
    fi

    tar -xf /tmp/$app_file -C /mnt/new_app
    if [ $? -ne 0 ]; then
        echo "Failed to untar file $app_file"
        exit 1
    fi

    # Unmount the partition and remove the folder
    umount /mnt/new_app
    if [ $? -ne 0 ]; then
        echo "Failed to unmount new_app"
        exit 1
    fi
    rm -rf /mnt/new_app

    # Remove the received file
    rm -rf /tmp/$app_file

    # Update the uboot env with the new app env
    fw_setenv -c $CONFIG_FILE "app_env" "$new_env"
    if [ $? -ne 0 ]; then
        echo "Failed to set $var"
        exit 1
    fi
    exit 0
}

update_app
