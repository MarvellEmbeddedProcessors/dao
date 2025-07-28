#!/bin/sh
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2025 Marvell.

mmc_root="/dev/mmcblk0p2"
root_mount="/mnt/new_root"
mmc_app1="/dev/mmcblk0p3"
app1_mount="/mnt/new_app1"
mmc_app2="/dev/mmcblk0p5"
app2_mount="/mnt/new_app2"

unmount_root() {
    umount $root_mount
    rm -rf $root_mount
}

cleanup_root() {
    file=$1
    dir=$2
    # Remove the received file and remove the directory.
    rm -rf $root_mount/$1
    rm -rf $root_mount/$2
    unmount_root
}

update_partition() {
    # Recreate extended and logical partitions.
    # Delete all extended partitions (p4 and above) one by one
    partnums=$(fdisk -l /dev/mmcblk0 | awk '/mmcblk0p[4-9]|mmcblk0p[1-9][0-9]+/ {match($1, /p([0-9]+)$/ , a); if (a[1] >= 4) print a[1]}' | sort -nr)
    fdisk_cmds=""
    for num in $partnums; do
        fdisk_cmds="$fdisk_cmds d\n$num\n"
    done

    fdisk /dev/mmcblk0 <<EOF
$(echo -e "$fdisk_cmds")
w
EOF
    partprobe

    echo "Deleted all extended partitions"
    # Get the end sector of p3 and calculate the start sector for p4
    # fdisk -l output: ... StartLBA EndLBA Sectors ...
    # We want the next sector after p3's end
    p3_end=$(fdisk -l /dev/mmcblk0 | awk '/mmcblk0p3/ {print $5}')
    p4_start=$((p3_end + 1))

    fdisk /dev/mmcblk0 <<EOF
n
e
$p4_start

n

+512M
n

+3G
w
EOF

    partprobe /dev/mmcblk0
    mkfs.ext4 /dev/mmcblk0p5
    mkfs.ext4 /dev/mmcblk0p6
}

update_fw() {
    img_file=$1
    img_dir="${img_file%.tar}"

    # Check for the presence of received file
    if [ ! -f $root_mount/$img_file ]; then
        echo "New image file is not present"
        unmount_root
        exit 1
    fi

    # Remove all the contents except the received file.
    find "$root_mount" -type f ! -name "$img_file" -exec rm -f {} +

    # Untar the received file
    tar --touch -xf $root_mount/$img_file -C $root_mount

    # Update the MMC firmware
    dd if=$root_mount/$img_dir/ls2_d0_mmc_bl_fw.img bs=512 count=32768 of=/dev/mmcblk0

    # Move the Kernel image
    mv $root_mount/$img_dir/Image $root_mount

    # Update the new rootfs
    tar --touch -xf $root_mount/$img_dir/rootfs.tar -C $root_mount

    # Update the application in the app1 partition
    mkdir $app1_mount
    mount $mmc_app1 $app1_mount
    if [ $? -ne 0 ]; then
        echo "Failed to mount app1 partition"
        cleanup_root $img_file $img_dir
        exit 1
    fi
    rm -rf $app1_mount/*
    tar --touch -xf $root_mount/$img_dir/lc_service.tar -C $app1_mount/

    # unmount the app1 and remove the mount point.
    umount $app1_mount
    rm -rf $app1_mount

    update_partition

    # Update the application in the app2 partition
    mkdir $app2_mount
    mount $mmc_app2 $app2_mount
    if [ $? -ne 0 ]; then
        echo "Failed to mount app2 partition"
        cleanup_root $img_file $img_dir
        exit 1
    fi

    rm -rf $app2_mount/*
    tar --touch -xf $root_mount/$img_dir/lc_service.tar -C $app2_mount/

    # unmount the app2 and remove the mount point.
    umount $app2_mount
    rm -rf $app2_mount

    cleanup_root $img_file $img_dir
}

update_fw $1

