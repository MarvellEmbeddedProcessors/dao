#!/bin/bash
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2025 Marvell.

size=0

directory="$1"   # path to the dir
file_update="$2" # kernel/bootloader/rootfs

bootloader_image_size=0x1000000

kernel="$directory/Image"
rootfs="$directory/rootfs.tar"
bootloader="$directory/lc_mmc_bl.img"

# Check if the given directory exists
if [ ! -d "$directory" ]; then
	echo "Error: $directory is not a valid directory."
	exit 1
fi

# Get the file size in hex-format
echo "File sizes in directory: $directory"
for file in "$directory"/*; do
	if [[ "$file_update" == kernel ]]; then
		if [ "$file" = "$kernel" ]; then
			# Print file size in bytes and file name
			size=$(stat -c %s "$file")
			size=$(printf '0x%X\n' $size)
			echo "$file: $size bytes"
			break;
		fi
	elif [[ "$file_update" == bootloader ]]; then
		if [ "$file" == "$bootloader" ]; then
			# Print file size in bytes and file name
			size=$(stat -c %s "$file")
			size=$(printf '0x%x\n' $size)
			echo "$file: $size bytes"
			if [ $size -ne $bootloader_image_size ]; then
				exit 1
			fi
			break;
		fi
	elif [[ "$file_update" == rootfs ]]; then
		if [ "$file" = "$rootfs" ]; then
			# Print file size in bytes and file name
			size=$(stat -c %s "$file")
			size=$(printf '0x%X\n' $size)
			echo "$file: $size bytes"
			break;
		fi
	fi
done

if [ $(printf "%d\n" "$size") -eq 0 ]; then
	echo "File is EMPTY"
	exit 1
fi

if [[ "$file_update" == kernel ]]; then
	command="cp $file /Image"
	echo "$command"
	eval $command
elif [[ "$file_update" == rootfs ]]; then
	command="rm -r /lib /lib64 /bin /boot /dev /etc /media /root /linuxrc"
	echo "$command"
	eval $command
	command="rm -r /opt /proc /share /sys /usr /var /run /dev /sbin /libexec"
	echo "$command"
	eval $command
	command="tar -xf $file"
	echo "$command"
	eval $command
elif [[ "$file_update" == bootloader ]]; then
	command="dd if=$file bs=1M count=16 of=/dev/mmcblk0"
	echo "$command"
	eval $command
fi
