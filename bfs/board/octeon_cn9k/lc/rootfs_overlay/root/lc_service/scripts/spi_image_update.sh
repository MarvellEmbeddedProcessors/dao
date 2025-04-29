#!/bin/bash
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2025 Marvell.

kernel_image_size=0xc800000
bootloader_image_size=0x1000000

bootloader_image_offset=0x0
kernel_image_offset=0x1000000
size=0

directory="$1"   # path to the dir
file_update="$2" # kernel/bootloader

kernel="$directory/Image_ramfs"
bootloader="$directory/lc_spi_bl.img"

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
			max_size=$kernel_image_size
			echo "$file: $size bytes"
			break;
		fi
	elif [[ "$file_update" == bootloader ]]; then
		if [ "$file" == "$bootloader" ]; then
			# Print file size in bytes and file name
			size=$(stat -c %s "$file")
			size=$(printf '0x%x\n' $size)
			max_size=$bootloader_image_size
			echo "$file: $size bytes"
			break;
		fi
	fi
done

if [ $(printf "%d\n" "$size") -eq 0 ]; then
	echo "File is EMPTY"
	exit 1
fi

# File should not be bigger than the available space on the flash
if [ $(printf "%d\n" "$size") -gt $(printf "%d\n" "$max_size") ]; then
	echo "File is bigger than the available space  $size   $max_size"
	exit 1
fi

if [[ "$file_update" == kernel ]]; then
	command="mtd_debug erase /dev/mtd0 $kernel_image_offset $kernel_image_size"
	echo "$command"
	eval $command
	command="mtd_debug write /dev/mtd0 $kernel_image_offset $size $file"
	echo "$command"
	eval $command
elif [[ "$file_update" == bootloader ]]; then
	command="mtd_debug erase /dev/mtd0 $bootloader_image_offset $bootloader_image_size"
	echo "$command"
	eval $command
	command="mtd_debug write /dev/mtd0 $bootloader_image_offset $size $file"
	echo "$command"
	eval $command
fi
