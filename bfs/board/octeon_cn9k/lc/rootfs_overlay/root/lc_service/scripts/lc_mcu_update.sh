#!/bin/bash
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2025 Marvell.

file_dir="/tmp"
file_name="lcmcu"

update_mcu() {
    img_file=$1

    mkdir $file_dir/$file_name
    tar --touch -xf $file_dir/$img_file -C $file_dir/$file_name
    cd $file_dir/$file_name
    sh mcu_load_script.sh image ./session/
    cd $file_dir
    rm -r $file_dir/$file_name
    rm -r $file_dir/$img_file
}

update_mcu $1


