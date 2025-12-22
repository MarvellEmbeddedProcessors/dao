#!/bin/sh
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2025 Marvell.

# Global variable for heartbeat PID
HEARTBEAT_PID=""

# Stop heartbeat process cleanly
stop_heartbeat() {
    if [ -n "$HEARTBEAT_PID" ] && [ "$HEARTBEAT_PID" -gt 0 ]; then
        # Send TERM signal and wait for clean exit
        kill -TERM "$HEARTBEAT_PID" 2>/dev/null
 
        # Wait up to 2 seconds for process to exit
        local count=0
        while [ $count -lt 20 ]; do
            if ! kill -0 "$HEARTBEAT_PID" 2>/dev/null; then
                # Process has exited
                break
            fi
            usleep 100000  # 100ms
            count=$((count + 1))
        done

        # If still alive, force kill
        if kill -0 "$HEARTBEAT_PID" 2>/dev/null; then
            kill -9 "$HEARTBEAT_PID" 2>/dev/null
        fi

        # Wait for zombie cleanup
        wait "$HEARTBEAT_PID" 2>/dev/null
        HEARTBEAT_PID=""
    fi
}

# Cleanup function to ensure lock is released and heartbeat stopped
cleanup_lock() {
    # Stop heartbeat first
    stop_heartbeat

    # Release lock
    if [ -n "$LOCK_FD" ]; then
        DURATION=$(($(date +%s) - START_TIME))
        logger -t card_mgr_audit "LOCK_RELEASED: pid=$$ operation=failsafe_update duration=$DURATION"
        flock -u "$LOCK_FD" 2>/dev/null
    fi
}

# Trap to ensure cleanup on exit/signal
trap cleanup_lock EXIT INT TERM

# Background heartbeat process to update lock timestamp
# Exits when lock file is removed or on TERM signal
heartbeat() {
    # Set up trap to exit cleanly on TERM signal
    trap 'exit 0' TERM

    while true; do
        sleep 30
        if [ -f /var/lock/failsafe_update.lock ]; then
            echo "$$ $(date +%s)" > /var/lock/failsafe_update.lock
        else
            # Lock file removed, exit cleanly
            exit 0
        fi
    done
}

update_failsafe() {
    img_file=$1
    expected_chksum=$2
    START_TIME=$(date +%s)

    # Acquire exclusive lock to prevent concurrent failsafe updates
    # Lock file descriptor 200 will be held for the entire duration of this function
    exec 200>/var/lock/failsafe_update.lock
    LOCK_FD=200

    if ! flock -n 200; then
        echo "Error: Another failsafe update operation is already in progress."
        echo "Please wait for the current update to complete before trying again."
        logger -t card_mgr_audit "LOCK_BUSY: pid=$$ operation=failsafe_update"
        exit 1
    fi

    # Write PID and timestamp to lock file
    echo "$$ $(date +%s)" > /var/lock/failsafe_update.lock
    logger -t card_mgr_audit "LOCK_ACQUIRED: pid=$$ operation=failsafe_update file=$img_file"

    # Start heartbeat in background
    heartbeat &
    HEARTBEAT_PID=$!

   cmdline=$(cat /proc/cmdline)
    # Allow update only if booted from SPI (root= present)
    if ! echo "$cmdline" | grep -q "root="; then
        echo "Failsafe image update is not supported when not booted from SPI"
        logger -t card_mgr_audit "FAILSAFE_UPDATE_FAILED: pid=$$ reason=not_booted_from_spi"
        exit 1
    fi

    # Check if file exists
    if [ ! -f "/tmp/$img_file" ]; then
        echo "Error: File $img_file does not exist in /tmp."
        logger -t card_mgr_audit "FAILSAFE_UPDATE_FAILED: pid=$$ reason=file_not_found file=$img_file"
        exit 1
    fi

    # Calculate SHA256 checksum
    actual_chksum=$(sha256sum "/tmp/$img_file" | awk '{print $1}')

    if [ "$expected_chksum" != "$actual_chksum" ]; then
        echo "Checksum mismatch."
        rm /tmp/$img_file
        logger -t card_mgr_audit "FAILSAFE_UPDATE_FAILED: pid=$$ reason=checksum_mismatch expected=$expected_chksum actual=$actual_chksum"
        exit 1
    else
        echo "Checksum matched."
        logger -t card_mgr_audit "FAILSAFE_UPDATE_CHECKSUM: pid=$$ status=verified checksum=$actual_chksum"
    fi


    # Backup complete U-Boot environment
    fw_printenv -c /etc/fw_mmc_env.config > /tmp/mmc_env_backup.txt
    logger -t card_mgr_audit "FAILSAFE_UPDATE_BACKUP: pid=$$ status=uboot_env_backed_up"

    file_size=$(stat -c %s "/tmp/$img_file")
    logger -t card_mgr_audit "FAILSAFE_UPDATE_WRITE: pid=$$ status=starting size=$file_size"

    mtd_debug erase /dev/mtd0 0 $file_size
    mtd_debug write /dev/mtd0 0  $file_size "/tmp/$img_file"

    logger -t card_mgr_audit "FAILSAFE_UPDATE_WRITE: pid=$$ status=completed"

    # Restore complete U-Boot environment
    fw_setenv -c /etc/fw_mmc_env.config -s /tmp/mmc_env_backup.txt
    logger -t card_mgr_audit "FAILSAFE_UPDATE_RESTORE: pid=$$ status=uboot_env_restored"

    rm /tmp/$img_file
    rm /tmp/mmc_env_backup.txt

    logger -t card_mgr_audit "FAILSAFE_UPDATE_SUCCESS: pid=$$ duration=$(($(date +%s) - START_TIME))"

    # Note: Heartbeat cleanup is handled automatically by the EXIT trap
}

update_failsafe $1 $2

