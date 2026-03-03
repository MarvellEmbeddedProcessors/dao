#!/bin/sh
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2026 Marvell.
# Partition and logging redirection helpers (extracted from lc_env_setup.sh)

# --- Constants ---
TARGET_P6_BYTES=$((2 * 1024 * 1024 * 1024))

# --- Helper: derive partition node ---
_p6_node() {
    case $1 in
        *mmcblk*) echo "${1}p6" ;;
        *) echo "${1}6" ;;
    esac
}

# --- Helper: get partition size in bytes (multi fallback) ---
_p6_partition_bytes() {
    PDEV=$1
    SZ=""
    if command -v blockdev >/dev/null 2>&1; then
        SZ=$(blockdev --getsize64 "$PDEV" 2>/dev/null || echo "")
    fi
    if [ -z "$SZ" ]; then
        BASE=$(echo "$PDEV" | sed 's/[0-9]*$//')
        # fdisk fallback
        HUMAN=$(fdisk -l "$BASE" 2>/dev/null \
            | awk -v p="$(basename $PDEV)" '$1==p {print $(NF-1); exit}')
        if echo "$HUMAN" | grep -Eq '^[0-9.]+[KMG]$'; then
            NUM=${HUMAN%[KMG]}
            case $HUMAN in
                *K) MULT=1024 ;;
                *M) MULT=$((1024*1024)) ;;
                *G) MULT=$((1024*1024*1024)) ;;
                *) MULT=1 ;;
            esac
            SZ=$(awk -v n="$NUM" -v m="$MULT" 'BEGIN{printf "%0.f", n*m}')
        fi
    fi
    if [ -z "$SZ" ]; then
        SYS_B=$(basename "$PDEV")
        if [ -r "/sys/class/block/$SYS_B/size" ]; then
            SEC=$(cat /sys/class/block/$SYS_B/size 2>/dev/null)
            SZ=$((SEC * 512))
        fi
    fi
    echo "$SZ"
}

# --- Helper: ext4 geometry bytes (FS size) ---
_p6_ext4_geometry_bytes() {
    PDEV=$1
    command -v tune2fs >/dev/null 2>&1 || return 0
    BLK_SZ=$(tune2fs -l "$PDEV" 2>/dev/null | awk -F': ' '/Block size:/ {print $2}')
    BLK_CNT=$(tune2fs -l "$PDEV" 2>/dev/null | awk -F': ' '/Block count:/ {print $2}')
    if [ -n "$BLK_SZ" ] && [ -n "$BLK_CNT" ]; then
        echo $((BLK_SZ * BLK_CNT))
    fi
}

# --- Helper: unmount if mounted (device or /mnt/log referencing it) ---
_p6_unmount_device() {
    PDEV=$1
    if grep -q "^$PDEV " /proc/mounts; then
        umount "$PDEV" 2>/dev/null \
            || umount -l "$PDEV" 2>/dev/null \
            || echo "[partition6] Warning: unmount $PDEV failed"
    fi
    if grep -q " /mnt/log " /proc/mounts; then
        SRC=$(awk '/ \/mnt\/log / {print $1}' /proc/mounts | head -1)
        if [ "$SRC" = "$PDEV" ]; then
            umount /mnt/log 2>/dev/null \
                || umount -l /mnt/log 2>/dev/null \
                || echo "[partition6] Warning: unmount /mnt/log failed"
        fi
    fi
}

# --- Helper: recreate partition 6 to target size ---
_p6_recreate() {
    BASE=$1
    PDEV=$2
    echo "[partition6] Deleting & recreating partition 6"
    if echo "$BASE" | grep -q mmcblk; then
        (
            echo d   # delete
            echo 6   # partition number
            echo n   # new
            echo p   # primary
            echo 6   # partition number
            echo     # default first sector
            echo +2G # size
            echo w   # write
        ) | fdisk "$BASE" \
            > /tmp/part6_recreate_fdisk.log 2>&1 || {
            echo "[partition6] fdisk recreate failed"
            tail -5 /tmp/part6_recreate_fdisk.log 2>/dev/null
            return 1
        }
    else
        (
            echo d   # delete
            echo 6   # partition number
            echo n   # new
            echo     # default partition type/primary
            echo     # default first sector
            echo +2G # size
            echo w   # write
        ) | fdisk "$BASE" \
            > /tmp/part6_recreate_fdisk.log 2>&1 || {
            echo "[partition6] fdisk recreate failed"
            tail -5 /tmp/part6_recreate_fdisk.log 2>/dev/null
            return 1
        }
    fi
    sync
    sleep 1
    [ -b "$PDEV" ] || {
        echo "[partition6] $PDEV missing after recreation"
        return 1
    }
    return 0
}

# --- Helper: format partition with given fs type ---
_p6_format() {
    PDEV=$1; FST=$2
    echo "[partition6] Formatting $PDEV as $FST"
    if [ "$FST" = "ext4" ]; then
        mkfs.ext4 -F "$PDEV" || return 1
    elif [ "$FST" = "xfs" ]; then
        mkfs.xfs -f "$PDEV" || return 1
    else
        echo "[partition6] Unsupported FS_TYPE $FST"; return 1
    fi
}

# --- Helper: fsck + geometry fix ---
_p6_fsck_and_fix() {
    PDEV=$1; FST=$2
    command -v fsck >/dev/null 2>&1 || { echo "[partition6] fsck not available"; return 0; }
    fsck -n "$PDEV" >/tmp/part6_fsck.txt 2>&1 || FSCK_RC=$?
    FSCK_RC=${FSCK_RC:-0}
    [ $FSCK_RC -eq 0 ] && return 0
    echo "[partition6] fs issues rc=$FSCK_RC"
    if [ "$FST" = "ext4" ] && { [ $FSCK_RC -eq 8 ] || [ $FSCK_RC -eq 4 ]; }; then
        GEOM=$(_p6_ext4_geometry_bytes "$PDEV")
        PARTSZ=$(_p6_partition_bytes "$PDEV")
        if [ -n "$GEOM" ] && [ -n "$PARTSZ" ] && [ "$GEOM" -gt "$PARTSZ" ]; then
            echo "[partition6] filesystem geometry ($GEOM) > partition ($PARTSZ) -> reformatting"
            _p6_format "$PDEV" "$FST" || return 1
            return 0
        fi
    fi
    fsck -y "$PDEV" || echo "[partition6] fsck -y completed (issues may remain)"
}

# --- Helper: mount (with geometry retry for ext4) ---
_p6_mount() {
    PDEV=$1; FST=$2
    mkdir -p /mnt/log
    grep -q "^$PDEV " /proc/mounts && return 0
    grep -q " /mnt/log " /proc/mounts && return 0
    echo "[partition6] Mounting $PDEV on /mnt/log"
    if [ "$FST" = "ext4" ]; then
        mount -t ext4 "$PDEV" /mnt/log 2>/dev/null || MFAIL=1
    elif [ "$FST" = "xfs" ]; then
        mount -t xfs "$PDEV" /mnt/log 2>/dev/null || MFAIL=1
    else
        mount "$PDEV" /mnt/log 2>/dev/null || MFAIL=1
    fi
    if [ "$MFAIL" = "1" ] && [ "$FST" = "ext4" ]; then
        GEOM=$(_p6_ext4_geometry_bytes "$PDEV")
        PARTSZ=$(_p6_partition_bytes "$PDEV")
        if [ -n "$GEOM" ] && [ -n "$PARTSZ" ] && [ "$GEOM" -gt "$PARTSZ" ]; then
            echo "[partition6] Detected geometry mismatch at mount -> reformatting"
            if _p6_format "$PDEV" "$FST" \
                && mount -t ext4 "$PDEV" /mnt/log 2>/dev/null; then
                :
            else
                echo "[partition6] reformat/mount retry failed"
            fi
        else
            echo "[partition6] mount failed"
        fi
    fi
}

# --- Orchestrator ---
check_or_create_partition6() {
    BASE_DEV=${PART_BASE_DEV:-/dev/mmcblk0}
    FS_TYPE=${PART6_FS_TYPE:-ext4}
    CREATE=${AUTO_CREATE_P6:-0}

    PART_NODE=$(_p6_node "$BASE_DEV")
    if [ ! -b "$BASE_DEV" ]; then
        echo "[partition6] Base device $BASE_DEV not present; skipping"
        return 0
    fi

    if [ -b "$PART_NODE" ]; then
        P_BYTES=$(_p6_partition_bytes "$PART_NODE")
        if [ -n "$P_BYTES" ]; then
            if [ "$P_BYTES" -gt $TARGET_P6_BYTES ]; then
                echo "[partition6] Existing partition size $P_BYTES > 2GB; recreating"
                _p6_unmount_device "$PART_NODE"
                _p6_recreate "$BASE_DEV" "$PART_NODE" || return 1
                _p6_format "$PART_NODE" "$FS_TYPE" || return 1
            else
                echo "[partition6] Existing partition size $P_BYTES bytes (<=2GB)"
                _p6_fsck_and_fix "$PART_NODE" "$FS_TYPE" || return 1
            fi
        else
            echo "[partition6] Existing partition size unknown"
            _p6_fsck_and_fix "$PART_NODE" "$FS_TYPE" || return 1
        fi
        _p6_mount "$PART_NODE" "$FS_TYPE"
        return 0
    fi

    if [ "$CREATE" != "1" ]; then
        echo "[partition6] $PART_NODE missing; set AUTO_CREATE_P6=1 to create"
        return 0
    fi
    command -v fdisk >/dev/null 2>&1 || { echo "[partition6] fdisk not available"; return 1; }
    echo "[partition6] Creating partition 6 (2GB)"
    (
        echo n   # new
        echo p   # primary
        echo 6   # partition number
        echo     # default first sector
        echo +2G # size
        echo w   # write
    ) | fdisk "$BASE_DEV" > /tmp/part6_fdisk.log 2>&1 || {
        echo "[partition6] fdisk creation failed"
        tail -5 /tmp/part6_fdisk.log 2>/dev/null
        return 1
    }
    sync; sleep 1
    if [ -b "$PART_NODE" ]; then
        _p6_format "$PART_NODE" "$FS_TYPE" || return 1
        _p6_mount "$PART_NODE" "$FS_TYPE"
    else
        echo "[partition6] Partition node not found after creation"; return 1
    fi
}

# Mount helper
# Old helper replaced by _p6_mount

check_or_create_partition6
