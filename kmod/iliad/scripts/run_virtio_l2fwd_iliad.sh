#!/bin/bash
# SPDX-License-Identifier: Marvell-Proprietary
# Copyright (c) 2025 Marvell.
#
# Run virtio-l2fwd for Iliad platform with vhost-net kernel interface

set -e

# Configuration (override via environment variables)
CORES=${CORES:-"2-6"}
DMA_THRESH=${DMA_THRESH:-2}
SW_FREE=${SW_FREE:-1}
NUM_MBUFS=${NUM_MBUFS:-}
MAX_PKT_LEN=${MAX_PKT_LEN:-9600}
POOL_BUF_LEN=${POOL_BUF_LEN:-10240}
VIRTIO_MASK=${VIRTIO_MASK:-"0x1"}
HUGEPAGE_MEM_GB=${HUGEPAGE_MEM_GB:-5}
VERBOSE_STATS=${VERBOSE_STATS:-0}
GDB_DEBUG=${GDB_DEBUG:-0}
DAEMON_MODE=${DAEMON_MODE:-0}
DAEMON_LOG=${DAEMON_LOG:-"/var/log/virtio-l2fwd.log"}
TXQUEUELEN=${TXQUEUELEN:-10000}
MTU=${MTU:-9000}

# Vhost options
VHOST_IFACE=${VHOST_IFACE:-"virtio_user0"}
VHOST_QUEUES=${VHOST_QUEUES:-64}
VHOST_QUEUE_SIZE=${VHOST_QUEUE_SIZE:-1024}

# ODM VF PCI device ID
ODM_VF_DEVICE_ID="177d:a08c"

# Script directory (for finding co-located files)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KMOD_PATH="${KMOD_PATH:-$SCRIPT_DIR/iliad_cdev.ko}"

# Runtime state
BIND_SCRIPT=""
ODM_VFS=""
APP_PATH=""
APP_PID=""
APP_CMD=()

log() { echo "[$(date +%H:%M:%S)] $*" >&2; }
die() { echo "Error: $*" >&2; exit 1; }

show_usage() {
    cat << EOF
Usage: $0 [options]

Run virtio-l2fwd for Iliad with vhost-net kernel interface.

Options:
  --kmod-path PATH    Path to iliad_cdev.ko (default: \$SCRIPT_DIR/iliad_cdev.ko)
  --app-path PATH     Path to dao-virtio-l2fwd (auto-detected in PATH or cwd)
  --daemon, -d        Run in background (log to DAEMON_LOG)
  --help              Show this help

Environment variables (with defaults):
  CORES=$CORES  DMA_THRESH=$DMA_THRESH  SW_FREE=$SW_FREE
  VIRTIO_MASK=$VIRTIO_MASK  HUGEPAGE_MEM_GB=$HUGEPAGE_MEM_GB
  VERBOSE_STATS=$VERBOSE_STATS  GDB_DEBUG=$GDB_DEBUG  DAEMON_MODE=$DAEMON_MODE
  DAEMON_LOG=$DAEMON_LOG
  KMOD_PATH=\$SCRIPT_DIR/iliad_cdev.ko

Vhost configuration:
  VHOST_IFACE=$VHOST_IFACE  VHOST_QUEUES=$VHOST_QUEUES
  VHOST_QUEUE_SIZE=$VHOST_QUEUE_SIZE (vring size)
  TXQUEUELEN=$TXQUEUELEN  NUM_MBUFS=  (optional, no default)

Optional (for jumbo frames):
  MAX_PKT_LEN=$MAX_PKT_LEN  POOL_BUF_LEN=$POOL_BUF_LEN  MTU=$MTU
  Example: MAX_PKT_LEN=9600 POOL_BUF_LEN=10240 MTU=9000 $0
EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help) show_usage; exit 0 ;;
            -d|--daemon) DAEMON_MODE=1; shift ;;
            --kmod-path) KMOD_PATH="$2"; shift 2 ;;
            --app-path) APP_PATH="$2"; shift 2 ;;
            *) die "Unknown option: $1" ;;
        esac
    done
}

detect_odm_vfs() {
    local vfs=$(lspci -d "$ODM_VF_DEVICE_ID" | awk '{print $1}' | sort | tr '\n' ',' | sed 's/,$//')
    [[ -z "$vfs" ]] && die "No ODM VFs found (PCI ID: $ODM_VF_DEVICE_ID)"
    local count=$(echo "$vfs" | tr ',' '\n' | wc -l)
    log "Found $count ODM VFs"
    echo "$vfs"
}

find_executable() {
    local name=$1
    command -v "$name" 2>/dev/null && return 0
    [[ -x "./$name" ]] && echo "./$name" && return 0
    return 1
}

setup_odm() {
    if [[ "$(cat /sys/module/vfio_pci/parameters/enable_sriov 2>/dev/null)" != "1" ]]; then
        log "Enabling SR-IOV..."
        echo 1 | tee /sys/module/vfio_pci/parameters/enable_sriov > /dev/null
    fi

    if ! systemctl is-active --quiet odm_pf_driver.service; then
        log "Starting odm_pf_driver.service..."
        systemctl enable odm_pf_driver.service
        systemctl start odm_pf_driver.service
        sleep 2
        systemctl is-active --quiet odm_pf_driver.service || \
            die "odm_pf_driver.service failed. Check: journalctl -u odm_pf_driver.service"
    fi
}

bind_odm_vfs() {
    [[ -f "$BIND_SCRIPT" ]] || die "Bind script not found: $BIND_SCRIPT"
    $BIND_SCRIPT -b vfio-pci ${ODM_VFS//,/ }
    log "ODM VFs bound to vfio-pci: ${ODM_VFS//,/ }"
}

get_odm_uuid() {
    local uuid=$(journalctl -u odm_pf_driver.service --no-pager | \
        grep "Generated UUID:" | tail -1 | awk '{print $NF}')
    [[ -n "$uuid" ]] || die "Failed to extract UUID from ODM service logs"
    echo "$uuid"
}

setup_hugepages() {
    mkdir -p /dev/hugepages/
    if ! mountpoint -q /dev/hugepages/; then
        mount -t hugetlbfs nodev /dev/hugepages/ || die "Failed to mount hugepages"
    fi

    # Get hugepage size in kB and calculate required pages
    local hpsize_kb=$(awk '/Hugepagesize:/ {print $2}' /proc/meminfo)
    [[ -n "$hpsize_kb" ]] || die "Cannot determine Hugepagesize"
    local req_kb=$((HUGEPAGE_MEM_GB * 1024 * 1024))
    local req_pages=$(( (req_kb + hpsize_kb - 1) / hpsize_kb ))

    local current=$(cat /proc/sys/vm/nr_hugepages)
    if [[ $current -lt $req_pages ]]; then
        log "Allocating $req_pages hugepages (${HUGEPAGE_MEM_GB}GB, pagesize=${hpsize_kb}kB)"
        echo $req_pages > /proc/sys/vm/nr_hugepages
        local actual=$(cat /proc/sys/vm/nr_hugepages)
        if [[ $actual -lt $req_pages ]]; then
            log "Warning: Only $actual/$req_pages hugepages available"
        fi
    fi
}

setup_vhost_net() {
    if [[ ! -c /dev/vhost-net ]]; then
        modprobe vhost-net 2>/dev/null || die "Failed to load vhost-net (CONFIG_VHOST_NET required)"
        log "vhost-net module loaded"
    fi
}

load_kernel_module() {
    lsmod | grep -q "^iliad_cdev" && return 0
    modprobe iliad_cdev 2>/dev/null && { log "iliad_cdev loaded via modprobe"; return 0; }
    [[ -f "$KMOD_PATH" ]] || die "Kernel module not found: $KMOD_PATH"
    insmod "$KMOD_PATH"
    log "iliad_cdev loaded via insmod"
}

build_app_command() {
    local uuid=$1
    APP_CMD=("$APP_PATH" -l "$CORES")

    # Add ODM VFs
    IFS=',' read -ra odm_vfs <<< "$ODM_VFS"
    for vf in "${odm_vfs[@]}"; do APP_CMD+=(-a "$vf"); done

    APP_CMD+=(--vfio-vf-token="$uuid")
    local vdev="net_virtio_user0,path=/dev/vhost-net"
    vdev+=",iface=$VHOST_IFACE,queues=$VHOST_QUEUES,queue_size=$VHOST_QUEUE_SIZE"
    APP_CMD+=(--vdev="$vdev")
    APP_CMD+=(--)
    APP_CMD+=(-d "$DMA_THRESH" -v "$VIRTIO_MASK" -y 0 -p 0x1 -P)
    APP_CMD+=(--max-pkt-len="$MAX_PKT_LEN" --pool-buf-len="$POOL_BUF_LEN")
    [[ -n "$NUM_MBUFS" ]] && APP_CMD+=(--max-num-mbufs="$NUM_MBUFS") || true
    [[ "$SW_FREE" == "1" ]] && APP_CMD+=(-f) || true
    [[ "$VERBOSE_STATS" == "1" ]] && APP_CMD+=(-s) || true
}

tune_interface() {
    local iface=$1 timeout=30 elapsed=0

    log "Waiting for interface $iface..."
    while [[ $elapsed -lt $timeout && ! -d "/sys/class/net/$iface" ]]; do
        sleep 1; ((++elapsed))
    done

    if [[ ! -d "/sys/class/net/$iface" ]]; then
        log "Warning: Interface $iface not found after ${timeout}s"
        return 1
    fi

    sleep 1
    ip link set "$iface" up 2>/dev/null || true
    [[ -n "$TXQUEUELEN" ]] && ip link set "$iface" txqueuelen "$TXQUEUELEN" 2>/dev/null || true
    [[ -n "$MTU" ]] && ip link set "$iface" mtu "$MTU" 2>/dev/null || true

    local mtu=$(cat /sys/class/net/$iface/mtu 2>/dev/null || echo '?')
    local txq=$(cat /sys/class/net/$iface/tx_queue_len 2>/dev/null || echo '?')
    log "Interface $iface configured (txq=$txq, mtu=$mtu)"
}

cleanup() {
    trap - SIGINT SIGTERM  # Prevent re-entry
    log "Shutting down..."
    if [[ -n "$APP_PID" ]] && kill -0 "$APP_PID" 2>/dev/null; then
        kill -SIGINT "$APP_PID" 2>/dev/null
        # Wait for app to terminate (max 5s)
        local i=0
        while kill -0 "$APP_PID" 2>/dev/null && [[ $i -lt 5 ]]; do
            sleep 1; ((++i))
        done
        # Force kill if still running
        kill -9 "$APP_PID" 2>/dev/null
    fi
    wait 2>/dev/null  # Reap any zombies
    exit 0
}

main() {
    [[ $EUID -eq 0 ]] || die "Must run as root (use sudo)"
    parse_args "$@"
    command -v lspci &>/dev/null || die "lspci not found (install pciutils)"

    # Find required executables
    BIND_SCRIPT=$(find_executable "oxk-devbind-basic.sh") || die "oxk-devbind-basic.sh not found"
    if [[ -z "$APP_PATH" ]]; then
        APP_PATH=$(find_executable "dao-virtio-l2fwd") || \
            die "dao-virtio-l2fwd not found (use --app-path)"
    else
        [[ -x "$APP_PATH" ]] || die "Application not executable: $APP_PATH"
    fi

    log "Iliad virtio-l2fwd setup (iface: $VHOST_IFACE)"

    setup_hugepages
    setup_odm
    ODM_VFS=$(detect_odm_vfs)
    bind_odm_vfs
    load_kernel_module
    setup_vhost_net

    local uuid=$(get_odm_uuid)
    build_app_command "$uuid"

    local gdb_prefix=""; [[ "$GDB_DEBUG" == "1" ]] && gdb_prefix="gdb --args " || true
    echo "Command: ${gdb_prefix}${APP_CMD[*]}"
    echo "Interface '$VHOST_IFACE' will be created (MTU=$MTU, queue_size=$VHOST_QUEUE_SIZE)."
    echo "Configure with: ip addr add <IP>/<PREFIX> dev $VHOST_IFACE"

    if [[ "$GDB_DEBUG" == "1" ]]; then
        gdb --args "${APP_CMD[@]}"
    elif [[ "$DAEMON_MODE" == "1" ]]; then
        log "Logging to: $DAEMON_LOG"
        "${APP_CMD[@]}" >> "$DAEMON_LOG" 2>&1 &
        APP_PID=$!
        tune_interface "$VHOST_IFACE"
        kill -0 "$APP_PID" 2>/dev/null || die "Application crashed (check $DAEMON_LOG)"
        disown "$APP_PID"
        log "Daemon running (PID: $APP_PID). Stop with: kill -SIGINT $APP_PID"
    else
        "${APP_CMD[@]}" &
        APP_PID=$!
        tune_interface "$VHOST_IFACE" &
        trap cleanup SIGINT SIGTERM
        log "Running (PID: $APP_PID). Ctrl+C to stop"
        wait "$APP_PID"
    fi
}

main "$@"
