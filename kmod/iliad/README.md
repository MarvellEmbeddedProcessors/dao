# Iliad Platform

## Overview

The Iliad platform support includes kernel modules and setup scripts for running virtio-l2fwd application with vhost-net kernel interface support.

## Components

- **iliad_cdev**: Character device kernel module to access ODM registers and PEM BAR4 (for shared memory) at endpoint
- **octep_cxl_quirk**: Kernel module for CXL quirk handling at host
- **scripts/run_virtio_l2fwd_iliad.sh**: Automated setup and launch script for dao_virtio_l2fwd application

## Why octep_cxl_quirk Module is Needed

The `octep_cxl_quirk` module is essential for enabling ODM (Offload Data Movement) features on the Iliad platform while maintaining CXL (Compute Express Link) functionality.

### Problem Statement

On the Iliad platform, CXL and ODM are represented by a single Physical Function (PF) at the host. This creates a challenge: we need to access ODM-specific features such as:
- ODM interrupts (which are the same as CXL PCI device interrupts; the cxl_pci driver allocates the first 16 vectors but only uses a few, leaving vectors 8-15 available)
- ODM BAR0 space (which is at an offset of CXL PCI device BAR0)
- PEM BAR4 space (which appears at the host as CXL PCI device BAR4)

All of this must be done without disrupting the existing CXL functionality that is already in use.

### Solution

The `octep_cxl_quirk` module solves this by creating a platform device that exposes resources from the CXL PCI device that are **unused by CXL**:

1. **ODM BAR0 space**: Memory region allocated for ODM registers, located at an offset of CXL PCI device BAR0. In vDPA functionality, the ODM block is used for DMA and interrupt delivery
2. **PEM BAR4 space**: Memory region belonging to the PEM (PCI Express Interface) block, which appears at the host as CXL PCI device BAR4. In vDPA functionality, the PEM block is used for shared memory between device and host
3. **ODM unused MSI-X vectors**: ODM interrupt vectors (vectors 8-15) from the CXL PCI device MSI-X allocation. The cxl_pci driver allocates the first 16 vectors but only uses a few, leaving vectors 8-15 available for ODM use

### How It Works

1. The quirk module identifies the CXL PCI device
2. It extracts unused resources:
   - ODM BAR0 space (at offset of CXL PCI device BAR0, for ODM DMA operations)
   - PEM BAR4 space (CXL PCI device BAR4, for PEM shared memory)
   - ODM unused MSI-X vectors (vectors 8-15 from CXL PCI device interrupts, for ODM interrupt delivery)
3. It creates a platform device (`octep_vdpa_plat`) with these resources
4. The OCTEON EP vDPA platform driver (`octep_vdpa_plat.ko`) probes this platform device
5. This enables the vDPA driver to use ODM block for DMA and interrupt delivery, and PEM block for shared memory, independently of CXL

This architecture allows both CXL and ODM/vDPA functionality to coexist on the same PF without interference, as they operate on separate resource sets.

## System Requirements

### Kernel Version Requirements
- Linux kernel version 6.6 or later
- Kernel compiled with:
  - VFIO support (CONFIG_VFIO_PCI)
  - SR-IOV support (CONFIG_PCI_IOV)
  - Hugepage support (CONFIG_HUGETLBFS)
  - CXL support (CONFIG_CXL_BUS etc for host)

### Hardware Requirements
- PCIe devices with vendor:device IDs:
  - PF: 177d:a08b
  - VF: 177d:a08c
- Minimum 2GB RAM for hugepages
- IOMMU-capable system

## Limitations

### Transfer Rate Limitation

**Current Limitation**: The Iliad platform currently supports transfer rates up to **500 Mbps** between host and device.

#### Why This Happens

At high transfer rates, the ODM DMA engine experiences stalls where completion notifications are not received for some operations. This causes the DMA queue to appear stuck, blocking further data transfers until the system recovers or times out.

#### Solution: Rate Limit on Host Interface

To prevent this, configure a fixed bandwidth limit on the host's virtio interface that matches what the device can sustain. This allows TCP to operate smoothly without triggering congestion control.

**Configure host interface rate limit (one-time setup after vDPA device creation):**

```bash
# Set rate limit to 500 Mbps on host virtio interface
sudo tc qdisc add dev <interface> root tbf rate 500mbit burst 256kb latency 50ms
```

Replace `<interface>` with the actual virtio interface name on the host (e.g., `ens513`).

**To verify the rate limit:**

```bash
tc qdisc show dev <interface>
```

**To remove the rate limit:**

```bash
sudo tc qdisc del dev <interface> root
```

**Note**: This rate limit should be configured on the **host side** interface that connects to the device. The limit ensures TCP operates within the device's processing capacity, preventing congestion-induced stalls.

## Building Kernel Modules

The modules can be built using meson:

```bash
# Cross-compile for ARM64 (iliad_cdev)
ninja kmod/iliad/iliad_cdev/iliad_cdev.ko

# Native build for x86 (octep_cxl_quirk)
ninja kmod/iliad/octep_cxl_quirk/octep_cxl_quirk.ko
```

The modules will be built in the build directory:
- `build/kmod/iliad/iliad_cdev/iliad_cdev.ko` - Character device module for endpoint
- `build/kmod/iliad/octep_cxl_quirk/octep_cxl_quirk.ko` - Quirk module for host

**Note**: The `octep_cxl_quirk` module must be built natively on the x86 host system where it will be loaded, as it interacts with the CXL PCI device on the host.

## Quick Start

The `run_virtio_l2fwd_iliad.sh` script automates the complete setup and execution:

```bash
cd /path/to/your/dpu-offload
sudo ./kmod/iliad/scripts/run_virtio_l2fwd_iliad.sh
```

This will:
1. Enable SR-IOV in vfio_pci module (if not already enabled)
2. Start the odm_pf_driver.service (if not already running)
3. Auto-detect ODM VF devices (device ID `177d:a08c`)
4. Setup hugepages (5GB by default, automatically calculates pages based on system hugepage size)
5. Bind VF devices to vfio-pci driver
6. Load the iliad_cdev kernel module (tries modprobe first, then insmod)
7. Load vhost-net kernel module
8. Extract VF UUID from service logs
9. Launch the virtio-l2fwd application with default settings
10. Configure the kernel network interface (MTU, TX queue length)

**Note**: The script is idempotent - it checks the state of each component and only performs actions if needed. You can run it multiple times safely.

## Script Parameters

The script accepts the following command-line parameters:

| Parameter | Description | Default Behavior |
|-----------|-------------|------------------|
| `--help` or `-h` | Display help message and exit | - |
| `--daemon` or `-d` | Run application in background and exit | Foreground mode |
| `--app-path PATH` | Path to `dao-virtio-l2fwd` executable | Auto-detected using `which`, then falls back to `./dao-virtio-l2fwd` |
| `--kmod-path PATH` | Path to `iliad_cdev.ko` kernel module | Script directory (`$SCRIPT_DIR/iliad_cdev.ko`), tries `modprobe iliad_cdev` first |

### Usage Examples

```bash
# Basic usage with auto-detection
sudo ./kmod/iliad/scripts/run_virtio_l2fwd_iliad.sh

# Show help message
sudo ./kmod/iliad/scripts/run_virtio_l2fwd_iliad.sh --help

# Specify custom application path
sudo ./kmod/iliad/scripts/run_virtio_l2fwd_iliad.sh --app-path /path/to/dao-virtio-l2fwd

# Specify custom kernel module path
sudo ./kmod/iliad/scripts/run_virtio_l2fwd_iliad.sh --kmod-path /path/to/iliad_cdev.ko

# Specify both custom paths
sudo ./kmod/iliad/scripts/run_virtio_l2fwd_iliad.sh \
    --app-path /path/to/dao-virtio-l2fwd \
    --kmod-path /path/to/iliad_cdev.ko
```

**Note**: If parameters are not provided, the script will attempt to auto-detect the required executables and kernel module. If auto-detection fails, the script will exit with an error message indicating which component was not found.

## Configuration

The script supports configuration via environment variables. All configuration values have defaults and can be overridden by setting environment variables before running the script.

### Configuration Variables

| Environment Variable | Description | Default Value |
|---------------------|-------------|---------------|
| `CORES` | CPU cores to use (e.g., "2-6") | `2-6` |
| `DMA_THRESH` | DMA flush threshold | `2` |
| `SW_FREE` | Enable software mbuf freeing (set to `1` to enable) | `1` |
| `VIRTIO_MASK` | Virtio mask | `0x1` |
| `HUGEPAGE_MEM_GB` | Hugepage memory in GB (auto-calculates page count) | `5` |
| `VERBOSE_STATS` | Print verbose statistics (set to `1` to enable) | `0` |
| `GDB_DEBUG` | Run with gdb --args (set to `1` to enable) | `0` |
| `DAEMON_MODE` | Run in background (set to `1` to enable, or use `--daemon`) | `0` |
| `DAEMON_LOG` | Log file path for daemon mode output | `/var/log/virtio-l2fwd.log` |
| `VHOST_IFACE` | Kernel interface name | `virtio_user0` |
| `VHOST_QUEUES` | Number of queues | `64` |
| `VHOST_QUEUE_SIZE` | Vring size | `1024` |
| `TXQUEUELEN` | TX queue length for kernel interface | `10000` |
| `NUM_MBUFS` | Number of mbufs (optional, uses app default if not set) | *(empty)* |
| `MAX_PKT_LEN` | Maximum packet length | `9600` |
| `POOL_BUF_LEN` | Mbuf pool buffer length | `10240` |
| `MTU` | MTU for kernel interface | `9000` |

### Usage Examples

```bash
# Use default configuration (creates kernel interface 'virtio_user0')
sudo ./kmod/iliad/scripts/run_virtio_l2fwd_iliad.sh

# Override specific values
CORES="4-8" DMA_THRESH=4 sudo ./kmod/iliad/scripts/run_virtio_l2fwd_iliad.sh

# Override multiple values with custom interface name and more hugepage memory
CORES="2-4" VHOST_IFACE="vhost0" HUGEPAGE_MEM_GB=8 \
    sudo ./kmod/iliad/scripts/run_virtio_l2fwd_iliad.sh

# Run in daemon mode (background, logs to /var/log/virtio-l2fwd.log)
sudo ./kmod/iliad/scripts/run_virtio_l2fwd_iliad.sh --daemon

# Run daemon with custom log file
DAEMON_LOG=/tmp/l2fwd.log sudo ./kmod/iliad/scripts/run_virtio_l2fwd_iliad.sh --daemon

# Monitor daemon logs
tail -f /var/log/virtio-l2fwd.log

# Override mbuf count if needed
NUM_MBUFS=262144 sudo ./kmod/iliad/scripts/run_virtio_l2fwd_iliad.sh
```

**Note**: Environment variables can be exported in your shell session or set inline before the command. The script will use the provided values or fall back to defaults if not set.

## Auto-Detection

The script automatically detects:

### Device Detection

- **ODM VF Devices**: Searches for device ID `177d:a08c` using `lspci -d 177d:a08c`

All detected ODM VF devices are automatically used for binding and application launch.

### Executable Detection

The script automatically finds executables using `which`, with fallback to current directory:

- **oxk-devbind-basic.sh**: Searches PATH, then `./oxk-devbind-basic.sh`
- **dao-virtio-l2fwd**: Searches PATH, then `./dao-virtio-l2fwd` (or use `--app-path`)
- **iliad_cdev.ko**: Defaults to script directory (`$SCRIPT_DIR/iliad_cdev.ko`), tries `modprobe iliad_cdev` first (or use `--kmod-path`)

## What the Script Does

### 1. Setup Hugepages
- Creates `/dev/hugepages/` directory if needed
- Mounts hugepages filesystem if not already mounted
- Reads system hugepage size from `/proc/meminfo`
- Calculates required number of pages based on `HUGEPAGE_MEM_GB` (default: 5GB)
- Allocates hugepages (only if current value is less than required)

### 2. Setup ODM (SR-IOV, Service, VF Binding)
- **Enable SR-IOV**: Checks if enabled, enables only if needed
- **Start ODM Service**: Checks if running, starts only if needed
- **Bind VF Devices**: Binds all detected VF devices to vfio-pci driver

### 3. Load Kernel Module
The script tries to load the kernel module in this order:
1. Check if already loaded (skip if yes)
2. `modprobe iliad_cdev` (if module is installed)
3. `insmod <KMOD_PATH>` (from specified path or `./iliad_cdev.ko`)

### 4. Get UUID
Extracts VF UUID from odm_pf_driver.service logs.

### 5. Launch Application
Runs dao-virtio-l2fwd with all detected devices and configuration.

## Examples

### Example 1: Basic Run with Auto-Detection

Run the script with default settings. All executables and kernel modules are auto-detected:

```bash
cd /path/to/your/dpu-offload
sudo ./kmod/iliad/scripts/run_virtio_l2fwd_iliad.sh
```

### Example 2: Custom Application Path

Specify a custom path to the `dao-virtio-l2fwd` executable:

```bash
sudo ./kmod/iliad/scripts/run_virtio_l2fwd_iliad.sh \
    --app-path /path/to/dao-virtio-l2fwd
```

### Example 3: Custom Kernel Module Path

Specify a custom path to the `iliad_cdev.ko` kernel module:

```bash
sudo ./kmod/iliad/scripts/run_virtio_l2fwd_iliad.sh \
    --kmod-path build/kmod/iliad/iliad_cdev/iliad_cdev.ko
```

### Example 4: Both Custom Paths

Specify both application and kernel module paths:

```bash
sudo ./kmod/iliad/scripts/run_virtio_l2fwd_iliad.sh \
    --app-path /path/to/your/dpu-offload/build/app/virtio-l2fwd/dao-virtio-l2fwd \
    --kmod-path /path/to/your/dpu-offload/build/kmod/iliad/iliad_cdev/iliad_cdev.ko
```

## Manual Setup (if script fails)

If you need to run steps manually:

1. **Enable SR-IOV**:
   ```bash
   echo 1 | sudo tee /sys/module/vfio_pci/parameters/enable_sriov
   ```

2. **Start service and get UUID**:
   ```bash
   sudo systemctl enable odm_pf_driver.service
   sudo systemctl start odm_pf_driver.service
   sudo journalctl -u odm_pf_driver.service | grep "Generated UUID"
   ```

3. **Detect devices**:
   ```bash
   # PF device
   lspci -d 177d:a08b

   # VF devices
   lspci -d 177d:a08c
   ```

4. **Setup hugepages** (calculate pages based on your system's hugepage size):
   ```bash
   sudo mkdir -p /dev/hugepages/
   sudo mount -t hugetlbfs nodev /dev/hugepages/
   # Check hugepage size: grep Hugepagesize /proc/meminfo
   # For 512MB pages, 10 pages = 5GB; for 2MB pages, 2560 pages = 5GB
   echo <num_pages> | sudo tee /proc/sys/vm/nr_hugepages
   ```

5. **Bind VF devices**:
   ```bash
   sudo ./oxk-devbind-basic.sh -b vfio-pci <vf_device1> <vf_device2> ...
   ```

6. **Load kernel module**:
   ```bash
   sudo modprobe iliad_cdev
   # OR
   sudo insmod build/kmod/iliad/iliad_cdev/iliad_cdev.ko
   ```

7. **Load vhost-net kernel module**:
   ```bash
   sudo modprobe vhost-net
   ```

8. **Run application** (replace `<UUID>` and `<vf_devices>` with actual values):
   ```bash
   sudo ./dao-virtio-l2fwd -l 2-6 \
       -a <vf_device1> -a <vf_device2> ... \
       --vfio-vf-token=<UUID> \
       --vdev=net_virtio_user0,path=/dev/vhost-net,iface=virtio_user0,queues=64,queue_size=1024 \
       -- -d 2 -v 0x1 -y 0 -p 0x1 -P \
       --max-pkt-len=9600 --pool-buf-len=10240 -f
   ```

   This will create a kernel network interface named `virtio_user0` that can be configured
   using standard networking tools like `ip` or `ifconfig`.

## Kernel Network Interface (vhost-net)

The virtio-l2fwd application uses the `net_virtio_user` DPDK driver with the vhost-net kernel module to create a kernel network interface. When the application starts, it automatically creates a network interface (default: `virtio_user0`) that can be used for kernel networking.

### How It Works

1. The vhost-net kernel module (`/dev/vhost-net`) provides the backend for virtio devices
2. The DPDK `net_virtio_user` driver connects to vhost-net and creates a kernel interface
3. The kernel interface can be configured using standard tools (`ip`, `ifconfig`, etc.)

### Configuring the Kernel Interface

After the application starts, configure the interface:

```bash
# Bring up the interface
ip link set virtio_user0 up

# Assign an IP address
ip addr add 192.168.1.100/24 dev virtio_user0

# View interface status
ip link show virtio_user0
ip addr show virtio_user0
```

## Host-Side Configuration After Running L2FWD

After running the virtio-l2fwd application on the board using the run script, perform the following steps on the host to create a vDPA platform device and establish communication with the board.

### Load Quirk Module

Load the quirk module to create a vDPA platform device from the CXL PCI device:

```bash
# Load the quirk module (built in build/kmod/iliad/octep_cxl_quirk/)
insmod build/kmod/iliad/octep_cxl_quirk/octep_cxl_quirk.ko

# OR if installed system-wide
modprobe octep_cxl_quirk
```
**Verify the module loaded successfully:**
```bash
# Check if module is loaded
lsmod | grep octep_cxl_quirk

# Check if platform device was created
ls -l /sys/bus/platform/devices/octep_vdpa_plat

# Check kernel messages for quirk module activity
dmesg | grep -i "octep.*quirk\|octep.*vdpa.*platform"
```

Expected output should show the platform device registration message.

### Load vDPA Platform Driver

Load the vDPA platform driver:

```bash
modprobe virtio_vdpa
insmod octep_vdpa_plat.ko
```

### Stop NetworkManager

Stop the NetworkManager service:

```bash
sudo service NetworkManager stop
```

### Create vDPA Device

Create a vDPA device named `vdpa0` using the platform management device:

```bash
vdpa dev add name vdpa0 mgmtdev platform/octep_vdpa_plat
```

This step creates a kernel interface that enables communication with the board.

### Delete vDPA Device

To remove the vDPA device when no longer needed:

```bash
vdpa dev del vdpa0
```

This removes the vDPA device and frees associated resources.

## Notes

- The script must be run as root (use `sudo`)
- The script uses `set -e` to exit on any error
- All configuration can be overridden via environment variables
- Devices and executables are auto-detected
- The UUID is automatically extracted from systemd journal logs
- Kernel module loading tries `modprobe` first, then `insmod`
- The script is idempotent - safe to run multiple times
- Press Ctrl+C to gracefully stop the application (waits up to 5 seconds before force kill)
- Use `--daemon` mode to run in background; logs go to `/var/log/virtio-l2fwd.log` by default
- Stop daemon with `kill -SIGINT <PID>`

## Directory Structure

```
kmod/iliad/
├── README.md                    # This file
├── meson.build                  # Build configuration
├── iliad_cdev/                  # iliad_cdev kernel module
│   ├── meson.build
│   ├── iliad_cdev.c
│   └── Makefile
├── octep_cxl_quirk/             # octep_cxl_quirk kernel module
│   ├── meson.build
│   ├── octep_cxl_quirk.c
│   └── Makefile
└── scripts/                     # Setup scripts
    └── run_virtio_l2fwd_iliad.sh
```
