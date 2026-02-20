# Iliad Platform

## Overview

The Iliad platform support provides the components and software used to establish a network connection between the Iliad host and board over PCIe.
The speed of the connection is **10Gbps** with default MTU (1500).

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
2. It extracts unused resources (ODM BAR0, PEM BAR4, MSI-X vectors 8–15)
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
- Minimum 5GB RAM for hugepages
- IOMMU-capable system

## Build Instructions

### Building dao_virtio_l2fwd Application

To build `dao-virtio-l2fwd`, follow [Compiling DAO from sources](../../doc/guides/gsg/build.rst). Use the `cn10k` configuration for compatibility with the Iliad platform.

### Building board kernel modules

For getting sources and creating the meson build folder with the cn10k config file and `kernel_dir`, see [Compiling DAO from sources](../../doc/guides/gsg/build.rst).

Then build the character device module:

```bash
ninja -C <build_dir> kmod/iliad/iliad_cdev/iliad_cdev.ko
```

### Building host kernel modules

The host modules (`octep_vdpa_plat.ko` and `octep_cxl_quirk.ko`) are the OCTEON EP vDPA platform driver and the CXL quirk module used on the host. They must be built with native compilation on the x86 host where they will be loaded.

**Kernel configuration**: Ensure the following are enabled in the kernel used for building (e.g. in `$kernel_dir/.config` or your running kernel's config):

- `CONFIG_VDPA=y`
- `CONFIG_VHOST_IOTLB=y`
- `CONFIG_VHOST=y`
- `CONFIG_VHOST_VDPA=y`
- `CONFIG_VIRTIO_VDPA=y`

Create a meson build folder with the host kernel source:

```bash
meson build -Dkernel_dir=/lib/modules/$(uname -r)/build
```

Then build the platform and quirk modules:

```bash
ninja -C build kmod/vdpa/octeon_ep/octep_vdpa_plat.ko
ninja -C build kmod/iliad/octep_cxl_quirk/octep_cxl_quirk.ko
```

## Quick Start

The `run_virtio_l2fwd_iliad.sh` script automates the complete setup and execution. The script expects the ODM PF driver service and binaries to be present in the rootfs.
If they are not, see [accelerator-odm-userspace-pf-driver](https://github.com/Marvell-Lab/accelerator-odm-userspace-pf-driver).

**Foreground mode** (Ctrl+C to stop):

```bash
cd /path/to/your/script
sudo ./kmod/iliad/scripts/run_virtio_l2fwd_iliad.sh
```

**Daemon mode** (returns to shell immediately; application runs in background):

```bash
sudo ./kmod/iliad/scripts/run_virtio_l2fwd_iliad.sh -d
# Monitor logs:
tail -f /var/log/virtio-l2fwd.log
# Stop the daemon (use the PID printed by the script):
kill -SIGINT <PID>
```

In both modes, the script will:
1. Setup hugepages (5GB by default, automatically calculates pages based on system hugepage size)
2. Enable SR-IOV in vfio_pci module (if not already enabled)
3. Start the odm_pf_driver.service (if not already running)
4. Auto-detect ODM VF devices (device ID `177d:a08c`)
5. Bind VF devices to vfio-pci driver
6. Load the iliad_cdev kernel module (tries modprobe first, then insmod)
7. Load vhost-net kernel module
8. Extract VF UUID from service logs
9. Launch the virtio-l2fwd application with default settings
10. Configure the kernel network interface (MTU, tx queue length via `VIRTIO_NET_TX_QUEUE_LEN`)

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
| `CORES` | CPU cores to use (e.g., "2-5") | `2-5` |
| `DMA_THRESH` | DMA flush threshold | `2` |
| `SW_FREE` | Enable software mbuf freeing (set to `1` to enable) | `1` |
| `VIRTIO_MASK` | Virtio mask | `0x1` |
| `HUGEPAGE_MEM_GB` | Hugepage memory in GB (auto-calculates page count) | `5` |
| `VERBOSE_STATS` | Print verbose statistics (set to `1` to enable) | `0` |
| `GDB_DEBUG` | Run with gdb --args (set to `1` to enable) | `0` |
| `DAEMON_MODE` | Run in background (set to `1` to enable, or use `--daemon`) | `0` |
| `DAEMON_LOG` | Log file path for daemon mode output | `/var/log/virtio-l2fwd.log` |
| `VHOST_IFACE` | Kernel interface name (virtio_net/vhost_net) | `virtio_user0` |
| `VHOST_QUEUES` | Number of queues | `64` |
| `VHOST_QUEUE_SIZE` | Vring size | `1024` |
| `VIRTIO_NET_TX_QUEUE_LEN` | Tx queue length of the virtio_net interface (vhost_net backend) | `10000` |
| `KMOD_PATH` | Path to `iliad_cdev.ko` (overrides default `$SCRIPT_DIR/iliad_cdev.ko`; same as `--kmod-path`) | `$SCRIPT_DIR/iliad_cdev.ko` |
| `NUM_MBUFS` | Number of mbufs; passed only when set | *(unset)* |
| `MAX_PKT_LEN` | Maximum packet length; passed only when set | *(unset)* |
| `POOL_BUF_LEN` | Mbuf pool buffer length; passed only when set | *(unset)* |
| `MTU` | MTU for kernel interface; applied only when set | *(unset)* |

### Configuration Examples

```bash
# Use default configuration (creates kernel interface 'virtio_user0')
sudo ./kmod/iliad/scripts/run_virtio_l2fwd_iliad.sh

# Override values with custom interface name, hugepage memory, and virtio_net tx queue length
sudo VHOST_IFACE="vhost0" HUGEPAGE_MEM_GB=8 VIRTIO_NET_TX_QUEUE_LEN=16384 \
    ./kmod/iliad/scripts/run_virtio_l2fwd_iliad.sh

# Run in daemon mode (background, logs to /var/log/virtio-l2fwd.log)
sudo ./kmod/iliad/scripts/run_virtio_l2fwd_iliad.sh --daemon

# Run daemon with custom log file
DAEMON_LOG=/tmp/l2fwd.log sudo ./kmod/iliad/scripts/run_virtio_l2fwd_iliad.sh --daemon

# Monitor daemon logs
tail -f /var/log/virtio-l2fwd.log
```

## What the Script Does

### 1. Setup Hugepages
- Creates `/dev/hugepages/` directory if needed
- Mounts hugepages filesystem if not already mounted
- Reads system hugepage size from `/proc/meminfo`
- Calculates required number of pages based on `HUGEPAGE_MEM_GB` (default: 5GB)
- Allocates hugepages (only if current value is less than required)

### 2. Setup ODM (SR-IOV and Service)
- **Enable SR-IOV**: Checks if enabled, enables only if needed
- **Start ODM Service**: Checks if running, starts only if needed

### 3. Detect and Bind ODM VFs
- Detects all ODM VF devices with PCI ID `177d:a08c` using `lspci`
- Binds all detected VF devices to vfio-pci driver via `oxk-devbind-basic.sh`

### 4. Load Kernel Module
The script tries to load the kernel module in this order:
1. Check if already loaded (skip if yes)
2. `modprobe iliad_cdev` (if module is installed)
3. `insmod <KMOD_PATH>` (from specified path or `$SCRIPT_DIR/iliad_cdev.ko`)

### 5. Load vhost-net Module
Loads the `vhost-net` kernel module if `/dev/vhost-net` does not exist yet.

### 6. Get UUID
Extracts VF UUID from odm_pf_driver.service logs.

### 7. Launch Application
Runs dao-virtio-l2fwd with all detected devices and configuration.

### 8. Tune Interface
Waits for the kernel interface (`VHOST_IFACE`) to appear, then brings it up and applies `VIRTIO_NET_TX_QUEUE_LEN` and `MTU` when set.

## Manual Setup (if script fails)

If you need to run steps manually:

1. **Setup hugepages** (calculate pages based on your system's hugepage size):
   ```bash
   sudo mkdir -p /dev/hugepages/
   sudo mount -t hugetlbfs nodev /dev/hugepages/
   # Check hugepage size: grep Hugepagesize /proc/meminfo
   # For 512MB pages, 10 pages = 5GB; for 2MB pages, 2560 pages = 5GB
   echo <num_pages> | sudo tee /proc/sys/vm/nr_hugepages
   ```

2. **Enable SR-IOV**:
   ```bash
   echo 1 | sudo tee /sys/module/vfio_pci/parameters/enable_sriov
   ```

3. **Start service and get UUID**:
   ```bash
   sudo systemctl enable odm_pf_driver.service
   sudo systemctl start odm_pf_driver.service
   sudo journalctl -u odm_pf_driver.service | grep "Generated UUID"
   ```

4. **Detect devices**:
   ```bash
   # PF device
   lspci -d 177d:a08b

   # VF devices
   lspci -d 177d:a08c
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
   sudo ./dao-virtio-l2fwd -l 2-5 \
       -a <vf_device1> -a <vf_device2> ... \
       --vfio-vf-token=<UUID> \
       --vdev=net_virtio_user0,path=/dev/vhost-net,iface=virtio_user0,queues=64,queue_size=1024 \
       -- -d 2 -v 0x1 -y 0 -p 0x1 -P -f
   ```

   This creates the kernel network interface (default: `virtio_user0`).

## Kernel Network Interface (vhost-net)

The virtio-l2fwd application uses the `net_virtio_user` DPDK driver with the vhost-net kernel module to create a kernel network interface. When the application starts, it automatically creates a network interface (default: `virtio_user0`).

### How It Works

1. The vhost-net kernel module (`/dev/vhost-net`) provides the backend for virtio devices
2. The DPDK `net_virtio_user` driver connects to vhost-net and creates a kernel interface
3. The kernel interface can be configured using standard tools (`ip`, `ifconfig`, etc.)

### Configuring the Kernel Interface

The script automatically brings up the interface and applies `VIRTIO_NET_TX_QUEUE_LEN` (tx queue length) and `MTU` when set. After the application starts, assign an address and use the interface:

```bash
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

# Check if platform device was created
ls -l /sys/bus/platform/devices/octep_vdpa_plat
```

### Load vDPA Platform Driver

Load the vDPA platform driver (use the path where you built `octep_vdpa_plat.ko`; see [Building host kernel modules](#building-host-kernel-modules)):

```bash
modprobe virtio_vdpa
insmod build/kmod/vdpa/octeon_ep/octep_vdpa_plat.ko
# OR if installed system-wide:
# modprobe octep_vdpa_plat
```

### Stop NetworkManager

NetworkManager may remove or overwrite addresses you set manually on the vDPA/virtio interfaces. Stop it so your configured addresses stay in place.

```bash
sudo service NetworkManager stop
```

### Create vDPA Device

Create a vDPA device named `vdpa0` using the platform management device:

```bash
vdpa dev add name vdpa0 mgmtdev platform/octep_vdpa_plat
```

### Verify vDPA Device and Kernel Interface

The virtio_vdpa driver probes the vDPA device, registers a virtio network device with the kernel and virtio_net binds to it to create a kernel interface.
Check that the vDPA device and the kernel network interface were created:

```bash
# List vDPA devices
vdpa dev show

# virtio_vdpa creates a kernel interface (e.g. virtio_user0)
ip link show
```

Assign an IP address on the host in the same network as the board, then verify connectivity:

```bash
# Assign IP in the same subnet as the board (use the interface name from ip link show)
sudo ip addr add 192.168.1.101/24 dev <host_interface>

# Bring the interface up
sudo ip link set <host_interface> up

# Ping the board (use the IP you assigned on the board, e.g. on virtio_user0)
ping 192.168.1.100
```

Replace `<host_interface>` with the actual interface name from `ip link show`.

## Cleanup / Unload

Cleanup is the reverse of the load sequence: perform steps on the **host** first, then on the **board**.

### On the host

1. **Delete the vDPA device** (removes the virtio_net kernel interface):

   ```bash
   vdpa dev del vdpa0
   ```

2. **Unload the vDPA platform driver**:

   ```bash
   rmmod octep_vdpa_plat
   # If installed: modprobe -r octep_vdpa_plat
   ```

3. **Unload the quirk module**:

   ```bash
   rmmod octep_cxl_quirk
   # If installed: modprobe -r octep_cxl_quirk
   ```

4. **(Optional)** Restart NetworkManager if you stopped it:

   ```bash
   sudo service NetworkManager start
   ```

### On the board

1. **Stop the virtio-l2fwd application**:
   - If running in the foreground: press **Ctrl+C**.
   - If running as a daemon: find the PID and send SIGINT, e.g. `kill -SIGINT <PID>` or `kill -2 <PID>`. If the process does not exit after a while, send SIGKILL: `kill -SIGKILL <PID>` or `kill -9 <PID>`.

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
└── scripts/                     # Setup script
    └── run_virtio_l2fwd_iliad.sh
```
