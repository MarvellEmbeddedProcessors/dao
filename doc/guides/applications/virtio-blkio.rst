..  SPDX-License-Identifier: Marvell-MIT
    Copyright (c) 2025 Marvell.

************
VirtIO-blkIO
************

The ``dao-virtio-blkio`` application is Dataplane development kit(DPDK) application that allows to exercise usecase of presenting the Virtio block devices and integrate them with various backend storage devices. The application leverages the **DAO Virtio Block Library** to dequeue and process I/O requests, decode them, and invoke appropriate backend device hooks to perform the actual I/O operations.

The application is dependent on below libraries for its functionality:

- DAO ``dmadev`` library to use DPI HW and transfer data between Host and Octeon memory.
- DAO ``virtio_blkdev`` library to receive / send BIO operations from / to host.
- DAO ``blkdev`` library to hook device specific functions to handle each supported IO operations.

Key Features:

- **Backend Storage Support**: Supports RAMDISK for now. Any other storage device can be used as the backend.
- **Virtio Block Device Management**: Virtio lib handles initialization, configuration, and teardown of Virtio block devices.
- **In-Order and Out-of-Order Processing**: Supports in-order for now. out-of-order processing support will be added in future.
- **Per-Queue Stash Management**: Maintains a per-queue stash to store in-flight, in-progress, and incomplete requests.
- **Multi-Core Support**: Distributes workloads across multiple CPU cores for parallel processing.
- **Custom Configuration**: Provides flexible configuration options via command-line arguments.

Architecture
------------
The application architecture is designed to efficiently handle Virtio block I/O requests. Below is a high-level flow:

- **Dequeue Requests**: The application dequeues I/O requests using the DAO Virtio Block Library APIs.
- **Decode Requests**: Decodes the requests to determine the type (read, write, flush, etc.).
- **Process Requests**: Processes the requests and invokes backend device hooks for actual I/O operations.
- **Stash Management**: Maintains a per-queue stash for in-flight and incomplete requests.
- **Completion Handling**: Handles completed requests and updates the status.

Application Workflow
--------------------
The application workflow is as follows:

Initialization
~~~~~~~~~~~~~~
- Initializes the Environment Abstraction Layer (EAL).
- Parses command-line arguments.
- Configures Virtio devices, DMA devices, and memory pools.

Main Processing Loop
~~~~~~~~~~~~~~~~~~~~
The main loop processes requests in a structured order using two types of stashes:

- **Completed Requests Stash**: Holds requests that have been processed and are ready for completion marking.
- **Pending Requests Stash**: Tracks requests that are in progress or require further processing.

The workflow for processing requests is as follows:

- **Check and Drain Completed Requests Stash**:
   The application first checks the completed stash and processes all requests that are ready for marking as completed.

- **Process Pending Requests Stash**:
   The application then checks the pending stash for in-progress requests. Completed requests are moved to the completed stash, while others remain parked in the pending stash.

- **Dequeue New Requests**:
   Fresh requests are dequeued from Virtio queues using ``dao_virtio_blk_dequeue_burst()`` and processed. If a request cannot be completed immediately, it is parked in the pending stash for future processing. Decodes the dequeued requests to determine the operation type. Processes the requests by invoking backend device hooks.

Request Processing
~~~~~~~~~~~~~~~~~~
Each worker core calls ``virtio_blk_io_process_request(uint16_t dev_id, void *vbuf)``. This function decodes the I/O request into different request types supported by the devices, such as:

   - ``VIRTIO_BLK_T_IN``: Read request
   - ``VIRTIO_BLK_T_OUT``: Write request
   - ``VIRTIO_BLK_T_FLUSH``
   - ``VIRTIO_BLK_T_DISCARD``
   - ``VIRTIO_BLK_T_WRITE_ZEROES``
   - ``VIRTIO_BLK_T_GET_ID``
   - ``VIRTIO_BLK_T_SECURE_ERASE``

Once the request is decoded, the API invokes the ``blkdev`` library APIs (e.g., ``dao_blkdev_*()``) to call device-specific hook functions and returns one of the following:

   - ``DAO_VIRTIO_BLK_REQ_COMPLETE``: The request is completed.
   - ``DAO_VIRTIO_BLK_REQ_IN_PROGRESS``: The request is still under process. This can happen when the underlying block device needs time to process the request. In such cases, the API returns after the asynchronous request is submitted. This request needs to be tracked in the application and polled in the future for completion.

Requests that return ``DAO_VIRTIO_BLK_REQ_IN_PROGRESS`` are added to a list in the application and need to be periodically checked for completions using ``virtio_blk_request_get_status()``.

Completion Handling
~~~~~~~~~~~~~~~~~~~
Completion marking of the block I/O request means that the request submitted by the driver is completed and the response is ready to be returned. Once the request processing is completed (i.e., ``virtio_blk_io_process_request`` returns ``DAO_VIRTIO_BLK_REQ_COMPLETE``), the block I/O application calls ``dao_virtio_blk_process_compl()``. As part of this, the following operations are executed:

   - For read requests, the DMA of data and block I/O status from OCTEON to host memory is issued.
   - For other requests, the block I/O request status is updated from OCTEON to host memory.
   - Fetch DMA status and update the shadow mbuf offset, so that the service core can mark the descriptors as used based on the shadow mbuf offset.

Teardown
~~~~~~~~
   - Releases Virtio devices, DMA devices, and memory pools.
   - Cleans up the EAL environment.

Setting up EP environment
-------------------------

Setup SDP PF/VF count in EBF menu
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Number of virtio devices is equal to number of SDP VF's enabled. So make sure that config is setup
correctly in EBF menu.

:doc:`Steps to configure PCIe EP <../howtoguides/pcie_config>`

Setup huge pages for DPDK application
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Setup enough hugepages and a mount point for the same in order for the dao-virtio-blkio application
to run.

.. code-block:: bash

   echo 25 | tee /proc/sys/vm/nr_hugepages
   mkdir -p /mnt/huge 2> /dev/null
   mount -t hugetlbfs nodev /mnt/huge

Bind required DMA devices to vfio-pci
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
``virtio-blkio`` application needs two DMA devices per lcore one for DEV2MEM and another for
MEM2DEV and two more for control lcore. Control lcore is created by virtio library to
handle control commands. Below is sample code to bind DMA VF's to vfio-pci.

.. code-block:: bash

   DPI_PF=`lspci -d :a080 | awk -e '{print $1}'`

   # Enhance DPI engine FIFO size and MRRS
   echo 0x10101010 > /sys/module/octeontx2_dpi/parameters/eng_fifo_buf
   echo 512 > /sys/module/octeontx2_dpi/parameters/mrrs
   echo 256 > /sys/module/octeontx2_dpi/parameters/mps

   echo $DPI_PF > /sys/bus/pci/devices/$DPI_PF/driver/unbind
   echo octeontx2-dpi > /sys/bus/pci/devices/$DPI_PF/driver_override
   echo $DPI_PF > /sys/bus/pci/drivers_probe

   echo 32 >/sys/bus/pci/devices/$DPI_PF/sriov_numvfs
   DPI_VF=`lspci -d :a081 | awk -e '{print $1}' | head -22`
   dpdk-devbind.py -b vfio-pci $DPI_VF

Bind required NPA PF to vfio-pci
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Application needs buffers to hold block requests. So it creates and uses buffer pool managed by CN10K NPA HW so that automatic recycle of buffers can be supported on completion.

Sample code to map CN10K memory manager device to vfio-pci.

.. code-block:: bash

   NPA_PF=`lspci -d :a0fb | awk -e '{print $1}'`
   dpdk-devbind.py -b vfio-pci $NPA_PF

Bind required SDP RVU devices to vfio-pci
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
VirtIO library uses ``RVU SDP devices`` to configure virtio configuration space.

.. code-block:: bash

   dpdk-devbind.py -b vfio-pci 0002:18:00.0
   dpdk-devbind.py -b vfio-pci 0002:19:00.0


Running the EP firmware application
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
The application as number of command line options:

.. code-block:: console

   dao-virtio-blkio [EAL Options] -- -v <VIRTIOMASK_L[,VIRTIOMASK_H]> [other application options]

Supported Arguments
The application supports the following command-line arguments for configuration and customization:

.. code-block:: text

    +----------------------+-----------------------------------------------+
    | Argument             | Description                                   |
    +======================+===============================================+
    | -v                   | Virtio device mask (hexadecimal bitmask).     |
    +----------------------+-----------------------------------------------+
    | -d                   | DMA flush threshold (1-15, default: 8).       |
    +----------------------+-----------------------------------------------+
    | -f                   | Disable auto-free for Virtio Tx buffers.      |
    +----------------------+-----------------------------------------------+
    | -y                   | Override DMA VFID.                            |
    +----------------------+-----------------------------------------------+
    | --virtio-blkconfig   | Configure block device attributes.            |
    +----------------------+-----------------------------------------------+
    | --per-dev-pool       | Enable per-device buffer pool.                |
    +----------------------+-----------------------------------------------+
    | --in-order           | Enable in-order processing.                   |
    +----------------------+-----------------------------------------------+

Detailed Key-Value Pairs for `--virtio-blkconfig`

The `--virtio-blkconfig` argument allows users to configure specific attributes for Virtio block devices. Below are the supported key-value pairs:

.. code-block:: text

    +----------------+----------------------------------------------------+
    | Key            | Description                                        |
    +================+====================================================+
    | capacity       | Capacity of the block device in MB or GB expressed |
    |                | using suffix M and G respectively.                 |
    |                | Example: `capacity=100M`                           |
    +----------------+----------------------------------------------------+
    | blk_sz         | Sector size of the device (must be a power of 2).  |
    |                | Example: `blk_sz=512`                              |
    +----------------+----------------------------------------------------+
    | max_queues     | Maximum number of queues supported by the device.  |
    |                | Example: `max_queues=4`                            |
    +----------------+----------------------------------------------------+
    | max_segs       | Maximum number of segments per request (1-15).     |
    |                | Example: `max_segs=8`                              |
    +----------------+----------------------------------------------------+
    | max_seg_sz     | Maximum size of a single segment in bytes.         |
    |                | Example: `max_seg_sz=4096`                         |
    +----------------+----------------------------------------------------+
    | lcore_mask     | Hexadecimal bitmask of lcores assigned to the      |
    |                | device.                                            |
    |                | Example: `lcore_mask=0x3`                          |
    +----------------+----------------------------------------------------+

**Usage Example**:
Below are examples of how to run the application with different configurations:

- **Basic Execution**:

.. code-block:: bash

   DPI_ALLOW='-a 0000:06:00.1 -a 0000:06:00.2 -a 0000:06:00.3 -a 0000:06:00.4 -a 0000:06:00.5 -a 0000:06:00.6 -a 0000:06:00.7 -a 0000:06:01.0 -a 0000:06:01.1 -a 0000:06:01.2 -a 0000:06:01.3 -a 0000:06:01.4 -a 0000:06:01.5 -a 0000:06:01.6 -a 0000:06:01.7 -a 0000:06:02.0 -a 0000:06:02.1 -a 0000:06:02.2 -a 0000:06:02.3 -a 0000:06:02.4 -a 0000:06:02.5 -a 0000:06:02.6'

   NPA_PF=`lspci -d :a0fb | awk -e '{print $1}'`

   dao-virtio_blkio -l 2-4 -a $NPA_PF $DPI_ALLOW -- -v 0x1 --virtio-blkconfig "(0)"

This launches the application with default configuration for device 0.

- **Custom Configuration**:

.. code-block:: bash

   dao-virtio_blkio -l 2-7 -a $NPA_PF $DPI_ALLOW -- -v 0x1 --virtio-blkconfig "(0,capacity=100M,blk_sz=512,max_queues=4,max_segs=8,max_seg_sz=4096,lcore_mask=0xf0)"

This launche the application with following configurations for device 0:
   - Capacity: 100MiB
   - Sector size: 512B
   - Maximum queues: 4
   - Maximum segments per request: 8
   - Maximum segment size: 4096B
   - Assigned lcores: 4,5,6,7 (based on `lcore_mask=0xf0`)

Setting up Host environment
---------------------------

Prior to this, application should be up and running. Once the application is up, run steps on host as follows:

On Host, we need to bind host PF and VF devices provided by CN10K to ``octep_vdpa`` driver.

.. code-block:: console

   modprobe vdpa
   modprobe virtio-vdpa

   insmod octep_vdpa.ko

   HOST_PF=`lspci -Dn -d :b900 | head -1 | cut -f 1 -d " "`
   VF_CNT=1
   VF_CNT_MAX=`cat /sys/bus/pci/devices/$HOST_PF/sriov_totalvfs`
   VF_CNT=$((VF_CNT >VF_CNT_MAX ? VF_CNT_MAX : VF_CNT))

   echo $HOST_PF > /sys/bus/pci/devices/$HOST_PF/driver/unbind
   echo octep_vdpa > /sys/bus/pci/devices/$HOST_PF/driver_override
   echo $HOST_PF > /sys/bus/pci/drivers_probe
   echo $VF_CNT >/sys/bus/pci/devices/$HOST_PF/sriov_numvfs

   sleep 2
   # Get the list of management devices
   mgmt_devices=$(vdpa mgmtdev show | awk '/pci\/0000:/{print $1}' | sed 's/:$//')
   for mgmtdev in $mgmt_devices
   do
       vdpa_name="vdpa${mgmtdev##*/}"
       vdpa dev add name "$vdpa_name" mgmtdev "$mgmtdev"
       sleep 1
   done

After this step, the `dmesg` output can be checked to verify if the kernel virtio block driver has been probed and the VirtIO block device has been created. Tools such as `lsblk` or inspecting the `/dev` directory can be used to locate the created block device, typically named `/dev/vdX`, where `X` represents a letter corresponding to the device (e.g., `/dev/vda`, `/dev/vdb`, etc.).

Using block device on host
--------------------------

Once the VirtIO block device is created, it can be used like any other block device on the host. For example, it can be formatted with a filesystem, mounted, and utilized for storage purposes. To format the device, the `mkfs` command can be executed:

.. code-block:: console

   mkfs.ext4 /dev/vdX

To mount the device, a mount point can be created, followed by the use of the `mount` command:

.. code-block:: console

   mkdir -p /mnt/virtio_blk
   mount /dev/vdX /mnt/virtio_blk

After mounting, the filesystem becomes accessible for standard operations such as reading, writing, creating directories, and managing files. For instance:

.. code-block:: console

   echo "Hello, VirtIO Block!" > /mnt/virtio_blk/hello.txt

The mounted filesystem can be checked using the following command:

.. code-block:: console

   df -h /mnt/virtio_blk

To unmount the device, the `umount` command can be used:

.. code-block:: console

   umount /mnt/virtio_blk

Partitioning the device can be performed using tools like `fdisk` or `parted`. For example, the `fdisk` utility can be opened with the following command:

.. code-block:: console

   fdisk /dev/vdX

Within the `fdisk` utility, partitions can be created, deleted, or modified. After making changes, it is important to write the changes and exit.

To clean up, management devices can be removed using the following script:

.. code-block:: bash

    for mgmtdev in $mgmt_devices
    do
        vdpa dev del name "vdpa${mgmtdev##*/}"
    done
