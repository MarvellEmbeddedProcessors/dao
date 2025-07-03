..  SPDX-License-Identifier: Marvell-MIT
    Copyright (c) 2025 Marvell.

********************
Block Device Library
********************

The block device library provides a generic, extensible interface for managing block devices in high-performance environments. It abstracts block device operations such as read, write, flush, reset, and statistics, supporting multiple device types (e.g., RAM disk). The library is designed for integration into DPU offload and storage acceleration solutions, enabling efficient and flexible block storage management.

Features
--------

The library is designed to support various block device types, with extensibility for new types. Current supported devices are:

- **RAM Disk**: In-memory block device for fast, volatile storage.

The library supports the following generic features on a block device:

- **Read/Write Operations**: Efficient APIs for reading from and writing to block devices using IO vectors.
- **Flush**: Ensures all buffered data is written to the device.
- **Reset**: Resets the block device.
- **Unmap**: Deallocates or unmaps specified sectors/blocks.
- **Write Zeroes**: Writes zeroes to a specified region, with optional unmap support.
- **Discard**: Discards data in a specified sector range.
- **Device Identification**: Retrieve device identifiers as a string.
- **Statistics**: Collects and provides detailed statistics on read, write, flush, reset, unmap, and write zeroes operations.
- **Statistics Management**: APIs to retrieve and clear device statistics.
- **Extensible Handlers**: All operations are handled via a callback structure, allowing for easy extension and customization for new device types.

Library APIs
------------

Control Path API
~~~~~~~~~~~~~~~~
The control path API mainly consists of block device creation and deletion, and statistics management.

- Create a Block Device

*Block Device Configuration Structure*

.. literalinclude:: ../../../lib/blk_dev/dao_blk_dev.h
   :language: c
   :start-at: struct dao_blkdev_conf
   :end-before: End of structure dao_blkdev_conf.

*Initializes a block device with the given configuration and name.*

.. code-block:: c

   int dao_blkdev_create(uint16_t dev_id, struct dao_blkdev_conf *conf, const char *name);


- Delete a Block Device

*Cleans up and removes the specified block device.*

.. code-block:: c

   int dao_blkdev_destroy(uint16_t dev_id);

- Get Block Device Statistics

*Retrieves statistics for the device (read/write ops, bytes, etc.).*

.. code-block:: c

   void dao_blkdev_get_stats(uint16_t dev_id, dao_blkdev_stats_t *stats);


- Clear Block Device Statistics

*Clears the statistics counters for the device.*

.. code-block:: c

   void dao_blkdev_clear_stats(uint16_t dev_id);

Data Path API
~~~~~~~~~~~~~
Data path operations on the block device and the corresponding API are listed below:

- Block Device Read

*Reads data from the specified sector(s) into the provided IO vector.*

.. code-block:: c

   int dao_blkdev_read(uint16_t dev_id, uint64_t sector, blk_io_vec_t *iov, size_t len);

- Block Device Write

*Writes data to the specified sector(s) from the provided IO vector.*

.. code-block:: c

   int dao_blkdev_write(uint16_t dev_id, uint64_t sector, blk_io_vec_t *iov, size_t len);

- Block Device Flush

*Flushes any cached data to the device.*

.. code-block:: c

   int dao_blkdev_flush(uint16_t dev_id);

- Block Device Reset

*Resets the block device.*

.. code-block:: c

   int dao_blkdev_reset(uint16_t dev_id);

- Unmap Sectors of a Block Device

*Unmaps the specified range of sectors.*

.. code-block:: c

   int dao_blkdev_unmap(uint16_t dev_id, uint64_t sector, size_t len);

- Write Zeroes to a Block Device

*Writes zeroes to the specified range, with optional unmap.*

.. code-block:: c

   int dao_blkdev_write_zeroes(uint16_t dev_id, uint64_t sector, size_t len, uint8_t unmap);

- Get Device Identifier of a Block Device

*Retrieves the string identifier for the device.*

.. code-block:: c

   int dao_blkdev_get_id(uint16_t dev_id, char *name, size_t max_len);

- Discard Data

*Discards data in the specified sector range.*

.. code-block:: c

   int dao_blkdev_discard(uint16_t dev_id, uint64_t sector, size_t len);
