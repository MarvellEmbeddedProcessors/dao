/* SPDX-License-Identifier: Marvell-Proprietary
 * Copyright (c) 2025 Marvell
 */

#ifndef __INCLUDE_VIRTIO_BLK_H__
#define __INCLUDE_VIRTIO_BLK_H__

/** The feature bitmap for virtio blk */
#define VIRTIO_BLK_F_SIZE_MAX     1  /** Indicates maximum segment size */
#define VIRTIO_BLK_F_SEG_MAX      2  /** Indicates maximum num of segments */
#define VIRTIO_BLK_F_GEOMETRY     4  /** Legacy geometry available  */
#define VIRTIO_BLK_F_RO           5  /** Device is read-only */
#define VIRTIO_BLK_F_BLK_SIZE     6  /** Block size of disk is available*/
#define VIRTIO_BLK_F_FLUSH        9  /** Cache flush command support */
#define VIRTIO_BLK_F_TOPOLOGY     10 /** Topology information is available */
#define VIRTIO_BLK_F_CONFIG_WCE   11 /** Writeback mode is supported */
#define VIRTIO_BLK_F_MQ           12 /** support more than one vq */
#define VIRTIO_BLK_F_DISCARD      13 /** Discard command is supported */
#define VIRTIO_BLK_F_WRITE_ZEROES 14 /** Writes zeros command is supported */
#define VIRTIO_BLK_F_LIFETIME     15 /** Storage lifetime info available */
#define VIRTIO_BLK_F_SECURE_ERASE 16 /** Secure erase command is supported */
#define VIRTIO_BLK_F_ZONED        17 /** Zoned block device is supported */

struct virtio_blk_config {
	/** The capacity (in 512-byte sectors). */
	uint64_t capacity;
	/** The maximum segment size (if VIRTIO_BLK_F_SIZE_MAX) */
	uint32_t size_max;
	/** The maximum number of segments (if VIRTIO_BLK_F_SEG_MAX) */
	uint32_t seg_max;
	/** geometry of the device (if VIRTIO_BLK_F_GEOMETRY) */
	struct virtio_blk_geometry {
		uint16_t cylinders;
		uint8_t heads;
		uint8_t sectors;
	} geometry;

	/** block size of device (if VIRTIO_BLK_F_BLK_SIZE) */
	uint32_t blk_size;

	/** the next 4 entries are guarded by VIRTIO_BLK_F_TOPOLOGY  */
	struct virtio_blk_topology {
		/** exponent for physical block per logical block. */
		uint8_t physical_block_exp;
		/** alignment offset in logical blocks. */
		uint8_t alignment_offset;
		/** minimum I/O size without performance penalty in logical blocks. */
		uint16_t min_io_size;
		/** optimal sustained I/O size in logical blocks. */
		uint32_t opt_io_size;
	} topology;

	/** writeback mode (if VIRTIO_BLK_F_CONFIG_WCE) */
	uint8_t wce;
	uint8_t unused0;

	/** number of vqs, only available when VIRTIO_BLK_F_MQ is set */
	uint16_t num_queues;

	/** The next 3 entries are guarded by VIRTIO_BLK_F_DISCARD */
	/** The maximum discard sectors (in 512-byte sectors) for one segment. */
	uint32_t max_discard_sectors;
	/** The maximum number of discard segments in a discard command. */
	uint32_t max_discard_seg;
	/** Discard commands must be aligned to this number of sectors. */
	uint32_t discard_sector_alignment;

	/** The next 3 entries are guarded by VIRTIO_BLK_F_WRITE_ZEROES */
	/** The maximum number of write zeroes sectors (in 512-byte sectors) in one segment. */
	uint32_t max_write_zeroes_sectors;
	/** The maximum number of segments in a write zeroes command. */
	uint32_t max_write_zeroes_seg;
	/**
	 * Set if a VIRTIO_BLK_T_WRITE_ZEROES request may result in the deallocation of one or
	 * more of the sectors.
	 */
	uint8_t write_zeroes_may_unmap;

	uint8_t unused1[3];

	/** The next 3 entries are guarded by VIRTIO_BLK_F_SECURE_ERASE */
	/** The maximum secure erase sectors (in 512-byte sectors) for one segment. */
	uint32_t max_secure_erase_sectors;
	/** The maximum number of secure erase segments in a secure erase command. */
	uint32_t max_secure_erase_seg;
	/** Secure erase commands must be aligned to this number of sectors. */
	uint32_t secure_erase_sector_alignment;

	/** The next 3 entries are guarded by VIRTIO_BLK_F_ZONED */
	struct virtio_blk_zoned_characteristics {
		uint32_t zone_sectors;
		uint32_t max_open_zones;
		uint32_t max_active_zones;
		uint32_t max_append_sectors;
		uint32_t write_granularity;
		uint8_t model;
		uint8_t unused2[3];
	} zoned;
} __rte_packed;

struct virtio_blk_outhdr {
#define VIRTIO_BLK_T_IN           0
#define VIRTIO_BLK_T_OUT          1
#define VIRTIO_BLK_T_FLUSH        4
#define VIRTIO_BLK_T_GET_ID       8
#define VIRTIO_BLK_T_DISCARD      11
#define VIRTIO_BLK_T_WRITE_ZEROES 13
#define VIRTIO_BLK_T_SECURE_ERASE 14
	/** VIRTIO_BLK_T */
	uint32_t type;
	/** io priority. */
	uint32_t ioprio;
	/** Sector (ie. 512 byte offset) */
	uint64_t sector;
} __rte_packed;
#endif /* __INCLUDE_VIRTIO_BLK_H__ */
