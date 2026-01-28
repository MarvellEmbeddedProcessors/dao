/* SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 Marvell.
 */

#ifndef __OCTEP_SDP_H__
#define __OCTEP_SDP_H__

#include <linux/cpumask.h>
#include <linux/etherdevice.h>
#include <linux/if.h>
#include <linux/interrupt.h>
#include <linux/netdevice.h>
#include <linux/pci.h>
#include <linux/types.h>
#include <linux/workqueue.h>

#include <rdma/octep_rdma-abi.h>

#include "octep_mbox.h"
#include "octep_mbox_priv.h"
#include "octep_pfvf_mbox.h"

#include <asm/io.h>

#define OCTEP_RDMA_DEVID_CN106K_PF 0xb900
#define OCTEP_RDMA_DEVID_CN106K_VF 0xb903
#define OCTEP_RDMA_DEVID_CN105K_PF 0xba00
#define OCTEP_RDMA_DEVID_CN105K_VF 0xba03
#define OCTEP_RDMA_DEVID_CN103K_PF 0xbd00
#define OCTEP_RDMA_DEVID_CN103K_VF 0xbd03

#define OCTEP_MAX_QUEUES 63
#define OCTEP_MAX_IQ     OCTEP_MAX_QUEUES
#define OCTEP_MAX_OQ     OCTEP_MAX_QUEUES
#define OCTEP_MAX_VF     128

#define OCTEP_MAX_MSIX_VECTORS OCTEP_MAX_OQ

/* Flags to disable and enable Interrupts */
#define OCTEP_INPUT_INTR  (1)
#define OCTEP_OUTPUT_INTR (2)
#define OCTEP_MBOX_INTR   (4)
#define OCTEP_ALL_INTR    0xff

#define OCTEP_IQ_INTR_RESEND_BIT 59
#define OCTEP_OQ_INTR_RESEND_BIT 59

#define OCTEP_MMIO_REGIONS 6

#define IQ_INSTR_PENDING(iq) (((iq)->host_write_index - (iq)->flush_index) & (iq)->ring_size_mask)
#define IQ_INSTR_SPACE(iq)   ((iq)->max_count - IQ_INSTR_PENDING((iq)))

#ifndef UINT64_MAX
#define UINT64_MAX (u64)(~((u64)0)) /* 0xFFFFFFFFFFFFFFFF */
#endif

#define OCTEP_MSIX_NAME_SIZE (IFNAMSIZ + 32)

enum octep_wq_flag {
	OCTEP_WQ_EMPTY,
	OCTEP_WQ_POST,
};

/* Device status */
enum octep_dev_status {
	OCTEP_DEV_STATUS_INVALID,
	OCTEP_DEV_STATUS_ALLOC,
	OCTEP_DEV_STATUS_WAIT_FOR_FW,
	OCTEP_DEV_STATUS_INIT,
	OCTEP_DEV_STATUS_READY,
	OCTEP_DEV_STATUS_UNINIT
};

enum octep_wq_status {
	OCTEP_WQ_UNINITIALIZED,
	OCTEP_WQ_INITIALIZED,
	OCTEP_WQ_RUNNING,
	OCTEP_WQ_EXITED,
};

extern struct workqueue_struct *octep_wq;
/* Hardware Tx Instruction Header */
struct octep_instr_hdr {
	/* Data Len */
	u64 tlen : 16;

	/* Reserved */
	u64 rsvd : 20;

	/* PKIND for SDP */
	u64 pkind : 6;

	/* Front Data size */
	u64 fsz : 6;

	/* No. of entries in gather list */
	u64 gsz : 14;

	/* Gather indicator 1=gather*/
	u64 gather : 1;

	/* Reserved3 */
	u64 reserved3 : 1;
} __packed;

/* Extended Response Header in packet data received from Hardware.
 * Includes metadata like checksum status.
 * this is valid only if hardware/firmware published support for this.
 * This is at offset 0 of packet data (skb->data).
 */
struct octep_oq_resp_hw_ext {
	/* Reserved. */
	u64 rsvd : 48;

	/* offload flags */
	u16 rx_ol_flags;
} __packed;

#define OCTEP_OQ_RESP_HW_EXT_SIZE (sizeof(struct octep_oq_resp_hw_ext))

/* struct octep_oq_desc_hw - Octeon Hardware OQ descriptor format.
 *
 * The descriptor ring is made of descriptors which have 2 64-bit values:
 *
 *   @buffer_ptr: DMA address of the skb->data
 *   @info_ptr:  DMA address of host memory, used to update pkt count by hw.
 *               This is currently unused to save pci writes.
 */
struct octep_oq_desc_hw {
	dma_addr_t buffer_ptr;
	u64 info_ptr;
} __packed;

#define OCTEP_OQ_DESC_SIZE (sizeof(struct octep_oq_desc_hw))

/* Length of Rx packet DMA'ed by Octeon to Host.
 * this is in bigendian; so need to be converted to cpu endian.
 * Octeon writes this at the beginning of Rx buffer (skb->data).
 */
struct octep_oq_resp_hw {
	/* The Length of the packet. */
	__be64 length;
};

/* Rx offload flags */
#define OCTEP_RX_OFFLOAD_VLAN_STRIP BIT(0)
#define OCTEP_RX_OFFLOAD_IPV4_CKSUM BIT(1)
#define OCTEP_RX_OFFLOAD_UDP_CKSUM  BIT(2)
#define OCTEP_RX_OFFLOAD_TCP_CKSUM  BIT(3)

#define OCTEP_RX_OFFLOAD_CKSUM                                                                     \
	(OCTEP_RX_OFFLOAD_IPV4_CKSUM | OCTEP_RX_OFFLOAD_UDP_CKSUM | OCTEP_RX_OFFLOAD_TCP_CKSUM)

#define OCTEP_RX_IP_CSUM(flags)                                                                    \
	((flags) &                                                                                 \
	 (OCTEP_RX_OFFLOAD_IPV4_CKSUM | OCTEP_RX_OFFLOAD_TCP_CKSUM | OCTEP_RX_OFFLOAD_UDP_CKSUM))
#define OCTEP_OQ_RESP_HW_SIZE (sizeof(struct octep_oq_resp_hw))

/* Pointer to data buffer.
 * Driver keeps a pointer to the data buffer that it made available to
 * the Octeon device. Since the descriptor ring keeps physical (bus)
 * addresses, this field is required for the driver to keep track of
 * the virtual address pointers. The fields are operated by
 * OS-dependent routines.
 */
struct octep_rx_buffer {
	struct page *page;

	/* length from rx hardware descriptor after converting to cpu endian */
	u64 len;
};

/* Output Queue statistics. Each output queue has four stats fields. */
struct octep_oq_stats {
	/* Number of packets received from the Device. */
	u64 packets;

	/* Number of bytes received from the Device. */
	u64 bytes;

	/* Number of times failed to allocate buffers. */
	u64 alloc_failures;

	/* Number of packets for which data arrived late. */
	u64 pkts_delayed_data;
};

#define OCTEP_OQ_RECVBUF_SIZE (sizeof(struct octep_rx_buffer))
/* The Descriptor Ring Output Queue structure.
 * This structure has all the information required to implement a
 * Octeon OQ.
 */
struct octep_oq {
	u32 q_no;

	struct octep_sdp_dev *octep_dev;
	struct net_device *netdev;
	struct device *dev;

	struct napi_struct *napi;

	/* The receive buffer list. This list has the virtual addresses
	 * of the buffers.
	 */
	struct octep_rx_buffer *buff_info;

	/* Pointer to the mapped packet credit register.
	 * Host writes number of info/buffer ptrs available to this register
	 */
	u8 __iomem *pkts_credit_reg;

	/* Pointer to the mapped packet sent register.
	 * Octeon writes the number of packets DMA'ed to host memory
	 * in this register.
	 */
	u8 __iomem *pkts_sent_reg;

	/* Statistics for this OQ. */
	struct octep_oq_stats stats;

	/* Packets pending to be processed */
	u32 pkts_pending;
	u32 last_pkt_count;

	/* Index in the ring where the driver should read the next packet */
	u32 host_read_idx;

	/* Number of  descriptors in this ring. */
	u32 max_count;
	u32 ring_size_mask;

	/* The number of descriptors pending refill. */
	u32 refill_count;

	/* Index in the ring where the driver will refill the
	 * descriptor's buffer
	 */
	u32 host_refill_idx;
	u32 refill_threshold;

	/* The size of each buffer pointed by the buffer pointer. */
	u32 buffer_size;
	u32 max_single_buffer_size;

	/* indicates queue is suspended in case of unexpected/unhandled event */
	bool suspend;

	/* The 8B aligned descriptor ring starts at this address. */
	struct octep_oq_desc_hw *desc_ring;

	/* DMA mapped address of the OQ descriptor ring. */
	dma_addr_t desc_ring_dma;
};

#define OCTEP_OQ_SIZE (sizeof(struct octep_oq))
/* Tx offload flags */
#define OCTEP_TX_OFFLOAD_VLAN_INSERT BIT(0)
#define OCTEP_TX_OFFLOAD_IPV4_CKSUM  BIT(1)
#define OCTEP_TX_OFFLOAD_UDP_CKSUM   BIT(2)
#define OCTEP_TX_OFFLOAD_TCP_CKSUM   BIT(3)
#define OCTEP_TX_OFFLOAD_SCTP_CKSUM  BIT(4)
#define OCTEP_TX_OFFLOAD_TCP_TSO     BIT(5)
#define OCTEP_TX_OFFLOAD_UDP_TSO     BIT(6)

#define OCTEP_TX_OFFLOAD_CKSUM                                                                     \
	(OCTEP_TX_OFFLOAD_IPV4_CKSUM | OCTEP_TX_OFFLOAD_UDP_CKSUM | OCTEP_TX_OFFLOAD_TCP_CKSUM)

#define OCTEP_TX_OFFLOAD_TSO (OCTEP_TX_OFFLOAD_TCP_TSO | OCTEP_TX_OFFLOAD_UDP_TSO)

#define OCTEP_TX_IP_CSUM(flags)                                                                    \
	((flags) &                                                                                 \
	 (OCTEP_TX_OFFLOAD_IPV4_CKSUM | OCTEP_TX_OFFLOAD_TCP_CKSUM | OCTEP_TX_OFFLOAD_UDP_CKSUM))

#define OCTEP_TX_TSO(flags) ((flags) & (OCTEP_TX_OFFLOAD_TCP_TSO | OCTEP_TX_OFFLOAD_UDP_TSO))

/* bit 0 is vlan strip */
#define OCTEP_RX_CSUM_IP_VERIFIED BIT(1)
#define OCTEP_RX_CSUM_L4_VERIFIED BIT(2)

#define OCTEP_RX_CSUM_VERIFIED(flags)                                                              \
	((flags) & (OCTEP_RX_CSUM_L4_VERIFIED | OCTEP_RX_CSUM_IP_VERIFIED))

struct tx_mdata {
	/* offload flags */
	u16 ol_flags;

	/* gso size */
	u16 gso_size;

	/* gso flags */
	u16 gso_segs;

	/* reserved */
	u16 rsvd1;

	/* reserved */
	u64 rsvd2;
} __packed;

/* 64-byte Tx instruction format.
 * Format of instruction for a 64-byte mode input queue.
 *
 * only first 16-bytes (dptr and ih) are mandatory; rest are optional
 * and filled by the driver based on firmware/hardware capabilities.
 * These optional headers together called Front Data and its size is
 * described by ih->fsz.
 */
struct octep_tx_desc_hw {
	/* Pointer where the input data is available. */
	u64 dptr;

	/* Instruction Header. */
	union {
		struct octep_instr_hdr ih;
		u64 ih64;
	};
	union {
		u64 txm64[2];
		struct tx_mdata txm;
	};
	/* Additional headers available in a 64-byte instruction. */
	u64 exthdr[4];
} __packed;

#define OCTEP_IQ_DESC_SIZE (sizeof(struct octep_tx_desc_hw))

#define IQ_SEND_OK     0
#define IQ_SEND_STOP   1
#define IQ_SEND_FAILED -1

#define TX_BUFTYPE_NONE   0
#define TX_BUFTYPE_NET    1
#define TX_BUFTYPE_NET_SG 2
#define NUM_TX_BUFTYPES   3

/* Hardware format for Scatter/Gather list */
struct octep_tx_sglist_desc {
	u16 len[4];
	dma_addr_t dma_ptr[4];
} __packed;

/* Each Scatter/Gather entry sent to hardwar hold four pointers.
 * So, number of entries required is (MAX_SKB_FRAGS + 1)/4, where '+1'
 * is for main skb which also goes as a gather buffer to Octeon hardware.
 * To allocate sufficient SGLIST entries for a packet with max fragments,
 * align by adding 3 before calcuating max SGLIST entries per packet.
 */
#ifndef MAX_SKB_FRAGS
#define MAX_SKB_FRAGS 17
#endif
#define OCTEP_SGLIST_ENTRIES_PER_PKT ((MAX_SKB_FRAGS + 1 + 3) / 4)
#define OCTEP_SGLIST_SIZE_PER_PKT                                                                  \
	(OCTEP_SGLIST_ENTRIES_PER_PKT * sizeof(struct octep_tx_sglist_desc))

struct octep_tx_buffer {
	struct sk_buff *skb;
	dma_addr_t dma;
	struct octep_tx_sglist_desc *sglist;
	dma_addr_t sglist_dma;
	u8 gather;
	void *data;
	u32 nsegs;
	struct page *pages[10];
	void *sg_va_addr[10];
};

#define OCTEP_IQ_TXBUFF_INFO_SIZE (sizeof(struct octep_tx_buffer))

/* Input Queue statistics. Each input queue has four stats fields. */
struct octep_iq_stats {
	/* Instructions posted to this queue. */
	u64 instr_posted;

	/* Instructions copied by hardware for processing. */
	u64 instr_completed;

	/* Instructions that could not be processed. */
	u64 instr_dropped;

	/* Bytes sent through this queue. */
	u64 bytes_sent;

	/* Gather entries sent through this queue. */
	u64 sgentry_sent;

	/* Number of transmit failures due to TX_BUSY */
	u64 tx_busy;

	/* Number of times the queue is restarted */
	u64 restart_cnt;
};

/* The instruction (input) queue.
 * The input queue is used to post raw (instruction) mode data or packet
 * data to Octeon device from the host. Each input queue (up to 4) for
 * a Octeon device has one such structure to represent it.
 */
struct octep_iq {
	u32 q_no;

	struct octep_sdp_dev *octep_dev;
	struct net_device *netdev;
	struct device *dev;
	struct netdev_queue *netdev_q;

	/* Index in input ring where driver should write the next packet */
	u16 host_write_index;

	/* Index in input ring where Octeon is expected to read next packet */
	u16 octep_read_index;

	/* This index aids in finding the window in the queue where Octeon
	 * has read the commands.
	 */
	u16 flush_index;

	/* Statistics for this input queue. */
	struct octep_iq_stats stats;

	/* Pointer to the Virtual Base addr of the input ring. */
	struct octep_tx_desc_hw *desc_ring;

	/* DMA mapped base address of the input descriptor ring. */
	dma_addr_t desc_ring_dma;

	/* Info of Tx buffers pending completion. */
	struct octep_tx_buffer *buff_info;

	/* Base pointer to Scatter/Gather lists for all ring descriptors. */
	struct octep_tx_sglist_desc *sglist;

	/* DMA mapped addr of Scatter Gather Lists */
	dma_addr_t sglist_dma;

	/* Octeon doorbell register for the ring. */
	u8 __iomem *doorbell_reg;

	/* Octeon instruction count register for this ring. */
	u8 __iomem *inst_cnt_reg;

	/* interrupt level register for this ring */
	u8 __iomem *intr_lvl_reg;

	/* Maximum no. of instructions in this queue. */
	u32 max_count;
	u32 ring_size_mask;

	u32 pkt_in_done;
	u32 pkts_processed;

	u32 status;

	/* Number of instructions pending to be posted to Octeon. */
	u32 fill_cnt;

	/* The max. number of instructions that can be held pending by the
	 * driver before ringing doorbell.
	 */
	u32 fill_threshold;
	int msix_ent;
	spinlock_t iq_lock; /* lock for synchronization */
};

/* PCI address space mapping information.
 * Each of the 3 address spaces given by BAR0, BAR2 and BAR4 of
 * Octeon gets mapped to different physical address spaces in
 * the kernel.
 */
struct octep_mmio {
	/* The physical address to which the PCI address space is mapped. */
	u8 __iomem *hw_addr;

	/* Flag indicating the mapping was successful. */
	int mapped;
};

struct octep_pci_win_regs {
	u8 __iomem *pci_win_wr_addr;
	u8 __iomem *pci_win_rd_addr;
	u8 __iomem *pci_win_wr_data;
	u8 __iomem *pci_win_rd_data;
};

struct octep_hw_ops {
	void (*setup_iq_regs)(struct octep_sdp_dev *octep_dev, int q);
	int (*setup_oq_regs)(struct octep_sdp_dev *octep_dev, int q);
	void (*setup_mbox_regs)(struct octep_sdp_dev *octep_dev, int mbox);

	irqreturn_t (*mbox_intr_handler)(void *ioq_vector);
	irqreturn_t (*oei_intr_handler)(void *ioq_vector);
	irqreturn_t (*ire_intr_handler)(void *ioq_vector);
	irqreturn_t (*ore_intr_handler)(void *ioq_vector);
	irqreturn_t (*vfire_intr_handler)(void *ioq_vector);
	irqreturn_t (*vfore_intr_handler)(void *ioq_vector);
	irqreturn_t (*dma_intr_handler)(void *ioq_vector);
	irqreturn_t (*dma_vf_intr_handler)(void *ioq_vector);
	irqreturn_t (*pp_vf_intr_handler)(void *ioq_vector);
	irqreturn_t (*misc_intr_handler)(void *ioq_vector);
	irqreturn_t (*rsvd_intr_handler)(void *ioq_vector);
	irqreturn_t (*ioq_intr_handler)(void *ioq_vector);
	int (*soft_reset)(struct octep_sdp_dev *octep_dev);
	void (*reinit_regs)(struct octep_sdp_dev *octep_dev);
	u32 (*update_iq_read_idx)(struct octep_iq *iq);

	void (*enable_interrupts)(struct octep_sdp_dev *octep_dev);
	void (*disable_interrupts)(struct octep_sdp_dev *octep_dev);
	void (*poll_non_ioq_interrupts)(struct octep_sdp_dev *octep_dev);

	void (*enable_io_queues)(struct octep_sdp_dev *octep_dev);
	void (*disable_io_queues)(struct octep_sdp_dev *octep_dev);
	void (*enable_iq)(struct octep_sdp_dev *octep_dev, int q);
	void (*disable_iq)(struct octep_sdp_dev *octep_dev, int q);
	void (*enable_oq)(struct octep_sdp_dev *octep_dev, int q);
	void (*disable_oq)(struct octep_sdp_dev *octep_dev, int q);
	void (*reset_io_queues)(struct octep_sdp_dev *octep_dev);
	void (*dump_registers)(struct octep_sdp_dev *octep_dev);
	void (*dump_OQ_registers)(struct octep_sdp_dev *octep_dev, int q);
	int (*octep_update_config_active_io_ring)(struct octep_sdp_dev *octep_dev, u8 enable);
	void (*reset_iqueue)(struct octep_sdp_dev *octep_dev, int q);
};

/* PFVF mailbox data */
struct octep_mbox_data {
	u32 cmd;
	u32 total_len;
	u32 recv_len;
	u32 rsvd;
	u64 *data;
};

#define MAX_VF_PF_MBOX_DATA_SIZE 384
/* wrappers around work structs */
struct octep_pfvf_mbox_wk {
	struct work_struct work;
	void *ctxptr;
	u64 ctxul;
};

/* SDP device PFVF mailbox */
struct octep_sdp_mbox {
	/* A mutex to protect access to this q_mbox. */
	struct mutex lock;
	u32 vf_id;
	u32 config_data_index;
	u32 message_len;
	u8 __iomem *pf_vf_data_reg;
	u8 __iomem *vf_pf_data_reg;
	struct octep_pfvf_mbox_wk wk;
	struct octep_sdp_dev *octep_dev;
	struct octep_mbox_data mbox_data;
	u8 config_data[MAX_VF_PF_MBOX_DATA_SIZE];
};

/* VF information structure */
struct octep_pfvf_info {
	u8 mac_addr[ETH_ALEN];
	u32 mbox_version;
	u32 flags;
	struct net_device *netdev; /* VF's network device */
};

/* Octeon VF mailbox data */
struct octep_vf_mbox_data {
	/* Holds the offset of received data via mailbox. */
	u32 data_index;

	/* Holds the received data via mailbox. */
	u8 recv_data[OCTEP_RDMA_PFVF_MBOX_MAX_DATA_BUF_SIZE];
};

struct octep_vf_mbox_wk {
	struct work_struct work;
	void *ctxptr;
};

/* Octeon SDP VF mailbox */
struct octep_sdp_vf_mbox {
	/* A mutex to protect access to this q_mbox. */
	struct mutex lock;

	u32 state;

	/* SLI_MAC_PF_MBOX_INT for PF, SLI_PKT_MBOX_INT for VF. */
	u8 __iomem *mbox_int_reg;

	/* SLI_PKT_PF_VF_MBOX_SIG(0) for PF,
	 * SLI_PKT_PF_VF_MBOX_SIG(1) for VF.
	 */
	u8 __iomem *mbox_write_reg;

	/* SLI_PKT_PF_VF_MBOX_SIG(1) for PF,
	 * SLI_PKT_PF_VF_MBOX_SIG(0) for VF.
	 */
	u8 __iomem *mbox_read_reg;

	/* Octeon VF mailbox data */
	struct octep_vf_mbox_data mbox_data;

	/* Octeon VF mailbox work handler to process Mbox messages */
	struct octep_vf_mbox_wk wk;
};

/* Tx/Rx queue vector per interrupt. */
struct octep_ioq_vector {
	char name[OCTEP_MSIX_NAME_SIZE];
	struct napi_struct napi;
	struct octep_sdp_dev *octep_dev;
	struct octep_iq *iq;
	struct octep_oq *oq;
	cpumask_t affinity_mask;
};

/* Device state */
enum octep_dev_state {
	OCTEP_DEV_STATE_OPEN,
	OCTEP_DEV_STATE_READ_STATS,
	OCTEP_DEV_STATE_DOWN_IN_PROGRESS,
};

struct octep_sdp_dev {
	struct octep_config *conf;
	/** OS dependent PCI device pointer */
	struct pci_dev *pdev;
	/** work queue to initialize device */
	struct work_struct dev_setup_task;

	/* Octeon Chip type. */
	u16 chip_id;
	u16 rev_id;
	/* memory mapped io range */
	struct octep_mmio mmio[OCTEP_MMIO_REGIONS];

	/* Netdev corresponding to the Octeon device */
	struct net_device *netdev;
	/* MAC address */
	u8 mac_addr[ETH_ALEN];

	/* Tx queues (IQ: Instruction Queue) */
	u16 num_iqs;

	/* Pointers to Octeon Tx queues */
	struct octep_iq *iq[OCTEP_MAX_IQ];

	/* Rx queues (OQ: Output Queue) */
	u16 num_oqs;
	/* Pointers to Octeon Rx queues */
	struct octep_oq *oq[OCTEP_MAX_OQ];

	/* Hardware port number of the PCIe interface */
	u16 pcie_port;

	/* PCI Window registers to access some hardware CSRs */
	struct octep_pci_win_regs pci_win_regs;
	/* Hardware operations */
	struct octep_hw_ops hw_ops;

	/* IRQ info */
	u16 num_irqs;
	u16 num_non_ioq_irqs;
	u16 num_custom_irqs;
	char *non_ioq_irq_names;
	struct msix_entry *msix_entries;
	/* IOq information of it's corresponding MSI-X interrupt. */
	struct octep_ioq_vector *ioq_vector[OCTEP_MAX_QUEUES];

	struct octep_caps_region oct_caps;
	struct task_struct *thread;
	wait_queue_head_t wait_queue;
	enum octep_wq_flag wq_flag;
	enum octep_wq_status wq_state;
	/* PF VF mailbox */
	struct octep_sdp_mbox *mbox[OCTEP_MAX_VF];
	/* VFs info */
	struct octep_pfvf_info vf_info[OCTEP_MAX_VF];
	/* VF mailbox */
	struct octep_sdp_vf_mbox *vf_mbox;
	/* Enable non-ioq interrupt polling */
	bool poll_non_ioq_intr;
	/* Work entry to poll non-ioq interrupts */
	struct delayed_work intr_poll_task;
	/* Device status */
	atomic_t status;
	/* Firmware heartbeat timer */
	struct timer_list hb_timer;
	/* Firmware heartbeat miss count tracked by timer */
	atomic_t hb_miss_cnt;
	/* Task to reset device on heartbeat miss */
	/* Task to reset device on heartbeat miss */
	struct delayed_work hb_task;
	/* Task to reset VF device on heartbeat miss */
	struct delayed_work vf_hb_task;
	/* Device state */
	unsigned long state;
	/* Negotiated Mbox version */
	u32 mbox_neg_ver;
};

static inline u16 OCTEP_MAJOR_REV(struct octep_sdp_dev *octep_dev)
{
	u16 rev = (octep_dev->rev_id & 0xC) >> 2;

	return (rev == 0) ? 1 : rev;
}

static inline u16
OCTEP_MINOR_REV(struct octep_sdp_dev *octep_dev)
{
	return (octep_dev->rev_id & 0x3);
}

/* Octeon CSR read/write access APIs */
#define octep_write_csr(octep_dev, reg_off, value)                                                 \
	writel(value, (octep_dev)->mmio[0].hw_addr + (reg_off))

#define octep_write_csr64(octep_dev, reg_off, val64)                                               \
	writeq(val64, (octep_dev)->mmio[0].hw_addr + (reg_off))

#define octep_read_csr(octep_dev, reg_off) readl((octep_dev)->mmio[0].hw_addr + (reg_off))

#define octep_read_csr64(octep_dev, reg_off) readq((octep_dev)->mmio[0].hw_addr + (reg_off))

/* Read windowed register.
 * @param  oct   -  pointer to the Octeon device.
 * @param  addr  -  Address of the register to read.
 *
 * This routine is called to read from the indirectly accessed
 * Octeon registers that are visible through a PCI BAR0 mapped window
 * register.
 * @return  - 64 bit value read from the register.
 */
static inline u64
OCTEP_PCI_WIN_READ(struct octep_sdp_dev *octep_dev, u64 addr)
{
	u64 val64;

	addr |= 1ull << 53; /* read 8 bytes */
	writeq(addr, octep_dev->pci_win_regs.pci_win_rd_addr);
	val64 = readq(octep_dev->pci_win_regs.pci_win_rd_data);

	dev_dbg(&octep_dev->pdev->dev, "%s: reg: 0x%016llx val: 0x%016llx\n", __func__, addr,
		val64);

	return val64;
}

/* Write windowed register.
 * @param  oct  -  pointer to the Octeon device.
 * @param  addr -  Address of the register to write
 * @param  val  -  Value to write
 *
 * This routine is called to write to the indirectly accessed
 * Octeon registers that are visible through a PCI BAR0 mapped window
 * register.
 * @return   Nothing.
 */
static inline void
OCTEP_PCI_WIN_WRITE(struct octep_sdp_dev *octep_dev, u64 addr, u64 val)
{
	writeq(addr, octep_dev->pci_win_regs.pci_win_wr_addr);
	writeq(val, octep_dev->pci_win_regs.pci_win_wr_data);

	dev_dbg(&octep_dev->pdev->dev, "%s: reg: 0x%016llx val: 0x%016llx\n", __func__, addr, val);
}

int octep_oq_process_rx(struct octep_oq *oq, int budget);
int send_skbuff(struct octep_sdp_dev *octep_dev);
void octep_device_setup_cnxk_pf(struct octep_sdp_dev *octep_dev);
void octep_device_setup_cnxk_vf(struct octep_sdp_dev *octep_dev);
int octep_rdma_probe_dev(struct octep_sdp_dev *octep_dev);
void octep_device_cleanup(struct octep_sdp_dev *octep_dev);
int octep_setup_irqs(struct octep_sdp_dev *octep_dev);
void octep_clean_irqs(struct octep_sdp_dev *octep_dev);
int octep_device_qp_setup(struct octep_sdp_dev *octep_dev, int q_no, uint16_t sq_size,
			  uint16_t rq_size);
int octep_tx(struct octep_sdp_dev *octep_dev, int q_no, union octep_rdma_sqe *sqe);
int octep_device_qp_release(struct octep_sdp_dev *octep_dev, int q_no);
void octep_oq_free_ring_buffers(struct octep_oq *oq);
void octep_iq_reset_indices(struct octep_iq *iq);
void octep_oq_reset_indices(struct octep_oq *oq);
int octep_oq_check_hw_for_pkts(struct octep_sdp_dev *octep_dev, struct octep_oq *oq);
int octep_oq_refill(struct octep_sdp_dev *octep_dev, struct octep_oq *oq);
int octep_oq_fill_ring_buffers_custom(struct octep_sdp_dev *octep_dev, int q_no,
				      union octep_rdma_rqe *rqe, int i);

/* Function prototypes for work queue tasks and interrupt handlers */
void octep_intr_poll_task(struct work_struct *work);
void octep_hb_timeout_task(struct work_struct *work);
void cancel_all_tasks(struct octep_sdp_dev *octep_dev);

#endif /* __OCTEP_SDP_H__ */
