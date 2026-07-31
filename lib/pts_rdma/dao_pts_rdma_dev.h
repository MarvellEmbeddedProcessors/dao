/* SPDX-License-Identifier: Marvell-Proprietary
 * Copyright(C) 2025 Marvell.
 */
#ifndef __INCLUDE_DAO_PTS_RDMA_DEV_H__
#define __INCLUDE_DAO_PTS_RDMA_DEV_H__

/* Required standard and DPDK headers for types and mbuf helpers */
#include <rte_bitmap.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <stdbool.h>
#include <stdint.h>

#define DAO_PTS_RDMA_MAX_DEVS 128U
#define DAO_PTS_RDMA_MAX_QPS  1024U
#define DAO_PTS_RDMA_MAX_CQS  1024U

#define DAO_PTS_RDMA_MAX_SGES 6U

struct dao_pts_rdma_mbox_hdr {
	uint8_t ver;
	uint8_t rsvd1;
	uint16_t id;
	uint16_t rsvd2;
#define MBOX_REQ_SIG (0xdead)
#define MBOX_RSP_SIG (0xbeef)
	uint16_t sig;
};

struct dao_pts_rdma_mbox_sts {
	uint16_t rsp : 1;
	uint16_t rc : 15;
	uint16_t rsvd;
};

struct dao_pts_rdma_mbox {
	struct dao_pts_rdma_mbox_hdr hdr;
	struct dao_pts_rdma_mbox_sts sts;
	uint64_t rsvd;
	uint32_t data[];
};

/* Structure for PTS RDMA device basic SGE element */
struct dao_pts_rdma_sge {
	uint64_t addr;
	uint32_t length;
	uint32_t lkey;
} __attribute__((packed));

enum dao_pts_rdma_opcode {
	/* Defines matching with enum ibv_wr_opcode */
	DAO_PTS_RDMA_WRITE = 0,
	DAO_PTS_RDMA_WRITE_WITH_IMM = 1,
	DAO_PTS_RDMA_SEND = 2,
	DAO_PTS_RDMA_SEND_WITH_IMM = 3,
	DAO_PTS_RDMA_READ = 4,
	DAO_PTS_RDMA_ATOMIC_CMP_AND_SWP,
	DAO_PTS_RDMA_ATOMIC_FETCH_AND_ADD,
	DAO_PTS_RDMA_LOCAL_INV,
	DAO_PTS_RDMA_BIND_MW,
	DAO_PTS_RDMA_SEND_WITH_INV,
	DAO_PTS_RDMA_TSO,
	DAO_PTS_RDMA_DRIVER1,
	DAO_PTS_RDMA_FLUSH = 14,
	DAO_PTS_RDMA_ATOMIC_WRITE = 15,

	/* Custom opcodes */
	/** RDMA read completion with octeon as responder */
	DAO_PTS_RDMA_D2M_COMPL = 128,
};

/* Send flags that dictates work completion */
enum dao_pts_rdma_send_flags {
	DAO_PTS_RDMA_SEND_SIGNALLED = 1 << 1,
};

/* BIT 63:60 used for the direction */
#define DAO_PTS_RDMA_ENQ_M2D              (0X1ULL) /* RDMA_WRITE */
#define DAO_PTS_RDMA_ENQ_D2M              (0X2ULL) /* RDMA_READ */
#define DAO_PTS_RDMA_ENQ_M2D_RQE          (0X3ULL)
#define DAO_PTS_RDMA_ENQ_M2D_RQE_WITH_CQE (0X4ULL) /* SEND or RDMA_WRITE_WITH_IMM */
#define DAO_PTS_RDMA_ENQ_M2D_WITH_CQE     (0X5ULL) /* RDMA_WRITE_WITH_IMM */
#define DAO_PTS_RDMA_ENQ_M2D_SQE_WITH_CQE (0X6ULL) /* RDMA_READ_RESPONSE */
#define DAO_PTS_RDMA_ENQ_M2D_SQE          (0X7ULL) /* RDMA_READ_RESPONSE_WITHOUT_CQE */

/* Structure for PTS RDMA CQE DESCRIPTOR */
struct dao_pts_rdma_cqe {
	/* WORD 0 */
	uint8_t opcode;
	uint8_t status;
	uint16_t vendor_err;
	uint32_t byte_len;
	/* WORD 1 */
	uint64_t wr_id;
	/* WORD 2 */
	uint32_t reserved1;
	uint32_t imm_data;
	/* WORD 3 */
	uint32_t qp_id;
	uint32_t reserved2;
	/* WORD 4-7 */
	uint64_t ibqp;
	uint64_t reserved3[3];
} __attribute__((packed));

/* Structure for PTS RDMA RQE DESCRIPTOR */
union dao_pts_rdma_rqe {
	struct {
		/* WORD 0 */
		uint32_t flags;
		uint16_t reserved;
		uint16_t num_sge;
		/* WORD 1 */
		uint64_t wr_id;
		/* WORD 2-3 */
		struct dao_pts_rdma_sge sges0[1];
	};
	/* WORD 0-3 */
	struct dao_pts_rdma_sge sges1[2];
} __attribute__((packed));

/* Structure for PTS RDMA SQE DESCRIPTOR */
union dao_pts_rdma_sqe {
	struct {
		/* WORD 0 */
		uint8_t opcode;
		uint8_t send_flags;
		uint8_t flags;
		uint8_t num_sges;
		uint32_t imm_data;
		/* WORD 1 */
		uint64_t wr_id;
		/* WORD 2-3 */
		union {
			struct {
				uint64_t remote_addr;
				uint32_t rkey;
				uint32_t reserved;
			} rdma;
		};
		/* WORD 4-7 */
		struct dao_pts_rdma_sge sges0[2];
	};
	/* WORD 0-7 */
	struct dao_pts_rdma_sge sges1[4];
};

/* Structure for PTS RDMA device */
struct dao_pts_rdma_dev {
	/** Array of pts rdma dev queue pair pointers */
	void *qps[DAO_PTS_RDMA_MAX_QPS] __rte_cache_aligned;
	/** Dequeue function id */
	uint16_t deq_fn_id;
	/** Enqueue function id */
	uint16_t enq_fn_id;
	/** Descriptors management function id */
	uint16_t mgmt_fn_id;
	/** Bitmap to track enabled qps */
	struct rte_bitmap *qp_bmap;
	/** Table to find hash report based on packet type */
#define DAO_PTS_RDMA_DEV_MEM_SZ 16834
	uint8_t reserved[DAO_PTS_RDMA_DEV_MEM_SZ];
};

/* Structure for RDMA TR device configuration */
struct dao_pts_rdma_dev_conf {
	/** PEM device ID */
	uint16_t pem_devid;
	/** Vchan to use for this PTS RDMA dev */
	uint16_t dma_vchan;
	/** Max number of queue pairs */
	uint16_t max_qps_limit;
	/** Mac port ID*/
	uint16_t mac_port_id;
	/** Max number of CQs */
	uint16_t max_cqs_limit;
	/** Default dequeue mempool used for Inbound DMA'ed data */
	struct rte_mempool *data_pool;
	/** Auto free enabled/disabled */
	bool auto_free_en;
};

/* Structure for RDMA TR device info */
struct dao_pts_rdma_dev_info {
	/** Max number of queue pairs */
	uint16_t max_qps;
	/** Max number of CQs */
	uint16_t max_cqs;
	/** Notify offset multiply factor */
	uint16_t notify_off_mltpr;
	/** Notify queues multiply factor */
	uint16_t notify_qs_mltpr;
	/** BAR4 size */
	uint32_t bar4_sz;
};

#define DAO_PTS_RDMA_SQE_DESC_SIZE 32U
#define DAO_PTS_RDMA_SGE_OFFSET    DAO_PTS_RDMA_SQE_DESC_SIZE

#define DAO_PTS_RDMA_MBUF_TO_SGES(mbuf)                                                            \
	((struct dao_pts_rdma_sge *)((uint8_t *)rte_mbuf_to_priv(mbuf) + DAO_PTS_RDMA_SGE_OFFSET))

#define DAO_PTS_RDMA_MBUF_TO_CQE(mbuf)                                                             \
	((struct dao_pts_rdma_cqe *)((uint8_t *)rte_mbuf_to_priv(mbuf) + DAO_PTS_RDMA_SGE_OFFSET + \
				     ((mbuf)->l2_len * sizeof(struct dao_pts_rdma_sge))))

#define DAO_PTS_RDMA_RES_RQ_BITS       20
#define DAO_PTS_RDMA_RES_READ_BITS     22
#define DAO_PTS_RDMA_RES_NON_READ_BITS 22

#define DAO_PTS_RDMA_RES_RQ_SHIFT       0
#define DAO_PTS_RDMA_RES_READ_SHIFT     DAO_PTS_RDMA_RES_RQ_BITS
#define DAO_PTS_RDMA_RES_NON_READ_SHIFT (DAO_PTS_RDMA_RES_RQ_BITS + DAO_PTS_RDMA_RES_READ_BITS)

#define DAO_PTS_RDMA_RES_RQ_MASK       ((1ULL << DAO_PTS_RDMA_RES_RQ_BITS) - 1)
#define DAO_PTS_RDMA_RES_READ_MASK     ((1ULL << DAO_PTS_RDMA_RES_READ_BITS) - 1)
#define DAO_PTS_RDMA_RES_NON_READ_MASK ((1ULL << DAO_PTS_RDMA_RES_NON_READ_BITS) - 1)

/**
 * Get max supported read requests
 *
 * @return
 * max supported read requests
 */

int dao_pts_rdma_max_read_req_get(void);

/**
 * Set RDMA dev QP MTU.
 *
 * @param devid
 *   RDMA dev id
 * @param qp_id
 *   RDMA dev qp id
 * @param mtu
 *   MTU value to set
 * @return
 *   0 on success, negative on error
 */
int dao_pts_rdma_qp_mtu_set(uint16_t devid, uint16_t qp_id, uint16_t mtu);

/**
 * Get RDMA dev RQ depth.
 *
 * @param devid
 *   RDMA dev id
 * @param qp_id
 *   RDMA dev qp id
 * @param avail
 *   RDMA rq depth to return
 * @return
 *   0 on success, negative on error
 */
int dao_pts_rdma_rq_avail_get(uint16_t devid, uint16_t qp_id, uint16_t *avail);

/**
 * Get RDMA dev resource availability
 *
 * @param devid
 *   RDMA dev id
 * @param qp_id
 *   RDMA dev qp id
 * @param avail
 *   bits [19:0]  — RQ descriptor depth
 *   bits [41:20]  — non-read desc count available
 *   bits [63:42] — read desc count available
 * @return
 *   0 on success, negative on error
 */
int dao_pts_rdma_res_avail_get(uint16_t devid, uint16_t qp_id, uint64_t *avail);

/**
 * Get RDMA TR device info.
 *
 * @param pem_devid
 *   RDMA TR device pem id
 * @param dev_id
 *   RDMA TR device id
 * @param dev_info
 *   RDMA TR device info
 * @return
 *   0 on success, negative on error
 */
int dao_pts_rdma_dev_info_get(uint16_t pem_devid, uint16_t dev_id,
			      struct dao_pts_rdma_dev_info *dev_info);

/**
 * Set RDMA TR device QP's send queue mempool
 *
 * @param devid
 *   RDMA dev id
 * @param qp_id
 *   RDMA dev qp id
 * @param pool
 *   Mempool to assign to the SQ
 * @return
 *   0 on success, negative on error
 */
int dao_pts_rdma_qp_pool_set(uint16_t devid, uint16_t qp_id, struct rte_mempool *pool);

/**
 * Initialize RDMA TR device.
 *
 * @param dev_id
 *   RDMA TR device id
 * @param conf
 *   RDMA TR device configuration
 * @return
 *   0 on success, negative on error
 */
int dao_pts_rdma_dev_init(uint16_t dev_id, struct dao_pts_rdma_dev_conf *conf);

/**
 * Finalize RDMA TR device.
 *
 * @param dev_id
 *   RDMA TR device id
 * @return
 *   0 on success, negative on error
 */
int dao_pts_rdma_dev_fini(uint16_t dev_id);

/**
 * Update the RDMA TR device config opaque data.
 *
 * @param devid
 *   RDMA TR device id
 * @param opaque
 *   Opaque data to be updated
 * @param opaque_len
 *   Length of opaque data
 * @return
 *   0 on success, negative on error
 */
int dao_pts_rdma_dev_config_update(uint16_t devid, uint8_t *cfg, uint16_t cfg_len);

/**
 * Fetch the RDMA TR device descriptors from SQ, RQ and CQ.
 *
 * @param devid
 *   RDMA TR device id
 * @return
 *   0 on success, negative on error
 */
int dao_pts_rdma_desc_manage(uint16_t devid);

/**
 * Dequeue burst of packets from a qp(send queue) of a RDMA TR device.
 *
 * MBUF data return based on opcode.
 *
 * RDMA_WRITE:
 * RDMA_WRITE_WITH_IMM:
 *	rte_mbuf::packet_type : enum ibv_wr_opcode
 *      rte_mbuf::priv_data :
 *	    <SQE descriptor without SGEs - 64B>
 *      rte_mbuf::data :
 *	    <DMAed DATA from SGEs>
 *
 * RDMA_SEND:
 * RDMA_SEND_WITH_IMM:
 *	rte_mbuf::packet_type : enum ibv_wr_opcode
 *      rte_mbuf::priv_data :
 *	    <SQE descriptor without SGEs - 64B>
 *      rte_mbuf::data :
 *	    <DMAed DATA from SGEs>
 *
 * RDMA_READ:
 *	rte_mbuf::packet_type : enum ibv_wr_opcode
 *      rte_mbuf::priv_data :
 *	    <SQE descriptor with SGEs>
 *
 * RDMA_D2M_COMPL:
 *	rte_mbuf::packet_type : DAO_PTS_RDMA_D2M_COMPL
 *      rte_mbuf::priv_data + 32:
 *	    <array of `struct dao_pts_rdma_sge` representing remote addr>
 *      rte_mbuf::data :
 *          <packet data to be DMAed from SGEs>
 *
 * @param devid
 *   RDMA TR device id
 * @param qp_id
 *   Queue pair id
 * @param rx_pkts
 *   Array to store the dequeued packets
 * @param nb_pkts
 *   Maximum number of packets to dequeue
 *   bit 0-7 indicates packets to dequeue from host
 *   bit 8-15 indicates read reply packets count
 * @return
 *   Number of packets dequeued, 0 on error or no packets available.
 */
uint16_t dao_pts_rdma_dequeue_burst(uint16_t devid, uint16_t qp_id, struct rte_mbuf **rx_pkts,
				    uint16_t nb_pkts);

/**
 * Get the management QP ID for a device.
 *
 * @param devid
 *   Device identifier
 * @return
 *   Management QP ID (>= 0) if configured, -1 if not
 */
int32_t dao_pts_rdma_mgmt_qp_id_get(uint16_t devid);

/**
 * Enqueue burst of packets to a qp(completion queue or just DMA?) of a RDMA TR device.
 *
 * MBUF data expected.
 *	rte_mbuf::l2_len : sizeof SGE list.
 *      rte_mbuf::priv_data + 32:
 *	    <array of `struct dao_pts_rdma_sge` representing remote addr>
 *      rte_mbuf::priv_data + 32 + sizeof SGE list:
 *          <CQE data of 64B when CQE needs to be generated or 0B>
 *	rte_mbuf::data :
 *          In case of DAO_PTS_RDMA_ENQ_M2D*:
 *		<packet data to be DMAed to SGEs>
 *          In case of DAO_PTS_RDMA_ENQ_D2M*:
 *		<packet data to be DMAed from SGEs>
 *      rte_mbuf::ol_flags :
 *           DAO_PTS_RDMA_ENQ_M2D | DAO_PTS_RDMA_ENQ_D2M |
 *           DAO_PTS_RDMA_ENQ_M2D_RQE | DAO_PTS_RDMA_ENQ_M2D_RQE_WITH_CQE |
 *           DAO_PTS_RDMA_ENQ_M2D_WITH_CQE | DAO_PTS_RDMA_ENQ_M2D_SQE_WITH_CQE
 *
 * @param devid
 *   RDMA TR device id
 * @param qp_id
 *   Queue pair id.
 * @param tx_pkts
 *   Array of packets to enqueue
 * @param nb_pkts
 *   Number of packets to enqueue
 * @return
 *   Number of packets successfully enqueued, 0 on error or no space.
 */
uint16_t dao_pts_rdma_enqueue_burst(uint16_t devid, uint16_t qp_id, struct rte_mbuf **tx_pkts,
				    uint16_t nb_pkts);

/**
 * Enqueue burst of CQE to a CQ of a RDMA PTS device.
 *
 * @param devid
 *   RDMA TR device id
 * @param qp_id
 *   Queue pair id for which CQ is associated
 * @param recv
 *   true for receive queue CQ, false for send queue CQ
 * @param cqe
 *   Array of CQEs to enqueue
 * @param nb_cqes
 *   Number of CQEs to enqueue
 * @return
 *   Number of CQEs enqueued
 */
int dao_pts_rdma_enqueue_cqe(uint16_t devid, uint16_t qp_id, bool recv,
			     struct dao_pts_rdma_cqe *cqe, uint16_t nb_cqes);

/** RDMA TR device QP status callback */
typedef int (*dao_pts_rdma_dev_qp_status_cb_t)(uint16_t devid, uint16_t qp_id, uint16_t status);

/** RDMA TR device reset callback */
typedef int (*dao_pts_rdma_dev_reset_cb_t)(uint16_t devid);

/** RDMA TR device user mbox callback */
typedef int (*dao_pts_rdma_user_mbox_cb_t)(uint16_t devid, volatile struct dao_pts_rdma_mbox *req,
					   uint8_t *rsp, uint16_t *rsp_len);

/** RDMA TR device callbacks */
struct dao_pts_rdma_dev_cbs {
	/** Device QP status callback */
	dao_pts_rdma_dev_qp_status_cb_t qp_status_cb;
	/** Device reset callback */
	dao_pts_rdma_dev_reset_cb_t dev_reset_cb;
	/** Device user mbox callback */
	dao_pts_rdma_user_mbox_cb_t user_mbox_cb;
};

/**
 * Register RDMA TR device callbacks.
 *
 * @param cbs
 *   RDMA TR device callbacks
 */
void dao_pts_rdma_dev_cb_register(struct dao_pts_rdma_dev_cbs *cbs);

/**
 * Unregister RDMA TR device callbacks.
 */
void dao_pts_rdma_dev_cb_unregister(void);

/**
 * Copy given number of bytes to the dst buffer
 *
 * @param devid
 *   RDMA TR device id
 * @param dest
 *   Destination buffer
 * @param len
 *   Number of bytes to copy
 * @return
 *   Number of bytes copied on success, 0 on error
 */
uint16_t dao_pts_rdma_meta_data_get(uint16_t devid, void *dest, uint16_t len);

#endif /* __INCLUDE_DAO_PTS_RDMA_DEV_H__ */
