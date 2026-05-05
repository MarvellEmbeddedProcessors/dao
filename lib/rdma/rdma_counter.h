/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef __RDMA_COUNTER_H__
#define __RDMA_COUNTER_H__

#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <stdint.h>

#define RDMA_QP_MAX 1024

#define RDMA_INC_PORT_COUNTER(lcore, port, counter)                                                \
	rdma_counter_table[rdma_lcore_map->lcore_to_index[(lcore)]][(port)]                        \
		.port_counters[(counter)]++

#define RDMA_INC_QP_COUNTER(lcore, port, qid, counter)                                             \
	rdma_counter_table[rdma_lcore_map->lcore_to_index[(lcore)]][(port)]                        \
		.qp_counters[(qid)][(counter)]++

#define RDMA_PORT_COUNTER_LIST                                                                     \
	/** BTH header version mismatch detected during RDMA header validation. */                 \
	X(RDMA_RX_PORT_HDR_CHK_BTH_TVER_FAIL)                                                      \
	/** Multicast QPN detected, which is unsupported in the current RDMA implementation. */    \
	X(RDMA_RX_PORT_HDR_CHK_MULTICAST_QP_FAIL)                                                  \
	/** Invalid QPN encountered during RDMA header validation. */                              \
	X(RDMA_RX_PORT_HDR_CHK_QP_INV)                                                             \
	/** RDMA RX process header check failed */                                                 \
	X(RDMA_RX_PORT_RX_PROC_HDR_CHK_FAIL)                                                       \
	/** RDMA RX responder QP is not valid */                                                   \
	X(RDMA_RX_PORT_RSP_QP_INV)                                                                 \
	/** Invalid QPN encountered during processing ACK packets. */                              \
	X(RDMA_RX_PORT_PROC_ACK_QP_INV)                                                            \
	/** Invalid QPN encountered during TX Processing. */                                       \
	X(RDMA_TX_PORT_TX_PROC_QP_INV)                                                             \
	/** Invalid QPN encountered during requester Processing. */                                \
	X(RDMA_TX_PORT_REQ_QP_INV)

#define RDMA_QP_COUNTER_LIST                                                                       \
	/** QP accessed by a non-owner lcore during RDMA header check. */                          \
	X(RDMA_RX_QP_HDR_CHK_ACCESS_QP_BY_NON_OWNER_LCORE)                                         \
	/** Invalid QP state detected during RDMA header validation. */                            \
	X(RDMA_RX_QP_HDR_CHK_QP_STATE_INV)                                                         \
	/** Address mismatch or invalid address during RDMA header check. */                       \
	X(RDMA_RX_QP_HDR_CHK_ADDR_INV)                                                             \
	/** Key mismatch or invalid key during RDMA header check. */                               \
	X(RDMA_RX_QP_HDR_CHK_KEYS_INV)                                                             \
	/** Failed to extract ICRC from the incoming RDMA packet. */                               \
	X(RDMA_RX_QP_ICRC_CHK_PKT_ICRC_EXTRACT_FAIL)                                               \
	/** ICRC mismatch detected during RDMA packet ICRC check. */                               \
	X(RDMA_RX_QP_ICRC_CHECK_ICRC_MISMATCH)                                                     \
	/** Invalid ICRC detected during RDMA RX Process. */                                       \
	X(RDMA_RX_QP_RX_PROC_ICRC_CHK_FAIL)                                                        \
	/** Failed to allocate mbuf during CNP packet preparation. */                              \
	X(RDMA_RX_QP_SEND_CNP_MBUF_ALLOC_FAIL)                                                     \
	/** Failed to prepend headers to mbuf during CNP packet preparation. */                    \
	X(RDMA_RX_QP_SEND_CNP_MBUF_PREPEND_FAIL)                                                   \
	/** Failed to insert network headers into mbuf during CNP packet preparation. */           \
	X(RDMA_RX_QP_SEND_CNP_NET_HDR_INS_FAIL)                                                    \
	/** Failed to generate ICRC during CNP packet preparation. */                              \
	X(RDMA_RX_QP_SEND_CNP_ICRC_GEN_FAIL)                                                       \
	/** Failed to transmit CNP packet during CNP packet preparation. */                        \
	X(RDMA_RX_QP_SEND_CNP_TX_BURST_FAIL)                                                       \
	/** CNP sending throttled due to rate-limiting interval. */                                \
	X(RDMA_RX_QP_CNP_THROTTLED)                                                                \
	/** CNP packet successfully sent. */                                                       \
	X(RDMA_RX_QP_CNP_SENT)                                                                     \
	/** ECN Congestion Experienced (CE) mark detected on incoming packet. */                   \
	X(RDMA_RX_QP_ECN_CE_DETECTED)                                                              \
	/** DCQCN CNP received at the Reaction Point (sender side). */                             \
	X(RDMA_RX_QP_DCQCN_CNP_RECEIVED)                                                           \
	/** RDMA responder encountered QP in RESET state. */                                       \
	X(RDMA_RX_QP_RSP_QP_STATE_RESET)                                                           \
	/** RDMA responder detected error QP state during processing. */                           \
	X(RDMA_RX_QP_QUEUE_CHK_QP_STATE_ERR)                                                       \
	/** Packet sequence number is out of expected order. */                                    \
	X(RDMA_RX_QP_CHK_PSN_PKT_OUT_OF_SEQ_ERR)                                                   \
	/** Duplicate RDMA request detected based on PSN. */                                       \
	X(RDMA_RX_QP_CHK_PSN_DUP_REQ)                                                              \
	/** Missing LAST opcode in RC sequence */                                                  \
	X(RDMA_RX_QP_CHK_OP_SEQ_MISS_OP_LAST_C_ERR)                                                \
	/** Missing FIRST opcode in RC sequence */                                                 \
	X(RDMA_RX_QP_CHK_OP_SEQ_MISS_OP_FIRST_ERR)                                                 \
	/** Unsupported opcode detected during validation */                                       \
	X(RDMA_RX_QP_CHK_OP_VALID_UNSUPP_OP_ERR)                                                   \
	/** No available resources to handle incoming RDMA READ request. */                        \
	X(RDMA_RX_QP_CHK_RES_NO_READ_REQ_RES)                                                      \
	/** RNR: receiver not ready (insufficient RQ resources) */                                 \
	X(RDMA_RX_QP_CHK_RES_RNR_ERR)                                                              \
	/** Invalid RKEY index during RKEY validation. */                                          \
	X(RDMA_RX_QP_VAL_RKEY_INV_RKEY_INDEX)                                                      \
	/** Protection Domain (PD) not found during RKEY validation. */                            \
	X(RDMA_RX_QP_VAL_RKEY_PD_NOT_FOUND)                                                        \
	/** Memory Region (MR) not found during RKEY validation. */                                \
	X(RDMA_RX_QP_VAL_RKEY_MR_NOT_FOUND)                                                        \
	/** Access violation detected during RKEY validation. */                                   \
	X(RDMA_RX_QP_VAL_RKEY_ACC_VIOL)                                                            \
	/** Length violation detected during RKEY validation. */                                   \
	X(RDMA_RX_QP_VAL_RKEY_LEN_VIOL)                                                            \
	/** RKEY violation during responder rkey validation */                                     \
	X(RDMA_RX_QP_CHK_RKEY_INV_RKEY)                                                            \
	/** RDMA READ request length exceeds maximum allowed size. */                              \
	X(RDMA_RX_QP_HANDLE_READ_REQ_DMA_LEN_EXC)                                                  \
	/** Failed to allocate mbuf during RDMA read preparation */                                \
	X(RDMA_RX_QP_READ_PREP_PTS_ALLOC_MBUF_ERR)                                                 \
	/** Failed to prepare RDMA READ request for PTS. */                                        \
	X(RDMA_RX_QP_HANDLE_READ_REQ_READ_PREP_PTS_FAIL)                                           \
	/** QP is in error state during completion. */                                             \
	X(RDMA_RX_QP_DO_COMP_QP_STATE_ERR)                                                         \
	/** Failed to allocate mbuf during ACK packet preparation */                               \
	X(RDMA_RX_QP_PREP_ACK_PKT_MBUF_ALLOC_FAIL)                                                 \
	/** Failed to prepare ACK packet. */                                                       \
	X(RDMA_RX_QP_PREP_ACK_PKT_FAIL)                                                            \
	/** Failed to update ACK pending list during ACK send */                                   \
	X(RDMA_RX_QP_SEND_ACK_UPDATE_ACK_PENDING_LIST_ERR)                                         \
	/** Failed to transmit duplicate ACK via TX burst. */                                      \
	X(RDMA_RX_QP_SEND_DUP_ACK_TX_BURST_FAIL)                                                   \
	/** Class C error due to unsupported or invalid opcode. */                                 \
	X(RDMA_RX_QP_RSP_CLASS_C_ERR)                                                              \
	/** Receiver Not Ready (RNR) error during RDMA response. */                                \
	X(RDMA_RX_QP_RSP_CLASS_C_RNR_ERR)                                                          \
	/** Completion Queue (CQ) overflow detected. */                                            \
	X(RDMA_RX_QP_RSP_CQ_OVERFLOW_ERR)                                                          \
	/** Responder state machine: EXIT reached */                                               \
	X(RDMA_RX_QP_RSP_RESPST_EXIT)                                                              \
	/** Responder state machine: RESET handled (WQE cleared) */                                \
	X(RDMA_RX_QP_RSP_RESPST_RESET)                                                             \
	/** Responder state machine: ERROR entered (QP moved to ERROR) */                          \
	X(RDMA_RX_QP_RSP_RESPST_ERR)                                                               \
	/** RDMA responder failed during RX processing */                                          \
	X(RDMA_RX_QP_RX_PROC_RESPONDER_FAIL)                                                       \
	/** WQE already completed when fetched during ACK processing. */                           \
	X(RDMA_RX_QP_GET_WQE_WQE_STATE_DONE)                                                       \
	/** WQE in error state when fetched during ACK processing. */                              \
	X(RDMA_RX_QP_GET_WQE_WQE_STATE_ERR)                                                        \
	/** READ WQE retry: packet PSN ahead of expected range. */                                 \
	X(RDMA_RX_QP_CHK_PSN_READ_PSN_AHEAD_RETRY)                                                 \
	/** Opcode mismatch detected during ACK check. */                                          \
	X(RDMA_RX_QP_CHK_ACK_OPCODE_MISMATCH)                                                      \
	/** Receiver Not Ready (RNR) NAK received during ACK check. */                             \
	X(RDMA_RX_QP_CHK_ACK_RNR_NAK)                                                              \
	/** Remote SEQ mismatch: packet PSN vs expected completion PSN. */                         \
	X(RDMA_RX_QP_CHK_ACK_REMOTE_PSN_SEQ_ERR)                                                   \
	/** NAK received due to PSN sequence error. */                                             \
	X(RDMA_RX_QP_CHK_ACK_NAK_PSN_SEQ_ERR)                                                      \
	/** Unexpected NAK type received during ACK check. */                                      \
	X(RDMA_RX_QP_CHK_ACK_UNEXPECTED_NAK)                                                       \
	/** Unexpected opcode received during ACK check. */                                        \
	X(RDMA_RX_QP_CHK_ACK_UNEXPECTED_OPCODE)                                                    \
	/** Retry failed due to retransmission limit exceeded. */                                  \
	X(RDMA_RX_QP_ERR_RETRY_RETRANS_LIMIT_EXC)                                                  \
	/** RNR retry failed due to retry limit exceeded. */                                       \
	X(RDMA_RX_QP_RNR_RETRY_LIMIT_EXC_ERR)                                                      \
	/** RDMA completion state entered error path. */                                           \
	X(RDMA_RX_QP_RDMA_COMPST_ERR)                                                              \
	/** Processing ack failed during RX processing */                                          \
	X(RDMA_RX_QP_RX_PROC_PROCESS_ACK_FAIL)                                                     \
	/** QP accessed by a non-owner lcore during TX processing. */                              \
	X(RDMA_TX_QP_TX_PROC_ACC_QP_BY_NON_OWNER_LCORE)                                            \
	/** WQE list is empty during remaining segments TX processing. */                          \
	X(RDMA_TX_QP_PROC_REMAINING_SEGS_WQE_EMPTY)                                                \
	/** Requester failed during remaining segments TX processing. */                           \
	X(RDMA_TX_QP_PROC_REMAINING_SEGS_REQUESTER_FAIL)                                           \
	/** Failed to extract WQE from mbuf during preprocessing of dequeued packets. */           \
	X(RDMA_TX_QP_PREPROC_DEQ_PKTS_EXTRACT_WQE_FAIL)                                            \
	/** Invalid DMA length detected during preprocessing of dequeued packets. */               \
	X(RDMA_TX_QP_PREPROC_DEQ_PKTS_DMA_LEN_INV)                                                 \
	/** Preprocessing of dequeued RC packet(s) failed. */                                      \
	X(RDMA_TX_QP_PROC_RC_PKTS_PREPROC_DEQ_PKTS_FAIL)                                           \
	/** Failed to enqueue CQE during send CQE processing. */                                   \
	X(RDMA_TX_QP_SEND_CQE_ENQ_CQE_FAIL)                                                        \
	/** Failed to send CQE during send CQE processing. */                                      \
	X(RDMA_TX_QP_SEND_CQE_FAIL)                                                                \
	/** Read reply ACK mismatch: expected mbuf not found at head of ACK pending list. */       \
	X(RDMA_TX_QP_PROC_READ_REPLY_ACK_MISMATCH)                                                 \
	/** Read reply mbuf PSN mismatch: expected mbuf not found at head of ACK pending list. */  \
	X(RDMA_TX_QP_PROC_READ_REPLY_MBUF_PSN_MISMATCH)                                            \
	/** Failed to process RC read-reply packets. */                                            \
	X(RDMA_TX_QP_PROC_RC_PKTS_READ_REPLY_FAIL)                                                 \
	/** No available WQE found while processing RC packets. */                                 \
	X(RDMA_TX_QP_PROC_RC_PKTS_WQE_EMPTY)                                                       \
	/** QP is in error state during TX requester processing. */                                \
	X(RDMA_TX_QP_REQ_QP_STATE_ERR)                                                             \
	/** QP is in reset state during TX requester processing. */                                \
	X(RDMA_TX_QP_REQ_QP_STATE_RESET)                                                           \
	/** Requester halted: WQE is fenced and waiting for prior operations to complete. */       \
	X(RDMA_TX_QP_REQ_WQE_FENCED)                                                               \
	/** Local operation execution failed during requester processing. */                       \
	X(RDMA_TX_QP_REQ_LOCAL_OP_FAIL)                                                            \
	/** Requester failed: could not resolve next opcode for WQE. */                            \
	X(RDMA_TX_QP_REQ_OPCODE_ERR)                                                               \
	/** RDMA read request could not be issued due to exhausted read request credits. */        \
	X(RDMA_TX_QP_REQ_READ_CREDIT_EXHAUSTED)                                                    \
	/** Payload size exceeds MTU for UD QP */                                                  \
	X(RDMA_TX_QP_REQ_PAYLOAD_ERR)                                                              \
	/** Payload size exceeds MTU for non-UD QP */                                              \
	X(RDMA_TX_QP_REQ_PAYLOAD_EXC_MTU)                                                          \
	/** Failed to resolve Address Vector (AV) during requester processing. */                  \
	X(RDMA_TX_QP_REQ_AV_FAIL)                                                                  \
	/** Failed to insert RDMA protocol headers into mbuf. */                                   \
	X(RDMA_TX_QP_HDR_INSERT_PROTO_HDR_INS_FAIL)                                                \
	/** Failed to insert network headers into mbuf. */                                         \
	X(RDMA_TX_QP_HDR_INS_NET_HDR_INS_FAIL)                                                     \
	/** ICRC generation failed during header insertion. */                                     \
	X(RDMA_TX_QP_HDR_INSERT_ICRC_GEN_FAIL)                                                     \
	/** Failed to insert protocol headers during requester processing. */                      \
	X(RDMA_TX_QP_REQ_INSERT_HDR_FAIL)                                                          \
	/** WQE state set to ERROR during requester processing. */                                 \
	X(RDMA_TX_QP_REQ_WQE_STATE_ERR)                                                            \
	/** Requester processing failed for RC packet transmission. */                             \
	X(RDMA_TX_QP_PROC_RC_REQUESTER_FAIL)                                                       \
	/** RC packet processing failed during TX processing. */                                   \
	X(RDMA_TX_QP_TX_PROC_RC_PKT_PROCESS_FAIL)                                                  \
	/** UD requester processing failed during TX processing. */                                \
	X(RDMA_TX_QP_TX_PROC_UD_REQUESTER_FAIL)                                                    \
	/** Requester processing failed during TX processing. */                                   \
	X(RDMA_TX_QP_TX_PROC_REQUESTER_FAIL)                                                       \
	/** Failed to insert network headers. */                                                   \
	X(RDMA_QP_NET_HDR_INSERT_FAIL)                                                             \
	/** Failed to append generated ICRC to packet. */                                          \
	X(RDMA_QP_ICRC_GEN_APPEND_ICRC_FAIL)

enum rdma_port_counters {
#define X(name) name,
	RDMA_PORT_COUNTER_LIST
#undef X
		RDMA_MAX_NUM_PORT_COUNTERS
};

enum rdma_qp_counters {
#define X(name) name,
	RDMA_QP_COUNTER_LIST
#undef X
		RDMA_MAX_NUM_QP_COUNTERS
};

typedef struct rdma_counters {
	uint64_t port_counters[RDMA_MAX_NUM_PORT_COUNTERS];
	uint64_t qp_counters[RDMA_QP_MAX][RDMA_MAX_NUM_QP_COUNTERS];
} rdma_counter_t;

typedef struct rdma_lcore_map {
	int nb_lcore;
	int lcore_to_index[RTE_MAX_LCORE];
	int index_to_lcore[RTE_MAX_LCORE];
} rdma_lcore_map_t;

extern struct rdma_counters **rdma_counter_table;
extern struct rdma_lcore_map *rdma_lcore_map;

int rdma_counter_init(uint8_t nport);

#endif /* __RDMA_COUNTER_H__ */
