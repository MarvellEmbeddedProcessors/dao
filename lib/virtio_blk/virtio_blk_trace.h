/* SPDX-License-Identifier: Marvell-Proprietary
 * Copyright (c) 2025 Marvell.
 */

#include <rte_trace_point.h>

RTE_TRACE_POINT_FP(virtio_blk_trace_queue_context,
		   RTE_TRACE_POINT_ARGS(const char *func, uint8_t dev_id, uint8_t q_id,
					uint16_t sd_desc_off, uint16_t sd_mbuf_off,
					uint16_t pend_sd_desc, uint16_t pend_sd_mbuf,
					uint16_t last_off, uint16_t compl_off,
					uint16_t m2d_pend_sd_mbuf),
		   rte_trace_point_emit_string(func);
		   rte_trace_point_emit_u8(dev_id); rte_trace_point_emit_u8(q_id);
		   rte_trace_point_emit_u16(sd_desc_off); rte_trace_point_emit_u16(sd_mbuf_off);
		   rte_trace_point_emit_u16(pend_sd_desc); rte_trace_point_emit_u16(pend_sd_mbuf);
		   rte_trace_point_emit_u16(last_off); rte_trace_point_emit_u16(compl_off);
		   rte_trace_point_emit_u16(m2d_pend_sd_mbuf););

RTE_TRACE_POINT_FP(virtio_blk_trace_dma,
		   RTE_TRACE_POINT_ARGS(uint8_t dev_id, uint8_t q_id, uint16_t off, uintptr_t src,
					uintptr_t dst, uint32_t slen, uint32_t dlen, uint32_t dir),
		   rte_trace_point_emit_u8(dev_id);
		   rte_trace_point_emit_u8(q_id); rte_trace_point_emit_u16(off);
		   rte_trace_point_emit_ptr(src); rte_trace_point_emit_ptr(dst);
		   rte_trace_point_emit_u32(slen); rte_trace_point_emit_u32(dlen);
		   rte_trace_point_emit_u32(dir););

RTE_TRACE_POINT_FP(virtio_blk_trace_blob,
		   RTE_TRACE_POINT_ARGS(const char *name, uint8_t *val, uint8_t len),
		   rte_trace_point_emit_string(name);
		   rte_trace_point_emit_blob(val, len););

RTE_TRACE_POINT_FP(virtio_blk_trace_io_req,
		   RTE_TRACE_POINT_ARGS(uint8_t dev_id, uint8_t q_id, uint16_t deq_off,
					uint16_t buf_id, uint8_t type, uint64_t sector,
					uint32_t num_sectors),
		   rte_trace_point_emit_u8(dev_id);
		   rte_trace_point_emit_u8(q_id); rte_trace_point_emit_u16(deq_off);
		   rte_trace_point_emit_u16(buf_id); rte_trace_point_emit_u8(type);
		   rte_trace_point_emit_u64(sector); rte_trace_point_emit_u32(num_sectors););

RTE_TRACE_POINT_FP(virtio_blk_trace_io_req_compl,
		   RTE_TRACE_POINT_ARGS(uint8_t dev_id, uint8_t q_id, uint16_t enq_off,
					uint16_t buf_id, uint8_t type, uint8_t status),
		   rte_trace_point_emit_u8(dev_id);
		   rte_trace_point_emit_u8(q_id); rte_trace_point_emit_u16(enq_off);
		   rte_trace_point_emit_u16(buf_id); rte_trace_point_emit_u8(type);
		   rte_trace_point_emit_u8(status););

RTE_TRACE_POINT_FP(virtio_blk_trace_desc_flags,
		   RTE_TRACE_POINT_ARGS(const char *ring, uint8_t dev_id, uint8_t q_id,
					uint16_t off, uint16_t flags, uint16_t id, uint32_t len),
		   rte_trace_point_emit_string(ring);
		   rte_trace_point_emit_u8(dev_id); rte_trace_point_emit_u8(q_id);
		   rte_trace_point_emit_u16(off); rte_trace_point_emit_u16(flags);
		   rte_trace_point_emit_u16(id); rte_trace_point_emit_u32(len););
