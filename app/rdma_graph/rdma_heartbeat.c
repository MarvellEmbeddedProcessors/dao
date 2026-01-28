/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <errno.h>
#include <rte_alarm.h>
#include <rte_atomic.h>
#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_io.h>
#include <rte_memory.h>
#include <rte_timer.h>
#include <signal.h>

#include <dao_log.h>
#include <dao_pem.h>
#include <sdp.h>

#include "dao_pts_rdma_dev.h"
#include "dao_rdma_fp.h"
#include "dao_rdma_sp.h"
#include "pts_rdma_dev_priv.h"
#include "rdma_heartbeat.h"
#include "rdma_init.h"

/* SDP(0)_EPF(0..3)_OEI_TRIG(0..15): 0x86E0C0000000 | <<36 | <<25 | <<4 */
#define SDP0_EPFX_OEI_TRIG(sdp, pf, trig_idx)                                                      \
	(0x86E0C0000000ull | ((uint64_t)(sdp) << 36) | ((uint64_t)(pf) << 25) |                    \
	 ((uint64_t)(trig_idx) << 4))

enum sdp_epf_oei_trig_bit { SDP_EPF_OEI_TRIG_BIT_HEARTBEAT = 1 };

/* Heartbeat scratch register protocol values */
#define HB_SCRATCH_HOST_UP    1 /* Host writes when ready */
#define HB_SCRATCH_HOST_ACK   2 /* Host writes as heartbeat ACK */
#define HB_SCRATCH_HOST_RMMOD 3 /* Host writes when removing module */
#define HB_SCRATCH_CLEARED    0 /* DPU clears after processing */

/* OEI trig interrupt register contents */
union sdp_epf_oei_trig {
	uint64_t u64;
	struct {
		uint64_t bit_num : 6;
		uint64_t rsvd2 : 12;
		uint64_t clr : 1;
		uint64_t set : 1;
		uint64_t rsvd : 44;
	} s;
};

/* Static variables for heartbeat management */
static int hb_interval_ms = 5000; /* Default 5 seconds in milliseconds */
static enum rdma_dev_status rdma_dev_status = RDMA_DEV_STATUS_READY;
static enum hb_state current_hb_state = HB_STATE_WAIT_HOST_UP;
static uint64_t expected_ack_value = HB_SCRATCH_HOST_UP; /* Start by waiting for host up signal */

/* Link status monitoring state */
static bool link_status_initialized;

/**
 * rdma_abrupt_cleanup_resources - Emergency cleanup of RDMA resources
 *
 * Called when heartbeat timeout occurs or communication with host is lost.
 * Performs immediate cleanup of all RDMA resources to prevent resource leaks.
 */
void
rdma_abrupt_cleanup_resources(void)
{
	uint32_t dev_mask = rdma_main_cfg->cfg_prm->enabled_dev_mask;
	struct dao_pts_rdma_dev *dao_dev;
	struct pts_rdma_dev *dev;
	uint16_t devid, qp_id;
	int rc;

	dao_warn("Performing RDMA resource cleanup");

	/* First, set all ports to DOWN to stop new traffic */
	for (devid = 0; devid < RDMA_MAX_DEVS; devid++) {
		if (!(dev_mask & (1 << devid)))
			continue;
		dao_rdma_cleanup_resources(devid);
	}

	rte_delay_ms(500); /* Wait for threads to see cleanup flag */

	/* Manual cleanup for all enabled devices and ports */
	for (devid = 0; devid < RDMA_MAX_DEVS; devid++) {
		if (!(dev_mask & (1 << devid)))
			continue;

		dao_info("Cleaning up RDMA resources for device %d", devid);

		dao_dev = &dao_pts_rdma_devs[devid];
		dev = pts_rdma_dev_priv(dao_dev);

		/* Clean up all Queue Pairs (QPs) - direct memory cleanup */
		dao_info("Direct cleanup of QPs for device %d", devid);
		pts_rdma_clear_qp_info(dev);
	}

	if (pts_rdma_dev_cbs.qp_status_cb) {
		dao_info("Triggering QP status callbacks for cleanup notification");
		for (devid = 0; devid < RDMA_MAX_DEVS; devid++) {
			if (!(dev_mask & (1 << devid)))
				continue;

			dao_dev = &dao_pts_rdma_devs[devid];
			dev = pts_rdma_dev_priv(dao_dev);

			for (qp_id = 0; qp_id < dev->max_qps; qp_id++) {
				/* Notify that QP is disabled (enable = false) */
				rc = pts_rdma_dev_cbs.qp_status_cb(devid, qp_id, false);
				if (rc < 0) {
					dao_err("QP status callback failed for dev %d QP %d: %d",
						devid, qp_id, rc);
				}
			}
		}
	}

	/* Memory barrier to ensure all cleanup operations are visible */
	rte_io_wmb();

	dao_warn("Manual RDMA resource direct memory cleanup completed for all devices and ports");
}

/**
 * rdma_send_event_to_host - Send event to host via PEM
 *
 * @info: Event information to send
 *
 * Send heartbeat or status events to host
 * Uses SDP OEI trigger registers to generate MSI-X interrupts on host
 */
int
rdma_send_event_to_host(struct rdma_event_info *info)
{
	union sdp_epf_oei_trig trig = {0};
	uint64_t oei_trig_offset;
	uint16_t pem_id = 0, pf_id = 0; /* Default to PEM 0 and VF 0 for heartbeat */
	uint8_t sdp_id = 0;
	int rc;

	dao_dbg("Sending event type %d to host via PEM", info->e);
	oei_trig_offset = SDP0_EPFX_OEI_TRIG(sdp_id, pf_id, 0);

	/* Prepare OEI trigger register value */
	if (info->e == RDMA_EVENT_TYPE_HEARTBEAT) {
		trig.u64 = 0;
		trig.s.bit_num = SDP_EPF_OEI_TRIG_BIT_HEARTBEAT;
		trig.s.set = 1;

		dao_dbg("Triggering heartbeat OEI: PEM%d->SDP%d PF%d bit%d at 0x%lx", pem_id,
			sdp_id, pf_id, trig.s.bit_num, oei_trig_offset);
	} else if (info->e == RDMA_EVENT_TYPE_LINK_STATUS) {
		/* Use different bit ranges for UP vs DOWN:
		 * Bits 2-17: Link DOWN events (ports 0-15)
		 * Bits 18-33: Link UP events (ports 0-15)
		 */
		uint8_t base_bit;

		if (info->u.link_status.status == RTE_ETH_LINK_UP)
			base_bit = info->u.link_status.port_id + 18;
		else
			base_bit = info->u.link_status.port_id + 2;

		if (base_bit > 33) {
			dao_err("Port ID %d exceeds maximum (15)", info->u.link_status.port_id);
			return -EINVAL;
		}

		trig.u64 = 0;
		trig.s.bit_num = base_bit;
		trig.s.set = 1;

		dao_info("Triggering link %s OEI: PEM%d->SDP%d PF%d port%d bit%d at 0x%lx",
			 (info->u.link_status.status == RTE_ETH_LINK_UP) ? "UP" : "DOWN", pem_id,
			 sdp_id, pf_id, info->u.link_status.port_id, trig.s.bit_num,
			 oei_trig_offset);
	} else {
		dao_warn("Unsupported event type %d", info->e);
		return -1;
	}

	/* Write to SDP OEI trigger register to generate MSI-X interrupt on host */
	rc = sdp_oei_reg_write(oei_trig_offset, trig.u64);
	if (rc < 0) {
		dao_err("Failed to write OEI trigger register: %d", rc);
		return rc;
	}

	dao_dbg("OEI Trigger: PEM%d->SDP%d EPF%d bit%d, offset=0x%lx, value=0x%lx", pem_id, sdp_id,
		pf_id, trig.s.bit_num, oei_trig_offset, trig.u64);

	return 0;
}

/**
 * Link status callback function for DPDK
 * Called automatically when link status changes
 */
int
rdma_link_status_callback(uint16_t port_id, enum rte_eth_event_type type, void *param,
			  void *ret_param)
{
	struct rte_eth_link link;
	struct rdma_event_info info;
	int rc;

	RTE_SET_USED(param);
	RTE_SET_USED(ret_param);

	if (type != RTE_ETH_EVENT_INTR_LSC)
		return 0;

	/* Get current link status */
	rc = rte_eth_link_get_nowait(port_id, &link);
	if (rc < 0) {
		dao_err("Failed to get link status for port %d: %s", port_id, rte_strerror(-rc));
		return rc;
	}

	dao_info("Link status change detected for port %d: %s", port_id,
		 link.link_status ? "UP" : "DOWN");

	/* Send notification for both UP and DOWN events */
	info.e = RDMA_EVENT_TYPE_LINK_STATUS;
	info.u.link_status.port_id = port_id;
	info.u.link_status.status = link.link_status;

	if (link.link_status == RTE_ETH_LINK_UP) {
		dao_info("Link UP detected for port %d, sending notification to host", port_id);

		/* Send link up notification to host */
		rc = rdma_send_event_to_host(&info);
		if (rc < 0)
			dao_err("Failed to send link up notification for port %d", port_id);
		else
			dao_info("Link UP notification sent to host for port %d", port_id);
	} else if (link.link_status == RTE_ETH_LINK_DOWN) {
		dao_warn("Link DOWN detected for port %d, sending notification to host", port_id);

		/* Send link down notification to host */
		rc = rdma_send_event_to_host(&info);
		if (rc < 0)
			dao_err("Failed to send link down notification for port %d", port_id);
		else
			dao_info("Link DOWN notification sent to host for port %d", port_id);
	}

	return 0;
}

int
rdma_send_heartbeat(void)
{
	uint16_t pem_devid = rdma_main_cfg->pem_prm->pem_id;
	static uint64_t hb_count;
	struct rdma_event_info info;
	uint64_t scratch_offset;
	uint64_t ack_value;
	int rc;

	scratch_offset = SDP_EPFX_SCRATCH(0);
	hb_count++;

	/*
	 * SCRATCH REGISTER PROTOCOL:
	 * 1. Host writes HB_SCRATCH_HOST_UP when ready
	 * 2. DPU detects HOST_UP, clears to HB_SCRATCH_CLEARED, starts heartbeat
	 * 3. DPU sends heartbeat, waits for ACK
	 * 4. Host writes HB_SCRATCH_HOST_ACK as ACK
	 * 5. DPU detects ACK, clears to HB_SCRATCH_CLEARED, continues heartbeat cycle
	 * 6. Host writes HB_SCRATCH_HOST_RMMOD when removing module
	 *
	 */

	/* State machine for heartbeat ACK polling */
	if (current_hb_state == HB_STATE_WAIT_HOST_UP) {
		/* Continuously poll for host up signal (HB_SCRATCH_HOST_UP) */
		rc = dao_pem_sdp_reg_read(pem_devid, scratch_offset, &ack_value);
		if (rc < 0) {
			dao_err("Failed to read scratch register for host up polling: %d", rc);
			return rc;
		}

		if (ack_value == HB_SCRATCH_HOST_UP) {
			dao_info("Host UP signal detected (scratch register = %d)",
				 HB_SCRATCH_HOST_UP);
			dao_info("Transitioning to heartbeat ACK mode");

			/* Clear scratch register and send first heartbeat */
			rc = dao_pem_sdp_reg_write(pem_devid, scratch_offset, HB_SCRATCH_CLEARED);
			if (rc < 0) {
				dao_err("Failed to clear scratch register: %d", rc);
				return rc;
			}

			/* Send heartbeat to host */
			info.e = RDMA_EVENT_TYPE_HEARTBEAT;
			info.u.hbeat.dev_id = 0;
			info.u.hbeat.status = rdma_dev_status;

			rc = rdma_send_event_to_host(&info);
			if (rc < 0) {
				dao_warn("Failed to send heartbeat to host: %d", rc);
				return rc;
			}

			/* Switch to ACK polling state */
			current_hb_state = HB_STATE_WAIT_ACK;
			expected_ack_value = HB_SCRATCH_HOST_ACK;
			dao_info("RDMA Heartbeat #%lu sent, waiting for ACK (value %d)", hb_count,
				 HB_SCRATCH_HOST_ACK);

			return 0;
		}

		dao_dbg("Waiting for host UP signal current scratch value: %lu, expecting: %d",
			ack_value, HB_SCRATCH_HOST_UP);
		return 0; /* Keep polling */
	}

	if (current_hb_state == HB_STATE_WAIT_ACK) {
		static int no_ack_count;
		static bool heartbeat_sent;

		if (!heartbeat_sent) {
			/* Send heartbeat first */
			dao_dbg("RDMA Heartbeat #%lu - sending heartbeat", hb_count);

			info.e = RDMA_EVENT_TYPE_HEARTBEAT;
			info.u.hbeat.dev_id = 0;
			info.u.hbeat.status = rdma_dev_status;

			rc = rdma_send_event_to_host(&info);
			if (rc < 0) {
				dao_warn("Failed to send heartbeat to host: %d", rc);
				return rc;
			}
			heartbeat_sent = true;
			return 0; /* Wait for next timer cycle to check ACK */
		}

		/* Check for ACK on subsequent timer cycle */
		rc = dao_pem_sdp_reg_read(pem_devid, scratch_offset, &ack_value);
		if (rc < 0) {
			dao_err("Failed to read scratch register for ACK: %d", rc);
			return rc;
		}

		if (ack_value == expected_ack_value) {
			dao_dbg("Heartbeat ACK received (value: %lu)", ack_value);

			/* Clear scratch register after successful ACK */
			rc = dao_pem_sdp_reg_write(pem_devid, scratch_offset, HB_SCRATCH_CLEARED);
			if (rc < 0)
				dao_warn("Failed to clear scratch register after ACK: %d", rc);

			/* Reset counters for next heartbeat cycle */
			no_ack_count = 0;
			heartbeat_sent = false;
			return 0;
		} else if (ack_value == HB_SCRATCH_HOST_RMMOD) {
			/* Rmmod from host */
			dao_warn(
				"Host initiated RDMA module removal (scratch=%d), stopping heartbeat",
				HB_SCRATCH_HOST_RMMOD);
			/* Trigger recovery actions */
			rdma_abrupt_cleanup_resources();

			/* Reset state machine to wait for host UP again */
			current_hb_state = HB_STATE_WAIT_HOST_UP;
			expected_ack_value = HB_SCRATCH_HOST_UP;
			no_ack_count = 0;
			dao_info("State reset: Now polling for host UP signal");

			return 0;
		}
		/* No ACK yet - increment timeout counter */
		no_ack_count++;
		dao_dbg("Waiting for ACK, attempt %d (value=%lu, expecting=%lu)", no_ack_count,
			ack_value, expected_ack_value);

		/* Timeout after 5 heartbeat cycles */
		if (no_ack_count >= 5) {
			dao_err("Heartbeat ACK timeout after %d attempts", no_ack_count);

			/* Trigger recovery actions */
			rdma_abrupt_cleanup_resources();

			/* Reset state machine to wait for host UP again */
			current_hb_state = HB_STATE_WAIT_HOST_UP;
			expected_ack_value = HB_SCRATCH_HOST_UP;
			no_ack_count = 0;
			dao_info("State reset: Now polling for host UP signal");

			return -ETIMEDOUT;
		}

		return 0; /* Will retry on next timer cycle */
	}

	return 0;
}

void
rdma_handle_heartbeat_alarm(void)
{
	static int hb_timeout_count;
	int hb_status;

	/* Handle different heartbeat states */
	if (current_hb_state == HB_STATE_WAIT_HOST_UP) {
		/* Poll for host UP - no timeout handling needed */
		rdma_send_heartbeat();
		/* Check every 100ms when waiting for host */
		rdma_start_heartbeat_eal_alarm(100);
		dao_dbg("Waiting for host to come up");

	} else if (current_hb_state == HB_STATE_WAIT_ACK) {
		hb_status = rdma_send_heartbeat();

		if (hb_status < 0) {
			if (hb_status == -ETIMEDOUT) {
				hb_timeout_count++;
				dao_warn("Heartbeat ACK timeout #%d cleanup triggered",
					 hb_timeout_count);
				/* State machine already reset to
				   HB_STATE_WAIT_HOST_UP in rdma_send_heartbeat() */
				rdma_start_heartbeat_eal_alarm(100);
			} else {
				dao_warn("Heartbeat indicates unhealthy state error: %d",
					 hb_status);
				/* Reschedule next heartbeat */
				rdma_start_heartbeat_eal_alarm(hb_interval_ms);
			}
		} else {
			/* Reset timeout counter on successful heartbeat */
			if (hb_timeout_count > 0) {
				dao_info("Heartbeat ACK successful after %d timeouts",
					 hb_timeout_count);
				hb_timeout_count = 0;
			}
			/* Reschedule next heartbeat */
			rdma_start_heartbeat_eal_alarm(hb_interval_ms);
		}
	}
}

int
rdma_heartbeat_init(void)
{
	/* Initialize device status */
	rdma_dev_status = RDMA_DEV_STATUS_READY;

	rdma_start_heartbeat_eal_alarm(100);
	dao_info("Heartbeat system initialized and EAL alarm started with 100ms interval");

	return 0;
}

void
rdma_heartbeat_cleanup(void)
{
	rte_eal_alarm_cancel(heartbeat_alarm_cb, NULL);
	dao_info("DPDK heartbeat timer stopped");
}

int
rdma_link_status_init(void)
{
	uint16_t portid;
	int rc;

	/* Register link status callbacks for all ports */
	RTE_ETH_FOREACH_DEV(portid) {
		rc = rte_eth_dev_callback_register(portid, RTE_ETH_EVENT_INTR_LSC,
						   rdma_link_status_callback, NULL);
		if (rc < 0)
			dao_warn("Failed to register link status callback for port %d: %s", portid,
				 rte_strerror(-rc));
		else
			dao_info("Link status callback registered for port %d", portid);
	}
	link_status_initialized = true;

	return 0;
}

void
rdma_link_status_cleanup(void)
{
	uint16_t portid;

	if (!link_status_initialized)
		return;

	/* Unregister link status callbacks */
	RTE_ETH_FOREACH_DEV(portid) {
		rte_eth_dev_callback_unregister(portid, RTE_ETH_EVENT_INTR_LSC,
						rdma_link_status_callback, NULL);
	}

	link_status_initialized = false;
	dao_info("Link status callbacks unregistered");
}

/**
 * heartbeat_alarm_cb - EAL alarm callback for heartbeat
 *
 * @arg: Unused argument
 *
 * This function is called by the EAL alarm system and handles the heartbeat
 */
void
heartbeat_alarm_cb(void *arg)
{
	RTE_SET_USED(arg);

	/* Call the heartbeat alarm handler */
	rdma_handle_heartbeat_alarm();
}

/**
 * rdma_start_heartbeat_eal_alarm - Start heartbeat using EAL alarm
 *
 * @ms: Interval in milliseconds
 *
 * Sets up an EAL alarm to trigger heartbeat after specified time
 */
void
rdma_start_heartbeat_eal_alarm(uint32_t ms)
{
	rte_eal_alarm_set((uint64_t)ms * 1000, heartbeat_alarm_cb, NULL);
}
