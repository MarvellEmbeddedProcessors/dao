/* SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 Marvell.
 *
 * PCIe endpoint device setup: BAR mapping, MSI-X, heartbeat, mailbox.
 * The non-RDMA netdev uses a reserved management QP (N-1),
 * implemented in octep_rdma_netdev.c.
 */

#include <linux/moduleparam.h>
#include <linux/rcupdate.h>

#include "octep_rdma.h"
#include "octep_cq.h"
#include "octep_ep.h"
#include "octep_ep_regs.h"
#include "octep_pfvf_mbox.h"

#define OCTEP_INTR_POLL_TIME_MSECS 100
struct workqueue_struct *octep_wq;

/*
 * Debug: pointer to the CQ-IRQ-enabled device, used only by the read-only
 * cq_dump parameter below. Set when CQ IRQs are registered and cleared at
 * teardown. Not referenced on any data path.
 */
static struct octep_rdma_dev *octep_cq_dbg_dev;

/*
 * CQ interrupt diagnostics (read via cq_dump):
 *   fires      - times the CQ ISR ran
 *   comps      - times comp_handler was invoked (cb_notify was set)
 *   zero       - times the ISR read cb_notify==0 and skipped (stale-read race)
 */
static atomic_t octep_cq_bh_fires = ATOMIC_INIT(0);
static atomic_t octep_cq_bh_comps = ATOMIC_INIT(0);
static atomic_t octep_cq_bh_zero = ATOMIC_INIT(0);

/*
 * Live per-CQ interrupt state, read-only at
 * /sys/module/octep_rdma/parameters/cq_dump. This executes ONLY when the file
 * is read - never from the ISR, bottom half, or poll_cq - so it adds zero
 * fast-path cost (it carries no counters; it just snapshots BAR4 at read time).
 * For each CQ it reads the doorbell slot with the SAME offsets the bottom half
 * uses:
 *   pi/ci     producer/consumer indices (slot+0 / slot+4)
 *   pending   !queue_empty(pi,ci) -> host has un-consumed CQEs
 *   cbnotify  EP-written notify byte (slot+16)
 *   arm       EP-visible arm byte (slot+12)
 *   sw_armed  cq->armed shadow; notify=cq->notify; sig_pi=last_signaled_pi
 *   comp      comp_handler registered (1) -> event-mode consumer attached
 * Read this while an -e run is hung to locate the stall:
 *   pending=1 with pi>ci  -> the tail IS in host memory but no wakeup was
 *                            delivered (host-side lost edge; a watchdog fixes).
 *   pi==ci                -> the last CQE is NOT in host memory yet
 *                            (DPU-side producer/publish stall).
 */
static int cq_dump_get(char *buffer, const struct kernel_param *kp)
{
	struct octep_rdma_dev *rdma_dev = octep_cq_dbg_dev;
	struct octep_rdma_cq *cq;
	u8 __iomem *slot;
	u32 i, pi, ci, cbn, arm;
	int len = 0;

	if (!rdma_dev || !rdma_dev->cq_table)
		return scnprintf(buffer, PAGE_SIZE, "(no cq-intr device)\n");

	len += scnprintf(
		buffer + len, PAGE_SIZE - len,
		"dev max_cqs=%u cq_intr_enabled=%d nb_cq_irqs=%u isr_fires=%d comp_calls=%d zero_skips=%d\n",
		rdma_dev->max_cqs, rdma_dev->cq_intr_enabled, rdma_dev->nb_cq_irqs,
		atomic_read(&octep_cq_bh_fires), atomic_read(&octep_cq_bh_comps),
		atomic_read(&octep_cq_bh_zero));

	rcu_read_lock();
	for (i = 0; i < rdma_dev->max_cqs; i++) {
		cq = rcu_dereference(rdma_dev->cq_table[i]);
		if (!cq || !cq->cb_notify_addr)
			continue;

		slot = (u8 __iomem *)cq->cb_notify_addr - OCTEP_RDMA_CQ_NOTIFY_OFFSET;
		pi = readl((u32 __iomem *)slot);
		ci = readl((u32 __iomem *)(slot + 4));
		cbn = readb(cq->cb_notify_addr);
		arm = cq->arm_byte_addr ? readb(cq->arm_byte_addr) : 0xff;

		if (len >= PAGE_SIZE - 200) {
			len += scnprintf(buffer + len, PAGE_SIZE - len, "...(truncated)\n");
			break;
		}

		len += scnprintf(
			buffer + len, PAGE_SIZE - len,
			"cq[%u] pi=%u ci=%u u16pi=%u u16ci=%u pending=%d cbnotify=%u arm=%u sw_armed=%u notify=%u sig_pi=%u comp=%d ctx=%p ccalls=%u wd=%u depth=%u qmask=0x%x\n",
			cq->cqn, pi, ci, (u16)pi, (u16)ci, !octep_rdma_is_queue_empty(pi, ci), cbn,
			arm, cq->armed, cq->notify, cq->last_signaled_pi,
			cq->ibcq.comp_handler ? 1 : 0, cq->ibcq.cq_context, cq->dbg_comp_calls,
			cq->wd_fires, cq->depth, cq->qmask);
	}
	rcu_read_unlock();
	return len;
}

static const struct kernel_param_ops cq_dump_ops = {
	.get = cq_dump_get,
};
module_param_cb(cq_dump, &cq_dump_ops, NULL, 0444);
MODULE_PARM_DESC(
	cq_dump,
	"Live per-CQ interrupt state (pi/ci/cbnotify/arm/sig_pi); read-only, no fast-path cost");

static const char *octep_devid_to_str(struct octep_ep_dev *octep_dev)
{
	switch (octep_dev->chip_id) {
	case OCTEP_RDMA_DEVID_CN106K_PF:
	case OCTEP_RDMA_DEVID_CN106K_VF:
		return "CN10KA";
	case OCTEP_RDMA_DEVID_CN105K_PF:
	case OCTEP_RDMA_DEVID_CN105K_VF:
		return "CNF10KA";
	case OCTEP_RDMA_DEVID_CN103K_PF:
	case OCTEP_RDMA_DEVID_CN103K_VF:
		return "CN10KB";
	default:
		return "Unsupported";
	}
}

static int map_bar_region(struct octep_ep_dev *octep_dev)
{
	struct pci_dev *pdev = octep_dev->pdev;
	int i;

	/* Map BAR regions */
	for (i = 0; i < OCTEP_MMIO_REGIONS; i += 2) {
		octep_dev->mmio[i].hw_addr =
			ioremap(pci_resource_start(pdev, i), pci_resource_len(pdev, i));
		if (!octep_dev->mmio[i].hw_addr) {
			dev_err(&pdev->dev, "Failed to remap BAR-%d; start=0x%llx len=0x%llx\n", i,
				pci_resource_start(octep_dev->pdev, i),
				pci_resource_len(octep_dev->pdev, i));
			return -ENOMEM;
		}
		octep_dev->mmio[i].mapped = 1;
		dev_info(&pdev->dev, "BAR-%d: start=0x%llx len=0x%llx\n", i,
			 pci_resource_start(pdev, i), pci_resource_len(pdev, i));

		octep_dev->oct_caps.base[i] = octep_dev->mmio[i].hw_addr;
		if (pdev->is_virtfn)
			break;
	}
	return 0;
}

/* ---- MSIX + non-IOQ IRQ infrastructure (heartbeat, MBOX, errors) ---- */

static irqreturn_t octep_mbox_intr_handler(int irq, void *data)
{
	struct octep_ep_dev *octep_dev = data;

	return octep_dev->hw_ops.mbox_intr_handler(octep_dev);
}

static irqreturn_t octep_oei_intr_handler(int irq, void *data)
{
	struct octep_ep_dev *octep_dev = data;

	return octep_dev->hw_ops.oei_intr_handler(octep_dev);
}

static irqreturn_t octep_misc_intr_handler(int irq, void *data)
{
	struct octep_ep_dev *octep_dev = data;

	return octep_dev->hw_ops.misc_intr_handler(octep_dev);
}

static irqreturn_t octep_rsvd_intr_handler(int irq, void *data)
{
	struct octep_ep_dev *octep_dev = data;

	return octep_dev->hw_ops.rsvd_intr_handler(octep_dev);
}

/* Watchdog interval: 1ms — fast enough to recover lost MSI-X edges
 * without noticeable latency; slow enough to avoid meaningful CPU cost.
 */
#define CQ_WATCHDOG_INTERVAL_MS 1

/*
 * CQ watchdog — periodic safety net for lost MSI-X edges.
 *
 * The firmware fires a one-shot MSI-X when a new CQE is produced. If that
 * edge is lost (PCIe/APIC coalescing, timing), the host never wakes up.
 * This timer scans all armed CQs every ~1ms: if pi != ci (unconsumed
 * completions exist), call comp_handler directly — no interrupt needed.
 *
 * This replaces the firmware-side bounded-retry watchdog with a host-side
 * mechanism that cannot itself be lost (it's a local function call).
 */
static void octep_cq_watchdog_fn(struct work_struct *work)
{
	struct octep_rdma_dev *rdma_dev =
		container_of(to_delayed_work(work), struct octep_rdma_dev, cq_watchdog);
	struct octep_rdma_cq *cq;
	u8 __iomem *slot;
	u32 i, pi, ci;

	if (!rdma_dev->cq_table)
		goto resched;

	/*
	 * RCU read side keeps every cq we touch alive for the whole scan:
	 * octep_rdma_destroy_cq() clears the slot with rcu_assign_pointer() and
	 * synchronize_rcu()s before freeing, so a concurrent destroy can't free
	 * a cq out from under this loop (comp_handler must not sleep here).
	 */
	rcu_read_lock();
	for (i = 0; i < rdma_dev->max_cqs; i++) {
		cq = rcu_dereference(rdma_dev->cq_table[i]);
		if (!cq || !cq->cb_notify_addr)
			continue;

		/* Skip CQs without a user completion handler context.
		 * rdma_cm internal CQs have ctx=NULL and use solicited-only
		 * arming. Firing comp_handler on them delivers a spurious
		 * event that corrupts the rdma_cm state machine.
		 */
		if (!cq->ibcq.cq_context)
			continue;

		/* Host-side one-shot: only deliver while armed for NEXT_COMP.
		 * Solicited-only (cq->armed==1) is rdma_cm internal — the
		 * watchdog cannot verify the solicited bit in the CQE, so
		 * firing would be a spurious wakeup.
		 */
		if (cq->armed != OCTEP_RDMA_CQ_ARM_NEXT_COMP)
			continue;

		/* Read pi/ci from the BAR4 slot */
		slot = (u8 __iomem *)cq->cb_notify_addr - OCTEP_RDMA_CQ_NOTIFY_OFFSET;
		pi = readl((u32 __iomem *)slot);
		ci = readl((u32 __iomem *)(slot + 4));

		if (pi == ci)
			continue;

		/*
		 * One-shot consume shared with the BH: whichever path observes
		 * the unconsumed completions first (the interrupt BH, or this
		 * watchdog on a lost MSI-X edge) atomically clears cq->armed,
		 * disarms the EP (arm_byte) and delivers exactly one event. The
		 * consumer re-arms to get the next one, so there is no
		 * GFP_ATOMIC storm on an un-drained CQ.
		 */
		if (cmpxchg(&cq->armed, OCTEP_RDMA_CQ_ARM_NEXT_COMP, OCTEP_RDMA_CQ_DISARMED) !=
		    OCTEP_RDMA_CQ_ARM_NEXT_COMP)
			continue;

		/* Won the arm: this CQ left NEXT_COMP, drop it from the count. */
		atomic_dec(&rdma_dev->armed_nc);

		/*
		 * Disarm the EP before waking the consumer so it stops firing
		 * until the next req_notify_cq. Writing arm_byte=0 here (not
		 * after comp_handler) means a consumer that re-arms from inside
		 * the wakeup can't be clobbered: its arm_byte=2 lands after ours.
		 */
		if (cq->arm_byte_addr)
			writeb(OCTEP_RDMA_CQ_DISARMED, cq->arm_byte_addr);

		if (cq->ibcq.comp_handler) {
			cq->dbg_comp_calls++;
			cq->wd_fires++;
			atomic_inc(&octep_cq_bh_comps);
			cq->ibcq.comp_handler(&cq->ibcq, cq->ibcq.cq_context);
		}
	}
	rcu_read_unlock();

resched:
	/*
	 * Self-stop when no CQ is armed for NEXT_COMP. req_notify_cq restarts
	 * the watchdog (octep_rdma_cq_watchdog_kick) on the next arm, so it runs
	 * only while there is work to service. schedule_delayed_work() there is
	 * idempotent, making the restart race-free against this self-stop.
	 *
	 * Also honor cq_intr_enabled: octep_free_cq_irqs() clears it (with a
	 * barrier) before cancel_delayed_work_sync(), so once teardown starts
	 * this instance will not re-arm onto a device that is going away.
	 */
	if (READ_ONCE(rdma_dev->cq_intr_enabled) && atomic_read(&rdma_dev->armed_nc) > 0)
		schedule_delayed_work(&rdma_dev->cq_watchdog,
				      msecs_to_jiffies(CQ_WATCHDOG_INTERVAL_MS));
}

/*
 * (Re)start the CQ watchdog. Called from req_notify_cq when a CQ is armed for
 * NEXT_COMP. schedule_delayed_work() is a no-op if the work is already queued,
 * and will re-queue a work that has just self-stopped, so this closes the race
 * with the self-stop check in octep_cq_watchdog_fn: after any NEXT_COMP arm the
 * watchdog is guaranteed to be (re)scheduled.
 *
 * The cq_intr_enabled check prevents a req_notify_cq racing with teardown from
 * re-arming the watchdog after octep_free_cq_irqs() has cancelled it: teardown
 * clears the flag (with a barrier) before the cancel, so a kick that observes
 * the cleared flag will not schedule.
 */
void octep_rdma_cq_watchdog_kick(struct octep_rdma_dev *rdma_dev)
{
	if (READ_ONCE(rdma_dev->cq_intr_enabled))
		schedule_delayed_work(&rdma_dev->cq_watchdog,
				      msecs_to_jiffies(CQ_WATCHDOG_INTERVAL_MS));
}

/*
 * CQ completion bottom half.
 * Deferred from the (thin) hardirq via schedule_work(). Scans registered CQs
 * and, for each whose EP notify byte is set, clears the byte and (if the CQ is
 * armed for NEXT_COMP with unconsumed CQEs) wakes the consumer via a one-shot
 * comp_handler delivery. Shares the arm-state (cq->armed) and delivery policy
 * with octep_cq_watchdog_fn so the interrupt path and the lost-edge watchdog
 * never double-deliver. Running in process context keeps the BAR4 MMIO
 * reads/writes and the comp_handler wakeup off the hardirq path.
 */
static void octep_cq_work_fn(struct work_struct *work)
{
	struct octep_rdma_dev *rdma_dev = container_of(work, struct octep_rdma_dev, cq_work);
	struct octep_rdma_cq *cq;
	u8 __iomem *slot;
	u8 notify_val;
	u32 i, pi, ci;

	if (!rdma_dev->cq_table)
		return;

	/*
	 * RCU read side keeps every cq we touch alive for the whole scan:
	 * octep_rdma_destroy_cq() clears the slot with rcu_assign_pointer() and
	 * synchronize_rcu()s before freeing, so a concurrent destroy can't free
	 * a cq out from under this loop (comp_handler must not sleep here).
	 */
	rcu_read_lock();
	/* Scan all CQs to find which one(s) triggered */
	for (i = 0; i < rdma_dev->max_cqs; i++) {
		cq = rcu_dereference(rdma_dev->cq_table[i]);
		if (!cq || !cq->cb_notify_addr)
			continue;

		notify_val = readb(cq->cb_notify_addr);
		if (!notify_val) {
			/*
			 * BH ran but this CQ's cb_notify reads 0. Either it
			 * wasn't the CQ that triggered, or the EP's cb_notify
			 * store hasn't reached BAR4 memory yet (write-visibility
			 * race). Counted for diagnostics.
			 */
			atomic_inc(&octep_cq_bh_zero);
			continue;
		}

		/*
		 * Always clear cb_notify on a set byte so the EP can signal
		 * the next completion, even if we decide below not to wake a
		 * consumer for this edge.
		 */
		writeb(0, cq->cb_notify_addr);

		/*
		 * Deliver a completion event only when it is real and wanted -
		 * identical policy to octep_cq_watchdog_fn so the interrupt
		 * path and the watchdog can't disagree or double-deliver:
		 *   - user completion context present (skip rdma_cm internal CQs
		 *     whose ctx==NULL; firing on them corrupts the state machine)
		 *   - host-side one-shot: armed for NEXT_COMP (cq->armed==2)
		 *   - unconsumed CQEs actually exist (pi != ci)
		 *
		 * On the winning consume the host clears both cq->armed and the
		 * EP arm_byte (below), so the EP stops firing until the consumer
		 * re-arms via req_notify_cq - exactly one completion event per
		 * arm cycle. Any interrupt still in flight from before the
		 * disarm is dropped here: cq->armed already consumed, or a set
		 * cb_notify with pi==ci (EP init value, a neighbour CQ's edge,
		 * or a store-visibility race) never wakes ibv_get_cq_event()
		 * with nothing to poll (which made the consumer read a stale
		 * ibv_wc).
		 */
		if (!cq->ibcq.cq_context)
			continue;

		if (cq->armed != OCTEP_RDMA_CQ_ARM_NEXT_COMP)
			continue;

		/* Read pi/ci from the BAR4 slot (same layout as the watchdog) */
		slot = (u8 __iomem *)cq->cb_notify_addr - OCTEP_RDMA_CQ_NOTIFY_OFFSET;
		pi = readl((u32 __iomem *)slot);
		ci = readl((u32 __iomem *)(slot + 4));
		if (pi == ci)
			continue;

		/*
		 * One-shot: atomically consume the arm so the BH and the
		 * watchdog can never both deliver the same arm cycle. Only the
		 * winner clears cq->armed, disarms the EP and fires
		 * comp_handler; the consumer re-arms (req_notify_cq) to get the
		 * next event.
		 */
		if (cmpxchg(&cq->armed, OCTEP_RDMA_CQ_ARM_NEXT_COMP, OCTEP_RDMA_CQ_DISARMED) !=
		    OCTEP_RDMA_CQ_ARM_NEXT_COMP)
			continue;

		/* Won the arm: this CQ left NEXT_COMP, drop it from the count. */
		atomic_dec(&rdma_dev->armed_nc);

		/*
		 * Disarm the EP before waking the consumer so it stops firing
		 * until the next req_notify_cq. Writing arm_byte=0 here (not
		 * after comp_handler) means a consumer that re-arms from inside
		 * the wakeup can't be clobbered: its arm_byte=2 lands after ours.
		 */
		if (cq->arm_byte_addr)
			writeb(OCTEP_RDMA_CQ_DISARMED, cq->arm_byte_addr);

		/* Signal IB core - wake ibv_get_cq_event() / completion handler */
		if (cq->ibcq.comp_handler) {
			atomic_inc(&octep_cq_bh_comps);
			cq->dbg_comp_calls++;
			cq->ibcq.comp_handler(&cq->ibcq, cq->ibcq.cq_context);
		}
	}
	rcu_read_unlock();
}

/*
 * CQ Completion Interrupt Handler - thin hardirq (pure deferral).
 * EP fires this after writing cb_notify_addr=1 to BAR4. data is the
 * struct octep_rdma_dev registered at request_irq() time, so no
 * pci_get_drvdata() lookup is needed here.
 *
 * The hardirq does nothing but count the raw interrupt and kick the
 * bottom half (octep_cq_work_fn), which does the BAR4 scan + comp_handler
 * wakeup in process context. Note schedule_work() coalesces: multiple
 * interrupts arriving while the BH is queued/running collapse into fewer
 * BH passes (isr_fires can exceed comp_calls).
 */
static irqreturn_t octep_cq_intr_handler(int irq, void *data)
{
	struct octep_rdma_dev *rdma_dev = data;

	if (!rdma_dev)
		return IRQ_HANDLED;

	atomic_inc(&octep_cq_bh_fires);
	schedule_work(&rdma_dev->cq_work);

	return IRQ_HANDLED;
}

static int octep_enable_msix_range(struct octep_ep_dev *octep_dev)
{
	int num_msix, msix_allocated;
	int i;

	/*
	 * num_custom_irqs is seeded from the firmware caps (caps_rgn->nb_irqs)
	 * in octep_rdma_setup_task() before probe, so the CQ vector count tracks
	 * what the firmware actually uses instead of a fixed value.
	 */
	num_msix = CFG_GET_NON_IOQ_MSIX(octep_dev->conf) + octep_dev->num_custom_irqs;
	octep_dev->msix_entries = kcalloc(num_msix, sizeof(struct msix_entry), GFP_KERNEL);
	if (!octep_dev->msix_entries)
		return -ENOMEM;

	for (i = 0; i < num_msix; i++)
		octep_dev->msix_entries[i].entry = i;

	msix_allocated =
		pci_enable_msix_range(octep_dev->pdev, octep_dev->msix_entries, num_msix, num_msix);
	if (msix_allocated != num_msix) {
		dev_err(&octep_dev->pdev->dev, "Failed to enable %d msix irqs; got only %d\n",
			num_msix, msix_allocated);
		if (msix_allocated > 0)
			pci_disable_msix(octep_dev->pdev);
		kfree(octep_dev->msix_entries);
		octep_dev->msix_entries = NULL;
		return -1;
	}
	dev_info(&octep_dev->pdev->dev, "MSI-X enabled: total %d non-ioq %d custom %d\n",
		 msix_allocated, msix_allocated - octep_dev->num_custom_irqs,
		 octep_dev->num_custom_irqs);

	return 0;
}

static void octep_disable_msix(struct octep_ep_dev *octep_dev)
{
	if (octep_dev->msix_entries) {
		pci_disable_msix(octep_dev->pdev);
		kfree(octep_dev->msix_entries);
		octep_dev->msix_entries = NULL;
	}
}

static int octep_request_non_ioq_irqs(struct octep_ep_dev *octep_dev)
{
	struct net_device *netdev = octep_dev->netdev;
	struct msix_entry *msix_entry;
	char **non_ioq_msix_names;
	int num_non_ioq_msix;
	int ret, i;

	num_non_ioq_msix = CFG_GET_NON_IOQ_MSIX(octep_dev->conf);
	non_ioq_msix_names = CFG_GET_NON_IOQ_MSIX_NAMES(octep_dev->conf);

	octep_dev->non_ioq_irq_names = kcalloc(num_non_ioq_msix, OCTEP_MSIX_NAME_SIZE, GFP_KERNEL);
	if (!octep_dev->non_ioq_irq_names)
		return -ENOMEM;

	for (i = 0; i < num_non_ioq_msix; i++) {
		char *irq_name;

		irq_name = &octep_dev->non_ioq_irq_names[i * OCTEP_MSIX_NAME_SIZE];
		msix_entry = &octep_dev->msix_entries[i];

		snprintf(irq_name, OCTEP_MSIX_NAME_SIZE, "%s-%s", netdev->name,
			 non_ioq_msix_names[i]);
		dev_info(&octep_dev->pdev->dev, "Registering interrupt %d: %s (vector=%d)\n", i,
			 irq_name, msix_entry->vector);
		if (!strncmp(non_ioq_msix_names[i], "epf_mbox_rint", strlen("epf_mbox_rint"))) {
			ret = request_irq(msix_entry->vector, octep_mbox_intr_handler, 0, irq_name,
					  octep_dev);
		} else if (!strncmp(non_ioq_msix_names[i], "epf_oei_rint",
				    strlen("epf_oei_rint"))) {
			ret = request_irq(msix_entry->vector, octep_oei_intr_handler, 0, irq_name,
					  octep_dev);
		} else if (!strncmp(non_ioq_msix_names[i], "epf_misc_rint",
				    strlen("epf_misc_rint"))) {
			ret = request_irq(msix_entry->vector, octep_misc_intr_handler, 0, irq_name,
					  octep_dev);
		} else {
			ret = request_irq(msix_entry->vector, octep_rsvd_intr_handler, 0, irq_name,
					  octep_dev);
		}

		if (ret) {
			dev_err(&octep_dev->pdev->dev, "request_irq failed for %s; err=%d",
				irq_name, ret);
			goto irq_err;
		}
	}

	return 0;

irq_err:
	while (i) {
		--i;
		free_irq(octep_dev->msix_entries[i].vector, octep_dev);
	}
	kfree(octep_dev->non_ioq_irq_names);
	octep_dev->non_ioq_irq_names = NULL;
	return -1;
}

static void octep_free_non_ioq_irqs(struct octep_ep_dev *octep_dev)
{
	int i;

	if (!octep_dev->msix_entries)
		return;

	for (i = 0; i < CFG_GET_NON_IOQ_MSIX(octep_dev->conf); i++)
		free_irq(octep_dev->msix_entries[i].vector, octep_dev);

	kfree(octep_dev->non_ioq_irq_names);
	octep_dev->non_ioq_irq_names = NULL;
}

/*
 * Register CQ completion interrupt handlers on the "custom" MSI-X vectors.
 * These are vectors at indices [num_non_ioq_msix .. num_non_ioq_msix + num_custom_irqs - 1].
 */
int octep_request_cq_irqs(struct octep_ep_dev *octep_dev, struct octep_rdma_dev *rdma_dev)
{
	int num_non_ioq_msix = CFG_GET_NON_IOQ_MSIX(octep_dev->conf);
	int num_cq_irqs = octep_dev->num_custom_irqs;
	struct msix_entry *msix_entry;
	int ret, i;

	if (!num_cq_irqs) {
		dev_info(&octep_dev->pdev->dev,
			 "[CQ_INTR] No CQ interrupt vectors available (custom_irqs=%d)\n",
			 num_cq_irqs);
		return 0;
	}

	/* Bottom half must be ready before any vector can fire. The watchdog is
	 * left un-scheduled here; req_notify_cq starts it (via
	 * octep_rdma_cq_watchdog_kick) only when a CQ is armed for NEXT_COMP,
	 * and it self-stops once the last such CQ disarms.
	 */
	INIT_WORK(&rdma_dev->cq_work, octep_cq_work_fn);
	INIT_DELAYED_WORK(&rdma_dev->cq_watchdog, octep_cq_watchdog_fn);

	/* Expose this device to the read-only cq_dump debug parameter. */
	octep_cq_dbg_dev = rdma_dev;

	for (i = 0; i < num_cq_irqs; i++) {
		msix_entry = &octep_dev->msix_entries[num_non_ioq_msix + i];

		dev_info(&octep_dev->pdev->dev,
			 "[CQ_INTR] Registering CQ interrupt %d: vector=%d\n", i,
			 msix_entry->vector);

		/* Pass rdma_dev as dev_id so the ISR avoids a pci_get_drvdata() lookup. */
		ret = request_irq(msix_entry->vector, octep_cq_intr_handler, 0, "octep_rdma_cq",
				  rdma_dev);
		if (ret) {
			dev_err(&octep_dev->pdev->dev,
				"[CQ_INTR] request_irq failed for CQ vec %d; err=%d\n", i, ret);
			goto cq_irq_err;
		}
	}

	dev_info(&octep_dev->pdev->dev, "[CQ_INTR] Registered %d CQ interrupt vectors\n",
		 num_cq_irqs);
	return 0;

cq_irq_err:
	while (i) {
		--i;
		msix_entry = &octep_dev->msix_entries[num_non_ioq_msix + i];
		free_irq(msix_entry->vector, rdma_dev);
	}
	if (octep_cq_dbg_dev == rdma_dev)
		octep_cq_dbg_dev = NULL;
	/* Stop any re-arm (watchdog resched / req_notify kick) before cancel. */
	WRITE_ONCE(rdma_dev->cq_intr_enabled, false);
	smp_wmb();
	/* No vector can fire now; flush any bottom half already queued. */
	cancel_delayed_work_sync(&rdma_dev->cq_watchdog);
	cancel_work_sync(&rdma_dev->cq_work);
	return ret;
}

void octep_free_cq_irqs(struct octep_ep_dev *octep_dev, struct octep_rdma_dev *rdma_dev)
{
	int num_non_ioq_msix = CFG_GET_NON_IOQ_MSIX(octep_dev->conf);
	int num_cq_irqs = octep_dev->num_custom_irqs;
	struct msix_entry *msix_entry;
	int i;

	if (!num_cq_irqs)
		return;

	for (i = 0; i < num_cq_irqs; i++) {
		msix_entry = &octep_dev->msix_entries[num_non_ioq_msix + i];
		free_irq(msix_entry->vector, rdma_dev);
	}

	if (octep_cq_dbg_dev == rdma_dev)
		octep_cq_dbg_dev = NULL;

	/*
	 * Stop the watchdog from re-arming before we cancel it. Both the
	 * watchdog resched and req_notify_cq's kick honor cq_intr_enabled, so
	 * clearing it (ordered before the cancel by smp_wmb) makes the cancel
	 * final even though the IB device is still registered at this point and
	 * a verbs req_notify_cq could otherwise kick the watchdog concurrently.
	 */
	WRITE_ONCE(rdma_dev->cq_intr_enabled, false);
	smp_wmb();

	/* No vector can fire now; flush watchdog + bottom half still in flight. */
	cancel_delayed_work_sync(&rdma_dev->cq_watchdog);
	cancel_work_sync(&rdma_dev->cq_work);

	dev_info(&octep_dev->pdev->dev, "[CQ_INTR] Freed %d CQ interrupt vectors\n", num_cq_irqs);
}

int octep_setup_msix(struct octep_ep_dev *octep_dev)
{
	int ret;

	ret = octep_enable_msix_range(octep_dev);
	if (ret)
		return ret;

	ret = octep_request_non_ioq_irqs(octep_dev);
	if (ret) {
		octep_disable_msix(octep_dev);
		return ret;
	}

	octep_dev->hw_ops.enable_interrupts(octep_dev);
	dev_info(&octep_dev->pdev->dev, "MSIX + non-IOQ IRQs registered\n");
	return 0;
}

void octep_cleanup_msix(struct octep_ep_dev *octep_dev)
{
	if (!octep_dev->msix_entries)
		return;

	octep_dev->hw_ops.disable_interrupts(octep_dev);
	octep_free_non_ioq_irqs(octep_dev);
	octep_disable_msix(octep_dev);
	dev_info(&octep_dev->pdev->dev, "MSIX + non-IOQ IRQs cleaned up\n");
}

/* ---- PF-VF heartbeat / interrupt poll tasks ---- */

void cancel_all_tasks(struct octep_ep_dev *octep_dev)
{
	octep_dev->poll_non_ioq_intr = false;
	cancel_delayed_work_sync(&octep_dev->intr_poll_task);
}

void octep_hb_timeout_task(struct work_struct *work)
{
	struct octep_ep_dev *octep_dev = container_of(work, struct octep_ep_dev, hb_task.work);

	int status, miss_cnt;

	status = atomic_read(&octep_dev->status);
	if (status != OCTEP_DEV_STATUS_READY)
		return;

	miss_cnt = atomic_inc_return(&octep_dev->hb_miss_cnt);
	dev_dbg(&octep_dev->pdev->dev, "miss cnt %d %s", miss_cnt, __func__);

	if (miss_cnt < octep_dev->conf->fw_info.hb_miss_count) {
		queue_delayed_work(octep_wq, &octep_dev->hb_task,
				   msecs_to_jiffies(octep_dev->conf->fw_info.hb_interval));

		u64 ack_value = 0x2;

		octep_write_csr64(octep_dev, CNXK_SDP_EPF_SCRATCH, ack_value);
		dev_dbg(&octep_dev->pdev->dev,
			"Heartbeat ACK "
			" written to scratch register: 0x%llx",
			ack_value);
		return;
	}

	octep_write_csr64(octep_dev, CNXK_SDP_EPF_SCRATCH, 0x0);
	dev_info(&octep_dev->pdev->dev, "Heartbeat missed, scratch reg cleared");

	octep_rdma_send_heartbeat_miss_to_all_vfs(octep_dev, miss_cnt);
	dev_info(&octep_dev->pdev->dev, "Missed %u heartbeats. carrier off, stopping polling",
		 miss_cnt);

	atomic_set(&octep_dev->status, OCTEP_DEV_STATUS_UNINIT);

	dev_err(&octep_dev->pdev->dev,
		"Device marked as failed and cleaned up due to heartbeat timeout\n");
}

void octep_intr_poll_task(struct work_struct *work)
{
	struct octep_ep_dev *octep_dev =
		container_of(work, struct octep_ep_dev, intr_poll_task.work);
	int status;

	status = atomic_read(&octep_dev->status);
	if (status != OCTEP_DEV_STATUS_READY || !octep_dev->poll_non_ioq_intr) {
		dev_info(&octep_dev->pdev->dev, "Interrupt poll task stopped");
		return;
	}

	octep_dev->hw_ops.poll_non_ioq_interrupts(octep_dev);
	queue_delayed_work(octep_wq, &octep_dev->intr_poll_task,
			   msecs_to_jiffies(OCTEP_INTR_POLL_TIME_MSECS));
}

static void octep_vf_hb_timeout_task(struct work_struct *work)
{
	struct octep_ep_dev *octep_dev = container_of(work, struct octep_ep_dev, vf_hb_task.work);
	struct octep_ep_vf_mbox *mbox = NULL;
	u64 pf_vf_data;

	mbox = octep_dev->vf_mbox;
	pf_vf_data = readq(mbox->mbox_read_reg);
	if (pf_vf_data == 0xFFFFFFFFFFFFFFFFU) {
		dev_info(&octep_dev->pdev->dev, "VF interface :%s. carrier off\n",
			 octep_dev->netdev->name);
		netif_carrier_off(octep_dev->netdev);
		return;
	}
	queue_delayed_work(octep_wq, &octep_dev->vf_hb_task,
			   msecs_to_jiffies(OCTEP_DEFAULT_VF_HB_INTERVAL));
}

/* ---- Device setup / cleanup ---- */

static int octep_ep_dev_setup(struct octep_ep_dev *octep_dev)
{
	struct pci_dev *pdev = octep_dev->pdev;
	int i;

	octep_dev->conf = kzalloc(sizeof(*octep_dev->conf), GFP_KERNEL);
	if (!octep_dev->conf)
		return -ENOMEM;

	if (map_bar_region(octep_dev))
		goto ioremap_err;

	octep_dev->chip_id = pdev->device;
	octep_dev->rev_id = pdev->revision;
	dev_info(&pdev->dev, "chip_id = 0x%x\n", pdev->device);

	switch (octep_dev->chip_id) {
	case OCTEP_RDMA_DEVID_CN105K_PF:
	case OCTEP_RDMA_DEVID_CN106K_PF:
	case OCTEP_RDMA_DEVID_CN103K_PF:
		dev_info(&pdev->dev, "Setting up OCTEON %s PF PASS%d.%d\n",
			 octep_devid_to_str(octep_dev), OCTEP_MAJOR_REV(octep_dev),
			 OCTEP_MINOR_REV(octep_dev));
		octep_device_setup_cnxk_pf(octep_dev);
		break;
	case OCTEP_RDMA_DEVID_CN105K_VF:
	case OCTEP_RDMA_DEVID_CN106K_VF:
	case OCTEP_RDMA_DEVID_CN103K_VF:
		dev_info(&pdev->dev, "Setting up OCTEON %s VF PASS%d.%d\n",
			 octep_devid_to_str(octep_dev), OCTEP_MAJOR_REV(octep_dev),
			 OCTEP_MINOR_REV(octep_dev));
		octep_device_setup_cnxk_vf(octep_dev);
		break;
	default:
		dev_err(&pdev->dev, "%s: unsupported device\n", __func__);
		goto ioremap_err;
	}

	return 0;

ioremap_err:
	for (i = 0; i < OCTEP_MMIO_REGIONS; i++) {
		if (octep_dev->mmio[i].mapped) {
			iounmap(octep_dev->mmio[i].hw_addr);
			octep_dev->mmio[i].mapped = 0;
		}
	}
	kfree(octep_dev->conf);
	octep_dev->conf = NULL;

	return -ENODEV;
}

int octep_rdma_probe_dev(struct octep_ep_dev *octep_dev)
{
	struct net_device *netdev = octep_dev->netdev;
	int err;

	err = octep_ep_dev_setup(octep_dev);
	if (err) {
		dev_err(&octep_dev->pdev->dev, "Device setup failed\n");
		return -1;
	}

	netif_carrier_off(netdev);

	if (octep_vf_setup_mbox(octep_dev)) {
		dev_err(&octep_dev->pdev->dev, "VF Mailbox setup failed\n");
		goto dev_cleanup;
	}

	if (octep_vf_mbox_version_check(octep_dev)) {
		dev_err(&octep_dev->pdev->dev, "PF VF Mailbox version mismatch\n");
		goto dev_cleanup;
	}

	eth_hw_addr_set(netdev, octep_dev->mac_addr);
	dev_info(&octep_dev->pdev->dev, "MAC address: %pM\n", netdev->dev_addr);

	err = octep_setup_msix(octep_dev);
	if (err) {
		dev_err(&octep_dev->pdev->dev, "MSIX setup failed\n");
		goto dev_cleanup;
	}

	clear_bit(OCTEP_DEV_STATE_OPEN, &octep_dev->state);

	INIT_DELAYED_WORK(&octep_dev->vf_hb_task, octep_vf_hb_timeout_task);
	queue_delayed_work(octep_wq, &octep_dev->vf_hb_task,
			   msecs_to_jiffies(OCTEP_DEFAULT_VF_HB_INTERVAL));

	dev_info(&octep_dev->pdev->dev, "Device setup successful\n");

	return 0;

dev_cleanup:
	octep_device_cleanup(octep_dev);
	return -1;
}

void octep_device_cleanup(struct octep_ep_dev *octep_dev)
{
	int i;

	dev_info(&octep_dev->pdev->dev, "Cleaning up Octeon Device ...\n");
	cancel_delayed_work_sync(&octep_dev->vf_hb_task);
	octep_cleanup_msix(octep_dev);

	for (i = 0; i < OCTEP_MMIO_REGIONS; i++) {
		if (octep_dev->mmio[i].mapped)
			iounmap(octep_dev->mmio[i].hw_addr);
	}

	kfree(octep_dev->conf);
	octep_dev->conf = NULL;
}
