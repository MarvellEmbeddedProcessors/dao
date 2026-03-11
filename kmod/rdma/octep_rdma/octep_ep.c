/* SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 Marvell.
 *
 * PCIe endpoint device setup: BAR mapping, MSI-X, heartbeat, mailbox.
 * The non-RDMA netdev uses a reserved management QP (N-1),
 * implemented in octep_rdma_netdev.c.
 */

#include "octep_rdma.h"
#include "octep_ep.h"
#include "octep_ep_regs.h"
#include "octep_pfvf_mbox.h"

#define OCTEP_INTR_POLL_TIME_MSECS 100
struct workqueue_struct *octep_wq;

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

static int octep_enable_msix_range(struct octep_ep_dev *octep_dev)
{
	int num_msix, msix_allocated;
	int i;

	octep_dev->num_custom_irqs = 5;
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
