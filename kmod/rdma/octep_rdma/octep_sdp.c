/* SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 Marvell.
 */

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/skbuff.h>
#include <linux/udp.h>

#include "octep_rdma.h"
#include "octep_sdp.h"
#include "octep_sdp_regs.h"
#include "octep_pfvf_mbox.h"

#define OCTEP_INTR_POLL_TIME_MSECS 100
struct workqueue_struct *octep_wq;

static const char *octep_devid_to_str(struct octep_sdp_dev *octep_dev)
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

static int
map_bar_region(struct octep_sdp_dev *octep_dev)
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

static int
octep_alloc_ioq_vectors(struct octep_sdp_dev *octep_dev)
{
	int i;
	struct octep_ioq_vector *ioq_vector;

	for (i = 0; i < octep_dev->num_oqs; i++) {
		octep_dev->ioq_vector[i] = vzalloc(sizeof(*octep_dev->ioq_vector[i]));
		if (!octep_dev->ioq_vector[i])
			goto free_ioq_vector;

		ioq_vector = octep_dev->ioq_vector[i];
		ioq_vector->iq = octep_dev->iq[i];
		ioq_vector->oq = octep_dev->oq[i];
		ioq_vector->octep_dev = octep_dev;
	}

	dev_info(&octep_dev->pdev->dev, "Allocated %d IOQ vectors\n", octep_dev->num_oqs);
	return 0;

free_ioq_vector:
	while (i) {
		i--;
		vfree(octep_dev->ioq_vector[i]);
		octep_dev->ioq_vector[i] = NULL;
	}
	return -1;
}

static void
octep_free_ioq_vectors(struct octep_sdp_dev *octep_dev)
{
	int i;

	for (i = 0; i < octep_dev->num_oqs; i++) {
		if (octep_dev->ioq_vector[i]) {
			vfree(octep_dev->ioq_vector[i]);
			octep_dev->ioq_vector[i] = NULL;
		}
	}
}

static int
octep_enable_msix_range(struct octep_sdp_dev *octep_dev)
{
	int num_msix, msix_allocated;
	int i;

	octep_dev->num_custom_irqs = 5;
	dev_dbg(&octep_dev->pdev->dev, "[%s] octep_dev->num_oqs %d non_ioq_msix %d\n", __func__,
		octep_dev->num_oqs, CFG_GET_NON_IOQ_MSIX(octep_dev->conf));
	/* Generic interrupts apart from input/output queues */
	num_msix = octep_dev->num_oqs + CFG_GET_NON_IOQ_MSIX(octep_dev->conf) +
		   octep_dev->num_custom_irqs;
	octep_dev->msix_entries = kcalloc(num_msix, sizeof(struct msix_entry), GFP_KERNEL);

	if (!octep_dev->msix_entries)
		goto msix_alloc_err;

	for (i = 0; i < num_msix; i++)
		octep_dev->msix_entries[i].entry = i;

	msix_allocated =
		pci_enable_msix_range(octep_dev->pdev, octep_dev->msix_entries, num_msix, num_msix);

	printk("MSI-X allocated %d entries (requested %d)\n", msix_allocated, num_msix);
	if (msix_allocated != num_msix) {
		dev_err(&octep_dev->pdev->dev, "Failed to enable %d msix irqs; got only %d\n",
			num_msix, msix_allocated);
		goto enable_msix_err;
	}
	octep_dev->num_irqs = msix_allocated - octep_dev->num_custom_irqs;
	dev_info(&octep_dev->pdev->dev, "MSI-X enabled: total %d num_irqs %d custom irq %d\n",
		 msix_allocated, octep_dev->num_irqs, octep_dev->num_custom_irqs);

	return 0;

enable_msix_err:
	if (msix_allocated > 0)
		pci_disable_msix(octep_dev->pdev);
	kfree(octep_dev->msix_entries);
	octep_dev->msix_entries = NULL;
msix_alloc_err:
	return -1;
}

static void
octep_disable_msix(struct octep_sdp_dev *octep_dev)
{
	if (octep_dev->msix_entries) {
		pci_disable_msix(octep_dev->pdev);
		kfree(octep_dev->msix_entries);
		octep_dev->msix_entries = NULL;
	}
	dev_info(&octep_dev->pdev->dev, "Disabled MSI-X\n");
}

static irqreturn_t
octep_mbox_intr_handler(int irq, void *data)
{
	struct octep_sdp_dev *octep_dev = data;

	return octep_dev->hw_ops.mbox_intr_handler(octep_dev);
}

static irqreturn_t
octep_oei_intr_handler(int irq, void *data)
{
	struct octep_sdp_dev *octep_dev = data;

	return octep_dev->hw_ops.oei_intr_handler(octep_dev);
}

static irqreturn_t
octep_ire_intr_handler(int irq, void *data)
{
	struct octep_sdp_dev *octep_dev = data;

	return octep_dev->hw_ops.ire_intr_handler(octep_dev);
}

static irqreturn_t
octep_ore_intr_handler(int irq, void *data)
{
	struct octep_sdp_dev *octep_dev = data;

	return octep_dev->hw_ops.ore_intr_handler(octep_dev);
}

static irqreturn_t
octep_vfire_intr_handler(int irq, void *data)
{
	struct octep_sdp_dev *octep_dev = data;

	pr_info("DBG: %s", __func__);
	return octep_dev->hw_ops.vfire_intr_handler(octep_dev);
}

static irqreturn_t
octep_vfore_intr_handler(int irq, void *data)
{
	struct octep_sdp_dev *octep_dev = data;

	return octep_dev->hw_ops.vfore_intr_handler(octep_dev);
}

static irqreturn_t
octep_dma_intr_handler(int irq, void *data)
{
	struct octep_sdp_dev *octep_dev = data;

	return octep_dev->hw_ops.dma_intr_handler(octep_dev);
}

static irqreturn_t
octep_dma_vf_intr_handler(int irq, void *data)
{
	struct octep_sdp_dev *octep_dev = data;

	return octep_dev->hw_ops.dma_vf_intr_handler(octep_dev);
}

static irqreturn_t
octep_pp_vf_intr_handler(int irq, void *data)
{
	struct octep_sdp_dev *octep_dev = data;

	return octep_dev->hw_ops.pp_vf_intr_handler(octep_dev);
}

static irqreturn_t
octep_misc_intr_handler(int irq, void *data)
{
	struct octep_sdp_dev *octep_dev = data;

	return octep_dev->hw_ops.misc_intr_handler(octep_dev);
}

static irqreturn_t
octep_rsvd_intr_handler(int irq, void *data)
{
	struct octep_sdp_dev *octep_dev = data;

	return octep_dev->hw_ops.rsvd_intr_handler(octep_dev);
}

static irqreturn_t
octep_ioq_intr_handler(int irq, void *data)
{
	struct octep_ioq_vector *ioq_vector = data;
	struct octep_sdp_dev *octep_dev = ioq_vector->octep_dev;

	return octep_dev->hw_ops.ioq_intr_handler(ioq_vector);
}

static int
octep_request_irqs(struct octep_sdp_dev *octep_dev)
{
	struct net_device *netdev = octep_dev->netdev;
	struct octep_ioq_vector *ioq_vector;
	struct msix_entry *msix_entry;
	char **non_ioq_msix_names;
	int num_non_ioq_msix;
	int ret, i, j;

	num_non_ioq_msix = CFG_GET_NON_IOQ_MSIX(octep_dev->conf);
	non_ioq_msix_names = CFG_GET_NON_IOQ_MSIX_NAMES(octep_dev->conf);

	octep_dev->non_ioq_irq_names = kcalloc(num_non_ioq_msix, OCTEP_MSIX_NAME_SIZE, GFP_KERNEL);
	if (!octep_dev->non_ioq_irq_names)
		goto alloc_err;

	/* First few MSI-X interrupts are non-queue interrupts */
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
		} else if (!strncmp(non_ioq_msix_names[i], "epf_ire_rint",
				    strlen("epf_ire_rint"))) {
			ret = request_irq(msix_entry->vector, octep_ire_intr_handler, 0, irq_name,
					  octep_dev);
		} else if (!strncmp(non_ioq_msix_names[i], "epf_ore_rint",
				    strlen("epf_ore_rint"))) {
			ret = request_irq(msix_entry->vector, octep_ore_intr_handler, 0, irq_name,
					  octep_dev);
		} else if (!strncmp(non_ioq_msix_names[i], "epf_vfire_rint",
				    strlen("epf_vfire_rint"))) {
			ret = request_irq(msix_entry->vector, octep_vfire_intr_handler, 0, irq_name,
					  octep_dev);
		} else if (!strncmp(non_ioq_msix_names[i], "epf_vfore_rint",
				    strlen("epf_vfore_rint"))) {
			ret = request_irq(msix_entry->vector, octep_vfore_intr_handler, 0, irq_name,
					  octep_dev);
		} else if (!strncmp(non_ioq_msix_names[i], "epf_dma_rint",
				    strlen("epf_dma_rint"))) {
			ret = request_irq(msix_entry->vector, octep_dma_intr_handler, 0, irq_name,
					  octep_dev);
		} else if (!strncmp(non_ioq_msix_names[i], "epf_dma_vf_rint",
				    strlen("epf_dma_vf_rint"))) {
			ret = request_irq(msix_entry->vector, octep_dma_vf_intr_handler, 0,
					  irq_name, octep_dev);
		} else if (!strncmp(non_ioq_msix_names[i], "epf_pp_vf_rint",
				    strlen("epf_pp_vf_rint"))) {
			ret = request_irq(msix_entry->vector, octep_pp_vf_intr_handler, 0, irq_name,
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
			goto non_ioq_irq_err;
		}
	}

	/* Request IRQs for Tx/Rx queues */
	for (j = 0; j < octep_dev->num_oqs; j++) {
		ioq_vector = octep_dev->ioq_vector[j];
		msix_entry = &octep_dev->msix_entries[j + num_non_ioq_msix];

		snprintf(ioq_vector->name, sizeof(ioq_vector->name), "%s-q%d", netdev->name, j);
		ret = request_irq(msix_entry->vector, octep_ioq_intr_handler, 0, ioq_vector->name,
				  ioq_vector);
		if (ret) {
			dev_err(&octep_dev->pdev->dev, "request_irq failed for Q-%d; err=%d", j,
				ret);
			goto ioq_irq_err;
		}

		cpumask_set_cpu(j % num_online_cpus(), &ioq_vector->affinity_mask);
		irq_set_affinity_hint(msix_entry->vector, &ioq_vector->affinity_mask);
	}

	return 0;
ioq_irq_err:
	while (j) {
		--j;
		ioq_vector = octep_dev->ioq_vector[j];
		msix_entry = &octep_dev->msix_entries[j + num_non_ioq_msix];
		irq_set_affinity_hint(msix_entry->vector, NULL);
		free_irq(msix_entry->vector, ioq_vector);
	}
non_ioq_irq_err:
	while (i) {
		--i;
		free_irq(octep_dev->msix_entries[i].vector, octep_dev);
	}
	kfree(octep_dev->non_ioq_irq_names);
	octep_dev->non_ioq_irq_names = NULL;
alloc_err:
	return -1;
}

static void
octep_free_irqs(struct octep_sdp_dev *octep_dev)
{
	int i;

	if (octep_dev->msix_entries) {
		/* First few MSI-X interrupts are non queue interrupts; free them */
		for (i = 0; i < CFG_GET_NON_IOQ_MSIX(octep_dev->conf); i++)
			free_irq(octep_dev->msix_entries[i].vector, octep_dev);
		kfree(octep_dev->non_ioq_irq_names);

		/* Free IRQs for Input/Output (Tx/Rx) queues */
		dev_info(&octep_dev->pdev->dev, "%s: Freeing IRQs total %d\n", __func__,
			 octep_dev->num_irqs);
		for (i = CFG_GET_NON_IOQ_MSIX(octep_dev->conf); i < octep_dev->num_irqs; i++) {
			irq_set_affinity_hint(octep_dev->msix_entries[i].vector, NULL);
			free_irq(octep_dev->msix_entries[i].vector,
				 octep_dev->ioq_vector[i - CFG_GET_NON_IOQ_MSIX(octep_dev->conf)]);
		}
	}
}

int octep_setup_irqs(struct octep_sdp_dev *octep_dev)
{
	if (octep_alloc_ioq_vectors(octep_dev))
		goto ioq_vector_err;

	if (octep_enable_msix_range(octep_dev))
		goto enable_msix_err;

	if (octep_request_irqs(octep_dev))
		goto request_irq_err;

	return 0;

request_irq_err:
	octep_disable_msix(octep_dev);
enable_msix_err:
	octep_free_ioq_vectors(octep_dev);
ioq_vector_err:
	return -1;
}

void octep_clean_irqs(struct octep_sdp_dev *octep_dev)
{
	octep_free_irqs(octep_dev);
	octep_disable_msix(octep_dev);
	octep_free_ioq_vectors(octep_dev);
}

void
octep_oq_reset_indices(struct octep_oq *oq)
{
	oq->host_read_idx = 0;
	oq->host_refill_idx = 0;
	oq->refill_count = 0;
	oq->last_pkt_count = 0;
	oq->pkts_pending = 0;
}

static int
octep_oq_fill_ring_buffers(struct octep_oq *oq)
{
	struct octep_oq_desc_hw *desc_ring = oq->desc_ring;
	struct octep_oq_resp_hw *resp_hw;
	struct page *page;
	u32 i;

	for (i = 0; i < oq->max_count; i++) {
		page = dev_alloc_page();
		if (unlikely(!page)) {
			dev_err(oq->dev, "Rx buffer alloc failed\n");
			goto rx_buf_alloc_err;
		}
		resp_hw = page_address(page);
		resp_hw->length = 0x0;

		desc_ring[i].buffer_ptr =
			dma_map_page(oq->dev, page, 0, PAGE_SIZE, DMA_FROM_DEVICE);
		if (dma_mapping_error(oq->dev, desc_ring[i].buffer_ptr)) {
			dev_err(oq->dev, "OQ-%d buffer alloc: DMA mapping error!\n", oq->q_no);
			put_page(page);
			goto dma_map_sg_err;
		}
		oq->buff_info[i].page = page;
		dev_dbg(oq->dev, "[%s] OQ-%d Allocated buffer[%d] @0x%llx page %p\n", __func__,
			oq->q_no, i, desc_ring[i].buffer_ptr, oq->buff_info[i].page);
	}

	return 0;

dma_map_sg_err:
rx_buf_alloc_err:
	while (i) {
		i--;
		dma_unmap_page(oq->dev, desc_ring[i].buffer_ptr, PAGE_SIZE, DMA_FROM_DEVICE);
		put_page(oq->buff_info[i].page);
		oq->buff_info[i].page = NULL;
	}

	return -1;
}

void
octep_oq_free_ring_buffers(struct octep_oq *oq)
{
	struct octep_oq_desc_hw *desc_ring = oq->desc_ring;
	int i;

	if (!oq->desc_ring || !oq->buff_info)
		return;

	for (i = 0; i < oq->max_count; i++) {
		if (oq->buff_info[i].page) {
			dev_dbg(oq->dev, "[%s] OQ-%d Freeing buffer[%d] @0x%llx page %p\n",
				__func__, oq->q_no, i, desc_ring[i].buffer_ptr,
				oq->buff_info[i].page);
			dma_unmap_page(oq->dev, desc_ring[i].buffer_ptr, PAGE_SIZE,
				       DMA_FROM_DEVICE);
			put_page(oq->buff_info[i].page);
			oq->buff_info[i].page = NULL;
			desc_ring[i].buffer_ptr = 0;
		}
	}
	octep_oq_reset_indices(oq);
}

static int
octep_free_oq(struct octep_oq *oq)
{
	struct octep_sdp_dev *octep_dev = oq->octep_dev;
	int q_no = oq->q_no;

	octep_oq_free_ring_buffers(oq);

	vfree(oq->buff_info);

	if (oq->desc_ring)
		dma_free_coherent(oq->dev, oq->max_count * OCTEP_OQ_DESC_SIZE, oq->desc_ring,
				  oq->desc_ring_dma);

	vfree(oq);
	octep_dev->oq[q_no] = NULL;
	octep_dev->num_oqs--;
	return 0;
}

static void
octep_free_oqs(struct octep_sdp_dev *octep_dev)
{
	int i;

	for (i = 0; i < octep_dev->num_oqs; i++) {
		if (!octep_dev->oq[i])
			continue;
		octep_free_oq(octep_dev->oq[i]);
		dev_info(&octep_dev->pdev->dev, "Successfully freed OQ(RxQ)-%d.\n", i);
	}
}

static int
octep_setup_oq(struct octep_sdp_dev *octep_dev, int q_no)
{
	struct octep_oq *oq;
	u32 desc_ring_size;

	oq = vzalloc(sizeof(*oq));
	if (!oq)
		goto create_oq_fail;

	octep_dev->oq[q_no] = oq;

	oq->octep_dev = octep_dev;
	oq->netdev = octep_dev->netdev;
	oq->dev = &octep_dev->pdev->dev;
	oq->q_no = q_no;
	oq->max_count = CFG_GET_OQ_NUM_DESC(octep_dev->conf);
	oq->ring_size_mask = oq->max_count - 1;
	oq->buffer_size = CFG_GET_OQ_BUF_SIZE(octep_dev->conf);
	oq->max_single_buffer_size = oq->buffer_size - OCTEP_OQ_RESP_HW_SIZE;

	/* When the hardware/firmware supports additional capabilities,
	 * additional header is filled-in by Octeon after length field in
	 * Rx packets. this header contains additional packet information.
	 */
	if (octep_dev->conf->fw_info.rx_ol_flags)
		oq->max_single_buffer_size -= OCTEP_OQ_RESP_HW_EXT_SIZE;

	oq->refill_threshold = CFG_GET_OQ_REFILL_THRESHOLD(octep_dev->conf);

	desc_ring_size = oq->max_count * OCTEP_OQ_DESC_SIZE;
	oq->desc_ring = dma_alloc_coherent(oq->dev, desc_ring_size, &oq->desc_ring_dma, GFP_KERNEL);

	if (unlikely(!oq->desc_ring)) {
		dev_err(oq->dev, "Failed to allocate DMA memory for OQ-%d !!\n", q_no);
		goto desc_dma_alloc_err;
	}

	oq->buff_info = vzalloc(oq->max_count * OCTEP_OQ_RECVBUF_SIZE);
	if (unlikely(!oq->buff_info)) {
		dev_err(&octep_dev->pdev->dev, "Failed to allocate buffer info for OQ-%d\n", q_no);
		goto buf_list_err;
	}

	if (octep_oq_fill_ring_buffers(oq))
		goto oq_fill_buff_err;

	octep_oq_reset_indices(oq);
	if (octep_dev->hw_ops.setup_oq_regs(octep_dev, q_no)) {
		dev_err(&octep_dev->pdev->dev, "Failed to setup OQ-%d registers\n", q_no);
		goto oq_fill_buff_err;
	}

	octep_dev->num_oqs++;

	return 0;

oq_fill_buff_err:
	vfree(oq->buff_info);
	oq->buff_info = NULL;
buf_list_err:
	dma_free_coherent(oq->dev, desc_ring_size, oq->desc_ring, oq->desc_ring_dma);
	oq->desc_ring = NULL;
desc_dma_alloc_err:
	vfree(oq);
	octep_dev->oq[q_no] = NULL;
create_oq_fail:
	return -ENOMEM;
}

static int
octep_setup_oqs(struct octep_sdp_dev *octep_dev)
{
	int i, retval = 0;

	octep_dev->num_oqs = 0;
	for (i = 0; i < CFG_GET_PORTS_ACTIVE_IO_RINGS(octep_dev->conf); i++) {
		retval = octep_setup_oq(octep_dev, i);
		if (retval) {
			dev_err(&octep_dev->pdev->dev, "Failed to setup OQ(RxQ)-%d.\n", i);
			goto oq_setup_err;
		}
		dev_info(&octep_dev->pdev->dev, "Successfully setup OQ(RxQ)-%d. oq %p\n", i,
			 octep_dev->oq[i]);
	}

	return 0;

oq_setup_err:
	while (i) {
		i--;
		octep_free_oq(octep_dev->oq[i]);
	}
	return -1;
}

/* Cancel all tasks except hb task */
void cancel_all_tasks(struct octep_sdp_dev *octep_dev)
{
	octep_dev->poll_non_ioq_intr = false;
	cancel_delayed_work_sync(&octep_dev->intr_poll_task);
}

/**
 * octep_hb_timeout_task - work queue task to check firmware heartbeat.
 *
 * @work: pointer to hb work_struct
 *
 * Check for heartbeat miss count. Uninitialize oct device if miss count
 * exceeds configured max heartbeat miss count.
 *
 **/
void octep_hb_timeout_task(struct work_struct *work)
{
	struct octep_sdp_dev *octep_dev = container_of(work, struct octep_sdp_dev, hb_task.work);

	int status, miss_cnt;

	status = atomic_read(&octep_dev->status);
	if (status != OCTEP_DEV_STATUS_INIT && status != OCTEP_DEV_STATUS_READY)
		return;

	miss_cnt = atomic_inc_return(&octep_dev->hb_miss_cnt);
	dev_info(&octep_dev->pdev->dev, "miss cnt %d %s", miss_cnt, __func__);

	if (miss_cnt < octep_dev->conf->fw_info.hb_miss_count) {
		queue_delayed_work(octep_wq, &octep_dev->hb_task,
				   msecs_to_jiffies(octep_dev->conf->fw_info.hb_interval));

		/* Write acknowledgment to scratch register */
		u64 ack_value = 0x2;

		octep_write_csr64(octep_dev, CNXK_SDP_EPF_SCRATCH, ack_value);
		dev_dbg(&octep_dev->pdev->dev,
			"Heartbeat ACK "
			" written to scratch register: 0x%llx",
			ack_value);
		return;
	}

	/* Heartbeat missed - clear scratch register to reset state */
	octep_write_csr64(octep_dev, CNXK_SDP_EPF_SCRATCH, 0x0);
	dev_info(&octep_dev->pdev->dev, "Heartbeat missed, scratch reg cleared");

	/* Send heartbeat miss notification to all VFs */
	octep_rdma_send_heartbeat_miss_to_all_vfs(octep_dev, miss_cnt);
	dev_info(&octep_dev->pdev->dev, "Missed %u heartbeats. carrier off, stopping polling",
		 miss_cnt);

	/* Set device status to failed */
	atomic_set(&octep_dev->status, OCTEP_DEV_STATUS_UNINIT);

	dev_err(&octep_dev->pdev->dev,
		"Device marked as failed and cleaned up due to heartbeat timeout\n");
}

/**
 * octep_intr_poll_task - work queue task to process non-ioq interrupts.
 *
 * @work: pointer to mbox work_struct
 *
 * Process non-ioq interrupts to handle control mailbox, pfvf mailbox.
 **/
void octep_intr_poll_task(struct work_struct *work)
{
	struct octep_sdp_dev *octep_dev =
		container_of(work, struct octep_sdp_dev, intr_poll_task.work);
	int status;

	status = atomic_read(&octep_dev->status);
	if ((status != OCTEP_DEV_STATUS_INIT && status != OCTEP_DEV_STATUS_READY) ||
	    !octep_dev->poll_non_ioq_intr) {
		dev_info(&octep_dev->pdev->dev, "Interrupt poll task stopped");
		return;
	}

	octep_dev->hw_ops.poll_non_ioq_interrupts(octep_dev);
	queue_delayed_work(octep_wq, &octep_dev->intr_poll_task,
			   msecs_to_jiffies(OCTEP_INTR_POLL_TIME_MSECS));
}

/**
 * octep_vf_hb_timeout_task - work queue task to check PF state.
 *
 * @work: pointer to hb work_struct
 *
 * Check for PF state by reading PF VF data Mailbox register.
 * if the read value is all F's means PF/PCIe is in reset state,
 * Then turn off netif carrier.
 *
 **/
static void octep_vf_hb_timeout_task(struct work_struct *work)
{
	struct octep_sdp_dev *octep_dev = container_of(work, struct octep_sdp_dev, vf_hb_task.work);
	struct octep_sdp_vf_mbox *mbox = NULL;
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

static int octep_sdp_dev_setup(struct octep_sdp_dev *octep_dev)
{
	struct pci_dev *pdev = octep_dev->pdev;
	int i;

	/* allocate memory for octep_dev->conf */
	octep_dev->conf = kzalloc(sizeof(*octep_dev->conf), GFP_KERNEL);
	if (!octep_dev->conf)
		return -ENOMEM;

	if (map_bar_region(octep_dev))
		goto unsupported_dev;

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
	while (i) {
		i--;
		iounmap(octep_dev->mmio[i].hw_addr);
		octep_dev->mmio[i].mapped = 0;
	}
	kfree(octep_dev->conf);
	octep_dev->conf = NULL;
unsupported_dev:
	return -ENODEV;
}

void
octep_iq_reset_indices(struct octep_iq *iq)
{
	iq->fill_cnt = 0;
	iq->host_write_index = 0;
	iq->octep_read_index = 0;
	iq->flush_index = 0;
	iq->pkts_processed = 0;
	iq->pkt_in_done = 0;
}

static int
octep_setup_iq(struct octep_sdp_dev *octep_dev, int q_no)
{
	u32 desc_ring_size, buff_info_size, sglist_size;
	struct octep_iq *iq;
	int i;

	iq = vzalloc(sizeof(*iq));
	if (!iq)
		goto iq_alloc_err;
	octep_dev->iq[q_no] = iq;

	iq->octep_dev = octep_dev;
	iq->netdev = octep_dev->netdev;
	iq->dev = &octep_dev->pdev->dev;
	iq->q_no = q_no;
	iq->max_count = CFG_GET_IQ_NUM_DESC(octep_dev->conf);
	iq->ring_size_mask = iq->max_count - 1;
	iq->fill_threshold = CFG_GET_IQ_DB_MIN(octep_dev->conf);
	iq->netdev_q = netdev_get_tx_queue(iq->netdev, q_no);

	/* Allocate memory for hardware queue descriptors */
	desc_ring_size = OCTEP_IQ_DESC_SIZE * CFG_GET_IQ_NUM_DESC(octep_dev->conf);
	iq->desc_ring = dma_alloc_coherent(iq->dev, desc_ring_size, &iq->desc_ring_dma, GFP_KERNEL);
	if (unlikely(!iq->desc_ring)) {
		dev_err(iq->dev, "Failed to allocate DMA memory for IQ-%d\n", q_no);
		goto desc_dma_alloc_err;
	}

	/* Allocate memory for hardware SGLIST descriptors */
	sglist_size = OCTEP_SGLIST_SIZE_PER_PKT * CFG_GET_IQ_NUM_DESC(octep_dev->conf);
	iq->sglist = dma_alloc_coherent(iq->dev, sglist_size, &iq->sglist_dma, GFP_KERNEL);
	if (unlikely(!iq->sglist)) {
		dev_err(iq->dev, "Failed to allocate DMA memory for IQ-%d SGLIST\n", q_no);
		goto sglist_alloc_err;
	}

	/* allocate memory to manage Tx packets pending completion */
	buff_info_size = OCTEP_IQ_TXBUFF_INFO_SIZE * iq->max_count;
	iq->buff_info = vzalloc(buff_info_size);
	if (!iq->buff_info) {
		dev_err(iq->dev, "Failed to allocate buff info for IQ-%d\n", q_no);
		goto buff_info_err;
	}

	/* Setup sglist addresses in tx_buffer entries */
	for (i = 0; i < CFG_GET_IQ_NUM_DESC(octep_dev->conf); i++) {
		struct octep_tx_buffer *tx_buffer;

		tx_buffer = &iq->buff_info[i];
		tx_buffer->sglist = &iq->sglist[i * OCTEP_SGLIST_ENTRIES_PER_PKT];
		tx_buffer->sglist_dma = iq->sglist_dma + (i * OCTEP_SGLIST_SIZE_PER_PKT);
	}

	octep_iq_reset_indices(iq);
	octep_dev->hw_ops.setup_iq_regs(octep_dev, q_no);

	octep_dev->num_iqs++;
	return 0;

buff_info_err:
	dma_free_coherent(iq->dev, sglist_size, iq->sglist, iq->sglist_dma);
sglist_alloc_err:
	dma_free_coherent(iq->dev, desc_ring_size, iq->desc_ring, iq->desc_ring_dma);
desc_dma_alloc_err:
	vfree(iq);
	octep_dev->iq[q_no] = NULL;
iq_alloc_err:
	return -1;
}

static void
octep_free_iq(struct octep_iq *iq)
{
	struct octep_sdp_dev *octep_dev = iq->octep_dev;
	u64 desc_ring_size, sglist_size;
	int q_no = iq->q_no;

	desc_ring_size = OCTEP_IQ_DESC_SIZE * CFG_GET_IQ_NUM_DESC(octep_dev->conf);

	vfree(iq->buff_info);

	if (iq->desc_ring)
		dma_free_coherent(iq->dev, desc_ring_size, iq->desc_ring, iq->desc_ring_dma);

	sglist_size = OCTEP_SGLIST_SIZE_PER_PKT * CFG_GET_IQ_NUM_DESC(octep_dev->conf);
	if (iq->sglist)
		dma_free_coherent(iq->dev, sglist_size, iq->sglist, iq->sglist_dma);

	vfree(iq);
	octep_dev->iq[q_no] = NULL;
	octep_dev->num_iqs--;
}

static int
octep_setup_iqs(struct octep_sdp_dev *octep_dev)
{
	int i;

	octep_dev->num_iqs = 0;
	for (i = 0; i < CFG_GET_PORTS_ACTIVE_IO_RINGS(octep_dev->conf); i++) {
		if (octep_setup_iq(octep_dev, i)) {
			dev_err(&octep_dev->pdev->dev, "Failed to setup IQ(TxQ)-%d.\n", i);
			goto iq_setup_err;
		}
		dev_info(&octep_dev->pdev->dev, "Successfully setup IQ(TxQ)-%d.\n", i);
	}

	return 0;

iq_setup_err:
	while (i) {
		i--;
		octep_free_iq(octep_dev->iq[i]);
	}
	return -1;
}

static void
octep_free_iqs(struct octep_sdp_dev *octep_dev)
{
	int i;

	for (i = 0; i < octep_dev->num_iqs; i++) {
		if (!octep_dev->iq[i])
			continue;
		octep_free_iq(octep_dev->iq[i]);
		dev_info(&octep_dev->pdev->dev, "Successfully destroyed IQ(TxQ)-%d.\n", i);
	}
	octep_dev->num_iqs = 0;
}

static void
octep_iq_free_pending(struct octep_iq *iq)
{
	struct octep_tx_buffer *tx_buffer;
	struct skb_shared_info *shinfo;
	u32 fi = iq->flush_index;
	struct sk_buff *skb;
	u8 frags, i;

	while (fi != iq->host_write_index) {
		tx_buffer = iq->buff_info + fi;
		skb = tx_buffer->skb;

		fi++;
		if (unlikely(fi == iq->max_count))
			fi = 0;

		if (!tx_buffer->gather) {
			dma_unmap_single(iq->dev, tx_buffer->dma, tx_buffer->skb->len,
					 DMA_TO_DEVICE);
			dev_kfree_skb_any(skb);
			continue;
		}

		/* Scatter/Gather */
		shinfo = skb_shinfo(skb);
		frags = shinfo->nr_frags;

		dma_unmap_single(iq->dev, tx_buffer->sglist[0].dma_ptr[0],
				 tx_buffer->sglist[0].len[3], DMA_TO_DEVICE);

		i = 1; /* entry 0 is main skb, unmapped above */
		while (frags--) {
			dma_unmap_page(iq->dev, tx_buffer->sglist[i >> 2].dma_ptr[i & 3],
				       tx_buffer->sglist[i >> 2].len[i & 3], DMA_TO_DEVICE);
			i++;
		}

		dev_kfree_skb_any(skb);
	}

	iq->flush_index = fi;
	netdev_tx_reset_queue(netdev_get_tx_queue(iq->netdev, iq->q_no));
}

static void
octep_clean_iqs(struct octep_sdp_dev *octep_dev)
{
	int i;

	for (i = 0; i < octep_dev->num_iqs; i++) {
		octep_iq_free_pending(octep_dev->iq[i]);
		octep_iq_reset_indices(octep_dev->iq[i]);
	}
}

static void
octep_oq_dbell_init(struct octep_sdp_dev *octep_dev)
{
	int i;

	for (i = 0; i < octep_dev->num_oqs; i++)
		writel(octep_dev->oq[i]->max_count, octep_dev->oq[i]->pkts_credit_reg);
}

static int
octep_iq_process_completions(struct octep_iq *iq, u16 budget)
{
	struct octep_sdp_dev *octep_dev = iq->octep_dev;
	u32 compl_pkts, compl_bytes, compl_sg;
	struct octep_tx_buffer *tx_buffer;
	struct skb_shared_info *shinfo;
	u32 fi = iq->flush_index;
	struct sk_buff *skb;
	u8 frags, i;

	compl_pkts = 0;
	compl_sg = 0;
	compl_bytes = 0;
	iq->octep_read_index = octep_dev->hw_ops.update_iq_read_idx(iq);

	dev_dbg(&octep_dev->pdev->dev, "[%s] iq->octep_read_index %d budget %d\n", __func__,
		iq->octep_read_index, budget);
	while (likely(budget && (fi != iq->octep_read_index))) {
		tx_buffer = iq->buff_info + fi;
		skb = tx_buffer->skb;

		fi++;
		if (unlikely(fi == iq->max_count))
			fi = 0;
		compl_bytes += skb->len;
		compl_pkts++;
		budget--;

		if (!tx_buffer->gather) {
			dma_unmap_single(iq->dev, tx_buffer->dma, tx_buffer->skb->len,
					 DMA_TO_DEVICE);
			dev_kfree_skb_any(skb);
			continue;
		}

		/* Scatter/Gather */
		shinfo = skb_shinfo(skb);
		frags = shinfo->nr_frags;
		compl_sg++;

		dma_unmap_single(iq->dev, tx_buffer->sglist[0].dma_ptr[0],
				 tx_buffer->sglist[0].len[3], DMA_TO_DEVICE);

		i = 1; /* entry 0 is main skb, unmapped above */
		while (frags--) {
			dma_unmap_page(iq->dev, tx_buffer->sglist[i >> 2].dma_ptr[i & 3],
				       tx_buffer->sglist[i >> 2].len[3 - (i & 3)], DMA_TO_DEVICE);
			i++;
		}

		dev_kfree_skb_any(skb);
	}

	iq->pkts_processed += compl_pkts;
	iq->stats.instr_completed += compl_pkts;
	iq->stats.bytes_sent += compl_bytes;
	iq->stats.sgentry_sent += compl_sg;
	iq->flush_index = fi;

	netdev_tx_completed_queue(iq->netdev_q, compl_pkts, compl_bytes);

	if (unlikely(__netif_subqueue_stopped(iq->netdev, iq->q_no)) &&
	    (IQ_INSTR_SPACE(iq) > OCTEP_WAKE_QUEUE_THRESHOLD)) {
		dev_info(&octep_dev->pdev->dev, "[%s] Waking up subqueue\n", __func__);
		netif_wake_subqueue(iq->netdev, iq->q_no);
	}
	return !budget;
}

static void
octep_update_pkt(struct octep_iq *iq, struct octep_oq *oq)
{
	u32 pkts_pend = READ_ONCE(oq->pkts_pending);
	u32 last_pkt_count = READ_ONCE(oq->last_pkt_count);
	u32 pkts_processed = READ_ONCE(iq->pkts_processed);
	u32 pkt_in_done = READ_ONCE(iq->pkt_in_done);

	if (oq->suspend)
		return;

	if (pkts_processed) {
		writel(pkts_processed, iq->inst_cnt_reg);
		readl(iq->inst_cnt_reg);
		WRITE_ONCE(iq->pkt_in_done, (pkt_in_done - pkts_processed));
		WRITE_ONCE(iq->pkts_processed, 0);
	}
	if (last_pkt_count - pkts_pend) {
		writel(last_pkt_count - pkts_pend, oq->pkts_sent_reg);
		readl(oq->pkts_sent_reg);
		WRITE_ONCE(oq->last_pkt_count, pkts_pend);
	}
	/* Flush the previous wrties before writing to RESEND bit */
	smp_wmb();
}

static void
octep_enable_ioq_irq(struct octep_iq *iq, struct octep_oq *oq)
{
	writeq(1UL << OCTEP_OQ_INTR_RESEND_BIT, oq->pkts_sent_reg);
	writeq(1UL << OCTEP_IQ_INTR_RESEND_BIT, iq->inst_cnt_reg);
}

static int
octep_napi_poll(struct napi_struct *napi, int budget)
{
	struct octep_ioq_vector *ioq_vector = container_of(napi, struct octep_ioq_vector, napi);
	struct octep_oq *oq = ioq_vector->oq;
	u32 tx_pending, rx_done = 0;

	if (oq->suspend) {
		napi_complete(napi);
		return (budget - 1);
	}

	tx_pending = octep_iq_process_completions(ioq_vector->iq, budget);
	rx_done = octep_oq_process_rx(ioq_vector->oq, budget);

	octep_update_pkt(ioq_vector->iq, ioq_vector->oq);
	if (oq->suspend) {
		napi_complete(napi);
		return (budget - 1);
	}

	/* need more polling if tx completion processing is still pending or
	 * processed at least 'budget' number of rx packets.
	 */
	if (tx_pending || rx_done >= budget)
		return budget;

	napi_complete_done(napi, rx_done);
	octep_enable_ioq_irq(ioq_vector->iq, ioq_vector->oq);
	return rx_done;
}

static void
octep_napi_add(struct octep_sdp_dev *octep_dev)
{
	int i;

	for (i = 0; i < octep_dev->num_oqs; i++) {
		netdev_dbg(octep_dev->netdev, "Adding NAPI on Q-%d\n", i);
		netif_napi_add(octep_dev->netdev, &octep_dev->ioq_vector[i]->napi, octep_napi_poll);
		octep_dev->oq[i]->napi = &octep_dev->ioq_vector[i]->napi;
	}
}

static void
octep_napi_delete(struct octep_sdp_dev *octep_dev)
{
	int i;

	for (i = 0; i < octep_dev->num_oqs; i++) {
		netdev_dbg(octep_dev->netdev, "Deleting NAPI on Q-%d\n", i);
		if (octep_dev->oq[i]->napi) {
			netif_napi_del(&octep_dev->ioq_vector[i]->napi);
			octep_dev->oq[i]->napi = NULL;
		}
	}
}

static void
octep_napi_enable(struct octep_sdp_dev *octep_dev)
{
	int i;

	for (i = 0; i < octep_dev->num_oqs; i++) {
		netdev_dbg(octep_dev->netdev, "Enabling NAPI on Q-%d\n", i);
		napi_enable(&octep_dev->ioq_vector[i]->napi);
	}
}

static void
octep_napi_disable(struct octep_sdp_dev *octep_dev)
{
	int i;

	for (i = 0; i < octep_dev->num_oqs; i++) {
		netdev_dbg(octep_dev->netdev, "Disabling NAPI on Q-%d\n", i);
		if (octep_dev->oq[i]->napi)
			napi_disable(&octep_dev->ioq_vector[i]->napi);
	}
}

static void
octep_link_up(struct net_device *netdev)
{
	netif_carrier_on(netdev);
	netif_tx_start_all_queues(netdev);
}

static int
octep_open(struct net_device *netdev)
{
	struct octep_sdp_dev *octep_dev = netdev_priv(netdev);
	int ret;

	netdev_info(netdev, "Starting netdev ...\n");
	netdev_info(netdev, "pci name %s\n", pci_name(octep_dev->pdev));
	netif_carrier_off(netdev);

	octep_dev->hw_ops.reset_io_queues(octep_dev);

	if (octep_setup_iqs(octep_dev))
		goto setup_iq_err;
	if (octep_setup_oqs(octep_dev))
		goto setup_oq_err;
	if (octep_setup_irqs(octep_dev))
		goto setup_irq_err;

	ret = netif_set_real_num_tx_queues(netdev, octep_dev->num_oqs);
	if (ret)
		goto set_queues_err;
	ret = netif_set_real_num_rx_queues(netdev, octep_dev->num_iqs);
	if (ret)
		goto set_queues_err;

	octep_napi_add(octep_dev);
	octep_napi_enable(octep_dev);

	/* Stop PF polling when first VF interface opens to avoid conflicts */
	if (octep_dev->pdev && octep_dev->pdev->is_virtfn) {
		/* Increment active VF count and stop PF polling if first VF */
		struct pci_dev *pf_dev = pci_physfn(octep_dev->pdev);

		if (pf_dev) {
			struct octep_pf *octpf = pci_get_drvdata(pf_dev);

			if (octpf && octpf->octep_dev) {
				int prev_count;

				prev_count = atomic_fetch_inc(&octpf->active_vf_count);
				if (prev_count == 0) {
					/* First VF opening - stop PF polling and heartbeat */
					dev_info(
						&octep_dev->pdev->dev,
						"First VF interface opening - stopping PF polling and heartbeat\n");
					octpf->octep_dev->poll_non_ioq_intr = false;
				}
			}
		}
	}

	/* Enable Octeon device interrupts */
	octep_dev->hw_ops.enable_interrupts(octep_dev);

	/* Enable the input and output queues for this Octeon device */
	octep_dev->hw_ops.enable_io_queues(octep_dev);

	octep_oq_dbell_init(octep_dev);

	octep_link_up(netdev);

	set_bit(OCTEP_DEV_STATE_OPEN, &octep_dev->state);

	netdev_info(netdev, "Started netdev ...\n");

	return 0;

set_queues_err:
	octep_napi_disable(octep_dev);
	octep_napi_delete(octep_dev);
setup_irq_err:
	octep_free_oqs(octep_dev);
setup_oq_err:
	octep_free_iqs(octep_dev);
setup_iq_err:
	return -1;
}

static void
octep_get_stats64(struct net_device *netdev, struct rtnl_link_stats64 *stats)
{
	struct octep_sdp_dev *octep_dev = netdev_priv(netdev);
	u64 tx_packets, tx_bytes, rx_packets, rx_bytes;
	int q;

	set_bit(OCTEP_DEV_STATE_READ_STATS, &octep_dev->state);
	/* Memory Barrier */
	smp_mb__after_atomic();
	if (!test_bit(OCTEP_DEV_STATE_OPEN, &octep_dev->state)) {
		clear_bit(OCTEP_DEV_STATE_READ_STATS, &octep_dev->state);
		return;
	}

	tx_packets = 0;
	tx_bytes = 0;
	rx_packets = 0;
	rx_bytes = 0;
	for (q = 0; q < octep_dev->num_oqs; q++) {
		struct octep_iq *iq = octep_dev->iq[q];
		struct octep_oq *oq = octep_dev->oq[q];

		tx_packets += iq->stats.instr_completed;
		tx_bytes += iq->stats.bytes_sent;
		rx_packets += oq->stats.packets;
		rx_bytes += oq->stats.bytes;
	}
	stats->tx_packets = tx_packets;
	stats->tx_bytes = tx_bytes;
	stats->rx_packets = rx_packets;
	stats->rx_bytes = rx_bytes;
	clear_bit(OCTEP_DEV_STATE_READ_STATS, &octep_dev->state);
}

static int
octep_stop(struct net_device *netdev)
{
	struct octep_sdp_dev *octep_dev = netdev_priv(netdev);

	dev_info(&octep_dev->pdev->dev, "Stopping the device ...\n");

	if (!test_bit(OCTEP_DEV_STATE_OPEN, &octep_dev->state)) {
		netdev_info(netdev, "Already Stopped the device by FLR\n");
		return 0;
	}

	clear_bit(OCTEP_DEV_STATE_OPEN, &octep_dev->state);
	/* Memory Barrier */
	smp_mb__after_atomic();

	set_bit(OCTEP_DEV_STATE_DOWN_IN_PROGRESS, &octep_dev->state);
	/* Memory Barrier */
	smp_mb__after_atomic();

	/* Stop Tx from stack */
	netif_tx_stop_all_queues(netdev);
	netif_carrier_off(netdev);
	netif_tx_disable(netdev);

	octep_napi_disable(octep_dev);
	octep_napi_delete(octep_dev);
	octep_dev->hw_ops.disable_interrupts(octep_dev);

	/* Cancel VF heartbeat timeout task if this is a VF */
	if (octep_dev->pdev && octep_dev->pdev->is_virtfn)
		if (cancel_delayed_work(&octep_dev->vf_hb_task))
			dev_info(&octep_dev->pdev->dev,
				 "VF heartbeat task stopped during interface stop\n");

	octep_clean_irqs(octep_dev);
	octep_clean_iqs(octep_dev);

	octep_dev->hw_ops.disable_io_queues(octep_dev);
	octep_dev->hw_ops.reset_io_queues(octep_dev);
	octep_free_oqs(octep_dev);
	octep_free_iqs(octep_dev);

	/* Restart PF polling when last VF interface closes */
	struct pci_dev *pf_dev = pci_physfn(octep_dev->pdev);

	if (pf_dev) {
		struct octep_pf *octpf = pci_get_drvdata(pf_dev);

		if (octpf && octpf->octep_dev &&
		    atomic_read(&octpf->octep_dev->status) == OCTEP_DEV_STATUS_READY) {
			int prev_count;

			prev_count = atomic_fetch_dec(&octpf->active_vf_count);
			if (prev_count == 1) {
				/* Last VF closing - restart PF polling and heartbeat */
				dev_info(&octep_dev->pdev->dev,
					 "Last VF interface closing "
					 "restarting PF polling and heartbeat\n");
				octpf->octep_dev->poll_non_ioq_intr = true;
				queue_delayed_work(octep_wq, &octpf->octep_dev->intr_poll_task,
						   msecs_to_jiffies(OCTEP_INTR_POLL_TIME_MSECS));
				/* Reset heartbeat miss count and restart heartbeat monitoring */
				atomic_set(&octpf->octep_dev->hb_miss_cnt, 0);
				queue_delayed_work(
					octep_wq, &octpf->octep_dev->hb_task,
					msecs_to_jiffies(
						octpf->octep_dev->conf->fw_info.hb_interval));
			}
		}
	}

	clear_bit(OCTEP_DEV_STATE_DOWN_IN_PROGRESS, &octep_dev->state);
	/* Memory Barrier */
	smp_mb__after_atomic();

	dev_info(&octep_dev->pdev->dev, "Device stopped !!\n");
	return 0;
}

static int octep_iq_full_check(struct octep_iq *iq)
{
	if (likely((IQ_INSTR_SPACE(iq)) > OCTEP_WAKE_QUEUE_THRESHOLD))
		return 0;

	/* Stop the queue if unable to send */
	netif_stop_subqueue(iq->netdev, iq->q_no);

	/* check again and restart the queue, in case NAPI has just freed
	 * enough Tx ring entries.
	 */
	if (unlikely(IQ_INSTR_SPACE(iq) > OCTEP_WAKE_QUEUE_THRESHOLD)) {
		netif_start_subqueue(iq->netdev, iq->q_no);
		iq->stats.restart_cnt++;
		return 0;
	}

	return 1;
}

static netdev_tx_t
octep_start_xmit(struct sk_buff *skb, struct net_device *netdev)
{
	struct octep_sdp_dev *octep_dev = netdev_priv(netdev);
	netdev_features_t feat = netdev->features;
	struct octep_tx_sglist_desc *sglist;
	struct octep_tx_buffer *tx_buffer;
	struct octep_tx_desc_hw *hw_desc;
	struct skb_shared_info *shinfo;
	struct octep_instr_hdr *ih;
	struct octep_iq *iq;
	skb_frag_t *frag;
	u16 nr_frags, si;
	int xmit_more;
	u16 q_no, wi;

	if (skb_put_padto(skb, ETH_ZLEN))
		return NETDEV_TX_OK;

	q_no = skb_get_queue_mapping(skb);
	if (q_no >= octep_dev->num_iqs) {
		netdev_err(netdev, "Invalid Tx skb->queue_mapping=%d\n", q_no);
		q_no = q_no % octep_dev->num_iqs;
	}

	iq = octep_dev->iq[q_no];
	if (octep_iq_full_check(iq)) {
		iq->stats.tx_busy++;
		return NETDEV_TX_BUSY;
	}

	shinfo = skb_shinfo(skb);
	nr_frags = shinfo->nr_frags;

	wi = iq->host_write_index;
	hw_desc = &iq->desc_ring[wi];
	hw_desc->ih64 = 0;

	tx_buffer = iq->buff_info + wi;
	tx_buffer->skb = skb;

	ih = &hw_desc->ih;
	/* TODO prefill */
	ih->pkind = octep_dev->conf->fw_info.pkind;
	ih->fsz = octep_dev->conf->fw_info.fsz;
	ih->tlen = skb->len + ih->fsz;

	if (!nr_frags) {
		tx_buffer->gather = 0;
		tx_buffer->dma = dma_map_single(iq->dev, skb->data, skb->len, DMA_TO_DEVICE);
		if (dma_mapping_error(iq->dev, tx_buffer->dma))
			goto dma_map_err;
		hw_desc->dptr = tx_buffer->dma;
	} else {
		/* Scatter/Gather */
		dma_addr_t dma;
		u16 len;

		sglist = tx_buffer->sglist;

		ih->gsz = nr_frags + 1;
		ih->gather = 1;
		tx_buffer->gather = 1;

		len = skb_headlen(skb);
		dma = dma_map_single(iq->dev, skb->data, len, DMA_TO_DEVICE);
		if (dma_mapping_error(iq->dev, dma))
			goto dma_map_err;

		memset(sglist, 0, OCTEP_SGLIST_SIZE_PER_PKT);
		sglist[0].len[3] = len;
		sglist[0].dma_ptr[0] = dma;

		si = 1; /* entry 0 is main skb, mapped above */
		frag = &shinfo->frags[0];
		while (nr_frags--) {
			len = skb_frag_size(frag);
			dma = skb_frag_dma_map(iq->dev, frag, 0, len, DMA_TO_DEVICE);
			if (dma_mapping_error(iq->dev, dma))
				goto dma_map_sg_err;

			sglist[si >> 2].len[3 - (si & 3)] = len;
			sglist[si >> 2].dma_ptr[si & 3] = dma;

			frag++;
			si++;
		}
		hw_desc->dptr = tx_buffer->sglist_dma;
	}

	if (octep_dev->conf->fw_info.tx_ol_flags) {
		if ((feat & (NETIF_F_TSO)) && (skb_is_gso(skb))) {
			hw_desc->txm.ol_flags = OCTEP_TX_OFFLOAD_CKSUM;
			hw_desc->txm.ol_flags |= OCTEP_TX_OFFLOAD_TSO;
			hw_desc->txm.gso_size = skb_shinfo(skb)->gso_size;
			hw_desc->txm.gso_segs = skb_shinfo(skb)->gso_segs;
		} else if (feat & (NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM)) {
			hw_desc->txm.ol_flags = OCTEP_TX_OFFLOAD_CKSUM;
		}
		/* due to ESR txm will be swapped by hw */
		hw_desc->txm64[0] = cpu_to_be64(hw_desc->txm64[0]);
	}

	netdev_tx_sent_queue(iq->netdev_q, skb->len);

	xmit_more = netdev_xmit_more();

	skb_tx_timestamp(skb);
	iq->fill_cnt++;
	wi++;
	iq->host_write_index = wi & iq->ring_size_mask;
	if (xmit_more && (IQ_INSTR_PENDING(iq) < (iq->max_count - OCTEP_WAKE_QUEUE_THRESHOLD)) &&
	    iq->fill_cnt < iq->fill_threshold)
		return NETDEV_TX_OK;

	/* Flush the hw descriptors before writing to doorbell */
	smp_wmb();
	writel(iq->fill_cnt, iq->doorbell_reg);
	iq->stats.instr_posted += iq->fill_cnt;
	iq->fill_cnt = 0;
	dev_dbg(&octep_dev->pdev->dev,
		"TxQ-%d: Doorbell write %d iq->fill_cnt %d wi %d iq->ring_size_mask %x\n", q_no,
		iq->host_write_index, iq->fill_cnt, wi, iq->ring_size_mask);
	return NETDEV_TX_OK;

dma_map_sg_err:
	if (si > 0) {
		dma_unmap_single(iq->dev, sglist[0].dma_ptr[0], sglist[0].len[3], DMA_TO_DEVICE);
		sglist[0].len[0] = 0;
	}
	while (si > 1) {
		dma_unmap_page(iq->dev, sglist[si >> 2].dma_ptr[si & 3],
			       sglist[si >> 2].len[si & 3], DMA_TO_DEVICE);
		sglist[si >> 2].len[si & 3] = 0;
		si--;
	}
	tx_buffer->gather = 0;
dma_map_err:
	dev_kfree_skb_any(skb);
	return NETDEV_TX_OK;
}

static int
__octep_oq_process_rx(struct octep_sdp_dev *octep_dev, struct octep_oq *oq, u16 pkts_to_process)
{
	struct octep_oq_resp_hw_ext *resp_hw_ext = NULL;
	netdev_features_t feat = oq->netdev->features;
	struct octep_rx_buffer *buff_info;
	struct octep_oq_resp_hw *resp_hw;
	u32 pkt, rx_bytes, desc_used;
	u16 data_offset, rx_ol_flags;
	struct sk_buff *skb;
	struct page *page;
	u32 read_idx, i;

	read_idx = READ_ONCE(oq->host_read_idx);
	rx_bytes = 0;
	desc_used = 0;
	for (pkt = 0; pkt < pkts_to_process; pkt++) {
		buff_info = (struct octep_rx_buffer *)&oq->buff_info[read_idx];
		page = buff_info->page;
		dma_unmap_page(oq->dev, oq->desc_ring[read_idx].buffer_ptr, PAGE_SIZE,
			       DMA_FROM_DEVICE);
		resp_hw = page_address(buff_info->page);
		/* Memory Barrier */
		smp_rmb();

		if (unlikely(*((volatile uint64_t *)&resp_hw->length) == 0)) {
			int retry = 100;

			dev_dbg(oq->dev,
				"OQ[%d]: host_read_idx: %d; Data not ready yet, "
				"Retry; pkt=%u, pkt_count=%u, pending=%u\n",
				oq->q_no, oq->host_read_idx, pkt, pkts_to_process,
				oq->pkts_pending);
			oq->stats.pkts_delayed_data++;
			while (retry-- && unlikely(*((volatile uint64_t *)&resp_hw->length) == 0))
				usleep_range(40, 60);
			if (unlikely(!resp_hw->length)) {
				dev_err(oq->dev, "OQ[%d]: ZERO_PKT_LEN pkt:%d SUSPENDED", oq->q_no,
					pkt);
				for (i = 0; i < octep_dev->num_oqs; i++) {
					octep_dev->oq[i]->suspend = true;
					octep_dev->hw_ops.disable_iq(octep_dev, i);
					octep_dev->hw_ops.disable_oq(octep_dev, i);
				}
				oq->desc_ring[read_idx].buffer_ptr =
					dma_map_page(oq->dev, page, 0, PAGE_SIZE, DMA_FROM_DEVICE);
				/* Stop Tx from stack */
				netif_tx_stop_all_queues(octep_dev->netdev);
				netif_carrier_off(octep_dev->netdev);
				netif_tx_disable(octep_dev->netdev);
				return pkt;
			}
		}
		buff_info->page = NULL;

		/* Swap the length field that is in Big-Endian to CPU */
		buff_info->len = be64_to_cpu(resp_hw->length);
		if (octep_dev->conf->fw_info.rx_ol_flags) {
			/* Extended response header is immediately after
			 * response header (resp_hw)
			 */
			resp_hw_ext = (struct octep_oq_resp_hw_ext *)(resp_hw + 1);
			buff_info->len -= OCTEP_OQ_RESP_HW_EXT_SIZE;
			/* Packet Data is immediately after
			 * extended response header.
			 */
			data_offset = OCTEP_OQ_RESP_HW_SIZE + OCTEP_OQ_RESP_HW_EXT_SIZE;
			rx_ol_flags = resp_hw_ext->rx_ol_flags;
		} else {
			/* Data is immediately after
			 * Hardware Rx response header.
			 */
			data_offset = OCTEP_OQ_RESP_HW_SIZE;
			rx_ol_flags = 0;
		}
		rx_bytes += buff_info->len;

		if (buff_info->len <= oq->max_single_buffer_size) {
			skb = build_skb((void *)resp_hw, PAGE_SIZE);
			skb_reserve(skb, data_offset);
			skb_put(skb, buff_info->len);
			read_idx++;
			desc_used++;
			if (read_idx == oq->max_count)
				read_idx = 0;
		} else {
			struct skb_shared_info *shinfo;
			u16 data_len;

			skb = build_skb((void *)resp_hw, PAGE_SIZE);
			skb_reserve(skb, data_offset);
			/* Head fragment includes response header(s);
			 * subsequent fragments contains only data.
			 */
			skb_put(skb, oq->max_single_buffer_size);
			read_idx++;
			desc_used++;
			if (read_idx == oq->max_count)
				read_idx = 0;

			shinfo = skb_shinfo(skb);
			data_len = buff_info->len - oq->max_single_buffer_size;
			while (data_len) {
				dma_unmap_page(oq->dev, oq->desc_ring[read_idx].buffer_ptr,
					       PAGE_SIZE, DMA_FROM_DEVICE);
				buff_info = (struct octep_rx_buffer *)&oq->buff_info[read_idx];
				if (data_len < oq->buffer_size) {
					buff_info->len = data_len;
					data_len = 0;
				} else {
					buff_info->len = oq->buffer_size;
					data_len -= oq->buffer_size;
				}

				skb_add_rx_frag(skb, shinfo->nr_frags, buff_info->page, 0,
						buff_info->len, buff_info->len);
				buff_info->page = NULL;
				read_idx++;
				desc_used++;
				if (read_idx == oq->max_count)
					read_idx = 0;
			}
		}
		skb->dev = oq->netdev;
		skb->protocol = eth_type_trans(skb, skb->dev);
		if (feat & NETIF_F_RXCSUM && OCTEP_RX_CSUM_VERIFIED(rx_ol_flags))
			skb->ip_summed = CHECKSUM_UNNECESSARY;
		else
			skb->ip_summed = CHECKSUM_NONE;
		napi_gro_receive(oq->napi, skb);
	}

	WRITE_ONCE(oq->host_read_idx, read_idx);
	oq->refill_count += desc_used;
	oq->stats.packets += pkt;
	oq->stats.bytes += rx_bytes;
	dev_dbg(oq->dev, "________ OQ-%d: pkts=%d, bytes=%d\n", oq->q_no, pkt, rx_bytes);

	return pkt;
}

int
octep_oq_check_hw_for_pkts(struct octep_sdp_dev *octep_dev, struct octep_oq *oq)
{
	u32 pkt_count, new_pkts;
	u32 last_pkt_count, pkts_pending;

	pkt_count = readl(oq->pkts_sent_reg);
	if (unlikely(pkt_count == 0xFFFFFFFF)) {
		writel(pkt_count, oq->pkts_sent_reg);
		pkt_count = 0;
		dev_err_ratelimited(oq->dev, "OQ-%u count read failure\n", oq->q_no);
		return 0;
	}
	last_pkt_count = READ_ONCE(oq->last_pkt_count);
	new_pkts = pkt_count - last_pkt_count;

	if (pkt_count < last_pkt_count) {
		dev_err(oq->dev, "OQ-%u pkt_count(%u) < oq->last_pkt_count(%u)\n", oq->q_no,
			pkt_count, last_pkt_count);
	}

	/* Clear the hardware packets counter register if the rx queue is
	 * being processed continuously with-in a single interrupt and
	 * reached half its max value.
	 * this counter is not cleared every time read, to save write cycles.
	 */
	if (unlikely(pkt_count > 0xF0000000U)) {
		writel(pkt_count, oq->pkts_sent_reg);
		pkt_count = readl(oq->pkts_sent_reg);
		if (unlikely(pkt_count == 0xFFFFFFFF)) {
			pkt_count = 0;
			dev_err_ratelimited(oq->dev, "OQ-%u count readback failure\n", oq->q_no);
		}
		new_pkts += pkt_count;
	}
	WRITE_ONCE(oq->last_pkt_count, pkt_count);
	pkts_pending = READ_ONCE(oq->pkts_pending);
	WRITE_ONCE(oq->pkts_pending, (pkts_pending + new_pkts));
	return new_pkts;
}

int
octep_oq_refill(struct octep_sdp_dev *octep_dev, struct octep_oq *oq)
{
	struct octep_oq_desc_hw *desc_ring = oq->desc_ring;
	struct octep_oq_resp_hw *resp_hw;
	struct page *page;
	u32 refill_idx, i;

	refill_idx = oq->host_refill_idx;
	for (i = 0; i < oq->refill_count; i++) {
		page = dev_alloc_page();
		if (unlikely(!page)) {
			dev_err(oq->dev, "refill: rx buffer alloc failed\n");
			oq->stats.alloc_failures++;
			break;
		}
		resp_hw = page_address(page);
		resp_hw->length = 0x0;

		desc_ring[refill_idx].buffer_ptr =
			dma_map_page(oq->dev, page, 0, PAGE_SIZE, DMA_FROM_DEVICE);
		if (dma_mapping_error(oq->dev, desc_ring[refill_idx].buffer_ptr)) {
			dev_err(oq->dev, "OQ-%d buffer refill: DMA mapping error!\n", oq->q_no);
			put_page(page);
			oq->stats.alloc_failures++;
			break;
		}
		oq->buff_info[refill_idx].page = page;
		refill_idx++;
		if (refill_idx == oq->max_count)
			refill_idx = 0;
	}
	oq->host_refill_idx = refill_idx;
	oq->refill_count -= i;

	return i;
}

int
octep_oq_process_rx(struct octep_oq *oq, int budget)
{
	u32 pkts_available, pkts_processed, total_pkts_processed;
	struct octep_sdp_dev *octep_dev = oq->octep_dev;
	u32 pkts_pending;

	pkts_available = 0;
	pkts_processed = 0;
	total_pkts_processed = 0;
	while (total_pkts_processed < budget) {
		if (oq->suspend)
			return 0;

		/* update pending count only when current one exhausted */
		pkts_pending = READ_ONCE(oq->pkts_pending);
		if (pkts_pending == 0)
			octep_oq_check_hw_for_pkts(octep_dev, oq);
		pkts_available = min(budget - total_pkts_processed, oq->pkts_pending);
		if (!pkts_available)
			break;

		pkts_processed = __octep_oq_process_rx(octep_dev, oq, pkts_available);
		pkts_pending = READ_ONCE(oq->pkts_pending);
		WRITE_ONCE(oq->pkts_pending, (pkts_pending - pkts_processed));
		total_pkts_processed += pkts_processed;

		if (oq->suspend)
			return 0;
	}

	if (oq->refill_count >= oq->refill_threshold) {
		u32 desc_refilled = octep_oq_refill(octep_dev, oq);

		/* flush pending writes before updating credits */
		smp_wmb();
		writel(desc_refilled, oq->pkts_credit_reg);
	}

	dev_dbg(oq->dev, "OQ-%u: pkts_processed %u, total_pkts_processed %u\n", oq->q_no,
		pkts_processed, total_pkts_processed);
	return total_pkts_processed;
}

static int
octep_set_mac(struct net_device *netdev, void *p)
{
	struct octep_sdp_dev *octep_dev = netdev_priv(netdev);
	struct sockaddr *addr = (struct sockaddr *)p;

	if (!is_valid_ether_addr(addr->sa_data))
		return -EADDRNOTAVAIL;

	memcpy(octep_dev->mac_addr, addr->sa_data, ETH_ALEN);
#if defined(USE_ETHER_ADDR_COPY)
	ether_addr_copy(netdev->dev_addr, addr->sa_data);
#else
	eth_hw_addr_set(netdev, addr->sa_data);
#endif

	return 0;
}

static int
octep_change_mtu(struct net_device *netdev, int new_mtu)
{
	int err = 0;

	/* FIXME : TBD */
	if (netdev->mtu == new_mtu)
		return 0;

	netdev->mtu = new_mtu;

	return err;
}

static const struct net_device_ops octep_netdev_ops = {
	.ndo_open = octep_open,
	.ndo_stop = octep_stop,
	.ndo_start_xmit = octep_start_xmit,
	.ndo_get_stats64 = octep_get_stats64,
	.ndo_set_mac_address = octep_set_mac,
	.ndo_change_mtu = octep_change_mtu,
};

int
octep_rdma_probe_dev(struct octep_sdp_dev *octep_dev)
{
	struct net_device *netdev = octep_dev->netdev;
	int err;

	/* Do not free resources on failure. driver unload will
	 * lead to freeing resources.
	 */
	err = octep_sdp_dev_setup(octep_dev);
	if (err) {
		dev_err(&octep_dev->pdev->dev, "Device setup failed\n");
		return -1;
	}

	netdev->netdev_ops = &octep_netdev_ops;
	netif_carrier_off(netdev);

	if (octep_vf_setup_mbox(octep_dev)) {
		dev_err(&octep_dev->pdev->dev, "VF Mailbox setup failed\n");
		err = -ENOMEM;
		//Todo - Add cleanups for this API
		return -1;
	}

	if (octep_vf_mbox_version_check(octep_dev)) {
		dev_err(&octep_dev->pdev->dev, "PF VF Mailbox version mismatch\n");
		err = -EINVAL;
		return -1;
	}

	netdev->hw_features = NETIF_F_SG;
	if (OCTEP_TX_IP_CSUM(octep_dev->conf->fw_info.tx_ol_flags))
		netdev->hw_features |= (NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM);

	if (OCTEP_RX_IP_CSUM(octep_dev->conf->fw_info.rx_ol_flags))
		netdev->hw_features |= NETIF_F_RXCSUM;

	/* FIXME : MTU from octeon ??*/
	netdev->min_mtu = OCTEP_MIN_MTU;
	netdev->max_mtu = OCTEP_MAX_MTU - (ETH_HLEN + ETH_FCS_LEN);
	netdev->mtu = OCTEP_DEFAULT_MTU;

	netdev->features |= netdev->hw_features;

	eth_hw_addr_set(netdev, octep_dev->mac_addr);
	dev_info(&octep_dev->pdev->dev, "MAC address: %pM\n", netdev->dev_addr);

	err = register_netdev(netdev);
	if (err) {
		dev_err(&octep_dev->pdev->dev, "Failed to register netdev\n");
		return -1;
	}
	dev_info(&octep_dev->pdev->dev, "Device setup successful\n");

	clear_bit(OCTEP_DEV_STATE_OPEN, &octep_dev->state);

	INIT_DELAYED_WORK(&octep_dev->vf_hb_task, octep_vf_hb_timeout_task);
	queue_delayed_work(octep_wq, &octep_dev->vf_hb_task,
			   msecs_to_jiffies(OCTEP_DEFAULT_VF_HB_INTERVAL));

	return 0;
}

void octep_device_cleanup(struct octep_sdp_dev *octep_dev)
{
	int i;

	dev_info(&octep_dev->pdev->dev, "Cleaning up Octeon Device ...\n");
	for (i = 0; i < OCTEP_MMIO_REGIONS; i++) {
		if (octep_dev->mmio[i].mapped)
			iounmap(octep_dev->mmio[i].hw_addr);
	}

	kfree(octep_dev->conf);
	octep_dev->conf = NULL;
}
