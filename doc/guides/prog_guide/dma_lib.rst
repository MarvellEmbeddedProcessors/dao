..  SPDX-License-Identifier: Marvell-MIT
    Copyright (c) 2024 Marvell.

***********
DMA Library
***********

DMA library provides two different interfaces, an interface to access configuration and
fetch descriptors called control DMA. Another one to send receive packets from host to
Octeon target. Atleast one DMA device reserved for control path.

Initialization
~~~~~~~~~~~~~~

Control path DMA devices can access using

``dao_dma_ctrl_dev_set``

``dao_dma_ctrl_dev2mem``

``dao_dma_ctrl_mem2dev``

For better performance binding DMA devices per lcore in data path using following APIs

``dao_dma_lcore_dev2mem_set``

``dao_dma_lcore_mem2dev_set``

Packet Processing
~~~~~~~~~~~~~~~~~

Packets enqueued to DMA in vector way using ``dao_dma_enq_x4`` or submit in regular way ``dao_dma_enq_x1``

Platform supports maximum 15 pointer pairs in single DMA request, better utilization we
will submit DMA request in burst mode by enqueuing multiple packets, to flush the DMA
use ``dao_dma_flush``, or use ``dao_dma_flush_submit`` to flush and enqueue new requests.

To get DMA status by index ``dao_dma_op_status``, fetch complete DMA statistics using
``dao_dma_stats_get``.

DMA completion status can be checked using ``dao_dma_check_compl``. Block wait on DMA
completions using ``dao_dma_compl_wait`` used to handle reset request.

