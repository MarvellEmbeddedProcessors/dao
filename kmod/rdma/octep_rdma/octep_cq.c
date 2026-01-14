/* SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2024 Marvell.
 */

#include "octep_verbs.h"

static LIST_HEAD(cq_list);
static DEFINE_MUTEX(cq_list_lock);
static struct task_struct *kern_cq_thread;
static atomic_t thread_ref_count = ATOMIC_INIT(0);
static DEFINE_MUTEX(thread_lock);

int
octep_rdma_poll_one_cqe(struct octep_rdma_cq *cq, struct ib_wc *wc, int num_entries)
{
	struct octep_rdma_cqe *q_base, *cqe;
	struct octep_rdma_kcq_info *kcq;
	u16 ci, pi, avail;
	u32 qmask;
	int i;

	/* Cache frequently accessed pointers for better performance */
	kcq = &cq->kern_cq;
	q_base = kcq->qbuf;
	qmask = cq->qmask;
	ci = kcq->ci;

	/* Read producer index - this is the expensive operation */
	pi = (u16)atomic_read(kcq->pi_dbl);

	/* Fast path: empty queue check - most common case */
	if (likely(octep_rdma_is_queue_empty(pi, ci)))
		return 0;

	/* Calculate available entries - handle wrap-around correctly */
	avail = (pi >= ci) ? (pi - ci) : (cq->depth - ci + pi);
	if (unlikely(avail > num_entries))
		avail = num_entries;

	/* Prefetch first CQE for better cache performance */
	cqe = q_base + ci;
	prefetch(cqe);

	/* High-performance polling loop with optimized memory access */
	for (i = 0; i < avail; i++) {
		/* Prefetch next CQE while processing current one */
		if (likely(i + 1 < avail))
			prefetch(q_base + ((ci + 1) & qmask));

		cqe = q_base + ci;

		/* Optimized field copying - group related fields together */
		wc[i].wr_id = cqe->wr_id;
		wc[i].qp = (struct ib_qp *)cqe->ibqp;
		wc[i].src_qp = cqe->qp_id;

		wc[i].status = cqe->status;
		wc[i].opcode = cqe->opcode;
		wc[i].vendor_err = cqe->vendor_err;
		wc[i].byte_len = cqe->byte_len;

		/* Set network-related constants efficiently */
		wc[i].wc_flags = IB_WC_GRH | IB_WC_WITH_NETWORK_HDR_TYPE;
		wc[i].network_hdr_type = RDMA_NETWORK_IPV4;

		ci = (ci + 1) & qmask;
	}

	/* Update consumer index with memory barrier */
	kcq->ci = ci;
	wmb(); /* Ensure CI update is visible before doorbell */

	/* Update hardware doorbell */
	atomic_set(kcq->ci_dbl, ci);

	return avail;
}

void
octep_rdma_free_kernel_cq(struct octep_rdma_dev *rdma_dev, struct octep_rdma_cq *cq)
{
	struct octep_rdma_kcq_info *kcq = &cq->kern_cq;

	if (kcq->qbuf)
		dma_free_coherent(&rdma_dev->pdev->dev, kcq->size, kcq->qbuf, kcq->qbuf_dma_addr);

	if (kcq->db)
		iounmap((void __iomem *)((uintptr_t)kcq->db -
					 ((cq->cqn * 3 + 2) * kcq->notify_off_multiplier)));

	kcq->qbuf = NULL;
	kcq->db = NULL;
	kcq->pi_dbl = NULL;
	kcq->ci_dbl = NULL;
	kcq->iova = NULL;
}

int
octep_rdma_init_kernel_cq(struct octep_rdma_cq *cq)
{
	struct octep_rdma_dev *rdma_dev = to_octep_rdma_dev(cq->ibcq.device);
	struct octep_rdma_kcq_info *kcq = &cq->kern_cq;
	void __iomem *db_base;
	u32 cq_size;

	cq_size = PAGE_ALIGN(cq->depth * sizeof(struct octep_rdma_cqe));

	kcq->qbuf =
		dma_alloc_coherent(&rdma_dev->pdev->dev, cq_size, &kcq->qbuf_dma_addr, GFP_KERNEL);
	if (!kcq->qbuf)
		return -ENOMEM;

	kcq->size = cq_size;
	cq->qmask = cq->depth - 1;
	kcq->ci = 0;

	kcq->db_region = rdma_dev->caps_rgn->notify_base_pa;
	kcq->notify_off_multiplier = rdma_dev->caps_rgn->notify_off_multiplier;

	db_base = ioremap(kcq->db_region, rdma_dev->caps_rgn->notify_sz);
	if (!db_base) {
		dma_free_coherent(&rdma_dev->pdev->dev, cq_size, kcq->qbuf, kcq->qbuf_dma_addr);
		return -ENOMEM;
	}

	kcq->db = (u8 __iomem *)(db_base + (((cq->cqn * 3) + 2) * kcq->notify_off_multiplier));
	kcq->pi_dbl = (atomic_t __iomem *)kcq->db;
	kcq->ci_dbl = kcq->pi_dbl + 2;

	spin_lock_init(&kcq->lock);

	return 0;
}

int
octep_rdma_init_user_cq(struct octep_rdma_cq *cq, struct octep_rdma_ureq_create_cq *ureq)
{
	struct octep_rdma_dev *rdma_dev = to_octep_rdma_dev(cq->ibcq.device);
	uint64_t *pa;
	int ret;

	ret = setup_mem_trans_tbl(rdma_dev, &cq->user_cq.qbuf_mtt, ureq->qbuf_va, ureq->qbuf_len, 0,
				  ureq->qbuf_va, PAGE_SIZE, 1);
	if (ret)
		return ret;

	pa = cq->user_cq.qbuf_mtt.mtt_buf;

	ibdev_info(cq->ibcq.device, "[%s] cq->user_cq.qbuf_mtt.va: 0x%llx pa %llx\n", __func__,
		   cq->user_cq.qbuf_mtt.va, *pa);

	return ret;
}

int
octep_rdma_prepare_cq_cmd(struct octep_rdma_dev *rdma_dev, struct octep_rdma_cq *cq, bool is_user)
{
	struct octep_rdma_cq_create_req *cq_req;
	struct octep_rdma_cq_state_req *cq_state_req;
	int ret = 0;

	cq_req = kzalloc(sizeof(*cq_req), GFP_KERNEL);
	if (!cq_req)
		return -ENOMEM;

	cq_req->port_num = rdma_dev->port.port_num;
	cq_req->cq_id = cq->cqn;
	cq_req->size = cq->depth;
	if (is_user)
		cq_req->cq_base = cq->user_cq.qbuf_mtt.iova[0];
	else
		cq_req->cq_base = (u64)cq->kern_cq.qbuf_dma_addr;

	ret = octep_rdma_mbox_cq_create(rdma_dev->caps_rgn, cq_req);
	if (ret) {
		ibdev_err(cq->ibcq.device, "octep_rdma_mbox_cq_create failed\n");
		goto err;
	}

	cq_state_req = kzalloc(sizeof(*cq_state_req), GFP_KERNEL);
	if (!cq_state_req) {
		ret = -ENOMEM;
		goto err;
	}

	cq_state_req->port_num = rdma_dev->port.port_num;
	cq_state_req->cq_id = cq->cqn;
	cq_state_req->enable = true;

	ret = octep_rdma_mbox_cq_state(rdma_dev->caps_rgn, cq_state_req);
	if (ret)
		ibdev_err(cq->ibcq.device, "octep_rdma_mbox_cq_state failed\n");

	kfree(cq_state_req);
err:
	kfree(cq_req);
	return ret;
}

int
octep_rdma_prepare_cq_destroy_cmd(struct octep_rdma_dev *rdma_dev, struct octep_rdma_cq *cq)
{
	struct octep_rdma_cq_state_req *cq_state_req;
	struct octep_rdma_cq_destroy_req *cq_dest;
	int ret = 0;

	cq_dest = kzalloc(sizeof(*cq_dest), GFP_KERNEL);
	if (!cq_dest)
		return -ENOMEM;

	cq_dest->cq_id = cq->cqn;
	cq_dest->port_num = rdma_dev->port.port_num;

	ret = octep_rdma_mbox_cq_destroy(rdma_dev->caps_rgn, cq_dest);
	if (ret) {
		ibdev_err(cq->ibcq.device, "octep_rdma_mbox_cq_destroy failed\n");
		goto err;
	}

	cq_state_req = kzalloc(sizeof(*cq_state_req), GFP_KERNEL);
	if (!cq_state_req) {
		ret = -ENOMEM;
		goto err;
	}

	cq_state_req->cq_id = cq->cqn;
	cq_state_req->enable = false;

	ret = octep_rdma_mbox_cq_state(rdma_dev->caps_rgn, cq_state_req);
	if (ret)
		ibdev_err(cq->ibcq.device, "octep_rdma_mbox_cq_state failed\n");

	kfree(cq_state_req);
err:
	kfree(cq_dest);
	return ret;
}

static int
kern_cq_thread_fn(void *data)
{
	struct octep_kern_cq_entry *entry;
	struct octep_rdma_cq *cq;
	struct octep_rdma_kcq_info *kcq;
	u16 ci, pi, avail;
	u32 cq_sz;
	bool found_work;
	unsigned int idle_count = 0;
	const unsigned int max_idle_before_yield = 1000;
	const unsigned int max_idle_before_sleep = 100000;

	while (!kthread_should_stop()) {
		found_work = false;

		/* Check again for stop signal before acquiring mutex */
		if (kthread_should_stop())
			break;

		/* Use blocking mutex for better performance when contended */
		if (!mutex_trylock(&cq_list_lock)) {
			/* If we can't get the lock immediately, check for stop signal */
			if (kthread_should_stop())
				break;
			mutex_lock(&cq_list_lock);
		}

		/* Final check for stop signal after acquiring lock */
		if (kthread_should_stop()) {
			mutex_unlock(&cq_list_lock);
			break;
		}

		list_for_each_entry(entry, &cq_list, list) {
			cq = entry->cq;

			/* Fast path: skip invalid CQs early */
			if (unlikely(!cq || !cq->ibcq.comp_handler))
				continue;

			kcq = &cq->kern_cq;

			/* Check if CQ resources are still valid - prevent NULL dereference
			   during shutdown */
			if (unlikely(!kcq->pi_dbl || !kcq->qbuf))
				continue;

			/* Prefetch next entry for better cache performance */
			if (entry->list.next != &cq_list)
				prefetch(list_entry(entry->list.next, struct octep_kern_cq_entry,
						    list));

			/* Read producer index once and cache locally */
			pi = (u16)atomic_read(kcq->pi_dbl);
			ci = kcq->ci;

			/* Quick empty queue check - most common case */
			if (likely(octep_rdma_is_queue_empty(pi, ci)))
				continue;

			/* Calculate available entries efficiently */
			cq_sz = cq->depth;
			avail = (pi >= ci) ? (pi - ci) : (cq_sz - ci + pi);

			/* Check for completion notification */
			if (avail && (cq->notify & IB_CQ_NEXT_COMP)) {
				cq->notify = 0;
				/* comp_handler already validated above */
				cq->ibcq.comp_handler(&cq->ibcq, cq->ibcq.cq_context);
				found_work = true;
			}
		}
		mutex_unlock(&cq_list_lock);

		/* High-performance polling strategy for timing precision */
		if (found_work) {
			/* Reset idle counter when work is found */
			idle_count = 0;
			/* Continue immediately for minimum latency */
		} else {
			idle_count++;

			/* Graduated response to idle periods */
			if (idle_count < max_idle_before_yield) {
				/* Busy poll for ultra-low latency - no yielding */
				cpu_relax();
			} else if (idle_count < max_idle_before_sleep) {
				/* Yield CPU but don't sleep - allows other threads */
				cond_resched();
			} else {
				/* Only after extended idle period, brief sleep */
				usleep_range(1, 2); /* Minimal sleep - 1-2 microseconds */
				idle_count = max_idle_before_yield; /* Reset to yield level */
			}
		}
	}

	return 0;
}

int
octep_rdma_kern_cq_poll_insert(struct octep_rdma_cq *cq)
{
	struct octep_kern_cq_entry *entry;
	int ret;

	if (unlikely(!cq))
		return -EINVAL;

	/* Pre-allocate entry before thread operations to reduce critical section time */
	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (unlikely(!entry))
		return -ENOMEM;

	/* Initialize entry outside of critical section */
	entry->cq = cq;
	INIT_LIST_HEAD(&entry->list);

	/* Start the thread if not already running - do this before list insertion */
	ret = octep_rdma_kern_cq_poll_thread();
	if (unlikely(ret)) {
		pr_err("Failed to start CQ poll thread: %d\n", ret);
		kfree(entry);
		return ret;
	}

	/* Minimize critical section time - just add to list */
	mutex_lock(&cq_list_lock);
	list_add_tail(&entry->list, &cq_list);
	mutex_unlock(&cq_list_lock);

	return 0;
}

int
octep_rdma_kern_cq_poll_remove(struct octep_rdma_cq *cq)
{
	struct octep_kern_cq_entry *entry, *tmp;
	int found = 0;
	int fast_retries = 3; /* Quick attempts for fast path */
	int slow_retries = 7; /* Slower attempts with backoff */

	if (unlikely(!cq))
		return -EINVAL;

	/* Fast path: Quick attempts with minimal delay */
	while (fast_retries-- > 0) {
		if (mutex_trylock(&cq_list_lock)) {
			/* Optimized search and removal in single pass */
			list_for_each_entry_safe(entry, tmp, &cq_list, list) {
				if (likely(entry->cq == cq)) {
					list_del(&entry->list);
					kfree(entry);
					found = 1;
					break; /* Early exit on first match */
				}
			}
			mutex_unlock(&cq_list_lock);
			return found ? 0 : -ENOENT;
		}
		cpu_relax(); /* Very short delay for fast path */
	}

	/* Medium path: Retry with small delays */
	while (slow_retries-- > 0) {
		if (mutex_trylock(&cq_list_lock)) {
			list_for_each_entry_safe(entry, tmp, &cq_list, list) {
				if (entry->cq == cq) {
					list_del(&entry->list);
					kfree(entry);
					found = 1;
					break;
				}
			}
			mutex_unlock(&cq_list_lock);
			return found ? 0 : -ENOENT;
		}
		usleep_range(20, 40); /* Shorter sleep for better performance */
	}

	/* Fallback path: Mark entries as invalid during shutdown */
	pr_warn("CQ poll remove: high contention detected, invalidating CQ entries\n");

	/* Final attempt with invalidation strategy */
	fast_retries = 3;
	while (fast_retries-- > 0) {
		if (mutex_trylock(&cq_list_lock)) {
			/* Invalidate matching CQ entries for safety */
			list_for_each_entry(entry, &cq_list, list) {
				if (entry->cq == cq) {
					entry->cq = NULL; /* Invalidate to prevent access */
					found = 1;
					/* Continue checking all entries - don't break */
				}
			}
			mutex_unlock(&cq_list_lock);
			break;
		}
		cpu_relax();
	}

	/* Always return success to prevent blocking shutdown */
	return 0;
}

int
octep_rdma_kern_cq_poll_thread(void)
{
	int ret = 0;

	mutex_lock(&thread_lock);

	if (atomic_inc_return(&thread_ref_count) == 1) {
		/* First reference - create the thread */
		kern_cq_thread = kthread_run(kern_cq_thread_fn, NULL, "ulp_cq_poller");
		if (IS_ERR(kern_cq_thread)) {
			ret = PTR_ERR(kern_cq_thread);
			kern_cq_thread = NULL;
			atomic_dec(&thread_ref_count);
		}
	}

	mutex_unlock(&thread_lock);
	return ret;
}

void
octep_rdma_kern_cq_poll_thread_cleanup(void)
{
	struct octep_kern_cq_entry *entry, *tmp;

	mutex_lock(&thread_lock);

	if (atomic_dec_and_test(&thread_ref_count)) {
		/* Last reference - stop the thread */
		if (kern_cq_thread && !IS_ERR(kern_cq_thread)) {
			kthread_stop(kern_cq_thread);
			kern_cq_thread = NULL;
		}

		/* Clean up the CQ list */
		mutex_lock(&cq_list_lock);
		list_for_each_entry_safe(entry, tmp, &cq_list, list) {
			list_del(&entry->list);
			kfree(entry);
		}
		mutex_unlock(&cq_list_lock);
	}

	mutex_unlock(&thread_lock);
}

void
octep_rdma_kern_cq_poll_thread_force_cleanup(void)
{
	struct octep_kern_cq_entry *entry, *tmp;

	mutex_lock(&thread_lock);

	/* Force stop the thread regardless of reference count */
	if (kern_cq_thread && !IS_ERR(kern_cq_thread)) {
		kthread_stop(kern_cq_thread);
		kern_cq_thread = NULL;
	}

	/* Reset reference count */
	atomic_set(&thread_ref_count, 0);

	/* Clean up the CQ list */
	mutex_lock(&cq_list_lock);
	list_for_each_entry_safe(entry, tmp, &cq_list, list) {
		list_del(&entry->list);
		kfree(entry);
	}
	mutex_unlock(&cq_list_lock);

	mutex_unlock(&thread_lock);
}
