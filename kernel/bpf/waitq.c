// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

#include <linux/bpf.h>
#include <linux/rcupdate_trace.h>
#include <linux/wait.h>

struct bpf_waitq_kern {
	wait_queue_head_t waitq;
	struct rcu_head rcu;
	bool draining;
};

struct bpf_waitq_opaque {
	struct bpf_waitq_kern *waitq;
} __aligned(8);

static void bpf_waitq_free_rcu(struct rcu_head *rcu)
{
	struct bpf_waitq_kern *waitq = container_of(rcu, struct bpf_waitq_kern, rcu);
	unsigned long flags;
	bool free_waitq;

	spin_lock_irqsave(&waitq->waitq.lock, flags);
	waitq->draining = true;
	__wake_up_locked(&waitq->waitq, TASK_NORMAL, 0);
	free_waitq = list_empty(&waitq->waitq.head);
	spin_unlock_irqrestore(&waitq->waitq.lock, flags);

	if (free_waitq)
		kfree(waitq);
}

void bpf_waitq_cancel_and_free(void *val)
{
	struct bpf_waitq_opaque *opaque = val;
	struct bpf_waitq_kern *waitq;

	waitq = xchg(&opaque->waitq, NULL);
	if (waitq)
		call_rcu_tasks_trace(&waitq->rcu, bpf_waitq_free_rcu);
}
