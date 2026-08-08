// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/cgroup.h>
#include <linux/hrtimer.h>
#include <linux/kthread.h>
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

struct bpf_kthread_kern {
	struct task_struct *task;
	struct bpf_map *map;
	struct bpf_prog *prog;
	struct cgroup *cgrp;
	void *callback_fn;
	void *value;
	struct completion initialized;
	spinlock_t lock;
	struct work_struct stop_work;
	struct rcu_head rcu;
	bool start_requested;
	bool stopping;
};

struct bpf_kthread_opaque {
	struct bpf_kthread_kern *kthread;
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

static void bpf_kthread_free_rcu(struct rcu_head *rcu)
{
	struct bpf_kthread_kern *kthread = container_of(rcu, struct bpf_kthread_kern, rcu);

	bpf_prog_put(kthread->prog);
	kfree(kthread);
}

static int bpf_kthread_stop_one(struct bpf_kthread_kern *kthread)
{
	struct task_struct *task;
	unsigned long flags;
	int ret;

	spin_lock_irqsave(&kthread->lock, flags);
	kthread->stopping = true;
	task = kthread->task;
	spin_unlock_irqrestore(&kthread->lock, flags);

	ret = task ? kthread_stop_put(task) : -ENOENT;

	spin_lock_irqsave(&kthread->lock, flags);
	kthread->task = NULL;
	spin_unlock_irqrestore(&kthread->lock, flags);
#ifdef CONFIG_CGROUPS
	if (kthread->cgrp) {
		cgroup_put(kthread->cgrp);
		kthread->cgrp = NULL;
	}
#endif

	call_rcu_tasks_trace(&kthread->rcu, bpf_kthread_free_rcu);
	return ret;
}

static void bpf_kthread_stop_work(struct work_struct *work)
{
	struct bpf_kthread_kern *kthread = container_of(work, struct bpf_kthread_kern, stop_work);

	bpf_kthread_stop_one(kthread);
}

static void bpf_kthread_begin_stop(struct bpf_kthread_kern *kthread)
{
	struct task_struct *task = NULL;
	unsigned long flags;

	spin_lock_irqsave(&kthread->lock, flags);
	kthread->stopping = true;
	if (kthread->task) {
		task = kthread->task;
		get_task_struct(task);
	}
	spin_unlock_irqrestore(&kthread->lock, flags);

	if (task) {
		wake_up_process(task);
		put_task_struct(task);
	}
}

void bpf_kthread_cancel_and_free(void *val)
{
	struct bpf_kthread_opaque *opaque = val;
	struct bpf_kthread_kern *kthread;

	kthread = xchg(&opaque->kthread, NULL);
	if (!kthread)
		return;

	bpf_kthread_begin_stop(kthread);
	schedule_work(&kthread->stop_work);
}

static int bpf_kthread_run(void *data)
{
	struct bpf_kthread_kern *kthread = data;
	bpf_callback_t callback_fn = READ_ONCE(kthread->callback_fn);
	int ret = 0;

	set_current_state(TASK_UNINTERRUPTIBLE);
	complete(&kthread->initialized);
	while (!READ_ONCE(kthread->start_requested) &&
	       !kthread_should_stop() && !READ_ONCE(kthread->stopping)) {
		schedule();
		set_current_state(TASK_UNINTERRUPTIBLE);
	}
	__set_current_state(TASK_RUNNING);

	while (!kthread_should_stop() && !READ_ONCE(kthread->stopping)) {
		void *key;
		u32 idx;

		rcu_read_lock_trace();
		migrate_disable();
		if (READ_ONCE(kthread->stopping)) {
			migrate_enable();
			rcu_read_unlock_trace();
			break;
		}

		key = bpf_map_key_from_value(kthread->map, kthread->value, &idx);
		ret = (int)callback_fn((u64)(long)kthread->map, (u64)(long)key,
				       (u64)(long)kthread->value, 0, 0);

		migrate_enable();
		rcu_read_unlock_trace();
		if (ret)
			break;
		cond_resched();
	}

	return ret;
}

__bpf_kfunc_start_defs();

__bpf_kfunc int bpf_waitq_init(struct bpf_waitq *waitq, void *p__const_map,
			       unsigned int flags)
{
	struct bpf_waitq_opaque *opaque = (struct bpf_waitq_opaque *)waitq;
	struct bpf_map *map = p__const_map;
	struct bpf_waitq_kern *new_waitq;

	BUILD_BUG_ON(sizeof(struct bpf_waitq_opaque) > sizeof(struct bpf_waitq));
	BUILD_BUG_ON(__alignof__(struct bpf_waitq_opaque) != __alignof__(struct bpf_waitq));

	if (flags)
		return -EINVAL;
	if (READ_ONCE(opaque->waitq))
		return -EBUSY;

	new_waitq = bpf_map_kzalloc(map, sizeof(*new_waitq), GFP_KERNEL | __GFP_NOWARN);
	if (!new_waitq)
		return -ENOMEM;
	init_waitqueue_head(&new_waitq->waitq);

	if (cmpxchg(&opaque->waitq, NULL, new_waitq)) {
		kfree(new_waitq);
		return -EBUSY;
	}

	/*
	 * Order publication against the final map user-reference release. Either
	 * release observes the queue or this side observes a zero user count.
	 */
	smp_mb();
	if (!atomic64_read(&map->usercnt)) {
		bpf_waitq_cancel_and_free(opaque);
		return -EPERM;
	}

	return 0;
}

__bpf_kfunc int bpf_waitq_wait(struct bpf_waitq *waitq, const u32 *word,
			       u32 expected, u64 timeout_ns, u64 flags)
{
	struct bpf_waitq_opaque *opaque = (struct bpf_waitq_opaque *)waitq;
	struct bpf_waitq_kern *waitq_kern;
	wait_queue_entry_t entry;
	unsigned long irq_flags;
	bool free_waitq = false;
	int ret = 0;

	if (flags)
		return -EINVAL;

	waitq_kern = READ_ONCE(opaque->waitq);
	if (!waitq_kern)
		return -EINVAL;

	init_waitqueue_entry(&entry, current);
	entry.flags |= WQ_FLAG_EXCLUSIVE;

	spin_lock_irqsave(&waitq_kern->waitq.lock, irq_flags);
	if (waitq_kern->draining) {
		ret = -ENOENT;
		goto unlock;
	}
	/* Observe the condition update that precedes bpf_waitq_wake(). */
	if (smp_load_acquire(word) != expected) {
		ret = -EAGAIN;
		goto unlock;
	}
	__add_wait_queue_entry_tail(&waitq_kern->waitq, &entry);
	set_current_state(TASK_UNINTERRUPTIBLE);
	spin_unlock_irqrestore(&waitq_kern->waitq.lock, irq_flags);

	migrate_enable();
	rcu_read_unlock_trace();

	if ((current->flags & PF_KTHREAD) && kthread_should_stop()) {
		__set_current_state(TASK_RUNNING);
		ret = -EINTR;
	} else if (timeout_ns == U64_MAX) {
		schedule();
	} else {
		ktime_t expires = ns_to_ktime(timeout_ns);

		if (!schedule_hrtimeout(&expires, HRTIMER_MODE_REL))
			ret = -ETIMEDOUT;
	}
	__set_current_state(TASK_RUNNING);

	spin_lock_irqsave(&waitq_kern->waitq.lock, irq_flags);
	list_del_init(&entry.entry);
	if (waitq_kern->draining && list_empty(&waitq_kern->waitq.head))
		free_waitq = true;
	spin_unlock_irqrestore(&waitq_kern->waitq.lock, irq_flags);

	if (free_waitq)
		kfree(waitq_kern);

	rcu_read_lock_trace();
	migrate_disable();
	return ret;

unlock:
	spin_unlock_irqrestore(&waitq_kern->waitq.lock, irq_flags);
	return ret;
}

__bpf_kfunc int bpf_waitq_wake(struct bpf_waitq *waitq, u32 nr, u64 flags)
{
	struct bpf_waitq_opaque *opaque = (struct bpf_waitq_opaque *)waitq;
	struct bpf_waitq_kern *waitq_kern;
	int nr_exclusive;

	if (flags)
		return -EINVAL;
	if (!nr)
		return 0;

	waitq_kern = READ_ONCE(opaque->waitq);
	if (!waitq_kern)
		return -EINVAL;

	nr_exclusive = nr == U32_MAX ? 0 : min_t(u32, nr, INT_MAX);
	/* Publish BPF-side condition updates before waking a queued waiter. */
	smp_mb();
	return __wake_up(&waitq_kern->waitq, TASK_NORMAL, nr_exclusive, NULL);
}

__bpf_kfunc int bpf_kthread_create(struct bpf_kthread *kthread, void *p__const_map,
				   u64 cgroup_id,
				   int (callback_fn)(void *map, int *key, void *value),
				   struct bpf_prog_aux *aux)
{
	struct bpf_kthread_opaque *opaque = (struct bpf_kthread_opaque *)kthread;
	struct bpf_map *map = p__const_map;
	struct bpf_kthread_kern *new_kthread;
	struct bpf_prog *prog;
	struct task_struct *task;
	struct cgroup *cgrp = NULL;
	int err;

	BUILD_BUG_ON(sizeof(struct bpf_kthread_opaque) > sizeof(struct bpf_kthread));
	BUILD_BUG_ON(__alignof__(struct bpf_kthread_opaque) != __alignof__(struct bpf_kthread));

	if (READ_ONCE(opaque->kthread))
		return -EBUSY;

	prog = bpf_prog_inc_not_zero(aux->prog);
	if (IS_ERR(prog))
		return PTR_ERR(prog);

	new_kthread = bpf_map_kzalloc(map, sizeof(*new_kthread), GFP_KERNEL | __GFP_NOWARN);
	if (!new_kthread) {
		bpf_prog_put(prog);
		return -ENOMEM;
	}

	new_kthread->map = map;
	new_kthread->prog = prog;
	new_kthread->callback_fn = callback_fn;
	new_kthread->value = (void *)opaque - map->record->kthread_off;
	init_completion(&new_kthread->initialized);
	spin_lock_init(&new_kthread->lock);
	INIT_WORK(&new_kthread->stop_work, bpf_kthread_stop_work);

	if (cgroup_id) {
#ifdef CONFIG_CGROUPS
		cgrp = cgroup_get_from_id(cgroup_id);
		if (IS_ERR(cgrp)) {
			err = PTR_ERR(cgrp);
			goto free_kthread;
		}
		new_kthread->cgrp = cgrp;
#else
		err = -EOPNOTSUPP;
		goto free_kthread;
#endif
	}

	task = kthread_create(bpf_kthread_run, new_kthread, "bpf_kthread/%u", map->id);
	if (IS_ERR(task)) {
		err = PTR_ERR(task);
		goto put_cgroup;
	}
	get_task_struct(task);
	new_kthread->task = task;
	if (cgrp) {
		wake_up_process(task);
		wait_for_completion(&new_kthread->initialized);
		err = cgroup_kthread_attach(cgrp, task);
		if (err)
			goto stop_task;
	}

	if (cmpxchg(&opaque->kthread, NULL, new_kthread)) {
		err = -EBUSY;
		goto stop_task;
	}

	/*
	 * Order publication against the final map user-reference release. Either
	 * release observes the kthread or this side observes a zero user count.
	 */
	smp_mb();
	if (!atomic64_read(&map->usercnt)) {
		bpf_kthread_cancel_and_free(opaque);
		return -EPERM;
	}

	return 0;

stop_task:
	kthread_stop_put(task);
put_cgroup:
	if (cgrp)
		cgroup_put(cgrp);
free_kthread:
	bpf_prog_put(prog);
	kfree(new_kthread);
	return err;
}

__bpf_kfunc int bpf_kthread_start(struct bpf_kthread *kthread, u64 flags)
{
	struct bpf_kthread_opaque *opaque = (struct bpf_kthread_opaque *)kthread;
	struct bpf_kthread_kern *kthread_kern;
	struct task_struct *task = NULL;
	unsigned long irq_flags;

	if (flags)
		return -EINVAL;

	kthread_kern = READ_ONCE(opaque->kthread);
	if (!kthread_kern)
		return -EINVAL;

	spin_lock_irqsave(&kthread_kern->lock, irq_flags);
	if (!kthread_kern->stopping && kthread_kern->task) {
		kthread_kern->start_requested = true;
		task = kthread_kern->task;
		get_task_struct(task);
	}
	spin_unlock_irqrestore(&kthread_kern->lock, irq_flags);
	if (!task)
		return -ENOENT;

	wake_up_process(task);
	put_task_struct(task);
	return 0;
}

__bpf_kfunc int bpf_kthread_stop(struct bpf_kthread *kthread, u64 flags)
{
	struct bpf_kthread_opaque *opaque = (struct bpf_kthread_opaque *)kthread;
	struct bpf_kthread_kern *kthread_kern;
	unsigned long irq_flags;

	if (flags)
		return -EINVAL;

	kthread_kern = READ_ONCE(opaque->kthread);
	if (!kthread_kern)
		return -EINVAL;

	spin_lock_irqsave(&kthread_kern->lock, irq_flags);
	if (kthread_kern->task == current) {
		spin_unlock_irqrestore(&kthread_kern->lock, irq_flags);
		return -EDEADLK;
	}
	spin_unlock_irqrestore(&kthread_kern->lock, irq_flags);

	if (cmpxchg(&opaque->kthread, kthread_kern, NULL) != kthread_kern)
		return -ENOENT;

	bpf_kthread_begin_stop(kthread_kern);
	return bpf_kthread_stop_one(kthread_kern);
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(bpf_waitq_kfunc_ids)
BTF_ID_FLAGS(func, bpf_waitq_init)
BTF_ID_FLAGS(func, bpf_waitq_wait, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_waitq_wake)
BTF_ID_FLAGS(func, bpf_kthread_create, KF_SLEEPABLE | KF_IMPLICIT_ARGS)
BTF_ID_FLAGS(func, bpf_kthread_start)
BTF_ID_FLAGS(func, bpf_kthread_stop, KF_SLEEPABLE)
BTF_KFUNCS_END(bpf_waitq_kfunc_ids)

static const struct btf_kfunc_id_set bpf_waitq_kfunc_set = {
	.owner = THIS_MODULE,
	.set = &bpf_waitq_kfunc_ids,
};

static int __init bpf_waitq_kfunc_init(void)
{
	return register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL, &bpf_waitq_kfunc_set);
}
late_initcall(bpf_waitq_kfunc_init);
