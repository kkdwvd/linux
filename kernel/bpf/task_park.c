// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/cpuhotplug.h>
#include <linux/filter.h>
#include <linux/hrtimer.h>
#include <linux/irq_work.h>
#include <linux/kthread.h>
#include <linux/rcupdate_trace.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/sched/wake_q.h>

/*
 * A BPF program that blocks for an event keeps its own queue of waiters and
 * its own notion of when the event has arrived. The kernel contributes two
 * operations over the task: bpf_task_park() puts the current task to sleep
 * and bpf_task_wake() makes a task runnable. The only shared state is one
 * word in the task, bpf_wake_pending, which lets the program check its
 * condition outside the kernel without losing a wake that lands between
 * the check and the sleep: the waker sets the word before it wakes the
 * task, and a park that finds it set returns instead of sleeping.
 *
 * The word also carries the ordering the program relies on. A waker
 * publishes its condition and then calls bpf_task_wake(); a waiter reads
 * the condition, finds it unmet, calls bpf_task_park(), and reads the
 * condition again after the return. The second read must see the waker's
 * condition whenever the park returned because of that wake, so the store
 * of the word and the load that consumes it are both an xchg(): the store
 * is fully ordered after the waker's condition stores, the load before the
 * waiter's later condition loads. A release would not do for the store. Of
 * two wakers' stores one overwrites the other, the waiter observes only the
 * later one, and nothing would order the earlier waker's condition before
 * the waiter's read of it. The xchg() also makes the consume atomic: a wake
 * that lands between the waiter's observation of the word and its reset is
 * not erased but stays pending for the next park.
 */

/*
 * A wake asked for with IRQs disabled cannot be issued there: the caller may
 * have interrupted the scheduler with the task's pi_lock or a runqueue lock
 * held, or may run in NMI context, where try_to_wake_up() may take neither.
 * Such wakes are queued on the CPU and issued from irq_work once IRQs are
 * enabled again.
 *
 * The queue goes through a node of its own in the task, under the rule the
 * scheduler's wake queues follow for theirs: a task is on at most one queue,
 * whoever claimed the node wakes the task, and a waker that finds it claimed
 * leaves the wake to the claimant. The pending word is set before the claim
 * is tried, so a wake left this way still reaches a parked task through the
 * claimant's wake, and any other task through its next park.
 *
 * The task's wake_q node would save the field, but whoever claims that node
 * may turn away a futex, rwsem or semaphore wakeup that then relies on the
 * claimant, and so has to wake with TASK_NORMAL. A program could then aim a
 * wake of an uninterruptible sleep at any task it names, and not every such
 * sleep has a loop around it: a new kthread sleeps once until its creator
 * wakes it. With its own node the drain wakes interruptible sleeps only, as
 * the direct wake does.
 *
 * The queue is a stack with a per-CPU head: pushed with cmpxchg() from
 * whatever context asks, emptied with one xchg() by the irq_work, so a push
 * that interrupts the drain lands on an empty stack and queues the work
 * again.
 *
 * A queued task is pinned through rcu_users, the count bpf_task_acquire()
 * takes, and for its reason: the pointer a program passes need not come with
 * a count to add to. The task may be one whose fork is failing, which is
 * freed without a look at its usage count, or one past its last schedule.
 * Neither can be asleep in a park, so a task whose rcu_users is zero is not
 * queued. The count is dropped by the drain, never by the caller, which may
 * be in NMI context, where the last drop could not call call_rcu().
 *
 * A CPU that is not online does not run its irq_work, and work queued there
 * would stay on its list after the CPU comes back. Its last run on the way
 * down is in smpcfd_dying_cpu(), after the CPU has left the online mask, and
 * code that programs attach to still runs with IRQs disabled after that. A
 * wake asked for on such a CPU goes on its stack without the irq_work. The
 * stack is emptied from another CPU once the CPU is dead, and by the irq_work
 * once it is online again, which also covers a wake asked for before a CPU
 * coming up is marked online.
 */
static DEFINE_PER_CPU(struct wake_q_node *, bpf_task_wake_queue);

static void bpf_task_wake_drain(struct wake_q_node **queue)
{
	struct wake_q_node *node = xchg(queue, NULL);

	while (node) {
		struct task_struct *task = container_of(node, struct task_struct, bpf_wake_node);

		node = node->next == WAKE_Q_TAIL ? NULL : node->next;
		/* The task may be queued again from here on. */
		WRITE_ONCE(task->bpf_wake_node.next, NULL);
		wake_up_state(task, TASK_INTERRUPTIBLE);
		put_task_struct_rcu_user(task);
	}
}

static void bpf_task_wake_deferred(struct irq_work *work)
{
	bpf_task_wake_drain(this_cpu_ptr(&bpf_task_wake_queue));
}

static DEFINE_PER_CPU(struct irq_work, bpf_task_wake_work) =
	IRQ_WORK_INIT_HARD(bpf_task_wake_deferred);

static void bpf_task_wake_defer(struct task_struct *task)
{
	struct wake_q_node *node = &task->bpf_wake_node, *head;

	/*
	 * The claim, as in __wake_q_add(): NULL is free, anything else is
	 * queued. The xchg() that stored the pending word is a full barrier
	 * between that store and the claim, so a claim lost to another holder
	 * is still covered: the holder's wake follows its own reset of the
	 * node, which this claim did not observe, so the task it wakes
	 * observes the word.
	 */
	if (cmpxchg_relaxed(&node->next, NULL, WAKE_Q_TAIL))
		return;
	/*
	 * A task that cannot be pinned is not asleep in a park: give the
	 * claim back. A waker that lost the claim meanwhile loses nothing,
	 * since the word it stored is there for the task's first park.
	 */
	if (!refcount_inc_not_zero(&task->rcu_users)) {
		WRITE_ONCE(node->next, NULL);
		return;
	}
	head = this_cpu_read(bpf_task_wake_queue);
	do {
		WRITE_ONCE(node->next, head ?: WAKE_Q_TAIL);
	} while (!try_cmpxchg(this_cpu_ptr(&bpf_task_wake_queue), &head, node));
	if (likely(cpu_online(smp_processor_id())))
		irq_work_queue(this_cpu_ptr(&bpf_task_wake_work));
}

/* Runs on @cpu, in its hotplug thread. */
static int bpf_task_wake_cpu_online(unsigned int cpu)
{
	irq_work_queue(per_cpu_ptr(&bpf_task_wake_work, cpu));
	return 0;
}

static int bpf_task_wake_cpu_dead(unsigned int cpu)
{
	bpf_task_wake_drain(per_cpu_ptr(&bpf_task_wake_queue, cpu));
	return 0;
}

static int __init bpf_task_wake_init(void)
{
	int ret;

	ret = cpuhp_setup_state(CPUHP_AP_ONLINE_DYN, "bpf/task_wake:online",
				bpf_task_wake_cpu_online, NULL);
	if (ret < 0)
		return ret;
	ret = cpuhp_setup_state_nocalls(CPUHP_BP_PREPARE_DYN, "bpf/task_wake:dead",
					NULL, bpf_task_wake_cpu_dead);
	return ret < 0 ? ret : 0;
}
subsys_initcall(bpf_task_wake_init);

/*
 * What ends a park besides a wake and the timeout: a stop or park request for
 * a kthread, or a signal. Both are checked for every caller, since a kthread
 * that allowed signals has them too, and the kthread checks are false for a
 * user task. The request is reported apart from a signal because nothing
 * clears it while the thread's function runs: every later park fails the same
 * way, so the caller has to return.
 */
static int bpf_task_park_interrupted(void)
{
	if (kthread_should_stop_or_park())
		return -ESHUTDOWN;
	if (signal_pending(current))
		return -EINTR;
	return 0;
}

__bpf_kfunc_start_defs();

/**
 * bpf_task_park - Sleep until bpf_task_wake() is called for the current task
 * @timeout_ns: relative timeout, or U64_MAX for none
 * @flags: must be 0
 * @aux: the calling program, set by the verifier
 *
 * Returns at once if a wake is pending from a bpf_task_wake() that found the
 * task running. Otherwise sleeps interruptibly until a wake, the timeout, a
 * signal, or a stop or park request for a kthread. A wake takes precedence
 * over a timeout or a signal noticed at the same time, since the waker may
 * already have accounted for it, and a return for any of the three consumes
 * the pending wake. A stop or park request takes precedence over all of
 * them, as a kernel thread tests kthread_should_stop() before it looks for
 * work: the call returns -ESHUTDOWN and leaves a pending wake pending. Any
 * return hands control back to the program's own check of its condition, and
 * spurious returns are possible. A @timeout_ns of 0 polls: it reports a stop
 * or park request as -ESHUTDOWN, then a pending wake, a pending signal as
 * -EINTR, and otherwise -ETIMEDOUT, without sleeping.
 *
 * Every call past the argument check leaves the read section the program
 * runs under and lets the task migrate until it returns, whether it sleeps or
 * not, so the program may go on on another CPU after any of them. For the
 * time slice that bounds the program's loops, such a call ends one invocation
 * and begins the next: the slice starts over when the call returns.
 *
 * Return: 0 when a wake was consumed or the sleep ended for no recorded
 * reason, -ETIMEDOUT when the timeout passed, -ESHUTDOWN when a stop or park
 * request for a kthread is pending and -EINTR when a signal is, whether it
 * was found before the sleep or ended it, even if the timeout passed
 * meanwhile, -EINVAL when @flags is not 0. Nothing clears a stop or park
 * request while the thread's function runs, so once a call has returned
 * -ESHUTDOWN, every later one does too.
 */
__bpf_kfunc int bpf_task_park(u64 timeout_ns, u64 flags, struct bpf_prog_aux *aux)
{
	ktime_t expires = min_t(u64, timeout_ns, KTIME_MAX);
	int ret;

	if (flags)
		return -EINVAL;

	/*
	 * Sleepable programs run with migration disabled under a Tasks Trace
	 * RCU read section. Neither may be held across a sleep of unbounded
	 * length: the read section would stall every Tasks Trace grace period
	 * in the system, and a migration-disabled sleeper keeps rq->nr_pinned
	 * raised, which blocks CPU offline in balance_hotplug_wait() and pins
	 * the wakeup to the CPU it slept on.
	 *
	 * Dropping both is correct only where the caller's runner holds the
	 * program, and with it its maps and context, for the whole
	 * invocation, so that the program's own memory needs no grace period,
	 * and where nothing on the run path keeps per-CPU state across the
	 * program. A program that keeps such state itself, a stack in arena, is
	 * refused the call, and one that calls it is kept out of prog arrays,
	 * where the caller of a tail call holds it through this very read
	 * section; the time slice of may_goto, kept per CPU as well, starts
	 * over when the call returns. The verifier confines the call to
	 * such contexts: the main body of a syscall program or of a BPF kthread
	 * and the functions either calls directly, never any other callback,
	 * and never a region that pins the CPU, a lock, a saved IRQ state or an
	 * RCU read section. It also invalidates every pointer the program holds
	 * across the call except its stack, its context, maps it references
	 * directly and the values of its arrays, arena memory and
	 * verifier-tracked references. What remains is that the program may
	 * resume on another CPU, which is part of the contract.
	 *
	 * Both are dropped on every call, also on one that finds a wake or a
	 * signal pending and does not sleep. The verifier treats every call
	 * as a sleep, and a program that polls in a loop ends its read section
	 * at every turn.
	 */
	migrate_enable();
	rcu_read_unlock_trace();

	/*
	 * set_current_state() is a full barrier that pairs with the one in
	 * try_to_wake_up() after the waker's store of bpf_wake_pending:
	 * either this task observes the pending wake below or the waker
	 * observes it sleeping and wakes it. kthread_stop(), kthread_park()
	 * and signal delivery set their flag and wake the task in the same
	 * way, so the same ordering covers them.
	 */
	set_current_state(TASK_INTERRUPTIBLE);
	ret = bpf_task_park_interrupted();
	if (ret || READ_ONCE(current->bpf_wake_pending)) {
		__set_current_state(TASK_RUNNING);
	} else {
		/*
		 * A NULL expiry sleeps without a timer; a zero one returns at
		 * once. schedule_hrtimeout() tells an expiry from an early
		 * return, but not a wake from a signal or a stop or park
		 * request, so read the flags again, as before the sleep. They
		 * win over an expiry that fired at the same time, since they
		 * stay pending and the timeout does not; a wake, consumed
		 * below, wins over a signal and the expiry.
		 */
		if (!schedule_hrtimeout(timeout_ns == U64_MAX ? NULL : &expires, HRTIMER_MODE_REL))
			ret = -ETIMEDOUT;
		ret = bpf_task_park_interrupted() ?: ret;
	}

	rcu_read_lock_trace();
	migrate_disable();
	/* For the time slice of may_goto, an invocation begins here. */
	bpf_timed_may_goto_rearm(aux);

	/*
	 * Consume the wake. xchg() is fully ordered, so the condition loads
	 * the program makes after the return see the stores the waker made
	 * before its bpf_task_wake(). A wake that raced with the timeout or
	 * the signal wins: the waker may have accounted for it. A stop or park
	 * request wins over the wake and leaves it pending, the way a kernel
	 * thread's loop tests the stop before it looks for work. The thread is
	 * on its way out, and what it was handed is for its stopper to see to.
	 */
	if (ret != -ESHUTDOWN && xchg(&current->bpf_wake_pending, 0))
		ret = 0;
	return ret;
}

/**
 * bpf_task_wake - Wake a task parked in bpf_task_park()
 * @task: task to wake
 * @flags: must be 0
 *
 * Marks a wake pending for @task and wakes it if it sleeps interruptibly.
 * A task that is not parked keeps the pending wake until its next
 * bpf_task_park(), which then returns at once.
 *
 * The wake takes the task's pi_lock and a runqueue lock, which the kernel
 * code a program runs in or interrupts may already hold, and it may not be
 * issued in NMI context at all. Such code and NMI context both run with IRQs
 * disabled, so a call with IRQs disabled marks the wake pending and queues it
 * for irq_work on the calling CPU, which issues it once IRQs are enabled
 * again. Such a call cannot tell whether the task was asleep and returns 2.
 *
 * The irq_work issues the wake through try_to_wake_up(), with IRQs disabled.
 * A program attached to code on that path, such as an fentry program on
 * try_to_wake_up(), runs again from there. If it calls bpf_task_wake() every
 * time it runs, each deferred wake queues the next and the CPU serves little
 * else. Such a program has to tell the wakes it caused from the ones it
 * reacts to.
 *
 * Return: 1 when @task was asleep and is now runnable, 0 when it was not, 2
 * when the wake was deferred, -EINVAL when @flags is not 0.
 */
__bpf_kfunc int bpf_task_wake(struct task_struct *task, u64 flags)
{
	if (flags)
		return -EINVAL;

	/*
	 * xchg() is a full barrier. It orders the program's stores before this
	 * call, its condition, before the word, so a park that consumes the
	 * word sees them, also when what it consumes is another waker's store
	 * that overwrote this one. try_to_wake_up() then orders the store
	 * before its load of the task state, pairing with set_current_state()
	 * in bpf_task_park().
	 */
	xchg(&task->bpf_wake_pending, 1);
	if (unlikely(irqs_disabled())) {
		bpf_task_wake_defer(task);
		return 2;
	}
	return wake_up_state(task, TASK_INTERRUPTIBLE);
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(bpf_task_park_kfunc_ids)
BTF_ID_FLAGS(func, bpf_task_park, KF_SLEEPABLE | KF_IMPLICIT_ARGS)
BTF_KFUNCS_END(bpf_task_park_kfunc_ids)

BTF_KFUNCS_START(bpf_task_wake_kfunc_ids)
BTF_ID_FLAGS(func, bpf_task_wake, KF_RCU)
BTF_KFUNCS_END(bpf_task_wake_kfunc_ids)

static const struct btf_kfunc_id_set bpf_task_park_kfunc_set = {
	.owner = THIS_MODULE,
	.set = &bpf_task_park_kfunc_ids,
};

static const struct btf_kfunc_id_set bpf_task_wake_kfunc_set = {
	.owner = THIS_MODULE,
	.set = &bpf_task_wake_kfunc_ids,
};

/*
 * The park stays with syscall programs, whose runner holds the program across
 * the sleep. The wake touches only the task and defers itself where it cannot
 * be issued, so every program type has it, to wake a parked task from the
 * kernel event that makes it worth waking.
 */
static int __init bpf_task_park_kfunc_init(void)
{
	int ret;

	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL, &bpf_task_park_kfunc_set);
	return ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_UNSPEC, &bpf_task_wake_kfunc_set);
}
late_initcall(bpf_task_park_kfunc_init);
