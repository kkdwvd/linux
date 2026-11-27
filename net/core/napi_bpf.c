// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

#include <linux/bpf.h>
#include <linux/bpf_coro.h>
#include <linux/bpf_verifier.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/capability.h>
#include <linux/netdevice.h>
#include <linux/nsproxy.h>
#include <linux/sched.h>
#include <linux/static_call.h>
#include <net/gro.h>
#include <net/net_namespace.h>
#include <trace/events/napi.h>

#include "dev.h"

/* kfuncs for polling NAPIs from BPF kthreads. The mechanism, and what keeps
 * the device in control of a NAPI that a program polls, is described above
 * napi_bpf_bind_locked().
 *
 * A NAPI is named by its ID, the one netlink reports for the NAPI and for its
 * queues, and is looked up on every call. A program holds no NAPI pointer, so
 * a device that reconfigures its queues or goes away needs nothing from the
 * program, which sees an error for the ID and can bind again when the NAPI is
 * back.
 */

__bpf_kfunc_start_defs();

/**
 * bpf_napi_bind - Make a BPF kthread the poller of a NAPI
 * @napi_id: ID of a NAPI
 * @task: a thread created by bpf_kthread_create()
 * @flags: must be 0
 *
 * From now on a schedule of the NAPI, by its interrupt or otherwise, wakes
 * @task with the wake bpf_task_wake() issues instead of raising softirq, and
 * the NAPI waits for bpf_napi_poll(). Several NAPIs may be bound to one
 * thread. Binding a NAPI that is bound moves it to @task, and binding one
 * whose polls return -ECANCELED puts it back in service.
 *
 * The binding ends with bpf_napi_unbind(), when the thread's callback returns,
 * and whenever the device disables the NAPI or its threaded setting is
 * written; the NAPI is then polled by softirq again.
 *
 * Return: 0 on success, -EINVAL if @flags is not 0, -ENOENT if no NAPI has
 * this ID, -ESRCH if @task is not a BPF kthread, or one whose callback has
 * returned or that is being stopped, -EBUSY if the NAPI is in the kernel's
 * threaded mode, -EOPNOTSUPP if it cannot be polled by a thread.
 */
__bpf_kfunc int bpf_napi_bind(u32 napi_id, struct task_struct *task, u64 flags)
{
	struct napi_struct *napi;
	int ret;

	if (flags)
		return -EINVAL;

	napi = napi_bpf_by_id_lock(napi_id);
	if (!napi)
		return -ENOENT;
	ret = napi_bpf_bind_locked(napi, task);
	netdev_unlock(napi->dev);
	return ret;
}

/**
 * bpf_napi_unbind - Return a NAPI to softirq
 * @napi_id: ID of a NAPI
 *
 * Waits for a poll of the NAPI that is in progress. Work that was pending for
 * the thread is done by softirq.
 *
 * Return: 0 on success, also when the NAPI was not bound, -ENOENT if no NAPI
 * has this ID.
 */
__bpf_kfunc int bpf_napi_unbind(u32 napi_id)
{
	struct napi_struct *napi;

	napi = napi_bpf_by_id_lock(napi_id);
	if (!napi)
		return -ENOENT;
	napi_bpf_unbind_locked(napi);
	netdev_unlock(napi->dev);
	return 0;
}

/**
 * bpf_napi_poll - One round of service of a bound NAPI
 * @napi_id: ID of a NAPI bound with bpf_napi_bind()
 * @flags: BPF_NAPI_POLL_F_BUSY or 0
 *
 * Calls the driver's poll once, with the NAPI's budget, if the NAPI is
 * scheduled for its thread. The thread's loop polls each of its NAPIs until
 * none reports BPF_NAPI_POLL_MORE and then sleeps in bpf_task_park(); a
 * schedule that arrives in between leaves a wake pending, so the park returns
 * at once.
 *
 * With BPF_NAPI_POLL_F_BUSY the poll leaves the NAPI scheduled and its
 * interrupt masked, and also takes a NAPI that was not scheduled. The thread
 * then polls again when it sees fit, right away or after a timed park, and
 * no interrupt comes until a poll without the flag has completed the NAPI. A
 * NAPI left scheduled and unpolled for about a second is taken away from the
 * thread, whether a busy poll or an interrupt scheduled it.
 *
 * Any program may poll any bound NAPI: a poll is service, and two callers
 * exclude each other. The call is a rescheduling point.
 *
 * Return: the number of packets processed, at most BPF_NAPI_POLL_WORK_MASK,
 * ORed with BPF_NAPI_POLL_MORE if the NAPI is still scheduled for its thread.
 * -EAGAIN if the NAPI is not scheduled for its thread, -EBUSY if another
 * caller is polling it, -ENOENT if no NAPI with this ID is bound, -ECANCELED
 * if the NAPI was taken away from its thread for not being polled, until a
 * new bind, -EINVAL for unknown @flags.
 */
__bpf_kfunc int bpf_napi_poll(u32 napi_id, u64 flags)
{
	int ret;

	ret = napi_bpf_poll(napi_id, flags);
	/* What napi_threaded_poll_loop() does between the rounds of a NAPI
	 * thread, for a thread that polls in a loop without ever parking.
	 */
	cond_resched();
	return ret;
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(bpf_napi_kfunc_ids)
BTF_ID_FLAGS(func, bpf_napi_bind, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_napi_unbind, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_napi_poll, KF_SLEEPABLE)
BTF_KFUNCS_END(bpf_napi_kfunc_ids)

/* NAPI IDs are global, and a BPF kthread runs with the kernel's credentials
 * whoever created it, so there is nothing to check when a kfunc is called.
 * The program is checked instead, when it is loaded: it may call these kfuncs
 * only if its loader has CAP_NET_ADMIN in the initial user namespace. A BPF
 * token, which delegates within a user namespace, does not grant that.
 */
static int bpf_napi_kfunc_filter(const struct bpf_prog *prog, u32 kfunc_id)
{
	if (!btf_id_set8_contains(&bpf_napi_kfunc_ids, kfunc_id))
		return 0;
	return capable(CAP_NET_ADMIN) ? 0 : -EPERM;
}

static const struct btf_kfunc_id_set bpf_napi_kfunc_set = {
	.owner = THIS_MODULE,
	.set = &bpf_napi_kfunc_ids,
	.filter = bpf_napi_kfunc_filter,
};

/* Syscall programs create BPF kthreads, and a thread's callback is part of
 * the syscall program that created it.
 */
static int __init bpf_napi_kfunc_init(void)
{
	return register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL, &bpf_napi_kfunc_set);
}
late_initcall(bpf_napi_kfunc_init);

#ifdef CONFIG_BPF_JIT
/*
 * The extension at the step where a NAPI is scheduled.
 *
 * A NAPI that is scheduled has to be polled, and where and when is a step of the receive
 * path that the kernel decides in ____napi_schedule(): softirq on the CPU that scheduled it,
 * or the thread of the NAPI. An extension takes that step over for the NAPIs of one device.
 * It is code in place of the kernel's, not a setting: __napi_schedule() and
 * __napi_schedule_irqoff() call it where they called ____napi_schedule(), and so does
 * __napi_poll() where a poll in softirq has used up its budget and the NAPI wants its next
 * one. What the step is made of stays the kernel's: the queues, the wake, the driver's poll.
 *
 * The unit is a POLL: one call of the driver's poll that is owed. The extension is entered
 * with the NAPI as a reference that it has to give up, see struct bpf_napi_ops, and is a
 * coroutine as a rule:
 *
 *	frame = bpf_coro_frame_alloc_napi(size, napi);	its frame is in the NAPI
 *	bpf_napi_defer(frame, BPF_NAPI_SOFTIRQ);	the boundary: the poll waits
 *	...						softirq, or the thread, gets to it
 *	bpf_napi_poll_run(napi);			the operation, and the end of the frame
 *
 * The NAPI is the host of the frame, see "Hosts" in kernel/bpf/coro.c: it lends the frame
 * napi_struct::bpf_poll_frame, and the frame is there for as long as the code has the NAPI.
 * NAPI_STATE_SCHED is what makes that one owner at a time, and the frame is alive inside
 * its span only: from the entry to the call of the driver's poll, which gives the reference
 * up before it calls the driver. The driver may complete the NAPI in its poll, and another
 * CPU may schedule it and write the next frame while the first poll is on its way out.
 *
 * bpf_napi_defer() is the kernel's own two choices: softirq on this CPU, by the local half
 * of ____napi_schedule(), or the thread that the NAPI is bound to, by napi_bpf_schedule().
 * The kernel keeps the frame where it is and marks the NAPI, napi_struct::bpf_poll_gen, and
 * __napi_poll() resumes the continuation in place of its call of the driver's poll,
 * wherever it runs: net_rx_action(), or a thread's bpf_napi_poll(). Both have bottom halves
 * off and a network context, and the continuation is verified as code for that, whatever
 * the entry was, see __coro_defer in kernel/bpf/verifier.c. So the entry, which runs with
 * interrupts off, cannot poll, and the continuation can.
 *
 * Code that has nothing to do where the NAPI is polled needs no frame for saying where
 * that is: bpf_napi_poll_at() is the same two choices with the kernel's own poll behind
 * them, and nothing to resume.
 *
 * A thread that polls a NAPI nobody scheduled for it enters by itself, at again(): its
 * next poll of a NAPI that used up its budget, and a busy poll that takes an idle NAPI.
 * There the code may call bpf_napi_poll_run() at once: the poll runs in the thread, with no
 * suspension, which is the kernel's inline.
 *
 * Nothing of the receive path is lost on the way. A repoll in softirq that is deferred to
 * softirq stays on the list of the round that polled it, under that round's budget and
 * time: the entry only marks it. What the driver's poll did under the continuation is what
 * __napi_poll() returns. The timers of GRO and of interrupt deferral schedule the NAPI
 * like an interrupt, and pass the entry. A schedule of a NAPI that is scheduled sets
 * NAPI_STATE_MISSED and folds into the poll that is owed, and napi_complete_done() enters
 * for it once. Busy polling by a socket takes the NAPI without a schedule and polls it in
 * the caller: it does not pass. Nor does a NAPI in the kernel's threaded mode.
 *
 * The device stays in control:
 * - The verifier refuses an entry that returns with the NAPI, see __ref.
 * - A frame that is deferred holds nothing but its NAPI, so the kernel ends it without a
 *   call of the program wherever it takes the NAPI back: the watchdog of a thread that does
 *   not poll, an unbind, a detach. It forgets the mark, and polls.
 * - A continuation that returns without the poll, or that the kernel unwinds, leaves the
 *   poll to __napi_poll(), which calls the driver as it would have. So does an entry that
 *   the kernel unwinds: its landing pad gives the NAPI to ____napi_schedule().
 * - Only one extension is attached at a time, to one device.
 *
 * One extension in one place is also what makes its calls direct. The kernel knows at the
 * attach what it will call at the entries and where it resumes. The calls of schedule() and
 * again() are static calls that the attach patches, to the programs themselves and not to
 * the members of the struct_ops, which are trampolines around them. A trampoline is for a
 * caller that may be anywhere: it enters a read section of RCU, disables migration and
 * notes the program for the helpers that ask what runs. The entries have interrupts or
 * bottom halves off, which is the first two, and no helper of this program type asks. And a
 * frame whose first slot is the resume function that the verifier noted for the program of
 * schedule() is resumed by bpf_coro_run_bh(), which asks the frame nothing, in place of
 * bpf_coro_run(). BPF_NAPI_OPS_F_INDIRECT keeps the calls through the pointers of the
 * extension and of the frame, to compare the two.
 *
 * The kernel's unwinding of an entry needs nothing of the trampoline. An entry is the main
 * program of its invocation: where the kernel stops it, the landing pads in its own text
 * give up what it holds, the NAPI to bpf_napi_poll_native() or bpf_napi_poll_run(), and it
 * leaves with exit like any return, to whoever called.
 */

/**
 * struct bpf_napi_ops - the extension
 * @schedule: The NAPI was scheduled, @reason BPF_NAPI_SCHEDULE: with interrupts off, in
 *	hard interrupt context as a rule. Or softirq polled it and it wants its next poll,
 *	BPF_NAPI_REPOLL. The code defers the poll with bpf_napi_defer(), or leaves it to the
 *	kernel with bpf_napi_poll_native().
 * @again: The thread that polls the NAPI is in bpf_napi_poll() and nothing was deferred
 *	to it, BPF_NAPI_AGAIN. The code polls with bpf_napi_poll_run(), or defers.
 * @ifindex: the device, in the network namespace of whoever attaches
 * @flags: BPF_NAPI_OPS_F_INDIRECT, or 0
 */
struct bpf_napi_ops {
	void (*schedule)(struct napi_struct *napi, u32 reason);
	void (*again)(struct napi_struct *napi, u32 reason);
	u32 ifindex;
	u32 flags;
};

static_assert(sizeof_field(struct napi_struct, bpf_poll_frame) > BPF_CORO_FRAME_HDR);

/* The largest frame of a poll */
#define BPF_NAPI_POLL_FRAME	(sizeof_field(struct napi_struct, bpf_poll_frame) - BPF_CORO_FRAME_HDR)

DEFINE_STATIC_KEY_FALSE(napi_ext_key);

static unsigned int napi_ext_no_prog(const void *ctx, const struct bpf_insn *insn)
{
	return 0;
}

/* schedule() and again() of the extension that is attached, and whether the calls are direct */
DEFINE_STATIC_CALL(napi_ext_schedule_call, napi_ext_no_prog);
DEFINE_STATIC_CALL(napi_ext_again_call, napi_ext_no_prog);
static DEFINE_STATIC_KEY_FALSE(napi_ext_direct_key);
/* the programs of the two, and what the kernel resumes of the frames that it defers */
static const struct bpf_prog *napi_ext_prog, *napi_ext_again_prog;
static void *napi_ext_resume;

static DEFINE_MUTEX(napi_ext_mutex);
static const struct bpf_napi_ops __rcu *napi_ext_ops;
static struct net_device *napi_ext_dev;
static netdevice_tracker napi_ext_dev_tracker;
/* and of the extension on the path of a packet, below */
static struct net_device *rx_ext_dev;
static void rx_ext_detach(void);

/* What the code of the extension is in, on this CPU */
enum {
	NAPI_EXT_NONE,
	/* the three reasons of an entry, in their order: see napi_ext_enter() */
	NAPI_EXT_SCHEDULE,	/* schedule(BPF_NAPI_SCHEDULE): interrupts off */
	NAPI_EXT_REPOLL,	/* schedule(BPF_NAPI_REPOLL): softirq, in __napi_poll() */
	NAPI_EXT_AGAIN,		/* again(): a thread, in __napi_poll() */
	NAPI_EXT_RESUME,	/* a continuation, in __napi_poll() */
	NAPI_EXT_DONE,		/* it gave the NAPI up */
};

/*
 * A CPU runs the code for one NAPI at a time, with interrupts or bottom halves off, except
 * that the driver's poll which the code calls may schedule its NAPI again, which enters
 * anew: napi_ext_enter() saves this and puts it back.
 */
struct napi_ext_cpu {
	/* the two arguments of schedule() and again(): what a program has for its context */
	struct napi_struct *napi;
	u64 reason;
	int work;	/* what the driver's poll did, -1 if nothing called it */
	u8 ctx;
	bool repoll;	/* NAPI_EXT_REPOLL: softirq is to keep the NAPI on the list of its round */
};

static DEFINE_PER_CPU(struct napi_ext_cpu, napi_ext_cpu);

/*
 * Which attachment this is, never 0: what a NAPI with a frame deferred has in bpf_poll_gen,
 * so that a frame of an extension that is gone is nothing to the next one. And what it has
 * where the code left the poll to the kernel in the NAPI's thread, see bpf_napi_poll_at().
 */
static u32 napi_ext_gen;
#define NAPI_EXT_KERNEL	U32_MAX

/**
 * napi_ext_enter - have the extension do the step where a NAPI is scheduled
 * @napi: the NAPI, which the caller owns: NAPI_STATE_SCHED is set, and it is on no list
 * @reason: BPF_NAPI_SCHEDULE with interrupts off, BPF_NAPI_REPOLL in softirq
 * @repoll: for BPF_NAPI_REPOLL: set if softirq is to poll the NAPI again in a later round
 *
 * Returns false if the extension is gone, and for an entry that did not give the NAPI up,
 * which the verifier does not load: the kernel does its own step then.
 */
static __always_inline int __napi_ext_enter(struct napi_ext_cpu *cur,
					    const struct bpf_napi_ops *ops,
					    struct napi_struct *napi, u32 reason)
{
	int ret;

	BUILD_BUG_ON(NAPI_EXT_SCHEDULE != 1 + BPF_NAPI_SCHEDULE ||
		     NAPI_EXT_REPOLL != 1 + BPF_NAPI_REPOLL);
	/*
	 * The context is the first thing stored: an entry from an interrupt that finds none
	 * has all of this one's stores still to come, and one that finds it puts back what
	 * it found, see napi_ext_enter_nested().
	 */
	cur->ctx = 1 + reason;
	barrier();
	cur->napi = napi;
	cur->reason = reason;
	cur->repoll = false;
	/* the context of a struct_ops program: the arguments of its member */
	if (static_branch_likely(&napi_ext_direct_key))
		static_call(napi_ext_schedule_call)(&cur->napi, napi_ext_prog->insnsi);
	else
		ops->schedule(napi, reason);
	ret = cur->ctx != NAPI_EXT_DONE ? 0 : cur->repoll ? NAPI_EXT_REPOLLS : NAPI_EXT_ENTERED;
	barrier();
	cur->ctx = NAPI_EXT_NONE;
	return ret;
}

/*
 * An entry inside one that is on this CPU already, from an interrupt or from what the
 * code of the other one called: what that one has is put back, in one piece.
 */
static noinline int napi_ext_enter_nested(const struct bpf_napi_ops *ops,
					  struct napi_struct *napi, u32 reason)
{
	struct napi_ext_cpu *cur = this_cpu_ptr(&napi_ext_cpu), saved = *cur;
	unsigned long flags;
	int ret;

	cur->ctx = NAPI_EXT_NONE;
	ret = __napi_ext_enter(cur, ops, napi, reason);
	local_irq_save(flags);
	*cur = saved;
	local_irq_restore(flags);
	return ret;
}

int napi_ext_enter(struct napi_struct *napi, u32 reason)
{
	struct napi_ext_cpu *cur = this_cpu_ptr(&napi_ext_cpu);
	const struct bpf_napi_ops *ops;

	/* interrupts or bottom halves are off: a read section that napi_ext_detach() waits for */
	ops = rcu_dereference_sched(napi_ext_ops);
	if (unlikely(!ops) || !napi_ext_on(napi))
		return 0;
	/* nothing of the extension is on this CPU as a rule, and then nothing to put back */
	if (unlikely(cur->ctx != NAPI_EXT_NONE))
		return napi_ext_enter_nested(ops, napi, reason);
	return __napi_ext_enter(cur, ops, napi, reason);
}

/**
 * napi_ext_poll - the extension's part of a poll, in __napi_poll()
 * @napi: the NAPI, scheduled, with bottom halves off
 * @deferred: set if the code deferred the poll once more: the NAPI is the caller's no more
 *
 * A poll that was deferred goes on in its continuation, which calls the driver's poll. A
 * thread that polls without one enters at again(). Returns what the driver's poll did, or
 * -1 if nothing called it: the kernel does.
 */
static __always_inline int __napi_ext_poll(struct napi_ext_cpu *cur,
					   const struct bpf_napi_ops *ops,
					   struct napi_struct *napi, u32 gen)
{
	int work;

	/* the context first, see __napi_ext_enter() */
	cur->ctx = gen ? NAPI_EXT_RESUME : NAPI_EXT_AGAIN;
	barrier();
	cur->napi = napi;
	cur->work = -1;
	if (gen) {
		void *frame = (void *)napi->bpf_poll_frame + BPF_CORO_FRAME_HDR;

		/* the program is the attachment's, which waits for this: see napi_ext_detach() */
		if (static_branch_likely(&napi_ext_direct_key) &&
		    *(void **)frame == READ_ONCE(napi_ext_resume))
			bpf_coro_run_bh(napi_ext_prog, frame);
		else
			bpf_coro_run(frame);
		work = cur->work;
	} else {
		/* a thread that keeps the NAPI in hand comes by with nothing deferred */
		cur->reason = BPF_NAPI_AGAIN;
		if (static_branch_likely(&napi_ext_direct_key))
			static_call(napi_ext_again_call)(&cur->napi, napi_ext_again_prog->insnsi);
		else
			ops->again(napi, BPF_NAPI_AGAIN);
		work = cur->work;
		if (cur->ctx == NAPI_EXT_DONE && work < 0)
			work = NAPI_EXT_DEFERRED;
	}
	barrier();
	cur->ctx = NAPI_EXT_NONE;
	return work;
}

static noinline int napi_ext_poll_nested(const struct bpf_napi_ops *ops,
					 struct napi_struct *napi, u32 gen)
{
	struct napi_ext_cpu *cur = this_cpu_ptr(&napi_ext_cpu), saved = *cur;
	unsigned long flags;
	int work;

	cur->ctx = NAPI_EXT_NONE;
	work = __napi_ext_poll(cur, ops, napi, gen);
	local_irq_save(flags);
	*cur = saved;
	local_irq_restore(flags);
	return work;
}

int napi_ext_poll(struct napi_struct *napi)
{
	struct napi_ext_cpu *cur = this_cpu_ptr(&napi_ext_cpu);
	const struct bpf_napi_ops *ops = rcu_dereference_sched(napi_ext_ops);
	u32 gen = napi->bpf_poll_gen;

	/* the caller owns the NAPI: the mark is its to take */
	if (gen)
		napi->bpf_poll_gen = 0;
	/* the kernel polls: the extension is gone, or said so, or left a frame of another */
	if (unlikely(!ops) || gen == NAPI_EXT_KERNEL)
		return -1;
	if (!gen) {
		/* softirq, or a kernel thread, with a NAPI that came by the kernel's own hand */
		if (!(READ_ONCE(napi->state) & NAPIF_STATE_BPF_POLLING))
			return -1;
	} else if (unlikely(gen != READ_ONCE(napi_ext_gen))) {
		return -1;
	}
	if (unlikely(cur->ctx != NAPI_EXT_NONE))
		return napi_ext_poll_nested(ops, napi, gen);
	return __napi_ext_poll(cur, ops, napi, gen);
}

/*
 * A NAPI appears, with the lock of its device: it has the extension if the device has it.
 * Its memory may have been a NAPI before, and what it was then says nothing.
 */
void napi_ext_add(struct napi_struct *napi)
{
	napi->bpf_poll_gen = 0;
	if (napi->dev == READ_ONCE(napi_ext_dev))
		set_bit(NAPI_STATE_EXT, &napi->state);
	else
		clear_bit(NAPI_STATE_EXT, &napi->state);
	/* a node with no frames, and with the extension that its device has */
	napi->bpf_held = 0;
	WRITE_ONCE(napi->bpf_rx, napi->dev == READ_ONCE(rx_ext_dev));
}

/* Has the code on this CPU @napi in hand, in one of @ctxs, a mask? */
static __always_inline bool napi_ext_in(const struct napi_ext_cpu *cur,
					const struct napi_struct *napi, u32 ctxs)
{
	return !WARN_ON_ONCE(cur->napi != napi || !(BIT(cur->ctx) & ctxs));
}

__bpf_kfunc_start_defs();

/**
 * bpf_coro_frame_alloc_napi - the coroutine frame of a poll, in its NAPI
 * @size__k: the size of the frame, which the verifier checked against BPF_NAPI_POLL_FRAME
 * @napi__coro_host: the NAPI that the extension was entered with
 * @aux: the program
 *
 * The frame is there for as long as the code has the NAPI, and nothing frees it. Returns
 * the frame, or NULL for a program whose last reference is gone.
 */
__bpf_kfunc void *bpf_coro_frame_alloc_napi(u64 size__k, struct napi_struct *napi__coro_host,
					    struct bpf_prog_aux *aux)
{
	return bpf_coro_frame_in(napi__coro_host->bpf_poll_frame, aux);
}

/**
 * bpf_napi_defer - have the poll of a NAPI wait for softirq, or for the thread of the NAPI
 * @frame__coro_defer: the frame of the poll, from bpf_coro_frame_alloc_napi(), with the
 *	NAPI in one of its slots
 * @where: BPF_NAPI_SOFTIRQ, or BPF_NAPI_THREAD
 *
 * The step that ____napi_schedule() is, as a boundary: the kernel keeps the frame in the
 * NAPI and resumes its continuation where the NAPI is polled next, in softirq on this CPU
 * or under the bpf_napi_poll() of a thread. BPF_NAPI_THREAD is softirq for a NAPI that is
 * bound to no thread, or whose thread the kernel took it from. A repoll that waits for
 * softirq stays in the round that polled it. Never resumes in the call.
 */
__bpf_kfunc void bpf_napi_defer(void *frame__coro_defer, u32 where)
{
	struct napi_struct *napi = container_of(frame__coro_defer - BPF_CORO_FRAME_HDR,
						struct napi_struct, bpf_poll_frame);
	struct napi_ext_cpu *cur = this_cpu_ptr(&napi_ext_cpu);
	unsigned long flags = 0;

	if (!napi_ext_in(cur, napi,
			 BIT(NAPI_EXT_SCHEDULE) | BIT(NAPI_EXT_REPOLL) | BIT(NAPI_EXT_AGAIN)))
		return;
	/* before the NAPI is where another CPU finds it */
	napi->bpf_poll_gen = READ_ONCE(napi_ext_gen);
	/* schedule() has interrupts off as it is */
	if (cur->ctx != NAPI_EXT_SCHEDULE)
		local_irq_save(flags);
	if (where == BPF_NAPI_THREAD && napi_bpf_schedule(napi)) {
		/* its thread has it: an again() that keeps it for the next call, too */
	} else if (cur->ctx == NAPI_EXT_REPOLL) {
		cur->repoll = true;
	} else {
		if (cur->ctx == NAPI_EXT_AGAIN) {
			/*
			 * The thread lets it go, as a poll that completes it does, and a busy
			 * poll ends with the mark: softirq has to be able to complete it.
			 */
			clear_bit(NAPI_STATE_IN_BUSY_POLL, &napi->state);
			clear_bit(NAPI_STATE_SCHED_THREADED, &napi->state);
		}
		napi_schedule_local(napi);
	}
	if (cur->ctx != NAPI_EXT_SCHEDULE)
		local_irq_restore(flags);
	cur->ctx = NAPI_EXT_DONE;
}

/**
 * bpf_napi_poll_native - leave the poll of a NAPI to the kernel
 * @napi: the NAPI that schedule() was entered with
 *
 * The kernel's own step for this poll, with no frame: ____napi_schedule(), or for a repoll
 * the list of the round. It is what the landing pad of schedule() calls too.
 */
__bpf_kfunc void bpf_napi_poll_native(struct napi_struct *napi)
{
	struct napi_ext_cpu *cur = this_cpu_ptr(&napi_ext_cpu);

	if (!napi_ext_in(cur, napi, BIT(NAPI_EXT_SCHEDULE) | BIT(NAPI_EXT_REPOLL)))
		return;
	if (cur->ctx == NAPI_EXT_REPOLL)
		cur->repoll = true;
	else
		napi_schedule_native(napi);
	cur->ctx = NAPI_EXT_DONE;
}

/**
 * bpf_napi_poll_at - leave the poll of a NAPI to the kernel, where the code says
 * @napi: the NAPI that schedule() was entered with
 * @where: BPF_NAPI_SOFTIRQ, or BPF_NAPI_THREAD
 *
 * bpf_napi_defer() for code that has nothing to do where the NAPI is polled: no frame, and
 * no continuation. The poll waits for softirq on this CPU or for the thread that the NAPI
 * is bound to, softirq if it has none, and whoever gets to it calls the driver as the
 * kernel does. The step is the extension's, and what it costs is the entry.
 */
__bpf_kfunc void bpf_napi_poll_at(struct napi_struct *napi, u32 where)
{
	struct napi_ext_cpu *cur = this_cpu_ptr(&napi_ext_cpu);
	unsigned long flags = 0;

	if (!napi_ext_in(cur, napi, BIT(NAPI_EXT_SCHEDULE) | BIT(NAPI_EXT_REPOLL)))
		return;
	if (where == BPF_NAPI_THREAD) {
		/* the thread's poll of it is the kernel's, and no again() */
		napi->bpf_poll_gen = NAPI_EXT_KERNEL;
		if (cur->ctx != NAPI_EXT_SCHEDULE)
			local_irq_save(flags);
		if (napi_bpf_schedule(napi)) {
			if (cur->ctx != NAPI_EXT_SCHEDULE)
				local_irq_restore(flags);
			cur->ctx = NAPI_EXT_DONE;
			return;
		}
		if (cur->ctx != NAPI_EXT_SCHEDULE)
			local_irq_restore(flags);
		napi->bpf_poll_gen = 0;
	}
	if (cur->ctx == NAPI_EXT_REPOLL)
		cur->repoll = true;
	else
		napi_schedule_local(napi);
	cur->ctx = NAPI_EXT_DONE;
}

/**
 * bpf_napi_poll_run - the driver's poll of a NAPI, once, with its budget
 * @napi: the NAPI, which the caller owns: the continuation of a poll that was deferred,
 *	or again()
 *
 * The operation of the unit, and the end of its frame: the caller has no NAPI when the
 * driver is entered, and looks at no frame afterwards. No lookup, no claim and no sleep:
 * the code is in __napi_poll(), which gets what the poll did.
 */
__bpf_kfunc void bpf_napi_poll_run(struct napi_struct *napi)
{
	struct napi_ext_cpu *cur = this_cpu_ptr(&napi_ext_cpu);
	int work;

	if (!napi_ext_in(cur, napi, BIT(NAPI_EXT_RESUME) | BIT(NAPI_EXT_AGAIN)))
		return;
	cur->ctx = NAPI_EXT_DONE;
	work = napi->poll(napi, napi->weight);
	trace_napi_poll(napi, work, napi->weight);
	xdp_do_check_flushed(napi);
	/* the same CPU, and what the driver's poll entered on the way has put @cur back */
	cur->work = work;
}

__bpf_kfunc_end_defs();

static int bpf_napi_ops__schedule(struct napi_struct *napi__ref, u32 reason)
{
	return 0;
}

static int bpf_napi_ops__again(struct napi_struct *napi__ref, u32 reason)
{
	return 0;
}

static struct bpf_napi_ops __bpf_napi_ops_stubs = {
	.schedule = (void *)bpf_napi_ops__schedule,
	.again = (void *)bpf_napi_ops__again,
};

static struct bpf_struct_ops bpf_bpf_napi_ops;

BTF_KFUNCS_START(napi_ext_kfunc_ids)
BTF_ID_FLAGS(func, bpf_coro_frame_alloc_napi, KF_ACQUIRE | KF_RET_NULL | KF_IMPLICIT_ARGS)
BTF_ID_FLAGS(func, bpf_napi_defer)
BTF_ID_FLAGS(func, bpf_napi_poll_native, KF_RELEASE)
BTF_ID_FLAGS(func, bpf_napi_poll_at, KF_RELEASE)
BTF_ID_FLAGS(func, bpf_napi_poll_run, KF_RELEASE)
BTF_KFUNCS_END(napi_ext_kfunc_ids)

/* what a continuation calls: code that __napi_poll() resumes */
BTF_KFUNCS_START(napi_ext_cont_kfunc_ids)
BTF_ID_FLAGS(func, bpf_napi_poll_run, KF_RELEASE)
BTF_KFUNCS_END(napi_ext_cont_kfunc_ids)

BTF_ID_LIST(napi_ext_ids)
BTF_ID(func, bpf_napi_poll_native)
BTF_ID(func, bpf_napi_poll_run)
BTF_ID(func, bpf_coro_frame_alloc_napi)
BTF_ID(func, bpf_napi_poll_at)

/*
 * schedule() runs with interrupts off and cannot poll, and again() is in the poll and has
 * no other step to leave the NAPI to. Each has one call that takes the NAPI alone, which
 * is what its landing pad calls.
 */
static int napi_ext_kfunc_filter(const struct bpf_prog *prog, u32 kfunc_id)
{
	u32 moff;

	if (!btf_id_set8_contains(&napi_ext_kfunc_ids, kfunc_id))
		return 0;
	if (prog->aux->st_ops != &bpf_bpf_napi_ops)
		return -EACCES;
	/* a continuation, see __coro_defer: as __napi_poll() resumes it */
	if (prog->type != BPF_PROG_TYPE_STRUCT_OPS)
		return kfunc_id == napi_ext_ids[1] ? 0 : -EACCES;
	moff = prog->aux->attach_st_ops_member_off;
	if (kfunc_id == napi_ext_ids[0] || kfunc_id == napi_ext_ids[3])
		return moff == offsetof(struct bpf_napi_ops, schedule) ? 0 : -EACCES;
	if (kfunc_id == napi_ext_ids[1])
		return moff == offsetof(struct bpf_napi_ops, again) ? 0 : -EACCES;
	return 0;
}

static const struct btf_kfunc_id_set napi_ext_kfunc_set = {
	.owner = THIS_MODULE,
	.set = &napi_ext_kfunc_ids,
	.filter = napi_ext_kfunc_filter,
};

static const struct btf_kfunc_id_set napi_ext_cont_kfunc_set = {
	.owner = THIS_MODULE,
	.set = &napi_ext_cont_kfunc_ids,
	.filter = napi_ext_kfunc_filter,
};

static const struct bpf_verifier_ops bpf_napi_verifier_ops = {
	.get_func_proto = bpf_base_func_proto,
	.is_valid_access = bpf_tracing_btf_ctx_access,
};

static int bpf_napi_ops_init(struct btf *btf)
{
	return 0;
}

static int bpf_napi_ops_init_member(const struct btf_type *t, const struct btf_member *member,
				    void *kdata, const void *udata)
{
	const struct bpf_napi_ops *uops = udata;
	struct bpf_napi_ops *ops = kdata;

	switch (__btf_member_bit_offset(t, member) / 8) {
	case offsetof(struct bpf_napi_ops, ifindex):
		ops->ifindex = uops->ifindex;
		return 1;
	case offsetof(struct bpf_napi_ops, flags):
		if (uops->flags & ~BPF_NAPI_OPS_F_INDIRECT)
			return -EINVAL;
		ops->flags = uops->flags;
		return 1;
	}
	return 0;
}

static int bpf_napi_ops_validate(void *kdata)
{
	struct bpf_napi_ops *ops = kdata;

	return ops->schedule && ops->again && ops->ifindex ? 0 : -EINVAL;
}

/* Take the extension off its device. With napi_ext_mutex. */
static void napi_ext_detach(void)
{
	struct net_device *dev = napi_ext_dev;
	struct napi_struct *napi;

	if (!dev)
		return;
	netdev_lock(dev);
	WRITE_ONCE(napi_ext_dev, NULL);
	list_for_each_entry(napi, &dev->napi_list, dev_list)
		clear_bit(NAPI_STATE_EXT, &napi->state);
	netdev_unlock(dev);
	rcu_assign_pointer(napi_ext_ops, NULL);
	/*
	 * No entry and no continuation runs any more, and none begins. The polls that it
	 * deferred are the kernel's, each where it waits: a mark that is left says which
	 * attachment its frame was of, and that one is gone, see napi_ext_poll().
	 */
	synchronize_rcu();
	if (static_key_enabled(&napi_ext_direct_key)) {
		static_branch_disable(&napi_ext_direct_key);
		static_call_update(napi_ext_schedule_call, napi_ext_no_prog);
		static_call_update(napi_ext_again_call, napi_ext_no_prog);
		WRITE_ONCE(napi_ext_resume, NULL);
	}
	static_branch_dec(&napi_ext_key);
	static_branch_dec(&napi_poll_hook_key);
	netdev_put(dev, &napi_ext_dev_tracker);
}

/* The programs of schedule() and again(), in that order */
static int napi_ext_member_progs(struct bpf_prog *prog, void *data)
{
	const struct bpf_prog **progs = data;

	if (prog->aux->attach_st_ops_member_off == offsetof(struct bpf_napi_ops, schedule))
		progs[0] = prog;
	else if (prog->aux->attach_st_ops_member_off == offsetof(struct bpf_napi_ops, again))
		progs[1] = prog;
	return 0;
}

/* The program of the first member of a struct_ops */
static int napi_ext_first_prog(struct bpf_prog *prog, void *data)
{
	*(const struct bpf_prog **)data = prog;
	return 1;
}

static int bpf_napi_ops_reg(void *kdata, struct bpf_link *link)
{
	struct bpf_napi_ops *ops = kdata;
	struct napi_struct *napi;
	struct net_device *dev;
	int err = 0;

	mutex_lock(&napi_ext_mutex);
	if (rcu_access_pointer(napi_ext_ops)) {
		err = -EBUSY;
		goto out;
	}
	dev = netdev_get_by_index(current->nsproxy->net_ns, ops->ifindex, &napi_ext_dev_tracker,
				  GFP_KERNEL);
	if (!dev) {
		err = -ENODEV;
		goto out;
	}
	if (!(ops->flags & BPF_NAPI_OPS_F_INDIRECT)) {
		/* before a NAPI can enter */
		const struct bpf_prog *progs[2] = {};

		bpf_struct_ops_for_each_prog(kdata, napi_ext_member_progs, progs);
		napi_ext_prog = progs[0];
		napi_ext_again_prog = progs[1];
		WRITE_ONCE(napi_ext_resume, bpf_coro_defer_resume(napi_ext_prog));
		static_call_update(napi_ext_schedule_call, napi_ext_prog->bpf_func);
		static_call_update(napi_ext_again_call, napi_ext_again_prog->bpf_func);
		static_branch_enable(&napi_ext_direct_key);
	}
	/* another attachment than any before it: never 0, nor what says that the kernel polls */
	WRITE_ONCE(napi_ext_gen, napi_ext_gen + 1 >= NAPI_EXT_KERNEL ? 1 : napi_ext_gen + 1);
	static_branch_inc(&napi_ext_key);
	static_branch_inc(&napi_poll_hook_key);
	rcu_assign_pointer(napi_ext_ops, ops);
	netdev_lock(dev);
	if (dev->reg_state != NETREG_REGISTERED) {
		err = -ENODEV;
	} else {
		WRITE_ONCE(napi_ext_dev, dev);
		list_for_each_entry(napi, &dev->napi_list, dev_list)
			if (!test_bit(NAPI_STATE_PERCPU, &napi->state))
				set_bit(NAPI_STATE_EXT, &napi->state);
	}
	netdev_unlock(dev);
	if (err) {
		rcu_assign_pointer(napi_ext_ops, NULL);
		synchronize_rcu();
		if (static_key_enabled(&napi_ext_direct_key)) {
			static_branch_disable(&napi_ext_direct_key);
			static_call_update(napi_ext_schedule_call, napi_ext_no_prog);
			static_call_update(napi_ext_again_call, napi_ext_no_prog);
		}
		static_branch_dec(&napi_ext_key);
		static_branch_dec(&napi_poll_hook_key);
		netdev_put(dev, &napi_ext_dev_tracker);
	}
out:
	mutex_unlock(&napi_ext_mutex);
	return err;
}

static void bpf_napi_ops_unreg(void *kdata, struct bpf_link *link)
{
	mutex_lock(&napi_ext_mutex);
	if (rcu_access_pointer(napi_ext_ops) == kdata) {
		napi_ext_detach();
		rcu_assign_pointer(napi_ext_ops, NULL);
	}
	mutex_unlock(&napi_ext_mutex);
}

/* The device goes with the extension on it: the extension stays registered, on nothing */
static int napi_ext_netdev_event(struct notifier_block *nb, unsigned long event, void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);

	if (event != NETDEV_UNREGISTER ||
	    (dev != READ_ONCE(napi_ext_dev) && dev != READ_ONCE(rx_ext_dev)))
		return NOTIFY_DONE;
	mutex_lock(&napi_ext_mutex);
	if (dev == napi_ext_dev)
		napi_ext_detach();
	if (dev == rx_ext_dev)
		rx_ext_detach();
	mutex_unlock(&napi_ext_mutex);
	return NOTIFY_DONE;
}

static struct notifier_block napi_ext_netdev_notifier = {
	.notifier_call = napi_ext_netdev_event,
};

static struct bpf_struct_ops bpf_bpf_napi_ops = {
	.verifier_ops = &bpf_napi_verifier_ops,
	.reg = bpf_napi_ops_reg,
	.unreg = bpf_napi_ops_unreg,
	.validate = bpf_napi_ops_validate,
	.init_member = bpf_napi_ops_init_member,
	.init = bpf_napi_ops_init,
	.name = "bpf_napi_ops",
	.cfi_stubs = &__bpf_napi_ops_stubs,
	.owner = THIS_MODULE,
};

static int __init napi_ext_init(void)
{
	int ret;

	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_STRUCT_OPS, &napi_ext_kfunc_set);
	ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP, &napi_ext_cont_kfunc_set);
	ret = ret ?: bpf_coro_register_host(napi_ext_ids[2], BPF_NAPI_POLL_FRAME);
	ret = ret ?: register_netdevice_notifier(&napi_ext_netdev_notifier);
	return ret ?: register_bpf_struct_ops(&bpf_bpf_napi_ops, bpf_napi_ops);
}
late_initcall(napi_ext_init);

/*
 * The extension on the path of a packet.
 *
 * A packet that a driver hands to napi_gro_receive() has a path that the kernel wrote in
 * gro_receive_skb(): into GRO, which merges it into a packet of its flow, holds it for the
 * next one, or has no use for it; and then, alone or with what was merged into it, onto the
 * batch of its NAPI, which the kernel delivers as a list. An extension is that path for the
 * packets of one device, as code in place of the kernel's: gro_receive_skb() calls arrive()
 * where it called dev_gro_receive(). What the path is made of stays the kernel's: GRO, the
 * batch, the delivery.
 *
 * The unit is a PACKET. The extension is entered with the skb as a reference that it has to
 * give up, see struct bpf_rx_ops, and is a coroutine:
 *
 *	frame = bpf_coro_frame_alloc_skb(size, skb);	its frame is in the head of the packet
 *	if (bpf_rx_gro(frame))				the boundary: GRO has the packet
 *		return;
 *	bpf_rx_batch(skb);				or not: it goes on, to the batch
 *	...
 *	bpf_rx_batch(skb);				the continuation, at the flush
 *
 * The packet is the host of the frame, see "Hosts" in kernel/bpf/coro.c: it lends the first
 * NET_SKB_PAD bytes of its head, the headroom that every driver leaves below a packet and
 * that nothing on the receive path writes. The frame is bare: nothing is written where it
 * starts but what the code stores, and it is there for as long as the code has the packet.
 * A head that is shared with a clone, or that has its link layer header or metadata within
 * those bytes, lends nothing: bpf_coro_frame_alloc_skb() returns NULL, and the code leaves
 * the packet to the kernel with bpf_rx_native(), or goes on without a frame. No other
 * memory stands in.
 *
 * bpf_rx_gro() is dev_gro_receive() as a boundary that answers at once, see __coro_offer in
 * kernel/bpf/verifier.c. GRO merges the packet into one that it holds: the packet is gone
 * as a unit and its frame with it, there is nothing to resume. Or GRO holds the packet: the
 * frame stays suspended in the head, and gro_complete() resumes its continuation where it
 * called gro_normal_one(), in whichever flush that is. In both cases the kfunc returns true
 * and the entry has no packet. Or GRO has no use for the packet: the kfunc returns false,
 * nothing has happened to the frame, and the code goes on in the entry.
 *
 * bpf_rx_batch() is gro_normal_one(), the end of the unit and of its frame: the packet is
 * on the list of its NAPI, with the segments that GRO counted for it, and the kernel
 * delivers the list when it is full or the poll is over, as before. bpf_rx_native() is the
 * kernel's own remainder of the path wherever the packet is, with no frame: all of it for
 * a packet that GRO has not seen, the batch for one that it has.
 *
 * So the null extension, bpf_rx_gro() and then bpf_rx_batch() on both ways out, is the
 * kernel's path exactly: the same calls in the same order on the same packets. The driver
 * builds the skb as before, no XDP program is involved, and checksum, hash and what the
 * hardware merged are what they were.
 *
 * GRO is a fold: where it merges a packet into one that it holds, two units become one, and
 * the frame of the packet that is merged is over. What an extension keeps per packet across
 * the hold has to be combined then, and the frame is no place for it: a suspended frame is
 * verified from what it was when it was suspended, and nothing but its own continuation may
 * write it. So a packet with a frame has a word of state beside the frame, in the same
 * headroom, zero at first, which the code sets and reads with bpf_rx_set_state() and
 * bpf_rx_state(). An extension with a merge() is called where GRO has merged a packet into
 * a held one, both with frames, with the two words, and returns the word of the packet that
 * stays. With no merge() the call is not there, and the word of the packet that stays is
 * what it was.
 *
 * Most packets need no frame: GRO merges them into one that it holds, or has no use for
 * them, and their path is over in the entry. So the code may offer a packet before it has
 * written anything. bpf_rx_pass() is dev_gro_receive() and, unless GRO holds the packet,
 * what gro_receive_skb() does with the answer, as a call that may decline, see __offer in
 * kernel/bpf/verifier.c: true, and the packet is gone; false, and GRO holds it, for the
 * code, which takes the frame then and stays with the packet, bpf_rx_hold(). That is
 * bpf_rx_gro() from there on. bpf_rx_offer() is the same offer for code that goes on with
 * a packet of no use to GRO, to a backlog, say: it returns GRO's answer and the code has
 * the packet in every case, with the answer still to be seen through where it gives the
 * packet up. A packet that was offered with no frame has no word of state, and merge()
 * gets 0 for it.
 *
 * A packet can also wait for another CPU. bpf_rx_backlog() is the step that RPS is in the
 * kernel, as a boundary that may decline: the packet goes onto the backlog of the CPU that
 * the code names, with its frame suspended in its head, and process_backlog() resumes the
 * continuation there, which hands the packet to the stack with bpf_rx_deliver(). A queue
 * that is full takes nothing, as it does of the kernel, which then drops: here the kfunc
 * returns false and the code goes on with the packet, onto the batch, say. A packet that
 * waits in a backlog says so in its control block, which is the queue's while it waits.
 *
 * A continuation runs inside the flush that resumes it, which may be inside bpf_rx_gro()
 * for another packet: GRO flushes a held packet to make room, or because the one that
 * arrives ends its flow's run. The code of the extension nests then, a continuation under
 * its own entry, and what the outer one has in hand is saved and put back, see
 * rx_ext_resume_nested(). An entry that finds nothing of the extension on its CPU, which is
 * the rule, saves nothing.
 *
 * The device stays in control:
 * - The verifier refuses an entry or a continuation that returns with the packet.
 * - A frame that is suspended holds nothing but its packet, so wherever the kernel takes a
 *   held packet for itself the frame is over without a call of the program: a NAPI that is
 *   deleted frees what it holds, and a packet whose protocol fails to complete it is freed.
 * - A detach forgets the frames that are suspended in held packets: each packet is the
 *   kernel's at its flush. Frames are told apart by attachment, not by program, see
 *   rx_ext_hold(), so that a frame of an extension that is gone is never resumed, by the
 *   next one either. The same for a packet in a backlog: the kernel delivers it, and a
 *   device that goes has its packets flushed from the backlogs as before.
 * - A continuation that the kernel unwinds gives the packet to the batch by its landing
 *   pad, and so does an entry: the packet of code that is unwound may go past GRO.
 * - Only one extension is attached at a time, to one device. It is another one than the
 *   extension at the step where a NAPI is scheduled, and either is there without the other.
 *
 * Packets that a driver hands to napi_gro_frags() do not pass, nor those of a GRO node
 * that is not a NAPI's: they take the kernel's path.
 */

/**
 * struct bpf_rx_ops - the extension on the path of a packet
 * @arrive: A driver handed @skb to napi_gro_receive(), in the poll of a NAPI of the device:
 *	with bottom halves off. The code offers it to GRO with bpf_rx_gro(), puts it on the
 *	batch with bpf_rx_batch(), or leaves it to the kernel with bpf_rx_native().
 * @merge: Optional. GRO has merged a packet into one that it holds, and both have frames of
 *	this extension: @from is the state of the packet that is over, @into that of the one
 *	that stays, whose state the return value is from then on. Runs inside bpf_rx_gro()
 *	of the packet that is merged, and calls nothing of the path.
 * @ifindex: the device, in the network namespace of whoever attaches
 * @flags: 0
 */
struct bpf_rx_ops {
	void (*arrive)(struct sk_buff *skb);
	u64 (*merge)(u64 into, u64 from);
	u32 ifindex;
	u32 flags;
};

/*
 * What the head of a packet lends: the headroom below any packet of any driver, which is a
 * frame and behind it the word of state that a fold combines.
 */
#define BPF_RX_ROOM	round_down(NET_SKB_PAD, sizeof(u64))
#define BPF_RX_FRAME	(BPF_RX_ROOM - sizeof(u64))

DEFINE_STATIC_KEY_FALSE(rx_ext_key);
/* which attachment this is: never 0, see rx_ext_hold() */
u32 rx_ext_gen;

static u64 rx_ext_no_merge(u64 into, u64 from)
{
	return into;
}

/* merge() of the extension that is attached, if it has one */
DEFINE_STATIC_KEY_FALSE(rx_ext_merge_key);
DEFINE_STATIC_CALL(rx_ext_merge_call, rx_ext_no_merge);

static unsigned int rx_ext_no_arrive(const void *ctx, const struct bpf_insn *insn)
{
	return 0;
}

/*
 * arrive() of the extension that is attached: the program itself, not the trampoline of the
 * struct_ops member. The trampoline is for a caller that may be anywhere: it enters a read
 * section of RCU, disables migration and notes the program for the helpers that ask what
 * runs. gro_receive_skb() is in the poll of a NAPI, with bottom halves off, which is the
 * first two, and no helper of this program type asks. Per packet that is half of what the
 * extension costs. The program's run statistics do not count these calls.
 */
DEFINE_STATIC_CALL(rx_ext_arrive_call, rx_ext_no_arrive);
/* the program that arrive() and its continuations are */
static const struct bpf_prog *rx_ext_prog;
static const struct bpf_rx_ops __rcu *rx_ext_ops;
static netdevice_tracker rx_ext_dev_tracker;

/* What the code of the extension is in, on this CPU */
enum {
	RX_EXT_NONE,
	RX_EXT_ARRIVE,		/* arrive(): in gro_receive_skb() */
	RX_EXT_RESUME,		/* a continuation: in gro_complete() */
	RX_EXT_BACKLOG,		/* a continuation: in process_backlog() */
	RX_EXT_DONE,		/* it gave the packet up */
};

/*
 * A CPU runs the code for one packet at a time, with bottom halves off, except that GRO
 * and the delivery of a batch, which the code calls, may flush a held packet and resume its
 * continuation: rx_ext_arrive() and rx_ext_resume() save this and put it back.
 */
struct rx_ext_cpu {
	struct gro_node *gro;	/* NULL in process_backlog() */
	/* the argument of arrive(): what its program has for a context */
	struct sk_buff *skb;
	gro_result_t ret;	/* what gro_receive_skb() returns for the packet */
	union {
		struct {
			u8 ctx;
			bool offered;	/* GRO has seen the packet: not a second time */
			bool framed;	/* its head lent a frame, and has the word of state */
			bool pending;	/* bpf_rx_offer() did: GRO's answer is to be seen through */
		};
		u32 state;		/* the four, in the one store that begins an entry */
	};
};

/*
 * An entry begins, with a packet that GRO has @seen, in a frame, or not: the context is in
 * the first thing stored. An entry from an interrupt that finds none has all of this one's
 * stores still to come, and one that finds it puts back what it found, see
 * rx_ext_arrive_nested().
 */
static __always_inline void rx_ext_begin(struct rx_ext_cpu *cur, u8 ctx, bool seen)
{
	const struct rx_ext_cpu begin = { .ctx = ctx, .offered = seen, .framed = seen };

	cur->state = begin.state;
	barrier();
}

static DEFINE_PER_CPU(struct rx_ext_cpu, rx_ext_cpu);

/**
 * rx_ext_arrive - have the extension be the path of a packet from gro_receive_skb() on
 * @gro: the node of the NAPI that is polled
 * @skb: the packet
 * @ret: what gro_receive_skb() returns for it
 *
 * Returns false if the extension is gone: the kernel's own path then.
 */
/*
 * gro_skb_finish() said again: that one has one caller, gro_receive_skb(), and is compiled
 * into it, which a second caller would undo.
 */
static __always_inline gro_result_t rx_ext_gro_finish(struct gro_node *gro, struct sk_buff *skb,
						      gro_result_t ret)
{
	switch (ret) {
	case GRO_NORMAL:
		gro_normal_one(gro, skb, 1);
		break;

	case GRO_MERGED_FREE:
		if (NAPI_GRO_CB(skb)->free == NAPI_GRO_FREE_STOLEN_HEAD)
			napi_skb_free_stolen_head(skb);
		else if (skb->fclone != SKB_FCLONE_UNAVAILABLE)
			__kfree_skb(skb);
		else
			__napi_kfree_skb(skb, SKB_CONSUMED);
		break;

	case GRO_HELD:
	case GRO_MERGED:
	case GRO_CONSUMED:
		break;
	}

	return ret;
}

/* The kernel's own path for a packet from where gro_receive_skb() asks the extension */
static noinline gro_result_t rx_ext_none(struct gro_node *gro, struct sk_buff *skb)
{
	return rx_ext_gro_finish(gro, skb, rx_ext_gro_receive(gro, skb));
}

/*
 * An entry returned with its packet, which no code does that was loaded: one that GRO has
 * seen goes no second time, and one that it has not goes the kernel's way.
 */
static noinline void rx_ext_kept(struct rx_ext_cpu *cur)
{
	WARN_ON_ONCE(1);
	if (cur->pending)
		rx_ext_gro_finish(cur->gro, cur->skb, cur->ret);
	else if (cur->offered)
		gro_normal_one(cur->gro, cur->skb, 1);
	else
		cur->ret = rx_ext_none(cur->gro, cur->skb);
	cur->ctx = RX_EXT_DONE;
}

static __always_inline gro_result_t __rx_ext_arrive(struct rx_ext_cpu *cur, struct gro_node *gro,
						    struct sk_buff *skb)
{
	gro_result_t ret;

	rx_ext_begin(cur, RX_EXT_ARRIVE, false);
	cur->gro = gro;
	cur->skb = skb;
	cur->ret = GRO_NORMAL;
	/* the context of a struct_ops program: the arguments of its member */
	static_call(rx_ext_arrive_call)(&cur->skb, rx_ext_prog->insnsi);
	if (unlikely(cur->ctx != RX_EXT_DONE))
		rx_ext_kept(cur);
	ret = cur->ret;
	barrier();
	cur->ctx = RX_EXT_NONE;
	return ret;
}

/*
 * An entry inside one that is on this CPU already, which called the kernel, or was
 * interrupted by code that polls: what that one has is put back, in one piece.
 */
static noinline gro_result_t rx_ext_arrive_nested(struct gro_node *gro, struct sk_buff *skb)
{
	struct rx_ext_cpu *cur = this_cpu_ptr(&rx_ext_cpu), saved = *cur;
	unsigned long flags;
	gro_result_t ret;

	cur->ctx = RX_EXT_NONE;
	ret = __rx_ext_arrive(cur, gro, skb);
	local_irq_save(flags);
	*cur = saved;
	local_irq_restore(flags);
	return ret;
}

/**
 * rx_ext_arrive - a packet arrives at a node while an extension is attached
 * @gro: the node
 * @skb: the packet, as gro_receive_skb() has it for dev_gro_receive()
 *
 * The extension is the path of the packet from here, where the node has one: the node of a
 * NAPI of the device that it is attached to. A node of its own, which has no id, is no
 * NAPI's. Returns what gro_receive_skb() returns for the packet.
 */
gro_result_t rx_ext_arrive(struct gro_node *gro, struct sk_buff *skb)
{
	struct rx_ext_cpu *cur = this_cpu_ptr(&rx_ext_cpu);

	/* bottom halves are off: a read section that rx_ext_detach() waits for */
	if (unlikely(!gro->cached_napi_id || !READ_ONCE(gro_napi(gro)->bpf_rx) ||
		     !rcu_dereference_sched(rx_ext_ops)))
		return rx_ext_none(gro, skb);
	/* nothing of the extension is on this CPU as a rule, and then nothing to put back */
	if (unlikely(cur->ctx != RX_EXT_NONE))
		return rx_ext_arrive_nested(gro, skb);
	return __rx_ext_arrive(cur, gro, skb);
}

/**
 * rx_ext_resume - the packet that GRO held goes on in its continuation, in gro_complete()
 * @gro: the node that held it
 * @skb: the packet, off the list of the node, with a frame suspended in its head
 *
 * Returns false if nothing put the packet on the batch: the kernel does.
 */
static __always_inline bool __rx_ext_resume(struct rx_ext_cpu *cur, struct gro_node *gro,
					    struct sk_buff *skb, u8 ctx)
{
	bool done;

	rx_ext_begin(cur, ctx, true);
	cur->gro = gro;
	cur->skb = skb;
	bpf_coro_run_bh(rx_ext_prog, skb->head);
	done = cur->ctx == RX_EXT_DONE;
	barrier();
	cur->ctx = RX_EXT_NONE;
	return done;
}

/* A flush inside bpf_rx_gro() or bpf_rx_offer() for another packet, as a rule */
static noinline bool rx_ext_resume_nested(struct gro_node *gro, struct sk_buff *skb, u8 ctx)
{
	struct rx_ext_cpu *cur = this_cpu_ptr(&rx_ext_cpu), saved = *cur;
	unsigned long flags;
	bool done;

	cur->ctx = RX_EXT_NONE;
	done = __rx_ext_resume(cur, gro, skb, ctx);
	local_irq_save(flags);
	*cur = saved;
	local_irq_restore(flags);
	return done;
}

bool rx_ext_resume(struct gro_node *gro, struct sk_buff *skb)
{
	struct rx_ext_cpu *cur = this_cpu_ptr(&rx_ext_cpu);

	/* the frame is of this attachment, see rx_ext_held(), unless that is gone */
	if (unlikely(!rcu_dereference_sched(rx_ext_ops)))
		return false;
	if (cur->ctx != RX_EXT_NONE)
		return rx_ext_resume_nested(gro, skb, RX_EXT_RESUME);
	return __rx_ext_resume(cur, gro, skb, RX_EXT_RESUME);
}

/**
 * rx_ext_deliver - a packet that waited in a backlog goes on in its continuation
 * @skb: the packet, off the queue, which says that an extension put it there
 *
 * Returns false if nothing handed the packet to the stack: process_backlog() does. That is
 * the case of a packet whose extension is gone.
 */
bool rx_ext_deliver(struct sk_buff *skb)
{
	struct rx_ext_cpu *cur = this_cpu_ptr(&rx_ext_cpu);
	u32 gen = RX_EXT_CB(skb)->gen;

	/* the control block is the stack's from here on */
	RX_EXT_CB(skb)->owner = NULL;
	if (unlikely(!rcu_dereference_sched(rx_ext_ops)) || gen != READ_ONCE(rx_ext_gen))
		return false;
	if (unlikely(cur->ctx != RX_EXT_NONE))
		return rx_ext_resume_nested(NULL, skb, RX_EXT_BACKLOG);
	return __rx_ext_resume(cur, NULL, skb, RX_EXT_BACKLOG);
}

/*
 * @skb is held in @gro with a frame of the extension suspended in its head. The packets
 * that the node holds are marked one by one, and the mark means something only while the
 * node knows the attachment: frames of an extension that was here before, and whatever was
 * in the mark of a packet that was held with none attached, are nothing to this one. So
 * the first frame of an attachment in a node clears the marks that it finds there.
 */
static void rx_ext_hold(struct gro_node *gro, struct sk_buff *skb)
{
	struct napi_struct *napi = gro_napi(gro);
	u32 gen = READ_ONCE(rx_ext_gen);
	struct sk_buff *p;
	u32 i;

	if (unlikely(napi->bpf_held != gen)) {
		for (i = 0; i < GRO_HASH_BUCKETS; i++)
			list_for_each_entry(p, &gro->hash[i].list, list)
				NAPI_GRO_CB(p)->bpf_frame = 0;
		napi->bpf_held = gen;
	}
	NAPI_GRO_CB(skb)->bpf_frame = 1;
}

/* The word of state of a packet whose head lent a frame */
static u64 *rx_ext_state(const struct sk_buff *skb)
{
	return (u64 *)(skb->head + BPF_RX_FRAME);
}

/**
 * rx_ext_merge - GRO has merged a packet into one that it holds
 * @p: the packet that stays
 * @skb: the packet that is over as a unit
 *
 * The extension combines their state, if @skb is the packet that the code on this CPU is
 * offering, with a frame, and @p has a frame of this attachment suspended in it: both are
 * in the node that is polled. Then the two words are the extension's, see rx_ext_hold().
 * Returns 0, which is what its callers return.
 */
int rx_ext_merge(struct sk_buff *p, struct sk_buff *skb)
{
	struct rx_ext_cpu *cur = this_cpu_ptr(&rx_ext_cpu);
	u64 *into;

	if (cur->skb != skb || cur->ctx != RX_EXT_ARRIVE)
		return 0;
	if (!NAPI_GRO_CB(p)->bpf_frame || gro_napi(cur->gro)->bpf_held != READ_ONCE(rx_ext_gen))
		return 0;
	into = rx_ext_state(p);
	/* a packet that was offered with no frame has no word: 0 for it */
	*into = static_call(rx_ext_merge_call)(*into, cur->framed ? *rx_ext_state(skb) : 0);
	return 0;
}

/* Has the code on this CPU @skb in hand, in one of @ctxs, a mask? */
static __always_inline bool rx_ext_in(const struct rx_ext_cpu *cur, const struct sk_buff *skb,
				      u32 ctxs)
{
	return !WARN_ON_ONCE(cur->skb != skb || !(BIT(cur->ctx) & ctxs));
}

/*
 * The batch of the NAPI: with the segments that GRO counted for a packet that it flushes.
 * In process_backlog() there is no batch: the stack gets the packet, as it does there.
 */
static void rx_ext_batch(struct rx_ext_cpu *cur, struct sk_buff *skb)
{
	int segs = cur->ctx == RX_EXT_RESUME ? NAPI_GRO_CB(skb)->count : 1;
	struct gro_node *gro = cur->gro;

	/* GRO answered bpf_rx_offer(): what gro_receive_skb() does with the answer */
	if (cur->pending) {
		cur->pending = false;
		cur->ctx = RX_EXT_DONE;
		rx_ext_gro_finish(gro, skb, cur->ret);
		return;
	}
	cur->ret = GRO_NORMAL;
	cur->ctx = RX_EXT_DONE;
	if (gro)
		gro_normal_one(gro, skb, segs);
	else
		rx_ext_netif_receive_skb(skb);
}

/* The contexts in which the code has a packet in hand */
#define RX_EXT_HAS	(BIT(RX_EXT_ARRIVE) | BIT(RX_EXT_RESUME) | BIT(RX_EXT_BACKLOG))

__bpf_kfunc_start_defs();

/**
 * bpf_coro_frame_alloc_skb - the coroutine frame of a packet's path, in the head of the packet
 * @size__k: the size of the frame, which the verifier checked against BPF_RX_FRAME
 * @skb__coro_host: the packet that the extension was entered with
 *
 * The frame is the first bytes of the head, as they are, and is there for as long as the
 * code has the packet. Behind it is the packet's word of state, 0 from here on. Returns the frame, or NULL for a head that is shared with a clone
 * or that has the link layer header or metadata of the packet within those bytes.
 */
__bpf_kfunc void *bpf_coro_frame_alloc_skb(u64 size__k, struct sk_buff *skb__coro_host)
{
	struct rx_ext_cpu *cur = this_cpu_ptr(&rx_ext_cpu);
	struct sk_buff *skb = skb__coro_host;

	if (unlikely(!skb_mac_header_was_set(skb) || skb_cloned(skb) || skb_shared(skb) ||
		     skb->mac_header < BPF_RX_ROOM + skb_metadata_len(skb)))
		return NULL;
	if (WARN_ON_ONCE(cur->skb != skb))
		return NULL;
	cur->framed = true;
	*rx_ext_state(skb) = 0;
	return skb->head;
}

/**
 * bpf_rx_set_state - set the word of state of a packet
 * @skb: the packet that the caller owns, with a frame
 * @state: what a merge() of the extension combines where GRO merges packets
 *
 * The word is 0 for a packet whose frame is new. Nothing for a packet with no frame.
 */
__bpf_kfunc void bpf_rx_set_state(struct sk_buff *skb, u64 state)
{
	struct rx_ext_cpu *cur = this_cpu_ptr(&rx_ext_cpu);

	if (cur->skb == skb && cur->framed)
		*rx_ext_state(skb) = state;
}

/**
 * bpf_rx_state - the word of state of a packet
 * @skb: the packet that the caller owns, with a frame
 *
 * In the continuation of a packet that GRO held: what the merge() of the extension made of
 * it and of the packets that were merged into it. 0 for a packet with no frame.
 */
__bpf_kfunc u64 bpf_rx_state(struct sk_buff *skb)
{
	struct rx_ext_cpu *cur = this_cpu_ptr(&rx_ext_cpu);

	return cur->skb == skb && cur->framed ? *rx_ext_state(skb) : 0;
}

/**
 * bpf_rx_gro - offer a packet to GRO
 * @frame__coro_offer: the frame of the packet's path, from bpf_coro_frame_alloc_skb(), with
 *	the packet in one of its slots
 *
 * dev_gro_receive() as a boundary. Returns true where GRO has the packet: merged into one
 * that it holds, and then the frame is over with the packet; or held, and then
 * gro_complete() resumes the continuation with the packet that is flushed, which stands for
 * all that were merged into it. Returns false where GRO has no use for the packet, and
 * for one that it has seen: the code goes on with packet and frame.
 */
__bpf_kfunc bool bpf_rx_gro(void *frame__coro_offer)
{
	struct rx_ext_cpu *cur = this_cpu_ptr(&rx_ext_cpu);
	struct gro_node *gro = cur->gro;
	struct sk_buff *skb = cur->skb;
	enum gro_result ret;

	if (WARN_ON_ONCE(cur->ctx != RX_EXT_ARRIVE || skb->head != frame__coro_offer) ||
	    cur->offered)
		return false;
	cur->offered = true;
	ret = rx_ext_gro_receive(gro, skb);
	/* the same CPU, and what GRO flushed and resumed on the way has put @cur back */
	if (ret == GRO_NORMAL)
		return false;
	if (ret == GRO_HELD)
		rx_ext_hold(gro, skb);
	cur->ret = rx_ext_gro_finish(gro, skb, ret);
	cur->ctx = RX_EXT_DONE;
	return true;
}

/**
 * bpf_rx_offer - offer a packet to GRO with no frame
 * @skb: the packet that arrive() was entered with
 *
 * dev_gro_receive() for code that has written nothing yet: most packets are merged into
 * another or of no use to GRO, and their path needs no frame. Returns GRO's answer, an enum
 * gro_result: GRO_NORMAL where GRO has no use for the packet, GRO_HELD where it holds the
 * packet, and any other where the packet is part of another one now. The code has the
 * packet still in each case, and the answer is seen through where it gives the packet up:
 * bpf_rx_batch() puts a packet of no use to GRO on the batch and lets the others be, as
 * gro_receive_skb() does. Behind GRO_HELD the code can take a frame and stay with the
 * packet: bpf_rx_hold(). A second offer is none, and returns GRO_NORMAL.
 */
__bpf_kfunc u32 bpf_rx_offer(struct sk_buff *skb)
{
	struct rx_ext_cpu *cur = this_cpu_ptr(&rx_ext_cpu);
	struct gro_node *gro = cur->gro;
	enum gro_result ret;

	if (WARN_ON_ONCE(cur->skb != skb || cur->ctx != RX_EXT_ARRIVE) || cur->offered)
		return GRO_NORMAL;
	cur->offered = true;
	ret = rx_ext_gro_receive(gro, skb);
	/* the same CPU, and what GRO flushed and resumed on the way has put @cur back */
	cur->ret = ret;
	cur->pending = true;
	return ret;
}

/**
 * bpf_rx_pass - leave a packet to GRO, unless GRO holds it
 * @skb__offer: the packet that arrive() was entered with
 *
 * bpf_rx_offer() and, for a packet that GRO does not hold, bpf_rx_batch() in one: what most
 * packets of a stream need, which are merged into one that GRO holds, and what a packet
 * needs that GRO has no use for. Returns true for those: the packet is no longer the
 * code's. Returns false for a packet that GRO holds, and for one that GRO has seen before:
 * the code has it still, and can take a frame and stay with it, bpf_rx_hold(), or give it
 * up, which leaves it to GRO's flush.
 */
__bpf_kfunc bool bpf_rx_pass(struct sk_buff *skb__offer)
{
	struct rx_ext_cpu *cur = this_cpu_ptr(&rx_ext_cpu);
	struct sk_buff *skb = skb__offer;
	struct gro_node *gro = cur->gro;
	enum gro_result ret;

	if (WARN_ON_ONCE(cur->skb != skb || cur->ctx != RX_EXT_ARRIVE) || cur->offered)
		return false;
	cur->offered = true;
	ret = rx_ext_gro_receive(gro, skb);
	cur->ret = ret;
	if (ret == GRO_HELD) {
		cur->pending = true;
		return false;
	}
	cur->ctx = RX_EXT_DONE;
	rx_ext_gro_finish(gro, skb, ret);
	return true;
}

/**
 * bpf_rx_hold - stay with a packet that GRO holds
 * @frame__coro_offer: the frame of the packet's path, from bpf_coro_frame_alloc_skb(), with
 *	the packet in one of its slots
 *
 * Behind bpf_rx_offer() that returned GRO_HELD: the frame is suspended in the head of
 * the packet, and gro_complete() resumes the continuation with the packet that is flushed,
 * as for bpf_rx_gro(). Returns true then. Returns false for a packet that GRO does not hold
 * for this code: it goes on with packet and frame.
 */
__bpf_kfunc bool bpf_rx_hold(void *frame__coro_offer)
{
	struct rx_ext_cpu *cur = this_cpu_ptr(&rx_ext_cpu);
	struct sk_buff *skb = cur->skb;

	if (WARN_ON_ONCE(cur->ctx != RX_EXT_ARRIVE || skb->head != frame__coro_offer))
		return false;
	if (!cur->pending || cur->ret != GRO_HELD)
		return false;
	rx_ext_hold(cur->gro, skb);
	cur->pending = false;
	cur->ctx = RX_EXT_DONE;
	return true;
}

/**
 * bpf_rx_backlog - offer a packet to the backlog of a CPU
 * @frame__coro_offer: the frame of the packet's path, with the packet in one of its slots
 * @cpu: the CPU
 *
 * The step that RPS is, as a boundary. Returns true where the queue took the packet:
 * process_backlog() resumes the continuation on that CPU, in softirq. Returns false where
 * it did not, because it is full, the CPU is not there or the device is down: the code goes
 * on with packet and frame. A queue that fills between the look at it and the packet, and
 * the limit on a flow where the administrator set one, drop the packet as they do of RPS.
 */
__bpf_kfunc bool bpf_rx_backlog(void *frame__coro_offer, u32 cpu)
{
	struct rx_ext_cpu *cur = this_cpu_ptr(&rx_ext_cpu);
	struct sk_buff *skb = cur->skb;

	if (WARN_ON_ONCE(!(BIT(cur->ctx) & RX_EXT_HAS) || skb->head != frame__coro_offer))
		return false;
	if (cpu >= nr_cpu_ids || !cpu_online(cpu))
		return false;
	/* only a packet that is the code's alone: not one that GRO has, behind bpf_rx_offer() */
	if (cur->pending) {
		if (cur->ret != GRO_NORMAL)
			return false;
		cur->pending = false;
	}
	/* the queue's while the packet waits, and how process_backlog() knows */
	RX_EXT_CB(skb)->owner = &rx_ext_gen;
	RX_EXT_CB(skb)->gen = READ_ONCE(rx_ext_gen);
	if (!backlog_enqueue(skb, cpu)) {
		RX_EXT_CB(skb)->owner = NULL;
		return false;
	}
	/* the packet may be on its way on that CPU: nothing of it from here on */
	cur->ret = GRO_NORMAL;
	cur->ctx = RX_EXT_DONE;
	return true;
}

/**
 * bpf_rx_deliver - hand a packet to the stack
 * @skb: the packet, which the caller owns
 *
 * __netif_receive_skb() for the continuation of a packet that waited in a backlog, the end
 * of the unit and of its frame. In the poll of a NAPI, where the kernel delivers by the
 * batch, it is the batch.
 */
__bpf_kfunc void bpf_rx_deliver(struct sk_buff *skb)
{
	struct rx_ext_cpu *cur = this_cpu_ptr(&rx_ext_cpu);

	if (rx_ext_in(cur, skb, RX_EXT_HAS))
		rx_ext_batch(cur, skb);
}

/**
 * bpf_rx_native - leave a packet to the kernel
 * @skb: the packet, which the caller owns: arrive(), or the continuation of a packet that
 *	GRO held
 *
 * The kernel's own remainder of the path, with no frame: GRO and what follows from it for a
 * packet that GRO has not seen, the batch for one that it has.
 */
__bpf_kfunc void bpf_rx_native(struct sk_buff *skb)
{
	struct rx_ext_cpu *cur = this_cpu_ptr(&rx_ext_cpu);
	struct gro_node *gro;

	if (!rx_ext_in(cur, skb, RX_EXT_HAS))
		return;
	if (cur->offered) {
		rx_ext_batch(cur, skb);
		return;
	}
	gro = cur->gro;
	cur->offered = true;
	cur->ctx = RX_EXT_DONE;
	cur->ret = rx_ext_gro_finish(gro, skb, rx_ext_gro_receive(gro, skb));
}

/**
 * bpf_rx_batch - put a packet on the batch of its NAPI
 * @skb: the packet, as for bpf_rx_native()
 *
 * gro_normal_one(), the end of the unit and of its frame: the kernel delivers the batch as
 * a list. A packet that GRO has not seen goes past GRO. In process_backlog(), where there
 * is no batch, the stack gets the packet. The landing pads of the extension call this,
 * bpf_rx_deliver() or bpf_rx_native(), whichever btf_find_release_kfunc() finds first: each
 * ends the unit wherever it is.
 */
__bpf_kfunc void bpf_rx_batch(struct sk_buff *skb)
{
	struct rx_ext_cpu *cur = this_cpu_ptr(&rx_ext_cpu);

	if (rx_ext_in(cur, skb, RX_EXT_HAS))
		rx_ext_batch(cur, skb);
}

__bpf_kfunc_end_defs();

static int bpf_rx_ops__arrive(struct sk_buff *skb__ref)
{
	return 0;
}

static u64 bpf_rx_ops__merge(u64 into, u64 from)
{
	return into;
}

static struct bpf_rx_ops __bpf_rx_ops_stubs = {
	.arrive = (void *)bpf_rx_ops__arrive,
	.merge = bpf_rx_ops__merge,
};

static struct bpf_struct_ops bpf_bpf_rx_ops;

BTF_KFUNCS_START(rx_ext_kfunc_ids)
BTF_ID_FLAGS(func, bpf_coro_frame_alloc_skb, KF_ACQUIRE | KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_rx_set_state)
BTF_ID_FLAGS(func, bpf_rx_state)
BTF_ID_FLAGS(func, bpf_rx_gro)
BTF_ID_FLAGS(func, bpf_rx_offer)
BTF_ID_FLAGS(func, bpf_rx_hold)
BTF_ID_FLAGS(func, bpf_rx_pass)
BTF_ID_FLAGS(func, bpf_rx_backlog)
BTF_ID_FLAGS(func, bpf_rx_native, KF_RELEASE)
BTF_ID_FLAGS(func, bpf_rx_batch, KF_RELEASE)
BTF_ID_FLAGS(func, bpf_rx_deliver, KF_RELEASE)
BTF_KFUNCS_END(rx_ext_kfunc_ids)

/* what a continuation calls: code that gro_complete() or process_backlog() resumes */
BTF_KFUNCS_START(rx_ext_cont_kfunc_ids)
BTF_ID_FLAGS(func, bpf_rx_set_state)
BTF_ID_FLAGS(func, bpf_rx_state)
BTF_ID_FLAGS(func, bpf_rx_backlog)
BTF_ID_FLAGS(func, bpf_rx_native, KF_RELEASE)
BTF_ID_FLAGS(func, bpf_rx_batch, KF_RELEASE)
BTF_ID_FLAGS(func, bpf_rx_deliver, KF_RELEASE)
BTF_KFUNCS_END(rx_ext_cont_kfunc_ids)

BTF_ID_LIST(rx_ext_ids)
BTF_ID(func, bpf_coro_frame_alloc_skb)
BTF_ID(func, bpf_rx_gro)
BTF_ID(func, bpf_rx_offer)
BTF_ID(func, bpf_rx_hold)
BTF_ID(func, bpf_rx_pass)

/* A continuation has its frame, and its packet has been through GRO. */
static int rx_ext_kfunc_filter(const struct bpf_prog *prog, u32 kfunc_id)
{
	if (!btf_id_set8_contains(&rx_ext_kfunc_ids, kfunc_id))
		return 0;
	if (prog->aux->st_ops != &bpf_bpf_rx_ops)
		return -EACCES;
	if (prog->type != BPF_PROG_TYPE_STRUCT_OPS)
		return kfunc_id == rx_ext_ids[0] || kfunc_id == rx_ext_ids[1] ||
		       kfunc_id == rx_ext_ids[2] || kfunc_id == rx_ext_ids[3] ||
		       kfunc_id == rx_ext_ids[4] ? -EACCES : 0;
	return prog->aux->attach_st_ops_member_off == offsetof(struct bpf_rx_ops, arrive) ?
	       0 : -EACCES;
}

static const struct btf_kfunc_id_set rx_ext_kfunc_set = {
	.owner = THIS_MODULE,
	.set = &rx_ext_kfunc_ids,
	.filter = rx_ext_kfunc_filter,
};

static const struct btf_kfunc_id_set rx_ext_cont_kfunc_set = {
	.owner = THIS_MODULE,
	.set = &rx_ext_cont_kfunc_ids,
	.filter = rx_ext_kfunc_filter,
};

static int bpf_rx_ops_init_member(const struct btf_type *t, const struct btf_member *member,
				  void *kdata, const void *udata)
{
	const struct bpf_rx_ops *uops = udata;
	struct bpf_rx_ops *ops = kdata;

	switch (__btf_member_bit_offset(t, member) / 8) {
	case offsetof(struct bpf_rx_ops, ifindex):
		ops->ifindex = uops->ifindex;
		return 1;
	case offsetof(struct bpf_rx_ops, flags):
		if (uops->flags)
			return -EINVAL;
		return 1;
	}
	return 0;
}

static int bpf_rx_ops_validate(void *kdata)
{
	struct bpf_rx_ops *ops = kdata;

	return ops->arrive && ops->ifindex ? 0 : -EINVAL;
}

/* No code of the extension runs, and none begins: its calls are what they were with none */
static void rx_ext_calls_off(void)
{
	static_call_update(rx_ext_arrive_call, rx_ext_no_arrive);
	if (static_key_enabled(&rx_ext_merge_key)) {
		static_branch_disable(&rx_ext_merge_key);
		static_call_update(rx_ext_merge_call, rx_ext_no_merge);
	}
}

/* Take the extension off its device. With napi_ext_mutex. */
static void rx_ext_detach(void)
{
	struct net_device *dev = rx_ext_dev;
	struct napi_struct *napi;

	if (!dev)
		return;
	netdev_lock(dev);
	WRITE_ONCE(rx_ext_dev, NULL);
	list_for_each_entry(napi, &dev->napi_list, dev_list)
		WRITE_ONCE(napi->bpf_rx, 0);
	netdev_unlock(dev);
	rcu_assign_pointer(rx_ext_ops, NULL);
	/*
	 * No entry and no continuation runs any more, and none begins. The frames that are
	 * suspended in held packets are forgotten where they are: each packet is the kernel's
	 * at its flush, and the next attachment is another one to the nodes, see rx_ext_hold().
	 */
	synchronize_rcu();
	rx_ext_calls_off();
	static_branch_dec(&rx_ext_key);
	netdev_put(dev, &rx_ext_dev_tracker);
}

static int bpf_rx_ops_reg(void *kdata, struct bpf_link *link)
{
	struct bpf_rx_ops *ops = kdata;
	struct napi_struct *napi;
	struct net_device *dev;
	int err = 0;

	mutex_lock(&napi_ext_mutex);
	if (rcu_access_pointer(rx_ext_ops)) {
		err = -EBUSY;
		goto out;
	}
	dev = netdev_get_by_index(current->nsproxy->net_ns, ops->ifindex, &rx_ext_dev_tracker,
				  GFP_KERNEL);
	if (!dev) {
		err = -ENODEV;
		goto out;
	}
	/* before a packet can enter */
	bpf_struct_ops_for_each_prog(kdata, napi_ext_first_prog, &rx_ext_prog);
	static_call_update(rx_ext_arrive_call, rx_ext_prog->bpf_func);
	if (ops->merge) {
		static_call_update(rx_ext_merge_call, ops->merge);
		static_branch_enable(&rx_ext_merge_key);
	}
	WRITE_ONCE(rx_ext_gen, rx_ext_gen + 1 ?: 1);
	static_branch_inc(&rx_ext_key);
	rcu_assign_pointer(rx_ext_ops, ops);
	netdev_lock(dev);
	if (dev->reg_state != NETREG_REGISTERED) {
		err = -ENODEV;
	} else {
		WRITE_ONCE(rx_ext_dev, dev);
		list_for_each_entry(napi, &dev->napi_list, dev_list)
			WRITE_ONCE(napi->bpf_rx, 1);
	}
	netdev_unlock(dev);
	if (err) {
		rcu_assign_pointer(rx_ext_ops, NULL);
		synchronize_rcu();
		rx_ext_calls_off();
		static_branch_dec(&rx_ext_key);
		netdev_put(dev, &rx_ext_dev_tracker);
	}
out:
	mutex_unlock(&napi_ext_mutex);
	return err;
}

static void bpf_rx_ops_unreg(void *kdata, struct bpf_link *link)
{
	mutex_lock(&napi_ext_mutex);
	if (rcu_access_pointer(rx_ext_ops) == kdata)
		rx_ext_detach();
	mutex_unlock(&napi_ext_mutex);
}

static struct bpf_struct_ops bpf_bpf_rx_ops = {
	.verifier_ops = &bpf_napi_verifier_ops,
	.reg = bpf_rx_ops_reg,
	.unreg = bpf_rx_ops_unreg,
	.validate = bpf_rx_ops_validate,
	.init_member = bpf_rx_ops_init_member,
	.init = bpf_napi_ops_init,
	.name = "bpf_rx_ops",
	.cfi_stubs = &__bpf_rx_ops_stubs,
	.owner = THIS_MODULE,
};

static int __init rx_ext_init(void)
{
	int ret;

	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_STRUCT_OPS, &rx_ext_kfunc_set);
	ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP, &rx_ext_cont_kfunc_set);
	ret = ret ?: bpf_coro_register_bare_host(rx_ext_ids[0], BPF_RX_FRAME);
	return ret ?: register_bpf_struct_ops(&bpf_bpf_rx_ops, bpf_rx_ops);
}
late_initcall(rx_ext_init);
#endif /* CONFIG_BPF_JIT */
