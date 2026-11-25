// SPDX-License-Identifier: GPL-2.0
/*
 * BPF coroutine frames, and their resumption from the kernel; see include/linux/bpf_coro.h.
 */
#include <linux/bpf.h>
#include <linux/bpf_coro.h>
#include <linux/bpf_unwind.h>
#include <linux/btf.h>
#include <linux/filter.h>
#include <linux/irq_work.h>
#include <linux/llist.h>
#include <linux/preempt.h>
#include <linux/rcupdate.h>
#include <linux/rcupdate_trace.h>
#include <linux/slab.h>
#include <linux/workqueue.h>

/*
 * In front of every frame. The program gets the address behind it: the verifier bounds the
 * accesses through a PTR_TO_CORO_FRAME by the frame, and passes only the start of the frame
 * to a __coro_frame argument. The header is a multiple of 8 bytes, where a pointer has 4 too,
 * and kmalloc aligns the allocation to ARCH_KMALLOC_MINALIGN, 8 bytes at least on the
 * architectures whose JITs call kfuncs: the frame has the 8-byte alignment that the accesses
 * of the program need.
 */
struct bpf_coro_frame_hdr {
	/* the program that allocated the frame, which the frame holds a reference on */
	struct bpf_prog *prog;
	/* a parked frame that the kernel is to destroy, see bpf_coro_drop() */
	struct llist_node drop;
} __aligned(8);

static_assert(sizeof(struct bpf_coro_frame_hdr) % sizeof(u64) == 0);

static struct bpf_coro_frame_hdr *bpf_coro_frame_hdr(void *frame)
{
	return frame - sizeof(struct bpf_coro_frame_hdr);
}

/*
 * The frames that hold the last reference on their program. bpf_prog_put() frees the
 * program then, which takes locks and queues work: a program in NMI, or one that traces the
 * code holding such a lock, may do neither. irq_work does it in their place. Such a frame is
 * dead, and its first 8 bytes link it into the list, see bpf_coro_frame_alloc().
 */
struct bpf_coro_free_list {
	struct llist_head frames;
	struct irq_work work;
};

static void bpf_coro_free_deferred(struct irq_work *work)
{
	struct bpf_coro_free_list *list = container_of(work, struct bpf_coro_free_list, work);
	struct llist_node *node, *next;
	struct bpf_coro_frame_hdr *hdr;

	llist_for_each_safe(node, next, llist_del_all(&list->frames)) {
		hdr = bpf_coro_frame_hdr(node);
		bpf_prog_put(hdr->prog);
		kfree_nolock(hdr);
	}
}

static DEFINE_PER_CPU(struct bpf_coro_free_list, bpf_coro_free_lists) = {
	.frames = LLIST_HEAD_INIT(frames),
	.work = IRQ_WORK_INIT(bpf_coro_free_deferred),
};

__bpf_kfunc_start_defs();

/*
 * Coroutine frames are heap memory whose contents the verifier tracks slot by slot like the
 * program stack, see PTR_TO_CORO_FRAME. The size is a verifier-checked constant, so the
 * allocation and the tracked size agree, except that a frame has room for the llist_node of
 * its free. The frame holds a reference on the program: a program whose last reference is
 * gone, and which only runs until a grace period ends, gets no frame.
 */
__bpf_kfunc void *bpf_coro_frame_alloc(u64 size__k, void *ctx__ign, struct bpf_prog_aux *aux)
{
	struct bpf_coro_frame_hdr *hdr;
	struct bpf_prog *prog;

	hdr = kmalloc_nolock(sizeof(*hdr) + max_t(u64, size__k, sizeof(struct llist_node)),
			     __GFP_ACCOUNT, NUMA_NO_NODE);
	if (!hdr)
		return NULL;
	prog = bpf_prog_inc_not_zero(aux->prog);
	if (IS_ERR(prog)) {
		kfree_nolock(hdr);
		return NULL;
	}
	hdr->prog = prog;
	return hdr + 1;
}

/*
 * Free a frame and drop its reference on the program. It is the kfunc, and what kernel code
 * frees a frame with: it may be called in any context.
 */
__bpf_kfunc void bpf_coro_frame_free(void *p__coro_frame)
{
	struct bpf_coro_frame_hdr *hdr = bpf_coro_frame_hdr(p__coro_frame);
	struct bpf_coro_free_list *list;

	/* Not the last reference: the program stays, and the memory goes at once. */
	if (atomic64_add_unless(&hdr->prog->aux->refcnt, -1, 1)) {
		kfree_nolock(hdr);
		return;
	}
	/* The work frees what is on its own list, so the list of any CPU will do. */
	list = raw_cpu_ptr(&bpf_coro_free_lists);
	llist_add(p__coro_frame, &list->frames);
	irq_work_queue(&list->work);
}
EXPORT_SYMBOL_GPL(bpf_coro_frame_free);

__bpf_kfunc_end_defs();

/* The task that runs bpf_coro_run() on this CPU at each context level, see bpf_coro_run(). */
struct bpf_coro_runners {
	struct task_struct *task[4];
};

static DEFINE_PER_CPU(struct bpf_coro_runners, bpf_coro_runners);

/*
 * Like interrupt_context_level(), but on PREEMPT_RT too, where softirqs are served in task
 * context and preempt_count() doesn't tell.
 */
static int bpf_coro_run_level(void)
{
	if (in_nmi())
		return 3;
	if (in_hardirq())
		return 2;
	return in_serving_softirq() ? 1 : 0;
}

/*
 * Resume the coroutine of @frame: call the resume function in its first slot with the frame
 * as its argument. It is a subprogram of the program that the frame holds a reference on, and
 * runs like any invocation of the program, under RCU with migration disabled, in a context
 * where the kfuncs of the program type are valid, which the caller sees to. Like the call of
 * any async callback it is an invocation of its own for the time of may_goto, see
 * bpf_timed_may_goto_save().
 *
 * It is never called inside an invocation of a program, from a kfunc that the program calls:
 * a continuation that suspends its frame again to such a kfunc would nest without bound. Where
 * that happens the same task is in here twice at the same context level of the CPU. The
 * warning catches that much, see bpf_coro_runners: not a kfunc that resumes a frame in the
 * call of a program that no bpf_coro_run() entered, nor one that nests while another task's
 * call of this CPU, which was preempted, holds the task level.
 *
 * The continuation owns the frame and may free it, and with it the reference that keeps the
 * program loaded. A program is freed after a grace period of RCU, or of RCU Tasks Trace if it
 * runs sleepable, see __bpf_prog_put_noref(): the call and what follows it here are in a read
 * section of the one that applies.
 *
 * The call has a landing pad, like the call of a helper whose callback may unwind, see
 * bpf_call_cb(). The verifier has a continuation leave with kexit when the kernel unwinds it,
 * see push_coro_suspend(), and kexit returns here, behind the label: the pads of the program
 * have released what the continuation held. Nothing on the way to it says who is told, so this
 * tells a struct_ops, as bpf_prog_unwound_to_kernel() would where kexit finds no landing pad.
 * unwind_exit of the program comes to the label too: the continuation did not return either,
 * and nobody else is told, as where such a frame returns into the kernel.
 *
 * Returns true when the continuation did not return: the kernel unwound it, or the program's
 * own unwinding left it. The kfunc can react, by closing a connection or waking a waiter, say.
 */
static noinline bool __bpf_coro_run(void *frame, int slot)
{
	struct bpf_prog *prog = bpf_coro_frame_hdr(frame)->prog;
	bpf_callback_t resume = READ_ONCE(((bpf_callback_t *)frame)[slot]);
	bool sleepable = bpf_prog_runs_sleepable(prog);
	struct bpf_timed_may_goto saved;
	struct task_struct *runner;
	bool unwound = false;
	u64 ret, kind;
	int level;

	if (sleepable)
		rcu_read_lock_trace();
	rcu_read_lock();
	migrate_disable();
	level = bpf_coro_run_level();
	runner = this_cpu_cmpxchg(bpf_coro_runners.task[level], NULL, current);
	WARN_ONCE(runner == current, "bpf_coro_run() inside a BPF program\n");
	bpf_timed_may_goto_save(prog, &saved);
	bpf_call_cb(resume, frame, 0, 0, 0, 0, ret, kind, left);
	goto done;
left:
	unwound = true;
	if (kind)
		bpf_prog_unwound_to_kernel((unsigned long)resume);
done:
	bpf_timed_may_goto_restore(prog, &saved);
	if (!runner)
		this_cpu_write(bpf_coro_runners.task[level], NULL);
	migrate_enable();
	rcu_read_unlock();
	if (sleepable)
		rcu_read_unlock_trace();
	return unwound;
}

bool bpf_coro_run(void *frame)
{
	return __bpf_coro_run(frame, 0);
}
EXPORT_SYMBOL_GPL(bpf_coro_run);

/*
 * Parked frames.
 *
 * bpf_coro_park_xdp() and bpf_coro_park_syscall() suspend a coroutine like a kfunc that keeps
 * the frame, and give the frame back to the program, as a pointer that it owns and can only
 * move: into a kptr field of a map value or of an allocated object, and out of it again with
 * bpf_kptr_xchg(). The kernel resumes no such frame. A program does, when it has the pointer:
 * it loads the resume function from the first slot of the frame, or the destroy function from
 * the second one, and calls it with the frame, see check_coro_callx(). No kernel code is on
 * that way, so the continuation was verified for the context that calls it: the kfunc names
 * the type of program whose context that is, the continuation is verified as code of such a
 * program from the suspension on, and the type of the pointer says so to whoever holds it.
 *
 * Where no program calls the destroy function the kernel does: bpf_coro_drop_xdp() and
 * bpf_coro_drop_syscall() for a program that is not of the type the frame was parked for, or
 * that a landing pad stands in for, and the destructors of the kptr fields when a map or an
 * object goes with a frame in it. That may be in any context, so the frame waits on a list of
 * the CPU for a work item in a context of the type: softirq with a network context for XDP,
 * a kernel thread for a syscall program.
 */
struct bpf_coro_xdp {
};

struct bpf_coro_syscall {
};

struct bpf_coro_drops {
	struct llist_head frames;
	struct irq_work irq_work;
	struct work_struct work;
	bool net;
};

static void bpf_coro_drop_work(struct work_struct *work)
{
	struct bpf_coro_drops *drops = container_of(work, struct bpf_coro_drops, work);
	struct bpf_net_context net_ctx, *net = NULL;
	struct llist_node *node, *next;

	llist_for_each_safe(node, next, llist_del_all(&drops->frames)) {
		void *frame = container_of(node, struct bpf_coro_frame_hdr, drop) + 1;

		if (drops->net) {
			local_bh_disable();
			net = bpf_net_ctx_set(&net_ctx);
		}
		/* The destroy function frees the frame, also when the kernel unwinds it. */
		__bpf_coro_run(frame, 1);
		if (drops->net) {
			bpf_net_ctx_clear(net);
			local_bh_enable();
		}
	}
}

/* Queueing work takes locks: not where the frame is dropped, which may be NMI. */
static void bpf_coro_drop_irq_work(struct irq_work *irq_work)
{
	struct bpf_coro_drops *drops = container_of(irq_work, struct bpf_coro_drops, irq_work);

	queue_work(drops->net ? system_bh_wq : system_percpu_wq, &drops->work);
}

static DEFINE_PER_CPU(struct bpf_coro_drops, bpf_coro_drops_xdp) = {
	.frames = LLIST_HEAD_INIT(frames),
	.irq_work = IRQ_WORK_INIT(bpf_coro_drop_irq_work),
	.net = true,
};

static DEFINE_PER_CPU(struct bpf_coro_drops, bpf_coro_drops_syscall) = {
	.frames = LLIST_HEAD_INIT(frames),
	.irq_work = IRQ_WORK_INIT(bpf_coro_drop_irq_work),
};

static void bpf_coro_drop(void *frame, struct bpf_coro_drops *drops)
{
	llist_add(&bpf_coro_frame_hdr(frame)->drop, &drops->frames);
	irq_work_queue(&drops->irq_work);
}

__bpf_kfunc_start_defs();

/**
 * bpf_coro_park_xdp - suspend a coroutine for an XDP program to resume
 * @frame__coro_suspend: the frame
 *
 * The frame is the program's again, as a pointer that it can keep in a kptr field. The resume
 * and the destroy function in its first two slots are verified as code of an XDP program from
 * here on, whatever program this is, and an XDP program that holds the pointer calls them.
 */
__bpf_kfunc struct bpf_coro_xdp *bpf_coro_park_xdp(void *frame__coro_suspend)
{
	return frame__coro_suspend;
}

/**
 * bpf_coro_park_syscall - suspend a coroutine for a syscall program to resume
 * @frame__coro_suspend: the frame
 *
 * Like bpf_coro_park_xdp(), for a syscall program and the kernel threads that it runs.
 */
__bpf_kfunc struct bpf_coro_syscall *bpf_coro_park_syscall(void *frame__coro_suspend)
{
	return frame__coro_suspend;
}

/**
 * bpf_coro_drop_xdp - have the kernel destroy a parked coroutine
 * @coro: the frame
 *
 * The destroy function of the frame runs soon, in softirq context. It takes the frame alone
 * and is KF_RELEASE with no other flag: a landing pad calls it too.
 */
__bpf_kfunc void bpf_coro_drop_xdp(struct bpf_coro_xdp *coro)
{
	bpf_coro_drop(coro, this_cpu_ptr(&bpf_coro_drops_xdp));
}

/**
 * bpf_coro_drop_syscall - have the kernel destroy a parked coroutine
 * @coro: the frame
 *
 * Like bpf_coro_drop_xdp(); the destroy function runs in a kernel thread.
 */
__bpf_kfunc void bpf_coro_drop_syscall(struct bpf_coro_syscall *coro)
{
	bpf_coro_drop(coro, this_cpu_ptr(&bpf_coro_drops_syscall));
}

/* The destructors of kptr fields that hold a parked frame */
__bpf_kfunc void bpf_coro_xdp_dtor(void *coro)
{
	bpf_coro_drop(coro, this_cpu_ptr(&bpf_coro_drops_xdp));
}
CFI_NOSEAL(bpf_coro_xdp_dtor);

__bpf_kfunc void bpf_coro_syscall_dtor(void *coro)
{
	bpf_coro_drop(coro, this_cpu_ptr(&bpf_coro_drops_syscall));
}
CFI_NOSEAL(bpf_coro_syscall_dtor);

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(bpf_coro_park_kfunc_ids)
BTF_ID_FLAGS(func, bpf_coro_park_xdp, KF_ACQUIRE)
BTF_ID_FLAGS(func, bpf_coro_park_syscall, KF_ACQUIRE)
BTF_ID_FLAGS(func, bpf_coro_drop_xdp, KF_RELEASE)
BTF_ID_FLAGS(func, bpf_coro_drop_syscall, KF_RELEASE)
BTF_KFUNCS_END(bpf_coro_park_kfunc_ids)

static const struct btf_kfunc_id_set bpf_coro_park_kfunc_set = {
	.owner = THIS_MODULE,
	.set = &bpf_coro_park_kfunc_ids,
};

BTF_ID_LIST(bpf_coro_dtor_ids)
BTF_ID(struct, bpf_coro_xdp)
BTF_ID(func, bpf_coro_xdp_dtor)
BTF_ID(struct, bpf_coro_syscall)
BTF_ID(func, bpf_coro_syscall_dtor)

static int __init bpf_coro_init(void)
{
	const struct btf_id_dtor_kfunc dtors[] = {
		{ .btf_id = bpf_coro_dtor_ids[0], .kfunc_btf_id = bpf_coro_dtor_ids[1] },
		{ .btf_id = bpf_coro_dtor_ids[2], .kfunc_btf_id = bpf_coro_dtor_ids[3] },
	};
	int cpu, ret;

	for_each_possible_cpu(cpu) {
		INIT_WORK(&per_cpu(bpf_coro_drops_xdp, cpu).work, bpf_coro_drop_work);
		INIT_WORK(&per_cpu(bpf_coro_drops_syscall, cpu).work, bpf_coro_drop_work);
	}
	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP, &bpf_coro_park_kfunc_set);
	ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_SCHED_CLS, &bpf_coro_park_kfunc_set);
	ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL, &bpf_coro_park_kfunc_set);
	return ret ?: register_btf_id_dtor_kfuncs(dtors, ARRAY_SIZE(dtors), THIS_MODULE);
}
late_initcall(bpf_coro_init);
