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
	/* the program that allocated the frame, which is there for as long as the frame is */
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
 * The lifetime of a frame.
 *
 * A frame takes no reference on its program: its allocation and its free write nothing that
 * another CPU reads. What keeps the image of the program for as long as one of its frames can
 * be resumed or destroyed is whoever can do that:
 * - The program itself, while it runs.
 * - A kfunc that keeps the frame it suspends, see bpf_coro_run(): it takes a reference on
 *   bpf_coro_frame_prog() before it returns, and puts it when it has resumed or freed the
 *   frame.
 * - A program that takes a parked frame out of a map and calls it, see "Parked frames" below:
 *   it is the frame's program, or it is bound to that program and holds it, see
 *   claim_coro_maps() in verifier.c.
 * - The kernel, which destroys the parked frames that a program drops or leaves behind: the
 *   program is not freed before that is done, see bpf_coro_prog_release().
 */
__bpf_kfunc_start_defs();

/*
 * Coroutine frames are heap memory whose contents the verifier tracks slot by slot like the
 * program stack, see PTR_TO_CORO_FRAME. The size is a verifier-checked constant, so the
 * allocation and the tracked size agree. A program whose last reference is gone, and which
 * only runs until a grace period ends, gets no frame: so does the destroy function of a frame
 * that such a program left parked, and bpf_coro_prog_release() comes to an end.
 */
__bpf_kfunc void *bpf_coro_frame_alloc(u64 size__k, void *ctx__ign, struct bpf_prog_aux *aux)
{
	struct bpf_coro_frame_hdr *hdr;

	if (unlikely(!atomic64_read(&aux->refcnt)))
		return NULL;
	hdr = kmalloc_nolock(sizeof(*hdr) + size__k, __GFP_ACCOUNT, NUMA_NO_NODE);
	if (!hdr)
		return NULL;
	hdr->prog = aux->prog;
	return hdr + 1;
}

/* Free a frame. It is the kfunc, and what kernel code frees a frame with, in any context. */
__bpf_kfunc void bpf_coro_frame_free(void *p__coro_frame)
{
	kfree_nolock(bpf_coro_frame_hdr(p__coro_frame));
}
EXPORT_SYMBOL_GPL(bpf_coro_frame_free);

__bpf_kfunc_end_defs();

/*
 * The program of @frame, for the kfunc that keeps the frame: it holds the program for as long as
 * it has the frame, see "The lifetime of a frame" above.
 */
struct bpf_prog *bpf_coro_frame_prog(void *frame)
{
	return bpf_coro_frame_hdr(frame)->prog;
}
EXPORT_SYMBOL_GPL(bpf_coro_frame_prog);

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
 * as its argument. It is a subprogram of the program of the frame, which the caller holds, and
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
 * The continuation owns the frame and may free it. The caller puts its reference on the
 * program after the call, which may be the last one: a program is freed after a grace period
 * of RCU, or of RCU Tasks Trace if it runs sleepable, see __bpf_prog_put_noref(), and the call
 * and what follows it here are in a read section of the one that applies.
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
 * that a landing pad stands in for, the destructors of the kptr fields when an object goes
 * with a frame in it, and bpf_coro_prog_release() for all that is left when the program of
 * the frames goes. That may be in any context, so the frame waits on a list of the CPU for a
 * work item in a context of the type: softirq with a network context for XDP, a kernel thread
 * for a syscall program.
 *
 * The program that calls a frame is the frame's own or holds it, see "The lifetime of a
 * frame" above. A frame goes from one program to another through a map only, so a map whose
 * values can hold frames has one owner, the program that parks them, and is used by that
 * program and by the programs that are bound to it, see claim_coro_maps() in verifier.c.
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

/* The work destroys what is on its own list, so the list of any CPU will do. */
static void bpf_coro_drop(void *frame, struct bpf_coro_drops *drops)
{
	struct bpf_coro_frame_hdr *hdr = bpf_coro_frame_hdr(frame);

	/* first, see bpf_coro_prog_release() */
	atomic_long_inc(&hdr->prog->aux->coro_drops);
	llist_add(&hdr->drop, &drops->frames);
	irq_work_queue(&drops->irq_work);
}

/* All that was given to bpf_coro_drop() is destroyed, as far as it has got to its list. */
static void bpf_coro_drops_flush(void)
{
	struct bpf_coro_drops *drops;
	int cpu;

	for_each_possible_cpu(cpu) {
		drops = &per_cpu(bpf_coro_drops_xdp, cpu);
		irq_work_sync(&drops->irq_work);
		flush_work(&drops->work);
		drops = &per_cpu(bpf_coro_drops_syscall, cpu);
		irq_work_sync(&drops->irq_work);
		flush_work(&drops->work);
	}
}

/**
 * bpf_coro_prog_release - destroy the parked frames of a program whose last reference is gone
 * @prog: the program, which parks frames
 *
 * No frame holds the program, so nothing but this stands between a parked frame and the day
 * on which its functions are freed. Whatever could call one is going: the programs that are
 * bound to @prog held it until they were freed, and what still runs of them and of @prog
 * itself ends with a grace period. The frames are in the maps that @prog owns, see
 * claim_coro_maps() in verifier.c, or on their way out of one, in a destructor or on a list of
 * bpf_coro_drop(). The kernel destroys them all, in the context of their type, while all of
 * @prog is still there.
 *
 * A destroy function is code of @prog, and may move another frame from one value to another,
 * or drop one. So this looks again until a round finds nothing: no frame in a map, and no
 * frame given to bpf_coro_drop() from before the round began until all that was on the lists
 * when it ended has been destroyed. bpf_coro_drop() counts first, in a section that a grace
 * period waits for. Then no code of @prog has run in the round, nothing has moved, and there
 * is no frame. That round comes: a destroy function gets no new frame, see
 * bpf_coro_frame_alloc(), and suspends none, see push_coro_suspend() in verifier.c, so each
 * one that runs leaves one frame less.
 *
 * Process context, in which it sleeps.
 */
void bpf_coro_prog_release(struct bpf_prog *prog)
{
	struct bpf_prog_aux *aux = prog->aux;
	struct bpf_map *map;
	long drops;
	u32 i;

	/*
	 * Code of it that may sleep, the program or an async callback, holds frames in a read
	 * section of RCU Tasks Trace: they are back in a map, or on a list, when it has ended.
	 */
	if (bpf_prog_runs_sleepable(prog))
		synchronize_rcu_tasks_trace();
	do {
		drops = atomic_long_read(&aux->coro_drops);
		synchronize_rcu();
		bpf_coro_drops_flush();
		/* for the objects that go with their frames, see __bpf_obj_drop_impl() */
		migrate_disable();
		for (i = 0; i < aux->used_map_cnt; i++) {
			map = aux->used_maps[i];
			if (READ_ONCE(map->coro_owner) == aux)
				map->ops->map_free_parked(map);
		}
		migrate_enable();
		/* something was found: it is on a list now, and the next round begins with it */
		if (drops != atomic_long_read(&aux->coro_drops))
			continue;
		synchronize_rcu();
		bpf_coro_drops_flush();
	} while (drops != atomic_long_read(&aux->coro_drops));
}

__bpf_kfunc_start_defs();

/**
 * bpf_coro_park_xdp - suspend a coroutine for an XDP program to resume
 * @frame__coro_suspend: the frame
 *
 * The frame is the program's again, as a pointer that it can keep in a kptr field. The resume
 * and the destroy function in its first two slots are verified as code of an XDP program from
 * here on, whatever program this is, and an XDP program that holds the pointer calls them:
 * this program, or one that is bound to it and takes the pointer out of a map of this one.
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
	bpf_coro_drop(coro, raw_cpu_ptr(&bpf_coro_drops_xdp));
}

/**
 * bpf_coro_drop_syscall - have the kernel destroy a parked coroutine
 * @coro: the frame
 *
 * Like bpf_coro_drop_xdp(); the destroy function runs in a kernel thread.
 */
__bpf_kfunc void bpf_coro_drop_syscall(struct bpf_coro_syscall *coro)
{
	bpf_coro_drop(coro, raw_cpu_ptr(&bpf_coro_drops_syscall));
}

/* The destructors of kptr fields that hold a parked frame */
__bpf_kfunc void bpf_coro_xdp_dtor(void *coro)
{
	bpf_coro_drop(coro, raw_cpu_ptr(&bpf_coro_drops_xdp));
}
CFI_NOSEAL(bpf_coro_xdp_dtor);

__bpf_kfunc void bpf_coro_syscall_dtor(void *coro)
{
	bpf_coro_drop(coro, raw_cpu_ptr(&bpf_coro_drops_syscall));
}
CFI_NOSEAL(bpf_coro_syscall_dtor);

__bpf_kfunc_end_defs();

/* Does a kptr field with destructor @dtor hold a parked frame? See bpf_record_holds_parked(). */
bool bpf_coro_is_parked_dtor(void (*dtor)(void *))
{
	return dtor == bpf_coro_xdp_dtor || dtor == bpf_coro_syscall_dtor;
}

/*
 * @prog is freed, and the maps that could hold its parked frames, see claim_coro_maps() in
 * verifier.c, are nobody's again: no frame of it is left, see bpf_coro_prog_release(), and no
 * program that could put one there.
 *
 * Not at its last put: code of it may run on until a grace period ends, and would find the
 * frames of the next owner in the map, which it does not hold: it could keep one past that
 * owner's release. bpf_prog_free_deferred() calls this where it gives up the maps of the
 * program altogether, behind the grace period of __bpf_prog_put_noref(): nothing of the
 * program runs there that could use a map, or the map itself would go under it. A program
 * that did not load never ran.
 */
void bpf_coro_prog_disown(struct bpf_prog *prog)
{
	struct bpf_prog_aux *aux = prog->aux;
	u32 i;

	for (i = 0; i < aux->used_map_cnt; i++)
		cmpxchg(&aux->used_maps[i]->coro_owner, aux, NULL);
}

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
