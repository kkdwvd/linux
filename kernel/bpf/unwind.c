// SPDX-License-Identifier: GPL-2.0-only
/*
 * The exception unwinder: from a throw site, walk the BPF frames up to the
 * one the kernel entered, once per phase of the release order, releasing
 * what the slots of each frame hold of that phase, see frame_desc.c, and
 * recovering the callee-saved registers the discarded frames saved, then
 * transfer to that frame, which returns, or leaves into the pad of the helper
 * that ran it.
 */
#include <linux/bpf.h>
#include <linux/bpf_verifier.h>
#include <linux/filter.h>
#include <linux/irqflags.h>
#include <linux/kasan.h>

void bpf_frame_desc_pool_free(struct bpf_frame_desc_pool *pool)
{
	u32 i;

	if (!pool)
		return;
	for (i = 0; i < pool->cnt; i++)
		kvfree(pool->desc[i]);
	kvfree(pool->resources);
	kvfree(pool);
}

static bool resource_is_lock(u8 kind)
{
	return kind == BPF_RESOURCE_SPIN_LOCK || kind == BPF_RESOURCE_RES_LOCK;
}

static bool resource_is_section(u8 kind)
{
	return kind == BPF_RESOURCE_RCU || kind == BPF_RESOURCE_PREEMPT;
}

/*
 * Release one resource by its handle, at run time: the pointer to an object,
 * the address of a stack object or of a lock, or nothing for a section. Not
 * inlined so that every release of an unwind can be observed by attaching to
 * this function.
 */
noinline void bpf_unwind_release(const struct bpf_resource *res, void *handle)
{
	/* A destructor that needs RCU protection gets it here, whatever the frames held. */
	if (res->rcu)
		rcu_read_lock();
	switch (res->kind) {
	case BPF_RESOURCE_OBJ:
		bpf_obj_drop_impl(handle, res->meta);
		break;
	case BPF_RESOURCE_PERCPU_OBJ:
		bpf_percpu_obj_drop_impl(handle, res->meta);
		break;
	case BPF_RESOURCE_KPTR:
	case BPF_RESOURCE_ITER:
		res->dtor(handle);
		break;
#ifdef CONFIG_NET
	case BPF_RESOURCE_SOCK:
		bpf_sk_release_proto.func((u64)(long)handle, 0, 0, 0, 0);
		break;
#endif
	case BPF_RESOURCE_RINGBUF:
		bpf_ringbuf_discard_proto.func((u64)(long)handle, 0, 0, 0, 0);
		break;
	case BPF_RESOURCE_DYNPTR_FILE:
		bpf_dynptr_file_free(handle);
		break;
	case BPF_RESOURCE_SPIN_LOCK:
		bpf_spin_unlock_proto.func((u64)(long)handle, 0, 0, 0, 0);
		break;
	case BPF_RESOURCE_RES_LOCK:
		bpf_res_spin_unlock(handle);
		break;
	case BPF_RESOURCE_IRQ_FLAG:
		bpf_local_irq_restore(handle);
		break;
	case BPF_RESOURCE_RCU:
		bpf_rcu_read_unlock();
		break;
	case BPF_RESOURCE_PREEMPT:
		bpf_preempt_enable();
		break;
	default:
		WARN_ON_ONCE(1);
	}
	if (res->rcu)
		rcu_read_unlock();
}

/* The sections of a frame are counted, per kind. */
enum {
	BPF_UNWIND_SECTION_RCU,
	BPF_UNWIND_SECTION_PREEMPT,
	BPF_UNWIND_NR_SECTIONS,
};

static int section_index(u8 kind)
{
	return kind == BPF_RESOURCE_RCU ? BPF_UNWIND_SECTION_RCU : BPF_UNWIND_SECTION_PREEMPT;
}

/*
 * The release order. Objects never run under a lock or with IRQs disabled by
 * any frame, and a sleeping destructor runs after every section is left; an
 * RCU-protected object is destroyed before the sections end.
 */
enum {
	BPF_UNWIND_PHASE_LOCKS,		/* locks and IRQ flags */
	BPF_UNWIND_PHASE_RCU_OBJS,	/* objects whose destructor needs RCU protection */
	BPF_UNWIND_PHASE_SECTIONS,	/* RCU and preemption sections */
	BPF_UNWIND_PHASE_OBJS,		/* everything else */
	BPF_UNWIND_NR_PHASES,
};

static int release_phase(const struct bpf_resource *res)
{
	if (resource_is_lock(res->kind) || res->kind == BPF_RESOURCE_IRQ_FLAG)
		return BPF_UNWIND_PHASE_LOCKS;
	if (resource_is_section(res->kind))
		return BPF_UNWIND_PHASE_SECTIONS;
	return res->rcu ? BPF_UNWIND_PHASE_RCU_OBJS : BPF_UNWIND_PHASE_OBJS;
}

struct bpf_throw_ctx {
	struct bpf_prog *prog;	/* the program of the frame the unwinder stops at */
	u64 sp;
	u64 bp;
	int cnt;
	const struct bpf_throw_regs *regs;	/* callee-saved registers of the throw site, or NULL */
	unsigned int kind;			/* BPF_THROW_*: how the throw site was reached */
	int phase;				/* BPF_UNWIND_PHASE_*: what this walk releases */
	/*
	 * The callee-saved registers of the frame being walked, R6-R9 then the
	 * architecture's own: what the throw site had, then what each frame
	 * recovered of its caller's. After the frame the unwinder stops at they
	 * are the ones its caller expects back.
	 */
	u64 saved[BPF_THROW_NR_CALLEE_SAVED];
	/* The sections the frames hold, per kind, summed by the first walk. */
	const struct bpf_resource *section[BPF_UNWIND_NR_SECTIONS];
	s64 nr_sections[BPF_UNWIND_NR_SECTIONS];
	/*
	 * When that frame is a callback a helper ran: the pad of the helper, the
	 * frame pointer of the last kernel frame passed, the return address of
	 * the outermost helper into the program, where the helper keeps it, and
	 * the hidden slot of the frame that called the helper for the cookie.
	 */
	u64 pad;
	u64 kernel_bp;
	u64 site;
	u64 *slot;
	u64 *cookie_slot;
	const struct bpf_prog *site_prog;
	u64 site_fp;
	/*
	 * The cookie the innermost frame kept in its hidden slot, when the
	 * unwinding goes on from the call of a helper whose callback threw.
	 */
	u64 cookie;
};

/*
 * The aux the JIT filled: the symbol of a program JITed as a set of functions
 * covers its first function.
 */
static const struct bpf_prog_aux *bpf_unwind_fn(const struct bpf_prog *prog)
{
	return !prog->is_func && prog->aux->func ? prog->aux->func[0]->aux : prog->aux;
}

/*
 * Recover the caller's callee-saved registers from a frame: those its
 * prologue saved sit in the frame, the rest are still the values the frame
 * itself has.
 */
static void bpf_unwind_recover(const struct bpf_prog_aux *fn, u64 bp, u64 *regs, int n)
{
	int i;

	for (i = 0; i < n; i++)
		if (fn->callee_reg_off[i])
			regs[i] = *(u64 *)(long)(bp + fn->callee_reg_off[i]);
}

/* The frame descriptor of the function @prog is, the slots of its frames, or NULL. */
static const struct bpf_frame_desc *bpf_unwind_desc(const struct bpf_prog *prog)
{
	const struct bpf_prog_aux *fn = bpf_unwind_fn(prog);

	return fn->frame_desc ? fn->frame_desc_pool->desc[fn->frame_desc - 1] : NULL;
}

/*
 * The R10 of the frame of @prog whose native frame pointer is @bp: a fixed
 * distance from it, or, with a private stack, this CPU's private frame.
 */
static u64 bpf_unwind_fp(const struct bpf_prog *prog, u64 bp)
{
	const struct bpf_prog_aux *fn = bpf_unwind_fn(prog);

	if (fn->priv_stack_ptr)
		return (u64)(long)this_cpu_ptr(fn->priv_stack_ptr) + fn->priv_frame_off;
	return bp + fn->frame_fp_off;
}

/*
 * Is the frame of @prog the outermost one of an invocation: one the kernel
 * entered on its own, the main program, which a tail called program is too,
 * an asynchronous callback or the exception callback? A callback a helper
 * ran is not: the frames of its invocation go on below the helper.
 */
static bool bpf_unwind_outermost(const struct bpf_prog *prog)
{
	return !bpf_is_subprog(prog) || prog->aux->async_cb || prog->aux->exception_cb;
}

/* The count of the sections of @kind in the frame of @prog at @fp, or NULL. */
static s64 *bpf_unwind_counter(const struct bpf_prog *prog, u64 fp, int kind)
{
	const struct bpf_frame_desc_pool *pool = bpf_unwind_fn(prog)->frame_desc_pool;
	const struct bpf_frame_desc *d = bpf_unwind_desc(prog);
	u32 i;

	for (i = 0; d && i < d->nent; i++)
		if ((d->ent[i].flags & BPF_FRAME_ENT_COUNTER) &&
		    section_index(pool->resources[d->ent[i].res].kind) == kind)
			return (s64 *)(long)(fp + d->ent[i].off);
	return NULL;
}

/*
 * Release what the slots of the frame of @prog at @fp hold of the phase of
 * this walk. The first walk sums the frame's counts of sections for their
 * phase, and releases the locks and IRQ flags in two passes: the flags a
 * frame saved with interrupts enabled, of which it can have one at most,
 * since every later save found them disabled, are restored last, after the
 * locks and the other flags in whatever order the frame took them.
 */
static void bpf_unwind_release_frame(struct bpf_throw_ctx *ctx, const struct bpf_prog *prog, u64 fp)
{
	const struct bpf_frame_desc_pool *pool = bpf_unwind_fn(prog)->frame_desc_pool;
	int passes = ctx->phase == BPF_UNWIND_PHASE_LOCKS ? 2 : 1, pass, s;
	const struct bpf_frame_desc *d = bpf_unwind_desc(prog);
	bool late;
	u32 i;

	if (!d)
		return;
	for (pass = 0; pass < passes; pass++) {
		for (i = 0; i < d->nent; i++) {
			const struct bpf_frame_desc_entry *ent = &d->ent[i];
			const struct bpf_resource *res = &pool->resources[ent->res];
			u64 *slot = (u64 *)(long)(fp + ent->off);
			void *handle = (void *)(long)*slot;

			if (ent->flags & BPF_FRAME_ENT_COUNTER) {
				if (ctx->phase != BPF_UNWIND_PHASE_LOCKS || pass)
					continue;
				s = section_index(res->kind);
				ctx->section[s] = res;
				ctx->nr_sections[s] += (s64)*slot;
				continue;
			}
			if (!handle || release_phase(res) != ctx->phase)
				continue;
			late = res->kind == BPF_RESOURCE_IRQ_FLAG &&
			       !arch_irqs_disabled_flags(*(unsigned long *)handle);
			if (passes == 2 && late != (pass == 1))
				continue;
			bpf_unwind_release(res, handle);
		}
	}
}

/*
 * Leave the sections the frames hold in all, per kind, as the first walk
 * summed them. Sections of one kind are all the same: the sum is left.
 */
static void bpf_unwind_sections(struct bpf_throw_ctx *ctx)
{
	int s;

	for (s = 0; s < BPF_UNWIND_NR_SECTIONS; s++) {
		s64 *below;

		/*
		 * The frames of a callback left sections the frames below the
		 * helper entered: those are in that many less, which the frame
		 * that called the helper counts from here on, for the unwinding
		 * that goes on from its call.
		 */
		if (ctx->nr_sections[s] < 0) {
			below = ctx->pad && ctx->site_prog ?
				bpf_unwind_counter(ctx->site_prog, ctx->site_fp, s) : NULL;
			if (!WARN_ONCE(!below, "bpf: %lld sections of %s to leave\n",
				       ctx->nr_sections[s], ctx->prog->aux->name))
				*below += ctx->nr_sections[s];
			continue;
		}
		while (ctx->nr_sections[s]-- > 0)
			bpf_unwind_release(ctx->section[s], NULL);
	}
}

static bool bpf_stack_walker(void *cookie, u64 ip, u64 sp, u64 bp)
{
	struct bpf_throw_ctx *ctx = cookie;
	const struct bpf_prog_aux *fn;
	struct bpf_prog *prog;
	u64 fp;

	/*
	 * The RCU read lock is held to safely traverse the latch tree, but we
	 * don't need its protection when accessing the prog, since it has an
	 * active stack frame on the current stack trace, and won't disappear.
	 */
	rcu_read_lock();
	prog = bpf_prog_ksym_find(ip);
	rcu_read_unlock();
	/*
	 * The kernel frames below the first BPF frame are the unwinder's own.
	 * The first one above a subprog's frame is the kernel code that ran
	 * the subprog as a callback, where the unwinder stops: when it is a
	 * helper with a pad, see bpf_call_cb(), the callback leaves into the
	 * pad and the walk goes on, through the helpers the helper called with
	 * pads of their own, to the frame of the program that called it, where
	 * the return address of the outermost helper is found.
	 */
	if (!prog) {
		if (!ctx->cnt)
			return true;
		if (!ctx->pad) {
			ctx->pad = bpf_unwind_target(ip);
			if (ctx->pad == ip) {
				ctx->pad = 0;
				return false;
			}
		}
		ctx->kernel_bp = bp;
		return true;
	}
	fn = bpf_unwind_fn(prog);
	fp = bpf_unwind_fp(prog, bp);
	if (ctx->pad) {
		/*
		 * The frame of the program that called the helper, which the
		 * throw that follows the pad unwinds, see bpf_throw_unwind(): it
		 * has the return address of the helper and the slot for the
		 * cookie, and the walk ends here.
		 */
		ctx->site = ip;
		ctx->site_prog = prog;
		ctx->site_fp = fp;
		ctx->slot = bpf_arch_ret_slot(ctx->kernel_bp, sp);
		if (fn->throw_cookie_off)
			ctx->cookie_slot = (u64 *)(long)(fp + fn->throw_cookie_off);
		return false;
	}
	/*
	 * Release what the frame holds of this walk's phase, then recover the
	 * caller's callee-saved registers from the frame.
	 */
	bpf_unwind_release_frame(ctx, prog, fp);
	bpf_unwind_recover(fn, bp, ctx->saved, BPF_THROW_NR_CALLEE_SAVED);
	/* The innermost frame called the helper whose callback threw: it has the cookie. */
	if (!ctx->cnt && ctx->kind == BPF_THROW_RETHROW && !WARN_ON_ONCE(!fn->throw_cookie_off))
		ctx->cookie = *(u64 *)(long)(fp + fn->throw_cookie_off);
	ctx->cnt++;
	ctx->prog = prog;
	ctx->sp = sp;
	ctx->bp = bp;
	/*
	 * A program that is not a subprog was entered from the kernel or by a
	 * tail call and is the frame the unwinder stops at; a tail called
	 * program thus completes into the program that called it. A subprog
	 * is unwound through, unless the kernel ran it as a callback.
	 */
	return bpf_is_subprog(prog);
}

/* What bpf_unwind_forget() and bpf_unwind_handover() look for as they walk the frames. */
struct bpf_slot_walk {
	u64 handle;
	u32 res;
	int seen;	/* BPF frames passed */
	const struct bpf_prog *from;
	u64 from_fp;
};

/* Does a slot of class @res hold what a release of @want released, see frame_desc.c? */
static bool bpf_slot_matches(const struct bpf_frame_desc_pool *pool, u16 res, u32 want)
{
	if (want & BPF_FORGET_ANY_OF_KIND)
		return pool->resources[res].kind == (want & 0xff);
	return res == want;
}

static bool bpf_forget_walker(void *cookie, u64 ip, u64 sp, u64 bp)
{
	const struct bpf_frame_desc_pool *pool;
	struct bpf_slot_walk *w = cookie;
	const struct bpf_frame_desc *d;
	struct bpf_prog *prog;
	u64 fp, *slot;
	u32 i;

	rcu_read_lock();
	prog = bpf_prog_ksym_find(ip);
	rcu_read_unlock();
	/* this function's own frames, or those of a helper that ran a callback */
	if (!prog)
		return true;
	/* the frame that releases looked through its own slots */
	if (w->seen++) {
		pool = bpf_unwind_fn(prog)->frame_desc_pool;
		d = bpf_unwind_desc(prog);
		fp = bpf_unwind_fp(prog, bp);
		for (i = 0; d && i < d->nent; i++) {
			if ((d->ent[i].flags & BPF_FRAME_ENT_COUNTER) ||
			    !bpf_slot_matches(pool, d->ent[i].res, w->res))
				continue;
			slot = (u64 *)(long)(fp + d->ent[i].off);
			if (*slot != w->handle)
				continue;
			*slot = 0;
			return false;
		}
	}
	return !bpf_unwind_outermost(prog);
}

/*
 * A frame released a resource whose handle is in none of its slots: another
 * frame of the invocation holds it, or holds an equal handle that stands in
 * for it. Clear the nearest slot of class @res below the releasing frame that
 * holds @handle, so that the slots of the frames go on holding one handle for
 * every resource held. Returns @ret, the R0 of the release, which the code
 * that calls this passes through it.
 */
u64 bpf_unwind_forget(u64 handle, u64 res, u64 ret)
{
	struct bpf_slot_walk w = { .handle = handle, .res = res };

	if (handle)
		arch_bpf_stack_walk(bpf_forget_walker, &w);
	return ret;
}

static bool bpf_handover_walker(void *cookie, u64 ip, u64 sp, u64 bp)
{
	const struct bpf_frame_desc_pool *pool;
	const struct bpf_frame_desc *from, *to;
	struct bpf_slot_walk *w = cookie;
	struct bpf_prog *prog;
	u64 fp, val, *slot;
	u32 i, k;

	rcu_read_lock();
	prog = bpf_prog_ksym_find(ip);
	rcu_read_unlock();
	if (!prog)
		return true;
	fp = bpf_unwind_fp(prog, bp);
	if (!w->seen++) {
		w->from = prog;
		w->from_fp = fp;
		/* the kernel takes nothing over */
		return !bpf_unwind_outermost(prog) && bpf_unwind_desc(prog);
	}
	/* the frame it returns to, below the helper that ran it if it is a callback */
	pool = bpf_unwind_fn(prog)->frame_desc_pool;
	from = bpf_unwind_desc(w->from);
	to = bpf_unwind_desc(prog);
	for (i = 0; i < from->nent; i++) {
		const struct bpf_frame_desc_entry *ent = &from->ent[i];
		u8 kind = pool->resources[ent->res].kind;

		slot = (u64 *)(long)(w->from_fp + ent->off);
		val = *slot;
		if (!val)
			continue;
		*slot = 0;
		for (k = 0; to && k < to->nent; k++) {
			u64 *dst = (u64 *)(long)(fp + to->ent[k].off);

			if ((to->ent[k].flags ^ ent->flags) & BPF_FRAME_ENT_COUNTER)
				continue;
			if (ent->flags & BPF_FRAME_ENT_COUNTER) {
				if (pool->resources[to->ent[k].res].kind != kind)
					continue;
				*dst += val;
				break;
			}
			if (to->ent[k].res != ent->res || *dst)
				continue;
			*dst = val;
			break;
		}
		WARN_ONCE(!to || k == to->nent, "bpf: %s has no slot for what %s returns with\n",
			  prog->aux->name, w->from->aux->name);
	}
	return false;
}

/*
 * A frame is about to return while it holds something: its caller holds it
 * from here on. Move what the slots of the frame hold, and its counts of
 * sections, into the slots of the frame it returns to, which the verifier
 * gave room for them.
 */
u64 bpf_unwind_handover(void)
{
	struct bpf_slot_walk w = {};

	arch_bpf_stack_walk(bpf_handover_walker, &w);
	return 0;
}

/*
 * Walk the frames from the throw site outwards for one phase, from the
 * callee-saved registers of the throw site again: every walk passes the same
 * frames and ends at the same one, with the same registers recovered and the
 * same pad found. What the walk learns of the pad is acted on once they are
 * over.
 */
static void bpf_unwind_walk(struct bpf_throw_ctx *ctx, int phase)
{
	ctx->phase = phase;
	ctx->cnt = 0;
	ctx->pad = 0;
	ctx->kernel_bp = 0;
	ctx->site = 0;
	ctx->slot = NULL;
	ctx->cookie_slot = NULL;
	ctx->site_prog = NULL;
	memcpy(ctx->saved, ctx->regs->saved, sizeof(ctx->saved));
	arch_bpf_stack_walk(bpf_stack_walker, ctx);
}

/*
 * Release what the frames hold in four phases, each a walk over the frames
 * innermost first that releases each frame's entries of the phase in
 * descriptor order: locks and IRQ flags, RCU-protected objects, sections,
 * then the other objects. The frames are released as the walk passes them, so
 * their number is not bounded: a recursive subprog nests as deep as the stack
 * allows. The sections need no walk of their own, the first one summed them.
 */
static void bpf_unwind_frames(struct bpf_throw_ctx *ctx)
{
	int phase;

	for (phase = 0; phase < BPF_UNWIND_NR_PHASES; phase++) {
		if (phase == BPF_UNWIND_PHASE_SECTIONS)
			bpf_unwind_sections(ctx);
		else
			bpf_unwind_walk(ctx, phase);
	}
}

/*
 * Unwind the BPF frames above the throw site up to the one the kernel
 * entered: the main program, which its exception callback returns from, or
 * a callback. A callback a helper ran leaves into the pad of the helper the
 * way unwind_exit does, with the return address of the call in the program
 * as its r0; the helper drops what it holds and returns, with that r0, to
 * bpf_rethrow_entry(), which the unwinder made its return address, and the
 * unwinding goes on from the call of the helper. The cookie waits in a
 * hidden stack slot of the frame that called the helper meanwhile, since r0
 * is all that the helper passes on. A callback the kernel ran on its own, a
 * timer's, returns to it. @regs are the callee-saved registers of the throw
 * site, which the entry of the architecture captured: what the frames
 * unwound saved of them is restored for the callback. @kind says how the
 * throw site was reached.
 */
__bpf_unwind_entry
void bpf_throw_unwind(struct bpf_throw_regs *regs, u64 cookie, unsigned int kind)
{
	struct bpf_throw_ctx ctx = { .regs = regs, .kind = kind };
	struct bpf_prog_aux *aux, *main_aux;
	u64 (*cb)(u64, u64, u64, u64, u64);

	/*
	 * The kfunc passes NULL, and the verifier retargets its call to
	 * bpf_arch_throw_entry() wherever there is one. An architecture without
	 * the entry keeps the rules it had: a program throws holding nothing,
	 * and not from a callback, see check_callbacks(), so the frames have
	 * nothing to release, and its main program saves every callee-saved
	 * register in its frame, where its exception callback finds them.
	 */
	if (regs) {
		bpf_unwind_frames(&ctx);
	} else {
		ctx.phase = BPF_UNWIND_NR_PHASES;
		arch_bpf_stack_walk(bpf_stack_walker, &ctx);
	}
	WARN_ON_ONCE(!ctx.prog);
	WARN_ON_ONCE(ctx.prog && !ctx.prog->aux->main_prog_aux->exception_boundary);
	WARN_ON_ONCE(!ctx.bp);
	WARN_ON_ONCE(!ctx.cnt);
	/*
	 * Prevent KASAN false positives for CONFIG_KASAN_STACK by unpoisoning
	 * deeper stack depths than ctx.sp as we do not return from here, which
	 * skips compiler generated instrumentation to do the same. Some
	 * architectures cannot recover sp while unwinding, so fall back to bp.
	 */
	kasan_unpoison_task_stack_below((void *)(long)(ctx.sp ?: ctx.bp));
	aux = ctx.prog->aux;
	main_aux = aux->main_prog_aux;
	/*
	 * The unwinding went on from the call of a helper whose callback threw:
	 * the cookie of the throw is in the frame that called the helper.
	 */
	if (kind == BPF_THROW_RETHROW)
		cookie = ctx.cookie;
	/*
	 * The main program completes with the cookie, through its exception
	 * callback, which does not throw itself. A callback a helper ran leaves
	 * into the pad of the helper, and the unwinding goes on from the call of
	 * the helper, where the program's main frame is reached in turn; a
	 * callback the kernel ran on its own returns 0, which the kernel code
	 * ignores.
	 */
	if (ctx.pad) {
		/*
		 * The slot may hold the address signed, see bpf_arch_ret_addr(),
		 * which the walker strips from what it reports; the entry is
		 * stored raw, since the pad of the helper signs what it leaves
		 * with, see bpf_unwind_leave(). Without the slot of the cookie
		 * or the return address of the helper the frames below cannot
		 * be unwound, which the verifier rules out: the helper returns
		 * to the program then, which goes on as if the callback had
		 * returned.
		 */
		if (!WARN_ON_ONCE(!ctx.slot || !ctx.cookie_slot ||
				  bpf_arch_ret_addr(ctx.slot) != ctx.site)) {
			*ctx.cookie_slot = cookie;
			*ctx.slot = (u64)(long)bpf_arch_rethrow_entry();
		}
		bpf_arch_set_ret_addr(ctx.bp, ctx.pad);
		cookie = ctx.site;
		cb = main_aux->bpf_unwind_ret_cb;
	} else if (bpf_is_subprog(ctx.prog)) {
		/*
		 * A callback the kernel ran on its own, a timer's or a work
		 * item's. Any other kernel frame above a subprog is a bug: the
		 * verifier lets a helper run a callback that throws only with a
		 * pad, and only fentry may attach to a subprog an unwind can pass
		 * through, see bpf_check_attach_target(), since the trampoline of
		 * anything else would be that frame. Completing the frame with 0
		 * is the least that can be done then: the frames below are not
		 * unwound, their caller takes the value for the subprog's result,
		 * and what they hold leaks, but the kernel goes on.
		 */
		WARN_ONCE(!aux->async_cb,
			  "bpf: unwinding %s stopped at %s under a frame that is not BPF code\n",
			  main_aux->name, aux->name);
		cookie = 0;
		cb = main_aux->bpf_unwind_ret_cb;
	} else {
		cb = main_aux->bpf_exception_cb;
	}
	/*
	 * Every program that throws has both callbacks, see bpf_do_misc_fixups();
	 * without one nothing completes the frame, and there is no return from
	 * here.
	 */
	BUG_ON(!cb);
	cb(cookie, ctx.sp, ctx.bp, regs ? (u64)(long)ctx.saved : 0, 0);
	WARN(1, "A call to BPF exception callback should never return\n");
}
