// SPDX-License-Identifier: GPL-2.0-only
/*
 * The exception unwinder: from a throw site, walk the BPF frames up to the
 * one the kernel entered, once per phase of the release order, releasing
 * what each frame holds of that phase according to its frame descriptor and
 * recovering the callee-saved registers the discarded frames saved, then
 * transfer to that frame, which returns, or leaves into the pad of the helper
 * that ran it.
 */
#include <linux/bpf.h>
#include <linux/bpf_verifier.h>
#include <linux/filter.h>
#include <linux/kasan.h>

/*
 * Convert the instruction indices of the throw-site table to native offsets.
 * offsets[k] is the first byte of instruction k relative to image and
 * offsets[prog->len] the end of the program, as for bpf_prog_update_insn_ptrs().
 */
void bpf_prog_fill_frame_desc_table(struct bpf_prog *prog, const u32 *offsets, void *image)
{
	struct bpf_frame_desc_table *tab = prog->aux->frame_desc_table;
	u32 i;

	if (!tab || tab->filled)
		return;

	for (i = 0; i < tab->cnt; i++) {
		struct bpf_frame_desc_site *site = &tab->site[i];

		site->end = image + offsets[site->off + 1] - (void *)prog->bpf_func;
		site->off = image + offsets[site->off] - (void *)prog->bpf_func;
	}
	tab->filled = true;
}

/*
 * Find the descriptor of the throw site of prog that ip falls into, or NULL.
 * ip is an address within the instruction: a caller that holds a return
 * address passes ra - 1, since the return address is the first byte of the
 * next instruction.
 */
const struct bpf_frame_desc *bpf_prog_frame_desc_lookup(const struct bpf_prog *prog,
							unsigned long ip)
{
	const struct bpf_frame_desc_table *tab = prog->aux->frame_desc_table;
	unsigned long off;
	u32 l, r, m;

	if (!tab || !tab->filled)
		return NULL;
	off = ip - (unsigned long)prog->bpf_func;

	/* The entries are disjoint and sorted: find the first that ends after off. */
	l = 0;
	r = tab->cnt;
	while (l < r) {
		m = l + (r - l) / 2;
		if (tab->site[m].end <= off)
			l = m + 1;
		else
			r = m;
	}
	if (l == tab->cnt || tab->site[l].off > off)
		return NULL;
	return prog->aux->frame_desc_pool->desc[tab->site[l].desc];
}

void bpf_frame_desc_table_free(struct bpf_frame_desc_table *tab)
{
	kvfree(tab);
}

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
	return kind == BPF_RESOURCE_SPIN_LOCK || kind == BPF_RESOURCE_RES_LOCK ||
	       kind == BPF_RESOURCE_RES_LOCK_IRQ;
}

static bool resource_is_section(u8 kind)
{
	return kind == BPF_RESOURCE_RCU || kind == BPF_RESOURCE_PREEMPT;
}

/*
 * Release one resource by its handle, at run time: the pointer to an object,
 * the address of a stack object or of a lock, or nothing for a section.
 * @flags is the saved IRQ flags of an irqsave lock. Not inlined so that every
 * release of an unwind can be observed by attaching to this function.
 */
noinline void bpf_unwind_release(const struct bpf_resource *res, void *handle, void *flags)
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
	case BPF_RESOURCE_DYNPTR_RINGBUF:
		bpf_ringbuf_discard_dynptr_proto.func((u64)(long)handle, 0, 0, 0, 0);
		break;
	case BPF_RESOURCE_SPIN_LOCK:
		bpf_spin_unlock_proto.func((u64)(long)handle, 0, 0, 0, 0);
		break;
	case BPF_RESOURCE_RES_LOCK:
		bpf_res_spin_unlock(handle);
		break;
	case BPF_RESOURCE_RES_LOCK_IRQ:
		bpf_res_spin_unlock_irqrestore(handle, flags);
		break;
	case BPF_RESOURCE_IRQ_FLAG:
		bpf_local_irq_restore(handle);
		break;
	case BPF_RESOURCE_IRQ_FLAG_LOCK:
		/* Restored together with the lock that saved them. */
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

/* The sections of a frame are counted, not located, per kind. */
enum {
	BPF_UNWIND_SECTION_RCU,
	BPF_UNWIND_SECTION_PREEMPT,
	BPF_UNWIND_NR_SECTIONS,
};

static int section_index(u8 kind)
{
	return kind == BPF_RESOURCE_RCU ? BPF_UNWIND_SECTION_RCU : BPF_UNWIND_SECTION_PREEMPT;
}

static bool resource_is_irq(u8 kind)
{
	return kind == BPF_RESOURCE_IRQ_FLAG || kind == BPF_RESOURCE_IRQ_FLAG_LOCK;
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
	if (resource_is_lock(res->kind) || resource_is_irq(res->kind))
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
	const struct bpf_throw_regs *regs;	/* register file of the throw site, or NULL */
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
	 * the outermost helper into the program and where the helper keeps it.
	 */
	u64 pad;
	u64 kernel_bp;
	u64 site;
	u64 *slot;
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

/*
 * The handle of a located entry of the frame being walked: the pointer the
 * location holds, or the address of the stack object at it. @fp is the
 * frame's R10; its R6-R9 are the ones the walk recovered so far, and only
 * the innermost frame has R0-R5, in the register file of the throw site.
 * Returns false when there is nothing to release.
 */
static bool bpf_unwind_handle(const struct bpf_throw_ctx *ctx, const struct bpf_prog *prog, u64 fp,
			      const struct bpf_frame_desc_entry *ent, void **handle)
{
	const char *name = prog->aux->name;
	u64 val;

	switch (ent->loc) {
	case BPF_FRAME_LOC_STACK:
		val = fp + ent->off;
		if (!(ent->flags & BPF_FRAME_ENT_INDIRECT)) {
			*handle = (void *)(long)val;
			return true;
		}
		val = *(u64 *)(long)val;
		break;
	case BPF_FRAME_LOC_REG:
		if (ent->off >= BPF_REG_6) {
			val = ctx->saved[ent->off - BPF_REG_6];
		} else if (!ctx->cnt) {
			val = ctx->regs->r[ent->off];
		} else {
			WARN_ONCE(1, "bpf: no register file to release R%d of %s from\n", ent->off,
				  name);
			return false;
		}
		break;
	default:
		WARN_ONCE(1, "bpf: bad location %d in a frame descriptor of %s\n", ent->loc, name);
		return false;
	}
	if (!val) {
		WARN_ONCE(!(ent->flags & BPF_FRAME_ENT_NULLABLE),
			  "bpf: NULL in a location of %s that holds a resource\n", name);
		return false;
	}
	*handle = (void *)(long)val;
	return true;
}

/*
 * Release the resource a located entry of the frame being walked describes.
 * @flags carries the saved IRQ flags of an irqsave lock from their entry to
 * the lock's, which follows it.
 */
static void bpf_unwind_entry(struct bpf_throw_ctx *ctx, const struct bpf_prog *prog, u64 fp,
			     const struct bpf_frame_desc_entry *ent, const struct bpf_resource *res,
			     void **flags)
{
	void *handle;

	if (ent->loc == BPF_FRAME_LOC_NONE) {
		if (WARN_ON_ONCE(!resource_is_lock(res->kind)))
			return;
		handle = res->addr;
	} else {
		if (!bpf_unwind_handle(ctx, prog, fp, ent, &handle))
			goto out;
		if (resource_is_lock(res->kind))
			handle += res->delta;
	}
	/* The flags of an irqsave lock are not released on their own: the lock restores them. */
	if (res->kind == BPF_RESOURCE_IRQ_FLAG_LOCK) {
		*flags = handle;
		return;
	}
	/* The flags entry precedes its lock and agrees with it on NULL. */
	if (res->kind == BPF_RESOURCE_RES_LOCK_IRQ &&
	    WARN_ONCE(!*flags, "bpf: no irq flags for the lock of %s\n", prog->aux->name))
		goto out;
	bpf_unwind_release(res, handle, *flags);
out:
	if (res->kind == BPF_RESOURCE_RES_LOCK_IRQ)
		*flags = NULL;
}

/*
 * Count the sections a frame's entry holds for their phase. The entry counts
 * the sections the frame entered less those of its callers it or a callee
 * left, which nets out a callee's leaving of a caller's section, and a frame
 * whose paths disagree on the count keeps it in a counter slot.
 */
static void bpf_unwind_count(struct bpf_throw_ctx *ctx, u64 fp,
			     const struct bpf_frame_desc_entry *ent, const struct bpf_resource *res)
{
	int s = section_index(res->kind);

	ctx->section[s] = res;
	if (ent->loc == BPF_FRAME_LOC_NONE)
		ctx->nr_sections[s] += ent->off;
	else if (!WARN_ON_ONCE(ent->loc != BPF_FRAME_LOC_STACK ||
			       !(ent->flags & BPF_FRAME_ENT_COUNTER)))
		ctx->nr_sections[s] += *(s64 *)(long)(fp + ent->off);
}

/*
 * Release what the frame of @prog at @pc holds of the phase of this walk, in
 * descriptor order. The first walk counts the frame's sections for theirs.
 */
static void bpf_unwind_frame(struct bpf_throw_ctx *ctx, const struct bpf_prog *prog,
			     unsigned long pc, u64 fp)
{
	const struct bpf_frame_desc_pool *pool = prog->aux->frame_desc_pool;
	const struct bpf_frame_desc *d;
	void *flags = NULL;
	u32 i;

	if (!prog->aux->frame_desc_table)
		return;
	d = bpf_prog_frame_desc_lookup(prog, pc);
	if (WARN_ONCE(!d, "bpf: no frame descriptor for %s at %lx\n", prog->aux->name, pc))
		return;
	for (i = 0; i < d->nent; i++) {
		const struct bpf_frame_desc_entry *ent = &d->ent[i];
		const struct bpf_resource *res = &pool->resources[ent->res];
		int phase = release_phase(res);

		if (phase == BPF_UNWIND_PHASE_SECTIONS) {
			if (ctx->phase == BPF_UNWIND_PHASE_LOCKS)
				bpf_unwind_count(ctx, fp, ent, res);
			continue;
		}
		if (phase == ctx->phase)
			bpf_unwind_entry(ctx, prog, fp, ent, res, &flags);
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
		WARN_ONCE(ctx->nr_sections[s] < 0, "bpf: %lld sections of %s to leave\n",
			  ctx->nr_sections[s], ctx->prog->aux->name);
		while (ctx->nr_sections[s]-- > 0)
			bpf_unwind_release(ctx->section[s], NULL, NULL);
	}
}

static bool bpf_stack_walker(void *cookie, u64 ip, u64 sp, u64 bp)
{
	struct bpf_throw_ctx *ctx = cookie;
	struct bpf_prog *prog;

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
	if (ctx->pad) {
		ctx->site = ip;
		ctx->slot = bpf_arch_ret_slot(ctx->kernel_bp, sp);
		return false;
	}
	if (ctx->regs) {
		const struct bpf_prog_aux *fn = bpf_unwind_fn(prog);
		u64 fp = bp + fn->frame_fp_off;

		/* With a private stack, the frame's R10 is this CPU's private frame. */
		if (fn->priv_stack_ptr)
			fp = (u64)(long)this_cpu_ptr(fn->priv_stack_ptr) + fn->priv_frame_off;
		/*
		 * Release what the frame holds of this walk's phase. The
		 * innermost frame of a fault is at the faulting instruction;
		 * every other frame is at a call, whose return address is the
		 * first byte of the next instruction. Then recover the caller's
		 * callee-saved registers from the frame.
		 */
		bpf_unwind_frame(ctx, prog, ctx->cnt || ctx->kind != BPF_THROW_FAULT ? ip - 1 : ip,
				 fp);
		bpf_unwind_recover(fn, bp, ctx->saved, BPF_THROW_NR_CALLEE_SAVED);
	}
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

/*
 * Walk the frames from the throw site outwards for one phase, from the
 * register file of the throw site again: every walk passes the same frames
 * and ends at the same one, with the same registers recovered and the same
 * pad found. What the walk learns of the pad is acted on once they are over.
 */
static void bpf_unwind_walk(struct bpf_throw_ctx *ctx, int phase)
{
	ctx->phase = phase;
	ctx->cnt = 0;
	ctx->pad = 0;
	ctx->kernel_bp = 0;
	ctx->site = 0;
	ctx->slot = NULL;
	if (ctx->regs)
		memcpy(ctx->saved, &ctx->regs->r[BPF_REG_6], sizeof(ctx->saved));
	arch_bpf_stack_walk(bpf_stack_walker, ctx);
}

/*
 * Release what the frames hold in four phases, each a walk over the frames
 * innermost first that releases each frame's entries of the phase in
 * descriptor order: locks and IRQ flags, RCU-protected objects, sections,
 * then the other objects. The frames are never gathered, so their number
 * is not bounded: a recursive subprog nests as deep as the stack allows.
 * The sections need no walk of their own, the first one summed them.
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
 * bpf_cancel_entry(), which the unwinder made its return address, and the
 * cancellation goes on from the call. A callback the kernel ran returns the
 * program's cancel value to it. @regs is the register file of the throw
 * site, or NULL when the architecture has no native entry and the kfunc was
 * called directly; with it, the resources the frames unwound hold are
 * released and their callee-saved registers restored for the callback,
 * without it the main program's prologue has saved them all. @kind says how
 * the throw site was reached.
 */
void bpf_throw_unwind(struct bpf_throw_regs *regs, u64 cookie, unsigned int kind)
{
	struct bpf_throw_ctx ctx = { .regs = regs, .kind = kind };
	bool kernel = kind != BPF_THROW_CALL, tell = kernel;
	struct bpf_prog_aux *aux, *main_aux;
	u64 (*cb)(u64, u64, u64, u64, u64);

	bpf_unwind_frames(&ctx);
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
	/*
	 * The main program completes with the cookie, or with the program
	 * type's default when the kernel raised the throw. A site in the
	 * exception callback completes the way a kernel throw does, since the
	 * callback cannot be run a second time. A callback a helper ran leaves
	 * into the pad of the helper, and the cancellation goes on from the
	 * call to it, where the program's main frame is reached in turn; a
	 * callback the kernel ran returns the cancel value, which the kernel
	 * code ignores. A struct_ops gets to know that the kernel cancelled an
	 * invocation of one of its programs, once the invocation is over.
	 */
	aux = ctx.prog->aux;
	main_aux = aux->main_prog_aux;
	if (ctx.pad) {
		if (!WARN_ON_ONCE(!ctx.slot || *ctx.slot != ctx.site))
			*ctx.slot = (u64)(long)bpf_arch_cancel_entry();
		bpf_arch_set_ret_addr(ctx.bp, ctx.pad);
		cookie = ctx.site;
		cb = main_aux->bpf_cancel_cb;
		tell = false;
	} else if (aux->exception_cb || bpf_is_subprog(ctx.prog)) {
		/* The verifier lets a helper run a callback with a site only with a pad. */
		WARN_ON_ONCE(!aux->exception_cb && !aux->async_cb);
		cookie = main_aux->cancel_retval;
		cb = main_aux->bpf_cancel_cb;
	} else {
		if (kernel)
			cookie = main_aux->cancel_retval;
		cb = main_aux->bpf_exception_cb;
	}
	if (tell && main_aux->prog->type == BPF_PROG_TYPE_STRUCT_OPS && main_aux->st_ops &&
	    main_aux->st_ops->cancel)
		main_aux->st_ops->cancel(main_aux->prog);
	WARN_ON_ONCE(!cb);
	cb(cookie, ctx.sp, ctx.bp, (u64)(long)ctx.saved, 0);
	WARN(1, "A call to BPF exception callback should never return\n");
}
