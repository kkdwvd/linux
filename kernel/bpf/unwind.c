// SPDX-License-Identifier: GPL-2.0-only
/*
 * The exception unwinder: from a throw site, gather the BPF frames up to the
 * one the kernel entered, release what they hold according to their frame
 * descriptors, recover the callee-saved registers the discarded frames
 * saved, and transfer to that frame, which returns.
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

/* One BPF frame of an unwind, recorded by the stack walk and released after it. */
struct bpf_unwind_frame {
	const struct bpf_prog *prog;
	const struct bpf_frame_desc *desc;	/* of the instruction the frame is at, or NULL */
	u64 bp;					/* the native frame pointer the walk reported */
	u64 fp;					/* the frame's R10 */
};

struct bpf_throw_ctx {
	struct bpf_prog *prog;	/* the program of the frame the unwinder stops at */
	u64 sp;
	u64 bp;
	int cnt;
	const struct bpf_throw_regs *regs;	/* register file of the throw site, or NULL */
	/*
	 * The callee-saved registers of the frame being walked, R6-R9 then the
	 * architecture's own: what the throw site had, then what each frame
	 * recovered of its caller's. After the main frame they are the ones
	 * its caller expects back.
	 */
	u64 saved[BPF_THROW_NR_CALLEE_SAVED];
	/* The BPF frames the walk found, innermost first. */
	u32 nr_frames;
	struct bpf_unwind_frame frames[MAX_CALL_FRAMES];
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
 * The R6-R9 of frame @f: the throw site's, then what each frame below it
 * saved of its caller's, as the walk recovered them.
 */
static void bpf_unwind_frame_regs(const struct bpf_throw_ctx *ctx, u32 f, u64 *regs)
{
	u32 g;

	memcpy(regs, &ctx->regs->r[BPF_REG_6], (BPF_REG_10 - BPF_REG_6) * sizeof(*regs));
	for (g = 0; g < f; g++)
		bpf_unwind_recover(bpf_unwind_fn(ctx->frames[g].prog), ctx->frames[g].bp, regs,
				   BPF_REG_10 - BPF_REG_6);
}

/*
 * Record a BPF frame for the releases that follow the walk: its program, the
 * descriptor of the instruction @pc is in, and its frame pointers.
 */
static void bpf_unwind_record(struct bpf_throw_ctx *ctx, const struct bpf_prog *prog,
			      unsigned long pc, u64 bp, u64 fp)
{
	struct bpf_unwind_frame *frame;

	if (WARN_ONCE(ctx->nr_frames == MAX_CALL_FRAMES, "bpf: more than %d frames to unwind\n",
		      MAX_CALL_FRAMES))
		return;
	frame = &ctx->frames[ctx->nr_frames++];
	frame->prog = prog;
	frame->bp = bp;
	frame->fp = fp;
	if (!prog->aux->frame_desc_table)
		return;
	frame->desc = bpf_prog_frame_desc_lookup(prog, pc);
	WARN_ONCE(!frame->desc, "bpf: no frame descriptor for %s at %lx\n", prog->aux->name, pc);
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

/*
 * The handle of a located entry of frame @f: the pointer the location holds,
 * or the address of the stack object at it. Returns false when there is
 * nothing to release.
 */
static bool bpf_unwind_handle(const struct bpf_throw_ctx *ctx, u32 f,
			      const struct bpf_frame_desc_entry *ent, void **handle)
{
	const struct bpf_unwind_frame *frame = &ctx->frames[f];
	const char *name = frame->prog->aux->name;
	u64 regs[BPF_REG_10 - BPF_REG_6];
	u64 val;

	switch (ent->loc) {
	case BPF_FRAME_LOC_STACK:
		val = frame->fp + ent->off;
		if (!(ent->flags & BPF_FRAME_ENT_INDIRECT)) {
			*handle = (void *)(long)val;
			return true;
		}
		val = *(u64 *)(long)val;
		break;
	case BPF_FRAME_LOC_REG:
		/* A register holds a pointer: only the innermost frame has R0-R5. */
		if (ent->off >= BPF_REG_6) {
			bpf_unwind_frame_regs(ctx, f, regs);
			val = regs[ent->off - BPF_REG_6];
		} else if (!f && ctx->regs) {
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
 * Release the resource a located entry of frame @f describes. @flags carries
 * the saved IRQ flags of an irqsave lock from their entry to the lock's,
 * which follows it.
 */
static void bpf_unwind_entry(struct bpf_throw_ctx *ctx, u32 f,
			     const struct bpf_frame_desc_entry *ent, const struct bpf_resource *res,
			     void **flags)
{
	void *handle;

	if (ent->loc == BPF_FRAME_LOC_NONE) {
		if (WARN_ON_ONCE(!resource_is_lock(res->kind)))
			return;
		handle = res->addr;
	} else {
		if (!bpf_unwind_handle(ctx, f, ent, &handle))
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
	    WARN_ONCE(!*flags, "bpf: no irq flags for the lock of %s\n", ctx->frames[f].prog->aux->name))
		goto out;
	bpf_unwind_release(res, handle, *flags);
out:
	if (res->kind == BPF_RESOURCE_RES_LOCK_IRQ)
		*flags = NULL;
}

/*
 * Leave the sections the frames hold in all, per kind. A frame's entry counts
 * the sections it entered less those of its callers it or a callee left,
 * which nets out a callee's leaving of a caller's section, and a frame whose
 * paths disagree on the count keeps it in a counter slot. Sections of one
 * kind are all the same: the sum is left.
 */
static void bpf_unwind_sections(struct bpf_throw_ctx *ctx)
{
	const struct bpf_resource *res[BPF_UNWIND_NR_SECTIONS] = {};
	s64 n[BPF_UNWIND_NR_SECTIONS] = {};
	u32 f, i;
	int s;

	for (f = 0; f < ctx->nr_frames; f++) {
		const struct bpf_unwind_frame *frame = &ctx->frames[f];
		const struct bpf_frame_desc *d = frame->desc;
		const struct bpf_frame_desc_pool *pool;

		if (!d)
			continue;
		pool = frame->prog->aux->frame_desc_pool;
		for (i = 0; i < d->nent; i++) {
			const struct bpf_frame_desc_entry *ent = &d->ent[i];
			const struct bpf_resource *r = &pool->resources[ent->res];

			if (!resource_is_section(r->kind))
				continue;
			s = section_index(r->kind);
			res[s] = r;
			if (ent->loc == BPF_FRAME_LOC_NONE)
				n[s] += ent->off;
			else if (!WARN_ON_ONCE(ent->loc != BPF_FRAME_LOC_STACK ||
					       !(ent->flags & BPF_FRAME_ENT_COUNTER)))
				n[s] += *(s64 *)(long)(frame->fp + ent->off);
		}
	}
	for (s = 0; s < BPF_UNWIND_NR_SECTIONS; s++) {
		WARN_ONCE(n[s] < 0, "bpf: %lld sections of %s to leave\n", n[s],
			  ctx->frames[0].prog->aux->name);
		while (n[s]-- > 0)
			bpf_unwind_release(res[s], NULL, NULL);
	}
}

/*
 * Release what the recorded frames hold, in four phases over all of them,
 * innermost frame first and each frame's entries in descriptor order: locks
 * and IRQ flags, RCU-protected objects, sections, then the other objects.
 */
static void bpf_unwind_frames(struct bpf_throw_ctx *ctx)
{
	u32 f, i;
	int phase;

	for (phase = 0; phase < BPF_UNWIND_NR_PHASES; phase++) {
		if (phase == BPF_UNWIND_PHASE_SECTIONS) {
			bpf_unwind_sections(ctx);
			continue;
		}
		for (f = 0; f < ctx->nr_frames; f++) {
			const struct bpf_unwind_frame *frame = &ctx->frames[f];
			const struct bpf_frame_desc *d = frame->desc;
			const struct bpf_frame_desc_pool *pool;
			void *flags = NULL;

			if (!d)
				continue;
			pool = frame->prog->aux->frame_desc_pool;
			for (i = 0; i < d->nent; i++) {
				const struct bpf_frame_desc_entry *ent = &d->ent[i];
				const struct bpf_resource *res = &pool->resources[ent->res];

				if (release_phase(res) != phase)
					continue;
				bpf_unwind_entry(ctx, f, ent, res, &flags);
			}
		}
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
	if (!prog)
		return !ctx->cnt;
	if (ctx->regs) {
		const struct bpf_prog_aux *fn = bpf_unwind_fn(prog);
		u64 fp = bp;

		/*
		 * Record the frame for the releases once the walk is over. Every
		 * frame is at a call, whose return address is the first byte of
		 * the next instruction. Then recover the caller's callee-saved
		 * registers from the frame.
		 */
		bpf_unwind_record(ctx, prog, ip - 1, bp, fp);
		bpf_unwind_recover(fn, bp, ctx->saved, BPF_THROW_NR_CALLEE_SAVED);
	}
	ctx->cnt++;
	if (bpf_is_subprog(prog))
		return true;
	ctx->prog = prog;
	ctx->sp = sp;
	ctx->bp = bp;
	return false;
}

/*
 * Unwind the stack to the exception callback of the main program. @regs is the
 * register file of the throw site, or NULL when the architecture has no native
 * entry and the kfunc was called directly; with it, the resources the frames
 * unwound hold are released and their callee-saved registers restored for the
 * callback, without it the main program's prologue has saved them all.
 */
void bpf_throw_unwind(struct bpf_throw_regs *regs, u64 cookie)
{
	struct bpf_throw_ctx ctx = { .regs = regs };

	if (regs)
		memcpy(ctx.saved, &regs->r[BPF_REG_6], sizeof(ctx.saved));
	arch_bpf_stack_walk(bpf_stack_walker, &ctx);
	WARN_ON_ONCE(!ctx.prog);
	WARN_ON_ONCE(ctx.prog && !ctx.prog->aux->exception_boundary);
	WARN_ON_ONCE(!ctx.bp);
	WARN_ON_ONCE(!ctx.cnt);
	bpf_unwind_frames(&ctx);
	/*
	 * Prevent KASAN false positives for CONFIG_KASAN_STACK by unpoisoning
	 * deeper stack depths than ctx.sp as we do not return from here, which
	 * skips compiler generated instrumentation to do the same. Some
	 * architectures cannot recover sp while unwinding, so fall back to bp.
	 */
	kasan_unpoison_task_stack_below((void *)(long)(ctx.sp ?: ctx.bp));
	ctx.prog->aux->bpf_exception_cb(cookie, ctx.sp, ctx.bp, (u64)(long)ctx.saved, 0);
	WARN(1, "A call to BPF exception callback should never return\n");
}
