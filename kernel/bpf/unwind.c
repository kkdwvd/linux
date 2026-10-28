// SPDX-License-Identifier: GPL-2.0-only
/*
 * The exception unwinder: from a throw site, walk the BPF frames up to the
 * one the kernel entered, once per phase of the release order, releasing
 * what each frame holds of that phase according to the frame descriptor of
 * its site and of the chain of its callers, once the walk knows them, and
 * recovering the callee-saved registers the discarded frames saved, then
 * transfer to that frame, which returns.
 */
#include <linux/bpf.h>
#include <linux/bpf_verifier.h>
#include <linux/filter.h>
#include <linux/irqflags.h>
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
 * The entries of the throw site of prog that ip falls into, [*first, *last)
 * of its table, one per chain the site has a descriptor for; false when ip
 * is in no site. ip is an address within the instruction: a caller that
 * holds a return address passes ra - 1, since the return address is the
 * first byte of the next instruction.
 */
static bool bpf_unwind_site(const struct bpf_prog *prog, unsigned long ip, u32 *first, u32 *last)
{
	const struct bpf_frame_desc_table *tab = prog->aux->frame_desc_table;
	unsigned long off;
	u32 l, r, m;

	if (!tab || !tab->filled)
		return false;
	off = ip - (unsigned long)prog->bpf_func;

	/* The sites are disjoint and sorted: find the first entry that ends after off. */
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
		return false;
	*first = l;
	for (r = l + 1; r < tab->cnt && tab->site[r].off == tab->site[l].off; r++)
		;
	*last = r;
	return true;
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
	kvfree(pool->nodes);
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

/* A frame the walk has passed and not released yet, see bpf_unwind_note(). */
struct bpf_unwind_pending {
	const struct bpf_prog *prog;
	unsigned long pc;
	u64 bp;
	u64 fp;
};

/*
 * Which descriptor of a site applies to a frame depends on the chain of its
 * callers, which the walk gets to after the frame: a frame is released once
 * this many callers are known, which is more than the verifier tells a chain
 * apart by, or at the end of the walk.
 */
#define BPF_UNWIND_WINDOW	32

struct bpf_throw_ctx {
	struct bpf_prog *prog;	/* the program of the frame the unwinder stops at */
	u64 sp;
	u64 bp;
	int cnt;
	const struct bpf_throw_regs *regs;	/* register file of the throw site, or NULL */
	int phase;				/* BPF_UNWIND_PHASE_*: what this walk releases */
	/*
	 * The callee-saved registers of the frame being walked, R6-R9 then the
	 * architecture's own: what the throw site had, then what each frame
	 * recovered of its caller's. After the main frame they are the ones
	 * its caller expects back.
	 */
	u64 saved[BPF_THROW_NR_CALLEE_SAVED];
	/* The sections the frames hold, per kind, summed by the first walk. */
	const struct bpf_resource *section[BPF_UNWIND_NR_SECTIONS];
	s64 nr_sections[BPF_UNWIND_NR_SECTIONS];
	/*
	 * The frames the walk has passed and not released yet, innermost first,
	 * see bpf_stack_walker(); how many frames the walk released already,
	 * and the callee-saved registers recovered through them, from which
	 * those of a pending frame are replayed through the frames pending
	 * below it.
	 */
	struct bpf_unwind_pending pending[BPF_UNWIND_WINDOW];
	int nr_pending;
	int nr_known;
	int released;
	u64 base[BPF_REG_10 - BPF_REG_6];
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
 * The handle of a located entry of the frame being released: the pointer
 * the location holds, or the address of the stack object at it. @fp is the
 * frame's R10 and @regs its R6-R9, replayed through the frames below it, and
 * only the @innermost frame has R0-R5, in the register file of the throw
 * site. Returns false when there is nothing to release.
 */
static bool bpf_unwind_handle(const struct bpf_throw_ctx *ctx, const struct bpf_prog *prog, u64 fp,
			      const struct bpf_frame_desc_entry *ent, const u64 *regs, bool innermost,
			      void **handle)
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
			val = regs[ent->off - BPF_REG_6];
		} else if (innermost && ctx->regs) {
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
			     const u64 *regs, bool innermost, void **flags)
{
	void *handle;

	if (ent->loc == BPF_FRAME_LOC_NONE) {
		if (WARN_ON_ONCE(!resource_is_lock(res->kind)))
			return;
		handle = res->addr;
	} else {
		if (!bpf_unwind_handle(ctx, prog, fp, ent, regs, innermost, &handle))
			goto out;
		/* The pointer may point into the object, or at the object that holds the lock. */
		handle -= res->delta;
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

/* Were interrupts enabled when the flags of @ent were saved? Not when the flags are not there. */
static bool bpf_unwind_irqs_enabled(const struct bpf_throw_ctx *ctx, const struct bpf_prog *prog,
				    u64 fp, const struct bpf_frame_desc_entry *ent, const u64 *regs,
				    bool innermost)
{
	void *handle;

	if (ent->loc == BPF_FRAME_LOC_NONE ||
	    !bpf_unwind_handle(ctx, prog, fp, ent, regs, innermost, &handle))
		return false;
	return !arch_irqs_disabled_flags(*(unsigned long *)handle);
}

/*
 * Release what the frame of @prog that descriptor @d describes holds of the
 * phase of this walk, in descriptor order; @regs are its R6-R9, and the
 * @innermost frame has R0-R5 in the register file of the throw site. The
 * first walk counts the frame's sections for theirs, and releases the locks
 * and IRQ flags in two passes: the flags a frame saved with interrupts
 * enabled, of which it can have one at most, since every later save found
 * them disabled, are restored last, after the locks and the other flags in
 * whatever order the frame saved them; the flags of an irqsave lock go with
 * the lock.
 */
static void bpf_unwind_frame(struct bpf_throw_ctx *ctx, const struct bpf_prog *prog,
			     const struct bpf_frame_desc *d, u64 fp, const u64 *regs, bool innermost)
{
	const struct bpf_frame_desc_pool *pool = prog->aux->frame_desc_pool;
	int passes = ctx->phase == BPF_UNWIND_PHASE_LOCKS ? 2 : 1, pass;
	u32 i;

	for (pass = 0; pass < passes; pass++) {
		void *flags = NULL;
		bool late = false;

		for (i = 0; i < d->nent; i++) {
			const struct bpf_frame_desc_entry *ent = &d->ent[i];
			const struct bpf_resource *res = &pool->resources[ent->res];
			int phase = release_phase(res);

			if (phase == BPF_UNWIND_PHASE_SECTIONS) {
				if (ctx->phase == BPF_UNWIND_PHASE_LOCKS && !pass)
					bpf_unwind_count(ctx, fp, ent, res);
				continue;
			}
			if (phase != ctx->phase)
				continue;
			if (passes == 2) {
				/* an irqsave lock goes in the pass of its flags, which precede it */
				if (resource_is_irq(res->kind))
					late = bpf_unwind_irqs_enabled(ctx, prog, fp, ent, regs,
								       innermost);
				else if (res->kind != BPF_RESOURCE_RES_LOCK_IRQ)
					late = false;
				if (late != (pass == 1))
					continue;
			}
			bpf_unwind_entry(ctx, prog, fp, ent, res, regs, innermost, &flags);
		}
	}
}

/*
 * The node of the chain of pending frame @i in the trie of its program: the
 * path through the sites its callers wait in, nearest first, as far as the
 * trie has it. The verifier interned the chains it told descriptors apart
 * by, and no more: a frame it saw under a shorter chain, the frame below
 * being the main program or a subprog verified on its own, is found at the
 * node of that chain by bpf_unwind_pick().
 */
static u32 bpf_unwind_chain(const struct bpf_throw_ctx *ctx, const struct bpf_frame_desc_pool *pool,
			    int i)
{
	u32 node = 0, first, last, n;
	int k;

	for (k = i + 1; k < ctx->nr_known; k++) {
		const struct bpf_unwind_pending *c = &ctx->pending[k];

		if (c->prog->aux->frame_desc_pool != pool ||
		    !bpf_unwind_site(c->prog, c->pc, &first, &last))
			break;
		for (n = 1; n < pool->node_cnt; n++)
			if (pool->nodes[n].parent == node &&
			    pool->nodes[n].subprog == c->prog->aux->func_idx &&
			    pool->nodes[n].site == first)
				break;
		if (n == pool->node_cnt)
			break;
		node = n;
	}
	return node;
}

/*
 * The descriptor of the site at entries [first, last) of the table of @prog
 * for chain @node, or for the nearest ancestor of the node that has one: a
 * site has one for a shorter chain where the verifier saw the frame under
 * that one, and that for any chain, at the root, where the chains agree.
 */
static const struct bpf_frame_desc *bpf_unwind_pick(const struct bpf_prog *prog, u32 first, u32 last,
						    u32 node)
{
	const struct bpf_frame_desc_pool *pool = prog->aux->frame_desc_pool;
	const struct bpf_frame_desc_table *tab = prog->aux->frame_desc_table;
	u32 i;

	for (;;) {
		for (i = first; i < last; i++)
			if (tab->site[i].node == node)
				return pool->desc[tab->site[i].desc];
		if (!node)
			return NULL;
		node = pool->nodes[node].parent;
	}
}

/*
 * Release what pending frame @i holds of the phase of this walk, by the
 * descriptor of its site for the chain of its callers. Its R6-R9 are
 * replayed from those recovered through the frames released before it,
 * through the frames pending below it.
 */
static void bpf_unwind_release_pending(struct bpf_throw_ctx *ctx, int i)
{
	const struct bpf_unwind_pending *p = &ctx->pending[i];
	const struct bpf_prog *prog = p->prog;
	const struct bpf_frame_desc *d;
	u64 regs[BPF_REG_10 - BPF_REG_6];
	u32 first, last;
	int k;

	if (!prog->aux->frame_desc_table)
		return;
	if (WARN_ONCE(!bpf_unwind_site(prog, p->pc, &first, &last),
		      "bpf: no frame descriptor for %s at %lx\n", prog->aux->name, p->pc))
		return;
	d = bpf_unwind_pick(prog, first, last, bpf_unwind_chain(ctx, prog->aux->frame_desc_pool, i));
	if (WARN_ONCE(!d, "bpf: no frame descriptor for the chain of %s at %lx\n", prog->aux->name,
		      p->pc))
		return;
	memcpy(regs, ctx->base, sizeof(regs));
	for (k = 0; k < i; k++)
		bpf_unwind_recover(bpf_unwind_fn(ctx->pending[k].prog), ctx->pending[k].bp, regs,
				   ARRAY_SIZE(regs));
	bpf_unwind_frame(ctx, prog, d, p->fp, regs, !ctx->released && !i);
}

/*
 * Note a frame the walk passed, to release once its callers are known, or,
 * when it is not one to @release, to be known as a caller of the pending
 * frames. The window holds BPF_UNWIND_WINDOW frames: when it is full, the
 * oldest frame to release has that many callers known, more than the
 * verifier tells a chain apart by, and is released, with its callee-saved
 * registers recovered into the base the pending frames replay from.
 */
static void bpf_unwind_note(struct bpf_throw_ctx *ctx, const struct bpf_prog *prog, unsigned long pc,
			    u64 bp, u64 fp, bool release)
{
	if (ctx->nr_known == BPF_UNWIND_WINDOW) {
		if (ctx->nr_pending) {
			bpf_unwind_release_pending(ctx, 0);
			bpf_unwind_recover(bpf_unwind_fn(ctx->pending[0].prog), ctx->pending[0].bp,
					   ctx->base, ARRAY_SIZE(ctx->base));
			ctx->nr_pending--;
			ctx->released++;
		}
		memmove(ctx->pending, ctx->pending + 1, (ctx->nr_known - 1) * sizeof(ctx->pending[0]));
		ctx->nr_known--;
	}
	ctx->pending[ctx->nr_known++] = (struct bpf_unwind_pending) {
		.prog = prog, .pc = pc, .bp = bp, .fp = fp,
	};
	if (release)
		ctx->nr_pending++;
}

/* The walk is over: the callers of the pending frames are all known. */
static void bpf_unwind_flush(struct bpf_throw_ctx *ctx)
{
	int i;

	for (i = 0; i < ctx->nr_pending; i++)
		bpf_unwind_release_pending(ctx, i);
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
	if (!prog)
		return !ctx->cnt;
	if (ctx->regs) {
		const struct bpf_prog_aux *fn = bpf_unwind_fn(prog);
		u64 fp = bp + fn->frame_fp_off;

		/* With a private stack, the frame's R10 is this CPU's private frame. */
		if (fn->priv_stack_ptr)
			fp = (u64)(long)this_cpu_ptr(fn->priv_stack_ptr) + fn->priv_frame_off;
		/*
		 * Note the frame, to release what it holds of this walk's
		 * phase once its callers are known. Every frame is at a call,
		 * whose return address is the first byte of the next
		 * instruction. Then recover the caller's callee-saved registers
		 * from the frame.
		 */
		bpf_unwind_note(ctx, prog, ip - 1, bp, fp, true);
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
 * Walk the frames from the throw site outwards for one phase, from the
 * register file of the throw site again: every walk passes the same frames
 * and ends at the same one, with the same registers recovered.
 */
static void bpf_unwind_walk(struct bpf_throw_ctx *ctx, int phase)
{
	ctx->phase = phase;
	ctx->cnt = 0;
	ctx->nr_pending = 0;
	ctx->nr_known = 0;
	ctx->released = 0;
	if (ctx->regs) {
		memcpy(ctx->saved, &ctx->regs->r[BPF_REG_6], sizeof(ctx->saved));
		memcpy(ctx->base, &ctx->regs->r[BPF_REG_6], sizeof(ctx->base));
	}
	arch_bpf_stack_walk(bpf_stack_walker, ctx);
	bpf_unwind_flush(ctx);
}

/*
 * Release what the frames hold in four phases, each a walk over the frames
 * innermost first that releases each frame's entries of the phase in
 * descriptor order: locks and IRQ flags, RCU-protected objects, sections,
 * then the other objects. The frames are released as they leave the window
 * of the walk, so their number is not bounded: a recursive subprog nests as
 * deep as the stack allows. The sections need no walk of their own, the
 * first one summed them.
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
 * Unwind the stack to the exception callback of the main program. @regs is the
 * register file of the throw site, or NULL when the architecture has no native
 * entry and the kfunc was called directly; with it, the resources the frames
 * unwound hold are released and their callee-saved registers restored for the
 * callback, without it the main program's prologue has saved them all.
 */
void bpf_throw_unwind(struct bpf_throw_regs *regs, u64 cookie)
{
	struct bpf_throw_ctx ctx = { .regs = regs };

	bpf_unwind_frames(&ctx);
	WARN_ON_ONCE(!ctx.prog);
	WARN_ON_ONCE(ctx.prog && !ctx.prog->aux->exception_boundary);
	WARN_ON_ONCE(!ctx.bp);
	WARN_ON_ONCE(!ctx.cnt);
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
