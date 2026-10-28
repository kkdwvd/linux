// SPDX-License-Identifier: GPL-2.0-only
/*
 * The exception unwinder: from a throw site, release what each BPF frame
 * holds according to its frame descriptor, recover the callee-saved
 * registers the discarded frames saved, and transfer to the frame the kernel
 * entered, which returns.
 */
#include <linux/bpf.h>
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
const struct bpf_frame_desc *bpf_prog_frame_desc_lookup(const struct bpf_prog *prog, unsigned long ip)
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

/*
 * Release the resource an entry describes, at run time. Not inlined so that
 * every release of an unwind can be observed by attaching to this function.
 */
noinline void bpf_unwind_release(const struct bpf_resource *res, void *loc, void *flags)
{
	void *obj;

	switch (res->kind) {
	case BPF_RESOURCE_DYNPTR_RINGBUF:
		bpf_ringbuf_discard_dynptr_proto.func((u64)(long)loc, 0, 0, 0, 0);
		return;
	case BPF_RESOURCE_ITER:
		res->dtor(loc);
		return;
	case BPF_RESOURCE_IRQ_FLAG:
		bpf_local_irq_restore(loc);
		return;
	case BPF_RESOURCE_IRQ_FLAG_LOCK:
		/* Restored together with the lock that saved it. */
		return;
	case BPF_RESOURCE_RCU:
		bpf_rcu_read_unlock();
		return;
	case BPF_RESOURCE_PREEMPT:
		bpf_preempt_enable();
		return;
	case BPF_RESOURCE_SPIN_LOCK:
	case BPF_RESOURCE_RES_LOCK:
	case BPF_RESOURCE_RES_LOCK_IRQ:
		obj = loc ? *(void **)loc + res->delta : res->addr;
		if (res->kind == BPF_RESOURCE_SPIN_LOCK)
			bpf_spin_unlock_proto.func((u64)(long)obj, 0, 0, 0, 0);
		else if (res->kind == BPF_RESOURCE_RES_LOCK)
			bpf_res_spin_unlock(obj);
		else
			bpf_res_spin_unlock_irqrestore(obj, flags);
		return;
	default:
		break;
	}
	obj = *(void **)loc;
	if (!obj)
		return;
	switch (res->kind) {
	case BPF_RESOURCE_OBJ:
		bpf_obj_drop_impl(obj, res->meta);
		break;
	case BPF_RESOURCE_PERCPU_OBJ:
		bpf_percpu_obj_drop_impl(obj, res->meta);
		break;
	case BPF_RESOURCE_KPTR:
		res->dtor(obj);
		break;
#ifdef CONFIG_INET
	case BPF_RESOURCE_SOCK:
		bpf_sk_release_proto.func((u64)(long)obj, 0, 0, 0, 0);
		break;
#endif
	case BPF_RESOURCE_RINGBUF:
		bpf_ringbuf_discard_proto.func((u64)(long)obj, 0, 0, 0, 0);
		break;
	default:
		WARN_ON_ONCE(1);
	}
}

/*
 * Release the resources of one frame of @prog during an unwind. @pc is an
 * address inside the instruction the frame is at, @fp the frame's BPF frame
 * pointer, @regs the register file saved at the throw site when this is the
 * innermost frame, and @callee_regs the frame's R6-R9.
 */
void bpf_unwind_frame(const struct bpf_prog *prog, unsigned long pc, u64 fp,
		      const struct bpf_throw_regs *regs, const u64 *callee_regs)
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
		void *loc;
		u64 reg;
		int n;

		if (ent->loc == BPF_FRAME_LOC_NONE) {
			for (n = ent->off; n; n--)
				bpf_unwind_release(res, NULL, flags);
			if (res->kind == BPF_RESOURCE_RES_LOCK_IRQ)
				flags = NULL;
			continue;
		}
		if (ent->loc == BPF_FRAME_LOC_STACK) {
			loc = (void *)(long)(fp + ent->off);
		} else if (ent->off >= BPF_REG_6) {
			reg = callee_regs[ent->off - BPF_REG_6];
			loc = &reg;
		} else if (regs) {
			reg = regs->r[ent->off];
			loc = &reg;
		} else {
			WARN_ONCE(1, "bpf: no register file to release R%d of %s from\n", ent->off,
				  prog->aux->name);
			continue;
		}
		/* The flags of an irqsave lock precede the lock, which restores them. */
		if (res->kind == BPF_RESOURCE_IRQ_FLAG_LOCK)
			flags = loc;
		bpf_unwind_release(res, loc, flags);
		if (res->kind == BPF_RESOURCE_RES_LOCK_IRQ)
			flags = NULL;
	}
}

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
};

static bool bpf_stack_walker(void *cookie, u64 ip, u64 sp, u64 bp)
{
	struct bpf_throw_ctx *ctx = cookie;
	struct bpf_prog *prog;
	int i;

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
		/* The symbol of a program JITed as a set of functions covers its first function. */
		const struct bpf_prog_aux *fn = !prog->is_func && prog->aux->func ?
						prog->aux->func[0]->aux : prog->aux;
		u64 fp = bp + fn->frame_fp_off;

		/* With a private stack, the frame's R10 is this CPU's private frame. */
		if (fn->priv_stack_ptr)
			fp = (u64)(long)this_cpu_ptr(fn->priv_stack_ptr) + fn->priv_frame_off;
		/*
		 * Release what this frame holds. Every frame is at a call, whose
		 * return address is the first byte of the next instruction. Then
		 * recover the caller's callee-saved registers: those this frame's
		 * prologue saved sit in its frame, the rest are still the values
		 * the frame itself has.
		 */
		bpf_unwind_frame(prog, ip - 1, fp, ctx->cnt ? NULL : ctx->regs, ctx->saved);
		for (i = 0; i < BPF_THROW_NR_CALLEE_SAVED; i++)
			if (fn->callee_reg_off[i])
				ctx->saved[i] = *(u64 *)(long)(bp + fn->callee_reg_off[i]);
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
 * entry and the kfunc was called directly; with it, the callee-saved registers
 * of the frames unwound are restored for the callback, without it the main
 * program's prologue has saved them all.
 */
void bpf_throw_unwind(struct bpf_throw_regs *regs, u64 cookie)
{
	struct bpf_throw_ctx ctx = { .regs = regs };

	if (regs)
		memcpy(ctx.saved, &regs->r[BPF_REG_6], sizeof(ctx.saved));
	arch_bpf_stack_walk(bpf_stack_walker, &ctx);
	WARN_ON_ONCE(!ctx.prog);
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
