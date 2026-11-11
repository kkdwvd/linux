// SPDX-License-Identifier: GPL-2.0-only
/*
 * Frame descriptors: the hidden stack slots in which the frames of a program
 * that may throw keep the handles of the kernel resources they hold, for the
 * unwinder to release.
 *
 * Nothing is inferred about where a program keeps a reference. The handle of
 * a resource is written down when the resource is acquired: the pointer a
 * call returns, the address of the iterator, the saved IRQ flags or the lock
 * a call takes, the record of a ringbuf dynptr. It goes into a slot of the
 * frame that runs the call, and comes out again when the resource is
 * released. The slots of a frame for one resource class form a pool, as many
 * as a frame holds of the class at once: an acquisition takes the first free
 * slot, a release clears the slot that holds its handle. The sections a
 * frame is in, RCU read and preemption disabled, have no handle and are
 * counted in a slot, one per kind. The unwinder releases, for every frame it
 * unwinds, what the slots of the frame hold, see unwind.c.
 *
 * A frame may release what another frame holds: a callee drops the object it
 * was passed, a callback the object of the frame that called the helper. The
 * handle is in no slot of the releasing frame then, and bpf_unwind_forget()
 * walks the frames below for it and clears the nearest slot of the class
 * that holds it. Two references to one object have equal handles, and the
 * slot that is cleared may be that of the other one: the slots of the
 * frames then hold one handle for every reference held, which is all the
 * unwinder needs, and a release that does not find its handle in its own
 * frame walks the frames below as well. A frame that returns while it holds
 * something, a reference it returns or stored for its caller, a lock it
 * took, hands the slots it has in use and its counts over to the frame it
 * returns to, in bpf_unwind_handover(), before it goes.
 *
 * The main pass records, for every call that acquires or releases, the
 * class, where the handle is and how many of a class a frame holds at once.
 * The slots are reserved and the instructions that keep them emitted after
 * the pass. Each of them follows a call of a helper or a kfunc, or sits in
 * front of an exit.
 */
#include <linux/bpf.h>
#include <linux/bpf_verifier.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/kallsyms.h>
#include <linux/sort.h>

#define verbose(env, fmt, args...) bpf_verifier_log_write(env, fmt, ##args)

#define SECTION_KINDS		2	/* RCU read, preemption disabled */

/* Intern a resource class; descriptors refer to it by index. */
static int resource_intern(struct bpf_verifier_env *env, const struct bpf_resource *res)
{
	struct bpf_resource *tab;
	u32 i, cnt = env->resource_cnt;

	for (i = 0; i < cnt; i++)
		if (!memcmp(&env->resources[i], res, sizeof(*res)))
			return i;
	if (cnt >= U16_MAX)
		return -E2BIG;
	tab = kvrealloc(env->resources, array_size(cnt + 1, sizeof(*tab)), GFP_KERNEL_ACCOUNT);
	if (!tab)
		return -ENOMEM;
	tab[cnt] = *res;
	env->resources = tab;
	env->resource_cnt = cnt + 1;
	return cnt;
}

/*
 * Resolve the destructor of a referenced kernel object through the BTF
 * destructor registry, and check that the program could have called the
 * matching release kfunc itself: that is the context in which running the
 * destructor is legal. A class interned for the type already has it resolved.
 */
static int resource_registry(struct bpf_verifier_env *env, struct btf *btf, u32 btf_id,
			     struct bpf_resource *res, const char *what, bool report)
{
	const char *name = btf_name_by_offset(btf, btf_type_by_id(btf, btf_id)->name_off);
	struct btf *dtor_btf = btf;
	const struct btf_id_dtor_kfunc *dtor = btf_find_dtor(&dtor_btf, btf_id);
	const struct btf_type *t;
	u32 i, *flags;

	for (i = 0; i < env->resource_cnt; i++) {
		const struct bpf_resource *r = &env->resources[i];

		if (r->kind == res->kind && r->btf == btf && r->btf_id == btf_id) {
			res->dtor = r->dtor;
			res->sleeps = r->sleeps;
			return 0;
		}
	}
	if (!dtor || !(dtor->flags & BPF_DTOR_CLEANUP)) {
		if (report)
			verbose(env, "frame_desc: no cleanup destructor registered for %s %s\n", what,
				name);
		return -EOPNOTSUPP;
	}
	flags = btf_kfunc_flags(dtor_btf, dtor->release_btf_id, env->prog);
	if (!flags || !btf_kfunc_is_allowed(dtor_btf, dtor->release_btf_id, env->prog)) {
		if (report)
			verbose(env, "frame_desc: release kfunc of %s %s is not callable by this program\n",
				what, name);
		return -EOPNOTSUPP;
	}
	res->sleeps = *flags & KF_SLEEPABLE;
	t = btf_type_by_id(dtor_btf, dtor->kfunc_btf_id);
	res->dtor = t ? (void *)kallsyms_lookup_name(btf_name_by_offset(dtor_btf, t->name_off)) :
			NULL;
	if (!res->dtor) {
		if (report)
			verbose(env, "frame_desc: cannot resolve the destructor of %s %s\n", what, name);
		return -EINVAL;
	}
	return 0;
}

static bool helper_ok(struct bpf_verifier_env *env, enum bpf_func_id func_id)
{
	return env->ops->get_func_proto && env->ops->get_func_proto(func_id, env->prog);
}

/*
 * Does @reg point to one of the socket structs of vmlinux BTF? A referenced
 * one is the cast of an acquired socket by a helper such as
 * bpf_skc_to_tcp_sock(), which carries the socket's reference under the
 * struct's type.
 */
static bool reg_is_sock_btf(const struct bpf_reg_state *reg)
{
#ifdef CONFIG_NET
	int i;

	if (!btf_is_vmlinux(reg->btf))
		return false;
	for (i = 0; i < MAX_BTF_SOCK_TYPE; i++)
		if (reg->btf_id == btf_sock_ids[i])
			return true;
#endif
	return false;
}

/*
 * Classify the reference a register holds, @report why it cannot be. A
 * reference of a type that no destructor is registered for, or whose release
 * kfunc the program may not call, has no class: the frames keep no handle of
 * it, and a throw may not be reached while it is held.
 */
static int resource_describe(struct bpf_verifier_env *env, const struct bpf_reg_state *reg,
			     struct bpf_resource *resp, bool report)
{
	u32 flags = type_flag(reg->type) & ~PTR_MAYBE_NULL;
	struct bpf_resource res;
	int ret;

	memset(&res, 0, sizeof(res));
	switch (base_type(reg->type)) {
	case PTR_TO_BTF_ID:
		if (flags & MEM_ALLOC) {
			if (flags & ~(MEM_ALLOC | MEM_PERCPU))
				goto unsupported;
			res.kind = flags & MEM_PERCPU ? BPF_RESOURCE_PERCPU_OBJ : BPF_RESOURCE_OBJ;
			res.meta = btf_find_struct_meta(reg->btf, reg->btf_id);
			/* where the program may not drop the object, the unwinder may not either */
			if (res.meta && bpf_nmi_unsafe_prog(env) &&
			    btf_record_has_nmi_unsafe_fields(res.meta->record))
				goto unsupported;
			/* the types without fields to destroy are freed alike: one class */
			break;
		}
		if (flags & ~PTR_TRUSTED)
			goto unsupported;
		res.btf = reg->btf;
		res.btf_id = reg->btf_id;
		/* A socket cast to one of its structs is still what bpf_sk_release() takes. */
		if (reg_is_sock_btf(reg) && helper_ok(env, BPF_FUNC_sk_release)) {
			res.kind = BPF_RESOURCE_SOCK;
			break;
		}
		res.kind = BPF_RESOURCE_KPTR;
		ret = resource_registry(env, reg->btf, reg->btf_id, &res, "object", report);
		if (ret)
			return ret;
		break;
	case PTR_TO_SOCKET:
	case PTR_TO_SOCK_COMMON:
	case PTR_TO_TCP_SOCK:
		if (flags || !helper_ok(env, BPF_FUNC_sk_release))
			goto unsupported;
		res.kind = BPF_RESOURCE_SOCK;
		break;
	case PTR_TO_MEM:
		if (flags != MEM_RINGBUF || !helper_ok(env, BPF_FUNC_ringbuf_discard))
			goto unsupported;
		res.kind = BPF_RESOURCE_RINGBUF;
		break;
	default:
		goto unsupported;
	}
	*resp = res;
	return 0;
unsupported:
	if (report)
		verbose(env, "frame_desc: cannot release a reference of type %s\n",
			reg_type_str(env, reg->type));
	return -EOPNOTSUPP;
}

/*
 * The class of the iterator in @reg, the first slot of an iterator. An
 * RCU-protected iterator is destroyed before the sections of its frame end,
 * unless its destructor sleeps: that runs after every section, which is
 * the only place the program could have called it.
 */
static int resource_of_iter(struct bpf_verifier_env *env, const struct bpf_reg_state *reg)
{
	struct bpf_resource res;
	int ret;

	/* nothing may release it once its RCU protection ended */
	if (reg->type & PTR_UNTRUSTED)
		return -EOPNOTSUPP;
	memset(&res, 0, sizeof(res));
	res.kind = BPF_RESOURCE_ITER;
	res.btf = reg->iter.btf;
	res.btf_id = reg->iter.btf_id;
	ret = resource_registry(env, reg->iter.btf, reg->iter.btf_id, &res, "iterator", false);
	if (ret)
		return ret;
	res.rcu = (reg->type & MEM_RCU) && !res.sleeps;
	return resource_intern(env, &res);
}

/*
 * Does @reg point into the object of reference @id, @off bytes in: the node
 * of a list or a tree is popped and pushed that way, and the object it is
 * in is released.
 */
static bool reg_ref_off(const struct bpf_reg_state *reg, int id, s16 *off)
{
	if (reg->type == SCALAR_VALUE || reg->type == NOT_INIT || reg->id != id ||
	    !tnum_is_const(reg->var_off) || reg->var_off.value != (u64)(s16)reg->var_off.value)
		return false;
	*off = reg->var_off.value;
	return true;
}

/*
 * Does @reg point into the object whose lock @ref holds? Any constant offset
 * will do: the lock is found from the pointer value by a fixed delta, which
 * the class carries, like the delta of a pointer into an object.
 */
static bool reg_is_lock(const struct bpf_reg_state *reg, const struct bpf_reference_state *ref)
{
	if (reg->type == NOT_INIT || reg->type == SCALAR_VALUE || reg->id != ref->id ||
	    !tnum_is_const(reg->var_off))
		return false;
	if (reg->type == PTR_TO_MAP_VALUE)
		return reg->map_ptr == ref->ptr;
	return base_type(reg->type) == PTR_TO_BTF_ID && (type_flag(reg->type) & MEM_ALLOC) &&
	       reg->btf == ref->ptr;
}

/*
 * Is @slot the stack object of reference @id: the first slot of an iterator,
 * of a ringbuf dynptr, which tracks the record's reference as its parent,
 * or saved IRQ flags?
 */
static bool stack_slot_is_object(const struct bpf_stack_state *slot, int id)
{
	const struct bpf_reg_state *reg = &slot->spilled_ptr;

	switch (slot->slot_type[BPF_REG_SIZE - 1]) {
	case STACK_DYNPTR:
		return reg->dynptr.first_slot && reg->parent_id == id &&
		       (reg->dynptr.type == BPF_DYNPTR_TYPE_RINGBUF ||
			reg->dynptr.type == BPF_DYNPTR_TYPE_FILE);
	case STACK_ITER:
	case STACK_IRQ_FLAG:
		return reg->id == id;
	default:
		return false;
	}
}

/*
 * The frame and slot of the stack object of reference @ref, if it is one:
 * the object may be in the stack of another frame, created through a
 * pointer to it.
 */
static bool stack_object_find(const struct bpf_verifier_state *st,
			      const struct bpf_reference_state *ref, int *frameno, int *spi)
{
	int f, k;

	for (f = st->curframe; f >= 0; f--) {
		const struct bpf_func_state *frame = st->frame[f];

		for (k = 0; k < bpf_stack_nr_slots(frame); k++) {
			if (!stack_slot_is_object(bpf_stack_slot(frame, k), ref->id))
				continue;
			*frameno = f;
			*spi = k;
			return true;
		}
	}
	return false;
}

/*
 * The slot of @st that @reg points at, when it is the stack object of the
 * reference @id: a referenced dynptr and its clones share the reference, and
 * any of them is the object, see stack_slot_is_object(), so a pointer to any
 * of them holds the handle.
 */
static const struct bpf_stack_state *reg_object_slot(const struct bpf_verifier_state *st,
						     const struct bpf_reg_state *reg, int id)
{
	const struct bpf_stack_state *slot;
	const struct bpf_func_state *frame;
	s64 off;
	int spi;

	if (reg->type != PTR_TO_STACK || !tnum_is_const(reg->var_off) ||
	    reg->frameno > st->curframe)
		return NULL;
	off = reg->var_off.value;
	if (off >= 0 || off % BPF_REG_SIZE)
		return NULL;
	frame = st->frame[reg->frameno];
	spi = -off / BPF_REG_SIZE - 1;
	if (spi >= bpf_stack_nr_slots(frame))
		return NULL;
	slot = bpf_stack_slot(frame, spi);
	return stack_slot_is_object(slot, id) ? slot : NULL;
}


/*
 * The register among R1-R5 that holds the handle of @ref at the current
 * insn, or -1; a release may take the node of the object, @adj bytes in.
 */
static int handle_regno(struct bpf_verifier_env *env, struct bpf_verifier_state *st,
			const struct bpf_reference_state *ref, s16 *adj)
{
	const struct bpf_reg_state *regs = st->frame[st->curframe]->regs;
	int objframe = -1, spi = -1, k;

	*adj = 0;
	if (ref->type == REF_TYPE_PTR || ref->type == REF_TYPE_IRQ)
		stack_object_find(st, ref, &objframe, &spi);
	for (k = BPF_REG_1; k <= BPF_REG_5; k++) {
		if (ref->type & REF_TYPE_LOCK_MASK ? reg_is_lock(&regs[k], ref) :
		    objframe >= 0 ? reg_object_slot(st, &regs[k], ref->id) != NULL :
		    reg_ref_off(&regs[k], ref->id, adj))
			return k;
	}
	return -1;
}

/* The class of the sections of @kind, 0 RCU read and 1 preemption disabled. */
static int resource_of_section(struct bpf_verifier_env *env, u8 kind)
{
	struct bpf_resource res;

	memset(&res, 0, sizeof(res));
	res.kind = kind ? BPF_RESOURCE_PREEMPT : BPF_RESOURCE_RCU;
	return resource_intern(env, &res);
}

static int resource_of_kind(struct bpf_verifier_env *env, u8 kind)
{
	struct bpf_resource res;

	memset(&res, 0, sizeof(res));
	res.kind = kind;
	return resource_intern(env, &res);
}

/*
 * The class of the resource refs[@idx] the current insn acquires, and how the
 * insn has its handle: in R@regno @after the call, the pointer the call
 * returns, which may point @adj bytes into the object, or in the register in
 * front of it, the pointer the call takes to a lock or to a stack object. The
 * handle of a ringbuf dynptr is the record, the first word of the dynptr, so
 * that a clone releases it as well as the dynptr it was reserved into.
 * -EOPNOTSUPP for a resource the unwinder cannot release.
 */
static int acquired_class(struct bpf_verifier_env *env, struct bpf_verifier_state *st,
			  const struct bpf_reference_state *ref, int regno, bool after, u8 *flags,
			  s16 *adj)
{
	const struct bpf_func_state *frame = st->frame[st->curframe];
	const struct bpf_stack_state *slot;
	struct bpf_resource res;
	struct bpf_reg_state reg;
	int objframe, spi, ret;

	*adj = 0;
	if (after) {
		reg = frame->regs[regno];
		if (!reg_ref_off(&reg, ref->id, adj))
			*adj = 0;
		reg.var_off = tnum_const(0);
		ret = resource_describe(env, &reg, &res, false);
		return ret ? -EOPNOTSUPP : resource_intern(env, &res);
	}
	*flags |= BPF_RES_F_ARG;
	if (ref->type & REF_TYPE_LOCK_MASK)
		return resource_of_kind(env, ref->type == REF_TYPE_LOCK ? BPF_RESOURCE_SPIN_LOCK :
								   BPF_RESOURCE_RES_LOCK);
	if (!stack_object_find(st, ref, &objframe, &spi))
		return -EOPNOTSUPP;
	slot = bpf_stack_slot(st->frame[objframe], spi);
	switch (slot->slot_type[BPF_REG_SIZE - 1]) {
	case STACK_DYNPTR:
		*flags |= BPF_RES_F_DEREF;
		return resource_of_kind(env, slot->spilled_ptr.dynptr.type == BPF_DYNPTR_TYPE_FILE ?
					     BPF_RESOURCE_DYNPTR_FILE : BPF_RESOURCE_RINGBUF);
	case STACK_IRQ_FLAG:
		return resource_of_kind(env, BPF_RESOURCE_IRQ_FLAG);
	default:
		ret = resource_of_iter(env, &slot->spilled_ptr);
		return ret < 0 ? -EOPNOTSUPP : ret;
	}
}

/*
 * A call of @subprog acquires or releases a resource of class @res: the
 * handle is in @reg. The calls of an insn are the same on every visit but
 * for the class, which a release may differ in.
 */
static int point_add(struct bpf_verifier_env *env, u8 kind, u16 subprog, u16 res, u8 reg, u8 flags,
		     s16 adj)
{
	struct bpf_res_point *p;
	u32 i, cnt = env->res_point_cnt, insn = env->insn_idx;

	for (i = 0; i < cnt; i++) {
		p = &env->res_points[i];
		if (p->insn != insn || p->kind != kind)
			continue;
		if (p->res == res && p->reg == reg) {
			if (p->adj != adj || (p->flags ^ flags) & ~BPF_RES_F_FOREIGN) {
				verbose(env, "frame_desc: insn %d takes the handle of a resource differently on different paths\n",
					insn);
				return -EINVAL;
			}
			p->flags |= flags;
			return 0;
		}
		/* which one it acquired nothing tells at run time */
		if (kind == BPF_RES_INSERT && p->reg == reg) {
			verbose(env, "frame_desc: insn %d acquires resources of different types on different paths\n",
				insn);
			return -EINVAL;
		}
		if (kind == BPF_RES_REMOVE && p->reg == reg &&
		    (env->resources[p->res].kind != env->resources[res].kind || p->adj != adj ||
		     (p->flags ^ flags) & BPF_RES_F_DEREF)) {
			verbose(env, "frame_desc: insn %d releases resources of different kinds on different paths\n",
				insn);
			return -EINVAL;
		}
	}
	p = kvrealloc(env->res_points, array_size(cnt + 1, sizeof(*p)), GFP_KERNEL_ACCOUNT);
	if (!p)
		return -ENOMEM;
	p[cnt] = (struct bpf_res_point) { .insn = insn, .subprog = subprog, .res = res, .kind = kind,
					  .reg = reg, .flags = flags, .adj = adj };
	env->res_points = p;
	env->res_point_cnt = cnt + 1;
	return 0;
}

static struct bpf_res_pool *pool_find(struct bpf_verifier_env *env, u16 subprog, u16 res)
{
	u32 i;

	for (i = 0; i < env->res_pool_cnt; i++)
		if (env->res_pools[i].subprog == subprog && env->res_pools[i].res == res)
			return &env->res_pools[i];
	return NULL;
}

/*
 * The current frame holds what its state says: make sure its subprog has a
 * slot for each resource of every class it holds, the ones it acquired and
 * the ones a callee handed it when it returned.
 */
static int pools_note(struct bpf_verifier_env *env, const struct bpf_verifier_state *st)
{
	u16 subprog = st->frame[st->curframe]->subprogno;
	struct bpf_res_pool *pool;
	int i, k;

	for (i = 0; i < st->acquired_refs; i++) {
		const struct bpf_reference_state *ref = &st->refs[i];
		u32 n = 0, cnt = env->res_pool_cnt;

		if (!ref->res || ref->frameno != st->curframe)
			continue;
		for (k = 0; k < st->acquired_refs; k++)
			n += st->refs[k].res == ref->res && st->refs[k].frameno == st->curframe;
		pool = pool_find(env, subprog, ref->res - 1);
		if (pool) {
			pool->size = max_t(u32, pool->size, n);
			continue;
		}
		pool = kvrealloc(env->res_pools, array_size(cnt + 1, sizeof(*pool)), GFP_KERNEL_ACCOUNT);
		if (!pool)
			return -ENOMEM;
		pool[cnt] = (struct bpf_res_pool) { .subprog = subprog, .res = ref->res - 1, .size = n };
		env->res_pools = pool;
		env->res_pool_cnt = cnt + 1;
	}
	return 0;
}

/*
 * Record that the current insn acquires the resource refs[@idx], whose handle
 * is in R@regno @after the insn, the pointer a call returns, or in front of
 * it, the pointer to a stack object or to a lock the call takes. A call that
 * @may_fail, a resilient lock, has acquired it only when it returns 0. The
 * handle is put into a slot of the frame after the call. A resource the
 * unwinder cannot release gets no slot, and a throw may not be reached while
 * it is held, see bpf_reference_state::res.
 */
int bpf_frame_desc_record_acquire(struct bpf_verifier_env *env, int idx, int regno, bool after,
				  bool may_fail)
{
	struct bpf_verifier_state *st = env->cur_state;
	struct bpf_reference_state *ref = &st->refs[idx];
	u8 flags = may_fail ? BPF_RES_F_MAY_FAIL : 0;
	int res, ret;
	s16 adj;

	ref->res = 0;
	if (!env->describe_frames || st->speculative)
		return 0;
	res = acquired_class(env, st, ref, regno, after, &flags, &adj);
	if (res == -EOPNOTSUPP)
		return 0;
	if (res < 0)
		return res;
	ref->res = res + 1;
	ret = point_add(env, BPF_RES_INSERT, st->frame[st->curframe]->subprogno, res, regno, flags,
			adj);
	return ret ?: pools_note(env, st);
}

/*
 * Record that the current insn releases the resource refs[@idx], before it
 * is released: its handle, in the register the insn takes it from, leaves
 * the slot that holds it after the call. A frame that does not hold the
 * resource itself, or whose slot of it another release cleared for an equal
 * handle, has bpf_unwind_forget() look in the frames below.
 */
int bpf_frame_desc_record_release(struct bpf_verifier_env *env, int idx)
{
	struct bpf_verifier_state *st = env->cur_state;
	const struct bpf_reference_state *ref = &st->refs[idx];
	int objframe, spi, regno;
	u8 flags = 0;
	s16 adj;

	if (!env->describe_frames || st->speculative || !ref->res)
		return 0;
	regno = handle_regno(env, st, ref, &adj);
	if (regno < 0) {
		verbose(env, "frame_desc: insn %d releases a resource whose handle is in no register\n",
			env->insn_idx);
		return -EINVAL;
	}
	if (ref->type == REF_TYPE_PTR && stack_object_find(st, ref, &objframe, &spi) &&
	    (env->resources[ref->res - 1].kind == BPF_RESOURCE_RINGBUF ||
	     env->resources[ref->res - 1].kind == BPF_RESOURCE_DYNPTR_FILE))
		flags |= BPF_RES_F_DEREF;
	if (ref->frameno != st->curframe) {
		flags |= BPF_RES_F_FOREIGN;
		env->foreign_release = true;
	}
	return point_add(env, BPF_RES_REMOVE, st->frame[st->curframe]->subprogno, ref->res - 1, regno,
			 flags, adj);
}

/*
 * The kernel holds a reference for the __ref argument @argno of a struct_ops
 * program, refs[@idx], and the program releases it or hands it back: the main
 * program holds it from its first insn, in a slot its entry fills from the
 * context. An argument of a type the unwinder cannot release gets no slot,
 * like any such reference.
 */
int bpf_frame_desc_record_ctx_arg(struct bpf_verifier_env *env, int idx, int argno)
{
	const struct bpf_ctx_arg_aux *info = &env->prog->aux->ctx_arg_info[argno];
	struct bpf_verifier_state *st = env->cur_state;
	struct bpf_reference_state *ref = &st->refs[idx];
	struct bpf_reg_state reg = {};
	struct bpf_res_ctx_arg *args;
	u32 i, cnt = env->res_ctx_arg_cnt;
	struct bpf_resource res;
	int ret;

	ref->res = 0;
	if (!env->describe_frames)
		return 0;
	reg.type = info->reg_type & ~PTR_MAYBE_NULL;
	reg.btf = info->btf;
	reg.btf_id = info->btf_id;
	if (resource_describe(env, &reg, &res, false))
		return 0;
	ret = resource_intern(env, &res);
	if (ret < 0)
		return ret;
	ref->res = ret + 1;
	for (i = 0; i < cnt; i++)
		if (env->res_ctx_args[i].argno == argno)
			return pools_note(env, st);
	args = kvrealloc(env->res_ctx_args, array_size(cnt + 1, sizeof(*args)), GFP_KERNEL_ACCOUNT);
	if (!args)
		return -ENOMEM;
	args[cnt] = (struct bpf_res_ctx_arg) { .res = ret, .argno = argno, .ctx_off = info->offset };
	env->res_ctx_args = args;
	env->res_ctx_arg_cnt = cnt + 1;
	return pools_note(env, st);
}

/* The current insn enters (@delta 1) or leaves (-1) a section of @kind: counted by its frame. */
int bpf_frame_desc_record_section(struct bpf_verifier_env *env, u8 kind, s8 delta)
{
	struct bpf_verifier_state *st = env->cur_state;
	struct bpf_section_insn *si;
	u32 i, cnt = env->section_insn_cnt;

	if (!env->describe_frames || st->speculative)
		return 0;
	env->section_kinds |= BIT(kind);
	for (i = 0; i < cnt; i++)
		if (env->section_insns[i].insn == env->insn_idx)
			return 0;
	si = kvrealloc(env->section_insns, array_size(cnt + 1, sizeof(*si)), GFP_KERNEL_ACCOUNT);
	if (!si)
		return -ENOMEM;
	si[cnt] = (struct bpf_section_insn) { .insn = env->insn_idx, .kind = kind, .delta = delta,
					      .subprog = st->frame[st->curframe]->subprogno };
	env->section_insns = si;
	env->section_insn_cnt = cnt + 1;
	return 0;
}

/* A callee returned to the current frame of @st: what it handed over needs slots here. */
int bpf_frame_desc_record_return(struct bpf_verifier_env *env, struct bpf_verifier_state *st)
{
	if (!env->describe_frames || st->speculative)
		return 0;
	return pools_note(env, st);
}

/*
 * The current frame returns to its caller. What it still holds, the caller
 * holds from here on: a reference it returns, or one it stored where its
 * caller finds it, a lock or a section it took for its caller, or less
 * sections than it was called in. Its slots go with the frame, so a frame of
 * a subprog that may return that way hands them over first. The entry counts
 * of the sections are lowered as the frame leaves its callers' sections, see
 * release_context_state(), which counts those apart.
 */
void bpf_frame_desc_record_exit(struct bpf_verifier_env *env)
{
	struct bpf_verifier_state *st = env->cur_state;
	const struct bpf_func_state *frame = st->frame[st->curframe];
	int i;

	if (!env->describe_frames || st->speculative)
		return;
	if (st->active_rcu_locks != frame->entry_rcu_locks || frame->rcu_released_below ||
	    st->active_preempt_locks != frame->entry_preempt_locks || frame->preempt_released_below)
		env->subprog_info[frame->subprogno].hands_over = true;
	for (i = 0; i < st->acquired_refs; i++)
		if (st->refs[i].res && st->refs[i].frameno == st->curframe)
			env->subprog_info[frame->subprogno].hands_over = true;
}

/*
 * A round of the main pass is dropped, see do_check_all(): what its paths
 * recorded goes with it.
 */
void bpf_frame_desc_reset(struct bpf_verifier_env *env)
{
	int i;

	env->res_point_cnt = 0;
	env->res_pool_cnt = 0;
	env->res_ctx_arg_cnt = 0;
	env->section_insn_cnt = 0;
	env->section_kinds = 0;
	env->foreign_release = false;
	for (i = 0; i < env->subprog_cnt; i++)
		env->subprog_info[i].hands_over = false;
}

void bpf_frame_desc_env_free(struct bpf_verifier_env *env)
{
	kvfree(env->res_points);
	kvfree(env->res_pools);
	kvfree(env->section_insns);
	kvfree(env->res_ctx_args);
	kvfree(env->frame_desc_new_of);
	kvfree(env->resources);
	env->res_points = NULL;
	env->res_pools = NULL;
	env->section_insns = NULL;
	env->res_ctx_args = NULL;
	env->frame_desc_new_of = NULL;
	env->resources = NULL;
}

/* Is point @i the first of its insn that releases the handle in its register? */
static bool point_first_of_reg(const struct bpf_verifier_env *env, u32 i)
{
	const struct bpf_res_point *p = &env->res_points[i];
	u32 k;

	for (k = 0; k < i; k++) {
		const struct bpf_res_point *o = &env->res_points[k];

		if (o->insn == p->insn && o->kind == p->kind && o->reg == p->reg)
			return false;
	}
	return true;
}

/*
 * The handle of point @i waits in a hidden slot across its call: which of the
 * slots, among the handles of the insn. The handles a call takes in arguments
 * have slots of their own, and so do the ones it releases, where the classes
 * a release may be of share the slot of their register.
 */
static int point_tmp(const struct bpf_verifier_env *env, u32 i)
{
	const struct bpf_res_point *p = &env->res_points[i];
	int n = 0;
	u32 k;

	for (k = 0; k < i; k++) {
		const struct bpf_res_point *o = &env->res_points[k];

		if (o->insn != p->insn || o->kind != p->kind)
			continue;
		if (p->kind == BPF_RES_INSERT)
			n += !!(o->flags & BPF_RES_F_ARG);
		else if (o->reg == p->reg)
			return point_tmp(env, k);
		else
			n += point_first_of_reg(env, k);
	}
	return n;
}

/* How many handles the calls of @subprog take in arguments at one insn, or release at one. */
static void temps_needed(struct bpf_verifier_env *env, u16 subprog, int *args, int *rels)
{
	u32 i;

	*args = 0;
	*rels = 0;
	for (i = 0; i < env->res_point_cnt; i++) {
		const struct bpf_res_point *p = &env->res_points[i];

		if (p->subprog != subprog)
			continue;
		if (p->kind == BPF_RES_REMOVE)
			*rels = max(*rels, point_tmp(env, i) + 1);
		else if (p->flags & BPF_RES_F_ARG)
			*args = max(*args, point_tmp(env, i) + 1);
	}
}

/*
 * Reserve the hidden slots, once the pass has seen every frame: the pools,
 * zeroed at the entry of the subprog, the counts of the sections, which every
 * subprog gets when the program has sections at all, since a frame may be
 * handed the count of the frame above it, and the slots a handle waits in
 * across the call that takes or releases it.
 */
int bpf_frame_desc_resolve(struct bpf_verifier_env *env)
{
	u32 i, k, len = env->prog->len;
	int s, ret, args, rels;

	if (!env->res_point_cnt && !env->section_insn_cnt && !env->res_pool_cnt)
		return 0;
	/* the pass named the insns of the program it verified, see bpf_frame_desc_emit() */
	for (i = 0; i < len; i++)
		env->frame_desc_orig_len = max(env->frame_desc_orig_len,
					       env->insn_aux_data[i].orig_idx + 1);
	env->frame_desc_new_of = kvcalloc(env->frame_desc_orig_len, sizeof(u32), GFP_KERNEL_ACCOUNT);
	if (!env->frame_desc_new_of)
		return -ENOMEM;
	/*
	 * The insns of a patch all name the insn they replaced, and its aux
	 * data went to the last of them, see bpf_patch_insn_data(): the last
	 * wins, which is the call when a guard was put in front of it.
	 */
	for (i = 0; i < len; i++)
		env->frame_desc_new_of[env->insn_aux_data[i].orig_idx] = i;

	for (i = 0; i < env->res_pool_cnt; i++) {
		struct bpf_res_pool *pool = &env->res_pools[i];

		u32 filled = 0;

		ret = bpf_reserve_stack_slots(env, pool->subprog, pool->size, &pool->off);
		/* the first slots of the main program hold what the kernel passed it */
		for (k = 0; !ret && !pool->subprog && k < env->res_ctx_arg_cnt; k++) {
			if (env->res_ctx_args[k].res != pool->res)
				continue;
			ret = bpf_stack_slot_init_ctx(env, pool->off - filled * BPF_REG_SIZE,
						      env->res_ctx_args[k].ctx_off);
			filled++;
		}
		if (verifier_bug_if(filled > pool->size, env, "%u ctx arguments for %u slots", filled,
				    pool->size))
			return -EFAULT;
		for (k = filled; !ret && k < pool->size; k++)
			ret = bpf_stack_slot_init(env, pool->subprog, pool->off - k * BPF_REG_SIZE, 0);
		if (ret)
			return ret;
		env->frame_desc_slots += pool->size;
	}
	for (s = 0; s < env->subprog_cnt; s++) {
		struct bpf_subprog_info *sub = &env->subprog_info[s];

		for (k = 0; k < SECTION_KINDS; k++) {
			if (!(env->section_kinds & BIT(k)))
				continue;
			ret = bpf_reserve_stack_slots(env, s, 1, &sub->section_off[k]);
			ret = ret ?: bpf_stack_slot_init(env, s, sub->section_off[k], 0);
			if (ret)
				return ret;
			env->frame_desc_slots++;
		}
		for (i = 0; i < env->res_point_cnt; i++) {
			const struct bpf_res_point *p = &env->res_points[i];

			if (p->subprog != s || p->kind != BPF_RES_REMOVE || !env->foreign_release ||
			    !bpf_is_sync_callback_calling_insn(&env->prog->insnsi[env->frame_desc_new_of[p->insn]]))
				continue;
			for (k = 0; k < MAX_BPF_FUNC_REG_ARGS; k++) {
				ret = bpf_reserve_stack_slots(env, s, 1, &sub->res_save_off[k]);
				if (ret)
					return ret;
			}
			env->frame_desc_slots += MAX_BPF_FUNC_REG_ARGS;
			break;
		}
		temps_needed(env, s, &args, &rels);
		if (verifier_bug_if(args > ARRAY_SIZE(sub->res_arg_off) ||
				    rels > ARRAY_SIZE(sub->res_rel_off), env,
				    "%d handles taken and %d released at one insn", args, rels))
			return -EFAULT;
		for (k = 0; k < args; k++) {
			ret = bpf_reserve_stack_slots(env, s, 1, &sub->res_arg_off[k]);
			if (ret)
				return ret;
		}
		for (k = 0; k < rels; k++) {
			ret = bpf_reserve_stack_slots(env, s, 1, &sub->res_rel_off[k]);
			if (ret)
				return ret;
		}
		env->frame_desc_slots += args + rels;
	}
	return 0;
}

/* What is emitted at an insn of the current image, in this order. */
enum {
	EMIT_SAVE_ARG,		/* the handle a call takes, in front of it */
	EMIT_SAVE_REL,		/* the handle a call releases, in front of it */
	EMIT_REMOVE_FIRST,	/* in front of a call that runs a callback: the handle leaves its slot */
	EMIT_SECTION,		/* the section count, in front of a call entering or leaving one */
	EMIT_REMOVE,		/* after the call: the handle leaves its slot */
	EMIT_INSERT,		/* after the call: the handle goes into a free slot */
};

struct emit_point {
	u32 insn;
	u8 kind;
	u8 reg;
	u8 flags;
	u8 tmp;		/* which of the slots the handle waits in */
	s8 delta;	/* EMIT_SECTION */
	u16 subprog;
	u16 res;
	s16 adj;
	s16 off;	/* the slot the handle waits in, or the count */
};

static int point_cmp(const void *a, const void *b)
{
	const struct emit_point *x = a, *y = b;

	if (x->insn != y->insn)
		return x->insn < y->insn ? -1 : 1;
	if (x->kind != y->kind)
		return x->kind - y->kind;
	return x->tmp - y->tmp;
}

/* The handle in R1 goes into the first free slot of @pool; the last one is free when the others are not. */
static int emit_insert(struct bpf_insn *buf, const struct bpf_res_pool *pool)
{
	int i, cnt = 0;

	for (i = 0; i < pool->size - 1; i++) {
		s16 off = pool->off - i * BPF_REG_SIZE;

		buf[cnt++] = BPF_LDX_MEM(BPF_DW, BPF_REG_AX, BPF_REG_FP, off);
		buf[cnt++] = BPF_JMP_IMM(BPF_JNE, BPF_REG_AX, 0, 2);
		buf[cnt++] = BPF_STX_MEM(BPF_DW, BPF_REG_FP, BPF_REG_1, off);
		buf[cnt++] = BPF_JMP_A(4 * (pool->size - 2 - i) + 1);
	}
	buf[cnt++] = BPF_STX_MEM(BPF_DW, BPF_REG_FP, BPF_REG_1, pool->off - i * BPF_REG_SIZE);
	return cnt;
}

/*
 * After a call that acquired: the handle, the pointer the call returned or
 * the one it took, which waited in a slot, goes into the pool of its class.
 * Nothing was acquired when the call failed or returned NULL. R1-R5 are free
 * after a call.
 */
static int emit_acquired(struct bpf_verifier_env *env, struct bpf_insn *buf,
			 const struct emit_point *p)
{
	const struct bpf_res_pool *pool = pool_find(env, p->subprog, p->res);
	int cnt = 0, skip, n = 4 * (pool->size - 1) + 1;

	if (p->flags & BPF_RES_F_ARG) {
		buf[cnt++] = BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_FP, p->off);
		if (p->flags & BPF_RES_F_DEREF)
			buf[cnt++] = BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_1, 0);
	} else {
		buf[cnt++] = BPF_MOV64_REG(BPF_REG_1, p->reg);
	}
	skip = n + !!p->adj;
	if (p->flags & BPF_RES_F_MAY_FAIL)
		buf[cnt++] = BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, skip + 1);
	buf[cnt++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, 0, skip);
	if (p->adj)
		buf[cnt++] = BPF_ALU64_IMM(BPF_SUB, BPF_REG_1, p->adj);
	return cnt + emit_insert(buf + cnt, pool);
}

/*
 * After a call that released: the handle, which waited in a slot, leaves the
 * slot of the frame that holds it, of the pool of any of the classes @p[0..n)
 * the release may be of. When no slot of the frame holds it, another frame
 * does, or one of its slots stands in for this one: bpf_unwind_forget() finds
 * it, and returns R0 as it was.
 */
static int emit_released(struct bpf_verifier_env *env, struct bpf_insn *buf,
			 const struct emit_point *p, int n)
{
	int i, k, cnt = 0, slots = 0, at = 0, tail;

	for (i = 0; i < n; i++) {
		const struct bpf_res_pool *pool = pool_find(env, p[i].subprog, p[i].res);

		slots += pool ? pool->size : 0;
	}
	tail = env->foreign_release ? 3 : 0;
	buf[cnt++] = BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_FP, p->off);
	if (p->adj)
		buf[cnt++] = BPF_ALU64_IMM(BPF_SUB, BPF_REG_1, p->adj);
	for (i = 0; i < n; i++) {
		const struct bpf_res_pool *pool = pool_find(env, p[i].subprog, p[i].res);

		for (k = 0; pool && k < pool->size; k++, at++) {
			s16 off = pool->off - k * BPF_REG_SIZE;

			buf[cnt++] = BPF_LDX_MEM(BPF_DW, BPF_REG_AX, BPF_REG_FP, off);
			buf[cnt++] = BPF_JMP_REG(BPF_JNE, BPF_REG_AX, BPF_REG_1, 2);
			buf[cnt++] = BPF_ST_MEM(BPF_DW, BPF_REG_FP, off, 0);
			buf[cnt++] = BPF_JMP_A(4 * (slots - 1 - at) + tail);
		}
	}
	if (tail) {
		buf[cnt++] = BPF_MOV64_IMM(BPF_REG_2, n == 1 ? p->res :
					   BPF_FORGET_ANY_OF_KIND | env->resources[p->res].kind);
		buf[cnt++] = BPF_MOV64_REG(BPF_REG_3, BPF_REG_0);
		buf[cnt++] = BPF_EMIT_KERNEL_CALL(bpf_unwind_forget);
	}
	return cnt;
}

/*
 * In front of a call that releases and runs a callback, bpf_rbtree_add(): the
 * resource is gone whichever way the call leaves, and it does not come back
 * here when the callback throws, so the handle, which the register @p->reg
 * holds, leaves its slot first. bpf_unwind_forget() is called with R1-R5
 * saved, which the call that follows takes its arguments in.
 */
static int emit_released_first(struct bpf_verifier_env *env, struct bpf_insn *buf,
			       const struct emit_point *p, int n)
{
	const struct bpf_subprog_info *sub = &env->subprog_info[p->subprog];
	int i, k, cnt = 0, slots = 0, at = 0, tail;

	for (i = 0; i < n; i++) {
		const struct bpf_res_pool *pool = pool_find(env, p[i].subprog, p[i].res);

		slots += pool ? pool->size : 0;
	}
	tail = env->foreign_release ? 2 * MAX_BPF_FUNC_REG_ARGS + 4 + !!p->adj : 0;
	for (i = 0; i < n; i++) {
		const struct bpf_res_pool *pool = pool_find(env, p[i].subprog, p[i].res);

		for (k = 0; pool && k < pool->size; k++, at++) {
			s16 off = pool->off - k * BPF_REG_SIZE;

			buf[cnt++] = BPF_LDX_MEM(BPF_DW, BPF_REG_AX, BPF_REG_FP, off);
			if (p->adj)
				buf[cnt++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_AX, p->adj);
			buf[cnt++] = BPF_JMP_REG(BPF_JNE, BPF_REG_AX, p->reg, 2);
			buf[cnt++] = BPF_ST_MEM(BPF_DW, BPF_REG_FP, off, 0);
			buf[cnt++] = BPF_JMP_A((4 + !!p->adj) * (slots - 1 - at) + tail);
		}
	}
	if (!tail)
		return cnt;
	for (i = 0; i < MAX_BPF_FUNC_REG_ARGS; i++)
		buf[cnt++] = BPF_STX_MEM(BPF_DW, BPF_REG_FP, BPF_REG_1 + i, sub->res_save_off[i]);
	buf[cnt++] = BPF_MOV64_REG(BPF_REG_1, p->reg);
	if (p->adj)
		buf[cnt++] = BPF_ALU64_IMM(BPF_SUB, BPF_REG_1, p->adj);
	buf[cnt++] = BPF_MOV64_IMM(BPF_REG_2, n == 1 ? p->res :
				   BPF_FORGET_ANY_OF_KIND | env->resources[p->res].kind);
	buf[cnt++] = BPF_MOV64_IMM(BPF_REG_3, 0);
	buf[cnt++] = BPF_EMIT_KERNEL_CALL(bpf_unwind_forget);
	for (i = 0; i < MAX_BPF_FUNC_REG_ARGS; i++)
		buf[cnt++] = BPF_LDX_MEM(BPF_DW, BPF_REG_1 + i, BPF_REG_FP, sub->res_save_off[i]);
	return cnt;
}

/* The insns that go in front of an insn for the @n points from @p. */
static int emit_before(struct bpf_verifier_env *env, struct bpf_insn *buf,
		       const struct emit_point *p, int n)
{
	int i, k, cnt = 0;

	for (i = 0; i < n; i++) {
		switch (p[i].kind) {
		case EMIT_REMOVE_FIRST:
			/* the classes the release may be of: one handle */
			for (k = i + 1; k < n && p[k].kind == EMIT_REMOVE_FIRST &&
				    p[k].tmp == p[i].tmp; k++)
				;
			cnt += emit_released_first(env, buf + cnt, &p[i], k - i);
			i = k - 1;
			break;
		case EMIT_SAVE_ARG:
			buf[cnt++] = BPF_STX_MEM(BPF_DW, BPF_REG_FP, p[i].reg, p[i].off);
			break;
		case EMIT_SAVE_REL:
			/* the record of a dynptr, which the call takes out of the dynptr */
			if (p[i].flags & BPF_RES_F_DEREF) {
				buf[cnt++] = BPF_LDX_MEM(BPF_DW, BPF_REG_AX, p[i].reg, 0);
				buf[cnt++] = BPF_STX_MEM(BPF_DW, BPF_REG_FP, BPF_REG_AX, p[i].off);
				break;
			}
			buf[cnt++] = BPF_STX_MEM(BPF_DW, BPF_REG_FP, p[i].reg, p[i].off);
			break;
		case EMIT_SECTION:
			buf[cnt++] = BPF_LDX_MEM(BPF_DW, BPF_REG_AX, BPF_REG_FP, p[i].off);
			buf[cnt++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_AX, p[i].delta);
			buf[cnt++] = BPF_STX_MEM(BPF_DW, BPF_REG_FP, BPF_REG_AX, p[i].off);
			break;
		}
	}
	return cnt;
}

/* The insns that follow an insn for the @n points from @p: the releases, then the acquisitions. */
static int emit_after(struct bpf_verifier_env *env, struct bpf_insn *buf, const struct emit_point *p,
		      int n)
{
	int i, k, cnt = 0;

	for (i = 0; i < n; i = k) {
		if (p[i].kind == EMIT_INSERT) {
			cnt += emit_acquired(env, buf + cnt, &p[i]);
			k = i + 1;
			continue;
		}
		for (k = i + 1; k < n && p[k].kind == EMIT_REMOVE && p[k].tmp == p[i].tmp; k++)
			;
		cnt += emit_released(env, buf + cnt, &p[i], k - i);
	}
	return cnt;
}

/* An upper bound of the insns emitted for one point. */
static int point_cost(struct bpf_verifier_env *env, const struct emit_point *p)
{
	const struct bpf_res_pool *pool;

	switch (p->kind) {
	case EMIT_SAVE_ARG:
		return 1;
	case EMIT_SAVE_REL:
		return 2;
	case EMIT_SECTION:
		return 3;
	default:
		pool = pool_find(env, p->subprog, p->res);
		return 2 * MAX_BPF_FUNC_REG_ARGS + 8 + 5 * (pool ? pool->size : 0);
	}
}

/*
 * Before a frame of @subprog returns: bpf_unwind_handover() moves what its
 * slots hold into those of the frame it returns to. R6 is free at an exit.
 */
static int emit_handover(struct bpf_verifier_env *env, int subprog)
{
	u32 i, start = env->subprog_info[subprog].start, end = env->subprog_info[subprog + 1].start;
	struct bpf_insn buf[4], *insn;

	for (i = start; i < end; i++) {
		if (env->prog->insnsi[i].code != (BPF_JMP | BPF_EXIT))
			continue;
		buf[0] = BPF_MOV64_REG(BPF_REG_6, BPF_REG_0);
		buf[1] = BPF_EMIT_KERNEL_CALL(bpf_unwind_handover);
		buf[2] = BPF_MOV64_REG(BPF_REG_0, BPF_REG_6);
		buf[3] = env->prog->insnsi[i];
		insn = bpf_patch_list_add(env, i, buf, ARRAY_SIZE(buf));
		if (IS_ERR(insn))
			return PTR_ERR(insn);
		env->frame_desc_insns += 3;
	}
	return 0;
}

/*
 * Keep the slots and the counts up to date, through the patch list. What
 * goes in front of an insn is patched in with the insn, so that the jumps to
 * it land on it; what follows a call is inserted in front of the next insn,
 * which a jump to that insn skips, as it skips the call. When unwind_goto
 * follows a call, nothing may come between: the callee that unwound returns
 * right after the call and goes where unwind_goto says, so what follows the
 * call is put on both ways out, in place of the unwind_goto.
 */
int bpf_frame_desc_emit(struct bpf_verifier_env *env)
{
	u32 i, k, n = 0, len = env->prog->len, orig_len = env->frame_desc_orig_len, max = 0;
	const u32 *new_of = env->frame_desc_new_of;
	struct emit_point *points;
	struct bpf_insn *buf = NULL, *scratch = NULL, *insn;
	int ret = 0, cnt, off, s;

	if (!env->res_point_cnt && !env->section_insn_cnt)
		return 0;
	points = kvcalloc(2 * env->res_point_cnt + env->section_insn_cnt, sizeof(*points),
			  GFP_KERNEL_ACCOUNT);
	if (!points)
		return -ENOMEM;
	for (i = 0; i < env->res_point_cnt; i++) {
		const struct bpf_res_point *p = &env->res_points[i];
		const struct bpf_subprog_info *sub = &env->subprog_info[p->subprog];
		struct emit_point e = { .reg = p->reg, .flags = p->flags, .subprog = p->subprog,
					.res = p->res, .adj = p->adj };

		if (verifier_bug_if(p->insn >= orig_len, env, "resource at insn %d", p->insn)) {
			ret = -EFAULT;
			goto out;
		}
		e.insn = new_of[p->insn];
		e.tmp = point_tmp(env, i);
		if (p->kind == BPF_RES_INSERT) {
			e.kind = EMIT_INSERT;
			if (p->flags & BPF_RES_F_ARG)
				e.off = sub->res_arg_off[e.tmp];
			points[n++] = e;
			if (p->flags & BPF_RES_F_ARG) {
				e.kind = EMIT_SAVE_ARG;
				points[n++] = e;
			}
			continue;
		}
		/* gone whichever way the call leaves, and it may leave by a throw of its callback */
		if (bpf_is_sync_callback_calling_insn(&env->prog->insnsi[e.insn])) {
			e.kind = EMIT_REMOVE_FIRST;
			points[n++] = e;
			continue;
		}
		e.off = sub->res_rel_off[e.tmp];
		e.kind = EMIT_REMOVE;
		points[n++] = e;
		/* the classes a release may be of share the handle: saved once */
		if (point_first_of_reg(env, i)) {
			e.kind = EMIT_SAVE_REL;
			points[n++] = e;
		}
	}
	for (i = 0; i < env->section_insn_cnt; i++) {
		const struct bpf_section_insn *si = &env->section_insns[i];

		if (verifier_bug_if(si->insn >= orig_len, env, "section at insn %d", si->insn)) {
			ret = -EFAULT;
			goto out;
		}
		points[n++] = (struct emit_point) {
			.insn = new_of[si->insn], .kind = EMIT_SECTION, .delta = si->delta,
			.off = env->subprog_info[si->subprog].section_off[si->kind],
		};
	}
	sort(points, n, sizeof(*points), point_cmp, NULL);

	for (i = 0; i < n; i = k) {
		for (k = i, cnt = 0; k < n && points[k].insn == points[i].insn; k++)
			cnt += point_cost(env, &points[k]);
		max = max_t(u32, max, cnt);
	}
	/* twice what follows a call, around an unwind_goto, and the insn itself */
	buf = kvcalloc(2 * max + 4, sizeof(*buf), GFP_KERNEL_ACCOUNT);
	scratch = kvcalloc(max + 1, sizeof(*scratch), GFP_KERNEL_ACCOUNT);
	if (!buf || !scratch) {
		ret = -ENOMEM;
		goto out;
	}

	for (i = 0; i < n; i = k) {
		u32 idx = points[i].insn, nb = 0, na;

		for (k = i; k < n && points[k].insn == idx; k++)
			nb += points[k].kind <= EMIT_SECTION;
		na = k - i - nb;
		if (verifier_bug_if(idx >= len || env->prog->insnsi[idx].code != (BPF_JMP | BPF_CALL),
				    env, "resource kept at insn %d, not a call", idx)) {
			ret = -EFAULT;
			goto out;
		}
		if (nb) {
			cnt = emit_before(env, buf, &points[i], nb);
			buf[cnt++] = env->prog->insnsi[idx];
			insn = bpf_patch_list_add(env, idx, buf, cnt);
			if (IS_ERR(insn)) {
				ret = PTR_ERR(insn);
				goto out;
			}
			env->frame_desc_insns += cnt - 1;
		}
		if (!na)
			continue;
		cnt = emit_after(env, scratch, &points[i + nb], na);
		if (idx + 1 < len && bpf_is_unwind_goto(&env->prog->insnsi[idx + 1])) {
			struct bpf_insn ug = env->prog->insnsi[idx + 1];

			/*
			 * The jump where unwind_goto went sits 2 * cnt + 2 insns
			 * below it: a target in front of the unwind_goto did not
			 * move with it, one behind it did.
			 */
			off = ug.off < -1 ? ug.off - (2 * cnt + 2) : ug.off;
			if (off < S16_MIN) {
				verbose(env, "frame_desc: the unwind_goto at insn %d jumps too far for what follows its call\n",
					idx + 1);
				ret = -ERANGE;
				goto out;
			}
			buf[0] = ug;
			buf[0].off = cnt + 1;
			memcpy(buf + 1, scratch, cnt * sizeof(*buf));
			buf[cnt + 1] = BPF_JMP_A(cnt + 1);
			memcpy(buf + cnt + 2, scratch, cnt * sizeof(*buf));
			buf[2 * cnt + 2] = BPF_JMP_A(off);
			insn = bpf_patch_list_add(env, idx + 1, buf, 2 * cnt + 3);
			ret = IS_ERR(insn) ? PTR_ERR(insn) : 0;
			env->frame_desc_insns += 2 * cnt + 2;
		} else {
			ret = bpf_patch_list_insert(env, idx + 1, scratch, cnt);
			env->frame_desc_insns += cnt;
		}
		if (ret)
			goto out;
	}
	for (s = 1; s < env->subprog_cnt && !ret; s++)
		if (env->subprog_info[s].hands_over)
			ret = emit_handover(env, s);
	ret = ret ?: bpf_patch_list_commit(env);
out:
	kvfree(scratch);
	kvfree(buf);
	kvfree(points);
	return ret;
}

/* A stack object may use a referenced object the frame holds as well: it goes first. */
static bool resource_goes_first(const struct bpf_resource *res)
{
	return res->kind == BPF_RESOURCE_ITER || res->kind == BPF_RESOURCE_DYNPTR_FILE;
}

/*
 * The frame descriptor of every subprog that has slots: the slots of its
 * pools, each of which holds the handle of a resource of the pool's class or
 * NULL, and the counts of its sections. The unwinder releases what the slots
 * of a frame hold in the order of the entries, within a phase: the iterators
 * and the readers of file dynptrs come before the references, which they may
 * be iterating over or reading. Identical descriptors share a body in the
 * pool of the program, which takes the resource classes over.
 */
int bpf_frame_desc_build(struct bpf_verifier_env *env)
{
	struct bpf_frame_desc_pool *pool;
	u32 i, k, n, s;
	int res;

	if (!env->res_pool_cnt && !env->section_kinds)
		return 0;
	pool = kvzalloc(struct_size(pool, desc, 0), GFP_KERNEL_ACCOUNT);
	if (!pool)
		return -ENOMEM;
	env->frame_desc_pool = pool;
	for (s = 0; s < env->subprog_cnt; s++) {
		struct bpf_subprog_info *sub = &env->subprog_info[s];
		struct bpf_frame_desc *d;

		for (i = 0, n = 0; i < env->res_pool_cnt; i++)
			n += env->res_pools[i].subprog == s ? env->res_pools[i].size : 0;
		n += hweight8(env->section_kinds);
		if (!n)
			continue;
		d = kvzalloc(struct_size(d, ent, n), GFP_KERNEL_ACCOUNT);
		if (!d)
			return -ENOMEM;
		d->size = struct_size(d, ent, n);
		for (i = 0; i < 2 * env->res_pool_cnt; i++) {
			const struct bpf_res_pool *p = &env->res_pools[i % env->res_pool_cnt];
			bool first = i < env->res_pool_cnt;

			if (p->subprog != s || resource_goes_first(&env->resources[p->res]) != first)
				continue;
			for (k = 0; k < p->size; k++)
				d->ent[d->nent++] = (struct bpf_frame_desc_entry) {
					.res = p->res, .off = p->off - k * BPF_REG_SIZE,
				};
		}
		for (k = 0; k < SECTION_KINDS; k++) {
			if (!(env->section_kinds & BIT(k)))
				continue;
			res = resource_of_section(env, k);
			if (res < 0) {
				kvfree(d);
				return res;
			}
			d->ent[d->nent++] = (struct bpf_frame_desc_entry) {
				.res = res, .off = sub->section_off[k], .flags = BPF_FRAME_ENT_COUNTER,
			};
		}
		for (i = 0; i < pool->cnt; i++)
			if (pool->desc[i]->size == d->size && !memcmp(pool->desc[i], d, d->size))
				break;
		if (i < pool->cnt) {
			kvfree(d);
			sub->frame_desc = i + 1;
			continue;
		}
		pool = kvrealloc(pool, struct_size(pool, desc, pool->cnt + 1), GFP_KERNEL_ACCOUNT);
		if (!pool) {
			kvfree(d);
			return -ENOMEM;
		}
		env->frame_desc_pool = pool;
		pool->desc[pool->cnt] = d;
		env->frame_desc_bytes += d->size;
		sub->frame_desc = ++pool->cnt;
	}
	pool->resources = env->resources;
	pool->resource_cnt = env->resource_cnt;
	env->frame_desc_bytes += env->resource_cnt * sizeof(*env->resources);
	env->resources = NULL;
	return 0;
}
