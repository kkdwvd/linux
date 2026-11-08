// SPDX-License-Identifier: GPL-2.0-only
/*
 * Frame descriptors: which registers and stack slots of a BPF frame hold
 * kernel resources at an instruction where the program may be unwound.
 *
 * The verifier calls bpf_frame_desc_site() at every such site with the state
 * the site is reached in, and describes the current frame alone, at the
 * instruction. A caller frame waits in a call, which is a site of its own,
 * where the caller is described from its state at the call: that way the
 * unwinder releases each frame from its instruction pointer alone. One
 * descriptor is built per (subprog, insn), and the paths that reach the
 * instruction are merged into it.
 *
 * A frame lists exactly the references it owns, see
 * bpf_reference_state::frameno. What it holds for a caller is the caller's to
 * list, at the call the caller waits in, and what a callee returns with
 * becomes the caller's at the return. A stack object, an iterator or a
 * dynptr, is listed where it is when it is in the frame's own stack, and
 * through a pointer to it otherwise.
 */
#include <linux/bpf.h>
#include <linux/bpf_verifier.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/kallsyms.h>
#include <linux/sort.h>

#define verbose(env, fmt, args...) bpf_verifier_log_write(env, fmt, ##args)

/*
 * What a location (register or stack slot) has held across the paths merged
 * into a descriptor so far. Only RES locations are released at run time; NULL
 * is the one disagreement allowed with RES, since the unwinder skips NULL.
 */
enum {
	LOC_UNSEEN,	/* no path classified this location yet */
	LOC_NULL,	/* known NULL on every path so far */
	LOC_RES,	/* holds the resource of class .res, maybe NULL on some path */
	LOC_COPY,	/* held a copy of a resource that is released elsewhere */
	LOC_OTHER,	/* held something that must not be released */
};

/* Per-path classification of a location. */
enum {
	CLASS_OTHER,
	CLASS_NULL,
	CLASS_RES,
	CLASS_COPY,
};

#define CALLEE_SAVED_REGS	(BIT(BPF_REG_6) | BIT(BPF_REG_7) | BIT(BPF_REG_8) | BIT(BPF_REG_9))
#define FRAME_LOCS		(BPF_REG_10 + MAX_BPF_STACK_SLOTS)
/* Release ranks of the entries without an acquisition order, see entry_cmp(). */
#define ORDER_RCU_OBJ		-1
#define ORDER_SECTION		-2
#define ORDER_OBJ		-3

/* A candidate location of one reference on the current path. */
struct cand {
	u8 is_slot;
	u8 indirect;	/* the location holds a pointer to the resource */
	u16 idx;	/* register number or spi */
	u16 res;
	u8 nullable;	/* the pointer may be NULL on this path: not checked yet */
};

/* Per-site working storage, allocated once per verification. */
struct scratch {
	struct cand cands[FRAME_LOCS];
	u8 class[FRAME_LOCS];
	u8 nullable[FRAME_LOCS];
	u8 indirect[FRAME_LOCS];
	u16 res[FRAME_LOCS];
	u32 acq[FRAME_LOCS];
	struct bpf_frame_desc_build *build;
	u32 pc;
	u32 live_regs;
	const unsigned long *live_stack;
};

/* Make room for @nr_slots stack slots in the descriptor at @slot, of insn @pc. */
static struct bpf_frame_desc_build *build_grow(struct bpf_verifier_env *env, u32 pc,
					       struct bpf_frame_desc_build **slot, u32 nr_slots)
{
	struct bpf_frame_desc_build *b = *slot;
	u32 old = b ? b->nr_slots : 0, first = old;
	bool new = !b;

	if (b && old >= nr_slots)
		return b;
	b = kvrealloc(b, struct_size(b, slots, nr_slots), GFP_KERNEL_ACCOUNT);
	if (!b)
		return NULL;
	if (new)
		memset(b, 0, offsetof(struct bpf_frame_desc_build, slots));
	memset(&b->slots[old], 0, (nr_slots - old) * sizeof(b->slots[0]));
	b->pc = pc;
	b->nr_slots = nr_slots;
	*slot = b;
	/*
	 * A slot the earlier visits did not have was not in their frames, and
	 * holds anything on their paths: nothing is released from it unless a
	 * scalar tells the paths apart, see guarded(), or it is mirrored.
	 */
	if (!new && b->visits)
		for (; first < nr_slots; first++)
			b->slots[first].state = LOC_OTHER;
	return b;
}

/* The descriptor of insn @pc, which @slot holds, or the aux data of the insn when NULL. */
static struct bpf_frame_desc_build *build_get(struct bpf_verifier_env *env, u32 pc, u32 nr_slots,
					      struct bpf_frame_desc_build **slot)
{
	return build_grow(env, pc, slot ?: &env->insn_aux_data[pc].frame_desc, nr_slots);
}

void bpf_frame_desc_build_destroy(struct bpf_frame_desc_build *b)
{
	kvfree(b);
}

void bpf_frame_desc_build_free(struct bpf_insn_aux_data *aux)
{
	bpf_frame_desc_build_destroy(aux->frame_desc);
	bpf_frame_desc_build_destroy(aux->guard_desc);
	aux->frame_desc = NULL;
	aux->guard_desc = NULL;
}

/*
 * A round of the main pass is dropped, see do_check_all(): what its paths put
 * into the descriptors goes with it.
 */
void bpf_frame_desc_reset(struct bpf_verifier_env *env)
{
	struct bpf_insn_aux_data *aux = env->insn_aux_data;
	u32 i;

	for (i = 0; i < env->prog->len; i++)
		bpf_frame_desc_build_free(&aux[i]);
	for (i = 0; i < env->subprog_cnt; i++) {
		bpf_frame_desc_build_destroy(env->subprog_info[i].entry_guard);
		env->subprog_info[i].entry_guard = NULL;
	}
	kvfree(env->resources);
	env->resources = NULL;
	env->resource_cnt = 0;
	env->frame_desc_visits = 0;
	env->frame_desc_conflicts = 0;
}

void bpf_frame_desc_env_free(struct bpf_verifier_env *env)
{
	int i;

	for (i = 0; i < env->subprog_cnt; i++)
		bpf_frame_desc_build_destroy(env->subprog_info[i].entry_guard);
	kvfree(env->resources);
	kvfree(env->frame_desc_scratch);
	env->resources = NULL;
	env->frame_desc_scratch = NULL;
}

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
			     struct bpf_resource *res, const char *what)
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
		verbose(env, "frame_desc: no cleanup destructor registered for %s %s\n", what, name);
		return -EOPNOTSUPP;
	}
	flags = btf_kfunc_flags(dtor_btf, dtor->release_btf_id, env->prog);
	if (!flags) {
		verbose(env, "frame_desc: release kfunc of %s %s is not callable by this program\n",
			what, name);
		return -EOPNOTSUPP;
	}
	res->sleeps = *flags & KF_SLEEPABLE;
	t = btf_type_by_id(dtor_btf, dtor->kfunc_btf_id);
	res->dtor = t ? (void *)kallsyms_lookup_name(btf_name_by_offset(dtor_btf, t->name_off)) :
			NULL;
	if (!res->dtor) {
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
 * Classify a register or spilled register that holds a reference. The pointer
 * may point into the object, see reg_is_ref(): the class carries by how much.
 * A reference of a type that no destructor is registered for, or whose
 * release kfunc the program may not call, has no class: it is one the program
 * could not release either, so a site holding it is one the verifier would
 * reject anyway, for the leak.
 */
static int resource_describe(struct bpf_verifier_env *env, const struct bpf_reg_state *reg,
			     struct bpf_resource *resp)
{
	u32 flags = type_flag(reg->type) & ~PTR_MAYBE_NULL;
	struct bpf_resource res;
	int ret;

	memset(&res, 0, sizeof(res));
	res.type = reg->type & ~PTR_MAYBE_NULL;
	res.delta = reg->var_off.value;
	switch (base_type(reg->type)) {
	case PTR_TO_BTF_ID:
		res.btf = reg->btf;
		res.btf_id = reg->btf_id;
		if (flags & MEM_ALLOC) {
			if (flags & ~(MEM_ALLOC | MEM_PERCPU))
				goto unsupported;
			res.kind = flags & MEM_PERCPU ? BPF_RESOURCE_PERCPU_OBJ : BPF_RESOURCE_OBJ;
			res.meta = btf_find_struct_meta(reg->btf, reg->btf_id);
			break;
		}
		if (flags & ~PTR_TRUSTED)
			goto unsupported;
		/* A socket cast to one of its structs is still what bpf_sk_release() takes. */
		if (reg_is_sock_btf(reg) && helper_ok(env, BPF_FUNC_sk_release)) {
			res.kind = BPF_RESOURCE_SOCK;
			break;
		}
		res.kind = BPF_RESOURCE_KPTR;
		ret = resource_registry(env, reg->btf, reg->btf_id, &res, "object");
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
	verbose(env, "frame_desc: cannot release a reference of type %s\n",
		reg_type_str(env, reg->type));
	return -EOPNOTSUPP;
}

static int resource_of_reg(struct bpf_verifier_env *env, const struct bpf_reg_state *reg)
{
	struct bpf_resource res;
	int ret;

	ret = resource_describe(env, reg, &res);
	return ret ?: resource_intern(env, &res);
}

/*
 * The class of the reference the kernel holds for __ref argument @argno of a
 * struct_ops program: the object as the program loads it from the context,
 * or, @through a pointer to the context at a location, the word @load_off
 * into the context, where the kernel put the argument.
 */
static int resource_of_ctx_arg(struct bpf_verifier_env *env, u32 argno, bool through, s16 load_off)
{
	const struct bpf_ctx_arg_aux *info = &env->prog->aux->ctx_arg_info[argno];
	struct bpf_reg_state reg = { .type = info->reg_type, .btf = info->btf, .btf_id = info->btf_id };
	struct bpf_resource res;
	int ret;

	ret = resource_describe(env, &reg, &res);
	if (ret)
		return ret;
	res.through = through;
	res.load_off = load_off;
	return resource_intern(env, &res);
}

static int resource_of_dynptr(struct bpf_verifier_env *env, const struct bpf_reg_state *reg)
{
	struct bpf_resource res;

	if (!helper_ok(env, BPF_FUNC_ringbuf_discard_dynptr)) {
		verbose(env, "frame_desc: cannot release a ringbuf dynptr in this program\n");
		return -EOPNOTSUPP;
	}
	memset(&res, 0, sizeof(res));
	res.kind = BPF_RESOURCE_DYNPTR_RINGBUF;
	return resource_intern(env, &res);
}

/*
 * Does frame @frameno of @st own reference @ref: the frame that acquired it,
 * or was handed it at a return, see bpf_reference_state::frameno. A reference
 * the kernel holds for a __ref argument of a struct_ops program was acquired
 * by no frame; the main program holds it for the kernel, and owns it for the
 * descriptors, so that it is listed wherever main holds it, whether or not
 * the program releases it, and released by the unwinder when main is unwound
 * with it. A callee that releases it claims it like any reference of a frame
 * below, and main drops it at the call that passed it the context.
 */
static bool ref_owned(const struct bpf_verifier_state *st, const struct bpf_reference_state *ref,
		      int frameno)
{
	if (ref->frameno == frameno)
		return true;
	return ref->frameno < 0 && bpf_origin_is_ctx_arg(ref->origin) && frameno == 0 &&
	       st->frame[0]->subprogno == 0;
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

	if (reg->type & PTR_UNTRUSTED) {
		verbose(env,
			"frame_desc: cannot release an iterator after its RCU protection ended\n");
		return -EOPNOTSUPP;
	}
	memset(&res, 0, sizeof(res));
	res.kind = BPF_RESOURCE_ITER;
	res.btf = reg->iter.btf;
	res.btf_id = reg->iter.btf_id;
	ret = resource_registry(env, reg->iter.btf, reg->iter.btf_id, &res, "iterator");
	if (ret)
		return ret;
	res.rcu = (reg->type & MEM_RCU) && !res.sleeps;
	return resource_intern(env, &res);
}

/*
 * Does @reg hold the object of reference @id: the pointer to it, or one a
 * constant number of bytes into it, which the class of the location carries
 * as its delta, see resource_of_reg()?
 */
static bool reg_is_ref(const struct bpf_reg_state *reg, int id)
{
	return reg->type != SCALAR_VALUE && reg->type != NOT_INIT && reg->id == id &&
	       tnum_is_const(reg->var_off) && reg->var_off.value == (u64)(s16)reg->var_off.value;
}

/*
 * Does @slot hold 8 bytes of zero: a spilled zero that fills it, or zero
 * bytes? A spill of fewer bytes leaves the rest as they were.
 */
static bool stack_slot_is_null(const struct bpf_stack_state *slot)
{
	int i;

	if (bpf_is_spilled_scalar_reg(slot))
		return bpf_spill_size(slot) == BPF_REG_SIZE &&
		       bpf_register_is_null((struct bpf_reg_state *)&slot->spilled_ptr);
	for (i = 0; i < BPF_REG_SIZE; i++)
		if (slot->slot_type[i] != STACK_ZERO)
			return false;
	return true;
}

/*
 * Is @slot the stack object of reference @id: the first slot of an iterator,
 * or of a ringbuf dynptr, which tracks the record's reference as its parent?
 */
static bool stack_slot_is_object(const struct bpf_stack_state *slot, int id)
{
	const struct bpf_reg_state *reg = &slot->spilled_ptr;

	switch (slot->slot_type[BPF_REG_SIZE - 1]) {
	case STACK_DYNPTR:
		return reg->dynptr.first_slot && reg->dynptr.type == BPF_DYNPTR_TYPE_RINGBUF &&
		       reg->parent_id == id;
	case STACK_ITER:
		return reg->id == id;
	default:
		return false;
	}
}

/* The class of the stack object at @slot, see stack_slot_is_object(). */
static int resource_of_object(struct bpf_verifier_env *env, const struct bpf_stack_state *slot)
{
	if (slot->slot_type[BPF_REG_SIZE - 1] == STACK_DYNPTR)
		return resource_of_dynptr(env, &slot->spilled_ptr);
	return resource_of_iter(env, &slot->spilled_ptr);
}

/*
 * Does @slot hold the pointer of reference @id, and what resource class is
 * it then, when @classify? -ENOENT when it does not.
 */
static int stack_slot_ref(struct bpf_verifier_env *env, const struct bpf_stack_state *slot, int id,
			  bool classify)
{
	const struct bpf_reg_state *reg = &slot->spilled_ptr;

	if (slot->slot_type[BPF_REG_SIZE - 1] != STACK_SPILL || !bpf_is_spilled_reg(slot) ||
	    !reg_is_ref(reg, id))
		return -ENOENT;
	return classify ? resource_of_reg(env, reg) : 0;
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

/* The id of the reference the stack object in @slot is, see stack_slot_is_object(). */
static int object_slot_id(const struct bpf_stack_state *slot)
{
	return slot->slot_type[BPF_REG_SIZE - 1] == STACK_DYNPTR ? slot->spilled_ptr.parent_id :
								    slot->spilled_ptr.id;
}

/* Does @reg point at the stack object at slot @spi of frame @frameno? */
static bool reg_points_at(const struct bpf_reg_state *reg, int frameno, int spi)
{
	return reg->type == PTR_TO_STACK && reg->frameno == frameno &&
	       tnum_is_const(reg->var_off) && (s64)reg->var_off.value == -(spi + 1) * BPF_REG_SIZE;
}

/*
 * Rank a candidate location that no earlier path lists: a location another
 * path left NULL merges best, then a stack slot or a callee-saved register,
 * which outlive calls, before a caller-saved register. Lower is better.
 */
static int cand_rank(const struct cand *c, const struct bpf_frame_desc_loc *loc)
{
	int rank = loc->state == LOC_NULL ? 0 : 4;

	if (c->is_slot)
		return rank;
	return rank + (c->idx >= BPF_REG_6 ? 1 : 2);
}

static struct bpf_frame_desc_loc *build_loc(struct bpf_frame_desc_build *b, const struct cand *c)
{
	return c->is_slot ? &b->slots[c->idx] : &b->regs[c->idx];
}

static int cand_idx(const struct cand *c)
{
	return c->is_slot ? BPF_REG_10 + c->idx : c->idx;
}

/*
 * Choose where the reference acquired at @acq is released from, given its @nr
 * candidate locations on this path and what earlier paths put into the
 * descriptor. A location an earlier path already lists for it must be
 * reused, so that the reference is never listed twice on a path; otherwise
 * prefer a location no earlier path has put a resource or a copy into, by
 * rank. Fails when earlier paths list it at two candidates (-EEXIST), list
 * something else at one (-EINVAL), or when no candidate is free (-ENOENT).
 */
static int choose(struct bpf_verifier_env *env, struct scratch *s, int nr, u32 acq)
{
	int i, chosen = -1, free = -1, free_rank = INT_MAX;

	for (i = 0; i < nr; i++) {
		const struct cand *c = &s->cands[i];
		struct bpf_frame_desc_loc *loc = build_loc(s->build, c);

		if (loc->state == LOC_RES) {
			if (loc->acq != acq)
				return -EINVAL;
			if (chosen >= 0)
				return -EEXIST;
			chosen = i;
		} else if (loc->state == LOC_UNSEEN || loc->state == LOC_NULL) {
			int rank = cand_rank(c, loc);

			if (rank < free_rank) {
				free = i;
				free_rank = rank;
			}
		}
	}
	if (chosen >= 0)
		return chosen;
	return free >= 0 ? free : -ENOENT;
}

/*
 * No location lists the reference acquired at @acq on every path reaching
 * the site: the paths disagree on where it is, @why. The program is
 * rejected for now.
 */
static int conflict(struct bpf_verifier_env *env, u32 acq, const char *why)
{
	env->frame_desc_conflicts++;
	verbose(env, "frame_desc: the reference acquired at insn %d %s: no location describes it on every path\n",
		acq, why);
	return -EINVAL;
}

/* Merge one path's classification of a location into the descriptor. */
static int merge(struct bpf_verifier_env *env, struct bpf_frame_desc_loc *loc, int class, u16 res,
		 u32 acq, bool indirect)
{
	int ret;

	switch (loc->state) {
	case LOC_UNSEEN:
	case LOC_NULL:
		switch (class) {
		case CLASS_RES:
			loc->nullable = loc->state == LOC_NULL;
			loc->state = LOC_RES;
			loc->res = res;
			loc->acq = acq;
			loc->indirect = indirect;
			break;
		case CLASS_NULL:
			loc->state = LOC_NULL;
			break;
		case CLASS_COPY:
			loc->state = LOC_COPY;
			break;
		default:
			loc->state = LOC_OTHER;
		}
		return 0;
	case LOC_RES:
		switch (class) {
		case CLASS_RES:
			/* choose() reuses a listed location only for the same acquisition. */
			if (loc->indirect == indirect)
				return 0;
			return conflict(env, acq, "is a stack object on one path and a pointer on another");
		case CLASS_NULL:
			/* A stack object in place is never NULL. */
			if (!loc->indirect)
				return conflict(env, loc->acq, "is a stack object that is not there on every path");
			loc->nullable = 1;
			return 0;
		default:
			/* Not the resource on this path: the listing is withdrawn. */
			ret = conflict(env, loc->acq, "is at different locations on different paths");
			if (ret)
				return ret;
			loc->state = LOC_OTHER;
			if (class == CLASS_COPY)
				return conflict(env, acq, "shares a location with another resource");
			return 0;
		}
	default:
		/* choose() never lists a location an earlier path used otherwise. */
		if (class == CLASS_RES)
			return conflict(env, acq, "shares a location with another resource");
		return 0;
	}
}

/* Release order: locks and IRQ flags, RCU objects, sections, then other objects. */
static int entry_cmp(const void *a, const void *b)
{
	const struct bpf_frame_desc_entry *x = a, *y = b;

	if (x->order != y->order)
		return y->order - x->order;
	if (x->loc != y->loc)
		return x->loc - y->loc;
	if (x->off != y->off)
		return x->off - y->off;
	return x->res - y->res;
}

static s16 resource_order(const struct bpf_verifier_env *env, u16 res)
{
	return env->resources[res].rcu ? ORDER_RCU_OBJ : ORDER_OBJ;
}

/* Lay out the entries of one descriptor: every listed location of the frame. */
static u32 build_body(const struct bpf_verifier_env *env, const struct bpf_frame_desc_build *b,
		      struct bpf_frame_desc *d)
{
	u32 n = 0, i;

	for (i = 0; i < BPF_REG_10 + b->nr_slots; i++) {
		const struct bpf_frame_desc_loc *loc = i < BPF_REG_10 ? &b->regs[i] :
								     &b->slots[i - BPF_REG_10];
		struct bpf_frame_desc_entry *ent;

		if (loc->state != LOC_RES)
			continue;
		if (!d) {
			n++;
			continue;
		}
		ent = &d->ent[n++];
		ent->loc = i < BPF_REG_10 ? BPF_FRAME_LOC_REG : BPF_FRAME_LOC_STACK;
		ent->off = i < BPF_REG_10 ? i : -(i - BPF_REG_10 + 1) * BPF_REG_SIZE;
		ent->flags = (loc->indirect ? BPF_FRAME_ENT_INDIRECT : 0) |
			     (loc->nullable ? BPF_FRAME_ENT_NULLABLE : 0);
		ent->res = loc->res;
		ent->order = resource_order(env, loc->res);
	}
	if (d) {
		d->nent = n;
		d->size = struct_size(d, ent, n);
		sort(d->ent, n, sizeof(d->ent[0]), entry_cmp, NULL);
	}
	return n;
}

/* Add the descriptor of @b to the pool, sharing an identical earlier one. */
static int pool_add(struct bpf_verifier_env *env, const struct bpf_frame_desc_build *b)
{
	struct bpf_frame_desc_pool *pool = env->frame_desc_pool;
	struct bpf_frame_desc *d;
	u32 i, n = build_body(env, b, NULL);

	d = kvzalloc(struct_size(d, ent, n), GFP_KERNEL_ACCOUNT);
	if (!d)
		return -ENOMEM;
	build_body(env, b, d);
	for (i = 0; i < pool->cnt; i++) {
		if (pool->desc[i]->size == d->size && !memcmp(pool->desc[i], d, d->size)) {
			kvfree(d);
			return i;
		}
	}
	pool = kvrealloc(pool, struct_size(pool, desc, pool->cnt + 1), GFP_KERNEL_ACCOUNT);
	if (!pool) {
		kvfree(d);
		return -ENOMEM;
	}
	env->frame_desc_pool = pool;
	pool->desc[pool->cnt] = d;
	env->frame_desc_bytes += d->size;
	return pool->cnt++;
}

/* Is @insn, after all rewrites, what the unwinder sees a site through: a call. */
static bool site_insn_ok(const struct bpf_insn *insn)
{
	return insn->code == (BPF_JMP | BPF_CALL);
}

/*
 * After all instruction rewrites, turn the descriptors attached to instructions
 * into the per subprogram tables the unwinder uses, keyed by instruction index
 * until the JIT fills in native offsets. Identical descriptors share a body.
 */
int bpf_frame_desc_build_tables(struct bpf_verifier_env *env)
{
	struct bpf_insn_aux_data *aux = env->insn_aux_data;
	struct bpf_frame_desc_pool *pool;
	int i, s, ret;

	if (!env->frame_desc_visits)
		return 0;
	pool = kvzalloc(struct_size(pool, desc, 0), GFP_KERNEL_ACCOUNT);
	if (!pool)
		return -ENOMEM;
	env->frame_desc_pool = pool;
	for (s = 0; s < env->subprog_cnt; s++) {
		u32 start = env->subprog_info[s].start, end = env->subprog_info[s + 1].start;
		struct bpf_frame_desc_table *tab;
		u32 cnt = 0;

		for (i = start; i < end; i++)
			cnt += !!aux[i].frame_desc;
		if (!cnt)
			continue;
		tab = kvzalloc(struct_size(tab, site, cnt), GFP_KERNEL_ACCOUNT);
		if (!tab)
			return -ENOMEM;
		env->subprog_info[s].frame_desc_table = tab;
		env->frame_desc_bytes += struct_size(tab, site, cnt);
		for (i = start; i < end; i++) {
			if (!aux[i].frame_desc)
				continue;
			if (verifier_bug_if(!site_insn_ok(&env->prog->insnsi[i]), env,
					    "frame descriptor at insn %d is not at a site", i))
				return -EFAULT;
			ret = pool_add(env, aux[i].frame_desc);
			if (ret < 0)
				return ret;
			tab->site[tab->cnt++] = (struct bpf_frame_desc_site) { .off = i - start,
									      .desc = ret };
			env->frame_desc_sites++;
		}
	}
	/* a guard whose may_goto was not added after all, see check_recursion() */
	for (s = 0; s < env->subprog_cnt; s++) {
		bpf_frame_desc_build_destroy(env->subprog_info[s].entry_guard);
		env->subprog_info[s].entry_guard = NULL;
	}
	env->frame_desc_pool->resources = env->resources;
	env->frame_desc_pool->resource_cnt = env->resource_cnt;
	env->frame_desc_bytes += env->resource_cnt * sizeof(*env->resources);
	env->resources = NULL;
	/* A program without BPF-to-BPF calls is JITed whole: hand it the main table. */
	if (env->subprog_cnt == 1) {
		env->prog->aux->frame_desc_table = env->subprog_info[0].frame_desc_table;
		env->subprog_info[0].frame_desc_table = NULL;
	}
	return 0;
}

/*
 * The tables key sites by instruction index until the JIT fills them. A commit
 * of the patch list after they were built, which only constant blinding does,
 * moves the insns of each subprog: a site keeps the last insn of the patch of
 * its insn, where the aux data of a patched insn goes, and the sites of a
 * subprog stay relative to its start. The subprog starts are still those of the
 * old image here, see bpf_patch_list_commit().
 */
void bpf_frame_desc_remap_tables(struct bpf_verifier_env *env, const struct bpf_patch_image *img)
{
	int s;

	for (s = 0; s < env->subprog_cnt; s++) {
		struct bpf_frame_desc_table *tab = env->subprog_cnt == 1 ?
			env->prog->aux->frame_desc_table : env->subprog_info[s].frame_desc_table;
		u32 start = env->subprog_info[s].start, i;

		if (!tab || tab->filled)
			continue;
		for (i = 0; i < tab->cnt; i++) {
			u32 off = start + tab->site[i].off;

			tab->site[i].off = bpf_patch_image_remap(img, img->new_off, off + 1) - 1 -
					   bpf_patch_image_remap(img, img->new_off, start);
		}
	}
}

/*
 * The locations of the frame that hold the pointer of reference @ref: the
 * live registers and the live stack slots the state allocated. Those of a
 * reference the frame does not own are copies, which need no class.
 */
static int find_cands(struct bpf_verifier_env *env, struct scratch *s,
		      const struct bpf_func_state *frame, const struct bpf_reference_state *ref,
		      bool classify)
{
	int k, nr = 0, ret;

	for (k = 0; k < BPF_REG_10; k++) {
		if (!(s->live_regs & BIT(k)) || !reg_is_ref(&frame->regs[k], ref->id))
			continue;
		ret = classify ? resource_of_reg(env, &frame->regs[k]) : 0;
		if (ret < 0)
			return ret;
		s->cands[nr++] = (struct cand) { .indirect = 1, .idx = k, .res = ret,
						 .nullable = type_may_be_null(frame->regs[k].type) };
	}
	for (k = 0; k < bpf_stack_nr_slots(frame); k++) {
		const struct bpf_stack_state *slot = bpf_stack_slot(frame, k);

		if (!test_bit(k, s->live_stack))
			continue;
		ret = stack_slot_ref(env, slot, ref->id, classify);
		if (ret == -ENOENT)
			continue;
		if (ret < 0)
			return ret;
		s->cands[nr++] = (struct cand) { .is_slot = 1, .indirect = 1, .idx = k, .res = ret,
						 .nullable = type_may_be_null(slot->spilled_ptr.type) };
	}
	/*
	 * A reference the kernel holds for a __ref argument sits in the context
	 * until the program loads it: a live pointer to the context holds it,
	 * through the context, by a class that says how far in, see
	 * resource_of_ctx_arg(). The pointer may point into the context.
	 */
	if (bpf_origin_is_ctx_arg(ref->origin)) {
		u32 argno = BPF_ORIGIN_CTX_ARGNO(ref->origin);
		s64 base = env->prog->aux->ctx_arg_info[argno].offset, off;

		for (k = 0; k < BPF_REG_10 + bpf_stack_nr_slots(frame); k++) {
			const struct bpf_reg_state *reg;
			bool is_slot = k >= BPF_REG_10;

			if (is_slot) {
				const struct bpf_stack_state *slot = bpf_stack_slot(frame, k - BPF_REG_10);

				if (!test_bit(k - BPF_REG_10, s->live_stack) || !bpf_is_spilled_reg(slot))
					continue;
				reg = &slot->spilled_ptr;
			} else {
				if (!(s->live_regs & BIT(k)))
					continue;
				reg = &frame->regs[k];
			}
			if (reg->type != PTR_TO_CTX || !tnum_is_const(reg->var_off))
				continue;
			off = base - (s64)reg->var_off.value;
			if (off != (s16)off)
				continue;
			ret = classify ? resource_of_ctx_arg(env, argno, true, off) : 0;
			if (ret < 0)
				return ret;
			s->cands[nr++] = (struct cand) { .is_slot = is_slot, .indirect = 1,
							 .idx = is_slot ? k - BPF_REG_10 : k, .res = ret };
		}
	}
	return nr;
}

/*
 * The locations of the frame that give the stack object of reference @ref,
 * at slot @spi of frame @objframe: the slot itself when it is in this frame,
 * whether it is live or not, since the joins of the verifier keep stack
 * objects whatever their liveness, and the live registers and stack slots
 * that point at it, which release it through the pointer.
 */
static int find_object_cands(struct bpf_verifier_env *env, struct scratch *s,
			     const struct bpf_verifier_state *st, int objframe, int spi,
			     bool classify)
{
	const struct bpf_func_state *frame = st->frame[st->curframe];
	int id = object_slot_id(bpf_stack_slot(st->frame[objframe], spi));
	int k, nr = 0, res = 0;

	if (classify) {
		res = resource_of_object(env, bpf_stack_slot(st->frame[objframe], spi));
		if (res < 0)
			return res;
	}
	if (objframe == st->curframe)
		s->cands[nr++] = (struct cand) { 1, 0, spi, res };
	/* a pointer to the object, or to any clone of a dynptr, which is the object as well */
	for (k = 0; k < BPF_REG_10; k++) {
		if (!(s->live_regs & BIT(k)) || !reg_object_slot(st, &frame->regs[k], id))
			continue;
		s->cands[nr++] = (struct cand) { 0, 1, k, res };
	}
	for (k = 0; k < bpf_stack_nr_slots(frame); k++) {
		const struct bpf_stack_state *slot = bpf_stack_slot(frame, k);

		if (!test_bit(k, s->live_stack) || !bpf_is_spilled_reg(slot) ||
		    !reg_object_slot(st, &slot->spilled_ptr, id))
			continue;
		s->cands[nr++] = (struct cand) { 1, 1, k, res };
	}
	return nr;
}

/* Classify the @nr candidates of a reference the frame holds for another frame. */
static void place_copy(struct scratch *s, int nr)
{
	int k;

	for (k = 0; k < nr; k++)
		s->class[cand_idx(&s->cands[k])] = CLASS_COPY;
}

/*
 * List reference @ref the frame owns at one of its @nr candidate locations on
 * this path, the one the paths agree on, see choose(). The other candidates
 * hold copies. A reference no live location holds is one the program never
 * reads again: it would leak at the site, which rejects the program for now.
 */
static int place_ref(struct bpf_verifier_env *env, struct scratch *s,
		     const struct bpf_reference_state *ref, int nr)
{
	const char *why;
	int k, chosen;

	if (!nr) {
		verbose(env, "frame_desc: reference id=%d (acquired at insn %d) is held at no live location\n",
			ref->id, ref->insn_idx);
		return -EINVAL;
	}
	chosen = choose(env, s, nr, ref->insn_idx);
	why = chosen == -ENOENT ? "has no location free to be released from" :
	      chosen == -EEXIST ? "is at different locations on different paths" :
	      chosen == -EINVAL ? "shares a location with another resource on another path" : NULL;
	if (why)
		return conflict(env, ref->insn_idx, why);
	for (k = 0; k < nr; k++) {
		const struct cand *c = &s->cands[k];
		int idx = cand_idx(c);

		s->class[idx] = k == chosen ? CLASS_RES : CLASS_COPY;
		s->res[idx] = c->res;
		s->acq[idx] = ref->insn_idx;
		s->nullable[idx] = c->nullable;
		s->indirect[idx] = c->indirect;
	}
	return 0;
}

/*
 * Record the state of the current frame at a site where the program may be
 * unwound. @regs_saved says that the entry the unwinder is reached through
 * saves R0-R9 of the frame; otherwise it waits in a call and only keeps R6-R9
 * and its stack. Only live locations are considered, which keeps the
 * descriptors consistent with the joins of the verifier: two states it joins
 * agree on every live location, and so do a state and one it is within.
 */
static int site_do(struct bpf_verifier_env *env, bool regs_saved,
		   struct bpf_frame_desc_build **slot)
{
	struct bpf_verifier_state *st = env->cur_state;
	struct bpf_func_state *frame = st->frame[st->curframe];
	struct scratch *s = env->frame_desc_scratch;
	struct bpf_frame_desc_build *b;
	int i, k, nr, ret;

	if (!s) {
		s = kvzalloc_obj(*s, GFP_KERNEL_ACCOUNT);
		if (!s)
			return -ENOMEM;
		env->frame_desc_scratch = s;
	}
	env->frame_desc_visits++;

	s->pc = env->insn_idx;
	s->live_regs = env->insn_aux_data[s->pc].live_regs_before;
	if (!regs_saved)
		s->live_regs &= CALLEE_SAVED_REGS;
	s->live_stack = env->insn_aux_data[s->pc].live_stack_before;
	memset(s->class, 0, sizeof(s->class));
	memset(s->nullable, 0, sizeof(s->nullable));
	b = build_get(env, s->pc, bpf_stack_nr_slots(frame), slot);
	if (!b)
		return -ENOMEM;
	b->regs_saved = regs_saved;
	s->build = b;

	/* List every reference the frame owns; what it holds for others are copies. */
	for (i = 0; i < st->acquired_refs; i++) {
		const struct bpf_reference_state *ref = &st->refs[i];
		bool owned = ref_owned(st, ref, st->curframe);
		int objframe, spi;

		if (ref->type != REF_TYPE_PTR)
			continue;
		if (stack_object_find(st, ref, &objframe, &spi))
			nr = find_object_cands(env, s, st, objframe, spi, owned);
		else
			nr = find_cands(env, s, frame, ref, owned);
		if (nr < 0)
			return nr;
		if (!owned) {
			place_copy(s, nr);
			continue;
		}
		ret = place_ref(env, s, ref, nr);
		if (ret)
			return ret;
	}

	/* Classify the remaining live locations and merge. */
	for (k = 0; k < BPF_REG_10 + b->nr_slots; k++) {
		struct bpf_frame_desc_loc *dst;

		if (k < BPF_REG_10) {
			if (!(s->live_regs & BIT(k)))
				continue;
			if (!s->class[k] && bpf_register_is_null(&frame->regs[k]))
				s->class[k] = CLASS_NULL;
			dst = &b->regs[k];
		} else {
			int spi = k - BPF_REG_10;

			if (!test_bit(spi, s->live_stack))
				continue;
			/* A live slot this state has not allocated holds anything. */
			if (!s->class[k] && spi < bpf_stack_nr_slots(frame) &&
			    stack_slot_is_null(bpf_stack_slot(frame, spi)))
				s->class[k] = CLASS_NULL;
			dst = &b->slots[spi];
		}
		ret = merge(env, dst, s->class[k], s->res[k], s->acq[k], s->indirect[k]);
		if (ret)
			return ret;
		/*
		 * A reference the program has not checked for NULL yet is held by
		 * its id all the same: where the location lists it, the unwinder
		 * has to skip NULL, which the acquisition may have returned.
		 */
		if (s->class[k] == CLASS_RES && s->nullable[k] && dst->state == LOC_RES)
			dst->nullable = 1;
	}
	b->visits++;
	return 0;
}

/*
 * Describe the current frame at a site where the program may be unwound: a
 * bpf_throw() call. The descriptor goes to the aux data of the insn, or to
 * @slot: the site of a may_goto the verifier adds is the insn it goes in
 * front of, and the descriptor is moved onto the may_goto once it is there.
 */
static int site(struct bpf_verifier_env *env, bool regs_saved, struct bpf_frame_desc_build **slot)
{
	if (env->cur_state->speculative)
		return 0;
	return site_do(env, regs_saved, slot);
}

int bpf_frame_desc_site(struct bpf_verifier_env *env, bool regs_saved)
{
	return site(env, regs_saved, NULL);
}

/* The timed may_goto slow path saves R0-R9, like the entry of bpf_throw(). */
int bpf_frame_desc_guard_site(struct bpf_verifier_env *env, struct bpf_frame_desc_build **slot)
{
	return site(env, true, slot);
}
