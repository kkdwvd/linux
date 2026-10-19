// SPDX-License-Identifier: GPL-2.0-only
/*
 * Frame descriptors: which registers and stack slots of each BPF frame hold
 * kernel resources at an instruction where the program may be unwound.
 *
 * The verifier calls bpf_fdesc_site() at every such site with the state the
 * site is reached in. For the innermost frame the site is the instruction
 * itself; for every caller frame it is the call instruction the frame waits
 * in, since that is where the unwinder finds the frame's return address. One
 * descriptor is built per (subprog, insn) and merged over all paths reaching
 * it, so that the unwinder can release the resources of a frame from its
 * instruction pointer alone.
 */
#include <linux/bpf.h>
#include <linux/bpf_verifier.h>
#include <linux/btf.h>
#include <linux/kallsyms.h>
#include <linux/sort.h>

#define verbose(env, fmt, args...) bpf_verifier_log_write(env, fmt, ##args)

/*
 * What a location (register or stack slot) has held across the paths merged
 * into a descriptor so far. Only RES locations are released at run time; NULL
 * is the one disagreement allowed with RES, since the unwinder skips NULL.
 */
enum {
	FDESC_LOC_UNSEEN,	/* no path classified this location yet */
	FDESC_LOC_NULL,		/* known NULL on every path so far */
	FDESC_LOC_RES,		/* holds the resource of class .res, maybe NULL on some path */
	FDESC_LOC_COPY,		/* held a copy of a resource that is released elsewhere */
	FDESC_LOC_OTHER,	/* held something that must not be released */
};

/* Per-path classification of a location. */
enum {
	FDESC_CLASS_OTHER,
	FDESC_CLASS_NULL,
	FDESC_CLASS_RES,
	FDESC_CLASS_COPY,
};

#define FDESC_REGS_CALLEE_SAVED	(BIT(BPF_REG_6) | BIT(BPF_REG_7) | BIT(BPF_REG_8) | BIT(BPF_REG_9))
#define FDESC_FRAME_LOCS	(BPF_REG_10 + MAX_BPF_STACK_SLOTS)
#define FDESC_MAX_FIXED		32	/* locks, IRQ flags and sections a frame may hold */

/* A candidate location of one reference on the current path. */
struct fdesc_cand {
	u16 frameno;
	u16 is_slot;
	u16 idx;	/* register number or spi */
	u16 res;
};

/* Per-site working storage, allocated once per verification. */
struct fdesc_scratch {
	struct fdesc_cand cands[MAX_CALL_FRAMES * FDESC_FRAME_LOCS];
	u8 class[MAX_CALL_FRAMES][FDESC_FRAME_LOCS];
	u16 res[MAX_CALL_FRAMES][FDESC_FRAME_LOCS];
	struct bpf_fdesc_build *builds[MAX_CALL_FRAMES];
	u32 pcs[MAX_CALL_FRAMES];
	u32 live_regs[MAX_CALL_FRAMES];
	struct bpf_fdesc_ent fixed[MAX_CALL_FRAMES][FDESC_MAX_FIXED];
	u16 nr_fixed[MAX_CALL_FRAMES];
	u16 obj_frames;		/* frames that release an object on this path */
	u16 sleep_frames;	/* frames that release an object whose destructor sleeps */
};

static struct bpf_fdesc_build *fdesc_build_get(struct bpf_verifier_env *env, u32 pc, u32 nr_slots)
{
	struct bpf_fdesc_build *b = env->insn_aux_data[pc].fdesc;

	if (!b) {
		b = kvzalloc(struct_size(b, slots, nr_slots), GFP_KERNEL_ACCOUNT);
		if (!b)
			return NULL;
		b->pc = pc;
		b->nr_slots = nr_slots;
		env->insn_aux_data[pc].fdesc = b;
	} else if (b->nr_slots < nr_slots) {
		b = kvrealloc(b, struct_size(b, slots, nr_slots), GFP_KERNEL_ACCOUNT);
		if (!b)
			return NULL;
		memset(&b->slots[b->nr_slots], 0, (nr_slots - b->nr_slots) * sizeof(b->slots[0]));
		b->nr_slots = nr_slots;
		env->insn_aux_data[pc].fdesc = b;
	}
	return b;
}

static void fdesc_build_destroy(struct bpf_fdesc_build *b)
{
	if (!b)
		return;
	kvfree(b->callers);
	kvfree(b->fixed);
	kvfree(b);
}

void bpf_fdesc_build_free(struct bpf_insn_aux_data *aux)
{
	fdesc_build_destroy(aux->fdesc);
	aux->fdesc = NULL;
}

/* The subprog insn @idx belongs to. */
static int fdesc_insn_subprog(struct bpf_verifier_env *env, u32 idx)
{
	int s;

	for (s = 0; s < env->subprog_cnt; s++)
		if (idx < env->subprog_info[s + 1].start)
			return s;
	return -1;
}

/* Remember that the site of @b was reached with @caller waiting in a call. */
static int fdesc_add_caller(struct bpf_fdesc_build *b, struct bpf_fdesc_build *caller)
{
	struct bpf_fdesc_build **callers;
	int i;

	for (i = 0; i < b->nr_callers; i++)
		if (b->callers[i] == caller)
			return 0;
	callers = kvrealloc(b->callers, array_size(b->nr_callers + 1, sizeof(*callers)),
			    GFP_KERNEL_ACCOUNT);
	if (!callers)
		return -ENOMEM;
	callers[b->nr_callers++] = caller;
	b->callers = callers;
	return 0;
}

void bpf_fdesc_env_free(struct bpf_verifier_env *env)
{
	kvfree(env->fdesc_res);
	kvfree(env->fdesc_scratch);
	env->fdesc_res = NULL;
	env->fdesc_scratch = NULL;
}

/* Intern a resource class; descriptors refer to it by index. */
static int fdesc_res_intern(struct bpf_verifier_env *env, const struct bpf_fdesc_res *res)
{
	struct bpf_fdesc_res *tab;
	u32 i, cnt = env->fdesc_res_cnt;

	for (i = 0; i < cnt; i++)
		if (!memcmp(&env->fdesc_res[i], res, sizeof(*res)))
			return i;
	if (cnt >= U16_MAX)
		return -E2BIG;
	tab = kvrealloc(env->fdesc_res, array_size(cnt + 1, sizeof(*tab)), GFP_KERNEL_ACCOUNT);
	if (!tab)
		return -ENOMEM;
	tab[cnt] = *res;
	env->fdesc_res = tab;
	env->fdesc_res_cnt = cnt + 1;
	return cnt;
}

/*
 * Resolve the destructor of a referenced kernel object or an iterator through
 * the BTF destructor registry, and check that the program could have called
 * the matching release kfunc itself: that is the context in which running the
 * destructor is legal. A class interned for the type already has it resolved.
 */
static int fdesc_res_registry(struct bpf_verifier_env *env, struct btf *btf, u32 btf_id,
			      struct bpf_fdesc_res *res, const char *what)
{
	const struct btf_id_dtor_kfunc *dtor = btf_find_dtor(btf, btf_id);
	const char *name = btf_name_by_offset(btf, btf_type_by_id(btf, btf_id)->name_off);
	const struct btf_type *t;
	u32 i, *flags;

	for (i = 0; i < env->fdesc_res_cnt; i++) {
		const struct bpf_fdesc_res *r = &env->fdesc_res[i];

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
	flags = btf_kfunc_flags(btf, dtor->release_btf_id, env->prog);
	if (!flags) {
		verbose(env, "frame_desc: release kfunc of %s %s is not callable by this program\n",
			what, name);
		return -EOPNOTSUPP;
	}
	res->sleeps = *flags & KF_SLEEPABLE;
	t = btf_type_by_id(btf, dtor->kfunc_btf_id);
	res->dtor = t ? (void *)kallsyms_lookup_name(btf_name_by_offset(btf, t->name_off)) : NULL;
	if (!res->dtor) {
		verbose(env, "frame_desc: cannot resolve the destructor of %s %s\n", what, name);
		return -EINVAL;
	}
	return 0;
}

static bool fdesc_helper_ok(struct bpf_verifier_env *env, enum bpf_func_id func_id)
{
	return env->ops->get_func_proto && env->ops->get_func_proto(func_id, env->prog);
}

/* Classify a register or spilled register that holds a reference. */
static int fdesc_res_of_reg(struct bpf_verifier_env *env, const struct bpf_reg_state *reg)
{
	u32 flags = type_flag(reg->type) & ~PTR_MAYBE_NULL;
	struct bpf_fdesc_res res;
	int ret;

	memset(&res, 0, sizeof(res));
	res.type = reg->type & ~PTR_MAYBE_NULL;
	switch (base_type(reg->type)) {
	case PTR_TO_BTF_ID:
		res.btf = reg->btf;
		res.btf_id = reg->btf_id;
		if (flags & MEM_ALLOC) {
			if (flags & ~(MEM_ALLOC | MEM_PERCPU))
				goto unsupported;
			res.kind = flags & MEM_PERCPU ? BPF_FDESC_PERCPU_OBJ : BPF_FDESC_OBJ;
			res.meta = btf_find_struct_meta(reg->btf, reg->btf_id);
			break;
		}
		if (flags & ~PTR_TRUSTED)
			goto unsupported;
		res.kind = BPF_FDESC_KPTR;
		ret = fdesc_res_registry(env, reg->btf, reg->btf_id, &res, "object");
		if (ret)
			return ret;
		break;
	case PTR_TO_SOCKET:
	case PTR_TO_SOCK_COMMON:
	case PTR_TO_TCP_SOCK:
		if (flags || !fdesc_helper_ok(env, BPF_FUNC_sk_release))
			goto unsupported;
		res.kind = BPF_FDESC_SOCK;
		break;
	case PTR_TO_MEM:
		if (flags != MEM_RINGBUF || !fdesc_helper_ok(env, BPF_FUNC_ringbuf_discard))
			goto unsupported;
		res.kind = BPF_FDESC_RINGBUF;
		break;
	default:
		goto unsupported;
	}
	return fdesc_res_intern(env, &res);
unsupported:
	verbose(env, "frame_desc: cannot release a reference of type %s\n",
		reg_type_str(env, reg->type));
	return -EOPNOTSUPP;
}

static int fdesc_res_of_dynptr(struct bpf_verifier_env *env, const struct bpf_reg_state *reg)
{
	struct bpf_fdesc_res res;

	if (!fdesc_helper_ok(env, BPF_FUNC_ringbuf_discard_dynptr)) {
		verbose(env, "frame_desc: cannot release a ringbuf dynptr in this program\n");
		return -EOPNOTSUPP;
	}
	memset(&res, 0, sizeof(res));
	res.kind = BPF_FDESC_DYNPTR_RINGBUF;
	return fdesc_res_intern(env, &res);
}

static int fdesc_res_of_iter(struct bpf_verifier_env *env, const struct bpf_reg_state *reg)
{
	struct bpf_fdesc_res res;
	int ret;

	memset(&res, 0, sizeof(res));
	res.kind = BPF_FDESC_ITER;
	res.btf = reg->iter.btf;
	res.btf_id = reg->iter.btf_id;
	ret = fdesc_res_registry(env, reg->iter.btf, reg->iter.btf_id, &res, "iterator");
	if (ret)
		return ret;
	return fdesc_res_intern(env, &res);
}

/*
 * Does @reg hold the object of reference @id itself? A pointer with the same
 * id but an offset points into the object and cannot be released.
 */
static bool fdesc_reg_is_ref(const struct bpf_reg_state *reg, int id)
{
	return reg->type != SCALAR_VALUE && reg->type != NOT_INIT && reg->id == id &&
	       tnum_is_const(reg->var_off) && reg->var_off.value == 0;
}

static bool fdesc_slot_is_null(const struct bpf_stack_state *slot)
{
	int i;

	if (bpf_is_spilled_scalar_reg(slot))
		return bpf_register_is_null((struct bpf_reg_state *)&slot->spilled_ptr);
	for (i = 0; i < BPF_REG_SIZE; i++)
		if (slot->slot_type[i] != STACK_ZERO)
			return false;
	return true;
}

/* Does @slot hold reference @id, and what resource class is it then? */
static int fdesc_slot_ref(struct bpf_verifier_env *env, const struct bpf_stack_state *slot, int id)
{
	const struct bpf_reg_state *reg = &slot->spilled_ptr;

	switch (slot->slot_type[BPF_REG_SIZE - 1]) {
	case STACK_SPILL:
		if (!bpf_is_spilled_reg(slot) || !fdesc_reg_is_ref(reg, id))
			return -ENOENT;
		return fdesc_res_of_reg(env, reg);
	case STACK_DYNPTR:
		/* A referenced dynptr tracks its reference as the parent. */
		if (!reg->dynptr.first_slot || reg->dynptr.type != BPF_DYNPTR_TYPE_RINGBUF ||
		    reg->parent_id != id)
			return -ENOENT;
		return fdesc_res_of_dynptr(env, reg);
	case STACK_ITER:
		/* The first slot of an iterator carries its reference id. */
		if (reg->id != id)
			return -ENOENT;
		return fdesc_res_of_iter(env, reg);
	default:
		return -ENOENT;
	}
}

static bool fdesc_res_is_lock(const struct bpf_fdesc_res *res)
{
	return res->kind == BPF_FDESC_SPIN_LOCK || res->kind == BPF_FDESC_RES_LOCK ||
	       res->kind == BPF_FDESC_RES_LOCK_IRQ;
}

static u8 fdesc_lock_kind(enum ref_state_type type)
{
	switch (type) {
	case REF_TYPE_LOCK:
		return BPF_FDESC_SPIN_LOCK;
	case REF_TYPE_RES_LOCK:
		return BPF_FDESC_RES_LOCK;
	default:
		return BPF_FDESC_RES_LOCK_IRQ;
	}
}

/* Offset of the lock of kind @kind in the object @rec describes. */
static int fdesc_lock_off(const struct btf_record *rec, u8 kind)
{
	if (kind == BPF_FDESC_SPIN_LOCK)
		return btf_record_has_field(rec, BPF_SPIN_LOCK) ? rec->spin_lock_off : -ENOENT;
	return btf_record_has_field(rec, BPF_RES_SPIN_LOCK) ? rec->res_spin_lock_off : -ENOENT;
}

/*
 * Does @reg point into the object whose lock @ref holds? Any constant offset
 * will do: the lock is found from the pointer value by a fixed delta.
 */
static bool fdesc_reg_is_lock(const struct bpf_reg_state *reg,
			      const struct bpf_reference_state *ref)
{
	if (reg->type == NOT_INIT || reg->type == SCALAR_VALUE || reg->id != ref->id ||
	    !tnum_is_const(reg->var_off))
		return false;
	if (reg->type == PTR_TO_MAP_VALUE)
		return reg->map_ptr == ref->ptr;
	return base_type(reg->type) == PTR_TO_BTF_ID && (type_flag(reg->type) & MEM_ALLOC) &&
	       reg->btf == ref->ptr;
}

/* The class of a lock of kind @kind reached from the pointer in @reg. */
static int fdesc_res_of_lock(struct bpf_verifier_env *env, const struct bpf_reg_state *reg, u8 kind)
{
	const struct btf_record *rec;
	struct bpf_fdesc_res res;
	s64 delta;
	int off;

	if (reg->type == PTR_TO_MAP_VALUE) {
		rec = reg->map_ptr->record;
	} else {
		struct btf_struct_meta *meta = btf_find_struct_meta(reg->btf, reg->btf_id);

		rec = meta ? meta->record : NULL;
	}
	off = fdesc_lock_off(rec, kind);
	if (off < 0)
		return off;
	delta = off - (s64)reg->var_off.value;
	if (delta != (s16)delta)
		return -ERANGE;
	memset(&res, 0, sizeof(res));
	res.kind = kind;
	res.delta = delta;
	return fdesc_res_intern(env, &res);
}

/*
 * A lock in the value of a single element array map, that is in a global
 * variable, has a fixed address: no location of the program needs to point at
 * it. The verifier tracks such a lock without an id; a lock without an id in
 * any other map cannot be told from the locks of the other elements.
 */
static int fdesc_res_of_global_lock(struct bpf_verifier_env *env,
				    const struct bpf_reference_state *ref, u8 kind)
{
	struct bpf_map *map = NULL;
	struct bpf_fdesc_res res;
	u64 addr;
	int i, off;

	for (i = 0; i < env->used_map_cnt; i++)
		if (env->used_maps[i] == ref->ptr)
			map = env->used_maps[i];
	if (!map || map->map_type != BPF_MAP_TYPE_ARRAY || map->max_entries != 1 ||
	    !map->ops->map_direct_value_addr) {
		verbose(env, "frame_desc: cannot tell which element holds the lock acquired at insn %d\n",
			ref->insn_idx);
		return -EINVAL;
	}
	off = fdesc_lock_off(map->record, kind);
	if (off < 0 || map->ops->map_direct_value_addr(map, &addr, off))
		return -EINVAL;
	memset(&res, 0, sizeof(res));
	res.kind = kind;
	res.addr = (void *)(long)(addr + off);
	return fdesc_res_intern(env, &res);
}

static void fdesc_verbose_cand(struct bpf_verifier_env *env, const struct fdesc_cand *c)
{
	if (c->is_slot)
		verbose(env, "frame%d fp%d", c->frameno, -(c->idx + 1) * BPF_REG_SIZE);
	else
		verbose(env, "frame%d R%d", c->frameno, c->idx);
}

/*
 * Rank a candidate location that no earlier path lists: a location another
 * path left NULL merges best, then a stack slot or a callee-saved register,
 * which outlive calls, before a caller-saved register. Lower is better.
 */
static int fdesc_cand_rank(const struct fdesc_cand *c, const struct bpf_fdesc_loc *loc)
{
	int rank = loc->state == FDESC_LOC_NULL ? 0 : 4;

	if (c->is_slot)
		return rank;
	return rank + (c->idx >= BPF_REG_6 ? 1 : 2);
}

/*
 * Choose where reference @ref is released from, given its candidate locations
 * on this path and what earlier paths put into the descriptors. A location
 * that an earlier path already lists must be reused, so that the reference is
 * never listed twice on a path; otherwise prefer a location no earlier path
 * has put a resource or a copy into, by rank and then outermost frame first.
 */
static int fdesc_choose(struct bpf_verifier_env *env, struct fdesc_scratch *s,
			const struct bpf_reference_state *ref, int nr)
{
	int i, chosen = -1, fallback = -1, fallback_rank = INT_MAX;

	for (i = 0; i < nr; i++) {
		const struct fdesc_cand *c = &s->cands[i];
		struct bpf_fdesc_build *b = s->builds[c->frameno];
		struct bpf_fdesc_loc *loc = c->is_slot ? &b->slots[c->idx] : &b->regs[c->idx];

		if (loc->state == FDESC_LOC_RES) {
			if (chosen >= 0) {
				verbose(env, "frame_desc: reference id=%d is listed at ", ref->id);
				fdesc_verbose_cand(env, &s->cands[chosen]);
				verbose(env, " and at ");
				fdesc_verbose_cand(env, c);
				verbose(env, " on different paths\n");
				return -EINVAL;
			}
			if (loc->res != c->res) {
				verbose(env, "frame_desc: ");
				fdesc_verbose_cand(env, c);
				verbose(env, " holds a different resource on another path\n");
				return -EINVAL;
			}
			chosen = i;
		} else if (loc->state == FDESC_LOC_UNSEEN || loc->state == FDESC_LOC_NULL) {
			int rank = fdesc_cand_rank(c, loc);

			if (rank < fallback_rank) {
				fallback = i;
				fallback_rank = rank;
			}
		}
	}
	if (chosen >= 0)
		return chosen;
	if (fallback >= 0)
		return fallback;
	verbose(env, "frame_desc: no location to release reference id=%d (acquired at insn %d) from\n",
		ref->id, ref->insn_idx);
	return -EINVAL;
}

/* Merge one path's classification of a location into the descriptor. */
static int fdesc_merge(struct bpf_fdesc_loc *loc, int class, u16 res)
{
	switch (loc->state) {
	case FDESC_LOC_UNSEEN:
	case FDESC_LOC_NULL:
		switch (class) {
		case FDESC_CLASS_RES:
			loc->nullable = loc->state == FDESC_LOC_NULL;
			loc->state = FDESC_LOC_RES;
			loc->res = res;
			break;
		case FDESC_CLASS_NULL:
			loc->state = FDESC_LOC_NULL;
			break;
		case FDESC_CLASS_COPY:
			loc->state = FDESC_LOC_COPY;
			break;
		default:
			loc->state = FDESC_LOC_OTHER;
		}
		return 0;
	case FDESC_LOC_RES:
		switch (class) {
		case FDESC_CLASS_RES:
			/* fdesc_choose() reuses a listed location only for the same class. */
			return 0;
		case FDESC_CLASS_NULL:
			loc->nullable = 1;
			return 0;
		default:
			return -EINVAL;
		}
	default:
		/* fdesc_choose() never lists a location an earlier path used otherwise. */
		return class == FDESC_CLASS_RES ? -EINVAL : 0;
	}
}

/* Release order: latest acquired lock or IRQ flag first, sections, then objects. */
static int fdesc_ent_cmp(const void *a, const void *b)
{
	const struct bpf_fdesc_ent *x = a, *y = b;

	if (x->order != y->order)
		return y->order - x->order;
	if (x->loc != y->loc)
		return x->loc - y->loc;
	if (x->off != y->off)
		return x->off - y->off;
	return x->res - y->res;
}

/*
 * Lay out the entries of one descriptor: every listed location of the frame
 * and the locks, IRQ flags and sections it holds.
 */
static u32 fdesc_build_body(const struct bpf_fdesc_build *b, struct bpf_fdesc *d)
{
	u32 n = 0, i;

	for (i = 0; i < BPF_REG_10 + b->nr_slots; i++) {
		const struct bpf_fdesc_loc *loc = i < BPF_REG_10 ? &b->regs[i] :
								   &b->slots[i - BPF_REG_10];
		struct bpf_fdesc_ent *ent;

		if (loc->state != FDESC_LOC_RES)
			continue;
		if (!d) {
			n++;
			continue;
		}
		ent = &d->ent[n++];
		ent->loc = i < BPF_REG_10 ? BPF_FDESC_LOC_REG : BPF_FDESC_LOC_STACK;
		ent->off = i < BPF_REG_10 ? i : -(i - BPF_REG_10 + 1) * BPF_REG_SIZE;
		ent->flags = loc->nullable ? BPF_FDESC_F_NULLABLE : 0;
		ent->res = loc->res;
		ent->order = -2;
	}
	if (d) {
		for (i = 0; i < b->nr_fixed; i++)
			d->ent[n++] = b->fixed[i];
		d->nent = n;
		d->size = struct_size(d, ent, n);
		sort(d->ent, n, sizeof(d->ent[0]), fdesc_ent_cmp, NULL);
	} else {
		n += b->nr_fixed;
	}
	return n;
}

/* Add the descriptor of @b to the pool, sharing an identical earlier one. */
static int fdesc_pool_add(struct bpf_verifier_env *env, const struct bpf_fdesc_build *b)
{
	struct bpf_fdesc_pool *pool = env->fdesc_pool;
	struct bpf_fdesc *d;
	u32 i, n = fdesc_build_body(b, NULL);

	d = kvzalloc(struct_size(d, ent, n), GFP_KERNEL_ACCOUNT);
	if (!d)
		return -ENOMEM;
	fdesc_build_body(b, d);
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
	env->fdesc_pool = pool;
	pool->desc[pool->cnt] = d;
	env->fdesc_bytes += d->size;
	return pool->cnt++;
}

/*
 * After all instruction rewrites, turn the descriptors attached to instructions
 * into the per subprogram tables the unwinder uses, keyed by instruction index
 * until the JIT fills in native offsets. Identical descriptors share a body.
 */
int bpf_fdesc_build_tables(struct bpf_verifier_env *env)
{
	struct bpf_insn_aux_data *aux = env->insn_aux_data;
	struct bpf_fdesc_pool *pool;
	int i, s, ret;

	if (!env->fdesc_visits)
		return 0;
	pool = kvzalloc(struct_size(pool, desc, 0), GFP_KERNEL_ACCOUNT);
	if (!pool)
		return -ENOMEM;
	env->fdesc_pool = pool;
	for (s = 0; s < env->subprog_cnt; s++) {
		u32 start = env->subprog_info[s].start, end = env->subprog_info[s + 1].start;
		struct bpf_fdesc_tab *tab;
		u32 cnt = 0;

		for (i = start; i < end; i++)
			cnt += aux[i].fdesc && !aux[i].fdesc->fallback && !aux[i].fdesc->conflict;
		if (!cnt)
			continue;
		tab = kvzalloc(struct_size(tab, pc, cnt), GFP_KERNEL_ACCOUNT);
		if (!tab)
			return -ENOMEM;
		env->subprog_info[s].fdesc_tab = tab;
		env->fdesc_bytes += struct_size(tab, pc, cnt);
		for (i = start; i < end; i++) {
			if (!aux[i].fdesc || aux[i].fdesc->fallback || aux[i].fdesc->conflict)
				continue;
			if (verifier_bug_if(env->prog->insnsi[i].code != (BPF_JMP | BPF_CALL), env,
					    "frame descriptor at insn %d is not at a call", i))
				return -EFAULT;
			ret = fdesc_pool_add(env, aux[i].fdesc);
			if (ret < 0)
				return ret;
			tab->pc[tab->cnt++] = (struct bpf_fdesc_pc) { .off = i - start, .desc = ret };
			env->fdesc_sites++;
		}
	}
	env->fdesc_pool->res = env->fdesc_res;
	env->fdesc_pool->res_cnt = env->fdesc_res_cnt;
	env->fdesc_bytes += env->fdesc_res_cnt * sizeof(*env->fdesc_res);
	env->fdesc_res = NULL;
	/* A program without BPF-to-BPF calls is JITed whole: hand it the main table. */
	if (env->subprog_cnt == 1) {
		env->prog->aux->fdesc_tab = env->subprog_info[0].fdesc_tab;
		env->subprog_info[0].fdesc_tab = NULL;
	}
	return 0;
}

/*
 * The tables key sites by instruction index until the JIT fills them. A patch
 * of @len insns at @off after they were built, which only constant blinding
 * does, moves the sites of that subprog behind the patch, and the patched
 * instruction's own site with it, as its aux data moves to the end of the
 * patch. @prog is the patched program; the one the env still points at may
 * have been freed by the patch.
 */
void bpf_fdesc_adjust_tables(struct bpf_verifier_env *env, struct bpf_prog *prog, u32 off,
			     u32 len)
{
	int s = fdesc_insn_subprog(env, off);
	struct bpf_fdesc_tab *tab;
	u32 i, rel;

	if (len == 1 || s < 0)
		return;
	tab = env->subprog_cnt == 1 ? prog->aux->fdesc_tab : env->subprog_info[s].fdesc_tab;
	if (!tab || tab->filled)
		return;
	rel = off - env->subprog_info[s].start;
	for (i = 0; i < tab->cnt; i++)
		if (tab->pc[i].off >= rel)
			tab->pc[i].off += len - 1;
}

/*
 * Release the resource an entry describes, at run time. Not inlined so that
 * every release of an unwind can be observed by attaching to this function.
 */
noinline void bpf_fdesc_release(const struct bpf_fdesc_res *res, void *loc, void *flags)
{
	void *obj;

	switch (res->kind) {
	case BPF_FDESC_DYNPTR_RINGBUF:
		bpf_ringbuf_discard_dynptr_proto.func((u64)(long)loc, 0, 0, 0, 0);
		return;
	case BPF_FDESC_ITER:
		res->dtor(loc);
		return;
	case BPF_FDESC_IRQ_FLAG:
		bpf_local_irq_restore(loc);
		return;
	case BPF_FDESC_IRQ_FLAG_LOCK:
		/* Restored together with the lock that saved it. */
		return;
	case BPF_FDESC_RCU:
		bpf_rcu_read_unlock();
		return;
	case BPF_FDESC_PREEMPT:
		bpf_preempt_enable();
		return;
	case BPF_FDESC_SPIN_LOCK:
	case BPF_FDESC_RES_LOCK:
	case BPF_FDESC_RES_LOCK_IRQ:
		obj = loc ? *(void **)loc + res->delta : res->addr;
		if (res->kind == BPF_FDESC_SPIN_LOCK)
			bpf_spin_unlock_proto.func((u64)(long)obj, 0, 0, 0, 0);
		else if (res->kind == BPF_FDESC_RES_LOCK)
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
	case BPF_FDESC_OBJ:
		bpf_obj_drop_impl(obj, res->meta);
		break;
	case BPF_FDESC_PERCPU_OBJ:
		bpf_percpu_obj_drop_impl(obj, res->meta);
		break;
	case BPF_FDESC_KPTR:
		res->dtor(obj);
		break;
#ifdef CONFIG_INET
	case BPF_FDESC_SOCK:
		bpf_sk_release_proto.func((u64)(long)obj, 0, 0, 0, 0);
		break;
#endif
	case BPF_FDESC_RINGBUF:
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
void bpf_fdesc_unwind_frame(const struct bpf_prog *prog, unsigned long pc, u64 fp,
			    const struct bpf_throw_regs *regs, const u64 *callee_regs)
{
	const struct bpf_fdesc_pool *pool = prog->aux->fdesc_pool;
	const struct bpf_fdesc *d;
	void *flags = NULL;
	u32 i;

	if (!prog->aux->fdesc_tab)
		return;
	d = bpf_prog_fdesc_lookup(prog, pc);
	if (WARN_ONCE(!d, "bpf: no frame descriptor for %s at %lx\n", prog->aux->name, pc))
		return;
	for (i = 0; i < d->nent; i++) {
		const struct bpf_fdesc_ent *ent = &d->ent[i];
		const struct bpf_fdesc_res *res = &pool->res[ent->res];
		void *loc;
		u64 reg;
		int n;

		if (ent->loc == BPF_FDESC_LOC_NONE) {
			for (n = ent->off; n; n--)
				bpf_fdesc_release(res, NULL, flags);
			if (res->kind == BPF_FDESC_RES_LOCK_IRQ)
				flags = NULL;
			continue;
		}
		if (ent->loc == BPF_FDESC_LOC_STACK) {
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
		if (res->kind == BPF_FDESC_IRQ_FLAG_LOCK)
			flags = loc;
		bpf_fdesc_release(res, loc, flags);
		if (res->kind == BPF_FDESC_RES_LOCK_IRQ)
			flags = NULL;
	}
}

/* Is the site one the kernel chose, which falls back when it cannot be described? */
static bool fdesc_site_implicit(u8 site)
{
	return site == BPF_FDESC_SITE_MAY_GOTO || site == BPF_FDESC_SITE_GLOBAL;
}

/* Is the site a call to a global subprog, where the frame keeps only R6-R9? */
static bool fdesc_site_is_call(u8 site)
{
	return site == BPF_FDESC_SITE_CALL || site == BPF_FDESC_SITE_GLOBAL;
}

/* Append a lock, IRQ flag or section entry of frame @f on this path. */
static int fdesc_fixed_add(struct bpf_verifier_env *env, struct fdesc_scratch *s, int f,
			   struct bpf_fdesc_ent ent)
{
	if (s->nr_fixed[f] >= FDESC_MAX_FIXED) {
		verbose(env, "frame_desc: frame%d holds too many locks and sections\n", f);
		return -E2BIG;
	}
	s->fixed[f][s->nr_fixed[f]++] = ent;
	return 0;
}

/* The entry an earlier path listed for the lock or IRQ flag of rank @order, and its frame. */
static const struct bpf_fdesc_ent *fdesc_fixed_find(struct fdesc_scratch *s, int curframe,
						    s16 order, int *frame)
{
	int f, i;

	for (f = 0; f <= curframe; f++) {
		struct bpf_fdesc_build *b = s->builds[f];

		for (i = 0; i < b->nr_fixed; i++) {
			if (b->fixed[i].order == order) {
				*frame = f;
				return &b->fixed[i];
			}
		}
	}
	return NULL;
}

/*
 * Place a held lock: at its fixed address when it has one, else at a live
 * location holding a pointer into its object. An earlier path's choice must
 * be reused, as the entries have to agree. Locks are the innermost resources,
 * so prefer the innermost frame, then a stack slot or callee-saved register.
 */
static int fdesc_place_lock(struct bpf_verifier_env *env, struct fdesc_scratch *s,
			    const struct bpf_reference_state *ref, s16 order)
{
	struct bpf_verifier_state *st = env->cur_state;
	struct bpf_fdesc_ent ent = { .order = order };
	u8 kind = fdesc_lock_kind(ref->type);
	const struct bpf_fdesc_ent *prev;
	const struct fdesc_cand *c;
	int f, k, nr = 0, prev_frame, chosen = -1, best = INT_MAX, ret;

	if (!ref->id) {
		ret = fdesc_res_of_global_lock(env, ref, kind);
		if (ret < 0)
			return ret;
		ent.loc = BPF_FDESC_LOC_NONE;
		ent.off = 1;
		ent.res = ret;
		return fdesc_fixed_add(env, s, st->curframe, ent);
	}
	for (f = st->curframe; f >= 0; f--) {
		struct bpf_func_state *frame = st->frame[f];
		const unsigned long *live_stack = env->insn_aux_data[s->pcs[f]].live_stack_before;

		for (k = 0; k < BPF_REG_10; k++) {
			if (!(s->live_regs[f] & BIT(k)) || !fdesc_reg_is_lock(&frame->regs[k], ref))
				continue;
			ret = fdesc_res_of_lock(env, &frame->regs[k], kind);
			if (ret < 0)
				return ret;
			s->cands[nr++] = (struct fdesc_cand) { f, 0, k, ret };
		}
		for (k = 0; k < frame->allocated_stack / BPF_REG_SIZE; k++) {
			const struct bpf_stack_state *slot = bpf_stack_slot(frame, k);

			if (!test_bit(k, live_stack) || !bpf_is_spilled_reg(slot) ||
			    !fdesc_reg_is_lock(&slot->spilled_ptr, ref))
				continue;
			ret = fdesc_res_of_lock(env, &slot->spilled_ptr, kind);
			if (ret < 0)
				return ret;
			s->cands[nr++] = (struct fdesc_cand) { f, 1, k, ret };
		}
	}
	prev = fdesc_fixed_find(s, st->curframe, order, &prev_frame);
	for (k = 0; k < nr; k++) {
		int rank;

		c = &s->cands[k];
		if (prev) {
			if (c->frameno == prev_frame && c->res == prev->res &&
			    prev->loc == (c->is_slot ? BPF_FDESC_LOC_STACK : BPF_FDESC_LOC_REG) &&
			    prev->off == (c->is_slot ? -(c->idx + 1) * BPF_REG_SIZE : c->idx)) {
				chosen = k;
				break;
			}
			continue;
		}
		rank = (st->curframe - c->frameno) * 4;
		rank += c->is_slot ? 0 : c->idx >= BPF_REG_6 ? 1 : 2;
		if (rank < best) {
			best = rank;
			chosen = k;
		}
	}
	if (chosen < 0) {
		verbose(env, "frame_desc: %s to release the lock acquired at insn %d from\n",
			prev ? "another path uses a different location" : "no location",
			ref->insn_idx);
		return -EINVAL;
	}
	c = &s->cands[chosen];
	ent.loc = c->is_slot ? BPF_FDESC_LOC_STACK : BPF_FDESC_LOC_REG;
	ent.off = c->is_slot ? -(c->idx + 1) * BPF_REG_SIZE : c->idx;
	ent.res = c->res;
	return fdesc_fixed_add(env, s, c->frameno, ent);
}

/*
 * Place saved IRQ flags: the stack slot they live in. The flags of an irqsave
 * lock are restored by the lock, so they must sit in the lock's frame.
 */
static int fdesc_place_irq(struct bpf_verifier_env *env, struct fdesc_scratch *s,
			   const struct bpf_reference_state *ref, s16 order)
{
	struct bpf_verifier_state *st = env->cur_state;
	struct bpf_fdesc_ent ent = { .order = order, .loc = BPF_FDESC_LOC_STACK };
	struct bpf_fdesc_res res;
	int f, k, ret;

	for (f = st->curframe; f >= 0; f--) {
		struct bpf_func_state *frame = st->frame[f];
		const unsigned long *live_stack = env->insn_aux_data[s->pcs[f]].live_stack_before;

		for (k = 0; k < frame->allocated_stack / BPF_REG_SIZE; k++) {
			const struct bpf_stack_state *slot = bpf_stack_slot(frame, k);
			bool lock = slot->spilled_ptr.irq.kfunc_class == IRQ_LOCK_KFUNC;

			if (slot->slot_type[BPF_REG_SIZE - 1] != STACK_IRQ_FLAG ||
			    slot->spilled_ptr.id != ref->id)
				continue;
			if (!test_bit(k, live_stack)) {
				verbose(env, "frame_desc: the irq flags saved at insn %d are dead\n",
					ref->insn_idx);
				return -EINVAL;
			}
			if (lock && (!s->nr_fixed[f] ||
				     s->fixed[f][s->nr_fixed[f] - 1].order != order - 1)) {
				verbose(env, "frame_desc: the lock of the irq flags saved at insn %d is not in their frame\n",
					ref->insn_idx);
				return -EINVAL;
			}
			memset(&res, 0, sizeof(res));
			res.kind = lock ? BPF_FDESC_IRQ_FLAG_LOCK : BPF_FDESC_IRQ_FLAG;
			ret = fdesc_res_intern(env, &res);
			if (ret < 0)
				return ret;
			ent.off = -(k + 1) * BPF_REG_SIZE;
			ent.res = ret;
			return fdesc_fixed_add(env, s, f, ent);
		}
	}
	verbose(env, "frame_desc: no stack slot holds the irq flags saved at insn %d\n", ref->insn_idx);
	return -EINVAL;
}

/* Sections have no location; the frame that entered them leaves them. */
static int fdesc_place_section(struct bpf_verifier_env *env, struct fdesc_scratch *s, int f,
			       u8 kind, u32 count)
{
	struct bpf_fdesc_ent ent = { .order = -1, .loc = BPF_FDESC_LOC_NONE };
	struct bpf_fdesc_res res;
	int ret;

	if (!count)
		return 0;
	if (count > S16_MAX) {
		verbose(env, "frame_desc: frame%d is in too many nested sections\n", f);
		return -E2BIG;
	}
	memset(&res, 0, sizeof(res));
	res.kind = kind;
	ret = fdesc_res_intern(env, &res);
	if (ret < 0)
		return ret;
	ent.off = count;
	ent.res = ret;
	return fdesc_fixed_add(env, s, f, ent);
}

/*
 * Place the locks, IRQ flags and sections held on this path. Unlike objects,
 * these are released in order: the verifier keeps locks and IRQ flags in
 * acquisition order, and the unwinder releases inner frames first, so the
 * ranks placed in a frame must all follow those of its callers. Every path
 * must place exactly the same entries in every frame.
 */
static int fdesc_place_fixed(struct bpf_verifier_env *env, struct fdesc_scratch *s)
{
	struct bpf_verifier_state *st = env->cur_state;
	int i, f, k, order = 0, last = -1, ret;

	memset(s->nr_fixed, 0, sizeof(s->nr_fixed));
	for (i = 0; i < st->acquired_refs; i++) {
		const struct bpf_reference_state *ref = &st->refs[i];

		if (ref->type & REF_TYPE_LOCK_MASK)
			ret = fdesc_place_lock(env, s, ref, order++);
		else if (ref->type == REF_TYPE_IRQ)
			ret = fdesc_place_irq(env, s, ref, order++);
		else
			continue;
		if (ret)
			return ret;
	}
	for (f = 0; f <= st->curframe; f++) {
		ret = fdesc_place_section(env, s, f, BPF_FDESC_RCU, st->frame[f]->rcu_locks);
		ret = ret ?: fdesc_place_section(env, s, f, BPF_FDESC_PREEMPT,
						 st->frame[f]->preempt_locks);
		if (ret)
			return ret;
	}

	for (f = 0; f <= st->curframe; f++) {
		struct bpf_fdesc_build *b = s->builds[f];
		size_t sz = s->nr_fixed[f] * sizeof(s->fixed[f][0]);

		sort(s->fixed[f], s->nr_fixed[f], sizeof(s->fixed[f][0]), fdesc_ent_cmp, NULL);
		/* Sorted latest first: the last ranked entry has the lowest rank. */
		for (k = s->nr_fixed[f] - 1; k >= 0; k--) {
			if (s->fixed[f][k].order < 0)
				continue;
			if (s->fixed[f][k].order <= last) {
				verbose(env, "frame_desc: frame%d insn %d: holds a lock or irq flags acquired before a caller's\n",
					f, s->pcs[f]);
				return -EINVAL;
			}
			last = s->fixed[f][0].order;
			break;
		}
		if (!b->visits) {
			/* A visit that failed in a later frame may have placed these already. */
			kvfree(b->fixed);
			b->fixed = sz ? kvmemdup(s->fixed[f], sz, GFP_KERNEL_ACCOUNT) : NULL;
			if (sz && !b->fixed)
				return -ENOMEM;
			b->nr_fixed = s->nr_fixed[f];
		} else if (b->nr_fixed != s->nr_fixed[f] ||
			   (sz && memcmp(b->fixed, s->fixed[f], sz))) {
			verbose(env, "frame_desc: frame%d insn %d: holds different locks or sections on another path\n",
				f, s->pcs[f]);
			return -EINVAL;
		}
	}
	return 0;
}

/*
 * Record the state at a site where the program may be unwound. @site says
 * which registers of the innermost frame the unwinder can see: at a
 * bpf_throw() call the entry stub saves R0-R9, while a frame waiting in a
 * call only keeps R6-R9 and its stack. Only live locations are considered,
 * which keeps the descriptors consistent with state pruning: two states the
 * verifier treats as equivalent agree on every live location.
 */
static int fdesc_site_do(struct bpf_verifier_env *env, enum bpf_fdesc_site site)
{
	struct bpf_verifier_state *st = env->cur_state;
	struct fdesc_scratch *s = env->fdesc_scratch;
	int f, i, k, nr, held, ret;

	if (!s) {
		s = kvzalloc_obj(*s, GFP_KERNEL_ACCOUNT);
		if (!s)
			return -ENOMEM;
		env->fdesc_scratch = s;
	}
	env->fdesc_visits++;
	s->obj_frames = 0;
	s->sleep_frames = 0;

	for (f = 0; f <= st->curframe; f++) {
		struct bpf_func_state *frame = st->frame[f];
		u32 nr_slots = frame->allocated_stack / BPF_REG_SIZE;

		s->pcs[f] = f == st->curframe ? env->insn_idx : st->frame[f + 1]->callsite;
		s->builds[f] = fdesc_build_get(env, s->pcs[f], nr_slots);
		if (!s->builds[f])
			return -ENOMEM;
		memset(s->class[f], 0, BPF_REG_10 + nr_slots);
		s->live_regs[f] = env->insn_aux_data[s->pcs[f]].live_regs_before;
		if (f != st->curframe || fdesc_site_is_call(site))
			s->live_regs[f] &= FDESC_REGS_CALLEE_SAVED;
		if (!s->builds[f]->site)
			s->builds[f]->site = f == st->curframe ? site : BPF_FDESC_SITE_CALLER;
	}
	for (f = 0; f < st->curframe; f++) {
		ret = fdesc_add_caller(s->builds[st->curframe], s->builds[f]);
		if (ret)
			return ret;
	}

	/* Place every reference at one live location. */
	for (i = 0; i < st->acquired_refs; i++) {
		const struct bpf_reference_state *ref = &st->refs[i];
		int chosen;

		if (ref->type != REF_TYPE_PTR)
			continue;
		nr = 0;
		for (f = 0; f <= st->curframe; f++) {
			struct bpf_func_state *frame = st->frame[f];
			const unsigned long *live_stack = env->insn_aux_data[s->pcs[f]].live_stack_before;

			for (k = 0; k < BPF_REG_10; k++) {
				if (!(s->live_regs[f] & BIT(k)) || !fdesc_reg_is_ref(&frame->regs[k], ref->id))
					continue;
				ret = fdesc_res_of_reg(env, &frame->regs[k]);
				if (ret < 0)
					return ret;
				s->cands[nr++] = (struct fdesc_cand) { f, 0, k, ret };
			}
			/* Only the slots this state allocated hold anything. */
			for (k = 0; k < frame->allocated_stack / BPF_REG_SIZE; k++) {
				if (!test_bit(k, live_stack))
					continue;
				ret = fdesc_slot_ref(env, bpf_stack_slot(frame, k), ref->id);
				if (ret == -ENOENT)
					continue;
				if (ret < 0)
					return ret;
				s->cands[nr++] = (struct fdesc_cand) { f, 1, k, ret };
			}
		}
		chosen = fdesc_choose(env, s, ref, nr);
		if (chosen < 0) {
			env->fdesc_conflicts++;
			return chosen;
		}
		for (k = 0; k < nr; k++) {
			const struct fdesc_cand *c = &s->cands[k];
			int idx = c->is_slot ? BPF_REG_10 + c->idx : c->idx;

			s->class[c->frameno][idx] = k == chosen ? FDESC_CLASS_RES : FDESC_CLASS_COPY;
			s->res[c->frameno][idx] = c->res;
		}
		s->obj_frames |= BIT(s->cands[chosen].frameno);
		if (env->fdesc_res[s->cands[chosen].res].sleeps)
			s->sleep_frames |= BIT(s->cands[chosen].frameno);
	}

	ret = fdesc_place_fixed(env, s);
	if (ret) {
		env->fdesc_conflicts++;
		return ret;
	}
	/*
	 * The objects of a frame are released after its own locks and sections,
	 * but while the frames above still hold theirs. A caller's lock forbids
	 * any release, as the program could call none there; a caller's
	 * section or IRQ flags forbid a destructor that sleeps.
	 */
	for (f = 1, held = 0; f <= st->curframe; f++) {
		for (k = 0; k < s->nr_fixed[f - 1]; k++)
			held |= fdesc_res_is_lock(&env->fdesc_res[s->fixed[f - 1][k].res]) ? 2 : 1;
		if (!((held & 2 ? s->obj_frames : s->sleep_frames) & BIT(f)))
			continue;
		verbose(env, "frame_desc: frame%d insn %d: holds an object that cannot be released under what a caller holds\n",
			f, s->pcs[f]);
		env->fdesc_conflicts++;
		return -EINVAL;
	}

	/* Classify the remaining live locations and merge every frame. */
	for (f = 0; f <= st->curframe; f++) {
		struct bpf_func_state *frame = st->frame[f];
		struct bpf_fdesc_build *b = s->builds[f];
		const unsigned long *live_stack = env->insn_aux_data[s->pcs[f]].live_stack_before;
		int loc;

		for (loc = 0; loc < BPF_REG_10 + b->nr_slots; loc++) {
			struct bpf_fdesc_loc *dst;

			if (loc < BPF_REG_10) {
				if (!(s->live_regs[f] & BIT(loc)))
					continue;
				if (!s->class[f][loc] && bpf_register_is_null(&frame->regs[loc]))
					s->class[f][loc] = FDESC_CLASS_NULL;
				dst = &b->regs[loc];
			} else {
				k = loc - BPF_REG_10;
				if (!test_bit(k, live_stack))
					continue;
				/* A live slot this state has not allocated holds anything. */
				if (!s->class[f][loc] && k < frame->allocated_stack / BPF_REG_SIZE &&
				    fdesc_slot_is_null(bpf_stack_slot(frame, k)))
					s->class[f][loc] = FDESC_CLASS_NULL;
				dst = &b->slots[k];
			}
			ret = fdesc_merge(dst, s->class[f][loc], s->res[f][loc]);
			if (ret) {
				b->conflict = true;
				env->fdesc_conflicts++;
				verbose(env, "frame_desc: frame%d insn %d: ", f, s->pcs[f]);
				if (loc < BPF_REG_10)
					verbose(env, "R%d", loc);
				else
					verbose(env, "fp%d", -(k + 1) * BPF_REG_SIZE);
				verbose(env, " holds a resource on one path and something else on another\n");
				return ret;
			}
		}
		b->visits++;
	}
	return 0;
}

/* Is the program below a callback? It runs under a kernel frame the unwinder would have to skip. */
static bool fdesc_site_masked(struct bpf_verifier_env *env)
{
	struct bpf_verifier_state *st = env->cur_state;
	int f;

	for (f = 0; f <= st->curframe; f++) {
		struct bpf_func_state *frame = st->frame[f];

		if (frame->in_callback_fn || frame->in_async_callback_fn ||
		    frame->in_exception_callback_fn)
			return true;
	}
	return false;
}

/*
 * Describe the state at a site where the program may be unwound. A site the
 * program asked for, bpf_throw() or a call to a global subprog that may
 * throw, must be describable or the program is rejected. An implicit site,
 * which the kernel would use to cancel the program, falls back to its
 * ordinary semantics instead.
 */
int bpf_fdesc_site(struct bpf_verifier_env *env, enum bpf_fdesc_site site)
{
	bool implicit = fdesc_site_implicit(site);
	struct fdesc_scratch *s;
	int ret;

	if (env->cur_state->speculative)
		return 0;
	if (implicit && !env->cancellable)
		return 0;
	if (fdesc_site_masked(env)) {
		/* A throw below a callback is rejected once the call graph is checked. */
		if (implicit)
			env->fdesc_masked++;
		return 0;
	}
	ret = fdesc_site_do(env, site);
	if (!ret || ret == -ENOMEM || !implicit)
		return ret;
	s = env->fdesc_scratch;
	s->builds[env->cur_state->curframe]->fallback = true;
	env->fdesc_fallbacks++;
	return 0;
}

/*
 * After verification, decide which sites the unwinder may be entered from. A
 * frame whose descriptor conflicts cannot be unwound through, which takes
 * every site reached under it with it: an explicit site then rejects the
 * program, an implicit site falls back. A program keeping an implicit site
 * needs the exception boundary the throw path relies on.
 *
 * A global subprog is verified on its own, so its sites know nothing of its
 * callers: each call to it is a site in the caller, and the frames of a
 * global subprog, or of anything it calls, can only be unwound when every
 * call to it can be. A site below a callback can never be: a kernel frame
 * sits between it and the exception boundary.
 */
/* Can the unwinder enter at the site of @b and get through every frame above it? */
static bool fdesc_build_valid(struct bpf_verifier_env *env, const struct bpf_fdesc_build *b)
{
	const struct bpf_subprog_info *subprog = env->subprog_info;
	int c;

	if (b->conflict || subprog[fdesc_insn_subprog(env, b->pc)].cancel_fallback)
		return false;
	for (c = 0; c < b->nr_callers; c++) {
		const struct bpf_fdesc_build *caller = b->callers[c];

		if (caller->conflict || subprog[fdesc_insn_subprog(env, caller->pc)].cancel_fallback)
			return false;
	}
	return true;
}

int bpf_fdesc_resolve(struct bpf_verifier_env *env)
{
	struct bpf_insn_aux_data *aux = env->insn_aux_data;
	struct bpf_subprog_info *subprog = env->subprog_info;
	bool changed;
	int i;

	for (i = 0; i < env->prog->len; i++) {
		struct bpf_fdesc_build *b = aux[i].fdesc;

		if (!b || !fdesc_site_implicit(b->site) || b->fallback ||
		    !subprog[fdesc_insn_subprog(env, i)].below_cb)
			continue;
		b->fallback = true;
		env->fdesc_masked++;
	}
	do {
		changed = false;
		for (i = 0; i < env->prog->len; i++) {
			struct bpf_fdesc_build *b = aux[i].fdesc;
			const struct bpf_insn *insn = &env->prog->insnsi[i];
			int callee;

			if (!b || !fdesc_site_is_call(b->site))
				continue;
			callee = bpf_find_subprog(env, i + insn->imm + 1);
			if (subprog[callee].cancel_fallback || (!b->fallback && fdesc_build_valid(env, b)))
				continue;
			subprog[callee].cancel_fallback = true;
			changed = true;
		}
	} while (changed);
	for (i = 0; i < env->prog->len; i++) {
		struct bpf_fdesc_build *b = aux[i].fdesc;
		bool valid;

		if (!b || b->site == BPF_FDESC_SITE_CALLER || b->fallback)
			continue;
		valid = fdesc_build_valid(env, b);
		if (valid) {
			if (fdesc_site_implicit(b->site))
				env->seen_exception = true;
			continue;
		}
		if (fdesc_site_implicit(b->site)) {
			b->fallback = true;
			env->fdesc_fallbacks++;
			continue;
		}
		verbose(env, "frame_desc: a caller of the throw at insn %d cannot be described\n", i);
		return -EINVAL;
	}
	return 0;
}

/*
 * An instruction rewrite moved a site's descriptor to insn @from together
 * with the rest of its aux data; the slow path call the unwinder sees the
 * site through is insn @to. A site that fell back keeps no descriptor.
 */
void bpf_fdesc_move_site(struct bpf_verifier_env *env, u32 from, u32 to)
{
	struct bpf_fdesc_build *b = env->insn_aux_data[from].fdesc;

	if (!b)
		return;
	env->insn_aux_data[from].fdesc = NULL;
	if (b->fallback || b->conflict) {
		fdesc_build_destroy(b);
		return;
	}
	env->insn_aux_data[to].fdesc = b;
}
