// SPDX-License-Identifier: GPL-2.0-only
/*
 * Frame descriptors: which registers and stack slots of each BPF frame hold
 * kernel resources at an instruction where the program may be unwound.
 *
 * The verifier calls bpf_frame_desc_site() at every such site with the state
 * the site is reached in. For the innermost frame the site is the instruction
 * itself; for every caller frame it is the call instruction the frame waits
 * in, since that is where the unwinder finds the frame's return address. One
 * descriptor is built per (subprog, insn) and merged over all paths reaching
 * it, so that the unwinder can release the resources of a frame from its
 * instruction pointer alone. A site that cannot be described rejects the
 * program.
 *
 * A reference acquired by a call is kept in a unique slot of the acquiring
 * frame, a hidden stack slot that the acquisition fills and every release
 * clears, so that it is listed in that frame on every path without the
 * verifier state having to agree on a location. Whether the slot can be kept
 * up to date is only known after verification, when every release of the
 * acquisition has been seen, so each reference is also placed at a live
 * location the paths agree on, which is what describes a reference whose
 * slot cannot be, and what describes iterators and dynptrs, which live in
 * stack slots of their own.
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
#define MAX_FIXED		32	/* locks, IRQ flags and sections a frame may hold */
/* Release ranks of the entries without an acquisition order, see entry_cmp(). */
#define ORDER_RCU_OBJ		-1
#define ORDER_SECTION		-2
#define ORDER_OBJ		-3

/* What the frames above a frame hold, which limits what the frame may release. */
#define HELD_SECTION		BIT(0)	/* an RCU or preemption section, or IRQ flags */
#define HELD_LOCK		BIT(1)

/* A candidate location of one reference on the current path. */
struct cand {
	u16 frameno;
	u16 is_slot;
	u16 idx;	/* register number or spi */
	u16 res;
};

/* Per-site working storage, allocated once per verification. */
struct scratch {
	struct cand cands[MAX_CALL_FRAMES * FRAME_LOCS];
	u8 class[MAX_CALL_FRAMES][FRAME_LOCS];
	u16 res[MAX_CALL_FRAMES][FRAME_LOCS];
	u32 acq[MAX_CALL_FRAMES][FRAME_LOCS];
	struct bpf_frame_desc_build *builds[MAX_CALL_FRAMES];
	u32 pcs[MAX_CALL_FRAMES];
	u32 live_regs[MAX_CALL_FRAMES];
	struct bpf_frame_desc_entry fixed[MAX_CALL_FRAMES][MAX_FIXED];
	u16 nr_fixed[MAX_CALL_FRAMES];
	u8 held_above[MAX_CALL_FRAMES];	/* HELD_* of the frames above each frame */
	bool in_section[MAX_CALL_FRAMES];	/* a section is held by the frame or one above */
	int first;	/* the outermost frame the unwinder reaches from this site */
};

/* Make room for @nr_slots stack slots in the descriptor of insn @pc, which @b is or NULL. */
static struct bpf_frame_desc_build *build_grow(struct bpf_verifier_env *env, u32 pc,
					       struct bpf_frame_desc_build *b, u32 nr_slots)
{
	u32 old = b ? b->nr_slots : 0;

	if (b && old >= nr_slots)
		return b;
	b = kvrealloc(b, struct_size(b, slots, nr_slots), GFP_KERNEL_ACCOUNT);
	if (!b)
		return NULL;
	if (!old)
		memset(b, 0, offsetof(struct bpf_frame_desc_build, slots));
	memset(&b->slots[old], 0, (nr_slots - old) * sizeof(b->slots[0]));
	b->pc = pc;
	b->nr_slots = nr_slots;
	env->insn_aux_data[pc].frame_desc = b;
	return b;
}

static struct bpf_frame_desc_build *build_get(struct bpf_verifier_env *env, u32 pc, u32 nr_slots)
{
	return build_grow(env, pc, env->insn_aux_data[pc].frame_desc, nr_slots);
}

static void build_destroy(struct bpf_frame_desc_build *b)
{
	if (!b)
		return;
	kvfree(b->fixed);
	kvfree(b->slot_acqs);
	kvfree(b->spills);
	kvfree(b);
}

void bpf_frame_desc_build_free(struct bpf_insn_aux_data *aux)
{
	build_destroy(aux->frame_desc);
	aux->frame_desc = NULL;
}

/* The subprog insn @idx belongs to. */
static int insn_subprog(struct bpf_verifier_env *env, u32 idx)
{
	int s;

	for (s = 0; s < env->subprog_cnt; s++)
		if (idx < env->subprog_info[s + 1].start)
			return s;
	return -1;
}

void bpf_frame_desc_env_free(struct bpf_verifier_env *env)
{
	kvfree(env->resources);
	kvfree(env->frame_desc_scratch);
	kvfree(env->ref_releases);
	env->resources = NULL;
	env->frame_desc_scratch = NULL;
	env->ref_releases = NULL;
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
 * Resolve the destructor of a referenced kernel object or an iterator through
 * the BTF destructor registry, and check that the program could have called
 * the matching release kfunc itself: that is the context in which running the
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

/* Classify a register or spilled register that holds a reference. */
static int resource_of_reg(struct bpf_verifier_env *env, const struct bpf_reg_state *reg)
{
	u32 flags = type_flag(reg->type) & ~PTR_MAYBE_NULL;
	struct bpf_resource res;
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
			res.kind = flags & MEM_PERCPU ? BPF_RESOURCE_PERCPU_OBJ : BPF_RESOURCE_OBJ;
			res.meta = btf_find_struct_meta(reg->btf, reg->btf_id);
			break;
		}
		if (flags & ~PTR_TRUSTED)
			goto unsupported;
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
	return resource_intern(env, &res);
unsupported:
	verbose(env, "frame_desc: cannot release a reference of type %s\n",
		reg_type_str(env, reg->type));
	return -EOPNOTSUPP;
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
	res.rcu = reg->type & MEM_RCU;
	if (res.rcu && res.sleeps) {
		verbose(env, "frame_desc: RCU-protected iterator has a sleepable destructor\n");
		return -EOPNOTSUPP;
	}
	return resource_intern(env, &res);
}

/*
 * Does @reg hold the object of reference @id itself? A pointer with the same
 * id but an offset points into the object and cannot be released.
 */
static bool reg_is_ref(const struct bpf_reg_state *reg, int id)
{
	return reg->type != SCALAR_VALUE && reg->type != NOT_INIT && reg->id == id &&
	       tnum_is_const(reg->var_off) && reg->var_off.value == 0;
}

static bool stack_slot_is_null(const struct bpf_stack_state *slot)
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
static int stack_slot_ref(struct bpf_verifier_env *env, const struct bpf_stack_state *slot, int id)
{
	const struct bpf_reg_state *reg = &slot->spilled_ptr;

	switch (slot->slot_type[BPF_REG_SIZE - 1]) {
	case STACK_SPILL:
		if (!bpf_is_spilled_reg(slot) || !reg_is_ref(reg, id))
			return -ENOENT;
		return resource_of_reg(env, reg);
	case STACK_DYNPTR:
		/* A referenced dynptr tracks its reference as the parent. */
		if (!reg->dynptr.first_slot || reg->dynptr.type != BPF_DYNPTR_TYPE_RINGBUF ||
		    reg->parent_id != id)
			return -ENOENT;
		return resource_of_dynptr(env, reg);
	case STACK_ITER:
		/* The first slot of an iterator carries its reference id. */
		if (reg->id != id)
			return -ENOENT;
		return resource_of_iter(env, reg);
	default:
		return -ENOENT;
	}
}

static bool resource_is_lock(const struct bpf_resource *res)
{
	return res->kind == BPF_RESOURCE_SPIN_LOCK || res->kind == BPF_RESOURCE_RES_LOCK ||
	       res->kind == BPF_RESOURCE_RES_LOCK_IRQ;
}

static u8 lock_kind(enum ref_state_type type)
{
	switch (type) {
	case REF_TYPE_LOCK:
		return BPF_RESOURCE_SPIN_LOCK;
	case REF_TYPE_RES_LOCK:
		return BPF_RESOURCE_RES_LOCK;
	default:
		return BPF_RESOURCE_RES_LOCK_IRQ;
	}
}

/* Offset of the lock of kind @kind in the object @rec describes. */
static int lock_off(const struct btf_record *rec, u8 kind)
{
	if (kind == BPF_RESOURCE_SPIN_LOCK)
		return btf_record_has_field(rec, BPF_SPIN_LOCK) ? rec->spin_lock_off : -ENOENT;
	return btf_record_has_field(rec, BPF_RES_SPIN_LOCK) ? rec->res_spin_lock_off : -ENOENT;
}

/*
 * Does @reg point into the object whose lock @ref holds? Any constant offset
 * will do: the lock is found from the pointer value by a fixed delta.
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

/* The class of a lock of kind @kind reached from the pointer in @reg. */
static int resource_of_lock(struct bpf_verifier_env *env, const struct bpf_reg_state *reg, u8 kind)
{
	const struct btf_record *rec;
	struct bpf_resource res;
	s64 delta;
	int off;

	if (reg->type == PTR_TO_MAP_VALUE) {
		rec = reg->map_ptr->record;
	} else {
		struct btf_struct_meta *meta = btf_find_struct_meta(reg->btf, reg->btf_id);

		rec = meta ? meta->record : NULL;
	}
	off = lock_off(rec, kind);
	if (off < 0)
		return off;
	delta = off - (s64)reg->var_off.value;
	if (delta != (s16)delta)
		return -ERANGE;
	memset(&res, 0, sizeof(res));
	res.kind = kind;
	res.delta = delta;
	return resource_intern(env, &res);
}

/*
 * A lock in the value of a single element array map, that is in a global
 * variable, has a fixed address: no location of the program needs to point at
 * it. The verifier tracks such a lock without an id; a lock without an id in
 * any other map cannot be told from the locks of the other elements.
 */
static int resource_of_global_lock(struct bpf_verifier_env *env,
				   const struct bpf_reference_state *ref, u8 kind)
{
	struct bpf_map *map = NULL;
	struct bpf_resource res;
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
	off = lock_off(map->record, kind);
	if (off < 0 || map->ops->map_direct_value_addr(map, &addr, off))
		return -EINVAL;
	memset(&res, 0, sizeof(res));
	res.kind = kind;
	res.addr = (void *)(long)(addr + off);
	return resource_intern(env, &res);
}

/* Can a reference of class @res live in a unique slot: a pointer released from a register. */
static bool resource_slottable(const struct bpf_resource *res)
{
	switch (res->kind) {
	case BPF_RESOURCE_OBJ:
	case BPF_RESOURCE_PERCPU_OBJ:
	case BPF_RESOURCE_KPTR:
	case BPF_RESOURCE_SOCK:
	case BPF_RESOURCE_RINGBUF:
		return true;
	default:
		return false;
	}
}

/* Note that frame @b lists the reference acquired at @acq from its unique slot. */
static int build_add_slot(struct bpf_frame_desc_build *b, u32 acq)
{
	u32 *acqs;
	int i;

	for (i = 0; i < b->nr_slot_acqs; i++)
		if (b->slot_acqs[i] == acq)
			return 0;
	acqs = kvrealloc(b->slot_acqs, array_size(b->nr_slot_acqs + 1, sizeof(*acqs)),
			 GFP_KERNEL_ACCOUNT);
	if (!acqs)
		return -ENOMEM;
	acqs[b->nr_slot_acqs++] = acq;
	b->slot_acqs = acqs;
	return 0;
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

/*
 * Choose where the reference acquired at @acq is released from, given its @nr
 * candidate locations on this path and what earlier paths put into the
 * descriptors. A location an earlier path already lists for it must be
 * reused, so that the reference is never listed twice on a path; otherwise
 * prefer a location no earlier path has put a resource or a copy into, by rank
 * and then outermost frame first. Fails when earlier paths list it at two
 * candidates (-EEXIST), list something else at one (-EINVAL), or when no
 * candidate is free (-ENOENT).
 */
static int choose(struct scratch *s, int nr, u32 acq)
{
	int i, chosen = -1, free = -1, free_rank = INT_MAX;

	for (i = 0; i < nr; i++) {
		const struct cand *c = &s->cands[i];
		struct bpf_frame_desc_build *b = s->builds[c->frameno];
		struct bpf_frame_desc_loc *loc = c->is_slot ? &b->slots[c->idx] : &b->regs[c->idx];

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
 * A location cannot list the reference acquired at @acq on every path. The
 * reference has to be released from its unique slot instead; whether it can
 * be is settled after verification, where this rejects the program otherwise.
 */
static int need_slot(struct bpf_verifier_env *env, u32 acq, const char *why)
{
	struct bpf_insn_aux_data *aux = &env->insn_aux_data[acq];

	if (aux->ref_slot == BPF_REF_SLOT_BAD) {
		verbose(env, "frame_desc: the reference acquired at insn %d %s\n", acq, why);
		return -EINVAL;
	}
	aux->ref_slot_needed = true;
	return 0;
}

/* Merge one path's classification of a location into the descriptor. */
static int merge(struct bpf_verifier_env *env, struct bpf_frame_desc_loc *loc, int class, u16 res,
		 u32 acq)
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
			return 0;
		case CLASS_NULL:
			loc->nullable = 1;
			return 0;
		default:
			/* Not the resource on this path: the listing is withdrawn. */
			ret = need_slot(env, loc->acq, "is at different locations on different paths");
			if (ret)
				return ret;
			loc->state = LOC_OTHER;
			if (class == CLASS_COPY)
				return need_slot(env, acq, "shares a location with another resource");
			return 0;
		}
	default:
		/* choose() never lists a location an earlier path used otherwise. */
		if (class == CLASS_RES)
			return need_slot(env, acq, "shares a location with another resource");
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

/*
 * Lay out the entries of one descriptor: every listed location of the frame,
 * the locks, IRQ flags and sections it holds, and the unique slots it owns.
 */
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
		ent->flags = loc->nullable ? BPF_FRAME_ENT_NULLABLE : 0;
		ent->res = loc->res;
		ent->order = resource_order(env, loc->res);
	}
	if (d) {
		for (i = 0; i < b->nr_fixed; i++)
			d->ent[n++] = b->fixed[i];
		for (i = 0; i < b->nr_spills; i++)
			d->ent[n++] = b->spills[i];
		d->nent = n;
		d->size = struct_size(d, ent, n);
		sort(d->ent, n, sizeof(d->ent[0]), entry_cmp, NULL);
	} else {
		n += b->nr_fixed + b->nr_spills;
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

/*
 * Is @insn, after all rewrites, what the unwinder sees a site through: a call,
 * or the probed access of an arena site.
 */
static bool site_insn_ok(const struct bpf_insn *insn)
{
	u8 class = BPF_CLASS(insn->code), mode = BPF_MODE(insn->code);

	if (insn->code == (BPF_JMP | BPF_CALL))
		return true;
	if (class == BPF_LDX)
		return mode == BPF_PROBE_MEM32 || mode == BPF_PROBE_MEM32SX;
	if (class == BPF_STX)
		return mode == BPF_PROBE_MEM32 || mode == BPF_PROBE_ATOMIC;
	return class == BPF_ST && mode == BPF_PROBE_MEM32;
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
 * The tables key sites by instruction index until the JIT fills them. A patch
 * of @len insns at @off after they were built, which only constant blinding
 * does, moves the sites of that subprog behind the patch, and the patched
 * instruction's own site with it, as its aux data moves to the end of the
 * patch. @prog is the patched program; the one the env still points at may
 * have been freed by the patch.
 */
void bpf_frame_desc_adjust_tables(struct bpf_verifier_env *env, struct bpf_prog *prog, u32 off,
				  u32 len)
{
	int s = insn_subprog(env, off);
	struct bpf_frame_desc_table *tab;
	u32 i, rel;

	if (len == 1 || s < 0)
		return;
	tab = env->subprog_cnt == 1 ? prog->aux->frame_desc_table :
				      env->subprog_info[s].frame_desc_table;
	if (!tab || tab->filled)
		return;
	rel = off - env->subprog_info[s].start;
	for (i = 0; i < tab->cnt; i++)
		if (tab->site[i].off >= rel)
			tab->site[i].off += len - 1;
}

/* Append a lock, IRQ flag or section entry of frame @f on this path. */
static int fixed_add(struct bpf_verifier_env *env, struct scratch *s, int f,
		     struct bpf_frame_desc_entry ent)
{
	if (s->nr_fixed[f] >= MAX_FIXED) {
		verbose(env, "frame_desc: frame%d holds too many locks and sections\n", f);
		return -E2BIG;
	}
	s->fixed[f][s->nr_fixed[f]++] = ent;
	return 0;
}

/* The entry an earlier path listed for the lock or IRQ flag of rank @order, and its frame. */
static const struct bpf_frame_desc_entry *fixed_find(struct scratch *s, int curframe, s16 order,
						     int *frame)
{
	int f, i;

	for (f = s->first; f <= curframe; f++) {
		struct bpf_frame_desc_build *b = s->builds[f];

		for (i = 0; i < b->nr_fixed; i++) {
			if (b->fixed[i].order == order) {
				*frame = f;
				return &b->fixed[i];
			}
		}
	}
	return NULL;
}

static int frame_of_subprog(struct bpf_verifier_env *env, int sub);

/*
 * Place a held lock: at its fixed address when it has one, else at a live
 * location holding a pointer into its object. An earlier path's choice must
 * be reused, as the entries have to agree. Locks are the innermost resources,
 * so prefer the innermost frame, then a stack slot or callee-saved register.
 * A lock a frame below the first one the unwinder reaches holds stays held,
 * see first_frame(): it is listed in that frame, which this site does not
 * emit, so that the frames above know what a caller holds.
 */
static int place_lock(struct bpf_verifier_env *env, struct scratch *s,
		      const struct bpf_reference_state *ref, s16 order)
{
	struct bpf_verifier_state *st = env->cur_state;
	struct bpf_frame_desc_entry ent = { .order = order };
	u8 kind = lock_kind(ref->type);
	const struct bpf_frame_desc_entry *prev;
	const struct cand *c;
	int f, k, nr = 0, prev_frame, chosen = -1, best = INT_MAX, ret;

	f = frame_of_subprog(env, insn_subprog(env, ref->insn_idx));
	if (f >= 0 && f < s->first) {
		struct bpf_resource res = { .kind = kind };

		ret = resource_intern(env, &res);
		if (ret < 0)
			return ret;
		ent.loc = BPF_FRAME_LOC_NONE;
		ent.res = ret;
		return fixed_add(env, s, f, ent);
	}
	if (!ref->id) {
		ret = resource_of_global_lock(env, ref, kind);
		if (ret < 0)
			return ret;
		ent.loc = BPF_FRAME_LOC_NONE;
		ent.off = 1;
		ent.res = ret;
		return fixed_add(env, s, st->curframe, ent);
	}
	for (f = st->curframe; f >= 0; f--) {
		struct bpf_func_state *frame = st->frame[f];
		const unsigned long *live_stack = env->insn_aux_data[s->pcs[f]].live_stack_before;

		for (k = 0; k < BPF_REG_10; k++) {
			if (!(s->live_regs[f] & BIT(k)) || !reg_is_lock(&frame->regs[k], ref))
				continue;
			ret = resource_of_lock(env, &frame->regs[k], kind);
			if (ret < 0)
				return ret;
			s->cands[nr++] = (struct cand) { f, 0, k, ret };
		}
		for (k = 0; k < frame->allocated_stack / BPF_REG_SIZE; k++) {
			const struct bpf_stack_state *slot = bpf_stack_slot(frame, k);

			if (!test_bit(k, live_stack) || !bpf_is_spilled_reg(slot) ||
			    !reg_is_lock(&slot->spilled_ptr, ref))
				continue;
			ret = resource_of_lock(env, &slot->spilled_ptr, kind);
			if (ret < 0)
				return ret;
			s->cands[nr++] = (struct cand) { f, 1, k, ret };
		}
	}
	prev = fixed_find(s, st->curframe, order, &prev_frame);
	for (k = 0; k < nr; k++) {
		int rank;

		c = &s->cands[k];
		if (prev) {
			if (c->frameno == prev_frame && c->res == prev->res &&
			    prev->loc == (c->is_slot ? BPF_FRAME_LOC_STACK : BPF_FRAME_LOC_REG) &&
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
	ent.loc = c->is_slot ? BPF_FRAME_LOC_STACK : BPF_FRAME_LOC_REG;
	ent.off = c->is_slot ? -(c->idx + 1) * BPF_REG_SIZE : c->idx;
	ent.res = c->res;
	return fixed_add(env, s, c->frameno, ent);
}

/*
 * Place saved IRQ flags: the stack slot they live in. The flags of an irqsave
 * lock are restored by the lock, so they must sit in the lock's frame.
 */
static int place_irq(struct bpf_verifier_env *env, struct scratch *s,
		     const struct bpf_reference_state *ref, s16 order)
{
	struct bpf_verifier_state *st = env->cur_state;
	struct bpf_frame_desc_entry ent = { .order = order, .loc = BPF_FRAME_LOC_STACK };
	struct bpf_resource res;
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
			res.kind = lock ? BPF_RESOURCE_IRQ_FLAG_LOCK : BPF_RESOURCE_IRQ_FLAG;
			ret = resource_intern(env, &res);
			if (ret < 0)
				return ret;
			ent.off = -(k + 1) * BPF_REG_SIZE;
			ent.res = ret;
			return fixed_add(env, s, f, ent);
		}
	}
	verbose(env, "frame_desc: no stack slot holds the irq flags saved at insn %d\n", ref->insn_idx);
	return -EINVAL;
}

/* Sections have no location; the frame that entered them leaves them. */
static int place_section(struct bpf_verifier_env *env, struct scratch *s, int f, u8 kind,
			 u32 count)
{
	struct bpf_frame_desc_entry ent = { .order = ORDER_SECTION, .loc = BPF_FRAME_LOC_NONE };
	struct bpf_resource res;
	int ret;

	if (!count)
		return 0;
	if (count > S16_MAX) {
		verbose(env, "frame_desc: frame%d is in too many nested sections\n", f);
		return -E2BIG;
	}
	memset(&res, 0, sizeof(res));
	res.kind = kind;
	ret = resource_intern(env, &res);
	if (ret < 0)
		return ret;
	ent.off = count;
	ent.res = ret;
	return fixed_add(env, s, f, ent);
}

/*
 * Place the locks, IRQ flags and sections held on this path. Unlike objects,
 * these are released in order: the verifier keeps locks and IRQ flags in
 * acquisition order, and the unwinder releases inner frames first, so the
 * ranks placed in a frame must all follow those of its callers. Every path
 * must place exactly the same entries in every frame. The frames below the
 * first one the unwinder reaches keep what they hold; it still limits what
 * the frames above may release, which held_above records.
 */
static int place_fixed(struct bpf_verifier_env *env, struct scratch *s)
{
	struct bpf_verifier_state *st = env->cur_state;
	int i, f, k, order = 0, last = -1, held = 0, ret;
	bool section = false;

	memset(s->nr_fixed, 0, sizeof(s->nr_fixed));
	for (i = 0; i < st->acquired_refs; i++) {
		const struct bpf_reference_state *ref = &st->refs[i];

		if (ref->type & REF_TYPE_LOCK_MASK)
			ret = place_lock(env, s, ref, order++);
		else if (ref->type == REF_TYPE_IRQ)
			ret = place_irq(env, s, ref, order++);
		else
			continue;
		if (ret)
			return ret;
	}
	for (f = 0; f <= st->curframe; f++) {
		ret = place_section(env, s, f, BPF_RESOURCE_RCU, st->frame[f]->rcu_locks);
		ret = ret ?: place_section(env, s, f, BPF_RESOURCE_PREEMPT,
					   st->frame[f]->preempt_locks);
		if (ret)
			return ret;
	}

	for (f = 0; f <= st->curframe; f++) {
		struct bpf_frame_desc_build *b = s->builds[f];
		size_t sz = s->nr_fixed[f] * sizeof(s->fixed[f][0]);

		s->held_above[f] = held;
		section |= st->frame[f]->rcu_locks || st->frame[f]->preempt_locks;
		s->in_section[f] = section;
		for (k = 0; k < s->nr_fixed[f]; k++)
			held |= resource_is_lock(&env->resources[s->fixed[f][k].res]) ?
				HELD_LOCK : HELD_SECTION;
		sort(s->fixed[f], s->nr_fixed[f], sizeof(s->fixed[f][0]), entry_cmp, NULL);
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
		if (f < s->first)
			continue;
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
 * May frame @f release an object of class @res? Objects are released after
 * their frame's locks, RCU-protected objects before its sections and other
 * objects after them. The frames above still hold their resources, so a
 * caller's lock forbids any release, as the program could call none there, a
 * caller's section or IRQ flags forbid a destructor that sleeps, and in a
 * sleepable program an RCU-protected object needs a section around it.
 */
static const char *release_blocker(struct bpf_verifier_env *env, struct scratch *s, int f, u16 res)
{
	const struct bpf_resource *r = &env->resources[res];

	if (s->held_above[f] & HELD_LOCK)
		return "cannot be released under a lock a caller holds";
	if (r->sleeps && (s->held_above[f] & HELD_SECTION))
		return "has a sleeping destructor and a caller holds a section or irq flags";
	if (r->rcu && env->cur_state->in_sleepable && !s->in_section[f])
		return "is RCU protected and no section covers its release";
	return NULL;
}

/* The frame of @sub on the stack of the current state, or -1 once it has returned. */
static int frame_of_subprog(struct bpf_verifier_env *env, int sub)
{
	struct bpf_verifier_state *st = env->cur_state;
	int f;

	for (f = st->curframe; f >= 0; f--)
		if (st->frame[f]->subprogno == sub)
			return f;
	return -1;
}

/*
 * List reference @ref, of class @res with @nr candidate locations on this
 * path. A reference acquired by a call is listed from the unique slot of the
 * acquiring frame, which must be on the stack, and at a location the paths
 * agree on as a fallback; when the location cannot be found or a frame may
 * not release it, the slot is required. A reference no live location holds
 * can never be released by the program, which the verifier rejects for the
 * leak when the path ends, so it is left out here.
 */
static int place_ref(struct bpf_verifier_env *env, struct scratch *s,
		     const struct bpf_reference_state *ref, int nr)
{
	struct bpf_insn_aux_data *aux = &env->insn_aux_data[ref->insn_idx];
	const char *why;
	int k, res, chosen, af;

	if (!nr)
		return 0;
	res = s->cands[0].res;

	af = frame_of_subprog(env, insn_subprog(env, ref->insn_idx));
	if (aux->ref_slot == BPF_REF_SLOT_NONE) {
		if (resource_slottable(&env->resources[res]) &&
		    env->prog->insnsi[ref->insn_idx].code == (BPF_JMP | BPF_CALL)) {
			aux->ref_slot = BPF_REF_SLOT_WANTED;
			aux->ref_slot_resource = res;
		} else {
			aux->ref_slot = BPF_REF_SLOT_BAD;
		}
	}
	if (aux->ref_slot == BPF_REF_SLOT_WANTED) {
		why = af < 0 ? "was acquired in a subprog that returned" :
		      af >= s->first ? release_blocker(env, s, af, res) : NULL;
		if (why) {
			if (aux->ref_slot_needed) {
				verbose(env, "frame_desc: the reference acquired at insn %d %s, and no location describes it on every path\n",
					ref->insn_idx, why);
				return -EINVAL;
			}
			aux->ref_slot = BPF_REF_SLOT_BAD;
		} else if (af >= s->first) {
			int ret = build_add_slot(s->builds[af], ref->insn_idx);

			if (ret)
				return ret;
		}
	}

	chosen = choose(s, nr, ref->insn_idx);
	why = chosen == -ENOENT ? "has no location free to be released from" :
	      chosen == -EEXIST ? "is at different locations on different paths" :
	      chosen == -EINVAL ? "shares a location with another resource on another path" :
	      release_blocker(env, s, s->cands[chosen].frameno, res);
	for (k = 0; k < nr; k++) {
		const struct cand *c = &s->cands[k];
		int idx = c->is_slot ? BPF_REG_10 + c->idx : c->idx;

		s->class[c->frameno][idx] = !why && k == chosen ? CLASS_RES : CLASS_COPY;
		s->res[c->frameno][idx] = c->res;
		s->acq[c->frameno][idx] = ref->insn_idx;
	}
	if (!why)
		return 0;
	if (aux->ref_slot == BPF_REF_SLOT_WANTED) {
		aux->ref_slot_needed = true;
		return 0;
	}
	verbose(env, "frame_desc: reference id=%d (acquired at insn %d) %s\n", ref->id,
		ref->insn_idx, why);
	return -EINVAL;
}

/*
 * The outermost frame the unwinder reaches from a site: a callback runs under
 * a kernel frame, so a site inside one unwinds the callback's frames and the
 * callback leaves, into the pad of the helper that ran it or back to the
 * kernel code that did, and the frames below are unwound from the call of the
 * helper. The exception callback took the main frame over, so it is its own
 * outermost frame.
 */
static int first_frame(struct bpf_verifier_state *st)
{
	int f;

	for (f = st->curframe; f > 0; f--)
		if (st->frame[f]->in_callback_fn || st->frame[f]->in_async_callback_fn)
			return f;
	return 0;
}

/*
 * Record the state at a site where the program may be unwound. @regs_saved
 * says that the entry the unwinder is reached through saves R0-R9 of the
 * innermost frame; otherwise it is waiting in a call and only keeps R6-R9 and
 * its stack, as every caller frame does. At an arena access that is the
 * state before the access takes effect, since the fault precedes any write
 * of its result. Only live locations are considered, which keeps the
 * descriptors consistent with state pruning: two states the verifier treats
 * as equivalent agree on every live location.
 */
static int site_do(struct bpf_verifier_env *env, bool regs_saved)
{
	struct bpf_verifier_state *st = env->cur_state;
	struct scratch *s = env->frame_desc_scratch;
	int f, i, k, nr, ret;

	if (!s) {
		s = kvzalloc_obj(*s, GFP_KERNEL_ACCOUNT);
		if (!s)
			return -ENOMEM;
		env->frame_desc_scratch = s;
	}
	env->frame_desc_visits++;
	s->first = first_frame(st);

	for (f = 0; f <= st->curframe; f++) {
		struct bpf_func_state *frame = st->frame[f];
		u32 nr_slots = frame->allocated_stack / BPF_REG_SIZE;

		s->pcs[f] = f == st->curframe ? env->insn_idx : st->frame[f + 1]->callsite;
		s->live_regs[f] = env->insn_aux_data[s->pcs[f]].live_regs_before;
		if (f != st->curframe || !regs_saved)
			s->live_regs[f] &= CALLEE_SAVED_REGS;
		memset(s->class[f], 0, sizeof(s->class[f]));
		if (f < s->first)
			continue;
		s->builds[f] = build_get(env, s->pcs[f], nr_slots);
		if (!s->builds[f])
			return -ENOMEM;
		s->builds[f]->regs_saved = f == st->curframe && regs_saved;
	}

	ret = place_fixed(env, s);
	if (ret)
		return ret;

	/* List every reference the frames reached from here hold. */
	for (i = 0; i < st->acquired_refs; i++) {
		const struct bpf_reference_state *ref = &st->refs[i];
		int outermost = INT_MAX;

		if (ref->type != REF_TYPE_PTR)
			continue;
		nr = 0;
		for (f = 0; f <= st->curframe; f++) {
			struct bpf_func_state *frame = st->frame[f];
			const unsigned long *live_stack = env->insn_aux_data[s->pcs[f]].live_stack_before;

			for (k = 0; k < BPF_REG_10; k++) {
				if (!(s->live_regs[f] & BIT(k)) || !reg_is_ref(&frame->regs[k], ref->id))
					continue;
				ret = resource_of_reg(env, &frame->regs[k]);
				if (ret < 0)
					return ret;
				s->cands[nr++] = (struct cand) { f, 0, k, ret };
				outermost = min(outermost, f);
			}
			/* Only the slots this state allocated hold anything. */
			for (k = 0; k < frame->allocated_stack / BPF_REG_SIZE; k++) {
				if (!test_bit(k, live_stack))
					continue;
				ret = stack_slot_ref(env, bpf_stack_slot(frame, k), ref->id);
				if (ret == -ENOENT)
					continue;
				if (ret < 0)
					return ret;
				s->cands[nr++] = (struct cand) { f, 1, k, ret };
				outermost = min(outermost, f);
			}
		}
		/* A reference a frame below the first one holds is released with that frame. */
		f = frame_of_subprog(env, insn_subprog(env, ref->insn_idx));
		if ((f >= 0 ? f : outermost) < s->first)
			continue;
		ret = place_ref(env, s, ref, nr);
		if (ret)
			return ret;
	}

	/* Classify the remaining live locations and merge every frame. */
	for (f = s->first; f <= st->curframe; f++) {
		struct bpf_func_state *frame = st->frame[f];
		struct bpf_frame_desc_build *b = s->builds[f];
		const unsigned long *live_stack = env->insn_aux_data[s->pcs[f]].live_stack_before;
		int loc;

		for (loc = 0; loc < BPF_REG_10 + b->nr_slots; loc++) {
			struct bpf_frame_desc_loc *dst;

			if (loc < BPF_REG_10) {
				if (!(s->live_regs[f] & BIT(loc)))
					continue;
				if (!s->class[f][loc] && bpf_register_is_null(&frame->regs[loc]))
					s->class[f][loc] = CLASS_NULL;
				dst = &b->regs[loc];
			} else {
				k = loc - BPF_REG_10;
				if (!test_bit(k, live_stack))
					continue;
				/* A live slot this state has not allocated holds anything. */
				if (!s->class[f][loc] && k < frame->allocated_stack / BPF_REG_SIZE &&
				    stack_slot_is_null(bpf_stack_slot(frame, k)))
					s->class[f][loc] = CLASS_NULL;
				dst = &b->slots[k];
			}
			ret = merge(env, dst, s->class[f][loc], s->res[f][loc], s->acq[f][loc]);
			if (ret)
				return ret;
		}
		b->visits++;
	}
	return 0;
}

/*
 * Describe the state at a site where the program may be unwound: a bpf_throw()
 * call, a call to a global subprog, or a point at which the kernel may cancel
 * the program. A site that cannot be described rejects the program.
 */
int bpf_frame_desc_site(struct bpf_verifier_env *env, bool regs_saved)
{
	struct bpf_verifier_state *st = env->cur_state;
	int first, ret;

	if (st->speculative)
		return 0;
	/* A callback a helper ran leaves into the pad of the helper, which needs one. */
	first = first_frame(st);
	if (first && st->frame[first]->in_callback_fn) {
		ret = bpf_check_callback_site(env, st->frame[first]->callsite);
		if (ret)
			return ret;
	}
	return site_do(env, regs_saved);
}

/*
 * Can the slot of the reference acquired at @acq be kept up to date? Every
 * release must be in the acquiring subprog, so that the clear reaches the
 * slot, and must release references of this acquisition only: two
 * references of one type may be to one object, so a release insn that
 * releases one of several acquisitions on different paths could not tell
 * their slots apart by value.
 */
static const char *slot_blocker(struct bpf_verifier_env *env, u32 acq)
{
	int sub = insn_subprog(env, acq);
	u32 i, j;

	for (i = 0; i < env->ref_release_cnt; i++) {
		const struct bpf_ref_release *r = &env->ref_releases[i];

		if (r->acq != acq)
			continue;
		if (insn_subprog(env, r->rel) != sub)
			return "is released in another subprog";
		for (j = 0; j < env->ref_release_cnt; j++)
			if (env->ref_releases[j].rel == r->rel && env->ref_releases[j].acq != acq)
				return "is released by an insn that releases other references too";
	}
	return NULL;
}

/*
 * After verification, once every release has been seen and the stack is
 * final: reserve the unique slots that can be kept up to date, attach their
 * clears to the release insns, and make each such slot the only listing of
 * its reference by retracting every location that listed it. A reference
 * that needed its slot and gets none cannot be described.
 */
int bpf_frame_desc_resolve(struct bpf_verifier_env *env)
{
	struct bpf_insn_aux_data *aux = env->insn_aux_data;
	u32 i, k, len = env->prog->len;
	int ret;

	for (i = 0; i < len; i++) {
		const char *why;
		s16 off;

		if (aux[i].ref_slot != BPF_REF_SLOT_WANTED)
			continue;
		why = slot_blocker(env, i);
		if (why) {
			if (aux[i].ref_slot_needed) {
				verbose(env, "frame_desc: the reference acquired at insn %d %s, and no location describes it on every path\n",
					i, why);
				return -EINVAL;
			}
			aux[i].ref_slot = BPF_REF_SLOT_BAD;
			continue;
		}
		ret = bpf_reserve_stack_slots(env, insn_subprog(env, i), 1, &off);
		ret = ret ?: bpf_stack_slot_init(env, insn_subprog(env, i), off, 0);
		if (ret)
			return ret;
		aux[i].ref_slot = BPF_REF_SLOT_RESERVED;
		aux[i].ref_slot_off = off;
		env->ref_slots++;
	}

	/* An eligible acquisition is the only one its release insns release. */
	for (i = 0; i < env->ref_release_cnt; i++) {
		const struct bpf_ref_release *r = &env->ref_releases[i];

		if (aux[r->acq].ref_slot != BPF_REF_SLOT_RESERVED)
			continue;
		aux[r->rel].ref_slot_clear = true;
		aux[r->rel].ref_slot_clear_off = aux[r->acq].ref_slot_off;
	}

	for (i = 0; i < len; i++) {
		struct bpf_frame_desc_build *b = aux[i].frame_desc;
		int l;

		if (!b)
			continue;
		for (l = 0; l < BPF_REG_10 + b->nr_slots; l++) {
			struct bpf_frame_desc_loc *loc = l < BPF_REG_10 ? &b->regs[l] :
								     &b->slots[l - BPF_REG_10];

			if (loc->state == LOC_RES && aux[loc->acq].ref_slot == BPF_REF_SLOT_RESERVED)
				loc->state = LOC_OTHER;
		}
		if (!b->nr_slot_acqs)
			continue;
		b->spills = kvcalloc(b->nr_slot_acqs, sizeof(*b->spills), GFP_KERNEL_ACCOUNT);
		if (!b->spills)
			return -ENOMEM;
		for (k = 0; k < b->nr_slot_acqs; k++) {
			u32 acq = b->slot_acqs[k];

			if (aux[acq].ref_slot != BPF_REF_SLOT_RESERVED)
				continue;
			b->spills[b->nr_spills++] = (struct bpf_frame_desc_entry) {
				.loc = BPF_FRAME_LOC_STACK, .flags = BPF_FRAME_ENT_NULLABLE,
				.res = aux[acq].ref_slot_resource, .off = aux[acq].ref_slot_off,
				.order = resource_order(env, aux[acq].ref_slot_resource),
			};
		}
	}
	return 0;
}

/*
 * An instruction rewrite moved a site's descriptor to insn @from together
 * with the rest of its aux data; the instruction the unwinder sees the site
 * through is insn @to.
 */
void bpf_frame_desc_move_site(struct bpf_verifier_env *env, u32 from, u32 to)
{
	struct bpf_frame_desc_build *b = env->insn_aux_data[from].frame_desc;

	if (!b)
		return;
	env->insn_aux_data[from].frame_desc = NULL;
	env->insn_aux_data[to].frame_desc = b;
}

/*
 * Record that reference @id is released at the current insn: the unique slot
 * of its acquisition, if it gets one, is cleared there. A NULL check releases
 * a reference too, but leaves nothing in a slot.
 */
int bpf_frame_desc_record_release(struct bpf_verifier_env *env, int id)
{
	struct bpf_verifier_state *st = env->cur_state;
	struct bpf_ref_release *rels, rel = { .rel = env->insn_idx };
	u32 i;

	for (i = 0; i < st->acquired_refs; i++)
		if (st->refs[i].type == REF_TYPE_PTR && st->refs[i].id == id)
			break;
	if (i == st->acquired_refs)
		return 0;
	rel.acq = st->refs[i].insn_idx;
	for (i = 0; i < env->ref_release_cnt; i++)
		if (env->ref_releases[i].rel == rel.rel && env->ref_releases[i].acq == rel.acq)
			return 0;
	rels = kvrealloc(env->ref_releases, array_size(env->ref_release_cnt + 1, sizeof(*rels)),
			 GFP_KERNEL_ACCOUNT);
	if (!rels)
		return -ENOMEM;
	rels[env->ref_release_cnt++] = rel;
	env->ref_releases = rels;
	return 0;
}

/*
 * Keep the unique slots up to date: store the result of an acquisition into
 * its slot, and clear the slot before a release. Patching a call keeps the
 * jumps to it, so the clear precedes it; the aux data of the call, with the
 * descriptor of the site it may be, is moved back onto it.
 */
int bpf_frame_desc_emit_slots(struct bpf_verifier_env *env)
{
	struct bpf_insn *insn_buf = env->insn_buf;
	int i, cnt, delta = 0, insn_cnt = env->prog->len;

	if (!env->ref_slots)
		return 0;
	for (i = 0; i < insn_cnt; i++) {
		struct bpf_insn_aux_data *aux = &env->insn_aux_data[i + delta];
		struct bpf_insn *insn = &env->prog->insnsi[i + delta], *p = insn_buf;
		bool spill = aux->ref_slot == BPF_REF_SLOT_RESERVED;
		struct bpf_prog *new_prog;

		if (!spill && !aux->ref_slot_clear)
			continue;
		if (aux->ref_slot_clear)
			*p++ = BPF_ST_MEM(BPF_DW, BPF_REG_10, aux->ref_slot_clear_off, 0);
		*p++ = *insn;
		if (spill)
			*p++ = BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, aux->ref_slot_off);
		cnt = p - insn_buf;
		new_prog = bpf_patch_insn_data(env, i + delta, insn_buf, cnt);
		if (!new_prog)
			return -ENOMEM;
		env->prog = new_prog;
		/* The aux data of the call, which later fixups need, landed on the store. */
		if (spill)
			swap(env->insn_aux_data[i + delta + cnt - 1],
			     env->insn_aux_data[i + delta + cnt - 2]);
		env->ref_spills += cnt - 1;
		delta += cnt - 1;
	}
	return 0;
}

/*
 * The bpf_loop() call at insn @from was inlined: its callback is an ordinary
 * callee now, called from insn @to, and the frame is unwound through there
 * instead of stopping at the callback. The loop keeps R6, R7 and R8 in the
 * stack slots from @r6_off up while it runs, so what the descriptor listed in
 * those registers is listed in the slots.
 */
int bpf_frame_desc_inlined_loop(struct bpf_verifier_env *env, u32 from, u32 to, s16 r6_off)
{
	struct bpf_frame_desc_build *b = env->insn_aux_data[from].frame_desc;
	int r;

	if (!b)
		return 0;
	env->insn_aux_data[from].frame_desc = NULL;
	env->insn_aux_data[to].frame_desc = b;
	for (r = BPF_REG_6; r <= BPF_REG_8; r++) {
		u32 spi = -(r6_off + (r - BPF_REG_6) * BPF_REG_SIZE) / BPF_REG_SIZE - 1;

		if (b->regs[r].state != LOC_RES)
			continue;
		b = build_grow(env, to, b, spi + 1);
		if (!b)
			return -ENOMEM;
		b->slots[spi] = b->regs[r];
		b->regs[r].state = LOC_OTHER;
	}
	return 0;
}
