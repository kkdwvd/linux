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
 * through a pointer to it otherwise. Locks, IRQ flags and sections are
 * released in order, and every path reaching a site must place the same
 * ones: they are kept apart from the per location lattice, see
 * place_fixed().
 *
 * A frame may release what a frame below owns, in the context of the caller
 * or on its own with the caller's references inherited, and the frame below
 * still lists it at the call it waits in. The releasing frame retracts the
 * release: the handle goes into a retraction slot of its frame, which its
 * sites list, and the unwinder skips what a frame below lists under that
 * handle. A frame whose callee returned after releasing what a frame further
 * below owns retracts it the same way, from the register it passed the
 * handle in. Sections of the callers a frame left are retracted by count.
 *
 * Where the paths reaching a site do not agree on a location of a resource,
 * or no live location holds it, the resource is released from its mirror: a
 * hidden stack slot of the owner subprog, keyed by the acquiring insn, that
 * the acquisition fills with the handle, every release in the subprog clears,
 * and a return from a callee refreshes when the callee may have released or
 * returned the resource. The stack decides then. Mirrors are reserved and
 * their stores emitted after the main pass, for the resources that needed
 * one; the lattice comes first, and covers nearly every program.
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
#define MAX_FIXED		32	/* locks, IRQ flags and sections a frame may hold */
#define ACQ_NONE		(~0U)	/* sections have no acquiring insn */
#define MIRROR_KIND_PTR		0	/* the mirror holds the pointer the acquisition returned */
#define MIRROR_KIND_LOCK	0xff	/* the pointer to the lock; else the slot type of a stack object */
#define DISC_SLOTS		64	/* stack slots that may tell a call's outcome, see record_return() */
/* Release ranks of the entries without an acquisition order, see entry_cmp(). */
#define ORDER_RCU_OBJ		-1
#define ORDER_SECTION		-2
#define ORDER_OBJ		-3
#define ORDER_RETRACT		-4

/* The classes of handles the unwinder matches a retraction against. */
enum {
	HANDLE_PTR,
	HANDLE_ITER,
	HANDLE_DYNPTR,
	HANDLE_LOCK,
	HANDLE_IRQ,
	HANDLE_NONE,
};

/* A candidate location of one reference on the current path. */
struct cand {
	u8 is_slot;
	u8 indirect;	/* the location holds a pointer to the resource */
	u16 idx;	/* register number or spi */
	u16 res;
};

/* Per-site working storage, allocated once per verification. */
struct scratch {
	struct cand cands[FRAME_LOCS];
	u8 class[FRAME_LOCS];
	u8 indirect[FRAME_LOCS];
	u16 res[FRAME_LOCS];
	u32 acq[FRAME_LOCS];
	struct bpf_frame_desc_build *build;
	u32 pc;
	u32 subprog;
	u32 live_regs;
	const unsigned long *live_stack;
	struct bpf_frame_desc_fixed fixed[MAX_FIXED];
	u16 nr_fixed;
};

/* Make room for @nr_slots stack slots in the descriptor at @slot, of insn @pc. */
static struct bpf_frame_desc_build *build_grow(struct bpf_verifier_env *env, u32 pc,
					       struct bpf_frame_desc_build **slot, u32 nr_slots)
{
	struct bpf_frame_desc_build *b = *slot;
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
	*slot = b;
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
	if (!b)
		return;
	kvfree(b->fixed);
	kvfree(b->mirrors);
	kvfree(b->extra);
	kvfree(b);
}

void bpf_frame_desc_build_free(struct bpf_insn_aux_data *aux)
{
	bpf_frame_desc_build_destroy(aux->frame_desc);
	bpf_frame_desc_build_destroy(aux->guard_desc);
	aux->frame_desc = NULL;
	aux->guard_desc = NULL;
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
	for (i = 0; i < env->mirror_cnt; i++)
		kvfree(env->mirrors[i].stores);
	kvfree(env->mirrors);
	kvfree(env->call_refs);
	kvfree(env->retractions);
	kvfree(env->resources);
	env->mirrors = NULL;
	env->call_refs = NULL;
	env->retractions = NULL;
	env->resources = NULL;
	env->mirror_cnt = 0;
	env->call_ref_cnt = 0;
	env->retraction_cnt = 0;
	env->resource_cnt = 0;
	env->frame_desc_visits = 0;
	env->frame_desc_conflicts = 0;
	env->mirrors_needed = 0;
	for (i = 0; i < env->subprog_cnt; i++)
		env->subprog_info[i].max_retract = 0;
}

void bpf_frame_desc_env_free(struct bpf_verifier_env *env)
{
	int i;

	for (i = 0; i < env->subprog_cnt; i++)
		bpf_frame_desc_build_destroy(env->subprog_info[i].entry_guard);
	for (i = 0; i < env->mirror_cnt; i++)
		kvfree(env->mirrors[i].stores);
	kvfree(env->mirrors);
	kvfree(env->call_refs);
	kvfree(env->retractions);
	kvfree(env->retract_arrays);
	kvfree(env->resources);
	kvfree(env->frame_desc_scratch);
	env->mirrors = NULL;
	env->call_refs = NULL;
	env->retractions = NULL;
	env->retract_arrays = NULL;
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

/* The class of the IRQ flags at @slot: the flags of an irqsave lock are restored with it. */
static int resource_of_irq(struct bpf_verifier_env *env, const struct bpf_stack_state *slot)
{
	struct bpf_resource res;

	memset(&res, 0, sizeof(res));
	res.kind = slot->spilled_ptr.irq.kfunc_class == IRQ_LOCK_KFUNC ?
		   BPF_RESOURCE_IRQ_FLAG_LOCK : BPF_RESOURCE_IRQ_FLAG;
	return resource_intern(env, &res);
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
		return reg->dynptr.first_slot && reg->dynptr.type == BPF_DYNPTR_TYPE_RINGBUF &&
		       reg->parent_id == id;
	case STACK_ITER:
	case STACK_IRQ_FLAG:
		return reg->id == id;
	default:
		return false;
	}
}

/* The class of the stack object at @slot, see stack_slot_is_object(). */
static int resource_of_object(struct bpf_verifier_env *env, const struct bpf_stack_state *slot)
{
	switch (slot->slot_type[BPF_REG_SIZE - 1]) {
	case STACK_DYNPTR:
		return resource_of_dynptr(env, &slot->spilled_ptr);
	case STACK_IRQ_FLAG:
		return resource_of_irq(env, slot);
	default:
		return resource_of_iter(env, &slot->spilled_ptr);
	}
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

/* The mirror of the resource acquired at @acq that frames of @subprog own, if recorded. */
static struct bpf_mirror *mirror_find(struct bpf_verifier_env *env, u32 subprog, u32 acq)
{
	u32 i;

	for (i = 0; i < env->mirror_cnt; i++)
		if (env->mirrors[i].acq == acq && env->mirrors[i].subprog == subprog)
			return &env->mirrors[i];
	return NULL;
}

static struct bpf_mirror *mirror_get(struct bpf_verifier_env *env, u32 subprog, u32 acq)
{
	struct bpf_mirror *m = mirror_find(env, subprog, acq);
	u32 cnt = env->mirror_cnt;

	if (m)
		return m;
	m = kvrealloc(env->mirrors, array_size(cnt + 1, sizeof(*m)), GFP_KERNEL_ACCOUNT);
	if (!m)
		return NULL;
	env->mirrors = m;
	env->mirror_cnt = cnt + 1;
	m = &m[cnt];
	memset(m, 0, sizeof(*m));
	m->acq = acq;
	m->subprog = subprog;
	return m;
}

/* The resource acquired at @acq has to be released from its mirror at some site of @subprog. */
static int mirror_need(struct bpf_verifier_env *env, u32 subprog, u32 acq)
{
	struct bpf_mirror *m = mirror_get(env, subprog, acq);

	if (!m)
		return -ENOMEM;
	if (!m->needed)
		env->mirrors_needed++;
	m->needed = true;
	return 0;
}

static int mirror_store_add(struct bpf_mirror *m, u32 insn, u8 point, u8 reg, s16 off)
{
	struct bpf_mirror_store *st;
	u32 i;

	for (i = 0; i < m->nr_stores; i++)
		if (m->stores[i].insn == insn && m->stores[i].point == point)
			return 0;
	st = kvrealloc(m->stores, array_size(m->nr_stores + 1, sizeof(*st)), GFP_KERNEL_ACCOUNT);
	if (!st)
		return -ENOMEM;
	st[m->nr_stores++] = (struct bpf_mirror_store) { .insn = insn, .point = point, .reg = reg,
							 .off = off };
	m->stores = st;
	return 0;
}

/* Note that the frame of build @b owns the resource acquired at @acq at the site. */
static int build_add_mirror(struct bpf_frame_desc_build *b, u32 acq)
{
	u32 *acqs;
	int i;

	for (i = 0; i < b->nr_mirrors; i++)
		if (b->mirrors[i] == acq)
			return 0;
	acqs = kvrealloc(b->mirrors, array_size(b->nr_mirrors + 1, sizeof(*acqs)),
			 GFP_KERNEL_ACCOUNT);
	if (!acqs)
		return -ENOMEM;
	acqs[b->nr_mirrors++] = acq;
	b->mirrors = acqs;
	return 0;
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
 * the site: the paths disagree on where it is, @why. The reference is
 * released from its mirror instead.
 */
static int conflict(struct bpf_verifier_env *env, struct scratch *s, u32 acq, const char *why)
{
	env->frame_desc_conflicts++;
	if (env->log.level & BPF_LOG_LEVEL2)
		verbose(env, "frame_desc: insn %d: the reference acquired at insn %d %s: mirrored\n",
			s->pc, acq, why);
	return mirror_need(env, s->subprog, acq);
}

/* Merge one path's classification of a location into the descriptor. */
static int merge(struct bpf_verifier_env *env, struct scratch *s, struct bpf_frame_desc_loc *loc,
		 int class, u16 res, u32 acq, bool indirect)
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
			return conflict(env, s, acq, "is a stack object on one path and a pointer on another");
		case CLASS_NULL:
			/* A stack object in place is never NULL. */
			if (!loc->indirect)
				return conflict(env, s, loc->acq, "is a stack object that is not there on every path");
			loc->nullable = 1;
			return 0;
		default:
			/* Not the resource on this path: the listing is withdrawn. */
			ret = conflict(env, s, loc->acq, "is at different locations on different paths");
			if (ret)
				return ret;
			loc->state = LOC_OTHER;
			if (class == CLASS_COPY)
				return conflict(env, s, acq, "shares a location with another resource");
			return 0;
		}
	default:
		/* choose() never lists a location an earlier path used otherwise. */
		if (class == CLASS_RES)
			return conflict(env, s, acq, "shares a location with another resource");
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

/* The class of handle the unwinder matches a retraction of class @res against. */
static u8 handle_class(const struct bpf_verifier_env *env, u16 res)
{
	switch (env->resources[res].kind) {
	case BPF_RESOURCE_OBJ:
	case BPF_RESOURCE_PERCPU_OBJ:
	case BPF_RESOURCE_KPTR:
	case BPF_RESOURCE_SOCK:
	case BPF_RESOURCE_RINGBUF:
		return HANDLE_PTR;
	case BPF_RESOURCE_ITER:
		return HANDLE_ITER;
	case BPF_RESOURCE_DYNPTR_RINGBUF:
		return HANDLE_DYNPTR;
	case BPF_RESOURCE_SPIN_LOCK:
	case BPF_RESOURCE_RES_LOCK:
	case BPF_RESOURCE_RES_LOCK_IRQ:
		return HANDLE_LOCK;
	case BPF_RESOURCE_IRQ_FLAG:
	case BPF_RESOURCE_IRQ_FLAG_LOCK:
		return HANDLE_IRQ;
	default:
		return HANDLE_NONE;
	}
}

/*
 * Lay out the entries of one descriptor: every listed location of the frame,
 * the locks, IRQ flags and sections it holds, and the mirrors it lists.
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
		ent->flags = (loc->indirect ? BPF_FRAME_ENT_INDIRECT : 0) |
			     (loc->nullable ? BPF_FRAME_ENT_NULLABLE : 0);
		ent->res = loc->res;
		ent->order = resource_order(env, loc->res);
	}
	if (d) {
		for (i = 0; i < b->nr_fixed; i++)
			d->ent[n++] = b->fixed[i].ent;
		for (i = 0; i < b->nr_extra; i++)
			d->ent[n++] = b->extra[i];
		d->nent = n;
		d->size = struct_size(d, ent, n);
		sort(d->ent, n, sizeof(d->ent[0]), entry_cmp, NULL);
	} else {
		n += b->nr_fixed + b->nr_extra;
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
		s->cands[nr++] = (struct cand) { 0, 1, k, ret };
	}
	for (k = 0; k < bpf_stack_nr_slots(frame); k++) {
		if (!test_bit(k, s->live_stack))
			continue;
		ret = stack_slot_ref(env, bpf_stack_slot(frame, k), ref->id, classify);
		if (ret == -ENOENT)
			continue;
		if (ret < 0)
			return ret;
		s->cands[nr++] = (struct cand) { 1, 1, k, ret };
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
	int k, nr = 0, res = 0;

	if (classify) {
		res = resource_of_object(env, bpf_stack_slot(st->frame[objframe], spi));
		if (res < 0)
			return res;
	}
	if (objframe == st->curframe)
		s->cands[nr++] = (struct cand) { 1, 0, spi, res };
	for (k = 0; k < BPF_REG_10; k++) {
		if (!(s->live_regs & BIT(k)) || !reg_points_at(&frame->regs[k], objframe, spi))
			continue;
		s->cands[nr++] = (struct cand) { 0, 1, k, res };
	}
	for (k = 0; k < bpf_stack_nr_slots(frame); k++) {
		const struct bpf_stack_state *slot = bpf_stack_slot(frame, k);

		if (!test_bit(k, s->live_stack) || !bpf_is_spilled_reg(slot) ||
		    !reg_points_at(&slot->spilled_ptr, objframe, spi))
			continue;
		s->cands[nr++] = (struct cand) { 1, 1, k, res };
	}
	return nr;
}

/*
 * Classify the @nr candidates of a reference the frame holds for another
 * frame: copies, unless the location lists a resource of the frame's own,
 * such as an object whose lock a caller holds.
 */
static void place_copy(struct scratch *s, int nr)
{
	int k;

	for (k = 0; k < nr; k++)
		if (!s->class[cand_idx(&s->cands[k])])
			s->class[cand_idx(&s->cands[k])] = CLASS_COPY;
}

/* Append a lock, IRQ flag or section entry of the frame on this path. */
static int fixed_add(struct bpf_verifier_env *env, struct scratch *s,
		     struct bpf_frame_desc_entry ent, u32 acq)
{
	if (s->nr_fixed >= MAX_FIXED) {
		verbose(env, "frame_desc: frame%d holds too many locks and sections\n",
			env->cur_state->curframe);
		return -E2BIG;
	}
	s->fixed[s->nr_fixed++] = (struct bpf_frame_desc_fixed) { .ent = ent, .acq = acq };
	return 0;
}

/* The entry an earlier path placed for the lock or IRQ flags acquired at @acq, or NULL. */
static struct bpf_frame_desc_fixed *fixed_prev(struct bpf_frame_desc_build *b, u32 acq)
{
	int i;

	for (i = 0; i < b->nr_fixed; i++)
		if (b->fixed[i].acq == acq)
			return &b->fixed[i];
	return NULL;
}

static bool cand_is(const struct cand *c, const struct bpf_frame_desc_entry *ent)
{
	return ent->loc == (c->is_slot ? BPF_FRAME_LOC_STACK : BPF_FRAME_LOC_REG) &&
	       ent->off == (c->is_slot ? -(c->idx + 1) * BPF_REG_SIZE : c->idx) &&
	       ent->res == c->res;
}

/*
 * The lock or IRQ flags acquired at @acq have no location on this path, or
 * none the earlier paths agree on: they are released from the mirror. Place
 * an entry of rank @order for it, which the mirror replaces once reserved,
 * see build_mirror(); what an earlier path placed stays until then.
 */
static int fixed_mirror(struct bpf_verifier_env *env, struct scratch *s, u32 acq, s16 order)
{
	struct bpf_frame_desc_entry ent = { .order = order, .loc = BPF_FRAME_LOC_STACK,
					    .flags = BPF_FRAME_ENT_INDIRECT | BPF_FRAME_ENT_NULLABLE };
	int ret;

	ret = mirror_need(env, s->subprog, acq);
	return ret ?: fixed_add(env, s, ent, acq);
}

/* The live locations of the frame holding a pointer into the object of lock @ref. */
static int find_lock_cands(struct bpf_verifier_env *env, struct scratch *s,
			   const struct bpf_func_state *frame, const struct bpf_reference_state *ref)
{
	u8 kind = lock_kind(ref->type);
	int k, nr = 0, ret;

	if (!ref->id)
		return 0;
	for (k = 0; k < BPF_REG_10; k++) {
		if (!(s->live_regs & BIT(k)) || !reg_is_lock(&frame->regs[k], ref))
			continue;
		ret = resource_of_lock(env, &frame->regs[k], kind);
		if (ret < 0)
			return ret;
		s->cands[nr++] = (struct cand) { 0, 1, k, ret };
	}
	for (k = 0; k < bpf_stack_nr_slots(frame); k++) {
		const struct bpf_stack_state *slot = bpf_stack_slot(frame, k);

		if (!test_bit(k, s->live_stack) || !bpf_is_spilled_reg(slot) ||
		    !reg_is_lock(&slot->spilled_ptr, ref))
			continue;
		ret = resource_of_lock(env, &slot->spilled_ptr, kind);
		if (ret < 0)
			return ret;
		s->cands[nr++] = (struct cand) { 1, 1, k, ret };
	}
	return nr;
}

/*
 * Place a held lock of rank @order: at its fixed address when it has one,
 * else at a live location holding a pointer into its object. An earlier
 * path's choice must be reused, as the entries have to agree; otherwise
 * prefer a stack slot or a callee-saved register, which outlive calls.
 */
static int place_lock(struct bpf_verifier_env *env, struct scratch *s,
		      const struct bpf_reference_state *ref, s16 order)
{
	struct bpf_func_state *frame = env->cur_state->frame[env->cur_state->curframe];
	struct bpf_frame_desc_entry ent = { .order = order, .flags = BPF_FRAME_ENT_INDIRECT };
	const struct bpf_frame_desc_fixed *prev;
	const struct cand *c;
	int k, nr, chosen = -1, best = INT_MAX, ret;

	if (!ref->id) {
		ret = resource_of_global_lock(env, ref, lock_kind(ref->type));
		if (ret < 0)
			return ret;
		ent.loc = BPF_FRAME_LOC_NONE;
		ent.flags = 0;
		ent.off = 1;
		ent.res = ret;
		return fixed_add(env, s, ent, ref->insn_idx);
	}
	nr = find_lock_cands(env, s, frame, ref);
	if (nr < 0)
		return nr;
	prev = fixed_prev(s->build, ref->insn_idx);
	for (k = 0; prev && k < nr; k++) {
		if (cand_is(&s->cands[k], &prev->ent)) {
			chosen = k;
			break;
		}
	}
	for (k = 0; chosen < 0 && k < nr; k++) {
		int rank;

		c = &s->cands[k];
		rank = c->is_slot ? 0 : c->idx >= BPF_REG_6 ? 1 : 2;
		if (rank < best) {
			best = rank;
			chosen = k;
		}
	}
	/* no location on this path, or another one: the mirror, in place of whatever is listed */
	if (chosen < 0)
		return fixed_mirror(env, s, ref->insn_idx, order);
	c = &s->cands[chosen];
	ent.loc = c->is_slot ? BPF_FRAME_LOC_STACK : BPF_FRAME_LOC_REG;
	ent.off = c->is_slot ? -(c->idx + 1) * BPF_REG_SIZE : c->idx;
	ent.res = c->res;
	return fixed_add(env, s, ent, ref->insn_idx);
}

/*
 * Place saved IRQ flags of rank @order: the stack slot they live in, in
 * place when it is this frame's, through a live pointer to it otherwise,
 * like any stack object. An earlier path's choice must be reused.
 */
static int place_irq(struct bpf_verifier_env *env, struct scratch *s,
		     const struct bpf_reference_state *ref, s16 order)
{
	struct bpf_verifier_state *st = env->cur_state;
	struct bpf_frame_desc_entry ent = { .order = order };
	const struct bpf_frame_desc_fixed *prev;
	const struct cand *c;
	int objframe, spi, k, nr, chosen = -1;

	if (!stack_object_find(st, ref, &objframe, &spi)) {
		verifier_bug(env, "no stack slot holds the irq flags saved at insn %d",
			     ref->insn_idx);
		return -EFAULT;
	}
	nr = find_object_cands(env, s, st, objframe, spi, true);
	if (nr < 0)
		return nr;
	prev = fixed_prev(s->build, ref->insn_idx);
	for (k = 0; prev && k < nr; k++) {
		if (cand_is(&s->cands[k], &prev->ent)) {
			chosen = k;
			break;
		}
	}
	/* the slot itself first, then any pointer to it */
	for (k = 0; chosen < 0 && k < nr; k++) {
		if (!s->cands[k].indirect || k == nr - 1)
			chosen = k;
	}
	/* no location on this path, or another one: the mirror, in place of whatever is listed */
	if (chosen < 0)
		return fixed_mirror(env, s, ref->insn_idx, order);
	c = &s->cands[chosen];
	ent.loc = c->is_slot ? BPF_FRAME_LOC_STACK : BPF_FRAME_LOC_REG;
	ent.off = c->is_slot ? -(c->idx + 1) * BPF_REG_SIZE : c->idx;
	ent.flags = c->indirect ? BPF_FRAME_ENT_INDIRECT : 0;
	ent.res = c->res;
	return fixed_add(env, s, ent, ref->insn_idx);
}

/*
 * The RCU read or preemption disabled sections the current frame entered and
 * has not left. The verifier keeps per frame how much of what was held at its
 * entry is held ever since, see release_context_state(): what the state holds
 * now on top of that is this frame's own.
 */
static u32 frame_sections(const struct bpf_verifier_state *st, bool rcu)
{
	const struct bpf_func_state *frame = st->frame[st->curframe];

	return rcu ? st->active_rcu_locks - frame->entry_rcu_locks :
		     st->active_preempt_locks - frame->entry_preempt_locks;
}

/*
 * Sections have no location; the frame that entered them leaves them, and
 * retracts those of its callers it left, by count: a @retract entry.
 */
static int place_section(struct bpf_verifier_env *env, struct scratch *s, u8 kind, u32 count,
			 bool retract)
{
	struct bpf_frame_desc_entry ent = { .order = retract ? ORDER_RETRACT : ORDER_SECTION,
					    .loc = BPF_FRAME_LOC_NONE,
					    .flags = retract ? BPF_FRAME_ENT_RETRACT : 0 };
	struct bpf_resource res;
	int ret;

	if (!count)
		return 0;
	if (count > S16_MAX) {
		verbose(env, "frame_desc: frame%d is in too many nested sections\n",
			env->cur_state->curframe);
		return -E2BIG;
	}
	memset(&res, 0, sizeof(res));
	res.kind = kind;
	ret = resource_intern(env, &res);
	if (ret < 0)
		return ret;
	ent.off = count;
	ent.res = ret;
	return fixed_add(env, s, ent, ACQ_NONE);
}

/* The same lock or flags at the same place; the rank is renumbered after a merge. */
static bool fixed_same(const struct bpf_frame_desc_fixed *a, const struct bpf_frame_desc_fixed *b)
{
	return a->ent.loc == b->ent.loc && a->ent.off == b->ent.off && a->ent.res == b->ent.res &&
	       a->ent.flags == b->ent.flags;
}

/* Insert @e at @pos of the fixed list of @b. */
static int fixed_insert(struct bpf_frame_desc_build *b, int pos, const struct bpf_frame_desc_fixed *e)
{
	struct bpf_frame_desc_fixed *fixed;

	fixed = kvrealloc(b->fixed, array_size(b->nr_fixed + 1, sizeof(*fixed)), GFP_KERNEL_ACCOUNT);
	if (!fixed)
		return -ENOMEM;
	memmove(&fixed[pos + 1], &fixed[pos], (b->nr_fixed - pos) * sizeof(*fixed));
	fixed[pos] = *e;
	b->fixed = fixed;
	b->nr_fixed++;
	return 0;
}

/*
 * Merge the locks, IRQ flags and sections this path places, in acquisition
 * order, into the list of the descriptor. A lock or flags an earlier path
 * placed elsewhere, or did not place, or that this path does not place, is
 * released from its mirror, which is NULL where it is not held; the list
 * keeps the entry and its place in the order. The order of the paths has to
 * agree, as the unwinder releases in one order whatever is held. The
 * sections of the frame have no location to mirror and must agree.
 */
static int fixed_merge(struct bpf_verifier_env *env, struct scratch *s)
{
	struct bpf_frame_desc_build *b = s->build;
	int i, k, last = -1, order = 0, ret;

	for (k = 0; k < b->nr_fixed; k++)
		b->fixed[k].seen = false;
	for (i = 0; i < s->nr_fixed; i++) {
		const struct bpf_frame_desc_fixed *e = &s->fixed[i];

		if (e->acq == ACQ_NONE) {
			for (k = 0; k < b->nr_fixed; k++)
				if (b->fixed[k].acq == ACQ_NONE && b->fixed[k].ent.res == e->ent.res &&
				    b->fixed[k].ent.flags == e->ent.flags)
					break;
			if (k == b->nr_fixed || b->fixed[k].ent.off != e->ent.off)
				goto sections;
			b->fixed[k].seen = true;
			continue;
		}
		for (k = 0; k < b->nr_fixed; k++)
			if (b->fixed[k].acq == e->acq)
				break;
		if (k == b->nr_fixed) {
			/* not held on an earlier path: insert it after what precedes it here */
			ret = fixed_insert(b, last + 1, e);
			ret = ret ?: mirror_need(env, s->subprog, e->acq);
			if (ret)
				return ret;
			k = last + 1;
		} else if (k <= last) {
			verbose(env, "frame_desc: frame%d insn %d: holds locks or irq flags in different orders on different paths\n",
				env->cur_state->curframe, s->pc);
			return -EINVAL;
		} else if (!fixed_same(&b->fixed[k], e)) {
			ret = mirror_need(env, s->subprog, e->acq);
			if (ret)
				return ret;
		}
		b->fixed[k].seen = true;
		last = k;
	}
	for (k = 0; k < b->nr_fixed; k++) {
		if (b->fixed[k].seen)
			continue;
		if (b->fixed[k].acq == ACQ_NONE)
			goto sections;
		ret = mirror_need(env, s->subprog, b->fixed[k].acq);
		if (ret)
			return ret;
	}
	/* the list is in acquisition order: rank it again */
	for (k = 0; k < b->nr_fixed; k++)
		if (b->fixed[k].acq != ACQ_NONE)
			b->fixed[k].ent.order = order++;
	return 0;
sections:
	verbose(env, "frame_desc: frame%d insn %d: is in different sections on another path\n",
		env->cur_state->curframe, s->pc);
	return -EINVAL;
}

/*
 * Place the locks, IRQ flags and sections the frame holds on this path.
 * Unlike objects, these are released in order: the verifier keeps locks and
 * IRQ flags in acquisition order, and the frame ranks its own from 0, latest
 * released first, with the flags of an irqsave lock right before the lock,
 * which restores them. And they cannot be merged through NULL: every path
 * reaching the site places the same entries, or what differs is mirrored,
 * see fixed_merge().
 */
static int place_fixed(struct bpf_verifier_env *env, struct scratch *s)
{
	struct bpf_verifier_state *st = env->cur_state;
	struct bpf_frame_desc_build *b = s->build;
	int i, order = 0, ret;
	size_t sz;

	s->nr_fixed = 0;
	for (i = 0; i < st->acquired_refs; i++) {
		const struct bpf_reference_state *ref = &st->refs[i];

		if (ref->frameno != st->curframe)
			continue;
		if (ref->type & REF_TYPE_LOCK_MASK)
			ret = place_lock(env, s, ref, order++);
		else if (ref->type == REF_TYPE_IRQ)
			ret = place_irq(env, s, ref, order++);
		else
			continue;
		ret = ret ?: build_add_mirror(b, ref->insn_idx);
		if (ret)
			return ret;
	}
	ret = place_section(env, s, BPF_RESOURCE_RCU, frame_sections(st, true), false);
	ret = ret ?: place_section(env, s, BPF_RESOURCE_PREEMPT, frame_sections(st, false), false);
	ret = ret ?: place_section(env, s, BPF_RESOURCE_RCU,
				   st->frame[st->curframe]->rcu_released_below, true);
	ret = ret ?: place_section(env, s, BPF_RESOURCE_PREEMPT,
				   st->frame[st->curframe]->preempt_released_below, true);
	if (ret)
		return ret;

	sz = s->nr_fixed * sizeof(s->fixed[0]);
	if (b->visits)
		return fixed_merge(env, s);
	/* A visit that failed later on may have placed these already. */
	kvfree(b->fixed);
	b->fixed = sz ? kvmemdup(s->fixed, sz, GFP_KERNEL_ACCOUNT) : NULL;
	if (sz && !b->fixed)
		return -ENOMEM;
	b->nr_fixed = s->nr_fixed;
	return 0;
}

/*
 * List reference @ref the frame owns at one of its @nr candidate locations on
 * this path, the one the paths agree on, see choose(). The other candidates
 * hold copies. A reference no live location holds is one the program never
 * reads again, which would leak at the site: it is released from its mirror.
 */
static int place_ref(struct bpf_verifier_env *env, struct scratch *s,
		     const struct bpf_reference_state *ref, int nr)
{
	const char *why;
	int k, chosen;

	if (!nr)
		return conflict(env, s, ref->insn_idx, "is held at no live location");
	chosen = choose(env, s, nr, ref->insn_idx);
	why = chosen == -ENOENT ? "has no location free to be released from" :
	      chosen == -EEXIST ? "is at different locations on different paths" :
	      chosen == -EINVAL ? "shares a location with another resource on another path" : NULL;
	if (why)
		return conflict(env, s, ref->insn_idx, why);
	for (k = 0; k < nr; k++) {
		const struct cand *c = &s->cands[k];
		int idx = cand_idx(c);

		s->class[idx] = k == chosen ? CLASS_RES : CLASS_COPY;
		s->res[idx] = c->res;
		s->acq[idx] = ref->insn_idx;
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
	s->subprog = frame->subprogno;
	s->live_regs = env->insn_aux_data[s->pc].live_regs_before;
	if (!regs_saved)
		s->live_regs &= CALLEE_SAVED_REGS;
	s->live_stack = env->insn_aux_data[s->pc].live_stack_before;
	memset(s->class, 0, sizeof(s->class));
	b = build_get(env, s->pc, bpf_stack_nr_slots(frame), slot);
	if (!b)
		return -ENOMEM;
	b->regs_saved = regs_saved;
	s->build = b;

	ret = place_fixed(env, s);
	if (ret)
		return ret;

	/* List every reference the frame owns; what it holds for others are copies. */
	for (i = 0; i < st->acquired_refs; i++) {
		const struct bpf_reference_state *ref = &st->refs[i];
		bool owned = ref->frameno == st->curframe;
		int objframe, spi;

		if (ref->type != REF_TYPE_PTR) {
			/* The pointers to a lock or saved flags of another frame are copies too. */
			if (owned)
				continue;
			if (ref->type == REF_TYPE_IRQ)
				nr = stack_object_find(st, ref, &objframe, &spi) ?
				     find_object_cands(env, s, st, objframe, spi, false) : 0;
			else
				nr = find_lock_cands(env, s, frame, ref);
			if (nr < 0)
				return nr;
			place_copy(s, nr);
			continue;
		}
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
		ret = ret ?: build_add_mirror(b, ref->insn_idx);
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
		ret = merge(env, s, dst, s->class[k], s->res[k], s->acq[k], s->indirect[k]);
		if (ret)
			return ret;
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

/*
 * Record where the subprog obtains the handle of the resource refs[@idx] the
 * current frame just acquired: in R@regno @after the acquiring insn, the
 * pointer a call returns, or in front of it, the pointer to a stack object
 * or to a lock the call takes. The mirror of the resource, should a site
 * need it, is stored there, and classified from what the register holds.
 */
int bpf_frame_desc_record_acquire(struct bpf_verifier_env *env, int idx, int regno, bool after)
{
	struct bpf_verifier_state *st = env->cur_state;
	struct bpf_func_state *frame = st->frame[st->curframe];
	const struct bpf_reference_state *ref = &st->refs[idx];
	struct bpf_mirror *m;
	int objframe, spi;

	if (!env->describe_frames || st->speculative)
		return 0;
	m = mirror_get(env, frame->subprogno, env->insn_idx);
	if (!m)
		return -ENOMEM;
	if (m->reg.type == NOT_INIT) {
		if (after) {
			m->kind = MIRROR_KIND_PTR;
			m->reg = frame->regs[regno];
		} else if (ref->type & REF_TYPE_LOCK_MASK) {
			m->kind = MIRROR_KIND_LOCK;
			m->lock_kind = lock_kind(ref->type);
			m->reg = frame->regs[regno];
		} else if (stack_object_find(st, ref, &objframe, &spi)) {
			const struct bpf_stack_state *slot = bpf_stack_slot(st->frame[objframe], spi);

			m->kind = slot->slot_type[BPF_REG_SIZE - 1];
			m->reg = slot->spilled_ptr;
		}
	}
	return mirror_store_add(m, env->insn_idx, after ? MIRROR_AFTER : MIRROR_BEFORE, regno, 0);
}

/*
 * The class of the resource mirror @m holds, from what its acquisition
 * returned. The mirror of a lock holds the pointer to the lock the call took,
 * whether the lock has a fixed address or not: a class with no delta.
 */
static int mirror_resource(struct bpf_verifier_env *env, struct bpf_mirror *m)
{
	struct bpf_stack_state slot = { .spilled_ptr = m->reg };

	switch (m->kind) {
	case MIRROR_KIND_PTR:
		if (m->reg.type == NOT_INIT)
			break;
		return resource_of_reg(env, &m->reg);
	case MIRROR_KIND_LOCK:
		return resource_of_lock(env, &m->reg, m->lock_kind);
	default:
		slot.slot_type[BPF_REG_SIZE - 1] = m->kind;
		return resource_of_object(env, &slot);
	}
	verbose(env, "frame_desc: the reference acquired at insn %d is held by no register or stack slot of its owner\n",
		m->acq);
	return -EINVAL;
}

/* The register among R1-R5 that holds the handle of @ref at the current insn, or -1. */
static int handle_regno(struct bpf_verifier_env *env, struct bpf_verifier_state *st,
			const struct bpf_reference_state *ref)
{
	const struct bpf_reg_state *regs = st->frame[st->curframe]->regs;
	int objframe = -1, spi = -1, k;

	if (ref->type == REF_TYPE_PTR || ref->type == REF_TYPE_IRQ)
		stack_object_find(st, ref, &objframe, &spi);
	for (k = BPF_REG_1; k <= BPF_REG_5; k++) {
		if (ref->type & REF_TYPE_LOCK_MASK ? reg_is_lock(&regs[k], ref) :
		    objframe >= 0 ? reg_points_at(&regs[k], objframe, spi) :
		    reg_is_ref(&regs[k], ref->id))
			return k;
	}
	return -1;
}

/* Append @acq to the list of what the callee of frame @c released, see record_return(). */
static int frame_released_add(struct bpf_func_state *frame, u32 acq, u16 res, u8 reg, bool owner)
{
	struct bpf_released_ref *rel;

	rel = krealloc_array(frame->released == ZERO_SIZE_PTR ? NULL : frame->released,
			     frame->nr_released + 1, sizeof(*rel), GFP_KERNEL_ACCOUNT);
	if (!rel)
		return -ENOMEM;
	rel[frame->nr_released++] = (struct bpf_released_ref) { .acq = acq, .res = res, .reg = reg,
								.owner = owner };
	frame->released = rel;
	return 0;
}

/* The class of resource @ref, which the current frame releases from R@regno. */
static int resource_of_handle(struct bpf_verifier_env *env, struct bpf_verifier_state *st,
			      const struct bpf_reference_state *ref, int regno)
{
	const struct bpf_reg_state *reg = &st->frame[st->curframe]->regs[regno];
	int objframe, spi;

	if (ref->type & REF_TYPE_LOCK_MASK)
		return resource_of_lock(env, reg, lock_kind(ref->type));
	if (stack_object_find(st, ref, &objframe, &spi))
		return resource_of_object(env, bpf_stack_slot(st->frame[objframe], spi));
	return resource_of_reg(env, reg);
}

/*
 * The register in which frame @c of @st holds the handle of @ref while its
 * callee runs: one of its own R6-R9, or the one it passed the handle in,
 * which the callee's entry recorded; 0 for none.
 */
static u8 frame_handle_reg(struct bpf_verifier_state *st, int c, const struct bpf_reference_state *ref)
{
	const struct bpf_func_state *frame = st->frame[c], *callee = st->frame[c + 1];
	int objframe = -1, spi = -1, k;

	if (ref->type == REF_TYPE_PTR || ref->type == REF_TYPE_IRQ)
		stack_object_find(st, ref, &objframe, &spi);
	for (k = BPF_REG_6; k <= BPF_REG_9; k++) {
		if (ref->type & REF_TYPE_LOCK_MASK ? reg_is_lock(&frame->regs[k], ref) :
		    objframe >= 0 ? reg_points_at(&frame->regs[k], objframe, spi) :
		    reg_is_ref(&frame->regs[k], ref->id))
			return k;
	}
	for (k = 0; k < MAX_BPF_FUNC_REG_ARGS; k++) {
		const struct bpf_arg_ref *arg = &callee->arg_refs[k];

		if (objframe >= 0 ? arg->stack && arg->frameno == objframe &&
				    arg->off == -(spi + 1) * BPF_REG_SIZE :
		    !arg->stack && arg->id && arg->id == ref->id)
			return BPF_REG_1 + k;
	}
	return 0;
}

static int retraction_add(struct bpf_verifier_env *env, u32 rel, u16 subprog, u16 res, u8 reg)
{
	struct bpf_retraction *r;
	u32 i, cnt = env->retraction_cnt;

	for (i = 0; i < cnt; i++)
		if (env->retractions[i].rel == rel && env->retractions[i].reg == reg)
			return 0;
	r = kvrealloc(env->retractions, array_size(cnt + 1, sizeof(*r)), GFP_KERNEL_ACCOUNT);
	if (!r)
		return -ENOMEM;
	r[cnt] = (struct bpf_retraction) { .rel = rel, .subprog = subprog, .res = res, .reg = reg };
	env->retractions = r;
	env->retraction_cnt = cnt + 1;
	return 0;
}

/*
 * Record that the current insn releases the resource refs[@idx], before it
 * is released. A release in the frame that owns it clears the mirror, with
 * the handle in the register the insn takes it from, so that the mirror says
 * exactly whether the resource is held. A release of what a frame below owns
 * is retracted: the insn puts the handle into a retraction slot of the frame
 * first, and the frames in between are told, to retract it the same way
 * once their calls return, see bpf_frame_desc_record_return(). A callback
 * leaves into the kernel code that ran it, so a release in one cannot be
 * told to the frames below at all: the caller of the kernel code finds out
 * from its state after the call, which is enough unless the owner is below
 * it, and a mirror of the reference cannot be kept up to date.
 */
int bpf_frame_desc_record_release(struct bpf_verifier_env *env, int idx)
{
	struct bpf_verifier_state *st = env->cur_state;
	const struct bpf_reference_state *ref = &st->refs[idx];
	int f = st->curframe, g = ref->frameno, c, cb = -1, regno, res, ret;
	struct bpf_mirror *m;

	if (!env->describe_frames || st->speculative)
		return 0;
	/* every release but a NULL check, which records nothing, is a call */
	if (verifier_bug_if(!site_insn_ok(&env->prog->insnsi[env->insn_idx]), env,
			    "release at insn %d is not a call", env->insn_idx))
		return -EFAULT;
	regno = handle_regno(env, st, ref);
	if (g == f) {
		m = mirror_get(env, st->frame[f]->subprogno, ref->insn_idx);
		if (!m)
			return -ENOMEM;
		if (regno < 0)
			return 0;
		return mirror_store_add(m, env->insn_idx, MIRROR_CLEAR, regno, 0);
	}
	if (verifier_bug_if(regno < 0, env, "release at insn %d takes the handle from no register",
			    env->insn_idx))
		return -EFAULT;
	for (c = f; c > g; c--)
		if (st->frame[c]->in_callback_fn)
			cb = c;
	if (cb >= 0 && g < cb - 1) {
		verbose(env, "frame_desc: insn %d: the callback called at insn %d releases a reference of a frame below its caller, which the unwinder cannot follow\n",
			env->insn_idx, st->frame[cb]->callsite);
		return -EINVAL;
	}
	if (cb >= 0) {
		m = mirror_get(env, st->frame[g]->subprogno, ref->insn_idx);
		if (!m)
			return -ENOMEM;
		m->released_by_callback = true;
	}
	res = resource_of_handle(env, st, ref, regno);
	if (res < 0)
		return res;
	ret = retraction_add(env, env->insn_idx, st->frame[f]->subprogno, res, regno);
	if (ret)
		return ret;
	/* how much the frames that were entered with it retract at most */
	for (c = 0; c <= f; c++) {
		struct bpf_subprog_info *sub = &env->subprog_info[st->frame[c]->subprogno];

		if (idx < st->frame[c]->entry_refs)
			sub->max_retract = max_t(u32, sub->max_retract,
						 min_t(u32, st->frame[c]->refs_released_below + 1,
						       U8_MAX));
	}
	for (c = max(g, 0); c < f; c++) {
		ret = frame_released_add(st->frame[c], ref->insn_idx, res,
					 frame_handle_reg(st, c, ref), c == g);
		if (ret)
			return ret;
	}
	return 0;
}

static struct bpf_call_ref *call_ref_get(struct bpf_verifier_env *env, u32 call, u32 acq,
					 u32 subprog)
{
	struct bpf_call_ref *r;
	u32 i, cnt = env->call_ref_cnt;

	for (i = 0; i < cnt; i++)
		if (env->call_refs[i].call == call && env->call_refs[i].acq == acq)
			return &env->call_refs[i];
	r = kvrealloc(env->call_refs, array_size(cnt + 1, sizeof(*r)), GFP_KERNEL_ACCOUNT);
	if (!r)
		return NULL;
	env->call_refs = r;
	env->call_ref_cnt = cnt + 1;
	r = &r[cnt];
	memset(r, 0, sizeof(*r));
	r->call = call;
	r->acq = acq;
	r->subprog = subprog;
	r->r0_ok = true;
	r->slots_ok = ~0ULL;
	return r;
}

/* The stack slots of @frame that hold the pointer of reference @id, or are zero when @id is 0. */
static u64 frame_slots(struct bpf_verifier_env *env, const struct bpf_func_state *frame, int id)
{
	u64 mask = 0;
	int k;

	for (k = 0; k < bpf_stack_nr_slots(frame) && k < DISC_SLOTS; k++) {
		const struct bpf_stack_state *slot = bpf_stack_slot(frame, k);

		if (id ? stack_slot_ref(env, slot, id, false) == 0 : stack_slot_is_null(slot))
			mask |= BIT_ULL(k);
	}
	return mask;
}

/*
 * A call at @call_idx returned to the frame of @st, which @callee was the
 * frame of, and the state is what it is after the call. The callee may have
 * released a reference the frame owns, which the frame was told of, or
 * returned one, which the frame owns now: the mirror of the reference has to
 * be cleared or filled after the call, and when the callee does either only
 * on some paths, from where the paths tell apart, R0 or a stack slot of the
 * frame that holds the reference on the one kind of path and 0 on the other.
 * What the call does is recorded per path; what to emit is settled once
 * every path has returned, see mirror_resolve_calls().
 */
int bpf_frame_desc_record_return(struct bpf_verifier_env *env, struct bpf_verifier_state *st,
				 int call_idx, const struct bpf_func_state *callee)
{
	struct bpf_func_state *frame = st->frame[st->curframe];
	const struct bpf_reg_state *regs = frame->regs;
	struct bpf_call_ref *r;
	struct bpf_mirror *m;
	u32 i;

	if (!env->describe_frames || st->speculative)
		return 0;
	for (i = 0; i < frame->nr_released; i++) {
		const struct bpf_released_ref *e = &frame->released[i];

		r = call_ref_get(env, call_idx, e->acq, frame->subprogno);
		if (!r)
			return -ENOMEM;
		r->released = true;
		r->owner |= e->owner;
		r->r0_ok &= bpf_register_is_null((struct bpf_reg_state *)&regs[BPF_REG_0]);
		r->slots_ok &= frame_slots(env, frame, 0);
		/* a frame below owns it: retracted from the register it was passed in */
		r->res = e->res;
		r->reg = !r->reg ? e->reg ?: U8_MAX : r->reg == e->reg ? r->reg : U8_MAX;
	}
	frame->nr_released = 0;
	for (i = 0; i < st->acquired_refs; i++) {
		const struct bpf_reference_state *ref = &st->refs[i];
		bool in_r0 = ref->type == REF_TYPE_PTR && reg_is_ref(&regs[BPF_REG_0], ref->id);
		u64 slots = ref->type == REF_TYPE_PTR ? frame_slots(env, frame, ref->id) : 0;

		if (ref->frameno > (int)st->curframe)
			continue;
		r = call_ref_get(env, call_idx, ref->insn_idx, frame->subprogno);
		if (!r)
			return -ENOMEM;
		r->held = true;
		r->r0_ok &= in_r0;
		r->slots_ok &= slots;
		if (ref->frameno != st->curframe)
			continue;
		r->owner = true;
		if (i < callee->entry_refs)
			continue;
		/* the callee returned it: what classifies it is where it is now */
		r->transferred = true;
		m = mirror_get(env, frame->subprogno, ref->insn_idx);
		if (!m)
			return -ENOMEM;
		if (m->reg.type != NOT_INIT || ref->type != REF_TYPE_PTR)
			continue;
		m->kind = MIRROR_KIND_PTR;
		if (in_r0)
			m->reg = regs[BPF_REG_0];
		else if (slots)
			m->reg = bpf_stack_slot(frame, __ffs64(slots))->spilled_ptr;
	}
	return 0;
}

/*
 * Settle what the calls of the owner subprog do to mirror @m: a call that
 * returned the resource, or released it on some paths and not on others,
 * refreshes the mirror from R0 or from a stack slot that tells the paths
 * apart; a call that released it on every path clears the mirror.
 */
static int mirror_resolve_calls(struct bpf_verifier_env *env, struct bpf_mirror *m)
{
	u32 i;
	int ret;

	for (i = 0; i < env->call_ref_cnt; i++) {
		const struct bpf_call_ref *r = &env->call_refs[i];

		if (r->acq != m->acq || r->subprog != m->subprog || !r->owner)
			continue;
		if (r->transferred || (r->released && r->held)) {
			if (r->r0_ok)
				ret = mirror_store_add(m, r->call, MIRROR_AFTER, BPF_REG_0, 0);
			else if (r->slots_ok)
				ret = mirror_store_add(m, r->call, MIRROR_AFTER_SLOT, 0,
						       -(__ffs64(r->slots_ok) + 1) * BPF_REG_SIZE);
			else
				goto undecided;
		} else if (r->released) {
			ret = mirror_store_add(m, r->call, MIRROR_CLEAR_AFTER, 0, 0);
		} else {
			continue;
		}
		if (ret)
			return ret;
	}
	return 0;
undecided:
	verbose(env, "frame_desc: the call at insn %d %s the reference acquired at insn %d, and neither R0 nor a stack slot tells on every path\n",
		env->call_refs[i].call, env->call_refs[i].transferred ? "returns" : "may release",
		m->acq);
	return -EINVAL;
}

/* Does anything fill the mirror? A clear alone describes nothing. */
static bool mirror_is_written(const struct bpf_mirror *m)
{
	u32 i;

	for (i = 0; i < m->nr_stores; i++)
		if (m->stores[i].point != MIRROR_CLEAR && m->stores[i].point != MIRROR_CLEAR_AFTER)
			return true;
	return false;
}

/* The retraction array of @subprog for handles of the class of @res, made as needed. */
static struct bpf_retract_array *retract_array_get(struct bpf_verifier_env *env, u16 subprog,
						   u16 res)
{
	u8 hclass = handle_class(env, res);
	struct bpf_retract_array *a;
	u32 i, cnt = env->retract_array_cnt;

	for (i = 0; i < cnt; i++)
		if (env->retract_arrays[i].subprog == subprog && env->retract_arrays[i].hclass == hclass)
			return &env->retract_arrays[i];
	a = kvrealloc(env->retract_arrays, array_size(cnt + 1, sizeof(*a)), GFP_KERNEL_ACCOUNT);
	if (!a)
		return NULL;
	env->retract_arrays = a;
	env->retract_array_cnt = cnt + 1;
	a = &a[cnt];
	*a = (struct bpf_retract_array) { .subprog = subprog, .res = res, .hclass = hclass };
	return a;
}

/* The resources a call passed in one register that the callee released, see call_groups(). */
struct retract_group {
	u8 reg;
	u16 res;
	bool cond;	/* released on some paths only: R0 tells */
};

#define MAX_GROUPS	(BPF_REG_9 - BPF_REG_1 + 1)

/*
 * The registers the call at @call of @subprog passed resources in that the
 * callee released, of a frame below the caller: each is retracted once the
 * call returns, from a scratch slot when the register is caller-saved. The
 * resources passed in one register have to be of one class of handle, and
 * where one of them is released on some paths only, R0 has to tell.
 */
static int call_groups(struct bpf_verifier_env *env, u32 call, u16 subprog,
		       struct retract_group *g)
{
	u32 i;
	int n = 0, k;

	for (i = 0; i < env->call_ref_cnt; i++) {
		const struct bpf_call_ref *r = &env->call_refs[i];

		if (r->call != call || r->subprog != subprog || r->owner || !r->released)
			continue;
		if (r->reg < BPF_REG_1 || r->reg > BPF_REG_9) {
			verbose(env, "frame_desc: the call at insn %d releases the reference acquired at insn %d of a frame below, passed in no one register on every path\n",
				r->call, r->acq);
			return -EINVAL;
		}
		for (k = 0; k < n; k++)
			if (g[k].reg == r->reg)
				break;
		if (k == n) {
			g[n++] = (struct retract_group) { .reg = r->reg, .res = r->res, .cond = r->held };
			continue;
		}
		g[k].cond |= r->held;
		if (handle_class(env, g[k].res) != handle_class(env, r->res)) {
			verbose(env, "frame_desc: the call at insn %d releases resources of different kinds passed in R%d\n",
				r->call, r->reg);
			return -EINVAL;
		}
	}
	/* R0 has to tell for every resource of a group that is retracted on some paths only */
	for (i = 0; i < env->call_ref_cnt; i++) {
		const struct bpf_call_ref *r = &env->call_refs[i];

		if (r->call != call || r->subprog != subprog || r->owner || !r->released)
			continue;
		for (k = 0; g[k].reg != r->reg; k++)
			;
		if (g[k].cond && !r->r0_ok) {
			verbose(env, "frame_desc: the call at insn %d may release the reference acquired at insn %d of a frame below, and R0 does not tell on every path\n",
				r->call, r->acq);
			return -EINVAL;
		}
	}
	return n;
}

/* Is the record @i the first of its call? The groups of a call are made once. */
static bool call_ref_first(struct bpf_verifier_env *env, u32 i)
{
	u32 j;

	for (j = 0; j < i; j++)
		if (env->call_refs[j].call == env->call_refs[i].call)
			return false;
	return true;
}

/*
 * The retractions the frames of subprog @s make after their calls returned,
 * see bpf_frame_desc_record_return(): the arrays they need, and the scratch
 * slots a call needs at most for the handles in caller-saved registers.
 */
static int retract_resolve_calls(struct bpf_verifier_env *env, int s)
{
	struct bpf_subprog_info *sub = &env->subprog_info[s];
	struct retract_group g[MAX_GROUPS];
	u32 i, scratch;
	int n, k;

	for (i = 0; i < env->call_ref_cnt; i++) {
		if (env->call_refs[i].subprog != s || !call_ref_first(env, i))
			continue;
		n = call_groups(env, env->call_refs[i].call, s, g);
		if (n < 0)
			return n;
		for (k = 0, scratch = 0; k < n; k++) {
			if (!retract_array_get(env, s, g[k].res))
				return -ENOMEM;
			scratch += g[k].reg < BPF_REG_6;
		}
		sub->retract_scratch_cnt = max(sub->retract_scratch_cnt, scratch);
	}
	return 0;
}

/* Replace the listings of the resource acquired at @acq in @b by its mirror entry @ent. */
static int build_mirror(struct bpf_frame_desc_build *b, u32 acq, struct bpf_frame_desc_entry ent)
{
	struct bpf_frame_desc_entry *extra;
	int l;

	for (l = 0; l < BPF_REG_10 + b->nr_slots; l++) {
		struct bpf_frame_desc_loc *loc = l < BPF_REG_10 ? &b->regs[l] : &b->slots[l - BPF_REG_10];

		if (loc->state == LOC_RES && loc->acq == acq)
			loc->state = LOC_OTHER;
	}
	for (l = 0; l < b->nr_fixed; l++) {
		if (b->fixed[l].acq != acq)
			continue;
		ent.order = b->fixed[l].ent.order;
		b->fixed[l].ent = ent;
		return 0;
	}
	extra = kvrealloc(b->extra, array_size(b->nr_extra + 1, sizeof(*extra)), GFP_KERNEL_ACCOUNT);
	if (!extra)
		return -ENOMEM;
	extra[b->nr_extra++] = ent;
	b->extra = extra;
	return 0;
}

/* The subprog whose frame build @i describes: an insn, or the entry guard of a subprog. */
static struct bpf_frame_desc_build *build_nth(struct bpf_verifier_env *env, u32 i, int *subprog)
{
	u32 len = env->prog->len;

	if (i < 2 * len) {
		*subprog = insn_subprog(env, i / 2);
		return i & 1 ? env->insn_aux_data[i / 2].guard_desc : env->insn_aux_data[i / 2].frame_desc;
	}
	*subprog = i - 2 * len;
	return env->subprog_info[i - 2 * len].entry_guard;
}

/*
 * After the main pass, once every release and every return has been seen and
 * the stack is final: reserve the mirrors the sites need, settle what the
 * calls do to them, and make each the only listing of its resource in every
 * descriptor of the owner subprog that lists it. A mirror of what a callback
 * released cannot be kept up to date, see bpf_frame_desc_record_release(),
 * and rejects the program.
 */
int bpf_frame_desc_resolve(struct bpf_verifier_env *env)
{
	u32 i, k;
	int ret;

	for (i = 0; i < env->mirror_cnt; i++) {
		struct bpf_mirror *m = &env->mirrors[i];

		if (!m->needed)
			continue;
		if (m->released_by_callback) {
			verbose(env, "frame_desc: the reference acquired at insn %d is released by a callback and no location describes it on every path after the call\n",
				m->acq);
			return -EINVAL;
		}
		ret = mirror_resource(env, m);
		if (ret < 0)
			return ret;
		m->res = ret;
		ret = mirror_resolve_calls(env, m);
		if (ret)
			return ret;
		if (!mirror_is_written(m)) {
			verbose(env, "frame_desc: the reference acquired at insn %d is obtained by no call of its owner\n",
				m->acq);
			return -EINVAL;
		}
		ret = bpf_reserve_stack_slots(env, m->subprog, 1, &m->off);
		ret = ret ?: bpf_stack_slot_init(env, m->subprog, m->off, 0);
		if (ret)
			return ret;
	}

	/* The retraction arrays: what a subprog's frames release of their callers'. */
	for (i = 0; i < env->retraction_cnt; i++) {
		const struct bpf_retraction *r = &env->retractions[i];

		if (!retract_array_get(env, r->subprog, r->res))
			return -ENOMEM;
	}
	for (i = 0; i < env->subprog_cnt; i++) {
		ret = retract_resolve_calls(env, i);
		if (ret)
			return ret;
	}
	for (i = 0; i < env->retract_array_cnt; i++) {
		struct bpf_retract_array *a = &env->retract_arrays[i];
		struct bpf_subprog_info *sub = &env->subprog_info[a->subprog];
		s16 off;

		if (sub->max_retract > BPF_UNWIND_MAX_RETRACT) {
			verbose(env, "frame_desc: subprog %d releases more than %d references of its callers\n",
				a->subprog, BPF_UNWIND_MAX_RETRACT);
			return -EINVAL;
		}
		a->n = sub->max_retract;
		ret = bpf_reserve_stack_slots(env, a->subprog, a->n + 1, &off);
		for (k = 0; !ret && k <= a->n; k++)
			ret = bpf_stack_slot_init(env, a->subprog, off - k * BPF_REG_SIZE, 0);
		if (ret)
			return ret;
		a->cnt_off = off;
		a->base = off - a->n * BPF_REG_SIZE;
		env->retraction_slots += a->n + 1;
	}
	for (i = 0; i < env->subprog_cnt; i++) {
		struct bpf_subprog_info *sub = &env->subprog_info[i];

		if (!sub->retract_scratch_cnt)
			continue;
		ret = bpf_reserve_stack_slots(env, i, sub->retract_scratch_cnt + 1,
					      &sub->retract_scratch);
		if (ret)
			return ret;
		sub->retract_tmp = sub->retract_scratch - sub->retract_scratch_cnt * BPF_REG_SIZE;
	}

	/* Every descriptor, the guards the verifier adds may_goto for included. */
	for (i = 0; i < 2 * env->prog->len + env->subprog_cnt; i++) {
		struct bpf_frame_desc_build *b;
		int subprog;

		b = build_nth(env, i, &subprog);
		if (!b)
			continue;
		for (k = 0; k < env->retract_array_cnt; k++) {
			const struct bpf_retract_array *a = &env->retract_arrays[k];
			struct bpf_frame_desc_entry *extra;
			int n;

			if (a->subprog != subprog)
				continue;
			extra = kvrealloc(b->extra, array_size(b->nr_extra + a->n, sizeof(*extra)),
					  GFP_KERNEL_ACCOUNT);
			if (!extra)
				return -ENOMEM;
			b->extra = extra;
			for (n = 0; n < a->n; n++) {
				extra[b->nr_extra++] = (struct bpf_frame_desc_entry) {
					.loc = BPF_FRAME_LOC_STACK, .flags = BPF_FRAME_ENT_RETRACT,
					.res = a->res, .off = a->base + n * BPF_REG_SIZE,
					.order = ORDER_RETRACT,
				};
			}
		}
		for (k = 0; k < b->nr_mirrors; k++) {
			struct bpf_mirror *m = mirror_find(env, subprog, b->mirrors[k]);
			struct bpf_frame_desc_entry ent;

			if (!m || !m->needed)
				continue;
			ent = (struct bpf_frame_desc_entry) {
				.loc = BPF_FRAME_LOC_STACK,
				.flags = BPF_FRAME_ENT_INDIRECT | BPF_FRAME_ENT_NULLABLE,
				.res = m->res, .off = m->off, .order = resource_order(env, m->res),
			};
			ret = build_mirror(b, m->acq, ent);
			if (ret)
				return ret;
		}
	}
	return 0;
}

/* What is emitted at an insn of the current image, in this order; see emit_before(). */
enum {
	EMIT_STORE_BEFORE,	/* the mirror from the register, in front of the insn */
	EMIT_CLEAR,		/* the mirror, in front of a release */
	EMIT_RETRACT,		/* the handle into the retraction array, in front of a release */
	EMIT_SCRATCH,		/* the handle into a scratch slot, in front of a call */
	EMIT_STORE_AFTER,	/* the mirror from R0 */
	EMIT_STORE_AFTER_SLOT,	/* the mirror from a stack slot */
	EMIT_CLEAR_AFTER,	/* the mirror, after a call that released it */
	EMIT_COMMIT,		/* the handle a callee released into the retraction array */
};

struct emit_point {
	u32 insn;
	u8 kind;
	u8 reg;
	bool cond;	/* EMIT_COMMIT: only when R0 is 0 */
	s16 off;	/* the mirror, or the scratch slot */
	s16 src;	/* EMIT_STORE_AFTER_SLOT: the slot read */
	s16 base;	/* the retraction array */
	s16 cnt_off;
	s16 tmp;	/* EMIT_COMMIT from a scratch slot: where R0 waits */
};

static int point_cmp(const void *a, const void *b)
{
	const struct emit_point *x = a, *y = b;

	if (x->insn != y->insn)
		return x->insn < y->insn ? -1 : 1;
	return x->kind - y->kind;
}

static const u8 mirror_emit_kind[] = {
	[MIRROR_BEFORE] = EMIT_STORE_BEFORE,
	[MIRROR_CLEAR] = EMIT_CLEAR,
	[MIRROR_AFTER] = EMIT_STORE_AFTER,
	[MIRROR_AFTER_SLOT] = EMIT_STORE_AFTER_SLOT,
	[MIRROR_CLEAR_AFTER] = EMIT_CLEAR_AFTER,
};

/* Append the handle in R@reg to the retraction array: array[cnt] = reg; cnt += 8. */
static int emit_retract(struct bpf_insn *buf, const struct emit_point *p, u8 reg)
{
	int cnt = 0;

	buf[cnt++] = BPF_LDX_MEM(BPF_DW, BPF_REG_AX, BPF_REG_FP, p->cnt_off);
	buf[cnt++] = BPF_ALU64_REG(BPF_ADD, BPF_REG_AX, BPF_REG_FP);
	buf[cnt++] = BPF_STX_MEM(BPF_DW, BPF_REG_AX, reg, p->base);
	buf[cnt++] = BPF_LDX_MEM(BPF_DW, BPF_REG_AX, BPF_REG_FP, p->cnt_off);
	buf[cnt++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_AX, BPF_REG_SIZE);
	buf[cnt++] = BPF_STX_MEM(BPF_DW, BPF_REG_FP, BPF_REG_AX, p->cnt_off);
	return cnt;
}

/*
 * The insns that keep the mirrors and the retractions up to date, in front of
 * an insn of the current image, @n points from @p: the stores of the handle a
 * call takes, the clears of the releases, the retractions of the releases and
 * what a call keeps across it. A release insn reached with the references of
 * several mirrored acquisitions clears the first mirror whose value is the
 * handle released, so that two references to one object count right.
 */
static int emit_before(struct bpf_insn *buf, const struct emit_point *p, int n)
{
	int i, cnt = 0, clears = 0;

	for (i = 0; i < n; i++)
		clears += p[i].kind == EMIT_CLEAR;
	for (i = 0; i < n; i++) {
		switch (p[i].kind) {
		case EMIT_STORE_BEFORE:
		case EMIT_SCRATCH:
			buf[cnt++] = BPF_STX_MEM(BPF_DW, BPF_REG_FP, p[i].reg, p[i].off);
			break;
		case EMIT_CLEAR:
			if (clears == 1) {
				buf[cnt++] = BPF_ST_MEM(BPF_DW, BPF_REG_FP, p[i].off, 0);
				break;
			}
			buf[cnt++] = BPF_LDX_MEM(BPF_DW, BPF_REG_AX, BPF_REG_FP, p[i].off);
			buf[cnt++] = BPF_JMP_REG(BPF_JNE, BPF_REG_AX, p[i].reg, 2);
			buf[cnt++] = BPF_ST_MEM(BPF_DW, BPF_REG_FP, p[i].off, 0);
			buf[cnt++] = BPF_JMP_A(4 * (--clears));
			break;
		case EMIT_RETRACT:
			cnt += emit_retract(buf + cnt, &p[i], p[i].reg);
			break;
		}
	}
	return cnt;
}

/*
 * The insns that refresh the mirrors and commit the retractions after a call,
 * @n points from @p. A retraction from a caller-saved register goes through
 * the scratch slot, with R0 kept aside; one the callee makes only on some
 * paths is skipped where R0, which tells, holds the resource.
 */
static int emit_after(struct bpf_insn *buf, const struct emit_point *p, int n)
{
	int i, cnt = 0, start;

	for (i = 0; i < n; i++) {
		switch (p[i].kind) {
		case EMIT_STORE_AFTER:
			buf[cnt++] = BPF_STX_MEM(BPF_DW, BPF_REG_FP, p[i].reg, p[i].off);
			break;
		case EMIT_STORE_AFTER_SLOT:
			buf[cnt++] = BPF_LDX_MEM(BPF_DW, BPF_REG_AX, BPF_REG_FP, p[i].src);
			buf[cnt++] = BPF_STX_MEM(BPF_DW, BPF_REG_FP, BPF_REG_AX, p[i].off);
			break;
		case EMIT_CLEAR_AFTER:
			buf[cnt++] = BPF_ST_MEM(BPF_DW, BPF_REG_FP, p[i].off, 0);
			break;
		case EMIT_COMMIT:
			start = cnt;
			if (p[i].cond)
				cnt++;
			if (p[i].reg >= BPF_REG_6) {
				cnt += emit_retract(buf + cnt, &p[i], p[i].reg);
			} else {
				buf[cnt++] = BPF_STX_MEM(BPF_DW, BPF_REG_FP, BPF_REG_0, p[i].tmp);
				buf[cnt++] = BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_FP, p[i].off);
				cnt += emit_retract(buf + cnt, &p[i], BPF_REG_0);
				buf[cnt++] = BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_FP, p[i].tmp);
			}
			if (p[i].cond)
				buf[start] = BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, cnt - start - 1);
			break;
		}
	}
	return cnt;
}

/* The points of the retractions in the current image, after those of the mirrors. */
static int retract_points(struct bpf_verifier_env *env, struct emit_point *points, u32 n,
			  const u32 *new_of, u32 orig_len)
{
	struct retract_group g[MAX_GROUPS];
	u32 i, scratch;
	int k, cnt;

	for (i = 0; i < env->retraction_cnt; i++) {
		const struct bpf_retraction *r = &env->retractions[i];
		const struct bpf_retract_array *a = retract_array_get(env, r->subprog, r->res);

		if (verifier_bug_if(!a || r->rel >= orig_len, env, "retraction at insn %d", r->rel))
			return -EFAULT;
		points[n++] = (struct emit_point) {
			.insn = new_of[r->rel], .kind = EMIT_RETRACT, .reg = r->reg,
			.base = a->base, .cnt_off = a->cnt_off,
		};
	}
	for (i = 0; i < env->call_ref_cnt; i++) {
		const struct bpf_call_ref *r = &env->call_refs[i];
		const struct bpf_subprog_info *sub = &env->subprog_info[r->subprog];

		if (!call_ref_first(env, i))
			continue;
		cnt = call_groups(env, r->call, r->subprog, g);
		if (cnt < 0)
			return cnt;
		if (verifier_bug_if(cnt && r->call >= orig_len, env, "retraction at call %d", r->call))
			return -EFAULT;
		for (k = 0, scratch = 0; k < cnt; k++) {
			const struct bpf_retract_array *a = retract_array_get(env, r->subprog, g[k].res);
			s16 off = sub->retract_scratch - scratch * BPF_REG_SIZE;

			if (verifier_bug_if(!a, env, "retraction array at call %d", r->call))
				return -EFAULT;
			if (g[k].reg < BPF_REG_6) {
				points[n++] = (struct emit_point) {
					.insn = new_of[r->call], .kind = EMIT_SCRATCH, .reg = g[k].reg,
					.off = off,
				};
				scratch++;
			}
			points[n++] = (struct emit_point) {
				.insn = new_of[r->call], .kind = EMIT_COMMIT, .reg = g[k].reg,
				.cond = g[k].cond, .off = off, .tmp = sub->retract_tmp,
				.base = a->base, .cnt_off = a->cnt_off,
			};
		}
	}
	return n;
}

/* How many insns the point @p takes, see emit_before() and emit_after(). */
static int point_cost(const struct emit_point *p, int clears)
{
	switch (p->kind) {
	case EMIT_CLEAR:
		return clears == 1 ? 1 : 4;
	case EMIT_RETRACT:
		return 6;
	case EMIT_STORE_AFTER_SLOT:
		return 2;
	case EMIT_COMMIT:
		return (p->reg >= BPF_REG_6 ? 6 : 9) + p->cond;
	default:
		return 1;
	}
}

/* The insns the @n points from @p take, before or after their insn. */
static int points_cost(const struct emit_point *p, int n)
{
	int i, clears = 0, cost = 0;

	for (i = 0; i < n; i++)
		clears += p[i].kind == EMIT_CLEAR;
	for (i = 0; i < n; i++)
		cost += point_cost(&p[i], clears);
	return cost;
}

int bpf_frame_desc_emit(struct bpf_verifier_env *env)
{
	struct bpf_insn *buf = env->insn_buf, *scratch, *insn;
	struct emit_point *points;
	u32 i, k, n = 0, len = env->prog->len, orig_len = 0, *new_of;
	int ret = 0, cnt;

	if (!env->mirrors_needed && !env->retraction_cnt && !env->call_ref_cnt)
		return 0;
	for (i = 0; i < len; i++)
		orig_len = max(orig_len, env->insn_aux_data[i].orig_idx + 1);
	/* the aux data of a patched insn went to the last insn of its patch */
	new_of = kvcalloc(orig_len, sizeof(*new_of), GFP_KERNEL_ACCOUNT);
	if (!new_of)
		return -ENOMEM;
	for (i = 0; i < len; i++)
		new_of[env->insn_aux_data[i].orig_idx] = i;
	for (i = 0; i < env->mirror_cnt; i++)
		n += env->mirrors[i].needed ? env->mirrors[i].nr_stores : 0;
	n += env->retraction_cnt + 2 * env->call_ref_cnt;
	points = kvcalloc(n, sizeof(*points), GFP_KERNEL_ACCOUNT);
	scratch = kvcalloc(INSN_BUF_SIZE, sizeof(*scratch), GFP_KERNEL_ACCOUNT);
	if (!points || !scratch) {
		ret = -ENOMEM;
		goto out;
	}
	for (i = 0, n = 0; i < env->mirror_cnt; i++) {
		const struct bpf_mirror *m = &env->mirrors[i];

		if (!m->needed)
			continue;
		for (k = 0; k < m->nr_stores; k++) {
			const struct bpf_mirror_store *s = &m->stores[k];

			if (verifier_bug_if(s->insn >= orig_len, env, "mirror store at insn %d",
					    s->insn)) {
				ret = -EFAULT;
				goto out;
			}
			points[n++] = (struct emit_point) {
				.insn = new_of[s->insn], .kind = mirror_emit_kind[s->point],
				.reg = s->reg, .off = m->off, .src = s->off,
			};
		}
	}
	ret = retract_points(env, points, n, new_of, orig_len);
	if (ret < 0)
		goto out;
	n = ret;
	sort(points, n, sizeof(*points), point_cmp, NULL);

	for (i = 0; i < n; i = k) {
		u32 idx = points[i].insn, nb = 0, na;

		for (k = i; k < n && points[k].insn == idx; k++)
			nb += points[k].kind <= EMIT_SCRATCH;
		if (verifier_bug_if(!site_insn_ok(&env->prog->insnsi[idx]), env,
				    "mirror written at insn %d, not a call", idx)) {
			ret = -EFAULT;
			goto out;
		}
		/* what goes in front of the insn sorts first; the rest follows it */
		if (nb) {
			if (points_cost(&points[i], nb) >= INSN_BUF_SIZE)
				goto too_many;
			cnt = emit_before(scratch, &points[i], nb);
			memcpy(buf, scratch, cnt * sizeof(*buf));
			buf[cnt++] = env->prog->insnsi[idx];
			insn = bpf_patch_list_add(env, idx, buf, cnt);
			if (IS_ERR(insn)) {
				ret = PTR_ERR(insn);
				goto out;
			}
			env->mirror_insns += cnt - 1;
		}
		na = k - i - nb;
		if (!na)
			continue;
		if (points_cost(&points[i + nb], na) > INSN_BUF_SIZE)
			goto too_many;
		cnt = emit_after(scratch, &points[i + nb], na);
		if (idx + 1 < len && bpf_is_unwind_goto(&env->prog->insnsi[idx + 1])) {
			struct bpf_insn ug = env->prog->insnsi[idx + 1];

			if (2 * cnt + 3 > INSN_BUF_SIZE)
				goto too_many;
			buf[0] = ug;
			buf[0].off = cnt + 1;
			memcpy(buf + 1, scratch, cnt * sizeof(*buf));
			buf[cnt + 1] = BPF_JMP_A(cnt + 1);
			memcpy(buf + cnt + 2, scratch, cnt * sizeof(*buf));
			buf[2 * cnt + 2] = BPF_JMP_A(ug.off);
			insn = bpf_patch_list_add(env, idx + 1, buf, 2 * cnt + 3);
			ret = IS_ERR(insn) ? PTR_ERR(insn) : 0;
			env->mirror_insns += 2 * cnt + 2;
		} else {
			memcpy(buf, scratch, cnt * sizeof(*buf));
			ret = bpf_patch_list_insert(env, idx + 1, buf, cnt);
			env->mirror_insns += cnt;
		}
		if (ret)
			goto out;
	}
	ret = bpf_patch_list_commit(env);
out:
	kvfree(scratch);
	kvfree(points);
	kvfree(new_of);
	return ret;
too_many:
	verbose(env, "frame_desc: too many mirrors and retractions written at insn %d\n",
		points[i].insn);
	ret = -E2BIG;
	goto out;
}
