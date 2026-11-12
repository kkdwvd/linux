// SPDX-License-Identifier: GPL-2.0-only
/*
 * Landing pads that the verifier emits.
 *
 * A SITE is an insn at which the verifier lets a frame unwind although the program has no code
 * for that:
 *   - may_goto that the verifier adds
 *   - the check at the entry of a recursive subprog
 * The resources that the frame acquired since its entry have to be released on the way out. The
 * code that does it is a LANDING PAD: calls of the functions that the program itself would call,
 * then 'r0 = 0' and unwind_exit, or exit in a frame that cannot unwind.
 *
 *	bpf_rcu_read_lock();				   call bpf_rcu_read_lock
 *	do {						1: ...
 *		p = bpf_map_lookup_elem(&map, &key);	   call bpf_map_lookup_elem
 *	} while (!p);					   may_goto pad
 *	v = *p;						   if r0 == 0 goto 1b
 *	bpf_rcu_read_unlock();				   ...
 *	return v;					   exit
 *						      pad: call bpf_rcu_read_unlock
 *							   r0 = 0
 *							   exit
 *
 * The work is split in layers:
 *
 *   who         A frame releases what it acquired since its entry. A landing pad that a caller
 *               has in the program is code like any other.
 *   plan        bpf_pad_visit(). One per site: what the pad has to release. A state that leaves
 *               its frame at a site VISITS the plan. The plan has to serve all states that visit
 *               it. If it cannot that is a CONFLICT.
 *   main pass   unwind_frame() in verifier.c. After the visit what the frame acquired is
 *               dropped from the state, by the functions that a release call of the program ends
 *               up in, and what is left of the state goes to the caller.
 *   settle      bpf_pads_settle(), after a pass that counts. A conflict is an error of the
 *               pass, like any other: of the state that visits, or of the site.
 *   code        bpf_pad_insns(). The insns of the pad of a plan, and their aux data.
 *   emission    bpf_insert_sites() in fixups.c, after the main pass.
 *
 * The main pass does not see the insns of a pad. They are trusted, like all that the verifier
 * emits. So a plan has to be right for every state that gets to its site. All that the code of a pad
 * fixes is compared on each visit: the calls and their constant arguments, the places, the order,
 * the number of sections.
 *
 * A state that is pruned or joined on the way does not get to the site. The state that it was found
 * within, or was joined with, visits for both. The pad is right for it too, because a plan is made
 * of what the main pass compares before one state stands for another. Two states meet only with
 * the same join key, see bpf_same_join_key() and same_refs(): the numbers of sections, refs[] entry
 * by entry, what each frame had at its entry, the objects in the stack that are held. Then
 * bpf_state_subsumes() compares what is in the registers and stack slots that are live at the
 * site. Where two states differ there bpf_states_join() does not refuse: the state that goes on has
 * nothing that can be read at that place, so it is no place of a plan and not 0 either. What is
 * not live is gone before the states meet, see bpf_clean_verifier_state().
 *
 * Plans live as long as a pass. A pass that is kept keeps its plans, see bpf_pads_move().
 *
 * A section has no handle: the plan has their number. Every other resource that the frame
 * acquired is an ENTRY of the plan. Its release takes a handle: the address of the lock, of
 * the irq flags. A PLACE is where the pad finds it: a register or a stack slot of the program that
 * is live at the site, a constant address. What is there may differ from the handle by a constant,
 * the delta: a pointer to a map value will do for the lock in it, R10 for irq flags in the stack.
 *
 *	v = bpf_map_lookup_elem(&map, &key);		   r6 = r0
 *	...						   ...
 *	bpf_spin_lock(&v->lock);			   call bpf_spin_lock
 *	do {						1: r1 = *(u64 *)(r6 + 8)
 *		i = v->idx;				   may_goto pad
 *	} while (i >= 4);				   if r1 > 3 goto 1b
 *	...						   ...
 *						      pad: r1 = r6
 *							   call bpf_spin_unlock
 *							   r0 = 0
 *							   exit
 *
 * A state may have the handle in several places, the CANDIDATES. Those that all visits have in
 * common stay, one of them is emitted. If a caller has the irq flags, a pointer to them is a place.
 * The release and the place tell the entries of a plan apart, see visit_refs().
 *
 * Only the program counter tells a pad what is held: every visit has to hold every entry.
 * A pad has one order, see release_ents(), among equals that of refs[], the youngest first. Locks
 * and irq flags have to be released that way. If states acquired them in different orders there is
 * a conflict.
 */
#include <linux/bpf.h>
#include <linux/bpf_verifier.h>
#include <linux/btf_ids.h>
#include <linux/filter.h>

#define verbose(env, fmt, args...) bpf_verifier_log_write(env, fmt, ##args)

/* The kfunc that releases a resource, by enum bpf_pad_class */
BTF_ID_LIST(pad_kfuncs)
BTF_ID(func, bpf_rcu_read_unlock)
BTF_ID(func, bpf_preempt_enable)
BTF_ID(func, bpf_local_irq_restore)
BTF_ID(func, bpf_res_spin_unlock)
BTF_ID(func, bpf_res_spin_unlock_irqrestore)

static struct bpf_insn helper_call(enum bpf_func_id func_id)
{
	return BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, func_id);
}

/* The insn of a pad that releases one resource of @class */
static struct bpf_insn release_call(enum bpf_pad_class class)
{
	if (class == BPF_PAD_SPIN_LOCK)
		return helper_call(BPF_FUNC_spin_unlock);
	return BPF_CALL_KFUNC(0, pad_kfuncs[class]);
}

/*
 * A pad is going to call what @insn calls, if the program can call that. The passes that follow the
 * emission look for the descriptor of a kfunc, which the program gets here, and for the prototype
 * of a helper.
 * Returns the reason of a conflict.
 */
static int get_release(struct bpf_verifier_env *env, const struct bpf_insn *insn)
{
	const struct bpf_func_proto *fn;
	u32 log_level = env->log.level;
	struct bpf_call_arg_meta meta;
	int err;

	if (bpf_helper_call(insn))
		return bpf_get_helper_proto(env, insn->imm, &fn) ? BPF_CONFLICT_NO_RELEASE : 0;
	env->log.level = 0;
	err = bpf_add_kfunc_call(env, insn->imm, insn->off);
	err = err ?: bpf_fetch_kfunc_arg_meta(env, insn->imm, insn->off, &meta);
	env->log.level = log_level;
	if (err == -ENOMEM)
		return err;
	return err ? BPF_CONFLICT_NO_RELEASE : 0;
}

struct bpf_pad_plan *bpf_pad_plan(const struct bpf_insn_aux_data *aux, enum bpf_site_kind kind)
{
	struct bpf_pad_plan *plan;

	for (plan = aux->pad_plans; plan; plan = plan->next)
		if (plan->kind == kind)
			return plan;
	return NULL;
}

/* A new plan is the empty one: the pad releases nothing. NULL if there is no memory. */
struct bpf_pad_plan *bpf_pad_plan_get(struct bpf_verifier_env *env, int insn_idx,
				      enum bpf_site_kind kind)
{
	struct bpf_insn_aux_data *aux = &env->insn_aux_data[insn_idx];
	struct bpf_pad_plan *plan = bpf_pad_plan(aux, kind);

	if (plan)
		return plan;
	plan = kzalloc_obj(*plan, BPF_VERIFIER_GFP);
	if (!plan)
		return NULL;
	plan->kind = kind;
	plan->next = aux->pad_plans;
	aux->pad_plans = plan;
	return plan;
}

static void free_plans(struct bpf_pad_plan *plan)
{
	struct bpf_pad_plan *next;

	for (; plan; plan = next) {
		next = plan->next;
		kfree(plan->ents);
		kfree(plan);
	}
}

void bpf_pad_plans_free(struct bpf_insn_aux_data *aux)
{
	free_plans(aux->pad_plans);
	aux->pad_plans = NULL;
}

/* A pass or a path-sensitive run begins */
void bpf_pads_new_round(struct bpf_verifier_env *env)
{
	int i;

	for (i = 0; i < env->prog->len; i++)
		bpf_pad_plans_free(&env->insn_aux_data[i]);
}

/*
 * The plans are what a pass found, like the fixups of the insns, and a pass that is kept can
 * become the result when a later one has an error. So the plans move with the snapshot of the
 * pass, see copy_snapshot(): to @plans, which has an entry per insn, if @save, else back from
 * there. What was at the destination is freed, and the source has no plans after that.
 */
void bpf_pads_move(struct bpf_verifier_env *env, struct bpf_pad_plan **plans, bool save)
{
	struct bpf_insn_aux_data *aux = env->insn_aux_data;
	int i;

	for (i = 0; i < env->prog->len; i++, aux++) {
		if (save) {
			free_plans(plans[i]);
			plans[i] = aux->pad_plans;
			aux->pad_plans = NULL;
		} else {
			free_plans(aux->pad_plans);
			aux->pad_plans = plans[i];
			plans[i] = NULL;
		}
	}
}

/* The snapshot that has @plans of @cnt insns is freed */
void bpf_pads_free_moved(struct bpf_pad_plan **plans, u32 cnt)
{
	u32 i;

	for (i = 0; i < cnt; i++)
		free_plans(plans[i]);
}

/* How many sections of @class the current frame of @st has entered and not left */
static u32 frame_sections(const struct bpf_verifier_state *st, enum bpf_pad_class class)
{
	const struct bpf_func_state *frame = st->frame[st->curframe];

	if (class == BPF_PAD_RCU)
		return st->active_rcu_locks - frame->entry_rcu_locks;
	return st->active_preempt_locks - frame->entry_preempt_locks;
}

/* The class of @ref */
static int ref_class(const struct bpf_reference_state *ref)
{
	switch (ref->type) {
	case REF_TYPE_IRQ:
		return BPF_PAD_IRQ;
	case REF_TYPE_LOCK:
		return BPF_PAD_SPIN_LOCK;
	case REF_TYPE_RES_LOCK:
		return BPF_PAD_RES_LOCK;
	case REF_TYPE_RES_LOCK_IRQ:
		return BPF_PAD_RES_LOCK_IRQ;
	default:
		return -ENOENT;
	}
}

/* Where the lock of @class is in what @rec describes */
static int lock_off(const struct btf_record *rec, enum bpf_pad_class class)
{
	if (class == BPF_PAD_SPIN_LOCK)
		return btf_record_has_field(rec, BPF_SPIN_LOCK) ? rec->spin_lock_off : -ENOENT;
	return btf_record_has_field(rec, BPF_RES_SPIN_LOCK) ? rec->res_spin_lock_off : -ENOENT;
}

/*
 * If @reg, which is at (@loc, @at), points into the map value or the object that the lock @ref
 * is in, at a constant offset, that is a candidate. It is what the release asks of its argument,
 * see process_spin_lock(): all candidates of a visit give the same handle.
 */
static void add_lock_cand(struct bpf_pad_place *cand, int *nr, const struct bpf_reg_state *reg,
			  const struct bpf_reference_state *ref, enum bpf_place_loc loc, int at)
{
	const struct btf_struct_meta *meta;
	const struct btf_record *rec;
	s64 delta;
	int off;

	if (*nr == BPF_PAD_MAX_CANDS || reg->id != ref->id || !tnum_is_const(reg->var_off))
		return;
	if (reg->type == PTR_TO_MAP_VALUE && reg->map_ptr == ref->ptr) {
		rec = reg->map_ptr->record;
	} else if (reg->type == (PTR_TO_BTF_ID | MEM_ALLOC) && reg->btf == ref->ptr) {
		meta = btf_find_struct_meta(reg->btf, reg->btf_id);
		rec = meta ? meta->record : NULL;
	} else {
		return;
	}
	off = lock_off(rec, ref_class(ref));
	delta = (s64)reg->var_off.value - off;
	if (off < 0 || delta < -S32_MAX || delta > S32_MAX)
		return;
	cand[(*nr)++] = (struct bpf_pad_place){ .loc = loc, .at = at, .delta = delta };
}

/*
 * If @reg, which is at (@loc, @at), points to the stack of the same frame as @obj, at a constant
 * offset, that is a candidate.
 */
static void add_obj_cand(struct bpf_pad_place *cand, int *nr, const struct bpf_reg_state *reg,
			 const struct bpf_reg_state *obj, enum bpf_place_loc loc, int at)
{
	s64 delta = reg->var_off.value - obj->var_off.value;

	if (*nr == BPF_PAD_MAX_CANDS || reg->type != PTR_TO_STACK || reg->frameno != obj->frameno ||
	    !tnum_is_const(reg->var_off) || delta < -S32_MAX || delta > S32_MAX)
		return;
	cand[(*nr)++] = (struct bpf_pad_place){ .loc = loc, .at = at, .delta = delta };
}

static void add_cand(struct bpf_pad_place *cand, int *nr, const struct bpf_reg_state *reg,
		     const struct bpf_reference_state *ref, const struct bpf_reg_state *obj,
		     enum bpf_place_loc loc, int at)
{
	if (obj)
		add_obj_cand(cand, nr, reg, obj, loc, at);
	else
		add_lock_cand(cand, nr, reg, ref, loc, at);
}

/*
 * The places of the current frame of @st that have the address of the lock @ref at @insn_idx: R6-R9
 * and stack slots. If @ref is an object in the stack of a caller @obj is its address.
 * A register or a stack slot that is not live there is no place: the passes that follow use
 * such a register, remove the store to such a slot, and states that differ in it are the same to
 * the main pass. Nor is a slot of the spills around bpf_fastcall calls: they are removed unless the
 * main pass sees another access to the slot, and it does not see the pad.
 */
static int find_cands(struct bpf_verifier_env *env, const struct bpf_verifier_state *st,
		      int insn_idx, const struct bpf_reference_state *ref,
		      const struct bpf_reg_state *obj, struct bpf_pad_place *cand)
{
	const struct bpf_insn_aux_data *aux = &env->insn_aux_data[insn_idx];
	const struct bpf_func_state *frame = st->frame[st->curframe];
	int fastcall_off = env->subprog_info[frame->subprogno].fastcall_stack_off;
	const struct bpf_stack_state *slot;
	int i, off, nr = 0;

	for (i = BPF_REG_6; i < BPF_REG_FP; i++)
		if (aux->live_regs_before & BIT(i))
			add_cand(cand, &nr, &frame->regs[i], ref, obj, BPF_PLACE_REG, i);
	for (i = 0; i < bpf_stack_nr_slots(frame); i++) {
		slot = bpf_stack_slot(frame, i);
		off = -(i + 1) * BPF_REG_SIZE;
		if (test_bit(i, aux->live_stack_before) && bpf_spill_size(slot) == BPF_REG_SIZE &&
		    off >= fastcall_off)
			add_cand(cand, &nr, &slot->spilled_ptr, ref, obj, BPF_PLACE_SPILL, off);
	}
	return nr;
}

/* The places that have the address of the lock @ref, see find_cands() */
static int find_lock_cands(struct bpf_verifier_env *env, const struct bpf_verifier_state *st,
			   int insn_idx, const struct bpf_reference_state *ref,
			   struct bpf_pad_place *cand)
{
	const struct bpf_map *map;
	int i, off, nr = 0;
	u64 addr;

	/* A lock in a global variable, the only value of an array: no id, a constant address. */
	for (i = 0; !ref->id && i < env->used_map_cnt; i++) {
		map = env->used_maps[i];
		off = lock_off(map->record, ref_class(ref));
		if (map != ref->ptr || map->map_type != BPF_MAP_TYPE_ARRAY || off < 0 ||
		    map->ops->map_direct_value_addr(map, &addr, off))
			continue;
		cand[nr++] = (struct bpf_pad_place){ .loc = BPF_PLACE_MAP_VALUE, .at = i,
						     .delta = -off };
	}
	return ref->id ? find_cands(env, st, insn_idx, ref, NULL, cand) : nr;
}

/* Is slot @spi of @frame the irq flags @ref? */
static bool slot_is_obj(const struct bpf_func_state *frame, int spi,
			const struct bpf_reference_state *ref)
{
	const struct bpf_reg_state *reg = &bpf_stack_slot(frame, spi)->spilled_ptr;

	switch (bpf_stack_slot(frame, spi)->slot_type[BPF_REG_SIZE - 1]) {
	case STACK_IRQ_FLAG:
		return reg->id == ref->id;
	}
	return false;
}

/*
 * If @ref is an object in the stack: the places that have its address at @insn_idx. R10 if the
 * current frame of @st has the object. If a caller has it, what find_cands() finds: the function
 * got a pointer and made the object there, like the constructor of a guard.
 * *@obj: the first slot of the object.
 */
static int find_obj_cands(struct bpf_verifier_env *env, const struct bpf_verifier_state *st,
			  int insn_idx, const struct bpf_reference_state *ref,
			  struct bpf_pad_place *cand, const struct bpf_stack_state **obj)
{
	const struct bpf_func_state *frame;
	struct bpf_reg_state addr;
	int f, i, nr = 0;

	for (f = st->curframe; f >= 0 && !nr; f--) {
		frame = st->frame[f];
		for (i = 0; i < bpf_stack_nr_slots(frame) && nr < BPF_PAD_MAX_CANDS; i++) {
			if (!slot_is_obj(frame, i, ref))
				continue;
			*obj = nr ? *obj : bpf_stack_slot(frame, i);
			if (f == st->curframe) {
				cand[nr++] = (struct bpf_pad_place){ .loc = BPF_PLACE_REG,
								     .at = BPF_REG_FP,
								     .delta = (i + 1) * BPF_REG_SIZE };
				continue;
			}
			addr = frame->regs[BPF_REG_FP];
			addr.var_off = tnum_const(-(i + 1) * BPF_REG_SIZE);
			return find_cands(env, st, insn_idx, ref, &addr, cand);
		}
	}
	return nr;
}

/*
 * The candidates for argument @arg of the release that @ent and @new have in common go to @cand.
 * Returns how many there are.
 */
static int common_cands(const struct bpf_pad_ent *ent, const struct bpf_pad_ent *new, int arg,
			struct bpf_pad_place *cand)
{
	const struct bpf_pad_place *old = ent->cand[arg], *place = new->cand[arg];
	int i, j, n = 0;

	for (i = 0; i < ent->nr_cands[arg]; i++) {
		for (j = 0; j < new->nr_cands[arg]; j++) {
			if (old[i].loc != place[j].loc || old[i].at != place[j].at ||
			    old[i].delta != place[j].delta)
				continue;
			cand[n++] = old[i];
			break;
		}
	}
	return n;
}

/*
 * Make @ent what @ref, one of refs[] of @st, is to a landing pad at @insn_idx: the call that
 * releases it, and the places of the current frame that have the arguments.
 * Returns the reason of a conflict.
 */
static int ref_ent(struct bpf_verifier_env *env, struct bpf_pad_ent *ent,
		   const struct bpf_verifier_state *st, int insn_idx,
		   const struct bpf_reference_state *ref)
{
	const struct bpf_stack_state *obj = NULL;
	int class = ref_class(ref);

	if (verifier_bug_if(class < 0, env, "no landing pad releases reference type %d", ref->type))
		return -EFAULT;
	memset(ent, 0, sizeof(*ent));
	ent->origin = ref->origin;
	ent->class = class;
	ent->release = release_call(class);
	if (class == BPF_PAD_IRQ)
		ent->nr_cands[0] = find_obj_cands(env, st, insn_idx, ref, ent->cand[0], &obj);
	else
		ent->nr_cands[0] = find_lock_cands(env, st, insn_idx, ref, ent->cand[0]);
	if (class == BPF_PAD_RES_LOCK_IRQ) {
		/* The same insn saved irq flags, the next of refs[]: the second argument. */
		if (verifier_bug_if(ref + 1 == st->refs + st->acquired_refs ||
				    ref[1].type != REF_TYPE_IRQ || ref[1].insn_idx != ref->insn_idx,
				    env, "no irq flags after the lock of insn %d", ref->insn_idx))
			return -EFAULT;
		ent->nr_cands[1] = find_obj_cands(env, st, insn_idx, ref + 1, ent->cand[1], &obj);
		if (!ent->nr_cands[1])
			return BPF_CONFLICT_NO_PLACE;
	}
	return ent->nr_cands[0] ? 0 : BPF_CONFLICT_NO_PLACE;
}

/* The entry of @plan that refs[@ref] is on this visit */
static struct bpf_pad_ent *held_ent(const struct bpf_pad_plan *plan, int ref)
{
	int i;

	for (i = 0; i < plan->nr_ents; i++)
		if (plan->ents[i].ref == ref)
			return &plan->ents[i];
	return NULL;
}

/*
 * The entry of @plan that @new is: nothing else is that entry on this visit, the same call releases
 * both, and they have a candidate in common for each of its arguments. @origin: and the origin.
 */
static struct bpf_pad_ent *match_ent(const struct bpf_pad_plan *plan, const struct bpf_pad_ent *new,
				     bool origin)
{
	struct bpf_pad_place cand[BPF_PAD_MAX_CANDS];
	struct bpf_pad_ent *ent;
	int i, arg;

	for (i = 0; i < plan->nr_ents; i++) {
		ent = &plan->ents[i];
		if (ent->ref >= 0 || (origin && ent->origin != new->origin) ||
		    memcmp(&ent->release, &new->release, sizeof(ent->release)))
			continue;
		for (arg = 0; arg < BPF_PAD_MAX_ARGS; arg++)
			if (new->nr_cands[arg] && !common_cands(ent, new, arg, cand))
				break;
		if (arg == BPF_PAD_MAX_ARGS)
			return ent;
	}
	return NULL;
}

/* @new is one more entry of @plan. Returns it, or NULL if there is no memory. */
static struct bpf_pad_ent *add_ent(struct bpf_pad_plan *plan, const struct bpf_pad_ent *new)
{
	if (!plan->ents)
		plan->ents = kzalloc_objs(*plan->ents, BPF_PAD_MAX_ENTS, BPF_VERIFIER_GFP);
	if (!plan->ents)
		return NULL;
	plan->ents[plan->nr_ents] = *new;
	return &plan->ents[plan->nr_ents++];
}

/*
 * The resources with a handle that the current frame of @st acquired: refs[] from
 * entry_refs on, oldest first. Which entry is one of them? What a pad does with an entry is a call
 * with what it finds at a place, so that is what an entry is, like a variable with a destructor. It
 * does not matter which insn acquired what is there. Where that leaves a choice the origin decides.
 * Every visit has to hold every entry.
 * Locks and irq flags have to be in refs[] in the order of the plan.
 * Returns the reason of a conflict.
 */
static int visit_refs(struct bpf_verifier_env *env, struct bpf_pad_plan *plan,
		      const struct bpf_verifier_state *st, int insn_idx)
{
	const struct bpf_reference_state *ref;
	struct bpf_pad_ent new, *ent;
	int i, arg, pass, pos, err;

	for (i = 0; i < plan->nr_ents; i++)
		plan->ents[i].ref = -1;
	for (pass = 0; pass < 2; pass++) {
		for (i = st->frame[st->curframe]->entry_refs; i < st->acquired_refs; i++) {
			ref = &st->refs[i];
			/* irq flags that a lock saved are an argument of its entry */
			if (i && ref[-1].type == REF_TYPE_RES_LOCK_IRQ)
				continue;
			if (held_ent(plan, i))
				continue;
			err = ref_ent(env, &new, st, insn_idx, ref);
			if (err)
				return err;
			ent = match_ent(plan, &new, !pass);
			if (!ent && !pass)
				continue;
			if (!ent && plan->visited)
				return BPF_CONFLICT_NOT_ALWAYS_HELD;
			if (!ent && plan->nr_ents == BPF_PAD_MAX_ENTS)
				return BPF_CONFLICT_TOO_MUCH;
			ent = ent ?: add_ent(plan, &new);
			if (!ent)
				return -ENOMEM;
			ent->ref = i;
			for (arg = 0; arg < BPF_PAD_MAX_ARGS; arg++)
				ent->nr_cands[arg] = common_cands(ent, &new, arg, ent->cand[arg]);
		}
	}
	for (i = st->frame[st->curframe]->entry_refs, pos = 0; i < st->acquired_refs; i++) {
		ent = held_ent(plan, i);
		if (!ent)
			continue;
		if (ent - plan->ents < pos)
			return BPF_CONFLICT_ORDER_DIFFERS;
		pos = ent - plan->ents;
	}
	for (i = 0; i < plan->nr_ents; i++)
		if (plan->ents[i].ref < 0)
			return BPF_CONFLICT_NOT_ALWAYS_HELD;
	return 0;
}

/*
 * The current frame of @st is about to be unwound at the site of @kind at @insn_idx. Make the plan
 * of the site serve @st too. A visit at which the frame holds nothing is a visit like any other.
 *
 * Sections: the pad leaves as many as the frame has entered. That is a number of calls in the
 * code of the pad, so it has to be the same on all visits.
 *
 * Returns the plan. It tells whether there is a conflict.
 */
struct bpf_pad_plan *bpf_pad_visit(struct bpf_verifier_env *env,
				   const struct bpf_verifier_state *st, int insn_idx,
				   enum bpf_site_kind kind)
{
	struct bpf_pad_plan *plan;
	u32 class, nr;
	int err;

	plan = bpf_pad_plan_get(env, insn_idx, kind);
	if (!plan)
		return ERR_PTR(-ENOMEM);
	if (plan->conflict)
		return plan;
	err = visit_refs(env, plan, st, insn_idx);
	if (err < 0)
		return ERR_PTR(err);
	plan->conflict = err;
	for (class = 0; class < BPF_PAD_NR_SECTIONS; class++) {
		nr = frame_sections(st, class);
		if (nr > BPF_PAD_MAX_SECTIONS)
			plan->conflict = BPF_CONFLICT_TOO_MUCH;
		else if (plan->visited && plan->sections[class] != nr)
			plan->conflict = BPF_CONFLICT_SECTIONS_DIFFER;
		plan->sections[class] = nr;
	}
	plan->visited = true;
	return plan;
}

/*
 * R@reg = the handle that is at @place. Returns the number of insns.
 */
static int load_handle(struct bpf_verifier_env *env, struct bpf_insn *buf,
		       struct bpf_insn_aux_data *aux, int reg, const struct bpf_pad_place *place)
{
	const struct bpf_map *map;
	u64 addr = 0;
	int n = 0;

	switch (place->loc) {
	case BPF_PLACE_REG:
		buf[n++] = BPF_MOV64_REG(reg, place->at);
		break;
	case BPF_PLACE_SPILL:
		buf[n++] = BPF_LDX_MEM(BPF_DW, reg, BPF_REG_FP, place->at);
		break;
	case BPF_PLACE_MAP_VALUE:
		/* what check_and_resolve_insns() makes of such an insn. find_lock_cands() asked. */
		map = env->used_maps[place->at];
		map->ops->map_direct_value_addr(map, &addr, -place->delta);
		addr -= place->delta;
		aux[n].map_index = place->at;
		aux[n].map_off = -place->delta;
		buf[n++] = BPF_RAW_INSN(BPF_LD | BPF_DW | BPF_IMM, reg, BPF_PSEUDO_MAP_VALUE, 0,
					(u32)addr);
		buf[n++] = BPF_RAW_INSN(0, 0, 0, 0, addr >> 32);
		return n;
	}
	if (place->delta)
		buf[n++] = BPF_ALU64_IMM(BPF_ADD, reg, -place->delta);
	return n;
}

/* The insns that release the entries of @plan, the youngest first */
static int release_ents(struct bpf_verifier_env *env, const struct bpf_pad_plan *plan,
			struct bpf_insn *buf, struct bpf_insn_aux_data *aux)
{
	const struct bpf_pad_ent *ent;
	int i, arg, n = 0;

	for (i = plan->nr_ents - 1; i >= 0; i--) {
		ent = &plan->ents[i];
		for (arg = 0; arg < BPF_PAD_MAX_ARGS && ent->nr_cands[arg]; arg++)
			n += load_handle(env, &buf[n], &aux[n], BPF_REG_1 + arg, &ent->cand[arg][0]);
		buf[n++] = ent->release;
	}
	return n;
}

/*
 * The insns of the landing pad of @plan, a site in @subprog, but for the last one, which leaves the
 * frame. The passes that follow the emission look up in the aux data of an insn what the main pass
 * notes there. It does not see these insns: what it would note goes to @aux, one per insn.
 * Returns the number of insns, less than BPF_PAD_MAX_INSNS.
 */
int bpf_pad_insns(struct bpf_verifier_env *env, const struct bpf_pad_plan *plan, int subprog,
		  struct bpf_insn *buf, struct bpf_insn_aux_data *aux)
{
	int class, i, n;

	n = release_ents(env, plan, buf, aux);
	for (class = 0; class < BPF_PAD_NR_SECTIONS; class++)
		for (i = 0; i < plan->sections[class]; i++)
			buf[n++] = release_call(class);
	buf[n++] = BPF_MOV64_IMM(BPF_REG_0, bpf_unwound_retval(env, subprog));
	if (bpf_ret_reg_pair(env, subprog))
		buf[n++] = BPF_MOV64_IMM(BPF_REG_2, 0);
	return n;
}

/* All visits of @plan are over. Returns the reason of a conflict. */
static int settle_plan(struct bpf_verifier_env *env, struct bpf_pad_plan *plan)
{
	struct bpf_insn release;
	int i, class, err = plan->conflict;

	for (i = 0; !err && i < plan->nr_ents; i++)
		err = get_release(env, &plan->ents[i].release);
	for (class = 0; !err && class < BPF_PAD_NR_SECTIONS; class++) {
		release = release_call(class);
		if (plan->sections[class])
			err = get_release(env, &release);
	}
	return err;
}

/* 'spin_lock@5(r6-8)': what insn 5 brought to the frame, the arguments of its release */
static void print_ent(struct bpf_verifier_env *env, const struct bpf_pad_ent *ent)
{
	static const char * const class[] = {
		[BPF_PAD_IRQ]			= "irq",
		[BPF_PAD_RES_LOCK]		= "res_lock",
		[BPF_PAD_RES_LOCK_IRQ]		= "res_lock_irq",
		[BPF_PAD_SPIN_LOCK]		= "spin_lock",
	};
	const struct bpf_pad_place *place;
	int arg;

	verbose(env, "%s@%d(", class[ent->class], ent->origin);
	for (arg = 0; arg < BPF_PAD_MAX_ARGS && ent->nr_cands[arg]; arg++) {
		place = &ent->cand[arg][0];
		verbose(env, "%s", arg ? ", " : "");
		if (place->loc == BPF_PLACE_SPILL)
			verbose(env, "*fp%d", place->at);
		else if (place->loc == BPF_PLACE_MAP_VALUE)
			verbose(env, "map#%d", place->at);
		else if (place->at == BPF_REG_FP)
			verbose(env, "fp");
		else
			verbose(env, "r%d", place->at);
		if (place->delta)
			verbose(env, "%+d", -place->delta);
	}
	verbose(env, ") ");
}

/* The plan of the site at insn @i, or why there is none */
static void print_plan(struct bpf_verifier_env *env, int i, const struct bpf_pad_plan *plan)
{
	static const char * const kind[] = {
		[BPF_SITE_GUARD]		= "may_goto",
		[BPF_SITE_RECURSION]		= "recursion check",
	};
	static const char * const why[] = {
		[BPF_CONFLICT_SECTIONS_DIFFER]	= "the number of sections differs",
		[BPF_CONFLICT_TOO_MUCH]		= "too much is held",
		[BPF_CONFLICT_NO_RELEASE]	= "the program can call nothing that releases a resource",
		[BPF_CONFLICT_NOT_ALWAYS_HELD]	= "a resource is held on some paths only",
		[BPF_CONFLICT_NO_PLACE]		= "no place has the handle on all paths",
		[BPF_CONFLICT_ORDER_DIFFERS]	= "the order of the releases differs",
	};
	int j;

	verbose(env, "landing pad of %s at %d: ", kind[plan->kind], i);
	for (j = plan->nr_ents - 1; !plan->conflict && j >= 0; j--)
		print_ent(env, &plan->ents[j]);
	if (plan->conflict)
		verbose(env, "conflict: %s\n", why[plan->conflict]);
	else
		verbose(env, "rcu=%d preempt=%d\n", plan->sections[BPF_PAD_RCU],
			plan->sections[BPF_PAD_PREEMPT]);
}

/* What the landing pad of the site of @plan at @insn_idx releases, or why there is none */
void bpf_pad_log(struct bpf_verifier_env *env, int insn_idx, const struct bpf_pad_plan *plan)
{
	print_plan(env, insn_idx, plan);
}

/*
 * A pass that counts is over: all states have visited the plans. A state whose visit made a
 * conflict was unproven at the site, see unwind_frame(). A conflict that shows only now is an
 * error of the pass as well, and its site is an unproven insn for the next one, see
 * bpf_find_unproven_after_pass().
 */
int bpf_pads_settle(struct bpf_verifier_env *env)
{
	struct bpf_pad_plan *plan;
	int i, err;

	for (i = 0; i < env->prog->len; i++) {
		if (env->insn_aux_data[i].pad_plans && bpf_must_abort())
			return -EINTR;
		for (plan = env->insn_aux_data[i].pad_plans; plan; plan = plan->next) {
			err = settle_plan(env, plan);
			if (err < 0)
				return err;
			plan->conflict = err;
			if (plan->conflict) {
				print_plan(env, i, plan);
				return -EINVAL;
			}
		}
	}
	return 0;
}

/* A site at the insn has no landing pad that serves all states, see bpf_pads_settle() */
bool bpf_pads_conflict(const struct bpf_insn_aux_data *aux)
{
	const struct bpf_pad_plan *plan;

	for (plan = aux->pad_plans; plan; plan = plan->next)
		if (plan->conflict)
			return true;
	return false;
}

/* The plans of the program */
void bpf_pads_log(struct bpf_verifier_env *env)
{
	const struct bpf_pad_plan *plan;
	int i;

	if (!(env->log.level & BPF_LOG_LEVEL2))
		return;
	for (i = 0; i < env->prog->len; i++)
		for (plan = env->insn_aux_data[i].pad_plans; plan; plan = plan->next)
			print_plan(env, i, plan);
}
