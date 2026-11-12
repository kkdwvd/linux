// SPDX-License-Identifier: GPL-2.0-only
/*
 * Landing pads that the verifier emits.
 *
 * A SITE is an insn at which the verifier lets a frame unwind although the program has no code
 * for that:
 *   - may_goto that the verifier adds
 *   - the check at the entry of a recursive subprog
 *   - a call of a subprog that comes back with unwind_exit and has no unwind_goto after it
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
 *   who         A frame releases what it acquired since its entry, and what a subprog that it
 *               called returned with. A landing pad that a caller has in the program is code
 *               like any other.
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
 * the number of sections. A call that the type of the program cannot make is a conflict, see
 * get_release(). The pad of a callee releases pointers under the locks of its callers. A call that
 * the program could not make there is a conflict too, except the free of an object that has only
 * memory to give back, see can_release_under_lock().
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
 * The frames of a program are unwound one by one. The pad of a frame ends in unwind_exit, which
 * goes to unwind_goto after the call in the caller, and that goes to the pad of the caller:
 *
 *	static int wait(void)				wait:
 *	{						1: ...
 *		do {					   may_goto pad
 *			...				   if r0 == 0 goto 1b
 *		} while (!p);				   ...
 *		return *p;				   exit
 *	}					      pad: r0 = 0
 *							   unwind_exit
 *	bpf_rcu_read_lock();				prog:
 *	v = wait();					   call bpf_rcu_read_lock
 *	bpf_rcu_read_unlock();				   call wait
 *	return v;					   unwind_goto pad
 *							   ...
 *							   exit
 *						      pad: call bpf_rcu_read_unlock
 *							   r0 = 0
 *							   exit
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
 * common stay, one of them is emitted. The calls of a pad clobber R0-R5: they are places for the
 * first argument of the first call only, see settle_ent().
 *
 * A pointer that a helper or a kfunc returned and that has to be released is its own handle. A copy
 * of it, a pointer to a node in the object, a socket that a helper has cast are places of one
 * entry. What releases it follows from its type, see ref_release(). An iterator
 * and a dynptr that has to be released are objects in the stack, like irq flags. If a caller has
 * the object, a pointer to it is a place.
 * The release and the place tell the entries of a plan apart, see visit_refs().
 *
 *	t = bpf_task_from_pid(pid);			   call bpf_task_from_pid
 *	...						   r6 = r0
 *	v = wait();					   ...
 *	bpf_task_release(t);				   call wait
 *							   unwind_goto pad
 *							   ...
 *						      pad: r1 = r6
 *							   call bpf_task_release
 *							   r0 = 0
 *							   exit
 *
 * Only the program counter tells a pad what is held: every visit has to hold every entry.
 * A pad has one order, see enum pad_turn, among equals that of refs[], the youngest first. Locks
 * and irq flags have to be released that way, and a dynptr ahead of the pointer that it was made
 * from. States that acquired them in different orders can be a conflict.
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

/* They free an object of the program, and one per cpu */
BTF_ID_LIST(pad_obj_drop)
BTF_ID(func, bpf_obj_drop)
BTF_ID(func, bpf_percpu_obj_drop)

/* It releases the dynptr of bpf_dynptr_from_file() */
BTF_ID_LIST_SINGLE(pad_file_discard, func, bpf_dynptr_file_discard)

static struct bpf_insn helper_call(enum bpf_func_id func_id)
{
	return BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, func_id);
}

/* The insn of a pad that releases one resource of @class. A pointer: see ref_release(). */
static struct bpf_insn release_call(enum bpf_pad_class class)
{
	if (class == BPF_PAD_SPIN_LOCK)
		return helper_call(BPF_FUNC_spin_unlock);
	return BPF_CALL_KFUNC(0, pad_kfuncs[class]);
}

static bool is_obj_drop(const struct bpf_insn *insn)
{
	return bpf_pseudo_kfunc_call(insn) && !insn->off &&
	       (insn->imm == pad_obj_drop[0] || insn->imm == pad_obj_drop[1]);
}

/* The second argument of the helper that @insn calls is flags */
static bool takes_flags(const struct bpf_insn *insn)
{
	if (!bpf_helper_call(insn))
		return false;
	switch (insn->imm) {
	case BPF_FUNC_ringbuf_discard:
	case BPF_FUNC_ringbuf_discard_dynptr:
		return true;
	}
	return false;
}

/*
 * bpf_iter_<type>_destroy() for the iterator whose first slot is @iter: the type of the object
 * names it, see btf_check_iter_kfuncs(). If that is a type of a module, the index of its BTF in
 * fd_array goes to *@off, from @insn if that is a call of a kfunc of the same BTF.
 */
static s32 iter_destroy_kfunc(struct bpf_verifier_env *env, const struct bpf_reg_state *iter,
			      const struct bpf_insn *insn, s16 *off)
{
	const struct btf *btf = iter->iter.btf;
	const struct btf_type *t = btf_type_by_id(btf, iter->iter.btf_id);
	struct bpf_call_arg_meta meta;
	char name[128];

	*off = 0;
	if (btf_is_module(btf)) {
		if (!bpf_pseudo_kfunc_call(insn) || !insn->imm ||
		    bpf_fetch_kfunc_arg_meta(env, insn->imm, insn->off, &meta) || meta.btf != btf)
			return -ENOENT;
		*off = insn->off;
	}
	snprintf(name, sizeof(name), "%s_destroy", btf_name_by_offset(btf, t->name_off));
	return btf_find_by_name_kind(btf, name, BTF_KIND_FUNC);
}

/* Does bpf_sk_release() take what is in @reg? A socket, or what a helper has cast one to. */
static bool reg_is_sock(const struct bpf_reg_state *reg)
{
	if (type_is_sk_pointer(base_type(reg->type)))
		return true;
#ifdef CONFIG_NET
	if (base_type(reg->type) == PTR_TO_BTF_ID && btf_is_vmlinux(reg->btf))
		for (int i = 0; i < MAX_BTF_SOCK_TYPE; i++)
			if (reg->btf_id == btf_sock_ids[i])
				return true;
#endif
	return false;
}

/*
 * The call that releases the pointer in @reg. Its type tells: that is all that the verifier asks of
 * the argument of a release, whichever insn acquired the pointer. An object of the program is freed.
 * A kernel object: see btf_find_release_kfunc(). If a kfunc of a module returned the pointer @off is
 * the index of its BTF in fd_array, and that BTF comes first: nf_conn is a type of vmlinux, and the
 * kfuncs for it may be in a module.
 */
static int type_release(struct bpf_verifier_env *env, const struct bpf_reg_state *reg, s16 off,
			struct bpf_insn *release)
{
	const struct btf *btf = reg->btf;
	s32 id = -ENOENT;

	if (base_type(reg->type) != PTR_TO_BTF_ID)
		return -ENOENT;
	if (!btf_is_kernel(btf)) {
		*release = BPF_CALL_KFUNC(0, pad_obj_drop[!!(reg->type & MEM_PERCPU)]);
		return 0;
	}
	if (btf_is_module(btf)) {
		id = btf_find_release_kfunc(btf, reg->btf_id, env->prog);
		/* the module releases it itself, and nothing says where its BTF is in fd_array */
		if (id >= 0 && !off)
			return -ENOENT;
		if (id < 0) {
			btf = btf_base_btf(btf);
			off = 0;
		}
	}
	if (id < 0)
		id = btf_find_release_kfunc(btf, reg->btf_id, env->prog);
	*release = BPF_CALL_KFUNC(off, id);
	return min(id, 0);
}

/*
 * The call that releases the pointer @ref, which is in @reg. If @ref is an object in the stack
 * @reg is its first slot, @iter: that of an iterator.
 * What the main pass compares before one state stands for another decides: the type of what is in
 * @reg, the kind of the object, and whether @ref came with a __ref argument, see same_refs() and
 * bpf_same_join_key(). The insn that acquired @ref is not compared, and a join keeps one of two.
 * It is asked what the type leaves open:
 *   - Which helper made a socket or a record of a ring buffer. That is believed only where @reg
 *     is what such a helper returns.
 *   - Where the BTF of a module is in fd_array, if the insn is a call of a kfunc. Its index is
 *     taken as it is, with no test of @reg. R0 of a kfunc has the BTF of that kfunc, see
 *     check_kfunc_call(), a helper that casts a socket gives it a type of vmlinux, and a join
 *     keeps a register only where both states have one type in it. So a pointer to a type of
 *     a module that a kfunc acquired came out of a kfunc of that module, and the index is that
 *     of the BTF in which type_release() finds the kfunc. Where @reg has a type of vmlinux and
 *     the index is one of a module, the kfunc is looked up in the sets of that module like any
 *     call of the program, see get_release(): unless the module has registered that very
 *     function it is no kfunc there, and that is a conflict.
 */
static int ref_release(struct bpf_verifier_env *env, const struct bpf_reference_state *ref,
		       const struct bpf_reg_state *reg, bool iter, struct bpf_insn *release)
{
	const struct bpf_insn *insn = &env->prog->insnsi[ref->insn_idx];
	s16 off;
	s32 id;

	if (iter) {
		id = iter_destroy_kfunc(env, reg, insn, &off);
		*release = BPF_CALL_KFUNC(off, id);
		return min(id, 0);
	}
	if (reg->type == CONST_PTR_TO_DYNPTR) {
		if (reg->dynptr.type == BPF_DYNPTR_TYPE_FILE)
			*release = BPF_CALL_KFUNC(0, pad_file_discard[0]);
		else if (reg->dynptr.type == BPF_DYNPTR_TYPE_RINGBUF)
			*release = helper_call(BPF_FUNC_ringbuf_discard_dynptr);
		else
			return -ENOENT;
		return 0;
	}
	/* no insn acquired a __ref argument of struct_ops */
	if (ref->ctx_arg)
		return type_release(env, reg, 0, release);
	if (bpf_pseudo_kfunc_call(insn))
		return type_release(env, reg, insn->off, release);
	if (!bpf_helper_call(insn))
		return type_release(env, reg, 0, release);
	switch (insn->imm) {
	case BPF_FUNC_sk_lookup_tcp:
	case BPF_FUNC_sk_lookup_udp:
	case BPF_FUNC_skc_lookup_tcp:
	case BPF_FUNC_map_lookup_elem:
		if (!reg_is_sock(reg))
			break;
		*release = helper_call(BPF_FUNC_sk_release);
		return 0;
	case BPF_FUNC_ringbuf_reserve:
		if (base_type(reg->type) != PTR_TO_MEM || !(reg->type & MEM_RINGBUF))
			break;
		*release = helper_call(BPF_FUNC_ringbuf_discard);
		return 0;
	case BPF_FUNC_kptr_xchg:
		return type_release(env, reg, 0, release);
	}
	return -ENOENT;
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

/* @callee came back to the call of @plan: it takes its place in the list */
static int plan_add_callee(struct bpf_verifier_env *env, struct bpf_pad_plan *plan, u32 callee)
{
	u32 n = plan->nr_callees, mid, lo = 0, hi = n, *list;

	while (lo < hi) {
		mid = (lo + hi) / 2;
		if (plan->callee[mid] < callee)
			lo = mid + 1;
		else
			hi = mid;
	}
	if (lo < n && plan->callee[lo] == callee)
		return 0;
	/* the list has room for the next power of two */
	if (!(n & (n - 1))) {
		list = krealloc_array(plan->callee, n ? 2 * n : 1, sizeof(*list), BPF_VERIFIER_GFP);
		if (!list)
			return -ENOMEM;
		plan->callee = list;
	}
	/* callx can have many callees, and each new one moves those above it */
	bpf_add_cost(env, (n - lo) * sizeof(*list) / 64, BPF_COST_SCAN);
	memmove(&plan->callee[lo + 1], &plan->callee[lo], (n - lo) * sizeof(*list));
	plan->callee[lo] = callee;
	plan->nr_callees++;
	return 0;
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

/* @callee was left with unwind_exit and comes back to the call at @call_idx, which is a site */
int bpf_pad_note_callee(struct bpf_verifier_env *env, int call_idx, int callee)
{
	struct bpf_pad_plan *plan = bpf_pad_plan_get(env, call_idx, BPF_SITE_CALL);

	if (!plan)
		return -ENOMEM;
	return plan_add_callee(env, plan, callee);
}

static void free_plans(struct bpf_pad_plan *plan)
{
	struct bpf_pad_plan *next;

	for (; plan; plan = next) {
		next = plan->next;
		kfree(plan->ents);
		kfree(plan->callee);
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

	env->pads_late = false;
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
	case REF_TYPE_PTR:
		return BPF_PAD_REF;
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
 * If @reg, which is at (@loc, @at), is the pointer @ref plus a constant, that is a candidate:
 * a copy, a pointer to a node in an object, what a helper made of a socket. But not the
 * result of bpf_skc_to_mptcp_sock(): it has the id of the socket and is another socket.
 */
static void add_ref_cand(struct bpf_pad_place *cand, int *nr, const struct bpf_reg_state *reg,
			 const struct bpf_reference_state *ref, enum bpf_place_loc loc, int at)
{
	s64 delta = reg->var_off.value;

	if (*nr == BPF_PAD_MAX_CANDS || reg->id != ref->id || reg->type == SCALAR_VALUE ||
	    reg->type == NOT_INIT || !tnum_is_const(reg->var_off) ||
	    delta < -S32_MAX || delta > S32_MAX)
		return;
#ifdef CONFIG_NET
	if (base_type(reg->type) == PTR_TO_BTF_ID && btf_is_vmlinux(reg->btf) &&
	    reg->btf_id == btf_sock_ids[BTF_SOCK_TYPE_MPTCP])
		return;
#endif
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
	else if (ref->type == REF_TYPE_PTR)
		add_ref_cand(cand, nr, reg, ref, loc, at);
	else
		add_lock_cand(cand, nr, reg, ref, loc, at);
}

/*
 * The places of the current frame of @st that have the handle of @ref, a lock or a pointer, at
 * @insn_idx: R6-R9 and stack slots, then R0-R5, which are dead after a call. If @ref is an object
 * in the stack of a caller @obj is its address.
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
	for (i = BPF_REG_0; i < BPF_REG_6; i++)
		if (aux->live_regs_before & BIT(i))
			add_cand(cand, &nr, &frame->regs[i], ref, obj, BPF_PLACE_REG, i);
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

/*
 * A register of the current frame of @st, spilled or not, live or not, that has the pointer @ref:
 * it tells the type. R0-R5 come last. NULL if there is none.
 */
static const struct bpf_reg_state *ref_reg(const struct bpf_verifier_state *st,
					   const struct bpf_reference_state *ref)
{
	const struct bpf_func_state *frame = st->frame[st->curframe];
	const struct bpf_stack_state *slot;
	int i;

	for (i = 0; i < bpf_stack_nr_slots(frame); i++) {
		slot = bpf_stack_slot(frame, i);
		if (bpf_is_spilled_reg(slot) && slot->spilled_ptr.id == ref->id)
			return &slot->spilled_ptr;
	}
	for (i = BPF_REG_9; i >= BPF_REG_0; i--)
		if (frame->regs[i].type != NOT_INIT && frame->regs[i].id == ref->id)
			return &frame->regs[i];
	return NULL;
}

/*
 * Slot @spi of @frame is the first one of an iterator. Is the iterator all that its destructor asks
 * for? The program can write to the other slots, and it can leave what protects an iterator that
 * RCU protects. Then nothing can destroy the iterator any more.
 */
static bool iter_is_valid(const struct bpf_func_state *frame, int spi)
{
	const struct bpf_reg_state *reg = &bpf_stack_slot(frame, spi)->spilled_ptr;
	const struct btf_type *t = btf_type_by_id(reg->iter.btf, reg->iter.btf_id);

	return !bpf_iter_slots_valid_init(frame, spi, reg->iter.btf, reg->iter.btf_id,
					  t->size / BPF_REG_SIZE);
}

/*
 * Is slot @spi of @frame the first one of the object @ref: irq flags, an iterator, a dynptr?
 * A store to a slot of irq flags or of a dynptr leaves nothing of them.
 */
static bool slot_is_obj(const struct bpf_func_state *frame, int spi,
			const struct bpf_reference_state *ref)
{
	const struct bpf_reg_state *reg = &bpf_stack_slot(frame, spi)->spilled_ptr;

	switch (bpf_stack_slot(frame, spi)->slot_type[BPF_REG_SIZE - 1]) {
	case STACK_IRQ_FLAG:
		return reg->id == ref->id;
	case STACK_ITER:
		return reg->id == ref->id && iter_is_valid(frame, spi);
	case STACK_DYNPTR:
		/* any other dynptr is made from a pointer, and that is what @ref is */
		return reg->dynptr.first_slot && reg->parent_id == ref->id &&
		       (reg->dynptr.type == BPF_DYNPTR_TYPE_RINGBUF ||
			reg->dynptr.type == BPF_DYNPTR_TYPE_FILE);
	}
	return false;
}

/*
 * If @ref is an object in the stack: the places that have its address at @insn_idx. R10 if the
 * current frame of @st has the object. If a caller has it, what find_cands() finds: the function
 * got a pointer and made the object there, like the constructor of a guard. A clone of a dynptr is
 * one more place of the same resource. *@obj: the first slot of the object.
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
 * Can a pad free an object of type @btf_id of the program with the call @release? That runs the
 * destructors of its fields. Under a lock of a caller: see can_release_under_lock().
 * A tracing program must not do that to fields that are not NMI safe, see check_kfunc_call().
 * bpf_percpu_obj_drop() takes no description of fields: a per-cpu object has none that the kernel
 * looks after, bpf_percpu_obj_new() makes no other. The type of a pointer behind __percpu_kptr can
 * have such fields all the same, and bpf_fixup_kfunc_call() takes a call that frees that type
 * for a bug of the verifier. No pad makes that call.
 */
static bool can_free_obj(struct bpf_verifier_env *env, const struct bpf_insn *release, u32 btf_id)
{
	const struct btf *btf = env->prog->aux->btf;
	const struct btf_struct_meta *meta = btf_find_struct_meta(btf, btf_id);

	if (meta && release->imm == pad_obj_drop[1])
		return false;
	if (meta && bpf_prog_may_run_in_nmi(env) && btf_record_has_nmi_unsafe_fields(meta->record))
		return false;
	return true;
}

/*
 * Can a pad of @frame make the call of @ent, which releases a pointer, an iterator or a dynptr,
 * under the locks that are held then? Those of its callers are: what the callers hold is in the
 * first entry_refs of refs[] of @st. The pad has released the locks of its own frame by then,
 * unless RCU protects @ent: such an iterator goes ahead of them, see enum pad_turn, and every
 * lock in refs[] counts. The frame takes its locks behind the insn that made the iterator, where
 * a hidden slot got its release, so for them the visit asks: ref_ent() is called for every
 * state that holds the iterator.
 * Under a lock a program may call only a kfunc that is KF_SPINLOCK_SAFE, see do_check_insn(), and
 * so may its pad: the release of a kernel object runs code of its owner. The program has no such
 * call for an object of its own. The pad frees one there all the same if that runs no destructor
 * of a field, see bpf_obj_free_runs_dtor(): it only gives the memory back.
 */
static bool can_release_under_lock(struct bpf_verifier_env *env,
				   const struct bpf_verifier_state *st,
				   const struct bpf_func_state *frame, const struct bpf_pad_ent *ent)
{
	u32 i, nr = ent->rcu ? st->acquired_refs : frame->entry_refs;
	struct bpf_call_arg_meta meta;

	if (ent->class < BPF_PAD_REF)
		return true;
	for (i = 0; i < nr && !(st->refs[i].type & REF_TYPE_LOCK_MASK); i++)
		;
	if (i == nr)
		return true;
	if (is_obj_drop(&ent->release))
		return !bpf_obj_free_runs_dtor(env->prog->aux->btf, ent->obj_type);
	return bpf_pseudo_kfunc_call(&ent->release) &&
	       !bpf_fetch_kfunc_arg_meta(env, ent->release.imm, ent->release.off, &meta) &&
	       (meta.kfunc_flags & KF_SPINLOCK_SAFE);
}

/*
 * What the release of @ent needs beside the handle, which is in @reg. Flags, the second argument:
 * they are 0. The type of an object of the program: that is no argument. It is in the aux data of
 * the call that frees the object, see bpf_insn_aux_data::kptr_struct_meta, so a call of a pad frees
 * one type. Its id in the BTF of the program names it.
 */
static int ent_imm(struct bpf_verifier_env *env, struct bpf_pad_ent *ent,
		   const struct bpf_reg_state *reg)
{
	if (is_obj_drop(&ent->release)) {
		if (reg->btf != env->prog->aux->btf)
			return BPF_CONFLICT_NO_PLACE;
		if (!can_free_obj(env, &ent->release, reg->btf_id))
			return BPF_CONFLICT_NO_RELEASE;
		ent->obj_type = reg->btf_id;
	}
	if (takes_flags(&ent->release))
		ent->cand[1][ent->nr_cands[1]++] = (struct bpf_pad_place){ .loc = BPF_PLACE_IMM };
	return 0;
}

/* See ref_ent(). @ref is a pointer. */
static int ptr_ent(struct bpf_verifier_env *env, struct bpf_pad_ent *ent,
		   const struct bpf_verifier_state *st, int insn_idx,
		   const struct bpf_reference_state *ref)
{
	const struct bpf_reg_state *regs = st->frame[st->curframe]->regs, *reg = ref_reg(st, ref);

	if (!reg)
		return BPF_CONFLICT_NO_PLACE;
	if (type_may_be_null(reg->type))
		return BPF_CONFLICT_NOT_ALWAYS_HELD;
	if (ref_release(env, ref, reg, false, &ent->release))
		return BPF_CONFLICT_NO_RELEASE;
	ent->nr_cands[0] = find_cands(env, st, insn_idx, ref, NULL, ent->cand[0]);
	if (!ent->nr_cands[0] && reg >= &regs[BPF_REG_0] && reg <= &regs[BPF_REG_5])
		return BPF_CONFLICT_CALLER_SAVED;
	return ent_imm(env, ent, reg);
}

/* See ref_ent(). @ref is an iterator or a dynptr, and @slot the first one that it has. */
static int obj_ent(struct bpf_verifier_env *env, struct bpf_pad_ent *ent,
		   const struct bpf_reference_state *ref, const struct bpf_stack_state *slot)
{
	if (ref_release(env, ref, &slot->spilled_ptr, slot->slot_type[0] == STACK_ITER, &ent->release))
		return BPF_CONFLICT_NO_RELEASE;
	if (slot->slot_type[0] == STACK_ITER) {
		ent->class = BPF_PAD_ITER;
		ent->rcu = slot->spilled_ptr.type & MEM_RCU;
	} else {
		ent->class = BPF_PAD_DYNPTR;
	}
	return ent_imm(env, ent, &slot->spilled_ptr);
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
	int class = ref_class(ref), err = 0;

	if (verifier_bug_if(class < 0, env, "no landing pad releases reference type %d", ref->type))
		return -EFAULT;
	memset(ent, 0, sizeof(*ent));
	ent->origin = ref->origin;
	ent->class = class;
	if (class != BPF_PAD_REF)
		ent->release = release_call(class);
	if (class == BPF_PAD_REF || class == BPF_PAD_IRQ)
		ent->nr_cands[0] = find_obj_cands(env, st, insn_idx, ref, ent->cand[0], &obj);
	else
		ent->nr_cands[0] = find_lock_cands(env, st, insn_idx, ref, ent->cand[0]);
	if (class == BPF_PAD_REF && obj)
		err = obj_ent(env, ent, ref, obj);
	else if (class == BPF_PAD_REF)
		err = ptr_ent(env, ent, st, insn_idx, ref);
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
	if (!err && !can_release_under_lock(env, st, st->frame[st->curframe], ent))
		return BPF_CONFLICT_NO_RELEASE;
	if (!err && !ent->nr_cands[0])
		return BPF_CONFLICT_NO_PLACE;
	return err;
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
		    memcmp(&ent->release, &new->release, sizeof(ent->release)) ||
		    ent->obj_type != new->obj_type || ent->rcu != new->rcu)
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

/* refs[@child] of @st was made from the pointer refs[@parent], see invalidate_reference() */
static bool ref_is_child(const struct bpf_verifier_state *st, int child, int parent)
{
	return st->refs[child].type == REF_TYPE_PTR && st->refs[parent].type == REF_TYPE_PTR &&
	       st->refs[child].parent_id == st->refs[parent].id;
}

/*
 * The resources with a handle that the current frame of @st acquired: refs[] from
 * entry_refs on, oldest first. Which entry is one of them? What a pad does with an entry is a call
 * with what it finds at a place, so that is what an entry is, like a variable with a destructor. It
 * does not matter which insn acquired what is there: an iterator that is destroyed and made again
 * is one entry, two nodes that one insn in a loop took off a list are two. Where that leaves a
 * choice the origin decides.
 * Every visit has to hold every entry.
 * Locks and irq flags have to be in refs[] in the order of the plan, and so do a pointer and what
 * was made from it.
 * Returns the reason of a conflict.
 */
static int visit_refs(struct bpf_verifier_env *env, struct bpf_pad_plan *plan,
		      const struct bpf_verifier_state *st, int insn_idx)
{
	const struct bpf_reference_state *ref;
	struct bpf_pad_ent new, *ent;
	int i, j, arg, pass, pos, err;

	/* the pad of a call runs after the call: what is live at the next insn is there */
	insn_idx += plan->kind == BPF_SITE_CALL;
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
		if (!ent || ent->class >= BPF_PAD_REF)
			continue;
		if (ent - plan->ents < pos)
			return BPF_CONFLICT_ORDER_DIFFERS;
		pos = ent - plan->ents;
	}
	for (i = 0; i < plan->nr_ents; i++)
		for (j = 0; j < i; j++)
			if (plan->ents[i].ref >= 0 && plan->ents[j].ref >= 0 &&
			    ref_is_child(st, plan->ents[j].ref, plan->ents[i].ref))
				return BPF_CONFLICT_ORDER_DIFFERS;
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
	case BPF_PLACE_IMM:
		buf[n++] = BPF_MOV64_IMM(reg, place->delta);
		return n;
	}
	if (place->delta)
		buf[n++] = BPF_ALU64_IMM(BPF_ADD, reg, -place->delta);
	return n;
}

/*
 * The turns of a pad. Few functions can be called under a lock, and a release may sleep: locks and
 * irq flags go first, then the pad leaves the sections, pointers and objects go last.
 * An iterator that RCU protects goes ahead of them all: a section or irq flags may be what protects
 * it, see in_rcu_cs(). So it goes under the locks of the frame, see can_release_under_lock().
 */
enum pad_turn {
	PAD_TURN_RCU_ITERS,
	PAD_TURN_LOCKS,
	PAD_TURN_POINTERS,
};

static enum pad_turn release_turn(const struct bpf_pad_ent *ent)
{
	if (ent->rcu)
		return PAD_TURN_RCU_ITERS;
	return ent->class < BPF_PAD_REF ? PAD_TURN_LOCKS : PAD_TURN_POINTERS;
}

/* The insns that release the entries of @plan whose turn it is, the youngest first */
static int release_ents(struct bpf_verifier_env *env, const struct bpf_pad_plan *plan,
			enum pad_turn turn, struct bpf_insn *buf, struct bpf_insn_aux_data *aux)
{
	const struct bpf_pad_ent *ent;
	int i, arg, n = 0;

	for (i = plan->nr_ents - 1; i >= 0; i--) {
		ent = &plan->ents[i];
		if (release_turn(ent) != turn)
			continue;
		for (arg = 0; arg < BPF_PAD_MAX_ARGS && ent->nr_cands[arg]; arg++)
			n += load_handle(env, &buf[n], &aux[n], BPF_REG_1 + arg, &ent->cand[arg][0]);
		if (is_obj_drop(&ent->release))
			aux[n].kptr_struct_meta = btf_find_struct_meta(env->prog->aux->btf,
								       ent->obj_type);
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

	n = release_ents(env, plan, PAD_TURN_RCU_ITERS, buf, aux);
	n += release_ents(env, plan, PAD_TURN_LOCKS, &buf[n], &aux[n]);
	for (class = 0; class < BPF_PAD_NR_SECTIONS; class++)
		for (i = 0; i < plan->sections[class]; i++)
			buf[n++] = release_call(class);
	n += release_ents(env, plan, PAD_TURN_POINTERS, &buf[n], &aux[n]);
	buf[n++] = BPF_MOV64_IMM(BPF_REG_0, bpf_unwound_retval(env, subprog));
	if (bpf_ret_reg_pair(env, subprog))
		buf[n++] = BPF_MOV64_IMM(BPF_REG_2, 0);
	return n;
}

/* Is the first call of the pad of @plan the release of @ent? See bpf_pad_insns(). */
static bool released_first(const struct bpf_pad_plan *plan, const struct bpf_pad_ent *ent)
{
	const struct bpf_pad_ent *other;
	int i;

	for (i = 0; i < plan->nr_ents; i++) {
		other = &plan->ents[i];
		if (release_turn(other) < release_turn(ent) ||
		    (release_turn(other) == release_turn(ent) && other > ent))
			return false;
	}
	return release_turn(ent) != PAD_TURN_POINTERS ||
	       (!plan->sections[BPF_PAD_RCU] && !plan->sections[BPF_PAD_PREEMPT]);
}

/* The calls of a pad clobber it */
static bool place_is_caller_saved(const struct bpf_pad_place *place)
{
	return place->loc == BPF_PLACE_REG && place->at < BPF_REG_6;
}

/*
 * The first candidate of @ent is emitted. Can the pad of @plan use it?
 * Returns the reason of a conflict.
 */
static int settle_ent(struct bpf_verifier_env *env, const struct bpf_pad_plan *plan,
		      struct bpf_pad_ent *ent)
{
	struct bpf_pad_place *cand = ent->cand[0];

	if (place_is_caller_saved(&cand[0]) && !released_first(plan, ent))
		return BPF_CONFLICT_CALLER_SAVED;
	/* R1 is loaded first */
	if (ent->nr_cands[1] && place_is_caller_saved(&ent->cand[1][0]))
		return BPF_CONFLICT_CALLER_SAVED;
	return get_release(env, &ent->release);
}

/* All visits of @plan are over. Returns the reason of a conflict. */
static int settle_plan(struct bpf_verifier_env *env, struct bpf_pad_plan *plan)
{
	struct bpf_insn release;
	int i, class, err = plan->conflict;

	for (i = 0; !err && i < plan->nr_ents; i++)
		err = settle_ent(env, plan, &plan->ents[i]);
	for (class = 0; !err && class < BPF_PAD_NR_SECTIONS; class++) {
		release = release_call(class);
		if (plan->sections[class])
			err = get_release(env, &release);
	}
	return err;
}

/*
 * Sites whose pads have the same insns share one. But not a pad that frees an object of the
 * program: the same insns free another type at another site, see ent_imm().
 */
bool bpf_pad_can_be_shared(const struct bpf_pad_plan *plan)
{
	int i;

	for (i = 0; i < plan->nr_ents; i++)
		if (is_obj_drop(&plan->ents[i].release))
			return false;
	return true;
}

/* 'spin_lock@5(r6-8)': what insn 5 brought to the frame, the arguments of its release */
static void print_ent(struct bpf_verifier_env *env, const struct bpf_pad_ent *ent)
{
	static const char * const class[] = {
		[BPF_PAD_IRQ]			= "irq",
		[BPF_PAD_RES_LOCK]		= "res_lock",
		[BPF_PAD_RES_LOCK_IRQ]		= "res_lock_irq",
		[BPF_PAD_SPIN_LOCK]		= "spin_lock",
		[BPF_PAD_REF]			= "ref",
		[BPF_PAD_ITER]			= "iter",
		[BPF_PAD_DYNPTR]		= "dynptr",
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
		else if (place->loc == BPF_PLACE_IMM)
			verbose(env, "%d", place->delta);
		else if (place->at == BPF_REG_FP)
			verbose(env, "fp");
		else
			verbose(env, "r%d", place->at);
		if (place->delta && place->loc != BPF_PLACE_IMM)
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
		[BPF_SITE_CALL]			= "call",
	};
	static const char * const why[] = {
		[BPF_CONFLICT_SECTIONS_DIFFER]	= "the number of sections differs",
		[BPF_CONFLICT_TOO_MUCH]		= "too much is held",
		[BPF_CONFLICT_NO_RELEASE]	= "the program can call nothing that releases a resource",
		[BPF_CONFLICT_NOT_ALWAYS_HELD]	= "a resource is held on some paths only",
		[BPF_CONFLICT_NO_PLACE]		= "no place has the handle on all paths",
		[BPF_CONFLICT_ORDER_DIFFERS]	= "the order of the releases differs",
		[BPF_CONFLICT_CANNOT_UNWIND]	= "the frame cannot unwind",
		[BPF_CONFLICT_CALLER_SAVED]	= "a handle is in R0-R5 only",
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
