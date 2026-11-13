// SPDX-License-Identifier: GPL-2.0-only
/*
 * Landing pads that the verifier emits.
 *
 * A SITE is an insn at which the verifier lets a frame unwind although the program has no code
 * for that:
 *   - may_goto that the verifier adds
 *   - the check at the entry of a recursive subprog
 *   - a call of a subprog that comes back with unwind_exit and has no unwind_goto after it
 *   - a call of a helper whose callback comes back that way
 *   - a load, a store or an atomic insn in arena, when it faults
 * The resources that the frame acquired since its entry have to be released on the way out. The
 * code that does it is a LANDING PAD: calls of the functions that the program itself would call,
 * then 'r0 = 0' and unwind_exit, or exit in a frame that the kernel called.
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
 *               pass, like any other: of the state that visits, or of the site. Unless the
 *               site has another way out.
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
 * Plans live as long as a pass. A pass that is kept keeps its plans, see bpf_pads_move(). What
 * one pass gives to the next one grows to the safe side: did_unwind of a global subprog and
 * fault_full. bail_unwinds that is cleared late goes to the second run of the same pass only, see
 * check_funcs().
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
 * With bpf_loop(n, wait, ...) in place of wait() it is the same code. The helper is a frame of the
 * kernel between the two. It has a pad of its own, see bpf_call_cb(): unwind_exit of the callback
 * goes there, the helper releases what it holds itself and goes to unwind_goto after its call.
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
 * A state may have the handle in several places, the CANDIDATES. Those that all visits which hold
 * the entry have in common stay, one of them is emitted. The calls of a pad clobber R0-R5: they are
 * places for the first argument of the first call only, see settle_ent().
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
 * WHETHER an entry is held when the pad runs, see settle_ent():
 *   - All visits hold it: the program counter tells.
 *   - A candidate is 0 on all visits that don't: the pad tests it. That is how the program itself
 *     tells, a pointer that is NULL as long as there is nothing to release.
 *   - Otherwise the function gets hidden slots, see below, or there is a conflict.
 * A pointer that the program has not compared with NULL yet when it gets to the site is tested too.
 *
 *	t = NULL;					   r6 = 0
 *	if (pid)					   if r1 == 0 goto 1f
 *		t = bpf_task_from_pid(pid);		   call bpf_task_from_pid
 *	v = wait();					   r6 = r0
 *	if (t)						1: call wait
 *		bpf_task_release(t);			   unwind_goto pad
 *							   ...
 *						      pad: r1 = r6
 *							   if r1 == 0 goto 2f
 *							   call bpf_task_release
 *							2: r0 = 0
 *							   exit
 *
 * A pad has one order, see enum pad_turn, among equals that of refs[], the youngest first. Locks
 * and irq flags have to be released that way, and a dynptr ahead of the pointer that it was made
 * from. States that acquired them in different orders can be a conflict.
 *
 * An ACCESS TO ARENA has unwind_goto after it like a call. It is no code: the handler of the fault
 * looks it up. The pad gets the registers and the stack as they were before the access.
 *
 *	t = bpf_task_from_pid(pid);			   r6 = r0
 *	...						   ...
 *	v = node->val;					   r1 = *(u64 *)(r7 + 8)
 *	bpf_task_release(t);				   unwind_goto pad
 *							   ...
 *						      pad: r1 = r6
 *							   call bpf_task_release
 *							   r0 = 0
 *							   exit
 *
 * It is the one site with another way out: without unwind_goto the handler skips the access, a load
 * reads 0. That is what a conflict means here, see skip_faults(): it does not reject the program.
 * Nor does a call that has nothing but such accesses below it, see bpf_pad_must_unwind().
 *
 * HIDDEN SLOTS are the fallback for what neither the program counter nor a place tells. Here only
 * the program knows what 'own' means:
 *
 *	if (x)						   *(u64 *)(r10 - 8) = 0
 *		t = bpf_task_from_pid(a);		   *(u64 *)(r10 - 16) = 0
 *	else						   ...
 *		t = bpf_task_from_pid(b);		   call bpf_task_from_pid
 *	own = !!t;					   *(u64 *)(r10 - 8) = r0
 *	if (!t)						   ...
 *		t = bpf_get_current_task_btf();		   call bpf_task_from_pid
 *	v = wait(t);					   *(u64 *)(r10 - 16) = r0
 *	if (own)					   ...
 *		bpf_task_release(t);			   call wait
 *							   unwind_goto pad
 *							   ...
 *							   ax = *(u64 *)(r10 - 8)
 *							   if ax != r1 goto 1f
 *							   *(u64 *)(r10 - 8) = 0
 *							   goto 2f
 *							1: ax = *(u64 *)(r10 - 16)
 *							   if ax != r1 goto 2f
 *							   *(u64 *)(r10 - 16) = 0
 *							2: call bpf_task_release
 *							   ...
 *						      pad: r1 = *(u64 *)(r10 - 16)
 *							   if r1 == 0 goto 3f
 *							   call bpf_task_release
 *							3: r1 = *(u64 *)(r10 - 8)
 *							   if r1 == 0 goto 4f
 *							   call bpf_task_release
 *							4: r0 = 0
 *							   exit
 *
 * Each call that acquires has a slot of its own, below the stack of the function, where no access
 * of the program gets. The slots of a frame that are not 0 are, one to one, what the frame holds:
 *   entry       all slots are 0
 *   acquire     the slot takes what the release takes: R0, the address of a lock or of an object
 *   release     the slot that has the handle is cleared. It is found at run time.
 *   pad         'if (slot) release(slot)' over the slots, the same at all sites of the function
 * The stores follow from the insn and from what the main pass notes where it processes the insn,
 * see bpf_pad_note_acquire() and what follows it, never from the states at a site: a state that was
 * pruned or joined on the way does not get there, and which insn acquired a reference is not
 * compared when that is done. What no store can follow is noted as well, see 'no_slots'.
 * A function has slots for a GROUP of classes, see enum bpf_pad_group and settle_slots(). All its
 * pads release that group through the slots alone. All else stays as it is: a program that needs no
 * slot has no store and no byte of stack for them. A site with another way out never asks for them.
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
	plan->nulls.regs = U16_MAX;
	bitmap_fill(plan->nulls.slots, MAX_BPF_STACK_SLOTS);
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
	struct bpf_insn_aux_data *aux = env->insn_aux_data;
	int i;

	env->pads_late = false;
	for (i = 0; i < env->prog->len; i++, aux++) {
		bpf_pad_plans_free(aux);
		kfree(aux->pad_note);
		aux->pad_note = NULL;
	}
}

/*
 * The plans and the notes are what a pass found, like the fixups of the insns, and a pass that
 * is kept can become the result when a later one has an error. So they move with the snapshot
 * of the pass, see copy_snapshot(): to @moved, which has an entry per insn, if @save, else back
 * from there. What was at the destination is freed, and the source has nothing after that.
 */
void bpf_pads_move(struct bpf_verifier_env *env, struct bpf_pads_moved *moved, bool save)
{
	struct bpf_insn_aux_data *aux = env->insn_aux_data;
	int i;

	for (i = 0; i < env->prog->len; i++, aux++, moved++) {
		if (save) {
			free_plans(moved->plans);
			kfree(moved->note);
			moved->plans = aux->pad_plans;
			moved->note = aux->pad_note;
			aux->pad_plans = NULL;
			aux->pad_note = NULL;
		} else {
			free_plans(aux->pad_plans);
			kfree(aux->pad_note);
			aux->pad_plans = moved->plans;
			aux->pad_note = moved->note;
			moved->plans = NULL;
			moved->note = NULL;
		}
	}
}

/* The snapshot that has @moved of @cnt insns is freed */
void bpf_pads_free_moved(struct bpf_pads_moved *moved, u32 cnt)
{
	u32 i;

	for (i = 0; i < cnt; i++) {
		free_plans(moved[i].plans);
		kfree(moved[i].note);
	}
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
	cand[(*nr)++] = (struct bpf_pad_place){ .loc = loc, .at = at, .delta = delta,
						.maybe_null = type_may_be_null(reg->type) };
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
 * the main pass. Nor is a register of which only the lower half is live: the pad reads 64 bits, and
 * 'w6 = 0' is zero extended only if an insn of the program reads the upper half, see zext_dst.
 * Nor is a slot of the spills around bpf_fastcall calls: they are removed unless the
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
		if (aux->live_hi32_before & BIT(i))
			add_cand(cand, &nr, &frame->regs[i], ref, obj, BPF_PLACE_REG, i);
	for (i = 0; i < bpf_stack_nr_slots(frame); i++) {
		slot = bpf_stack_slot(frame, i);
		off = -(i + 1) * BPF_REG_SIZE;
		if (test_bit(i, aux->live_stack_before) && bpf_spill_size(slot) == BPF_REG_SIZE &&
		    off >= fastcall_off)
			add_cand(cand, &nr, &slot->spilled_ptr, ref, obj, BPF_PLACE_SPILL, off);
	}
	for (i = BPF_REG_0; i < BPF_REG_6; i++)
		if (aux->live_hi32_before & BIT(i))
			add_cand(cand, &nr, &frame->regs[i], ref, obj, BPF_PLACE_REG, i);
	return nr;
}

/* The places that have the address of the lock @ref, see find_cands() */
static int find_lock_cands(struct bpf_verifier_env *env, const struct bpf_verifier_state *st,
			   int insn_idx, const struct bpf_reference_state *ref,
			   struct bpf_pad_place *cand)
{
	struct bpf_pad_place kept[BPF_PAD_MAX_CANDS];
	const struct bpf_map *map;
	int i, off, nr = 0, nr_kept;
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
	/* One insn may take one of several such locks. The program keeps the address to unlock. */
	nr_kept = min(find_cands(env, st, insn_idx, ref, NULL, kept), BPF_PAD_MAX_CANDS - nr);
	memcpy(&cand[nr], kept, nr_kept * sizeof(*cand));
	return nr + nr_kept;
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

static bool reg_is_null(const struct bpf_reg_state *reg)
{
	return reg->type == SCALAR_VALUE && tnum_equals_const(reg->var_off, 0);
}

static void find_nulls(const struct bpf_func_state *frame, struct bpf_pad_nulls *nulls)
{
	const struct bpf_stack_state *slot;
	int i, j;

	memset(nulls, 0, sizeof(*nulls));
	for (i = BPF_REG_0; i < BPF_REG_FP; i++)
		if (reg_is_null(&frame->regs[i]))
			nulls->regs |= BIT(i);
	for (i = 0; i < bpf_stack_nr_slots(frame); i++) {
		slot = bpf_stack_slot(frame, i);
		for (j = 0; j < BPF_REG_SIZE && slot->slot_type[j] == STACK_ZERO; j++)
			;
		if (j == BPF_REG_SIZE ||
		    (bpf_spill_size(slot) == BPF_REG_SIZE && reg_is_null(&slot->spilled_ptr)))
			__set_bit(i, nulls->slots);
	}
}

/* An address in the stack and the address of a map value are never 0 */
static bool place_is_null(const struct bpf_pad_nulls *nulls, const struct bpf_pad_place *place)
{
	if (place->loc == BPF_PLACE_REG)
		return nulls->regs & BIT(place->at);
	return place->loc == BPF_PLACE_SPILL &&
	       test_bit(-place->at / BPF_REG_SIZE - 1, nulls->slots);
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
			cand[n] = old[i];
			cand[n++].maybe_null |= place[j].maybe_null;
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

/*
 * @new is one more entry of @plan, number @pos. None of the visits so far held it.
 * Returns it, or NULL if there is no memory.
 */
static struct bpf_pad_ent *add_ent(struct bpf_pad_plan *plan, const struct bpf_pad_ent *new,
				   int pos)
{
	struct bpf_pad_ent *ent;
	int i;

	if (!plan->ents)
		plan->ents = kzalloc_objs(*plan->ents, BPF_PAD_MAX_ENTS, BPF_VERIFIER_GFP);
	if (!plan->ents)
		return NULL;
	ent = &plan->ents[pos];
	memmove(ent + 1, ent, (plan->nr_ents++ - pos) * sizeof(*ent));
	*ent = *new;
	ent->always = !plan->visited;
	/* the address of an object in the stack does not tell whether the object is set up */
	if (ent->class == BPF_PAD_IRQ || ent->class >= BPF_PAD_ITER)
		return ent;
	for (i = 0; i < ent->nr_cands[0]; i++)
		ent->cand[0][i].null = place_is_null(&plan->nulls, &ent->cand[0][i]);
	return ent;
}

/*
 * A visit holds the entries @a and @b of @plan, and @a has to stand before @b: the pad releases
 * @b first. Returns false if another visit wants them the other way round, in one step or in
 * several: no order suits both.
 */
static bool put_before(struct bpf_pad_plan *plan, int a, int b)
{
	int i;

	if (plan->before[b] & BIT(a))
		return false;
	for (i = 0; i < plan->nr_ents; i++)
		if (i == a || (plan->before[i] & BIT(a)))
			plan->before[i] |= BIT(b) | plan->before[b];
	return true;
}

/* The calls of a pad clobber it */
static bool place_is_caller_saved(const struct bpf_pad_place *place)
{
	return place->loc == BPF_PLACE_REG && place->at < BPF_REG_6;
}

/*
 * The pad finds the handle of @ent in a register that its calls clobber: the candidate that
 * settle_ent() takes, when all visits are over
 */
static bool ent_is_clobbered(const struct bpf_pad_ent *ent)
{
	int i;

	for (i = 0; i < ent->nr_cands[0] && !ent->always && !ent->cand[0][i].null; i++)
		;
	return i < ent->nr_cands[0] && place_is_caller_saved(&ent->cand[0][i]);
}

/*
 * Does @a stand before @b where no visit says? The pad releases what stands last first, and that
 * has to be the entry whose handle its calls clobber, see released_first(). Else the one that got
 * to the frame at the lower insn stands first.
 */
static bool ent_stands_before(const struct bpf_pad_ent *a, const struct bpf_pad_ent *b)
{
	bool a_clobbered = ent_is_clobbered(a), b_clobbered = ent_is_clobbered(b);

	return a_clobbered != b_clobbered ? b_clobbered : a->origin < b->origin;
}

/*
 * All visits of @plan are over: put its entries in an order that suits each of them, see
 * visit_refs(). There is one, since put_before() refused what would close a cycle. Of the entries
 * that nothing stands before any more the next one is chosen by what the entries are, see
 * ent_stands_before(), so that the order of what no visit held together does not depend on the
 * visits either.
 */
static int order_ents(struct bpf_verifier_env *env, struct bpf_pad_plan *plan)
{
	int i, j, k, n = plan->nr_ents, next;
	u8 row, bit;

	if (plan->ordered)
		return 0;
	plan->ordered = true;
	for (k = 0; k < n; k++) {
		next = -1;
		for (i = k; i < n; i++) {
			for (j = k; j < n; j++)
				if (plan->before[j] & BIT(i))
					break;
			if (j == n && (next < 0 ||
				       ent_stands_before(&plan->ents[i], &plan->ents[next])))
				next = i;
		}
		/* put_before() keeps a cycle out. A plan that is half in order is no plan. */
		if (verifier_bug_if(next < 0, env, "the entries of a landing pad have no order"))
			return -EFAULT;
		if (next == k)
			continue;
		/* the entries and what is noted about them trade places */
		swap(plan->ents[k], plan->ents[next]);
		swap(plan->before[k], plan->before[next]);
		for (i = 0; i < n; i++) {
			row = plan->before[i];
			bit = (!!(row & BIT(k)) << next) | (!!(row & BIT(next)) << k);
			plan->before[i] = (row & ~(BIT(k) | BIT(next))) | bit;
		}
	}
	return 0;
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
 * An entry need not be held on all visits. What it takes to find out how the pad can tell is noted
 * here, see settle_ent().
 * The pad releases locks and irq flags in the reverse of the order in which a state took them,
 * and what was made from a pointer before the pointer. Only a state that holds two entries says
 * something about their order, and it must not matter which of the states gets here first: the
 * state that holds both has to find them in its own order, not in the order of the visits. So a
 * visit notes the order of the entries that it holds, pair by pair, see put_before(), and
 * order_ents() puts them in an order that suits all visits when they are over. There is none if
 * two states took two locks in two orders: that is the conflict.
 * Returns the reason of a conflict.
 */
static int visit_refs(struct bpf_verifier_env *env, struct bpf_pad_plan *plan,
		      const struct bpf_verifier_state *st, int insn_idx)
{
	const struct bpf_reference_state *ref;
	struct bpf_pad_ent new, *ent, *prev;
	struct bpf_pad_nulls nulls;
	int i, j, arg, pass, err;

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
			if (!ent && plan->nr_ents == BPF_PAD_MAX_ENTS)
				return BPF_CONFLICT_TOO_MUCH;
			/* the place of an entry is its number until order_ents() */
			if (!ent)
				ent = add_ent(plan, &new, plan->nr_ents);
			if (!ent)
				return -ENOMEM;
			ent->ref = i;
			/* whichever state comes first: the insn that brings it to the frame first */
			ent->origin = min(ent->origin, new.origin);
			for (arg = 0; arg < BPF_PAD_MAX_ARGS; arg++)
				ent->nr_cands[arg] = common_cands(ent, &new, arg, ent->cand[arg]);
		}
	}
	prev = NULL;
	for (i = st->frame[st->curframe]->entry_refs; i < st->acquired_refs; i++) {
		ent = held_ent(plan, i);
		if (!ent || ent->class >= BPF_PAD_REF)
			continue;
		if (prev && !put_before(plan, prev - plan->ents, ent - plan->ents))
			return BPF_CONFLICT_ORDER_DIFFERS;
		prev = ent;
	}
	for (i = 0; i < plan->nr_ents; i++)
		for (j = 0; j < plan->nr_ents; j++)
			if (plan->ents[i].ref >= 0 && plan->ents[j].ref >= 0 &&
			    ref_is_child(st, plan->ents[j].ref, plan->ents[i].ref) &&
			    !put_before(plan, i, j))
				return BPF_CONFLICT_ORDER_DIFFERS;
	find_nulls(st->frame[st->curframe], &nulls);
	for (i = 0; i < plan->nr_ents; i++) {
		ent = &plan->ents[i];
		if (ent->ref >= 0)
			continue;
		ent->always = false;
		for (j = 0; j < ent->nr_cands[0]; j++)
			ent->cand[0][j].null &= place_is_null(&nulls, &ent->cand[0][j]);
	}
	plan->nulls.regs &= nulls.regs;
	bitmap_and(plan->nulls.slots, plan->nulls.slots, nulls.slots, MAX_BPF_STACK_SLOTS);
	return 0;
}

/*
 * The current frame of @st is about to be unwound at the site of @kind at @insn_idx. Make the plan
 * of the site serve @st too. A visit at which the frame holds nothing is a visit like any other.
 *
 * Sections: the pad leaves as many as the frame has entered. That is a number of calls in the
 * code of the pad, so it has to be the same on all visits, or the function gets hidden slots.
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
			plan->sections_differ |= BIT(class);
		plan->sections[class] = nr;
	}
	plan->visited = true;
	return plan;
}

/* The group of @class */
static int class_group(int class)
{
	if (class < BPF_PAD_NR_SECTIONS)
		return class;
	return class < BPF_PAD_REF ? BPF_PAD_GROUP_LOCKS : BPF_PAD_GROUP_REFS;
}

/* How many of refs[@from] .. refs[@to - 1] of @st are of @group */
static int count_refs(const struct bpf_verifier_state *st, int from, int to, int group)
{
	int i, n = 0;

	for (i = from; i < to; i++)
		n += class_group(ref_class(&st->refs[i])) == group;
	return n;
}

/* NULL if there is no memory */
static struct bpf_pad_note *pad_note_get(struct bpf_verifier_env *env, int insn_idx)
{
	struct bpf_insn_aux_data *aux = &env->insn_aux_data[insn_idx];

	if (!aux->pad_note)
		aux->pad_note = kzalloc_obj(*aux->pad_note, BPF_VERIFIER_GFP);
	return aux->pad_note;
}

/*
 * What the current insn does to a resource of @group concerns a frame that waits in a call, where
 * no store can follow it. It may be the same object that another frame holds once more. So none
 * of the functions on the stack gets hidden slots for @group.
 */
void bpf_pad_no_slots(struct bpf_verifier_env *env, enum bpf_pad_group group)
{
	const struct bpf_verifier_state *st = env->cur_state;
	int f;

	for (f = 0; f <= st->curframe; f++)
		env->subprog_info[st->frame[f]->subprogno].no_slots |= BIT(group);
}

/*
 * Make @ent what a hidden slot is to a plan if it has what is in @reg: the handle of @ref, which
 * is one of refs[] of @st, plus a constant. @by_type: no insn of the function acquired @ref.
 * False if there is no such entry.
 */
static bool slot_ent(struct bpf_verifier_env *env, struct bpf_pad_ent *ent,
		     const struct bpf_verifier_state *st, const struct bpf_reference_state *ref,
		     const struct bpf_reg_state *reg, bool by_type)
{
	s64 off = reg->var_off.value;
	int err = 0;

	if (!tnum_is_const(reg->var_off))
		return false;
	memset(ent, 0, sizeof(*ent));
	ent->ref = -1;
	ent->class = ref_class(ref);
	ent->nr_cands[0] = 1;
	ent->cand[0][0] = (struct bpf_pad_place){ .loc = BPF_PLACE_SPILL, .null = true };
	if (ent->class == BPF_PAD_RES_LOCK_IRQ)
		ent->cand[1][ent->nr_cands[1]++] = ent->cand[0][0];
	if (ent->class != BPF_PAD_REF) {
		ent->release = release_call(ent->class);
	} else if (reg->type == PTR_TO_STACK) {
		err = obj_ent(env, ent, ref, bpf_stack_slot(st->frame[reg->frameno],
							    -off / BPF_REG_SIZE - 1));
	} else {
		ent->cand[0][0].delta = off;
		err = by_type ? type_release(env, reg, 0, &ent->release) :
				ref_release(env, ref, reg, false, &ent->release);
		err = err ?: ent_imm(env, ent, reg);
		err = err ?: off != (s16)off;
	}
	return !err;
}

/*
 * The call at @insn_idx, in @sub, brings @ent to a frame that holds @held of the group. R@src goes
 * to the slot. The stores at an insn and the entry of its slots are code: all states that get to
 * the insn have to agree on them. Locks and irq flags are released in the order of the run, which
 * slots don't have: one at a time.
 */
static void note_acquire(struct bpf_verifier_env *env, struct bpf_subprog_info *sub, int insn_idx,
			 const struct bpf_pad_ent *ent, int src, int held)
{
	struct bpf_pad_note *note = pad_note_get(env, insn_idx);
	int group = class_group(ent->class);

	if (!note) {
		sub->no_slots |= BIT(group);
		return;
	}
	if (!note->acquires) {
		note->acquires = true;
		note->src = src;
		note->ent = *ent;
		note->ent.origin = insn_idx;
	}
	if (note->src != src || note->ent.class != ent->class || note->ent.rcu != ent->rcu ||
	    memcmp(&note->ent.release, &ent->release, sizeof(ent->release)) ||
	    note->ent.obj_type != ent->obj_type ||
	    note->ent.cand[0][0].delta != ent->cand[0][0].delta ||
	    held >= BPF_PAD_MAX_ENTS || (held && group == BPF_PAD_GROUP_LOCKS))
		sub->no_slots |= BIT(group) | BIT(class_group(note->ent.class));
	else
		note->held = max_t(int, note->held, held);
}

/*
 * The current insn acquired the youngest of refs[]. @reg has what the release takes: R0, or the
 * argument that is the address of the lock or of the object in the stack.
 * No slot: the argument is in the stack. A reference with a parent, which has to be released
 * first. bpf_map_lookup_elem(): what it returns has to be released if the map has sockets.
 */
void bpf_pad_note_acquire(struct bpf_verifier_env *env, const struct bpf_reg_state *reg)
{
	const struct bpf_insn *insn = &env->prog->insnsi[env->insn_idx];
	const struct bpf_verifier_state *st = env->cur_state;
	const struct bpf_func_state *frame = st->frame[st->curframe];
	const struct bpf_reference_state *ref = &st->refs[st->acquired_refs - 1];
	struct bpf_subprog_info *sub = &env->subprog_info[frame->subprogno];
	int group = class_group(ref_class(ref));
	struct bpf_pad_ent ent;

	if (reg < &frame->regs[BPF_REG_0] || reg > &frame->regs[BPF_REG_5] ||
	    (ref->type == REF_TYPE_PTR && ref->parent_id) ||
	    (bpf_helper_call(insn) && insn->imm == BPF_FUNC_map_lookup_elem) ||
	    !slot_ent(env, &ent, st, ref, reg, false) ||
	    !can_release_under_lock(env, st, frame, &ent))
		sub->no_slots |= BIT(group);
	else
		note_acquire(env, sub, env->insn_idx, &ent, reg - frame->regs,
			     count_refs(st, frame->entry_refs, st->acquired_refs - 1, group));
}

/*
 * If @ref is an object in the stack: its first slot, and its address goes to @addr.
 * NULL otherwise.
 */
static const struct bpf_stack_state *find_obj(const struct bpf_verifier_state *st,
					      const struct bpf_reference_state *ref,
					      struct bpf_reg_state *addr)
{
	int f, i;

	for (f = st->curframe; f >= 0 && !(ref->type & REF_TYPE_LOCK_MASK); f--) {
		for (i = 0; i < bpf_stack_nr_slots(st->frame[f]); i++) {
			if (!slot_is_obj(st->frame[f], i, ref))
				continue;
			*addr = st->frame[f]->regs[BPF_REG_FP];
			addr->var_off = tnum_const(-(i + 1) * BPF_REG_SIZE);
			return bpf_stack_slot(st->frame[f], i);
		}
	}
	return NULL;
}

/* The current insn, in @sub, releases a resource of @group. R@reg has the handle plus @delta. */
static void note_release(struct bpf_verifier_env *env, struct bpf_subprog_info *sub, int group,
			 int reg, int delta)
{
	struct bpf_pad_note *note = pad_note_get(env, env->insn_idx);

	if (!note) {
		sub->no_slots |= BIT(group);
		return;
	}
	if (!note->releases) {
		note->releases = true;
		note->group = group;
		note->reg = reg;
		note->delta = delta;
	}
	if (note->group != group || note->reg != reg || note->delta != delta)
		sub->no_slots |= BIT(group) | BIT(note->group);
}

/*
 * The current insn releases refs[@idx] of the current state. The slot that has the handle is found
 * at run time, by the register among R1-R5 that has it too. A register that the insn does not
 * read may have anything in a state that was not looked at.
 */
void bpf_pad_note_release(struct bpf_verifier_env *env, int idx)
{
	const struct bpf_verifier_state *st = env->cur_state;
	const struct bpf_func_state *frame = st->frame[st->curframe];
	const struct bpf_reference_state *ref = &st->refs[idx];
	struct bpf_subprog_info *sub = &env->subprog_info[frame->subprogno];
	int r, nr = 0, group = class_group(ref_class(ref));
	const struct bpf_stack_state *obj;
	struct bpf_pad_place place = {};
	struct bpf_reg_state addr;

	if (env->pad_releases)
		return;
	if (idx < frame->entry_refs) {
		bpf_pad_no_slots(env, group);
		return;
	}
	obj = find_obj(st, ref, &addr);
	/* irq flags that a lock saved are the second word of its slot */
	if (ref->type == REF_TYPE_IRQ && obj && obj->spilled_ptr.irq.kfunc_class == IRQ_LOCK_KFUNC)
		return;
	for (r = BPF_REG_1; r <= BPF_REG_5 && !nr; r++)
		if (env->insn_aux_data[env->insn_idx].live_regs_before & BIT(r))
			add_cand(&place, &nr, &frame->regs[r], ref, obj ? &addr : NULL,
				 BPF_PLACE_REG, r);
	if (!nr || place.delta != (s16)place.delta)
		sub->no_slots |= BIT(group);
	else
		note_release(env, sub, group, place.at, place.delta);
}

/* The current insn enters a section of @class, or leaves one. It has not changed the state yet. */
void bpf_pad_note_section(struct bpf_verifier_env *env, enum bpf_pad_class class, bool enter)
{
	const struct bpf_verifier_state *st = env->cur_state;
	struct bpf_subprog_info *sub = &env->subprog_info[st->frame[st->curframe]->subprogno];
	struct bpf_pad_ent ent = {
		.ref = -1,
		.class = class,
		.release = release_call(class),
		.nr_cands[0] = 1,
		.cand[0][0] = { .loc = BPF_PLACE_SPILL, .null = true },
	};

	if (enter)
		note_acquire(env, sub, env->insn_idx, &ent, 0, frame_sections(st, class));
	else if (frame_sections(st, class))
		note_release(env, sub, class, 0, 0);
	else
		bpf_pad_no_slots(env, class_group(class));
}

/*
 * The current frame of @st returns to the call at @call_idx in @caller, with what it acquired and
 * did not release. @plain: with exit, and it is no callback.
 * One pointer that is in R0 is what a kfunc returns: the call acquires it. What releases it follows
 * from its type: states with the same pointer from different insns are the same to the main pass.
 * The store after the call takes R0 as it is, so it has to be 0 when nothing comes with it.
 * Nothing else has a store: it goes past the store if the frame unwinds.
 */
void bpf_pad_note_return(struct bpf_verifier_env *env, const struct bpf_verifier_state *st,
			 const struct bpf_func_state *caller, int call_idx, bool plain)
{
	const struct bpf_func_state *callee = st->frame[st->curframe];
	const struct bpf_reference_state *ref = &st->refs[callee->entry_refs];
	struct bpf_subprog_info *sub = &env->subprog_info[caller->subprogno];
	struct bpf_insn_aux_data *aux = &env->insn_aux_data[call_idx];
	const struct bpf_reg_state *r0 = &callee->regs[BPF_REG_0];
	int i, nr = st->acquired_refs - callee->entry_refs, in_r0 = 0;
	struct bpf_pad_place place;
	struct bpf_pad_ent ent;

	for (i = 0; i < BPF_PAD_NR_SECTIONS; i++)
		if (frame_sections(st, i))
			sub->no_slots |= BIT(i);
	if (plain && nr == 1 && ref->type == REF_TYPE_PTR && !ref->parent_id)
		add_ref_cand(&place, &in_r0, r0, ref, BPF_PLACE_REG, BPF_REG_0);
	if (in_r0 && slot_ent(env, &ent, st, ref, r0, true) &&
	    can_release_under_lock(env, st, caller, &ent)) {
		note_acquire(env, sub, call_idx, &ent, BPF_REG_0,
			     count_refs(st, caller->entry_refs, callee->entry_refs,
					BPF_PAD_GROUP_REFS));
	} else {
		for (i = 0; i < nr; i++)
			sub->no_slots |= BIT(class_group(ref_class(&ref[i])));
		aux->call_brings_nothing |= plain && !reg_is_null(r0);
	}
	if (aux->call_brings_nothing && aux->pad_note && aux->pad_note->acquires)
		sub->no_slots |= BIT(BPF_PAD_GROUP_REFS);
}

/* The pad finds out by itself whether it has to release @ent: what is at the place may be 0 */
static bool ent_is_tested(const struct bpf_pad_ent *ent)
{
	return !ent->always || ent->cand[0][0].maybe_null;
}

/*
 * R@reg = the handle that is at @place. @test: if there is 0 the entry is not held, the second insn
 * is a jump, and release_ents() knows where to. It comes first: 0 minus the delta is not 0.
 * Returns the number of insns.
 */
static int load_handle(struct bpf_verifier_env *env, struct bpf_insn *buf,
		       struct bpf_insn_aux_data *aux, int reg, const struct bpf_pad_place *place,
		       bool test)
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
	if (test)
		buf[n++] = BPF_JMP_IMM(BPF_JEQ, reg, 0, 0);
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
	int i, arg, first, n = 0;

	for (i = plan->nr_ents - 1; i >= 0; i--) {
		ent = &plan->ents[i];
		if (release_turn(ent) != turn)
			continue;
		first = n;
		for (arg = 0; arg < BPF_PAD_MAX_ARGS && ent->nr_cands[arg]; arg++)
			n += load_handle(env, &buf[n], &aux[n], BPF_REG_1 + arg, &ent->cand[arg][0],
					 !arg && ent_is_tested(ent));
		if (is_obj_drop(&ent->release))
			aux[n].kptr_struct_meta = btf_find_struct_meta(env->prog->aux->btf,
								       ent->obj_type);
		buf[n++] = ent->release;
		if (ent_is_tested(ent))
			buf[first + 1].off = n - first - 2;
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

/*
 * How does the pad of @plan tell whether @ent is held? See the comment at the top. The candidate
 * that is emitted goes first. Returns the reason of a conflict.
 */
static int settle_ent(struct bpf_verifier_env *env, const struct bpf_pad_plan *plan,
		      struct bpf_pad_ent *ent)
{
	struct bpf_pad_place *cand = ent->cand[0];
	int i;

	for (i = 0; i < ent->nr_cands[0] && !ent->always && !cand[i].null; i++)
		;
	if (i == ent->nr_cands[0])
		return BPF_CONFLICT_NOT_ALWAYS_HELD;
	swap(cand[0], cand[i]);
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

	if (!err && plan->sections_differ)
		err = BPF_CONFLICT_SECTIONS_DIFFER;
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
 * Is the pad the only way out of the site of @plan? An access to arena that faults can be skipped.
 * So can all of them below a call, unless a subprog comes back to the call that is left elsewhere.
 */
bool bpf_pad_must_unwind(struct bpf_verifier_env *env, const struct bpf_pad_plan *plan)
{
	int s;

	if (plan->kind != BPF_SITE_CALL)
		return plan->kind != BPF_SITE_FAULT;
	bpf_pad_for_each_callee(plan, s)
		if (env->subprog_info[s].must_unwind)
			return true;
	return false;
}

/* What a subprog is left for may be found after its callers were unwound: look at them again */
void bpf_pads_must_unwind(struct bpf_verifier_env *env)
{
	struct bpf_subprog_info *sub;
	const struct bpf_pad_plan *plan;
	bool changed;
	int i, s;

	do {
		changed = false;
		for (s = 0; s < env->subprog_cnt; s++) {
			sub = &env->subprog_info[s];
			for (i = sub->start; i < sub[1].start && !sub->must_unwind; i++) {
				plan = bpf_pad_plan(&env->insn_aux_data[i], BPF_SITE_CALL);
				sub->must_unwind = plan && bpf_pad_must_unwind(env, plan);
				changed |= sub->must_unwind;
			}
		}
	} while (changed);
}

/*
 * The groups of which @plan has something that its pad cannot tell whether it is held. Slots are
 * stores on the normal path: none where there is another way out, and none for a site that the
 * program does not have.
 */
static u8 plan_needs_slots(struct bpf_verifier_env *env, const struct bpf_pad_plan *plan)
{
	u8 groups = plan->sections_differ;
	int i, err;

	if (!plan->used || plan->conflict || !bpf_pad_must_unwind(env, plan))
		return 0;
	for (i = 0; i < plan->nr_ents; i++) {
		err = settle_ent(env, plan, &plan->ents[i]);
		if (err == BPF_CONFLICT_NOT_ALWAYS_HELD || err == BPF_CONFLICT_CALLER_SAVED)
			groups |= BIT(class_group(plan->ents[i].class));
	}
	return groups;
}

/* The slot of bpf_res_spin_lock_irqsave() has a word for the second argument of the release */
static int slot_words(const struct bpf_pad_note *note)
{
	return note->ent.class == BPF_PAD_RES_LOCK_IRQ ? 2 : 1;
}

/* Does the pad of @plan run in a frame that has set up its hidden slots? */
static bool plan_has_slots(const struct bpf_pad_plan *plan)
{
	return plan->kind != BPF_SITE_RECURSION && !plan->conflict;
}

/* Has @plan room for @slots entries in place of those that it has of @group? */
static bool plan_has_room(const struct bpf_pad_plan *plan, int group, int slots)
{
	int i;

	for (i = 0; i < plan->nr_ents; i++)
		slots += class_group(plan->ents[i].class) != group;
	return slots <= BPF_PAD_MAX_ENTS;
}

/*
 * The pad of @plan releases what the frame holds of @group through the hidden slots of the @nr
 * calls @notes and in no other way. A slot is an entry that is tested. For the order of a pad, see
 * enum pad_turn, the slots of sections go before all entries, those of references after
 * them, those of locks and irq flags after all entries.
 */
static int plan_take_slots(struct bpf_pad_plan *plan, int group, struct bpf_pad_note **notes,
			   int nr)
{
	struct bpf_pad_ent new, *ent;
	int i, k, pos = 0;

	for (i = 0, k = 0; i < plan->nr_ents; i++)
		if (class_group(plan->ents[i].class) != group)
			plan->ents[k++] = plan->ents[i];
	plan->nr_ents = k;
	if (group < BPF_PAD_NR_SECTIONS) {
		plan->sections[group] = 0;
		plan->sections_differ &= ~BIT(group);
	}
	if (group == BPF_PAD_GROUP_LOCKS)
		pos = plan->nr_ents;
	while (group == BPF_PAD_GROUP_REFS && pos < plan->nr_ents &&
	       plan->ents[pos].class < BPF_PAD_NR_SECTIONS)
		pos++;
	for (i = 0; i < nr; i++) {
		for (k = 0; k < notes[i]->nr_slots; k++) {
			new = notes[i]->ent;
			new.cand[0][0].at = notes[i]->off - k * BPF_REG_SIZE;
			if (slot_words(notes[i]) == 2)
				new.cand[1][0].at = notes[i]->off - BPF_REG_SIZE;
			ent = add_ent(plan, &new, pos++);
			if (!ent)
				return -ENOMEM;
			ent->always = false;
			ent->cand[0][0].null = true;
		}
	}
	return 0;
}

/*
 * Give subprog @s hidden slots for all that it acquires of @group, below its stack: every access of
 * the program to the frame, also one of a callee through a pointer, has raised stack_depth.
 * A call that is on no cycle runs once per frame: one slot. Any other has one more than the frame
 * holds of the group when it gets there, so that one is free.
 * Returns 0 if that cannot be: a release that the program cannot call, no room in a pad or in the
 * stack.
 */
static int subprog_take_slots(struct bpf_verifier_env *env, int s, int group)
{
	struct bpf_subprog_info *sub = &env->subprog_info[s];
	struct bpf_insn_aux_data *aux = env->insn_aux_data;
	struct bpf_pad_note *note, *notes[BPF_PAD_MAX_ENTS];
	int i, err, nr = 0, slots = 0, words = 0;
	struct bpf_pad_plan *plan;

	for (i = sub->start; i < sub[1].start; i++) {
		note = aux[i].pad_note;
		if (!note || !note->acquires || class_group(note->ent.class) != group)
			continue;
		err = nr < BPF_PAD_MAX_ENTS ? get_release(env, &note->ent.release) : 1;
		if (err)
			return min(err, 0);
		notes[nr++] = note;
		note->nr_slots = bpf_loop_at_index(env, i) < 0 ? 1 : 1 + note->held;
		note->off = -(int)bpf_stack_depth_with_slots(sub) - (words + 1) * BPF_REG_SIZE;
		slots += note->nr_slots;
		words += note->nr_slots * slot_words(note);
	}
	if (!nr)
		return 0;
	for (i = sub->start; i < sub[1].start; i++)
		for (plan = aux[i].pad_plans; plan; plan = plan->next)
			if (plan->used && plan_has_slots(plan) &&
			    !plan_has_room(plan, group, slots) && bpf_pad_must_unwind(env, plan))
				return 0;
	sub->hidden_words += words;
	err = bpf_hidden_slots_fit(env);
	if (err <= 0) {
		sub->hidden_words -= words;
		return err;
	}
	for (i = sub->start; i < sub[1].start; i++) {
		for (plan = aux[i].pad_plans; plan; plan = plan->next) {
			/* it has another way out */
			if (plan_has_slots(plan) && !plan_has_room(plan, group, slots))
				plan->conflict = BPF_CONFLICT_SLOTS_FULL;
			err = plan_has_slots(plan) ? plan_take_slots(plan, group, notes, nr) : 0;
			if (err)
				return err;
		}
	}
	sub->slots |= BIT(group);
	return 1;
}

/*
 * Hidden slots are the fallback: a subprog gets them for a group of which one of its plans has
 * something that the pad cannot tell otherwise. A slot takes the first call of a pad from an entry
 * that is in R0-R5, so look again. If the subprog cannot have them its plans stay as they are.
 */
static int settle_slots(struct bpf_verifier_env *env)
{
	struct bpf_insn_aux_data *aux = env->insn_aux_data;
	struct bpf_subprog_info *sub;
	struct bpf_pad_plan *plan;
	int i, s, err;
	u8 need;

	for (s = 0; s < env->subprog_cnt; s++) {
		env->subprog_info[s].slots = 0;
		env->subprog_info[s].hidden_words = 0;
	}
	for (s = 0; s < env->subprog_cnt; s++) {
		sub = &env->subprog_info[s];
		do {
			if (bpf_must_abort())
				return -EINTR;
			need = 0;
			for (i = sub->start; i < sub[1].start; i++)
				for (plan = aux[i].pad_plans; plan; plan = plan->next)
					need |= plan_needs_slots(env, plan);
			need &= ~sub->no_slots;
			err = need ? subprog_take_slots(env, s, __ffs(need)) : 0;
			if (err < 0)
				return err;
			if (need && !err)
				sub->no_slots |= BIT(__ffs(need));
		} while (need);
	}
	return 0;
}

static bool note_has_slots(const struct bpf_subprog_info *sub, const struct bpf_pad_note *note)
{
	return note && note->acquires && (sub->slots & BIT(class_group(note->ent.class)));
}

/*
 * The calls of subprog @s that have hidden slots go to @notes, which has room for BPF_PAD_MAX_ENTS.
 * A slot is an entry of each plan of the subprog, so all groups together have no more slots than
 * that, see plan_has_room(), and the insns of the stores are sized for as many, see
 * BPF_PAD_MAX_SLOT_INSNS. Nothing else keeps the calls that few: check it where they are written.
 * Returns how many there are.
 */
int bpf_pad_slot_notes(struct bpf_verifier_env *env, int s, const struct bpf_pad_note **notes)
{
	const struct bpf_subprog_info *sub = &env->subprog_info[s];
	const struct bpf_pad_note *note;
	int i, nr = 0, slots = 0;

	for (i = sub->start; i < sub[1].start; i++) {
		note = env->insn_aux_data[i].pad_note;
		if (!note_has_slots(sub, note))
			continue;
		slots += note->nr_slots;
		if (verifier_bug_if(slots > BPF_PAD_MAX_ENTS, env,
				    "func#%d has %d hidden slots, a landing pad has %d entries",
				    s, slots, BPF_PAD_MAX_ENTS))
			return -EFAULT;
		notes[nr++] = note;
	}
	return nr;
}

/*
 * The entry of a function: all words of its hidden slots are 0. The frame holds nothing of its own,
 * and a pad reads all slots, also at a site that is before the calls that fill them.
 */
int bpf_pad_entry_insns(const struct bpf_pad_note **notes, int nr, struct bpf_insn *buf)
{
	int i, k, n = 0;

	for (i = 0; i < nr; i++)
		for (k = 0; k < notes[i]->nr_slots * slot_words(notes[i]); k++)
			buf[n++] = BPF_ST_MEM(BPF_DW, BPF_REG_FP, notes[i]->off - k * BPF_REG_SIZE,
					      0);
	return n;
}

/*
 * The call of @note acquires: a slot takes what the release takes, unconditionally. 0 in R0 means
 * that nothing was acquired, and 0 in a slot means the same. A section has no handle: 1.
 * If the call has several slots the first one that is 0 is filled. The frame holds no more than
 * 'held' of the group, so there is one.
 */
static int set_insns(const struct bpf_pad_note *note, struct bpf_insn *buf)
{
	int k, n = 0, nr = note->nr_slots, off = note->off;

	for (k = 0; k < nr; k++, off -= BPF_REG_SIZE) {
		if (nr > 1) {
			buf[n++] = BPF_LDX_MEM(BPF_DW, BPF_REG_AX, BPF_REG_FP, off);
			buf[n++] = BPF_JMP_IMM(BPF_JNE, BPF_REG_AX, 0, k == nr - 1 ? 1 : 2);
		}
		if (note->ent.class < BPF_PAD_NR_SECTIONS)
			buf[n++] = BPF_ST_MEM(BPF_DW, BPF_REG_FP, off, 1);
		else
			buf[n++] = BPF_STX_MEM(BPF_DW, BPF_REG_FP, note->src, off);
		if (k < nr - 1)
			buf[n++] = BPF_JMP_A((nr - 1 - k) * 4 - 1);
	}
	/* the irq flags, the next argument: the pad reads the word if the slot is not 0 */
	if (slot_words(note) == 2)
		buf[n++] = BPF_STX_MEM(BPF_DW, BPF_REG_FP, note->src + 1, off);
	return n;
}

/*
 * The call of @rel releases: the slot of the group that has the handle is cleared, whichever call
 * filled it in this run. The first match ends the search: two references to one object are the
 * same handle in two slots, and one of them is released. No match: the call was given NULL.
 * Sections are all alike: the first slot that is not 0.
 */
static int clear_insns(const struct bpf_pad_note **notes, int nr, const struct bpf_pad_note *rel,
		       struct bpf_insn *buf)
{
	int i, k, n = 0, off, delta, reg;

	for (i = 0; i < nr; i++) {
		if (class_group(notes[i]->ent.class) != rel->group)
			continue;
		delta = rel->delta - notes[i]->ent.cand[0][0].delta;
		/*
		 * The delta is made of constants that the program chose, the offsets of a node in
		 * its object. It is added in R0, which a call is about to clobber: there the JIT
		 * blinds it like any other constant of the program. An insn on AX is not blinded.
		 */
		reg = delta ? BPF_REG_0 : BPF_REG_AX;
		for (k = 0; k < notes[i]->nr_slots; k++) {
			off = notes[i]->off - k * BPF_REG_SIZE;
			buf[n++] = BPF_LDX_MEM(BPF_DW, reg, BPF_REG_FP, off);
			if (delta)
				buf[n++] = BPF_ALU64_IMM(BPF_ADD, reg, delta);
			if (rel->group < BPF_PAD_NR_SECTIONS)
				buf[n++] = BPF_JMP_IMM(BPF_JEQ, reg, 0, 2);
			else
				buf[n++] = BPF_JMP_REG(BPF_JNE, reg, rel->reg, 2);
			buf[n++] = BPF_ST_MEM(BPF_DW, BPF_REG_FP, off, 0);
			buf[n++] = BPF_JMP_A(0);
		}
	}
	/* nothing follows the last slot */
	buf[--n - 2].off = 1;
	for (i = 0; i < n; i++)
		if (buf[i].code == (BPF_JMP | BPF_JA))
			buf[i].off = n - i - 1;
	return n;
}

/* The insns that go before the call of @note in @sub. @notes: the @nr calls with slots. */
int bpf_pad_insns_before(const struct bpf_subprog_info *sub, const struct bpf_pad_note **notes,
			 int nr, const struct bpf_pad_note *note, struct bpf_insn *buf)
{
	int n = 0;

	if (note && note->releases && (sub->slots & BIT(note->group)))
		n = clear_insns(notes, nr, note, buf);
	/* an address that the call takes. The resource is held when the call returns. */
	if (note_has_slots(sub, note) && note->ent.class != BPF_PAD_REF)
		n += set_insns(note, &buf[n]);
	return n;
}

/* The insns that go after the call of @note, which is in @sub */
int bpf_pad_insns_after(const struct bpf_subprog_info *sub, const struct bpf_pad_note *note,
			struct bpf_insn *buf)
{
	int n = 0;

	if (!note_has_slots(sub, note))
		return 0;
	if (note->ent.class == BPF_PAD_REF)
		return set_insns(note, buf);
	/* the lock was not taken. The upper half of an int is not defined. */
	if (note->ent.class == BPF_PAD_RES_LOCK || note->ent.class == BPF_PAD_RES_LOCK_IRQ) {
		buf[n++] = BPF_JMP32_IMM(BPF_JEQ, BPF_REG_0, 0, 1);
		buf[n++] = BPF_ST_MEM(BPF_DW, BPF_REG_FP, note->off, 0);
	}
	return n;
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

/*
 * 'spin_lock@5(r6-8)': what insn 5 brought to the frame, the arguments of its release.
 * 'if not 0': the pad tests the first one.
 */
static void print_ent(struct bpf_verifier_env *env, const struct bpf_pad_ent *ent)
{
	static const char * const class[] = {
		[BPF_PAD_RCU]			= "rcu",
		[BPF_PAD_PREEMPT]		= "preempt",
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
	verbose(env, ")%s ", ent_is_tested(ent) ? " if not 0" : "");
}

/* The plan of the site at insn @i, or why there is none */
static void print_plan(struct bpf_verifier_env *env, int i, const struct bpf_pad_plan *plan)
{
	static const char * const kind[] = {
		[BPF_SITE_GUARD]		= "may_goto",
		[BPF_SITE_RECURSION]		= "recursion check",
		[BPF_SITE_CALL]			= "call",
		[BPF_SITE_FAULT]		= "arena access",
	};
	static const char * const why[] = {
		[BPF_CONFLICT_SECTIONS_DIFFER]	= "the number of sections differs",
		[BPF_CONFLICT_TOO_MUCH]		= "too much is held",
		[BPF_CONFLICT_SLOTS_FULL]	=
			"the function has more hidden slots than a pad has entries",
		[BPF_CONFLICT_NO_RELEASE]	= "the program can call nothing that releases a resource",
		[BPF_CONFLICT_NOT_ALWAYS_HELD]	= "a resource is held on some paths only",
		[BPF_CONFLICT_NO_PLACE]		= "no place has the handle on all paths",
		[BPF_CONFLICT_ORDER_DIFFERS]	= "the order of the releases differs",
		[BPF_CONFLICT_CANNOT_UNWIND]	=
			"the JIT or the helper that calls the function cannot unwind it",
		[BPF_CONFLICT_NO_EXIT]		= "the function has no exit",
		[BPF_CONFLICT_NO_PERFMON]	= "the program is loaded without CAP_PERFMON",
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
 * The site of @plan, at insn @i, has no pad. An access to arena: it is skipped when it faults.
 * What follows the access was verified, and less unwinds than the main pass looked at.
 * Or it is a call, and only accesses to arena unwind below it. They are skipped: what came back to
 * the call cannot unwind, nor can what came back to the calls in there. The pass is done again,
 * and they cannot from its start, see check_funcs().
 */
static int skip_faults(struct bpf_verifier_env *env, int i, const struct bpf_pad_plan *plan)
{
	struct bpf_insn_aux_data *aux = env->insn_aux_data;
	int s, c, cnt = env->subprog_cnt;
	struct bpf_subprog_info *sub;
	unsigned long *todo;

	if (plan->kind == BPF_SITE_FAULT) {
		aux[i].fault_skips = true;
		return 0;
	}
	todo = bitmap_zalloc(cnt, BPF_VERIFIER_GFP);
	if (!todo)
		return -ENOMEM;
	env->faults_late = true;
	bpf_pad_for_each_callee(plan, c)
		__set_bit(c, todo);
	while ((s = find_first_bit(todo, cnt)) < cnt) {
		__clear_bit(s, todo);
		sub = &env->subprog_info[s];
		if (!sub->bail_unwinds)
			continue;
		sub->bail_unwinds = false;
		for (i = sub->start; i < sub[1].start; i++) {
			plan = bpf_pad_plan(&aux[i], BPF_SITE_CALL);
			if (plan)
				bpf_pad_for_each_callee(plan, c)
					__set_bit(c, todo);
		}
	}
	bitmap_free(todo);
	return 0;
}

/*
 * The main pass unwinds at more sites than the program has in the end: pass 0 takes the edge of
 * may_goto in every loop that nothing stops, and a loop that has a trip count gets no may_goto.
 * The states that left a frame there went on to the callers, and visited the plans of the calls.
 * Note the sites at which the program does leave a frame. The caller has dropped the guards and
 * marked the subprogs that unwind, see bpf_mark_subprogs_that_unwind(): the emission asks the
 * same, and what it is going to use is among what is marked here. Only these plans are settled.
 * What a state found at any other site, a conflict or a need for hidden slots, does not count.
 */
void bpf_pads_mark_used(struct bpf_verifier_env *env)
{
	struct bpf_pad_plan *plan;
	int i;

	for (i = 0; i < env->prog->len; i++)
		for (plan = env->insn_aux_data[i].pad_plans; plan; plan = plan->next)
			plan->used = bpf_site_is_used(env, i, plan);
}

/*
 * A pass that counts is over: all states have visited the plans. A state whose visit made a
 * conflict ended at the site, see unwind_frame(): as an unproven insn if the program has the site
 * for sure. A conflict that shows only now, at a site that the program has, is an error of the
 * pass as well, and its site is an unproven insn for the next one, see
 * bpf_find_unproven_after_pass().
 */
int bpf_pads_settle(struct bpf_verifier_env *env)
{
	struct bpf_subprog_info *sub;
	struct bpf_pad_plan *plan;
	int i, s, err;

	bpf_pads_must_unwind(env);
	/* hidden slots take their places among entries that have theirs */
	for (i = 0; i < env->prog->len; i++) {
		for (plan = env->insn_aux_data[i].pad_plans; plan; plan = plan->next) {
			err = order_ents(env, plan);
			if (err)
				return err;
		}
	}
	err = settle_slots(env);
	if (err)
		return err;
	for (i = 0; i < env->prog->len; i++) {
		if (env->insn_aux_data[i].pad_plans && bpf_must_abort())
			return -EINTR;
		for (plan = env->insn_aux_data[i].pad_plans; plan; plan = plan->next) {
			if (!plan->used)
				continue;
			err = settle_plan(env, plan);
			if (err < 0)
				return err;
			plan->conflict = err;
			if (plan->conflict && bpf_pad_must_unwind(env, plan)) {
				print_plan(env, i, plan);
				return -EINVAL;
			}
			err = plan->conflict ? skip_faults(env, i, plan) : 0;
			if (err)
				return err;
		}
	}
	/* The main pass is over: the program has no access to its stack that is not known. */
	for (s = 0; !env->faults_late && s < env->subprog_cnt; s++) {
		sub = &env->subprog_info[s];
		if (!sub->hidden_words)
			continue;
		sub->stack_depth = bpf_stack_depth_with_slots(sub);
		/* check_max_stack_depth() would put the stack of the callees there */
		sub->keep_fastcall_stack = true;
	}
	return 0;
}

/*
 * A site at the insn has no landing pad that serves all states and no other way out, see
 * bpf_pads_settle()
 */
bool bpf_pads_conflict(struct bpf_verifier_env *env, const struct bpf_insn_aux_data *aux)
{
	const struct bpf_pad_plan *plan;

	for (plan = aux->pad_plans; plan; plan = plan->next)
		if (plan->used && plan->conflict && bpf_pad_must_unwind(env, plan))
			return true;
	return false;
}

/* The loop @l is the loop @h, or a loop inside it */
static bool loop_is_in(struct bpf_verifier_env *env, int l, int h)
{
	return l == h || bpf_is_nested_loop(env, l, h);
}

/*
 * Is @n a conditional jump that leaves the loop @h? From the loop itself, as
 * bpf_insn_leaves_loop() asks, or from a loop inside it: a loop can have its only way out there.
 */
static bool jump_leaves_loop(struct bpf_verifier_env *env, int h, int n)
{
	const struct bpf_insn *insn = &env->prog->insnsi[n];

	if (!bpf_insn_is_cond_jump(insn->code) || BPF_OP(insn->code) == BPF_JCOND ||
	    !loop_is_in(env, bpf_loop_at_index(env, n), h))
		return false;
	return !loop_is_in(env, bpf_loop_at_index(env, n + insn->off + 1), h) ||
	       !loop_is_in(env, bpf_loop_at_index(env, n + 1), h);
}

/*
 * The landing pad of the call of @plan has a conflict, and that is an error: what the call calls
 * is unwound. Where that is at may_goto that the verifier adds, it depends on the
 * values that got to the loop: may_goto is there because a state went around without a trip
 * count. A function is verified for its calls together, and two calls of which each has a trip
 * count can make such a state between them:
 *
 *	static long count(long step, long end)		count(1, 1000000);
 *	{						count(-1, -999993);
 *		long i = 0;
 *							step is 1 or -1, end is one of two
 *		do					numbers: any pair, and no trip count
 *			i += step;
 *		while (i != end);
 *		return i;
 *	}
 *
 * Kept apart no call is left at may_goto, the call is no site, and what its frame holds does not
 * matter. Nothing in the call tells: its arguments are constants. So the jumps that leave such a
 * loop are a cause of the error as well, in each function that came back unwound to the call or
 * to a call below it. What they read decides the trip count, and the next pass keeps it apart,
 * see bpf_note_unproven_cause(), down to the arguments of the function. Such a jump can be in a
 * loop inside the one that has may_goto, see jump_leaves_loop().
 * Only a loop of which the pass knows that it has no trip count counts, see
 * bpf_flow_guard_is_guess().
 */
static void note_causes(struct bpf_verifier_env *env, const struct bpf_pad_plan *plan)
{
	struct bpf_subprog_info *sub = env->subprog_info;
	int s;

	if (plan->kind != BPF_SITE_CALL)
		return;
	bpf_pad_for_each_callee(plan, s)
		sub[s].below_conflict = true;
}

/*
 * The causes of all conflicts of the pass, see note_causes(), which has marked the functions that
 * came back to their calls. One walk serves them all: what a function has of causes is the same
 * for every conflict above it, a function is scanned once for the jumps that leave its loops, and
 * a pass can have a conflict at every call.
 */
static void note_causes_below(struct bpf_verifier_env *env)
{
	const struct bpf_insn_aux_data *aux = env->insn_aux_data;
	struct bpf_subprog_info *sub = env->subprog_info;
	int i, n, h, s, c, top = 0, cnt = env->subprog_cnt;
	const struct bpf_pad_plan *below;
	bool guards;
	int *stack;

	for (s = 0; s < cnt && !sub[s].below_conflict; s++)
		;
	if (s == cnt)
		return;
	/* a function is walked once, for its calls: it is on the stack once, when it gets its mark */
	stack = kvmalloc_array(cnt, sizeof(*stack), BPF_VERIFIER_GFP);
	if (!stack) {
		env->no_mem = true;
		return;
	}
	for (; s < cnt; s++)
		if (sub[s].below_conflict)
			stack[top++] = s;
	while (top) {
		s = stack[--top];
		/*
		 * A signal ends the load. The budget of the pass does not: the pass that has the
		 * error can be over it, and the passes behind it need the notes all the same.
		 */
		bpf_add_cost(env, sub[s + 1].start - sub[s].start, BPF_COST_SCAN);
		env->aborted |= bpf_must_abort();
		if (env->aborted)
			break;
		for (i = sub[s].start; i < sub[s + 1].start; i++) {
			for (below = aux[i].pad_plans; below; below = below->next) {
				if (below->kind != BPF_SITE_CALL || !below->visited)
					continue;
				/*
				 * The frame is left at this call, whatever what it calls
				 * was left at: the check of a recursion is no insn to
				 * note. The jumps that can skip the call are a cause.
				 */
				bpf_note_controlled_cause(env, i);
				bpf_pad_for_each_callee(below, c) {
					if (sub[c].below_conflict)
						continue;
					sub[c].below_conflict = true;
					stack[top++] = c;
				}
			}
		}
	}
	kvfree(stack);
	for (s = 0; s < cnt; s++) {
		guards = false;
		for (i = sub[s].start; sub[s].below_conflict && i < sub[s + 1].start; i++) {
			if (!aux[i].loop_guard || bpf_flow_guard_is_guess(env, i))
				continue;
			h = bpf_loop_at_index(env, i);
			aux[h].loop->guard_is_cause = guards = true;
		}
		if (!guards)
			continue;
		/* a jump is asked about the marked loops that it is in: LOOP_STACK_SIZE at most */
		bpf_add_cost(env, sub[s + 1].start - sub[s].start, BPF_COST_SCAN);
		for (n = sub[s].start; n < sub[s + 1].start; n++) {
			for (h = bpf_loop_at_index(env, n); h >= 0; h = aux[h].loop_header) {
				if (!aux[h].loop->guard_is_cause || !jump_leaves_loop(env, h, n))
					continue;
				bpf_note_unproven_cause(env, n);
				break;
			}
		}
		for (n = sub[s].start; n < sub[s + 1].start; n++)
			if (aux[n].loop)
				aux[n].loop->guard_is_cause = false;
	}
}

/*
 * The pass is over and has an error. Note the causes of the conflicts that are one: those that a
 * state made an error where it visited, see unwind_frame(), and those that bpf_pads_settle() found.
 */
void bpf_pads_note_causes(struct bpf_verifier_env *env)
{
	const struct bpf_pad_plan *plan;
	int i, s;

	for (s = 0; s < env->subprog_cnt; s++)
		env->subprog_info[s].below_conflict = false;
	for (i = 0; i < env->prog->len; i++)
		for (plan = env->insn_aux_data[i].pad_plans; plan; plan = plan->next)
			if (plan->failed || (plan->used && plan->conflict &&
					     bpf_pad_must_unwind(env, plan)))
				note_causes(env, plan);
	note_causes_below(env);
	/* the caller looks at the limits before it goes on. This is for a load that is to end. */
	bpf_check_limits(env);
}

/* The plans of the sites that the program has */
void bpf_pads_log(struct bpf_verifier_env *env)
{
	const struct bpf_pad_plan *plan;
	int i;

	if (!(env->log.level & BPF_LOG_LEVEL2))
		return;
	for (i = 0; i < env->prog->len; i++)
		for (plan = env->insn_aux_data[i].pad_plans; plan; plan = plan->next)
			if (plan->used)
				print_plan(env, i, plan);
}
