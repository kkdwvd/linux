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
 *   code        bpf_pad_insns(). The insns of the pad of a plan.
 *   emission    bpf_insert_sites() in fixups.c, after the main pass.
 *
 * The main pass does not see the insns of a pad. They are trusted, like all that the verifier
 * emits. So a plan has to be right for every state that gets to its site. All that the code of a pad
 * fixes is compared on each visit: the number of sections.
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

/* The insn of a pad that releases one resource of @class */
static struct bpf_insn release_call(enum bpf_pad_class class)
{
	return BPF_CALL_KFUNC(0, pad_kfuncs[class]);
}

/*
 * A pad is going to call what @insn calls, if the program can call that. The passes that follow the
 * emission look for the descriptor of a kfunc, which the program gets here.
 * Returns the reason of a conflict.
 */
static int get_release(struct bpf_verifier_env *env, const struct bpf_insn *insn)
{
	u32 log_level = env->log.level;
	struct bpf_call_arg_meta meta;
	int err;

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

	plan = bpf_pad_plan_get(env, insn_idx, kind);
	if (!plan)
		return ERR_PTR(-ENOMEM);
	if (plan->conflict)
		return plan;
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
 * The insns of the landing pad of @plan, a site in @subprog, but for the last one, which leaves the
 * frame. Returns their number, less than BPF_PAD_MAX_INSNS.
 */
int bpf_pad_insns(struct bpf_verifier_env *env, const struct bpf_pad_plan *plan, int subprog,
		  struct bpf_insn *buf)
{
	int class, i, n = 0;

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
	int class, err = plan->conflict;

	for (class = 0; !err && class < BPF_PAD_NR_SECTIONS; class++) {
		release = release_call(class);
		if (plan->sections[class])
			err = get_release(env, &release);
	}
	return err;
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
	};

	verbose(env, "landing pad of %s at %d: ", kind[plan->kind], i);
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
