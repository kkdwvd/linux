// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
/*
 * Cancellation of a program on pads that the verifier generates.
 *
 * When a cancellation point fires the invocation ends there. A point is the
 * stack check of a recursive subprog that finds no room. Each frame of the call
 * chain runs a pad, from the frame at the point to the frame that the kernel
 * entered. A pad releases what its frame holds and leaves the frame with
 * cancel_exit, which returns to the pad of the call in the caller: 'cancel_goto
 * pad' behind the call names it. The pad of the main program returns to the
 * kernel. A cancellation runs pads only, never the code of the program again.
 *
 * A site is an insn at which a frame can be cancelled: a point, or the call of
 * a subprog, which a cancellation comes back through. The main pass records
 * whether the frame at the site holds anything of its own. No kind of resource
 * is described yet: a frame that holds anything of its own declines.
 *
 * After the main pass bpf_cancel_resolve() finds the subprogs that can be
 * cancelled, and with them the sites that get a pad. No pad is generated yet:
 * the stack check leaves the subprog as it always did.
 */
#include <linux/bpf.h>
#include <linux/bpf_verifier.h>
#include <linux/filter.h>
#include <linux/slab.h>

#define verbose(env, fmt, args...) bpf_verifier_log_write(env, fmt, ##args)

/* Why a site declines */
enum cancel_reason {
	CANCEL_OK,
	/* the frame holds entries of refs[] that no kind describes */
	CANCEL_REFS,
	/* it is in an RCU or preemption section that it entered */
	CANCEL_SECTION,
	/* a helper or a kfunc calls the subprog, or it is the exception callback */
	CANCEL_CALLBACK,
	/* a call of the subprog has no pad */
	CANCEL_CALLER,
	/* the kernel entered the subprog, and it may not return 0 */
	CANCEL_RETVAL,
	/* no JIT that runs pads compiles the program */
	CANCEL_NO_JIT,
	__CANCEL_REASONS,
};

/* In the stats. New reasons go to the end, see bpf_cancel_print_stats() */
static const char * const cancel_reason_str[__CANCEL_REASONS] = {
	[CANCEL_REFS]		= "refs",
	[CANCEL_SECTION]	= "section",
	[CANCEL_CALLBACK]	= "callback",
	[CANCEL_CALLER]		= "caller",
	[CANCEL_RETVAL]		= "retval",
	[CANCEL_NO_JIT]		= "jit",
};

struct cancel_site {
	u32 insn_idx;	/* in the program as the main pass has it */
	u32 next;	/* the next site at the insn + 1 */
	u8 type;	/* enum bpf_cancel_site_type */
	u8 decline;	/* enum cancel_reason */
	/* The rest is found by bpf_cancel_resolve() */
	u32 subprog;	/* the one that the insn is in */
	int callee;	/* of a call insn */
	bool padded;
	/* no cancellation gets here: it has no pad and does not decline */
	bool unused;
};

/* What bpf_cancel_resolve() finds out about a subprog */
struct cancel_sub {
	u8 why;		/* enum cancel_reason: why it cannot be cancelled */
	bool called;	/* by a call in the program */
	bool has_point;	/* a point is in it or in what it calls */
	/* and a cancellation comes out of it: the calls of it need pads */
	bool raises;
};

struct bpf_cancel {
	struct cancel_site *sites;
	u32 nr_sites;
	u32 cap_sites;
	struct cancel_sub *subs;
};

static struct cancel_site *cancel_find_site(struct bpf_verifier_env *env, u32 insn_idx,
					    enum bpf_cancel_site_type type)
{
	struct cancel_site *site;
	u32 id;

	for (id = env->insn_aux_data[insn_idx].cancel_site; id; id = site->next) {
		site = &env->cancel->sites[id - 1];
		if (site->type == type)
			return site;
	}
	return NULL;
}

static struct cancel_site *cancel_get_site(struct bpf_verifier_env *env, u32 insn_idx,
					   enum bpf_cancel_site_type type)
{
	struct bpf_insn_aux_data *aux = &env->insn_aux_data[insn_idx];
	struct bpf_cancel *c = env->cancel;
	struct cancel_site *site;
	u32 cap;

	if (!c) {
		c = kzalloc_obj(*c, GFP_KERNEL_ACCOUNT);
		if (!c)
			return NULL;
		env->cancel = c;
	}
	site = cancel_find_site(env, insn_idx, type);
	if (site)
		return site;

	if (c->nr_sites == c->cap_sites) {
		cap = max(2 * c->cap_sites, 16U);
		site = kvrealloc(c->sites, cap * sizeof(*site), GFP_KERNEL_ACCOUNT);
		if (!site)
			return NULL;
		c->sites = site;
		c->cap_sites = cap;
	}
	site = &c->sites[c->nr_sites++];
	memset(site, 0, sizeof(*site));
	site->insn_idx = insn_idx;
	site->type = type;
	site->next = aux->cancel_site;
	aux->cancel_site = c->nr_sites;
	return site;
}

/*
 * Does the current frame of @st hold anything of its own? Returns the reason why the site
 * declines if it does.
 *
 * Its own is what the frame has not got from its callers: refs[] from entry_refs on and the
 * sections that it entered. The callers are recorded with what they hold at their calls.
 */
static int cancel_collect(struct bpf_verifier_env *env, const struct bpf_verifier_state *st,
			  enum bpf_cancel_site_type type)
{
	const struct bpf_func_state *frame = st->frame[st->curframe];

	/* references, locks, IRQ flags */
	if (st->acquired_refs != frame->entry_refs)
		return CANCEL_REFS;
	if (st->active_rcu_locks != frame->entry_rcu_locks ||
	    st->active_preempt_locks != frame->entry_preempt_locks)
		return CANCEL_SECTION;
	return 0;
}

/*
 * The current state is at a site, in front of env->insn_idx. Record what its
 * current frame holds there. The frames below wait in calls, which are sites
 * of their own.
 */
int bpf_cancel_record(struct bpf_verifier_env *env, enum bpf_cancel_site_type type)
{
	const struct bpf_verifier_state *st = env->cur_state;
	struct cancel_site *site;
	int reason;

	/* the program doesn't get there */
	if (st->speculative)
		return 0;
	site = cancel_get_site(env, env->insn_idx, type);
	if (!site)
		return -ENOMEM;
	if (site->decline)
		return 0;

	/*
	 * The stack check is in front of the first insn and only calls get to it: the
	 * frame has taken nothing yet, whatever a state that jumps to that insn holds.
	 */
	reason = 0;
	if (type != BPF_CANCEL_SITE_ENTRY)
		reason = cancel_collect(env, st, type);
	site->decline = reason;
	return 0;
}

/* A point is where a cancellation begins. A call passes it on. */
static bool cancel_is_point(struct bpf_verifier_env *env, const struct cancel_site *site)
{
	/*
	 * The main pass records the stack check of every subprog that may be on a cycle.
	 * check_recursion() has found the ones that are, and only they get the check.
	 */
	if (site->type == BPF_CANCEL_SITE_ENTRY)
		return env->subprog_info[site->subprog].recursive;
	return false;
}

/* The next subprog from @from on that the call at @site may call, -1 if there is none */
static int cancel_next_callee(struct bpf_verifier_env *env, const struct cancel_site *site,
			      int from)
{
	/* it's not recorded which callx calls what: each one may call all that its subprog calls */
	if (bpf_is_callx(&env->prog->insnsi[site->insn_idx]))
		return bpf_next_callx_callee(env, site->subprog, from);
	return site->callee >= from ? site->callee : -1;
}

#define cancel_for_each_callee(env, site, t)				\
	for (t = cancel_next_callee(env, site, 0); t >= 0;		\
	     t = cancel_next_callee(env, site, t + 1))

/* Does the kernel enter subprog @s: the pad of such a frame is the last one to run */
static bool cancel_sub_is_top(struct bpf_verifier_env *env, int s)
{
	return !s || env->subprog_info[s].is_async_cb;
}

/* Why subprog @s cannot be cancelled, whatever its calls are like */
static u8 cancel_sub_reason(struct bpf_verifier_env *env, int s)
{
	const struct bpf_subprog_info *sub = &env->subprog_info[s];
	s32 val;

	/* what a recursion takes too. A device runs the insns that its driver was given. */
	if (!bpf_prog_has_invocation_budget(env->prog) || !bpf_jit_supports_cancel() ||
	    bpf_prog_is_offloaded(env->prog->aux))
		return CANCEL_NO_JIT;
	/*
	 * cancel_exit finds the pad of its call through the symbol of the program, which is
	 * there with CAP_BPF. The return that it changes is mispredicted: what is behind the
	 * call runs speculatively on what the pads left, which nothing verified.
	 */
	if (!env->bpf_capable || !env->bypass_spec_v1)
		return CANCEL_NO_JIT;
	/*
	 * The helper or the kfunc that calls a callback has no pad: it would go on with what
	 * the callback left. The exception callback returns from the frame of the main program.
	 */
	if (sub->is_loop_cb || sub->is_other_cb || sub->is_exception_cb)
		return CANCEL_CALLBACK;
	/* the caller of an extension is the program that it extends, which has no pad for it */
	if (!s && env->prog->type == BPF_PROG_TYPE_EXT)
		return CANCEL_CALLER;
	/*
	 * The pad of a frame that the kernel entered reports and returns to the kernel. A frame
	 * that a call entered would do the same, in place of going on in the pad of the call.
	 */
	if (cancel_sub_is_top(env, s) && env->cancel->subs[s].called)
		return CANCEL_CALLBACK;
	/* the main program returns the value of its type to the kernel, an async callback 0 */
	if (!s && !bpf_prog_cancel_retval(env, &val))
		return CANCEL_RETVAL;
	if (sub->is_async_cb && sub->async_ret_nonzero)
		return CANCEL_RETVAL;
	return CANCEL_OK;
}

/*
 * A frame that is cancelled returns to the pad of the call that it was called by. Where the
 * call has no pad it would return behind the call, to code that was verified for another R0.
 * So a subprog can be cancelled only if every call of it has a pad, in a subprog that can be
 * cancelled in turn: up to the frame that the kernel entered, the main program or an async
 * callback. What cannot be cancelled takes all that it calls with it.
 */
static void cancel_drop_subs(struct bpf_verifier_env *env)
{
	struct bpf_cancel *c = env->cancel;
	struct cancel_site *site;
	bool changed;
	u32 i;
	int t;

	do {
		changed = false;
		for (i = 0; i < c->nr_sites; i++) {
			site = &c->sites[i];
			if (site->type != BPF_CANCEL_SITE_CALL ||
			    (!site->decline && !c->subs[site->subprog].why))
				continue;
			cancel_for_each_callee(env, site, t) {
				if (c->subs[t].why)
					continue;
				c->subs[t].why = CANCEL_CALLER;
				changed = true;
			}
		}
	} while (changed);
}

/*
 * Does a cancellation get to @site: it begins there, or it comes out of what the call calls.
 * @has_point: it would get there if nothing declined.
 */
static bool cancel_gets_to(struct bpf_verifier_env *env, const struct cancel_site *site,
			   bool *has_point)
{
	const struct bpf_cancel *c = env->cancel;
	bool raises;
	int t;

	*has_point = raises = cancel_is_point(env, site);
	if (site->type != BPF_CANCEL_SITE_CALL)
		return raises;
	cancel_for_each_callee(env, site, t) {
		*has_point |= c->subs[t].has_point;
		raises |= c->subs[t].raises;
	}
	return raises;
}

/* A cancellation that gets to a site with a pad comes out of the subprog of the site. */
static void cancel_find_raising(struct bpf_verifier_env *env)
{
	struct bpf_cancel *c = env->cancel;
	bool changed, usable, has_point, raises;
	struct cancel_site *site;
	struct cancel_sub *sub;
	u32 i;

	do {
		changed = false;
		for (i = 0; i < c->nr_sites; i++) {
			site = &c->sites[i];
			sub = &c->subs[site->subprog];
			usable = !site->decline && !sub->why;
			/* nothing to add */
			if (sub->has_point && (sub->raises || !usable))
				continue;
			raises = cancel_gets_to(env, site, &has_point) && usable;
			if ((has_point && !sub->has_point) || (raises && !sub->raises)) {
				sub->has_point |= has_point;
				sub->raises |= raises;
				changed = true;
			}
		}
	} while (changed);
}

/*
 * The main pass is over and no insn has moved yet. Find the subprogs that can be cancelled,
 * and what becomes of each site: it gets a pad, it declines, or no cancellation gets there.
 */
int bpf_cancel_resolve(struct bpf_verifier_env *env)
{
	struct bpf_cancel *c = env->cancel;
	struct cancel_site *site;
	bool has_point, raises;
	struct bpf_insn *insn;
	u32 i;
	int s;

	if (!c || !c->nr_sites)
		return 0;
	c->subs = kvcalloc(env->subprog_cnt, sizeof(*c->subs), GFP_KERNEL_ACCOUNT);
	if (!c->subs)
		return -ENOMEM;

	for (i = 0; i < c->nr_sites; i++) {
		site = &c->sites[i];
		insn = &env->prog->insnsi[site->insn_idx];
		site->subprog = bpf_find_containing_subprog(env, site->insn_idx) -
				env->subprog_info;
		site->callee = -1;
		if (bpf_pseudo_call(insn))
			site->callee = bpf_find_subprog(env, site->insn_idx + insn->imm + 1);
		if (site->type != BPF_CANCEL_SITE_CALL)
			continue;
		cancel_for_each_callee(env, site, s)
			c->subs[s].called = true;
	}
	for (s = 0; s < env->subprog_cnt; s++)
		c->subs[s].why = cancel_sub_reason(env, s);
	cancel_drop_subs(env);
	cancel_find_raising(env);

	for (i = 0; i < c->nr_sites; i++) {
		site = &c->sites[i];
		raises = cancel_gets_to(env, site, &has_point);
		if (!site->decline)
			site->decline = c->subs[site->subprog].why;
		/*
		 * A call that declines counts when it is in the way of a point in what it calls.
		 * A call that doesn't decline needs a pad only for what comes out of the callee.
		 */
		if (!has_point || (!site->decline && !raises))
			site->unused = true;
		else if (!site->decline)
			site->padded = true;
	}
	return 0;
}

/* The main pass starts over: the states of the round that is dropped never run */
void bpf_cancel_reset(struct bpf_verifier_env *env)
{
	struct bpf_cancel *c = env->cancel;
	u32 i;

	if (!c)
		return;
	for (i = 0; i < c->nr_sites; i++)
		env->insn_aux_data[c->sites[i].insn_idx].cancel_site = 0;
	c->nr_sites = 0;
}

void bpf_cancel_free(struct bpf_verifier_env *env)
{
	struct bpf_cancel *c = env->cancel;

	if (!c)
		return;
	kvfree(c->sites);
	kvfree(c->subs);
	kfree(c);
	env->cancel = NULL;
}

/* One line of the stats. Selftests match it: new counters go to the end. */
void bpf_cancel_print_stats(struct bpf_verifier_env *env)
{
	const struct bpf_cancel *c = env->cancel;
	u32 cnt[__CANCEL_REASONS] = {}, sites = 0, padded = 0, i;

	for (i = 0; c && i < c->nr_sites; i++) {
		if (c->sites[i].unused)
			continue;
		sites++;
		if (c->sites[i].padded)
			padded++;
		else
			cnt[c->sites[i].decline]++;
	}
	verbose(env, "cancel sites %u padded %u declined", sites, padded);
	for (i = CANCEL_OK + 1; i < __CANCEL_REASONS; i++)
		verbose(env, " %s %u", cancel_reason_str[i], cnt[i]);
	verbose(env, "\n");
}
