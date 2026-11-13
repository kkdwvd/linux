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
 * Nothing reads the records yet, and no pad is generated.
 */
#include <linux/bpf.h>
#include <linux/bpf_verifier.h>
#include <linux/filter.h>
#include <linux/slab.h>

/* Why a site declines */
enum cancel_reason {
	CANCEL_OK,
	/* the frame holds entries of refs[] that no kind describes */
	CANCEL_REFS,
	/* it is in an RCU or preemption section that it entered */
	CANCEL_SECTION,
};

struct cancel_site {
	u32 insn_idx;	/* in the program as the main pass has it */
	u32 next;	/* the next site at the insn + 1 */
	u8 type;	/* enum bpf_cancel_site_type */
	u8 decline;	/* enum cancel_reason */
};

struct bpf_cancel {
	struct cancel_site *sites;
	u32 nr_sites;
	u32 cap_sites;
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
	kfree(c);
	env->cancel = NULL;
}
