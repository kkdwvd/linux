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
 * what the frame at the site holds, as a list of entries: one per resource, with
 * its kind, the place of its handle and how it is released. Many states visit
 * a site. An entry that every visit has in the same place is released as it is.
 * An entry that only some visits have takes a condition: a drop flag of the
 * frame says at run time whether the frame holds it, see "Drop flags", and the
 * site declines where no flag can. A site at which the frame holds what has no
 * entry declines.
 *
 * These kinds of resource are described:
 * - IRQ flags and locks: the pad restores the flags that its frame saved and
 *   unlocks the locks that it took, the ones that were taken last first. A lock
 *   is found at an address that is known, or through a live pointer of the
 *   frame to what the lock is in.
 * - open-coded iterators: the pad calls bpf_iter_<type>_destroy().
 * - dynptrs that hold a reference: the pad discards the ringbuf record, or frees
 *   the reader of the file.
 * - RCU read sections and preemption-disabled sections: the pad leaves the ones
 *   that its frame entered.
 * - references whose handle the frame has in a register or in a stack slot,
 *   where a kfunc or a helper releases them: a kernel object, a socket, a
 *   ringbuf record, an object that the program owns, see
 *   cancel_collect_ptr().
 * A frame that holds anything else of its own declines. So does the frame that
 * waits in a call when a callee releases what the frame holds: its pad would
 * release that again.
 *
 * A reference that a frame gives away in a call is the callee's from the call
 * on: the frame passes the handle in an argument and keeps it in no place that
 * is live, see bpf_cancel_ref_moves(). The callee releases it, in its code or
 * in its pads, or returns with it and the frame holds it again.
 *
 * After the main pass bpf_cancel_resolve() finds the subprogs that can be
 * cancelled, and with them the sites that get a pad. The pads go behind the last
 * insn of their subprog, see bpf_insert_loop_guards().
 *
 * The main pass verifies what it always did: the stack check leaves the
 * subprog. That is what the program does at a site that declines. A site with a
 * pad doesn't get there any more.
 */
#include <linux/bpf.h>
#include <linux/bpf_verifier.h>
#include <linux/btf_ids.h>
#include <linux/filter.h>
#include <linux/slab.h>
#include <linux/sort.h>

#define verbose(env, fmt, args...) bpf_verifier_log_write(env, fmt, ##args)

/*
 * The kinds of resource, in the order in which a pad releases them. A kind has
 * a function that finds the resources of a frame and adds their entries, called
 * from cancel_collect(), and one that emits the release of an entry, called
 * from cancel_emit_entry().
 *
 * The order is that of the contexts which the releases need. Locks and IRQ
 * flags go first: an object cannot be freed under a lock. RCU and preemption
 * sections go last: an object may only live inside of one.
 */
enum cancel_kind {
	/* IRQ flags that bpf_local_irq_save() saved to a slot of the stack */
	CANCEL_IRQ,
	/* a lock, by what unlocks it: bpf_spin_unlock(), */
	CANCEL_SPIN_LOCK,
	/* bpf_res_spin_unlock(), */
	CANCEL_RES_LOCK,
	/* or bpf_res_spin_unlock_irqrestore(), which restores the IRQ flags of the lock too */
	CANCEL_RES_LOCK_IRQ,
	/*
	 * A dynptr in the stack of the frame that holds a reference, see cancel_collect_dynptr().
	 * In front of what the reference may be the child of: an iterator, another reference.
	 */
	CANCEL_KIND_DYNPTR,
	/* an open-coded iterator in the stack of the frame, see cancel_collect_iter() */
	CANCEL_KIND_ITER,
	/* a reference whose handle is a pointer in a register or in a stack slot */
	CANCEL_PTR,
	/*
	 * The sections that the frame entered, see cancel_collect_section(). These two are
	 * the last ones. Which of them is left first makes no difference: either kind nests by
	 * a count and may be left inside a section of the other, as a program may do too.
	 */
	CANCEL_RCU,
	CANCEL_PREEMPT,
	__CANCEL_KINDS,
};

/*
 * Locks and IRQ flags are one phase: the first kinds. Within it the order is not that of the
 * kinds. Each release puts back what its acquisition found: the flags of an outer
 * bpf_local_irq_save() that are restored in front of those of an inner one leave interrupts
 * off for good, and so does their restore in front of the unlock of a bpf_spin_lock that was
 * taken under them. So the pad releases what the frame took last first, see rank in struct
 * cancel_entry.
 */
static bool cancel_kind_ordered(u8 kind)
{
	return kind <= CANCEL_RES_LOCK_IRQ;
}

/* The most insns that a pad takes to release an entry */
#define CANCEL_ENTRY_INSNS	8
/* and to test the flag of an entry with a condition */
#define CANCEL_FLAG_INSNS	2

/* Why a site declines */
enum cancel_reason {
	CANCEL_OK,
	/* the frame holds entries of refs[] that no kind describes */
	CANCEL_REFS,
	/* it entered more RCU or preemption sections than a pad leaves, or a pad lacks the kfunc */
	CANCEL_SECTION,
	/* it is in an RCU or preemption section in some visits only, or in fewer of them */
	CANCEL_COND,
	/* a helper or a kfunc calls the subprog, or it is the exception callback */
	CANCEL_CALLBACK,
	/* a call of the subprog has no pad */
	CANCEL_CALLER,
	/* the kernel entered the subprog, and it may not return 0 */
	CANCEL_RETVAL,
	/* no JIT that runs pads compiles the program */
	CANCEL_NO_JIT,
	/* a callee releases what the frame holds at the call */
	CANCEL_FOREIGN,
	/* it holds a lock or IRQ flags that a pad has no way to */
	CANCEL_LOCK_PLACE,
	/* it holds an iterator that its pad cannot find or may not destroy */
	CANCEL_ITER,
	/* it holds a reference through dynptrs that its pad cannot find or may not release */
	CANCEL_DYNPTR,
	/* the handle of a reference is in no register or stack slot that a pad can read */
	CANCEL_PLACE,
	/* nothing that a pad may call there releases a reference */
	CANCEL_RELEASE,
	/*
	 * The last ones are for what only some visits hold, see "Drop flags". No flag says
	 * whether the frame holds it: frames hold two resources of its class at a time,
	 */
	CANCEL_MULTI,
	/* or nothing tells at run time when a frame comes to hold one, or gives it up, */
	CANCEL_INEXACT,
	/* or the visits have a resource of the class in two places, */
	CANCEL_PLACES,
	/* or the frame has no room for the flag. */
	CANCEL_STACK,
	__CANCEL_REASONS,
};

/* In the stats. New reasons go to the end, see bpf_cancel_print_stats() */
static const char * const cancel_reason_str[__CANCEL_REASONS] = {
	[CANCEL_REFS]		= "refs",
	[CANCEL_SECTION]	= "section",
	[CANCEL_COND]		= "cond",
	[CANCEL_CALLBACK]	= "callback",
	[CANCEL_CALLER]		= "caller",
	[CANCEL_RETVAL]		= "retval",
	[CANCEL_NO_JIT]		= "jit",
	[CANCEL_FOREIGN]	= "foreign",
	[CANCEL_LOCK_PLACE]	= "lock",
	[CANCEL_ITER]		= "iter",
	[CANCEL_DYNPTR]		= "dynptr",
	[CANCEL_PLACE]		= "place",
	[CANCEL_RELEASE]	= "release",
	[CANCEL_MULTI]		= "multi",
	[CANCEL_INEXACT]	= "inexact",
	[CANCEL_PLACES]		= "places",
	[CANCEL_STACK]		= "stack",
};

/* The place of an entry that has no handle */
#define CANCEL_NO_PLACE		S16_MAX

/* One resource that a frame holds at a site */
struct cancel_entry {
	u8 kind;	/* enum cancel_kind */
	bool cond;	/* some visits are without it: its release takes a condition */
	/* where the handle is: a register, or below 0 the offset of a stack slot from r10 */
	s16 place;
	/*
	 * Of a lock or IRQ flags: how many of the two the frame took before it. refs[] has them
	 * in that order.
	 */
	u16 rank;
	/* of a lock that was taken with IRQ flags: the offset of their slot from r10 */
	s16 irq_off;
	u8 flags;	/* of the kind, they go with arg */
	u64 arg;	/* how to release it, in the terms of the kind */
	/* of an object that the program owns: the pointer in place is that many bytes into it */
	s32 off;
	/*
	 * Of a handle that is a pointer: the places of the frame that have it like place does,
	 * as far as there are bits for them: registers, and the first slots of the stack. In an
	 * entry of a site: the ones that every visit has which holds the entry. Visits that
	 * picked different places agree on one of these, see cancel_agree_on_places().
	 */
	u16 regs;
	u64 slots;
	/*
	 * An origin of what the visits hold there + 1, see struct cancel_origin: the visits
	 * make their origins one class. 0 if no visit has one.
	 */
	u32 origin;
	bool stray;	/* a visit holds something there that has no origin */
	/* with a condition: the offset of the drop flag from r10, once the site gets a pad */
	s16 flag;
	/*
	 * Of a lock at a known address: a place leads to it as well, with the lock alt_arg
	 * bytes from where its pointer points. Visits that hold such locks at different
	 * addresses may agree on it, see cancel_merge().
	 */
	bool alt;
	s16 alt_place;
	s32 alt_arg;
};

static bool cancel_place_is_reg(int place)
{
	return place >= BPF_REG_0 && place < BPF_REG_FP;
}

/* @place has the handle of @e too, see regs and slots in struct cancel_entry */
static void cancel_note_place(struct cancel_entry *e, int place)
{
	int spi = -place / BPF_REG_SIZE - 1;

	if (cancel_place_is_reg(place))
		e->regs |= BIT(place);
	else if (spi < BITS_PER_TYPE(e->slots))
		e->slots |= BIT_ULL(spi);
}

/*
 * A place that @a and @b both have their handles in, CANCEL_NO_PLACE if they have none. The
 * first one in the order in which a visit picks its place, see cancel_collect_ptr().
 */
static int cancel_common_place(const struct cancel_entry *a, const struct cancel_entry *b)
{
	u16 regs = a->regs & b->regs;
	u64 slots = a->slots & b->slots;

	if (regs >> BPF_REG_6)
		return BPF_REG_6 + __ffs(regs >> BPF_REG_6);
	if (slots)
		return -(int)(__ffs64(slots) + 1) * BPF_REG_SIZE;
	return CANCEL_NO_PLACE;
}

struct cancel_list {
	struct cancel_entry *entries;
	u32 nr;
	u32 cap;
};

struct cancel_site {
	u32 insn_idx;	/* in the program as the main pass has it */
	u32 next;	/* the next site at the insn + 1 */
	u8 type;	/* enum bpf_cancel_site_type */
	u8 decline;	/* enum cancel_reason */
	bool visited;
	/* what the frame holds, over all visits */
	struct cancel_list held;
	/* The rest is found by bpf_cancel_resolve() */
	u32 subprog;	/* the one that the insn is in */
	int callee;	/* of a call insn */
	bool padded;
	/* no cancellation gets here: it has no pad and does not decline */
	bool unused;
	u32 pad;	/* of a call that is padded */
};

/* The sites of a subprog that hold the same have one pad */
struct cancel_pad {
	u32 site;	/* one of them */
	u32 next;	/* the next pad of the subprog + 1 */
	/* its first insn is that many insns in front of the end of the subprog */
	u32 back;
};

/* What bpf_cancel_resolve() finds out about a subprog */
struct cancel_sub {
	u8 why;		/* enum cancel_reason: why it cannot be cancelled */
	bool called;	/* by a call in the program */
	/* it cannot be cancelled whatever its frames hold, see cancel_find_stuck() */
	bool stuck;
	bool has_point;	/* a point is in it or in what it calls */
	/* and a cancellation comes out of it: the calls of it need pads */
	bool raises;
	u32 pads;	/* its first pad + 1 */
};

/*
 * The origin of a resource is the insn that brought it to the frame which is to release
 * it: the call that acquired it, or the call of the subprog that returned with it. refs[]
 * has the insn, see origin in struct bpf_reference_state. Nothing compares these insns when
 * a state is found to be within another one, or when two states are joined. So the origin in
 * a state is one of several insns that may have brought the resource when the program gets
 * there: the one of the state, and those of the states that it stands for. Such origins are
 * one class, see bpf_cancel_alias_refs(). What is to be known about a resource by its origin
 * has to hold for the class.
 *
 * The main pass notes what tells whether a frame holds a resource of a class at run time:
 * how each origin brings one, which insns take one away, and whether a frame holds two at
 * a time.
 */
struct cancel_origin {
	u32 insn_idx;	/* in the program as the main pass has it */
	u32 up;		/* towards the origin that stands for the class, which has itself here */
	u32 subprog;	/* the one that the insn is in */
	/*
	 * What tells behind the insn that it brought a resource, enum bpf_cancel_acquire.
	 * Nothing does until a visit says what.
	 */
	u8 how;
	/* a return through the call brought nothing, and NULL in R0 */
	bool null_ret;
	/* nothing tells whether a frame holds a resource of the origin */
	bool inexact;
	/* a frame held two resources of the origin at a time */
	bool multi;
	/*
	 * The rest is for the class, in the origin that stands for it, and found by
	 * bpf_cancel_resolve(): inexact and multi are for the class then too.
	 */
	bool no_room;	/* the frame has no room for the flag */
	bool used;	/* a pad reads the flag */
	s16 flag;	/* its offset from r10, 0 if the class has none */
};

/*
 * A visit of the call at @insn_idx took a resource of @origin away from the frame that the
 * call is in. The visits of an insn are found through the insn.
 */
struct cancel_release {
	u32 insn_idx;	/* in the program as the main pass has it */
	u32 next;	/* the next one of the insn + 1 */
	u32 origin;	/* CANCEL_NO_ORIGIN: a visit took nothing away that has an origin */
};

#define CANCEL_NO_ORIGIN	U32_MAX

/* A frame held a resource of origin @a and one of origin @b at a time */
struct cancel_pair {
	u32 a, b;
};

/* With more pairs than that no class is known to be held once at a time */
#define CANCEL_PAIRS_MAX	256

struct bpf_cancel {
	struct cancel_site *sites;
	u32 nr_sites;
	u32 cap_sites;
	/* what the frame holds in the visit that is recorded */
	struct cancel_list visit;
	/* it is of a call, and the frame is in the state while the callee is verified */
	bool caller_in_state;
	/* the state as a frame that waits in a call has it, see cancel_record_callers() */
	struct bpf_verifier_state caller;
	struct cancel_sub *subs;
	struct cancel_pad *pads;
	u32 nr_pads;
	u32 cap_pads;
	/* the pads of one subprog, see bpf_cancel_append_pads() */
	struct bpf_insn *insns;
	u32 cap_insns;
	/* the insns that bring resources to their frames, see bpf_cancel_record_origin() */
	struct cancel_origin *origins;
	u32 nr_origins;
	u32 cap_origins;
	/* what takes them away, see bpf_cancel_record_release() */
	struct cancel_release *releases;
	u32 nr_releases;
	u32 cap_releases;
	bool no_releases;	/* not all of them are here */
	/* what is held together, see cancel_add_pair() */
	struct cancel_pair *pairs;
	u32 nr_pairs;
	u32 cap_pairs;
	bool no_pairs;		/* not all of them are here */
	/* the flags that are reserved, see cancel_reserve_flags() */
	u32 nr_flags;
};

/*
 * CANCEL_PTR: the pad calls what releases the reference with the handle in R1. arg is the
 * BTF id of a kfunc, and from bit 32 on off of its call, see struct bpf_release_kfunc.
 */

/* flags: the handle is NULL if nothing was acquired, and the pad tests it */
#define CANCEL_PTR_NULL		BIT(0)
/* arg is the id of a helper */
#define CANCEL_PTR_HELPER	BIT(1)
/* an object that the program owns is dropped: arg is the btf_record of its type, or NULL */
#define CANCEL_PTR_OBJ		BIT(2)
/* and it is a per-CPU object */
#define CANCEL_PTR_PERCPU	BIT(3)

static int cancel_list_add(struct cancel_list *list, const struct cancel_entry *e)
{
	struct cancel_entry *entries;
	u32 cap;

	if (list->nr == list->cap) {
		cap = max(2 * list->cap, 4U);
		entries = krealloc_array(list->entries, cap, sizeof(*entries), GFP_KERNEL_ACCOUNT);
		if (!entries)
			return -ENOMEM;
		list->entries = entries;
		list->cap = cap;
	}
	list->entries[list->nr++] = *e;
	return 0;
}

/*
 * The flags of an entry of @kind that visits may differ in. A handle that may be NULL in one
 * visit and is tested in another one is one entry: the test of the pad does no harm where the
 * program has made it. A callee makes it for the frame that waits in its call.
 */
static u8 cancel_soft_flags(u8 kind)
{
	return kind == CANCEL_PTR ? CANCEL_PTR_NULL : 0;
}

/*
 * Entries are matched by place, not by what took the resource: "A or B is
 * held, in r8" is one entry, released in one way.
 */
static bool cancel_entry_same(const struct cancel_entry *a, const struct cancel_entry *b)
{
	/*
	 * A lock or IRQ flags are released at their rank. Visits that took the same in another
	 * order have other entries, and the site declines: no pad is right for both. So it
	 * does when one visit holds one more in front of what both hold: that shifts the ranks
	 * behind it. The slot of the flags that a lock was taken with is a second place.
	 */
	if (cancel_kind_ordered(a->kind) && (a->rank != b->rank || a->irq_off != b->irq_off))
		return false;
	return a->kind == b->kind && a->place == b->place &&
	       !((a->flags ^ b->flags) & ~cancel_soft_flags(a->kind)) &&
	       a->arg == b->arg && a->off == b->off && a->flag == b->flag;
}

/* Are @a and @b the same but for the place: is what they hold released in one way? */
static bool cancel_entry_alike(const struct cancel_entry *a, const struct cancel_entry *b)
{
	struct cancel_entry at = *b;

	at.place = a->place;
	return cancel_entry_same(a, &at);
}

static bool cancel_list_has(const struct cancel_list *list, const struct cancel_entry *e)
{
	u32 i;

	for (i = 0; i < list->nr; i++)
		if (cancel_entry_same(&list->entries[i], e))
			return true;
	return false;
}

static struct cancel_entry *cancel_list_find(const struct cancel_list *list,
					     const struct cancel_entry *e)
{
	u32 i;

	for (i = 0; i < list->nr; i++)
		if (cancel_entry_same(&list->entries[i], e))
			return &list->entries[i];
	return NULL;
}

/* The origin of @ref, below 0 if it has none: no insn of its frame brought it there */
static int cancel_ref_origin(struct bpf_verifier_env *env, const struct bpf_reference_state *ref)
{
	u32 o;

	if (ref->origin < 0)
		return -1;
	o = env->insn_aux_data[ref->origin].cancel_origin;
	if (verifier_bug_if(!o, env, "cancel: insn %d is no origin", ref->origin))
		return -1;
	return o - 1;
}

/* The origin that stands for the class of origin @o */
static u32 cancel_class(struct bpf_cancel *c, u32 o)
{
	struct cancel_origin *origins = c->origins;

	while (origins[o].up != o) {
		origins[o].up = origins[origins[o].up].up;
		o = origins[o].up;
	}
	return o;
}

/* The classes of origins @x and @y become one */
static void cancel_union(struct bpf_cancel *c, u32 x, u32 y)
{
	x = cancel_class(c, x);
	c->origins[x].up = cancel_class(c, y);
}

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
 * A pad finds the handle of a resource in a place: a register of the frame or a slot of its
 * stack. The record of a visit is made from one state, which stands for every state that was
 * pruned against it on the way to the site. Only what is live is compared then, and the
 * insns that the verifier adds take a register that is dead for scratch, see
 * bpf_insert_loop_guards(). So a place has to be live in front of the site.
 *
 * Can the pad of the site that the current frame of @st is at, in front of st->insn_idx,
 * read register @regno? At a call the cancellation comes back out of the callee, which keeps
 * R6-R9 only.
 */
static bool cancel_reg_is_place(struct bpf_verifier_env *env, const struct bpf_verifier_state *st,
				enum bpf_cancel_site_type type, int regno)
{
	if (!(env->insn_aux_data[st->insn_idx].live_regs_before & BIT(regno)))
		return false;
	return type != BPF_CANCEL_SITE_CALL || (regno >= BPF_REG_6 && regno <= BPF_REG_9);
}

/*
 * Can it read the register that the current frame of @st spilled to slot @spi? Iterators,
 * dynptrs and IRQ flags don't ask: their slots are compared whether they are live or not, and
 * the program cannot write to them.
 */
static bool cancel_spill_is_place(struct bpf_verifier_env *env,
				  const struct bpf_verifier_state *st,
				  enum bpf_cancel_site_type type, int spi)
{
	struct bpf_func_state *frame = st->frame[st->curframe];
	const struct bpf_reg_state *reg;
	int i;

	if (!bpf_stack_slot_alive(env, st->curframe, spi * 2) ||
	    !bpf_stack_slot_alive(env, st->curframe, spi * 2 + 1))
		return false;
	/* bpf_remove_fastcall_spills_fills() may drop the spill */
	if (-(spi + 1) * BPF_REG_SIZE < env->subprog_info[frame->subprogno].fastcall_stack_off)
		return false;
	if (type != BPF_CANCEL_SITE_CALL)
		return true;
	/*
	 * A callee that is given a pointer to a stack may write to the slot, through that
	 * pointer or through one that it finds there. Without one it reaches no frame below.
	 * What a callee does to the slot shows where it is verified with this frame in the
	 * state: every site that a cancellation can come back from looks at the frame again,
	 * see cancel_record_callers().
	 */
	for (i = BPF_REG_1; i <= BPF_REG_5 && !env->cancel->caller_in_state; i++)
		if (base_type(frame->regs[i].type) == PTR_TO_STACK)
			return false;
	bpf_for_each_spilled_stack_arg(i, frame, reg)
		if (reg && base_type(reg->type) == PTR_TO_STACK)
			return false;
	return true;
}

/* The kfuncs that a pad calls for locks and IRQ flags */
enum cancel_lock_kfunc {
	CANCEL_KF_local_irq_restore,
	CANCEL_KF_res_spin_unlock,
	CANCEL_KF_res_spin_unlock_irqrestore,
};

BTF_ID_LIST(cancel_lock_kfuncs)
BTF_ID(func, bpf_local_irq_restore)
BTF_ID(func, bpf_res_spin_unlock)
BTF_ID(func, bpf_res_spin_unlock_irqrestore)

/*
 * The rank of refs[@idx] of @st, a lock or IRQ flags: how many of the two are in front of it
 * among the entries of its owner. refs[] is in the order of acquisition: a new entry goes to
 * the end, and release_reference_state() keeps the order of the rest. It is the same order in
 * every state that this one stands for, since refs[] is compared entry by entry.
 */
static u32 cancel_lock_rank(const struct bpf_verifier_state *st, u32 idx)
{
	u32 i, rank = 0;

	for (i = 0; i < idx; i++)
		if (st->refs[i].frameno == st->refs[idx].frameno &&
		    (st->refs[i].type & (REF_TYPE_IRQ | REF_TYPE_LOCK_MASK)))
			rank++;
	return rank;
}

/*
 * The slot of the current frame of @st that has the IRQ flags of refs[@idx], below 0 if it
 * has none: the flags may be in a slot of a caller that the frame was given a pointer to.
 *
 * The slot needs no register that is live. Such slots are compared in every state, and the
 * flags are there as long as the slot is: a write of the program turns it into another kind
 * of slot. The entry stays in refs[] then and nothing can restore the flags any more, so
 * that program is rejected when it gets to its exit.
 */
static int cancel_irq_slot(const struct bpf_verifier_state *st, u32 idx)
{
	const struct bpf_func_state *frame = st->frame[st->curframe];
	const struct bpf_stack_state *slot;
	u32 spi;
	int i;

	for (spi = 0; spi < bpf_stack_nr_slots(frame); spi++) {
		slot = bpf_stack_slot(frame, spi);
		for (i = 0; i < BPF_REG_SIZE; i++)
			if (slot->slot_type[i] != STACK_IRQ_FLAG)
				break;
		if (i == BPF_REG_SIZE && slot->spilled_ptr.id == st->refs[idx].id)
			return spi;
	}
	return -ENOENT;
}

/*
 * bpf_res_spin_lock_irqsave() takes a lock and saves IRQ flags, and only
 * bpf_res_spin_unlock_irqrestore() undoes the two. refs[] has an entry for each, the flags
 * right behind the lock: one call adds them, and the call that removes them asks for the last
 * lock and the last flags in refs[], see active_lock_id and active_irq_id.
 *
 * The slot of the current frame of @st that has the flags of the lock refs[@idx], below 0 if
 * it has none.
 */
static int cancel_lock_irq_slot(const struct bpf_verifier_state *st, u32 idx)
{
	const struct bpf_func_state *frame = st->frame[st->curframe];
	int spi;

	if (idx + 1 >= st->acquired_refs || st->refs[idx + 1].type != REF_TYPE_IRQ ||
	    st->refs[idx + 1].frameno != st->refs[idx].frameno)
		return -ENOENT;
	spi = cancel_irq_slot(st, idx + 1);
	if (spi < 0 || bpf_stack_slot(frame, spi)->spilled_ptr.irq.kfunc_class != IRQ_LOCK_KFUNC)
		return -ENOENT;
	return spi;
}

/*
 * IRQ flags that bpf_local_irq_save() saved: the pad calls bpf_local_irq_restore() with the
 * slot. The flags that bpf_res_spin_lock_irqsave() saved are in the entry of the lock.
 */
static int cancel_collect_irq(const struct bpf_verifier_state *st, u32 idx,
			      struct cancel_list *visit)
{
	const struct bpf_func_state *frame = st->frame[st->curframe];
	struct cancel_entry e = { .kind = CANCEL_IRQ };
	u32 rank;
	int spi;

	if (st->refs[idx].type != REF_TYPE_IRQ)
		return CANCEL_REFS;
	spi = cancel_irq_slot(st, idx);
	rank = cancel_lock_rank(st, idx);
	if (spi < 0 || rank > U16_MAX)
		return CANCEL_LOCK_PLACE;
	if (bpf_stack_slot(frame, spi)->spilled_ptr.irq.kfunc_class != IRQ_NATIVE_KFUNC) {
		/* the lock is the entry in front, which got here and has the slot */
		if (idx && st->refs[idx - 1].type == REF_TYPE_RES_LOCK_IRQ &&
		    cancel_lock_irq_slot(st, idx - 1) == spi)
			return 0;
		return CANCEL_LOCK_PLACE;
	}
	e.place = -(spi + 1) * BPF_REG_SIZE;
	e.rank = rank;
	return cancel_list_add(visit, &e);
}

/* How far the lock of @ref is into what has @rec, below 0 if that has no such lock */
static int cancel_lock_off(const struct btf_record *rec, const struct bpf_reference_state *ref)
{
	if (IS_ERR_OR_NULL(rec))
		return -ENOENT;
	return ref->type == REF_TYPE_LOCK ? rec->spin_lock_off : rec->res_spin_lock_off;
}

/*
 * A lock doesn't move while it is held. Is the lock of @ref at an address that is known now?
 * It is when the lock is in the only element of an array map that the program refers to,
 * like every lock in a global variable: whatever pointer the lock was taken through points
 * into that element. The map that stands for the inner maps of a map has no elements, and
 * is not among used_maps.
 */
static bool cancel_lock_addr(struct bpf_verifier_env *env, const struct bpf_reference_state *ref,
			     u64 *addr)
{
	const struct bpf_map *map = NULL;
	u64 base;
	int off;
	u32 i;

	for (i = 0; i < env->used_map_cnt && !map; i++)
		if (env->used_maps[i] == ref->ptr)
			map = env->used_maps[i];
	if (!map || map->map_type != BPF_MAP_TYPE_ARRAY || !map->ops->map_direct_value_addr)
		return false;
	off = cancel_lock_off(map->record, ref);
	if (off < 0 || map->ops->map_direct_value_addr(map, &base, off))
		return false;
	*addr = base + off;
	return true;
}

/*
 * Does @reg point into what the lock of @ref is in: the map value or the object? It has the
 * id of the lock then, and the type that a lock is taken through. Its offset has to be
 * known: *@delta is from where it points to the lock. A lock without an id is found by no
 * pointer, since nothing tells pointers without an id apart. Unless its map has
 * @one_elem: every pointer into the map points into that element then.
 */
static bool cancel_reg_at_lock(const struct bpf_reg_state *reg,
			       const struct bpf_reference_state *ref, bool one_elem, s32 *delta)
{
	const struct btf_struct_meta *meta;
	const struct btf_record *rec;
	s64 off;

	if (reg->type == PTR_TO_MAP_VALUE) {
		if (reg->map_ptr != ref->ptr)
			return false;
		rec = reg->map_ptr->record;
	} else if (reg->type == (PTR_TO_BTF_ID | MEM_ALLOC)) {
		if (reg->btf != ref->ptr)
			return false;
		meta = btf_find_struct_meta(reg->btf, reg->btf_id);
		rec = meta ? meta->record : NULL;
	} else {
		return false;
	}
	if (one_elem) {
		if (reg->type != PTR_TO_MAP_VALUE)
			return false;
	} else if (!ref->id || reg->id != ref->id) {
		return false;
	}
	if (!tnum_is_const(reg->var_off))
		return false;
	off = cancel_lock_off(rec, ref);
	if (off < 0)
		return false;
	off -= (s64)reg->var_off.value;
	if (off != (s32)off)
		return false;
	*delta = off;
	return true;
}

/* The lock of @e by the pointer to it: alt_place and alt_arg of struct cancel_entry */
static void cancel_entry_use_alt(struct cancel_entry *e)
{
	e->place = e->alt_place;
	e->arg = e->alt_arg;
	e->alt = false;
}

/*
 * @reg is in @place, which a pad can read. Does it lead to the lock of @ref, see
 * cancel_reg_at_lock()? The first place that does is alt_place of @e, with the lock alt_arg
 * bytes from where it points. @e notes every place that points as far from the lock as that
 * one. Not for a lock at a known address, @one_elem: its entry goes by the address or by the
 * one place.
 */
static void cancel_lock_at(const struct bpf_reg_state *reg, const struct bpf_reference_state *ref,
			   bool one_elem, int place, struct cancel_entry *e)
{
	s32 delta;

	if (!cancel_reg_at_lock(reg, ref, one_elem, &delta))
		return;
	if (e->alt_place == CANCEL_NO_PLACE) {
		e->alt_place = place;
		e->alt_arg = delta;
	}
	if (!one_elem && delta == e->alt_arg)
		cancel_note_place(e, place);
}

/*
 * The live places of the current frame of @st that lead to the lock of @ref, into alt_place
 * and alt_arg of @e: CANCEL_NO_PLACE if it has none. R6-R9 are asked first, then the slots
 * of the stack, the lowest number first: visits that have the pointer in several
 * places pick the same one where they can, and note the others, see
 * cancel_agree_on_places(). @one_elem: see cancel_reg_at_lock().
 */
static void cancel_lock_place(struct bpf_verifier_env *env, const struct bpf_verifier_state *st,
			      enum bpf_cancel_site_type type,
			      const struct bpf_reference_state *ref, bool one_elem,
			      struct cancel_entry *e)
{
	const struct bpf_func_state *frame = st->frame[st->curframe];
	const struct bpf_stack_state *slot;
	int i;

	e->alt_place = CANCEL_NO_PLACE;
	for (i = BPF_REG_6; i <= BPF_REG_9; i++)
		if (cancel_reg_is_place(env, st, type, i))
			cancel_lock_at(&frame->regs[i], ref, one_elem, i, e);
	for (i = 0; i < bpf_stack_nr_slots(frame); i++) {
		slot = bpf_stack_slot(frame, i);
		if (bpf_is_spilled_reg(slot) && cancel_spill_is_place(env, st, type, i))
			cancel_lock_at(&slot->spilled_ptr, ref, one_elem,
				       -(i + 1) * BPF_REG_SIZE, e);
	}
}

/*
 * A lock: the pad calls what unlocks it with the address of the lock, which is e->arg, or
 * e->arg bytes from where the pointer in e->place points.
 *
 * An entry in refs[] is a lock that is held: bpf_res_spin_lock() may fail, but the state in
 * which it did has no entry, see check_kfunc_call().
 */
static int cancel_collect_lock(struct bpf_verifier_env *env, const struct bpf_verifier_state *st,
			       enum bpf_cancel_site_type type, u32 idx, struct cancel_list *visit)
{
	const struct bpf_reference_state *ref = &st->refs[idx];
	struct cancel_entry e = { .place = CANCEL_NO_PLACE };
	u32 rank;
	int spi;

	switch (ref->type) {
	case REF_TYPE_LOCK:
		e.kind = CANCEL_SPIN_LOCK;
		break;
	case REF_TYPE_RES_LOCK:
		e.kind = CANCEL_RES_LOCK;
		break;
	case REF_TYPE_RES_LOCK_IRQ:
		e.kind = CANCEL_RES_LOCK_IRQ;
		break;
	default:
		return CANCEL_REFS;
	}
	rank = cancel_lock_rank(st, idx);
	if (rank > U16_MAX)
		return CANCEL_LOCK_PLACE;
	e.rank = rank;
	if (ref->type == REF_TYPE_RES_LOCK_IRQ) {
		spi = cancel_lock_irq_slot(st, idx);
		if (spi < 0)
			return CANCEL_LOCK_PLACE;
		e.irq_off = -(spi + 1) * BPF_REG_SIZE;
	}
	if (cancel_lock_addr(env, ref, &e.arg)) {
		/*
		 * One of several locks that the program chose at run time has another
		 * address in every visit. The pointer that it was taken through says which.
		 */
		cancel_lock_place(env, st, type, ref, true, &e);
		e.alt = e.alt_place != CANCEL_NO_PLACE;
	} else {
		cancel_lock_place(env, st, type, ref, false, &e);
		if (e.alt_place == CANCEL_NO_PLACE)
			return CANCEL_LOCK_PLACE;
		cancel_entry_use_alt(&e);
	}
	return cancel_list_add(visit, &e);
}

/*
 * Is a lock held that the pad of the current frame of @st leaves alone? The pad releases the
 * locks of its frame in front of everything else. The frames below keep theirs until their
 * pads run.
 */
static bool cancel_lock_below(const struct bpf_verifier_state *st)
{
	u32 i;

	for (i = 0; i < st->acquired_refs; i++)
		if ((st->refs[i].type & REF_TYPE_LOCK_MASK) &&
		    st->refs[i].frameno < (int)st->curframe)
			return true;
	return false;
}

/*
 * May a pad of the current frame of @st call kfunc @func_id of @btf with the address of an
 * object of the frame in R1? It is the call that the program makes to release the object, so
 * the program has to be allowed to make it, see bpf_fetch_kfunc_arg_meta(). @flags are what
 * the kfunc is registered with to be the one that releases. Every flag more asks for what a
 * pad may be without: a context that may sleep, an RCU section, which the locks of the frame
 * may have been, a capability, an argument that the verifier fills in. All but
 * KF_SPINLOCK_SAFE, which a lock that is still held asks for, see do_check_insn().
 */
static bool cancel_kfunc_ok(struct bpf_verifier_env *env, const struct bpf_verifier_state *st,
			    const struct btf *btf, u32 func_id, u32 flags)
{
	u32 *kf_flags = btf_kfunc_flags(btf, func_id, env->prog);

	if (!kf_flags || !btf_kfunc_is_allowed(btf, func_id, env->prog))
		return false;
	if ((*kf_flags & ~KF_SPINLOCK_SAFE) != flags)
		return false;
	return (*kf_flags & KF_SPINLOCK_SAFE) || !cancel_lock_below(st);
}

/* The slot of @frame that the iterator of refs[] entry @id begins in, -1 if it has none */
static int cancel_find_iter(const struct bpf_func_state *frame, u32 id)
{
	const struct bpf_stack_state *slot;
	u32 spi;

	for (spi = 0; spi < bpf_stack_nr_slots(frame); spi++) {
		slot = bpf_stack_slot(frame, spi);
		if (slot->slot_type[BPF_REG_SIZE - 1] == STACK_ITER && slot->spilled_ptr.id == id)
			return spi;
	}
	return -1;
}

/*
 * The kfunc that destroys an iterator of type @btf_id of @btf, as its BTF id in @btf, below 0
 * if a pad of the current frame of @st may not call it. It is bpf_iter_<type>_destroy() of
 * the BTF that has the kfunc which made the iterator: process_iter_arg() takes no other, and
 * btf_check_iter_kfuncs() saw to the name and to the iterator being the only argument.
 */
static int cancel_iter_destroy(struct bpf_verifier_env *env, const struct bpf_verifier_state *st,
			       struct btf *btf, u32 btf_id)
{
	const struct btf_type *t = btf_type_by_id(btf, btf_id);
	char name[128];
	s32 func_id;
	int len;

	len = snprintf(name, sizeof(name), "%s_destroy", btf_name_by_offset(btf, t->name_off));
	if (len < 0 || len >= sizeof(name))
		return -ENAMETOOLONG;
	func_id = btf_find_by_name_kind(btf, name, BTF_KIND_FUNC);
	if (func_id < 0)
		return func_id;
	if (!cancel_kfunc_ok(env, st, btf, func_id, KF_ITER_DESTROY))
		return -EACCES;
	/* the name is made of that of the type, and two types may have one name */
	t = btf_type_by_id(btf, btf_type_by_id(btf, func_id)->type);
	if (btf_check_iter_arg(btf, t, 0) != btf_id)
		return -EINVAL;
	return func_id;
}

/*
 * An open-coded iterator. refs[@idx] is the reference that bpf_iter_<type>_new() took, and
 * the slot that the iterator begins in has its id. The pad calls bpf_iter_<type>_destroy()
 * with the address of the iterator, which is what the program does for an iterator that is
 * active and for one that is drained.
 *
 * The entry is made of what the STACK_ITER slots say, and stacksafe() compares all of that,
 * in slots that are dead too. A program can write to the slots. Nothing destroys the
 * iterator then, and the program is rejected for the reference that is left.
 */
static int cancel_collect_iter(struct bpf_verifier_env *env, const struct bpf_verifier_state *st,
			       u32 idx, struct cancel_list *visit)
{
	const struct bpf_func_state *frame = st->frame[st->curframe];
	const struct bpf_reference_state *ref = &st->refs[idx];
	struct cancel_entry e = { .kind = CANCEL_KIND_ITER };
	const struct bpf_stack_state *slot;
	const struct bpf_reg_state *it, *reg;
	const struct bpf_insn *insn;
	int spi, nr_slots, func_id, i;
	u32 fr;

	if (ref->type != REF_TYPE_PTR)
		return CANCEL_REFS;
	spi = cancel_find_iter(frame, ref->id);
	if (spi < 0) {
		/* a callee made it in the stack of a frame below: this pad has no address for it */
		for (fr = 0; fr < st->curframe; fr++)
			if (cancel_find_iter(st->frame[fr], ref->id) >= 0)
				return CANCEL_ITER;
		return CANCEL_REFS;
	}
	it = &bpf_stack_slot(frame, spi)->spilled_ptr;

	/* what bpf_iter_<type>_destroy() asks of the slots, see is_iter_reg_valid_init() */
	nr_slots = btf_type_by_id(it->iter.btf, it->iter.btf_id)->size / BPF_REG_SIZE;
	if (spi + 1 < nr_slots)
		return CANCEL_ITER;
	for (i = 0; i < nr_slots; i++) {
		slot = bpf_stack_slot(frame, spi - i);
		reg = &slot->spilled_ptr;
		if (slot->slot_type[BPF_REG_SIZE - 1] != STACK_ITER || (i && reg->id) ||
		    reg->iter.btf != it->iter.btf || reg->iter.btf_id != it->iter.btf_id ||
		    (reg->type & PTR_UNTRUSTED))
			return CANCEL_ITER;
	}
	/*
	 * PTR_UNTRUSTED above: the RCU section that the iterator was made in is over. MEM_RCU:
	 * it lasts, but it may be a lock or an IRQ flag of the frame, see in_rcu_cs(), and the
	 * pad has released these when it destroys the iterator. An RCU or a preemption section
	 * is left behind that, and a program that doesn't sleep is in one throughout.
	 */
	if ((it->type & MEM_RCU) && st->in_sleepable && !st->active_rcu_locks &&
	    !st->active_preempt_locks)
		return CANCEL_ITER;

	func_id = cancel_iter_destroy(env, st, it->iter.btf, it->iter.btf_id);
	if (func_id < 0)
		return CANCEL_ITER;
	/*
	 * A call names the BTF of a module by an index into fd_array. The call that made the
	 * iterator has one for the BTF of its kfunc, which is the BTF of the iterator.
	 */
	insn = &env->prog->insnsi[ref->insn_idx];
	if (!bpf_pseudo_kfunc_call(insn) || !insn->off != !btf_is_module(it->iter.btf))
		return CANCEL_ITER;

	e.place = -(spi + 1) * BPF_REG_SIZE;
	e.arg = (u64)(u16)insn->off << 32 | (u32)func_id;
	return cancel_list_add(visit, &e);
}

BTF_ID_LIST_SINGLE(cancel_dynptr_file_discard_id, func, bpf_dynptr_file_discard)

/*
 * The dynptr at the lowest address of @frame that has refs[] entry @id for its reference: the
 * offset from r10, and its type in @type. 0 if the frame has none.
 *
 * The constructor of a dynptr of the types of dynptr_type_referenced() takes a reference, and
 * the dynptr and its clones have the id of that as parent_id. A dynptr of another type may
 * have the id of a reference there too: that of the object which it was made from.
 */
static int cancel_find_dynptr(const struct bpf_func_state *frame, u32 id,
			      enum bpf_dynptr_type *type)
{
	const struct bpf_stack_state *slot;
	const struct bpf_reg_state *reg;
	int spi;

	for (spi = (int)bpf_stack_nr_slots(frame) - 1; spi > 0; spi--) {
		slot = bpf_stack_slot(frame, spi);
		reg = &slot->spilled_ptr;
		if (slot->slot_type[BPF_REG_SIZE - 1] != STACK_DYNPTR || !reg->dynptr.first_slot ||
		    reg->parent_id != id)
			continue;
		if (reg->dynptr.type != BPF_DYNPTR_TYPE_RINGBUF &&
		    reg->dynptr.type != BPF_DYNPTR_TYPE_FILE)
			continue;
		*type = reg->dynptr.type;
		return -(spi + 1) * BPF_REG_SIZE;
	}
	return 0;
}

/*
 * May a pad of the current frame of @st release what a dynptr of type @type holds? It calls
 * what the program calls with the address of the dynptr: the kfunc bpf_dynptr_file_discard(),
 * or the helper bpf_ringbuf_discard_dynptr(). The helper has to pass what check_helper_call()
 * asks of it, and under a lock the program calls no such helper, see do_check_insn().
 */
static bool cancel_dynptr_ok(struct bpf_verifier_env *env, const struct bpf_verifier_state *st,
			     enum bpf_dynptr_type type)
{
	u32 func_id = cancel_dynptr_file_discard_id[0];
	const struct bpf_func_proto *fn;
	struct btf *btf;

	if (type == BPF_DYNPTR_TYPE_FILE) {
		btf = bpf_get_btf_vmlinux();
		return !IS_ERR_OR_NULL(btf) && func_id &&
		       cancel_kfunc_ok(env, st, btf, func_id, KF_RELEASE);
	}
	return !cancel_lock_below(st) &&
	       !bpf_get_helper_proto(env, BPF_FUNC_ringbuf_discard_dynptr, &fn) &&
	       (env->prog->gpl_compatible || !fn->gpl_only) &&
	       (!fn->allowed || fn->allowed(env->prog)) && !fn->might_sleep;
}

/*
 * A dynptr that holds a reference: a ringbuf record, or the reader of a file. refs[@idx] is
 * the reference that its constructor took, see mark_stack_slots_dynptr(). The dynptr and its
 * clones point to the one record or reader, or are all empty, so the pad releases through
 * any one of them: the one at the lowest address of the frame, for the visits to agree.
 *
 * stacksafe() compares the type and the ids of a dynptr slot, in slots that are dead too: the
 * dynptr is there in every state that this one stands for, which may have clones more. The
 * program may overwrite a dynptr while a clone is left. destroy_if_dynptr_stack_slot() tells
 * when it does that to the dynptr of a frame which waits in a call.
 */
static int cancel_collect_dynptr(struct bpf_verifier_env *env, const struct bpf_verifier_state *st,
				 u32 idx, struct cancel_list *visit)
{
	const struct bpf_reference_state *ref = &st->refs[idx];
	struct cancel_entry e = { .kind = CANCEL_KIND_DYNPTR };
	enum bpf_dynptr_type type;
	u32 fr;

	/*
	 * The reference may have an iterator for its parent: bpf_dynptr_from_file() of the file
	 * of a vma that bpf_iter_task_vma_next() returned. The program cannot destroy the
	 * iterator first, see invalidate_reference(), and a pad doesn't.
	 */
	BUILD_BUG_ON(CANCEL_KIND_DYNPTR > CANCEL_KIND_ITER);

	if (ref->type != REF_TYPE_PTR)
		return CANCEL_REFS;
	e.place = cancel_find_dynptr(st->frame[st->curframe], ref->id, &type);
	if (!e.place) {
		/* all in the stacks of frames below: this pad has no address for them */
		for (fr = 0; fr < st->curframe; fr++)
			if (cancel_find_dynptr(st->frame[fr], ref->id, &type))
				return CANCEL_DYNPTR;
		return CANCEL_REFS;
	}
	if (!cancel_dynptr_ok(env, st, type))
		return CANCEL_DYNPTR;
	e.arg = type;
	return cancel_list_add(visit, &e);
}

/* May a pad call helper @func_id: the program may, and it is a call that does not sleep */
static bool cancel_helper_ok(struct bpf_verifier_env *env, int func_id)
{
	const struct bpf_func_proto *fn;

	if (bpf_get_helper_proto(env, func_id, &fn))
		return false;
	if (fn->gpl_only && !env->prog->gpl_compatible)
		return false;
	if (fn->allowed && !fn->allowed(env->prog))
		return false;
	return !fn->might_sleep;
}

/*
 * Is reference @id the one of an iterator or of a dynptr, in the stack of whichever frame?
 * These are other kinds, and no register has the id.
 */
static bool cancel_ref_of_stack_obj(const struct bpf_verifier_state *st, u32 id)
{
	const struct bpf_stack_state *slot;
	const struct bpf_func_state *frame;
	int fr, spi;

	for (fr = 0; fr <= st->curframe; fr++) {
		frame = st->frame[fr];
		for (spi = 0; spi < bpf_stack_nr_slots(frame); spi++) {
			slot = bpf_stack_slot(frame, spi);
			switch (slot->slot_type[BPF_REG_SIZE - 1]) {
			case STACK_ITER:
				if (slot->spilled_ptr.id == id)
					return true;
				break;
			case STACK_DYNPTR:
				/* of a record or a file: its reference is the parent */
				if (slot->spilled_ptr.parent_id == id &&
				    (slot->spilled_ptr.dynptr.type == BPF_DYNPTR_TYPE_RINGBUF ||
				     slot->spilled_ptr.dynptr.type == BPF_DYNPTR_TYPE_FILE))
					return true;
				break;
			default:
				break;
			}
		}
	}
	return false;
}

/* The kfuncs that drop an object which the program owns, the per-CPU one last */
BTF_ID_LIST(cancel_obj_drop_ids)
BTF_ID(func, bpf_obj_drop)
BTF_ID(func, bpf_percpu_obj_drop)

/*
 * May a pad drop the object in @reg, which the program owns, like bpf_obj_drop() does or,
 * for a @percpu one, bpf_percpu_obj_drop()? It does not call the kfunc, see
 * cancel_emit_ptr(), but it does no more than the program may do there by calling it.
 * *@rec is for the fields that go with the object.
 */
static bool cancel_obj_drop_ok(struct bpf_verifier_env *env, const struct bpf_verifier_state *st,
			       const struct bpf_reg_state *reg, bool percpu,
			       const struct btf_record **rec)
{
	const struct btf_struct_meta *meta = btf_find_struct_meta(reg->btf, reg->btf_id);
	struct btf *vmlinux = bpf_get_btf_vmlinux();

	*rec = meta ? meta->record : NULL;
	/* bpf_kptr_xchg() gets an object out of a map for a program that has no such kfunc */
	if (IS_ERR_OR_NULL(vmlinux) || !env->prog->gpl_compatible ||
	    !btf_kfunc_is_allowed(vmlinux, cancel_obj_drop_ids[percpu], env->prog))
		return false;
	/* neither kfunc is called under a lock */
	if (cancel_lock_below(st))
		return false;
	/* a per-CPU object has no fields, see bpf_fixup_kfunc_call() */
	if (percpu)
		return !meta;
	/* the fields that check_kfunc_call() lets no tracing program destroy */
	return !bpf_nmi_unsafe_prog(env) || !btf_record_has_nmi_unsafe_fields(*rec);
}

/*
 * @reg is in @place, which a pad can read, and has the id of a reference that the current
 * frame of @st is to release. Can the pad release the reference out of it? Returns 0 with
 * @e filled in if so. If not, the reason why the site declines: @reason, which the places
 * before this one left, where @reg is no handle at all.
 *
 * A pad makes the call that the program would make, so @reg has to be what the verifier
 * takes for the argument of that call, see check_func_arg(): the pointer that was acquired
 * and not one into the object, of the type that the release function is declared with.
 * What a helper like bpf_tcp_sock() made of a reference has the id as well, and is a
 * handle only where the program may release through it.
 *
 * A pointer into an object that the program owns is as good as the one to its start: it has
 * the type of the object and says how far into it it points, and the pad takes that off.
 * bpf_list_pop_front() and bpf_rbtree_remove() return such a pointer, to the node in the
 * object, and it is all that the frame has until the program has made the other one of it.
 *
 * A pointer that may be NULL is one that the program did not test since it was acquired:
 * the verifier drops the reference where the test finds NULL. Nothing was acquired then,
 * so the pad makes the test and leaves the call out. If a callee made the test, the place
 * of the caller has the same NULL, for as long as nothing else is written to it, see
 * cancel_null_in_place().
 */
static int cancel_ptr_handle(struct bpf_verifier_env *env, const struct bpf_verifier_state *st,
			     const struct bpf_reg_state *reg, int place, int reason,
			     struct cancel_entry *e)
{
	u32 flags = type_flag(reg->type) & ~PTR_MAYBE_NULL;
	const struct btf_record *rec;
	struct bpf_release_kfunc rel;
	int helper = 0;
	u8 how = 0;
	s64 off;

	if (!tnum_is_const(reg->var_off))
		return reason;
	off = reg->var_off.value;
	if (off && (base_type(reg->type) != PTR_TO_BTF_ID || !(flags & MEM_ALLOC)))
		return reason;
	/* the pad takes it off with an immediate */
	if (off != (s32)off || off == S32_MIN)
		return reason;

	switch (base_type(reg->type)) {
	case PTR_TO_BTF_ID:
		/*
		 * An object that the program allocated, took out of a map, or removed from a
		 * list or a tree.
		 */
		if (flags & MEM_ALLOC) {
			if (flags & ~(MEM_ALLOC | MEM_PERCPU))
				return CANCEL_REFS;
			if (!cancel_obj_drop_ok(env, st, reg, flags & MEM_PERCPU, &rec))
				return CANCEL_RELEASE;
			how = CANCEL_PTR_OBJ | (flags & MEM_PERCPU ? CANCEL_PTR_PERCPU : 0);
			e->arg = (unsigned long)rec;
			e->off = off;
			break;
		}
		/* a kernel object: referenced is as good as trusted for a release kfunc */
		if (flags & ~PTR_TRUSTED)
			return CANCEL_REFS;
		/* the kfunc takes a pointer to this very type, as a release kfunc has to */
		if (bpf_find_release_kfunc(env, reg->btf, reg->btf_id, false, &rel))
			return CANCEL_RELEASE;
		if (cancel_lock_below(st) && !(rel.flags & KF_SPINLOCK_SAFE))
			return CANCEL_RELEASE;
		e->arg = rel.func_id | (u64)rel.offset << 32;
		break;
	case PTR_TO_SOCKET:
	case PTR_TO_SOCK_COMMON:
	case PTR_TO_TCP_SOCK:
		/*
		 * A socket that a lookup returned, or what bpf_sk_fullsock() and bpf_tcp_sock()
		 * made of it: bpf_sk_release() takes these too, and it is one address.
		 */
		if (flags)
			return CANCEL_REFS;
		helper = BPF_FUNC_sk_release;
		break;
	case PTR_TO_MEM:
		/* a record of bpf_ringbuf_reserve(), which the program did not get to submit */
		if (flags != MEM_RINGBUF)
			return CANCEL_REFS;
		helper = BPF_FUNC_ringbuf_discard;
		break;
	default:
		return CANCEL_REFS;
	}
	if (helper) {
		/* under a lock the program calls no helper that releases */
		if (cancel_lock_below(st) || !cancel_helper_ok(env, helper))
			return CANCEL_RELEASE;
		how = CANCEL_PTR_HELPER;
		e->arg = helper;
	}

	e->kind = CANCEL_PTR;
	e->place = place;
	e->flags = (type_may_be_null(reg->type) ? CANCEL_PTR_NULL : 0) | how;
	return 0;
}

/*
 * @reg is in @place and has the id of a reference, see cancel_ptr_handle(). @reason is 0 if
 * a place before this one has the handle and is the place of @e: this one is noted if it
 * has the handle in the same way.
 */
static int cancel_ptr_place(struct bpf_verifier_env *env, const struct bpf_verifier_state *st,
			    const struct bpf_reg_state *reg, int place, int reason,
			    struct cancel_entry *e)
{
	struct cancel_entry other = {};

	if (reason) {
		reason = cancel_ptr_handle(env, st, reg, place, reason, e);
		if (!reason)
			cancel_note_place(e, place);
		return reason;
	}
	if (!cancel_ptr_handle(env, st, reg, place, CANCEL_PLACE, &other) &&
	    cancel_entry_alike(e, &other))
		cancel_note_place(e, place);
	return 0;
}

/*
 * refs[@idx] of @st is a reference to an object, and the pad releases it like the program
 * does: by a call with the handle. Find the handle in a place of the current frame. It has
 * the id of the reference there, which a state that stands for another one has in the same
 * places as that one: ids are compared along with the types, in what is live.
 *
 * Where more than one place has the handle the visits of a site pick the same one where they
 * can: R6-R9 come first, then the stack, the lowest number first. The entry
 * notes the other places, for the visits that cannot, see cancel_agree_on_places().
 */
static int cancel_collect_ptr(struct bpf_verifier_env *env, const struct bpf_verifier_state *st,
			      enum bpf_cancel_site_type type, u32 idx, struct cancel_list *visit)
{
	const struct bpf_reference_state *ref = &st->refs[idx];
	const struct bpf_func_state *frame = st->frame[st->curframe];
	const struct bpf_stack_state *slot;
	int reason = CANCEL_PLACE, i, spi;
	struct cancel_entry e = {};

	if (ref->type != REF_TYPE_PTR || cancel_ref_of_stack_obj(st, ref->id))
		return CANCEL_REFS;

	for (i = BPF_REG_6; i <= BPF_REG_9; i++)
		if (frame->regs[i].id == ref->id && cancel_reg_is_place(env, st, type, i))
			reason = cancel_ptr_place(env, st, &frame->regs[i], i, reason, &e);
	for (spi = 0; spi < bpf_stack_nr_slots(frame); spi++) {
		slot = bpf_stack_slot(frame, spi);
		if (bpf_is_spilled_reg(slot) && slot->spilled_ptr.id == ref->id &&
		    cancel_spill_is_place(env, st, type, spi))
			reason = cancel_ptr_place(env, st, &slot->spilled_ptr,
						  -(spi + 1) * BPF_REG_SIZE, reason, &e);
	}
	return reason ?: cancel_list_add(visit, &e);
}

/*
 * refs[@idx] of @st is for the current frame to release. Each kind that has entries in
 * refs[] is asked in turn. It adds an entry to @visit and returns 0, or returns CANCEL_REFS
 * for what is not of its kind, or the reason why the site declines.
 *
 * Whatever a kind takes from the state has to hold in every state that this one stands
 * for: the type of a register or a slot, which of them have the same id, a constant.
 * Not what is merely within bounds here.
 */
static int cancel_collect_ref(struct bpf_verifier_env *env, const struct bpf_verifier_state *st,
			      enum bpf_cancel_site_type type, u32 idx, struct cancel_list *visit)
{
	int reason = CANCEL_REFS;

	if (reason == CANCEL_REFS)
		reason = cancel_collect_irq(st, idx, visit);
	if (reason == CANCEL_REFS)
		reason = cancel_collect_lock(env, st, type, idx, visit);
	if (reason == CANCEL_REFS)
		reason = cancel_collect_iter(env, st, idx, visit);
	if (reason == CANCEL_REFS)
		reason = cancel_collect_dynptr(env, st, idx, visit);
	if (reason == CANCEL_REFS)
		reason = cancel_collect_ptr(env, st, type, idx, visit);
	return reason;
}

/* The most sections of one kind that a pad leaves: it calls the unlock once for each */
#define CANCEL_SECTION_MAX	4
static_assert(CANCEL_SECTION_MAX <= CANCEL_ENTRY_INSNS);

BTF_ID_LIST(cancel_section_kfuncs)
BTF_ID(func, bpf_rcu_read_unlock)
BTF_ID(func, bpf_preempt_enable)

/* The kfunc that leaves one section of @kind */
static u32 cancel_section_kfunc(u8 kind)
{
	return cancel_section_kfuncs[kind == CANCEL_PREEMPT];
}

/*
 * RCU read sections and preemption-disabled sections have no entry in refs[]. The state
 * counts them, and a frame has the count of those that it was entered in and that are held
 * ever since, see release_context_state(). The difference, @nr, is for the frame to leave:
 * the sections that it entered, or that a callee entered and returned in.
 *
 * One entry stands for all @nr sections of @kind. It has no place, and visits that differ in
 * @nr have different entries. The counts are the same in every state that this one stands
 * for: states that differ in one of them are neither pruned nor joined.
 */
static int cancel_collect_section(struct cancel_list *visit, u8 kind, u32 nr)
{
	struct cancel_entry e = { .kind = kind, .place = CANCEL_NO_PLACE, .arg = nr };

	if (!nr)
		return 0;
	if (nr > CANCEL_SECTION_MAX)
		return CANCEL_SECTION;
	return cancel_list_add(visit, &e);
}

/*
 * What the current frame of @st holds of its own, as entries in @visit. Each kind adds the
 * entries of its resources here. Returns the reason when the frame holds what has no entry,
 * below 0 on error.
 *
 * Its own is what the frame is to release: the entries of refs[] that it owns, see
 * bpf_frame_owns_ref(), and the sections that it entered. The callers are recorded with
 * what they hold at their calls.
 */
static int cancel_collect(struct bpf_verifier_env *env, const struct bpf_verifier_state *st,
			  enum bpf_cancel_site_type type, struct cancel_list *visit)
{
	const struct bpf_func_state *frame = st->frame[st->curframe];
	struct cancel_entry *e;
	int reason;
	u32 i, nr;

	for (i = 0; i < st->acquired_refs; i++) {
		if (!bpf_frame_owns_ref(st, st->curframe, i))
			continue;
		nr = visit->nr;
		reason = cancel_collect_ref(env, st, type, i, visit);
		if (reason)
			return reason;
		/* the entry is for refs[i]: what brought that tells whether the frame holds it */
		if (visit->nr > nr) {
			e = &visit->entries[nr];
			e->origin = cancel_ref_origin(env, &st->refs[i]) + 1;
			e->stray = !e->origin;
		}
	}
	reason = cancel_collect_section(visit, CANCEL_RCU,
					st->active_rcu_locks - frame->entry_rcu_locks);
	if (reason)
		return reason;
	return cancel_collect_section(visit, CANCEL_PREEMPT,
				      st->active_preempt_locks - frame->entry_preempt_locks);
}

/*
 * A visit holds the lock of @v, which is at a known address, and @held has no lock at that
 * address: the program chose one of several locks at run time, and each visit has another.
 * By address these are entries that no pad can tell apart. The visits may still have the
 * pointer to their lock in one place. Then the entries become one that goes by the pointer:
 * "one of the locks is held, r7 points to it".
 */
static void cancel_lock_by_pointer(struct cancel_list *held, struct cancel_entry *v)
{
	struct cancel_entry by_ptr, other, *e;
	u32 i;

	if (!v->alt || cancel_list_has(held, v))
		return;
	by_ptr = *v;
	cancel_entry_use_alt(&by_ptr);
	/* visits before this one went by the pointer already */
	if (cancel_list_has(held, &by_ptr)) {
		*v = by_ptr;
		return;
	}
	for (i = 0; i < held->nr; i++) {
		e = &held->entries[i];
		if (!e->alt)
			continue;
		other = *e;
		cancel_entry_use_alt(&other);
		if (!cancel_entry_same(&other, &by_ptr))
			continue;
		cancel_entry_use_alt(e);
		*v = by_ptr;
		return;
	}
}

/*
 * An entry of @held that is released like @v and holds what an origin of the class of @v
 * brought. With @same_place the one that has its handle in the place of @v, else one that
 * has it in a place where @v has its handle too. NULL if there is none, or if nothing tells
 * what brought the resource of @v.
 */
static struct cancel_entry *cancel_partner(struct bpf_cancel *c, const struct cancel_list *held,
					   const struct cancel_entry *v, bool same_place)
{
	struct cancel_entry *e;
	u32 i, r;

	if (!v->origin)
		return NULL;
	r = cancel_class(c, v->origin - 1);
	for (i = 0; i < held->nr; i++) {
		e = &held->entries[i];
		if (!e->origin || e->stray || cancel_class(c, e->origin - 1) != r ||
		    !cancel_entry_alike(e, v))
			continue;
		if (same_place ? e->place == v->place :
				 cancel_common_place(e, v) != CANCEL_NO_PLACE)
			return e;
	}
	return NULL;
}

/*
 * A visit picks one place for each handle, and visits that have a handle in several places
 * may pick different ones: one has it in r6 and in a slot, another one in the slot only. By
 * these places the entries are two, each held on some paths only, and no flag tells them
 * apart. But an entry notes all the places that have its handle, and the two can go by one
 * that both have: the slot.
 *
 * Only entries of one class of origins are made one like this: the same insns brought what
 * they hold. A common place alone does not tell. The second visit may hold another resource
 * in r6: if that became one entry with the resource of the first visit, the slot would be a
 * second entry for a resource that the first visit holds as well. What nothing is known to
 * have brought stays in the place that its visit picked.
 */
static void cancel_agree_on_places(struct bpf_cancel *c, struct cancel_list *held,
				   struct cancel_list *visit)
{
	struct cancel_entry *e, *v, at;
	int place;
	u32 i;

	/*
	 * The entries that stay where they are come first: of the places that they leave to
	 * their partners none has the handle of another entry of the visit.
	 */
	for (i = 0; i < visit->nr; i++) {
		v = &visit->entries[i];
		e = cancel_partner(c, held, v, true);
		if (!e)
			continue;
		e->regs &= v->regs;
		e->slots &= v->slots;
	}
	for (i = 0; i < visit->nr; i++) {
		v = &visit->entries[i];
		if (cancel_partner(c, held, v, true))
			continue;
		e = cancel_partner(c, held, v, false);
		if (!e)
			continue;
		place = cancel_common_place(e, v);
		/* an entry that is there already holds something else: no two are the same */
		at = *e;
		at.place = place;
		if (e->place != place && cancel_list_has(held, &at))
			continue;
		at = *v;
		at.place = place;
		if (v->place != place && cancel_list_has(visit, &at))
			continue;
		e->place = v->place = place;
		e->regs &= v->regs;
		e->slots &= v->slots;
	}
}

/*
 * The current frame of @st waits in a call and is without @e, which every visit of the call
 * held so far: a callee tested the handle and found NULL, so nothing was acquired, see
 * cancel_ptr_handle(). The pad makes that test too, and is right for this visit if the
 * place of @e still has the NULL: a callee may have written to a slot since. Then the
 * entry is one that this visit is without, like any other.
 */
static bool cancel_null_in_place(struct bpf_verifier_env *env, const struct bpf_verifier_state *st,
				 const struct cancel_entry *e)
{
	const struct bpf_func_state *frame = st->frame[st->curframe];
	int spi = -e->place / BPF_REG_SIZE - 1;
	const struct bpf_stack_state *slot;
	const struct bpf_reg_state *reg;

	if (e->kind != CANCEL_PTR || !(e->flags & CANCEL_PTR_NULL) || e->cond)
		return false;
	if (cancel_place_is_reg(e->place)) {
		if (!cancel_reg_is_place(env, st, BPF_CANCEL_SITE_CALL, e->place))
			return false;
		reg = &frame->regs[e->place];
	} else {
		if (spi >= bpf_stack_nr_slots(frame))
			return false;
		slot = bpf_stack_slot(frame, spi);
		if (bpf_spill_size(slot) != BPF_REG_SIZE ||
		    !cancel_spill_is_place(env, st, BPF_CANCEL_SITE_CALL, spi))
			return false;
		reg = &slot->spilled_ptr;
	}
	return reg->type == SCALAR_VALUE && tnum_equals_const(reg->var_off, 0);
}

/*
 * A visit of @site found c->visit. An entry that this visit or one before it
 * is without takes a condition. So does a resource that the visits have in
 * different places and that finds no place for all of them: these are two
 * entries. Whether a pad can tell if the frame holds an entry with a condition
 * is found out after the main pass, see cancel_site_flags(). It goes by what
 * brought the resource, and whatever brought what the visits have in one entry
 * is one class.
 *
 * @waits: the visit is of a frame that waits in the call, the current one of that state, see
 * cancel_record_callers(). NULL for the visit of a frame that gets to the site.
 */
static int cancel_merge(struct bpf_verifier_env *env, struct cancel_site *site,
			const struct bpf_verifier_state *waits)
{
	struct bpf_cancel *c = env->cancel;
	struct cancel_list *held = &site->held, *visit = &c->visit;
	struct cancel_entry *e, *v;
	int err;
	u32 i;

	for (i = 0; i < visit->nr; i++)
		cancel_lock_by_pointer(held, &visit->entries[i]);
	cancel_agree_on_places(c, held, visit);
	for (i = 0; i < held->nr; i++) {
		e = &held->entries[i];
		v = cancel_list_find(visit, e);
		if (!v && waits && cancel_null_in_place(env, waits, e)) {
			/* no other place is known to have the NULL in this visit */
			e->regs = 0;
			e->slots = 0;
			cancel_note_place(e, e->place);
			continue;
		}
		if (!v) {
			e->cond = true;
			continue;
		}
		/* the pointer is of use only where every visit with the lock has it */
		if (e->alt && (!v->alt || v->alt_place != e->alt_place || v->alt_arg != e->alt_arg))
			e->alt = false;
		/* and so is a place that the entry notes */
		e->regs &= v->regs;
		e->slots &= v->slots;
		/* see cancel_soft_flags() */
		e->flags |= v->flags;
		e->stray |= v->stray;
		if (e->origin && v->origin)
			cancel_union(c, e->origin - 1, v->origin - 1);
		else if (v->origin)
			e->origin = v->origin;
	}
	for (i = 0; i < visit->nr; i++) {
		e = &visit->entries[i];
		if (cancel_list_has(held, e))
			continue;
		e->cond = site->visited;
		err = cancel_list_add(held, e);
		if (err)
			return err;
	}
	site->visited = true;
	return 0;
}

/*
 * A visit of @site by a frame whose state is @st, with the frame as the current one. Record
 * what the frame holds there. Whatever the reason, a site that declines once declines.
 * @waits: the frame got to the site before and waits in the call, see
 * cancel_record_callers().
 */
static int cancel_record_visit(struct bpf_verifier_env *env, const struct bpf_verifier_state *st,
			       struct cancel_site *site, bool waits)
{
	struct bpf_cancel *c = env->cancel;
	int reason;

	if (site->decline)
		return 0;
	c->visit.nr = 0;
	reason = cancel_collect(env, st, site->type, &c->visit);
	if (reason < 0)
		return reason;
	if (reason) {
		site->decline = reason;
		return 0;
	}
	return cancel_merge(env, site, waits ? st : NULL);
}

/*
 * The frames of @st below the current one wait in calls, and a cancellation that begins at
 * the site of the current frame goes on in the pads of these calls. The record of a call is
 * made at the call. A callee that has a pointer to the stack of a caller may have written
 * since to a slot that the record took for the place of a handle.
 *
 * So each frame that waits visits its call again, as it is now: the pad has to be right for
 * that too. A cancellation gets to the pad of a call from a site at or above the callee, and
 * each of these makes the visit when the callee is verified with the frame in the state, see
 * bpf_cancel_record_call(). A slot that lost the handle is no place in the visit: its entry
 * switches to a place that all visits have, see cancel_agree_on_places(), or the call
 * declines.
 *
 * The visit is made from a state that ends at the frame: what the pad of the call finds when
 * the frames above are gone. Their entries of refs[] stay and count for nothing. Their
 * sections are left: the frame above was entered in what is held then.
 *
 * A frame that holds nothing does not visit a call that no visit held anything at. One that
 * held something does: what a callee tested and found to be NULL is an entry that this
 * visit is without, see cancel_null_in_place(). What a callee released declines the call
 * before that, see bpf_cancel_foreign_release().
 */
static int cancel_record_callers(struct bpf_verifier_env *env, const struct bpf_verifier_state *st)
{
	struct bpf_cancel *c = env->cancel;
	struct bpf_verifier_state *caller = &c->caller;
	struct cancel_site *site;
	u32 holds = 0, i;
	int fr, err;

	BUILD_BUG_ON(MAX_CALL_FRAMES > BITS_PER_TYPE(holds));

	for (i = 0; i < st->acquired_refs; i++)
		if (st->refs[i].frameno >= 0 && st->refs[i].frameno < st->curframe)
			holds |= BIT(st->refs[i].frameno);
	for (fr = st->curframe - 1; fr >= 0; fr--) {
		/* a helper or a kfunc that calls a callback is no site */
		site = cancel_find_site(env, st->frame[fr + 1]->callsite, BPF_CANCEL_SITE_CALL);
		if (!site || site->decline || (!site->held.nr && !(holds & BIT(fr))))
			continue;
		*caller = *st;
		caller->curframe = fr;
		caller->insn_idx = site->insn_idx;
		caller->active_rcu_locks = st->frame[fr + 1]->entry_rcu_locks;
		caller->active_preempt_locks = st->frame[fr + 1]->entry_preempt_locks;
		c->caller_in_state = true;
		err = cancel_record_visit(env, caller, site, true);
		if (err)
			return err;
	}
	return 0;
}

/*
 * The current state is at a site, in front of env->insn_idx. Record what its current frame
 * holds there, and what the frames below hold at their calls, see cancel_record_callers().
 * @caller_in_state: the site is a call, and the frame is in the state while the callee is
 * verified, see cancel_spill_is_place().
 */
static int cancel_record(struct bpf_verifier_env *env, enum bpf_cancel_site_type type,
			 bool caller_in_state)
{
	struct bpf_verifier_state *st = env->cur_state;
	struct cancel_site *site;
	int err;

	/* the program doesn't get there */
	if (st->speculative)
		return 0;
	site = cancel_get_site(env, env->insn_idx, type);
	if (!site)
		return -ENOMEM;
	/*
	 * The stack check is in front of the first insn and only calls get to it: the
	 * frame has taken nothing yet, whatever a state that jumps to that insn holds,
	 * and no call moves a reference into it, see bpf_cancel_ref_moves(). The frames
	 * below are as their calls found them.
	 */
	if (type == BPF_CANCEL_SITE_ENTRY) {
		env->cancel->visit.nr = 0;
		return site->decline ? 0 : cancel_merge(env, site, NULL);
	}
	/* for cancel_spill_is_place() */
	err = bpf_live_stack_query_init(env, st);
	if (err)
		return err;
	env->cancel->caller_in_state = caller_in_state;
	err = cancel_record_visit(env, st, site, false);
	if (err)
		return err;
	return cancel_record_callers(env, st);
}

int bpf_cancel_record(struct bpf_verifier_env *env, enum bpf_cancel_site_type type)
{
	return cancel_record(env, type, false);
}

/*
 * The current state calls a static subprog at env->insn_idx. @caller_in_state: the callee is
 * verified with the frames of the state below it, and not on its own, see
 * call_func_on_its_own().
 */
int bpf_cancel_record_call(struct bpf_verifier_env *env, bool caller_in_state)
{
	return cancel_record(env, BPF_CANCEL_SITE_CALL, caller_in_state);
}

/*
 * The current frame released what frame @owner of the current state is to release, or left
 * a section that it entered. The owner waits in a call, and the record of the call says that
 * it holds that: its pad would release it once more. The call declines.
 *
 * Nothing is to be done for what the frame owns itself.
 *
 * The callers of a function that is verified on its own are not in the state: @owner is
 * below 0 when one of them is the owner. Such a function is verified again in the context of
 * every caller that holds something, see func_is_on_its_own(), but only after it has
 * returned to one, see bpf_flow_return(). It may not return, when it throws say, and then the
 * call of the owner is never found. So the function cannot be cancelled, and with it nothing
 * that it calls: no cancellation comes back to the owner from behind the release. Little is
 * given away: where the call of the owner is found it declines, and what it gets to cannot be
 * cancelled either.
 */
void bpf_cancel_foreign_release(struct bpf_verifier_env *env, int owner)
{
	const struct bpf_verifier_state *st = env->cur_state;
	struct cancel_site *site;

	if (st->speculative)
		return;
	if (owner < 0) {
		env->subprog_info[st->frame[0]->subprogno].cancel_foreign = true;
		return;
	}
	if (owner >= st->curframe)
		return;
	/* every state that calls is recorded. A helper or a kfunc that calls a callback is no site. */
	site = cancel_find_site(env, st->frame[owner + 1]->callsite, BPF_CANCEL_SITE_CALL);
	if (site && !site->decline)
		site->decline = CANCEL_FOREIGN;
}

/*
 * Can the program have pads at all? These are the reasons of cancel_sub_reason() that hold
 * for every subprog. Where there are no pads it makes no difference which frame owns a
 * reference.
 */
static bool cancel_prog_may_have_pads(struct bpf_verifier_env *env)
{
	return bpf_prog_has_invocation_budget(env->prog) && bpf_jit_supports_cancel() &&
	       !bpf_prog_is_offloaded(env->prog->aux) && env->bpf_capable && env->bypass_spec_v1;
}

/*
 * @frame calls static subprog @subprog. The argument that the callee gets the handle with
 * @id in, 0 if it gets it in none: 1-5 for R1-R5, where the callee reads the register, then
 * the stack arguments that the callee takes. A register that the callee doesn't read is
 * left over from what was there before.
 */
static int cancel_arg_of(struct bpf_verifier_env *env, const struct bpf_func_state *frame,
			 int subprog, u32 id)
{
	const struct bpf_subprog_info *sub = &env->subprog_info[subprog];
	u16 live = env->insn_aux_data[sub->start].live_regs_before;
	const struct bpf_reg_state *reg;
	int i;

	for (i = BPF_REG_1; i <= BPF_REG_5; i++)
		if ((live & BIT(i)) && frame->regs[i].id == id)
			return i;
	for (i = 0; i < bpf_in_stack_arg_cnt(sub) && i < frame->out_stack_arg_cnt; i++) {
		reg = &frame->stack_arg_regs[i];
		if (reg->type != NOT_INIT && reg->id == id)
			return MAX_BPF_FUNC_REG_ARGS + 1 + i;
	}
	return 0;
}

/*
 * The current frame of @st calls static subprog @subprog at env->insn_idx. Does refs[@idx]
 * move: is it for the frame of the callee to release from the call on?
 *
 * A caller that passes the handle in an argument and keeps it nowhere else has given the
 * reference away. Only the callee gets to release it, or to hand it back by returning with
 * it, see prepare_func_exit(). While the caller is the owner the call declines: its pad has
 * no place to release from, and a callee that releases makes the release a foreign one, see
 * bpf_cancel_foreign_release(). With the callee as the owner the record of the call is
 * without the reference, and the sites of the callee have it, in the places of the callee.
 *
 * The reference moves when all of this holds:
 * - The caller owns it, and its handle is a pointer, see cancel_collect_ptr(). An iterator
 *   and a dynptr are found by their address in the stack of the frame that has them.
 * - The callee is given the handle, see cancel_arg_of().
 * - The caller keeps no copy: none of R6-R9 has the handle and is live in front of the call,
 *   and neither does a slot of the caller's stack. A slot counts even when no pad of the call
 *   could read it, see cancel_spill_is_place(): the caller reads it again.
 * - No other reference is its child. A child is released before its parent, and the pad of
 *   the callee runs before the pad of the frame that has the child.
 * - The callee is not recursive: the pad of its stack check releases nothing, see
 *   bpf_cancel_record().
 *
 * No pad depends on the choice: whichever frame is the owner, its sites find the handle in
 * a place of that frame or decline. But the owner is compared when states are pruned and
 * joined, see refsafe(), and states that are related but for the owner have to make the same
 * choice, or more states are verified than without it. So the choice is made of what is
 * compared in them: the registers and the slots that are live. A register or a slot that one
 * state never wrote to stands for the handle that the other state has there. These two
 * choose differently, and are verified apart while they are in the callee. Nothing moves in
 * a program that cannot have pads: its states are compared as they were.
 *
 * bpf_live_stack_query_init() was called for @st.
 */
bool bpf_cancel_ref_moves(struct bpf_verifier_env *env, const struct bpf_verifier_state *st,
			  u32 idx, int subprog)
{
	const struct bpf_func_state *frame = st->frame[st->curframe];
	const struct bpf_subprog_info *sub = &env->subprog_info[subprog];
	const struct bpf_reference_state *ref = &st->refs[idx];
	const struct bpf_stack_state *slot;
	u32 i;

	if (ref->type != REF_TYPE_PTR || !bpf_frame_owns_ref(st, st->curframe, idx) ||
	    sub->recursive || !cancel_prog_may_have_pads(env))
		return false;
	if (!cancel_arg_of(env, frame, subprog, ref->id))
		return false;

	for (i = BPF_REG_6; i <= BPF_REG_9; i++)
		if (frame->regs[i].id == ref->id &&
		    cancel_reg_is_place(env, st, BPF_CANCEL_SITE_CALL, i))
			return false;
	for (i = 0; i < bpf_stack_nr_slots(frame); i++) {
		slot = bpf_stack_slot(frame, i);
		if (bpf_is_spilled_reg(slot) && slot->spilled_ptr.id == ref->id &&
		    bpf_stack_slot_alive(env, st->curframe, i * 2) &&
		    bpf_stack_slot_alive(env, st->curframe, i * 2 + 1))
			return false;
	}

	for (i = 0; i < st->acquired_refs; i++)
		if (st->refs[i].type == REF_TYPE_PTR && st->refs[i].parent_id == ref->id)
			return false;
	return !cancel_ref_of_stack_obj(st, ref->id);
}

/* The origin that the insn at @insn_idx is, a new one if it is none yet. Below 0 on error. */
static int cancel_get_origin(struct bpf_verifier_env *env, int insn_idx)
{
	struct bpf_insn_aux_data *aux = &env->insn_aux_data[insn_idx];
	struct bpf_cancel *c = env->cancel;
	struct cancel_origin *o;
	u32 cap;

	if (aux->cancel_origin)
		return aux->cancel_origin - 1;
	if (!c) {
		c = kzalloc_obj(*c, GFP_KERNEL_ACCOUNT);
		if (!c)
			return -ENOMEM;
		env->cancel = c;
	}
	if (c->nr_origins == c->cap_origins) {
		cap = max(2 * c->cap_origins, 16U);
		o = kvrealloc(c->origins, cap * sizeof(*o), GFP_KERNEL_ACCOUNT);
		if (!o)
			return -ENOMEM;
		c->origins = o;
		c->cap_origins = cap;
	}
	o = &c->origins[c->nr_origins];
	memset(o, 0, sizeof(*o));
	o->insn_idx = insn_idx;
	o->up = c->nr_origins;
	o->subprog = bpf_find_containing_subprog(env, insn_idx) - env->subprog_info;
	aux->cancel_origin = ++c->nr_origins;
	return c->nr_origins - 1;
}

/*
 * A frame holds a resource of origin @a and one of origin @b at a time. Whether that is
 * two of one class is known when the classes are: after the main pass.
 */
static int cancel_add_pair(struct bpf_cancel *c, u32 a, u32 b)
{
	struct cancel_pair *pairs;
	u32 i, cap;

	if (a == b) {
		c->origins[a].multi = true;
		return 0;
	}
	if (a > b)
		swap(a, b);
	for (i = 0; i < c->nr_pairs; i++)
		if (c->pairs[i].a == a && c->pairs[i].b == b)
			return 0;
	if (c->nr_pairs == CANCEL_PAIRS_MAX) {
		c->no_pairs = true;
		return 0;
	}
	if (c->nr_pairs == c->cap_pairs) {
		cap = max(2 * c->cap_pairs, 8U);
		pairs = krealloc_array(c->pairs, cap, sizeof(*pairs), GFP_KERNEL_ACCOUNT);
		if (!pairs)
			return -ENOMEM;
		c->pairs = pairs;
		c->cap_pairs = cap;
	}
	c->pairs[c->nr_pairs].a = a;
	c->pairs[c->nr_pairs++].b = b;
	return 0;
}

/*
 * Frame @frame of @st comes to hold a resource of origin @x: together with what it holds
 * already, but for the entries of refs[] from @first on that are frame @from's.
 */
static int cancel_add_pairs(struct bpf_verifier_env *env, const struct bpf_verifier_state *st,
			    int frame, u32 x, int from, u32 first)
{
	struct bpf_cancel *c = env->cancel;
	int y, err;
	u32 i;

	for (i = 0; i < st->acquired_refs && !c->no_pairs; i++) {
		if (st->refs[i].frameno != frame || (i >= first && st->refs[i].frameno == from))
			continue;
		y = cancel_ref_origin(env, &st->refs[i]);
		if (y < 0)
			continue;
		err = cancel_add_pair(c, x, y);
		if (err)
			return err;
	}
	return 0;
}

/*
 * The current frame is about to hold one more entry of refs[], which the insn at @insn_idx
 * acquires: the insn is its origin. All entries come from acquire_reference_state(), which
 * makes the origin first.
 */
int bpf_cancel_record_origin(struct bpf_verifier_env *env, int insn_idx)
{
	const struct bpf_verifier_state *st = env->cur_state;
	int x;

	x = cancel_get_origin(env, insn_idx);
	if (x < 0)
		return x;
	return cancel_add_pairs(env, st, st->curframe, x, -1, st->acquired_refs);
}

/* Visits of an origin have to agree on what tells that it brought a resource */
static void cancel_note_how(struct cancel_origin *o, u8 how)
{
	if (how == BPF_CANCEL_ACQUIRE_SOMETIMES || (o->how && o->how != how))
		o->inexact = true;
	else
		o->how = how;
}

/*
 * The current insn is a call of a helper or of a kfunc that acquired the last entry of
 * refs[]. @how tells whether a visit of the call did, see enum bpf_cancel_acquire: the insn
 * that says at run time that the frame holds the resource is behind the call and has
 * nothing else to go by. BPF_CANCEL_ACQUIRE_R0 is for a reference to an object, and R0 is
 * what the call returns by now.
 *
 * A pointer that may be NULL has a reference in refs[] until the program tests it, see
 * mark_ptr_or_null_regs(). Nothing is held when the pointer is NULL, and nothing takes the
 * entry away but the test. So the call did not bring a resource then.
 */
void bpf_cancel_record_acquire(struct bpf_verifier_env *env, enum bpf_cancel_acquire how)
{
	const struct bpf_verifier_state *st = env->cur_state;
	const struct bpf_reference_state *ref = &st->refs[st->acquired_refs - 1];
	int x = cancel_ref_origin(env, ref);

	if (x < 0)
		return;
	if (how == BPF_CANCEL_ACQUIRE_R0 &&
	    st->frame[st->curframe]->regs[BPF_REG_0].id != ref->id)
		how = BPF_CANCEL_ACQUIRE_SOMETIMES;
	cancel_note_how(&env->cancel->origins[x], how);
}

/* May a test for NULL still find that reference @id was never acquired? */
static bool cancel_ref_may_be_null(struct bpf_verifier_state *st, u32 id)
{
	struct bpf_func_state *frame;
	struct bpf_reg_state *reg;
	bool ret = false;

	bpf_for_each_reg_in_vstate(st, frame, reg, ({
		if (reg->id == id && type_may_be_null(reg->type))
			ret = true;
	}));
	return ret;
}

/*
 * A subprog returns to the call at @call_idx, which frame @frame of @st made. What it
 * returns with is for that frame to release from now on: the entries of refs[] from @first
 * on that are frame @from's. The call brought them to the frame and is their origin there.
 * @r0 is R0 as the subprog leaves it.
 *
 * The insn that says at run time that the frame holds such a resource is behind the call.
 * It has R0 to go by: the pointer to the object, when that is what the subprog returns, or
 * NULL when a return brought nothing. A return that unwinds does not get to that insn: then
 * nothing tells. A helper or a kfunc that calls a callback returns whether the callback ran
 * or not: what a callback leaves to the frame that it was called for has no origin.
 */
int bpf_cancel_record_return(struct bpf_verifier_env *env, struct bpf_verifier_state *st,
			     int call_idx, int frame, int from, u32 first,
			     struct bpf_reg_state *r0)
{
	const struct bpf_insn *insn = &env->prog->insnsi[call_idx];
	bool callback = !bpf_pseudo_call(insn) && !bpf_is_callx(insn);
	struct bpf_reference_state *ref;
	struct cancel_origin *o = NULL;
	u32 i, nr = 0;
	int x = -1, how;

	if (!callback) {
		x = cancel_get_origin(env, call_idx);
		if (x < 0)
			return x;
		o = &env->cancel->origins[x];
	}
	for (i = first; i < st->acquired_refs; i++) {
		ref = &st->refs[i];
		if (ref->frameno != from)
			continue;
		ref->origin = callback ? -1 : call_idx;
		if (callback)
			continue;
		nr++;
		how = BPF_CANCEL_ACQUIRE_ALWAYS;
		if (st->unwound)
			how = BPF_CANCEL_ACQUIRE_SOMETIMES;
		else if (ref->type == REF_TYPE_PTR && r0->id == ref->id)
			how = BPF_CANCEL_ACQUIRE_R0;
		else if (ref->type == REF_TYPE_PTR && cancel_ref_may_be_null(st, ref->id))
			how = BPF_CANCEL_ACQUIRE_SOMETIMES;
		cancel_note_how(o, how);
	}
	if (callback)
		return 0;
	if (!nr) {
		if (bpf_register_is_null(r0))
			o->null_ret = true;
		else
			o->inexact = true;
		return 0;
	}
	if (nr > 1)
		o->multi = true;
	return cancel_add_pairs(env, st, frame, x, from, first);
}

/*
 * A visit of the current insn takes refs[@idx] of the current state away, or takes nothing
 * away when @idx is below 0 although other visits of the insn do. Every such visit is to be
 * noted: an insn in front of the call says at run time that the frame of the call does not
 * hold the resource any more, whatever the visit. That is right where every visit takes
 * away a resource of one class that its frame holds. Else nothing tells:
 * - A frame that does not hold the resource takes it away. Its owner is not told.
 * - The insn is no call of a helper or of a kfunc, where the insn in front has its place.
 *
 * Nothing is noted where a test for NULL takes a reference away: the call that acquired it
 * did not bring a resource, see bpf_cancel_record_acquire(). Or where a frame leaves with
 * what it holds, see bpf_cancel_record_return(), or leaves it to a callee, see
 * bpf_cancel_ref_moved().
 */
void bpf_cancel_record_release(struct bpf_verifier_env *env, int idx)
{
	struct bpf_insn_aux_data *aux = &env->insn_aux_data[env->insn_idx];
	const struct bpf_insn *insn = &env->prog->insnsi[env->insn_idx];
	const struct bpf_verifier_state *st = env->cur_state;
	struct bpf_cancel *c = env->cancel;
	struct cancel_release *rel;
	u32 x = CANCEL_NO_ORIGIN, r, cap;
	int o = -1;

	/* nothing has an origin */
	if (!c)
		return;
	if (idx >= 0)
		o = cancel_ref_origin(env, &st->refs[idx]);
	if (o >= 0 && st->refs[idx].frameno == st->curframe &&
	    (bpf_helper_call(insn) || bpf_pseudo_kfunc_call(insn)))
		x = o;
	else if (o >= 0)
		c->origins[o].inexact = true;

	for (r = aux->cancel_release; r; r = rel->next) {
		rel = &c->releases[r - 1];
		if (rel->origin == x)
			return;
	}
	if (c->nr_releases == c->cap_releases) {
		cap = max(2 * c->cap_releases, 16U);
		rel = kvrealloc(c->releases, cap * sizeof(*rel), GFP_KERNEL_ACCOUNT);
		if (!rel) {
			c->no_releases = true;
			return;
		}
		c->releases = rel;
		c->cap_releases = cap;
	}
	rel = &c->releases[c->nr_releases];
	rel->insn_idx = env->insn_idx;
	rel->origin = x;
	rel->next = aux->cancel_release;
	aux->cancel_release = ++c->nr_releases;
}

/*
 * No insn of the frame that is to release refs[@idx] of @st brings it there, or it leaves
 * the frame with no insn that takes it away: the kernel holds the reference for an argument
 * of the program, or the frame leaves it to a callee at a call. Whatever makes another frame
 * the owner of an entry without bpf_cancel_record_return() has to tell before it does.
 * Nothing tells at run time whether a frame holds such a resource. The entry has no origin
 * from now on.
 */
void bpf_cancel_ref_moved(struct bpf_verifier_env *env, struct bpf_verifier_state *st, int idx)
{
	int x = cancel_ref_origin(env, &st->refs[idx]);

	if (x >= 0)
		env->cancel->origins[x].inexact = true;
	st->refs[idx].origin = -1;
}

/*
 * @a stands for @b from now on: @b is within it, or it is the join of the two. They hold the
 * same resources, and the origins of the two that are in the same entry of refs[] become
 * one class. This only takes notes: whether a state stands for another one does not depend
 * on the origins. A resource that has no origin in one of the two is not known by its
 * origin in the other one either.
 *
 * What the callers of a function that is verified on its own hold is left out. The state at
 * the entry of the function is shared by calls from anywhere, each with what its caller
 * holds, and the function is not the owner of that. Every call gets its own entries back
 * when the function returns, see bpf_flow_return().
 */
void bpf_cancel_alias_refs(struct bpf_verifier_env *env, const struct bpf_verifier_state *a,
			   const struct bpf_verifier_state *b)
{
	struct bpf_cancel *c = env->cancel;
	int x, y;
	u32 i;

	for (i = 0; i < a->acquired_refs; i++) {
		if (a->refs[i].origin == b->refs[i].origin ||
		    a->refs[i].frameno == BPF_INHERITED_FRAME)
			continue;
		x = cancel_ref_origin(env, &a->refs[i]);
		y = cancel_ref_origin(env, &b->refs[i]);
		if (x >= 0 && y >= 0) {
			cancel_union(c, x, y);
			continue;
		}
		if (x >= 0)
			c->origins[x].inexact = true;
		if (y >= 0)
			c->origins[y].inexact = true;
	}
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
	/* a caller that was not in the state would release again, see bpf_cancel_foreign_release() */
	if (sub->cancel_foreign)
		return CANCEL_FOREIGN;
	return CANCEL_OK;
}

/*
 * What a frame holds cannot be released by a pad, as against the subprog having no way to be
 * cancelled at all. The text is for the log, see cancel_reject().
 */
static const char *cancel_shape_text(u8 reason)
{
	switch (reason) {
	case CANCEL_REFS:
		return "the frame holds a resource that no pad releases";
	case CANCEL_SECTION:
		return "the frame is in more RCU or preemption-disabled sections than a pad leaves";
	case CANCEL_COND:
		return "the paths to it are in different numbers of RCU or preemption-disabled sections";
	case CANCEL_FOREIGN:
		return "a callee releases what the frame holds";
	case CANCEL_LOCK_PLACE:
		return "no register or stack slot that a pad can read leads to a lock or IRQ flags of the frame (at a call: R6-R9, or a slot that the callee is seen to leave alone)";
	case CANCEL_ITER:
		return "the frame holds an iterator that a pad cannot destroy there";
	case CANCEL_DYNPTR:
		return "the frame holds a dynptr that a pad cannot release there";
	case CANCEL_PLACE:
		return "no register or stack slot that a pad can read has a reference of the frame as it was acquired (at a call: R6-R9, or a slot that the callee is seen to leave alone)";
	case CANCEL_RELEASE:
		return "nothing that a pad may call there releases a reference of the frame";
	case CANCEL_MULTI:
		return "the frame holds a resource on some paths only, and may hold two that one insn brought, like a lock and its IRQ flags";
	case CANCEL_INEXACT:
		return "the frame holds a resource on some paths only, and no insn of the frame tells when: it was given to a callee, or a release leaves it on some paths";
	case CANCEL_PLACES:
		return "the frame holds a resource on some paths only, in more than one place or behind locks that differ";
	case CANCEL_STACK:
		return "the frame holds a resource on some paths only, and its stack has no room for a flag";
	default:
		return NULL;
	}
}

static const char *cancel_site_str(const struct cancel_site *site)
{
	switch (site->type) {
	case BPF_CANCEL_SITE_ENTRY:
		return "recursive call";
	default:
		return "call";
	}
}

/*
 * The subprogs that cannot be cancelled whatever their frames hold: a callback, an extension,
 * one without a value to return, and all that these call. They go on as they did when a
 * point fires. Everywhere else a point ends the invocation, or the program is not loaded:
 * see cancel_reject().
 */
static void cancel_find_stuck(struct bpf_verifier_env *env)
{
	struct bpf_cancel *c = env->cancel;
	struct cancel_site *site;
	bool changed;
	u32 i;
	int s;

	for (s = 0; s < env->subprog_cnt; s++)
		c->subs[s].stuck = c->subs[s].why && c->subs[s].why != CANCEL_FOREIGN;
	do {
		changed = false;
		for (i = 0; i < c->nr_sites; i++) {
			site = &c->sites[i];
			if (site->type != BPF_CANCEL_SITE_CALL || !c->subs[site->subprog].stuck)
				continue;
			cancel_for_each_callee(env, site, s) {
				changed |= !c->subs[s].stuck;
				c->subs[s].stuck = true;
			}
		}
	} while (changed);
}

/*
 * A cancellation gets to @site, in a subprog that can be cancelled, and the frame holds what
 * no pad releases there. Going on as if no point had fired would leave it to the program
 * whether an invocation that ran out of time or faulted ever ends. The program is not
 * loaded, and the log says what the limit is. @of_subprog: the reason is that of the subprog
 * of the site, the site has none of its own.
 */
static bool cancel_reject(struct bpf_verifier_env *env, const struct cancel_site *site,
			  bool of_subprog)
{
	const char *text = cancel_shape_text(site->decline);

	if (!text || env->cancel->subs[site->subprog].stuck)
		return false;
	/* the function was verified on its own, see bpf_cancel_foreign_release() */
	if (of_subprog && site->decline == CANCEL_FOREIGN)
		text = "the function of the frame releases what a caller of it holds";
	verbose(env, "insn %d: the program cannot be cancelled at this %s: %s (%s)\n",
		site->insn_idx, cancel_site_str(site), text, cancel_reason_str[site->decline]);
	return true;
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
 * A pad calls kfunc @func_id like the program does, with @offset as in off of the call insn.
 * The program gets to know the kfunc. Returns @reason if it cannot: the site declines.
 */
static int cancel_add_kfunc(struct bpf_verifier_env *env, u32 func_id, u16 offset, u8 reason)
{
	int err = bpf_add_kfunc_call(env, func_id, offset);

	if (!err)
		return 0;
	return err == -ENOMEM ? err : reason;
}

/*
 * A program that saved IRQ flags or took a lock has the kfunc that undoes it: the two are in
 * one set of kfuncs, and no path gets to an exit without the call. An id of 0 is a kfunc that
 * the kernel was built without.
 */
static int cancel_add_lock_kfunc(struct bpf_verifier_env *env, enum cancel_lock_kfunc kf)
{
	if (!cancel_lock_kfuncs[kf])
		return CANCEL_LOCK_PLACE;
	return cancel_add_kfunc(env, cancel_lock_kfuncs[kf], 0, CANCEL_LOCK_PLACE);
}

/* bpf_spin_unlock() is a helper. The type of a program that calls bpf_spin_lock() has it. */
static int cancel_has_spin_unlock(struct bpf_verifier_env *env)
{
	const struct bpf_func_proto *fn;

	return bpf_get_helper_proto(env, BPF_FUNC_spin_unlock, &fn) ? CANCEL_LOCK_PLACE : 0;
}

/*
 * The main pass is over and @e may get into a pad. What the release needs of the program
 * is set up here, like the kfunc that it calls, see cancel_add_kfunc(). Returns the reason
 * why the site declines when that cannot be had, below 0 on error.
 */
static int cancel_prepare_entry(struct bpf_verifier_env *env, const struct cancel_entry *e)
{
	switch (e->kind) {
	case CANCEL_IRQ:
		return cancel_add_lock_kfunc(env, CANCEL_KF_local_irq_restore);
	case CANCEL_SPIN_LOCK:
		return cancel_has_spin_unlock(env);
	case CANCEL_RES_LOCK:
		return cancel_add_lock_kfunc(env, CANCEL_KF_res_spin_unlock);
	case CANCEL_RES_LOCK_IRQ:
		return cancel_add_lock_kfunc(env, CANCEL_KF_res_spin_unlock_irqrestore);
	case CANCEL_RCU:
	case CANCEL_PREEMPT:
		return cancel_add_kfunc(env, cancel_section_kfunc(e->kind), 0, CANCEL_SECTION);
	case CANCEL_KIND_ITER:
		return cancel_add_kfunc(env, (u32)e->arg, e->arg >> 32, CANCEL_ITER);
	case CANCEL_KIND_DYNPTR:
		/* the program has the helper, see cancel_dynptr_ok() */
		if (e->arg != BPF_DYNPTR_TYPE_FILE)
			return 0;
		return cancel_add_kfunc(env, cancel_dynptr_file_discard_id[0], 0, CANCEL_DYNPTR);
	case CANCEL_PTR:
		/* cancel_ptr_handle() made sure of the helper. The drop is no call of a kfunc. */
		if (e->flags & (CANCEL_PTR_HELPER | CANCEL_PTR_OBJ))
			return 0;
		return cancel_add_kfunc(env, (u32)e->arg, e->arg >> 32, CANCEL_RELEASE);
	default:
		return 0;
	}
}

/* The order of the entries in a pad: kind by kind */
static int cancel_entry_cmp(const void *a, const void *b)
{
	const struct cancel_entry *x = a, *y = b;

	/* locks and IRQ flags: the one that was taken last goes first, see cancel_kind_ordered() */
	if (cancel_kind_ordered(x->kind) && cancel_kind_ordered(y->kind) && x->rank != y->rank)
		return x->rank > y->rank ? -1 : 1;
	if (x->kind != y->kind)
		return x->kind < y->kind ? -1 : 1;
	if (x->place != y->place)
		return x->place < y->place ? -1 : 1;
	if (x->flags != y->flags)
		return x->flags < y->flags ? -1 : 1;
	if (x->arg != y->arg)
		return x->arg < y->arg ? -1 : 1;
	return x->off < y->off ? -1 : x->off > y->off;
}

static bool cancel_same_held(const struct cancel_site *a, const struct cancel_site *b)
{
	u32 i;

	if (a->held.nr != b->held.nr)
		return false;
	for (i = 0; i < a->held.nr; i++)
		if (!cancel_entry_same(&a->held.entries[i], &b->held.entries[i]) ||
		    a->held.entries[i].flags != b->held.entries[i].flags)
			return false;
	return true;
}

/*
 * @site gets a pad: the one that its subprog has for what the frame holds there, or a new
 * one. The stack check has its pad in place, see bpf_cancel_entry_pad().
 */
static int cancel_assign_pad(struct bpf_verifier_env *env, struct cancel_site *site)
{
	struct bpf_cancel *c = env->cancel;
	struct cancel_sub *sub = &c->subs[site->subprog];
	struct cancel_pad *pad;
	u32 p, cap;

	site->padded = true;
	if (site->type == BPF_CANCEL_SITE_ENTRY) {
		env->subprog_info[site->subprog].cancel_entry = true;
		return 0;
	}
	sort(site->held.entries, site->held.nr, sizeof(*site->held.entries), cancel_entry_cmp,
	     NULL);
	for (p = sub->pads; p; p = pad->next) {
		pad = &c->pads[p - 1];
		if (!cancel_same_held(&c->sites[pad->site], site))
			continue;
		site->pad = p - 1;
		return 0;
	}

	if (c->nr_pads == c->cap_pads) {
		cap = max(2 * c->cap_pads, 16U);
		pad = kvrealloc(c->pads, cap * sizeof(*pad), GFP_KERNEL_ACCOUNT);
		if (!pad)
			return -ENOMEM;
		c->pads = pad;
		c->cap_pads = cap;
	}
	pad = &c->pads[c->nr_pads];
	pad->site = site - c->sites;
	pad->next = sub->pads;
	pad->back = 0;
	site->pad = c->nr_pads++;
	sub->pads = c->nr_pads;
	return 0;
}

/*
 * Drop flags. Where the visits of a site disagree on whether the frame holds a resource, the
 * entry has a condition, and the pad releases it only if the frame holds it in this run. A
 * flag says so: a hidden byte of the frame that is zero when the frame begins, see
 * bpf_reserve_zeroed_stack(). It has no handle in it. The pad finds the resource in the
 * place of the program, as it does without a condition.
 *
 * A flag is for a class of origins: nothing tells which of them brought what a frame holds
 * when the program gets to a site. It is 1 exactly while the frame holds a resource of the
 * class. A store behind every origin sets it, under the test that tells whether the insn
 * brought something, and a store in front of every call that takes such a resource away
 * clears it, see bpf_cancel_insert_flag_stores(). A class has a flag only if these stores
 * are right in every run:
 * - Every origin is an insn of one subprog, and its visits agree on what tells that it
 *   brought a resource, see bpf_cancel_record_acquire() and bpf_cancel_record_return().
 * - No frame holds two resources of the class at a time: the flag cannot say which.
 * - The frame that holds a resource gives it up itself, at a call of a helper or of a
 *   kfunc, and no visit of that call leaves a resource of the class with the frame, see
 *   bpf_cancel_record_release(). What the visits of one call take away is one class.
 * - The frame has room for the flag.
 * At a site the class of an entry with a condition is in no other entry: its flag would
 * release two places.
 *
 * RCU and preemption sections have no entry in refs[], and so no origin. Visits that
 * disagree on them decline as CANCEL_COND.
 */

/* Why the class that @r stands for has no flag, CANCEL_OK if it can have one */
static u8 cancel_class_reason(const struct cancel_origin *r)
{
	if (r->multi)
		return CANCEL_MULTI;
	if (r->inexact)
		return CANCEL_INEXACT;
	return r->no_room ? CANCEL_STACK : CANCEL_OK;
}

/*
 * The main pass is over: the classes are what they are but for the calls that take away,
 * which are looked at first. Find for each class whether it can have a flag, see "Drop
 * flags".
 *
 * A pad loads from the flag what an insn in front of it stored. Where a load may run ahead
 * of such a store, see bypass_spec_v4, the pad would go by what the flag was before.
 */
static void cancel_find_flag_classes(struct bpf_verifier_env *env)
{
	struct bpf_cancel *c = env->cancel;
	const struct cancel_release *rel, *other;
	struct cancel_origin *o, *r;
	u32 i, n;

	for (i = 0; i < c->nr_releases; i++) {
		rel = &c->releases[i];
		if (rel->origin == CANCEL_NO_ORIGIN)
			continue;
		for (n = env->insn_aux_data[rel->insn_idx].cancel_release; n; n = other->next) {
			other = &c->releases[n - 1];
			if (other->origin == CANCEL_NO_ORIGIN)
				c->origins[rel->origin].inexact = true;
			else
				cancel_union(c, rel->origin, other->origin);
		}
	}
	for (i = 0; i < c->nr_origins; i++) {
		o = &c->origins[i];
		r = &c->origins[cancel_class(c, i)];
		if (o->inexact || o->subprog != r->subprog ||
		    o->how == BPF_CANCEL_ACQUIRE_SOMETIMES ||
		    (o->null_ret && o->how != BPF_CANCEL_ACQUIRE_R0) ||
		    c->no_releases || !env->bypass_spec_v4)
			r->inexact = true;
		if (o->multi || c->no_pairs)
			r->multi = true;
	}
	for (i = 0; i < c->nr_pairs; i++) {
		r = &c->origins[cancel_class(c, c->pairs[i].a)];
		if (r == &c->origins[cancel_class(c, c->pairs[i].b)])
			r->multi = true;
	}
}

/*
 * Can a flag tell for each entry of @site that only some visits have whether the frame
 * holds it? Returns the reason why the site declines if not.
 */
static u8 cancel_site_flags(struct bpf_verifier_env *env, const struct cancel_site *site)
{
	struct bpf_cancel *c = env->cancel;
	const struct cancel_entry *e, *other;
	u32 i, j, r;
	u8 reason;

	for (i = 0; i < site->held.nr; i++) {
		e = &site->held.entries[i];
		if (!e->cond)
			continue;
		if (e->kind == CANCEL_RCU || e->kind == CANCEL_PREEMPT)
			return CANCEL_COND;
		if (!e->origin || e->stray)
			return CANCEL_INEXACT;
		r = cancel_class(c, e->origin - 1);
		reason = cancel_class_reason(&c->origins[r]);
		if (reason)
			return reason;
		for (j = 0; j < site->held.nr; j++) {
			other = &site->held.entries[j];
			if (j != i && other->origin && cancel_class(c, other->origin - 1) == r)
				return CANCEL_PLACES;
		}
	}
	return CANCEL_OK;
}

/* The flags that pads read: those of the sites that get a pad as things are */
static void cancel_find_used(struct bpf_verifier_env *env)
{
	struct bpf_cancel *c = env->cancel;
	const struct cancel_site *site;
	const struct cancel_entry *e;
	bool has_point;
	u32 i, j;

	for (i = 0; i < c->nr_origins; i++)
		c->origins[i].used = false;
	for (i = 0; i < c->nr_sites; i++) {
		site = &c->sites[i];
		if (site->decline || c->subs[site->subprog].why ||
		    !cancel_gets_to(env, site, &has_point))
			continue;
		for (j = 0; j < site->held.nr; j++) {
			e = &site->held.entries[j];
			if (e->cond)
				c->origins[cancel_class(c, e->origin - 1)].used = true;
		}
	}
}

/*
 * Reserve the flags that are used and have no room yet: a byte each, in the frame of the
 * subprog that the origins of the class are in. A subprog is asked once, for all of its
 * flags. Returns the number of subprogs whose frames have no room, below 0 on error.
 */
static int cancel_reserve_flags(struct bpf_verifier_env *env)
{
	struct bpf_cancel *c = env->cancel;
	struct cancel_origin *o, *first;
	int err, failed = 0;
	bool jit_required;
	u32 i, j, nr;
	s16 off;

	for (i = 0; i < c->nr_origins; i++) {
		first = &c->origins[i];
		if (!first->used || first->flag)
			continue;
		for (j = i, nr = 0; j < c->nr_origins; j++) {
			o = &c->origins[j];
			nr += o->used && !o->flag && o->subprog == first->subprog;
		}
		/*
		 * Such stack is for a program that the interpreter never runs. One with a pad
		 * is that, and it is no pad without its flags.
		 */
		jit_required = env->prog->jit_required;
		env->prog->jit_required = 1;
		err = bpf_reserve_zeroed_stack(env, first->subprog, nr, &off);
		if (err && err != -ENOSPC)
			return err;
		if (err) {
			env->prog->jit_required = jit_required;
			failed++;
		}
		for (j = i; j < c->nr_origins; j++) {
			o = &c->origins[j];
			if (!o->used || o->flag || o->subprog != first->subprog)
				continue;
			if (err) {
				o->used = false;
				o->no_room = true;
				continue;
			}
			o->flag = off++;
			c->nr_flags++;
		}
	}
	return failed;
}

/* @site gets a pad: its entries that only some visits have go by the flags of their classes */
static int cancel_set_flags(struct bpf_verifier_env *env, struct cancel_site *site)
{
	struct bpf_cancel *c = env->cancel;
	struct cancel_entry *e;
	u32 i;

	for (i = 0; i < site->held.nr; i++) {
		e = &site->held.entries[i];
		if (!e->cond)
			continue;
		e->flag = c->origins[cancel_class(c, e->origin - 1)].flag;
		if (verifier_bug_if(!e->flag, env, "cancel: no flag for the site at insn %u",
				    site->insn_idx))
			return -EFAULT;
	}
	return 0;
}

/*
 * The main pass is over and no insn has moved yet. Find the subprogs that can be cancelled,
 * and what becomes of each site: it gets a pad, it declines, or no cancellation gets there.
 * The frames are as large as the program makes them, and may still take hidden slots that
 * count for the limits of the stack, see bpf_reserve_zeroed_stack().
 */
int bpf_cancel_resolve(struct bpf_verifier_env *env)
{
	struct bpf_cancel *c = env->cancel;
	struct cancel_site *site;
	bool has_point, raises, of_subprog, reject = false;
	struct bpf_insn *insn;
	int s, reason, err = 0;
	u32 i, j;

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
	cancel_find_stuck(env);
	cancel_find_flag_classes(env);
	/* a site that cannot have what its pad needs declines, before the calls are looked at */
	for (i = 0; i < c->nr_sites; i++) {
		site = &c->sites[i];
		if (c->subs[site->subprog].why)
			continue;
		for (j = 0; j < site->held.nr && !site->decline; j++) {
			reason = cancel_prepare_entry(env, &site->held.entries[j]);
			if (reason < 0)
				return reason;
			site->decline = reason;
		}
		if (!site->decline)
			site->decline = cancel_site_flags(env, site);
	}
	cancel_drop_subs(env);
	cancel_find_raising(env);
	/*
	 * Only the flags of sites that get a pad take room. A site whose frame has none
	 * declines after all, and fewer sites get a pad then: that is found once more.
	 */
	cancel_find_used(env);
	err = cancel_reserve_flags(env);
	if (err < 0)
		return err;
	if (err) {
		for (i = 0; i < c->nr_sites; i++) {
			site = &c->sites[i];
			if (!site->decline && !c->subs[site->subprog].why)
				site->decline = cancel_site_flags(env, site);
		}
		for (s = 0; s < env->subprog_cnt; s++)
			c->subs[s].has_point = c->subs[s].raises = false;
		cancel_drop_subs(env);
		cancel_find_raising(env);
		cancel_find_used(env);
	}
	err = 0;

	for (i = 0; i < c->nr_sites && !err; i++) {
		site = &c->sites[i];
		raises = cancel_gets_to(env, site, &has_point);
		of_subprog = !site->decline;
		if (!site->decline)
			site->decline = c->subs[site->subprog].why;
		/*
		 * A call that declines counts when it is in the way of a point in what it calls.
		 * A call that doesn't decline needs a pad only for what comes out of the callee.
		 */
		if (!has_point || (!site->decline && !raises))
			site->unused = true;
		else if (!site->decline)
			err = cancel_set_flags(env, site) ?: cancel_assign_pad(env, site);
		else
			reject |= cancel_reject(env, site, of_subprog);
	}
	if (!err && reject)
		err = -EINVAL;
	return err;
}

/* @reg = r10 + @off: the address of a slot of the stack */
static int cancel_emit_slot_addr(int reg, int off, struct bpf_insn *buf)
{
	buf[0] = BPF_MOV64_REG(reg, BPF_REG_FP);
	buf[1] = BPF_ALU64_IMM(BPF_ADD, reg, off);
	return 2;
}

/* bpf_local_irq_restore() of the flags in the slot at @place */
static int cancel_emit_irq(int place, struct bpf_insn *buf)
{
	int n = cancel_emit_slot_addr(BPF_REG_1, place, buf);

	buf[n++] = BPF_CALL_KFUNC(0, cancel_lock_kfuncs[CANCEL_KF_local_irq_restore]);
	return n;
}

/*
 * Leave the sections of @e, one call each. The fixups keep bpf_rcu_read_unlock() and
 * bpf_preempt_enable() as calls in every program, sleepable or not, and take nothing about
 * them from insn_aux_data: the call of a pad does what the call of the program would have done.
 */
static int cancel_emit_section(const struct cancel_entry *e, struct bpf_insn *buf)
{
	int n, nr = e->arg;

	for (n = 0; n < nr; n++)
		buf[n] = BPF_CALL_KFUNC(0, cancel_section_kfunc(e->kind));
	return n;
}

/*
 * Unlock the lock of @e. Its address is e->arg: an immediate, which bpf_insn_prepare_dump()
 * shows as the map value that it is, like the addresses that the program loads. Or the lock
 * is e->arg bytes from where the pointer in @place points: a register, or a slot that the
 * register was spilled to.
 */
static int cancel_emit_unlock(const struct cancel_entry *e, int place, struct bpf_insn *buf)
{
	struct bpf_insn addr[] = { BPF_LD_IMM64(BPF_REG_1, e->arg) };
	int n = 0, kf;

	if (place == CANCEL_NO_PLACE) {
		buf[n++] = addr[0];
		buf[n++] = addr[1];
	} else {
		if (cancel_place_is_reg(place))
			buf[n++] = BPF_MOV64_REG(BPF_REG_1, place);
		else
			buf[n++] = BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_FP, place);
		if (e->arg)
			buf[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, (s32)e->arg);
	}
	/* the helper is called by its id, like in a program */
	if (e->kind == CANCEL_SPIN_LOCK) {
		buf[n++] = BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_spin_unlock);
		return n;
	}
	kf = CANCEL_KF_res_spin_unlock;
	if (e->kind == CANCEL_RES_LOCK_IRQ) {
		n += cancel_emit_slot_addr(BPF_REG_2, e->irq_off, buf + n);
		kf = CANCEL_KF_res_spin_unlock_irqrestore;
	}
	buf[n++] = BPF_CALL_KFUNC(0, cancel_lock_kfuncs[kf]);
	return n;
}

/* bpf_iter_<type>_destroy(r10 + @place), see cancel_collect_iter() for e->arg */
static int cancel_emit_iter(const struct cancel_entry *e, int place, struct bpf_insn *buf)
{
	int n = 0;

	buf[n++] = BPF_MOV64_REG(BPF_REG_1, BPF_REG_FP);
	buf[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, place);
	buf[n++] = BPF_CALL_KFUNC(e->arg >> 32, (u32)e->arg);
	return n;
}

/*
 * Release the reference whose handle is in @place, unless there is none: CANCEL_PTR_NULL. A
 * pointer that is e->off bytes into its object is NULL when there is no object, too.
 */
static int cancel_emit_ptr(const struct cancel_entry *e, int place, struct bpf_insn *buf)
{
	int n = 0, test = -1;

	if (cancel_place_is_reg(place))
		buf[n++] = BPF_MOV64_REG(BPF_REG_1, place);
	else
		buf[n++] = BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, place);
	if (e->flags & CANCEL_PTR_NULL)
		test = n++;
	if (e->off)
		buf[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, -e->off);

	if (e->flags & CANCEL_PTR_OBJ) {
		struct bpf_insn rec[2] = { BPF_LD_IMM64(BPF_REG_2, e->arg) };

		/*
		 * What bpf_obj_drop() and bpf_percpu_obj_drop() come to. The fixup of their
		 * call takes the type from the aux data of the insn, and a pad has none.
		 */
		buf[n++] = rec[0];
		buf[n++] = rec[1];
		buf[n++] = BPF_MOV64_IMM(BPF_REG_3, !!(e->flags & CANCEL_PTR_PERCPU));
		buf[n++] = BPF_EMIT_KERNEL_CALL(__bpf_obj_drop_impl);
	} else if (e->flags & CANCEL_PTR_HELPER) {
		/* bpf_ringbuf_discard(record, 0) */
		if (e->arg == BPF_FUNC_ringbuf_discard)
			buf[n++] = BPF_MOV64_IMM(BPF_REG_2, 0);
		buf[n++] = BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, e->arg);
	} else {
		buf[n++] = BPF_CALL_KFUNC(e->arg >> 32, (u32)e->arg);
	}

	/* over the call and what sets up its other arguments */
	if (test >= 0)
		buf[test] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, 0, n - test - 1);
	return n;
}

/*
 * bpf_dynptr_file_discard(r10 + @place) or bpf_ringbuf_discard_dynptr(r10 + @place, 0). The
 * helper is called by its id, like in a program: bpf_do_misc_fixups() finds the function.
 */
static int cancel_emit_dynptr(const struct cancel_entry *e, int place, struct bpf_insn *buf)
{
	int n = 0;

	buf[n++] = BPF_MOV64_REG(BPF_REG_1, BPF_REG_FP);
	buf[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, place);
	if (e->arg == BPF_DYNPTR_TYPE_FILE) {
		buf[n++] = BPF_CALL_KFUNC(0, cancel_dynptr_file_discard_id[0]);
		return n;
	}
	buf[n++] = BPF_MOV64_IMM(BPF_REG_2, 0);
	buf[n++] = BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_ringbuf_discard_dynptr);
	return n;
}

/*
 * The insns that release @e, into @buf: CANCEL_ENTRY_INSNS at most. Returns how many. The
 * handle is in @place: R6-R9 or a stack slot, whatever e->place says. The insns may clobber
 * R0-R5 and nothing else.
 */
static int cancel_emit_entry(struct bpf_verifier_env *env, const struct cancel_entry *e,
			     int place, struct bpf_insn *buf)
{
	switch (e->kind) {
	case CANCEL_IRQ:
		return cancel_emit_irq(place, buf);
	case CANCEL_SPIN_LOCK:
	case CANCEL_RES_LOCK:
	case CANCEL_RES_LOCK_IRQ:
		return cancel_emit_unlock(e, place, buf);
	case CANCEL_RCU:
	case CANCEL_PREEMPT:
		return cancel_emit_section(e, buf);
	case CANCEL_KIND_ITER:
		return cancel_emit_iter(e, place, buf);
	case CANCEL_KIND_DYNPTR:
		return cancel_emit_dynptr(e, place, buf);
	case CANCEL_PTR:
		return cancel_emit_ptr(e, place, buf);
	default:
		verifier_bug(env, "cancel: no pad releases kind %d", e->kind);
		return -EFAULT;
	}
}

/*
 * Leave the frame of subprog @s: BPF_CANCEL_PAD_EXIT_INSNS at most. cancel_exit returns to
 * the pad of the call that the frame was called by. The kernel entered the main program or
 * an async callback, and nothing else does, see cancel_sub_reason(): all frames are done.
 * The pad tells that the program was cancelled and returns to the kernel like any exit.
 */
static int cancel_emit_exit(struct bpf_verifier_env *env, int s, struct bpf_insn *buf)
{
	s32 val = 0;
	int n = 0;

	if (cancel_sub_is_top(env, s)) {
		/* it didn't refuse in cancel_sub_reason() */
		if (!s)
			bpf_prog_cancel_retval(env, &val);
		buf[n++] = BPF_EMIT_KERNEL_CALL(bpf_prog_report_cancel);
		buf[n++] = BPF_MOV64_IMM(BPF_REG_0, val);
		buf[n++] = BPF_EXIT_INSN();
		return n;
	}
	buf[n++] = BPF_MOV64_IMM(BPF_REG_0, 0);
	buf[n++] = BPF_RAW_INSN(BPF_JMP | BPF_EXIT, 0, BPF_CANCEL_EXIT, 0, 0);
	env->subprog_info[s].can_cancel = true;
	env->prog->jit_required = 1;
	return n;
}

/* The pad of @site: release what the frame holds there, kind by kind, and leave the frame */
static int cancel_emit_pad(struct bpf_verifier_env *env, const struct cancel_site *site,
			   struct bpf_insn *buf)
{
	int n = 0, cnt, skip, place;
	const struct cancel_entry *e;
	u32 i;

	for (i = 0; i < site->held.nr; i++) {
		place = site->held.entries[i].place;
		/* the flag of an entry that only some visits have tells whether it is there */
		e = &site->held.entries[i];
		skip = e->flag ? CANCEL_FLAG_INSNS : 0;
		cnt = cancel_emit_entry(env, e, place, buf + n + skip);
		if (cnt < 0)
			return cnt;
		if (skip) {
			buf[n] = BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_FP, e->flag);
			buf[n + 1] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, 0, cnt);
		}
		n += skip + cnt;
	}
	return n + cancel_emit_exit(env, site->subprog, buf + n);
}

bool bpf_cancel_has_pads(const struct bpf_verifier_env *env)
{
	return env->cancel && env->cancel->nr_pads;
}

/*
 * Queue the pads of subprog @s behind @tail: the last insn of the subprog, or of what is
 * queued behind it already. Returns the number of insns that are going to be added.
 */
int bpf_cancel_append_pads(struct bpf_verifier_env *env, int s, const struct bpf_insn *tail)
{
	struct bpf_cancel *c = env->cancel;
	u32 p, n = 1, need = 1;
	struct cancel_pad *pad;
	struct bpf_insn *insn;
	int cnt;

	if (!bpf_cancel_has_pads(env) || !c->subs[s].pads)
		return 0;
	for (p = c->subs[s].pads; p; p = pad->next) {
		pad = &c->pads[p - 1];
		need += c->sites[pad->site].held.nr * (CANCEL_ENTRY_INSNS + CANCEL_FLAG_INSNS);
		need += BPF_CANCEL_PAD_EXIT_INSNS;
	}
	if (need > c->cap_insns) {
		insn = kvrealloc(c->insns, need * sizeof(*insn), GFP_KERNEL_ACCOUNT);
		if (!insn)
			return -ENOMEM;
		c->insns = insn;
		c->cap_insns = need;
	}

	c->insns[0] = *tail;
	for (p = c->subs[s].pads; p; p = pad->next) {
		pad = &c->pads[p - 1];
		pad->back = n;
		cnt = cancel_emit_pad(env, &c->sites[pad->site], c->insns + n);
		if (cnt < 0)
			return cnt;
		n += cnt;
	}
	/*
	 * Insns are added in front of the pads from now on, and none behind them or in
	 * them: a pad is found from the end of its subprog, see cancel_pad_idx().
	 */
	for (p = c->subs[s].pads; p; p = pad->next) {
		pad = &c->pads[p - 1];
		pad->back = n - pad->back;
	}
	insn = bpf_patch_list_add(env, env->subprog_info[s + 1].start - 1, c->insns, n);
	return IS_ERR(insn) ? PTR_ERR(insn) : n - 1;
}

/* Where the pad of @site is, once bpf_cancel_append_pads() put it into the program */
static int cancel_pad_idx(struct bpf_verifier_env *env, const struct cancel_site *site)
{
	return env->subprog_info[site->subprog + 1].start - env->cancel->pads[site->pad].back;
}

/*
 * The pad of the stack check of subprog @s, into @buf: the frame has taken nothing, it only
 * leaves. Returns the number of insns, BPF_CANCEL_PAD_EXIT_INSNS at most, 0 if the check has
 * no pad.
 */
int bpf_cancel_entry_pad(struct bpf_verifier_env *env, int s, struct bpf_insn *buf)
{
	if (!env->subprog_info[s].cancel_entry)
		return 0;
	return cancel_emit_exit(env, s, buf);
}

/*
 * 'cancel_goto pad' behind each call that a cancellation comes back through: cancel_exit of
 * the callee finds the pad by the return address of the call. unwind_goto of the program
 * stays directly behind its call. The pads and the guards are in the program.
 *
 *	call
 *	[unwind_goto]
 *	cancel_goto pad
 *	insn
 *
 * The offset of the pad has 32 bits and is in imm, like that of gotol: cancel_goto is one insn
 * however far the pad is, and a call that returns goes on with the insn that follows.
 */
int bpf_cancel_insert_gotos(struct bpf_verifier_env *env)
{
	struct bpf_insn cg, *insn = env->prog->insnsi;
	int len = env->prog->len, i, at, off, err;
	struct cancel_site *site;

	if (!bpf_cancel_has_pads(env))
		return 0;

	for (i = 0; i < len; i++) {
		site = cancel_find_site(env, i, BPF_CANCEL_SITE_CALL);
		if (!site || !site->padded)
			continue;
		/*
		 * In front of the insn that follows: a jump to that insn doesn't go through
		 * cancel_goto. A jump out of what is inserted counts from that insn.
		 */
		at = i + 1 + bpf_is_unwind_goto(&insn[i + 1]);
		off = cancel_pad_idx(env, site) - at;
		cg = BPF_RAW_INSN(BPF_JMP | BPF_JCOND, 0, BPF_CANCEL_GOTO, 0, off);
		err = bpf_patch_list_insert(env, at, &cg, 1);
		if (err)
			return err;
		env->prog->jit_required = 1;
	}
	err = bpf_patch_list_commit(env);
	if (err)
		return err;

	/* The insn that follows may be dead code, when the callee never returns. This is not. */
	insn = env->prog->insnsi;
	for (i = 0; i < env->prog->len; i++) {
		site = cancel_find_site(env, i, BPF_CANCEL_SITE_CALL);
		if (!site || !site->padded)
			continue;
		at = i + 1 + bpf_is_unwind_goto(&insn[i + 1]);
		env->insn_aux_data[at].seen = env->pass_cnt;
	}
	return 0;
}

/*
 * Keep the flags that pads read, see "Drop flags". The pads, the guards and cancel_goto are
 * in the program, and an insn that the main pass noted is found by what is known about it.
 *
 *	call acquire			*(u8 *)(r10 + flag) = 0
 *	if r0 == 0 goto +1		call release
 *	*(u8 *)(r10 + flag) = 1
 *	insn
 *
 * The flag is set in front of the insn that follows the call, and of may_goto that is
 * there: a jump to that insn brought nothing. Behind the call of a subprog cancel_goto
 * comes first, which only a cancellation takes.
 *
 * The flag is cleared right in front of the call, behind what jumps to the call and behind
 * its may_goto: the frame holds the resource until the call is made, and the call gets to no
 * pad before it returns.
 */
int bpf_cancel_insert_flag_stores(struct bpf_verifier_env *env)
{
	struct bpf_cancel *c = env->cancel;
	const struct cancel_origin *o, *r;
	const struct cancel_site *site;
	struct bpf_insn buf[2], *insn;
	int i, n, at, err;
	u32 x;

	if (!c || !c->nr_flags)
		return 0;

	for (i = 0; i < env->prog->len; i++) {
		/* what its visits take away is of one class by now, or of classes without a flag */
		x = env->insn_aux_data[i].cancel_release;
		x = x ? c->releases[x - 1].origin : CANCEL_NO_ORIGIN;
		r = x != CANCEL_NO_ORIGIN ? &c->origins[cancel_class(c, x)] : NULL;
		if (r && r->used && r->flag) {
			buf[0] = BPF_ST_MEM(BPF_B, BPF_REG_FP, r->flag, 0);
			buf[1] = env->prog->insnsi[i];
			insn = bpf_patch_list_add(env, i, buf, 2);
			if (IS_ERR(insn))
				return PTR_ERR(insn);
		}

		x = env->insn_aux_data[i].cancel_origin;
		if (!x)
			continue;
		o = &c->origins[x - 1];
		r = &c->origins[cancel_class(c, x - 1)];
		if (!r->used || !r->flag)
			continue;
		n = 0;
		if (o->how == BPF_CANCEL_ACQUIRE_R0)
			buf[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 1);
		else if (o->how == BPF_CANCEL_ACQUIRE_R0_ZERO)
			/* the kfunc returns an int */
			buf[n++] = BPF_JMP32_IMM(BPF_JNE, BPF_REG_0, 0, 1);
		buf[n++] = BPF_ST_MEM(BPF_B, BPF_REG_FP, r->flag, 1);
		insn = &env->prog->insnsi[i];
		at = i + 1;
		if (bpf_pseudo_call(insn) || bpf_is_callx(insn)) {
			at += bpf_is_unwind_goto(insn + 1);
			site = cancel_find_site(env, i, BPF_CANCEL_SITE_CALL);
			if (site && site->padded)
				at++;
		}
		err = bpf_patch_list_insert(env, at, buf, n);
		if (err)
			return err;
	}
	return bpf_patch_list_commit(env);
}

/* The main pass starts over: the states of the round that is dropped never run */
void bpf_cancel_reset(struct bpf_verifier_env *env)
{
	struct bpf_cancel *c = env->cancel;
	u32 i;

	if (!c)
		return;
	for (i = 0; i < c->nr_sites; i++) {
		env->insn_aux_data[c->sites[i].insn_idx].cancel_site = 0;
		kfree(c->sites[i].held.entries);
	}
	c->nr_sites = 0;
	for (i = 0; i < c->nr_origins; i++)
		env->insn_aux_data[c->origins[i].insn_idx].cancel_origin = 0;
	c->nr_origins = 0;
	for (i = 0; i < c->nr_releases; i++)
		env->insn_aux_data[c->releases[i].insn_idx].cancel_release = 0;
	c->nr_releases = 0;
	c->no_releases = false;
	c->nr_pairs = 0;
	c->no_pairs = false;
	c->nr_flags = 0;
}

void bpf_cancel_free(struct bpf_verifier_env *env)
{
	struct bpf_cancel *c = env->cancel;
	u32 i;

	if (!c)
		return;
	for (i = 0; i < c->nr_sites; i++)
		kfree(c->sites[i].held.entries);
	kvfree(c->sites);
	kfree(c->visit.entries);
	kvfree(c->subs);
	kvfree(c->pads);
	kvfree(c->insns);
	kvfree(c->origins);
	kvfree(c->releases);
	kfree(c->pairs);
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
