// SPDX-License-Identifier: GPL-2.0-only
/*
 * Frame descriptors: which registers and stack slots of a BPF frame hold
 * kernel resources at an instruction where the program may be unwound.
 *
 * The verifier calls bpf_frame_desc_site() at every such site with the state
 * the site is reached in, and describes the current frame alone, at the
 * instruction. A caller frame waits in a call, which is a site of its own,
 * where the caller is described from its state at the call: that way the
 * unwinder releases each frame from its instruction pointer alone, and
 * nothing a callee does to its own frame is the caller's concern. One
 * descriptor is built per (subprog, insn, chain of calls), the calls the
 * frames below wait in, and the paths that reach the instruction under the
 * chain are merged into it; the builds of the chains are merged back into
 * one after the pass where the chains agree, see remerge_builds().
 *
 * A frame lists the references it owns, see bpf_reference_state::frameno,
 * and those it holds for a frame below that it, or a callee of its, may
 * release: the transfer, see bpf_frame_desc_resolve(). The frame below does
 * not list them at the call through which they reached the releasing frame.
 * What a callee returns with becomes the caller's at the return. A stack
 * object, an iterator or a dynptr, is listed where it is when it is in the
 * frame's own stack, and through a pointer to it otherwise. Locks, IRQ flags
 * and sections are released in order, and every path reaching a site must
 * place the same ones: they are kept apart from the per location lattice,
 * see place_fixed(). Sections are counted per frame, net of the callers'
 * sections the frame left, in the descriptor where the paths agree, in a
 * hidden slot where they do not.
 *
 * Where the paths reaching a site do not agree on a location of a resource,
 * or no live location holds it, the resource is released from its mirror: a
 * hidden stack slot of the subprog, keyed by where the subprog obtains the
 * handle, its acquisition, its entry or a load from the stack of a frame
 * below, which that fills with the handle, every release in the subprog
 * clears, and a return from a callee refreshes when the callee may have
 * released or returned the resource. The stack decides then. Mirrors are
 * reserved and their stores emitted after the main pass, for the resources
 * that needed one; the lattice comes first, and covers nearly every program.
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
 * into a descriptor so far. Only RES and GUARD locations are released at run
 * time; NULL is the one disagreement allowed with RES, since the unwinder
 * skips NULL, and a GUARD location is released when a scalar of the frame
 * says that the resource is there, see guarded().
 */
enum {
	LOC_UNSEEN,	/* no path classified this location yet */
	LOC_NULL,	/* known NULL on every path so far */
	LOC_RES,	/* holds the resource of class .res, maybe NULL on some path */
	LOC_GUARD,	/* the resource of class .res on some paths, nothing to release on others */
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
#define ACQ_NONE		(~0U)	/* sections have no origin */
#define LISTED_FIXED		-2	/* listed as a fixed entry, see build_add_listing() */
#define PASSED_STACK		BIT(5)	/* reaches the callee through the stack, see site_passed() */
#define MIRROR_KIND_PTR		0	/* the pointer the acquisition returned */
#define MIRROR_KIND_LOCK	0xff	/* the pointer to the lock; else a stack object's slot type */
#define DISC_SLOTS		64	/* stack slots that may tell a call's outcome */
#define SECTION_KINDS		2	/* RCU read, preemption disabled */

/* What a register holds where a frame obtains references, over every visit, see cell_merge(). */
enum bpf_cell_state {
	CELL_UNSEEN,
	CELL_NULL,	/* NULL on every visit so far */
	CELL_RES,	/* references of the classes in .res on every visit, or NULL */
	CELL_OTHER,	/* something that is not a reference: the register cannot be mirrored */
};
#define LISTED_SKIPPED		-3	/* a frame below's, held nowhere here: see site_do() */
#define ORDER_BELOW		-1	/* of a frame below: after the frame's own */
/* Release ranks of the entries without an acquisition order, see entry_cmp(). */
#define ORDER_RCU_OBJ		-1
#define ORDER_SECTION		-2
#define ORDER_OBJ		-3
/* A candidate for a guard: a live scalar on every visit of the build so far, see cells_update(). */
enum {
	CAND_UNSEEN,
	CAND_SCALAR,
	CAND_NONE,
};

static void note_held(struct bpf_verifier_env *env, const struct bpf_verifier_state *st, u32 origin);

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
	u32 origin[FRAME_LOCS];
	u8 owned[FRAME_LOCS];
	struct bpf_frame_desc_build *build;
	u32 pc;
	u32 subprog;
	u32 node;	/* the chain of the frame */
	u32 live_regs;
	const unsigned long *live_stack;
	struct bpf_frame_desc_fixed fixed[MAX_FIXED];
	u16 nr_fixed;
	/* the live scalars of the frame on this visit, the candidates for a guard, see scratch_ranges() */
	struct bpf_guard_hull range[FRAME_LOCS];
	u8 scalar[FRAME_LOCS];
};

/*
 * A candidate for the guard of a location, see guarded(): the hull of its range
 * on the visits that hold the resource there and on those that hold nothing
 * to release there, and whether a constant on the one kind is outside every
 * range of the other, see cand_add().
 */
struct bpf_guard_cand {
	struct bpf_guard_hull held;
	struct bpf_guard_hull free;
	bool alive;	/* a live scalar on every visit */
	bool excl;	/* every free range excludes the held constant: BPF_FRAME_GUARD_EQ */
	bool excl32;
	bool hexcl;	/* every held range excludes the free constant: BPF_FRAME_GUARD_NE */
	bool hexcl32;
};

/* The candidates for the guard of location @loc of a build, see digest_open(). */
struct bpf_guard_digest {
	s16 loc;
	struct bpf_guard_digest *next;
	struct bpf_guard_cand cand[FRAME_LOCS];
};

/* Make room for @nr_slots stack slots in the descriptor at @slot, of insn @pc. */
static struct bpf_frame_desc_build *build_grow(struct bpf_verifier_env *env, u32 pc,
					       struct bpf_frame_desc_build **slot, u32 nr_slots)
{
	struct bpf_frame_desc_build *b = *slot;
	u32 old = b ? b->nr_slots : 0;
	bool new = !b;

	if (b && old >= nr_slots)
		return b;
	b = kvrealloc(b, struct_size(b, slots, nr_slots), GFP_KERNEL_ACCOUNT);
	if (!b)
		return NULL;
	if (new)
		memset(b, 0, offsetof(struct bpf_frame_desc_build, slots));
	memset(&b->slots[old], 0, (nr_slots - old) * sizeof(b->slots[0]));
	/* a slot the earlier visits did not have holds anything on them: no guard reads it */
	if (!new && b->visits)
		for (; old < nr_slots; old++)
			b->slots[old].cand = CAND_NONE;
	b->pc = pc;
	b->nr_slots = nr_slots;
	*slot = b;
	return b;
}

/*
 * The build of insn @pc for the chain @node, in the list @slot holds, or the
 * list in the aux data of the insn when @slot is NULL: the build of the node,
 * or a new one appended to the list.
 */
static struct bpf_frame_desc_build *build_get(struct bpf_verifier_env *env, u32 pc, u32 nr_slots,
					      struct bpf_frame_desc_build **slot, u32 node)
{
	struct bpf_frame_desc_build **pp = slot ?: &env->insn_aux_data[pc].frame_desc, *b;

	for (; *pp; pp = &(*pp)->next)
		if ((*pp)->node == node)
			break;
	b = build_grow(env, pc, pp, nr_slots);
	if (b)
		b->node = node;
	return b;
}

static void digests_free(struct bpf_frame_desc_build *b)
{
	struct bpf_guard_digest *d, *next;

	for (d = b->digests; d; d = next) {
		next = d->next;
		kvfree(d);
	}
	b->digests = NULL;
}

static void build_destroy(struct bpf_frame_desc_build *b)
{
	digests_free(b);
	kvfree(b->fixed);
	kvfree(b->listed);
	kvfree(b->targets);
	kvfree(b->extra);
	kvfree(b);
}

/* Destroy the list of builds at @b. */
void bpf_frame_desc_build_destroy(struct bpf_frame_desc_build *b)
{
	struct bpf_frame_desc_build *next;

	for (; b; b = next) {
		next = b->next;
		build_destroy(b);
	}
}

static void cells_free(struct bpf_cells *cells)
{
	kvfree(cells->sets);
	cells->sets = NULL;
	cells->cnt = 0;
}

void bpf_frame_desc_build_free(struct bpf_insn_aux_data *aux)
{
	bpf_frame_desc_build_destroy(aux->frame_desc);
	bpf_frame_desc_build_destroy(aux->guard_desc);
	aux->frame_desc = NULL;
	aux->guard_desc = NULL;
	cells_free(&aux->ref_load_cells);
}

/* The subprog insn @idx belongs to. */
static int insn_subprog(struct bpf_verifier_env *env, u32 idx)
{
	int l = 0, r = env->subprog_cnt, m;

	if (idx >= env->subprog_info[r].start)
		return -1;
	while (r - l > 1) {
		m = l + (r - l) / 2;
		if (env->subprog_info[m].start <= idx)
			l = m;
		else
			r = m;
	}
	return l;
}

/*
 * The trie of the chains of calls the main pass sees. The chain of a frame
 * is the sequence of the calls the frames below it wait in, nearest first:
 * a path from the root, node 0, which is the chain of the main program, of
 * a subprog verified on its own, of an asynchronous callback and of the
 * exception callback; the chain of a callback a helper runs begins with the
 * call of the helper. The verifier keeps its states apart by chain, so a
 * frame may hold different things at an insn under different chains, and
 * the descriptors follow: one build per (insn, chain), see build_get(),
 * which bpf_frame_desc_resolve() merges back where the chains agree. Here
 * the chains are paths of orig insns; the trie the unwinder walks names the
 * sites instead, see bpf_frame_desc_build_tables().
 */
static int chain_child(struct bpf_verifier_env *env, u32 parent, u32 pc, bool create)
{
	struct bpf_chain *c;
	u32 i, cnt = env->chain_cnt;

	for (i = 1; i < cnt; i++)
		if (env->chains[i].parent == parent && env->chains[i].pc == pc)
			return i;
	if (!create)
		return -ENOENT;
	c = kvrealloc(env->chains, array_size(cnt + 2, sizeof(*c)), GFP_KERNEL_ACCOUNT);
	if (!c)
		return -ENOMEM;
	env->chains = c;
	if (!cnt)
		c[cnt++] = (struct bpf_chain) { .pc = ~0 };
	c[cnt] = (struct bpf_chain) { .parent = parent, .pc = pc, .pool = ~0 };
	env->chain_cnt = cnt + 1;
	return cnt;
}

/* Is chain @v a proper prefix of chain @w: does the path to w go through v? */
static bool chain_is_prefix(const struct bpf_verifier_env *env, u32 v, u32 w)
{
	if (v == w)
		return false;
	while (w) {
		w = env->chains[w].parent;
		if (w == v)
			return true;
	}
	return false;
}

/*
 * The path of the chain of callsites @pcs, @n of them nearest first, from the
 * root: into @nodes, the root first, as far as the trie has it, or whole when
 * @create interns the rest. Returns how many nodes, or -ENOMEM. This is the
 * one place that says which way round the trie keeps a chain: the nearest
 * callsite is the child of the root, as the unwinder walks the callers of a
 * frame from the nearest, see bpf_unwind_chain(), and so a shorter chain of
 * the same frame, under a caller verified on its own, is a prefix of the
 * longer one, see merge_prefix_builds().
 */
static int chain_walk(struct bpf_verifier_env *env, const u32 *pcs, int n, bool create, u32 *nodes)
{
	int k, node = 0, cnt = 1;

	nodes[0] = 0;
	for (k = 0; k < n; k++) {
		int child = chain_child(env, node, pcs[k], create);

		if (child == -ENOENT)
			break;
		if (child < 0)
			return child;
		node = child;
		nodes[cnt++] = node;
	}
	return cnt;
}

/*
 * The node of the chain of the current frame of @st, interned: the callsites
 * of the frames below it, nearest first. Each frame keeps its node once it is
 * known, which the copies of the state carry on; the node of a frame is not
 * the child of its caller's, the caller's chain being the tail of its own,
 * so every frame that does not know its node yet walks its own path, the
 * frames below the current one included, whose nodes the records of a
 * release go by, see bpf_frame_desc_record_release().
 */
static int chain_of(struct bpf_verifier_env *env, struct bpf_verifier_state *st)
{
	u32 pcs[MAX_CALL_FRAMES], nodes[MAX_CALL_FRAMES + 1];
	int f, k, ret;

	for (f = 1; f <= st->curframe; f++) {
		if (st->frame[f]->chain)
			continue;
		for (k = 0; k < f; k++)
			pcs[k] = st->frame[f - k]->callsite;
		ret = chain_walk(env, pcs, f, true, nodes);
		if (ret < 0)
			return ret;
		st->frame[f]->chain = nodes[f] + 1;
	}
	return st->curframe ? st->frame[st->curframe]->chain - 1 : 0;
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
	kvfree(env->arrivals);
	kvfree(env->release_recs);
	kvfree(env->cb_releases);
	kvfree(env->slot_writes);
	kvfree(env->coclaims);
	kvfree(env->section_insns);
	kvfree(env->resources);
	kvfree(env->chains);
	env->mirrors = NULL;
	env->call_refs = NULL;
	env->arrivals = NULL;
	env->release_recs = NULL;
	env->cb_releases = NULL;
	env->slot_writes = NULL;
	env->coclaims = NULL;
	env->section_insns = NULL;
	env->resources = NULL;
	env->chains = NULL;
	env->chain_cnt = 0;
	env->mirror_cnt = 0;
	env->call_ref_cnt = 0;
	env->arrival_cnt = 0;
	env->release_rec_cnt = 0;
	env->cb_release_cnt = 0;
	env->slot_write_cnt = 0;
	env->coclaim_cnt = 0;
	env->section_insn_cnt = 0;
	env->resource_cnt = 0;
	env->frame_desc_visits = 0;
	env->frame_desc_conflicts = 0;
	env->frame_desc_guards = 0;
	env->mirrors_needed = 0;
	for (i = 0; i < env->subprog_cnt; i++) {
		struct bpf_subprog_info *sub = &env->subprog_info[i];

		cells_free(&sub->entry_cells);
		sub->section_counter = 0;
	}
	for (i = 0; i < env->prog->len; i++) {
		memset(&aux[i].ret_cell, 0, sizeof(aux[i].ret_cell));
		aux[i].ref_held_max = 0;
	}
}

void bpf_frame_desc_env_free(struct bpf_verifier_env *env)
{
	int i;

	for (i = 0; i < env->subprog_cnt; i++) {
		bpf_frame_desc_build_destroy(env->subprog_info[i].entry_guard);
		cells_free(&env->subprog_info[i].entry_cells);
	}
	for (i = 0; i < env->mirror_cnt; i++)
		kvfree(env->mirrors[i].stores);
	kvfree(env->mirrors);
	kvfree(env->call_refs);
	kvfree(env->arrivals);
	kvfree(env->release_recs);
	kvfree(env->cb_releases);
	kvfree(env->slot_writes);
	kvfree(env->coclaims);
	kvfree(env->section_insns);
	kvfree(env->resources);
	kvfree(env->frame_desc_scratch);
	kvfree(env->frame_desc_new_of);
	kvfree(env->frame_desc_targets);
	kvfree(env->frame_desc_reach);
	kvfree(env->frame_desc_moves);
	kvfree(env->chains);
	env->frame_desc_moves = NULL;
	env->chains = NULL;
	env->mirrors = NULL;
	env->call_refs = NULL;
	env->arrivals = NULL;
	env->release_recs = NULL;
	env->cb_releases = NULL;
	env->slot_writes = NULL;
	env->coclaims = NULL;
	env->section_insns = NULL;
	env->resources = NULL;
	env->frame_desc_scratch = NULL;
	env->frame_desc_new_of = NULL;
	env->frame_desc_targets = NULL;
	env->frame_desc_reach = NULL;
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
			     struct bpf_resource *res, const char *what, bool report)
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
		if (report)
			verbose(env, "frame_desc: no cleanup destructor registered for %s %s\n", what,
				name);
		return -EOPNOTSUPP;
	}
	flags = btf_kfunc_flags(dtor_btf, dtor->release_btf_id, env->prog);
	if (!flags) {
		if (report)
			verbose(env, "frame_desc: release kfunc of %s %s is not callable by this program\n",
				what, name);
		return -EOPNOTSUPP;
	}
	res->sleeps = *flags & KF_SLEEPABLE;
	t = btf_type_by_id(dtor_btf, dtor->kfunc_btf_id);
	res->dtor = t ? (void *)kallsyms_lookup_name(btf_name_by_offset(dtor_btf, t->name_off)) :
			NULL;
	if (!res->dtor) {
		if (report)
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

/*
 * Classify a register or spilled register that holds a reference, @report why
 * it cannot be. The pointer may point into the object, see reg_is_ref(): the
 * class carries by how much. A reference of a type that no destructor is
 * registered for, or whose release kfunc the program may not call, has no
 * class: it is one the program could not release either, so a site holding
 * it is one the verifier would reject anyway, for the leak.
 */
static int __resource_of_reg(struct bpf_verifier_env *env, const struct bpf_reg_state *reg,
			     bool report)
{
	u32 flags = type_flag(reg->type) & ~PTR_MAYBE_NULL;
	struct bpf_resource res;
	int ret;

	memset(&res, 0, sizeof(res));
	res.type = reg->type & ~PTR_MAYBE_NULL;
	res.delta = reg->var_off.value;
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
		ret = resource_registry(env, reg->btf, reg->btf_id, &res, "object", report);
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
	if (report)
		verbose(env, "frame_desc: cannot release a reference of type %s\n",
			reg_type_str(env, reg->type));
	return -EOPNOTSUPP;
}

static int resource_of_reg(struct bpf_verifier_env *env, const struct bpf_reg_state *reg)
{
	return __resource_of_reg(env, reg, true);
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
	ret = resource_registry(env, reg->iter.btf, reg->iter.btf_id, &res, "iterator", true);
	if (ret)
		return ret;
	res.rcu = (reg->type & MEM_RCU) && !res.sleeps;
	return resource_intern(env, &res);
}

/*
 * Does @reg point into the object of reference @id, @off bytes in: the node
 * of a list or a tree is popped and pushed that way, and the object it is
 * in is released.
 */
static bool reg_ref_off(const struct bpf_reg_state *reg, int id, s16 *off)
{
	if (reg->type == SCALAR_VALUE || reg->type == NOT_INIT || reg->id != id ||
	    !tnum_is_const(reg->var_off) || reg->var_off.value != (u64)(s16)reg->var_off.value)
		return false;
	*off = reg->var_off.value;
	return true;
}

/*
 * Does @reg hold the object of reference @id: the pointer to it, or one a
 * constant number of bytes into it, which the class of the location carries
 * as its delta, see __resource_of_reg().
 */
static bool reg_is_ref(const struct bpf_reg_state *reg, int id)
{
	s16 off;

	return reg_ref_off(reg, id, &off);
}

/*
 * Does @slot hold 8 bytes of zero: a spilled zero that fills it, or zero
 * bytes? A spill of fewer bytes leaves the rest as they were.
 */
static bool stack_slot_is_null(const struct bpf_stack_state *slot)
{
	int i;

	if (bpf_is_spilled_scalar_reg(slot))
		return bpf_spill_size(slot) == BPF_REG_SIZE &&
		       bpf_register_is_null((struct bpf_reg_state *)&slot->spilled_ptr);
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
 * will do: the lock is found from the pointer value by a fixed delta, which
 * the class carries, like the delta of a pointer into an object.
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
	/* the pointer points this far past the lock: negative for one in front of it */
	delta = (s64)reg->var_off.value - off;
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
 * which outlive calls, before a caller-saved register. At a call, whose live
 * registers are the callee-saved ones, a register comes before a slot: a
 * callee may write the frame's stack through a pointer into it, never its
 * callee-saved registers, see slot_writes_resolve(). Lower is better.
 */
static int cand_rank(const struct cand *c, const struct bpf_frame_desc_loc *loc, bool regs_saved)
{
	int rank = loc->state == LOC_NULL ? 0 : 4;

	if (!regs_saved)
		return rank + c->is_slot;
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

static struct bpf_frame_desc_loc *build_loc_nth(struct bpf_frame_desc_build *b, int l)
{
	return l < BPF_REG_10 ? &b->regs[l] : &b->slots[l - BPF_REG_10];
}

/*
 * A location that listed a resource is given up: what was listed there is
 * mirrored, and it lists nothing again.
 */
static void withdraw(struct bpf_frame_desc_loc *loc)
{
	loc->state = LOC_OTHER;
	loc->withdrawn = 1;
}

/*
 * Guards. A frame may hold a resource at a site on some paths and not on
 * others, since a callee, or the callback of a helper, released it on a
 * run-time condition the frame tests afterwards: a scalar of the frame, whose
 * range the verifier refined on each path and tests the frame's later
 * branches against. Where the paths disagree that way on a location, the
 * location is listed with a guard, the scalar, a constant and a test, when a
 * live scalar of the frame separates the paths that hold the resource from
 * the ones that do not: the unwinder tests it and skips the entry when it
 * says that the resource is gone. Only live scalars qualify: two states the
 * verifier joins or orders agree on the range of every live scalar, so that
 * the range a visit sees covers every path folded into it, while a dead one
 * says nothing about the paths. Each location of a build keeps the hull of
 * its range over the visits, see cells_update(); a location that comes to
 * disagree gets a digest, see digest_open(), which keeps for every candidate
 * the hull of its range on the visits that hold the resource and on the
 * others, and the guard is decided once the pass is over, see
 * guards_resolve(). No instruction is emitted for a guard. Where no scalar
 * tells, the location is withdrawn and the resource is mirrored, as before.
 */
/* The unsigned bounds of a scalar: the hull of its range, which may wrap around. */
static void hull_set(struct bpf_guard_hull *h, const struct bpf_reg_state *reg)
{
	h->min = cnum64_umin(reg->r64);
	h->max = cnum64_umax(reg->r64);
	h->min32 = cnum32_umin(reg->r32);
	h->max32 = cnum32_umax(reg->r32);
}

static void hull_union(struct bpf_guard_hull *h, const struct bpf_guard_hull *o)
{
	h->min = min(h->min, o->min);
	h->max = max(h->max, o->max);
	h->min32 = min(h->min32, o->min32);
	h->max32 = max(h->max32, o->max32);
}

static bool hull_has(const struct bpf_guard_hull *h, u64 v)
{
	return h->min <= v && v <= h->max;
}

static bool hull_has32(const struct bpf_guard_hull *h, u32 v)
{
	return h->min32 <= v && v <= h->max32;
}

/*
 * The candidates for a guard on this visit of @frame: the live scalars among
 * the locations the unwinder reads, R6-R9 of every frame, R0-R5 of the frame
 * at a site whose entry saves them, which the live set of the scratch says
 * already, and the stack slots a spilled scalar fills.
 */
static void scratch_ranges(struct scratch *s, const struct bpf_func_state *frame)
{
	int k;

	memset(s->scalar, 0, sizeof(s->scalar));
	for (k = 0; k < BPF_REG_10; k++) {
		const struct bpf_reg_state *reg = &frame->regs[k];

		if (!(s->live_regs & BIT(k)) || reg->type != SCALAR_VALUE)
			continue;
		hull_set(&s->range[k], reg);
		s->scalar[k] = 1;
	}
	for (k = 0; k < bpf_stack_nr_slots(frame) && k < MAX_BPF_STACK_SLOTS; k++) {
		const struct bpf_stack_state *slot = bpf_stack_slot(frame, k);

		if (!test_bit(k, s->live_stack) || !bpf_is_spilled_scalar_reg(slot) ||
		    bpf_spill_size(slot) != BPF_REG_SIZE)
			continue;
		hull_set(&s->range[BPF_REG_10 + k], &slot->spilled_ptr);
		s->scalar[BPF_REG_10 + k] = 1;
	}
}

/*
 * The ranges of this visit go into the hulls of the locations of @b: a
 * location stays a candidate while every visit finds a live scalar there.
 */
static void cells_update(struct bpf_frame_desc_build *b, const struct scratch *s)
{
	int k;

	for (k = 0; k < BPF_REG_10 + b->nr_slots; k++) {
		struct bpf_frame_desc_loc *loc = build_loc_nth(b, k);

		if (loc->cand == CAND_NONE)
			continue;
		if (!s->scalar[k]) {
			loc->cand = CAND_NONE;
			continue;
		}
		if (loc->cand == CAND_UNSEEN)
			loc->hull = s->range[k];
		else
			hull_union(&loc->hull, &s->range[k]);
		loc->cand = CAND_SCALAR;
	}
}

static struct bpf_guard_digest *digest_find(const struct bpf_frame_desc_build *b, int loc)
{
	struct bpf_guard_digest *d;

	for (d = b->digests; d; d = d->next)
		if (d->loc == loc)
			return d;
	return NULL;
}

/* The digest of location @loc of @b, with no candidate alive when new. */
static struct bpf_guard_digest *digest_get(struct bpf_frame_desc_build *b, int loc)
{
	struct bpf_guard_digest *d = digest_find(b, loc);

	if (d)
		return d;
	d = kvzalloc(sizeof(*d), GFP_KERNEL_ACCOUNT);
	if (!d)
		return NULL;
	d->loc = loc;
	d->next = b->digests;
	b->digests = d;
	return d;
}

/* Candidate @c ranges over @held on the visits that hold the resource, over @free on the others. */
static void cand_set(struct bpf_guard_cand *c, const struct bpf_guard_hull *held,
		     const struct bpf_guard_hull *free)
{
	c->alive = true;
	c->held = *held;
	c->free = *free;
	c->excl = !(held->min == held->max && hull_has(free, held->min));
	c->excl32 = !(held->min32 == held->max32 && hull_has32(free, held->min32));
	c->hexcl = !(free->min == free->max && hull_has(held, free->min));
	c->hexcl32 = !(free->min32 == free->max32 && hull_has32(held, free->min32));
}

/*
 * Candidate @c ranges over @r on another visit, one that holds the resource,
 * or one that does not when @free. A constant the other kind of visit keeps
 * has to stay outside every range of this kind for the tests on equality;
 * once the hull of a kind grows past a constant those are off anyway.
 */
static void cand_add(struct bpf_guard_cand *c, const struct bpf_guard_hull *r, bool free)
{
	struct bpf_guard_hull *mine = free ? &c->free : &c->held;
	const struct bpf_guard_hull *other = free ? &c->held : &c->free;
	bool *ex = free ? &c->excl : &c->hexcl, *ex32 = free ? &c->excl32 : &c->hexcl32;

	if (other->min == other->max && hull_has(r, other->min))
		*ex = false;
	if (other->min32 == other->max32 && hull_has32(r, other->min32))
		*ex32 = false;
	hull_union(mine, r);
}

/* Candidate @c takes what @o saw of the same location in another build of the insn. */
static void cand_merge(struct bpf_guard_cand *c, const struct bpf_guard_cand *o)
{
	if (!c->alive || !o->alive) {
		c->alive = false;
		return;
	}
	cand_add(c, &o->held, false);
	cand_add(c, &o->free, true);
	c->excl &= o->excl;
	c->excl32 &= o->excl32;
	c->hexcl &= o->hexcl;
	c->hexcl32 &= o->hexcl32;
}

/*
 * Location @k of the build held a resource on every visit so far and holds
 * nothing to release on this one, or the other way round when @holds: it is
 * guarded if a scalar tells the two kinds of visit apart. Open its digest
 * with every candidate of the build: the hull of a candidate over the visits
 * so far is its range on the one kind of visit, its range on this visit on
 * the other.
 */
static int digest_open(struct bpf_frame_desc_build *b, const struct scratch *s, int k, bool holds)
{
	struct bpf_guard_digest *d = digest_get(b, k);
	int c;

	if (!d)
		return -ENOMEM;
	for (c = 0; c < BPF_REG_10 + b->nr_slots; c++) {
		const struct bpf_frame_desc_loc *loc = build_loc_nth(b, c);
		struct bpf_guard_cand *cand = &d->cand[c];

		if (loc->cand != CAND_SCALAR || !s->scalar[c]) {
			cand->alive = false;
			continue;
		}
		if (holds)
			cand_set(cand, &s->range[c], &loc->hull);
		else
			cand_set(cand, &loc->hull, &s->range[c]);
	}
	return 0;
}

/*
 * Guarded location @k of the build is visited again: this visit holds the
 * resource there, or nothing to release when @free.
 */
static void digest_visit(struct bpf_frame_desc_build *b, const struct scratch *s, int k, bool free)
{
	struct bpf_guard_digest *d = digest_find(b, k);
	int c;

	if (!d)
		return;
	for (c = 0; c < BPF_REG_10 + b->nr_slots; c++) {
		struct bpf_guard_cand *cand = &d->cand[c];

		if (!cand->alive)
			continue;
		if (!s->scalar[c]) {
			cand->alive = false;
			continue;
		}
		cand_add(cand, &s->range[c], free);
	}
}

/*
 * The test of candidate @c, if it separates the visits: below some bound on
 * every visit that holds the resource and at or above it on every visit
 * that does not, or the other way round; else a constant on the one kind of
 * visit that is never seen on the other. In 64 bits, or in the low 32 bits
 * where the program compared the scalar in 32 bits.
 */
static bool cand_guard(const struct bpf_guard_cand *c, struct bpf_frame_desc_guard *g)
{
	const struct bpf_guard_hull *h = &c->held, *f = &c->free;

	if (h->max < f->min) {
		g->op = BPF_FRAME_GUARD_LT;
		g->val = f->min;
	} else if (f->max < h->min) {
		g->op = BPF_FRAME_GUARD_GE;
		g->val = h->min;
	} else if (h->min == h->max && c->excl) {
		g->op = BPF_FRAME_GUARD_EQ;
		g->val = h->min;
	} else if (f->min == f->max && c->hexcl) {
		g->op = BPF_FRAME_GUARD_NE;
		g->val = f->min;
	} else if (h->max32 < f->min32) {
		g->op = BPF_FRAME_GUARD_LT | BPF_FRAME_GUARD_32;
		g->val = f->min32;
	} else if (f->max32 < h->min32) {
		g->op = BPF_FRAME_GUARD_GE | BPF_FRAME_GUARD_32;
		g->val = h->min32;
	} else if (h->min32 == h->max32 && c->excl32) {
		g->op = BPF_FRAME_GUARD_EQ | BPF_FRAME_GUARD_32;
		g->val = h->min32;
	} else if (f->min32 == f->max32 && c->hexcl32) {
		g->op = BPF_FRAME_GUARD_NE | BPF_FRAME_GUARD_32;
		g->val = f->min32;
	} else {
		return false;
	}
	return true;
}

/*
 * The guard of a location of @b from its digest @d, if a candidate survived:
 * a callee-saved register first, which the unwinder has for every frame, then
 * a stack slot, then R0-R5, which it has for the frame whose entry saved
 * them.
 */
static bool guard_decide(const struct bpf_frame_desc_build *b, const struct bpf_guard_digest *d,
			 const unsigned long *written, struct bpf_frame_desc_guard *g)
{
	int pass, c, from, to;

	for (pass = 0; pass < 3; pass++) {
		if (pass == 0) {
			from = BPF_REG_6;
			to = BPF_REG_10;
		} else if (pass == 1) {
			from = BPF_REG_10;
			to = BPF_REG_10 + b->nr_slots;
		} else if (b->regs_saved) {
			from = BPF_REG_0;
			to = BPF_REG_6;
		} else {
			break;
		}
		for (c = from; c < to; c++) {
			/* a slot a callee writes says nothing at a site inside the callee */
			if (c >= BPF_REG_10 && test_bit(c - BPF_REG_10, written))
				continue;
			if (!d->cand[c].alive || !cand_guard(&d->cand[c], g))
				continue;
			g->loc = c < BPF_REG_10 ? BPF_FRAME_LOC_REG : BPF_FRAME_LOC_STACK;
			g->off = c < BPF_REG_10 ? c : -(c - BPF_REG_10 + 1) * BPF_REG_SIZE;
			return true;
		}
	}
	return false;
}

/* Any chain, where a key is looked up for a frame whatever it is under, see mirror_key(). */
/*
 * How frames of @subprog under chain @node got the reference of origin
 * @origin that they do not own, if known: as noted under the node, or under
 * a prefix of its chain, whose visits run under the node as well, see
 * merge_prefix_builds(). Noted differently under two of them, it has no one
 * place.
 */
static const struct bpf_arrival *arrival_lookup(struct bpf_verifier_env *env, u32 subprog,
						u32 origin, u32 node)
{
	static const struct bpf_arrival none = { .how = ARRIVE_NONE };
	const struct bpf_arrival *found = NULL;
	u32 i;

	for (i = 0; i < env->arrival_cnt; i++) {
		const struct bpf_arrival *a = &env->arrivals[i];

		if (a->origin != origin || a->subprog != subprog ||
		    (a->node != node && !chain_is_prefix(env, a->node, node)))
			continue;
		if (a->how == ARRIVE_NONE)
			return a;
		if (found && (found->how != a->how || found->at != a->at || found->res != a->res))
			return &none;
		found = a;
	}
	return found;
}

/*
 * Frames of @subprog under chain @node get the reference of origin @origin
 * @how, @at a register of the entry or a load insn, as a reference of class
 * @res; got it in two ways under the chain, it has no one place.
 */
static int arrival_add(struct bpf_verifier_env *env, u32 subprog, u32 origin, u32 node, u8 how,
		       u32 at, u16 res)
{
	struct bpf_arrival *a;
	u32 i, cnt = env->arrival_cnt;

	for (i = 0; i < cnt; i++) {
		a = &env->arrivals[i];
		if (a->origin != origin || a->subprog != subprog || a->node != node)
			continue;
		if (a->how != how || a->at != at || a->res != res)
			a->how = ARRIVE_NONE;
		return 0;
	}
	a = kvrealloc(env->arrivals, array_size(cnt + 1, sizeof(*a)), GFP_KERNEL_ACCOUNT);
	if (!a)
		return -ENOMEM;
	a[cnt] = (struct bpf_arrival) { .origin = origin, .node = node, .subprog = subprog,
					.how = how, .at = at, .res = res };
	env->arrivals = a;
	env->arrival_cnt = cnt + 1;
	return 0;
}

/*
 * Where frames of @subprog under chain @node obtain the reference of origin
 * @origin, which keys its mirror: the origin itself when the frame owns the
 * reference, see bpf_reference_state::origin, else how it arrived under the
 * chain and as what, since a register may carry an object and its lock at
 * once, which are released differently. Whether the frame owns it is noted
 * where the frame is described, not told from the origin: a frame of a
 * recursive subprog holds what another frame of the subprog owns by its
 * arrival, in a slot the owner's acquisition never writes.
 */
static void mirror_key(struct bpf_verifier_env *env, u32 subprog, u32 origin, u32 node, bool owned,
		       u8 *how, u32 *at, u16 *res)
{
	const struct bpf_arrival *a;

	*res = 0;
	if (owned) {
		*how = MIRROR_OWNED;
		*at = origin;
		return;
	}
	a = arrival_lookup(env, subprog, origin, node);
	if (!a || a->how == ARRIVE_NONE) {
		*how = MIRROR_NOWHERE;
		*at = origin;
	} else {
		*how = a->how == ARRIVE_REG ? MIRROR_ENTRY : MIRROR_LOAD;
		*at = a->at;
		*res = a->res;
	}
}

/* The mirror frames of @subprog write @how @at, of class @res where that tells them apart. */
static struct bpf_mirror *mirror_find(struct bpf_verifier_env *env, u32 subprog, u8 how, u32 at,
				      u16 res)
{
	u32 i;

	for (i = 0; i < env->mirror_cnt; i++) {
		const struct bpf_mirror *m = &env->mirrors[i];

		if (m->at == at && m->how == how && m->subprog == subprog &&
		    ((how != MIRROR_ENTRY && how != MIRROR_LOAD) || m->res == res))
			return &env->mirrors[i];
	}
	return NULL;
}

/* The mirror of the reference of origin @origin in frames of @subprog under chain @node, if recorded. */
static struct bpf_mirror *mirror_of(struct bpf_verifier_env *env, u32 subprog, u32 origin, u32 node,
				    bool owned)
{
	u8 how;
	u32 at;
	u16 res;

	mirror_key(env, subprog, origin, node, owned, &how, &at, &res);
	return mirror_find(env, subprog, how, at, res);
}

static struct bpf_mirror *mirror_get(struct bpf_verifier_env *env, u32 subprog, u8 how, u32 at,
				     u16 res)
{
	struct bpf_mirror *m = mirror_find(env, subprog, how, at, res);
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
	m->how = how;
	m->at = at;
	m->res = res;
	m->subprog = subprog;
	return m;
}

/*
 * The resource of origin @origin has to be released from its mirror at some
 * site of @subprog under chain @node.
 */
static int mirror_need(struct bpf_verifier_env *env, u32 subprog, u32 origin, u32 node, bool owned)
{
	struct bpf_mirror *m;
	u8 how;
	u32 at;
	u16 res;

	mirror_key(env, subprog, origin, node, owned, &how, &at, &res);
	m = mirror_get(env, subprog, how, at, res);
	if (!m)
		return -ENOMEM;
	if (!m->needed)
		env->mirrors_needed++;
	m->needed = true;
	return 0;
}

/* The class of @ref as @reg carries it, -ENOENT when it does not. */
static int ref_class_in_reg(struct bpf_verifier_env *env, struct bpf_verifier_state *st,
			    const struct bpf_reg_state *reg, const struct bpf_reference_state *ref)
{
	int objframe, spi;

	if (ref->type & REF_TYPE_LOCK_MASK)
		return reg_is_lock(reg, ref) ? resource_of_lock(env, reg, lock_kind(ref->type)) :
					       -ENOENT;
	if (stack_object_find(st, ref, &objframe, &spi))
		return reg_points_at(reg, objframe, spi) ?
		       resource_of_object(env, bpf_stack_slot(st->frame[objframe], spi)) : -ENOENT;
	if (ref->type != REF_TYPE_PTR || !reg_is_ref(reg, ref->id))
		return -ENOENT;
	return __resource_of_reg(env, reg, false);
}

/*
 * The classes of the references @reg carries, for a register that frames
 * obtain references in: an object, its lock, the flags it points at. Returns
 * how many, -1 for NULL, -2 for anything else, see cell_merge().
 */
static int reg_classes(struct bpf_verifier_env *env, struct bpf_verifier_state *st,
		       const struct bpf_reg_state *reg, u16 *res)
{
	int i, k, n = 0, ret;

	if (reg->type == SCALAR_VALUE)
		return bpf_register_is_null((struct bpf_reg_state *)reg) ? -1 : -2;
	for (i = 0; i < st->acquired_refs; i++) {
		ret = ref_class_in_reg(env, st, reg, &st->refs[i]);
		if (ret == -ENOENT)
			continue;
		if (ret < 0)
			return -2;
		for (k = 0; k < n && res[k] != ret; k++)
			;
		if (k < n)
			continue;
		if (n == BPF_CELL_CLASSES)
			return -2;
		res[n++] = ret;
	}
	return n ?: -2;
}

/*
 * Merge what a register holds on one visit, the @n classes in @res, into
 * what it holds on every visit: the classes it holds on all of them, as NULL
 * takes nothing away and anything else takes everything.
 */
static void cell_merge(struct bpf_cell *c, int n, const u16 *res)
{
	int i, k, kept = 0;

	if (c->state == CELL_OTHER || n == -2) {
		c->state = CELL_OTHER;
		c->nres = 0;
		return;
	}
	if (n == -1) {
		if (c->state == CELL_UNSEEN)
			c->state = CELL_NULL;
		return;
	}
	if (c->state != CELL_RES) {
		c->state = CELL_RES;
		c->nres = n;
		memcpy(c->res, res, n * sizeof(*res));
		return;
	}
	for (i = 0; i < c->nres; i++) {
		for (k = 0; k < n; k++) {
			if (res[k] != c->res[i])
				continue;
			c->res[kept++] = c->res[i];
			break;
		}
	}
	c->nres = kept;
	if (!kept)
		c->state = CELL_OTHER;
}

/* Does the register hold a reference of class @res, or NULL, on every visit? */
static bool cell_has(const struct bpf_cell *c, u16 res)
{
	int i;

	if (c->state != CELL_RES)
		return false;
	for (i = 0; i < c->nres; i++)
		if (c->res[i] == res)
			return true;
	return false;
}

/* The cells of a place for chain @node, added when @create. */
static struct bpf_cell_set *cells_get(struct bpf_cells *cells, u32 node, bool create)
{
	struct bpf_cell_set *sets;
	u32 i;

	for (i = 0; i < cells->cnt; i++)
		if (cells->sets[i].node == node)
			return &cells->sets[i];
	if (!create)
		return NULL;
	sets = kvrealloc(cells->sets, array_size(cells->cnt + 1, sizeof(*sets)), GFP_KERNEL_ACCOUNT);
	if (!sets)
		return NULL;
	memset(&sets[cells->cnt], 0, sizeof(*sets));
	sets[cells->cnt].node = node;
	cells->sets = sets;
	return &sets[cells->cnt++];
}

/* The store of mirror @m at @point of insn @insn, if recorded. */
static struct bpf_mirror_store *mirror_store_find(const struct bpf_mirror *m, u32 insn, u8 point)
{
	u32 i;

	for (i = 0; i < m->nr_stores; i++)
		if (m->stores[i].insn == insn && m->stores[i].point == point)
			return &m->stores[i];
	return NULL;
}

/* Add a store of mirror @m: at @insn, @point, from @reg, which points @adj bytes into the object. */
static int mirror_store_add(struct bpf_mirror *m, u32 insn, u8 point, u8 reg, s16 off, s16 adj)
{
	struct bpf_mirror_store *st;

	if (mirror_store_find(m, insn, point))
		return 0;
	st = kvrealloc(m->stores, array_size(m->nr_stores + 1, sizeof(*st)), GFP_KERNEL_ACCOUNT);
	if (!st)
		return -ENOMEM;
	st[m->nr_stores++] = (struct bpf_mirror_store) { .insn = insn, .point = point, .reg = reg,
							 .off = off, .adj = adj };
	m->stores = st;
	return 0;
}

/*
 * Note that the frame of build @b lists the resource of origin @origin at the
 * site, at location @loc of the lattice, or at none when it is mirrored,
 * under chain @node.
 */
static int build_add_listing(struct bpf_frame_desc_build *b, u32 origin, s16 loc, u32 node,
			     bool owned)
{
	struct bpf_frame_desc_listing *l;
	int i;

	for (i = 0; i < b->nr_listed; i++)
		if (b->listed[i].origin == origin && b->listed[i].loc == loc &&
		    b->listed[i].node == node && b->listed[i].owned == owned)
			return 0;
	l = kvrealloc(b->listed, array_size(b->nr_listed + 1, sizeof(*l)), GFP_KERNEL_ACCOUNT);
	if (!l)
		return -ENOMEM;
	l[b->nr_listed++] = (struct bpf_frame_desc_listing) { .origin = origin, .loc = loc,
							      .node = node, .owned = owned };
	b->listed = l;
	return 0;
}

/*
 * Choose where the reference is released from, given its @nr candidate
 * locations on this path and what earlier paths put into the descriptor. A
 * location an earlier path already lists for its class must be reused, so
 * that the reference is never listed twice on a path: whichever reference of
 * the class is there is released the same way; otherwise prefer a location no
 * earlier path has put a resource or a copy into, by rank; failing that, one
 * that held nothing to release on the earlier paths, which lists the
 * reference if a scalar guards it, see guarded(). Fails when earlier paths
 * list the class at two candidates (-EEXIST), list another class or a stack
 * object at one (-EINVAL), or when no candidate is free (-ENOENT).
 */
static int choose(struct bpf_verifier_env *env, struct scratch *s, int nr)
{
	int i, chosen = -1, free = -1, free_rank = INT_MAX, other = -1, other_rank = INT_MAX;

	for (i = 0; i < nr; i++) {
		const struct cand *c = &s->cands[i];
		struct bpf_frame_desc_loc *loc = build_loc(s->build, c);
		int rank = cand_rank(c, loc, s->build->regs_saved);

		if (loc->state == LOC_RES || loc->state == LOC_GUARD) {
			if (loc->res != c->res || loc->indirect != c->indirect)
				return -EINVAL;
			if (chosen >= 0)
				return -EEXIST;
			chosen = i;
		} else if (loc->state == LOC_UNSEEN || loc->state == LOC_NULL) {
			if (rank < free_rank) {
				free = i;
				free_rank = rank;
			}
		} else if (loc->state == LOC_OTHER && !loc->withdrawn && rank < other_rank) {
			other = i;
			other_rank = rank;
		}
	}
	if (chosen >= 0)
		return chosen;
	if (free >= 0)
		return free;
	return other >= 0 ? other : -ENOENT;
}

/*
 * No location lists the reference of origin @origin on every path reaching
 * the site: the paths disagree on where it is, @why. The reference is
 * released from its mirror instead.
 */
static int conflict(struct bpf_verifier_env *env, struct scratch *s, u32 origin, bool owned,
		    const char *why)
{
	env->frame_desc_conflicts++;
	if (env->log.level & BPF_LOG_LEVEL2)
		verbose(env, "frame_desc: insn %d: the reference obtained at insn %d %s: mirrored\n",
			s->pc, origin, why);
	return mirror_need(env, s->subprog, origin, s->node, owned);
}

/* Replace the section entry of kind @kind of @b by the counter entry, or add it. */
static int build_section_counter(struct bpf_frame_desc_build *b, u8 kind, u16 res, s16 off)
{
	struct bpf_frame_desc_entry ent = { .loc = BPF_FRAME_LOC_STACK, .flags = BPF_FRAME_ENT_COUNTER,
					    .res = res, .off = off, .order = ORDER_SECTION };
	struct bpf_frame_desc_fixed fixed = { .ent = ent, .origin = ACQ_NONE };
	struct bpf_frame_desc_fixed *list;
	int k;

	for (k = 0; k < b->nr_fixed; k++) {
		if (b->fixed[k].origin == ACQ_NONE && b->fixed[k].ent.res == res) {
			b->fixed[k].ent = ent;
			return 0;
		}
	}
	list = kvrealloc(b->fixed, array_size(b->nr_fixed + 1, sizeof(*list)), GFP_KERNEL_ACCOUNT);
	if (!list)
		return -ENOMEM;
	list[b->nr_fixed++] = fixed;
	b->fixed = list;
	return 0;
}

/*
 * Location @k holds the resource on some paths and nothing to release on
 * others: it @holds it on this path and did not on the earlier ones, or the
 * other way round. The location is guarded by a scalar that tells the paths
 * apart, if one is found once the pass is over, see guards_resolve(), and
 * withdrawn otherwise, when what is listed there goes to its mirror. The
 * reference listed is this path's when the location holds it now.
 */
static int guarded(struct bpf_verifier_env *env, struct scratch *s, int k, bool holds, u16 res,
		 u32 origin, bool owned, bool indirect)
{
	struct bpf_frame_desc_loc *loc = build_loc_nth(s->build, k);
	int ret;

	if (loc->state == LOC_GUARD) {
		digest_visit(s->build, s, k, !holds);
		return 0;
	}
	ret = digest_open(s->build, s, k, holds);
	if (ret)
		return ret;
	env->frame_desc_conflicts++;
	if (env->log.level & BPF_LOG_LEVEL2)
		verbose(env, "frame_desc: insn %d: the reference obtained at insn %d is held on some paths and not on others: guarded if a scalar tells\n",
			s->pc, holds ? origin : loc->origin);
	if (holds) {
		loc->res = res;
		loc->origin = origin;
		loc->owned = owned;
		loc->indirect = indirect;
	}
	loc->state = LOC_GUARD;
	return 0;
}

/*
 * Merge one path's classification of location @k into the descriptor. A
 * listing that is withdrawn takes every reference listed there with it: they
 * are mirrored once the pass is over, see bpf_frame_desc_resolve(). A
 * location that holds the resource on this path and nothing to release on
 * another, or the other way round, is guarded, see guarded().
 */
static int merge(struct bpf_verifier_env *env, struct scratch *s, int k, int class, u16 res,
		 u32 origin, bool owned, bool indirect)
{
	struct bpf_frame_desc_loc *loc = build_loc_nth(s->build, k);
	int ret;

	switch (loc->state) {
	case LOC_UNSEEN:
	case LOC_NULL:
		switch (class) {
		case CLASS_RES:
			loc->nullable = loc->state == LOC_NULL;
			loc->state = LOC_RES;
			loc->res = res;
			loc->origin = origin;
			loc->owned = owned;
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
	case LOC_GUARD:
		switch (class) {
		case CLASS_RES:
			/* choose() reuses a listed location only for the same class. */
			if (loc->res == res && loc->indirect == indirect) {
				if (loc->state == LOC_GUARD)
					digest_visit(s->build, s, k, false);
				return 0;
			}
			withdraw(loc);
			return conflict(env, s, origin, owned,
					"shares a location with another kind of resource");
		case CLASS_NULL:
			/* A stack object in place is never NULL: it is not there on this path. */
			if (!loc->indirect)
				return guarded(env, s, k, false, 0, 0, false, false);
			loc->nullable = 1;
			return 0;
		case CLASS_COPY:
			/* Another resource's copy on this path: the listing is withdrawn. */
			ret = conflict(env, s, loc->origin, loc->owned,
				       "is at different locations on different paths");
			if (ret)
				return ret;
			withdraw(loc);
			return conflict(env, s, origin, owned, "shares a location with another resource");
		default:
			/* Nothing to release here on this path: guarded, if a scalar tells. */
			return guarded(env, s, k, false, 0, 0, false, false);
		}
	default:
		if (class != CLASS_RES)
			return 0;
		/* choose() lists a location an earlier path used otherwise as a guarded one only. */
		if (loc->state == LOC_OTHER && !loc->withdrawn)
			return guarded(env, s, k, true, res, origin, owned, indirect);
		return conflict(env, s, origin, owned, "shares a location with another resource");
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

/*
 * The rank of an entry that is not among the locks and flags the frame
 * placed in acquisition order: a lock or flags of a frame below, which this
 * frame releases after its own, then RCU objects, then the rest.
 */
static s16 resource_order(const struct bpf_verifier_env *env, u16 res)
{
	u8 kind = env->resources[res].kind;

	if (kind == BPF_RESOURCE_SPIN_LOCK || kind == BPF_RESOURCE_RES_LOCK ||
	    kind == BPF_RESOURCE_RES_LOCK_IRQ || kind == BPF_RESOURCE_IRQ_FLAG ||
	    kind == BPF_RESOURCE_IRQ_FLAG_LOCK)
		return ORDER_BELOW;
	return env->resources[res].rcu ? ORDER_RCU_OBJ : ORDER_OBJ;
}

/* An entry with its guard while the entries are sorted, see build_body(). */
struct body_entry {
	struct bpf_frame_desc_entry ent;
	struct bpf_frame_desc_guard guard;
};

static int body_cmp(const void *a, const void *b)
{
	return entry_cmp(&((const struct body_entry *)a)->ent, &((const struct body_entry *)b)->ent);
}

/*
 * Lay out the entries of one descriptor into @ents, or count them: every
 * listed location of the frame, with its guard where it has one, the locks,
 * IRQ flags and sections it holds, and the mirrors it lists. Returns how
 * many, and in @nguards how many are guarded.
 */
static u32 build_body(const struct bpf_verifier_env *env, const struct bpf_frame_desc_build *b,
		      struct body_entry *ents, u32 *nguards)
{
	u32 n = 0, ng = 0, i;

	for (i = 0; i < BPF_REG_10 + b->nr_slots; i++) {
		const struct bpf_frame_desc_loc *loc = i < BPF_REG_10 ? &b->regs[i] :
								     &b->slots[i - BPF_REG_10];
		struct bpf_frame_desc_entry *ent;

		if (loc->state != LOC_RES && loc->state != LOC_GUARD)
			continue;
		ng += loc->state == LOC_GUARD;
		if (!ents) {
			n++;
			continue;
		}
		ent = &ents[n].ent;
		ent->loc = i < BPF_REG_10 ? BPF_FRAME_LOC_REG : BPF_FRAME_LOC_STACK;
		ent->off = i < BPF_REG_10 ? i : -(i - BPF_REG_10 + 1) * BPF_REG_SIZE;
		ent->flags = (loc->indirect ? BPF_FRAME_ENT_INDIRECT : 0) |
			     (loc->nullable ? BPF_FRAME_ENT_NULLABLE : 0) |
			     (loc->state == LOC_GUARD ? BPF_FRAME_ENT_GUARDED : 0);
		ent->res = loc->res;
		ent->order = resource_order(env, loc->res);
		if (loc->state == LOC_GUARD)
			ents[n].guard = loc->guard;
		n++;
	}
	if (ents) {
		for (i = 0; i < b->nr_fixed; i++)
			ents[n++].ent = b->fixed[i].ent;
		for (i = 0; i < b->nr_extra; i++)
			ents[n++].ent = b->extra[i];
		sort(ents, n, sizeof(ents[0]), body_cmp, NULL);
	} else {
		n += b->nr_fixed + b->nr_extra;
	}
	*nguards = ng;
	return n;
}

/* The size of a descriptor of @n entries, @ng of them guarded: the guards follow the entries. */
static u32 desc_size(u32 n, u32 ng)
{
	u32 size = struct_size_t(struct bpf_frame_desc, ent, n);

	if (ng)
		size = ALIGN(size, __alignof__(struct bpf_frame_desc_guard)) +
		       ng * sizeof(struct bpf_frame_desc_guard);
	return size;
}

/* Add the descriptor of @b to the pool, sharing an identical earlier one. */
static int pool_add(struct bpf_verifier_env *env, const struct bpf_frame_desc_build *b)
{
	struct bpf_frame_desc_pool *pool = env->frame_desc_pool;
	struct bpf_frame_desc_guard *guards;
	struct bpf_frame_desc *d;
	struct body_entry *ents;
	u32 i, k, ng, n = build_body(env, b, NULL, &ng);

	ents = kvcalloc(n, sizeof(*ents), GFP_KERNEL_ACCOUNT);
	d = kvzalloc(desc_size(n, ng), GFP_KERNEL_ACCOUNT);
	if (!ents || !d) {
		kvfree(ents);
		kvfree(d);
		return -ENOMEM;
	}
	build_body(env, b, ents, &ng);
	d->nent = n;
	d->nguards = ng;
	d->size = desc_size(n, ng);
	guards = (struct bpf_frame_desc_guard *)bpf_frame_desc_guards(d);
	for (i = 0, k = 0; i < n; i++) {
		d->ent[i] = ents[i].ent;
		if (ents[i].ent.flags & BPF_FRAME_ENT_GUARDED)
			guards[k++] = ents[i].guard;
	}
	kvfree(ents);
	env->frame_desc_guards += ng;
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
 * direct or through a function pointer, or the probed access of an arena site.
 */
static bool site_insn_ok(const struct bpf_insn *insn)
{
	u8 class = BPF_CLASS(insn->code), mode = BPF_MODE(insn->code);

	if (insn->code == (BPF_JMP | BPF_CALL) || bpf_is_callx(insn))
		return true;
	if (class == BPF_LDX)
		return mode == BPF_PROBE_MEM32 || mode == BPF_PROBE_MEM32SX;
	if (class == BPF_STX)
		return mode == BPF_PROBE_MEM32 || mode == BPF_PROBE_ATOMIC;
	return class == BPF_ST && mode == BPF_PROBE_MEM32;
}

/*
 * The node of the program's trie for chain @node of the pass, interning it
 * and its ancestors: a node names the site of its call, by the subprog and
 * the first entry of the site in the subprog's table, which @site_of gives
 * for the orig insn of the call.
 */
static int pool_intern_chain(struct bpf_verifier_env *env, const u32 *site_of, u32 node)
{
	struct bpf_frame_desc_pool *pool = env->frame_desc_pool;
	struct bpf_chain *c = &env->chains[node];
	struct bpf_chain_node *nodes;
	int parent;

	if (!node)
		return 0;
	if (c->pool != ~0U)
		return c->pool;
	parent = pool_intern_chain(env, site_of, c->parent);
	if (parent < 0)
		return parent;
	if (verifier_bug_if(c->pc >= env->frame_desc_orig_len || !site_of[2 * c->pc + 1], env,
			    "chain through insn %d, which is not a site", c->pc))
		return -EFAULT;
	nodes = kvrealloc(pool->nodes, array_size(pool->node_cnt + 1, sizeof(*nodes)),
			  GFP_KERNEL_ACCOUNT);
	if (!nodes)
		return -ENOMEM;
	pool->nodes = nodes;
	nodes[pool->node_cnt] = (struct bpf_chain_node) {
		.parent = parent, .subprog = site_of[2 * c->pc], .site = site_of[2 * c->pc + 1] - 1,
	};
	c->pool = pool->node_cnt++;
	env->frame_desc_bytes += sizeof(*nodes);
	return c->pool;
}

static int site_cmp(const void *a, const void *b)
{
	const struct bpf_frame_desc_site *x = a, *y = b;

	if (x->off != y->off)
		return x->off < y->off ? -1 : 1;
	return x->node < y->node ? -1 : x->node > y->node;
}

/*
 * Build the trie of the chains the tables tell the descriptors of a site
 * apart by, with the root, and key the entries by its nodes, sorted by site
 * and node.
 */
static int pool_build_chains(struct bpf_verifier_env *env, const u32 *site_of)
{
	struct bpf_frame_desc_pool *pool = env->frame_desc_pool;
	int s, ret;
	u32 i;

	pool->nodes = kvzalloc(sizeof(*pool->nodes), GFP_KERNEL_ACCOUNT);
	if (!pool->nodes)
		return -ENOMEM;
	pool->node_cnt = 1;
	env->frame_desc_bytes += sizeof(*pool->nodes);
	for (s = 0; s < env->subprog_cnt; s++) {
		struct bpf_frame_desc_table *tab = env->subprog_info[s].frame_desc_table;

		if (!tab)
			continue;
		for (i = 0; i < tab->cnt; i++) {
			ret = pool_intern_chain(env, site_of, tab->site[i].node);
			if (ret < 0)
				return ret;
			tab->site[i].node = ret;
		}
		sort(tab->site, tab->cnt, sizeof(tab->site[0]), site_cmp, NULL);
	}
	env->chain_nodes = pool->node_cnt - 1;
	return 0;
}

/*
 * After all instruction rewrites, turn the descriptors attached to instructions
 * into the per subprogram tables the unwinder uses, keyed by instruction index
 * until the JIT fills in native offsets, and by the chain where an insn has a
 * descriptor per chain. Identical descriptors share a body.
 */
int bpf_frame_desc_build_tables(struct bpf_verifier_env *env)
{
	struct bpf_insn_aux_data *aux = env->insn_aux_data;
	struct bpf_frame_desc_pool *pool;
	u32 *site_of;	/* of an orig insn: subprog and first entry, see pool_intern_chain() */
	int i, s, ret;

	if (!env->frame_desc_visits)
		return 0;
	pool = kvzalloc(struct_size(pool, desc, 0), GFP_KERNEL_ACCOUNT);
	site_of = kvcalloc(2 * env->frame_desc_orig_len, sizeof(*site_of), GFP_KERNEL_ACCOUNT);
	if (!pool || !site_of) {
		kvfree(pool);
		kvfree(site_of);
		return -ENOMEM;
	}
	env->frame_desc_pool = pool;
	for (s = 0; s < env->subprog_cnt; s++) {
		u32 start = env->subprog_info[s].start, end = env->subprog_info[s + 1].start;
		struct bpf_frame_desc_table *tab;
		struct bpf_frame_desc_build *b;
		u32 cnt = 0;

		for (i = start; i < end; i++)
			for (b = aux[i].frame_desc; b; b = b->next)
				cnt++;
		if (!cnt)
			continue;
		tab = kvzalloc(struct_size(tab, site, cnt), GFP_KERNEL_ACCOUNT);
		if (!tab) {
			ret = -ENOMEM;
			goto out;
		}
		env->subprog_info[s].frame_desc_table = tab;
		env->frame_desc_bytes += struct_size(tab, site, cnt);
		for (i = start; i < end; i++) {
			b = aux[i].frame_desc;
			if (!b)
				continue;
			if (verifier_bug_if(!site_insn_ok(&env->prog->insnsi[i]), env,
					    "frame descriptor at insn %d is not at a site", i)) {
				ret = -EFAULT;
				goto out;
			}
			/* where the calls the pass named by insn ended up: the chains name them */
			if (b->callsite) {
				site_of[2 * b->pc] = s;
				site_of[2 * b->pc + 1] = tab->cnt + 1;
			}
			env->chain_split_sites += !!b->next;
			for (; b; b = b->next) {
				ret = pool_add(env, b);
				if (ret < 0)
					goto out;
				/* one build is for any chain: nothing to tell it from */
				tab->site[tab->cnt++] = (struct bpf_frame_desc_site) {
					.off = i - start, .desc = ret,
					.node = aux[i].frame_desc->next ? b->node : 0,
				};
				env->frame_desc_sites++;
			}
		}
	}
	ret = pool_build_chains(env, site_of);
	if (ret)
		goto out;
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
	ret = 0;
out:
	kvfree(site_of);
	return ret;
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

/* Append a lock, IRQ flag or section entry of the frame on this path. */
static int fixed_add(struct bpf_verifier_env *env, struct scratch *s,
		     struct bpf_frame_desc_entry ent, u32 origin, bool owned)
{
	if (s->nr_fixed >= MAX_FIXED) {
		verbose(env, "frame_desc: frame%d holds too many locks and sections\n",
			env->cur_state->curframe);
		return -E2BIG;
	}
	s->fixed[s->nr_fixed++] = (struct bpf_frame_desc_fixed) { .ent = ent, .origin = origin,
								   .node = s->node, .owned = owned };
	return 0;
}

/* The entry an earlier path placed for the lock or IRQ flags of origin @origin, or NULL. */
static struct bpf_frame_desc_fixed *fixed_prev(struct bpf_frame_desc_build *b, u32 origin)
{
	int i;

	for (i = 0; i < b->nr_fixed; i++)
		if (b->fixed[i].origin == origin)
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
 * The lock or IRQ flags of origin @origin have no location on this path, or
 * none the earlier paths agree on: they are released from the mirror. Place
 * an entry of rank @order for it, which the mirror replaces once reserved,
 * see build_mirror(); what an earlier path placed stays until then.
 */
static int fixed_mirror(struct bpf_verifier_env *env, struct scratch *s, u32 origin, bool owned,
			s16 order)
{
	struct bpf_frame_desc_entry ent = { .order = order, .loc = BPF_FRAME_LOC_STACK,
					    .flags = BPF_FRAME_ENT_INDIRECT | BPF_FRAME_ENT_NULLABLE };
	int ret;

	ret = mirror_need(env, s->subprog, origin, s->node, owned);
	return ret ?: fixed_add(env, s, ent, origin, owned);
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
 * Returns 1 for a lock of a frame below that this frame holds nowhere: it is
 * not this frame's to place, the owner places it at its call, or a holder
 * that releases it does.
 */
static int place_lock(struct bpf_verifier_env *env, struct scratch *s,
		      const struct bpf_reference_state *ref, s16 order)
{
	struct bpf_func_state *frame = env->cur_state->frame[env->cur_state->curframe];
	struct bpf_frame_desc_entry ent = { .order = order, .flags = BPF_FRAME_ENT_INDIRECT };
	bool owned = ref->frameno == env->cur_state->curframe;
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
		return fixed_add(env, s, ent, ref->origin, owned);
	}
	nr = find_lock_cands(env, s, frame, ref);
	if (nr < 0)
		return nr;
	if (!nr && !owned)
		return 1;
	prev = fixed_prev(s->build, ref->origin);
	for (k = 0; prev && k < nr; k++) {
		if (cand_is(&s->cands[k], &prev->ent)) {
			chosen = k;
			break;
		}
	}
	for (k = 0; chosen < 0 && k < nr; k++) {
		int rank;

		c = &s->cands[k];
		/* at a call a register, which a callee cannot write, see cand_rank() */
		if (!s->build->regs_saved)
			rank = c->is_slot;
		else
			rank = c->is_slot ? 0 : c->idx >= BPF_REG_6 ? 1 : 2;
		if (rank < best) {
			best = rank;
			chosen = k;
		}
	}
	/* no location on this path, or another one: the mirror, in place of whatever is listed */
	if (chosen < 0)
		return fixed_mirror(env, s, ref->origin, owned, order);
	c = &s->cands[chosen];
	ent.loc = c->is_slot ? BPF_FRAME_LOC_STACK : BPF_FRAME_LOC_REG;
	ent.off = c->is_slot ? -(c->idx + 1) * BPF_REG_SIZE : c->idx;
	ent.res = c->res;
	return fixed_add(env, s, ent, ref->origin, owned);
}

/*
 * Place saved IRQ flags of rank @order: the stack slot they live in, in
 * place when it is this frame's, through a live pointer to it otherwise,
 * like any stack object. An earlier path's choice must be reused. Returns 1
 * for the flags of a frame below that this frame holds nowhere, or that a
 * caller which is not in the state saved: not this frame's to place, like a
 * lock, see place_lock().
 */
static int place_irq(struct bpf_verifier_env *env, struct scratch *s,
		     const struct bpf_reference_state *ref, s16 order)
{
	struct bpf_verifier_state *st = env->cur_state;
	struct bpf_frame_desc_entry ent = { .order = order };
	bool owned = ref->frameno == st->curframe;
	const struct bpf_frame_desc_fixed *prev;
	const struct cand *c;
	int objframe, spi, k, nr, chosen = -1;

	if (!stack_object_find(st, ref, &objframe, &spi)) {
		if (!owned)
			return 1;
		verifier_bug(env, "no stack slot holds the irq flags saved at insn %d",
			     ref->insn_idx);
		return -EFAULT;
	}
	nr = find_object_cands(env, s, st, objframe, spi, true);
	if (nr < 0)
		return nr;
	if (!nr && !owned)
		return 1;
	prev = fixed_prev(s->build, ref->origin);
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
		return fixed_mirror(env, s, ref->origin, owned, order);
	c = &s->cands[chosen];
	ent.loc = c->is_slot ? BPF_FRAME_LOC_STACK : BPF_FRAME_LOC_REG;
	ent.off = c->is_slot ? -(c->idx + 1) * BPF_REG_SIZE : c->idx;
	ent.flags = c->indirect ? BPF_FRAME_ENT_INDIRECT : 0;
	ent.res = c->res;
	return fixed_add(env, s, ent, ref->origin, owned);
}

/*
 * The RCU read or preemption disabled sections the current frame entered and
 * has not left, less those of its callers it has left, itself or through a
 * callee: the net count the frame's entry adds up to, which the unwinder
 * sums over the frames. The verifier keeps per frame how much of what was
 * held at its entry is held ever since, and how much of it went, see
 * release_context_state(): what the state holds now on top of the former is
 * this frame's own.
 */
static s32 frame_sections(const struct bpf_verifier_state *st, bool rcu)
{
	const struct bpf_func_state *frame = st->frame[st->curframe];

	if (rcu)
		return (s32)(st->active_rcu_locks - frame->entry_rcu_locks) -
		       (s32)frame->rcu_released_below;
	return (s32)(st->active_preempt_locks - frame->entry_preempt_locks) -
	       (s32)frame->preempt_released_below;
}

/* Sections have no location; the frame that entered them leaves them, @count net. */
static int place_section(struct bpf_verifier_env *env, struct scratch *s, u8 kind, s32 count)
{
	struct bpf_frame_desc_entry ent = { .order = ORDER_SECTION, .loc = BPF_FRAME_LOC_NONE };
	struct bpf_resource res;
	int ret;

	if (!count)
		return 0;
	if (count > S16_MAX || count < S16_MIN) {
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
	return fixed_add(env, s, ent, ACQ_NONE, false);
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
 * The paths reaching the site disagree on how many sections of kind @res the
 * frame has to leave: the subprog counts them at run time, in a hidden slot
 * that each of its calls entering or leaving a section adjusts.
 */
static void section_disagree(struct bpf_verifier_env *env, struct scratch *s, u16 res)
{
	u8 kind = env->resources[res].kind == BPF_RESOURCE_RCU ? 0 : 1;

	env->subprog_info[s->subprog].section_counter |= BIT(kind);
}

/*
 * Merge the locks, IRQ flags and sections this path places, in acquisition
 * order, into the list of the descriptor. A lock or flags an earlier path
 * placed elsewhere, or did not place, or that this path does not place, is
 * released from its mirror, which is NULL where it is not held; the list
 * keeps the entry and its place in the order. Locks need no order among
 * themselves, as unlocking never blocks, and neither do IRQ flags: of the
 * flags a frame saved, those saved with interrupts enabled, one set at most,
 * are restored last, whatever the order the paths saved them in, see
 * bpf_unwind_frame(); the flags of an irqsave lock are placed right after
 * the lock on every path. The sections of the frame have no location to
 * mirror: where the paths disagree on their count, the subprog counts them
 * in a hidden slot, see section_disagree().
 */
static int fixed_merge(struct bpf_verifier_env *env, struct scratch *s)
{
	struct bpf_frame_desc_build *b = s->build;
	int i, k, last = -1, order = 0, ret;

	for (k = 0; k < b->nr_fixed; k++)
		b->fixed[k].seen = false;
	for (i = 0; i < s->nr_fixed; i++) {
		const struct bpf_frame_desc_fixed *e = &s->fixed[i];

		if (e->origin == ACQ_NONE) {
			for (k = 0; k < b->nr_fixed; k++)
				if (b->fixed[k].origin == ACQ_NONE && b->fixed[k].ent.res == e->ent.res)
					break;
			if (k == b->nr_fixed || b->fixed[k].ent.off != e->ent.off)
				section_disagree(env, s, e->ent.res);
			if (k < b->nr_fixed)
				b->fixed[k].seen = true;
			continue;
		}
		for (k = 0; k < b->nr_fixed; k++)
			if (b->fixed[k].origin == e->origin)
				break;
		if (k == b->nr_fixed) {
			/* not held on an earlier path: insert it after what precedes it here */
			ret = fixed_insert(b, last + 1, e);
			ret = ret ?: mirror_need(env, s->subprog, e->origin, s->node, e->owned);
			if (ret)
				return ret;
			k = last + 1;
		} else if (!fixed_same(&b->fixed[k], e)) {
			ret = mirror_need(env, s->subprog, e->origin, s->node, e->owned);
			if (ret)
				return ret;
		}
		b->fixed[k].seen = true;
		last = max(last, k);
	}
	for (k = 0; k < b->nr_fixed; k++) {
		if (b->fixed[k].seen)
			continue;
		if (b->fixed[k].origin == ACQ_NONE) {
			section_disagree(env, s, b->fixed[k].ent.res);
			continue;
		}
		ret = mirror_need(env, s->subprog, b->fixed[k].origin, b->fixed[k].node,
				  b->fixed[k].owned);
		if (ret)
			return ret;
	}
	/* the list is in acquisition order: rank it again */
	for (k = 0; k < b->nr_fixed; k++)
		if (b->fixed[k].origin != ACQ_NONE)
			b->fixed[k].ent.order = order++;
	return 0;
}

/*
 * Place the locks, IRQ flags and sections the frame holds on this path, for
 * itself or for a frame below. Unlike objects, these are released in order:
 * the verifier keeps locks and IRQ flags in acquisition order, and the frame
 * ranks them from 0, latest released first, with the flags of an irqsave
 * lock right before the lock, which restores them. And they cannot be merged
 * through NULL: every path reaching the site places the same entries, or
 * what differs is mirrored, see fixed_merge().
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

		if (ref->type & REF_TYPE_LOCK_MASK)
			ret = place_lock(env, s, ref, order);
		else if (ref->type == REF_TYPE_IRQ)
			ret = place_irq(env, s, ref, order);
		else
			continue;
		if (ret < 0)
			return ret;
		if (ret == 0)
			order++;
		/* not this frame's to place, unless it turns out to list it, see resolve_transfer() */
		ret = build_add_listing(b, ref->origin, ret ? LISTED_SKIPPED : LISTED_FIXED, s->node,
					ref->frameno == st->curframe);
		if (ret)
			return ret;
	}
	ret = place_section(env, s, BPF_RESOURCE_RCU, frame_sections(st, true));
	ret = ret ?: place_section(env, s, BPF_RESOURCE_PREEMPT, frame_sections(st, false));
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
	bool owned = ref->frameno == env->cur_state->curframe;
	const char *why;
	int k, chosen, ret;

	if (!nr)
		return conflict(env, s, ref->origin, owned, "is held at no live location") ?: -1;
	chosen = choose(env, s, nr);
	why = chosen == -ENOENT ? "has no location free to be released from" :
	      chosen == -EEXIST ? "is at different locations on different paths" :
	      chosen == -EINVAL ? "shares a location with another resource on another path" : NULL;
	if (why) {
		ret = conflict(env, s, ref->origin, owned, why);
		return ret ?: -1;
	}
	for (k = 0; k < nr; k++) {
		const struct cand *c = &s->cands[k];
		int idx = cand_idx(c);

		s->class[idx] = k == chosen ? CLASS_RES : CLASS_COPY;
		s->res[idx] = c->res;
		s->origin[idx] = ref->origin;
		s->owned[idx] = owned;
		s->indirect[idx] = c->indirect;
	}
	return cand_idx(&s->cands[chosen]);
}

/* Note that the call of build @b may enter subprog @callee. */
static int build_add_target(struct bpf_frame_desc_build *b, u16 callee)
{
	u16 *targets;
	int i;

	for (i = 0; i < b->nr_targets; i++)
		if (b->targets[i] == callee)
			return 0;
	targets = kvrealloc(b->targets, array_size(b->nr_targets + 1, sizeof(*targets)),
			    GFP_KERNEL_ACCOUNT);
	if (!targets)
		return -ENOMEM;
	targets[b->nr_targets++] = callee;
	b->targets = targets;
	return 0;
}

/* Does @reg hold the handle of @ref, or point at its stack object, in @st? */
static bool reg_has_ref(const struct bpf_verifier_state *st, const struct bpf_reg_state *reg,
			const struct bpf_reference_state *ref)
{
	int objframe, spi;

	if (ref->type & REF_TYPE_LOCK_MASK)
		return reg_is_lock(reg, ref);
	if (stack_object_find(st, ref, &objframe, &spi))
		return reg_points_at(reg, objframe, spi);
	return reg_is_ref(reg, ref->id);
}

/* Is @ref spilled in, or a stack object in, the stack of frame @frameno of @st? */
static bool frame_stack_has_ref(const struct bpf_verifier_state *st, int frameno,
				const struct bpf_reference_state *ref)
{
	const struct bpf_func_state *frame = st->frame[frameno];
	int objframe, spi, k;

	if (stack_object_find(st, ref, &objframe, &spi))
		return objframe == frameno;
	for (k = 0; k < bpf_stack_nr_slots(frame); k++) {
		const struct bpf_stack_state *slot = bpf_stack_slot(frame, k);

		if (bpf_is_spilled_reg(slot) && reg_has_ref(st, &slot->spilled_ptr, ref))
			return true;
	}
	return false;
}

/*
 * What location @l of frame @h of @st holds now, for what the frame lists
 * there in @b, the build of the call the frame waits in: the resource of one
 * of its listings, NULL, or nothing to release, which a resource a callback
 * released since is.
 */
static int feed_class(struct bpf_verifier_env *env, const struct bpf_verifier_state *st,
		      const struct bpf_frame_desc_build *b, const struct bpf_func_state *frame, int h,
		      int l)
{
	const struct bpf_stack_state *slot = NULL;
	const struct bpf_reg_state *reg = NULL;
	int i, j, spi = l - BPF_REG_10;

	if (l < BPF_REG_10)
		reg = &frame->regs[l];
	else if (spi < bpf_stack_nr_slots(frame))
		slot = bpf_stack_slot(frame, spi);
	else
		return CLASS_OTHER;
	for (i = 0; i < b->nr_listed; i++) {
		const struct bpf_frame_desc_listing *lst = &b->listed[i];

		if (lst->loc != l)
			continue;
		for (j = 0; j < st->acquired_refs; j++) {
			const struct bpf_reference_state *ref = &st->refs[j];

			if (ref->origin != lst->origin || (ref->frameno == h) != lst->owned)
				continue;
			if (reg ? reg_has_ref(st, reg, ref) :
			    stack_slot_is_object(slot, ref->id) ||
			    (bpf_is_spilled_reg(slot) && reg_has_ref(st, &slot->spilled_ptr, ref)))
				return CLASS_RES;
		}
	}
	if (reg ? bpf_register_is_null((struct bpf_reg_state *)reg) : stack_slot_is_null(slot))
		return CLASS_NULL;
	return CLASS_OTHER;
}

/*
 * The callback a helper runs, and the frames above it up to the helper call,
 * may release what the frame that called the helper holds: that frame lists
 * the resource at the call, guarded by a scalar the callback stores to in
 * the frame's stack, see bpf_frame_desc_record_release(). The guard has to
 * be right at every site inside the callback, not only when the callback
 * returns to the call: between the release and the store the two disagree.
 * So a site in a frame above a callback is a visit of the descriptor of the
 * helper call of the frame below the callback, for what that frame lists
 * there: whether each listed location holds its resource now, and the
 * scalars of the frame as they are now, which only its stack can change.
 */
static int guard_feed(struct bpf_verifier_env *env, struct bpf_verifier_state *st)
{
	struct scratch *s = env->frame_desc_scratch;
	struct bpf_frame_desc_build *b;
	int k, h, l, cls, ret;

	for (k = 1; k <= st->curframe; k++) {
		const struct bpf_func_state *frame;
		u32 callsite, node;

		if (!st->frame[k]->in_callback_fn)
			continue;
		h = k - 1;
		frame = st->frame[h];
		callsite = st->frame[k]->callsite;
		/* the frames know their chains: chain_of() walked them at the site */
		node = h ? frame->chain - 1 : 0;
		b = build_get(env, callsite, bpf_stack_nr_slots(frame), NULL, node);
		if (!b)
			return -ENOMEM;
		/* the call is visited before the callback runs; should it not be, nothing is guarded there */
		if (!b->visits) {
			b->fed_blind = true;
			continue;
		}
		s->build = b;
		s->pc = callsite;
		s->subprog = frame->subprogno;
		s->node = node;
		s->live_regs = env->insn_aux_data[callsite].live_regs_before & CALLEE_SAVED_REGS;
		s->live_stack = env->insn_aux_data[callsite].live_stack_before;
		scratch_ranges(s, frame);
		for (l = 0; l < BPF_REG_10 + b->nr_slots; l++) {
			struct bpf_frame_desc_loc *loc = build_loc_nth(b, l);

			if (loc->state != LOC_RES && loc->state != LOC_GUARD)
				continue;
			cls = feed_class(env, st, b, frame, h, l);
			if (cls == CLASS_RES) {
				if (loc->state == LOC_GUARD)
					digest_visit(b, s, l, false);
				continue;
			}
			if (cls == CLASS_NULL && loc->indirect) {
				loc->nullable = 1;
				continue;
			}
			ret = guarded(env, s, l, false, 0, 0, false, false);
			if (ret)
				return ret;
		}
		cells_update(b, s);
	}
	return 0;
}

/*
 * The site is a call of BPF code: note, for every reference listed, which
 * of R1-R5 pass it to the callee, and whether the callee can reach it through
 * the stack: as a stack argument, or spilled in, or a stack object in, a
 * frame that a stack pointer argument points into. The callee chain may
 * release what it is passed, and then lists it, see bpf_frame_desc_resolve().
 */
static void site_passed(struct bpf_verifier_env *env, struct bpf_verifier_state *st,
			struct bpf_frame_desc_build *b)
{
	const struct bpf_func_state *frame = st->frame[st->curframe];
	u32 stack_frames = 0;
	int k, i, l;

	for (k = BPF_REG_1; k <= BPF_REG_5; k++)
		if (frame->regs[k].type == PTR_TO_STACK)
			stack_frames |= BIT(frame->regs[k].frameno);
	for (i = 0; i < frame->out_stack_arg_cnt; i++)
		if (frame->stack_arg_regs[i].type == PTR_TO_STACK)
			stack_frames |= BIT(frame->stack_arg_regs[i].frameno);
	for (l = 0; l < b->nr_listed; l++) {
		struct bpf_frame_desc_listing *lst = &b->listed[l];

		for (i = 0; i < st->acquired_refs; i++) {
			const struct bpf_reference_state *ref = &st->refs[i];

			if (ref->origin != lst->origin)
				continue;
			for (k = BPF_REG_1; k <= BPF_REG_5; k++)
				if (reg_has_ref(st, &frame->regs[k], ref))
					lst->passed |= BIT(k - 1);
			for (k = 0; k < frame->out_stack_arg_cnt; k++)
				if (reg_has_ref(st, &frame->stack_arg_regs[k], ref))
					lst->passed |= PASSED_STACK;
			for (k = 0; k <= st->curframe; k++)
				if ((stack_frames & BIT(k)) && frame_stack_has_ref(st, k, ref))
					lst->passed |= PASSED_STACK;
		}
	}
}

/*
 * Record the state of the current frame at a site where the program may be
 * unwound, in the build of the insn for the chain the frame is under. @regs_saved
 * says that the entry the unwinder is reached through saves R0-R9 of the
 * frame; otherwise it waits in a call and only keeps R6-R9 and its stack. A
 * call of BPF code may enter @callee, which may release what it is passed.
 * Only live locations are considered, which keeps the descriptors consistent
 * with the joins of the verifier: two states it joins agree on every live
 * location, and so do a state and one it is within.
 */
static int site_do(struct bpf_verifier_env *env, bool regs_saved,
		   struct bpf_frame_desc_build **slot, int callee)
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
	ret = chain_of(env, st);
	if (ret < 0)
		return ret;
	s->node = ret;
	b = build_get(env, s->pc, bpf_stack_nr_slots(frame), slot, ret);
	if (!b)
		return -ENOMEM;
	b->regs_saved = regs_saved;
	s->build = b;
	scratch_ranges(s, frame);

	/*
	 * Several references of one origin, which a loop the verifier unrolled
	 * acquired at one insn, need a slot each in the mirror of the origin:
	 * note how many, should a site need the mirror, see mirror_resource().
	 */
	for (i = 0; i < st->acquired_refs; i++)
		note_held(env, st, st->refs[i].origin);

	ret = place_fixed(env, s);
	if (ret)
		return ret;

	/*
	 * List every reference the frame holds, its own and, provisionally,
	 * those of the frames below: what it will not release is dropped after
	 * the pass, see bpf_frame_desc_resolve(). A reference of a frame below
	 * that this frame holds in no live location is not its to list: the
	 * owner lists it at its call, or the holder that releases it does, from
	 * its mirror should that be this frame after all, which is noted.
	 * Whether the frame owns a reference goes with the listing: a frame of
	 * a recursive subprog may hold what another frame of the subprog owns,
	 * obtained at the same insn as its own.
	 */
	for (i = 0; i < st->acquired_refs; i++) {
		const struct bpf_reference_state *ref = &st->refs[i];
		bool owned = ref->frameno == st->curframe;
		int objframe, spi;

		if (ref->type != REF_TYPE_PTR)
			continue;
		if (stack_object_find(st, ref, &objframe, &spi))
			nr = find_object_cands(env, s, st, objframe, spi, true);
		else
			nr = find_cands(env, s, frame, ref, true);
		if (nr < 0)
			return nr;
		if (!nr && !owned) {
			ret = build_add_listing(b, ref->origin, LISTED_SKIPPED, s->node, false);
			if (ret)
				return ret;
			continue;
		}
		ret = place_ref(env, s, ref, nr);
		if (ret < -1)
			return ret;
		ret = build_add_listing(b, ref->origin, ret, s->node, owned);
		if (ret)
			return ret;
	}

	/* Classify the remaining live locations and merge. */
	for (k = 0; k < BPF_REG_10 + b->nr_slots; k++) {
		if (k < BPF_REG_10) {
			if (!(s->live_regs & BIT(k)))
				continue;
			if (!s->class[k] && bpf_register_is_null(&frame->regs[k]))
				s->class[k] = CLASS_NULL;
		} else {
			int spi = k - BPF_REG_10;

			if (!test_bit(spi, s->live_stack))
				continue;
			/* A live slot this state has not allocated holds anything. */
			if (!s->class[k] && spi < bpf_stack_nr_slots(frame) &&
			    stack_slot_is_null(bpf_stack_slot(frame, spi)))
				s->class[k] = CLASS_NULL;
		}
		ret = merge(env, s, k, s->class[k], s->res[k], s->origin[k], s->owned[k],
			    s->indirect[k]);
		if (ret)
			return ret;
	}
	cells_update(b, s);
	if (callee >= 0) {
		ret = build_add_target(b, callee);
		if (ret)
			return ret;
		b->is_call = true;
		site_passed(env, st, b);
	}
	/* the chains name the calls, of BPF code and of helpers running callbacks, by their sites */
	b->callsite |= callee != -1;
	b->visits++;
	return guard_feed(env, st);
}

/*
 * Describe the current frame at a site where the program may be unwound: a
 * bpf_throw() call, a call of BPF code, or a point at which the kernel may
 * cancel the program. The descriptor goes to the aux data of the insn, or to
 * @slot: the site of a may_goto the verifier adds is the insn it goes in
 * front of, and the descriptor is moved onto the may_goto once it is there.
 * A cancellation inside a callback a helper ran unwinds the callback, which
 * leaves into the pad of the helper: the helper needs one, see
 * bpf_check_callback_site(); bpf_throw() is refused in callbacks.
 */
static int site(struct bpf_verifier_env *env, bool regs_saved, struct bpf_frame_desc_build **slot,
		int callee)
{
	struct bpf_verifier_state *st = env->cur_state;
	int f, ret;

	if (st->speculative)
		return 0;
	for (f = env->cancellable ? st->curframe : 0; f > 0; f--) {
		if (!st->frame[f]->in_callback_fn)
			continue;
		ret = bpf_check_callback_site(env, st->frame[f]->callsite);
		if (ret)
			return ret;
		break;
	}
	return site_do(env, regs_saved, slot, callee);
}

int bpf_frame_desc_site(struct bpf_verifier_env *env, bool regs_saved)
{
	return site(env, regs_saved, NULL, -1);
}

/* The timed may_goto slow path saves R0-R9, like the entry of bpf_throw(). */
int bpf_frame_desc_guard_site(struct bpf_verifier_env *env, struct bpf_frame_desc_build **slot)
{
	return site(env, true, slot, -1);
}

/*
 * The current insn calls BPF code: subprog @callee, or the callback of a
 * helper or kfunc when @callee is -1. The frame waits in the call with R6-R9
 * and its stack, and is described from there; what it holds at the call is
 * noted for what the return finds released.
 */
int bpf_frame_desc_call_site(struct bpf_verifier_env *env, int callee)
{
	int ret;

	if (!env->describe_frames)
		return 0;
	ret = callee >= 0 ? bpf_frame_desc_record_call(env) : 0;
	return ret ?: site(env, false, NULL, callee >= 0 ? callee : -2);
}

/*
 * Record where the subprog obtains the handle of the resource refs[@idx] the
 * current frame just acquired: in R@regno @after the acquiring insn, the
 * pointer a call returns, or in front of it, the pointer to a stack object
 * or to a lock the call takes. The mirror of the resource, should a site
 * need it, is stored there, and classified from what the register holds. A
 * call that @may_fail, a resilient lock, leaves the resource unheld on the
 * path it fails on, which the verifier forks before the call: the mirror is
 * cleared after the call where R0 is not 0.
 */
int bpf_frame_desc_record_acquire(struct bpf_verifier_env *env, int idx, int regno, bool after,
				  bool may_fail)
{
	struct bpf_verifier_state *st = env->cur_state;
	struct bpf_func_state *frame = st->frame[st->curframe];
	const struct bpf_reference_state *ref = &st->refs[idx];
	struct bpf_mirror *m;
	int objframe, spi, ret;
	s16 adj = 0;

	if (!env->describe_frames || st->speculative)
		return 0;
	m = mirror_get(env, frame->subprogno, MIRROR_OWNED, ref->origin, 0);
	if (!m)
		return -ENOMEM;
	note_held(env, st, ref->origin);
	if (after && !reg_ref_off(&frame->regs[regno], ref->id, &adj))
		adj = 0;
	if (m->reg.type == NOT_INIT) {
		if (after) {
			/* the store takes the pointer back to the object: the class has no delta */
			m->kind = MIRROR_KIND_PTR;
			m->reg = frame->regs[regno];
			m->reg.var_off = tnum_const(0);
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
	ret = mirror_store_add(m, env->insn_idx, after ? MIRROR_AFTER : MIRROR_BEFORE, regno, 0, adj);
	if (!ret && may_fail)
		ret = mirror_store_add(m, env->insn_idx, MIRROR_CLEAR_FAIL, 0, 0, 0);
	return ret;
}

/*
 * The class of the resource mirror @m holds, from what its acquisition
 * returned. The mirror of a lock holds the pointer to the lock the call took,
 * whether the lock has a fixed address or not: a class with no delta.
 */
static int mirror_resource(struct bpf_verifier_env *env, struct bpf_mirror *m)
{
	struct bpf_stack_state slot = { .spilled_ptr = m->reg };
	const struct bpf_insn_aux_data *aux;
	struct bpf_reg_state reg;
	const struct bpf_insn *insn;
	int ret;

	m->nr_slots = 1;
	if (m->ambiguous) {
		verbose(env, "frame_desc: the pointer to the stack object obtained at insn %d is in different registers at the call on different paths\n",
			m->at);
		return -EINVAL;
	}
	switch (m->how) {
	case MIRROR_ENTRY:
	case MIRROR_LOAD:
		/* what arrived, under the chains of the sites listing it, see mirror_sound_at() */
		return m->res;
	case MIRROR_NOWHERE:
		verbose(env, "frame_desc: the reference obtained at insn %d is held by no register the frame obtained it in\n",
			m->at);
		return -EINVAL;
	}
	aux = &env->insn_aux_data[env->frame_desc_new_of[m->at]];
	insn = &env->prog->insnsi[env->frame_desc_new_of[m->at]];
	if (aux->ref_held_max > 1 && m->kind != MIRROR_KIND_PTR) {
		verbose(env, "frame_desc: two references obtained at insn %d are held at once, and no one slot can mirror both\n",
			m->at);
		return -EINVAL;
	}
	switch (m->kind) {
	case MIRROR_KIND_PTR:
		if (m->reg.type == NOT_INIT)
			break;
		reg = m->reg;
		/*
		 * References of one acquisition held several at once, by a loop
		 * the verifier unrolled, get a slot each: the acquisition fills
		 * the first free one, see emit_after(), and a release clears the
		 * one holding what it releases, see emit_before(). The slots hold
		 * the pointer as the acquisition returned it, which may point
		 * into the object: the class carries by how much. The mirror
		 * takes as many slots as the frame has room for below its stack.
		 */
		if (aux->ref_held_max > 1) {
			const struct bpf_mirror_store *st = mirror_store_find(m, m->at, MIRROR_AFTER);

			m->nr_slots = aux->ref_held_max;
			reg.var_off = tnum_const(st ? st->adj : 0);
		}
		ret = resource_of_reg(env, &reg);
		/* returned by a subprog: R0 is stored whatever the call returns with */
		if (ret >= 0 && (bpf_pseudo_call(insn) || bpf_is_callx(insn)) &&
		    !cell_has(&aux->ret_cell, ret)) {
			verbose(env, "frame_desc: the call at insn %d returns the reference on some paths and something else on others\n",
				m->at);
			return -EINVAL;
		}
		return ret;
	case MIRROR_KIND_LOCK:
		return resource_of_lock(env, &m->reg, m->lock_kind);
	default:
		slot.slot_type[BPF_REG_SIZE - 1] = m->kind;
		return resource_of_object(env, &slot);
	}
	verbose(env, "frame_desc: the reference obtained at insn %d is held by no register or stack slot of its owner\n",
		m->at);
	return -EINVAL;
}

/*
 * A frame of @st just entered its subprog under chain @node: note what R1-R5
 * hold over every entry under the chain, and in which register each
 * reference of a frame below arrives, which is where the subprog's mirror of
 * it is written, see mirror_key().
 */
static int record_entry(struct bpf_verifier_env *env, struct bpf_verifier_state *st,
			const struct bpf_reg_state *regs, int subprog, int owner, u32 node)
{
	struct bpf_subprog_info *sub = &env->subprog_info[subprog];
	struct bpf_cell_set *cells;
	u16 res[BPF_CELL_CLASSES];
	int k, i, n, ret;

	if (!env->describe_frames || st->speculative)
		return 0;
	cells = cells_get(&sub->entry_cells, node, true);
	if (!cells)
		return -ENOMEM;
	for (k = 0; k < MAX_BPF_FUNC_REG_ARGS; k++) {
		const struct bpf_reg_state *reg = &regs[BPF_REG_1 + k];

		n = reg_classes(env, st, reg, res);
		cell_merge(&cells->cell[k], n, res);
		if (n <= 0)
			continue;
		for (i = 0; i < st->acquired_refs; i++) {
			const struct bpf_reference_state *ref = &st->refs[i];

			if (ref->frameno == owner)
				continue;
			ret = ref_class_in_reg(env, st, reg, ref);
			if (ret < 0)
				continue;
			ret = arrival_add(env, subprog, ref->origin, node, ARRIVE_REG, BPF_REG_1 + k,
					  ret);
			if (ret)
				return ret;
		}
	}
	return 0;
}

int bpf_frame_desc_record_entry(struct bpf_verifier_env *env, struct bpf_verifier_state *st)
{
	const struct bpf_func_state *frame = st->frame[st->curframe];
	int node;

	if (!env->describe_frames || st->speculative)
		return 0;
	node = chain_of(env, st);
	if (node < 0)
		return node;
	return record_entry(env, st, frame->regs, frame->subprogno, st->curframe, node);
}

/*
 * The current frame of @st, the caller, calls @subprog, which is verified on
 * its own, at the root of the chains: what the subprog gets in R1-R5 is what
 * the caller has there, dead or not, under the caller's ids, which the entry
 * state renames.
 */
int bpf_frame_desc_record_entry_of(struct bpf_verifier_env *env, struct bpf_verifier_state *st,
				   int subprog)
{
	return record_entry(env, st, st->frame[st->curframe]->regs, subprog, -2, 0);
}

/*
 * Frames of @subprog run as invocations of their own, with what the kernel
 * hands them in R1-R5: the subprog may be called by the program as well, on
 * its own, and no register of its entry can mirror what arrives there then.
 */
void bpf_frame_desc_record_async_entry(struct bpf_verifier_env *env, int subprog)
{
	struct bpf_cell_set *cells = cells_get(&env->subprog_info[subprog].entry_cells, 0, true);
	int k;

	/* without the memory to note it, the entry is as good as never visited */
	if (!cells)
		return;
	for (k = 0; k < MAX_BPF_FUNC_REG_ARGS; k++)
		cell_merge(&cells->cell[k], -2, NULL);
}

/*
 * The current insn loaded R@regno from the stack of a frame below: a
 * reference of that frame may arrive in the current frame this way, which is
 * then where the subprog's mirror of it is written.
 */
int bpf_frame_desc_record_load(struct bpf_verifier_env *env, int regno)
{
	struct bpf_verifier_state *st = env->cur_state;
	struct bpf_func_state *frame = st->frame[st->curframe];
	struct bpf_insn_aux_data *aux = &env->insn_aux_data[env->insn_idx];
	const struct bpf_reg_state *reg = &frame->regs[regno];
	struct bpf_cell_set *cells;
	u16 res[BPF_CELL_CLASSES];
	int n, i, ret, node;

	if (!env->describe_frames || st->speculative)
		return 0;
	node = chain_of(env, st);
	if (node < 0)
		return node;
	cells = cells_get(&aux->ref_load_cells, node, true);
	if (!cells)
		return -ENOMEM;
	n = reg_classes(env, st, reg, res);
	cell_merge(&cells->cell[0], n, res);
	if (n <= 0)
		return 0;
	for (i = 0; i < st->acquired_refs; i++) {
		const struct bpf_reference_state *ref = &st->refs[i];

		if (ref->frameno == st->curframe)
			continue;
		ret = ref_class_in_reg(env, st, reg, ref);
		if (ret < 0)
			continue;
		ret = arrival_add(env, frame->subprogno, ref->origin, node, ARRIVE_LOAD, env->insn_idx,
				  ret);
		if (ret)
			return ret;
	}
	return 0;
}

/*
 * Note that insn @insn of @subprog changes the sections of kind @kind the
 * frame holds by @delta, for the counter of the subprog: a call entering or
 * leaving one, or, @after the call, a call of BPF code whose callee entered
 * or left some of the caller's, which the counter has to follow as well; a
 * callee that does so differently on different paths cannot be followed.
 */
static int section_insn_add(struct bpf_verifier_env *env, u32 insn, u16 subprog, u8 kind, s8 delta,
			    bool after)
{
	struct bpf_section_insn *si;
	u32 i, cnt = env->section_insn_cnt;

	for (i = 0; i < cnt; i++) {
		si = &env->section_insns[i];
		if (si->insn != insn || si->after != after || si->kind != kind)
			continue;
		if (si->delta != delta)
			si->conflict = true;
		return 0;
	}
	si = kvrealloc(env->section_insns, array_size(cnt + 1, sizeof(*si)), GFP_KERNEL_ACCOUNT);
	if (!si)
		return -ENOMEM;
	si[cnt] = (struct bpf_section_insn) { .insn = insn, .kind = kind, .delta = delta,
					      .subprog = subprog, .after = after };
	env->section_insns = si;
	env->section_insn_cnt = cnt + 1;
	return 0;
}

/*
 * Note how many references of origin @origin the current frame of @st owns
 * at once: a mirror of the origin needs a slot each. What the frames below
 * own at the same origin, in a recursive subprog, sits in their slots.
 */
static void note_held(struct bpf_verifier_env *env, const struct bpf_verifier_state *st, u32 origin)
{
	struct bpf_insn_aux_data *aux = &env->insn_aux_data[origin];
	u32 i, n = 0;

	for (i = 0; i < st->acquired_refs; i++)
		n += st->refs[i].origin == origin && st->refs[i].frameno == st->curframe;
	aux->ref_held_max = max_t(u32, aux->ref_held_max, min_t(u32, n, U16_MAX));
}

/* The current insn enters (@delta 1) or leaves (-1) a section of @kind, for the counters. */
int bpf_frame_desc_record_section(struct bpf_verifier_env *env, u8 kind, s8 delta)
{
	struct bpf_verifier_state *st = env->cur_state;

	if (!env->describe_frames || st->speculative)
		return 0;
	return section_insn_add(env, env->insn_idx, st->frame[st->curframe]->subprogno, kind, delta,
				false);
}

/*
 * The current frame wrote the bytes [@min_off, @max_off) of the stack of
 * @frame, a frame below, through a pointer into its stack: a struct the frame
 * passed to a callee, which the callee fills, a buffer a helper writes into.
 * The descriptor of @frame at the call it waits in was built from its state
 * at the call and lists what the slots held then; a site in the callee would
 * have the unwinder release what they hold now. Note the slots for the call,
 * see slot_writes_resolve(). Where the frame above is a callback, every site
 * inside it visits the descriptor with what the slots hold then, see
 * guard_feed(): nothing is noted.
 */
int bpf_frame_desc_record_stack_write(struct bpf_verifier_env *env, const struct bpf_func_state *frame,
				      int min_off, int max_off)
{
	struct bpf_verifier_state *st = env->cur_state;
	struct bpf_slot_write *w;
	u32 i, cnt = env->slot_write_cnt, call;
	int lo, hi;

	if (!env->describe_frames || st->speculative || frame->frameno >= st->curframe ||
	    min_off >= max_off || max_off > 0)
		return 0;
	if (st->frame[frame->frameno + 1]->in_callback_fn)
		return 0;
	call = st->frame[frame->frameno + 1]->callsite;
	lo = max_t(int, -max_off / BPF_REG_SIZE, 0);
	hi = min_t(int, (-min_off - 1) / BPF_REG_SIZE, MAX_BPF_STACK_SLOTS - 1);
	if (lo > hi)
		return 0;
	for (i = 0; i < cnt; i++) {
		w = &env->slot_writes[i];
		if (w->call == call && w->spi_lo <= lo && w->spi_hi >= hi)
			return 0;
	}
	w = kvrealloc(env->slot_writes, array_size(cnt + 1, sizeof(*w)), GFP_KERNEL_ACCOUNT);
	if (!w)
		return -ENOMEM;
	w[cnt] = (struct bpf_slot_write) { .call = call, .spi_lo = lo, .spi_hi = hi };
	env->slot_writes = w;
	env->slot_write_cnt = cnt + 1;
	return 0;
}

/*
 * The register among R1-R5 that holds the handle of @ref at the current
 * insn, or -1; a release may take the node of the object, @adj bytes in.
 */
static int handle_regno(struct bpf_verifier_env *env, struct bpf_verifier_state *st,
			const struct bpf_reference_state *ref, s16 *adj)
{
	const struct bpf_reg_state *regs = st->frame[st->curframe]->regs;
	int objframe = -1, spi = -1, k;

	*adj = 0;
	if (ref->type == REF_TYPE_PTR || ref->type == REF_TYPE_IRQ)
		stack_object_find(st, ref, &objframe, &spi);
	for (k = BPF_REG_1; k <= BPF_REG_5; k++) {
		if (ref->type & REF_TYPE_LOCK_MASK ? reg_is_lock(&regs[k], ref) :
		    objframe >= 0 ? reg_points_at(&regs[k], objframe, spi) :
		    reg_ref_off(&regs[k], ref->id, adj))
			return k;
	}
	return -1;
}

/*
 * Does a frame of @subprog under chain @node, or one below it, release the
 * reference of origin @origin?
 */
static bool marked(const struct bpf_verifier_env *env, u32 origin, u32 node, u32 subprog)
{
	u32 i;

	for (i = 0; i < env->release_rec_cnt; i++) {
		const struct bpf_release_rec *r = &env->release_recs[i];

		if (r->origin == origin && r->node == node && r->subprog == subprog)
			return true;
	}
	return false;
}

/* A frame of @subprog under chain @node, entered from the call at @call, releases @origin at or below it. */
static int mark_add(struct bpf_verifier_env *env, u32 origin, u32 node, u32 call, u16 subprog)
{
	struct bpf_release_rec *r;
	u32 cnt = env->release_rec_cnt;

	if (marked(env, origin, node, subprog))
		return 0;
	r = kvrealloc(env->release_recs, array_size(cnt + 1, sizeof(*r)), GFP_KERNEL_ACCOUNT);
	if (!r)
		return -ENOMEM;
	r[cnt] = (struct bpf_release_rec) { .origin = origin, .node = node, .call = call,
					    .subprog = subprog };
	env->release_recs = r;
	env->release_rec_cnt = cnt + 1;
	return 0;
}

/*
 * The callback of the call at @call, made by a frame of @subprog under chain
 * @node, or a frame above the callback, may release the reference of origin
 * @origin the frame holds, @owned or not: see cb_release_check().
 */
static int cb_release_add(struct bpf_verifier_env *env, u32 origin, u32 call, u32 node, u16 subprog,
			  bool owned)
{
	struct bpf_cb_release *r;
	u32 i, cnt = env->cb_release_cnt;

	for (i = 0; i < cnt; i++) {
		r = &env->cb_releases[i];
		if (r->origin == origin && r->call == call && r->node == node &&
		    r->subprog == subprog && r->owned == owned)
			return 0;
	}
	r = kvrealloc(env->cb_releases, array_size(cnt + 1, sizeof(*r)), GFP_KERNEL_ACCOUNT);
	if (!r)
		return -ENOMEM;
	r[cnt] = (struct bpf_cb_release) { .origin = origin, .call = call, .node = node,
					   .subprog = subprog, .owned = owned };
	env->cb_releases = r;
	env->cb_release_cnt = cnt + 1;
	return 0;
}

/*
 * Record that the current insn releases the resource refs[@idx], before it
 * is released: the frame's mirror of it is cleared, with the handle in the
 * register the insn takes it from, so that the mirror says exactly whether
 * the resource is held. A release of what a frame below owns is noted for
 * the frame and for every frame between, by the chain each is under: they
 * are the ones to list the resource then, and the owner lists it no more at
 * the call it passed it through, see resolve_transfer(). A callback leaves
 * into the kernel code that ran it, which no descriptor sees through, and
 * the frames below the helper call are unwound from the call once the
 * helper has returned the cancellation: the frame that called the helper
 * lists the resource at the call, released on the run-time condition the
 * callback tested, which a scalar of the frame has to tell, see guarded(); the
 * callback and the frames between do not list it. Locks and IRQ flags are
 * not guarded: a callback may not release those of the frames below.
 */
int bpf_frame_desc_record_release(struct bpf_verifier_env *env, int idx)
{
	struct bpf_verifier_state *st = env->cur_state;
	const struct bpf_reference_state *ref = &st->refs[idx];
	u32 subprog = st->frame[st->curframe]->subprogno;
	struct bpf_mirror *m;
	int c, regno, ret, node;
	u8 how;
	u32 at;
	u16 res;
	s16 adj;

	if (!env->describe_frames || st->speculative)
		return 0;
	/* every release but a NULL check, which records nothing, is a call */
	if (verifier_bug_if(!site_insn_ok(&env->prog->insnsi[env->insn_idx]), env,
			    "release at insn %d is not a call", env->insn_idx))
		return -EFAULT;
	node = chain_of(env, st);
	if (node < 0)
		return node;
	if (ref->frameno != st->curframe) {
		/* the frames know their chains: chain_of() walked them */
		for (c = ref->frameno + 1; c <= st->curframe; c++) {
			if (st->frame[c]->in_callback_fn)
				break;
			ret = mark_add(env, ref->origin, c ? st->frame[c]->chain - 1 : 0,
				       c ? st->frame[c]->callsite : ~0U, st->frame[c]->subprogno);
			if (ret)
				return ret;
		}
		if (c <= st->curframe) {
			if (ref->type != REF_TYPE_PTR) {
				verbose(env, "frame_desc: insn %d: a callback may not release the lock or IRQ flags the frames below the helper call hold\n",
					env->insn_idx);
				return -EINVAL;
			}
			ret = cb_release_add(env, ref->origin, st->frame[c]->callsite,
					     c > 1 ? st->frame[c - 1]->chain - 1 : 0,
					     st->frame[c - 1]->subprogno, ref->frameno == c - 1);
			if (ret)
				return ret;
		}
	}
	regno = handle_regno(env, st, ref, &adj);
	if (regno < 0)
		return 0;
	mirror_key(env, subprog, ref->origin, node, ref->frameno == st->curframe, &how, &at, &res);
	m = mirror_get(env, subprog, how, at, res);
	if (!m)
		return -ENOMEM;
	return mirror_store_add(m, env->insn_idx, MIRROR_CLEAR, regno, 0, adj);
}

static struct bpf_call_ref *call_ref_get(struct bpf_verifier_env *env, u32 call, u32 origin,
					 u32 subprog, bool owned, u32 node)
{
	struct bpf_call_ref *r;
	u32 i, cnt = env->call_ref_cnt;

	for (i = 0; i < cnt; i++)
		if (env->call_refs[i].call == call && env->call_refs[i].origin == origin &&
		    env->call_refs[i].owned == owned && env->call_refs[i].node == node)
			return &env->call_refs[i];
	r = kvrealloc(env->call_refs, array_size(cnt + 1, sizeof(*r)), GFP_KERNEL_ACCOUNT);
	if (!r)
		return NULL;
	env->call_refs = r;
	env->call_ref_cnt = cnt + 1;
	r = &r[cnt];
	memset(r, 0, sizeof(*r));
	r->call = call;
	r->origin = origin;
	r->node = node;
	r->subprog = subprog;
	r->owned = owned;
	r->r0_ok = true;
	r->slots_ok = ~0ULL;
	return r;
}

/*
 * The stack slots of @frame that hold the pointer of reference @id, to the
 * object itself as the mirror refreshed from the slot holds it, or are zero
 * when @id is 0.
 */
static u64 frame_slots(struct bpf_verifier_env *env, const struct bpf_func_state *frame, int id)
{
	u64 mask = 0;
	int k;

	for (k = 0; k < bpf_stack_nr_slots(frame) && k < DISC_SLOTS; k++) {
		const struct bpf_stack_state *slot = bpf_stack_slot(frame, k);

		if (id ? stack_slot_ref(env, slot, id, false) == 0 && !slot->spilled_ptr.var_off.value :
			 stack_slot_is_null(slot))
			mask |= BIT_ULL(k);
	}
	return mask;
}

static int state_held(const struct bpf_verifier_state *st, u32 origin, bool owned);

/*
 * The current frame is about to call a subprog: note what it holds, so that
 * the return can tell what the callee released, how many references of an
 * origin it holds several of, since the callee releasing one of them leaves
 * the frame holding the origin, and which stack slots R1-R5 point at, where
 * the callee may create a stack object the frame returns with, see
 * bpf_frame_desc_record_return(). The notes go by the chain the frame is
 * under, which tells the mirror of a reference the frame does not own.
 */
int bpf_frame_desc_record_call(struct bpf_verifier_env *env)
{
	struct bpf_verifier_state *st = env->cur_state;
	struct bpf_func_state *frame = st->frame[st->curframe];
	struct bpf_call_ref *r;
	u32 i, k;
	int node;

	if (!env->describe_frames || st->speculative)
		return 0;
	node = chain_of(env, st);
	if (node < 0)
		return node;
	for (i = 0; i < SECTION_KINDS; i++)
		frame->call_sections[i] = frame_sections(st, !i);
	for (i = 0; i < MAX_BPF_FUNC_REG_ARGS; i++) {
		const struct bpf_reg_state *reg = &frame->regs[BPF_REG_1 + i];
		s64 off = reg->var_off.value;

		frame->call_obj_frame[i] = -1;
		if (reg->type != PTR_TO_STACK || !tnum_is_const(reg->var_off) || off >= 0 ||
		    off % BPF_REG_SIZE)
			continue;
		frame->call_obj_frame[i] = reg->frameno;
		frame->call_obj_spi[i] = -off / BPF_REG_SIZE - 1;
	}
	frame->call_held_cnt = 0;
	for (i = 0; i < st->acquired_refs; i++) {
		bool owned = st->refs[i].frameno == st->curframe;
		u32 origin = st->refs[i].origin;
		int n;

		r = call_ref_get(env, env->insn_idx, origin, frame->subprogno, owned, node);
		if (!r)
			return -ENOMEM;
		r->held_before = true;
		n = state_held(st, origin, owned);
		if (n < 2)
			continue;
		for (k = 0; k < frame->call_held_cnt; k++)
			if (frame->call_held[k].origin == origin && frame->call_held[k].owned == owned)
				break;
		if (k < frame->call_held_cnt)
			continue;
		if (k == BPF_CALL_HELD) {
			verbose(env, "frame_desc: the call at insn %d holds references of more than %d origins several at once\n",
				env->insn_idx, BPF_CALL_HELD);
			return -E2BIG;
		}
		frame->call_held[k] = (struct bpf_call_held) { .origin = origin, .owned = owned,
							       .cnt = min_t(int, n, U16_MAX) };
		frame->call_held_cnt++;
	}
	return 0;
}

/* How many references of origin @origin, @owned by the current frame or not, does @st hold? */
static int state_held(const struct bpf_verifier_state *st, u32 origin, bool owned)
{
	int i, n = 0;

	for (i = 0; i < st->acquired_refs; i++)
		n += st->refs[i].origin == origin && (st->refs[i].frameno == st->curframe) == owned;
	return n;
}

/*
 * A call at @call_idx returned to the frame of @st, and the state is what it
 * is after the call. What the callee returned is the frame's now, obtained at
 * the call: the mirror of such a reference is stored from R0 after the call,
 * as after an acquiring call; that of a stack object the callee created
 * through a pointer the frame passed, in this frame's stack or further
 * below, from the register that passed the pointer, in front of the call, as
 * for an acquiring call that takes the pointer. The callee may also have
 * released a reference the frame held, which the state no longer holds: the
 * mirror has to be cleared after the call, and when the callee releases it
 * only on some paths, refreshed from where the paths tell apart, R0 or a
 * stack slot of the frame that holds the reference on the one kind of path
 * and 0 on the other. A callee that releases one of several references of
 * an origin the frame holds leaves the frame holding the origin, which the
 * count at the call tells. What the call does is recorded per path; what to
 * emit is settled once every path has returned, see mirror_resolve_calls().
 */
int bpf_frame_desc_record_return(struct bpf_verifier_env *env, struct bpf_verifier_state *st,
				 int call_idx)
{
	struct bpf_func_state *frame = st->frame[st->curframe];
	const struct bpf_reg_state *regs = frame->regs;
	const struct bpf_mirror_store *store;
	struct bpf_call_ref *r;
	struct bpf_mirror *m;
	u16 res[BPF_CELL_CLASSES];
	u32 i;
	int objframe, spi, k, ret, node;
	s16 r0_off = 0;

	if (!env->describe_frames || st->speculative)
		return 0;
	node = chain_of(env, st);
	if (node < 0)
		return node;
	/* what the callee did to the sections the frame holds, for its counter */
	for (k = 0; k < SECTION_KINDS; k++) {
		s32 n = frame_sections(st, !k) - frame->call_sections[k];

		if (n < S8_MIN || n > S8_MAX) {
			verbose(env, "frame_desc: the call at insn %d changes too many sections\n",
				call_idx);
			return -E2BIG;
		}
		ret = section_insn_add(env, call_idx, frame->subprogno, k, n, true);
		if (ret)
			return ret;
	}
	/* what R0 holds after the call on every return, for a mirror stored from it */
	k = reg_classes(env, st, &regs[BPF_REG_0], res);
	cell_merge(&env->insn_aux_data[call_idx].ret_cell, k, res);
	for (i = 0; i < st->acquired_refs; i++) {
		const struct bpf_reference_state *ref = &st->refs[i];
		bool in_r0 = ref->type == REF_TYPE_PTR &&
			     reg_ref_off(&regs[BPF_REG_0], ref->id, &r0_off);

		r = call_ref_get(env, call_idx, ref->origin, frame->subprogno,
				 ref->frameno == st->curframe, node);
		if (!r)
			return -ENOMEM;
		/* R0 has to point the same way into the object on every path that holds it */
		if (in_r0 && r->held && r->r0_off != r0_off)
			in_r0 = false;
		if (in_r0)
			r->r0_off = r0_off;
		r->held = true;
		r->r0_ok &= in_r0;
		r->slots_ok &= ref->type == REF_TYPE_PTR ? frame_slots(env, frame, ref->id) : 0;
		if (ref->origin != (u32)call_idx)
			continue;
		note_held(env, st, ref->origin);
		if (in_r0) {
			/* the callee returned it: an acquisition at the call */
			m = mirror_get(env, frame->subprogno, MIRROR_OWNED, ref->origin, 0);
			if (!m)
				return -ENOMEM;
			if (m->reg.type == NOT_INIT) {
				m->kind = MIRROR_KIND_PTR;
				m->reg = regs[BPF_REG_0];
				m->reg.var_off = tnum_const(0);
			}
			ret = mirror_store_add(m, call_idx, MIRROR_AFTER, BPF_REG_0, 0, r0_off);
			if (ret)
				return ret;
			continue;
		}
		/* a stack object the callee created where one of R1-R5 pointed at the call */
		if ((ref->type != REF_TYPE_PTR && ref->type != REF_TYPE_IRQ) ||
		    !stack_object_find(st, ref, &objframe, &spi))
			continue;
		for (k = 0; k < MAX_BPF_FUNC_REG_ARGS; k++)
			if (frame->call_obj_frame[k] == objframe && frame->call_obj_spi[k] == spi)
				break;
		if (k == MAX_BPF_FUNC_REG_ARGS)
			continue;
		m = mirror_get(env, frame->subprogno, MIRROR_OWNED, ref->origin, 0);
		if (!m)
			return -ENOMEM;
		if (m->reg.type == NOT_INIT) {
			const struct bpf_stack_state *slot = bpf_stack_slot(st->frame[objframe], spi);

			m->kind = slot->slot_type[BPF_REG_SIZE - 1];
			m->reg = slot->spilled_ptr;
		}
		/* another path passed the pointer in another register: no one place to store */
		store = mirror_store_find(m, call_idx, MIRROR_BEFORE);
		if (store && store->reg != BPF_REG_1 + k)
			m->ambiguous = true;
		ret = mirror_store_add(m, call_idx, MIRROR_BEFORE, BPF_REG_1 + k, 0, 0);
		if (ret)
			return ret;
	}
	/* what was held at the call on some path and is not held now */
	for (i = 0; i < env->call_ref_cnt; i++) {
		r = &env->call_refs[i];
		if (r->call != (u32)call_idx || r->node != (u32)node || !r->held_before ||
		    state_held(st, r->origin, r->owned))
			continue;
		r->absent = true;
		r->r0_ok &= bpf_register_is_null((struct bpf_reg_state *)&regs[BPF_REG_0]);
		r->slots_ok &= frame_slots(env, frame, 0);
	}
	/* what was held several at once at the call and is held fewer now: the callee released one */
	for (i = 0; i < frame->call_held_cnt; i++) {
		const struct bpf_call_held *h = &frame->call_held[i];
		int n = state_held(st, h->origin, h->owned);

		if (!n || n >= h->cnt)
			continue;
		r = call_ref_get(env, call_idx, h->origin, frame->subprogno, h->owned, node);
		if (!r)
			return -ENOMEM;
		r->partial = true;
	}
	/* what the call returns with on some path and not on this one, see mirror_check_obtained() */
	if (!state_held(st, call_idx, true)) {
		r = call_ref_get(env, call_idx, call_idx, frame->subprogno, true, node);
		if (!r)
			return -ENOMEM;
		r->absent = true;
	}
	return 0;
}

/*
 * A stack object obtained through a call of a subprog is mirrored from the
 * pointer the frame passed, in front of the call: the mirror holds the
 * pointer from then on, whether the callee created the object or not. A
 * callee that does so on some paths and not on others leaves the mirror
 * wrong on the latter, and nothing after the call tells the paths apart as
 * R0 does for a returned pointer: no mirror then.
 */
static int mirror_check_obtained(struct bpf_verifier_env *env, const struct bpf_mirror *m)
{
	bool held = false, absent = false;
	u32 i;

	if (m->how != MIRROR_OWNED || !mirror_store_find(m, m->at, MIRROR_BEFORE))
		return 0;
	/* under any chain of the calling frame: the store in front of the call is one for all */
	for (i = 0; i < env->call_ref_cnt; i++) {
		const struct bpf_call_ref *r = &env->call_refs[i];

		if (r->call != m->at || r->origin != m->at || !r->owned)
			continue;
		held |= r->held;
		absent |= r->absent;
	}
	if (!held || !absent)
		return 0;
	verbose(env, "frame_desc: the call at insn %d returns with the stack object obtained there on some paths and not on others\n",
		m->at);
	return -EINVAL;
}

static bool call_releases(struct bpf_verifier_env *env, u32 call, u32 origin);

/* Is @r a record of a call of the subprog of @m whose reference the frame mirrors in @m? */
static bool call_ref_mirrors(struct bpf_verifier_env *env, const struct bpf_call_ref *r,
			     const struct bpf_mirror *m)
{
	return r->subprog == m->subprog &&
	       mirror_of(env, r->subprog, r->origin, r->node, r->owned) == m;
}

/*
 * Settle what the calls of the subprog do to mirror @m: a call whose callee
 * releases what the mirror holds, after which it is gone on every path,
 * clears the mirror; one after which it is gone on some paths and held on
 * others refreshes the mirror from R0 or from a stack slot that tells the
 * paths apart. A call is recorded per reference and per chain of the
 * calling frame, and the mirror of a reference the frame does not own goes
 * by the chain, see mirror_key(): the records of one call that resolve to
 * the mirror, of any origin under any chain, are taken together, since what
 * is emitted after the call is emitted once for all of them.
 */
static int mirror_resolve_calls(struct bpf_verifier_env *env, struct bpf_mirror *m)
{
	u32 i, j;
	int ret;

	for (i = 0; i < env->call_ref_cnt; i++) {
		struct bpf_call_ref c = env->call_refs[i];
		bool releases;

		if (!call_ref_mirrors(env, &c, m))
			continue;
		/* at the first of the records of the call */
		for (j = 0; j < i; j++)
			if (env->call_refs[j].call == c.call &&
			    call_ref_mirrors(env, &env->call_refs[j], m))
				break;
		if (j < i)
			continue;
		releases = call_releases(env, c.call, c.origin);
		for (j = i + 1; j < env->call_ref_cnt; j++) {
			const struct bpf_call_ref *o = &env->call_refs[j];

			if (o->call != c.call || !call_ref_mirrors(env, o, m))
				continue;
			/* R0 has to point the same way into the object on every path that holds it */
			if (o->held && c.held && o->r0_off != c.r0_off)
				c.r0_ok = false;
			if (o->held && !c.held)
				c.r0_off = o->r0_off;
			c.held_before |= o->held_before;
			c.held |= o->held;
			c.absent |= o->absent;
			c.partial |= o->partial;
			c.r0_ok &= o->r0_ok;
			c.slots_ok &= o->slots_ok;
			releases |= call_releases(env, o->call, o->origin);
		}
		if (!c.held_before || !(c.absent || c.partial) || !releases)
			continue;
		if (!c.held) {
			ret = mirror_store_add(m, c.call, MIRROR_CLEAR_AFTER, 0, 0, 0);
		} else if (m->nr_slots > 1) {
			verbose(env, "frame_desc: the call at insn %d may release one of the references obtained at insn %d, which are held several at once\n",
				c.call, c.origin);
			return -EINVAL;
		} else if (c.r0_ok) {
			ret = mirror_store_add(m, c.call, MIRROR_AFTER, BPF_REG_0, 0, c.r0_off);
		} else if (c.slots_ok) {
			ret = mirror_store_add(m, c.call, MIRROR_AFTER_SLOT, 0,
					       -(__ffs64(c.slots_ok) + 1) * BPF_REG_SIZE, 0);
		} else {
			verbose(env, "frame_desc: the call at insn %d may release the reference obtained at insn %d, and neither R0 nor a stack slot tells on every path\n",
				c.call, c.origin);
			return -EINVAL;
		}
		if (ret)
			return ret;
	}
	return 0;
}

/* Does anything fill the mirror? A clear alone describes nothing. */
static bool mirror_is_written(const struct bpf_mirror *m)
{
	u32 i;

	for (i = 0; i < m->nr_stores; i++)
		if (m->stores[i].point != MIRROR_CLEAR && m->stores[i].point != MIRROR_CLEAR_AFTER &&
		    m->stores[i].point != MIRROR_CLEAR_FAIL)
			return true;
	return false;
}

/*
 * The lists of builds, by index: of the insns, of the guards in front of the
 * insns, then of the entry guards of the subprogs; and the subprog whose
 * frame the builds of a list describe.
 */
#define NR_LISTS(env)	(2 * (env)->prog->len + (env)->subprog_cnt)

static struct bpf_frame_desc_build **build_list(struct bpf_verifier_env *env, u32 idx, int *subprog)
{
	u32 len = env->prog->len;

	if (idx < 2 * len) {
		*subprog = insn_subprog(env, idx % len);
		return idx < len ? &env->insn_aux_data[idx].frame_desc :
				   &env->insn_aux_data[idx - len].guard_desc;
	}
	*subprog = idx - 2 * len;
	return &env->subprog_info[idx - 2 * len].entry_guard;
}

/* Walk every build of every list, see for_each_build(). */
struct build_cursor {
	u32 idx;
	int subprog;
	struct bpf_frame_desc_build *b;
};

static struct bpf_frame_desc_build *build_next(struct bpf_verifier_env *env, struct build_cursor *c)
{
	if (c->b) {
		c->b = c->b->next;
		if (c->b)
			return c->b;
		c->idx++;
	}
	for (; c->idx < NR_LISTS(env); c->idx++) {
		c->b = *build_list(env, c->idx, &c->subprog);
		if (c->b)
			return c->b;
	}
	return NULL;
}

#define for_each_build(env, c, b)							\
	for ((c)->idx = 0, (c)->b = NULL, (b) = build_next(env, c); (b); (b) = build_next(env, c))

/*
 * A location of the lattice lists whichever reference of its class is there:
 * when any of the references listed there needs its mirror, the mirror
 * would list it a second time, so the location is withdrawn and every
 * reference listed there goes to its mirror; and a reference whose location
 * was withdrawn during the pass needs its mirror too. Settle that to a fixed
 * point over all descriptors, before the mirrors are reserved.
 */
static int mirror_settle(struct bpf_verifier_env *env)
{
	struct bpf_frame_desc_build *b;
	struct build_cursor c;
	u32 k, j;
	bool again = true;
	int ret;

	while (again) {
		again = false;
		for_each_build(env, &c, b) {
			int subprog = c.subprog;

			for (k = 0; k < b->nr_listed; k++) {
				const struct bpf_frame_desc_listing *l = &b->listed[k];
				struct bpf_frame_desc_loc *loc;
				struct bpf_mirror *m;

				if (l->loc < 0 || l->dropped)
					continue;
				loc = build_loc_nth(b, l->loc);
				m = mirror_of(env, subprog, l->origin, l->node, l->owned);
				if ((loc->state == LOC_RES || loc->state == LOC_GUARD) && !(m && m->needed))
					continue;
				/* withdrawn, or mirrored: nothing listed there stays */
				if (loc->state == LOC_RES || loc->state == LOC_GUARD)
					withdraw(loc);
				for (j = 0; j < b->nr_listed; j++) {
					if (b->listed[j].loc != l->loc || b->listed[j].dropped)
						continue;
					m = mirror_of(env, subprog, b->listed[j].origin,
						      b->listed[j].node, b->listed[j].owned);
					if (m && m->needed)
						continue;
					ret = mirror_need(env, subprog, b->listed[j].origin,
							  b->listed[j].node, b->listed[j].owned);
					if (ret)
						return ret;
					again = true;
				}
			}
		}
	}
	return 0;
}

/* What @dst lists, from @src: the lattice, not the candidate it is for a guard. */
static void loc_copy_listing(struct bpf_frame_desc_loc *dst, const struct bpf_frame_desc_loc *src)
{
	dst->state = src->state;
	dst->nullable = src->nullable;
	dst->indirect = src->indirect;
	dst->owned = src->owned;
	dst->res = src->res;
	dst->origin = src->origin;
	dst->withdrawn = src->withdrawn;
	dst->guard = src->guard;
}

/*
 * Merge what a location holds in build @src into what it holds in @dst, a
 * build of the same insn, as merge() does for the paths of one build: NULL
 * on one side makes the resource of the other nullable, and different
 * resources, or a resource against a copy, conflict, after which the
 * location is withdrawn. A resource on one side and nothing to release on
 * the other is guarded, like between the paths of one build, and so is a
 * guarded location against anything but another resource; the caller merges
 * the digests then. When @strict, the guards are decided already: guarded
 * locations merge only when they agree, and nothing becomes guarded. Returns
 * 1 on a conflict, 2 when the location is guarded.
 */
static int loc_merge(struct bpf_frame_desc_loc *dst, const struct bpf_frame_desc_loc *src, bool strict)
{
	bool dres = dst->state == LOC_RES || dst->state == LOC_GUARD;
	bool sres = src->state == LOC_RES || src->state == LOC_GUARD;

	if (src->state == LOC_UNSEEN)
		return 0;
	if (dst->state == LOC_UNSEEN) {
		loc_copy_listing(dst, src);
		return dst->state == LOC_GUARD ? 2 : 0;
	}
	if (dst->state == LOC_NULL && src->state == LOC_NULL)
		return 0;
	if (dst->state == LOC_NULL && sres) {
		loc_copy_listing(dst, src);
		dst->nullable = 1;
		return dst->state == LOC_GUARD ? 2 : 0;
	}
	if (dres && src->state == LOC_NULL) {
		dst->nullable = 1;
		return dst->state == LOC_GUARD ? 2 : 0;
	}
	if (dres && sres) {
		if (dst->res != src->res || dst->indirect != src->indirect) {
			withdraw(dst);
			return 1;
		}
		if (dst->state == LOC_RES && src->state == LOC_RES) {
			dst->nullable |= src->nullable;
			return 0;
		}
		if (strict) {
			if (dst->state != src->state || memcmp(&dst->guard, &src->guard, sizeof(dst->guard))) {
				withdraw(dst);
				return 1;
			}
			dst->nullable |= src->nullable;
			return 0;
		}
		dst->nullable |= src->nullable;
		dst->state = LOC_GUARD;
		return 2;
	}
	if (dres || sres) {
		/* a withdrawn location lists nothing again: what it listed is mirrored */
		if (strict || dst->withdrawn || src->withdrawn) {
			withdraw(dst);
			return 1;
		}
		if (sres)
			loc_copy_listing(dst, src);
		dst->state = LOC_GUARD;
		return 2;
	}
	dst->state = LOC_OTHER;
	dst->withdrawn |= src->withdrawn;
	return 0;
}

/* The hull and the standing as a candidate of a location of @dst before a merge, see build_merge(). */
struct cell_snap {
	struct bpf_guard_hull hull;
	u8 cand;
};

/*
 * Location @l of @dst is guarded after the merge of @src into it: merge the
 * digests. A side that was guarded brings its digest; a side that held the
 * resource on every visit adds the hull of each candidate as a range that
 * holds it, a side that held nothing to release adds it as one that does
 * not; NULL adds nothing. The hulls of @dst are those from before the merge,
 * in @snap.
 */
static int digest_merge(struct bpf_frame_desc_build *dst, const struct bpf_frame_desc_build *src,
			int l, const struct cell_snap *snap, u8 dstate, u8 sstate)
{
	const struct bpf_guard_digest *sd = sstate == LOC_GUARD ? digest_find(src, l) : NULL;
	struct bpf_guard_digest *dd = digest_find(dst, l);
	bool dnew = !dd;
	int c;

	if (dnew) {
		dd = digest_get(dst, l);
		if (!dd)
			return -ENOMEM;
	}
	for (c = 0; c < BPF_REG_10 + dst->nr_slots; c++) {
		struct bpf_guard_cand *cand = &dd->cand[c];
		const struct bpf_frame_desc_loc *o = c < BPF_REG_10 + src->nr_slots ? build_loc_nth((struct bpf_frame_desc_build *)src, c) : NULL;
		const struct bpf_guard_hull *shull = o && o->cand == CAND_SCALAR ? &o->hull : NULL;
		const struct bpf_guard_hull *dhull = snap[c].cand == CAND_SCALAR ? &snap[c].hull : NULL;

		if (dstate == LOC_GUARD && sstate == LOC_GUARD) {
			if (!sd || !cand->alive) {
				cand->alive = false;
				continue;
			}
			cand_merge(cand, &sd->cand[c]);
			continue;
		}
		if (dstate == LOC_GUARD) {
			if (!cand->alive)
				continue;
			if (!shull || sstate == LOC_UNSEEN)
				cand->alive = sstate == LOC_NULL || sstate == LOC_UNSEEN ? cand->alive : false;
			else if (sstate == LOC_RES)
				cand_add(cand, shull, false);
			else if (sstate != LOC_NULL)
				cand_add(cand, shull, true);
			continue;
		}
		if (sstate == LOC_GUARD) {
			if (!sd) {
				cand->alive = false;
				continue;
			}
			*cand = sd->cand[c];
			if (!cand->alive || dstate == LOC_NULL || dstate == LOC_UNSEEN)
				continue;
			if (!dhull)
				cand->alive = false;
			else if (dstate == LOC_RES)
				cand_add(cand, dhull, false);
			else
				cand_add(cand, dhull, true);
			continue;
		}
		/* a resource on one side, nothing to release on the other */
		if (!dhull || !shull) {
			cand->alive = false;
			continue;
		}
		if (dstate == LOC_RES)
			cand_set(cand, dhull, shull);
		else
			cand_set(cand, shull, dhull);
	}
	return 0;
}

/* The fixed entry of @b for @e: the lock or flags of its origin, or the section of its kind. */
static struct bpf_frame_desc_fixed *fixed_find(struct bpf_frame_desc_build *b,
					       const struct bpf_frame_desc_fixed *e)
{
	int k;

	for (k = 0; k < b->nr_fixed; k++)
		if (b->fixed[k].origin == e->origin &&
		    (e->origin != ACQ_NONE || b->fixed[k].ent.res == e->ent.res))
			return &b->fixed[k];
	return NULL;
}

static void section_disagree_in(struct bpf_verifier_env *env, int subprog, u16 res)
{
	u8 kind = env->resources[res].kind == BPF_RESOURCE_RCU ? 0 : 1;

	env->subprog_info[subprog].section_counter |= BIT(kind);
}

/*
 * Merge build @src into the build at @dstp, of the same insn of @subprog:
 * the lattice, see loc_merge(), the listings, the locks, flags and sections,
 * and the targets of a call. When @strict a conflict fails the merge, and so
 * do locks, flags or sections placed differently, or placed in one build
 * only: the builds stay apart then, and 1 is returned. Otherwise a location
 * in conflict is withdrawn and what is listed there goes to its mirror, see
 * mirror_settle(), and a lock or flags placed differently, or in one build
 * only, goes to its mirror too, and sections that differ to the counter of
 * the subprog, as between the paths of one build, see fixed_merge().
 */
static int build_merge(struct bpf_verifier_env *env, int subprog, struct bpf_frame_desc_build **dstp,
		       const struct bpf_frame_desc_build *src, bool strict)
{
	struct bpf_frame_desc_build *dst;
	struct cell_snap *snap;
	bool fresh;
	int l, i, k, order = 0, ret;

	dst = build_grow(env, src->pc, dstp, src->nr_slots);
	if (!dst)
		return -ENOMEM;
	if (verifier_bug_if(dst->regs_saved != src->regs_saved || dst->nr_extra || src->nr_extra,
			    env, "merging the builds of insn %d", src->pc))
		return -EFAULT;
	/* a build without visits is the fresh one of remerge_builds(): it takes what @src has */
	fresh = !dst->visits;
	snap = kvcalloc(FRAME_LOCS, sizeof(*snap), GFP_KERNEL_ACCOUNT);
	if (!snap)
		return -ENOMEM;
	for (l = 0; l < BPF_REG_10 + dst->nr_slots; l++) {
		const struct bpf_frame_desc_loc *d = build_loc_nth(dst, l);

		snap[l].hull = d->hull;
		snap[l].cand = d->cand;
	}
	for (l = 0; l < BPF_REG_10 + src->nr_slots; l++) {
		struct bpf_frame_desc_loc *d = build_loc_nth(dst, l);
		const struct bpf_frame_desc_loc *o = build_loc_nth((struct bpf_frame_desc_build *)src, l);
		u8 dstate = d->state, sstate = o->state;

		ret = loc_merge(d, o, strict);
		if (ret == 1 && strict) {
			kvfree(snap);
			return 1;
		}
		if (ret == 2) {
			ret = digest_merge(dst, src, l, snap, dstate, sstate);
			if (ret) {
				kvfree(snap);
				return ret;
			}
		}
	}
	/* the candidates of the merged build: live scalars on the visits of both */
	for (l = 0; l < BPF_REG_10 + dst->nr_slots; l++) {
		struct bpf_frame_desc_loc *d = build_loc_nth(dst, l);
		const struct bpf_frame_desc_loc *o = l < BPF_REG_10 + src->nr_slots ?
			build_loc_nth((struct bpf_frame_desc_build *)src, l) : NULL;

		if (fresh) {
			d->cand = o ? o->cand : CAND_NONE;
			d->hull = o ? o->hull : d->hull;
		} else if (snap[l].cand == CAND_SCALAR && o && o->cand == CAND_SCALAR) {
			d->hull = snap[l].hull;
			hull_union(&d->hull, &o->hull);
			d->cand = CAND_SCALAR;
		} else {
			d->cand = CAND_NONE;
		}
	}
	kvfree(snap);
	dst->fed_blind |= src->fed_blind;
	for (i = 0; i < src->nr_listed; i++) {
		const struct bpf_frame_desc_listing *sl = &src->listed[i];
		struct bpf_frame_desc_listing *dl = NULL;

		for (k = 0; k < dst->nr_listed; k++) {
			if (dst->listed[k].origin != sl->origin)
				continue;
			/* listed by one chain and released below it by another: not one site */
			if (strict && dst->listed[k].dropped != sl->dropped)
				return 1;
			if (dst->listed[k].loc == sl->loc && dst->listed[k].node == sl->node &&
			    dst->listed[k].owned == sl->owned)
				dl = &dst->listed[k];
		}
		if (!dl) {
			ret = build_add_listing(dst, sl->origin, sl->loc, sl->node, sl->owned);
			if (ret)
				return ret;
			dl = &dst->listed[dst->nr_listed - 1];
			dl->dropped = sl->dropped;
		}
		dl->passed |= sl->passed;
	}
	for (i = 0; i < src->nr_fixed; i++) {
		const struct bpf_frame_desc_fixed *e = &src->fixed[i];
		struct bpf_frame_desc_fixed *f = fixed_find(dst, e);
		bool same = f && fixed_same(f, e) && (e->origin != ACQ_NONE || f->ent.off == e->ent.off);

		if (same)
			continue;
		if (strict)
			return 1;
		if (e->origin == ACQ_NONE) {
			section_disagree_in(env, subprog, e->ent.res);
			continue;
		}
		if (!f) {
			ret = fixed_insert(dst, dst->nr_fixed, e);
			if (ret)
				return ret;
		}
		ret = mirror_need(env, subprog, e->origin, e->node, e->owned);
		if (ret)
			return ret;
	}
	for (k = 0; k < dst->nr_fixed; k++) {
		const struct bpf_frame_desc_fixed *f = &dst->fixed[k];

		if (fixed_find((struct bpf_frame_desc_build *)src, f))
			continue;
		if (strict)
			return 1;
		if (f->origin == ACQ_NONE) {
			section_disagree_in(env, subprog, f->ent.res);
			continue;
		}
		ret = mirror_need(env, subprog, f->origin, f->node, f->owned);
		if (ret)
			return ret;
	}
	for (k = 0; k < dst->nr_fixed; k++)
		if (dst->fixed[k].origin != ACQ_NONE)
			dst->fixed[k].ent.order = order++;
	for (i = 0; i < src->nr_targets; i++) {
		ret = build_add_target(dst, src->targets[i]);
		if (ret)
			return ret;
	}
	dst->is_call |= src->is_call;
	dst->callsite |= src->callsite;
	dst->visits += src->visits;
	return 0;
}

/*
 * A frame the pass visited under a chain runs, at run time, under every
 * chain that extends it: the main program and a subprog verified on its own
 * have callers the pass did not see, and a subprog visited under a short
 * chain for one of them is visited under the longer chains as well where a
 * caller is verified in context. The unwinder looks a frame up by the
 * deepest node of its chain it finds, see bpf_unwind_chain(): so the build
 * of a chain is merged into every build of the same insn whose chain extends
 * it, and stays for the chains that have no build of their own.
 */
static int merge_prefix_builds(struct bpf_verifier_env *env)
{
	struct bpf_frame_desc_build **head, **w, *v;
	u32 idx;
	int subprog, ret;

	for (idx = 0; idx < NR_LISTS(env); idx++) {
		head = build_list(env, idx, &subprog);
		if (!*head || !(*head)->next)
			continue;
		for (w = head; *w; w = &(*w)->next) {
			for (v = *head; v; v = v->next) {
				if (!chain_is_prefix(env, v->node, (*w)->node))
					continue;
				ret = build_merge(env, subprog, w, v, false);
				if (ret)
					return ret;
			}
		}
	}
	return 0;
}

/*
 * Is mirror @m sound for a frame under chain @node: does the register of the
 * entry, or the load, it is stored from hold a reference of its class, or
 * NULL, on every visit under the node, and under the prefixes of its chain,
 * whose visits run under the node as well? Otherwise what the store puts in
 * the mirror is no handle, and no site under the node may list the mirror.
 * The mirror of a resource the subprog obtains itself holds its handle or
 * NULL under every chain.
 */
static bool mirror_sound_at(struct bpf_verifier_env *env, const struct bpf_mirror *m, u32 node)
{
	const struct bpf_cells *cells;
	int k = 0;
	u32 i;

	if (m->how == MIRROR_ENTRY) {
		cells = &env->subprog_info[m->subprog].entry_cells;
		k = m->at - BPF_REG_1;
	} else if (m->how == MIRROR_LOAD) {
		cells = &env->insn_aux_data[env->frame_desc_new_of[m->at]].ref_load_cells;
	} else {
		return true;
	}
	for (i = 0; i < cells->cnt; i++) {
		const struct bpf_cell *c = &cells->sets[i].cell[k];

		if (cells->sets[i].node != node && !chain_is_prefix(env, cells->sets[i].node, node))
			continue;
		if (c->state != CELL_UNSEEN && c->state != CELL_NULL && !cell_has(c, m->res))
			return false;
	}
	return true;
}

static int mirror_unsound(struct bpf_verifier_env *env, const struct bpf_mirror *m)
{
	if (m->how == MIRROR_ENTRY)
		verbose(env, "frame_desc: subprog %d gets a reference in R%d at its entry on some paths and something else on others\n",
			m->subprog, m->at);
	else
		verbose(env, "frame_desc: the load at insn %d yields a reference on some paths and something else on others\n",
			m->at);
	return -EINVAL;
}

/* The mirrors each build lists have to be sound under the build's chain. */
static int check_mirrors_sound(struct bpf_verifier_env *env)
{
	struct bpf_frame_desc_build *b;
	struct build_cursor c;
	u32 k;

	for_each_build(env, &c, b) {
		for (k = 0; k < b->nr_listed; k++) {
			const struct bpf_frame_desc_listing *l = &b->listed[k];
			const struct bpf_mirror *m;

			if (l->dropped)
				continue;
			m = mirror_of(env, c.subprog, l->origin, l->node, l->owned);
			if (m && m->needed && !mirror_sound_at(env, m, b->node))
				return mirror_unsound(env, m);
		}
	}
	return 0;
}

/* Does build @b drop a listing of a reference that mirror @m holds under the build's chain? */
static bool build_drops_into(struct bpf_verifier_env *env, int subprog,
			     const struct bpf_frame_desc_build *b, const struct bpf_mirror *m)
{
	u32 k;

	for (k = 0; k < b->nr_listed; k++) {
		const struct bpf_frame_desc_listing *l = &b->listed[k];

		if (l->dropped && mirror_of(env, subprog, l->origin, l->node, l->owned) == m)
			return true;
	}
	return false;
}

/*
 * The builds of an insn for the chains the pass kept apart are merged back
 * into one where the chains agree, see build_merge(), and where the mirrors
 * one lists are sound under the chains of the others: the site has one
 * descriptor then, for any chain, and the chains need no node of the trie
 * for it. A mirror filled from a register of the entry or by a load holds
 * whatever arrives there under any chain: a chain that drops what arrives
 * there, for the frame below to list it at its call, cannot share the
 * descriptor that lists the mirror, which would release it as well.
 * Otherwise the site keeps a descriptor per chain, and the unwinder tells
 * them apart by the chain of the frame. One build alone is for any chain as
 * well: no other chain reaches the insn.
 */
static int remerge_builds(struct bpf_verifier_env *env)
{
	struct bpf_frame_desc_build **head, *a, *b, *r;
	u32 idx, nr_slots, k;
	int subprog, ret;

	for (idx = 0; idx < NR_LISTS(env); idx++) {
		head = build_list(env, idx, &subprog);
		if (!*head || !(*head)->next)
			continue;
		nr_slots = 0;
		for (b = *head; b; b = b->next)
			nr_slots = max_t(u32, nr_slots, b->nr_slots);
		r = NULL;
		if (!build_grow(env, (*head)->pc, &r, nr_slots))
			return -ENOMEM;
		r->regs_saved = (*head)->regs_saved;
		for (b = *head; b; b = b->next) {
			ret = build_merge(env, subprog, &r, b, true);
			if (ret)
				break;
		}
		for (a = *head; !ret && a; a = a->next) {
			for (k = 0; !ret && k < a->nr_listed; k++) {
				const struct bpf_frame_desc_listing *l = &a->listed[k];
				const struct bpf_mirror *m;

				if (l->dropped)
					continue;
				m = mirror_of(env, subprog, l->origin, l->node, l->owned);
				if (!m || !m->needed)
					continue;
				for (b = *head; b; b = b->next) {
					if (!mirror_sound_at(env, m, b->node))
						ret = 1;
					if ((m->how == MIRROR_ENTRY || m->how == MIRROR_LOAD) &&
					    build_drops_into(env, subprog, b, m))
						ret = 1;
				}
			}
		}
		if (ret < 0) {
			build_destroy(r);
			return ret;
		}
		if (ret) {
			build_destroy(r);
			continue;
		}
		bpf_frame_desc_build_destroy(*head);
		*head = r;
	}
	return 0;
}

/* List mirror @ent of origin @origin in @b, in place of its fixed entry when it has one. */
static int build_mirror(struct bpf_frame_desc_build *b, u32 origin, struct bpf_frame_desc_entry ent)
{
	struct bpf_frame_desc_entry *extra;
	int l;

	for (l = 0; l < b->nr_fixed; l++) {
		if (b->fixed[l].origin != origin)
			continue;
		ent.order = b->fixed[l].ent.order;
		b->fixed[l].ent = ent;
		return 0;
	}
	for (l = 0; l < b->nr_extra; l++)
		if (b->extra[l].off == ent.off)
			return 0;
	extra = kvrealloc(b->extra, array_size(b->nr_extra + 1, sizeof(*extra)), GFP_KERNEL_ACCOUNT);
	if (!extra)
		return -ENOMEM;
	extra[b->nr_extra++] = ent;
	b->extra = extra;
	return 0;
}

/* Does @s call @t through calls of BPF code, in any number of steps, or is it @t? See reach_build(). */
static bool reaches(const struct bpf_verifier_env *env, u32 s, u32 t)
{
	return test_bit(t, env->frame_desc_reach + s * BITS_TO_LONGS(env->subprog_cnt));
}

/*
 * Does a frame of @subprog under chain @node, or under a prefix of its chain,
 * release @origin at or below it? A release in a frame verified on its own
 * is recorded at the root for that frame's subprog alone, the frames that
 * call it not being in its state: it stands for every call of the subprog,
 * from @subprog itself or from any subprog it reaches through calls.
 */
static bool marked_up(const struct bpf_verifier_env *env, u32 origin, u32 node, u32 subprog)
{
	u32 i;

	for (;;) {
		if (marked(env, origin, node, subprog))
			return true;
		if (!node)
			break;
		node = env->chains[node].parent;
	}
	for (i = 0; i < env->release_rec_cnt; i++) {
		const struct bpf_release_rec *r = &env->release_recs[i];

		if (r->origin == origin && !r->node && reaches(env, subprog, r->subprog))
			return true;
	}
	return false;
}

/*
 * Does a frame of @s under chain @node list the reference of origin @origin
 * for another target of a callx?
 */
static bool coclaimed(struct bpf_verifier_env *env, u32 s, u32 origin, u32 node)
{
	u32 i;

	for (i = 0; i < env->coclaim_cnt; i++) {
		const struct bpf_coclaim *c = &env->coclaims[i];

		if (c->origin == origin && c->subprog == s &&
		    (c->node == node || chain_is_prefix(env, c->node, node)))
			return true;
	}
	return false;
}

static int coclaim_add(struct bpf_verifier_env *env, u32 s, u32 origin, u32 node)
{
	struct bpf_coclaim *c;
	u32 cnt = env->coclaim_cnt;

	c = kvrealloc(env->coclaims, array_size(cnt + 1, sizeof(*c)), GFP_KERNEL_ACCOUNT);
	if (!c)
		return -ENOMEM;
	c[cnt] = (struct bpf_coclaim) { .origin = origin, .subprog = s, .node = node };
	env->coclaims = c;
	env->coclaim_cnt = cnt + 1;
	return 0;
}

/*
 * Does a frame of @s under chain @node list the reference of origin @origin,
 * which it does not own: does it or a callee release it, under the chain or
 * a prefix of it, or one that arrives the way it does, in the same register
 * of the entry or by the same load, as a reference of the same class, since
 * the mirror of that register or load lists whatever arrived there; or is
 * it a target of a callx another target of which lists it, see
 * coclaim_targets()?
 */
static bool claimed(struct bpf_verifier_env *env, u32 s, u32 origin, u32 node)
{
	const struct bpf_arrival *a;
	u32 i;

	if (coclaimed(env, s, origin, node) || marked_up(env, origin, node, s))
		return true;
	a = arrival_lookup(env, s, origin, node);
	if (!a || a->how == ARRIVE_NONE)
		return false;
	for (i = 0; i < env->arrival_cnt; i++) {
		const struct bpf_arrival *o = &env->arrivals[i];

		if (o->subprog != s || o->how != a->how || o->at != a->at || o->res != a->res ||
		    (o->node != node && !chain_is_prefix(env, o->node, node)))
			continue;
		if (marked_up(env, o->origin, node, s) || coclaimed(env, s, o->origin, node))
			return true;
	}
	return false;
}

/*
 * The chain of a frame the call of build @b enters: the call, nearest, then
 * the chain of the frame of the build. Walk its nodes from the root as far
 * as the trie has them, into @nodes: a frame of the callee visited under a
 * shorter chain, from a caller verified on its own, is at one of the shorter
 * ones and runs under the longer ones, see merge_prefix_builds(). Returns
 * how many, and the deepest last. The path up from the node of the build
 * yields its chain outermost first, see chain_walk(): it is put down from
 * the end.
 */
static int callee_chain(struct bpf_verifier_env *env, const struct bpf_frame_desc_build *b,
			u32 *nodes)
{
	u32 pcs[MAX_CALL_FRAMES + 1], node;
	int depth = 0, k;

	for (node = b->node; node; node = env->chains[node].parent)
		depth++;
	if (verifier_bug_if(depth > MAX_CALL_FRAMES, env, "chain of %d calls at insn %d", depth,
			    b->pc)) {
		nodes[0] = 0;
		return 1;
	}
	pcs[0] = b->pc;
	for (node = b->node, k = depth; node; node = env->chains[node].parent)
		pcs[k--] = env->chains[node].pc;
	return chain_walk(env, pcs, depth + 1, false, nodes);
}

/*
 * Does target @t of the call of build @b list the reference of origin
 * @origin, under some chain the call enters it under?
 */
static bool callee_claims(struct bpf_verifier_env *env, const struct bpf_frame_desc_build *b, u32 t,
			  u32 origin)
{
	u32 nodes[MAX_CALL_FRAMES + 2];
	int n = callee_chain(env, b, nodes), k;

	for (k = 0; k < n; k++)
		if (claimed(env, t, origin, nodes[k]))
			return true;
	return false;
}

/*
 * A callx passes what it passes to every target alike, and the caller lists
 * nothing a target releases: the targets that do not release it list it,
 * as a reference that arrived the way it did, from their lattice or their
 * mirror, under the deepest chain the call enters them under. A target may
 * be one of another callx in turn: to a fixed point.
 */
static int coclaim_targets(struct bpf_verifier_env *env)
{
	struct bpf_frame_desc_build *b;
	struct build_cursor c;
	bool again = true;
	u32 k, nodes[MAX_CALL_FRAMES + 2];
	int t, n, ret;

	while (again) {
		again = false;
		for_each_build(env, &c, b) {
			if (!b->is_call || b->nr_targets < 2)
				continue;
			n = callee_chain(env, b, nodes);
			for (k = 0; k < b->nr_listed; k++) {
				const struct bpf_frame_desc_listing *l = &b->listed[k];
				bool any = false;

				if (!l->passed)
					continue;
				for (t = 0; t < b->nr_targets; t++)
					any |= callee_claims(env, b, b->targets[t], l->origin);
				if (!any)
					continue;
				for (t = 0; t < b->nr_targets; t++) {
					if (callee_claims(env, b, b->targets[t], l->origin))
						continue;
					ret = coclaim_add(env, b->targets[t], l->origin, nodes[n - 1]);
					if (ret)
						return ret;
					again = true;
				}
			}
		}
	}
	return 0;
}

/*
 * The subprogs the call at @call of the current image may enter: a static or
 * global subprog, or the targets of a callx. None for a call of a helper or a
 * kfunc, whose callback is not reached through the call.
 */
static int call_targets(struct bpf_verifier_env *env, u32 call, u16 *targets)
{
	const struct bpf_insn *insn = &env->prog->insnsi[call];
	u32 cnt = env->subprog_cnt, s, n = 0;
	int callee;

	if (bpf_pseudo_call(insn)) {
		callee = bpf_find_subprog(env, call + insn->imm + 1);
		if (callee >= 0)
			targets[n++] = callee;
	} else if (bpf_is_callx(insn) && env->callx_edges) {
		s = insn_subprog(env, call);
		for (callee = 0; callee < cnt; callee++)
			if (test_bit(s * cnt + callee, env->callx_edges))
				targets[n++] = callee;
	}
	return n;
}

/*
 * Which subprogs a frame of each subprog may enter through calls of BPF
 * code, transitively, itself included: static and global calls and the
 * targets of a callx, never a callback, which the kernel runs; a release
 * recorded at the root for a subprog verified on its own reaches every call
 * of it through them, see marked_up() and call_releases(). A row of
 * BITS_TO_LONGS(subprog_cnt) longs per subprog, from the insns of the image
 * as it is after the pass.
 */
static int reach_build(struct bpf_verifier_env *env)
{
	u32 cnt = env->subprog_cnt, stride = BITS_TO_LONGS(cnt), i, s, t;
	u16 *targets = env->frame_desc_targets;
	unsigned long *reach;
	bool again = true;
	int n, k;

	reach = kvcalloc(cnt * stride, sizeof(*reach), GFP_KERNEL_ACCOUNT);
	if (!reach)
		return -ENOMEM;
	env->frame_desc_reach = reach;
	for (s = 0; s < cnt; s++)
		__set_bit(s, reach + s * stride);
	for (i = 0; i < env->prog->len; i++) {
		const struct bpf_insn *insn = &env->prog->insnsi[i];

		if (!bpf_pseudo_call(insn) && !bpf_is_callx(insn))
			continue;
		s = insn_subprog(env, i);
		n = call_targets(env, i, targets);
		for (k = 0; k < n; k++)
			__set_bit(targets[k], reach + s * stride);
	}
	while (again) {
		again = false;
		for (s = 0; s < cnt; s++) {
			unsigned long *row = reach + s * stride;

			for_each_set_bit(t, row, cnt) {
				if (t == s || bitmap_subset(reach + t * stride, row, cnt))
					continue;
				bitmap_or(row, row, reach + t * stride, cnt);
				again = true;
			}
		}
	}
	return 0;
}

/*
 * Does a callee of the call at @call (an orig insn) release the reference of
 * origin @origin, under some chain: a frame entered from the call, which the
 * record of the release names, or one verified on its own, of a target of
 * the call or of a subprog a target reaches, see marked_up()?
 */
static bool call_releases(struct bpf_verifier_env *env, u32 call, u32 origin)
{
	u16 *targets = env->frame_desc_targets;
	int i, n;
	u32 k;

	if (verifier_bug_if(call >= env->frame_desc_orig_len, env, "call at insn %d", call))
		return false;
	n = call_targets(env, env->frame_desc_new_of[call], targets);
	for (k = 0; k < env->release_rec_cnt; k++) {
		const struct bpf_release_rec *r = &env->release_recs[k];

		if (r->origin != origin)
			continue;
		if (r->node) {
			if (r->call == call)
				return true;
			continue;
		}
		for (i = 0; i < n; i++)
			if (reaches(env, targets[i], r->subprog))
				return true;
	}
	return false;
}

/*
 * The transfer: a frame lists what it owns and what it, or a callee, releases
 * of what the frames below own, under the chain it is under or a prefix of
 * it, which the frames below do not list at the call through which the
 * resource reached the releasing frame, under the chains the call enters
 * it under. Drop every other provisional listing, and withdraw a location of
 * the lattice whose listings are dropped, which a reference listed there
 * that stays is then mirrored for, see mirror_settle().
 */
static int resolve_transfer(struct bpf_verifier_env *env)
{
	struct bpf_frame_desc_build *b;
	struct build_cursor c;
	u32 k, j;
	int ret;

	ret = coclaim_targets(env);
	if (ret)
		return ret;
	for_each_build(env, &c, b) {
		int subprog = c.subprog;

		for (k = 0; k < b->nr_listed; k++) {
			struct bpf_frame_desc_listing *l = &b->listed[k];
			int t;
			u8 how;
			u32 at;
			u16 res;

			if (!l->owned && !claimed(env, subprog, l->origin, b->node)) {
				l->dropped = true;
				continue;
			}
			/*
			 * Held nowhere at the site by a frame that lists it after all:
			 * from its mirror, which its entry fills; a load would fill it
			 * too late for a site in front of the load.
			 */
			if (l->loc == LISTED_SKIPPED) {
				mirror_key(env, subprog, l->origin, l->node, false, &how, &at, &res);
				if (how == MIRROR_LOAD) {
					verbose(env, "frame_desc: subprog %d releases the reference obtained at insn %d, which it holds nowhere at insn %d, before loading it at insn %d\n",
						subprog, l->origin, b->pc, at);
					return -EINVAL;
				}
				ret = mirror_need(env, subprog, l->origin, l->node, false);
				if (ret)
					return ret;
				l->loc = -1;
			}
			/* passed to a callee chain that lists it: the chain releases it */
			for (t = 0; l->passed && t < b->nr_targets; t++) {
				if (!callee_claims(env, b, b->targets[t], l->origin))
					continue;
				l->dropped = true;
				break;
			}
		}
		for (k = 0; k < b->nr_listed; k++) {
			const struct bpf_frame_desc_listing *l = &b->listed[k];

			if (!l->dropped)
				continue;
			if (l->loc >= 0) {
				withdraw(build_loc_nth(b, l->loc));
				continue;
			}
			if (l->loc != LISTED_FIXED)
				continue;
			for (j = 0; j < b->nr_fixed; j++) {
				if (b->fixed[j].origin != l->origin)
					continue;
				memmove(&b->fixed[j], &b->fixed[j + 1],
					(b->nr_fixed - j - 1) * sizeof(b->fixed[0]));
				b->nr_fixed--;
				break;
			}
		}
	}
	return 0;
}

/*
 * The sections a subprog's frames disagree on are counted in a hidden slot:
 * every call of the subprog that enters a section adds one, every call that
 * leaves one takes one, a call of BPF code whose callee left some of the
 * frame's sections, or entered some and returned with them, adds what the
 * callee did once it returned, and the descriptors list the slot. What a
 * callee does to its caller's sections is the same on every path through
 * the call in all but contrived programs, where the caller's continuation
 * has to tell the paths apart by itself: the counter cannot follow those.
 */
static int resolve_section_counters(struct bpf_verifier_env *env)
{
	struct bpf_frame_desc_build *b;
	struct build_cursor c;
	u32 s, i;
	int kind, ret;

	for (s = 0; s < env->subprog_cnt; s++) {
		struct bpf_subprog_info *sub = &env->subprog_info[s];

		for (kind = 0; kind < SECTION_KINDS; kind++) {
			if (!(sub->section_counter & BIT(kind)))
				continue;
			ret = bpf_reserve_stack_slots(env, s, 1, &sub->section_off[kind]);
			ret = ret ?: bpf_stack_slot_init(env, s, sub->section_off[kind], 0);
			if (ret)
				return ret;
			env->section_counters++;
		}
	}
	for (i = 0; i < env->section_insn_cnt; i++) {
		const struct bpf_section_insn *si = &env->section_insns[i];

		if (!si->after || !si->conflict ||
		    !(env->subprog_info[si->subprog].section_counter & BIT(si->kind)))
			continue;
		verbose(env, "frame_desc: the call at insn %d changes the %s sections its caller holds differently on different paths, which the caller counts\n",
			si->insn, si->kind ? "preemption disabled" : "RCU read");
		return -EINVAL;
	}
	for_each_build(env, &c, b) {
		struct bpf_subprog_info *sub = &env->subprog_info[c.subprog];

		for (kind = 0; kind < SECTION_KINDS; kind++) {
			struct bpf_resource res = { .kind = kind ? BPF_RESOURCE_PREEMPT :
							       BPF_RESOURCE_RCU };

			if (!(sub->section_counter & BIT(kind)))
				continue;
			ret = resource_intern(env, &res);
			if (ret < 0)
				return ret;
			ret = build_section_counter(b, kind, ret, sub->section_off[kind]);
			if (ret)
				return ret;
		}
	}
	return 0;
}

/*
 * A frame waiting in a call lists what it keeps in its stack from its state
 * at the call, and the callee may have written some of those slots since,
 * through a pointer into the frame's stack, see
 * bpf_frame_desc_record_stack_write(). Withdraw what the descriptors of the
 * call list at the written slots, under every chain: the resource is
 * mirrored then, as one at a location the paths disagree on is, and so are a
 * lock or IRQ flags placed there.
 */
static int slot_writes_resolve(struct bpf_verifier_env *env)
{
	struct bpf_frame_desc_build *b;
	u32 i, spi;
	int k, ret;

	for (i = 0; i < env->slot_write_cnt; i++) {
		const struct bpf_slot_write *w = &env->slot_writes[i];
		u32 call = env->frame_desc_new_of[w->call];
		int subprog = insn_subprog(env, call);

		for (b = env->insn_aux_data[call].frame_desc; b; b = b->next) {
			for (spi = w->spi_lo; spi <= w->spi_hi && spi < b->nr_slots; spi++) {
				struct bpf_frame_desc_loc *loc = &b->slots[spi];

				if (loc->state != LOC_RES && loc->state != LOC_GUARD)
					continue;
				env->frame_desc_conflicts++;
				if (env->log.level & BPF_LOG_LEVEL2)
					verbose(env, "frame_desc: insn %d: the reference obtained at insn %d is in a slot a callee writes: mirrored\n",
						w->call, loc->origin);
				withdraw(loc);
			}
			for (k = 0; k < b->nr_fixed; k++) {
				const struct bpf_frame_desc_fixed *f = &b->fixed[k];

				if (f->ent.loc != BPF_FRAME_LOC_STACK || f->origin == ACQ_NONE ||
				    -f->ent.off / BPF_REG_SIZE - 1 < w->spi_lo ||
				    -f->ent.off / BPF_REG_SIZE - 1 > w->spi_hi)
					continue;
				env->frame_desc_conflicts++;
				ret = mirror_need(env, subprog, f->origin, f->node, f->owned);
				if (ret)
					return ret;
			}
		}
	}
	return 0;
}

/* The slots of the frame that a callee of the call at @pc writes, see slot_writes_resolve(). */
static void slots_written_at(const struct bpf_verifier_env *env, u32 pc, unsigned long *written)
{
	u32 i, spi;

	bitmap_zero(written, MAX_BPF_STACK_SLOTS);
	for (i = 0; i < env->slot_write_cnt; i++) {
		const struct bpf_slot_write *w = &env->slot_writes[i];

		if (w->call != pc)
			continue;
		for (spi = w->spi_lo; spi <= w->spi_hi; spi++)
			__set_bit(spi, written);
	}
}

/*
 * Decide the guards: a location that held a resource on some visits and
 * nothing to release on others lists the resource with the scalar its digest
 * found, or is withdrawn, after which what is listed there goes to its
 * mirror, see mirror_settle(). After the transfer, which drops listings, and
 * before the mirrors are settled.
 */
static int guards_resolve(struct bpf_verifier_env *env)
{
	DECLARE_BITMAP(written, MAX_BPF_STACK_SLOTS);
	struct bpf_frame_desc_build *b;
	struct build_cursor c;
	u32 k;

	for_each_build(env, &c, b) {
		slots_written_at(env, b->pc, written);
		for (k = 0; k < BPF_REG_10 + b->nr_slots; k++) {
			struct bpf_frame_desc_loc *loc = build_loc_nth(b, k);
			const struct bpf_guard_digest *d;

			if (loc->state != LOC_GUARD)
				continue;
			d = digest_find(b, k);
			memset(&loc->guard, 0, sizeof(loc->guard));
			if (d && !b->fed_blind && guard_decide(b, d, written, &loc->guard)) {
				static const char * const ops[] = { "<", ">=", "==", "!=" };

				if (env->log.level & BPF_LOG_LEVEL2)
					verbose(env, "frame_desc: insn %d: the reference obtained at insn %d is held when %s%d %s %llu%s\n",
						b->pc, loc->origin,
						loc->guard.loc == BPF_FRAME_LOC_REG ? "R" : "fp",
						loc->guard.off, ops[loc->guard.op & ~BPF_FRAME_GUARD_32],
						loc->guard.val,
						loc->guard.op & BPF_FRAME_GUARD_32 ? " in 32 bits" : "");
				continue;
			}
			if (env->log.level & BPF_LOG_LEVEL2)
				verbose(env, "frame_desc: insn %d: no scalar of the frame tells whether the reference obtained at insn %d is held: mirrored\n",
					b->pc, loc->origin);
			withdraw(loc);
		}
		digests_free(b);
	}
	return 0;
}

/*
 * The frame that called a helper whose callback may release a reference the
 * frame holds lists it at the call, guarded, see
 * bpf_frame_desc_record_release(): it may not be released from a mirror of
 * the frame, which the release in the callback does not clear and the return
 * of the helper does not refresh, and the frame has to hold it at the call,
 * where the guard is.
 */
static int cb_release_check(struct bpf_verifier_env *env)
{
	u32 i, k;

	for (i = 0; i < env->cb_release_cnt; i++) {
		const struct bpf_cb_release *r = &env->cb_releases[i];
		const struct bpf_mirror *m = mirror_of(env, r->subprog, r->origin, r->node, r->owned);
		struct bpf_frame_desc_build *b, *head;
		bool listed = false;

		head = env->insn_aux_data[env->frame_desc_new_of[r->call]].frame_desc;
		for (b = head; b && !listed && !(m && m->needed); b = b->next) {
			/* the build of the frame's chain, or the one build left for every chain */
			if (b->node != r->node && head->next)
				continue;
			for (k = 0; k < b->nr_listed && !listed; k++) {
				const struct bpf_frame_desc_listing *l = &b->listed[k];
				const struct bpf_frame_desc_loc *loc;

				if (l->origin != r->origin || l->owned != r->owned || l->dropped ||
				    l->loc < 0)
					continue;
				loc = build_loc_nth(b, l->loc);
				listed = loc->state == LOC_RES || loc->state == LOC_GUARD;
			}
		}
		if (!listed) {
			verbose(env, "frame_desc: insn %d: the callback may release the reference obtained at insn %d, and no scalar of the frame tells on every path\n",
				r->call, r->origin);
			return -EINVAL;
		}
	}
	return 0;
}

/*
 * The sites asked for mirrors during the pass for whatever they could not
 * place, the references of the frames below included, whose listings the
 * transfer may have dropped since: a mirror that no listing that stays
 * refers to is not reserved, and not counted.
 */
static void mirror_drop_unlisted(struct bpf_verifier_env *env)
{
	struct bpf_frame_desc_build *b;
	struct build_cursor c;
	u32 i, k;

	for (i = 0; i < env->mirror_cnt; i++)
		env->mirrors[i].listed = false;
	for_each_build(env, &c, b) {
		for (k = 0; k < b->nr_listed; k++) {
			struct bpf_mirror *m;

			if (b->listed[k].dropped)
				continue;
			m = mirror_of(env, c.subprog, b->listed[k].origin, b->listed[k].node,
				      b->listed[k].owned);
			if (m)
				m->listed = true;
		}
	}
	env->mirrors_needed = 0;
	for (i = 0; i < env->mirror_cnt; i++) {
		env->mirrors[i].needed &= env->mirrors[i].listed;
		env->mirrors_needed += env->mirrors[i].needed;
	}
}

/*
 * After the main pass, once every release and every return has been seen and
 * the stack is final: merge the builds of the chains that run one under the
 * other, settle which frame lists what, decide the guards, reserve the
 * mirrors the sites need, settle what the calls do to them, merge the builds
 * of the chains that agree back into one, and list each mirror in every
 * descriptor of its subprog that lists its resource, which lists it nowhere
 * else.
 */
int bpf_frame_desc_resolve(struct bpf_verifier_env *env)
{
	struct bpf_frame_desc_build *b;
	struct build_cursor c;
	u32 i, k, len = env->prog->len;
	int ret;

	if (!env->frame_desc_visits)
		return 0;
	/* the pass named the insns of the program it verified, see bpf_frame_desc_emit() */
	for (i = 0; i < len; i++)
		env->frame_desc_orig_len = max(env->frame_desc_orig_len,
					       env->insn_aux_data[i].orig_idx + 1);
	env->frame_desc_new_of = kvcalloc(env->frame_desc_orig_len, sizeof(u32), GFP_KERNEL_ACCOUNT);
	env->frame_desc_targets = kvcalloc(env->subprog_cnt, sizeof(u16), GFP_KERNEL_ACCOUNT);
	if (!env->frame_desc_new_of || !env->frame_desc_targets)
		return -ENOMEM;
	for (i = 0; i < len; i++)
		env->frame_desc_new_of[env->insn_aux_data[i].orig_idx] = i;

	/*
	 * A loop guard the pass described, which bpf_insert_loop_guards() did
	 * not add after all: not a site, and nothing is mirrored for it.
	 */
	for (i = 0; i < len; i++) {
		bpf_frame_desc_build_destroy(env->insn_aux_data[i].guard_desc);
		env->insn_aux_data[i].guard_desc = NULL;
	}

	ret = reach_build(env);
	ret = ret ?: merge_prefix_builds(env);
	ret = ret ?: resolve_transfer(env);
	ret = ret ?: slot_writes_resolve(env);
	ret = ret ?: guards_resolve(env);
	ret = ret ?: mirror_settle(env);
	ret = ret ?: check_mirrors_sound(env);
	ret = ret ?: remerge_builds(env);
	ret = ret ?: resolve_section_counters(env);
	if (ret)
		return ret;
	mirror_drop_unlisted(env);
	ret = cb_release_check(env);
	if (ret)
		return ret;
	for (i = 0; i < env->mirror_cnt; i++) {
		struct bpf_mirror *m = &env->mirrors[i];

		if (!m->needed)
			continue;
		ret = mirror_resource(env, m);
		if (ret < 0)
			return ret;
		m->res = ret;
		/* the subprog gets it in a register at its entry: stored in front of its first insn */
		ret = 0;
		if (m->how == MIRROR_ENTRY)
			ret = mirror_store_add(m, m->subprog, MIRROR_ENTRY_STORE, m->at, 0, 0);
		else if (m->how == MIRROR_LOAD)
			ret = mirror_store_add(m, m->at, MIRROR_AFTER,
					       env->prog->insnsi[env->frame_desc_new_of[m->at]].dst_reg, 0, 0);
		ret = ret ?: mirror_resolve_calls(env, m);
		ret = ret ?: mirror_check_obtained(env, m);
		if (ret)
			return ret;
		if (!mirror_is_written(m)) {
			verbose(env, "frame_desc: the reference obtained at insn %d is held by no register the frame obtained it in\n",
				m->at);
			return -EINVAL;
		}
		ret = bpf_reserve_stack_slots(env, m->subprog, m->nr_slots, &m->off);
		if (ret) {
			verbose(env, "frame_desc: no room in the stack of subprog %d for the mirror of %d references obtained at insn %d\n",
				m->subprog, m->nr_slots, m->at);
			return ret;
		}
		for (k = 0; !ret && k < m->nr_slots; k++)
			ret = bpf_stack_slot_init(env, m->subprog, m->off - k * BPF_REG_SIZE, 0);
		if (ret)
			return ret;
	}

	/* Every descriptor, the guards the verifier adds may_goto for included. */
	for_each_build(env, &c, b) {
		for (k = 0; k < b->nr_listed; k++) {
			struct bpf_mirror *m = mirror_of(env, c.subprog, b->listed[k].origin,
							 b->listed[k].node, b->listed[k].owned);
			struct bpf_frame_desc_entry ent;

			if (b->listed[k].dropped || !m || !m->needed)
				continue;
			ent = (struct bpf_frame_desc_entry) {
				.loc = BPF_FRAME_LOC_STACK,
				.flags = BPF_FRAME_ENT_INDIRECT | BPF_FRAME_ENT_NULLABLE,
				.res = m->res, .off = m->off, .order = resource_order(env, m->res),
			};
			for (i = 0; i < m->nr_slots; i++) {
				ent.off = m->off - i * BPF_REG_SIZE;
				ret = build_mirror(b, b->listed[k].origin, ent);
				if (ret)
					return ret;
			}
		}
	}
	return 0;
}

/*
 * Insn @off is being replaced by a patch of the list, and the insn the unwinder
 * sees the site through is insn @k of the patch, not its last insn, where the
 * aux data of @off goes: the commit moves the descriptor there, see
 * bpf_frame_desc_remap_aux().
 */
int bpf_frame_desc_move_site(struct bpf_verifier_env *env, u32 off, u32 k)
{
	struct bpf_frame_desc_move *moves;
	u32 cnt = env->frame_desc_move_cnt;

	if (!env->insn_aux_data[off].frame_desc)
		return 0;
	moves = kvrealloc(env->frame_desc_moves, array_size(cnt + 1, sizeof(*moves)),
			  GFP_KERNEL_ACCOUNT);
	if (!moves)
		return -ENOMEM;
	moves[cnt] = (struct bpf_frame_desc_move) { .off = off, .k = k };
	env->frame_desc_moves = moves;
	env->frame_desc_move_cnt = cnt + 1;
	return 0;
}

/*
 * Apply the moves of bpf_frame_desc_move_site() to the aux data of the new
 * image, which the commit has put in place: the descriptor of a replaced insn
 * went to the last insn of its patch with the rest of its aux data.
 */
void bpf_frame_desc_remap_aux(struct bpf_verifier_env *env, const struct bpf_patch_image *img)
{
	struct bpf_insn_aux_data *aux = env->insn_aux_data;
	u32 i;

	for (i = 0; i < env->frame_desc_move_cnt; i++) {
		const struct bpf_frame_desc_move *m = &env->frame_desc_moves[i];
		u32 first = bpf_patch_image_remap(img, img->new_off, m->off);
		u32 last = bpf_patch_image_remap(img, img->new_off, m->off + 1) - 1;

		/* not replaced after all, or the site is at the last insn anyway */
		if (first + m->k >= last)
			continue;
		aux[first + m->k].frame_desc = aux[last].frame_desc;
		aux[last].frame_desc = NULL;
	}
	env->frame_desc_move_cnt = 0;
}

/*
 * A rewrite of insn @off keeps register @reg in the stack slot at @slot_off
 * of the frame while the unwinder may see the site: what the descriptor
 * listed in the register is listed in the slot.
 */
int bpf_frame_desc_spilled_reg(struct bpf_verifier_env *env, u32 off, int reg, s16 slot_off)
{
	struct bpf_frame_desc_build **pp, *b;
	u32 spi = -slot_off / BPF_REG_SIZE - 1;
	int k;

	/* every build of the site: the chains share the slot */
	for (pp = &env->insn_aux_data[off].frame_desc; (b = *pp); pp = &(*pp)->next) {
		for (k = 0; k < b->nr_fixed; k++) {
			struct bpf_frame_desc_entry *ent = &b->fixed[k].ent;

			if (ent->loc != BPF_FRAME_LOC_REG || ent->off != reg)
				continue;
			ent->loc = BPF_FRAME_LOC_STACK;
			ent->off = slot_off;
		}
		/* a guard reading the register reads the slot */
		for (k = 0; k < BPF_REG_10 + b->nr_slots; k++) {
			struct bpf_frame_desc_loc *loc = build_loc_nth(b, k);

			if (loc->state != LOC_GUARD || loc->guard.loc != BPF_FRAME_LOC_REG ||
			    loc->guard.off != reg)
				continue;
			loc->guard.loc = BPF_FRAME_LOC_STACK;
			loc->guard.off = slot_off;
		}
		if (b->regs[reg].state != LOC_RES && b->regs[reg].state != LOC_GUARD)
			continue;
		b = build_grow(env, off, pp, spi + 1);
		if (!b)
			return -ENOMEM;
		b->slots[spi] = b->regs[reg];
		b->regs[reg].state = LOC_OTHER;
	}
	return 0;
}

/*
 * The bpf_loop() call at insn @off is being inlined: its callback is an
 * ordinary callee now, called from insn @call of the patch, and the frame is
 * unwound through there instead of stopping at the callback. The loop keeps
 * R6, R7 and R8 in the stack slots from @r6_off up while it runs.
 */
int bpf_frame_desc_inlined_loop(struct bpf_verifier_env *env, u32 off, u32 call, s16 r6_off)
{
	int r, ret;

	if (!env->insn_aux_data[off].frame_desc)
		return 0;
	ret = bpf_frame_desc_move_site(env, off, call);
	for (r = BPF_REG_6; r <= BPF_REG_8 && !ret; r++)
		ret = bpf_frame_desc_spilled_reg(env, off, r, r6_off + (r - BPF_REG_6) * BPF_REG_SIZE);
	return ret;
}

/* What is emitted at an insn of the current image, in this order; see emit_before(). */
enum {
	EMIT_ENTRY,		/* the mirror from the register, before the subprog's first insn */
	EMIT_STORE_BEFORE,	/* the mirror from the register, in front of the insn */
	EMIT_CLEAR,		/* the mirror, in front of a release */
	EMIT_SECTION,		/* the section count, in front of a call entering or leaving one */
	EMIT_STORE_AFTER,	/* the mirror from R0, or from the register a load filled */
	EMIT_STORE_AFTER_SLOT,	/* the mirror from a stack slot */
	EMIT_CLEAR_AFTER,	/* the mirror, after a call that released it */
	EMIT_CLEAR_FAIL,	/* the mirror, after a call that failed to acquire it: R0 is not 0 */
	EMIT_SECTION_AFTER,	/* the section count, after a call whose callee changed it */
	EMIT_STORE_AFTER_FREE,	/* the first free of the slots of a mirror, from R0 */
};

struct emit_point {
	u32 insn;
	u8 kind;
	u8 reg;
	s8 delta;	/* EMIT_SECTION */
	u16 nr;		/* EMIT_STORE_AFTER_FREE: the slots */
	s16 off;	/* the mirror, or the counter */
	s16 src;	/* EMIT_STORE_AFTER_SLOT: the slot read */
	s16 adj;	/* the register points that many bytes into the object */
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
	[MIRROR_CLEAR_FAIL] = EMIT_CLEAR_FAIL,
	[MIRROR_ENTRY_STORE] = EMIT_ENTRY,
};

/* The store of the handle in @reg, which points @adj bytes into the object, into the mirror at @off. */
static int emit_store(struct bpf_insn *buf, u8 reg, s16 adj, s16 off)
{
	int cnt = 0;

	if (!adj) {
		buf[cnt++] = BPF_STX_MEM(BPF_DW, BPF_REG_FP, reg, off);
		return cnt;
	}
	buf[cnt++] = BPF_MOV64_REG(BPF_REG_AX, reg);
	buf[cnt++] = BPF_ALU64_IMM(BPF_SUB, BPF_REG_AX, adj);
	buf[cnt++] = BPF_STX_MEM(BPF_DW, BPF_REG_FP, BPF_REG_AX, off);
	return cnt;
}

/* How many insns the point @p takes, see emit_before() and emit_after(). */
static int point_cost(const struct emit_point *p, int clears)
{
	switch (p->kind) {
	case EMIT_CLEAR:
		return clears == 1 ? 1 : 4 + !!p->adj;
	case EMIT_SECTION:
	case EMIT_SECTION_AFTER:
		return 3;
	case EMIT_STORE_AFTER_SLOT:
	case EMIT_CLEAR_FAIL:
		return 2;
	case EMIT_STORE_BEFORE:
	case EMIT_STORE_AFTER:
		return p->adj ? 3 : 1;
	case EMIT_STORE_AFTER_FREE:
		return 4 * p->nr - 1;
	default:
		return 1;
	}
}

/*
 * The insns that keep the mirrors and the section counts up to date in front
 * of an insn of the current image, @n points from @p: the stores of the
 * handle a call takes, the clears of the releases, and the adjustment of a
 * count. A release insn reached with the references of several mirrored
 * origins clears the first mirror whose value is the handle released, so
 * that two references to one object count right; a release that takes the
 * node of the object compares what the mirror holds moved to the node.
 */
static int emit_before(struct bpf_insn *buf, const struct emit_point *p, int n)
{
	int i, k, cnt = 0, clears = 0, rest;

	for (i = 0; i < n; i++)
		clears += p[i].kind == EMIT_CLEAR;
	for (i = 0; i < n; i++) {
		switch (p[i].kind) {
		case EMIT_STORE_BEFORE:
			cnt += emit_store(buf + cnt, p[i].reg, p[i].adj, p[i].off);
			break;
		case EMIT_CLEAR:
			if (clears == 1) {
				buf[cnt++] = BPF_ST_MEM(BPF_DW, BPF_REG_FP, p[i].off, 0);
				break;
			}
			/* cleared: over the clears that follow, to the insn */
			for (k = i + 1, rest = 0; k < n; k++)
				rest += p[k].kind == EMIT_CLEAR ? point_cost(&p[k], clears) : 0;
			buf[cnt++] = BPF_LDX_MEM(BPF_DW, BPF_REG_AX, BPF_REG_FP, p[i].off);
			if (p[i].adj)
				buf[cnt++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_AX, p[i].adj);
			buf[cnt++] = BPF_JMP_REG(BPF_JNE, BPF_REG_AX, p[i].reg, 2);
			buf[cnt++] = BPF_ST_MEM(BPF_DW, BPF_REG_FP, p[i].off, 0);
			buf[cnt++] = BPF_JMP_A(rest);
			break;
		case EMIT_SECTION:
			buf[cnt++] = BPF_LDX_MEM(BPF_DW, BPF_REG_AX, BPF_REG_FP, p[i].off);
			buf[cnt++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_AX, p[i].delta);
			buf[cnt++] = BPF_STX_MEM(BPF_DW, BPF_REG_FP, BPF_REG_AX, p[i].off);
			break;
		}
	}
	return cnt;
}

/* The insns that refresh the mirrors after an insn, @n points from @p. */
static int emit_after(struct bpf_insn *buf, const struct emit_point *p, int n)
{
	int i, k, cnt = 0;

	for (i = 0; i < n; i++) {
		switch (p[i].kind) {
		case EMIT_STORE_AFTER:
			cnt += emit_store(buf + cnt, p[i].reg, p[i].adj, p[i].off);
			break;
		case EMIT_STORE_AFTER_SLOT:
			buf[cnt++] = BPF_LDX_MEM(BPF_DW, BPF_REG_AX, BPF_REG_FP, p[i].src);
			buf[cnt++] = BPF_STX_MEM(BPF_DW, BPF_REG_FP, BPF_REG_AX, p[i].off);
			break;
		case EMIT_CLEAR_AFTER:
			buf[cnt++] = BPF_ST_MEM(BPF_DW, BPF_REG_FP, p[i].off, 0);
			break;
		case EMIT_CLEAR_FAIL:
			buf[cnt++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 1);
			buf[cnt++] = BPF_ST_MEM(BPF_DW, BPF_REG_FP, p[i].off, 0);
			break;
		case EMIT_SECTION_AFTER:
			buf[cnt++] = BPF_LDX_MEM(BPF_DW, BPF_REG_AX, BPF_REG_FP, p[i].off);
			buf[cnt++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_AX, p[i].delta);
			buf[cnt++] = BPF_STX_MEM(BPF_DW, BPF_REG_FP, BPF_REG_AX, p[i].off);
			break;
		case EMIT_STORE_AFTER_FREE:
			/* the first slot that is 0 takes it; the rest are left alone */
			for (k = 0; k < p[i].nr; k++) {
				s16 off = p[i].off - k * BPF_REG_SIZE;
				bool last = k == p[i].nr - 1;

				buf[cnt++] = BPF_LDX_MEM(BPF_DW, BPF_REG_AX, BPF_REG_FP, off);
				buf[cnt++] = BPF_JMP_IMM(BPF_JNE, BPF_REG_AX, 0, last ? 1 : 2);
				buf[cnt++] = BPF_STX_MEM(BPF_DW, BPF_REG_FP, p[i].reg, off);
				if (!last)
					buf[cnt++] = BPF_JMP_A((p[i].nr - 1 - k) * 4 - 1);
			}
			break;
		}
	}
	return cnt;
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

/*
 * Keep the mirrors and the section counts up to date, through the patch
 * list. What goes in front of an insn is patched in with the insn, so that
 * the jumps to it land on it; what follows a call, a refresh of a mirror or
 * the change a callee made to the count, is inserted in front of the next
 * insn, which a jump to that insn skips, as it skips the call. Neither
 * moves the aux data of the call, with the descriptor of the site it may be.
 * The store of what a subprog gets at its entry is inserted in front of its
 * first insn, where the calls land and the jumps back to the insn do not,
 * after the insn that takes the frame in the stack in arena when the subprog
 * has one, and in front of the check a recursive subprog gets, whose site
 * lists the mirror, see bpf_insert_recursion_checks().
 * When unwind_goto follows a call, nothing may come between: the callee that
 * unwound returns right after the call and goes where unwind_goto says, so
 * the refresh is put on both ways out, in place of the unwind_goto.
 */
int bpf_frame_desc_emit(struct bpf_verifier_env *env)
{
	struct bpf_insn *buf = NULL, *scratch = NULL, *insn;
	struct emit_point *points;
	u32 i, k, j, n = 0, len = env->prog->len, orig_len = env->frame_desc_orig_len, room = 0;
	const u32 *new_of = env->frame_desc_new_of;
	int ret = 0, cnt, off;

	if (!env->mirrors_needed && !env->section_counters)
		return 0;
	for (i = 0; i < env->mirror_cnt; i++)
		n += env->mirrors[i].needed ? env->mirrors[i].nr_stores * env->mirrors[i].nr_slots : 0;
	n += env->section_insn_cnt;
	points = kvcalloc(n, sizeof(*points), GFP_KERNEL_ACCOUNT);
	if (!points) {
		ret = -ENOMEM;
		goto out;
	}
	for (i = 0, n = 0; i < env->mirror_cnt; i++) {
		const struct bpf_mirror *m = &env->mirrors[i];

		if (!m->needed)
			continue;
		for (k = 0; k < m->nr_stores; k++) {
			const struct bpf_mirror_store *s = &m->stores[k];
			u32 at = s->insn < orig_len ? new_of[s->insn] : len, nr = 1;
			u8 kind = mirror_emit_kind[s->point];

			/* after the insn that takes the frame in the stack in arena, if any */
			if (s->point == MIRROR_ENTRY_STORE) {
				at = env->subprog_info[s->insn].start;
				at += is_arena_sp_adj(&env->prog->insnsi[at]);
				env->subprog_info[s->insn].entry_stores++;
			}
			if (verifier_bug_if(at >= len, env, "mirror store at insn %d", s->insn)) {
				ret = -EFAULT;
				goto out;
			}
			/*
			 * A mirror of several slots: the acquisition fills the first free
			 * one, the other stores go slot by slot.
			 */
			if (m->nr_slots > 1) {
				if (s->point == MIRROR_AFTER)
					kind = EMIT_STORE_AFTER_FREE;
				else
					nr = m->nr_slots;
			}
			for (j = 0; j < nr; j++) {
				points[n++] = (struct emit_point) {
					.insn = at, .kind = kind, .reg = s->reg, .nr = m->nr_slots,
					.off = m->off - j * BPF_REG_SIZE, .src = s->off, .adj = s->adj,
				};
				/* what arrived may point into the object: compare from there */
				if (s->point == MIRROR_CLEAR)
					points[n - 1].adj -= env->resources[m->res].delta;
			}
		}
	}
	for (i = 0; i < env->section_insn_cnt; i++) {
		const struct bpf_section_insn *s = &env->section_insns[i];
		const struct bpf_subprog_info *sub = &env->subprog_info[s->subprog];

		if (!(sub->section_counter & BIT(s->kind)) || (s->after && !s->delta))
			continue;
		if (verifier_bug_if(s->insn >= orig_len, env, "section at insn %d", s->insn)) {
			ret = -EFAULT;
			goto out;
		}
		points[n++] = (struct emit_point) {
			.insn = new_of[s->insn], .kind = s->after ? EMIT_SECTION_AFTER : EMIT_SECTION,
			.delta = s->delta, .off = sub->section_off[s->kind],
		};
	}
	sort(points, n, sizeof(*points), point_cmp, NULL);
	/* room for what goes before or after any one insn, twice for the ways out of an unwind_goto */
	for (i = 0; i < n; i = k) {
		for (k = i; k < n && points[k].insn == points[i].insn; k++)
			;
		room = max_t(u32, room, 2 * points_cost(&points[i], k - i) + 4);
	}
	buf = kvcalloc(room, sizeof(*buf), GFP_KERNEL_ACCOUNT);
	scratch = kvcalloc(room, sizeof(*scratch), GFP_KERNEL_ACCOUNT);
	if (!buf || !scratch) {
		ret = -ENOMEM;
		goto out;
	}

	for (i = 0; i < n; i = k) {
		u32 idx = points[i].insn, ne = 0, nb = 0, na;

		for (k = i; k < n && points[k].insn == idx; k++) {
			ne += points[k].kind == EMIT_ENTRY;
			nb += points[k].kind > EMIT_ENTRY && points[k].kind <= EMIT_SECTION;
		}
		na = k - i - ne - nb;
		/* a call, or the load a mirror is stored after; entry stores go in front of anything */
		if (verifier_bug_if((nb || na) && !site_insn_ok(&env->prog->insnsi[idx]) &&
				    (nb || BPF_CLASS(env->prog->insnsi[idx].code) != BPF_LDX), env,
				    "mirror written at insn %d, not a call", idx)) {
			ret = -EFAULT;
			goto out;
		}
		/* the entry stores sort first, then what goes in front of the insn */
		if (ne) {
			for (cnt = 0; cnt < ne; cnt++)
				buf[cnt] = BPF_STX_MEM(BPF_DW, BPF_REG_FP, points[i + cnt].reg,
						       points[i + cnt].off);
			ret = bpf_patch_list_insert(env, idx, buf, ne);
			if (ret)
				goto out;
			env->mirror_insns += ne;
		}
		if (nb) {
			cnt = emit_before(scratch, &points[i + ne], nb);
			memcpy(buf, scratch, cnt * sizeof(*buf));
			buf[cnt++] = env->prog->insnsi[idx];
			insn = bpf_patch_list_add(env, idx, buf, cnt);
			if (IS_ERR(insn)) {
				ret = PTR_ERR(insn);
				goto out;
			}
			env->mirror_insns += cnt - 1;
		}
		if (!na)
			continue;
		cnt = emit_after(scratch, &points[i + ne + nb], na);
		if (idx + 1 < len && bpf_is_unwind_goto(&env->prog->insnsi[idx + 1])) {
			struct bpf_insn ug = env->prog->insnsi[idx + 1];

			/*
			 * The jump where unwind_goto went sits 2 * cnt + 2 insns
			 * below it: a target in front of the unwind_goto did not
			 * move with it, one behind it did.
			 */
			off = ug.off < -1 ? ug.off - (2 * cnt + 2) : ug.off;
			if (off < S16_MIN) {
				verbose(env, "frame_desc: the unwind_goto at insn %d jumps too far for the refresh of the mirrors\n",
					idx + 1);
				ret = -ERANGE;
				goto out;
			}
			buf[0] = ug;
			buf[0].off = cnt + 1;
			memcpy(buf + 1, scratch, cnt * sizeof(*buf));
			buf[cnt + 1] = BPF_JMP_A(cnt + 1);
			memcpy(buf + cnt + 2, scratch, cnt * sizeof(*buf));
			buf[2 * cnt + 2] = BPF_JMP_A(off);
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
	kvfree(buf);
	kvfree(scratch);
	kvfree(points);
	return ret;
}
