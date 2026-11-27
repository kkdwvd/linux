// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/bpf_verifier.h>
#include <linux/filter.h>
#include <linux/vmalloc.h>
#include <linux/perf_event.h>
#include <net/xdp.h>
#include "disasm.h"

#define verbose(env, fmt, args...) bpf_verifier_log_write(env, fmt, ##args)

/*
 * Matches BPF_PROBE_ATOMIC too: bpf_convert_ctx_accesses() rewrites arena
 * atomics before bpf_opt_subreg_zext_lo32_rnd_hi32() runs.
 */
static bool is_cmpxchg_insn(const struct bpf_insn *insn)
{
	return BPF_CLASS(insn->code) == BPF_STX &&
	       (BPF_MODE(insn->code) == BPF_ATOMIC ||
		BPF_MODE(insn->code) == BPF_PROBE_ATOMIC) &&
	       insn->imm == BPF_CMPXCHG;
}

/* Returns true if 'insn' is an address space cast instruction translated as BPF_ALU op */
static bool is_addr_space_cast32(struct bpf_prog *prog, const struct bpf_insn *insn)
{
	struct bpf_map *arena = (struct bpf_map *)prog->aux->arena;

	if (insn->code != (BPF_ALU64 | BPF_MOV | BPF_X) || insn->off != BPF_ADDR_SPACE_CAST)
		return false;

	/* cast from as(1) to as(0) */
	if (insn->imm == 1)
		return true;

	/* cast from as(0) to as(1) */
	if (insn->imm == 1 << 16)
		return arena && arena->map_flags & BPF_F_NO_USER_CONV;

	/* non-BPF_F_NO_USER_CONV cast from as(0) to as(1) should be handled by JIT */
	return false;
}

/*
 * The insn accesses arena through a number. JITs add the base of arena
 * to the register as it is, so the access goes through the low 32 bits of
 * the number in BPF_REG_AX. Registers of the program are not changed: the
 * number may be compared or stored later, and on another path the register
 * may be PTR_TO_ARENA.
 *
 * Constant blinding leaves insns that use BPF_REG_AX alone, so the immediate
 * of st through a number is not blinded.
 */
static int arena_scalar_access(const struct bpf_insn *insn, struct bpf_insn *buf)
{
	bool load = BPF_CLASS(insn->code) == BPF_LDX || bpf_atomic_is_load_acq(insn);
	struct bpf_insn *patch = buf;

	*patch++ = BPF_MOV32_REG(BPF_REG_AX, load ? insn->src_reg : insn->dst_reg);
	*patch = *insn;
	if (load)
		patch->src_reg = BPF_REG_AX;
	else
		patch->dst_reg = BPF_REG_AX;
	patch++;
	return patch - buf;
}

/* Return the regno defined by the insn, or -1. */
static int insn_def_regno(const struct bpf_insn *insn)
{
	switch (BPF_CLASS(insn->code)) {
	case BPF_JMP:
	case BPF_JMP32:
	case BPF_ST:
		return -1;
	case BPF_STX:
		return bpf_atomic_load_reg(insn);
	default:
		return insn->dst_reg;
	}
}

/*
 * For use only in combination with insn_def_regno() >= 0.
 * Returns TRUE if the destination register operates on 64-bit,
 * otherwise return FALSE.
 */
static bool bpf_is_reg64(struct bpf_prog *prog, struct bpf_insn *insn)
{
	u8 class = BPF_CLASS(insn->code);
	u8 mode = BPF_MODE(insn->code);
	u8 size = BPF_SIZE(insn->code);
	u8 op = BPF_OP(insn->code);
	bool mode_mem;

	/* subregister endiness swap */
	if ((class == BPF_ALU || class == BPF_ALU64) && op == BPF_END && insn->imm != 64)
		return false;

	/* w0 += 1 */
	if (class == BPF_ALU && op != BPF_END)
		return false;

	/* address space casts converted to BPF_ALU, see bpf_do_misc_fixups() */
	if (is_addr_space_cast32(prog, insn))
		return false;

	/* non 64-bit, non signed extended loads */
	mode_mem = mode == BPF_MEM || mode == BPF_PROBE_MEM || mode == BPF_PROBE_MEM32;
	if (class == BPF_LDX && mode_mem && size != BPF_DW)
		return false;

	/* atomics, see insn_def_regno() */
	if (class == BPF_STX && size != BPF_DW)
		return false;

	/* both LD_IND and LD_ABS return 32-bit data. */
	if (class == BPF_LD && (mode == BPF_IND || mode == BPF_ABS))
		return false;

	/* Conservatively return true at default. */
	return true;
}

/*
 * Return the 32-bit subregister defined by INSN, or -1 if INSN does not
 * explicitly define a 32-bit value.
 */
int bpf_insn_def32(struct bpf_prog *prog, struct bpf_insn *insn)
{
	int dst_reg = insn_def_regno(insn);

	if (dst_reg < 0 || bpf_is_reg64(prog, insn))
		return -1;

	return dst_reg;
}

const struct btf_func_model *
bpf_jit_find_kfunc_model(const struct bpf_prog *prog,
			 const struct bpf_insn *insn)
{
	const struct bpf_kfunc_desc *res;
	struct bpf_kfunc_desc_tab *tab;

	tab = prog->aux->kfunc_tab;
	if ((u16)insn->off >= tab->nr_descs)
		return NULL;

	res = &tab->descs[(u16)insn->off];
	if (bpf_jit_supports_far_kfunc_call()) {
		if (res->func_id != insn->imm)
			return NULL;
	} else if ((s32)BPF_CALL_IMM(res->addr) != insn->imm) {
		return NULL;
	}

	return &res->func_model;
}

static int add_kfunc_in_insns(struct bpf_verifier_env *env,
			      struct bpf_insn *insn, int cnt)
{
	int i, ret;

	for (i = 0; i < cnt; i++, insn++) {
		if (bpf_pseudo_kfunc_call(insn)) {
			ret = bpf_add_kfunc_call(env, insn->imm, insn->off);
			if (ret < 0)
				return ret;
		}
	}
	return 0;
}

#ifndef CONFIG_BPF_JIT_ALWAYS_ON
static int get_callee_stack_depth(struct bpf_verifier_env *env,
				  const struct bpf_insn *insn, int idx)
{
	int start = idx + insn->imm + 1, subprog;

	subprog = bpf_find_subprog(env, start);
	if (verifier_bug_if(subprog < 0, env, "get stack depth: no program at insn %d", start))
		return -EFAULT;
	return env->subprog_info[subprog].stack_depth;
}
#endif

/*
 * Queue the replacement of insn 'off' by 'patch[0..len)' until
 * bpf_patch_list_commit(), see __bpf_patch_list_add(). Replacing one insn by
 * one moves nothing and is done right away in the program, unless 'off' has a
 * queued patch: the commit takes the insn from there.
 */
struct bpf_insn *bpf_patch_list_add(struct bpf_verifier_env *env, u32 off,
				    const struct bpf_insn *patch, u32 len)
{
	struct bpf_patch_list *pl = &env->patch_list;
	struct bpf_insn_patch *p = pl->cnt ? &pl->patches[pl->cnt - 1] : NULL;

	if (bpf_must_abort())
		return ERR_PTR(-EINTR);

	if (verifier_bug_if(!len || off >= env->prog->len ||
			    (p && (off < p->off || (off == p->off && !p->len))),
			    env, "insn %u patched out of order", off))
		return ERR_PTR(-EFAULT);

	if (len == 1 && (!p || off != p->off)) {
		struct bpf_insn *insn = &env->prog->insnsi[off];

		*insn = *patch;
		env->insn_aux_data[off].zext_dst = bpf_insn_def32(env->prog, insn) >= 0;
		/*
		 * A non-memory accessing insn could have been replaced by a
		 * memory accessing insn, systematically mark it for non-stack
		 * access.
		 */
		env->insn_aux_data[off].non_stack_access = bpf_is_mem_insn(insn);
		return insn;
	}

	return __bpf_patch_list_add(pl, env->prog, off, patch, len);
}

/* Queue the removal of insn 'off' until bpf_patch_list_commit(). */
int bpf_patch_list_del(struct bpf_verifier_env *env, u32 off)
{
	struct bpf_patch_list *pl = &env->patch_list;

	if (bpf_must_abort())
		return -EINTR;

	if (verifier_bug_if(off >= env->prog->len ||
			    (pl->cnt && off <= pl->patches[pl->cnt - 1].off),
			    env, "insn %u removed out of order", off))
		return -EFAULT;

	return __bpf_patch_list_del(pl, env->prog, off);
}

static int patch_list_insert(struct bpf_verifier_env *env, u32 off,
			     const struct bpf_insn *insns, u32 cnt, bool behind)
{
	struct bpf_patch_list *pl = &env->patch_list;
	struct bpf_insn_patch *p = pl->cnt ? &pl->patches[pl->cnt - 1] : NULL;

	if (bpf_must_abort())
		return -EINTR;

	if (verifier_bug_if(!cnt || off >= env->prog->len ||
			    (p && (off < p->off || (off == p->off && !p->len))),
			    env, "insns inserted at %u out of order", off))
		return -EFAULT;

	return __bpf_patch_list_insert(pl, env->prog, off, insns, cnt, behind);
}

/* Queue insns to go in front of insn 'off', see __bpf_patch_list_insert(). */
int bpf_patch_list_insert(struct bpf_verifier_env *env, u32 off,
			  const struct bpf_insn *insns, u32 cnt)
{
	return patch_list_insert(env, off, insns, cnt, false);
}

/*
 * Queue insns to go behind insn 'off'. They are not dead code: 'off' does not fall through and
 * a jump gets to them, or it is a call and they are what the call comes back to.
 */
int bpf_patch_list_append(struct bpf_verifier_env *env, u32 off,
			  const struct bpf_insn *insns, u32 cnt)
{
	return patch_list_insert(env, off, insns, cnt, true);
}

void bpf_patch_list_free(struct bpf_verifier_env *env)
{
	bpf_patch_list_release(&env->patch_list);
}

/*
 * Fill the aux data of the 'p->len' insns at 'slot' from the aux data 'old'
 * of the insn they replace. The insns in front of p->target were inserted.
 */
static void patch_list_adj_aux(struct bpf_prog *prog, struct bpf_insn_patch *p,
			       struct bpf_insn *patch,
			       const struct bpf_insn_aux_data *old,
			       struct bpf_insn_aux_data *slot)
{
	struct bpf_insn_aux_data *last = slot + p->self;
	struct bpf_insn *orig = &p->orig;
	u32 i;

	memset(slot, 0, sizeof(*slot) * p->len);
	*last = *old;
	/* Recompute zext_dst: the last insn of the patch need not be the patched one. */
	last->zext_dst = bpf_insn_def32(prog, &patch[p->self]) >= 0;

	for (i = 0; i < p->len; i++) {
		if (i == p->self)
			continue;
		/* Expand the seen count of the patched insn to the patch. */
		slot[i].seen = last->seen ?: i > p->self;
		/* messages name the insn of the original program */
		slot[i].orig_idx = last->orig_idx;
		/* for may_goto in front of the insn, see bpf_insert_sites() */
		slot[i].live_regs_before = last->live_regs_before;
		slot[i].zext_dst = bpf_insn_def32(prog, &patch[i]) >= 0;
		/*
		 * A copy of the patched insn keeps its marking. Any other
		 * memory accessing insn is new, systematically mark it for
		 * non-stack access.
		 */
		if (i >= p->target && !memcmp(&patch[i], orig, sizeof(*orig))) {
			slot[i].non_stack_access = last->non_stack_access;
			last->non_stack_access = false;
			slot[i].fault_unwinds = last->fault_unwinds;
			last->fault_unwinds = false;
		} else if (bpf_is_mem_insn(&patch[i])) {
			slot[i].non_stack_access = true;
		}
	}

	/*
	 * The last insn could be a newly generated BPF_ST/BPF_LDX/BPF_STX,
	 * systematically mark it for non-stack access if it is not the patched
	 * insn, otherwise keep the original marking.
	 */
	if (bpf_is_mem_insn(&patch[p->self]) &&
	    memcmp(&patch[p->self], orig, sizeof(*orig)))
		last->non_stack_access = true;

	/* jumps to the replaced insn land on p->target, so the barrier goes before it */
	if (p->target != p->self) {
		slot[p->target].indirect_target = last->indirect_target;
		slot[p->target].nospec = last->nospec;
		last->indirect_target = last->nospec = 0;
	}
}

/*
 * Let go of each range of removed insns: tell the device, whose driver finds
 * them through the aux data of the old image, and free what their aux data
 * points to. The commit can't fail anymore, so there is no check for a fatal
 * signal between the calls of the driver.
 */
static void patch_list_drop_removed(struct bpf_verifier_env *env)
{
	bool offloaded = bpf_prog_is_offloaded(env->prog->aux);
	struct bpf_patch_list *pl = &env->patch_list;
	u32 k, n;

	for (k = 0; k < pl->cnt; k = n) {
		for (n = k; n < pl->cnt && !pl->patches[n].len &&
		     pl->patches[n].off == pl->patches[k].off + n - k; n++)
			;
		if (n == k) {
			n++;
			continue;
		}
		if (offloaded)
			bpf_prog_offload_remove_insns(env, pl->patches[k].off, n - k);
		bpf_clear_insn_aux_data(env, pl->patches[k].off, n - k);
	}
}

/*
 * Make room for the insns that patch_image_relax() added.
 * A jump to dead code is dead code, see bpf_opt_hard_wire_dead_code_branches().
 */
static void patch_list_relax_aux(const struct bpf_patch_image *img, struct bpf_insn_aux_data *data)
{
	const u32 *map = img->relaxed;
	u32 i, k, to;

	for (i = img->short_cnt; i--;)
		data[map[i]] = data[i];
	for (i = 0; i < img->short_cnt; i++) {
		for (k = map[i] + 1; k < map[i + 1]; k++) {
			to = k + 1 + bpf_jmp_offset(&img->insns[k]);
			data[k] = (struct bpf_insn_aux_data){
				.orig_idx = data[map[i]].orig_idx,
				.seen = data[map[i]].seen ? data[to].seen : 0,
			};
		}
	}
}

/* Fill 'data', the aux data of the new image, from the aux data of the old one. */
static void patch_list_remap_aux(struct bpf_verifier_env *env,
				 const struct bpf_patch_image *img,
				 struct bpf_insn_aux_data *data)
{
	struct bpf_patch_list *pl = &env->patch_list;
	struct bpf_insn_patch *p;
	u32 i, k, end, pos;

	for (i = 0, k = 0, pos = 0; i < img->cnt; i = end) {
		if (k < pl->cnt && pl->patches[k].off == i) {
			p = &pl->patches[k++];
			if (p->len)
				patch_list_adj_aux(env->prog, p, &pl->insns[p->start],
						   &env->insn_aux_data[i], &data[pos]);
			pos += p->len;
			end = i + 1;
			continue;
		}
		end = k < pl->cnt ? pl->patches[k].off : img->cnt;
		memcpy(data + pos, env->insn_aux_data + i, sizeof(*data) * (end - i));
		pos += end - i;
	}
	if (img->relaxed)
		patch_list_relax_aux(img, data);
	vfree(env->insn_aux_data);
	env->insn_aux_data = data;
	env->insn_aux_data_len = img->new_cnt;
}

/*
 * Whether all insns from 'off' to the end of its subprog are removed. 'info'
 * has the 'cnt' subprogs of the old image and the fake 'exit' subprog.
 */
static bool patch_list_subprog_gone(const struct bpf_subprog_info *info, u32 cnt,
				    const u32 *new_off, u32 off)
{
	u32 l = 0, r = cnt, m;

	/* find the next subprog */
	while (l < r) {
		m = (l + r) / 2;
		if (info[m].start <= off)
			l = m + 1;
		else
			r = m;
	}
	return new_off[off] == new_off[info[l].start];
}

/*
 * Remove the subprogs whose insns are all removed, with their func_info.
 */
static void patch_list_del_subprogs(struct bpf_verifier_env *env,
				    const u32 *new_off)
{
	struct bpf_subprog_info *info = env->subprog_info;
	struct bpf_prog_aux *aux = env->prog->aux;
	int i, j, exc_cb = env->exception_callback_subprog;

	for (i = 0, j = 0; i < env->subprog_cnt; i++) {
		if (new_off[info[i].start] == new_off[info[i + 1].start]) {
			/* The exception callback is live, so it isn't removed. */
			if (env->exception_callback_subprog > i)
				exc_cb--;
			continue;
		}
		if (i != j) {
			info[j] = info[i];
			if (aux->func_info)
				aux->func_info[j] = aux->func_info[i];
			if (aux->func_info_aux)
				aux->func_info_aux[j] = aux->func_info_aux[i];
		}
		j++;
	}
	if (i == j)
		return;

	/* move fake 'exit' subprog as well */
	info[j] = info[i];
	/* func_info->insn_off is set after all code rewrites, in adjust_btf_func() */
	if (aux->func_info)
		aux->func_info_cnt -= i - j;
	env->subprog_cnt = j;
	env->exception_callback_subprog = exc_cb;
}

/*
 * Subprogs, and the function pointers that name them, follow their first insn.
 * A subprog whose insns are all removed goes away, and so do the pointers to
 * it. Only the subprogs tell where a function ends, so move the pointers while
 * the subprogs still have the starts in the old image.
 */
static void patch_list_remap_subprogs(struct bpf_verifier_env *env,
				      const struct bpf_patch_image *img)
{
	struct bpf_subprog_info *info = env->subprog_info;
	u32 i;

	for (i = 0; i < env->func_ptr_cnt; i++) {
		struct bpf_func_ptr *fp = &env->func_ptrs[i];

		if (fp->xlated_off == BPF_FUNC_PTR_DELETED)
			continue;
		if (bpf_patch_image_deleted(img, fp->xlated_off) &&
		    patch_list_subprog_gone(info, env->subprog_cnt, img->new_off,
					    fp->xlated_off))
			fp->xlated_off = BPF_FUNC_PTR_DELETED;
		else
			fp->xlated_off = bpf_patch_image_remap(img, img->new_off,
							       fp->xlated_off);
	}

	if (img->del)
		patch_list_del_subprogs(env, img->new_off);

	/* NOTE: fake 'exit' subprog should be updated as well. */
	for (i = 0; i <= env->subprog_cnt; i++) {
		info[i].start = bpf_patch_image_remap(img, img->new_off, info[i].start);
		/* the program gets there like by a jump */
		if (info[i].fault_pad)
			info[i].fault_pad = bpf_patch_image_remap(img, img->new_tgt,
								  info[i].fault_pad);
		if (img->new_linfo)
			info[i].linfo_idx =
				img->new_linfo[min(info[i].linfo_idx, img->nr_linfo)];
	}
}

/*
 * Apply all queued patches and removals in one go. Everything that names an
 * insn of the old image follows it to the new one. A patched insn is named by
 * the first insn of its patch. If insns were inserted in front of an insn,
 * jumps, instruction arrays and poke descriptors name the insn itself, while
 * subprogs, line info, function pointers and calls name the first inserted
 * insn.
 *
 * An entry that names a removed insn:
 *   jump, call, poke descriptor  names the next insn that stays
 *   subprog                      too, or goes away when none of its insns stays
 *   function pointer             follows its subprog or is BPF_FUNC_PTR_DELETED
 *   line info                    goes away, but the next insn that stays takes
 *                                the last record when it has none
 *   aux data                     goes away
 *   instruction array            is INSN_DELETED
 *
 * The order of the steps is a rule:
 * 1. All that can fail: build the new image aside and allocate memory. An
 *    error leaves the program and the env as they were.
 * 2. Let go of the removed insns while all of the env describes the old image:
 *    the helpers for that look at it.
 * 3. Move each table that names insns. The new value of an entry depends on
 *    its old value and on the maps of the image only. Function pointers need
 *    the old subprogs too, see patch_list_remap_subprogs(). Between the first
 *    and the last table one part of the env describes the old image and
 *    another part the new one, so don't call a helper that reads prog->len,
 *    the insns or one of these tables from the env or the program.
 * 4. Install the new image.
 */
int bpf_patch_list_commit(struct bpf_verifier_env *env)
{
	struct bpf_patch_list *pl = &env->patch_list;
	struct bpf_insn_aux_data *data = NULL;
	struct bpf_prog *prog = env->prog;
	struct bpf_patch_image img = {};
	int err = 0;
	u32 i;

	if (!pl->cnt)
		goto out;

	err = bpf_patch_list_build(pl, prog, &img);
	if (verifier_bug_if(err == -EFAULT, env, "insn %u jumps out of the program",
			    img.bad))
		goto out;
	if (err == -E2BIG)
		verbose(env, "BPF program is too large after the rewrites: more than %lu insns\n",
			BPF_PROG_MAX_LEN);
	if (err)
		goto out;

	err = -ENOMEM;
	data = __vmalloc(array_size(img.new_cnt, sizeof(*data)),
			 BPF_VERIFIER_GFP | __GFP_ZERO);
	if (!data)
		goto out;

	prog = bpf_prog_realloc(prog, bpf_prog_size(img.new_cnt), GFP_USER | BPF_GFP_MAYFAIL);
	if (!prog)
		goto out;
	env->prog = prog;
	err = 0;

	if (img.del)
		patch_list_drop_removed(env);

	patch_list_remap_aux(env, &img, data);
	data = NULL;
	patch_list_remap_subprogs(env, &img);
	for (i = 0; i < env->insn_array_map_cnt; i++)
		bpf_insn_array_remap(env->insn_array_maps[i], img.new_off,
				     img.new_tgt, img.cnt, img.grow);

	bpf_patch_image_install(prog, &img);
out:
	vfree(data);
	bpf_patch_image_free(&img);
	bpf_patch_list_release(pl);
	return err;
}

/*
 * The insn that subprog @s leaves with at a site of @kind: kexit when the kernel unwinds it,
 * unwind_exit on the way of an unwind that the program started, if it can leave that way. The main
 * program has no kexit: the kernel called it.
 */
static struct bpf_insn unwind_exit_insn(struct bpf_verifier_env *env, int s,
					enum bpf_site_kind kind)
{
	struct bpf_subprog_info *sub = &env->subprog_info[s];
	struct bpf_insn insn = BPF_EXIT_INSN();

	if (bpf_pad_kexits(env, s, kind)) {
		insn.src_reg = BPF_KEXIT;
		sub->can_kunwind = true;
		env->prog->jit_required = 1;
	} else if (!bpf_site_is_kernel(kind) && sub->bail_unwinds) {
		insn.src_reg = BPF_UNWIND_EXIT;
		sub->can_unwind = true;
		env->prog->jit_required = 1;
	}
	return insn;
}

/*
 * How subprog @s leaves when the check of its recursion stops it, see unwind_frame(). Returns the
 * length.
 */
static int emit_unwind_exit(struct bpf_verifier_env *env, int s, struct bpf_insn *buf)
{
	int n = 0;

	buf[n++] = BPF_MOV64_IMM(BPF_REG_0, bpf_unwound_retval(env));
	/* as a landing pad does, see bpf_pad_insns() */
	if (bpf_pad_kexits(env, s, BPF_SITE_RECURSION) || bpf_ret_reg_pair(env, s))
		buf[n++] = BPF_MOV64_IMM(BPF_REG_2, 0);
	buf[n++] = unwind_exit_insn(env, s, BPF_SITE_RECURSION);
	return n;
}

/*
 * The landing pad of a site in subprog @s. The only exit of a pad is its last insn. Nothing in a
 * pad is hardened against a cpu that mispredicts: only a program that is loaded with CAP_PERFMON
 * gets one, see frame_cannot_unwind().
 * The main program returns what the exception callback makes of the value. The pad has no index
 * yet: bpf_insert_sites() sets the offset of the call. The callback is not called a second time:
 * its unwind_exit gets to the exit of the pad like its exit does, and so does its kexit.
 * unwind_goto and kgoto say so, to bpf_unwind_target() and bpf_kunwind_target(): a return address
 * in a program without an entry is a lost unwind_exit or kexit. Only a callback that can leave
 * that way gets the insn, and such a program needs a JIT that knows it already. A pad of any other
 * program is plain BPF: the interpreter and the other JITs run it.
 * bpf_mark_subprogs_that_unwind() ran, so it is known which callback that is.
 * Returns the number of insns, BPF_PAD_MAX_INSNS + 4 at most.
 */
static int emit_pad(struct bpf_verifier_env *env, int s, const struct bpf_pad_plan *plan,
		    struct bpf_insn *buf, struct bpf_insn_aux_data *aux)
{
	int cb = env->exception_callback_subprog;
	int n = 0;

	n += bpf_pad_insns(env, plan, s, buf + n, aux + n);
	if (!s && cb) {
		bool kunwinds = bpf_subprog_kunwinds(&env->subprog_info[cb]);

		buf[n++] = BPF_CALL_REL(0);
		/*
		 * Both go to the exit. kgoto is no insn to go to: where the call has code behind
		 * it, a JIT may have the way of kexit to its pad in that place, which does that
		 * code once more. So unwind_goto goes past it.
		 */
		if (env->subprog_info[cb].can_unwind)
			buf[n++] = BPF_RAW_INSN(BPF_JMP32 | BPF_JCOND, 0, BPF_UNWIND_GOTO, 0,
						kunwinds);
		if (kunwinds)
			buf[n++] = BPF_RAW_INSN(BPF_JMP32 | BPF_JCOND, 0, BPF_KGOTO, 0, 0);
	}
	buf[n++] = unwind_exit_insn(env, s, plan->kind);
	return n;
}

/*
 * Does the program leave the frame at the site of @plan, which is at insn @i? The main pass looks
 * at more sites than that, see bpf_mark_subprogs_that_unwind(). What it found at the others does
 * not count, see bpf_pads_mark_used().
 */
bool bpf_site_is_used(struct bpf_verifier_env *env, int i, const struct bpf_pad_plan *plan)
{
	int s;

	/*
	 * A frame is one that the kernel unwinds already only behind a landing pad of the program
	 * that the kernel enters: if the function has none after all, no frame of it gets here
	 * that way.
	 */
	if (bpf_site_is_forced(plan->kind) && !bpf_find_containing_subprog(env, i)->enters_kpads)
		return false;
	switch (bpf_site_base(plan->kind)) {
	case BPF_SITE_GUARD:
		return env->insn_aux_data[i].loop_guard;
	case BPF_SITE_RECURSION:
		return bpf_find_containing_subprog(env, i)->recursive;
	case BPF_SITE_THROW:
		return true;
	case BPF_SITE_CALL:
		if (!plan->visited)
			return false;
		bpf_pad_for_each_callee(plan, s)
			if (env->subprog_info[s].can_unwind)
				return true;
		return false;
	case BPF_SITE_KCALL:
	case BPF_SITE_KENTRY:
		if (!plan->visited)
			return false;
		/* the kernel unwinds what is not the program's wherever it does that */
		if (plan->external)
			return true;
		bpf_pad_for_each_callee(plan, s)
			if (env->subprog_info[s].can_kunwind)
				return true;
		return false;
	case BPF_SITE_REMAINDER:
		return plan->visited;
	case BPF_SITE_FAULT:
		return !env->insn_aux_data[i].fault_skips;
	case BPF_SITE_MAY_GOTO:
		return plan->visited && !bpf_find_containing_subprog(env, i)->stuck;
	default:
		return false;
	}
}

/*
 * The main pass looked at more ways to unwind than the program has in the end: a loop that has a
 * trip count after all has no may_goto. Find the subprogs that get kexit: those that are left at a
 * site where the kernel unwinds. And those that get unwind_exit: they have a call with no
 * unwind_goto, to which unwind_exit of the program comes back. A call is a site if it calls one of
 * them: of one kind, of the other, or of both. The main pass asks the same when a global subprog
 * unwinds, see settle_late_unwinds(). The main program leaves with exit: it is marked for
 * bpf_check_attach_target(), see bpf_insert_sites().
 * And the subprogs in which the kernel enters a landing pad of the program, 'enters_kpads': a
 * callee of that call is left with kexit. Only there a frame can get to a site, or to unwind_exit,
 * while the kernel unwinds it, and only there the plans for that count.
 */
int bpf_mark_subprogs_that_unwind(struct bpf_verifier_env *env, bool in_pass)
{
	const struct bpf_insn_aux_data *aux = env->insn_aux_data;
	const struct bpf_pad_plan *plan;
	struct bpf_subprog_info *sub;
	bool changed, unwinds, kunwinds;
	int i, k, s, err;

	for (s = 0; s < env->subprog_cnt; s++)
		env->subprog_info[s].enters_kpads = false;
	do {
		changed = false;
		/*
		 * Callees first: callx and a cycle of calls need more rounds. A pass pays for each
		 * of them. The emission repeats what the pass that is loaded has paid for.
		 */
		err = in_pass ? bpf_add_cost_and_check(env, env->prog->len, BPF_COST_SCAN) :
		      bpf_must_abort() ? -EINTR : 0;
		if (err)
			return err;
		for (k = 0; k < env->subprog_cnt; k++) {
			s = env->subprog_topo_order[k];
			sub = &env->subprog_info[s];
			for (i = sub->start; sub->has_kpads && !sub->enters_kpads &&
			     i < sub[1].start; i++) {
				plan = bpf_pad_plan(&aux[i], BPF_SITE_KENTRY);
				if (plan && bpf_site_is_used(env, i, plan))
					sub->enters_kpads = changed = true;
			}
			if ((sub->can_unwind && sub->can_kunwind) || (s && !sub->bail_unwinds))
				continue;
			unwinds = sub->can_unwind;
			kunwinds = sub->can_kunwind;
			for (i = sub->start; i < sub[1].start && !(unwinds && kunwinds); i++) {
				kunwinds |= aux[i].loop_guard ||
					    (aux[i].fault_empty && !aux[i].fault_skips);
				for (plan = aux[i].pad_plans; plan; plan = plan->next) {
					/* the frame is not left at the entry of a landing pad */
					if (plan->kind == BPF_SITE_KENTRY ||
					    !bpf_site_is_used(env, i, plan))
						continue;
					if (bpf_site_is_kernel(plan->kind))
						kunwinds = true;
					else
						unwinds = true;
				}
			}
			changed |= unwinds != sub->can_unwind || kunwinds != sub->can_kunwind;
			sub->can_unwind = unwinds;
			sub->can_kunwind = kunwinds;
		}
	} while (changed);
	return 0;
}

/* Does the site of @plan at insn @i get a landing pad after its subprog? */
static bool plan_has_pad(struct bpf_verifier_env *env, int i, const struct bpf_pad_plan *plan)
{
	/* bpf_insert_recursion_checks() emits the pad of the check */
	return bpf_site_base(plan->kind) != BPF_SITE_RECURSION && bpf_site_is_used(env, i, plan);
}

/* The plan of a site of @kind at insn @i where no state got in the pass: the empty one will do */
static struct bpf_pad_plan *unvisited_plan(struct bpf_verifier_env *env, int i,
					   enum bpf_site_kind kind)
{
	struct bpf_pad_plan *plan = bpf_pad_plan(&env->insn_aux_data[i], kind);

	if (plan)
		return plan;
	plan = bpf_pad_plan_get(env, i, kind);
	if (plan)
		plan->used = true;
	return plan;
}

/*
 * What goes after a subprog: the stubs, see collect_stubs(), then the landing pads. Their insns,
 * and where each pad ends.
 */
struct pad_buf {
	struct bpf_insn *insns;
	int *ends;
	/* the hash of its insns -> a pad that can be shared, see add_pad() */
	struct bpf_index index;
	u64 seed;
	int max_nr;	/* the room of 'ends' */
	int max_cnt;	/* the room of 'insns' */
	int nr;		/* pads */
	int cnt;	/* insns */
	int stubs;	/* those of the stubs, in front of the first pad */
};

/*
 * Make room in @pads for @n more insns. A function can have a pad at each of its sites, so the
 * buffer doubles. It keeps its memory from one function to the next.
 */
static int reserve_pad_insns(struct pad_buf *pads, int n)
{
	int max = max3(2 * pads->max_cnt, pads->cnt + n, 64);
	void *mem;

	if (pads->cnt + n <= pads->max_cnt)
		return 0;
	mem = kvrealloc(pads->insns, array_size(max, sizeof(*pads->insns)), BPF_VERIFIER_GFP);
	if (!mem)
		return -ENOMEM;
	pads->insns = mem;
	pads->max_cnt = max;
	return 0;
}

/*
 * @new, of @n insns, is one more pad of @pads. @share: unless they have one with the same insns.
 * That pad is found by the hash of the insns, not by a walk over all pads of the function. The
 * seed is random: a program cannot select pads that collide.
 * Returns where the pad starts.
 */
static int add_pad(struct pad_buf *pads, const struct bpf_insn *new, int n, bool share)
{
	int k, start = pads->stubs;
	void *mem;
	u64 key = 0;

	if (bpf_must_abort())
		return -EINTR;
	/* the first pad of a function: the index has the pads of the function before */
	if (!pads->nr) {
		kvfree(pads->index.slots);
		pads->index = (struct bpf_index){};
		pads->seed = get_random_u64();
	}
	if (share)
		key = bpf_hash64(new, n * sizeof(*new), pads->seed);
	/* pads with the same hash have keys in a row */
	for (; share && (k = bpf_index_find(&pads->index, key)) >= 0; key++) {
		const struct bpf_insn *pad = &pads->insns[k ? pads->ends[k - 1] : start];

		if (&pads->insns[pads->ends[k]] - pad == n && !memcmp(pad, new, n * sizeof(*new)))
			return pad - pads->insns;
	}
	if (pads->nr == pads->max_nr) {
		k = max(2 * pads->max_nr, 16);
		mem = kvrealloc(pads->ends, array_size(k, sizeof(*pads->ends)), BPF_VERIFIER_GFP);
		if (!mem)
			return -ENOMEM;
		pads->ends = mem;
		pads->max_nr = k;
	}
	if (reserve_pad_insns(pads, n) || (share && bpf_index_add(&pads->index, key, pads->nr)))
		return -ENOMEM;
	memcpy(&pads->insns[pads->cnt], new, n * sizeof(*new));
	start = pads->cnt;
	pads->cnt += n;
	pads->ends[pads->nr++] = pads->cnt;
	return start;
}

/*
 * A UNIT is what goes after a subprog for one kind of site at one insn. The frames that are the
 * first to unwind at the site have one plan, those that the kernel unwinds already, in a landing
 * pad of the program, have another, see BPF_SITE_FORCED. The insn has one place to go to:
 *
 *	one plan		both
 *
 *	the pad			ax = K
 *				if ax == 0 goto 1f
 *				the pad of 'forced'
 *			     1:	the pad of 'plan'
 *
 * With one plan no frame gets there in the other way, in any state of the pass. K is the hidden
 * word of the function that says which it is, see kernel/bpf/pads.c. Two pads that have the
 * same insns need no test: in a program without bpf_throw() both load the value of the kernel, and
 * they differ only where the frames hold something else. See unit_pads_are_same().
 * Two kinds have a unit that is no pad: the entry of a landing pad that the kernel enters, and
 * what stands in for unwind_exit of the program, see emit_unit().
 */
struct pad_unit {
	struct bpf_pad_plan *plan;
	struct bpf_pad_plan *forced;
};

/* The most insns that a unit has, or an entry: four per save word, see bpf_pad_kentry_insns() */
#define PAD_UNIT_MAX_INSNS	(2 * (BPF_PAD_MAX_INSNS + 4) + 3 + 4 * BPF_PAD_MAX_SAVES)

/*
 * Do the two plans of @unit have the same landing pad: the same insns, and the same type of object
 * where it frees one? Then the unit is that pad alone, with no test of K.
 * The two pads are emitted to compare them, into @buf, which has room for a unit. What a pad notes
 * about its insns goes to @scratch then, as many entries as @buf has insns: a pad that is emitted
 * for the comparison is not where the unit puts it, and what it notes must not get to the aux data
 * of the program, see bpf_insert_sites().
 */
static bool unit_pads_are_same(struct bpf_verifier_env *env, int s, const struct pad_unit *unit,
			       struct bpf_insn *buf, struct bpf_insn_aux_data *scratch)
{
	int len, other;

	if (!bpf_pad_can_be_shared(unit->plan) || !bpf_pad_can_be_shared(unit->forced))
		return false;
	len = emit_pad(env, s, unit->forced, buf, scratch);
	other = emit_pad(env, s, unit->plan, buf + len, scratch + len);
	return other == len && !memcmp(buf, buf + len, len * sizeof(*buf));
}

/* Does the insn at @i have a unit for sites of @base? If so, it is in @unit. */
static bool site_unit(struct bpf_verifier_env *env, int i, enum bpf_site_kind base,
		      struct pad_unit *unit)
{
	const struct bpf_insn_aux_data *aux = &env->insn_aux_data[i];

	unit->forced = NULL;
	unit->plan = bpf_pad_plan(aux, base);
	if (unit->plan && !plan_has_pad(env, i, unit->plan))
		unit->plan = NULL;
	if (base >= BPF_SITE_KENTRY)
		return unit->plan;
	unit->forced = bpf_pad_plan(aux, base | BPF_SITE_FORCED);
	if (unit->forced && !plan_has_pad(env, i, unit->forced))
		unit->forced = NULL;
	return unit->plan || unit->forced;
}

/*
 * The insns of @unit, of kind @base, in subprog @s.
 *
 * BPF_SITE_KENTRY, the entry of a landing pad of the program that the kernel enters. kexit of the
 * callee comes back here:
 *
 *	bpf_pad_kentry_insns()		with or without a test of K, as the plan says
 *	gotol pad			bpf_insert_sites() sets the offset
 *
 * BPF_SITE_REMAINDER, in place of unwind_exit of the program that a frame gets to while the kernel
 * unwinds it. The insn becomes a jump to this:
 *
 *	ax = K
 *	if ax == 0 goto 1f
 *	the pad of the plan		what the frame still holds, the value, kexit
 * 1:	unwind_exit
 *
 * A frame that the program unwinds gets to the same insn, with K as 0, and leaves as it did.
 *
 * @aux gets what the pads note about their insns, and only about the insns that the unit has in
 * the end: each pad is emitted once, at its place. @scratch is for unit_pads_are_same().
 * Returns the number of insns, PAD_UNIT_MAX_INSNS at most.
 */
static int emit_unit(struct bpf_verifier_env *env, int s, enum bpf_site_kind base,
		     const struct pad_unit *unit, struct bpf_insn *buf,
		     struct bpf_insn_aux_data *aux, struct bpf_insn_aux_data *scratch)
{
	int k_off = env->subprog_info[s].k_off;
	int n = 0, len;

	if (base == BPF_SITE_KENTRY) {
		n += bpf_pad_kentry_insns(env, unit->plan, s, buf + n, aux + n);
		buf[n++] = BPF_JMP32_A(0);
		return n;
	}
	if (base != BPF_SITE_REMAINDER &&
	    (!(unit->plan && unit->forced) || unit_pads_are_same(env, s, unit, buf, scratch)))
		return emit_pad(env, s, unit->plan ?: unit->forced, buf, aux);
	buf[n++] = BPF_LDX_MEM(BPF_DW, BPF_REG_AX, BPF_REG_FP, k_off);
	buf[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_AX, 0, 0);
	len = emit_pad(env, s, unit->forced ?: unit->plan, buf + n, aux + n);
	buf[n - 1].off = len;
	n += len;
	if (base == BPF_SITE_REMAINDER) {
		buf[n++] = BPF_RAW_INSN(BPF_JMP | BPF_EXIT, 0, BPF_UNWIND_EXIT, 0, 0);
		return n;
	}
	return n + emit_pad(env, s, unit->plan, buf + n, aux + n);
}

/*
 * What the insns of a unit note about themselves in their aux data, see load_handle() and
 * release_ents() in pads.c: the map of an address, the type of an object that is freed. Nothing
 * else of @to changes: it is an insn of the program already.
 */
static void copy_pad_aux(struct bpf_insn_aux_data *to, const struct bpf_insn_aux_data *from)
{
	to->map_index = from->map_index;
	to->map_off = from->map_off;
	to->kptr_struct_meta = from->kptr_struct_meta;
}

/* Units with the same insns do the same: but for an entry, which goes to its own landing pad */
static bool unit_can_be_shared(enum bpf_site_kind base, const struct pad_unit *unit)
{
	return base != BPF_SITE_KENTRY &&
	       (!unit->plan || bpf_pad_can_be_shared(unit->plan)) &&
	       (!unit->forced || bpf_pad_can_be_shared(unit->forced));
}

/*
 * The STUBS of subprog @s, the first insns of @pads. Where unwind_exit of a callee comes back to
 * a call that is not in pad code, the frame gets into a landing pad of the program by the
 * unwinding of the program: the kernel is not unwinding it, and K has to say so. See
 * bpf_find_kernel_pads() for the kinds of code. There unwind_goto of the program goes to
 *
 *	*(u64 *)(r10 - K) = 0
 *	gotol pad			bpf_insert_sites() sets the offset
 *
 * One stub per landing pad, whichever calls go to it. In a function that has K and is not mixed:
 *   - Every unwind_goto of the program whose landing pad a state got to and whose call is not in
 *     pad code gets one. Also at a call that has no plan, which calls nothing that the kernel
 *     unwinds, and at one that goes to a pad which the kernel does not enter: a typed catch gets
 *     to unwind_exit of the function too. And also where no state got to unwind_goto itself:
 *     inline_bpf_loop() copies the target of such an insn when the pad is not dead code, so that
 *     is all that is asked here.
 *   - Not behind a call in pad code. A frame that the kernel unwinds gets there, and K stays set
 *     when its callee leaves with unwind_exit: with K cleared the frame would leave as one that
 *     the program unwinds, and a landing pad above would catch what the kernel unwinds.
 * No other function gets a stub: without K nothing reads the word, and offset 0 from R10 is no
 * word of the frame.
 *
 * A stub is no unit. It has no plan and no site, and it is not found by its insns, which are the
 * same for all stubs of a function until they have their offsets. 'kstub' of unwind_goto says
 * where its stub is, or that it gets none. That is decided here, once, on the insns that
 * bpf_find_kernel_pads() looked at: what the passes that follow put into the program has no
 * 'kpad_code'.
 * Returns how many unwind_goto got a stub.
 */
static int collect_stubs(struct bpf_verifier_env *env, int s, struct pad_buf *pads)
{
	const struct bpf_subprog_info *sub = &env->subprog_info[s];
	struct bpf_insn_aux_data *aux = env->insn_aux_data;
	int i, to, users = 0, len = sub[1].start - sub->start;
	const struct bpf_insn *insn;
	/* per insn of the function: 1 + where the stub that goes there starts */
	u32 *stub_of;

	if (!sub->k_off || sub->kpads_mixed)
		return 0;
	stub_of = kvcalloc(len, sizeof(*stub_of), BPF_VERIFIER_GFP);
	if (!stub_of)
		return -ENOMEM;
	for (i = sub->start + 1; i < sub[1].start; i++) {
		insn = &env->prog->insnsi[i];
		if (!bpf_is_unwind_goto(insn))
			continue;
		to = i + 1 + bpf_jmp_offset(insn);
		if (!aux[to].seen)
			continue;
		if (aux[i - 1].kpad_code) {
			aux[i].kstub = BPF_KSTUB_NONE;
			continue;
		}
		/*
		 * The main pass has seen it for itself where a frame that the kernel unwinds took
		 * this jump: a stub there would clear K of that frame, and a landing pad above
		 * would catch what the kernel unwinds.
		 */
		if (verifier_bug_if(aux[i].kforced, env,
				    "unwind_goto at insn %d of func#%d gets a stub in pad code",
				    i, s)) {
			users = -EFAULT;
			break;
		}
		if (!stub_of[to - sub->start]) {
			if (reserve_pad_insns(pads, 2)) {
				users = -ENOMEM;
				break;
			}
			pads->insns[pads->cnt++] = BPF_ST_MEM(BPF_DW, BPF_REG_FP, sub->k_off, 0);
			pads->insns[pads->cnt++] = BPF_JMP32_A(0);
			stub_of[to - sub->start] = pads->cnt - 1;
		}
		aux[i].kstub = stub_of[to - sub->start];
		users++;
	}
	kvfree(stub_of);
	pads->stubs = pads->cnt;
	return users;
}

/*
 * The stub of unwind_goto of the program at insn @i is in the program now, where the pads of
 * subprog @s are, from insn @pads on. It goes where unwind_goto goes, also behind what the passes
 * that follow put in front of that pad. unwind_goto itself goes to the stub once the pads have
 * their gotos, see insert_unwind_gotos().
 */
static int fill_stub(struct bpf_verifier_env *env, int s, int i, int pads)
{
	const struct bpf_subprog_info *sub = &env->subprog_info[s];
	struct bpf_insn clear = BPF_ST_MEM(BPF_DW, BPF_REG_FP, sub->k_off, 0);
	u32 kstub = env->insn_aux_data[i].kstub;
	struct bpf_insn *stub;
	int at, off;

	if (!kstub || kstub == BPF_KSTUB_NONE)
		return 0;
	at = pads + kstub - 1;
	if (verifier_bug_if(!sub->k_off || sub->kpads_mixed || at + 2 > sub[1].start ||
			    !bpf_is_unwind_goto(&env->prog->insnsi[i]), env,
			    "insn %d of func#%d has a stub", i, s))
		return -EFAULT;
	stub = &env->prog->insnsi[at];
	off = i + 1 + bpf_jmp_offset(&env->prog->insnsi[i]) - (at + 2);
	/* the store, and a jump that has no offset yet or the one of this landing pad */
	if (verifier_bug_if(memcmp(stub, &clear, sizeof(clear)) ||
			    stub[1].code != (BPF_JMP32 | BPF_JA) ||
			    (stub[1].imm && stub[1].imm != off), env,
			    "the stub of insn %d is not at insn %d", i, at))
		return -EFAULT;
	stub[1].imm = off;
	return 0;
}

/*
 * The landing pads of the sites of subprog @s go after its last insn, unit by unit. Units that
 * have the same insns share them. @new and @new_aux have room for a unit: the insns are what is
 * collected, and what the pads note about them is noted again when they are in the program, see
 * bpf_insert_sites(). In front of them the stubs, see collect_stubs(): @stubbed is how many
 * unwind_goto of the program go to one. Returns the insns in @pads, which has the memory of the
 * subprog before, and their number.
 */
static int collect_pads(struct bpf_verifier_env *env, int s, struct bpf_insn *new,
			struct bpf_insn_aux_data *new_aux, struct pad_buf *pads, int *stubbed)
{
	const struct bpf_subprog_info *sub = &env->subprog_info[s];
	struct bpf_insn_aux_data *aux = env->insn_aux_data;
	struct bpf_pad_plan *plan, *shared = NULL;
	int i, n, pad, base, last = sub[1].start - 1;
	struct pad_unit unit;
	bool unwinds, forced;

	pads->nr = pads->cnt = pads->stubs = 0;
	/* the entries and what follows the landing pads of the program agree on the save words */
	n = sub->save_words ? bpf_pad_check_saves(env, s) : 0;
	if (n)
		return n;
	n = collect_stubs(env, s, pads);
	if (n < 0)
		return n;
	*stubbed = n;
	for (i = sub->start; i <= last; i++) {
		if (aux[i].pad_plans && bpf_must_abort())
			return -EINTR;
		if (aux[i].loop_guard && !unvisited_plan(env, i, BPF_SITE_GUARD))
			return -ENOMEM;
		/*
		 * Nothing is held there: the same. There are many such accesses. They get no insn,
		 * a bit in the entry that they have in the exception table tells, and the pad of
		 * the first one serves all of the function, see bpf_arena_fault().
		 * Not where a frame gets to the access while the kernel unwinds it: that one has
		 * a pad of its own, and the access gets unwind_goto to a unit of both.
		 */
		plan = bpf_pad_plan(&aux[i], BPF_SITE_FAULT | BPF_SITE_FORCED);
		forced = plan && bpf_site_is_used(env, i, plan);
		unwinds = aux[i].fault_empty && !aux[i].fault_skips;
		aux[i].fault_unwinds = unwinds && !forced;
		if (unwinds && (forced || !shared)) {
			plan = unvisited_plan(env, i, BPF_SITE_FAULT);
			if (!plan)
				return -ENOMEM;
			shared = forced ? shared : plan;
		}
		for (base = 0; aux[i].pad_plans && base <= BPF_SITE_REMAINDER; base++) {
			if (!site_unit(env, i, base, &unit))
				continue;
			/* bpf_pads_settle() skips the sites that the program does not have */
			if (verifier_bug_if((unit.plan && (!unit.plan->used || unit.plan->conflict)) ||
					    (unit.forced &&
					     (!unit.forced->used || unit.forced->conflict)), env,
					    "the landing pad of insn %d was not settled", i))
				return -EFAULT;
			/* there is no K to test, or to set */
			if (verifier_bug_if((unit.forced || base >= BPF_SITE_KENTRY) && !sub->k_off,
					    env, "func#%d has no hidden word for insn %d", s, i))
				return -EFAULT;
			/*
			 * Is this call in pad code? Asked here, on the insns that
			 * bpf_find_kernel_pads() looked at, and never again: the plan keeps the
			 * answer for when the entry is emitted the second time.
			 */
			if (base == BPF_SITE_KENTRY)
				unit.plan->untested = !sub->kpads_mixed && !aux[i].kpad_code;
			/*
			 * The main pass has seen it for itself where a frame that the kernel
			 * unwinds got to the entry: there the entry is the second one of the
			 * frame. Without a test it would replace the value and the handles that
			 * the first one kept.
			 */
			if (verifier_bug_if(base == BPF_SITE_KENTRY && unit.plan->untested &&
					    unit.plan->forced_visit, env,
					    "the entry behind insn %d of func#%d does not test K",
					    i, s))
				return -EFAULT;
			/*
			 * What reads K: a unit with a pad for the frames that the kernel unwinds,
			 * and the code in place of unwind_exit. Where the entry of the function
			 * does not clear the word, each of them has to stand in pad code: no
			 * frame gets there without a store on its way, see kernel/bpf/pads.c.
			 * An entry that tests reads K too. It is one behind a call in pad code
			 * by what makes it test, so there is nothing to ask of it here: what
			 * the main pass saw is asked above.
			 */
			if (verifier_bug_if(!bpf_subprog_clears_k(sub) && !aux[i].kpad_code &&
					    (unit.forced || base == BPF_SITE_REMAINDER),
					    env, "insn %d of func#%d reads K outside of pad code",
					    i, s))
				return -EFAULT;
			n = emit_unit(env, s, base, &unit, new, new_aux, new_aux);
			pad = add_pad(pads, new, n, unit_can_be_shared(base, &unit));
			if (pad < 0)
				return pad;
			if (unit.plan)
				unit.plan->pad = pad;
			if (unit.forced)
				unit.forced->pad = pad;
		}
	}
	return pads->cnt;
}

/*
 * Where the unit of the site of @base at insn @i starts, counted from the first insn behind its
 * subprog. -1 if the insn has none, or if it is an access to arena that goes to the pad of the
 * function, see collect_pads().
 */
static int unit_pad(struct bpf_verifier_env *env, int i, enum bpf_site_kind base)
{
	struct pad_unit unit;

	if (!site_unit(env, i, base, &unit) ||
	    (base == BPF_SITE_FAULT && env->insn_aux_data[i].fault_unwinds))
		return -1;
	return (unit.plan ?: unit.forced)->pad;
}

/*
 * unwind_goto of the program at insn @i of subprog @s: where does its stub start, counted from the
 * first insn behind the subprog? -1 in @stub if it keeps its target.
 * What collect_stubs() decided is all that is read here. But look at every unwind_goto of the
 * program once more, with or without a plan at its call. In a function that has K and is not
 * mixed, one whose landing pad is not dead code and that has no stub lets a frame into pad code
 * past the store that clears K, with the word as an earlier frame left it, unless its call is in
 * pad code. In any other function a stub would write to a word that the frame does not have, or
 * that the kernel may have set. Neither loads.
 */
static int goto_stub(struct bpf_verifier_env *env, int s, int i, int *stub)
{
	const struct bpf_subprog_info *sub = &env->subprog_info[s];
	const struct bpf_insn_aux_data *aux = env->insn_aux_data;
	bool wanted = sub->k_off && !sub->kpads_mixed;
	u32 kstub = aux[i].kstub;
	bool seen;

	seen = aux[i + 1 + bpf_jmp_offset(&env->prog->insnsi[i])].seen;
	if (verifier_bug_if(wanted ? seen && !kstub : kstub, env,
			    "unwind_goto at insn %d of func#%d has %s stub", i, s,
			    kstub ? "a" : "no"))
		return -EFAULT;
	*stub = kstub && kstub != BPF_KSTUB_NONE ? kstub - 1 : -1;
	return 0;
}

/*
 * Add unwind_goto after the calls that are sites, see check_unwound_arrival(), and after the
 * accesses to arena that are, see check_arena_site(). Nothing stands between such an insn and its
 * unwind_goto, and jumps to the insn that follows it go past unwind_goto.
 * The pads are in the program: a call that has may_goto before it would need two jumps of one
 * patch, see bpf_patch_list_jump(). @added: how many insns the pads after each subprog have.
 *
 * unwind_goto is no code, the jumps that take a conditional jump to a target that is too far for
 * 16 bits would be, see patch_image_relax(). So it has 32 bits for the offset.
 *
 * And kgoto after the calls to which what the kernel unwinds comes back. It goes behind
 * unwind_goto of the call:
 *
 *	call foo		call foo		call foo
 *	kgoto kpad		unwind_goto pad		unwind_goto P	of the program
 *				kgoto kpad		kgoto kpad
 *
 * unwind_goto of the program takes the form that has 32 bits there: a jump that is taken around
 * its target would put two insns between it and kgoto. Where no state got to that unwind_goto it
 * is dead code, and a trap is going to stand in its place, or nothing at all: kgoto goes in front
 * of it, behind the call.
 * Where the kernel enters the landing pad of the program, kgoto goes to the entry of the pad
 * instead of a pad of the verifier, see enter_kernel_pad() in verifier.c. The state that entered
 * got to unwind_goto of the program, so that is no dead code.
 *
 * And unwind_goto of the program goes to its stub, where it has one, see collect_stubs(): in the
 * form that has 32 bits too, a stub is as far as a pad. @stubbed: how many of each subprog have
 * one. All of them have to be found again here.
 */
static int insert_unwind_gotos(struct bpf_verifier_env *env, const int *added, const int *stubbed)
{
	struct bpf_insn unwind_goto = BPF_RAW_INSN(BPF_JMP32 | BPF_JCOND, 0, BPF_UNWIND_GOTO, 0, 0);
	struct bpf_insn kgoto = BPF_RAW_INSN(BPF_JMP32 | BPF_JCOND, 0, BPF_KGOTO, 0, 0);
	struct bpf_patch_list *pl = &env->patch_list;
	int i, s, pads, err, pad, kpad, stub, stubs;
	const struct bpf_subprog_info *sub;
	const struct bpf_insn_patch *p;
	struct bpf_insn *insn;
	bool seen;

	for (s = 0; s < env->subprog_cnt; s++) {
		sub = &env->subprog_info[s];
		pads = sub[1].start - added[s];
		stubs = 0;
		for (i = sub->start; added[s] && i < pads; i++) {
			/* every unwind_goto in front of the pads is one of the program still */
			insn = &env->prog->insnsi[i + 1];
			stub = -1;
			err = bpf_is_unwind_goto(insn) ? goto_stub(env, s, i + 1, &stub) : 0;
			if (err)
				return err;
			pad = kpad = -1;
			if (env->insn_aux_data[i].pad_plans) {
				pad = unit_pad(env, i, BPF_SITE_CALL);
				if (pad < 0)
					pad = unit_pad(env, i, BPF_SITE_FAULT);
				kpad = unit_pad(env, i, BPF_SITE_KENTRY);
				/* a frame that cannot unwind has no pad, any other frame enters */
				if (verifier_bug_if(kpad >= 0 &&
						    unit_pad(env, i, BPF_SITE_KCALL) >= 0, env,
						    "kgoto of insn %d has two pads", i))
					return -EFAULT;
				if (kpad < 0)
					kpad = unit_pad(env, i, BPF_SITE_KCALL);
			}
			if (pad < 0 && kpad < 0 && stub < 0)
				continue;
			if (bpf_must_abort())
				return -EINTR;
			/* a state got to unwind_goto of the program: kgoto goes behind it */
			seen = bpf_is_unwind_goto(insn) && env->insn_aux_data[i + 1].seen;
			/* the insn that follows the site may be dead code, what is appended is not */
			if (pad >= 0) {
				err = bpf_patch_list_append(env, i, &unwind_goto, 1);
				if (err)
					return err;
				/* for bpf_check_unwind_gotos() */
				env->insn_aux_data[i].unwind_goto_follows = true;
				p = &pl->patches[pl->cnt - 1];
				bpf_patch_list_jump(pl, &pl->insns[p->start + p->len - 1],
						    pads + pad, 0);
			}
			if (kpad >= 0 && !seen) {
				err = bpf_patch_list_append(env, i, &kgoto, 1);
				if (err)
					return err;
				env->insn_aux_data[i].kgoto_follows = true;
				p = &pl->patches[pl->cnt - 1];
				bpf_patch_list_jump(pl, &pl->insns[p->start + p->len - 1],
						    pads + kpad, 0);
			}
			if (stub < 0 && !(kpad >= 0 && seen))
				continue;
			/*
			 * The program has unwind_goto there: no plan for unwind_exit. It goes to
			 * its stub or where it went, in the form that has 32 bits.
			 */
			unwind_goto.imm = 0;
			insn = __bpf_patch_list_add(pl, env->prog, i + 1, &unwind_goto, 1);
			if (IS_ERR(insn))
				return PTR_ERR(insn);
			bpf_patch_list_jump(pl, insn, stub >= 0 ? pads + stub :
					    i + 2 + bpf_jmp_offset(&env->prog->insnsi[i + 1]), 0);
			stubs += stub >= 0;
			if (kpad < 0 || !seen)
				continue;
			err = bpf_patch_list_append(env, i + 1, &kgoto, 1);
			if (err)
				return err;
			p = &pl->patches[pl->cnt - 1];
			bpf_patch_list_jump(pl, &pl->insns[p->start + p->len - 1], pads + kpad, 0);
			env->insn_aux_data[i].kgoto_follows = true;
		}
		if (verifier_bug_if(stubs != stubbed[s], env,
				    "%d unwind_goto of func#%d go to a stub, %d have one",
				    stubs, s, stubbed[s]))
			return -EFAULT;
	}
	return bpf_patch_list_commit(env);
}

/*
 * may_goto of the program that is a site goes to its landing pad, see check_may_goto_site(). No
 * state took its jump: the target that the program gave it may be dead code, and this insn would be
 * taken for a jump that is never taken, see bpf_opt_hard_wire_dead_code_branches(). The loop would
 * have nothing that stops it then. So this comes before dead code is looked for, and a pad is
 * never dead code.
 * The pads are in the program: may_goto that has one of the verifier before it would need two
 * jumps of one patch, see bpf_patch_list_jump(). @added: how many insns the pads after each subprog
 * have.
 */
static int retarget_may_gotos(struct bpf_verifier_env *env, const int *added)
{
	struct bpf_patch_list *pl = &env->patch_list;
	const struct bpf_subprog_info *sub;
	struct bpf_insn *insn;
	int i, s, pad;

	for (s = 0; s < env->subprog_cnt; s++) {
		sub = &env->subprog_info[s];
		for (i = sub->start; added[s] && i < sub[1].start - added[s]; i++) {
			if (!env->insn_aux_data[i].pad_plans)
				continue;
			pad = unit_pad(env, i, BPF_SITE_MAY_GOTO);
			if (pad < 0)
				continue;
			if (bpf_must_abort())
				return -EINTR;
			/* one insn for one, but queued: the list finds the offset, however far */
			insn = __bpf_patch_list_add(pl, env->prog, i, &env->prog->insnsi[i], 1);
			if (IS_ERR(insn))
				return PTR_ERR(insn);
			bpf_patch_list_jump(pl, insn, sub[1].start - added[s] + pad, 0);
		}
	}
	return bpf_patch_list_commit(env);
}

/*
 * Add the stores that keep the hidden slots up to date, see kernel/bpf/pads.c. @buf has room for
 * BPF_PAD_MAX_SLOT_INSNS. @added: how many insns the pads after each subprog have. Only they read
 * the slots.
 * What goes before a call is patched in with the call: jumps to the call go through it. The
 * guard of the call is there already and stays in front: the frame is not left between a store and
 * its call. What follows a call is appended behind it: jumps to the next insn go past it, as they
 * go past the call. unwind_goto that the verifier adds comes later and goes between the call and
 * the store.
 * The stores at the entry are inserted before the first insn: calls get there, jumps back
 * to that insn do not. They stand after the insn that takes the frame in the stack in arena, which
 * bpf_insert_recursion_checks() expects to be the first one.
 */
static int insert_slot_stores(struct bpf_verifier_env *env, struct bpf_insn *buf, const int *added)
{
	const struct bpf_pad_note *notes[BPF_PAD_MAX_ENTS];
	const struct bpf_insn_aux_data *aux = env->insn_aux_data;
	const struct bpf_subprog_info *sub;
	const struct bpf_insn *insn, *last;
	int i, s, n, nr, call, entry, err;

	for (s = 0; s < env->subprog_cnt; s++) {
		sub = &env->subprog_info[s];
		/* a mixed function clears K where the slots are, see bpf_pad_entry_insns() */
		if ((!sub->slots && !bpf_subprog_clears_k(sub)) || !added[s])
			continue;
		nr = sub->slots ? bpf_pad_slot_notes(env, s, notes) : 0;
		if (nr < 0)
			return nr;
		entry = sub->start + is_arena_sp_adj(&env->prog->insnsi[sub->start]);
		for (i = sub->start; i < sub[1].start; i++) {
			insn = &env->prog->insnsi[i];
			/* the patches are queued in the order of the insns */
			n = 0;
			if (i == entry && i > sub->start)
				n = bpf_pad_entry_insns(sub, notes, nr, buf);
			/* nothing stands between a call and unwind_goto of the program */
			call = i - 1 - (i > sub->start && bpf_is_unwind_goto(insn - 1));
			if (call >= (int)sub->start && !bpf_is_unwind_goto(insn))
				n += bpf_pad_insns_after(sub, notes, nr, aux[call].pad_note, &buf[n]);
			err = n ? bpf_patch_list_append(env, i - 1, buf, n) : 0;
			if (err)
				return err;
			n = bpf_pad_insns_before(sub, notes, nr, aux[i].pad_note, buf);
			buf[n] = *insn;
			last = n ? bpf_patch_list_add(env, i, buf, n + 1) : NULL;
			if (IS_ERR(last))
				return PTR_ERR(last);
			n = i == entry && i == sub->start ?
			    bpf_pad_entry_insns(sub, notes, nr, buf) : 0;
			err = n ? bpf_patch_list_insert(env, i, buf, n) : 0;
			if (err)
				return err;
		}
	}
	return bpf_patch_list_commit(env);
}

/*
 * Emit what the main pass decided about the sites: may_goto before the insns that it
 * marked, see check_loop_guard(), unwind_goto after calls and after accesses to arena, a jump in
 * place of a call of bpf_throw(), the landing pads, the stores to the hidden slots that the pads
 * read, and the pad as the target of may_goto that the program has, see check_may_goto_site().
 * What a pad does it did to the states that left the frame at the site, see unwind_frame().
 *
 *	may_goto pad
 *	insn
 *	...
 *	last insn of the subprog
 * pad:	the releases
 *	r0 = bpf_unwound_retval()
 *	exit
 *
 * bpf_do_misc_fixups() keeps the address of the count of may_goto in a register that is
 * dead at the may_goto. What is live in front of the insn is live in front of its guard.
 * Nothing else is: a landing pad reads places, which are live before the insn.
 */
int bpf_insert_sites(struct bpf_verifier_env *env)
{
	struct bpf_insn unwind_goto = BPF_RAW_INSN(BPF_JMP32 | BPF_JCOND, 0, BPF_UNWIND_GOTO, 0, 0);
	struct bpf_insn patch[2] = { BPF_RAW_INSN(BPF_JMP | BPF_JCOND, 0, 0, 0, 0) };
	struct bpf_insn_aux_data *aux = env->insn_aux_data, *pad_aux, *unit_aux;
	struct bpf_insn *new, *insn;
	struct pad_buf pads = {};
	struct bpf_subprog_info *sub;
	int i, k, s, n, cnt, base, err = 0;
	struct pad_unit unit;
	int *added, *stubbed;

	/* how many insns the pads after the subprog have, and how many of its unwind_goto a stub */
	added = kvzalloc_objs(int, env->subprog_cnt, BPF_VERIFIER_GFP);
	stubbed = kvzalloc_objs(int, env->subprog_cnt, BPF_VERIFIER_GFP);
	new = kvzalloc_objs(*new, max(PAD_UNIT_MAX_INSNS, BPF_PAD_MAX_SLOT_INSNS + 1),
			    BPF_VERIFIER_GFP);
	pad_aux = kvzalloc_objs(*pad_aux, PAD_UNIT_MAX_INSNS, BPF_VERIFIER_GFP);
	unit_aux = kvzalloc_objs(*unit_aux, PAD_UNIT_MAX_INSNS, BPF_VERIFIER_GFP);
	if (!added || !stubbed || !new || !pad_aux || !unit_aux) {
		err = -ENOMEM;
		goto out;
	}
	err = bpf_mark_subprogs_that_unwind(env, false);
	if (err)
		goto out;
	env->prog->aux->can_unwind = env->subprog_info[0].can_unwind ||
				     env->subprog_info[0].can_kunwind;
	for (s = 0; s < env->subprog_cnt && !err; s++) {
		sub = &env->subprog_info[s];
		cnt = collect_pads(env, s, new, pad_aux, &pads, &stubbed[s]);
		if (cnt < 0) {
			err = cnt;
			break;
		}
		/* see emit_pad() */
		if (verifier_bug_if(cnt && !bpf_may_unwind(env), env,
				    "func#%d has landing pads without CAP_PERFMON", s)) {
			err = -EFAULT;
			break;
		}
		added[s] = cnt;
		for (i = sub->start; i < sub[1].start; i++) {
			if (aux[i].loop_guard) {
				/* A jump to itself is a back edge. It goes through may_goto too. */
				patch[1] = env->prog->insnsi[i];
				insn = bpf_patch_list_add(env, i, patch, 2);
				if (IS_ERR(insn)) {
					err = PTR_ERR(insn);
					goto out;
				}
				/* however far the pad is, see bpf_patch_list_jump() */
				bpf_patch_list_jump(&env->patch_list, insn - 1, sub[1].start,
						    cnt - unit_pad(env, i, BPF_SITE_GUARD));
			}
			if (!aux[i].kstub || aux[i].kstub == BPF_KSTUB_NONE)
				continue;
			/*
			 * unwind_goto of the program that goes to a stub takes the form that has 32
			 * bits here already. Its stub goes where the insn goes when the pads are in
			 * the program, see fill_stub(), and that has to be the landing pad itself,
			 * for every unwind_goto that shares the stub. With 16 bits it can be a jump
			 * of the insn's own instead: when a jump anywhere in the program is too
			 * far, each jump that may be too far then gets one, see
			 * patch_image_relax().
			 */
			insn = __bpf_patch_list_add(&env->patch_list, env->prog, i, &unwind_goto,
						    1);
			if (IS_ERR(insn)) {
				err = PTR_ERR(insn);
				goto out;
			}
			bpf_patch_list_jump(&env->patch_list, insn,
					    i + 1 + bpf_jmp_offset(&env->prog->insnsi[i]), 0);
		}
		if (cnt)
			err = bpf_patch_list_append(env, i - 1, pads.insns, cnt);
	}
	err = err ?: bpf_patch_list_commit(env);
	if (err)
		goto out;
	/* the insns of the pads have aux data now, and a pad is where it was appended */
	aux = env->insn_aux_data;
	for (s = 0; s < env->subprog_cnt; s++) {
		sub = &env->subprog_info[s];
		for (i = sub->start; added[s] && i < sub[1].start - added[s]; i++) {
			err = aux[i].pad_plans && bpf_must_abort() ? -EINTR :
			      fill_stub(env, s, i, sub[1].start - added[s]);
			if (err)
				goto out;
			for (base = 0; aux[i].pad_plans && base <= BPF_SITE_REMAINDER; base++) {
				if (!site_unit(env, i, base, &unit))
					continue;
				cnt = sub[1].start - added[s] + (unit.plan ?: unit.forced)->pad;
				n = emit_unit(env, s, base, &unit, new, unit_aux, pad_aux);
				/*
				 * The unit is emitted a second time, for its aux data. What stands
				 * in the program is what collect_pads() made of the same plans: an
				 * entry that tests K there and not here, or the other way round,
				 * must not load. The aux data go to the program when that is
				 * known, not before: a unit that is another one could have more
				 * insns than there are behind its place.
				 */
				if (verifier_bug_if(cnt + n > sub[1].start ||
						    memcmp(new, &env->prog->insnsi[cnt],
							   n * sizeof(*new)), env,
						    "the pad of insn %d is not the one at insn %d",
						    i, cnt)) {
					err = -EFAULT;
					goto out;
				}
				for (k = 0; k < n; k++)
					copy_pad_aux(&aux[cnt + k], &unit_aux[k]);
				memset(unit_aux, 0, n * sizeof(*unit_aux));
				insn = &env->prog->insnsi[i];
				if (base == BPF_SITE_FAULT && aux[i].fault_unwinds)
					sub->fault_pad = cnt;
				/*
				 * No call is made, see check_kfunc_call(). And unwind_exit that a
				 * frame gets to while the kernel unwinds it tests K first.
				 */
				if (base == BPF_SITE_THROW || base == BPF_SITE_REMAINDER)
					*insn = BPF_JMP32_A(cnt - i - 1);
				/*
				 * The entry goes where unwind_goto of the program goes, also
				 * behind what the passes that follow put in front of the pad.
				 */
				if (base == BPF_SITE_KENTRY)
					env->prog->insnsi[cnt + n - 1].imm =
						i + 2 + bpf_jmp_offset(insn + 1) - (cnt + n);
			}
		}
		/* the only calls of a subprog in pads, see emit_pad() */
		for (insn = &env->prog->insnsi[i]; added[s] && i < sub[1].start; i++, insn++)
			if (bpf_pseudo_call(insn))
				insn->imm = env->subprog_info[env->exception_callback_subprog].start -
					    i - 1;
	}
	err = insert_slot_stores(env, new, added);
	err = err ?: insert_unwind_gotos(env, added, stubbed);
	err = err ?: retarget_may_gotos(env, added);
out:
	kvfree(added);
	kvfree(stubbed);
	kvfree(new);
	kvfree(pad_aux);
	kvfree(unit_aux);
	kvfree(pads.insns);
	kvfree(pads.ends);
	kvfree(pads.index.slots);
	return err;
}

/*
 * if (r10 is in the upper half of the kernel stack) goto +@off
 *
 * r10 of a subprog without a private stack is an address in the kernel stack that it runs on.
 * arm64: the stacks of tasks, of interrupts and of SDEI events have THREAD_SIZE bytes and are
 * aligned to twice that size. One bit of an address tells the half.
 * x86-64: the stack for interrupts is aligned to a page only. But the cpu has the top of the stack
 * of the task and the top of its stack for interrupts. In any other stack (NMI, #DB, #MC, #DF,
 * #VC) the check fails: they have half of the size.
 * R0 has nothing at the entry of a subprog.
 */
static int emit_stack_check(struct bpf_insn *buf, int off)
{
	int n = 0;

#if defined(CONFIG_X86_64) && !defined(CONFIG_UML)
	const void __percpu *top[] = { &cpu_current_top_of_stack, &hardirq_stack_ptr };
	int i;

	static_assert(IRQ_STACK_SIZE == THREAD_SIZE);
	for (i = 0; i < 2; i++) {
		buf[n++] = BPF_MOV64_IMM(BPF_REG_0, (u32)(__force unsigned long)top[i]);
		buf[n++] = BPF_MOV64_PERCPU_REG(BPF_REG_0, BPF_REG_0);
		buf[n++] = BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_0, 0);
		buf[n++] = BPF_ALU64_REG(BPF_SUB, BPF_REG_0, BPF_REG_10);
		buf[n++] = BPF_JMP_IMM(BPF_JLT, BPF_REG_0, THREAD_SIZE / 2, i ? off : off + 5);
	}
#else
	buf[n++] = BPF_JMP_IMM(BPF_JSET, BPF_REG_10, THREAD_SIZE / 2, off);
#endif
	return n;
}

/*
 * How deep a recursion goes is not known, so it is limited at run time. In the same
 * spirit as may_goto: the program goes on for as long as there is room and takes a way
 * out that was verified when there is none.
 *
 * Every subprog on a cycle of the call graph begins with:
 *
 *	may_goto bail;
 *	if (r10 is in the upper half of the kernel stack) goto body;
 *	bpf_prog_report_recursion();
 * bail:
 *	r0 = bpf_unwound_retval();
 *	unwind_exit;
 * body:
 *
 * It is the stack as it is: whatever is there is counted, be it the callers of the prog in the
 * kernel, another prog, a trampoline or a helper that calls a callback. An invocation in
 * another stack has nothing to do with it.
 *
 * The lower half is for what is below r10: the frame of the subprog, then what it calls.
 * That is the next recursive subprog, which doesn't get past its check, or a chain of calls that
 * check_max_stack_depth() looked at together with that frame.
 *
 * A subprog that calls itself twice doesn't have to go deep to go on forever: hence may_goto.
 * Once the time slice of the invocation is over the next call unwinds the program.
 */
int bpf_insert_recursion_checks(struct bpf_verifier_env *env)
{
	struct bpf_subprog_info *si = env->subprog_info;
	struct bpf_insn buf[24], nop = BPF_JMP_A(0), *insn;
	int s, n, jmp, bail, err;
	bool found = false;

	for (s = 1; s < env->subprog_cnt; s++)
		found |= si[s].recursive;
	if (!found)
		return 0;
	env->prog->jit_required = 1;

	for (s = 1; s < env->subprog_cnt; s++) {
		if (!si[s].recursive)
			continue;
		n = 0;
		/* The exit drops the frame in the stack in arena. Take it before the check. */
		if (is_arena_sp_adj(&env->prog->insnsi[si[s].start])) {
			buf[n++] = env->prog->insnsi[si[s].start];
			/* one insn for one: done at once, the list copies the nop */
			insn = bpf_patch_list_add(env, si[s].start, &nop, 1);
			if (IS_ERR(insn))
				return PTR_ERR(insn);
		}
		jmp = n++;
		bail = emit_unwind_exit(env, s, buf + n);
		n += emit_stack_check(buf + n, 1 + bail);
		/* The arguments are not needed any more */
		buf[n++] = BPF_EMIT_KERNEL_CALL(bpf_prog_report_recursion);
		buf[jmp] = BPF_RAW_INSN(BPF_JMP | BPF_JCOND, 0, 0, n - jmp - 1, 0);
		n += emit_unwind_exit(env, s, buf + n);
		/* calls get to the check, jumps to the first insn do not */
		err = bpf_patch_list_insert(env, si[s].start, buf, n);
		if (err)
			return err;
	}
	err = bpf_patch_list_commit(env);
	if (err)
		return err;
	/* may_goto keeps the address of its count in a register that is dead: R0 */
	for (s = 1; s < env->subprog_cnt; s++) {
		if (!si[s].recursive)
			continue;
		n = si[s].start + is_arena_sp_adj(&env->prog->insnsi[si[s].start]);
		env->insn_aux_data[n].live_regs_before = (u16)~BIT(BPF_REG_0);
	}
	return 0;
}

static void free_loop(struct bpf_loop *loop)
{
	if (!loop)
		return;
	kvfree(loop->thresholds);
	kvfree(loop->iv_thresholds);
	kvfree(loop->steps);
	kvfree(loop);
}

/* Clean up dynamically allocated fields of aux data for instructions [start, ...] */
void bpf_clear_insn_aux_data(struct bpf_verifier_env *env, int start, int len)
{
	struct bpf_insn_aux_data *aux_data = env->insn_aux_data;
	int end = start + len;
	int i;

	for (i = start; i < end; i++) {
		free_loop(aux_data[i].loop);
		free_loop(aux_data[i].callback_loop);
		free_loop(aux_data[i].recursion_loop);
		aux_data[i].loop = aux_data[i].callback_loop = aux_data[i].recursion_loop = NULL;
		env->mem -= bpf_pad_plans_free(&aux_data[i]);
		env->mem -= bpf_pad_note_free(aux_data[i].pad_note);
		aux_data[i].pad_note = NULL;
	}
}

static const struct bpf_insn NOP = BPF_JMP_IMM(BPF_JA, 0, 0, 0);
static const struct bpf_insn MAY_GOTO_0 = BPF_RAW_INSN(BPF_JMP | BPF_JCOND, 0, 0, 0, 0);

bool bpf_insn_is_cond_jump(u8 code)
{
	u8 op;

	op = BPF_OP(code);
	if (BPF_CLASS(code) == BPF_JMP32)
		return op != BPF_JA;

	if (BPF_CLASS(code) != BPF_JMP)
		return false;

	return op != BPF_JA && op != BPF_EXIT && op != BPF_CALL;
}

void bpf_opt_hard_wire_dead_code_branches(struct bpf_verifier_env *env)
{
	struct bpf_insn_aux_data *aux_data = env->insn_aux_data;
	struct bpf_insn ja = BPF_JMP_IMM(BPF_JA, 0, 0, 0);
	struct bpf_insn trap = BPF_JMP_IMM(BPF_JA, 0, 0, -1);
	struct bpf_insn *insn = env->prog->insnsi;
	const int insn_cnt = env->prog->len;
	bool unwinds, calls, traps;
	int i, callee;

	for (i = 0; i < insn_cnt; i++, insn++) {
		unwinds = bpf_is_pad_goto(insn) && aux_data[i + 1 + bpf_jmp_offset(insn)].seen;
		calls = (bpf_pseudo_call(insn) || bpf_is_callx(insn)) && aux_data[i].seen;
		/*
		 * The callee never exits. Its unwind_exit needs unwind_goto all the same, and
		 * its kexit needs kgoto.
		 * The cpu predicts that it returns to what follows, or speculates to an exit.
		 * Don't let the removal of dead code put something else there.
		 * Behind a call of a subprog that does not return, see bpf_compute_might_return(),
		 * the trap stands whoever loads the program: what the pass did not go on to must
		 * not be where a return from that call gets to, should one ever get there.
		 */
		traps = calls && !env->bypass_spec_v1;
		if (calls && !traps && bpf_pseudo_call(insn)) {
			callee = bpf_find_subprog(env, i + insn->imm + 1);
			traps = callee >= 0 && !env->subprog_info[callee].might_return;
		}
		/* a call that does not return may end the program, see check_final_calls() */
		if ((unwinds || traps) && i + 1 < insn_cnt && !aux_data[i + 1].seen) {
			memcpy(insn + 1, &trap, sizeof(trap));
			aux_data[i + 1].zext_dst = false;
			aux_data[i + 1].seen = env->check_cnt;
		}
		if (unwinds || !aux_data[i].seen || !bpf_insn_is_cond_jump(insn->code))
			continue;

		/* unwind_goto of the program that kgoto follows has its offset in imm */
		if (!aux_data[i + 1].seen)
			ja.off = insn->off;
		else if (!aux_data[i + 1 + bpf_jmp_offset(insn)].seen)
			ja.off = 0;
		else
			continue;

		if (bpf_prog_is_offloaded(env->prog->aux))
			bpf_prog_offload_replace_insn(env, i, &ja);

		/* If both edges are dead, no run gets here. The driver keeps the old target. */
		if (!aux_data[i + 1 + ja.off].seen)
			ja.off = -1;
		memcpy(insn, &ja, sizeof(ja));
	}
}

/*
 * The address of a function might be taken by the code that is not dead,
 * while the function itself is dead code, since nothing calls it. Keep the first
 * instruction of such function, so that the address remains valid and differs
 * from the addresses of other functions. Make it a trap like
 * sanitize_dead_code() does.
 */
static void keep_funcs_with_addr_taken(struct bpf_verifier_env *env)
{
	struct bpf_insn_aux_data *aux_data = env->insn_aux_data;
	struct bpf_insn trap = BPF_JMP_IMM(BPF_JA, 0, 0, -1);
	struct bpf_insn *insn = env->prog->insnsi;
	int insn_cnt = env->prog->len;
	int i, t;

	for (i = 0; i < insn_cnt; i++) {
		if (!aux_data[i].seen || !bpf_pseudo_func(insn + i))
			continue;
		t = i + insn[i].imm + 1;
		if (aux_data[t].seen)
			continue;
		memcpy(insn + t, &trap, sizeof(trap));
		aux_data[t].zext_dst = false;
		aux_data[t].seen = env->check_cnt;
	}
}

int bpf_opt_remove_dead_code(struct bpf_verifier_env *env)
{
	struct bpf_insn_aux_data *aux_data = env->insn_aux_data;
	int insn_cnt = env->prog->len;
	int i, err;

	keep_funcs_with_addr_taken(env);

	for (i = 0; i < insn_cnt; i++) {
		if (aux_data[i].seen)
			continue;
		err = bpf_patch_list_del(env, i);
		if (err)
			return err;
	}

	return bpf_patch_list_commit(env);
}

/*
 * Whether insn i is a nop once the insns between it and 'next' are gone: "ja"
 * or may_goto that goes to 'next' at most.
 */
static bool insn_is_nop(struct bpf_verifier_env *env, int i, int next)
{
	struct bpf_insn insn = env->prog->insnsi[i];

	/* keep a nospec insn, the barrier in front of it must stay */
	if (env->insn_aux_data[i].indirect_target || env->insn_aux_data[i].nospec)
		return false;
	if (insn.off < 0 || i + 1 + insn.off > next)
		return false;
	insn.off = 0;

	return !memcmp(&insn, &NOP, sizeof(NOP)) ||
	       !memcmp(&insn, &MAY_GOTO_0, sizeof(MAY_GOTO_0));
}

/*
 * addr_space_cast of a register into itself is removed if what the main pass finds there is a
 * pointer that is not in arena, see bpf_lower_cast_mov()
 */
static bool cast_may_be_nop(const struct bpf_insn *insn)
{
	return insn->code == (BPF_ALU64 | BPF_MOV | BPF_X) &&
	       insn->off == BPF_ADDR_SPACE_CAST && insn->dst_reg == insn->src_reg;
}

/*
 * may_goto that jumps over nothing, or over nothing but insns like itself, does nothing:
 * bpf_opt_remove_nops() removes it. clang makes such insns of a loop with can_loop that it unrolls.
 * The main pass is told now, see check_may_goto_site(): they are no sites.
 * A cast that may be removed counts as nothing too. If it stays, so does may_goto that jumps over
 * it, and it jumps where the program says: no site is always right, it is what the insn was before
 * the verifier unwound programs.
 */
void bpf_mark_may_goto_nops(struct bpf_verifier_env *env)
{
	struct bpf_insn *insns = env->prog->insnsi, insn;
	int i, next;

	for (i = env->prog->len - 1, next = env->prog->len; i >= 0; i--) {
		if (cast_may_be_nop(&insns[i]))
			continue;
		insn = insns[i];
		insn.off = 0;
		if (insns[i].off < 0 || i + 1 + insns[i].off > next ||
		    (memcmp(&insn, &NOP, sizeof(NOP)) && memcmp(&insn, &MAY_GOTO_0, sizeof(insn))))
			next = i;
		else
			env->insn_aux_data[i].may_goto_nop = bpf_is_may_goto_insn(&insn);
	}
}

/* addr_space_cast of a pointer that is not in arena is a move, see is_cast_mov() */
void bpf_lower_cast_mov(struct bpf_verifier_env *env)
{
	struct bpf_insn_aux_data *aux = env->insn_aux_data;
	struct bpf_insn *insn = env->prog->insnsi;
	int i;

	for (i = 0; i < env->prog->len; i++, insn++) {
		if (!aux[i].cast_mov)
			continue;
		/* an address in arena has 32 bits, this pointer has 64 */
		aux[i].zext_dst = false;
		if (insn->dst_reg == insn->src_reg)
			/* bpf_opt_remove_nops() removes it */
			*insn = NOP;
		else
			*insn = BPF_MOV64_REG(insn->dst_reg, insn->src_reg);
	}
}

/*
 * Make BPF_REG_ARENA_SP work. It holds the low 32 bits of the address, which is
 * what JITs add to the base of arena.
 *  - the main program takes a stack when it starts and returns it when it exits:
 *    the stack of the cpu when it's free, without a call.
 *    See struct bpf_arena_cpu_stack. So does a callback.
 *  - a function that has a frame drops it before exit.
 *  - 'rX = r12' gives the address like user space sees it, as other addresses
 *    in arena are.
 * It's done before bpf_convert_ctx_accesses(), so that this code is a part of the
 * program for gen_prologue() and gen_epilogue(). The prologue runs before the
 * program takes a stack. The epilogue runs after each exit, also when there is
 * no stack and the program is skipped.
 */

#define CPU_STACK_OFF(field) offsetof(struct bpf_arena_cpu_stack, field)

/* reg = this_cpu_ptr(stacks) */
static struct bpf_insn *emit_arena_stack_percpu(struct bpf_verifier_env *env,
						struct bpf_insn *patch, int reg)
{
	struct bpf_insn ld_stacks[2] = {
		BPF_LD_IMM64(reg, (__force long)bpf_arena_stack_percpu(env->prog->aux->arena))
	};

	*patch++ = ld_stacks[0];
	*patch++ = ld_stacks[1];
	*patch++ = BPF_MOV64_PERCPU_REG(reg, reg);
	return patch;
}

/*
 * Take a stack at the start of the main program or of a callback.
 *
 *	cnt = busy++;
 *	if (!cnt)
 *		goto free;
 * slow:
 *	r12 = bpf_arena_stack_get(aux, cnt);
 *	if (r12)
 *		goto done;
 *	return 0;
 * free:
 *	if (size < what the program needs)
 *		goto slow;
 *	r12 = base;
 * done:
 *
 * r0 and r6-r9 are not initialized when a function starts. Neither are r2-r5 in
 * the main program. A callback has arguments there.
 */
static int insert_arena_stack_get(struct bpf_verifier_env *env, int s)
{
	struct bpf_insn ld_aux[2] = { BPF_LD_IMM64(BPF_REG_1, (long)env->prog->aux) };
	int local = bpf_jit_supports_local_atomics() ? BPF_ATOMIC_LOCAL : 0;
	int ptr = s ? BPF_REG_6 : BPF_REG_2, cnt = s ? BPF_REG_7 : BPF_REG_3;
	int size = s ? BPF_REG_8 : BPF_REG_4;
	struct bpf_subprog_info *sub = &env->subprog_info[s];
	struct bpf_insn *buf = env->insn_buf, *patch;
	int jfree, jdone, jslow, slow, free, done, i;

	/* the arguments wait in the frame, nothing is there yet */
	if (s)
		sub->stack_depth = max(sub->stack_depth, MAX_BPF_FUNC_REG_ARGS * BPF_REG_SIZE);

	patch = emit_arena_stack_percpu(env, buf, ptr);
	*patch++ = BPF_MOV32_IMM(cnt, 1);
	*patch++ = BPF_ATOMIC_OP(BPF_DW, BPF_ADD | BPF_FETCH | local, ptr, cnt,
				 CPU_STACK_OFF(busy));
	jfree = patch++ - buf;
	slow = patch - buf;
	if (!s)
		*patch++ = BPF_MOV64_REG(BPF_REG_6, BPF_REG_1);
	for (i = BPF_REG_1; s && i <= BPF_REG_5; i++)
		*patch++ = BPF_STX_MEM(BPF_DW, BPF_REG_FP, i, -i * BPF_REG_SIZE);
	*patch++ = ld_aux[0];
	*patch++ = ld_aux[1];
	*patch++ = BPF_MOV64_REG(BPF_REG_2, cnt);
	*patch++ = BPF_EMIT_KERNEL_CALL(bpf_arena_stack_get);
	*patch++ = BPF_MOV32_REG(BPF_REG_ARENA_SP, BPF_REG_0);
	if (!s)
		*patch++ = BPF_MOV64_REG(BPF_REG_1, BPF_REG_6);
	for (i = BPF_REG_1; s && i <= BPF_REG_5; i++)
		*patch++ = BPF_LDX_MEM(BPF_DW, i, BPF_REG_FP, -i * BPF_REG_SIZE);
	jdone = patch++ - buf;
	*patch++ = BPF_MOV64_IMM(BPF_REG_0, 0);
	*patch++ = BPF_EXIT_INSN();
	free = patch - buf;
	*patch++ = BPF_LDX_MEM(BPF_W, size, ptr, CPU_STACK_OFF(size));
	jslow = patch++ - buf;
	*patch++ = BPF_LDX_MEM(BPF_W, BPF_REG_ARENA_SP, ptr, CPU_STACK_OFF(base));
	done = patch - buf;

	buf[jfree] = BPF_JMP_IMM(BPF_JEQ, cnt, 0, free - jfree - 1);
	buf[jdone] = BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, done - jdone - 1);
	/* size is 0 until the stack is allocated */
	buf[jslow] = BPF_JMP32_IMM(BPF_JLT, size, max(env->max_arena_stack_depth, 1),
				   slow - jslow - 1);

	/* a jump to the first insn doesn't take the stack again, neither does gotox */
	return bpf_patch_list_insert(env, sub->start, buf, done);
}

int bpf_insert_arena_stack(struct bpf_verifier_env *env)
{
	struct bpf_map *arena = (struct bpf_map *)env->prog->aux->arena;
	struct bpf_subprog_info *subprogs = env->subprog_info;
	struct bpf_insn *insn_buf = env->insn_buf, *patch, *insn;
	struct bpf_prog_aux *aux = env->prog->aux;
	struct bpf_insn ld_aux[2] = { BPF_LD_IMM64(BPF_REG_1, (long)aux) };
	int i, cur = 0, err, reg;

	if (!env->uses_arena_sp)
		return 0;

	/*
	 * With spare bytes r12 is neither the start nor the end of the stack,
	 * which may be at 0, so 'rX = r12' is not NULL.
	 */
	aux->arena_stack_size = round_up(env->max_arena_stack_depth + 64, PAGE_SIZE);

	for (i = 0; i < env->prog->len; i++) {
		insn = env->prog->insnsi + i;
		if (subprogs[cur + 1].start == i)
			cur++;
		patch = insn_buf;

		if (is_arena_sp_adj(insn)) {
			insn->code = BPF_ALU | BPF_ADD | BPF_K;
			env->insn_aux_data[i].zext_dst = true;
		} else if (is_arena_sp_mov(insn)) {
			/* rX = addr_space_cast(r12, 1, 0) */
			if (!(arena->map_flags & BPF_F_NO_USER_CONV)) {
				insn->off = BPF_ADDR_SPACE_CAST;
				insn->imm = 1 << 16;
			}
		} else if (insn->code == (BPF_JMP | BPF_EXIT)) {
			if (subprogs[cur].arena_stack_depth)
				*patch++ = BPF_ALU32_IMM(BPF_ADD, BPF_REG_ARENA_SP,
							 -(int)subprogs[cur].arena_stack_depth);
			if (!cur || subprogs[cur].arena_stack_entry) {
				/*
				 * r1-r5 are free. But for R2 in front of kexit, which is 0
				 * there, see bpf_pad_insns(): it stays 0 on both ways.
				 */
				reg = bpf_is_kexit(insn) ? BPF_REG_1 : BPF_REG_2;
				*patch++ = BPF_JMP32_IMM(BPF_JSET, BPF_REG_ARENA_SP,
							 BPF_ARENA_STACK_SLOW, 5);
				patch = emit_arena_stack_percpu(env, patch, reg);
				*patch++ = BPF_ST_MEM(BPF_DW, reg, CPU_STACK_OFF(busy), 0);
				*patch++ = *insn;
				*patch++ = BPF_MOV64_REG(BPF_REG_6, BPF_REG_0);
				*patch++ = ld_aux[0];
				*patch++ = ld_aux[1];
				*patch++ = BPF_MOV64_REG(BPF_REG_2, BPF_REG_ARENA_SP);
				*patch++ = BPF_EMIT_KERNEL_CALL(bpf_arena_stack_put);
				*patch++ = BPF_MOV64_REG(BPF_REG_0, BPF_REG_6);
				if (bpf_is_kexit(insn))
					*patch++ = BPF_MOV64_IMM(BPF_REG_2, 0);
			}
			if (patch != insn_buf)
				*patch++ = *insn;
		}

		if (patch != insn_buf) {
			insn = bpf_patch_list_add(env, i, insn_buf, patch - insn_buf);
			if (IS_ERR(insn))
				return PTR_ERR(insn);
		}
		/* Not before the insn is rewritten: the list takes a copy of it. */
		if (subprogs[cur].start == i && (!cur || subprogs[cur].arena_stack_entry)) {
			err = insert_arena_stack_get(env, cur);
			if (err)
				return err;
		}
	}
	return bpf_patch_list_commit(env);
}

int bpf_opt_remove_nops(struct bpf_verifier_env *env)
{
	int insn_cnt = env->prog->len;
	unsigned long *removed;
	int i, next, err = 0;

	removed = kvcalloc(BITS_TO_LONGS(insn_cnt), sizeof(long), BPF_VERIFIER_GFP);
	if (!removed)
		return -ENOMEM;

	/*
	 * Removing may_goto +0 turns the may_goto +1 in front of it into
	 * another one. Only a forward jump can turn into a nop, so walk from
	 * the end: all that insn i jumps over is decided when the walk gets to
	 * it. 'next' is the first insn behind i that stays. For a forward jump
	 * it is in the subprog of i, because a subprog doesn't end with one.
	 */
	for (i = insn_cnt - 1, next = insn_cnt; i >= 0; i--) {
		if (insn_is_nop(env, i, next))
			__set_bit(i, removed);
		else
			next = i;
	}

	for_each_set_bit(i, removed, insn_cnt) {
		err = bpf_patch_list_del(env, i);
		if (err)
			break;
	}
	kvfree(removed);

	return err ?: bpf_patch_list_commit(env);
}

int bpf_opt_subreg_zext_lo32_rnd_hi32(struct bpf_verifier_env *env,
					 const union bpf_attr *attr)
{
	struct bpf_insn *patch;
	/* use env->insn_buf as two independent buffers */
	struct bpf_insn *zext_patch = env->insn_buf;
	struct bpf_insn *rnd_hi32_patch = &env->insn_buf[2];
	struct bpf_insn_aux_data *aux = env->insn_aux_data;
	int i, err, patch_len, gotos, len = env->prog->len;
	struct bpf_insn *insns = env->prog->insnsi;
	bool rnd_hi32;

	rnd_hi32 = attr->prog_flags & BPF_F_TEST_RND_HI32;
	zext_patch[1] = BPF_ZEXT_REG(0);
	rnd_hi32_patch[1] = BPF_ALU64_IMM(BPF_MOV, BPF_REG_AX, 0);
	rnd_hi32_patch[2] = BPF_ALU64_IMM(BPF_LSH, BPF_REG_AX, 32);
	rnd_hi32_patch[3] = BPF_ALU64_REG(BPF_OR, 0, BPF_REG_AX);
	for (i = 0; i < len; i++) {
		struct bpf_insn insn;
		int load_reg;

		insn = insns[i];
		load_reg = insn_def_regno(&insn);
		if (!aux[i].zext_dst) {
			u8 code, class;
			u32 imm_rnd;

			if (!rnd_hi32)
				continue;

			code = insn.code;
			class = BPF_CLASS(code);
			if (load_reg == -1)
				continue;

			if (bpf_is_reg64(env->prog, &insn)) {
				if (class == BPF_LD &&
				    BPF_MODE(code) == BPF_IMM)
					i++;
				continue;
			}

			/* ctx load could be transformed into wider load. */
			if (class == BPF_LDX &&
			    aux[i].ptr_type == PTR_TO_CTX)
				continue;

			imm_rnd = get_random_u32();
			rnd_hi32_patch[0] = insn;
			rnd_hi32_patch[1].imm = imm_rnd;
			rnd_hi32_patch[3].dst_reg = load_reg;
			patch = rnd_hi32_patch;
			patch_len = 4;
			goto apply_patch_buffer;
		}

		/* Add in an zero-extend instruction if a) the JIT has requested
		 * it or b) it's a CMPXCHG.
		 *
		 * The latter is because: BPF_CMPXCHG always loads a value into
		 * R0, therefore always zero-extends. However some archs'
		 * equivalent instruction only does this load when the
		 * comparison is successful. This detail of CMPXCHG is
		 * orthogonal to the general zero-extension behaviour of the
		 * CPU, so it's treated independently of bpf_jit_needs_zext.
		 */
		if (!bpf_jit_needs_zext() && !is_cmpxchg_insn(&insn))
			continue;

		/* Zero-extension is done by the caller. */
		if (bpf_pseudo_kfunc_call(&insn))
			continue;

		if (verifier_bug_if(load_reg == -1, env,
				    "zext_dst is set, but no reg is defined"))
			return -EFAULT;

		zext_patch[0] = insn;
		zext_patch[1].dst_reg = load_reg;
		zext_patch[1].src_reg = load_reg;
		patch = zext_patch;
		patch_len = 2;
apply_patch_buffer:
		/*
		 * Nothing stands between an insn and its unwind_goto and kgoto. On the way to
		 * the landing pad the insn has not written the register.
		 */
		gotos = bpf_is_pad_goto(&insns[i + 1]);
		gotos += gotos && bpf_is_pad_goto(&insns[i + 2]);
		if (gotos) {
			err = bpf_patch_list_insert(env, i + 1 + gotos, patch + 1, patch_len - 1);
			if (err)
				return err;
			continue;
		}
		patch = bpf_patch_list_add(env, i, patch, patch_len);
		if (IS_ERR(patch))
			return PTR_ERR(patch);
	}

	return bpf_patch_list_commit(env);
}

/* convert load instructions that access fields of a context type into a
 * sequence of instructions that access fields of the underlying structure:
 *     struct __sk_buff    -> struct sk_buff
 *     struct bpf_sock_ops -> struct sock
 */
/*
 * A load through an __arena pointer member of a kernel struct reads the kernel
 * address of arena memory. Append the conversion to the arena pointer form,
 * (u32)(kaddr - kern_vm_start), that the struct_ops trampoline applies to
 * __arena arguments. A __nullable member keeps NULL as NULL, tested on the
 * full kernel address, and so does a probed load, which reads as 0 when it
 * faults. Returns the number of insns in @buf, 0 when the insn loads no such
 * member.
 */
static int arena_member_fixup(struct bpf_verifier_env *env, int idx, struct bpf_insn *insn,
			      struct bpf_insn *buf)
{
	struct bpf_insn_aux_data *aux = &env->insn_aux_data[idx];
	int cnt = 0;
	u32 base;

	if (!aux->arena_member)
		return 0;

	base = bpf_arena_get_kern_vm_start(env->prog->aux->arena);
	buf[cnt++] = *insn;
	if (aux->arena_member_nullable || BPF_MODE(insn->code) == BPF_PROBE_MEM)
		buf[cnt++] = BPF_JMP_IMM(BPF_JEQ, insn->dst_reg, 0, 1);
	buf[cnt++] = BPF_ALU32_IMM(BPF_SUB, insn->dst_reg, (s32)base);
	return cnt;
}

int bpf_convert_ctx_accesses(struct bpf_verifier_env *env)
{
	struct bpf_subprog_info *subprogs = env->subprog_info;
	const struct bpf_verifier_ops *ops = env->ops;
	int i, cnt, size, ctx_field_size, ret, epilogue_cnt = 0, first = 0;
	struct bpf_insn *epilogue_buf = env->epilogue_buf;
	struct bpf_insn *insn_buf = env->insn_buf;
	struct bpf_insn *insn;
	u32 target_size, size_default, off;
	enum bpf_access_type type;
	bool is_narrower_load;
	int epilogue_idx = 0;

	if (ops->gen_epilogue) {
		epilogue_cnt = ops->gen_epilogue(epilogue_buf, env->prog,
						 -(subprogs[0].stack_depth + 8));
		if (epilogue_cnt >= INSN_BUF_SIZE) {
			verifier_bug(env, "epilogue is too long");
			return -EFAULT;
		} else if (epilogue_cnt) {
			/* Save the ARG_PTR_TO_CTX for the epilogue to use */
			subprogs[0].stack_depth += 8;
			insn_buf[0] = BPF_STX_MEM(BPF_DW, BPF_REG_FP, BPF_REG_1,
						  -subprogs[0].stack_depth);
			ret = bpf_patch_list_insert(env, 0, insn_buf, 1);
			if (ret)
				return ret;
			first++;

			ret = add_kfunc_in_insns(env, epilogue_buf, epilogue_cnt - 1);
			if (ret < 0)
				return ret;
		}
	}

	if (ops->gen_prologue || env->seen_direct_write) {
		if (!ops->gen_prologue) {
			verifier_bug(env, "gen_prologue is null");
			return -EFAULT;
		}
		cnt = ops->gen_prologue(insn_buf, env->seen_direct_write,
					env->prog);
		if (cnt >= INSN_BUF_SIZE) {
			verifier_bug(env, "prologue is too long");
			return -EFAULT;
		} else if (cnt) {
			env->prog->aux->has_prologue = true;
			/* the prologue ends with the first insn of the program */
			if (verifier_bug_if(memcmp(&insn_buf[cnt - 1], env->prog->insnsi,
						   sizeof(*insn_buf)), env,
					    "prologue doesn't end with the first insn"))
				return -EFAULT;
			ret = bpf_patch_list_insert(env, 0, insn_buf, cnt - 1);
			if (ret)
				return ret;
			first += cnt - 1;

			ret = add_kfunc_in_insns(env, insn_buf, cnt - 1);
			if (ret < 0)
				return ret;
		}
	}

	/*
	 * The loop below rewrites some insns in place. No insn may have a queued
	 * patch when the loop gets to it: the list holds a copy of the insn.
	 */
	ret = bpf_patch_list_commit(env);
	if (ret)
		return ret;

	if (bpf_prog_is_offloaded(env->prog->aux))
		return 0;

	for (i = first; i < env->prog->len; i++) {
		bpf_convert_ctx_access_t convert_ctx_access;
		enum bpf_reg_type ptr_type;
		u8 mode;

		insn = &env->prog->insnsi[i];

		if (env->insn_aux_data[i].nospec) {
			WARN_ON_ONCE(env->insn_aux_data[i].alu_state);
			struct bpf_insn *patch = insn_buf;

			*patch++ = BPF_ST_NOSPEC();
			*patch++ = *insn;
			cnt = patch - insn_buf;
			insn = bpf_patch_list_add(env, i, insn_buf, cnt);
			if (IS_ERR(insn))
				return PTR_ERR(insn);
			/* This can not be easily merged with the
			 * nospec_result-case, because an insn may require a
			 * nospec before and after itself. Therefore also do not
			 * 'continue' here but potentially apply further
			 * patching to insn. *insn should equal patch[1] now.
			 */
		}

		if (insn->code == (BPF_LDX | BPF_MEM | BPF_B) ||
		    insn->code == (BPF_LDX | BPF_MEM | BPF_H) ||
		    insn->code == (BPF_LDX | BPF_MEM | BPF_W) ||
		    insn->code == (BPF_LDX | BPF_MEM | BPF_DW) ||
		    insn->code == (BPF_LDX | BPF_MEMSX | BPF_B) ||
		    insn->code == (BPF_LDX | BPF_MEMSX | BPF_H) ||
		    insn->code == (BPF_LDX | BPF_MEMSX | BPF_W)) {
			type = BPF_READ;
		} else if (insn->code == (BPF_STX | BPF_MEM | BPF_B) ||
			   insn->code == (BPF_STX | BPF_MEM | BPF_H) ||
			   insn->code == (BPF_STX | BPF_MEM | BPF_W) ||
			   insn->code == (BPF_STX | BPF_MEM | BPF_DW) ||
			   insn->code == (BPF_ST | BPF_MEM | BPF_B) ||
			   insn->code == (BPF_ST | BPF_MEM | BPF_H) ||
			   insn->code == (BPF_ST | BPF_MEM | BPF_W) ||
			   insn->code == (BPF_ST | BPF_MEM | BPF_DW)) {
			type = BPF_WRITE;
		} else if ((insn->code == (BPF_STX | BPF_ATOMIC | BPF_B) ||
			    insn->code == (BPF_STX | BPF_ATOMIC | BPF_H) ||
			    insn->code == (BPF_STX | BPF_ATOMIC | BPF_W) ||
			    insn->code == (BPF_STX | BPF_ATOMIC | BPF_DW)) &&
			   env->insn_aux_data[i].ptr_type == PTR_TO_ARENA) {
			insn->code = BPF_STX | BPF_PROBE_ATOMIC | BPF_SIZE(insn->code);
			env->prog->aux->num_exentries++;
			continue;
		} else if (bpf_is_pad_goto(insn)) {
			/* jit_subprogs() counts again, a prog of one function doesn't get there */
			env->prog->aux->num_exentries++;
			continue;
		} else if (insn->code == (BPF_STX | BPF_ATOMIC | BPF_DW) &&
			   insn->imm == BPF_LOAD_ACQ &&
			   env->insn_aux_data[i].arena_member) {
			/* an acquire load of an __arena member is rewritten like a plain load */
			cnt = arena_member_fixup(env, i, insn, insn_buf);
			insn = bpf_patch_list_add(env, i, insn_buf, cnt);
			if (IS_ERR(insn))
				return PTR_ERR(insn);
			continue;
		} else if (insn->code == (BPF_JMP | BPF_EXIT) &&
			   epilogue_cnt &&
			   i < subprogs[1].start) {
			/* Generate epilogue for the main prog */
			if (epilogue_idx) {
				/* jump back to the earlier generated epilogue */
				insn_buf[0] = BPF_JMP32_A(epilogue_idx - i - 1);
				cnt = 1;
			} else {
				memcpy(insn_buf, epilogue_buf,
				       epilogue_cnt * sizeof(*epilogue_buf));
				cnt = epilogue_cnt;
				/* epilogue_idx cannot be 0. It must have at
				 * least one ctx ptr saving insn before the
				 * epilogue.
				 */
				epilogue_idx = i;
			}
			goto patch_insn_buf;
		} else {
			continue;
		}

		if (type == BPF_WRITE &&
		    env->insn_aux_data[i].nospec_result) {
			/* nospec_result is only used to mitigate Spectre v4 and
			 * to limit verification-time for Spectre v1.
			 */
			struct bpf_insn *patch = insn_buf;

			*patch++ = *insn;
			*patch++ = BPF_ST_NOSPEC();
			cnt = patch - insn_buf;
			insn = bpf_patch_list_add(env, i, insn_buf, cnt);
			if (IS_ERR(insn))
				return PTR_ERR(insn);
			continue;
		}

		ptr_type = env->insn_aux_data[i].ptr_type;
		switch ((int)ptr_type) {
		case PTR_TO_CTX:
			if (!ops->convert_ctx_access)
				continue;
			convert_ctx_access = ops->convert_ctx_access;
			break;
		case PTR_TO_SOCKET:
		case PTR_TO_SOCK_COMMON:
			convert_ctx_access = bpf_sock_convert_ctx_access;
			break;
		case PTR_TO_TCP_SOCK:
			convert_ctx_access = bpf_tcp_sock_convert_ctx_access;
			break;
		case PTR_TO_XDP_SOCK:
			convert_ctx_access = bpf_xdp_sock_convert_ctx_access;
			break;
		case PTR_TO_ARENA:
			if (BPF_MODE(insn->code) == BPF_MEMSX) {
				if (!bpf_jit_supports_insn(insn, true)) {
					verbose(env, "sign extending loads from arena are not supported yet\n");
					return -EOPNOTSUPP;
				}
				insn->code = BPF_CLASS(insn->code) | BPF_PROBE_MEM32SX | BPF_SIZE(insn->code);
			} else {
				insn->code = BPF_CLASS(insn->code) | BPF_PROBE_MEM32 | BPF_SIZE(insn->code);
			}
			env->prog->aux->num_exentries++;
			continue;
		default:
			/*
			 * A pointer which may fault on a dereference must not
			 * be loaded from without fault protection, hence turn
			 * the BPF_LDX into a BPF_PROBE_MEM one so that a bad
			 * address is handled rather than panicking the kernel.
			 * A store through one is rejected earlier, there is no
			 * probed counterpart to rewrite it into.
			 */
			if (bpf_is_ptr_to_mem_or_btf_id(ptr_type) &&
			    bpf_may_fault_on_deref(ptr_type) &&
			    type == BPF_READ) {
				if (BPF_MODE(insn->code) == BPF_MEM)
					insn->code = BPF_LDX | BPF_PROBE_MEM |
						     BPF_SIZE(insn->code);
				else
					insn->code = BPF_LDX | BPF_PROBE_MEMSX |
						     BPF_SIZE(insn->code);
				env->prog->aux->num_exentries++;
			} else if (verifier_bug_if(bpf_may_fault_on_deref(ptr_type), env,
						   "access to a fault prone pointer is not rewritten as a probed one")) {
				return -EFAULT;
			}

			cnt = arena_member_fixup(env, i, insn, insn_buf);
			if (!cnt)
				continue;
			insn = bpf_patch_list_add(env, i, insn_buf, cnt);
			if (IS_ERR(insn))
				return PTR_ERR(insn);
			continue;
		}

		ctx_field_size = env->insn_aux_data[i].ctx_field_size;
		size = BPF_LDST_BYTES(insn);
		mode = BPF_MODE(insn->code);

		/* If the read access is a narrower load of the field,
		 * convert to a 4/8-byte load, to minimum program type specific
		 * convert_ctx_access changes. If conversion is successful,
		 * we will apply proper mask to the result.
		 */
		is_narrower_load = size < ctx_field_size;
		size_default = bpf_ctx_off_adjust_machine(ctx_field_size);
		off = insn->off;
		if (is_narrower_load) {
			u8 size_code;

			if (type == BPF_WRITE) {
				verifier_bug(env, "narrow ctx access misconfigured");
				return -EFAULT;
			}

			size_code = BPF_H;
			if (ctx_field_size == 4)
				size_code = BPF_W;
			else if (ctx_field_size == 8)
				size_code = BPF_DW;

			insn->off = off & ~(size_default - 1);
			insn->code = BPF_LDX | BPF_MEM | size_code;
		}

		target_size = 0;
		cnt = convert_ctx_access(type, insn, insn_buf, env->prog,
					 &target_size);
		if (cnt == 0 || cnt >= INSN_BUF_SIZE ||
		    (ctx_field_size && !target_size)) {
			verifier_bug(env, "error during ctx access conversion (%d)", cnt);
			return -EFAULT;
		}

		if (is_narrower_load && size < target_size) {
			u8 shift = bpf_ctx_narrow_access_offset(
				off, size, size_default) * 8;
			if (shift && cnt + 1 >= INSN_BUF_SIZE) {
				verifier_bug(env, "narrow ctx load misconfigured");
				return -EFAULT;
			}
			if (ctx_field_size <= 4) {
				if (shift)
					insn_buf[cnt++] = BPF_ALU32_IMM(BPF_RSH,
									insn->dst_reg,
									shift);
				insn_buf[cnt++] = BPF_ALU32_IMM(BPF_AND, insn->dst_reg,
								(1 << size * 8) - 1);
			} else {
				if (shift)
					insn_buf[cnt++] = BPF_ALU64_IMM(BPF_RSH,
									insn->dst_reg,
									shift);
				insn_buf[cnt++] = BPF_ALU32_IMM(BPF_AND, insn->dst_reg,
								(1ULL << size * 8) - 1);
			}
		}
		if (mode == BPF_MEMSX)
			insn_buf[cnt++] = BPF_RAW_INSN(BPF_ALU64 | BPF_MOV | BPF_X,
						       insn->dst_reg, insn->dst_reg,
						       size * 8, 0);

patch_insn_buf:
		insn = bpf_patch_list_add(env, i, insn_buf, cnt);
		if (IS_ERR(insn))
			return PTR_ERR(insn);
	}

	return bpf_patch_list_commit(env);
}

static u32 *bpf_dup_subprog_starts(struct bpf_verifier_env *env)
{
	u32 *starts = NULL;

	starts = kvmalloc_objs(u32, env->subprog_cnt, BPF_VERIFIER_GFP);
	if (starts) {
		for (int i = 0; i < env->subprog_cnt; i++)
			starts[i] = env->subprog_info[i].start;
	}
	return starts;
}

static void bpf_restore_subprog_starts(struct bpf_verifier_env *env, u32 *orig_starts)
{
	for (int i = 0; i < env->subprog_cnt; i++)
		env->subprog_info[i].start = orig_starts[i];
	/* restore the start of fake 'exit' subprog as well */
	env->subprog_info[env->subprog_cnt].start = env->prog->len;
}

/*
 * Replace the offsets of functions with their addresses in the maps of
 * the program, see resolve_func_ptrs() in verifier.c. The program must be
 * the only user of such map. From now on no other program can use it, see
 * bpf_map_claim().
 */
static int resolve_func_ptrs(struct bpf_verifier_env *env, struct bpf_prog *prog,
			     struct bpf_prog **func)
{
	unsigned long me = (unsigned long)prog->aux;
	struct bpf_func_ptr *ptr;
	int i, err, subprog;
	u64 addr, new, *slot;

	for (i = 0; i < env->func_ptr_cnt; i++) {
		ptr = &env->func_ptrs[i];

		/* pointers are sorted by map */
		if ((!i || ptr->map != ptr[-1].map) &&
		    cmpxchg(&ptr->map->user, me, me | BPF_MAP_USER_PATCHED) != me) {
			verbose(env, "map '%s' is used by another program\n", ptr->map->name);
			return -EBUSY;
		}

		/* it's the address of the value of the map whatever the offset is */
		err = ptr->map->ops->map_direct_value_addr(ptr->map, &addr, 0);
		if (verifier_bug_if(err, env, "no value of map '%s'", ptr->map->name))
			return -EFAULT;
		slot = (u64 *)(unsigned long)(addr + ptr->map_off);

		/*
		 * The function that is dead code is removed and the pointer is
		 * NULL. The program may read it, but callx of it is dead code
		 * too, see check_func_callx().
		 */
		new = 0;
		if (ptr->xlated_off != BPF_FUNC_PTR_DELETED) {
			subprog = bpf_find_subprog(env, ptr->xlated_off);
			if (verifier_bug_if(!func || subprog <= 0, env, "no function at insn %u",
					    ptr->xlated_off))
				return -EFAULT;
			new = (unsigned long)func[subprog]->bpf_func;
		}

		/* the map is frozen and nothing else uses it */
		if (verifier_bug_if(*slot != (u64)ptr->orig_off * sizeof(struct bpf_insn), env,
				    "map '%s' offset %u changed", ptr->map->name, ptr->map_off))
			return -EFAULT;
		WRITE_ONCE(*slot, new);
	}
	return 0;
}

static int insn_callee(struct bpf_verifier_env *env, int idx)
{
	return bpf_find_subprog(env, idx + env->prog->insnsi[idx].imm + 1);
}

static int jit_subprogs(struct bpf_verifier_env *env)
{
	struct bpf_prog *prog = env->prog, **func, *tmp;
	int i, j, subprog_start, subprog_end = 0, len, subprog;
	struct bpf_map *map_ptr;
	struct bpf_insn *insn;
	void *old_bpf_func;
	int err, num_exentries;

	err = bpf_prog_alloc_jited_linfo(prog);
	if (err)
		goto out_done;

	err = -ENOMEM;
	func = kvzalloc_objs(prog, env->subprog_cnt, BPF_VERIFIER_GFP);
	if (!func)
		goto out_done;

	for (i = 0; i < env->subprog_cnt; i++) {
		subprog_start = subprog_end;
		subprog_end = env->subprog_info[i + 1].start;

		len = subprog_end - subprog_start;
		err = -ENOMEM;
		/* bpf_prog_run() doesn't call subprogs directly,
		 * hence main prog stats include the runtime of subprogs.
		 * subprogs don't have IDs and not reachable via prog_get_next_id
		 * func[i]->stats will never be accessed and stays NULL
		 */
		func[i] = bpf_prog_alloc_no_stats(bpf_prog_size(len), GFP_USER | BPF_GFP_MAYFAIL);
		if (!func[i])
			goto out_free;
		memcpy(func[i]->insnsi, &prog->insnsi[subprog_start],
		       len * sizeof(struct bpf_insn));
		func[i]->type = prog->type;
		func[i]->len = len;
		for (j = 0, insn = func[i]->insnsi; j < len; j++, insn++) {
			if (!bpf_pseudo_func(insn) && !bpf_pseudo_call(insn))
				continue;
			/* a hard reject, there is no fall back to the interpreter */
			subprog = insn_callee(env, subprog_start + j);
			if (verifier_bug_if(subprog < 0, env, "No program to jit at insn %d",
					    subprog_start + j)) {
				err = -EFAULT;
				goto out_free;
			}
			/* JITs take the address from aux->func[] in the last pass */
			insn->imm = subprog;
			if (bpf_pseudo_func(insn)) {
#if defined(MODULES_VADDR)
				u64 addr = MODULES_VADDR;
#else
				u64 addr = VMALLOC_START;
#endif
				/* jit (e.g. x86_64) may emit fewer instructions
				 * if it learns a u32 imm is the same as a u64 imm.
				 * Set close enough to possible prog address.
				 */
				insn[0].imm = (u32)addr;
				insn[1].imm = addr >> 32;
			}
		}
		if (bpf_prog_calc_tag(func[i]))
			goto out_free;
		func[i]->is_func = 1;
		func[i]->sleepable = prog->sleepable;
		func[i]->blinded = prog->blinded;
		func[i]->aux->func_idx = i;
		/* Below members will be freed only at prog->aux */
		func[i]->aux->btf = prog->aux->btf;
		func[i]->aux->subprog_start = subprog_start;
		func[i]->aux->func_info = prog->aux->func_info;
		func[i]->aux->func_info_cnt = prog->aux->func_info_cnt;
		func[i]->aux->poke_tab = prog->aux->poke_tab;
		func[i]->aux->size_poke_tab = prog->aux->size_poke_tab;
		func[i]->aux->main_prog_aux = prog->aux;

		for (j = 0; j < prog->aux->size_poke_tab; j++) {
			struct bpf_jit_poke_descriptor *poke;

			poke = &prog->aux->poke_tab[j];
			if (poke->insn_idx < subprog_end &&
			    poke->insn_idx >= subprog_start)
				poke->aux = func[i]->aux;
		}

		func[i]->aux->name[0] = 'F';
		func[i]->aux->stack_depth = env->subprog_info[i].stack_depth;
		func[i]->aux->coro_defer = env->subprog_info[i].coro_defer;
		if (env->subprog_info[i].priv_stack_mode == PRIV_STACK_ADAPTIVE)
			func[i]->aux->jits_use_priv_stack = true;

		func[i]->jit_requested = 1;
		func[i]->blinding_requested = prog->blinding_requested;
		func[i]->aux->kfunc_tab = prog->aux->kfunc_tab;
		func[i]->aux->kfunc_btf_tab = prog->aux->kfunc_btf_tab;
		func[i]->aux->linfo = prog->aux->linfo;
		func[i]->aux->nr_linfo = prog->aux->nr_linfo;
		func[i]->aux->jited_linfo = prog->aux->jited_linfo;
		func[i]->aux->linfo_idx = env->subprog_info[i].linfo_idx;
		func[i]->aux->arena = prog->aux->arena;
		func[i]->aux->arena_stack_size = prog->aux->arena_stack_size;
		func[i]->aux->arena_stack_entry = env->subprog_info[i].arena_stack_entry;
		func[i]->aux->uses_arena_insns = bpf_prog_has_arena_insns(func[i]);
		func[i]->aux->used_maps = env->insn_array_maps;
		func[i]->aux->used_map_cnt = env->insn_array_map_cnt;
		num_exentries = 0;
		insn = func[i]->insnsi;
		for (j = 0; j < func[i]->len; j++, insn++) {
			if (BPF_CLASS(insn->code) == BPF_LDX &&
			    (BPF_MODE(insn->code) == BPF_PROBE_MEM ||
			     BPF_MODE(insn->code) == BPF_PROBE_MEM32 ||
			     BPF_MODE(insn->code) == BPF_PROBE_MEM32SX ||
			     BPF_MODE(insn->code) == BPF_PROBE_MEMSX))
				num_exentries++;
			if ((BPF_CLASS(insn->code) == BPF_STX ||
			     BPF_CLASS(insn->code) == BPF_ST) &&
			     BPF_MODE(insn->code) == BPF_PROBE_MEM32)
				num_exentries++;
			if (BPF_CLASS(insn->code) == BPF_STX &&
			     BPF_MODE(insn->code) == BPF_PROBE_ATOMIC)
				num_exentries++;
			if (bpf_is_pad_goto(insn))
				num_exentries++;
		}
		func[i]->aux->num_exentries = num_exentries;
		func[i]->aux->tail_call_reachable = env->subprog_info[i].tail_call_reachable;
		func[i]->aux->changes_pkt_data = env->subprog_info[i].changes_pkt_data;
		func[i]->aux->might_sleep = env->subprog_info[i].might_sleep;
		/* with unwind_exit or with kexit: what attaches to it asks, not which */
		func[i]->aux->can_unwind = env->subprog_info[i].can_unwind ||
					   env->subprog_info[i].can_kunwind;
		func[i]->aux->in_recursion = env->subprog_info[i].in_recursion;
		func[i]->aux->token = prog->aux->token;
		func[i] = bpf_int_jit_compile(env, func[i]);
		if (!func[i]->jited) {
			err = -ENOTSUPP;
			goto out_free;
		}
		err = -EINTR;
		if (bpf_must_abort())
			goto out_free;
	}

	/* at this point all bpf functions were successfully JITed
	 * now populate all bpf_calls with correct addresses and
	 * run last pass of JIT
	 */
	for (i = 0; i < env->subprog_cnt; i++) {
		insn = func[i]->insnsi;
		for (j = 0; j < func[i]->len; j++, insn++) {
			if (!bpf_pseudo_func(insn))
				continue;
			subprog = insn_callee(env, func[i]->aux->subprog_start + j);
			insn[0].imm = (u32)(long)func[subprog]->bpf_func;
			insn[1].imm = ((u64)(long)func[subprog]->bpf_func) >> 32;
		}

		/* we use the aux data to keep a list of the start addresses
		 * of the JITed images for each function in the program
		 *
		 * the imm field of a call has the subprog id, an index for this list
		 */
		func[i]->aux->func = func;
		func[i]->aux->func_cnt = env->subprog_cnt;
	}
	for (i = 0; i < env->subprog_cnt; i++) {
		old_bpf_func = func[i]->bpf_func;
		tmp = bpf_int_jit_compile(env, func[i]);
		if (tmp != func[i] || func[i]->bpf_func != old_bpf_func) {
			verbose(env, "JIT doesn't support bpf-to-bpf calls\n");
			err = -ENOTSUPP;
			goto out_free;
		}
		err = -EINTR;
		if (bpf_must_abort())
			goto out_free;
	}

	/* the addresses of all functions are final */
	err = resolve_func_ptrs(env, prog, func);
	if (err)
		goto out_free;

	/*
	 * Cleanup func[i]->aux fields which aren't required
	 * or can become invalid in future
	 */
	for (i = 0; i < env->subprog_cnt; i++) {
		func[i]->aux->used_maps = NULL;
		func[i]->aux->used_map_cnt = 0;
	}

	/* finally lock prog and jit images for all functions and
	 * populate kallsysm. Begin at the first subprogram, since
	 * bpf_prog_load will add the kallsyms for the main program.
	 */
	for (i = 1; i < env->subprog_cnt; i++) {
		err = bpf_prog_lock_ro(func[i]);
		if (err)
			goto out_free;
	}

	for (i = 1; i < env->subprog_cnt; i++)
		bpf_prog_kallsyms_add(func[i]);

	/* Last step: make now unused interpreter insns from main
	 * prog consistent for later dump requests, so they can
	 * later look the same as if they were interpreted only.
	 */
	for (i = 0, insn = prog->insnsi; i < prog->len; i++, insn++)
		if (bpf_pseudo_func(insn))
			insn[1].imm = insn_callee(env, i);

	prog->jited = 1;
	prog->bpf_func = func[0]->bpf_func;
	prog->jited_len = func[0]->jited_len;
	prog->aux->extable = func[0]->aux->extable;
	prog->aux->num_exentries = func[0]->aux->num_exentries;
	prog->aux->fault_pad = func[0]->aux->fault_pad;
	prog->aux->func = func;
	prog->aux->func_cnt = env->subprog_cnt;
	prog->aux->exception_callback_subprog = env->exception_callback_subprog;
	bpf_prog_jit_attempt_done(prog);
	return 0;
out_free:
	/* We failed JIT'ing, so at this point we need to unregister poke
	 * descriptors from subprogs, so that kernel is not attempting to
	 * patch it anymore as we're freeing the subprog JIT memory.
	 */
	for (i = 0; i < prog->aux->size_poke_tab; i++) {
		map_ptr = prog->aux->poke_tab[i].tail_call.map;
		map_ptr->ops->map_poke_untrack(map_ptr, prog->aux);
	}
	/* At this point we're guaranteed that poke descriptors are not
	 * live anymore. We can just unlink its descriptor table as it's
	 * released with the main prog.
	 */
	for (i = 0; i < env->subprog_cnt; i++) {
		if (!func[i])
			continue;
		func[i]->aux->poke_tab = NULL;
		bpf_jit_free(func[i]);
	}
	kvfree(func);
out_done:
	bpf_prog_jit_attempt_done(prog);
	return err;
}

int bpf_jit_subprogs(struct bpf_verifier_env *env)
{
	int err;
	bool blinded = false;
	struct bpf_prog *prog, *orig_prog;
	u32 *orig_subprog_starts;

	/* all functions that the maps point to are removed as dead code */
	if (env->subprog_cnt <= 1)
		return resolve_func_ptrs(env, env->prog, NULL);

	prog = orig_prog = env->prog;
	if (bpf_prog_need_blind(prog)) {
		orig_subprog_starts = bpf_dup_subprog_starts(env);
		if (!orig_subprog_starts) {
			err = -ENOMEM;
			goto out_cleanup;
		}
		prog = bpf_jit_blind_constants(env, prog);
		if (IS_ERR(prog)) {
			err = PTR_ERR(prog);
			prog = orig_prog;
			goto out_restore;
		}
		blinded = true;
	}

	err = jit_subprogs(env);
	if (err)
		goto out_jit_err;

	if (blinded) {
		bpf_jit_prog_release_other(prog, orig_prog);
		kvfree(orig_subprog_starts);
	}

	return 0;

out_jit_err:
	if (!blinded)
		goto out_cleanup;
	bpf_jit_prog_release_other(orig_prog, prog);
	/* roll back to the clean original prog */
	prog = env->prog = orig_prog;
out_restore:
	bpf_restore_subprog_starts(env, orig_subprog_starts);
	kvfree(orig_subprog_starts);
out_cleanup:
	/* cleanup main prog to be interpreted */
	prog->jit_requested = 0;
	prog->blinding_requested = 0;
	return err;
}

/* A load from arena, a store to it, or an atomic insn there: the code of it can fault */
static bool is_arena_access(const struct bpf_insn *insn)
{
	u8 class = BPF_CLASS(insn->code), mode = BPF_MODE(insn->code);

	if (class == BPF_LDX)
		return mode == BPF_PROBE_MEM32 || mode == BPF_PROBE_MEM32SX;
	if (class == BPF_ST)
		return mode == BPF_PROBE_MEM32;
	return class == BPF_STX && (mode == BPF_PROBE_MEM32 || mode == BPF_PROBE_ATOMIC);
}

/* A call of any kind: what it calls returns to the insn behind it */
static bool is_call(const struct bpf_insn *insn)
{
	return insn->code == (BPF_JMP | BPF_CALL) || bpf_is_callx(insn);
}

/* The exception table can have an entry at the end of the insn: a call, an access to arena */
static bool can_have_unwind_goto(const struct bpf_insn *insn)
{
	return is_call(insn) || is_arena_access(insn);
}

/*
 * A jump with an offset, see bpf_jmp_offset(): also may_goto, unwind_goto and kgoto. Not gotox, and
 * not the tail call that bpf_do_misc_fixups() has made of the call of the helper: it has no
 * offset, and what is taken leaves the program.
 */
static bool insn_goes_to(const struct bpf_insn *insn)
{
	u8 class = BPF_CLASS(insn->code), op = BPF_OP(insn->code);

	if (class != BPF_JMP && class != BPF_JMP32)
		return false;
	return op != BPF_CALL && op != BPF_EXIT && op != BPF_TAIL_CALL &&
	       !(op == BPF_JA && BPF_SRC(insn->code) == BPF_X);
}

/*
 * unwind_goto is no code. It is an entry of the exception table, which a JIT keys at the end of
 * the insn in front: a call, or an access to arena. No pass may put anything between the two.
 * After a call that would be a lost unwind_exit, which bpf_unwind_target() warns about when it
 * happens. After an access nothing would tell: a fault finds no entry, see
 * bpf_fault_unwind_target(), and the access is skipped as if no pad had been planned for it.
 * So look at the insns once they are final, from both sides: unwind_goto has such an insn in
 * front, and such an insn that the verifier gave unwind_goto still has it behind. An insn that a
 * pass has replaced by other code is no site any more: the inlined bpf_loop() has unwind_goto of
 * its own, see inline_bpf_loop().
 * kgoto is the same for kexit. It stands behind a call, or behind unwind_goto of a call. Not behind
 * an access to arena: the handler of a fault looks for unwind_goto there. kexit is in no frame
 * that the kernel calls: the main program leaves with exit. A call that the verifier gave kgoto
 * still has it, behind unwind_goto if there is one.
 * Neither of the two is a place to go to. Where the call has code behind it, like 'pop r9' on
 * x86-64, the JIT emits that code once more on the way to each pad, in a landing. A JIT may put
 * the landings where the insns are: then the place of kgoto behind unwind_goto is the way of
 * kexit, and what goes there does the code of the call a second time. x86-64 and arm64 put them
 * behind the function, and the rule is the same for all. A pad that is the insn behind the two is
 * named by unwind_goto +1, see emit_pad(). So no jump of any kind goes to kgoto behind
 * unwind_goto, and unwind_goto and kgoto go to neither of the two.
 */
int bpf_check_unwind_gotos(struct bpf_verifier_env *env)
{
	const struct bpf_insn *insns = env->prog->insnsi, *insn = insns;
	int i, to, len = env->prog->len;
	bool bad;

	for (i = 0; i < len; i++, insn++) {
		if (insn_goes_to(insn)) {
			to = i + 1 + bpf_jmp_offset(insn);
			bad = to < 0 || to >= len;
			if (!bad && bpf_is_pad_goto(insn))
				bad = bpf_is_pad_goto(&insns[to]);
			else if (!bad)
				bad = to && bpf_is_kgoto(&insns[to]) &&
				      bpf_is_unwind_goto(&insns[to - 1]);
			if (verifier_bug_if(bad, env,
					    "insn %d goes to unwind_goto or kgoto at insn %d", i, to))
				return -EFAULT;
		}
		if (bpf_is_unwind_goto(insn) &&
		    verifier_bug_if(!i || !can_have_unwind_goto(insn - 1), env,
				    "unwind_goto at insn %d follows no call and no access to arena",
				    i))
			return -EFAULT;
		if (bpf_is_kgoto(insn) &&
		    verifier_bug_if(!i || !(is_call(insn - 1) ||
					    (i > 1 && bpf_is_unwind_goto(insn - 1) &&
					     is_call(insn - 2))), env,
				    "kgoto at insn %d follows no call", i))
			return -EFAULT;
		if (bpf_is_kexit(insn) &&
		    verifier_bug_if(i < env->subprog_info[1].start, env,
				    "kexit at insn %d of the main program", i))
			return -EFAULT;
		if (env->insn_aux_data[i].unwind_goto_follows && can_have_unwind_goto(insn) &&
		    verifier_bug_if(i + 1 == len || !bpf_is_unwind_goto(insn + 1), env,
				    "insn %d has lost its unwind_goto", i))
			return -EFAULT;
		if (env->insn_aux_data[i].kgoto_follows && is_call(insn) &&
		    verifier_bug_if(i + 1 == len ||
				    !(bpf_is_kgoto(insn + 1) ||
				      (bpf_is_unwind_goto(insn + 1) && i + 2 < len &&
				       bpf_is_kgoto(insn + 2))), env,
				    "insn %d has lost its kgoto", i))
			return -EFAULT;
	}
	return 0;
}

int bpf_fixup_call_args(struct bpf_verifier_env *env)
{
#ifndef CONFIG_BPF_JIT_ALWAYS_ON
	struct bpf_prog *prog = env->prog;
	struct bpf_insn *insn = prog->insnsi;
	int i, depth;
#endif
	int err = 0;

	if (env->prog->jit_requested &&
	    !bpf_prog_is_offloaded(env->prog->aux)) {
		err = bpf_jit_subprogs(env);
		if (err == 0)
			return 0;
		if (err == -EFAULT || err == -EINTR || err == -ENOMEM)
			return err;
	}
#ifndef CONFIG_BPF_JIT_ALWAYS_ON
	if (prog->jit_required) {
		verbose(env, "program requires BPF JIT compiler but it is not available\n");
		return -EINVAL;
	}
	for (i = 0; i < env->subprog_cnt; i++) {
		if (env->subprog_info[i].stack_arg_cnt) {
			verbose(env, "stack args are not supported in non-JITed programs\n");
			return -EINVAL;
		}
	}
	if (env->subprog_cnt > 1 && env->prog->aux->tail_call_reachable) {
		/* When JIT fails the progs with bpf2bpf calls and tail_calls
		 * have to be rejected, since interpreter doesn't support them yet.
		 */
		verbose(env, "tail_calls are not allowed in non-JITed programs with bpf-to-bpf calls\n");
		return -EINVAL;
	}
	for (i = 0; i < prog->len; i++, insn++) {
		if (bpf_pseudo_func(insn)) {
			/* When JIT fails the progs with callback calls
			 * have to be rejected, since interpreter doesn't support them yet.
			 */
			verbose(env, "callbacks are not allowed in non-JITed programs\n");
			return -EINVAL;
		}

		if (!bpf_pseudo_call(insn))
			continue;
		depth = get_callee_stack_depth(env, insn, i);
		if (depth < 0)
			return depth;
		err = bpf_patch_call_args(insn, depth);
		if (err) {
			verbose(env, "stack depth %d exceeds interpreter stack depth limit\n",
				depth);
			return err;
		}
	}
	err = 0;
#endif
	return err;
}

/*
 * Timed may_goto. All may_goto of a prog use one count and one timestamp: per-cpu memory of the
 * prog, set in the first insns of the main prog, and by the callers of async callbacks.
 * @reg holds the address. It is a register that is dead at the may_goto, or R0 that is saved at
 * @save_off in the stack. @jmp is the insn that goes where may_goto goes.
 */
static int may_goto_expand_timed(struct bpf_insn *insn_buf, int *jmp,
				 struct bpf_timed_may_goto __percpu *tmg, int reg, int save_off)
{
	struct bpf_insn ld_tmg[] = { BPF_LD_IMM64(reg, (__force unsigned long)tmg) };
	int cnt = 0;

	if (save_off)
		insn_buf[cnt++] = BPF_STX_MEM(BPF_DW, BPF_REG_10, reg, save_off);
	insn_buf[cnt++] = ld_tmg[0];
	insn_buf[cnt++] = ld_tmg[1];
	insn_buf[cnt++] = BPF_MOV64_PERCPU_REG(reg, reg);
	insn_buf[cnt++] = BPF_LDX_MEM(BPF_DW, BPF_REG_AX, reg, 0);
	if (save_off) {
		insn_buf[cnt++] = BPF_JMP_IMM(BPF_JNE, BPF_REG_AX, 0, 2);
		insn_buf[cnt++] = BPF_LDX_MEM(BPF_DW, reg, BPF_REG_10, save_off);
	}
	*jmp = cnt;
	insn_buf[cnt++] = save_off ? BPF_JMP32_A(0) : BPF_JMP_IMM(BPF_JEQ, BPF_REG_AX, 0, 0);
	insn_buf[cnt++] = BPF_ALU64_IMM(BPF_SUB, BPF_REG_AX, 1);
	insn_buf[cnt++] = BPF_JMP_IMM(BPF_JNE, BPF_REG_AX, 0, 2);
	/* AX is the argument and the return value */
	insn_buf[cnt++] = BPF_MOV64_REG(BPF_REG_AX, reg);
	insn_buf[cnt++] = BPF_EMIT_CALL(arch_bpf_timed_may_goto);
	insn_buf[cnt++] = BPF_STX_MEM(BPF_DW, reg, BPF_REG_AX, 0);
	if (save_off)
		insn_buf[cnt++] = BPF_LDX_MEM(BPF_DW, reg, BPF_REG_10, save_off);
	return cnt;
}

#ifdef CONFIG_64BIT
struct bpf_div_magic {
	u64 m;		/* multiplier, sign extended for signed division */
	int s;		/* shift of the high half of the product */
	bool add;	/* multiplier has 65 bits, use the add sequence */
};

/*
 * m and s with n / d == mulhu(n, m) >> s for 2 <= d < 2^64 and n below
 * 2^(64 - lz), or (((n - t) >> 1) + t) >> (s - 1) with t = mulhu(n, m) when m
 * needs 65 bits. Hacker's Delight, 2nd ed., figure 10-2.
 */
static void bpf_magic_udiv(u64 d, int lz, struct bpf_div_magic *mag)
{
	u64 mask = ~0ULL >> (lz & 63);
	u64 nc, delta, q1, r1, q2, r2;
	int p;

	mag->add = false;
	/* Largest value with nc mod d == d - 1 */
	nc = mask - (mask % d + 1) % d;
	p = 63;
	q1 = (1ULL << 63) / nc;			/* 2^p / nc */
	r1 = (1ULL << 63) - q1 * nc;		/* 2^p mod nc */
	q2 = (~0ULL >> 1) / d;			/* (2^p - 1) / d */
	r2 = (~0ULL >> 1) - q2 * d;		/* (2^p - 1) mod d */
	do {
		p++;
		if (r1 >= nc - r1) {
			q1 = 2 * q1 + 1;
			r1 = 2 * r1 - nc;
		} else {
			q1 = 2 * q1;
			r1 = 2 * r1;
		}
		if (r2 + 1 >= d - r2) {
			if (q2 >= (~0ULL >> 1))
				mag->add = true;
			q2 = 2 * q2 + 1;
			r2 = 2 * r2 + 1 - d;
		} else {
			if (q2 >= (1ULL << 63))
				mag->add = true;
			q2 = 2 * q2;
			r2 = 2 * r2 + 1;
		}
		delta = d - 1 - r2;
	} while (p < 128 && (q1 < delta || (q1 == delta && r1 == 0)));

	mag->m = q2 + 1;
	mag->s = p - 64;
}

/*
 * m and s with n / d == q + (q >> 63), q = (mulhs(n, m) +- n) s>> s, for
 * 2 <= |d| < 2^63, adding n for d > 0 and m < 0, subtracting it for d < 0 and
 * m > 0. Hacker's Delight, 2nd ed., figure 10-1.
 */
static void bpf_magic_sdiv(s64 d, struct bpf_div_magic *mag)
{
	u64 ad = d < 0 ? -(u64)d : (u64)d;
	u64 t, anc, delta, q1, r1, q2, r2;
	int p;

	t = (1ULL << 63) + (d < 0);
	anc = t - 1 - t % ad;			/* |nc| */
	p = 63;
	q1 = (1ULL << 63) / anc;		/* 2^p / |nc| */
	r1 = (1ULL << 63) - q1 * anc;		/* 2^p mod |nc| */
	q2 = (1ULL << 63) / ad;			/* 2^p / |d| */
	r2 = (1ULL << 63) - q2 * ad;		/* 2^p mod |d| */
	do {
		p++;
		q1 = 2 * q1;
		r1 = 2 * r1;
		if (r1 >= anc) {
			q1++;
			r1 -= anc;
		}
		q2 = 2 * q2;
		r2 = 2 * r2;
		if (r2 >= ad) {
			q2++;
			r2 -= ad;
		}
		delta = ad - r2;
	} while (q1 < delta || (q1 == delta && r1 == 0));

	mag->m = q2 + 1;
	if (d < 0)
		mag->m = -mag->m;
	mag->s = p - 64;
	mag->add = false;
}

/*
 * 64-bit dst /= imm and dst %= imm as a uhmul or shmul by the magic number
 * with AX as scratch, into buf. Returns the count, or 0 to keep the division,
 * as for smod and for umod by a divisor that needs the add sequence.
 */
static int div_by_const(const struct bpf_insn *insn, struct bpf_insn *buf)
{
	bool is_mod = BPF_OP(insn->code) == BPF_MOD;
	bool is_signed = insn->off == 1;
	u8 dst = insn->dst_reg, ax = BPF_REG_AX;
	struct bpf_insn *p = buf;
	struct bpf_div_magic mag;
	s32 d = insn->imm;
	int pre = 0;

	if (is_signed) {
		/* |d| >= 2, d == -1 is gone already */
		if (is_mod || (d >= -1 && d <= 1))
			return 0;
		bpf_magic_sdiv(d, &mag);
	} else {
		/* d >= 2, a negative imm is a divisor above 2^63 */
		if (d < 2)
			return 0;
		bpf_magic_udiv(d, 0, &mag);
		if (mag.add && is_mod)
			return 0;
		/*
		 * Shift the dividend by the trailing zeros of an even divisor
		 * first, the magic number of the odd part then fits without
		 * the add sequence.
		 */
		if (mag.add && !(d & 1)) {
			pre = __ffs(d) & 31;
			bpf_magic_udiv(d >> pre, pre, &mag);
			if (mag.add)
				return 0;
		}
	}
	/* The add sequence shifts by s - 1. Never hit for d >= 2. */
	if (mag.s > 64 - !mag.add || (mag.add && !mag.s))
		return 0;

	if (pre)
		*p++ = BPF_ALU64_IMM(BPF_RSH, dst, pre);
	/* ax = m ll */
	*p++ = BPF_RAW_INSN(BPF_LD | BPF_DW | BPF_IMM, ax, 0, 0, (u32)mag.m);
	*p++ = BPF_RAW_INSN(0, 0, 0, 0, mag.m >> 32);
	if (is_signed) {
		/* ax = (shmul(dst, m) +- dst) s>> s; dst = ax + (ax >> 63) */
		*p++ = BPF_ALU64_REG_OFF(BPF_MUL, ax, dst, BPF_SHMUL);
		if (d > 0 && (s64)mag.m < 0)
			*p++ = BPF_ALU64_REG(BPF_ADD, ax, dst);
		else if (d < 0 && (s64)mag.m > 0)
			*p++ = BPF_ALU64_REG(BPF_SUB, ax, dst);
		if (mag.s)
			*p++ = BPF_ALU64_IMM(BPF_ARSH, ax, mag.s);
		*p++ = BPF_MOV64_REG(dst, ax);
		*p++ = BPF_ALU64_IMM(BPF_RSH, dst, 63);
		*p++ = BPF_ALU64_REG(BPF_ADD, dst, ax);
	} else if (is_mod) {
		/* dst -= (uhmul(dst, m) >> s) * d */
		*p++ = BPF_ALU64_REG_OFF(BPF_MUL, ax, dst, BPF_UHMUL);
		if (mag.s)
			*p++ = BPF_ALU64_IMM(BPF_RSH, ax, mag.s);
		*p++ = BPF_ALU64_IMM(BPF_MUL, ax, d);
		*p++ = BPF_ALU64_REG(BPF_SUB, dst, ax);
	} else if (mag.add) {
		/* ax = uhmul(dst, m); dst = (((dst - ax) >> 1) + ax) >> (s - 1) */
		*p++ = BPF_ALU64_REG_OFF(BPF_MUL, ax, dst, BPF_UHMUL);
		*p++ = BPF_ALU64_REG(BPF_SUB, dst, ax);
		*p++ = BPF_ALU64_IMM(BPF_RSH, dst, 1);
		*p++ = BPF_ALU64_REG(BPF_ADD, dst, ax);
		if (mag.s > 1)
			*p++ = BPF_ALU64_IMM(BPF_RSH, dst, mag.s - 1);
	} else {
		/* dst = uhmul(dst, m) >> s */
		*p++ = BPF_ALU64_REG_OFF(BPF_MUL, dst, ax, BPF_UHMUL);
		if (mag.s)
			*p++ = BPF_ALU64_IMM(BPF_RSH, dst, mag.s);
	}
	return p - buf;
}
#else
static int div_by_const(const struct bpf_insn *insn, struct bpf_insn *buf)
{
	return 0;
}
#endif

/* Do various post-verification rewrites in a single program pass.
 * These rewrites simplify JIT and interpreter implementations.
 */
int bpf_do_misc_fixups(struct bpf_verifier_env *env)
{
	struct bpf_prog *prog = env->prog;
	enum bpf_attach_type eatype = prog->expected_attach_type;
	enum bpf_prog_type prog_type = resolve_prog_type(prog);
	struct bpf_insn *insn = prog->insnsi;
	const struct bpf_func_proto *fn;
	const int insn_cnt = prog->len;
	const struct bpf_map_ops *ops;
	struct bpf_insn_aux_data *aux;
	struct bpf_insn *insn_buf = env->insn_buf;
	struct bpf_map *map_ptr;
	int i, ret, cnt, cur_subprog = 0;
	struct bpf_subprog_info *subprogs = env->subprog_info;
	u16 stack_depth = subprogs[cur_subprog].stack_depth;
	u16 stack_depth_extra = 0;
	/* arch_bpf_timed_may_goto() takes and returns AX in a cpu register: for JITs only */
	bool timed_may_goto = prog->jit_requested && bpf_jit_supports_timed_may_goto();
	struct bpf_timed_may_goto __percpu *tmg = NULL;

	for (i = 0; i < insn_cnt;) {
		if (is_addr_space_cast32(env->prog, insn)) {
			/* convert to 32-bit mov that clears upper 32-bit */
			insn->code = BPF_ALU | BPF_MOV | BPF_X;
			/* clear off and imm, so it's a normal 'wX = wY' from JIT pov */
			insn->off = 0;
			insn->imm = 0;
			goto next_insn;
		}

		if (env->insn_aux_data[i].needs_zext)
			/* Convert BPF_CLASS(insn->code) == BPF_ALU64 to 32-bit ALU */
			insn->code = BPF_ALU | BPF_OP(insn->code) | BPF_SRC(insn->code);

		if (env->insn_aux_data[i].arena_scalar) {
			cnt = arena_scalar_access(insn, insn_buf);

			insn = bpf_patch_list_add(env, i, insn_buf, cnt);
			if (IS_ERR(insn))
				return PTR_ERR(insn);
			goto next_insn;
		}

		/* Make sdiv/smod divide-by-minus-one exceptions impossible. */
		if ((insn->code == (BPF_ALU64 | BPF_MOD | BPF_K) ||
		     insn->code == (BPF_ALU64 | BPF_DIV | BPF_K) ||
		     insn->code == (BPF_ALU | BPF_MOD | BPF_K) ||
		     insn->code == (BPF_ALU | BPF_DIV | BPF_K)) &&
		    insn->off == 1 && insn->imm == -1) {
			bool is64 = BPF_CLASS(insn->code) == BPF_ALU64;
			bool isdiv = BPF_OP(insn->code) == BPF_DIV;
			struct bpf_insn *patch = insn_buf;

			if (isdiv)
				*patch++ = BPF_RAW_INSN((is64 ? BPF_ALU64 : BPF_ALU) |
							BPF_NEG | BPF_K, insn->dst_reg,
							0, 0, 0);
			else
				*patch++ = BPF_MOV32_IMM(insn->dst_reg, 0);

			cnt = patch - insn_buf;

			insn = bpf_patch_list_add(env, i, insn_buf, cnt);
			if (IS_ERR(insn))
				return PTR_ERR(insn);
			goto next_insn;
		}

		/* Divide by a constant via uhmul or shmul, LLVM does the 32-bit ones */
		if ((insn->code == (BPF_ALU64 | BPF_MOD | BPF_K) ||
		     insn->code == (BPF_ALU64 | BPF_DIV | BPF_K)) &&
		    prog->jit_requested && !prog->blinding_requested &&
		    !bpf_prog_is_offloaded(prog->aux) && bpf_jit_supports_hmul()) {
			cnt = div_by_const(insn, insn_buf);
			if (cnt) {
				insn = bpf_patch_list_add(env, i, insn_buf, cnt);
				if (IS_ERR(insn))
					return PTR_ERR(insn);
				goto next_insn;
			}
		}

		/* Make divide-by-zero and divide-by-minus-one exceptions impossible. */
		if (insn->code == (BPF_ALU64 | BPF_MOD | BPF_X) ||
		    insn->code == (BPF_ALU64 | BPF_DIV | BPF_X) ||
		    insn->code == (BPF_ALU | BPF_MOD | BPF_X) ||
		    insn->code == (BPF_ALU | BPF_DIV | BPF_X)) {
			bool is64 = BPF_CLASS(insn->code) == BPF_ALU64;
			bool isdiv = BPF_OP(insn->code) == BPF_DIV;
			bool is_sdiv = isdiv && insn->off == 1;
			bool is_smod = !isdiv && insn->off == 1;
			struct bpf_insn *patch = insn_buf;

			if (is_sdiv) {
				/* [R,W]x sdiv 0 -> 0
				 * LLONG_MIN sdiv -1 -> LLONG_MIN
				 * INT_MIN sdiv -1 -> INT_MIN
				 */
				*patch++ = BPF_MOV64_REG(BPF_REG_AX, insn->src_reg);
				*patch++ = BPF_RAW_INSN((is64 ? BPF_ALU64 : BPF_ALU) |
							BPF_ADD | BPF_K, BPF_REG_AX,
							0, 0, 1);
				*patch++ = BPF_RAW_INSN((is64 ? BPF_JMP : BPF_JMP32) |
							BPF_JGT | BPF_K, BPF_REG_AX,
							0, 4, 1);
				*patch++ = BPF_RAW_INSN((is64 ? BPF_JMP : BPF_JMP32) |
							BPF_JEQ | BPF_K, BPF_REG_AX,
							0, 1, 0);
				*patch++ = BPF_RAW_INSN((is64 ? BPF_ALU64 : BPF_ALU) |
							BPF_MOV | BPF_K, insn->dst_reg,
							0, 0, 0);
				/* BPF_NEG(LLONG_MIN) == -LLONG_MIN == LLONG_MIN */
				*patch++ = BPF_RAW_INSN((is64 ? BPF_ALU64 : BPF_ALU) |
							BPF_NEG | BPF_K, insn->dst_reg,
							0, 0, 0);
				*patch++ = BPF_JMP_IMM(BPF_JA, 0, 0, 1);
				*patch++ = *insn;
				cnt = patch - insn_buf;
			} else if (is_smod) {
				/* [R,W]x mod 0 -> [R,W]x */
				/* [R,W]x mod -1 -> 0 */
				*patch++ = BPF_MOV64_REG(BPF_REG_AX, insn->src_reg);
				*patch++ = BPF_RAW_INSN((is64 ? BPF_ALU64 : BPF_ALU) |
							BPF_ADD | BPF_K, BPF_REG_AX,
							0, 0, 1);
				*patch++ = BPF_RAW_INSN((is64 ? BPF_JMP : BPF_JMP32) |
							BPF_JGT | BPF_K, BPF_REG_AX,
							0, 3, 1);
				*patch++ = BPF_RAW_INSN((is64 ? BPF_JMP : BPF_JMP32) |
							BPF_JEQ | BPF_K, BPF_REG_AX,
							0, 3 + (is64 ? 0 : 1), 1);
				*patch++ = BPF_MOV32_IMM(insn->dst_reg, 0);
				*patch++ = BPF_JMP_IMM(BPF_JA, 0, 0, 1);
				*patch++ = *insn;

				if (!is64) {
					*patch++ = BPF_JMP_IMM(BPF_JA, 0, 0, 1);
					*patch++ = BPF_MOV32_REG(insn->dst_reg, insn->dst_reg);
				}
				cnt = patch - insn_buf;
			} else if (isdiv) {
				/* [R,W]x div 0 -> 0 */
				*patch++ = BPF_RAW_INSN((is64 ? BPF_JMP : BPF_JMP32) |
							BPF_JNE | BPF_K, insn->src_reg,
							0, 2, 0);
				*patch++ = BPF_ALU32_REG(BPF_XOR, insn->dst_reg, insn->dst_reg);
				*patch++ = BPF_JMP_IMM(BPF_JA, 0, 0, 1);
				*patch++ = *insn;
				cnt = patch - insn_buf;
			} else {
				/* [R,W]x mod 0 -> [R,W]x */
				*patch++ = BPF_RAW_INSN((is64 ? BPF_JMP : BPF_JMP32) |
							BPF_JEQ | BPF_K, insn->src_reg,
							0, 1 + (is64 ? 0 : 1), 0);
				*patch++ = *insn;

				if (!is64) {
					*patch++ = BPF_JMP_IMM(BPF_JA, 0, 0, 1);
					*patch++ = BPF_MOV32_REG(insn->dst_reg, insn->dst_reg);
				}
				cnt = patch - insn_buf;
			}

			insn = bpf_patch_list_add(env, i, insn_buf, cnt);
			if (IS_ERR(insn))
				return PTR_ERR(insn);
			goto next_insn;
		}

		/* Make it impossible to de-reference a userspace address */
		if (BPF_CLASS(insn->code) == BPF_LDX &&
		    (BPF_MODE(insn->code) == BPF_PROBE_MEM ||
		     BPF_MODE(insn->code) == BPF_PROBE_MEMSX)) {
			struct bpf_insn *patch = insn_buf;
			u64 uaddress_limit = bpf_arch_uaddress_limit();

			if (!uaddress_limit)
				goto next_insn;

			*patch++ = BPF_MOV64_REG(BPF_REG_AX, insn->src_reg);
			if (insn->off)
				*patch++ = BPF_ALU64_IMM(BPF_ADD, BPF_REG_AX, insn->off);
			*patch++ = BPF_ALU64_IMM(BPF_RSH, BPF_REG_AX, 32);
			*patch++ = BPF_JMP_IMM(BPF_JLE, BPF_REG_AX, uaddress_limit >> 32, 2);
			*patch++ = *insn;
			*patch++ = BPF_JMP_IMM(BPF_JA, 0, 0, 1);
			*patch++ = BPF_MOV64_IMM(insn->dst_reg, 0);

			cnt = patch - insn_buf;
			insn = bpf_patch_list_add(env, i, insn_buf, cnt);
			if (IS_ERR(insn))
				return PTR_ERR(insn);
			goto next_insn;
		}

		/* Implement LD_ABS and LD_IND with a rewrite, if supported by the program type. */
		if (BPF_CLASS(insn->code) == BPF_LD &&
		    (BPF_MODE(insn->code) == BPF_ABS ||
		     BPF_MODE(insn->code) == BPF_IND)) {
			cnt = env->ops->gen_ld_abs(insn, insn_buf);
			if (cnt == 0 || cnt >= INSN_BUF_SIZE) {
				verifier_bug(env, "%d insns generated for ld_abs", cnt);
				return -EFAULT;
			}

			insn = bpf_patch_list_add(env, i, insn_buf, cnt);
			if (IS_ERR(insn))
				return PTR_ERR(insn);
			goto next_insn;
		}

		/* Rewrite pointer arithmetic to mitigate speculation attacks. */
		if (insn->code == (BPF_ALU64 | BPF_ADD | BPF_X) ||
		    insn->code == (BPF_ALU64 | BPF_SUB | BPF_X)) {
			const u8 code_add = BPF_ALU64 | BPF_ADD | BPF_X;
			const u8 code_sub = BPF_ALU64 | BPF_SUB | BPF_X;
			struct bpf_insn *patch = insn_buf;
			bool issrc, isneg, isimm;
			u32 off_reg;

			aux = &env->insn_aux_data[i];
			if (!aux->alu_state ||
			    aux->alu_state == BPF_ALU_NON_POINTER)
				goto next_insn;

			isneg = aux->alu_state & BPF_ALU_NEG_VALUE;
			issrc = (aux->alu_state & BPF_ALU_SANITIZE) ==
				BPF_ALU_SANITIZE_SRC;
			isimm = aux->alu_state & BPF_ALU_IMMEDIATE;

			off_reg = issrc ? insn->src_reg : insn->dst_reg;
			if (isimm) {
				*patch++ = BPF_MOV32_IMM(BPF_REG_AX, aux->alu_limit);
			} else {
				if (isneg)
					*patch++ = BPF_ALU64_IMM(BPF_MUL, off_reg, -1);
				*patch++ = BPF_MOV32_IMM(BPF_REG_AX, aux->alu_limit);
				*patch++ = BPF_ALU64_REG(BPF_SUB, BPF_REG_AX, off_reg);
				*patch++ = BPF_ALU64_REG(BPF_OR, BPF_REG_AX, off_reg);
				*patch++ = BPF_ALU64_IMM(BPF_NEG, BPF_REG_AX, 0);
				*patch++ = BPF_ALU64_IMM(BPF_ARSH, BPF_REG_AX, 63);
				*patch++ = BPF_ALU64_REG(BPF_AND, BPF_REG_AX, off_reg);
			}
			if (!issrc)
				*patch++ = BPF_MOV64_REG(insn->dst_reg, insn->src_reg);
			insn->src_reg = BPF_REG_AX;
			if (isneg)
				insn->code = insn->code == code_add ?
					     code_sub : code_add;
			*patch++ = *insn;
			if (issrc && isneg && !isimm)
				*patch++ = BPF_ALU64_IMM(BPF_MUL, off_reg, -1);
			cnt = patch - insn_buf;

			insn = bpf_patch_list_add(env, i, insn_buf, cnt);
			if (IS_ERR(insn))
				return PTR_ERR(insn);
			goto next_insn;
		}

		if (bpf_is_may_goto_insn(insn) && timed_may_goto) {
			u16 live = env->insn_aux_data[i].live_regs_before;
			int reg, jmp, save_off = 0, to = i + insn->off + 1;

			/* a register that is dead here holds the address of the count */
			for (reg = BPF_REG_0; reg <= BPF_REG_9; reg++)
				if (!(live & BIT(reg)))
					break;
			if (reg > BPF_REG_9) {
				reg = BPF_REG_0;
				save_off = -stack_depth - 8;
				stack_depth_extra = 8;
			}
			if (!tmg) {
				tmg = alloc_percpu_gfp(struct bpf_timed_may_goto,
						       BPF_VERIFIER_GFP);
				if (!tmg)
					return -ENOMEM;
				prog->aux->timed_may_goto = tmg;
			}
			prog->jit_required = 1;
			cnt = may_goto_expand_timed(insn_buf, &jmp, tmg, reg, save_off);

			insn = bpf_patch_list_add(env, i, insn_buf, cnt);
			if (IS_ERR(insn))
				return PTR_ERR(insn);
			bpf_patch_list_jump(&env->patch_list, insn - (cnt - 1 - jmp), to, 0);
			goto next_insn;
		} else if (bpf_is_may_goto_insn(insn)) {
			int stack_off = -stack_depth - 8, to = i + insn->off + 1;

			stack_depth_extra = 8;
			insn_buf[0] = BPF_LDX_MEM(BPF_DW, BPF_REG_AX, BPF_REG_10, stack_off);
			insn_buf[1] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_AX, 0, 0);
			insn_buf[2] = BPF_ALU64_IMM(BPF_SUB, BPF_REG_AX, 1);
			insn_buf[3] = BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_AX, stack_off);

			insn = bpf_patch_list_add(env, i, insn_buf, 4);
			if (IS_ERR(insn))
				return PTR_ERR(insn);
			bpf_patch_list_jump(&env->patch_list, insn - 2, to, 0);
			goto next_insn;
		}

		if (bpf_jit_supports_percpu_insn() &&
		    insn->code == (BPF_LD | BPF_IMM | BPF_DW) &&
		    (insn->src_reg == BPF_PSEUDO_MAP_VALUE ||
		     insn->src_reg == BPF_PSEUDO_MAP_IDX_VALUE)) {
			struct bpf_map *map;

			aux = &env->insn_aux_data[i];
			map = env->used_maps[aux->map_index];
			if (map->map_type != BPF_MAP_TYPE_PERCPU_ARRAY)
				goto next_insn;

			prog->jit_required = true;

			/*
			 * We are *skipping* first half of ld_imm64 insn
			 * with 'i++;', patching over second half of it
			 * with that same half + mov64_percpu_reg insn.
			 * All because a patch can only
			 * replace one 8-byte insn, which does not work
			 * well for ld_imm64 insn.
			 */

			insn_buf[0] = insn[1];
			insn_buf[1] = BPF_MOV64_PERCPU_REG(insn->dst_reg, insn->dst_reg);
			cnt = 2;

			i++;
			insn = bpf_patch_list_add(env, i, insn_buf, cnt);
			if (IS_ERR(insn))
				return PTR_ERR(insn);
			goto next_insn;
		}

		if (insn->code != (BPF_JMP | BPF_CALL))
			goto next_insn;
		if (insn->src_reg == BPF_PSEUDO_CALL)
			goto next_insn;
		/* imm is not the id of a helper */
		if (!insn->src_reg && insn->off == BPF_KERNEL_CALL) {
			insn->off = 0;
			goto next_insn;
		}
		if (insn->src_reg == BPF_PSEUDO_KFUNC_CALL) {
			ret = bpf_fixup_kfunc_call(env, insn, insn_buf, i, &cnt);
			if (ret)
				return ret;
			if (cnt == 0)
				goto next_insn;

			insn = bpf_patch_list_add(env, i, insn_buf, cnt);
			if (IS_ERR(insn))
				return PTR_ERR(insn);
			goto next_insn;
		}

		/* Skip inlining the helper call if the JIT does it. */
		if (bpf_jit_inlines_helper_call(insn->imm)) {
			prog->jit_required = 1;
			goto next_insn;
		}

		if (insn->imm == BPF_FUNC_get_route_realm)
			prog->dst_needed = 1;
		if (insn->imm == BPF_FUNC_get_prandom_u32)
			bpf_user_rnd_init_once();
		if (insn->imm == BPF_FUNC_tail_call) {
			/* If we tail call into other programs, we
			 * cannot make any assumptions since they can
			 * be replaced dynamically during runtime in
			 * the program array.
			 */
			prog->cb_access = 1;
			if (!bpf_allow_tail_call_in_subprogs(env))
				prog->aux->stack_depth = MAX_BPF_STACK;
			prog->aux->max_pkt_offset = MAX_PACKET_OFF;

			/* mark bpf_tail_call as different opcode to avoid
			 * conditional branch in the interpreter for every normal
			 * call and to prevent accidental JITing by JIT compiler
			 * that doesn't support bpf_tail_call yet
			 */
			insn->imm = 0;
			insn->code = BPF_JMP | BPF_TAIL_CALL;

			aux = &env->insn_aux_data[i];
			if (env->bpf_capable && !prog->blinding_requested &&
			    prog->jit_requested &&
			    !bpf_map_key_poisoned(aux) &&
			    !bpf_map_ptr_poisoned(aux) &&
			    !bpf_map_ptr_unpriv(aux)) {
				struct bpf_jit_poke_descriptor desc = {
					.reason = BPF_POKE_REASON_TAIL_CALL,
					.tail_call.map = aux->map_ptr_state.map_ptr,
					.tail_call.key = bpf_map_key_immediate(aux),
					.insn_idx = i,
				};

				ret = bpf_jit_add_poke_descriptor(prog, &desc);
				if (ret < 0) {
					verbose(env, "adding tail call poke descriptor failed\n");
					return ret;
				}

				insn->imm = ret + 1;
				goto next_insn;
			}

			if (!bpf_map_ptr_unpriv(aux))
				goto next_insn;

			/* instead of changing every JIT dealing with tail_call
			 * emit two extra insns:
			 * if (index >= max_entries) goto out;
			 * index &= array->index_mask;
			 * to avoid out-of-bounds cpu speculation
			 */
			map_ptr = aux->map_ptr_state.map_ptr;
			insn_buf[0] = BPF_JMP_IMM(BPF_JGE, BPF_REG_3,
						  map_ptr->max_entries, 2);
			insn_buf[1] = BPF_ALU32_IMM(BPF_AND, BPF_REG_3,
						    container_of(map_ptr,
								 struct bpf_array,
								 map)->index_mask);
			insn_buf[2] = *insn;
			cnt = 3;
			insn = bpf_patch_list_add(env, i, insn_buf, cnt);
			if (IS_ERR(insn))
				return PTR_ERR(insn);
			goto next_insn;
		}

		aux = &env->insn_aux_data[i];
		if (aux->arg_prog) {
			/* The verifier will process callback_fn as many times as necessary
			 * with different maps and the register states prepared by
			 * set_timer_callback_state will be accurate.
			 *
			 * The following use case is valid:
			 *   map1 is shared by prog1, prog2, prog3.
			 *   prog1 calls bpf_timer_init for some map1 elements
			 *   prog2 calls bpf_timer_set_callback for some map1 elements.
			 *     Those that were not bpf_timer_init-ed will return -EINVAL.
			 *   prog3 calls bpf_timer_start for some map1 elements.
			 *     Those that were not both bpf_timer_init-ed and
			 *     bpf_timer_set_callback-ed will return -EINVAL.
			 */
			struct bpf_insn ld_addrs[2] = {
				BPF_LD_IMM64(aux->arg_prog, (long)prog->aux),
			};

			insn_buf[0] = ld_addrs[0];
			insn_buf[1] = ld_addrs[1];
			insn_buf[2] = *insn;
			cnt = 3;

			insn = bpf_patch_list_add(env, i, insn_buf, cnt);
			if (IS_ERR(insn))
				return PTR_ERR(insn);
			goto patch_call_imm;
		}

		/* bpf_per_cpu_ptr() and bpf_this_cpu_ptr() */
		if (env->insn_aux_data[i].call_with_percpu_alloc_ptr) {
			/* patch with 'r1 = *(u64 *)(r1 + 0)' since for percpu data,
			 * bpf_mem_alloc() returns a ptr to the percpu data ptr.
			 */
			insn_buf[0] = BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_1, 0);
			insn_buf[1] = *insn;
			cnt = 2;

			insn = bpf_patch_list_add(env, i, insn_buf, cnt);
			if (IS_ERR(insn))
				return PTR_ERR(insn);
			goto patch_call_imm;
		}

		/* BPF_EMIT_CALL() assumptions in some of the map_gen_lookup
		 * and other inlining handlers are currently limited to 64 bit
		 * only.
		 */
		if (prog->jit_requested && BITS_PER_LONG == 64 &&
		    (insn->imm == BPF_FUNC_map_lookup_elem ||
		     insn->imm == BPF_FUNC_map_update_elem ||
		     insn->imm == BPF_FUNC_map_delete_elem ||
		     insn->imm == BPF_FUNC_map_push_elem   ||
		     insn->imm == BPF_FUNC_map_pop_elem    ||
		     insn->imm == BPF_FUNC_map_peek_elem   ||
		     insn->imm == BPF_FUNC_redirect_map    ||
		     insn->imm == BPF_FUNC_for_each_map_elem ||
		     insn->imm == BPF_FUNC_map_lookup_percpu_elem)) {
			aux = &env->insn_aux_data[i];
			if (bpf_map_ptr_poisoned(aux))
				goto patch_call_imm;

			map_ptr = aux->map_ptr_state.map_ptr;
			ops = map_ptr->ops;
			if (insn->imm == BPF_FUNC_map_lookup_elem &&
			    ops->map_gen_lookup) {
				cnt = ops->map_gen_lookup(map_ptr, insn_buf);
				if (cnt == -EOPNOTSUPP)
					goto patch_map_ops_generic;
				if (cnt <= 0 || cnt >= INSN_BUF_SIZE) {
					verifier_bug(env, "%d insns generated for map lookup", cnt);
					return -EFAULT;
				}

				if (bpf_map_is_percpu_map(map_ptr->map_type))
					prog->jit_required = true;

				insn = bpf_patch_list_add(env, i, insn_buf, cnt);
				if (IS_ERR(insn))
					return PTR_ERR(insn);
				goto next_insn;
			}

			BUILD_BUG_ON(!__same_type(ops->map_lookup_elem,
				     (void *(*)(struct bpf_map *map, void *key))NULL));
			BUILD_BUG_ON(!__same_type(ops->map_delete_elem,
				     (long (*)(struct bpf_map *map, void *key))NULL));
			BUILD_BUG_ON(!__same_type(ops->map_update_elem,
				     (long (*)(struct bpf_map *map, void *key, void *value,
					      u64 flags))NULL));
			BUILD_BUG_ON(!__same_type(ops->map_push_elem,
				     (long (*)(struct bpf_map *map, void *value,
					      u64 flags))NULL));
			BUILD_BUG_ON(!__same_type(ops->map_pop_elem,
				     (long (*)(struct bpf_map *map, void *value))NULL));
			BUILD_BUG_ON(!__same_type(ops->map_peek_elem,
				     (long (*)(struct bpf_map *map, void *value))NULL));
			BUILD_BUG_ON(!__same_type(ops->map_redirect,
				     (long (*)(struct bpf_map *map, u64 index, u64 flags))NULL));
			BUILD_BUG_ON(!__same_type(ops->map_for_each_callback,
				     (long (*)(struct bpf_map *map,
					      bpf_callback_t callback_fn,
					      void *callback_ctx,
					      u64 flags))NULL));
			BUILD_BUG_ON(!__same_type(ops->map_lookup_percpu_elem,
				     (void *(*)(struct bpf_map *map, void *key, u32 cpu))NULL));

patch_map_ops_generic:
			switch (insn->imm) {
			case BPF_FUNC_map_lookup_elem:
				insn->imm = BPF_CALL_IMM(ops->map_lookup_elem);
				goto next_insn;
			case BPF_FUNC_map_update_elem:
				insn->imm = BPF_CALL_IMM(ops->map_update_elem);
				goto next_insn;
			case BPF_FUNC_map_delete_elem:
				insn->imm = BPF_CALL_IMM(ops->map_delete_elem);
				goto next_insn;
			case BPF_FUNC_map_push_elem:
				insn->imm = BPF_CALL_IMM(ops->map_push_elem);
				goto next_insn;
			case BPF_FUNC_map_pop_elem:
				insn->imm = BPF_CALL_IMM(ops->map_pop_elem);
				goto next_insn;
			case BPF_FUNC_map_peek_elem:
				insn->imm = BPF_CALL_IMM(ops->map_peek_elem);
				goto next_insn;
			case BPF_FUNC_redirect_map:
				insn->imm = BPF_CALL_IMM(ops->map_redirect);
				goto next_insn;
			case BPF_FUNC_for_each_map_elem:
				insn->imm = BPF_CALL_IMM(ops->map_for_each_callback);
				goto next_insn;
			case BPF_FUNC_map_lookup_percpu_elem:
				insn->imm = BPF_CALL_IMM(ops->map_lookup_percpu_elem);
				goto next_insn;
			}

			goto patch_call_imm;
		}

		/* Implement bpf_jiffies64 inline. */
		if (prog->jit_requested && BITS_PER_LONG == 64 &&
		    insn->imm == BPF_FUNC_jiffies64) {
			struct bpf_insn ld_jiffies_addr[2] = {
				BPF_LD_IMM64(BPF_REG_0,
					     (unsigned long)&jiffies),
			};

			insn_buf[0] = ld_jiffies_addr[0];
			insn_buf[1] = ld_jiffies_addr[1];
			insn_buf[2] = BPF_LDX_MEM(BPF_DW, BPF_REG_0,
						  BPF_REG_0, 0);
			cnt = 3;

			insn = bpf_patch_list_add(env, i, insn_buf, cnt);
			if (IS_ERR(insn))
				return PTR_ERR(insn);
			goto next_insn;
		}

#if defined(CONFIG_X86_64) && !defined(CONFIG_UML)
		/* Implement bpf_get_smp_processor_id() inline. */
		if (insn->imm == BPF_FUNC_get_smp_processor_id &&
		    bpf_verifier_inlines_helper_call(env, insn->imm)) {
			/* BPF_FUNC_get_smp_processor_id inlining is an
			 * optimization, so if cpu_number is ever
			 * changed in some incompatible and hard to support
			 * way, it's fine to back out this inlining logic
			 */
#ifdef CONFIG_SMP
			prog->jit_required = true;
			insn_buf[0] = BPF_MOV64_IMM(BPF_REG_0, (u32)(unsigned long)&cpu_number);
			insn_buf[1] = BPF_MOV64_PERCPU_REG(BPF_REG_0, BPF_REG_0);
			insn_buf[2] = BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_0, 0);
			cnt = 3;
#else
			insn_buf[0] = BPF_ALU32_REG(BPF_XOR, BPF_REG_0, BPF_REG_0);
			cnt = 1;
#endif
			insn = bpf_patch_list_add(env, i, insn_buf, cnt);
			if (IS_ERR(insn))
				return PTR_ERR(insn);
			goto next_insn;
		}

		/* Implement bpf_get_current_task() and bpf_get_current_task_btf() inline. */
		if ((insn->imm == BPF_FUNC_get_current_task || insn->imm == BPF_FUNC_get_current_task_btf) &&
		    bpf_verifier_inlines_helper_call(env, insn->imm)) {
			prog->jit_required = true;
			insn_buf[0] = BPF_MOV64_IMM(BPF_REG_0, (u32)(unsigned long)&current_task);
			insn_buf[1] = BPF_MOV64_PERCPU_REG(BPF_REG_0, BPF_REG_0);
			insn_buf[2] = BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_0, 0);
			cnt = 3;

			insn = bpf_patch_list_add(env, i, insn_buf, cnt);
			if (IS_ERR(insn))
				return PTR_ERR(insn);
			goto next_insn;
		}
#endif
		/* Implement bpf_get_func_arg inline. */
		if (prog_type == BPF_PROG_TYPE_TRACING &&
		    insn->imm == BPF_FUNC_get_func_arg) {
			if (eatype == BPF_TRACE_RAW_TP) {
				int nr_args = btf_type_vlen(prog->aux->attach_func_proto);

				/* skip 'void *__data' in btf_trace_##name() and save to reg0 */
				insn_buf[0] = BPF_MOV64_IMM(BPF_REG_0, nr_args - 1);
				cnt = 1;
			} else {
				/* Load nr_args from ctx - 8 */
				insn_buf[0] = BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_1, -8);
				insn_buf[1] = BPF_ALU64_IMM(BPF_AND, BPF_REG_0, 0xFF);
				cnt = 2;
			}
			insn_buf[cnt++] = BPF_JMP32_REG(BPF_JGE, BPF_REG_2, BPF_REG_0, 6);
			insn_buf[cnt++] = BPF_ALU32_IMM(BPF_LSH, BPF_REG_2, 3);
			insn_buf[cnt++] = BPF_ALU64_REG(BPF_ADD, BPF_REG_2, BPF_REG_1);
			insn_buf[cnt++] = BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_2, 0);
			insn_buf[cnt++] = BPF_STX_MEM(BPF_DW, BPF_REG_3, BPF_REG_0, 0);
			insn_buf[cnt++] = BPF_MOV64_IMM(BPF_REG_0, 0);
			insn_buf[cnt++] = BPF_JMP_A(1);
			insn_buf[cnt++] = BPF_MOV64_IMM(BPF_REG_0, -EINVAL);

			insn = bpf_patch_list_add(env, i, insn_buf, cnt);
			if (IS_ERR(insn))
				return PTR_ERR(insn);
			goto next_insn;
		}

		/* Implement bpf_get_func_ret inline. */
		if (prog_type == BPF_PROG_TYPE_TRACING &&
		    insn->imm == BPF_FUNC_get_func_ret) {
			if (eatype == BPF_TRACE_FEXIT ||
			    eatype == BPF_TRACE_FSESSION ||
			    eatype == BPF_TRACE_FEXIT_MULTI ||
			    eatype == BPF_TRACE_FSESSION_MULTI ||
			    eatype == BPF_MODIFY_RETURN) {
				/* Load nr_args from ctx - 8 */
				insn_buf[0] = BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_1, -8);
				insn_buf[1] = BPF_ALU64_IMM(BPF_AND, BPF_REG_0, 0xFF);
				insn_buf[2] = BPF_ALU64_IMM(BPF_LSH, BPF_REG_0, 3);
				insn_buf[3] = BPF_ALU64_REG(BPF_ADD, BPF_REG_0, BPF_REG_1);
				insn_buf[4] = BPF_LDX_MEM(BPF_DW, BPF_REG_3, BPF_REG_0, 0);
				insn_buf[5] = BPF_STX_MEM(BPF_DW, BPF_REG_2, BPF_REG_3, 0);
				insn_buf[6] = BPF_MOV64_IMM(BPF_REG_0, 0);
				cnt = 7;
			} else {
				insn_buf[0] = BPF_MOV64_IMM(BPF_REG_0, -EOPNOTSUPP);
				cnt = 1;
			}

			insn = bpf_patch_list_add(env, i, insn_buf, cnt);
			if (IS_ERR(insn))
				return PTR_ERR(insn);
			goto next_insn;
		}

		/* Implement get_func_arg_cnt inline. */
		if (prog_type == BPF_PROG_TYPE_TRACING &&
		    insn->imm == BPF_FUNC_get_func_arg_cnt) {
			if (eatype == BPF_TRACE_RAW_TP) {
				int nr_args = btf_type_vlen(prog->aux->attach_func_proto);

				/* skip 'void *__data' in btf_trace_##name() and save to reg0 */
				insn_buf[0] = BPF_MOV64_IMM(BPF_REG_0, nr_args - 1);
				cnt = 1;
			} else {
				/* Load nr_args from ctx - 8 */
				insn_buf[0] = BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_1, -8);
				insn_buf[1] = BPF_ALU64_IMM(BPF_AND, BPF_REG_0, 0xFF);
				cnt = 2;
			}

			insn = bpf_patch_list_add(env, i, insn_buf, cnt);
			if (IS_ERR(insn))
				return PTR_ERR(insn);
			goto next_insn;
		}

		/* Implement bpf_get_func_ip inline. */
		if (prog_type == BPF_PROG_TYPE_TRACING &&
		    insn->imm == BPF_FUNC_get_func_ip) {
			/* Load IP address from ctx - 16 */
			insn_buf[0] = BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_1, -16);

			insn = bpf_patch_list_add(env, i, insn_buf, 1);
			if (IS_ERR(insn))
				return PTR_ERR(insn);
			goto next_insn;
		}

		/* Implement bpf_get_branch_snapshot inline. */
		if (IS_ENABLED(CONFIG_PERF_EVENTS) &&
		    prog->jit_requested && BITS_PER_LONG == 64 &&
		    insn->imm == BPF_FUNC_get_branch_snapshot) {
			/* We are dealing with the following func protos:
			 * u64 bpf_get_branch_snapshot(void *buf, u32 size, u64 flags);
			 * int perf_snapshot_branch_stack(struct perf_branch_entry *entries, u32 cnt);
			 */
			const u32 br_entry_size = sizeof(struct perf_branch_entry);

			/* struct perf_branch_entry is part of UAPI and is
			 * used as an array element, so extremely unlikely to
			 * ever grow or shrink
			 */
			BUILD_BUG_ON(br_entry_size != 24);

			/* if (unlikely(flags)) return -EINVAL */
			insn_buf[0] = BPF_JMP_IMM(BPF_JNE, BPF_REG_3, 0, 7);

			/* Transform size (bytes) into number of entries (cnt = size / 24).
			 * But to avoid expensive division instruction, we implement
			 * divide-by-3 through multiplication, followed by further
			 * division by 8 through 3-bit right shift.
			 * Refer to book "Hacker's Delight, 2nd ed." by Henry S. Warren, Jr.,
			 * p. 227, chapter "Unsigned Division by 3" for details and proofs.
			 *
			 * N / 3 <=> M * N / 2^33, where M = (2^33 + 1) / 3 = 0xaaaaaaab.
			 */
			insn_buf[1] = BPF_MOV32_IMM(BPF_REG_0, 0xaaaaaaab);
			insn_buf[2] = BPF_ALU64_REG(BPF_MUL, BPF_REG_2, BPF_REG_0);
			insn_buf[3] = BPF_ALU64_IMM(BPF_RSH, BPF_REG_2, 36);

			/* call perf_snapshot_branch_stack implementation */
			insn_buf[4] = BPF_EMIT_CALL(static_call_query(perf_snapshot_branch_stack));
			/* if (entry_cnt == 0) return -ENOENT */
			insn_buf[5] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 4);
			/* return entry_cnt * sizeof(struct perf_branch_entry) */
			insn_buf[6] = BPF_ALU32_IMM(BPF_MUL, BPF_REG_0, br_entry_size);
			insn_buf[7] = BPF_JMP_A(3);
			/* return -EINVAL; */
			insn_buf[8] = BPF_MOV64_IMM(BPF_REG_0, -EINVAL);
			insn_buf[9] = BPF_JMP_A(1);
			/* return -ENOENT; */
			insn_buf[10] = BPF_MOV64_IMM(BPF_REG_0, -ENOENT);
			cnt = 11;

			insn = bpf_patch_list_add(env, i, insn_buf, cnt);
			if (IS_ERR(insn))
				return PTR_ERR(insn);
			goto next_insn;
		}

		/* Implement bpf_kptr_xchg inline */
		if (prog->jit_requested && BITS_PER_LONG == 64 &&
		    insn->imm == BPF_FUNC_kptr_xchg &&
		    bpf_jit_supports_ptr_xchg()) {
			insn_buf[0] = BPF_MOV64_REG(BPF_REG_0, BPF_REG_2);
			insn_buf[1] = BPF_ATOMIC_OP(BPF_DW, BPF_XCHG, BPF_REG_1, BPF_REG_0, 0);
			cnt = 2;

			insn = bpf_patch_list_add(env, i, insn_buf, cnt);
			if (IS_ERR(insn))
				return PTR_ERR(insn);
			goto next_insn;
		}
patch_call_imm:
		/* as the states that got to the call found it, see note_helper_prog_type() */
		fn = bpf_helper_proto_as(env, insn->imm, env->insn_aux_data[i].helper_prog_type);
		/* all functions that have prototype and verifier allowed
		 * programs to call them, must be real in-kernel functions
		 */
		if (!fn->func) {
			verifier_bug(env,
				     "not inlined functions %s#%d is missing func",
				     func_id_name(insn->imm), insn->imm);
			return -EFAULT;
		}
		insn->imm = BPF_CALL_IMM(fn->func);
next_insn:
		if (subprogs[cur_subprog + 1].start == i + 1) {
			subprogs[cur_subprog].stack_depth += stack_depth_extra;
			subprogs[cur_subprog].stack_extra = stack_depth_extra;

			stack_depth = subprogs[cur_subprog].stack_depth;
			if (stack_depth > MAX_BPF_STACK && !prog->jit_requested) {
				verbose(env, "stack size %d(extra %d) is too large\n",
					stack_depth, stack_depth_extra);
				return -EINVAL;
			}
			cur_subprog++;
			stack_depth = subprogs[cur_subprog].stack_depth;
			stack_depth_extra = 0;
		}
		i++;
		insn = &prog->insnsi[i];
	}

	ret = bpf_patch_list_commit(env);
	if (ret)
		return ret;
	prog = env->prog;

	env->prog->aux->stack_depth = subprogs[0].stack_depth;
	for (i = 0; i < env->subprog_cnt; i++) {
		int stack_slots = subprogs[i].stack_extra / 8;
		/* an invocation begins, see bpf_timed_may_goto_save() for async callbacks */
		bool main_prog = tmg && !i;
		/* only a helper calls it, in a loop that ends when it returns 1 */
		bool loop_cb = tmg && i && subprogs[i].is_loop_cb && !subprogs[i].is_called &&
			       !subprogs[i].is_other_cb && !subprogs[i].is_async_cb;
		/*
		 * The continuation of a parked coroutine frame, which a program calls, see
		 * check_coro_callx() in verifier.c, with no kernel code in between that would do
		 * bpf_timed_may_goto_save() for it: it does that itself. What it finds is the
		 * slice of its caller when that is the same program, and what an invocation of
		 * this program left on the CPU some time ago when it is another one. It keeps
		 * that in its stack and owns the slice, like the caller of an async callback, and
		 * puts it back where it leaves if it still owns it: such a function can also be
		 * called by a function of the program, another continuation among them, and an
		 * invocation of the program can interrupt it or go on next to it. Also where the
		 * kernel unwinds it: its caller may have interrupted an invocation of this program,
		 * which goes on with the slice when the caller is unwound.
		 */
		bool coro = tmg && i && subprogs[i].coro_parked;
		int saved_off = 0;

		if (timed_may_goto ? !main_prog && !loop_cb && !coro : !stack_slots)
			continue;
		if (stack_slots > 1) {
			verifier_bug(env, "stack_slots supports may_goto only");
			return -EFAULT;
		}

		cnt = 0;
		stack_depth = subprogs[i].stack_depth;
		if (timed_may_goto) {
			struct bpf_insn ld_tmg[] = {
				BPF_LD_IMM64(BPF_REG_0, (__force unsigned long)tmg)
			};
			int count_off = offsetof(struct bpf_timed_may_goto, count);
			int timestamp_off = offsetof(struct bpf_timed_may_goto, timestamp);
			int owner_off = offsetof(struct bpf_timed_may_goto, owner);

			/* R0 has nothing at the entry */
			insn_buf[cnt++] = ld_tmg[0];
			insn_buf[cnt++] = ld_tmg[1];
			insn_buf[cnt++] = BPF_MOV64_PERCPU_REG(BPF_REG_0, BPF_REG_0);
			if (main_prog) {
				insn_buf[cnt++] = BPF_ST_MEM(BPF_DW, BPF_REG_0, count_off,
							     BPF_MAX_TIMED_LOOPS);
				insn_buf[cnt++] = BPF_ST_MEM(BPF_DW, BPF_REG_0, timestamp_off, 0);
				insn_buf[cnt++] = BPF_ST_MEM(BPF_DW, BPF_REG_0, owner_off, 0);
			} else if (coro) {
				/* three words below all that the function has in its stack */
				saved_off = -round_up(stack_depth, BPF_REG_SIZE) -
					    (int)sizeof(struct bpf_timed_may_goto);
				subprogs[i].stack_depth = -saved_off;
				/*
				 * R1 to R5 may be arguments, of a call of the program if not of
				 * the continuation. AX is free between the insns of a program, and
				 * no insn that blinding rewrites stands where it is in use.
				 */
				insn_buf[cnt++] = BPF_LDX_MEM(BPF_DW, BPF_REG_AX, BPF_REG_0,
							      count_off);
				insn_buf[cnt++] = BPF_STX_MEM(BPF_DW, BPF_REG_FP, BPF_REG_AX,
							      saved_off + count_off);
				insn_buf[cnt++] = BPF_LDX_MEM(BPF_DW, BPF_REG_AX, BPF_REG_0,
							      timestamp_off);
				insn_buf[cnt++] = BPF_STX_MEM(BPF_DW, BPF_REG_FP, BPF_REG_AX,
							      saved_off + timestamp_off);
				insn_buf[cnt++] = BPF_LDX_MEM(BPF_DW, BPF_REG_AX, BPF_REG_0,
							      owner_off);
				insn_buf[cnt++] = BPF_STX_MEM(BPF_DW, BPF_REG_FP, BPF_REG_AX,
							      saved_off + owner_off);
				insn_buf[cnt++] = BPF_MOV64_REG(BPF_REG_AX, BPF_REG_FP);
				insn_buf[cnt++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_AX, saved_off);
				insn_buf[cnt++] = BPF_STX_MEM(BPF_DW, BPF_REG_0, BPF_REG_AX,
							      owner_off);
				insn_buf[cnt++] = BPF_ST_MEM(BPF_DW, BPF_REG_0, count_off,
							     BPF_MAX_TIMED_LOOPS);
				insn_buf[cnt++] = BPF_ST_MEM(BPF_DW, BPF_REG_0, timestamp_off, 0);
			} else {
				/*
				 * The time is up, but the helper would call the function again and
				 * again. End its loop. The verifier has seen that: the loop can end
				 * after each call.
				 *
				 * This is the one place where time that is up does not end the
				 * program, also where every frame can unwind, see
				 * check_may_goto_site(): the helper returns the number of calls
				 * that it made, and the program goes on with that until its next
				 * may_goto. It gets here when no may_goto runs between the one that
				 * found the time up, which falls through, and this entry.
				 *
				 * The check is no site, as may_goto of the program is one, because
				 * what carries that one does not carry it:
				 *  - A site is an insn of the program at which every frame of a
				 *    subprog is left, one answer per subprog. No insn stands for
				 *    this check in the main pass, and it is a way out of a frame
				 *    only if a loop helper called: it would take a visit where
				 *    such a helper enters its callback, and a kind of its own.
				 *  - That only loop helpers call the subprog is known when the
				 *    pass is over. 'stuck' hands "cannot unwind" to the run that
				 *    follows. Nothing hands this on.
				 *  - Whether the program has a timed may_goto at all is known
				 *    here, after the landing pads were emitted.
				 *  - Each call of such a helper would be a call that the kernel
				 *    unwinds through, with a landing pad in its caller, in every
				 *    program that has a may_goto anywhere.
				 */
				insn_buf[cnt++] = BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_0,
							      count_off);
				insn_buf[cnt++] = BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 2);
				insn_buf[cnt++] = BPF_MOV64_IMM(BPF_REG_0, 1);
				insn_buf[cnt++] = BPF_EXIT_INSN();
			}
		} else {
			/* Add ST insn to subprog prologue to init extra stack */
			insn_buf[cnt++] = BPF_ST_MEM(BPF_DW, BPF_REG_FP, -stack_depth,
						     BPF_MAX_LOOPS);
		}
		/* jumps to the first insn of the subprog skip the setup */
		ret = bpf_patch_list_insert(env, subprogs[i].start, insn_buf, cnt);
		if (ret)
			return ret;
		if (coro) {
			struct bpf_insn ld_r3[] = {
				BPF_LD_IMM64(BPF_REG_3, (__force unsigned long)tmg)
			};
			int count_off = offsetof(struct bpf_timed_may_goto, count);
			int timestamp_off = offsetof(struct bpf_timed_may_goto, timestamp);
			int owner_off = offsetof(struct bpf_timed_may_goto, owner);
			struct bpf_insn back[16], *exit;
			int j, n = 0;

			/* an exit has its value in R0, and in R2 if it is a pair or it is kexit */
			back[n++] = ld_r3[0];
			back[n++] = ld_r3[1];
			back[n++] = BPF_MOV64_PERCPU_REG(BPF_REG_3, BPF_REG_3);
			back[n++] = BPF_LDX_MEM(BPF_DW, BPF_REG_4, BPF_REG_3, owner_off);
			back[n++] = BPF_MOV64_REG(BPF_REG_5, BPF_REG_FP);
			back[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_5, saved_off);
			back[n++] = BPF_JMP_REG(BPF_JNE, BPF_REG_4, BPF_REG_5, 6);
			back[n++] = BPF_LDX_MEM(BPF_DW, BPF_REG_4, BPF_REG_FP,
						saved_off + count_off);
			back[n++] = BPF_STX_MEM(BPF_DW, BPF_REG_3, BPF_REG_4, count_off);
			back[n++] = BPF_LDX_MEM(BPF_DW, BPF_REG_4, BPF_REG_FP,
						saved_off + timestamp_off);
			back[n++] = BPF_STX_MEM(BPF_DW, BPF_REG_3, BPF_REG_4, timestamp_off);
			back[n++] = BPF_LDX_MEM(BPF_DW, BPF_REG_4, BPF_REG_FP,
						saved_off + owner_off);
			back[n++] = BPF_STX_MEM(BPF_DW, BPF_REG_3, BPF_REG_4, owner_off);
			for (j = subprogs[i].start; j < subprogs[i + 1].start; j++) {
				/* exit, kexit, and unwind_exit, which only a call of it has */
				if (prog->insnsi[j].code != (BPF_JMP | BPF_EXIT))
					continue;
				back[n] = prog->insnsi[j];
				exit = bpf_patch_list_add(env, j, back, n + 1);
				if (IS_ERR(exit))
					return PTR_ERR(exit);
			}
		}
	}

	ret = bpf_patch_list_commit(env);
	if (ret)
		return ret;
	prog = env->prog;

	/* Since poke tab is now finalized, publish aux to tracker. */
	for (i = 0; i < prog->aux->size_poke_tab; i++) {
		map_ptr = prog->aux->poke_tab[i].tail_call.map;
		if (!map_ptr->ops->map_poke_track ||
		    !map_ptr->ops->map_poke_untrack ||
		    !map_ptr->ops->map_poke_run) {
			verifier_bug(env, "poke tab is misconfigured");
			return -EFAULT;
		}

		ret = map_ptr->ops->map_poke_track(map_ptr, prog->aux);
		if (ret < 0) {
			verbose(env, "tracking tail call prog failed\n");
			return ret;
		}
	}

	return 0;
}

/*
 * When the callback can unwind and unwind_goto follows the call of bpf_loop,
 * unwind_goto follows the call of the callback, and the pad restores r6-r8 and
 * jumps to the pad after the call of bpf_loop with the r0 of the callback, which
 * the verifier has checked with the state of that r0. That pad has to be one the
 * verifier saw: a loop of no rounds never runs its callback, and an unwind_exit
 * may sit on a path never taken, so the pad can be dead, and dead code is
 * removed after the inlining, which sends a jump into it to whatever follows.
 * The unwind_goto that followed the call of bpf_loop doesn't follow a call
 * anymore and becomes a no-op jump either way. A loop of no rounds may have no
 * unwind_goto at all, since the verifier asked for none, and then the insn after
 * the call is some other insn.
 *
 * kgoto after the call of bpf_loop is the same for kexit of the callback: a pad
 * of its own, which goes where that kgoto went. The verifier emitted the pad
 * that it goes to, so it is not dead code. The callback may have no kexit yet:
 * bpf_insert_recursion_checks() adds the one of the check of a recursive
 * callback when the loop is inlined already. With both there are two pads, one
 * per way in which the callback is left, and neither is on the normal path.
 */
static int inline_bpf_loop(struct bpf_verifier_env *env, int position,
			   s32 stack_base, u32 callback_subprogno)
{
	const struct bpf_subprog_info *cb = &env->subprog_info[callback_subprogno];
	s32 r6_offset = stack_base + 0 * BPF_REG_SIZE;
	s32 r7_offset = stack_base + 1 * BPF_REG_SIZE;
	s32 r8_offset = stack_base + 2 * BPF_REG_SIZE;
	int reg_loop_max = BPF_REG_6;
	int reg_loop_cnt = BPF_REG_7;
	int reg_loop_ctx = BPF_REG_8;
	struct bpf_insn *unwind_goto = &env->prog->insnsi[position + 1], *kgoto;
	bool has_unwind_goto = bpf_is_unwind_goto(unwind_goto);
	int pad_off = bpf_jmp_offset(unwind_goto);
	bool pad = has_unwind_goto && cb->can_unwind &&
		   env->insn_aux_data[position + 2 + pad_off].seen;
	bool has_kgoto, kpad;
	/* where each pad goes: the insn of the old image */
	int to[2], npads = 0, i, off;

	struct bpf_insn *insn_buf = env->insn_buf;
	struct bpf_insn *last;
	u32 cnt = 0, call;

	kgoto = unwind_goto + has_unwind_goto;
	has_kgoto = bpf_is_kgoto(kgoto);
	kpad = has_kgoto && bpf_subprog_kunwinds(cb);
	if (pad)
		to[npads++] = position + 2 + pad_off;
	if (kpad)
		to[npads++] = kgoto - env->prog->insnsi + 1 + bpf_jmp_offset(kgoto);

	/* This represents an inlined version of bpf_iter.c:bpf_loop,
	 * be careful to modify this code in sync.
	 */

	/* Return error and jump to the end of the patch if
	 * expected number of iterations is too big.
	 */
	insn_buf[cnt++] = BPF_JMP_IMM(BPF_JLE, BPF_REG_1, BPF_MAX_LOOPS, 2 + 4 * npads);
	insn_buf[cnt++] = BPF_MOV64_IMM(BPF_REG_0, -E2BIG);
	insn_buf[cnt++] = BPF_JMP_IMM(BPF_JA, 0, 0, 16 + 5 * npads);
	for (i = 0; i < npads; i++) {
		/*
		 * A pad: r0 is what the callback left with. Nothing falls through to this
		 * place, so no jump around the pad is needed.
		 */
		insn_buf[cnt++] = BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_10, r6_offset);
		insn_buf[cnt++] = BPF_LDX_MEM(BPF_DW, BPF_REG_7, BPF_REG_10, r7_offset);
		insn_buf[cnt++] = BPF_LDX_MEM(BPF_DW, BPF_REG_8, BPF_REG_10, r8_offset);
		/* to the pad of the caller, the target is set below */
		insn_buf[cnt++] = BPF_JMP32_A(0);
	}
	/* spill R6, R7, R8 to use these as loop vars */
	insn_buf[cnt++] = BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_6, r6_offset);
	insn_buf[cnt++] = BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_7, r7_offset);
	insn_buf[cnt++] = BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_8, r8_offset);
	/* initialize loop vars */
	insn_buf[cnt++] = BPF_MOV64_REG(reg_loop_max, BPF_REG_1);
	insn_buf[cnt++] = BPF_MOV64_IMM(reg_loop_cnt, 0);
	insn_buf[cnt++] = BPF_MOV64_REG(reg_loop_ctx, BPF_REG_3);
	/* loop header,
	 * if reg_loop_cnt >= reg_loop_max skip the loop body
	 */
	insn_buf[cnt++] = BPF_JMP_REG(BPF_JGE, reg_loop_cnt, reg_loop_max, 5 + npads);
	/* callback call, the offset is set below */
	insn_buf[cnt++] = BPF_MOV64_REG(BPF_REG_1, reg_loop_cnt);
	insn_buf[cnt++] = BPF_MOV64_REG(BPF_REG_2, reg_loop_ctx);
	call = cnt;
	insn_buf[cnt++] = BPF_CALL_REL(0);
	/*
	 * To the pads above: when the callback left with unwind_exit, and when it left with
	 * kexit. The first pad is insn 3 of the patch, each has 4 insns.
	 */
	if (pad) {
		off = 3 - (int)cnt - 1;
		insn_buf[cnt++] = BPF_RAW_INSN(BPF_JMP | BPF_JCOND, 0, BPF_UNWIND_GOTO, off, 0);
	}
	if (kpad) {
		off = 3 + 4 * (npads - 1) - (int)cnt - 1;
		insn_buf[cnt++] = BPF_RAW_INSN(BPF_JMP32 | BPF_JCOND, 0, BPF_KGOTO, 0, off);
	}
	/* increment loop counter */
	insn_buf[cnt++] = BPF_ALU64_IMM(BPF_ADD, reg_loop_cnt, 1);
	/* jump to loop header if callback returned 0 */
	insn_buf[cnt++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, -6 - npads);
	/* return value of bpf_loop,
	 * set R0 to the number of iterations
	 */
	insn_buf[cnt++] = BPF_MOV64_REG(BPF_REG_0, reg_loop_cnt);
	/* restore original values of R6, R7, R8 */
	insn_buf[cnt++] = BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_10, r6_offset);
	insn_buf[cnt++] = BPF_LDX_MEM(BPF_DW, BPF_REG_7, BPF_REG_10, r7_offset);
	insn_buf[cnt++] = BPF_LDX_MEM(BPF_DW, BPF_REG_8, BPF_REG_10, r8_offset);

	last = bpf_patch_list_add(env, position, insn_buf, cnt);
	if (IS_ERR(last))
		return PTR_ERR(last);
	/* the BPF_CALL_REL instruction */
	bpf_patch_list_jump(&env->patch_list, last - (cnt - 1 - call),
			    env->subprog_info[callback_subprogno].start, 0);
	/*
	 * The last insn of a pad goes where the unwind_goto or the kgoto after the call of
	 * bpf_loop goes, whichever side of the call that is. A long jump, since they may jump
	 * as far as a jump can.
	 */
	for (i = 0; i < npads; i++)
		bpf_patch_list_jump(&env->patch_list, last - (cnt - 1 - (6 + 4 * i)), to[i], 0);
	/* The unwind_goto and the kgoto after the call of bpf_loop follow no call anymore. */
	if (has_unwind_goto)
		*unwind_goto = BPF_JMP_A(0);
	if (has_kgoto)
		*kgoto = BPF_JMP_A(0);
	return 0;
}

static bool is_bpf_loop_call(struct bpf_insn *insn)
{
	return insn->code == (BPF_JMP | BPF_CALL) &&
		insn->src_reg == 0 &&
		insn->imm == BPF_FUNC_loop;
}

/* For all sub-programs in the program (including main) check
 * insn_aux_data to see if there are bpf_loop calls that require
 * inlining. If such calls are found the calls are replaced with a
 * sequence of instructions produced by `inline_bpf_loop` function and
 * subprog stack_depth is increased by the size of 3 registers.
 * This stack space is used to spill values of the R6, R7, R8.  These
 * registers are used to store the loop bound, counter and context
 * variables.
 */
int bpf_optimize_bpf_loop(struct bpf_verifier_env *env)
{
	struct bpf_subprog_info *subprogs = env->subprog_info;
	int i, cur_subprog = 0, err;
	struct bpf_insn *insn = env->prog->insnsi;
	int insn_cnt = env->prog->len;
	u16 stack_depth = subprogs[cur_subprog].stack_depth;
	u16 stack_depth_roundup = round_up(stack_depth, 8) - stack_depth;
	u16 stack_depth_extra = 0;

	for (i = 0; i < insn_cnt; i++, insn++) {
		struct bpf_loop_inline_state *inline_state =
			&env->insn_aux_data[i].loop_inline_state;

		/*
		 * The callback that takes a stack in arena is not for a call from the program.
		 * The callback of a loop without iterations is dead code, it goes away.
		 */
		if (is_bpf_loop_call(insn) && inline_state->fit_for_inline &&
		    env->insn_aux_data[subprogs[inline_state->callback_subprogno].start].seen &&
		    !subprogs[inline_state->callback_subprogno].arena_stack_entry) {
			stack_depth_extra = BPF_REG_SIZE * 3 + stack_depth_roundup;
			err = inline_bpf_loop(env, i,
					      -(stack_depth + stack_depth_extra),
					      inline_state->callback_subprogno);
			if (err)
				return err;
		}

		if (subprogs[cur_subprog + 1].start == i + 1) {
			subprogs[cur_subprog].stack_depth += stack_depth_extra;
			cur_subprog++;
			stack_depth = subprogs[cur_subprog].stack_depth;
			stack_depth_roundup = round_up(stack_depth, 8) - stack_depth;
			stack_depth_extra = 0;
		}
	}

	env->prog->aux->stack_depth = env->subprog_info[0].stack_depth;

	return bpf_patch_list_commit(env);
}

/*
 * Remove unnecessary spill/fill pairs, members of fastcall pattern.
 * check_max_stack_depth() has adjusted the stack depth of subprograms.
 */
int bpf_remove_fastcall_spills_fills(struct bpf_verifier_env *env)
{
	struct bpf_insn_aux_data *aux = env->insn_aux_data;
	struct bpf_insn *insn = env->prog->insnsi;
	int insn_cnt = env->prog->len;
	u32 spills_num;
	int i, j;

	for (i = 0; i < insn_cnt; i++, insn++) {
		if (aux[i].fastcall_spills_num > 0) {
			spills_num = aux[i].fastcall_spills_num;
			/* NOPs would be removed by opt_remove_nops() */
			for (j = 1; j <= spills_num; ++j) {
				*(insn - j) = NOP;
				*(insn + j) = NOP;
			}
		}
	}

	return 0;
}
