// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#include <linux/bpf.h>
#include <linux/bpf_verifier.h>
#include <linux/btf_ids.h>
#include <linux/filter.h>
#include <linux/slab.h>
#include "diagnostics.h"
#include "exception.h"

#define verbose(env, fmt, args...) bpf_verifier_log_write(env, fmt, ##args)

#define MIN_BPF_CLEANUP_INFO_SIZE	12
#define MAX_CLEANUP_INFO_REC_SIZE	252	/* as MAX_FUNCINFO_REC_SIZE */

int bpf_exc_check_info(struct bpf_verifier_env *env, const union bpf_attr *attr,
		       bpfptr_t uattr)
{
	u32 krec_size = sizeof(struct bpf_cleanup_info);
	u32 i, nrec, urec_size, min_size, prev_end = 0;
	struct bpf_cleanup_info *krecord;
	bpfptr_t urecord;
	int ret = -EINVAL;

	nrec = attr->cleanup_info_cnt;
	if (!nrec)
		return 0;
	if (nrec > env->prog->len) {
		verbose(env, "cleanup info has %u records for %u instructions\n",
			nrec, env->prog->len);
		return -EINVAL;
	}

	urec_size = attr->cleanup_info_rec_size;
	if (urec_size < MIN_BPF_CLEANUP_INFO_SIZE ||
	    urec_size > MAX_CLEANUP_INFO_REC_SIZE ||
	    urec_size % sizeof(u32)) {
		verbose(env, "invalid cleanup info rec size %u\n", urec_size);
		return -EINVAL;
	}

	krecord = kvcalloc(nrec, krec_size, GFP_KERNEL_ACCOUNT | __GFP_NOWARN);
	if (!krecord)
		return -ENOMEM;

	min_size = min_t(u32, krec_size, urec_size);
	urecord = make_bpfptr(attr->cleanup_info, uattr.is_kernel);
	for (i = 0; i < nrec; i++) {
		struct bpf_subprog_info *sb, *se, *sl;
		struct bpf_cleanup_info *rec = &krecord[i];

		/*
		 * A record longer than the kernel's is taken only if the rest
		 * is zero. Unlike func_info, no size is handed back for the
		 * loader to zero the rest and retry: a field this kernel does
		 * not know could change what a pad does.
		 */
		ret = bpf_check_uarg_tail_zero(urecord, krec_size, urec_size);
		if (ret) {
			if (ret == -E2BIG)
				verbose(env, "nonzero tailing record in cleanup info\n");
			goto err_free;
		}

		if (copy_from_bpfptr(rec, urecord, min_size)) {
			ret = -EFAULT;
			goto err_free;
		}
		bpfptr_add(&urecord, urec_size);

		ret = -EINVAL;
		if (rec->begin_off >= rec->end_off) {
			verbose(env, "cleanup_info[%u]: begin %u >= end %u\n",
				i, rec->begin_off, rec->end_off);
			goto err_free;
		}
		if (rec->begin_off < prev_end) {
			verbose(env,
				"cleanup_info[%u]: range [%u,%u) is unsorted or overlaps the previous record\n",
				i, rec->begin_off, rec->end_off);
			goto err_free;
		}
		prev_end = rec->end_off;

		sb = bpf_find_containing_subprog(env, rec->begin_off);
		se = bpf_find_containing_subprog(env, rec->end_off - 1);
		sl = bpf_find_containing_subprog(env, rec->landing_pad_off);
		if (!sb || !se || !sl) {
			verbose(env, "cleanup_info[%u]: offset out of range\n", i);
			goto err_free;
		}
		if (sb != se || sb != sl) {
			verbose(env,
				"cleanup_info[%u]: range/landing pad span multiple subprogs\n",
				i);
			goto err_free;
		}
		/*
		 * A zero opcode is the second half of a 16-byte insn, not an
		 * insn. end_off is exclusive, so it may be one past the last.
		 */
		if (!env->prog->insnsi[rec->begin_off].code ||
		    !env->prog->insnsi[rec->landing_pad_off].code ||
		    (rec->end_off < env->prog->len &&
		     !env->prog->insnsi[rec->end_off].code)) {
			verbose(env, "cleanup_info[%u]: points at invalid insn\n", i);
			goto err_free;
		}
	}

	/* Reject a landing pad inside any call-site range, its own included. */
	ret = -EINVAL;
	for (i = 0; i < nrec; i++) {
		u32 pad = krecord[i].landing_pad_off;
		u32 l = 0, r = nrec;

		while (l < r) {
			u32 m = l + (r - l) / 2;

			if (pad < krecord[m].begin_off) {
				r = m;
			} else if (pad >= krecord[m].end_off) {
				l = m + 1;
			} else {
				verbose(env,
					"cleanup_info[%u]: landing pad %u is inside the call-site range of cleanup_info[%u]\n",
					i, pad, m);
				goto err_free;
			}
		}
	}

	env->cleanup_info = krecord;
	env->cleanup_info_cnt = nrec;
	return 0;

err_free:
	kvfree(krecord);
	return ret;
}

BTF_ID_LIST_SINGLE(bpf_unwind_id, func, bpf_unwind)
BTF_ID_LIST_SINGLE(bpf_unwind_resume_id, func, bpf_unwind_resume)

static bool is_kfunc(const struct bpf_insn *insn, u32 btf_id)
{
	return bpf_pseudo_kfunc_call(insn) && !insn->off && insn->imm == btf_id;
}

static bool is_resume(const struct bpf_insn *insn)
{
	return is_kfunc(insn, bpf_unwind_resume_id[0]);
}

bool bpf_is_unwind_kfunc(const struct bpf_insn *insn)
{
	return is_kfunc(insn, bpf_unwind_id[0]) || is_resume(insn);
}

static struct bpf_subprog_info *callee_of(struct bpf_verifier_env *env, u32 idx)
{
	return bpf_find_containing_subprog(env, idx + env->prog->insnsi[idx].imm + 1);
}

/* Can an unwind start at insn @idx, or come back through it out of a callee? */
static bool unwinds_at(struct bpf_verifier_env *env, u32 idx)
{
	const struct bpf_insn *insn = &env->prog->insnsi[idx];

	return bpf_is_unwind_kfunc(insn) ||
	       (bpf_pseudo_call(insn) && callee_of(env, idx)->might_unwind) ||
	       (bpf_is_callx(insn) && env->callx_unwinds);
}

/*
 * Can any subprog whose address is taken unwind? The callee of a callx is one
 * of them. With @mark, all of them say in r3 how they returned, so that the
 * caller of a callx can read r3 whichever of them it called.
 */
static bool addr_taken_unwinds(struct bpf_verifier_env *env, bool mark)
{
	struct bpf_subprog_info *sub;
	bool ret = false;
	u32 i;

	for (i = 0; i < env->prog->len; i++) {
		if (!bpf_pseudo_func(&env->prog->insnsi[i]))
			continue;
		sub = callee_of(env, i);
		ret |= sub->might_unwind;
		sub->ret_unwind |= mark;
	}
	for (i = 0; i < env->func_ptr_cnt; i++) {
		sub = bpf_find_containing_subprog(env, env->func_ptrs[i].xlated_off);
		ret |= sub->might_unwind;
		sub->ret_unwind |= mark;
	}
	return ret;
}

/*
 * Compute to a fixpoint which subprogs can unwind: one that calls
 * bpf_unwind() or bpf_unwind_resume(), one that calls a subprog that can,
 * and one with a callx once any address-taken subprog can. Returns whether
 * any can.
 */
static bool mark_might_unwind(struct bpf_verifier_env *env)
{
	struct bpf_subprog_info *sub;
	bool changed, any = false;
	u32 i;

	do {
		changed = false;
		for (i = 0; i < env->prog->len; i++) {
			sub = bpf_find_containing_subprog(env, i);
			if (sub->might_unwind || !unwinds_at(env, i))
				continue;
			sub->might_unwind = sub->ret_unwind = changed = any = true;
		}
		if (env->has_callx && !env->callx_unwinds && addr_taken_unwinds(env, false))
			env->callx_unwinds = changed = true;
	} while (changed);

	if (env->callx_unwinds)
		addr_taken_unwinds(env, true);
	return any;
}

/* The landing pad of the record covering insn @idx, or -1. */
static int pad_of(struct bpf_verifier_env *env, u32 idx)
{
	u32 l = 0, r = env->cleanup_info_cnt;

	while (l < r) {
		u32 m = l + (r - l) / 2;

		if (idx < env->cleanup_info[m].begin_off)
			r = m;
		else if (idx >= env->cleanup_info[m].end_off)
			l = m + 1;
		else
			return env->cleanup_info[m].landing_pad_off;
	}
	return -1;
}

/*
 * Replace insn @off with @buf[0..@cnt). Jumps and records that named @off go
 * on naming it, which is now the first insn of the patch; everything after
 * @off moves down by @cnt - 1.
 */
static int patch(struct bpf_verifier_env *env, u32 off, struct bpf_insn *buf, u32 cnt)
{
	u32 i, delta = cnt - 1, orig_idx = env->insn_aux_data[off].orig_idx;
	struct bpf_prog *prog;

	/* The insns of a patch are not adjusted for the patch itself. */
	if (bpf_pseudo_call(&buf[0]) && buf[0].imm >= 0)
		buf[0].imm += delta;
	prog = bpf_patch_insn_data(env, off, buf, cnt);
	if (!prog)
		return -ENOMEM;
	env->prog = prog;

	for (i = 0; i < cnt; i++)
		env->insn_aux_data[off + i].orig_idx = orig_idx;
	for (i = 0; i < env->subprog_cnt; i++)
		if (env->subprog_info[i].exit_idx != U32_MAX &&
		    env->subprog_info[i].exit_idx >= off)
			env->subprog_info[i].exit_idx += delta;
	for (i = 0; i < env->cleanup_info_cnt; i++) {
		struct bpf_cleanup_info *rec = &env->cleanup_info[i];

		if (rec->begin_off > off)
			rec->begin_off += delta;
		if (rec->end_off > off)
			rec->end_off += delta;
		if (rec->landing_pad_off > off)
			rec->landing_pad_off += delta;
	}
	return 0;
}

/*
 * The offset of a jump that will sit at index @from once the patch at @off
 * has added @delta insns, to the insn that is at @tgt before the patch.
 */
static s32 jmp_off(u32 off, u32 delta, u32 from, u32 tgt)
{
	if (tgt > off)
		tgt += delta;
	return (s32)tgt - (s32)from - 1;
}

/* Replace insn @off with @buf[0..@n) followed by 'goto @tgt'. */
static int patch_jump(struct bpf_verifier_env *env, u32 off, struct bpf_insn *buf, u32 n,
		      u32 tgt)
{
	s32 rel = jmp_off(off, n, off + n, tgt);
	int err;

	buf[n] = rel == (s16)rel ? BPF_JMP_A(rel) : BPF_JMP32_A(rel);
	err = patch(env, off, buf, n + 1);
	if (err)
		return err;
	env->insn_aux_data[off + n].unwind_jump = true;
	return n + 1;
}

/*
 * Replace insn @off with @buf[0..@n) followed by 'if r3 != 0 goto @tgt', as
 * two insns when @tgt is out of a conditional jump's reach. A JIT that drops
 * the branch drops both.
 */
static int patch_branch(struct bpf_verifier_env *env, u32 off, struct bpf_insn *buf, u32 n,
			u32 tgt)
{
	s32 rel = jmp_off(off, n, off + n, tgt);
	u32 cnt = n + 1;
	int err;

	if (rel == (s16)rel) {
		buf[n] = BPF_JMP_IMM(BPF_JNE, BPF_REG_UNWIND, 0, rel);
	} else {
		buf[n] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_UNWIND, 0, 1);
		buf[n + 1] = BPF_JMP32_A(jmp_off(off, n + 1, off + n + 1, tgt));
		cnt++;
	}
	err = patch(env, off, buf, cnt);
	if (err)
		return err;
	env->insn_aux_data[off + n].unwind_branch = true;
	if (cnt > n + 1)
		env->insn_aux_data[off + n + 1].unwind_branch = true;
	return cnt;
}

static bool is_final_call(struct bpf_verifier_env *env, const struct bpf_subprog_info *sub)
{
	const struct bpf_insn *insn = &env->prog->insnsi[(sub + 1)->start - 1];

	return BPF_CLASS(insn->code) == BPF_JMP && BPF_OP(insn->code) == BPF_CALL;
}

/*
 * check_subprogs() lets a subprog end with a call, as a compiler emits
 * nothing after a call it knows does not return: a pad's _Unwind_Resume,
 * or a call to a Rust function returning `!` because it unwinds. Refuse
 * any such call that cannot unwind, since it would return into the next
 * subprog.
 */
static int check_final_calls(struct bpf_verifier_env *env)
{
	struct bpf_subprog_info *sub;
	u32 last;

	for (sub = env->subprog_info; sub < env->subprog_info + env->subprog_cnt; sub++) {
		last = (sub + 1)->start - 1;
		if (!is_final_call(env, sub) || unwinds_at(env, last))
			continue;
		verbose(env, "last insn is not an exit or jmp\n");
		bpf_diag_program_structure(
			env, last, "subprogram can fall through",
			"End each subprogram with an exit or an explicit jump that keeps control flow inside the subprogram.",
			"Subprogram %d reaches its last instruction %d without an exit or jump, so control could continue into the next subprogram.",
			(int)(sub - env->subprog_info), last);
		return -EINVAL;
	}
	return 0;
}

/*
 * Put 'r0 = 0; exit' after a final call to a subprog, so that the call's
 * fall-through is an ordinary return and the unwind stub after it is
 * reached only by the branch planted after the call. The verifier walks
 * the fall-through only where the callee can return. A final call to
 * bpf_unwind() or bpf_unwind_resume() becomes a jump, which needs nothing
 * after it.
 */
static int add_exit_after_final_call(struct bpf_verifier_env *env, struct bpf_subprog_info *sub)
{
	u32 last = (sub + 1)->start - 1;
	struct bpf_insn buf[3];
	int err;

	if (bpf_is_unwind_kfunc(&env->prog->insnsi[last]))
		return 0;
	buf[0] = env->prog->insnsi[last];
	buf[1] = BPF_MOV64_IMM(BPF_REG_0, 0);
	buf[2] = BPF_EXIT_INSN();
	err = patch(env, last, buf, ARRAY_SIZE(buf));
	if (err)
		return err;
	if (sub->exit_idx == U32_MAX)
		sub->exit_idx = last + 2;
	return 0;
}

/*
 * The table has served: what the passes after the lowering need is in
 * insn_aux_data. A planted branch carries its target in its own off field,
 * and each landing pad's first insn is flagged for check_cfg(), which walks
 * it as a root of its own, since a pad over a call that cannot unwind has
 * no predecessor at all.
 */
static void retire_table(struct bpf_verifier_env *env)
{
	u32 i;

	for (i = 0; i < env->cleanup_info_cnt; i++)
		env->insn_aux_data[env->cleanup_info[i].landing_pad_off].landing_pad = true;
	kvfree(env->cleanup_info);
	env->cleanup_info = NULL;
	env->cleanup_info_cnt = 0;
}

#define UNWIND_STUB_LEN 3

/* Does an unwind leave @sub without a landing pad to run? */
static bool needs_stub(struct bpf_verifier_env *env, const struct bpf_subprog_info *sub)
{
	u32 i;

	for (i = sub->start; i < (sub + 1)->start; i++)
		if (unwinds_at(env, i) &&
		    (pad_of(env, i) < 0 || is_resume(&env->prog->insnsi[i])))
			return true;
	return false;
}

/* Append 'r0 = 0; r2 = 0; exit' to @sub, reached only by an unwind. */
static int add_stub(struct bpf_verifier_env *env, struct bpf_subprog_info *sub)
{
	u32 last = (sub + 1)->start - 1;
	struct bpf_insn buf[UNWIND_STUB_LEN + 1];
	int err;

	buf[0] = env->prog->insnsi[last];
	buf[1] = BPF_MOV64_IMM(BPF_REG_0, 0);
	buf[2] = BPF_MOV64_IMM(BPF_REG_2, 0);
	buf[3] = BPF_EXIT_INSN();
	err = patch(env, last, buf, ARRAY_SIZE(buf));
	if (err)
		return err;
	env->insn_aux_data[last + UNWIND_STUB_LEN].unwind_exit = true;
	sub->unwind_stub = true;
	return 0;
}

/*
 * Turn the table into code before anything looks at the program.
 *
 * A subprog that can unwind says in r3 how it returned, and a frame that
 * calls one branches on r3 right after the call:
 *
 *   exit                    r3 = 0; exit                (not in main)
 *   call bpf_unwind         r0 = 0; r3 = 1; goto pad
 *   call bpf_unwind_resume  r0 = 0; r3 = 1; goto stub
 *   call subprog, callx     call subprog; if r3 != 0 goto pad
 *
 * where pad is the landing pad of the record covering the call, or the stub
 * when none does. The stub is 'r0 = 0; r2 = 0; exit' after the last insn
 * of the subprog, reached only this way; the main program's returns zero
 * to the kernel.
 *
 * r3 exists only in the xlated program, as the verifier's encoding of the
 * unwinding flag: the planted insns are flagged in insn_aux_data, and a
 * JIT may leave them out and send the stub's return to the pad instead.
 */
int bpf_exc_lower(struct bpf_verifier_env *env)
{
	struct bpf_subprog_info *sub;
	struct bpf_insn buf[4];
	bool any;
	u32 i, n;
	int err, pad;

	any = mark_might_unwind(env);
	env->prog->aux->might_unwind = any;
	err = check_final_calls(env);
	if (err)
		return err;
	if (!any) {
		retire_table(env);
		return 0;
	}

	if (bpf_prog_is_offloaded(env->prog->aux)) {
		verbose(env, "unwinding is not supported for offloaded programs\n");
		return -EOPNOTSUPP;
	}
	if (!env->prog->jit_requested || !bpf_jit_supports_unwind()) {
		verbose(env, "exception cleanup needs a JIT that supports unwinding\n");
		return -EOPNOTSUPP;
	}
	env->prog->jit_required = 1;

	for (sub = env->subprog_info; sub < env->subprog_info + env->subprog_cnt; sub++) {
		/* Both leave the frame without saying how in r3. */
		if (sub->ret_unwind && sub != env->subprog_info &&
		    (sub->has_tail_call || sub->has_ld_abs)) {
			verbose(env, "subprog %d can unwind and has a %s\n",
				(int)(sub - env->subprog_info),
				sub->has_tail_call ? "tail call" : "BPF_LD_[ABS|IND]");
			return -EINVAL;
		}
		if (is_final_call(env, sub)) {
			err = add_exit_after_final_call(env, sub);
			if (err)
				return err;
		}
		if (!needs_stub(env, sub))
			continue;
		err = add_stub(env, sub);
		if (err)
			return err;
	}

	for (i = 0; i < env->prog->len; i += n) {
		struct bpf_insn *insn = &env->prog->insnsi[i];
		u32 stub;

		n = 1;
		sub = bpf_find_containing_subprog(env, i);
		stub = (sub + 1)->start - (sub->unwind_stub ? UNWIND_STUB_LEN : 0);
		if (!sub->ret_unwind || i >= stub)
			continue;

		if (insn->code == (BPF_JMP | BPF_EXIT)) {
			if (sub == env->subprog_info)
				continue;
			buf[0] = BPF_MOV64_IMM(BPF_REG_UNWIND, 0);
			buf[1] = *insn;
			n = 2;
			err = patch(env, i, buf, n);
			if (err)
				return err;
			env->insn_aux_data[i].unwind_set = true;
			continue;
		}

		if (!unwinds_at(env, i))
			continue;
		pad = is_resume(insn) ? -1 : pad_of(env, i);
		if (pad < 0)
			pad = stub;
		if (bpf_is_unwind_kfunc(insn)) {
			buf[0] = BPF_MOV64_IMM(BPF_REG_0, 0);
			buf[1] = BPF_MOV64_IMM(BPF_REG_UNWIND, 1);
			err = patch_jump(env, i, buf, 2, pad);
			if (err < 0)
				return err;
			env->insn_aux_data[i + 1].unwind_set = true;
		} else {
			buf[0] = *insn;
			err = patch_branch(env, i, buf, 1, pad);
			if (err < 0)
				return err;
		}
		n = err;
	}
	retire_table(env);
	return 0;
}
