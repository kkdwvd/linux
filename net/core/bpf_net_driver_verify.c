// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/bpf_net_driver.h>
#include <linux/btf.h>
#include <linux/slab.h>

#define BPF_NET_DRIVER_MAX_INSNS 32768

/*
 * A watchdog can revoke future callbacks, but cannot unwind a running one.
 * Check the original bytecode before verifier rewrites: its control-flow graph
 * must be acyclic, and calls can only enter the bounded driver kfuncs. Thus a
 * callback executes each original instruction at most once, regardless of the
 * compiler's block layout. It executes at most MAX_INSNS original instruction
 * slots and at most that many bounded kfunc calls. This is a bound on work, not
 * a wall-clock deadline; JIT expansion and memory access latency still apply.
 *
 * Keep the kfunc allowlist free of callback invocation, unbounded iteration and
 * sleepable operations. Helpers, subprograms and indirect control flow would
 * invalidate this argument even if the caller's control flow is acyclic.
 */
struct bpf_net_driver_cfg {
	u32 next[2];
	u32 indegree;
	u8 nr_next;
	u8 size;
};

static int bpf_net_driver_check_jump(const struct bpf_insn *insn, u32 index, u32 count,
				     struct bpf_net_driver_cfg *node)
{
	s64 target;
	s32 offset;

	switch (BPF_OP(insn->code)) {
	case BPF_CALL:
		if (insn->code != (BPF_JMP | BPF_CALL) || insn->dst_reg || insn->off ||
		    insn->src_reg != BPF_PSEUDO_KFUNC_CALL || insn->imm <= 0 ||
		    !bpf_net_driver_kfunc_allowed(insn->imm))
			return -EACCES;
		return 0;
	case BPF_EXIT:
		if (insn->code != (BPF_JMP | BPF_EXIT) || insn->dst_reg || insn->src_reg ||
		    insn->off || insn->imm)
			return -EINVAL;
		node->nr_next = 0;
		return 0;
	case BPF_JA:
		/* JMP32 JA uses a signed 32-bit immediate, not the offset field. */
		if (BPF_SRC(insn->code) != BPF_K || insn->dst_reg || insn->src_reg)
			return -EACCES;
		if (BPF_CLASS(insn->code) == BPF_JMP32) {
			if (insn->off)
				return -EINVAL;
			offset = insn->imm;
		} else {
			if (insn->imm)
				return -EINVAL;
			offset = insn->off;
		}
		break;
	case BPF_JEQ:
	case BPF_JNE:
	case BPF_JGT:
	case BPF_JGE:
	case BPF_JLT:
	case BPF_JLE:
	case BPF_JSET:
	case BPF_JSGT:
	case BPF_JSGE:
	case BPF_JSLT:
	case BPF_JSLE:
		if (BPF_SRC(insn->code) == BPF_X ? insn->imm : insn->src_reg)
			return -EINVAL;
		offset = insn->off;
		node->next[1] = index + 1;
		node->nr_next = 2;
		break;
	default:
		/* Includes may_goto, tail calls and internal interpreter calls. */
		return -EACCES;
	}

	target = (s64)index + 1 + offset;
	if (target < 0 || target >= count)
		return -EINVAL;
	node->next[0] = target;
	return 0;
}

static int bpf_net_driver_check_imm64(const struct bpf_insn *insn, u32 remaining)
{
	if (insn->code != (BPF_LD | BPF_DW | BPF_IMM))
		return -EACCES;
	if (!remaining || insn->off || insn[1].code || insn[1].dst_reg ||
	    insn[1].src_reg || insn[1].off)
		return -EINVAL;

	switch (insn->src_reg) {
	case 0:
	case BPF_PSEUDO_MAP_FD:
	case BPF_PSEUDO_MAP_VALUE:
	case BPF_PSEUDO_BTF_ID:
	case BPF_PSEUDO_MAP_IDX:
	case BPF_PSEUDO_MAP_IDX_VALUE:
		return 0;
	default:
		/* In particular, do not admit BPF_PSEUDO_FUNC callback addresses. */
		return -EACCES;
	}
}

static bool bpf_net_driver_alu_allowed(u8 code)
{
	switch (BPF_OP(code)) {
	case BPF_ADD:
	case BPF_SUB:
	case BPF_MUL:
	case BPF_DIV:
	case BPF_OR:
	case BPF_AND:
	case BPF_LSH:
	case BPF_RSH:
	case BPF_NEG:
	case BPF_MOD:
	case BPF_XOR:
	case BPF_MOV:
	case BPF_ARSH:
	case BPF_END:
		return true;
	default:
		return false;
	}
}

int bpf_net_driver_check_member(const struct btf_type *t, const struct btf_member *member,
				const struct bpf_prog *prog)
{
	u32 member_offset = __btf_member_bit_offset(t, member) / 8;
	struct bpf_net_driver_cfg *cfg;
	u32 i, j, nodes = 0, head = 0, tail = 0;
	u32 *ready;
	int err = 0;

	switch (member_offset) {
	case offsetof(struct bpf_net_driver_ops, open):
	case offsetof(struct bpf_net_driver_ops, poll):
	case offsetof(struct bpf_net_driver_ops, xmit):
	case offsetof(struct bpf_net_driver_ops, close):
		break;
	default:
		return -EOPNOTSUPP;
	}

	if (prog->sleepable || !prog->len)
		return -EINVAL;
	if (prog->len > BPF_NET_DRIVER_MAX_INSNS)
		return -E2BIG;

	cfg = kvcalloc(prog->len, sizeof(*cfg), GFP_KERNEL);
	ready = kvmalloc_array(prog->len, sizeof(*ready), GFP_KERNEL);
	if (!cfg || !ready) {
		err = -ENOMEM;
		goto out;
	}

	for (i = 0; i < prog->len; i++) {
		const struct bpf_insn *insn = &prog->insnsi[i];
		struct bpf_net_driver_cfg *node = &cfg[i];
		u32 remaining = prog->len - i - 1;

		node->size = 1;
		node->nr_next = 1;
		node->next[0] = i + 1;
		nodes++;

		switch (BPF_CLASS(insn->code)) {
		case BPF_LD:
			err = bpf_net_driver_check_imm64(insn, remaining);
			if (err)
				goto out;
			node->size = 2;
			node->next[0] = i + 2;
			i++;
			break;
		case BPF_LDX:
			if (BPF_MODE(insn->code) != BPF_MEM &&
			    BPF_MODE(insn->code) != BPF_MEMSX) {
				err = -EACCES;
				goto out;
			}
			break;
		case BPF_ST:
		case BPF_STX:
			/* Atomic RMWs may become retry loops in an architecture's JIT. */
			if (BPF_MODE(insn->code) != BPF_MEM) {
				err = -EACCES;
				goto out;
			}
			break;
		case BPF_ALU:
		case BPF_ALU64:
			/* Includes the MOV address-space casts used by typed arenas. */
			if (!bpf_net_driver_alu_allowed(insn->code)) {
				err = -EACCES;
				goto out;
			}
			break;
		case BPF_JMP:
		case BPF_JMP32:
			err = bpf_net_driver_check_jump(insn, i, prog->len, node);
			if (err)
				goto out;
			break;
		default:
			err = -EACCES;
			goto out;
		}
	}

	/* Resolve edges only after every LDIMM64 continuation has been marked. */
	for (i = 0; i < prog->len; i += cfg[i].size) {
		for (j = 0; j < cfg[i].nr_next; j++) {
			u32 next = cfg[i].next[j];

			if (next >= prog->len || !cfg[next].size) {
				err = -EINVAL;
				goto out;
			}
			cfg[next].indegree++;
		}
	}

	/*
	 * Kahn's algorithm includes every decoded instruction, not just those
	 * reached from the entry. A cycle leaves at least one node unprocessed.
	 */
	for (i = 0; i < prog->len; i += cfg[i].size)
		if (!cfg[i].indegree)
			ready[tail++] = i;
	while (head < tail) {
		struct bpf_net_driver_cfg *node = &cfg[ready[head++]];

		for (j = 0; j < node->nr_next; j++) {
			u32 next = node->next[j];

			if (!--cfg[next].indegree)
				ready[tail++] = next;
		}
	}
	err = tail == nodes ? 0 : -EACCES;
out:
	kvfree(ready);
	kvfree(cfg);
	/* The normal verifier checks operands, reachability and memory safety. */
	return err;
}
