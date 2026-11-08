// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>

#include "hidden_cancel_cb.skel.h"

/*
 * Whether the program ends in the callback the verifier appends to a program
 * that may be unwound, which returns its cookie: r0 = r1; exit. Returns -1
 * when the instructions cannot be read.
 */
static int ends_in_hidden_cb(int fd)
{
	struct bpf_prog_info info = {};
	struct bpf_insn insns[256];
	__u32 len = sizeof(info);
	const struct bpf_insn *mov, *exit;
	int cnt;

	info.xlated_prog_insns = ptr_to_u64(insns);
	info.xlated_prog_len = sizeof(insns);
	if (!ASSERT_OK(bpf_prog_get_info_by_fd(fd, &info, &len), "prog info"))
		return -1;
	cnt = info.xlated_prog_len / sizeof(*insns);
	if (!ASSERT_GE(cnt, 2, "insn count") || !ASSERT_LE(cnt, ARRAY_SIZE(insns), "insn count"))
		return -1;
	mov = &insns[cnt - 2];
	exit = &insns[cnt - 1];
	return mov->code == (BPF_ALU64 | BPF_MOV | BPF_X) && mov->dst_reg == BPF_REG_0 &&
	       mov->src_reg == BPF_REG_1 && !mov->off && !mov->imm &&
	       exit->code == (BPF_JMP | BPF_EXIT);
}

/*
 * A cancellable program whose only sites are calls has no cancellation point
 * and is never unwound: the verifier adds the hidden callback only to a
 * program with one.
 */
void test_hidden_cancel_cb(void)
{
	struct hidden_cancel_cb *skel;

	skel = hidden_cancel_cb__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;
	ASSERT_EQ(ends_in_hidden_cb(bpf_program__fd(skel->progs.only_calls)), 0,
		  "no callback without a cancellation point");
	ASSERT_EQ(ends_in_hidden_cb(bpf_program__fd(skel->progs.loop_and_call)), 1,
		  "callback with a may_goto");
	hidden_cancel_cb__destroy(skel);
}
