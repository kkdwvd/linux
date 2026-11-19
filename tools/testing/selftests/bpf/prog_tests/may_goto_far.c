// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>
#include <linux/filter.h>
#include <bpf/btf.h>

#define MAY_GOTO(off)	BPF_RAW_INSN(BPF_JMP | BPF_JCOND, 0, 0, off, 0)
#define FILL_CNT	33000

static struct bpf_insn *fill(struct bpf_insn *insn, int cnt, int reg)
{
	while (cnt--)
		*insn++ = BPF_MOV64_REG(BPF_REG_0, reg);
	return insn;
}

/*
 * Syscall prog that loops until may_goto expires. Its target is 'off' insns
 * away:
 *
 *	r6 = r7 = 0, but not a constant for the verifier
 *	r8 = 2
 *	r9 = 0
 *	r0 = r8		x FILL_CNT or 1
 * 1:	if r6 == r9 goto +1
 *	exit
 *	r6 = r8
 *	r0 = r9		x N when off is negative
 *	if r7 != r9 goto 3f
 * 2:	may_goto off	(1b or 4f)
 *	goto 2b
 * 3:	r0 = r8		x N when off is positive
 * 4:	exit
 *
 * The prog returns 0 when may_goto jumps to its target and 2 when
 * it lands in one of 'r0 = r8' areas. There are no constants between
 * may_goto and its target to keep the distance when constants are blinded.
 *
 * With SUBPROG all of that is a subprog.
 *
 * A prog that can be cancelled ends when the time of may_goto is up: may_goto
 * goes to a pad behind the last insn then, which is as far away, and the prog
 * returns 0 as well. With CALLBACK the subprog is called by a callback of
 * bpf_loop(), which is never cancelled, so may_goto jumps to its target. The
 * main prog adds CALLBACK_RET to what the subprog returns: it was not
 * cancelled.
 */
enum mode {
	MAIN,
	SUBPROG,
	CALLBACK,
};

#define CALLBACK_RET	5

/*
 * The address of a callback is taken only in a prog that has BTF for its
 * functions. Give the three of CALLBACK a FUNC each, all of them 'int f(void)'.
 * Returns the fd of the BTF.
 */
static int load_func_btf(struct bpf_func_info *func_info)
{
	static const char * const names[] = { "main_prog", "callback", "subprog" };
	int i, int_id, proto_id, fd = -1;
	struct btf *btf;

	btf = btf__new_empty();
	if (!ASSERT_OK_PTR(btf, "btf__new_empty"))
		return -1;
	int_id = btf__add_int(btf, "int", 4, BTF_INT_SIGNED);
	proto_id = btf__add_func_proto(btf, int_id);
	for (i = 0; i < ARRAY_SIZE(names); i++)
		func_info[i].type_id = btf__add_func(btf, names[i], BTF_FUNC_STATIC, proto_id);
	if (ASSERT_OK(btf__load_into_kernel(btf), "btf__load_into_kernel"))
		fd = dup(btf__fd(btf));
	btf__free(btf);
	return fd;
}

static void test_far(int off, enum mode mode)
{
	LIBBPF_OPTS(bpf_prog_load_opts, opts, .prog_flags = BPF_F_SLEEPABLE);
	LIBBPF_OPTS(bpf_test_run_opts, topts);
	int front = off < 0 ? 1 : FILL_CNT;
	int mid = off < 0 ? -off - 5 : 1;
	int back = off < 0 ? FILL_CNT : off - 1;
	struct bpf_func_info func_info[3];
	struct bpf_insn *insns, *insn;
	int fd, err, btf_fd = -1;

	insns = calloc(front + mid + back + 32, sizeof(*insns));
	if (!ASSERT_OK_PTR(insns, "calloc"))
		return;

	insn = insns;
	if (mode == SUBPROG) {
		*insn++ = BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, BPF_PSEUDO_CALL, 0, 1);
		*insn++ = BPF_EXIT_INSN();
	} else if (mode == CALLBACK) {
		/* bpf_loop(1, callback, fp - 8, 0); return *(fp - 8) + CALLBACK_RET; */
		*insn++ = BPF_ST_MEM(BPF_DW, BPF_REG_10, -8, 3);
		*insn++ = BPF_MOV64_IMM(BPF_REG_1, 1);
		*insn++ = BPF_RAW_INSN(BPF_LD | BPF_DW | BPF_IMM, BPF_REG_2, BPF_PSEUDO_FUNC, 0, 8);
		*insn++ = BPF_RAW_INSN(0, 0, 0, 0, 0);
		*insn++ = BPF_MOV64_REG(BPF_REG_3, BPF_REG_10);
		*insn++ = BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, -8);
		*insn++ = BPF_MOV64_IMM(BPF_REG_4, 0);
		*insn++ = BPF_EMIT_CALL(BPF_FUNC_loop);
		*insn++ = BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_10, -8);
		*insn++ = BPF_ALU64_IMM(BPF_ADD, BPF_REG_0, CALLBACK_RET);
		*insn++ = BPF_EXIT_INSN();
		/* the callback: *ctx = subprog(); return 0; */
		func_info[1].insn_off = insn - insns;
		*insn++ = BPF_MOV64_REG(BPF_REG_6, BPF_REG_2);
		*insn++ = BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, BPF_PSEUDO_CALL, 0, 3);
		*insn++ = BPF_STX_MEM(BPF_DW, BPF_REG_6, BPF_REG_0, 0);
		*insn++ = BPF_MOV64_IMM(BPF_REG_0, 0);
		*insn++ = BPF_EXIT_INSN();
		func_info[0].insn_off = 0;
		func_info[2].insn_off = insn - insns;
	}
	*insn++ = BPF_EMIT_CALL(BPF_FUNC_ktime_get_ns);
	*insn++ = BPF_MOV64_REG(BPF_REG_6, BPF_REG_0);
	*insn++ = BPF_ALU64_IMM(BPF_RSH, BPF_REG_6, 63);
	*insn++ = BPF_MOV64_REG(BPF_REG_7, BPF_REG_0);
	*insn++ = BPF_ALU64_IMM(BPF_RSH, BPF_REG_7, 63);
	*insn++ = BPF_MOV64_IMM(BPF_REG_8, 2);
	*insn++ = BPF_MOV64_IMM(BPF_REG_9, 0);
	insn = fill(insn, front, BPF_REG_8);
	*insn++ = BPF_JMP_REG(BPF_JEQ, BPF_REG_6, BPF_REG_9, 1);
	*insn++ = BPF_EXIT_INSN();
	*insn++ = BPF_MOV64_REG(BPF_REG_6, BPF_REG_8);
	insn = fill(insn, mid, BPF_REG_9);
	*insn++ = BPF_JMP_REG(BPF_JNE, BPF_REG_7, BPF_REG_9, 2);
	*insn++ = MAY_GOTO(off);
	*insn++ = BPF_JMP_A(-2);
	insn = fill(insn, back, BPF_REG_8);
	*insn++ = BPF_EXIT_INSN();

	if (mode == CALLBACK) {
		btf_fd = load_func_btf(func_info);
		if (btf_fd < 0) {
			free(insns);
			return;
		}
		opts.prog_btf_fd = btf_fd;
		opts.func_info = func_info;
		opts.func_info_cnt = ARRAY_SIZE(func_info);
		opts.func_info_rec_size = sizeof(*func_info);
	}

	fd = bpf_prog_load(BPF_PROG_TYPE_SYSCALL, NULL, "GPL", insns, insn - insns, &opts);
	if (btf_fd >= 0)
		close(btf_fd);
	free(insns);
	if (!ASSERT_GE(fd, 0, "prog_load"))
		return;

	err = bpf_prog_test_run_opts(fd, &topts);
	ASSERT_OK(err, "test_run");
	ASSERT_EQ(topts.retval, mode == CALLBACK ? CALLBACK_RET : 0, "retval");
	close(fd);
}

void test_may_goto_far(void)
{
	if (test__start_subtest("32762"))
		test_far(32762, MAIN);
	if (test__start_subtest("32767"))
		test_far(32767, MAIN);
	if (test__start_subtest("-32767"))
		test_far(-32767, MAIN);
	if (test__start_subtest("-32768"))
		test_far(-32768, MAIN);
	if (test__start_subtest("subprog 1"))
		test_far(1, SUBPROG);
	if (test__start_subtest("subprog 32767"))
		test_far(32767, SUBPROG);
	if (test__start_subtest("subprog -6"))
		test_far(-6, SUBPROG);
	if (test__start_subtest("subprog -32768"))
		test_far(-32768, SUBPROG);
	if (test__start_subtest("callback 1"))
		test_far(1, CALLBACK);
	if (test__start_subtest("callback 32767"))
		test_far(32767, CALLBACK);
	if (test__start_subtest("callback -6"))
		test_far(-6, CALLBACK);
	if (test__start_subtest("callback -32768"))
		test_far(-32768, CALLBACK);
}
