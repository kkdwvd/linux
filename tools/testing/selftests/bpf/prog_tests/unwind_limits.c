// SPDX-License-Identifier: GPL-2.0
/* Programs of many subprogs that unwind: what the verifier walks for them ends in time */

#include <test_progs.h>
#include <bpf/btf.h>
#include <linux/filter.h>

#define MAY_GOTO(off)	BPF_RAW_INSN(BPF_JMP | BPF_JCOND, 0, 0, off, 0)

/*
 * main -> f1 -> ... -> fn, each caller in front of its callee. fn has may_goto of the program, so
 * every function above it is left there too. R5 is not readable at the first insn: the load is
 * refused, behind the analyses that come before the main pass.
 */
static void test_chain(void)
{
	LIBBPF_OPTS(bpf_prog_load_opts, opts, .prog_flags = BPF_F_SLEEPABLE);
	const int funcs = 40000, cnt = 2 * funcs + 6;
	struct bpf_insn *insns = calloc(cnt, sizeof(*insns)), *f;
	int i, fd;

	if (!ASSERT_OK_PTR(insns, "insns"))
		return;
	insns[0] = BPF_MOV64_REG(BPF_REG_0, BPF_REG_5);
	insns[1] = BPF_CALL_REL(2);
	insns[2] = BPF_MOV64_IMM(BPF_REG_0, 0);
	insns[3] = BPF_EXIT_INSN();
	for (i = 1, f = insns + 4; i < funcs; i++) {
		*f++ = BPF_CALL_REL(1);
		*f++ = BPF_EXIT_INSN();
	}
	*f++ = BPF_MOV64_IMM(BPF_REG_0, 0);
	*f++ = MAY_GOTO(1);
	*f++ = BPF_MOV64_IMM(BPF_REG_0, 1);
	*f++ = BPF_EXIT_INSN();
	fd = bpf_prog_load(BPF_PROG_TYPE_SYSCALL, NULL, "GPL", insns, cnt, &opts);
	if (!ASSERT_EQ(fd, -EACCES, "load") && fd >= 0)
		close(fd);
	free(insns);
}

/*
 * The main prog calls bpf_loop() @cbs times, each time with a callback of its own, and then
 * @globals global subprogs. Each of those has a loop without a trip count: the verifier gives it
 * may_goto, and finds that the subprog is unwound there when its callers are verified already.
 */
static void test_globals(void)
{
	const int globals = 1000, cbs = 8000, funcs = 1 + globals + cbs;
	const int main_len = 6 * cbs + globals + 2, cnt = main_len + 3 * globals + 2 * cbs;
	LIBBPF_OPTS(bpf_prog_load_opts, opts, .prog_flags = BPF_F_SLEEPABLE);
	struct bpf_insn *insns = calloc(cnt, sizeof(*insns)), *insn = insns, *f;
	struct bpf_func_info *info = calloc(funcs, sizeof(*info));
	struct btf *btf = btf__new_empty();
	int i, n = 0, proto, fd, btf_fd = -1;
	const void *raw;
	char name[16];
	__u32 size;

	if (!ASSERT_OK_PTR(insns, "insns") || !ASSERT_OK_PTR(info, "info") ||
	    !ASSERT_OK_PTR(btf, "btf"))
		goto out;
	proto = btf__add_func_proto(btf, btf__add_int(btf, "int", 4, BTF_INT_SIGNED));
	info[n].type_id = btf__add_func(btf, "main", BTF_FUNC_GLOBAL, proto);
	info[n++].insn_off = 0;
	f = insns + main_len + 3 * globals;
	for (i = 0; i < cbs; i++, f += 2) {
		*insn++ = BPF_MOV64_IMM(BPF_REG_1, 1);
		*insn = BPF_RAW_INSN(BPF_LD | BPF_DW | BPF_IMM, BPF_REG_2, BPF_PSEUDO_FUNC, 0,
				     f - insn - 1);
		insn += 2;
		*insn++ = BPF_MOV64_IMM(BPF_REG_3, 0);
		*insn++ = BPF_MOV64_IMM(BPF_REG_4, 0);
		*insn++ = BPF_EMIT_CALL(BPF_FUNC_loop);
	}
	f = insns + main_len;
	for (i = 0; i < globals; i++, f += 3, insn++)
		*insn = BPF_CALL_REL(f - insn - 1);
	*insn++ = BPF_MOV64_IMM(BPF_REG_0, 0);
	*insn++ = BPF_EXIT_INSN();
	for (i = 0; i < globals; i++) {
		snprintf(name, sizeof(name), "g%d", i);
		info[n].type_id = btf__add_func(btf, name, BTF_FUNC_GLOBAL, proto);
		info[n++].insn_off = insn - insns;
		*insn++ = BPF_EMIT_CALL(BPF_FUNC_get_prandom_u32);
		*insn++ = BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, -2);
		*insn++ = BPF_EXIT_INSN();
	}
	for (i = 0; i < cbs; i++) {
		snprintf(name, sizeof(name), "cb%d", i);
		info[n].type_id = btf__add_func(btf, name, BTF_FUNC_STATIC, proto);
		info[n++].insn_off = insn - insns;
		*insn++ = BPF_MOV64_IMM(BPF_REG_0, 0);
		*insn++ = BPF_EXIT_INSN();
	}
	raw = btf__raw_data(btf, &size);
	btf_fd = bpf_btf_load(raw, size, NULL);
	if (!ASSERT_OK_FD(btf_fd, "btf_load"))
		goto out;
	opts.prog_btf_fd = btf_fd;
	opts.func_info = info;
	opts.func_info_cnt = funcs;
	opts.func_info_rec_size = sizeof(*info);
	fd = bpf_prog_load(BPF_PROG_TYPE_SYSCALL, NULL, "GPL", insns, cnt, &opts);
	if (ASSERT_OK_FD(fd, "load"))
		close(fd);
out:
	if (btf_fd >= 0)
		close(btf_fd);
	btf__free(btf);
	free(info);
	free(insns);
}

#define KFUNC(id)	BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, BPF_PSEUDO_KFUNC_CALL, 0, id)

/* Loads a tc program of @funcs global functions: function i starts at @start[i] */
static int load_global_funcs(const struct bpf_insn *insns, int cnt, const int *start, int funcs)
{
	struct bpf_func_info *info = calloc(funcs, sizeof(*info));
	LIBBPF_OPTS(bpf_prog_load_opts, opts);
	struct btf *btf = btf__new_empty();
	int i, proto, fd = -ENOMEM;
	const void *raw;
	char name[16];
	__u32 size;

	if (!info || !btf)
		goto out;
	proto = btf__add_func_proto(btf, btf__add_int(btf, "int", 4, BTF_INT_SIGNED));
	for (i = 0; i < funcs; i++) {
		snprintf(name, sizeof(name), "f%d", i);
		info[i].type_id = btf__add_func(btf, name, BTF_FUNC_GLOBAL, proto);
		info[i].insn_off = start[i];
	}
	raw = btf__raw_data(btf, &size);
	opts.prog_btf_fd = bpf_btf_load(raw, size, NULL);
	if (opts.prog_btf_fd < 0) {
		fd = opts.prog_btf_fd;
		goto out;
	}
	opts.func_info = info;
	opts.func_info_cnt = funcs;
	opts.func_info_rec_size = sizeof(*info);
	fd = bpf_prog_load(BPF_PROG_TYPE_SCHED_CLS, NULL, "GPL", insns, cnt, &opts);
	close(opts.prog_btf_fd);
out:
	btf__free(btf);
	free(info);
	return fd;
}

/*
 * main -> g1 -> ... -> gn, global functions, each callee in front of its caller. gn has may_goto
 * of the program, so the kernel may unwind each of them and every call is a site. main is in nine
 * RCU sections at its call of g1, which is more than the landing pad of that call can leave: the
 * load is refused, and what the verifier notes of the causes goes down the whole chain. main calls
 * the others too, so that all of them are verified in one sweep.
 */
static void test_causes(void)
{
	const int n = 60000, main_len = n + 20, cnt = main_len + 2 * n + 2;
	struct bpf_insn *insns = calloc(cnt, sizeof(*insns)), *insn = insns;
	struct btf *vmlinux = btf__load_vmlinux_btf();
	int *start = calloc(n + 1, sizeof(*start));
	int i, lock, unlock, fd;

/* where g(i) starts: gn has 4 insns and comes first, the others have 2 */
#define G(i)	(main_len + ((i) == n ? 0 : 4 + 2 * (n - 1 - (i))))
	if (!ASSERT_OK_PTR(vmlinux, "vmlinux") || !ASSERT_OK_PTR(insns, "insns") ||
	    !ASSERT_OK_PTR(start, "start"))
		goto out;
	lock = btf__find_by_name_kind(vmlinux, "bpf_rcu_read_lock", BTF_KIND_FUNC);
	unlock = btf__find_by_name_kind(vmlinux, "bpf_rcu_read_unlock", BTF_KIND_FUNC);
	if (!ASSERT_GT(lock, 0, "lock") || !ASSERT_GT(unlock, 0, "unlock"))
		goto out;
	for (i = 0; i < 9; i++)
		*insn++ = KFUNC(lock);
	*insn = BPF_CALL_REL(G(1) - (insn - insns) - 1);
	insn++;
	for (i = 0; i < 9; i++)
		*insn++ = KFUNC(unlock);
	for (i = 2; i <= n; i++, insn++)
		*insn = BPF_CALL_REL(G(i) - (insn - insns) - 1);
	*insn++ = BPF_MOV64_IMM(BPF_REG_0, 0);
	*insn++ = BPF_EXIT_INSN();
	*insn++ = BPF_MOV64_IMM(BPF_REG_0, 0);
	*insn++ = MAY_GOTO(1);
	*insn++ = BPF_MOV64_IMM(BPF_REG_0, 1);
	*insn++ = BPF_EXIT_INSN();
	for (i = n - 1; i >= 1; i--, insn++) {
		*insn = BPF_CALL_REL(G(i + 1) - (insn - insns) - 1);
		*++insn = BPF_EXIT_INSN();
	}
	for (i = 1; i <= n; i++)
		start[i] = G(n - i + 1);
#undef G
	fd = load_global_funcs(insns, cnt, start, n + 1);
	if (!ASSERT_EQ(fd, -EINVAL, "load") && fd >= 0)
		close(fd);
out:
	btf__free(vmlinux);
	free(start);
	free(insns);
}

/*
 * main calls the global function g 200000 times and has no exit: its frame cannot unwind. g has
 * 200000 insns and may_goto of the program, so each call also comes back the way the kernel leaves
 * g, to a frame that cannot be left: g is stuck, which the verifier finds for each of the calls.
 * The load is refused for the loop of main that never exits.
 */
static void test_skip(void)
{
	const int calls = 200000, len = 200000, cnt = calls + 2 + len;
	struct bpf_insn *insns = calloc(cnt, sizeof(*insns)), *insn = insns;
	const int start[] = { 0, calls + 2 };
	int i, fd;

	if (!ASSERT_OK_PTR(insns, "insns"))
		return;
	for (i = 0; i < calls; i++, insn++)
		*insn = BPF_CALL_REL(calls + 2 - i - 1);
	*insn++ = BPF_MOV64_IMM(BPF_REG_0, 0);
	*insn++ = BPF_JMP_A(-1);
	for (i = 0; i < len - 3; i++)
		*insn++ = BPF_MOV64_IMM(BPF_REG_0, 0);
	*insn++ = MAY_GOTO(1);
	*insn++ = BPF_MOV64_IMM(BPF_REG_0, 1);
	*insn++ = BPF_EXIT_INSN();
	fd = load_global_funcs(insns, cnt, start, 2);
	if (!ASSERT_EQ(fd, -EINVAL, "load") && fd >= 0)
		close(fd);
	free(insns);
}

void test_unwind_limits(void)
{
	if (test__start_subtest("chain"))
		test_chain();
	if (test__start_subtest("globals"))
		test_globals();
	if (test__start_subtest("causes"))
		test_causes();
	if (test__start_subtest("skip"))
		test_skip();
}
