// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <sys/resource.h>
#include "verifier_unwind.skel.h"
#include "unwind_attach.skel.h"

static char log_buf[16 * 1024];

static int run(int fd)
{
	char data[64] = {};
	LIBBPF_OPTS(bpf_test_run_opts, opts,
		.data_in = data,
		.data_size_in = sizeof(data),
		.repeat = 1,
	);

	ASSERT_OK(bpf_prog_test_run_opts(fd, &opts), "test_run");
	return opts.retval;
}

/*
 * msg: why it cannot be loaded. Otherwise retval is what the target returns
 * with the prog attached.
 */
static void attach(int tgt_fd, const char *func, const char *name, const char *msg, int retval)
{
	struct bpf_link *link = NULL;
	struct unwind_attach *skel;
	struct bpf_program *prog;
	int err;

	skel = unwind_attach__open();
	if (!ASSERT_OK_PTR(skel, "unwind_attach__open"))
		return;

	prog = bpf_object__find_program_by_name(skel->obj, name);
	if (!ASSERT_OK_PTR(prog, name))
		goto out;
	bpf_program__set_autoload(prog, true);
	log_buf[0] = 0;
	bpf_program__set_log_buf(prog, log_buf, sizeof(log_buf));
	err = bpf_program__set_attach_target(prog, tgt_fd, func);
	if (!ASSERT_OK(err, "set_attach_target"))
		goto out;

	err = unwind_attach__load(skel);
	if (msg) {
		ASSERT_ERR(err, name);
		ASSERT_HAS_SUBSTR(log_buf, msg, name);
		goto out;
	}
	if (!ASSERT_OK(err, name))
		goto out;

	link = bpf_program__attach(prog);
	if (!ASSERT_OK_PTR(link, "attach"))
		goto out;
	ASSERT_EQ(run(tgt_fd), retval, "retval");
	if (prog == skel->progs.fentry_unwind)
		ASSERT_EQ(skel->bss->fentry_cnt, 1, "fentry_cnt");
out:
	bpf_link__destroy(link);
	unwind_attach__destroy(skel);
}

/* A helper with a pad is notrace: nothing may put a return address of its own in its frame */
static void helper_with_pad(void)
{
	struct unwind_attach *skel;
	struct bpf_link *link;
	int err;

	skel = unwind_attach__open();
	if (!ASSERT_OK_PTR(skel, "unwind_attach__open"))
		return;
	bpf_program__set_autoload(skel->progs.fexit_bpf_loop, true);
	err = unwind_attach__load(skel);
	if (!err) {
		link = bpf_program__attach(skel->progs.fexit_bpf_loop);
		err = libbpf_get_error(link);
		bpf_link__destroy(link);
	}
	ASSERT_ERR(err, "fexit on bpf_loop");
	unwind_attach__destroy(skel);
}

/*
 * @name calls a global subprog that returns, and goes on behind the call. A kernel that takes the
 * subprog for one that never returns puts a trap behind the call, an insn that jumps to itself,
 * and a return would spin there for good. So look at the insn first: the test fails, and the prog
 * does not run.
 */
static void returns_behind_call(const char *name)
{
	struct bpf_insn *insns = NULL;
	struct verifier_unwind *skel;
	struct bpf_program *prog, *p;
	__u32 i, cnt = 0;

	skel = verifier_unwind__open();
	if (!ASSERT_OK_PTR(skel, "verifier_unwind__open"))
		return;
	prog = bpf_object__find_program_by_name(skel->obj, name);
	if (!ASSERT_OK_PTR(prog, name))
		goto out;
	bpf_object__for_each_program(p, skel->obj)
		bpf_program__set_autoload(p, p == prog);
	if (!ASSERT_OK(verifier_unwind__load(skel), name) ||
	    !ASSERT_OK(get_xlated_program(bpf_program__fd(prog), &insns, &cnt), "xlated"))
		goto out;
	/* the first call of a subprog, the unwind_goto and kgoto behind it, what it returns to */
	for (i = 0; i < cnt; i++)
		if (insns[i].code == (BPF_JMP | BPF_CALL) && insns[i].src_reg == BPF_PSEUDO_CALL)
			break;
	for (i++; i < cnt && BPF_OP(insns[i].code) == BPF_JCOND &&
		  (BPF_CLASS(insns[i].code) == BPF_JMP || BPF_CLASS(insns[i].code) == BPF_JMP32); i++)
		;
	if (ASSERT_LT(i, cnt, "the insn behind the call") &&
	    ASSERT_FALSE(insns[i].code == (BPF_JMP | BPF_JA) && insns[i].off == -1,
			 "a trap behind the call"))
		ASSERT_EQ(run(bpf_program__fd(prog)), 7, "retval");
	free(insns);
out:
	verifier_unwind__destroy(skel);
}

/* An extension of an LSM prog whose time slice is over denies */
static void extension_of_lsm_prog(void)
{
	struct unwind_attach *tgt = unwind_attach__open(), *ext = unwind_attach__open();

	if (!ASSERT_OK_PTR(tgt, "open tgt") || !ASSERT_OK_PTR(ext, "open ext"))
		goto out;
	bpf_program__set_autoload(tgt->progs.lsm_setnice, true);
	if (!ASSERT_OK(unwind_attach__load(tgt), "load lsm_setnice") ||
	    !ASSERT_OK(unwind_attach__attach(tgt), "attach lsm_setnice"))
		goto out;
	tgt->bss->lsm_pid = getpid();
	ASSERT_OK(setpriority(PRIO_PROCESS, 0, 0), "setpriority");

	bpf_program__set_autoload(ext->progs.freplace_policy_spins, true);
	bpf_program__set_attach_target(ext->progs.freplace_policy_spins,
				       bpf_program__fd(tgt->progs.lsm_setnice), "lsm_policy");
	if (!ASSERT_OK(unwind_attach__load(ext), "load freplace_policy_spins") ||
	    !ASSERT_OK(unwind_attach__attach(ext), "attach freplace_policy_spins"))
		goto out;
	ASSERT_EQ(setpriority(PRIO_PROCESS, 0, 0), -1, "setpriority");
	ASSERT_EQ(errno, EPERM, "errno");
out:
	unwind_attach__destroy(ext);
	unwind_attach__destroy(tgt);
}

void test_unwind_attach(void)
{
	static const char * const never_returns[][2] = {
		/* it has unwind_exit, and nothing else */
		{ "global_never_returns", "global_always_unwinds" },
		/* the kernel unwinds it, and it has no unwind_exit */
		{ "global_kunwinds_never_returns", "global_spins_or_throws" },
		/* it only calls what never returns */
		{ "global_chain_never_returns", "global_calls_static_never_returns" },
	};
	struct verifier_unwind *tgt;
	struct bpf_program *prog;
	int tgt_fd, plain_fd, shared_fd, tail_fd, throws_fd, err, key = 0, i;
	char msg[128];

	if (!is_jit_enabled()) {
		printf("%s:SKIP:JIT is disabled\n", __func__);
		test__skip();
		return;
	}
	tgt = verifier_unwind__open();
	if (!ASSERT_OK_PTR(tgt, "verifier_unwind__open"))
		return;
	bpf_object__for_each_program(prog, tgt->obj)
		bpf_program__set_autoload(prog, prog == tgt->progs.calls_global_unwinds ||
						prog == tgt->progs.calls_global_never_unwinds ||
						prog == tgt->progs.shared_pad ||
						prog == tgt->progs.tail_call_in_subprog ||
						prog == tgt->progs.exception_callback_unwinds ||
						prog == tgt->progs.global_never_returns ||
						prog == tgt->progs.global_kunwinds_never_returns ||
						prog == tgt->progs.global_chain_never_returns);
	err = verifier_unwind__load(tgt);
	if (err == -ENOTSUPP) {
		printf("%s:SKIP:JIT does not support unwinding\n", __func__);
		test__skip();
		goto out;
	}
	if (!ASSERT_OK(err, "verifier_unwind__load"))
		goto out;
	/*
	 * It calls global_unwinds(), which unwinds with r0 = 5, and returns r0 + 10
	 * from the pad.
	 */
	tgt_fd = bpf_program__fd(tgt->progs.calls_global_unwinds);
	plain_fd = bpf_program__fd(tgt->progs.calls_global_never_unwinds);
	ASSERT_EQ(run(tgt_fd), 15, "retval");

	attach(tgt_fd, "global_unwinds", "fentry_unwind", NULL, 15);
	/* unwind_exit would return to the trampoline */
	attach(tgt_fd, "global_unwinds", "fexit_unwind",
	       "Only fentry can attach to global_unwinds", 0);
	/* Nothing unwinds from an extension into the prog that it extends */
	attach(tgt_fd, "global_unwinds", "freplace_returns",
	       "Only fentry can attach to global_unwinds", 0);
	attach(plain_fd, "global_never_unwinds", "freplace_unwinds",
	       "unwind_exit in the main program of an extension", 0);
	ASSERT_EQ(run(tgt_fd), 15, "retval");
	extension_of_lsm_prog();

	/*
	 * The verifier does not go on behind a call of a global subprog that never returns. No
	 * extension returns in its place: such a subprog unwinds, whichever way.
	 */
	for (i = 0; i < ARRAY_SIZE(never_returns); i++) {
		prog = bpf_object__find_program_by_name(tgt->obj, never_returns[i][0]);
		if (!ASSERT_OK_PTR(prog, never_returns[i][0]))
			continue;
		snprintf(msg, sizeof(msg), "Only fentry can attach to %s", never_returns[i][1]);
		attach(bpf_program__fd(prog), never_returns[i][1], "freplace_returns", msg, 0);
		attach(bpf_program__fd(prog), never_returns[i][1], "fexit_unwind", msg, 0);
	}

	/*
	 * The pad of the main prog calls the exception callback and leaves with
	 * exit. unwind_exit of the callback gets to that exit like its exit
	 * does: nothing unwinds into the prog that is extended.
	 */
	shared_fd = bpf_program__fd(tgt->progs.shared_pad);
	attach(shared_fd, "global_never_unwinds", "freplace_throws", NULL, 3);

	tail_fd = bpf_program__fd(tgt->progs.tail_call_in_subprog);
	throws_fd = bpf_program__fd(tgt->progs.exception_callback_unwinds);
	err = bpf_map__update_elem(tgt->maps.prog_array, &key, sizeof(key),
				   &throws_fd, sizeof(throws_fd), 0);
	if (ASSERT_OK(err, "prog_array"))
		ASSERT_EQ(run(tail_fd), 7, "retval");

	helper_with_pad();
	/* by LD_ABS that fails, out of a cycle of calls, and through a jump table */
	returns_behind_call("global_ld_abs_returns");
	returns_behind_call("global_cycle_returns");
	returns_behind_call("global_gotox_returns");
out:
	verifier_unwind__destroy(tgt);
}
