// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include "verifier_coro_cont.skel.h"
#include "coro_cont_run.skel.h"

/* The suspend kfunc is bpf_testmod's. */
void test_verifier_coro_cont(void)
{
	if (!env.has_testmod) {
		test__skip();
		return;
	}

	RUN_TESTS(verifier_coro_cont);
}

/* Run the tc program @prog once: what it returned */
static int run(struct bpf_program *prog)
{
	char data[64] = {};
	LIBBPF_OPTS(bpf_test_run_opts, opts,
		.data_in = data,
		.data_size_in = sizeof(data),
		.repeat = 1,
	);

	if (!ASSERT_OK(bpf_prog_test_run_opts(bpf_program__fd(prog), &opts),
		       bpf_program__name(prog)))
		return -1;
	return opts.retval;
}

/*
 * What became of the frame that was suspended last for @id: whether the continuation was
 * unwound. bpf_testmod resumes it after the call, wait two seconds at most.
 */
static int result(struct coro_cont_run *skel, int id)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	int i;

	skel->bss->result_id = id;
	for (i = 0; i < 200; i++) {
		if (!ASSERT_OK(bpf_prog_test_run_opts(bpf_program__fd(skel->progs.coro_result),
						      &opts), "coro_result"))
			return -1;
		if (opts.retval != -EINPROGRESS)
			return opts.retval;
		usleep(10000);
	}
	return -EINPROGRESS;
}

enum {
	ID_RELEASE = 1,
	ID_AGAIN,
	ID_RETURNED,
	ID_UNWOUND,
	ID_APART_UNWOUND,
	ID_APART_RETURNED,
	ID_DIRECT,
	ID_SELF,
	ID_THROWS,
	ID_THROWS_EXC,
};

void test_coro_cont_run(void)
{
	struct coro_cont_run *skel;

	if (!env.has_testmod) {
		test__skip();
		return;
	}
	skel = coro_cont_run__open_and_load();
	if (!ASSERT_OK_PTR(skel, "coro_cont_run__open_and_load"))
		return;

	/* the continuation drops the object that the frame holds */
	if (test__start_subtest("release")) {
		skel->bss->coro_resumed = 0;
		ASSERT_EQ(run(skel->progs.coro_release), 0, "suspend");
		ASSERT_EQ(result(skel, ID_RELEASE), 0, "result");
		ASSERT_EQ(skel->bss->coro_resumed, 42, "coro_resumed");
	}
	/* it suspends the frame again three times, each one resumed after the last */
	if (test__start_subtest("again")) {
		skel->bss->coro_resumed = 0;
		ASSERT_EQ(run(skel->progs.coro_again), 0, "suspend");
		ASSERT_EQ(result(skel, ID_AGAIN), 0, "result");
		ASSERT_EQ(skel->bss->coro_resumed, 3, "coro_resumed");
	}
#if defined(__x86_64__) || defined(__aarch64__)
	/*
	 * The JITs that unwind: the continuation leaves with kexit into the landing pad of
	 * bpf_coro_run(), which tells whether it was unwound.
	 */
	if (test__start_subtest("returned")) {
		skel->bss->coro_resumed = 0;
		ASSERT_EQ(run(skel->progs.coro_returned), 0, "suspend");
		ASSERT_EQ(result(skel, ID_RETURNED), 0, "result");
		ASSERT_EQ(skel->bss->coro_resumed, 1, "coro_resumed");
	}
	if (test__start_subtest("unwound")) {
		skel->bss->coro_resumed = 0;
		skel->bss->behind = 0;
		ASSERT_EQ(run(skel->progs.coro_unwound), 0, "suspend");
		ASSERT_EQ(result(skel, ID_UNWOUND), 1, "result");
		ASSERT_EQ(skel->bss->coro_resumed, 0, "coro_resumed");
		ASSERT_EQ(skel->bss->behind, 0, "behind");
	}
	/* the same continuation, unwound in one resume and not in the other */
	if (test__start_subtest("apart")) {
		skel->bss->coro_resumed = 0;
		ASSERT_EQ(run(skel->progs.coro_apart), 0, "suspend");
		ASSERT_EQ(result(skel, ID_APART_UNWOUND), 1, "unwound");
		ASSERT_EQ(result(skel, ID_APART_RETURNED), 0, "returned");
		ASSERT_EQ(skel->bss->coro_resumed, 1, "coro_resumed");
	}
	/*
	 * The program calls the continuation too. Its recursion runs out of stack in both runs:
	 * the call in the program is unwound, and so is the program, which drops the packet, and
	 * bpf_coro_run() says that the continuation was unwound.
	 */
	if (test__start_subtest("direct")) {
		skel->bss->direct_runs = 0;
		skel->bss->frames = 0;
		skel->bss->behind = 0;
		ASSERT_EQ(run(skel->progs.coro_direct), 2 /* TC_ACT_SHOT */, "suspend");
		ASSERT_EQ(result(skel, ID_DIRECT), 1, "result");
		ASSERT_EQ(skel->bss->direct_runs, 0, "direct_runs");
		ASSERT_GT(skel->bss->frames, 2, "frames");
		ASSERT_EQ(skel->bss->behind, 0, "behind");
	}
	/* bpf_throw() in the continuation */
	if (test__start_subtest("throws")) {
		skel->bss->coro_resumed = 0;
		ASSERT_EQ(run(skel->progs.coro_throws), 0, "suspend");
		ASSERT_EQ(result(skel, ID_THROWS), 1, "result");
		ASSERT_EQ(skel->bss->coro_resumed, 0, "coro_resumed");
	}
	/* the same with an exception callback, which is not called for the continuation */
	if (test__start_subtest("throws_exception_cb")) {
		skel->bss->coro_resumed = 0;
		skel->bss->exc_cb_ran = 0;
		ASSERT_EQ(run(skel->progs.coro_throws_exc), 0, "suspend");
		ASSERT_EQ(result(skel, ID_THROWS_EXC), 1, "result");
		ASSERT_EQ(skel->bss->coro_resumed, 0, "coro_resumed");
		ASSERT_EQ(skel->bss->exc_cb_ran, 0, "exc_cb_ran");
	}
#endif
	/* it stores its own address in slot 0 each time */
	if (test__start_subtest("self")) {
		skel->bss->coro_resumed = 0;
		ASSERT_EQ(run(skel->progs.coro_self), 0, "suspend");
		ASSERT_EQ(result(skel, ID_SELF), 0, "result");
		ASSERT_EQ(skel->bss->coro_resumed, 3, "coro_resumed");
	}
	coro_cont_run__destroy(skel);
}
