// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <network_helpers.h>

#include "exceptions_cleanup.skel.h"

static void run_prog(struct exceptions_cleanup *skel, struct bpf_program *prog, int acquired,
		     int released, int retval)
{
	LIBBPF_OPTS(bpf_test_run_opts, ropts,
		.data_in = &pkt_v4,
		.data_size_in = sizeof(pkt_v4),
		.repeat = 1,
	);
	int ret, i;

	skel->bss->acquired_cnt = 0;
	skel->bss->released_cnt = 0;
	memset(skel->bss->acquired, 0, sizeof(skel->bss->acquired));
	memset(skel->bss->released, 0, sizeof(skel->bss->released));

	/* A tracing program runs on its hook, with no input. */
	if (bpf_program__type(prog) == BPF_PROG_TYPE_TRACING) {
		ropts.data_in = NULL;
		ropts.data_size_in = 0;
	}
	ret = bpf_prog_test_run_opts(bpf_program__fd(prog), &ropts);
	if (!ASSERT_OK(ret, "test_run"))
		return;
	ASSERT_EQ(ropts.retval, retval, "retval");
	ASSERT_EQ(skel->bss->acquired_cnt, acquired, "acquired");
	ASSERT_EQ(skel->bss->released_cnt, released, "released");
	for (i = 0; i < released; i++)
		ASSERT_NEQ(skel->bss->released[i], 0, "released ptr");
}

void test_exceptions_cleanup(void)
{
	struct exceptions_cleanup *skel;

	skel = exceptions_cleanup__open_and_load();
	if (!ASSERT_OK_PTR(skel, "exceptions_cleanup__open_and_load"))
		return;
	if (!ASSERT_OK(exceptions_cleanup__attach(skel), "attach"))
		goto out;

#define RUN(name, n, released, retval) do {				\
	if (test__start_subtest(#name))						\
		run_prog(skel, skel->progs.name, n, released, retval);		\
} while (0)
#define THROW(name, n) RUN(name, n, n, 0xeB9F)
	THROW(throw_obj_reg, 1);
	THROW(throw_obj_two, 2);
	THROW(throw_ringbuf, 1);
	THROW(throw_task, 1);
	THROW(throw_iter, 1);
	THROW(throw_obj_maybe, 1);
	THROW(throw_obj_caller, 1);
	THROW(throw_obj_unconditional, 1);
	THROW(throw_obj_subprog, 1);
	THROW(throw_obj_global_caller, 1);
	/* A cancelled tc program returns TC_ACT_SHOT. */
	RUN(cancel_may_goto_obj, 1, 1, 2);
	RUN(cancel_may_goto_caller, 1, 1, 2);
	RUN(cancel_may_goto_global, 1, 1, 2);
	RUN(cancel_may_goto_global_chain, 1, 1, 2);
	RUN(nocancel_may_goto_callback, 1, 0, 0);
	RUN(nocancel_may_goto_global_callback, 1, 0, 0);
	RUN(nocancel_may_goto_shared_subprog, 1, 0, 0);
	RUN(nocancel_may_goto_rcu, 1, 0, 0);
	/* A cancelled tracing program returns 0. */
	RUN(cancel_may_goto_priv_stack, 1, 1, 0);
#undef THROW
#undef RUN
out:
	exceptions_cleanup__destroy(skel);
}
