// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <network_helpers.h>

#include "exceptions_cleanup.skel.h"

static void run_prog(struct exceptions_cleanup *skel, struct bpf_program *prog, int expected)
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

	ret = bpf_prog_test_run_opts(bpf_program__fd(prog), &ropts);
	if (!ASSERT_OK(ret, "test_run"))
		return;
	ASSERT_EQ(ropts.retval, 0xeB9F, "retval");
	ASSERT_EQ(skel->bss->acquired_cnt, expected, "acquired");
	ASSERT_EQ(skel->bss->released_cnt, expected, "released");
	for (i = 0; i < expected; i++)
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

#define RUN(name, n) do { if (test__start_subtest(#name)) run_prog(skel, skel->progs.name, n); } while (0)
	RUN(throw_obj_reg, 1);
	RUN(throw_obj_two, 2);
	RUN(throw_ringbuf, 1);
	RUN(throw_task, 1);
	RUN(throw_iter, 1);
	RUN(throw_obj_maybe, 1);
	RUN(throw_obj_caller, 1);
	RUN(throw_obj_unconditional, 1);
	RUN(throw_obj_subprog, 1);
	RUN(throw_obj_global_caller, 1);
#undef RUN
out:
	exceptions_cleanup__destroy(skel);
}
