// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include "coro_frame.skel.h"

static void run_prog(struct bpf_program *prog, int expected)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	int err;

	err = bpf_prog_test_run_opts(bpf_program__fd(prog), &opts);
	ASSERT_OK(err, "test_run");
	ASSERT_EQ(opts.retval, expected, "retval");
}

void test_coro_frame(void)
{
	struct coro_frame *skel;

	skel = coro_frame__open_and_load();
	if (!ASSERT_OK_PTR(skel, "coro_frame__open_and_load"))
		return;

	if (test__start_subtest("sum"))
		run_prog(skel->progs.coro_frame_sum, 42);
	if (test__start_subtest("odd_size"))
		run_prog(skel->progs.coro_frame_odd_size, 6);

	coro_frame__destroy(skel);
}
