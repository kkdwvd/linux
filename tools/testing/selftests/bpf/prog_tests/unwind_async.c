// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include "unwind_async.skel.h"

static int run(struct bpf_program *prog)
{
	char data[64] = {};
	LIBBPF_OPTS(bpf_test_run_opts, opts,
		.data_in = data,
		.data_size_in = sizeof(data),
		.repeat = 1,
	);

	if (!ASSERT_OK(bpf_prog_test_run_opts(bpf_program__fd(prog), &opts), "test_run"))
		return -1;
	return opts.retval;
}

/*
 * The prog arms the callback and calls it directly. Called from BPF code the
 * callback returns to the pad after the call, so the prog returns 2. Called
 * by the kernel its unwind_exit is exit. The pad in the callback runs both
 * times.
 */
static void run_cb(struct unwind_async *skel, struct bpf_program *prog)
{
	int i;

	skel->bss->cb_runs = 0;
	skel->bss->pad_runs = 0;
	ASSERT_EQ(run(prog), 2, "called from BPF code");
	for (i = 0; i < 1000 && skel->bss->cb_runs < 2; i++)
		usleep(1000);
	ASSERT_EQ(skel->bss->cb_runs, 2, "cb_runs");
	ASSERT_EQ(skel->bss->pad_runs, 2, "pad_runs");
}

void test_unwind_async(void)
{
	struct unwind_async *skel;
	int err;

	if (!is_jit_enabled()) {
		printf("%s:SKIP:JIT is disabled\n", __func__);
		test__skip();
		return;
	}
	skel = unwind_async__open_and_load();
	err = libbpf_get_error(skel);
	if (err == -ENOTSUPP) {
		printf("%s:SKIP:JIT does not support unwinding\n", __func__);
		test__skip();
		return;
	}
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;
	if (test__start_subtest("timer"))
		run_cb(skel, skel->progs.timer_cb_unwinds);
	if (test__start_subtest("wq"))
		run_cb(skel, skel->progs.wq_cb_unwinds);
	unwind_async__destroy(skel);
}
