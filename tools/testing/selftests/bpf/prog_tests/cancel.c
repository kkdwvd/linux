// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <linux/pkt_cls.h>
#include "cancel.skel.h"

static char stream[64 * 1024];

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
 * The frames of the recursion count themselves on the way down, and what is behind a call
 * counts too. The test loader checks the return value and the stream of the same progs,
 * but it cannot read their variables.
 */
static void test_nothing_behind(struct cancel *skel, struct bpf_program *prog, int retval)
{
	skel->bss->frames = 0;
	skel->bss->behind = 0;
	ASSERT_EQ(run(prog), retval, "retval");
	ASSERT_GT(skel->bss->frames, 8, "frames");
	ASSERT_EQ(skel->bss->behind, 0, "behind");
}

/*
 * The callback of the timer runs when the prog that armed it has returned. The last thing
 * that it does is the line that its pad writes to the stream: wait for it.
 */
static void test_timer(struct cancel *skel)
{
	LIBBPF_OPTS(bpf_prog_stream_read_opts, ropts);
	int fd = bpf_program__fd(skel->progs.timer_recursion);
	const char *report, *cancelled = NULL;
	int i, n, len = 0;

	skel->bss->frames = 0;
	skel->bss->behind = 0;
	if (!ASSERT_EQ(run(skel->progs.timer_recursion), 0, "retval"))
		return;
	for (i = 0; i < 500 && !cancelled; i++) {
		n = bpf_prog_stream_read(fd, BPF_STREAM_STDERR, stream + len,
					 sizeof(stream) - len - 1, &ropts);
		if (n > 0)
			len += n;
		stream[len] = 0;
		cancelled = strstr(stream, "ERROR: Program was cancelled");
		if (!cancelled)
			usleep(10000);
	}
	if (!ASSERT_TRUE(cancelled != NULL, "cancelled"))
		return;
	report = strstr(stream, "ERROR: No room in the stack for a call of a recursive function");
	ASSERT_TRUE(report && report < cancelled, "report of the stack check");
	ASSERT_GT(skel->bss->frames, 8, "frames");
	ASSERT_EQ(skel->bss->behind, 0, "behind");
}

void serial_test_cancel(void)
{
	struct bpf_program *prog;
	struct cancel *skel;

	/* The interpreter runs no pads. */
	if (!is_jit_enabled()) {
		test__skip();
		return;
	}

	RUN_TESTS(cancel);

#if !defined(__x86_64__) && !defined(__aarch64__)
	return;
#endif
	skel = cancel__open();
	if (!ASSERT_OK_PTR(skel, "cancel__open"))
		return;
	bpf_object__for_each_program(prog, skel->obj)
		bpf_program__set_autoload(prog, prog == skel->progs.recursion_tc ||
						prog == skel->progs.recursion_socket ||
						prog == skel->progs.timer_recursion);
	if (!ASSERT_OK(cancel__load(skel), "cancel__load"))
		goto out;

	if (test__start_subtest("nothing_behind")) {
		test_nothing_behind(skel, skel->progs.recursion_tc, TC_ACT_SHOT);
		test_nothing_behind(skel, skel->progs.recursion_socket, 0);
	}
	if (test__start_subtest("timer"))
		test_timer(skel);
out:
	cancel__destroy(skel);
}
