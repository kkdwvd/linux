// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <linux/pkt_cls.h>
#include "coro_cancel.skel.h"

static char stream[64 * 1024];

/* Run @prog once. Returns what it returned. */
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

/* What @prog wrote to its stderr stream since this was called last */
static const char *read_stream(struct bpf_program *prog)
{
	LIBBPF_OPTS(bpf_prog_stream_read_opts, ropts);
	int fd = bpf_program__fd(prog), max = sizeof(stream) - 1, len = 0, n;

	do {
		n = bpf_prog_stream_read(fd, BPF_STREAM_STDERR, stream + len, max - len, &ropts);
		if (n > 0)
			len += n;
	} while (n > 0 && len < max);
	stream[len] = 0;
	return stream;
}

/*
 * @prog throws @cookie and has no exception callback: it returns the cookie, nothing ran behind
 * the throw, and nothing is reported.
 */
static void throws(struct coro_cancel *skel, struct bpf_program *prog, int cookie)
{
	skel->bss->behind = 0;
	ASSERT_EQ(run(prog), cookie, bpf_program__name(prog));
	ASSERT_EQ(skel->bss->behind, 0, bpf_program__name(prog));
	ASSERT_STREQ(read_stream(prog), "", bpf_program__name(prog));
}

/*
 * @prog is cancelled: it returns TC_ACT_SHOT, its pad says so in the stream, and nothing ran
 * behind a call of the recursion.
 */
static void cancelled(struct coro_cancel *skel, struct bpf_program *prog)
{
	skel->bss->behind = 0;
	ASSERT_EQ(run(prog), TC_ACT_SHOT, bpf_program__name(prog));
	ASSERT_EQ(skel->bss->behind, 0, bpf_program__name(prog));
	ASSERT_HAS_SUBSTR(read_stream(prog), "ERROR: Program was cancelled",
			  bpf_program__name(prog));
}

void serial_test_coro_cancel(void)
{
	struct coro_cancel *skel;

	/* The interpreter runs no pads. */
	if (!is_jit_enabled()) {
		test__skip();
		return;
	}

	/* what the verifier says about the progs */
	RUN_TESTS(coro_cancel);

#if !defined(__x86_64__) && !defined(__aarch64__)
	return;
#endif
	skel = coro_cancel__open_and_load();
	if (!ASSERT_OK_PTR(skel, "coro_cancel__open_and_load"))
		return;

	if (test__start_subtest("frames")) {
		cancelled(skel, skel->progs.frame_at_call);
		cancelled(skel, skel->progs.frame_spilled_at_call);
		throws(skel, skel->progs.frame_at_throw, 3);
		cancelled(skel, skel->progs.frame_maybe_null_at_call);
	}

	coro_cancel__destroy(skel);
}
