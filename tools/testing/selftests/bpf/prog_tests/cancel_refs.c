// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <linux/pkt_cls.h>
#include "cancel_refs.skel.h"

static char stream[64 * 1024];

/* Run @prog once. Returns what it returned. */
static int run(struct bpf_program *prog)
{
	char data[64] = {};
	LIBBPF_OPTS(bpf_test_run_opts, opts);

	/* a syscall prog takes no packet */
	if (bpf_program__type(prog) != BPF_PROG_TYPE_SYSCALL) {
		opts.data_in = data;
		opts.data_size_in = sizeof(data);
		opts.repeat = 1;
	}
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

/* "@prog @of", to tell which prog an assertion is about */
static const char *what(struct bpf_program *prog, const char *of)
{
	static char buf[128];

	snprintf(buf, sizeof(buf), "%s %s", bpf_program__name(prog), of);
	return buf;
}

static bool is_tc(struct bpf_program *prog)
{
	return bpf_program__type(prog) == BPF_PROG_TYPE_SCHED_CLS;
}

/*
 * @prog is cancelled: it returns the cancel value of its type where its last insn returns
 * something else, its pad says so in the stream, and nothing ran behind a call of the
 * recursion.
 */
static void cancelled(struct cancel_refs *skel, struct bpf_program *prog)
{
	skel->bss->behind = 0;
	ASSERT_EQ(run(prog), is_tc(prog) ? TC_ACT_SHOT : 0, what(prog, "retval"));
	ASSERT_EQ(skel->bss->behind, 0, what(prog, "behind"));
	ASSERT_HAS_SUBSTR(read_stream(prog), "ERROR: Program was cancelled", what(prog, "stream"));
}

static void test_iters(struct cancel_refs *skel)
{
	/* bpf_iter_num and the iterator of the module leave nothing behind that could be found */
	cancelled(skel, skel->progs.num_iter_at_call);
	cancelled(skel, skel->progs.testmod_iter_at_call);
	/* a prog that returns to user space inside of an RCU section draws a splat */
	cancelled(skel, skel->progs.task_iter_in_rcu);
}

void serial_test_cancel_refs(void)
{
	struct cancel_refs *skel;

	/* The interpreter runs no pads. */
	if (!is_jit_enabled()) {
		test__skip();
		return;
	}

	/* what the verifier says about the progs. They run below, where their globals are set. */
	RUN_TESTS(cancel_refs);

#if !defined(__x86_64__) && !defined(__aarch64__)
	return;
#endif
	skel = cancel_refs__open_and_load();
	if (!ASSERT_OK_PTR(skel, "cancel_refs__open_and_load"))
		return;

	if (test__start_subtest("iterators"))
		test_iters(skel);
	cancel_refs__destroy(skel);
}
