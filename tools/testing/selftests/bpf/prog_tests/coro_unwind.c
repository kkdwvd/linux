// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <linux/pkt_cls.h>
#include "coro_unwind.skel.h"

static char stream[64 * 1024];

/* What bpf_prog_report_recursion() writes to the stream */
#define RECURSION_TOO_DEEP "ERROR: No room in the stack for a call of a recursive function"

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
static void throws(struct coro_unwind *skel, struct bpf_program *prog, int cookie)
{
	skel->bss->behind = 0;
	ASSERT_EQ(run(prog), cookie, bpf_program__name(prog));
	ASSERT_EQ(skel->bss->behind, 0, bpf_program__name(prog));
	ASSERT_STREQ(read_stream(prog), "", bpf_program__name(prog));
}

/*
 * @prog is unwound when the recursion has no room in the stack: it returns TC_ACT_SHOT, the
 * stream says why, and nothing ran behind a call of the recursion.
 */
static void unwound(struct coro_unwind *skel, struct bpf_program *prog)
{
	skel->bss->behind = 0;
	ASSERT_EQ(run(prog), TC_ACT_SHOT, bpf_program__name(prog));
	ASSERT_EQ(skel->bss->behind, 0, bpf_program__name(prog));
	ASSERT_HAS_SUBSTR(read_stream(prog), RECURSION_TOO_DEEP, bpf_program__name(prog));
}

/* Is the program with @id freed within two seconds? The kernel frees it in the background. */
static bool prog_freed(__u32 id)
{
	int i, fd;

	for (i = 0; i < 200; i++) {
		fd = bpf_prog_get_fd_by_id(id);
		if (fd < 0)
			return errno == ENOENT;
		close(fd);
		usleep(10000);
	}
	return false;
}

/*
 * Each coroutine frame holds a reference on its prog, which the pads give back when they free
 * the frame: the progs go with the skeleton.
 */
static void destroy_and_check(struct coro_unwind *skel)
{
	struct bpf_prog_info info;
	struct bpf_program *prog;
	__u32 ids[64], len;
	int n = 0, i;

	bpf_object__for_each_program(prog, skel->obj) {
		memset(&info, 0, sizeof(info));
		len = sizeof(info);
		if (bpf_program__fd(prog) < 0 || n == ARRAY_SIZE(ids) ||
		    bpf_prog_get_info_by_fd(bpf_program__fd(prog), &info, &len))
			continue;
		ids[n++] = info.id;
	}
	coro_unwind__destroy(skel);
	for (i = 0; i < n; i++)
		ASSERT_TRUE(prog_freed(ids[i]), "prog_freed");
}

void serial_test_coro_unwind(void)
{
	struct coro_unwind *skel;

	/* The interpreter runs no pads. */
	if (!is_jit_enabled()) {
		test__skip();
		return;
	}

	/* what the verifier says about the progs */
	RUN_TESTS(coro_unwind);

#if !defined(__x86_64__) && !defined(__aarch64__)
	return;
#endif
	skel = coro_unwind__open_and_load();
	if (!ASSERT_OK_PTR(skel, "coro_unwind__open_and_load"))
		return;

	if (test__start_subtest("frames")) {
		unwound(skel, skel->progs.frame_at_call);
		unwound(skel, skel->progs.frame_spilled_at_call);
		throws(skel, skel->progs.frame_at_throw, 3);
		unwound(skel, skel->progs.frame_maybe_null_at_call);
	}
	destroy_and_check(skel);
}
