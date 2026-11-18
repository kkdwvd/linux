// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <linux/pkt_cls.h>
#include <sys/wait.h>
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

struct child {
	pid_t pid;
	int wfd;
};

/* A task that waits for the pipe to close, for the progs to take */
static bool start_child(struct child *child)
{
	int fds[2];
	char c;

	if (!ASSERT_OK(pipe(fds), "pipe"))
		return false;
	child->pid = fork();
	if (child->pid == 0) {
		close(fds[1]);
		if (read(fds[0], &c, 1) < 0)
			_exit(1);
		_exit(0);
	}
	close(fds[0]);
	child->wfd = fds[1];
	if (!ASSERT_GT(child->pid, 0, "fork")) {
		close(fds[1]);
		return false;
	}
	return true;
}

static void stop_child(struct child *child)
{
	close(child->wfd);
	waitpid(child->pid, NULL, 0);
}

static int task_users(struct coro_cancel *skel)
{
	skel->bss->task_rcu_users = -1;
	run(skel->progs.probe_task);
	return skel->bss->task_rcu_users;
}

/* The task that a prog held through a coroutine frame is released */
static void test_tasks(struct coro_cancel *skel)
{
	struct child child;
	int users;

	if (!start_child(&child))
		return;
	skel->bss->pid = child.pid;
	users = task_users(skel);
	if (!ASSERT_GT(users, 0, "task_users"))
		goto out;

	cancelled(skel, skel->progs.task_in_frame_at_call);
	ASSERT_EQ(task_users(skel), users, "task_in_frame_at_call");
	cancelled(skel, skel->progs.task_in_spilled_frame_at_call);
	ASSERT_EQ(task_users(skel), users, "task_in_spilled_frame_at_call");
	throws(skel, skel->progs.task_in_frame_at_throw, 4);
	ASSERT_EQ(task_users(skel), users, "task_in_frame_at_throw");
	throws(skel, skel->progs.task_in_frame_callee_throws, 5);
	ASSERT_EQ(task_users(skel), users, "task_in_frame_callee_throws");

	/*
	 * The continuation is cancelled inside of the call that suspends the coroutine, and
	 * reports that in the stream. The prog goes on behind the call.
	 */
	skel->bss->behind = 0;
	ASSERT_EQ(run(skel->progs.cont_task_at_call), TC_ACT_OK, "cont_task_at_call");
	ASSERT_EQ(skel->bss->behind, 0, "cont_task_at_call behind");
	ASSERT_HAS_SUBSTR(read_stream(skel->progs.cont_task_at_call),
			  "ERROR: Program was cancelled", "cont_task_at_call stream");
	ASSERT_EQ(task_users(skel), users, "cont_task_at_call");
out:
	stop_child(&child);
}

void serial_test_coro_cancel(void)
{
	struct coro_cancel *skel;

	/* The interpreter runs no pads, and the continuations take bpf_testmod. */
	if (!is_jit_enabled() || !env.has_testmod) {
		test__skip();
		return;
	}

	/* what the verifier says about the progs */
	RUN_TESTS(coro_cancel);

#if !defined(__x86_64__) && !defined(__aarch64__)
	return;
#endif
	skel = coro_cancel__open();
	if (!ASSERT_OK_PTR(skel, "coro_cancel__open"))
		return;
	/* the progs that the verifier rejects */
	bpf_program__set_autoload(skel->progs.task_in_frame_given_to_callee, false);
	bpf_program__set_autoload(skel->progs.cont_task_some_paths, false);
	if (!ASSERT_OK(coro_cancel__load(skel), "coro_cancel__load"))
		goto out;

	if (test__start_subtest("frames")) {
		cancelled(skel, skel->progs.frame_at_call);
		cancelled(skel, skel->progs.frame_spilled_at_call);
		throws(skel, skel->progs.frame_at_throw, 3);
		cancelled(skel, skel->progs.frame_maybe_null_at_call);
	}
	if (test__start_subtest("tasks"))
		test_tasks(skel);
out:
	coro_cancel__destroy(skel);
}
