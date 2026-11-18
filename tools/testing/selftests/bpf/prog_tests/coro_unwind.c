// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <linux/pkt_cls.h>
#include <sys/wait.h>
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

/* What became of the resume of the continuation: wait two seconds at most */
static int cont_result(struct coro_unwind *skel)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	int i;

	for (i = 0; i < 200; i++) {
		if (!ASSERT_OK(bpf_prog_test_run_opts(bpf_program__fd(skel->progs.cont_result),
						      &opts), "cont_result"))
			return -1;
		if (opts.retval != -EINPROGRESS)
			return opts.retval;
		usleep(10000);
	}
	return -EINPROGRESS;
}

static int task_users(struct coro_unwind *skel)
{
	skel->bss->task_rcu_users = -1;
	run(skel->progs.probe_task);
	return skel->bss->task_rcu_users;
}

/* The task that a prog held through a coroutine frame is released */
static void test_tasks(struct coro_unwind *skel)
{
	struct child child;
	int users;

	if (!start_child(&child))
		return;
	skel->bss->pid = child.pid;
	users = task_users(skel);
	if (!ASSERT_GT(users, 0, "task_users"))
		goto out;

	unwound(skel, skel->progs.task_in_frame_at_call);
	ASSERT_EQ(task_users(skel), users, "task_in_frame_at_call");
	unwound(skel, skel->progs.task_in_spilled_frame_at_call);
	ASSERT_EQ(task_users(skel), users, "task_in_spilled_frame_at_call");
	throws(skel, skel->progs.task_in_frame_at_throw, 4);
	ASSERT_EQ(task_users(skel), users, "task_in_frame_at_throw");
	throws(skel, skel->progs.task_in_frame_callee_throws, 5);
	ASSERT_EQ(task_users(skel), users, "task_in_frame_callee_throws");
	unwound(skel, skel->progs.task_in_frame_given_to_callee);
	ASSERT_EQ(task_users(skel), users, "task_in_frame_given_to_callee");
	unwound(skel, skel->progs.task_in_frame_taken_by_callee);
	ASSERT_EQ(task_users(skel), users, "task_in_frame_taken_by_callee");
	/* the second access to arena faults, which unwinds the prog too */
	skel->bss->behind = 0;
	ASSERT_EQ(run(skel->progs.task_out_of_frame_at_fault), TC_ACT_SHOT,
		  "task_out_of_frame_at_fault");
	ASSERT_EQ(skel->bss->behind, 0, "task_out_of_frame_at_fault behind");
	ASSERT_EQ(task_users(skel), users, "task_out_of_frame_at_fault");

	/*
	 * bpf_testmod resumes the continuation after the call that suspends the coroutine. It is
	 * unwound, the stream says why, and the landing pad of bpf_coro_run() tells bpf_testmod.
	 */
	skel->bss->behind = 0;
	ASSERT_EQ(run(skel->progs.cont_task_at_call), TC_ACT_OK, "cont_task_at_call");
	ASSERT_EQ(cont_result(skel), 1, "cont_task_at_call unwound");
	ASSERT_EQ(skel->bss->behind, 0, "cont_task_at_call behind");
	ASSERT_HAS_SUBSTR(read_stream(skel->progs.cont_task_at_call), RECURSION_TOO_DEEP,
			  "cont_task_at_call stream");
	ASSERT_EQ(task_users(skel), users, "cont_task_at_call");

	/*
	 * The same with the task two coroutine frames deep and in R7: the pad releases it from
	 * R7, frees the frame in the slot of the first one, then the first one
	 */
	ASSERT_EQ(run(skel->progs.cont_task_two_deep_r7), TC_ACT_OK, "cont_task_two_deep_r7");
	ASSERT_EQ(cont_result(skel), 1, "cont_task_two_deep_r7 unwound");
	ASSERT_HAS_SUBSTR(read_stream(skel->progs.cont_task_two_deep_r7), RECURSION_TOO_DEEP,
			  "cont_task_two_deep_r7 stream");
	ASSERT_EQ(task_users(skel), users, "cont_task_two_deep_r7");
out:
	stop_child(&child);
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

	/* The interpreter runs no pads, and the continuations take bpf_testmod. */
	if (!is_jit_enabled() || !env.has_testmod) {
		test__skip();
		return;
	}

	/* what the verifier says about the progs */
	RUN_TESTS(coro_unwind);

#if !defined(__x86_64__) && !defined(__aarch64__)
	return;
#endif
	skel = coro_unwind__open();
	if (!ASSERT_OK_PTR(skel, "coro_unwind__open"))
		return;
	/* the progs that the verifier rejects */
	bpf_program__set_autoload(skel->progs.cont_task_some_paths, false);
	bpf_program__set_autoload(skel->progs.cont_task_two_deep, false);
	bpf_program__set_autoload(skel->progs.cont_task_far, false);
	if (!ASSERT_OK(coro_unwind__load(skel), "coro_unwind__load"))
		goto out;

	if (test__start_subtest("frames")) {
		unwound(skel, skel->progs.frame_at_call);
		unwound(skel, skel->progs.frame_spilled_at_call);
		throws(skel, skel->progs.frame_at_throw, 3);
		unwound(skel, skel->progs.frame_maybe_null_at_call);
	}
	if (test__start_subtest("tasks"))
		test_tasks(skel);
	destroy_and_check(skel);
	return;
out:
	coro_unwind__destroy(skel);
}
