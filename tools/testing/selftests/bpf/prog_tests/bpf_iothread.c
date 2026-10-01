// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>
#include <sys/syscall.h>
#include "bpf_iothread.skel.h"
#include "bpf_iothread_failures.skel.h"

#define FRAME_MARK 0xc0ffeeULL

static int run_syscall_prog(struct bpf_program *prog, int *retval)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	int err;

	err = bpf_prog_test_run_opts(bpf_program__fd(prog), &opts);
	if (!err)
		*retval = (int)opts.retval;
	return err;
}

static bool wait_for_counter(__u32 *counter)
{
	int i;

	for (i = 0; i < 2000; i++) {
		if (READ_ONCE(*counter))
			return true;
		usleep(1000);
	}
	return false;
}

/* The io thread acts for this process: it reads our pipe into our memory. */
static void test_io_thread(struct bpf_iothread *skel, int *pipefd)
{
	volatile __u64 scratch = 0;
	__u64 token = 0x1234567890ULL;
	int err, ret;

	skel->bss->pipe_fd = pipefd[0];
	skel->bss->scratch_uaddr = (__u64)(uintptr_t)&scratch;
	if (!ASSERT_EQ(write(pipefd[1], &token, sizeof(token)), 8, "pipe_write"))
		return;

	err = run_syscall_prog(skel->progs.start_io_thread, &ret);
	if (!ASSERT_OK(err, "start_io_thread") || !ASSERT_EQ(ret, 0, "start_ret"))
		return;
	if (!ASSERT_TRUE(wait_for_counter(&skel->bss->cb_runs), "callback_ran"))
		goto stop;

	err = run_syscall_prog(skel->progs.stop_io_thread, &ret);
	ASSERT_OK(err, "stop_io_thread");
	ASSERT_EQ(ret, 0, "stop_ret");

	ASSERT_EQ(skel->bss->exec_getppid, getppid(), "exec_getppid");
	ASSERT_EQ(skel->bss->exec_getpid, getpid(), "exec_getpid");
	ASSERT_EQ(skel->bss->exec_refused, -ENOSYS, "exec_refused");
	ASSERT_EQ(skel->bss->exec_read, 8, "exec_read");
	ASSERT_EQ(scratch, token, "exec_read_data");

	err = run_syscall_prog(skel->progs.exec_from_task, &ret);
	ASSERT_OK(err, "exec_from_task");
	ASSERT_EQ(ret, -EPERM, "exec_from_task_ret");
	return;
stop:
	run_syscall_prog(skel->progs.stop_io_thread, &ret);
}

static void test_park(struct bpf_iothread *skel, int *pipefd)
{
	__u64 token = 1;
	int err, ret;

	skel->bss->pipe_fd = pipefd[0];

	/* Nothing to read: the frame waits. */
	err = run_syscall_prog(skel->progs.park_on_pipe, &ret);
	if (!ASSERT_OK(err, "park_on_pipe") || !ASSERT_EQ(ret, 0, "park_ret"))
		return;
	err = run_syscall_prog(skel->progs.unpark_one, &ret);
	ASSERT_OK(err, "unpark_empty");
	ASSERT_EQ(ret, -ENOENT, "unpark_empty_ret");

	/* Data makes it ready and signals the queue. */
	err = run_syscall_prog(skel->progs.sample_sequence, &ret);
	ASSERT_OK(err, "sample_sequence");
	ASSERT_EQ(write(pipefd[1], &token, sizeof(token)), 8, "pipe_write");
	usleep(10000);
	err = run_syscall_prog(skel->progs.wait_for_ready, &ret);
	ASSERT_OK(err, "wait_for_ready");
	ASSERT_EQ(ret, -EAGAIN, "wait_for_ready_ret");
	skel->bss->unparked_mark = 0;
	err = run_syscall_prog(skel->progs.unpark_one, &ret);
	ASSERT_OK(err, "unpark_ready");
	ASSERT_EQ(ret, 0, "unpark_ready_ret");
	ASSERT_EQ(skel->bss->unparked_mark, FRAME_MARK, "unparked_mark");
	ASSERT_EQ(read(pipefd[0], &token, sizeof(token)), 8, "pipe_drain");

	/* A bad descriptor: ready at once, so the coroutine can see the error. */
	err = run_syscall_prog(skel->progs.park_on_bad_fd, &ret);
	ASSERT_OK(err, "park_on_bad_fd");
	ASSERT_EQ(ret, 0, "park_bad_ret");
	err = run_syscall_prog(skel->progs.unpark_one, &ret);
	ASSERT_OK(err, "unpark_bad");
	ASSERT_EQ(ret, 0, "unpark_bad_ret");
	ASSERT_EQ(skel->bss->unparked_mark, FRAME_MARK + 1, "unparked_bad_mark");

	/* A yield: ready at once. */
	err = run_syscall_prog(skel->progs.park_yield, &ret);
	ASSERT_OK(err, "park_yield");
	ASSERT_EQ(ret, 0, "park_yield_ret");
	err = run_syscall_prog(skel->progs.unpark_one, &ret);
	ASSERT_OK(err, "unpark_yield");
	ASSERT_EQ(ret, 0, "unpark_yield_ret");
	ASSERT_EQ(skel->bss->unparked_mark, FRAME_MARK + 2, "unparked_yield_mark");

	/* A frame smaller than the size asked for is dropped, not returned. */
	err = run_syscall_prog(skel->progs.park_yield, &ret);
	ASSERT_OK(err, "park_yield2");
	err = run_syscall_prog(skel->progs.unpark_too_large, &ret);
	ASSERT_OK(err, "unpark_too_large");
	ASSERT_EQ(ret, -ENOENT, "unpark_too_large_ret");
	err = run_syscall_prog(skel->progs.unpark_one, &ret);
	ASSERT_OK(err, "unpark_after_drop");
	ASSERT_EQ(ret, -ENOENT, "unpark_after_drop_ret");
}

void test_bpf_iothread(void)
{
	struct bpf_iothread *skel;
	int pipefd[2];

	RUN_TESTS(bpf_iothread_failures);

	if (!ASSERT_OK(pipe2(pipefd, O_NONBLOCK), "pipe"))
		return;
	skel = bpf_iothread__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		goto close_pipe;

	if (test__start_subtest("io_thread"))
		test_io_thread(skel, pipefd);
	if (test__start_subtest("park"))
		test_park(skel, pipefd);

	bpf_iothread__destroy(skel);
close_pipe:
	close(pipefd[0]);
	close(pipefd[1]);
}
