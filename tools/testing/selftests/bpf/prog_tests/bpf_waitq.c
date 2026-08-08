// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>
#include "bpf_waitq_success.skel.h"
#include "bpf_waitq_failures.skel.h"

static int run_syscall_prog(struct bpf_program *prog, __u32 *retval)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	int err;

	err = bpf_prog_test_run_opts(bpf_program__fd(prog), &opts);
	if (!err)
		*retval = opts.retval;
	return err;
}

static bool wait_for_counter(__u32 *counter)
{
	int i;

	for (i = 0; i < 1000; i++) {
		if (READ_ONCE(*counter))
			return true;
		usleep(1000);
	}
	return false;
}

void test_bpf_waitq(void)
{
	struct bpf_waitq_success *skel;
	__u32 retval;
	int err;

	RUN_TESTS(bpf_waitq_failures);

	skel = bpf_waitq_success__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;

	err = run_syscall_prog(skel->progs.start_wake_case, &retval);
	if (!ASSERT_OK(err, "start_wake_case") || !ASSERT_EQ(retval, 0, "start_ret"))
		goto out;
	if (!ASSERT_TRUE(wait_for_counter(&skel->bss->callback_runs[0]), "thread_started"))
		goto out;

	err = run_syscall_prog(skel->progs.wake_thread, &retval);
	if (!ASSERT_OK(err, "wake_thread") || !ASSERT_LE(retval, 1, "wake_ret"))
		goto out;
	if (!ASSERT_TRUE(wait_for_counter(&skel->bss->callback_exits[0]), "thread_exited"))
		goto out;

	err = run_syscall_prog(skel->progs.stop_wake_thread, &retval);
	if (!ASSERT_OK(err, "stop_wake_thread") || !ASSERT_EQ(retval, 1, "wake_stop_ret"))
		goto out;
	err = run_syscall_prog(skel->progs.wait_mismatch, &retval);
	if (!ASSERT_OK(err, "wait_mismatch") ||
	    !ASSERT_EQ((__s32)retval, -EAGAIN, "mismatch_ret"))
		goto out;

	err = run_syscall_prog(skel->progs.start_stop_case, &retval);
	if (!ASSERT_OK(err, "start_stop_case") || !ASSERT_EQ(retval, 0, "stop_start_ret"))
		goto out;
	if (!ASSERT_TRUE(wait_for_counter(&skel->bss->callback_runs[1]), "stop_thread_started"))
		goto out;

	err = run_syscall_prog(skel->progs.stop_waiting_thread, &retval);
	if (!ASSERT_OK(err, "stop_waiting_thread") ||
	    !ASSERT_EQ(retval, 0, "waiting_stop_ret"))
		goto out;
	err = run_syscall_prog(skel->progs.wait_timeout, &retval);
	ASSERT_OK(err, "wait_timeout");
	ASSERT_EQ((__s32)retval, -ETIMEDOUT, "timeout_ret");
out:
	bpf_waitq_success__destroy(skel);
}
