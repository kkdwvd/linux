// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>
#include <pthread.h>
#include <signal.h>
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

/* A thread blocked in a syscall program that waits on the queue. */
struct waiter {
	struct bpf_program *prog;
	pthread_t thread;
	__u32 retval;
	int err;
	int done;
};

static void *waiter_fn(void *arg)
{
	struct waiter *w = arg;

	w->err = run_syscall_prog(w->prog, &w->retval);
	__atomic_store_n(&w->done, 1, __ATOMIC_RELEASE);
	return NULL;
}

static bool waiter_done(struct waiter *w)
{
	return __atomic_load_n(&w->done, __ATOMIC_ACQUIRE);
}

/*
 * Wake one waiter until a wake reports that it woke one, which it does only
 * once the waiter sleeps on the queue, or until the waiter has returned by
 * itself. Returns whether a wake found the waiter.
 */
static bool wake_waiter(struct bpf_waitq_success *skel, struct waiter *w)
{
	__u32 retval;
	int i;

	for (i = 0; i < 1000 && !waiter_done(w); i++) {
		if (run_syscall_prog(skel->progs.wake_one, &retval))
			return false;
		if (retval == 1)
			return true;
		usleep(1000);
	}
	return false;
}

static void test_wait(struct bpf_waitq_success *skel)
{
	__u32 retval;
	int err;

	err = run_syscall_prog(skel->progs.wait_mismatch, &retval);
	ASSERT_OK(err, "wait_mismatch");
	ASSERT_EQ((__s32)retval, -EAGAIN, "mismatch_ret");

	err = run_syscall_prog(skel->progs.wait_timeout, &retval);
	ASSERT_OK(err, "wait_timeout");
	ASSERT_EQ((__s32)retval, -ETIMEDOUT, "timeout_ret");
}

static void test_wake(struct bpf_waitq_success *skel)
{
	struct waiter w = { .prog = skel->progs.wait_forever };
	bool woken;

	if (!ASSERT_OK(pthread_create(&w.thread, NULL, waiter_fn, &w), "pthread_create"))
		return;
	woken = wake_waiter(skel, &w);
	pthread_join(w.thread, NULL);
	ASSERT_TRUE(woken, "woken");
	ASSERT_OK(w.err, "wait_forever");
	ASSERT_EQ((__s32)w.retval, 0, "wake_wait_ret");
}

static void test_wait_event(struct bpf_waitq_success *skel)
{
	__u32 retval;
	bool woken;
	int i, err;

	err = run_syscall_prog(skel->progs.wait_event_stale, &retval);
	ASSERT_OK(err, "wait_event_stale");
	ASSERT_EQ((__s32)retval, -EAGAIN, "event_stale_ret");

	err = run_syscall_prog(skel->progs.wait_event_timeout, &retval);
	ASSERT_OK(err, "wait_event_timeout");
	ASSERT_EQ((__s32)retval, -ETIMEDOUT, "event_timeout_ret");

	/* A wake that lands between the waiter's sample and its sleep is not a test of the wake. */
	for (i = 0; i < 10; i++) {
		struct waiter w = { .prog = skel->progs.wait_event_forever };

		if (!ASSERT_OK(pthread_create(&w.thread, NULL, waiter_fn, &w), "pthread_create"))
			return;
		woken = wake_waiter(skel, &w);
		pthread_join(w.thread, NULL);
		if (!ASSERT_OK(w.err, "wait_event_forever"))
			return;
		if (woken || (__s32)w.retval != -EAGAIN) {
			ASSERT_TRUE(woken, "event_woken");
			ASSERT_EQ((__s32)w.retval, 0, "event_wake_wait_ret");
			return;
		}
	}
	ASSERT_TRUE(false, "event_wake_raced_every_attempt");
}

static void sig_noop(int sig)
{
}

static void test_signal(struct bpf_waitq_success *skel)
{
	struct waiter w = { .prog = skel->progs.wait_forever };
	struct sigaction sa = { .sa_handler = sig_noop }, old_sa;
	bool interrupted;
	int i;

	if (!ASSERT_OK(sigaction(SIGUSR2, &sa, &old_sa), "sigaction"))
		return;
	if (!ASSERT_OK(pthread_create(&w.thread, NULL, waiter_fn, &w), "pthread_create"))
		goto out;
	/* A signal handled before the thread enters its syscall ends nothing: resend. */
	for (i = 0; i < 1000 && !waiter_done(&w); i++) {
		pthread_kill(w.thread, SIGUSR2);
		usleep(1000);
	}
	interrupted = waiter_done(&w);
	if (!interrupted)
		wake_waiter(skel, &w);
	pthread_join(w.thread, NULL);
	ASSERT_TRUE(interrupted, "interrupted");
	ASSERT_OK(w.err, "wait_forever");
	ASSERT_EQ((__s32)w.retval, -EINTR, "signal_wait_ret");
out:
	sigaction(SIGUSR2, &old_sa, NULL);
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

	err = run_syscall_prog(skel->progs.init_waitq, &retval);
	if (!ASSERT_OK(err, "init_waitq") || !ASSERT_EQ(retval, 0, "init_ret"))
		goto out;

	if (test__start_subtest("wait"))
		test_wait(skel);
	if (test__start_subtest("wake"))
		test_wake(skel);
	if (test__start_subtest("wait_event"))
		test_wait_event(skel);
	if (test__start_subtest("signal"))
		test_signal(skel);
out:
	bpf_waitq_success__destroy(skel);
}
