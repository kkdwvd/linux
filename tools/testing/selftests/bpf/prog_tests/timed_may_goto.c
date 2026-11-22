// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <sched.h>
#include <test_progs.h>
#include <network_helpers.h>
#include "timed_may_goto.skel.h"
#include "timed_may_goto_user.skel.h"
#include "timed_may_goto_ext.skel.h"

#define TRIES 4

static int run_tc(struct bpf_program *prog)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts,
		.data_in = &pkt_v4,
		.data_size_in = sizeof(pkt_v4),
		.repeat = 1,
	);

	if (!ASSERT_OK(bpf_prog_test_run_opts(bpf_program__fd(prog), &opts), "test_run"))
		return -1;
	return opts.retval;
}

static int run_syscall(struct bpf_program *prog)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);

	if (!ASSERT_OK(bpf_prog_test_run_opts(bpf_program__fd(prog), &opts), "test_run"))
		return -1;
	return opts.retval;
}

static void wait_for(int *val, int expected, const char *name)
{
	int i;

	for (i = 0; i < 500 && *(volatile int *)val != expected; i++)
		usleep(10000);
	ASSERT_EQ(*val, expected, name);
}

static void test_async(struct timed_may_goto_user *skel)
{
	ASSERT_EQ(run_syscall(skel->progs.async_after_timeout), -ECANCELED, "async_after_timeout");
	wait_for(&skel->bss->timer_cnt, 1000, "timer_cnt");
	wait_for(&skel->bss->wq_cnt, 1000, "wq_cnt");
	wait_for(&skel->bss->tw_cnt, 1000, "tw_cnt");
	wait_for(&skel->bss->rcu_cnt, 1000, "rcu_cnt");
	wait_for(&skel->bss->rcu_trace_cnt, 1000, "rcu_trace_cnt");
}

static long now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void test_timer_on_top(struct timed_may_goto_user *skel)
{
	long ms = now_ms();
	int ticks;

	/* the prog is unwound */
	ASSERT_EQ(run_syscall(skel->progs.spin_under_timer), -ECANCELED, "spin_under_timer");
	ms = now_ms() - ms;
	ticks = skel->bss->ticks;

	/* stop the timer */
	skel->bss->ticks = 100;
	ASSERT_GE(ms, 200, "ms");
	ASSERT_LE(ms, 500, "ms");
	/* control: the callback interrupted the prog, and its loop went on to the end */
	ASSERT_GE(ticks, 5, "ticks");
	ASSERT_LT(ticks, 100, "ticks");
}

static void test_freplace(struct timed_may_goto_user *skel)
{
	struct timed_may_goto_ext *ext;

	/* replaced_global() is unwound, and the prog with it */
	ASSERT_EQ(run_tc(skel->progs.freplace_target), 2, "not replaced");

	/* so it cannot be replaced */
	ext = timed_may_goto_ext__open();
	if (!ASSERT_OK_PTR(ext, "ext_open"))
		return;
	bpf_program__set_attach_target(ext->progs.replacement,
				       bpf_program__fd(skel->progs.freplace_target),
				       "replaced_global");
	ASSERT_ERR(timed_may_goto_ext__load(ext), "ext_load of what can unwind");
	timed_may_goto_ext__destroy(ext);

	ASSERT_EQ(run_tc(skel->progs.freplace_plain_target), 10, "not replaced");
	ext = timed_may_goto_ext__open();
	if (!ASSERT_OK_PTR(ext, "ext_open"))
		return;
	bpf_program__set_attach_target(ext->progs.replacement,
				       bpf_program__fd(skel->progs.freplace_plain_target),
				       "plain_global");
	if (!ASSERT_OK(timed_may_goto_ext__load(ext), "ext_load") ||
	    !ASSERT_OK(timed_may_goto_ext__attach(ext), "ext_attach"))
		goto out;
	/* Each call of the extension spins, is unwound and returns 2 into the prog, which goes on */
	ASSERT_EQ(run_tc(skel->progs.freplace_plain_target), 10 + TRIES * 2, "replaced");
	/* and each call had its time: a short loop came to its end before the call used it up */
	ASSERT_EQ(ext->bss->calls, TRIES, "calls of the extension");
	ASSERT_EQ(ext->bss->counted_to_1000, TRIES, "a slice per call");
out:
	timed_may_goto_ext__destroy(ext);
	ASSERT_EQ(run_tc(skel->progs.freplace_plain_target), 10, "not replaced");
}

/* What a prog leaves behind when its time is up doesn't matter for the next one on the cpu. */
static void test_tail_call_and_throw(struct timed_may_goto_user *skel)
{
	int key = 0, fd = bpf_program__fd(skel->progs.tail_callee);
	int map_fd = bpf_map__fd(skel->maps.jmp_table);

	if (!ASSERT_OK(bpf_map_update_elem(map_fd, &key, &fd, 0), "update"))
		return;

	/*
	 * Each run has its time: the loop counts to 1000, then the prog is unwound. With the count
	 * that the run before left behind the prog would be unwound in the short loop, which 2
	 * does not tell: the prog stores what it counted.
	 */
	skel->bss->normal_cnt = -1;
	ASSERT_EQ(run_tc(skel->progs.normal_prog), 2, "normal_prog");
	ASSERT_EQ(skel->bss->normal_cnt, 1000, "normal_cnt");
	skel->bss->normal_cnt = -1;
	ASSERT_EQ(run_tc(skel->progs.normal_prog), 2, "normal_prog");
	ASSERT_EQ(skel->bss->normal_cnt, 1000, "normal_cnt, second run");

	/* the callee is unwound and returns 2 into the subprog of its caller, which goes on */
	skel->bss->tail_callee_cnt = -1;
	ASSERT_EQ(run_tc(skel->progs.tail_call_in_subprog), 12, "tail_call_in_subprog");
	ASSERT_EQ(skel->bss->tail_callee_runs, 1, "tail_callee_runs");
	ASSERT_EQ(skel->bss->tail_callee_cnt, 1000, "tail_callee_cnt");

	/* the callee has its time when its caller has none left: it counts, then it is unwound */
	skel->bss->tail_callee_cnt = -1;
	ASSERT_EQ(run_tc(skel->progs.tail_call_after_timeout), 2, "tail_call_after_timeout");
	ASSERT_EQ(skel->bss->tail_callee_runs, 2, "tail_callee_runs");
	ASSERT_EQ(skel->bss->tail_callee_cnt, 1000, "tail_callee_cnt, caller out of time");

	ASSERT_EQ(run_tc(skel->progs.throw_after_timeout), 7, "throw_after_timeout");
	ASSERT_EQ(run_tc(skel->progs.throw_after_timeout), 7, "throw_after_timeout");
}

static void test_user_ringbuf(struct timed_may_goto_user *skel)
{
	struct user_ring_buffer *rb;
	void *sample;
	int i;

	rb = user_ring_buffer__new(bpf_map__fd(skel->maps.user_ringbuf), NULL);
	if (!ASSERT_OK_PTR(rb, "user_ring_buffer__new"))
		return;
	for (i = 0; i < TRIES; i++) {
		sample = user_ring_buffer__reserve(rb, 8);
		if (!ASSERT_OK_PTR(sample, "reserve"))
			goto out;
		user_ring_buffer__submit(rb, sample);
	}
	/*
	 * The helper takes a sample out of the buffer for each call. The callback is unwound in
	 * each run, and its sample is gone like one of a callback that returns.
	 */
	for (i = 0; i < TRIES; i++)
		ASSERT_EQ(run_syscall(skel->progs.drain), -ECANCELED, "drain");
	ASSERT_EQ(run_syscall(skel->progs.drain), 100, "drain of no samples");
out:
	user_ring_buffer__free(rb);
}

static void test_priv_stack(struct timed_may_goto_user *skel)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	int fd = bpf_program__fd(skel->progs.priv_stack);
	struct bpf_link *link;

	link = bpf_program__attach(skel->progs.priv_stack);
	if (!ASSERT_OK_PTR(link, "attach"))
		return;
	skel->bss->priv_stack_spun = skel->bss->priv_stack_cb_spun = -1;
	/* unwound in the first call: the prog does not get to what follows its loop */
	ASSERT_OK(bpf_prog_test_run_opts(fd, &opts), "test_run");
	ASSERT_OK(bpf_prog_test_run_opts(fd, &opts), "test_run");
	ASSERT_EQ(skel->bss->priv_stack_runs, 2, "priv_stack_runs");
	ASSERT_EQ(skel->bss->priv_stack_spun, -1, "priv_stack_spun");
	ASSERT_EQ(skel->bss->priv_stack_cb_spun, -1, "priv_stack_cb_spun");
	bpf_link__destroy(link);
}

/*
 * Serial: most progs spin for 250 ms in an RCU read-side critical section, one after the other.
 * That delays what other tests wait for. In parallel mode "mmap" gives up its wait for the end of
 * a map.
 */
void serial_test_timed_may_goto(void)
{
	struct timed_may_goto_user *skel;
	cpu_set_t old, new;

	/* The interpreter counts in each frame. */
	if (!is_jit_enabled()) {
		test__skip();
		return;
	}

	RUN_TESTS(timed_may_goto);

#if !defined(__x86_64__) && !defined(__aarch64__)
	return;
#endif
	skel = timed_may_goto_user__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;

	/* Count and timestamp are per-cpu: all progs of a subtest run on one cpu. */
	if (!ASSERT_OK(sched_getaffinity(0, sizeof(old), &old), "getaffinity"))
		goto out;
	CPU_ZERO(&new);
	CPU_SET(sched_getcpu(), &new);
	if (!ASSERT_OK(sched_setaffinity(0, sizeof(new), &new), "setaffinity"))
		goto out;

	if (test__start_subtest("async"))
		test_async(skel);
	if (test__start_subtest("timer_on_top"))
		test_timer_on_top(skel);
	if (test__start_subtest("freplace"))
		test_freplace(skel);
	if (test__start_subtest("tail_call_and_throw"))
		test_tail_call_and_throw(skel);
	if (test__start_subtest("user_ringbuf"))
		test_user_ringbuf(skel);
	if (test__start_subtest("priv_stack"))
		test_priv_stack(skel);

	sched_setaffinity(0, sizeof(old), &old);
out:
	timed_may_goto_user__destroy(skel);
}
