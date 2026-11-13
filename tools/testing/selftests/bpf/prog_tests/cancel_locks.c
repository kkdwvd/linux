// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <linux/pkt_cls.h>

/* The skeleton names the type of found[] and leaves it to us, see progs/cancel_locks.c */
struct at_entry {
	int preempt;
	int rcu;
	int irq;
};

#include "cancel_locks.skel.h"

/*
 * A prog that is cancelled runs nothing behind the point, so what its pads released shows in
 * the run that follows. Every prog is run twice. The second run takes the locks of the first:
 * a bpf_res_spin_lock that was left locked is not to be had, and a prog stays away from a
 * bpf_spin_lock that it finds locked, which would hang it. Both runs note what they were
 * entered in, see enter() in progs/cancel_locks.c: the second one has to find what the first
 * one found.
 *
 * The two runs of a tc prog are one BPF_PROG_TEST_RUN, with nothing but the loop of
 * bpf_test_run() between them, so the second run begins in what the pads of the first left
 * behind: interrupts that are off, a preempt count or an RCU nesting that is one too high.
 * With lockdep the kernel warns of interrupts that are off as soon as the first run returns,
 * in local_bh_enable(), and turns them on there. That warning is all that tells then.
 *
 * A syscall prog is not repeated, so its second run is entered from user space again. The RCU
 * nesting of the task is still what the first run left, where the kernel counts it. The preempt
 * count is until the task is scheduled, which is when the kernel complains and puts it right.
 */

struct test {
	const char *prog;
	/* the point is a loop that is out of time, and not a recursion that is out of stack */
	bool loop;
	/* the prog has two ways to the point, which take different things: take the other one too */
	bool two_ways;
};

static const struct test tests[] = {
	{ "spin_lock_global_at_call" },
	{ "spin_lock_in_map_at_call" },
	{ "spin_lock_spilled_at_call" },
	{ "res_lock_global_at_call" },
	{ "res_lock_in_map_at_call" },
	{ "res_lock_one_of_two_at_call", .two_ways = true },
	{ "res_lock_irqsave_at_call" },
	{ "irq_save_at_call" },
	{ "irq_save_twice_at_call" },
	{ "irq_save_twice_slots_swapped" },
	{ "irq_save_in_two_frames" },
	{ "spin_lock_in_irq_save_at_call" },
	{ "res_lock_irqsave_in_spin_lock_at_call" },
	{ "res_locks_irqsave_ab_at_call" },
	{ "res_locks_irqsave_ba_at_call" },
	{ "res_locks_in_irq_save_at_call" },
	{ "irq_save_orders_differ", .two_ways = true },
	{ "spin_lock_in_one_visit", .two_ways = true },
	{ "res_lock_in_one_visit", .two_ways = true },
	{ "rcu_at_call" },
	{ "preempt_at_call" },
	{ "sections_max_at_call" },
	{ "sections_of_callee_at_call" },
	{ "sections_in_two_frames" },
	{ "sleepable_rcu_at_call" },
	{ "sleepable_preempt_at_call" },
	{ "spin_lock_in_irq_save_in_rcu_at_call" },
	{ "spin_lock_in_irq_save_in_rcu_two_frames" },
};

/* Returns what the second run returned, below 0 if the runs failed */
static int run_twice(struct bpf_program *prog)
{
	char data[64] = {};
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	int i;

	if (bpf_program__type(prog) != BPF_PROG_TYPE_SYSCALL) {
		opts.data_in = data;
		opts.data_size_in = sizeof(data);
		opts.repeat = 2;
		if (!ASSERT_OK(bpf_prog_test_run_opts(bpf_program__fd(prog), &opts), "test_run"))
			return -1;
		return opts.retval;
	}
	for (i = 0; i < 2; i++)
		if (!ASSERT_OK(bpf_prog_test_run_opts(bpf_program__fd(prog), &opts), "test_run"))
			return -1;
	return opts.retval;
}

/*
 * The prog gets an object of its own, like in the test loader: one that does not load, or that
 * leaves a lock locked, is not in the way of the others. @zero: what the variable of that name
 * is to have, which the verifier knows nothing of.
 */
static void run_test(const struct test *t, unsigned long zero)
{
	struct bpf_program *prog, *other;
	int ret, cancelled;
	struct cancel_locks *skel;

	skel = cancel_locks__open();
	if (!ASSERT_OK_PTR(skel, "cancel_locks__open"))
		return;
	prog = bpf_object__find_program_by_name(skel->obj, t->prog);
	if (!ASSERT_OK_PTR(prog, t->prog))
		goto out;
	bpf_object__for_each_program(other, skel->obj)
		bpf_program__set_autoload(other, other == prog);
	if (!ASSERT_OK(cancel_locks__load(skel), "cancel_locks__load"))
		goto out;
	skel->bss->zero = zero;

	/* the cancel value of the type, which no prog returns at its end */
	cancelled = bpf_program__type(prog) == BPF_PROG_TYPE_SYSCALL ? 0 : TC_ACT_SHOT;

	ret = run_twice(prog);
	if (ret < 0)
		goto out;
	ASSERT_EQ(ret, cancelled, "retval");
	ASSERT_EQ(skel->bss->runs, 2, "runs");

	/* both runs got to the point, */
	ASSERT_GT(skel->bss->frames, 8, "frames");
	/* and neither went on from there */
	ASSERT_EQ(skel->bss->behind, 0, "behind");

	/* the second run found the locks free */
	ASSERT_EQ(skel->bss->stuck, 0, "stuck");
	ASSERT_EQ(skel->bss->lock_err, 0, "lock_err");
	/* and was entered in what the first one was entered in */
	ASSERT_EQ(skel->bss->found[1].irq, skel->bss->found[0].irq, "interrupts");
	ASSERT_EQ(skel->bss->found[1].preempt, skel->bss->found[0].preempt, "preempt count");
	ASSERT_EQ(skel->bss->found[1].rcu, skel->bss->found[0].rcu, "RCU nesting");
out:
	cancel_locks__destroy(skel);
}

void serial_test_cancel_locks(void)
{
	int i;

	/* The interpreter runs no pads. */
	if (!is_jit_enabled()) {
		test__skip();
		return;
	}

	RUN_TESTS(cancel_locks);

#if !defined(__x86_64__) && !defined(__aarch64__)
	return;
#endif
	for (i = 0; i < ARRAY_SIZE(tests); i++) {
		if (!test__start_subtest(tests[i].prog))
			continue;
		run_test(&tests[i], 0);
		if (tests[i].two_ways)
			run_test(&tests[i], 1);
	}
}
