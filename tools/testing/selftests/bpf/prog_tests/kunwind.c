// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <pthread.h>
#include "kunwind.skel.h"
#include "kunwind_load.skel.h"

/* The progs are there where the JIT unwinds and an arena faults into a landing pad */
#if defined(__x86_64__) || defined(__aarch64__)

static int run(struct bpf_program *prog)
{
	char data[64] = {};
	LIBBPF_OPTS(bpf_test_run_opts, opts,
		.data_in = data,
		.data_size_in = sizeof(data),
		.repeat = 1,
	);

	if (!ASSERT_OK(bpf_prog_test_run_opts(bpf_program__fd(prog), &opts), "test_run"))
		return -1;
	return opts.retval;
}

static int usage(struct kunwind *skel)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);

	if (!ASSERT_OK(bpf_prog_test_run_opts(bpf_program__fd(skel->progs.task_usage), &opts),
		       "usage"))
		return -1;
	return opts.retval;
}

static struct user_ring_buffer *rb;

static void submit(void)
{
	void *sample = user_ring_buffer__reserve(rb, 8);

	if (ASSERT_OK_PTR(sample, "reserve"))
		user_ring_buffer__submit(rb, sample);
}

#define TC_ACT_SHOT 2

/*
 * @kernel: what the prog returns when the kernel unwinds it: TC_ACT_SHOT, or what bpf_throw() was
 * passed, or what the exception callback made of that.
 * @returned: what the call returns when nothing unwinds.
 */
/*
 * @caught: what the pad of the prog finds in r0 when the program unwinds: what unwind_exit left, or
 * the value of the kernel if a global subprog is on the way.
 * @mid_pad: the frame in between has a landing pad of its own, which only cleans up and resumes:
 * it runs for unwind_exit, and when the kernel unwinds too. It does not catch.
 */
static void check_mid(struct kunwind *skel, const char *name, struct bpf_program *prog, int kernel,
		      int returned, bool sample, int caught, bool mid_pad)
{
	int before, after, ret;

	if (!test__start_subtest(name))
		return;
	skel->bss->mid_caught = 0;

	/* what is called returns: the prog goes on behind the call */
	skel->bss->mode = 0;
	skel->bss->caught = skel->bss->went_on = 0;
	if (sample)
		submit();
	before = usage(skel);
	ret = run(prog);
	after = usage(skel);
	ASSERT_EQ(ret, 1, "returns: retval");
	ASSERT_EQ(skel->bss->went_on, 100 + returned, "returns: went on");
	ASSERT_EQ(skel->bss->caught, 0, "returns: caught");
	ASSERT_EQ(after, before, "returns: references of the task");

	/*
	 * The kernel unwinds it: the landing pad of the prog, which catches, does not run, the
	 * prog does not go on, and it ends with the value of the kernel. Each frame has released
	 * its task.
	 */
	skel->bss->mode = 1;
	skel->bss->caught = skel->bss->went_on = 0;
	if (sample)
		submit();
	before = usage(skel);
	ret = run(prog);
	after = usage(skel);
	ASSERT_EQ(ret, kernel, "kernel unwinds: retval");
	ASSERT_EQ(skel->bss->went_on, 0, "kernel unwinds: went on");
	ASSERT_EQ(skel->bss->caught, 0, "kernel unwinds: caught");
	ASSERT_EQ(skel->bss->mid_caught, mid_pad, "kernel unwinds: the pad in between");
	ASSERT_EQ(after, before, "kernel unwinds: references of the task");

	/* unwind_exit of the program: its landing pad gets it, with what unwind_exit left */
	skel->bss->mode = 2;
	skel->bss->caught = skel->bss->went_on = 0;
	if (sample)
		submit();
	before = usage(skel);
	ret = run(prog);
	after = usage(skel);
	ASSERT_EQ(ret, 42, "program unwinds: retval");
	ASSERT_EQ(skel->bss->went_on, 0, "program unwinds: went on");
	ASSERT_EQ(skel->bss->caught, caught, "program unwinds: caught");
	ASSERT_EQ(skel->bss->mid_caught, mid_pad, "program unwinds: the pad in between");
	ASSERT_EQ(after, before, "program unwinds: references of the task");
}

static void check(struct kunwind *skel, const char *name, struct bpf_program *prog, int kernel,
		  int returned, bool sample)
{
	check_mid(skel, name, prog, kernel, returned, sample, 5, false);
}

/*
 * The callee of a tail call returns, is unwound by the kernel, or leaves with unwind_exit that
 * nothing in it catches. The caller sees its subprog return each time: 7, and twice the value of
 * the kernel.
 */
static void tail_call(struct kunwind *skel)
{
	static const int went_on[] = { 107, 100 + TC_ACT_SHOT, 100 + TC_ACT_SHOT };
	int i, before, after;

	if (!test__start_subtest("tail_call"))
		return;
	for (i = 0; i < 3; i++) {
		skel->bss->mode = i;
		skel->bss->caught = skel->bss->went_on = 0;
		before = usage(skel);
		ASSERT_EQ(run(skel->progs.above_tail_call), 1, "retval");
		after = usage(skel);
		ASSERT_EQ(skel->bss->went_on, went_on[i], "went on");
		ASSERT_EQ(skel->bss->caught, 0, "caught");
		ASSERT_EQ(after, before, "references of the task");
	}
}

/*
 * The exception callback of a main prog with a private stack returns, is unwound by the kernel, or
 * leaves with unwind_exit. The prog that got there by a tail call finds its r6-r9 as it left them.
 */
static void exception_cb_private_stack(struct kunwind *skel)
{
	static const struct {
		const char *how;
		int retval;
	} modes[] = {
		{ "returns", 109 },
		{ "kernel unwinds", 0 },
		{ "program unwinds", 5 },
	};
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	int i, j;

	if (!test__start_subtest("exception_cb_private_stack"))
		return;
	for (i = 0; i < ARRAY_SIZE(modes); i++) {
		skel->bss->mode = i;
		for (j = 0; j < 4; j++) {
			skel->bss->regs_in[j] = 0x1111111111111111ULL * (j + 1 + 4 * i);
			skel->bss->regs_out[j] = 0;
		}
		if (!ASSERT_OK(bpf_prog_test_run_opts(
				bpf_program__fd(skel->progs.regs_around_priv_stack_throws), &opts),
			       modes[i].how))
			return;
		ASSERT_EQ(opts.retval, modes[i].retval, modes[i].how);
		for (j = 0; j < 4; j++)
			ASSERT_EQ(skel->bss->regs_out[j], skel->bss->regs_in[j], modes[i].how);
	}
}

/*
 * The prog throws, the landing pad of its main frame calls the exception callback, and the
 * callback is unwound in turn while it holds a task: by its own bpf_throw(), by a fault in arena,
 * by a loop that is out of time, by a recursion that is too deep. It ran once, the tasks of the
 * prog and of the callback are released, and the prog returns the value of the unwind of the
 * callback.
 */
static void exception_cb_unwound(struct kunwind *skel, const char *name, struct bpf_program *prog,
				 int retval)
{
	int before, after, ret;

	if (!test__start_subtest(name))
		return;
	/* the recursion of recurses() has no end in mode 1, and the prog throws */
	skel->bss->mode = 1;
	skel->bss->cb_runs = 0;
	before = usage(skel);
	ret = run(prog);
	after = usage(skel);
	ASSERT_EQ(ret, retval, "retval");
	ASSERT_EQ(skel->bss->cb_runs, 1, "runs of the exception callback");
	ASSERT_EQ(after, before, "references of the task");

	/* nothing throws: the callback does not run */
	skel->bss->mode = 0;
	skel->bss->cb_runs = 0;
	before = usage(skel);
	ret = run(prog);
	after = usage(skel);
	ASSERT_EQ(ret, 1, "returns: retval");
	ASSERT_EQ(skel->bss->cb_runs, 0, "returns: runs of the exception callback");
	ASSERT_EQ(after, before, "returns: references of the task");
}

static void *load_thread(void *skel)
{
	return (void *)(long)kunwind__load(skel);
}

/*
 * A prog can be taken by its id and run while bpf_prog_load() still works on it. kunwind_load.c
 * holds the load of below_throw, in a second instance of the progs, where it has its id. The
 * kernel unwinds the prog there as it does when the load is over.
 */
static void by_id(void)
{
	char data[64] = {};
	LIBBPF_OPTS(bpf_test_run_opts, opts,
		.data_in = data,
		.data_size_in = sizeof(data),
		.repeat = 1,
	);
	struct kunwind_load *hold;
	struct kunwind *skel;
	int i, fd = -1, err = -1;
	pthread_t thread;
	void *ret;

	if (!test__start_subtest("by_id"))
		return;
	hold = kunwind_load__open_and_load();
	skel = kunwind__open();
	if (!ASSERT_OK_PTR(hold, "kunwind_load") || !ASSERT_OK_PTR(skel, "open"))
		goto out;
	skel->bss->mode = 1;
	hold->bss->pid = getpid();
	if (!ASSERT_OK(kunwind_load__attach(hold), "attach") ||
	    !ASSERT_OK(pthread_create(&thread, NULL, load_thread, skel), "thread"))
		goto out;
	for (i = 0; i < 50000 && !hold->bss->id; i++)
		usleep(100);
	if (hold->bss->id)
		fd = bpf_prog_get_fd_by_id(hold->bss->id);
	if (fd >= 0)
		err = bpf_prog_test_run_opts(fd, &opts);
	hold->bss->done = true;
	pthread_join(thread, &ret);
	if (ASSERT_OK((long)ret, "load") && ASSERT_GE(fd, 0, "the prog by its id") &&
	    ASSERT_OK(err, "test_run")) {
		ASSERT_EQ(opts.retval, 9, "kernel unwinds: retval");
		ASSERT_EQ(skel->bss->went_on, 0, "kernel unwinds: went on");
	}
	if (fd >= 0)
		close(fd);
out:
	kunwind__destroy(skel);
	kunwind_load__destroy(hold);
}

static void kunwind(void)
{
	struct kunwind *skel;
	int err;

	if (!is_jit_enabled()) {
		printf("%s:SKIP:JIT is disabled\n", __func__);
		test__skip();
		return;
	}
	skel = kunwind__open_and_load();
	err = libbpf_get_error(skel);
	if (err == -ENOTSUPP) {
		printf("%s:SKIP:JIT does not support unwinding\n", __func__);
		test__skip();
		return;
	}
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;
	rb = user_ring_buffer__new(bpf_map__fd(skel->maps.user_ringbuf), NULL);
	if (!ASSERT_OK_PTR(rb, "user_ring_buffer__new"))
		goto out;

	/* each way in which the kernel starts to unwind, two frames below the prog */
	check(skel, "throw", skel->progs.below_throw, 9, 7, false);
	check(skel, "throw_exception_cb", skel->progs.below_throw_exception_cb, 109, 7, false);
	check(skel, "fault", skel->progs.below_fault, TC_ACT_SHOT, 7, false);
	check(skel, "guard", skel->progs.below_guard, TC_ACT_SHOT, 7, false);
	check(skel, "may_goto", skel->progs.below_may_goto, TC_ACT_SHOT, 7, false);
	check(skel, "recursion", skel->progs.below_recursion, TC_ACT_SHOT, 7, false);
	/* and in a callback, with a helper or a kfunc in between */
	check(skel, "loop_inlined", skel->progs.below_loop_inlined, 9, 1, false);
	check(skel, "loop", skel->progs.below_loop, 9, 1, false);
	check(skel, "loop_guard", skel->progs.below_loop_guard, TC_ACT_SHOT, 1, false);
	check(skel, "for_each", skel->progs.below_for_each, 9, 1, false);
	check(skel, "for_each_two_maps", skel->progs.below_for_each_two_maps, 9, 1, false);
	check(skel, "drain", skel->progs.below_drain, 9, 1, true);
	check(skel, "find_vma", skel->progs.below_find_vma, 9, 0, false);
	check(skel, "rbtree_add", skel->progs.below_rbtree_add, 9, 0, false);
	/* a landing pad of the prog in the frame in between, which cleans up and unwinds on */
	check_mid(skel, "mid_pad_throw", skel->progs.below_mid_pad_throw, 9, 7, false, 5, true);
	check_mid(skel, "mid_pad_guard", skel->progs.below_mid_pad_guard, TC_ACT_SHOT, 7, false, 5,
		  true);
	/* a global subprog in between, which the callers find out late, or expect to be unwound */
	check_mid(skel, "global_guard", skel->progs.below_global_guard, TC_ACT_SHOT, 7, false,
		  TC_ACT_SHOT, false);
	check_mid(skel, "global_may_goto", skel->progs.below_global_may_goto, TC_ACT_SHOT, 7, false,
		  TC_ACT_SHOT, false);
	/* a callback that holds a task where it is unwound */
	check(skel, "loop_inlined_holds_fault", skel->progs.below_loop_inlined_holds_fault,
	      TC_ACT_SHOT, 1, false);
	check(skel, "loop_holds_fault", skel->progs.below_loop_holds_fault, TC_ACT_SHOT, 1, false);
	check(skel, "loop_holds_may_goto", skel->progs.below_loop_holds_may_goto, TC_ACT_SHOT, 1,
	      false);
	/* a lock next to the pad of the prog: each run takes it again */
	check(skel, "guard_lock", skel->progs.below_guard_lock, TC_ACT_SHOT, 7, false);
	tail_call(skel);
	/* the exception callback is unwound in turn, and is not called again */
	exception_cb_unwound(skel, "exception_cb_throws", skel->progs.throws_and_cb_throws_21, 21);
	exception_cb_unwound(skel, "exception_cb_faults", skel->progs.throws_and_cb_faults_holding,
			     TC_ACT_SHOT);
	exception_cb_unwound(skel, "exception_cb_spins", skel->progs.throws_and_cb_spins_holding,
			     TC_ACT_SHOT);
	exception_cb_unwound(skel, "exception_cb_recurses",
			     skel->progs.throws_and_cb_recurses_holding, TC_ACT_SHOT);
	exception_cb_private_stack(skel);
	by_id();
out:
	user_ring_buffer__free(rb);
	kunwind__destroy(skel);
}

#else

static void kunwind(void)
{
	test__skip();
}

#endif

void test_kunwind(void)
{
	kunwind();
}
