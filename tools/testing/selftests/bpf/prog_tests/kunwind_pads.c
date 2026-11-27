// SPDX-License-Identifier: GPL-2.0
#include <sched.h>
#include <test_progs.h>
#include <linux/capability.h>
#include "cap_helpers.h"
#include "kunwind_pads.skel.h"
#include "kunwind_pads_unpriv.skel.h"

/* The progs are there where the JIT unwinds and an arena faults into a landing pad */
#if defined(__x86_64__) || defined(__aarch64__)

#define TC_ACT_SHOT 2

/* What a run leaves behind */
struct result {
	int retval;
	__u64 went_on, caught, dtor_ran, handler_ran, personality_ran, terminated;
};

static int usage(struct kunwind_pads *skel)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);

	if (!ASSERT_OK(bpf_prog_test_run_opts(bpf_program__fd(skel->progs.task_usage), &opts),
		       "usage"))
		return -1;
	return opts.retval;
}

static int rcu_nesting(struct kunwind_pads *skel)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);

	if (!ASSERT_OK(bpf_prog_test_run_opts(bpf_program__fd(skel->progs.rcu_nesting), &opts),
		       "RCU nesting"))
		return -1;
	return opts.retval;
}

static int init_usage(struct kunwind_pads *skel)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);

	if (!ASSERT_OK(bpf_prog_test_run_opts(bpf_program__fd(skel->progs.init_usage), &opts),
		       "usage of pid 1"))
		return -1;
	return opts.retval;
}

/* Run @prog in @mode, 'mode_b' is @mode_b, and compare what it leaves with @want */
static void run_modes(struct kunwind_pads *skel, struct bpf_program *prog, int mode, int mode_b,
		      const struct result *want, const char *how)
{
	char data[64] = {};
	LIBBPF_OPTS(bpf_test_run_opts, opts,
		.data_in = data,
		.data_size_in = sizeof(data),
		.repeat = 1,
	);
	struct kunwind_pads__bss *bss = skel->bss;
	int before, after, init_before, init_after, rcu_before, rcu_after;

	bss->mode = mode;
	bss->mode_b = mode_b;
	bss->went_on = bss->caught = bss->dtor_ran = 0;
	bss->handler_ran = bss->personality_ran = bss->terminated = 0;
	before = usage(skel);
	init_before = init_usage(skel);
	rcu_before = rcu_nesting(skel);
	if (!ASSERT_OK(bpf_prog_test_run_opts(bpf_program__fd(prog), &opts), how))
		return;
	after = usage(skel);
	init_after = init_usage(skel);
	rcu_after = rcu_nesting(skel);
	ASSERT_EQ(opts.retval, want->retval, how);
	ASSERT_EQ(bss->went_on, want->went_on, "went on");
	ASSERT_EQ(bss->caught, want->caught, "caught");
	ASSERT_EQ(bss->dtor_ran, want->dtor_ran, "the destructor ran");
	ASSERT_EQ(bss->handler_ran, want->handler_ran, "the handler ran");
	ASSERT_EQ(bss->personality_ran, want->personality_ran, "the personality routine ran");
	ASSERT_EQ(bss->terminated, want->terminated, "terminated");
	ASSERT_EQ(after, before, "references of the task");
	ASSERT_EQ(init_after, init_before, "references of the task with pid 1");
	ASSERT_EQ(rcu_after, rcu_before, "RCU sections of the task");
}

static void run_mode(struct kunwind_pads *skel, struct bpf_program *prog, int mode,
		     const struct result *want, const char *how)
{
	run_modes(skel, prog, mode, 0, want, how);
}

#define R(args...) (&(struct result){ args })

/*
 * A function with a destructor between the prog and what the kernel unwinds. The landing pad of
 * the destructor runs, once. The prog does not go on, its catch does not run, and it ends with
 * @kernel: the value of the kernel, or what bpf_throw() was passed, or what the exception callback
 * makes of that. Each frame has released its task, and the function in between has left its RCU
 * section: the kernel would say so if it had not.
 * When the prog unwinds by itself all is as it was: the destructor runs, and the catch above.
 * @returned: what the call returns when nothing unwinds.
 */
static void dtor(struct kunwind_pads *skel, const char *name, struct bpf_program *prog, int kernel,
		 int returned)
{
	if (!test__start_subtest(name))
		return;
	run_mode(skel, prog, 0, R(.retval = 1, .went_on = 100 + returned), "returns");
	run_mode(skel, prog, 1, R(.retval = kernel, .dtor_ran = 1), "kernel unwinds");
	run_mode(skel, prog, 2, R(.retval = 42, .caught = 5, .dtor_ran = 1), "program unwinds");
}

/* Run the tracing prog @prog in @mode, on the cpu that the caller is on */
static void run_raw_tp(struct kunwind_pads *skel, struct bpf_program *prog, int mode,
		       const struct result *want, const char *how)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	struct kunwind_pads__bss *bss = skel->bss;

	bss->mode = mode;
	bss->went_on = bss->caught = bss->dtor_ran = bss->seen_in_frame = 0;
	if (!ASSERT_OK(bpf_prog_test_run_opts(bpf_program__fd(prog), &opts), how))
		return;
	ASSERT_EQ(opts.retval, want->retval, how);
	ASSERT_EQ(bss->went_on, want->went_on, "went on");
	ASSERT_EQ(bss->caught, want->caught, "caught");
	ASSERT_EQ(bss->dtor_ran, want->dtor_ran, "the destructor ran");
	/* the pad reads its frame through the register that the callee, and a landing, changed */
	ASSERT_EQ(bss->seen_in_frame, want->dtor_ran ? 0x77 : 0, "what the pad read in its frame");
}

/*
 * The hidden word of a frame in a private stack is the same word in every run on a cpu. The kernel
 * unwinds in one run, which sets it, and the prog unwinds in the next one: nothing of the first
 * run is left in the word when the landing pad resumes, and the prog catches.
 */
static void stale_private_stack(struct kunwind_pads *skel)
{
	struct bpf_program *prog = skel->progs.stale_in_private_stack;
	cpu_set_t old, one;

	if (!test__start_subtest("stale_private_stack"))
		return;
	if (!ASSERT_OK(sched_getaffinity(0, sizeof(old), &old), "sched_getaffinity"))
		return;
	CPU_ZERO(&one);
	CPU_SET(sched_getcpu(), &one);
	if (!ASSERT_OK(sched_setaffinity(0, sizeof(one), &one), "bind to one cpu"))
		return;
	run_raw_tp(skel, prog, 0, R(.retval = 1, .went_on = 107), "returns");
	run_raw_tp(skel, prog, 1, R(.retval = 0, .dtor_ran = 1), "kernel unwinds");
	run_raw_tp(skel, prog, 2, R(.retval = 42, .caught = 5, .dtor_ran = 1), "program unwinds");
	run_raw_tp(skel, prog, 1, R(.retval = 0, .dtor_ran = 1), "kernel unwinds again");
	run_raw_tp(skel, prog, 0, R(.retval = 1, .went_on = 107), "returns again");
	run_raw_tp(skel, prog, 2, R(.retval = 42, .caught = 5, .dtor_ran = 1),
		   "program unwinds again");
	ASSERT_OK(sched_setaffinity(0, sizeof(old), &old), "restore the cpus");
}

/*
 * A prog that unwinds is loaded without CAP_PERFMON: the verifier refuses it, on a kernel without
 * the mitigations too.
 */
static void no_perfmon(void)
{
	__u64 caps = 1ULL << CAP_PERFMON | 1ULL << CAP_SYS_ADMIN, old_caps;
	struct kunwind_pads_unpriv *skel;
	static char log[4096];
	int err;

	if (!test__start_subtest("no_perfmon"))
		return;
	skel = kunwind_pads_unpriv__open();
	if (!ASSERT_OK_PTR(skel, "open"))
		return;
	bpf_program__set_log_buf(skel->progs.catches, log, sizeof(log));
	if (!ASSERT_OK(cap_disable_effective(caps, &old_caps), "drop CAP_PERFMON"))
		goto out;
	err = kunwind_pads_unpriv__load(skel);
	ASSERT_OK(cap_enable_effective(old_caps, NULL), "restore the capabilities");
	ASSERT_EQ(err, -EPERM, "load");
	ASSERT_HAS_SUBSTR(log, "CAP_PERFMON is required to unwind", "log");
out:
	kunwind_pads_unpriv__destroy(skel);
}

static void kunwind_pads(void)
{
	struct kunwind_pads *skel;
	struct bpf_program *prog;
	int err;

	if (!is_jit_enabled()) {
		printf("%s:SKIP:JIT is disabled\n", __func__);
		test__skip();
		return;
	}
	skel = kunwind_pads__open_and_load();
	err = libbpf_get_error(skel);
	if (err == -ENOTSUPP) {
		printf("%s:SKIP:JIT does not support unwinding\n", __func__);
		test__skip();
		return;
	}
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;

	/* each way in which the kernel starts to unwind, below a function with a destructor */
	dtor(skel, "dtor_throw", skel->progs.dtor_below_throw, 9, 7);
	dtor(skel, "dtor_throw_exception_cb", skel->progs.dtor_below_throw_exception_cb, 109, 7);
	dtor(skel, "dtor_fault", skel->progs.dtor_below_fault, TC_ACT_SHOT, 7);
	dtor(skel, "dtor_guard", skel->progs.dtor_below_guard, TC_ACT_SHOT, 7);
	dtor(skel, "dtor_may_goto", skel->progs.dtor_below_may_goto, TC_ACT_SHOT, 7);
	dtor(skel, "dtor_recursion", skel->progs.dtor_below_recursion, TC_ACT_SHOT, 7);
	/* and in a callback of bpf_loop(), which returns 1 when its callback does */
	dtor(skel, "dtor_loop_throw", skel->progs.dtor_below_loop_throw, 9, 1);
	dtor(skel, "dtor_loop_fault", skel->progs.dtor_below_loop_fault, TC_ACT_SHOT, 1);
	dtor(skel, "dtor_loop_guard", skel->progs.dtor_below_loop_guard, TC_ACT_SHOT, 1);
	dtor(skel, "dtor_loop_may_goto", skel->progs.dtor_below_loop_may_goto, TC_ACT_SHOT, 1);
	dtor(skel, "dtor_loop_recursion", skel->progs.dtor_below_loop_recursion, TC_ACT_SHOT, 1);
	dtor(skel, "dtor_loop_inlined_throw", skel->progs.dtor_below_loop_inlined_throw, 9, 1);
	dtor(skel, "dtor_loop_inlined_guard", skel->progs.dtor_below_loop_inlined_guard,
	     TC_ACT_SHOT, 1);
	/* the call under the guard is callx */
	dtor(skel, "dtor_callx", skel->progs.dtor_callx_below_guard, TC_ACT_SHOT, 7);
	/* the function with the destructor is a global one */
	dtor(skel, "dtor_global", skel->progs.dtor_global_below_guard, TC_ACT_SHOT, 7);

	/*
	 * A pad that can return is not entered. The pad of the verifier releases the task, and
	 * the personality routine is not asked what a clause would make of the value of the kernel.
	 */
	if (test__start_subtest("typed_catch")) {
		prog = skel->progs.typed_catch_below_guard;
		skel->bss->selector = 1;
		run_mode(skel, prog, 0, R(.retval = 1, .went_on = 107), "returns");
		run_mode(skel, prog, 1, R(.retval = TC_ACT_SHOT), "kernel unwinds");
		run_mode(skel, prog, 2, R(.retval = 1, .went_on = 177, .handler_ran = 1,
					  .personality_ran = 1), "program unwinds, caught");
		skel->bss->selector = 0;
		run_mode(skel, prog, 1, R(.retval = TC_ACT_SHOT), "kernel unwinds, no clause");
		run_mode(skel, prog, 2, R(.retval = 42, .caught = 5, .personality_ran = 1),
			 "program unwinds, no clause");
	}
	if (test__start_subtest("catch_all")) {
		prog = skel->progs.catch_all_below_guard;
		run_mode(skel, prog, 0, R(.retval = 1, .went_on = 107), "returns");
		run_mode(skel, prog, 1, R(.retval = TC_ACT_SHOT), "kernel unwinds");
		run_mode(skel, prog, 2, R(.retval = 1, .went_on = 177, .handler_ran = 1),
			 "program unwinds");
	}
	/* nor is a pad that never resumes. When the prog unwinds, it throws 0. */
	if (test__start_subtest("terminate")) {
		prog = skel->progs.terminate_below_guard;
		run_mode(skel, prog, 0, R(.retval = 1, .went_on = 107), "returns");
		run_mode(skel, prog, 1, R(.retval = TC_ACT_SHOT), "kernel unwinds");
		run_mode(skel, prog, 2, R(.retval = 0, .terminated = 1), "program unwinds");
	}
	/*
	 * A handler that throws again cannot return: the pad is entered, the handler runs, and
	 * what it throws does not get to the catch of the prog above.
	 */
	if (test__start_subtest("catch_rethrow")) {
		prog = skel->progs.catch_rethrow_below_guard;
		skel->bss->selector = 1;
		run_mode(skel, prog, 0, R(.retval = 1, .went_on = 107), "returns");
		run_mode(skel, prog, 1, R(.retval = TC_ACT_SHOT, .handler_ran = 1,
					  .personality_ran = 1), "kernel unwinds");
		run_mode(skel, prog, 2, R(.retval = 42, .caught = 5, .handler_ran = 1,
					  .personality_ran = 1), "program unwinds");
		skel->bss->selector = 0;
	}
	/*
	 * Two pads and one resume block. The kernel unwinds the first callee and its pad runs, the
	 * kernel unwinds the second callee and its pad does not. Then the second callee throws:
	 * the word that the first run set is no longer set, and the prog above catches.
	 */
	if (test__start_subtest("shared_resume")) {
		prog = skel->progs.shared_resume_below_guard;
		run_modes(skel, prog, 0, 0, R(.retval = 1, .went_on = 107), "both return");
		run_modes(skel, prog, 1, 0, R(.retval = TC_ACT_SHOT, .dtor_ran = 1),
			  "kernel unwinds the first");
		run_modes(skel, prog, 0, 2, R(.retval = 42, .caught = 5, .personality_ran = 1),
			  "the second throws");
		run_modes(skel, prog, 0, 1, R(.retval = TC_ACT_SHOT), "kernel unwinds the second");
		run_modes(skel, prog, 2, 0, R(.retval = 42, .caught = 5, .dtor_ran = 1),
			  "the first throws");
		run_modes(skel, prog, 1, 0, R(.retval = TC_ACT_SHOT, .dtor_ran = 1),
			  "kernel unwinds the first again");
		skel->bss->selector = 1;
		run_modes(skel, prog, 0, 2, R(.retval = 1, .went_on = 177, .handler_ran = 1,
					      .personality_ran = 1), "the second throws, caught");
		skel->bss->selector = 0;
	}
	/* a throw that is a jump into the pad: the prog unwinds. At the call the kernel does. */
	if (test__start_subtest("raise_inlined")) {
		prog = skel->progs.raise_inlined_below_guard;
		run_mode(skel, prog, 0, R(.retval = 1, .went_on = 107), "returns");
		run_mode(skel, prog, 1, R(.retval = TC_ACT_SHOT, .dtor_ran = 1), "kernel unwinds");
		run_mode(skel, prog, 3, R(.retval = 42, .caught = 6, .dtor_ran = 1), "raises");
		run_mode(skel, prog, 1, R(.retval = TC_ACT_SHOT, .dtor_ran = 1),
			 "kernel unwinds again");
		run_mode(skel, prog, 2, R(.retval = 42, .caught = 5, .dtor_ran = 1),
			 "program unwinds");
	}
	/* unwind_exit of the prog in a pad that the kernel entered is not caught either */
	if (test__start_subtest("dtor_raises")) {
		prog = skel->progs.dtor_raises_below_guard;
		run_mode(skel, prog, 0, R(.retval = 1, .went_on = 107), "returns");
		run_mode(skel, prog, 1, R(.retval = TC_ACT_SHOT, .dtor_ran = 1), "kernel unwinds");
		run_mode(skel, prog, 2, R(.retval = 42, .caught = 1, .dtor_ran = 1),
			 "program unwinds");
	}
	/*
	 * The kernel starts a second time in the pad: the value stays the one of the first start,
	 * the cookie of bpf_throw(), which the exception callback gets. When the prog unwinds into
	 * the pad, the start in there is the first one.
	 */
	if (test__start_subtest("dtor_faults")) {
		prog = skel->progs.dtor_faults_below_throw;
		run_mode(skel, prog, 0, R(.retval = 1, .went_on = 107), "returns");
		run_mode(skel, prog, 1, R(.retval = 109, .dtor_ran = 1), "kernel unwinds");
		run_mode(skel, prog, 2, R(.retval = 100 + TC_ACT_SHOT, .dtor_ran = 1),
			 "program unwinds");
	}
	if (test__start_subtest("dtor_spins")) {
		prog = skel->progs.dtor_spins_below_throw;
		run_mode(skel, prog, 0, R(.retval = 1, .went_on = 107), "returns");
		run_mode(skel, prog, 1, R(.retval = 109, .dtor_ran = 1), "kernel unwinds");
		run_mode(skel, prog, 2, R(.retval = 100 + TC_ACT_SHOT, .dtor_ran = 1),
			 "program unwinds");
	}
	if (test__start_subtest("dtor_throws")) {
		prog = skel->progs.dtor_throws_below_throw;
		run_mode(skel, prog, 0, R(.retval = 1, .went_on = 107), "returns");
		run_mode(skel, prog, 1, R(.retval = 109, .dtor_ran = 1), "kernel unwinds");
		run_mode(skel, prog, 2, R(.retval = 121, .dtor_ran = 1), "program unwinds");
	}
	/*
	 * The pad leaves the task of its function when the kernel unwinds: the code behind the
	 * pad releases it, from the word that the entry of the pad put it into. Once: the count
	 * of the task is what it was.
	 */
	dtor(skel, "leaves_task_guard", skel->progs.leaves_task_below_guard, TC_ACT_SHOT, 7);
	dtor(skel, "leaves_task_throw", skel->progs.leaves_task_below_throw, 109, 7);
	dtor(skel, "leaves_task_fault", skel->progs.leaves_task_below_fault, TC_ACT_SHOT, 7);
	/*
	 * The same with a lock that the function took with the interrupts off, which its pad
	 * releases: the word of the task is the one that is read where the pad ends.
	 */
	dtor(skel, "leaves_task_lock", skel->progs.leaves_task_below_lock, TC_ACT_SHOT, 7);
	/*
	 * The pad of the prog has the task in r1 and in no other register when its loop is left,
	 * in an RCU section: the pad of the loop releases from the word. The kernel enters the
	 * landing pad, which says so, the section is left and the task released once.
	 */
	if (test__start_subtest("task_in_r1")) {
		prog = skel->progs.task_in_r1_below_guard;
		run_mode(skel, prog, 0, R(.retval = 1, .went_on = 107), "returns");
		run_mode(skel, prog, 1, R(.retval = TC_ACT_SHOT, .dtor_ran = 1), "kernel unwinds");
	}
	/*
	 * An object of the program that holds a task: the code behind the pad frees it from its
	 * word, as the type that it is. The count of the task says that its field was released.
	 */
	dtor(skel, "leaves_obj", skel->progs.leaves_obj_below_guard, TC_ACT_SHOT, 7);
	/*
	 * Two tasks that the function acquires in another order than its text has them. The pad
	 * leaves the first one: that one is released where the pad ends, the other one is not
	 * released a second time.
	 */
	dtor(skel, "two_out_of_order", skel->progs.two_out_of_order_below_guard, TC_ACT_SHOT, 7);
	/* the register has the task plus 8: the word has the task */
	dtor(skel, "leaves_task_offset", skel->progs.leaves_task_at_offset_below_guard,
	     TC_ACT_SHOT, 7);
	/* one task held at the first call, two at the second one, and one end for both pads */
	if (test__start_subtest("one_then_two")) {
		prog = skel->progs.one_then_two_below_guard;
		run_modes(skel, prog, 0, 0, R(.retval = 1, .went_on = 107), "both return");
		run_modes(skel, prog, 1, 0, R(.retval = TC_ACT_SHOT, .dtor_ran = 1),
			  "kernel unwinds the first");
		run_modes(skel, prog, 0, 1, R(.retval = TC_ACT_SHOT, .dtor_ran = 1),
			  "kernel unwinds the second");
		run_modes(skel, prog, 1, 0, R(.retval = TC_ACT_SHOT, .dtor_ran = 1),
			  "kernel unwinds the first again");
		run_modes(skel, prog, 2, 0, R(.retval = 42, .caught = 5, .dtor_ran = 1),
			  "the first throws");
		run_modes(skel, prog, 0, 2, R(.retval = 42, .caught = 5, .dtor_ran = 1),
			  "the second throws");
	}
	/*
	 * One task or two held at the first call, whose entry saves nothing for that, and one at
	 * the second call, whose entry saves it. When the kernel unwinds at the first call the
	 * pad releases both tasks, and the code behind the pads finds 0 in the save word: with
	 * the task there it would be released twice.
	 */
	if (test__start_subtest("one_or_two_then_one")) {
		prog = skel->progs.one_or_two_then_one_below_guard;
		run_modes(skel, prog, 0, 0, R(.retval = 1, .went_on = 107), "both return");
		run_modes(skel, prog, 1, 0, R(.retval = TC_ACT_SHOT, .dtor_ran = 1),
			  "kernel unwinds the first");
		run_modes(skel, prog, 0, 1, R(.retval = TC_ACT_SHOT, .dtor_ran = 1),
			  "kernel unwinds the second");
		run_modes(skel, prog, 2, 0, R(.retval = 42, .caught = 5, .dtor_ran = 1),
			  "the first throws");
		run_modes(skel, prog, 0, 2, R(.retval = 42, .caught = 5, .dtor_ran = 1),
			  "the second throws");
	}
	/*
	 * The call in the pad has a pad too, and the kernel unwinds what it calls: an entry that
	 * the frame gets to when the kernel unwinds it already. The value and the task of the
	 * first entry stay. When the prog unwinds into the pad, it is the first one.
	 */
	if (test__start_subtest("pad_in_pad")) {
		prog = skel->progs.pad_in_pad_below_throw;
		run_mode(skel, prog, 0, R(.retval = 1, .went_on = 107), "returns");
		run_mode(skel, prog, 1, R(.retval = 109, .dtor_ran = 1, .handler_ran = 1),
			 "kernel unwinds");
		run_mode(skel, prog, 2, R(.retval = 100 + TC_ACT_SHOT, .dtor_ran = 1,
					  .handler_ran = 1), "program unwinds");
	}
	/*
	 * The pad goes back to the first insn of its function, which throws then. The frame is
	 * still one that the kernel unwinds: nothing is caught.
	 */
	if (test__start_subtest("starts_again")) {
		prog = skel->progs.starts_again_below_fault;
		run_mode(skel, prog, 0, R(.retval = 42, .caught = 17), "throws what it got");
		run_mode(skel, prog, 1, R(.retval = TC_ACT_SHOT, .dtor_ran = 1), "kernel unwinds");
		ASSERT_EQ(skel->bss->mode, 0, "the pad went back to the first insn");
		run_mode(skel, prog, 2, R(.retval = 42, .caught = 5, .dtor_ran = 1),
			 "program unwinds");
	}
	/* four frames of one function, each with its own hidden word and save word */
	if (test__start_subtest("recursion")) {
		prog = skel->progs.recursion_with_pad_below_guard;
		run_mode(skel, prog, 0, R(.retval = 1, .went_on = 107), "returns");
		run_mode(skel, prog, 1, R(.retval = TC_ACT_SHOT, .dtor_ran = 4), "kernel unwinds");
		run_mode(skel, prog, 2, R(.retval = 42, .caught = 5, .dtor_ran = 4),
			 "program unwinds");
	}
	/* the pad is in the exception callback, 'mode_b' says how its callee leaves */
	if (test__start_subtest("exception_cb")) {
		prog = skel->progs.dtor_in_exception_cb;
		run_modes(skel, prog, 0, 0, R(.retval = 109), "returns");
		run_modes(skel, prog, 0, 1, R(.retval = TC_ACT_SHOT, .dtor_ran = 1),
			  "kernel unwinds");
		run_modes(skel, prog, 0, 2, R(.retval = 5, .dtor_ran = 1), "program unwinds");
	}
	/* the pad is in the callback of bpf_for_each_map_elem(), which returns 1 for one element */
	dtor(skel, "for_each_cb", skel->progs.dtor_in_for_each_cb, TC_ACT_SHOT, 1);
	/* the pad is in the frame that the kernel called */
	if (test__start_subtest("dtor_in_main")) {
		prog = skel->progs.dtor_in_main;
		run_mode(skel, prog, 0, R(.retval = 1, .went_on = 107), "returns");
		run_mode(skel, prog, 1, R(.retval = TC_ACT_SHOT, .dtor_ran = 1), "kernel unwinds");
		run_mode(skel, prog, 2, R(.retval = 65, .dtor_ran = 1), "program unwinds");
	}
	/*
	 * Stale words: the stack below the prog is full of ones when the function with the guard is
	 * called, its hidden word among them. The prog unwinds into the landing pad and the prog
	 * above catches, before and after a run in which the kernel unwinds.
	 */
	if (test__start_subtest("stale_guard")) {
		prog = skel->progs.stale_below_guard;
		run_mode(skel, prog, 2, R(.retval = 42, .caught = 5, .dtor_ran = 1),
			 "program unwinds");
		run_mode(skel, prog, 0, R(.retval = 1, .went_on = 107), "returns");
		run_mode(skel, prog, 1, R(.retval = TC_ACT_SHOT, .dtor_ran = 1), "kernel unwinds");
		run_mode(skel, prog, 2, R(.retval = 42, .caught = 5, .dtor_ran = 1),
			 "program unwinds again");
	}
	/* the same below bpf_throw(): the word of the value is stale too, the cookie gets there */
	if (test__start_subtest("stale_throw")) {
		prog = skel->progs.stale_below_throw;
		run_mode(skel, prog, 1, R(.retval = 109, .dtor_ran = 1), "kernel unwinds");
		run_mode(skel, prog, 2, R(.retval = 42, .caught = 5, .dtor_ran = 1),
			 "program unwinds");
		run_mode(skel, prog, 0, R(.retval = 1, .went_on = 107), "returns");
		run_mode(skel, prog, 1, R(.retval = 109, .dtor_ran = 1), "kernel unwinds again");
	}
	/*
	 * A typed catch behind a call that the verifier has no plan for. No clause takes what the
	 * callee threw, and the pad goes on where the hidden word is read: the prog above catches.
	 */
	if (test__start_subtest("stale_catch")) {
		prog = skel->progs.stale_below_catch;
		run_modes(skel, prog, 0, 2, R(.retval = 42, .caught = 5, .personality_ran = 1),
			  "the second throws, no clause");
		run_modes(skel, prog, 0, 0, R(.retval = 1, .went_on = 107), "both return");
		run_modes(skel, prog, 1, 0, R(.retval = TC_ACT_SHOT, .dtor_ran = 1),
			  "kernel unwinds the first");
		run_modes(skel, prog, 0, 2, R(.retval = 42, .caught = 5, .personality_ran = 1),
			  "the second throws again");
		run_modes(skel, prog, 2, 0, R(.retval = 42, .caught = 5, .dtor_ran = 1),
			  "the first throws");
		skel->bss->selector = 1;
		run_modes(skel, prog, 0, 2, R(.retval = 1, .went_on = 177, .handler_ran = 1,
					      .personality_ran = 1), "the second throws, caught");
		skel->bss->selector = 0;
	}
	/*
	 * The landing pad follows the call of a global function that never returns, and nothing
	 * clears the hidden word where the function begins. The throw leaves with unwind_exit: the
	 * stub clears the stale word, and the prog above catches. The kernel unwinds the throw:
	 * the entry sets the word.
	 */
	if (test__start_subtest("stale_global_throw")) {
		prog = skel->progs.stale_below_global_throw;
		run_modes(skel, prog, 0, 2, R(.retval = 42, .caught = 5, .dtor_ran = 1),
			  "the throw unwinds");
		run_modes(skel, prog, 0, 1, R(.retval = TC_ACT_SHOT, .dtor_ran = 1),
			  "kernel unwinds the throw");
		run_modes(skel, prog, 0, 2, R(.retval = 42, .caught = 5, .dtor_ran = 1),
			  "the throw unwinds again");
		run_modes(skel, prog, 2, 0, R(.retval = 42, .caught = 5, .dtor_ran = 1),
			  "the first call unwinds");
		run_modes(skel, prog, 1, 0, R(.retval = TC_ACT_SHOT, .dtor_ran = 1),
			  "kernel unwinds the first call");
	}
	/* four frames of one function, each with a hidden word that is stale */
	if (test__start_subtest("stale_recursion")) {
		prog = skel->progs.stale_below_recursion;
		run_mode(skel, prog, 2, R(.retval = 42, .caught = 5, .dtor_ran = 4),
			 "program unwinds");
		run_mode(skel, prog, 0, R(.retval = 1, .went_on = 107), "returns");
		run_mode(skel, prog, 1, R(.retval = TC_ACT_SHOT, .dtor_ran = 4), "kernel unwinds");
		run_mode(skel, prog, 2, R(.retval = 42, .caught = 5, .dtor_ran = 4),
			 "program unwinds again");
	}
	/*
	 * A frame that the kernel unwinds calls a function with a guard twice, in its pad. The
	 * kernel unwinds the callee of the first call, the callee of the second one leaves with
	 * unwind_exit: the guard resumes, and the pad of the second call gets the 5. The frame
	 * that calls keeps the cookie of its first entry, and the prog above does not catch.
	 */
	if (test__start_subtest("twice_in_pad")) {
		prog = skel->progs.twice_in_pad_below_throw;
		skel->bss->second_left = 0;
		run_modes(skel, prog, 1, 1, R(.retval = 109, .dtor_ran = 2), "kernel unwinds both");
		ASSERT_EQ(skel->bss->second_left, 5, "what the second call left");
		skel->bss->second_left = 0;
		run_modes(skel, prog, 2, 1, R(.retval = 100 + TC_ACT_SHOT, .dtor_ran = 2),
			  "program unwinds, kernel unwinds in the pad");
		ASSERT_EQ(skel->bss->second_left, 5, "what the second call left");
		skel->bss->second_left = 0;
		run_modes(skel, prog, 1, 2, R(.retval = 109, .dtor_ran = 2),
			  "kernel unwinds, program unwinds in the pad");
		ASSERT_EQ(skel->bss->second_left, 5, "what the second call left");
		run_modes(skel, prog, 1, 0, R(.retval = 109), "kernel unwinds, the pad returns");
		run_modes(skel, prog, 0, 0, R(.retval = 1, .went_on = 107), "returns");
	}
	/*
	 * bpf_loop() that is inlined, under a guard: unwind_exit of the callback gets to the stub
	 * of the helper's unwind_goto by a copy of that insn. The word is stale, the prog catches.
	 */
	if (test__start_subtest("stale_loop_inlined")) {
		prog = skel->progs.stale_below_loop_inlined;
		run_mode(skel, prog, 2, R(.retval = 42, .caught = 5, .dtor_ran = 1),
			 "program unwinds");
		run_mode(skel, prog, 0, R(.retval = 1, .went_on = 101), "returns");
		run_mode(skel, prog, 1, R(.retval = TC_ACT_SHOT, .dtor_ran = 1), "kernel unwinds");
		run_mode(skel, prog, 2, R(.retval = 42, .caught = 5, .dtor_ran = 1),
			 "program unwinds again");
	}
	/*
	 * The same loop in a pad that the kernel entered: the frame keeps the cookie of its first
	 * entry whatever the callback does, and the prog above does not catch.
	 */
	if (test__start_subtest("loop_in_pad")) {
		prog = skel->progs.loop_in_pad_below_throw;
		skel->bss->second_left = 7;
		run_modes(skel, prog, 1, 1, R(.retval = 109), "kernel unwinds both");
		ASSERT_EQ(skel->bss->second_left, 0, "what the pad of the loop got");
		run_modes(skel, prog, 1, 2, R(.retval = 109),
			  "kernel unwinds, the callback unwinds in the pad");
		ASSERT_EQ(skel->bss->second_left, 5, "what the callback left");
		skel->bss->second_left = 7;
		run_modes(skel, prog, 2, 1, R(.retval = 100 + TC_ACT_SHOT),
			  "program unwinds, kernel unwinds in the pad");
		ASSERT_EQ(skel->bss->second_left, 0, "what the pad of the loop got");
		run_modes(skel, prog, 2, 2, R(.retval = 42, .caught = 5),
			  "program unwinds, the callback unwinds in the pad");
		ASSERT_EQ(skel->bss->second_left, 5, "what the callback left");
		run_modes(skel, prog, 1, 0, R(.retval = 109), "kernel unwinds, the loop returns");
		run_modes(skel, prog, 0, 0, R(.retval = 1, .went_on = 107), "returns");
	}
	/*
	 * One pad behind a call on the normal path, where a stub clears the stale word, and behind
	 * a call in pad code, where nothing may clear it.
	 */
	if (test__start_subtest("shared_pad_in_and_out")) {
		prog = skel->progs.shared_pad_in_and_out;
		skel->bss->second_left = 0;
		run_modes(skel, prog, 2, 0, R(.retval = 42, .caught = 5),
			  "the first call unwinds: the stub");
		ASSERT_EQ(skel->bss->second_left, 5, "what the first call left");
		skel->bss->second_left = 0;
		run_modes(skel, prog, 0, 1, R(.retval = TC_ACT_SHOT, .dtor_ran = 1),
			  "kernel unwinds the second, the call in the pad unwinds: no stub");
		ASSERT_EQ(skel->bss->second_left, 5, "what the call in the pad left");
		skel->bss->second_left = 0;
		run_modes(skel, prog, 0, 2, R(.retval = 42, .caught = 5, .dtor_ran = 1),
			  "the second call unwinds, and the call in the pad");
		ASSERT_EQ(skel->bss->second_left, 5, "what the call in the pad left");
		run_modes(skel, prog, 1, 0, R(.retval = TC_ACT_SHOT), "kernel unwinds the first");
		run_modes(skel, prog, 0, 0, R(.retval = 1, .went_on = 107), "returns");
	}
	stale_private_stack(skel);
	/*
	 * Mixed functions clear the hidden word where they begin: the normal path gets to where
	 * the word is read. With the stack painted in front of each call.
	 */
	if (test__start_subtest("mixed_falls_into_pad")) {
		prog = skel->progs.mixed_falls_into_pad;
		run_mode(skel, prog, 0, R(.retval = 42, .caught = 17, .dtor_ran = 1),
			 "returns into the pad");
		run_mode(skel, prog, 1, R(.retval = TC_ACT_SHOT, .dtor_ran = 1), "kernel unwinds");
		run_mode(skel, prog, 2, R(.retval = 42, .caught = 15, .dtor_ran = 1),
			 "program unwinds");
		run_mode(skel, prog, 0, R(.retval = 42, .caught = 17, .dtor_ran = 1),
			 "returns into the pad again");
	}
	if (test__start_subtest("mixed_shares_unwind_exit")) {
		prog = skel->progs.mixed_shares_unwind_exit;
		run_mode(skel, prog, 0, R(.retval = 42, .caught = 17), "throws what it got");
		run_mode(skel, prog, 1, R(.retval = TC_ACT_SHOT, .dtor_ran = 1), "kernel unwinds");
		run_mode(skel, prog, 2, R(.retval = 42, .caught = 5, .dtor_ran = 1),
			 "program unwinds");
		run_mode(skel, prog, 0, R(.retval = 42, .caught = 17), "throws again");
	}
	if (test__start_subtest("mixed_jumps_into_pad")) {
		prog = skel->progs.mixed_jumps_into_pad;
		run_mode(skel, prog, 3, R(.retval = 42, .caught = 6, .dtor_ran = 1), "raises");
		run_mode(skel, prog, 0, R(.retval = 1, .went_on = 107), "returns");
		run_mode(skel, prog, 1, R(.retval = TC_ACT_SHOT, .dtor_ran = 1), "kernel unwinds");
		run_mode(skel, prog, 3, R(.retval = 42, .caught = 6, .dtor_ran = 1),
			 "raises again");
		run_mode(skel, prog, 2, R(.retval = 42, .caught = 5, .dtor_ran = 1),
			 "program unwinds");
	}
	if (test__start_subtest("mixed_starts_again")) {
		prog = skel->progs.mixed_starts_again;
		run_mode(skel, prog, 0, R(.retval = 42, .caught = 17), "throws what it got");
		run_mode(skel, prog, 1, R(.retval = TC_ACT_SHOT, .dtor_ran = 1), "kernel unwinds");
		ASSERT_EQ(skel->bss->mode, 0, "the pad went back to the first insn");
		run_mode(skel, prog, 2, R(.retval = 42, .caught = 5, .dtor_ran = 1),
			 "program unwinds");
	}
	/*
	 * A caller that holds more than a pad of the verifier releases, above a function with a
	 * guard that this caller keeps from its call. The program loads because the two calls are
	 * kept apart, and it loads with the landing pad entered: when the kernel unwinds below
	 * the other caller the destructor runs, and each frame leaves its own RCU sections.
	 */
	if (test__start_subtest("two_callers_of_guard")) {
		prog = skel->progs.two_callers_of_guard;
		run_mode(skel, prog, 0, R(.retval = 1), "returns");
		run_mode(skel, prog, 1, R(.retval = TC_ACT_SHOT, .dtor_ran = 1), "kernel unwinds");
	}
	/* the same where what keeps the caller from the unwinding is in the callee of the guard */
	if (test__start_subtest("two_callers_of_count")) {
		prog = skel->progs.two_callers_of_count;
		run_mode(skel, prog, 0, R(.retval = 1), "returns");
		run_mode(skel, prog, 1, R(.retval = TC_ACT_SHOT, .dtor_ran = 1), "kernel unwinds");
	}
	/*
	 * A landing pad that calls what has no plan, behind a call that the kernel unwinds only
	 * while two calls are verified together: the object loads, and no run enters the pad.
	 */
	if (test__start_subtest("pad_of_joined_calls")) {
		prog = skel->progs.pad_of_joined_calls;
		run_mode(skel, prog, 0, R(.retval = 1), "returns");
	}
	kunwind_pads__destroy(skel);
	no_perfmon();
}

#else

static void kunwind_pads(void)
{
	test__skip();
}

#endif

void test_kunwind_pads(void)
{
	kunwind_pads();
}
