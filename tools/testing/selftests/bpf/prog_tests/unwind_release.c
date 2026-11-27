// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include "unwind_release.skel.h"

/* good_pass_restored_holds_task() writes at an offset below 1 << 14 */
static char ctx[(1 << 14) + 8];

#define LOG_SIZE (4 << 20)

static int run(struct bpf_program *prog)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);

	if (bpf_program__fd(prog) < 0)
		return -1;
	opts.ctx_in = ctx;
	opts.ctx_size_in = sizeof(ctx);
	if (!ASSERT_OK(bpf_prog_test_run_opts(bpf_program__fd(prog), &opts), "run"))
		return -1;
	return opts.retval;
}

/*
 * Each prog is unwound while it holds a reference to the task that runs it. If its landing pad did
 * not release the reference, the task would have one more after each run.
 * @retval: what the unwound prog returns. The kernel unwinds all but one, and they are syscall
 * progs: -ECANCELED.
 */
static void __unwound_holding_task(struct unwind_release *skel, struct bpf_program *prog,
				   const char *name, int retval)
{
	int before, after, i;

	before = run(skel->progs.task_usage);
	for (i = 0; i < 3; i++)
		ASSERT_EQ(run(prog), retval, name);
	after = run(skel->progs.task_usage);
	ASSERT_GT(before, 0, "usage");
	ASSERT_EQ(after, before, name);
}

static void unwound_holding_task(struct unwind_release *skel, struct bpf_program *prog,
				 const char *name)
{
	__unwound_holding_task(skel, prog, name, -ECANCELED);
}

void test_unwind_release(void)
{
	struct unwind_release *skel;
	char *log, *slot_log, *may_goto_log;

	log = calloc(1, LOG_SIZE);
	slot_log = calloc(1, LOG_SIZE);
	may_goto_log = calloc(1, LOG_SIZE);
	if (!ASSERT_OK_PTR(log, "log") || !ASSERT_OK_PTR(slot_log, "slot_log") ||
	    !ASSERT_OK_PTR(may_goto_log, "may_goto_log"))
		goto free;
	skel = unwind_release__open();
	if (!ASSERT_OK_PTR(skel, "open"))
		goto free;
	bpf_program__set_log_buf(skel->progs.good_pass_restored_holds_task, log, LOG_SIZE);
	bpf_program__set_log_level(skel->progs.good_pass_restored_holds_task, 6);
	bpf_program__set_log_buf(skel->progs.good_pass_restored_may_goto_holds_task, may_goto_log,
				 LOG_SIZE);
	bpf_program__set_log_level(skel->progs.good_pass_restored_may_goto_holds_task, 6);
	bpf_program__set_log_buf(skel->progs.fault_slot_holds_task, slot_log, LOG_SIZE);
	bpf_program__set_log_level(skel->progs.fault_slot_holds_task, 2);
	if (!ASSERT_OK(unwind_release__load(skel), "load"))
		goto out;
	ASSERT_EQ(run(skel->progs.task_usage_holding), run(skel->progs.task_usage) + 1, "held");
	unwound_holding_task(skel, skel->progs.guard_holds_task, "guard");
	unwound_holding_task(skel, skel->progs.may_goto_holds_task, "may_goto");
	unwound_holding_task(skel, skel->progs.callee_may_goto_caller_holds_task,
			     "callee with may_goto");
	/* the prog unwinds by itself, with the value that it throws */
	__unwound_holding_task(skel, skel->progs.throw_holds_task, "throw", 0);
	unwound_holding_task(skel, skel->progs.callee_unwinds_caller_holds_task, "callee");
	/* An access to arena that faults: with the reference in a register, and in a hidden slot */
	unwound_holding_task(skel, skel->progs.fault_holds_task, "fault");
	ASSERT_HAS_SUBSTR(slot_log, "func#0 has hidden slots for: refs", "slot at the access");
	unwound_holding_task(skel, skel->progs.fault_slot_holds_task, "fault, slot");
	unwound_holding_task(skel, skel->progs.callee_faults_caller_slot, "callee faults, slot");
	/* and the slot is empty where the prog took no reference: the pad releases nothing */
	skel->data->take = 0;
	unwound_holding_task(skel, skel->progs.fault_slot_holds_task, "fault, empty slot");
	unwound_holding_task(skel, skel->progs.callee_faults_caller_slot,
			     "callee faults, empty slot");
	skel->data->take = 1;
	/* The landing pad is of the pass that was restored */
	ASSERT_HAS_SUBSTR(log, "landing pad of may_goto at", "pad of the good pass");
	ASSERT_HAS_SUBSTR(log, "BPF program is too complex", "later pass");
	unwound_holding_task(skel, skel->progs.good_pass_restored_holds_task, "restored");
	/* the same with may_goto that the prog has */
	ASSERT_HAS_SUBSTR(may_goto_log, "landing pad of may_goto of the program at",
			  "pad of the good pass, may_goto of the program");
	ASSERT_HAS_SUBSTR(may_goto_log, "BPF program is too complex", "later pass");
	unwound_holding_task(skel, skel->progs.good_pass_restored_may_goto_holds_task,
			     "restored, may_goto of the program");
out:
	unwind_release__destroy(skel);
free:
	free(log);
	free(slot_log);
	free(may_goto_log);
}
