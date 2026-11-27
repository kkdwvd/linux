// SPDX-License-Identifier: GPL-2.0
/*
 * The scheduler is unregistered, and its ops.exit_task() is unwound while it is
 * being disabled. That is no error that can be claimed any more, but the
 * operators are turned off: ops.exit_task() is not called for the other tasks.
 */
#include <bpf/bpf.h>
#include <scx/common.h>
#include <sys/wait.h>
#include <unistd.h>
#include "exit_task_unwound.bpf.skel.h"
#include "scx_test.h"

static enum scx_test_status setup(void **ctx)
{
	struct exit_task_unwound *skel;

	skel = exit_task_unwound__open();
	SCX_FAIL_IF(!skel, "Failed to open");
	SCX_ENUM_INIT(skel);
	SCX_FAIL_IF(exit_task_unwound__load(skel), "Failed to load skel");

	*ctx = skel;

	return SCX_TEST_PASS;
}

static enum scx_test_status run(void *ctx)
{
	struct exit_task_unwound *skel = ctx;
	struct bpf_link *link, *tp;

	/* the prog that tells the operator when the exit is claimed */
	tp = bpf_program__attach(skel->progs.exit_claimed);
	SCX_FAIL_IF(!tp, "Failed to attach to the tracepoint");

	link = bpf_map__attach_struct_ops(skel->maps.exit_task_unwound_ops);
	SCX_FAIL_IF(!link, "Failed to attach scheduler");

	/* a task that exits before the destroy claims the exit is not unwound */
	SCX_EQ(skel->bss->unloading, 0);
	bpf_link__destroy(link);
	bpf_link__destroy(tp);

	SCX_EQ(skel->data->uei.kind, EXIT_KIND(SCX_EXIT_UNREG));
	/*
	 * The disable path calls the operator for every task, one after the
	 * other, and the first call turns it off. A task that exits on another
	 * cpu at that time can get in, if it has asked for the operator before:
	 * one call per cpu besides the first one, not one per task.
	 */
	SCX_GT(skel->bss->nr_exit_task_unloading, 0);
	SCX_LE(skel->bss->nr_exit_task_unloading, libbpf_num_possible_cpus() + 1);

	return SCX_TEST_PASS;
}

static void cleanup(void *ctx)
{
	struct exit_task_unwound *skel = ctx;

	exit_task_unwound__destroy(skel);
}

struct scx_test exit_task_unwound = {
	.name = "exit_task_unwound",
	.description = "Verify that an unwound ops.exit_task() of a scheduler that is unregistered turns the operators off",
	.setup = setup,
	.run = run,
	.cleanup = cleanup,
};
REGISTER_SCX_TEST(&exit_task_unwound)
