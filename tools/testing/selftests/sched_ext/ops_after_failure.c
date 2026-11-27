// SPDX-License-Identifier: GPL-2.0
/*
 * A scheduler fails while it runs: one of its operators is unwound. The disable
 * path calls none of its operators after that, ops.cgroup_exit() included.
 */
#include <bpf/bpf.h>
#include <scx/common.h>
#include <sched.h>
#include <unistd.h>
#include "ops_after_failure.bpf.skel.h"
#include "scx_test.h"

static enum scx_test_status setup(void **ctx)
{
	struct ops_after_failure *skel;

	skel = ops_after_failure__open();
	SCX_FAIL_IF(!skel, "Failed to open");
	SCX_ENUM_INIT(skel);
	SCX_FAIL_IF(ops_after_failure__load(skel), "Failed to load skel");

	*ctx = skel;

	return SCX_TEST_PASS;
}

static enum scx_test_status run(void *ctx)
{
	struct ops_after_failure *skel = ctx;
	struct bpf_link *link, *tp;
	int i;

	/* the prog that tells ops.cgroup_exit() when the exit is claimed */
	tp = bpf_program__attach(skel->progs.exit_claimed);
	SCX_FAIL_IF(!tp, "Failed to attach to the tracepoint");

	link = bpf_map__attach_struct_ops(skel->maps.ops_after_failure_ops);
	SCX_FAIL_IF(!link, "Failed to attach scheduler");

	/* the root cgroup at least */
	SCX_GT(skel->bss->nr_cgroup_init, 0);
	SCX_EQ(skel->data->uei.kind, EXIT_KIND(SCX_EXIT_NONE));

	/* the next task that starts to run unwinds the operator: 5 s is far more than it takes */
	skel->bss->fail_now = true;
	for (i = 0; i < 5000 && !skel->data->uei.kind; i++) {
		sched_yield();
		usleep(1000);
	}

	bpf_link__destroy(link);
	bpf_link__destroy(tp);

	SCX_EQ(skel->data->uei.kind, EXIT_KIND(SCX_EXIT_ERROR));
	SCX_EQ(skel->bss->nr_cgroup_exit_failed, 0);

	return SCX_TEST_PASS;
}

static void cleanup(void *ctx)
{
	struct ops_after_failure *skel = ctx;

	ops_after_failure__destroy(skel);
}

struct scx_test ops_after_failure = {
	.name = "ops_after_failure",
	.description = "Verify that no cgroup is given back to a scheduler that failed",
	.setup = setup,
	.run = run,
	.cleanup = cleanup,
};
REGISTER_SCX_TEST(&ops_after_failure)
